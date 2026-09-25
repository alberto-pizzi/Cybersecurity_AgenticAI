from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

from utils import RequestRatePacer, request_contract_state_change_reason, request_same_origin_redirects, partial, scanner_session_probe, secops_parallelism_policy, skipped, success

from core.scannerCommon import mutate_parameter, proportional_budget, remaining_budget, service, wall_clock_deadline

mcp, _serve = service("Path Traversal and LFI Verifier", "traversal")

TRAVERSAL_SESSION_RATIO = 0.08
TRAVERSAL_REQUEST_RATIO = 0.12

CONTROL_PARAMETERS = {"submit", "button", "change", "login", "user_token", "csrf"}
PATH_PARAMETERS = {
    "file", "filename", "path", "page", "include", "template", "document",
    "folder", "dir", "directory", "view", "resource", "download",
}
PROBES = (
    ("../../../../../../etc/passwd", re.compile(r"(?m)(?:^|[>\r\n])root:x:0:0:"), "Linux /etc/passwd"),
    ("../../../../../../etc/hosts", re.compile(r"(?m)(?:^|[>\r\n])127\.0\.0\.1\s+localhost(?:\s|<|$)"), "Linux /etc/hosts"),
    (r"..\..\..\..\Windows\win.ini", re.compile(r"(?im)^\[(?:fonts|extensions|mci extensions)\]"), "Windows win.ini"),
)

# Send one bounded traversal request while preserving the discovered request contract.
def _request(url: str, cookies: str, method: str, data: str, pacer: RequestRatePacer, read_timeout: float, deadline: float, allow_state_changes: bool = False) -> requests.Response:
    headers = {"Cache-Control": "no-cache", "User-Agent": "SecOps-Path-Traversal-Verifier/1.0"}
    if cookies:
        headers["Cookie"] = cookies
    return request_same_origin_redirects(
        method, url, data=data if method != "GET" else None, headers=headers,
        timeout=(max(1.0, read_timeout * 0.25), max(1.0, read_timeout)), pacer=pacer, deadline=deadline, allow_state_changes=bool(allow_state_changes),
    )

# Extract a compact response excerpt around the marker used for LFI verification.
def _excerpt(text: str, match: re.Match[str] | None, limit: int = 1000) -> str:
    value = str(text or "")
    if not match:
        return value[:limit]
    start = max(0, match.start() - 180)
    return value[start:start + limit]

# Run bounded, read-only path traversal/LFI probes against file-like parameters.
@mcp.tool()
def run_traversal_scan(
    target_url: str, cookies: str = "", method: str = "GET", data: str = "", parameters: list[str] | None = None, timeout: int = 30,
    scan_profile: str = "balanced", request_rate: float | None = None, allow_state_changes: bool = False, session_probe_url: str = "", session_prevalidated: bool = False,
) -> dict:

    method = str(method or "GET").upper()
    timeout = max(10, min(int(timeout), 604800))
    profile = str(scan_profile or "balanced").strip().lower()
    if profile not in {"test", "fast", "balanced", "deep"}:
        raise ValueError("scan_profile must be test, fast, balanced, or deep")
    parameter_limit = 1 if profile == "test" else 2 if profile == "fast" else 3 if profile == "balanced" else 5
    deadline = wall_clock_deadline(timeout)
    request_budget = proportional_budget(timeout, TRAVERSAL_REQUEST_RATIO)
    pacer = RequestRatePacer(request_rate)
    if method not in {"GET", "POST"}:
        return partial(
            "Path Traversal/LFI", target_url, f"Unsupported HTTP method for bounded traversal verification: {method}.",
            diagnosis="unsupported_method", timed_out=False, vulnerabilities=[],
        )
    state_reason = request_contract_state_change_reason({"url": target_url, "method": method, "data": data, "parameters": parameters or []}) if not allow_state_changes else ""
    if state_reason:
        return skipped("Path Traversal/LFI", target_url, f"Traversal request blocked by allow_state_changes=false: {state_reason}.", diagnosis="state_change_policy_blocked", allow_state_changes=False)
    candidates = [
        value for value in dict.fromkeys(str(item) for item in (parameters or []) if str(item))
        if value.lower() in PATH_PARAMETERS and value.lower() not in CONTROL_PARAMETERS
    ]
    if not candidates:
        return success(
            "Path Traversal/LFI", target_url, "No file/path/include-style parameter was available for a bounded traversal probe.",
            vulnerabilities=[], applicable=False,
        )

    probe_target = str(session_probe_url or target_url)
    probe_method, probe_data = ("GET", "") if session_probe_url else (method, data)
    session_probe = ({'performed': False, 'authenticated': True, 'conclusive': True, 'prevalidated_by_orchestrator': True} if session_prevalidated else scanner_session_probe(probe_target, cookies, probe_method, probe_data, timeout=min(proportional_budget(timeout, TRAVERSAL_SESSION_RATIO), max(1, int(remaining_budget(deadline)))), attempts=1, pacer=pacer, deadline=deadline))
    if cookies and session_probe.get("performed") and session_probe.get("conclusive") and session_probe.get("authenticated") is False:
        return partial(
            "Path Traversal/LFI", target_url,
            "Traversal verification was not started because the authenticated request redirected to a login page.",
            diagnosis="authentication_precheck_failed", timed_out=False, vulnerabilities=[], session_probe=session_probe,
        )

    # Establish a benign baseline before sending read-only traversal variants.
    baseline: requests.Response | None = None
    baseline_error = ""
    try:
        baseline = _request(target_url, cookies, method, data, pacer, min(request_budget, max(1.0, remaining_budget(deadline))), deadline, bool(allow_state_changes))
    except requests.RequestException as exc:
        baseline_error = f"{type(exc).__name__}: {exc}"

    attempts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    parallelism = secops_parallelism_policy(request_rate)
    # Confirm only known file markers that are absent from the benign response. Independent
    # read-only payloads for one parameter run concurrently behind the shared request pacer.
    budget_exhausted = False
    for parameter in candidates[:parameter_limit]:
        if remaining_budget(deadline) <= 0:
            budget_exhausted = True
            break
        def run_probe(spec: tuple[str, re.Pattern[str], str]):
            payload, marker, label = spec
            probe_url, probe_data = mutate_parameter(target_url, method, data, parameter, payload, case_insensitive=True)
            try:
                response = _request(probe_url, cookies, method, probe_data, pacer, min(request_budget, max(1.0, remaining_budget(deadline))), deadline, bool(allow_state_changes))
                return payload, marker, label, response, None
            except requests.RequestException as exc:
                return payload, marker, label, None, exc
        worker_count = max(1, min(len(PROBES), int(parallelism.get("network_workers") or 1)))
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="secops-traversal") as executor:
            probe_results = list(executor.map(run_probe, PROBES))
        for payload, marker, label, response, probe_error in probe_results:
            if probe_error is not None or response is None:
                attempts.append({
                    "parameter": parameter, "payload": payload, "source": label, "error": f"{type(probe_error).__name__}: {probe_error}",
                })
                continue
            baseline_match = marker.search(baseline.text) if baseline is not None else None
            match = marker.search(response.text)

            confirmed = bool(match and not baseline_match and response.status_code < 400)
            attempt = {
                "parameter": parameter, "payload": payload, "source": label,
                "status": response.status_code, "final_url": str(response.url),
                "response_bytes": len(response.content), "confirmed": confirmed, "response_excerpt": _excerpt(response.text, match),
            }
            attempts.append(attempt)
            if confirmed:
                findings.append({
                    "alert": f"Local file inclusion/path traversal in parameter '{parameter}'", "risk": "high",
                    "category": "vulnerability", "verification_status": "known-local-file-marker-confirmed", "confidence": "high",
                    "description": (
                        f"A traversal payload supplied through '{parameter}' returned a marker from {label} "
                        "that was absent from the baseline response."
                    ),
                    "attack_preconditions": "An attacker must be able to submit the affected file/path parameter.",
                    "impact": (
                        "An attacker may read local files accessible to the web-server account, including configuration, "
                        "source, credentials or operating-system data. In include contexts, impact can increase if an "
                        "attacker can influence an included file."
                    ),
                    "solution": (
                        "Do not concatenate user input into filesystem paths or include statements. Map user choices to "
                        "server-side identifiers, canonicalize paths, enforce an allow-list, and verify that the resolved "
                        "path remains inside the intended directory."
                    ),
                    "url": target_url, "method": method, "parameter": parameter, "payload": payload,
                    "cwe_id": "22", "owasp_category": "A01:2021 Broken Access Control",
                    "technical_details": (
                        f"HTTP {response.status_code}; source marker={label}; response bytes={len(response.content)}; "
                        "marker absent from baseline=True."
                    ),
                    "reproduction": (
                        f"1. Send the original {method} request to {target_url}.\n"
                        f"2. Set '{parameter}' to: {payload}\n"
                        f"3. Confirm the response contains the expected marker from {label}."
                    ),
                    "evidence": (
                        f"Payload: {payload}\nFinal URL: {response.url}\n"
                        f"Response excerpt:\n{attempt['response_excerpt']}"
                    ),
                })
                break
        if findings:
            break

        if budget_exhausted:
            break

    common = {
        "vulnerabilities": findings, "attempts": attempts, "applicable": True,
        "authenticated": bool(cookies), "session_probe": session_probe,
        "execution_mode": "bounded_known_file_markers", "per_request_budget_seconds": request_budget,
        "tool_timeout_seconds": timeout, "phase_ratio_policy": {"session": TRAVERSAL_SESSION_RATIO, "request": TRAVERSAL_REQUEST_RATIO},
        "parallelism_policy": parallelism,
        "scan_profile": profile, "parameter_limit": parameter_limit,
        "baseline_available": baseline is not None, "baseline_error": baseline_error,
    }
    if budget_exhausted:
        return partial(
            "Path Traversal/LFI", target_url,
            f"Traversal verification reached its shared action time budget. Confirmed findings preserved: {len(findings)}.",
            diagnosis="time_limit_reached", timed_out=True, time_limit_reached=True, **common,
        )
    return success(
        "Path Traversal/LFI", target_url, f"Bounded traversal verification completed. Confirmed findings: {len(findings)}.",
        **common,
    )

if __name__ == "__main__":
    _serve()
