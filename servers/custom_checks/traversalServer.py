from __future__ import annotations

import re
from typing import Any

import requests

from utils import partial, scanner_session_probe, success

from core.scannerCommon import mutate_parameter, service

mcp, _serve = service("Path Traversal and LFI Verifier", "traversal")

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
def _request(url: str, cookies: str, method: str, data: str, read_timeout: float = 7.0) -> requests.Response:
    headers = {"Cache-Control": "no-cache", "User-Agent": "SecOps-Path-Traversal-Verifier/1.0"}
    if cookies:
        headers["Cookie"] = cookies
    return requests.request(
        method, url, data=data if method != "GET" else None, headers=headers,
        timeout=(3, max(3.0, read_timeout)), allow_redirects=True,
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
) -> dict:

    method = str(method or "GET").upper()
    timeout = max(10, min(int(timeout), 120))
    read_timeout = max(4.0, min(7.0, (timeout - 5.0) / 4.0))
    if method not in {"GET", "POST"}:
        return partial(
            "Path Traversal/LFI", target_url, f"Unsupported HTTP method for bounded traversal verification: {method}.",
            diagnosis="unsupported_method", timed_out=False, vulnerabilities=[],
        )
    candidates = [
        value for value in dict.fromkeys(str(item) for item in (parameters or []) if str(item))
        if value.lower() in PATH_PARAMETERS and value.lower() not in CONTROL_PARAMETERS
    ]
    if not candidates:
        return success(
            "Path Traversal/LFI", target_url, "No file/path/include-style parameter was available for a bounded traversal probe.",
            vulnerabilities=[], applicable=False,
        )

    session_probe = scanner_session_probe(target_url, cookies, method, data, timeout=4, attempts=1)
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
        baseline = _request(target_url, cookies, method, data, read_timeout)
    except requests.RequestException as exc:
        baseline_error = f"{type(exc).__name__}: {exc}"

    attempts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    # Confirm only known file markers that are absent from the benign response.
    for parameter in candidates[:2]:
        for payload, marker, label in PROBES:
            probe_url, probe_data = mutate_parameter(target_url, method, data, parameter, payload, case_insensitive=True)
            try:
                response = _request(probe_url, cookies, method, probe_data, read_timeout)
            except requests.RequestException as exc:
                attempts.append({
                    "parameter": parameter, "payload": payload, "source": label, "error": f"{type(exc).__name__}: {exc}",
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

    common = {
        "vulnerabilities": findings, "attempts": attempts, "applicable": True,
        "authenticated": bool(cookies), "session_probe": session_probe,
        "execution_mode": "bounded_known_file_markers", "request_timeout": round(read_timeout, 2),
        "baseline_available": baseline is not None, "baseline_error": baseline_error,
    }
    return success(
        "Path Traversal/LFI", target_url, f"Bounded traversal verification completed. Confirmed findings: {len(findings)}.",
        **common,
    )

if __name__ == "__main__":
    _serve()
