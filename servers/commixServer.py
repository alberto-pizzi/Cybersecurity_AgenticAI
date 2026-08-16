from __future__ import annotations

import html
import re
import sys
import time
import uuid

import requests
from typing import Any

from utils import failure, partial, response_excerpt, run_process, scanner_session_probe, success, trim_process_output

from scannerCommon import extend_request_cli, filter_control_parameters, find_repo_script, mutate_parameter, process_text, service

mcp, _serve = service("Commix Scanner", "commix")

def _findings(text: str, target_url: str, method: str) -> list[dict[str, Any]]:
    positive = r"(?:is vulnerable|appears to be injectable|seems injectable|command injection vulnerability)"
    if not re.search(rf"(?:parameter.+{positive}|{positive}.+parameter)", text, re.I):
        return []
    parameter_match = re.search(
        rf"(?:GET|POST)?\s*parameter\s*['\"]?([A-Za-z0-9_.-]+)['\"]?.{{0,120}}?{positive}", text, re.I,
    )
    if not parameter_match:
        parameter_match = re.search(r"(?:GET|POST)\s+parameter\s+['\"]([^'\"]+)['\"]", text, re.I)
    parameter = parameter_match.group(1) if parameter_match else ""
    payloads = [value.strip() for value in re.findall(r"(?:payload|Payload)\s*[:=]\s*(.+)", text)]
    technique_lines = [
        line.strip() for line in text.splitlines()
        if re.search(r"technique|vulnerable|injectable|payload", line, re.I)
    ]
    return [{
        "alert": (f"OS command injection in parameter '{parameter}'" if parameter else "OS command injection"),
        "risk": "critical", "category": "vulnerability", "verification_status": "scanner-confirmed-command-injection",
        "description": (
            f"Commix reported that the HTTP {method} parameter '{parameter}' is command-injectable."
            if parameter else
            f"Commix reported a command-injectable HTTP {method} parameter; the parameter name was not extracted by the parser."
        ),
        "impact": (
            "The affected input can reach an operating-system command execution path. An attacker may execute commands "
            "with the web application's operating-system privileges, access files and secrets available to that account, "
            "or use the host as a pivot, subject to platform and process restrictions."
        ),
        "solution": (
            "Remove shell-command construction from untrusted input. Use a safe library API for the required operation, "
            "apply strict allow-list validation, avoid invoking a shell, and run the service with minimal privileges."
        ),
        "url": target_url, "method": method, "parameter": parameter, "payloads": payloads[:10], "confidence": "high",
        "technical_details": f"Commix positive marker; parameter={parameter or 'not extracted'}; method={method}.",
        "evidence": "\n".join(technique_lines[:40]) or text[-5000:],
    }]

COMMAND_PARAMETERS = {"ip", "host", "hostname", "cmd", "command", "exec", "target", "domain"}

def _command_canary(
    target_url: str, cookies: str, method: str, data: str, parameters: list[str], timeout: int = 25,
) -> dict[str, Any]:
    """Attempt a harmless, bounded response-marker confirmation first.

    Network-like parameters use 127.0.0.1 instead of the crawler's placeholder
    value.  A placeholder such as ``1`` can make ping wait long enough that the
    appended marker command never executes before the HTTP timeout.
    """
    candidates = [value for value in parameters if value.lower() in COMMAND_PARAMETERS]
    if not candidates:
        return {"performed": False, "confirmed": False, "reason": "no_command_like_parameter"}

    parameter = candidates[0]
    nonce = uuid.uuid4().hex[:10].upper()
    marker = f"SECOPS_CMD_{nonce}"
    # The expected marker is intentionally NOT present verbatim in any request
    # payload.  A simple reflection of the submitted value therefore cannot be
    # mistaken for command execution.  The shell must join independently
    # supplied fragments (Unix printf or Windows variable expansion) before the
    # exact marker can appear in the response.
    suffixes = (
        f" & printf 'SECOPS_%s' 'CMD_{nonce}'",
        f" | printf 'SECOPS_%s' 'CMD_{nonce}'",
        f"; printf 'SECOPS_%s' 'CMD_{nonce}'; #",
        f' & set "SECOPS_PART=CMD_{nonce}" & call echo SECOPS_%%SECOPS_PART%%',
    )
    headers = {
        "Cache-Control": "no-cache", "User-Agent": "SecOps-Command-Injection-Verifier/3.0",
    }
    if cookies:
        headers["Cookie"] = cookies
    if method != "GET":
        stripped = str(data or "").lstrip()
        headers["Content-Type"] = (
            "application/json"
            if stripped.startswith(("{", "["))
            else "application/x-www-form-urlencoded"
        )

    network_parameter = parameter.lower() in {"ip", "host", "hostname", "target", "domain"}
    base_value = "127.0.0.1" if network_parameter else "echo"
    attempts: list[dict[str, Any]] = []
    deadline = time.monotonic() + max(8, min(int(timeout), 35))

    def mutate(value: str) -> tuple[str, str]:
        return mutate_parameter(
            target_url, method, data, parameter, value, case_insensitive=True
        )

    def send(value: str) -> requests.Response:
        request_url, request_data = mutate(value)
        remaining = max(3.0, deadline - time.monotonic())
        return requests.request(
            method, request_url, data=request_data if method != "GET" else None, headers=headers,
            timeout=(3, min(10.0, remaining)), allow_redirects=True,
        )

    baseline: dict[str, Any] = {}
    try:
        response = send(base_value)
        baseline = {
            "status": response.status_code, "final_url": str(response.url),
            "response_bytes": len(response.content), "marker_absent": marker not in html.unescape(response.text),
        }
    except requests.RequestException as exc:
        baseline = {"error": f"{type(exc).__name__}: {exc}", "marker_absent": True}

    for command_suffix in suffixes:
        if time.monotonic() >= deadline - 2:
            break
        injected_value = f"{base_value}{command_suffix}"
        request_url, request_data = mutate(injected_value)
        try:
            response = send(injected_value)
        except requests.RequestException as exc:
            attempts.append({"payload_suffix": command_suffix, "error": f"{type(exc).__name__}: {exc}"})
            continue
        decoded_body = html.unescape(response.text)
        marker_absent_from_payload = marker not in injected_value
        baseline_valid = (
            "status" in baseline
            and bool(baseline.get("marker_absent"))
            and int(baseline.get("status") or 0) < 500
        )
        confirmed = (
            baseline_valid
            and marker_absent_from_payload
            and marker in decoded_body
            and response.status_code < 500
        )
        attempt = {
            "payload_suffix": command_suffix, "status": response.status_code,
            "final_url": str(response.url), "request_url": request_url,
            "request_data": request_data, "response_bytes": len(response.content),
            "confirmed": confirmed, "marker_absent_from_payload": marker_absent_from_payload,
            "baseline_valid": baseline_valid, "response_excerpt": response_excerpt(response.text, marker),
        }
        attempts.append(attempt)
        if confirmed:
            return {
                "performed": True, "confirmed": True, "parameter": parameter, "marker": marker,
                "payload_suffix": command_suffix, "base_value": base_value, "baseline": baseline, "attempts": attempts,
                "verification_method": "non-reflective-transformed-marker-v2", **attempt,
            }
    return {
        "performed": True, "confirmed": False, "parameter": parameter, "marker": marker,
        "base_value": base_value, "baseline": baseline,
        "attempts": attempts, "canary_budget_seconds": max(8, min(int(timeout), 35)),
        "verification_method": "non-reflective-transformed-marker-v2",
    }

def _canary_finding(
    target_url: str, method: str, canary: dict[str, Any],
) -> list[dict[str, Any]]:
    if not canary.get("confirmed"):
        return []
    parameter = str(canary.get("parameter") or "")
    return [{
        "alert": f"OS command injection in parameter '{parameter}'", "risk": "critical",
        "category": "vulnerability", "verification_status": "unique-response-marker-command-execution-confirmed",
        "confidence": "high",
        "description": "A benign shell transformation appended to the selected input produced a unique server-side marker in the HTTP response. The exact marker was absent from both the baseline response and the submitted payload, so ordinary input reflection cannot explain the result.",
        "attack_preconditions": "An attacker must be able to submit the affected parameter to the command-execution handler.",
        "impact": "The attacker can execute operating-system commands with the web-server account's privileges, read accessible files and secrets, modify application data, and potentially pivot to other services reachable from the container or host.",
        "solution": "Remove shell command construction from untrusted input. Use a dedicated networking or process API, enforce a strict allow-list, avoid invoking a shell, and run the service under a minimally privileged account.",
        "url": target_url, "method": method, "parameter": parameter, "payload": canary.get("payload_suffix"),
        "cwe_id": "78", "owasp_category": "A03:2021 Injection",
        "technical_details": (
            f"HTTP {canary.get('status')}; marker={canary.get('marker')}; "
            f"marker absent from payload={canary.get('marker_absent_from_payload')}; "
            f"baseline valid={canary.get('baseline_valid')}; "
            f"verification={canary.get('verification_method')}; "
            f"response bytes={canary.get('response_bytes')}."
        ),
        "reproduction": (
            f"1. Send the {method} request to {target_url}.\n"
            f"2. Append the bounded transformation payload shown in the evidence to parameter '{parameter}'.\n"
            f"3. Confirm that the response contains '{canary.get('marker')}', even though that exact marker is absent from the submitted payload."
        ),
        "evidence": (
            f"Request URL: {canary.get('request_url')}\n"
            f"Request data: {canary.get('request_data')}\n"
            f"Response excerpt:\n{canary.get('response_excerpt')}"
        ),
    }]

@mcp.tool()
def run_commix_scan(
    target_url: str, cookies: str = "", method: str = "GET", data: str = "",
    parameters: list[str] | None = None, timeout: int = 150,
) -> dict:
    """Run Commix directly through Python and preserve bounded results."""
    method = method.upper()
    timeout = max(45, min(int(timeout), 600))
    parameters = filter_control_parameters(parameters)
    session_probe = scanner_session_probe(target_url, cookies, method, data, timeout=4, attempts=1)
    if cookies and session_probe.get("performed") and session_probe.get("conclusive") and session_probe.get("authenticated") is False:
        return partial("Commix", target_url, "Commix was not started because the authenticated request redirected to a login page.", diagnosis="authentication_precheck_failed", timed_out=False, vulnerabilities=[], session_probe=session_probe)
    started = time.monotonic()
    canary = _command_canary(
        target_url, cookies, method, data, parameters, timeout=max(8, min(35, timeout // 2)),
    )
    canary_findings = _canary_finding(target_url, method, canary)
    if canary_findings:
        return success("Commix", target_url, "The Commix MCP pre-verifier confirmed command execution with a non-reflective transformed marker; the slower full Commix phase was not required.", vulnerabilities=canary_findings, command_injection_found=True, request_method=method, tested_parameters=parameters, authenticated=bool(cookies), session_probe=session_probe, command_canary=canary, execution_mode="direct_canary", confirmation_engine="secops_non_reflective_command_canary")
    script = find_repo_script("commix", "commix.py")
    if script is None:
        return failure(
            "Commix", target_url, "commix.py was not found under ~/.local/opt/commix. Run initScript.py again.",
            diagnosis="missing_commix_script",
        )

    elapsed_canary = max(0, int(time.monotonic() - started))
    remaining_budget = max(10, timeout - elapsed_canary - 3)
    if remaining_budget < 20:
        return partial(
            "Commix", target_url,
            "The bounded response-marker check was inconclusive and consumed the available scanner budget; the slower Commix phase was not started.",
            diagnosis="bounded_canary_inconclusive", timed_out=False, vulnerabilities=[], request_method=method,
            tested_parameters=parameters, authenticated=bool(cookies),
            session_probe=session_probe, command_canary=canary, execution_mode="direct_canary_only",
        )

    command = [
        sys.executable, str(script), "--url", target_url,
        "--batch", "--ignore-session", "--disable-coloring", "--level", "1", "--timeout", "5", "--retries", "0", "--drop-set-cookie",
        "--time-limit", str(max(15, remaining_budget - 5)),
    ]
    extend_request_cli(command, data, parameters, cookies)

    result = run_process(
        "Commix", command, target=target_url, timeout=remaining_budget, accepted_codes=(0, 1), cwd=script.parent,
    )
    text = process_text(result)
    findings = _findings(text, target_url, method)
    common = {
        "vulnerabilities": findings, "request_method": method, "request_data_present": bool(data), "tested_parameters": parameters,
        "authenticated": bool(cookies), "execution_mode": "direct_python",
        "commix_script": str(script), "session_probe": session_probe, "command_canary": canary,
    }

    if result.get("diagnosis") == "timeout":
        return partial(
            "Commix", target_url, f"Commix reached its configured time budget. Findings preserved: {len(findings)}.",
            diagnosis="time_limit_reached", timed_out=True,
            time_limit_reached=True, duration_seconds=result.get("duration_seconds"),
            stdout=str(result.get("stdout", ""))[-10000:], stderr=str(result.get("stderr", ""))[-10000:],
            command=result.get("command", []), **common,
        )
    if result.get("status") != "success":
        result.update(common)
        return trim_process_output(result, 10000)

    return success(
        "Commix", target_url, f"Commix completed for {method}. Confirmed command-injection findings: {len(findings)}.",
        command_injection_found=bool(findings), duration_seconds=result.get("duration_seconds"),
        command=result.get("command", []), stdout=str(result.get("stdout", ""))[-10000:],
        stderr=str(result.get("stderr", ""))[-10000:], **common,
    )

if __name__ == "__main__":
    _serve()
