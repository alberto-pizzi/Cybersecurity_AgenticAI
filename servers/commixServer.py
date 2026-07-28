from __future__ import annotations

import argparse
import json
import html
import os
import re
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
from typing import Any

from fastmcp import FastMCP

from utils import ROOT_DIR, failure, partial, run_process, scanner_session_probe, success

mcp = FastMCP("Commix Scanner")


def _find_commix_script() -> Path | None:
    candidates = [
        Path.home() / ".local" / "opt" / "commix" / "commix.py",
        Path(ROOT_DIR) / "tools" / "commix" / "commix.py",
    ]
    launcher = Path.home() / ".local" / "bin" / "commix.bat"
    if launcher.is_file():
        text = launcher.read_text(encoding="utf-8", errors="replace")
        match = re.search(r'"([^"\r\n]*commix\.py)"|([A-Za-z]:\\[^\r\n]*?commix\.py)', text, re.I)
        if match:
            candidates.insert(0, Path(match.group(1) or match.group(2)))
    for path in candidates:
        if path.is_file():
            return path.resolve()
    return None


def _findings(text: str, target_url: str, method: str) -> list[dict[str, Any]]:
    if not re.search(r"(parameter.+is vulnerable|injectable parameter|command injection vulnerability)", text, re.I):
        return []
    parameter_match = re.search(
        r"(?:parameter|parameter\s*['\"])(?:\s*[:=]\s*)?['\"]?([A-Za-z0-9_.-]+)['\"]?.{0,80}?(?:vulnerable|injectable)",
        text,
        re.I,
    )
    if not parameter_match:
        parameter_match = re.search(r"(?:GET|POST) parameter ['\"]([^'\"]+)['\"]", text, re.I)
    parameter = parameter_match.group(1) if parameter_match else ""
    payloads = [value.strip() for value in re.findall(r"(?:payload|Payload)\s*[:=]\s*(.+)", text)]
    technique_lines = [
        line.strip() for line in text.splitlines()
        if re.search(r"technique|vulnerable|injectable|payload", line, re.I)
    ]
    return [{
        "alert": (f"OS command injection in parameter '{parameter}'" if parameter else "OS command injection"),
        "risk": "critical",
        "category": "vulnerability",
        "verification_status": "scanner-confirmed-command-injection",
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
        "url": target_url,
        "method": method,
        "parameter": parameter,
        "payloads": payloads[:10],
        "confidence": "high",
        "technical_details": f"Commix positive marker; parameter={parameter or 'not extracted'}; method={method}.",
        "evidence": "\n".join(technique_lines[:40]) or text[-5000:],
    }]



CONTROL_PARAMETERS = {"submit", "login", "change", "user_token", "csrf", "button"}
COMMAND_PARAMETERS = {"ip", "host", "hostname", "cmd", "command", "exec", "target", "domain"}


def _response_excerpt(text: str, marker: str, limit: int = 900) -> str:
    value = str(text or "")
    index = value.find(marker)
    if index < 0:
        return value[:limit]
    start = max(0, index - limit // 3)
    return value[start:start + limit]


def _command_canary(
    target_url: str,
    cookies: str,
    method: str,
    data: str,
    parameters: list[str],
    timeout: int = 25,
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
    marker = f"SECOPS_CMD_{uuid.uuid4().hex[:10].upper()}"
    # Try the cross-platform ampersand form first.  On Unix it backgrounds the
    # preceding ping and returns the marker immediately; on Windows cmd.exe it
    # is a command separator.  The previous order tried several potentially
    # slow ping variants before this one and could exhaust the canary budget.
    suffixes = (
        f" & echo {marker}",
        f" | echo {marker}",
        f"; printf '{marker}'; #",
        f"; echo {marker}; #",
        f" && echo {marker}",
    )
    headers = {
        "Cache-Control": "no-cache",
        "User-Agent": "SecOps-Command-Injection-Verifier/3.0",
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
        if method == "GET":
            parsed = urlparse(target_url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            changed: list[tuple[str, str]] = []
            replaced = False
            for name, current in pairs:
                if not replaced and name.lower() == parameter.lower():
                    changed.append((name, value)); replaced = True
                else:
                    changed.append((name, current))
            if not replaced:
                changed.append((parameter, value))
            return urlunparse(parsed._replace(query=urlencode(changed))), ""
        pairs = parse_qsl(data, keep_blank_values=True)
        changed = []
        replaced = False
        for name, current in pairs:
            if not replaced and name.lower() == parameter.lower():
                changed.append((name, value)); replaced = True
            else:
                changed.append((name, current))
        if not replaced:
            changed.append((parameter, value))
        return target_url, urlencode(changed)

    def send(value: str) -> requests.Response:
        request_url, request_data = mutate(value)
        remaining = max(3.0, deadline - time.monotonic())
        return requests.request(
            method,
            request_url,
            data=request_data if method != "GET" else None,
            headers=headers,
            timeout=(3, min(10.0, remaining)),
            allow_redirects=True,
        )

    baseline: dict[str, Any] = {}
    try:
        response = send(base_value)
        baseline = {
            "status": response.status_code,
            "final_url": str(response.url),
            "response_bytes": len(response.content),
            "marker_absent": marker not in html.unescape(response.text),
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
        confirmed = bool(baseline.get("marker_absent", True)) and marker in decoded_body
        attempt = {
            "payload_suffix": command_suffix,
            "status": response.status_code,
            "final_url": str(response.url),
            "request_url": request_url,
            "request_data": request_data,
            "response_bytes": len(response.content),
            "confirmed": confirmed,
            "response_excerpt": _response_excerpt(response.text, marker),
        }
        attempts.append(attempt)
        if confirmed:
            return {
                "performed": True,
                "confirmed": True,
                "parameter": parameter,
                "marker": marker,
                "payload_suffix": command_suffix,
                "base_value": base_value,
                "baseline": baseline,
                "attempts": attempts,
                **attempt,
            }
    return {
        "performed": True,
        "confirmed": False,
        "parameter": parameter,
        "marker": marker,
        "base_value": base_value,
        "baseline": baseline,
        "attempts": attempts,
        "canary_budget_seconds": max(8, min(int(timeout), 35)),
    }


def _canary_finding(
    target_url: str,
    method: str,
    canary: dict[str, Any],
) -> list[dict[str, Any]]:
    if not canary.get("confirmed"):
        return []
    parameter = str(canary.get("parameter") or "")
    return [{
        "alert": f"OS command injection in parameter '{parameter}'",
        "risk": "critical",
        "category": "vulnerability",
        "verification_status": "unique-response-marker-command-execution-confirmed",
        "confidence": "high",
        "description": "A benign shell output command appended to the selected input produced a unique server-side marker in the HTTP response. The marker was not present in the original input value and therefore confirms operating-system command execution.",
        "attack_preconditions": "An attacker must be able to submit the affected parameter to the command-execution handler.",
        "impact": "The attacker can execute operating-system commands with the web-server account's privileges, read accessible files and secrets, modify application data, and potentially pivot to other services reachable from the container or host.",
        "solution": "Remove shell command construction from untrusted input. Use a dedicated networking or process API, enforce a strict allow-list, avoid invoking a shell, and run the service under a minimally privileged account.",
        "url": target_url,
        "method": method,
        "parameter": parameter,
        "payload": canary.get("payload_suffix"),
        "cwe_id": "78",
        "owasp_category": "A03:2021 Injection",
        "technical_details": (
            f"HTTP {canary.get('status')}; marker={canary.get('marker')}; "
            f"response bytes={canary.get('response_bytes')}."
        ),
        "reproduction": (
            f"1. Send the {method} request to {target_url}.\n"
            f"2. Append '{canary.get('payload_suffix')}' to parameter '{parameter}'.\n"
            f"3. Confirm that the response contains the unique marker '{canary.get('marker')}'."
        ),
        "evidence": (
            f"Request URL: {canary.get('request_url')}\n"
            f"Request data: {canary.get('request_data')}\n"
            f"Response excerpt:\n{canary.get('response_excerpt')}"
        ),
    }]

def _trim(result: dict[str, Any], limit: int = 10000) -> dict[str, Any]:
    for key in ("stdout", "stderr"):
        value = str(result.get(key, ""))
        if len(value) > limit:
            result[key] = value[-limit:]
            result[f"{key}_truncated"] = True
    return result


@mcp.tool()
def run_commix_scan(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    timeout: int = 150,
) -> dict:
    """Run Commix directly through Python and preserve bounded results."""
    method = method.upper()
    timeout = max(45, min(int(timeout), 600))
    parameters = [value for value in dict.fromkeys(str(v) for v in (parameters or []) if str(v)) if value.lower() not in CONTROL_PARAMETERS]
    session_probe = scanner_session_probe(target_url, cookies, method, data)
    if cookies and session_probe.get("performed") and session_probe.get("conclusive") and session_probe.get("authenticated") is False:
        return partial("Commix", target_url, "Commix was not started because the authenticated request redirected to a login page.", diagnosis="authentication_precheck_failed", timed_out=False, vulnerabilities=[], session_probe=session_probe)
    started = time.monotonic()
    canary = _command_canary(
        target_url, cookies, method, data, parameters,
        timeout=max(8, min(35, timeout // 2)),
    )
    canary_findings = _canary_finding(target_url, method, canary)
    if canary_findings:
        return success("Commix", target_url, "A bounded response-marker canary confirmed command execution; the slower Commix phase was not required.", vulnerabilities=canary_findings, command_injection_found=True, request_method=method, tested_parameters=parameters, authenticated=bool(cookies), session_probe=session_probe, command_canary=canary, execution_mode="direct_canary")
    script = _find_commix_script()
    if script is None:
        return failure(
            "Commix", target_url,
            "commix.py was not found under ~/.local/opt/commix. Run initScript.py again.",
            diagnosis="missing_commix_script",
        )

    elapsed_canary = max(0, int(time.monotonic() - started))
    remaining_budget = max(10, timeout - elapsed_canary - 3)
    if remaining_budget < 20:
        return partial(
            "Commix", target_url,
            "The bounded response-marker check was inconclusive and consumed the available scanner budget; the slower Commix phase was not started.",
            diagnosis="bounded_canary_inconclusive",
            timed_out=False, vulnerabilities=[], request_method=method,
            tested_parameters=parameters, authenticated=bool(cookies),
            session_probe=session_probe, command_canary=canary,
            execution_mode="direct_canary_only",
        )

    command = [
        sys.executable, str(script),
        "--url", target_url,
        "--batch", "--level", "1",
        "--timeout", "5", "--retries", "0", "--drop-set-cookie",
        "--time-limit", str(max(15, remaining_budget - 5)),
    ]
    if data:
        command.extend(["--data", data])
    if parameters:
        command.extend(["-p", ",".join(dict.fromkeys(parameters))])
    if cookies:
        command.extend(["--cookie", cookies])

    result = run_process(
        "Commix",
        command,
        target=target_url,
        timeout=remaining_budget,
        accepted_codes=(0, 1),
        cwd=script.parent,
    )
    text = "\n".join(str(result.get(key, "")) for key in ("stdout", "stderr", "output"))
    findings = _findings(text, target_url, method)
    common = {
        "vulnerabilities": findings,
        "request_method": method,
        "request_data_present": bool(data),
        "tested_parameters": parameters,
        "authenticated": bool(cookies),
        "execution_mode": "direct_python",
        "commix_script": str(script),
        "session_probe": session_probe,
        "command_canary": canary,
    }

    if result.get("diagnosis") == "timeout":
        return partial(
            "Commix", target_url,
            f"Commix reached its configured time budget. Findings preserved: {len(findings)}.",
            diagnosis="time_limit_reached",
            timed_out=True,
            time_limit_reached=True,
            duration_seconds=result.get("duration_seconds"),
            stdout=str(result.get("stdout", ""))[-10000:],
            stderr=str(result.get("stderr", ""))[-10000:],
            command=result.get("command", []),
            **common,
        )
    if result.get("status") != "success":
        result.update(common)
        return _trim(result)

    return success(
        "Commix", target_url,
        f"Commix completed for {method}. Confirmed command-injection findings: {len(findings)}.",
        command_injection_found=bool(findings),
        duration_seconds=result.get("duration_seconds"),
        command=result.get("command", []),
        stdout=str(result.get("stdout", ""))[-10000:],
        stderr=str(result.get("stderr", ""))[-10000:],
        **common,
    )


def _once() -> int:
    try:
        arguments = json.loads(os.sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = run_commix_scan(**arguments)
    except Exception as exc:
        result = failure("Commix", "", f"One-shot Commix execution failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio")