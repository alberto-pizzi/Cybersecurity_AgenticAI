from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from utils import ROOT_DIR, failure, partial, run_process, success

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
    parameters = [str(value) for value in (parameters or []) if str(value)]
    script = _find_commix_script()
    if script is None:
        return failure(
            "Commix", target_url,
            "commix.py was not found under ~/.local/opt/commix. Run initScript.py again.",
            diagnosis="missing_commix_script",
        )

    command = [
        sys.executable, str(script),
        "--url", target_url,
        "--batch", "--level", "1",
        "--timeout", "5", "--retries", "0", "--drop-set-cookie",
        "--time-limit", str(max(30, timeout - 15)),
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
        timeout=timeout,
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