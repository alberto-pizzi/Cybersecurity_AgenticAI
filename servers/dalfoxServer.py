from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from utils import failure, partial, read_json_lines, run_process, success

mcp = FastMCP("Dalfox Scanner")


def _text_findings(text: str, target_url: str, method: str) -> list[dict[str, Any]]:
    evidence_lines = [
        line.strip()
        for line in text.splitlines()
        if re.search(r"\[V\]|\[POC\]|verified", line, re.I)
    ]
    if not evidence_lines:
        return []
    return [{
        "alert": "Cross-site scripting",
        "risk": "high",
        "category": "vulnerability",
        "description": f"Dalfox returned a verified or reproducible XSS vector in an HTTP {method} parameter.",
        "impact": "A successful payload can execute JavaScript in a victim's browser, enabling session theft, unauthorized actions, or content manipulation.",
        "solution": "Apply contextual output encoding, strict input validation, safe DOM APIs, and an effective Content Security Policy.",
        "url": target_url,
        "method": method,
        "confidence": "high",
        "evidence": "\n".join(evidence_lines[:20]),
    }]


def _json_findings(path: Path, target_url: str, method: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    findings: list[dict[str, Any]] = []
    for item in read_json_lines(path.read_text(encoding="utf-8", errors="replace")):
        finding_type = str(item.get("type", "")).upper()
        if finding_type not in {"V", "A", "R"}:
            continue
        severity = str(item.get("severity", "high" if finding_type == "V" else "medium")).lower()
        category = "vulnerability" if finding_type == "V" else "candidate"
        findings.append({
            "alert": str(item.get("type_description") or "Cross-site scripting"),
            "risk": severity,
            "category": category,
            "description": (
                "Dalfox verified an executable XSS vector."
                if finding_type == "V"
                else "Dalfox identified an XSS reflection or AST candidate requiring confirmation."
            ),
            "impact": "Successful XSS can execute attacker-controlled JavaScript in a victim browser session.",
            "solution": "Use context-aware output encoding, strict server-side validation, safe DOM APIs, and Content Security Policy.",
            "url": str(item.get("data") or target_url),
            "method": str(item.get("method") or method),
            "parameter": str(item.get("param") or ""),
            "confidence": "high" if finding_type == "V" else "medium",
            "inject_type": str(item.get("inject_type") or ""),
            "payload": str(item.get("payload") or "")[:1500],
            "evidence": str(item.get("evidence") or item)[:2500],
            "cwe": str(item.get("cwe") or ""),
        })
    return findings


def _looks_like_v3_cli_error(result: dict[str, Any]) -> bool:
    text = "\n".join(str(result.get(key, "")) for key in ("stdout", "stderr", "output")).lower()
    return int(result.get("return_code") or 0) == 2 and any(token in text for token in (
        "unexpected argument", "unrecognized", "unknown command", "found argument 'url'",
        "invalid value", "usage:",
    ))


def _trim(result: dict[str, Any]) -> dict[str, Any]:
    for key, limit in (("stdout", 8000), ("stderr", 8000)):
        value = str(result.get(key, ""))
        if len(value) > limit:
            result[key] = value[-limit:]
            result[f"{key}_truncated"] = True
    return result


def _run_v3(
    target_url: str,
    cookies: str,
    method: str,
    data: str,
    parameters: list[str],
    timeout: int,
    output_file: Path,
) -> dict[str, Any]:
    scan_timeout = max(20, timeout - 15)
    command = [
        "dalfox", "scan", target_url,
        "--format", "jsonl",
        "--output", str(output_file),
        "--no-color", "--silence",
        "--skip-mining",
        "--workers", "10",
        "--max-payloads-per-param", "40",
        "--timeout", "5",
        "--scan-timeout", str(scan_timeout),
    ]
    location = "query" if method == "GET" else "body"
    for parameter in dict.fromkeys(parameters):
        command.extend(["-p", f"{parameter}:{location}"])
    if method != "GET":
        command.extend(["-X", method])
    if data:
        command.extend(["-d", data])
    if cookies:
        command.extend(["--cookies", cookies])
    result = run_process("Dalfox", command, target=target_url, timeout=timeout, accepted_codes=(0, 1))
    result["dalfox_cli_generation"] = "v3"
    return _trim(result)


def _run_v2(
    target_url: str,
    cookies: str,
    method: str,
    data: str,
    parameters: list[str],
    timeout: int,
) -> dict[str, Any]:
    command = [
        "dalfox", "url", target_url,
        "--silence", "--skip-bav",
        "--worker", "10",
        "--timeout", "5",
    ]
    if method != "GET":
        command.extend(["--method", method])
    if data:
        command.extend(["--data", data])
    for parameter in dict.fromkeys(parameters):
        command.extend(["-p", parameter])
    if cookies:
        command.extend(["--cookie", cookies])
    result = run_process("Dalfox", command, target=target_url, timeout=timeout, accepted_codes=(0, 1))
    result["dalfox_cli_generation"] = "v2"
    return _trim(result)


@mcp.tool()
def run_dalfox_scan(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    timeout: int = 120,
) -> dict:
    """Run a bounded Dalfox scan with automatic v3/v2 CLI compatibility."""
    method = method.upper()
    timeout = max(30, min(int(timeout), 300))
    parameters = [str(value) for value in (parameters or []) if str(value)]
    common = {
        "request_method": method,
        "request_data_present": bool(data),
        "tested_parameters": parameters,
        "authenticated": bool(cookies),
    }

    with tempfile.TemporaryDirectory(prefix="dalfox-") as temporary_directory:
        output_file = Path(temporary_directory) / "dalfox.jsonl"
        result = _run_v3(target_url, cookies, method, data, parameters, timeout, output_file)
        if _looks_like_v3_cli_error(result):
            output_file.unlink(missing_ok=True)
            previous = {
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "return_code": result.get("return_code"),
            }
            result = _run_v2(target_url, cookies, method, data, parameters, timeout)
            result["compatibility_retry"] = previous

        text = "\n".join(str(result.get(key, "")) for key in ("stdout", "stderr", "output"))
        findings = (
            _json_findings(output_file, target_url, method)
            if result.get("dalfox_cli_generation") == "v3"
            else _text_findings(text, target_url, method)
        )
        common["vulnerabilities"] = findings
        common["dalfox_cli_generation"] = result.get("dalfox_cli_generation", "unknown")

        if result.get("diagnosis") == "timeout":
            return partial(
                "Dalfox", target_url,
                f"Dalfox reached its configured time budget. Findings preserved: {len(findings)}.",
                diagnosis="time_limit_reached",
                timed_out=True,
                time_limit_reached=True,
                duration_seconds=result.get("duration_seconds"),
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                command=result.get("command", []),
                **common,
            )
        if result.get("status") != "success":
            result.update(common)
            if int(result.get("return_code") or 0) == 2:
                result["diagnosis"] = "dalfox_cli_or_runtime_error"
                result["output"] = (
                    "Dalfox rejected the command or encountered a runtime/configuration error. "
                    f"CLI generation attempted: {common['dalfox_cli_generation']}. "
                    f"Details: {text[-2000:]}"
                )
            return result

        return success(
            "Dalfox", target_url,
            f"Dalfox completed for {method}. Findings: {len(findings)}.",
            xss_found=any(item.get("category") == "vulnerability" for item in findings),
            duration_seconds=result.get("duration_seconds"),
            command=result.get("command", []),
            **common,
        )


def _once() -> int:
    try:
        arguments = json.loads(os.sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = run_dalfox_scan(**arguments)
    except Exception as exc:
        result = failure("Dalfox", "", f"One-shot Dalfox execution failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio")