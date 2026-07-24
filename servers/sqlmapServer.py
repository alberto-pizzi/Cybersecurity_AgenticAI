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

mcp = FastMCP("SQLMap Scanner")


def _find_sqlmap_script() -> Path | None:
    candidates = [
        Path.home() / ".local" / "opt" / "sqlmap" / "sqlmap.py",
        Path(ROOT_DIR) / "tools" / "sqlmap" / "sqlmap.py",
    ]
    launcher = Path.home() / ".local" / "bin" / "sqlmap.bat"
    if launcher.is_file():
        text = launcher.read_text(encoding="utf-8", errors="replace")
        match = re.search(r'"([^"\r\n]*sqlmap\.py)"|([A-Za-z]:\\[^\r\n]*?sqlmap\.py)', text, re.I)
        if match:
            candidates.insert(0, Path(match.group(1) or match.group(2)))
    for path in candidates:
        if path.is_file():
            return path.resolve()
    return None


def _extract_findings(text: str, target_url: str, method: str) -> list[dict[str, Any]]:
    if not re.search(
        r"(identified the following injection point|parameter.+is vulnerable|appears to be injectable)",
        text,
        re.IGNORECASE,
    ):
        return []
    blocks = re.split(r"(?=Parameter:\s*)", text, flags=re.I)
    findings: list[dict[str, Any]] = []
    for block in blocks:
        if not re.search(r"Parameter:\s*", block, re.I):
            continue
        parameter = re.search(r"Parameter:\s*([^\s(]+)", block, re.I)
        evidence = []
        for label, pattern in (
            ("Type", r"Type:\s*(.+)"),
            ("Title", r"Title:\s*(.+)"),
            ("Payload", r"Payload:\s*(.+)"),
        ):
            match = re.search(pattern, block, re.I)
            if match:
                evidence.append(f"{label}: {match.group(1).strip()}")
        findings.append({
            "alert": "SQL injection",
            "risk": "high",
            "category": "vulnerability",
            "description": f"SQLMap confirmed SQL injection through an HTTP {method} parameter.",
            "impact": "An attacker may read or modify database data and, depending on database privileges, potentially compromise the server.",
            "solution": "Use parameterized queries, strict server-side validation, least-privileged database accounts, and generic error handling.",
            "url": target_url,
            "parameter": parameter.group(1) if parameter else "",
            "method": method,
            "confidence": "high",
            "evidence": "\n".join(evidence) or block[-2500:],
        })
    return findings or [{
        "alert": "SQL injection",
        "risk": "high",
        "category": "vulnerability",
        "description": f"SQLMap confirmed SQL injection through an HTTP {method} parameter.",
        "impact": "An attacker may access or modify database data.",
        "solution": "Use parameterized queries and strict validation.",
        "url": target_url,
        "method": method,
        "confidence": "high",
        "evidence": text[-2500:],
    }]


def _trim(result: dict[str, Any], limit: int = 12000) -> dict[str, Any]:
    for key in ("stdout", "stderr"):
        value = str(result.get(key, ""))
        if len(value) > limit:
            result[key] = value[-limit:]
            result[f"{key}_truncated"] = True
    return result


@mcp.tool()
def run_sqlmap_scan(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    timeout: int = 180,
) -> dict:
    """Run SQLMap directly through Python instead of the Windows batch launcher."""
    method = method.upper()
    timeout = max(45, min(int(timeout), 600))
    parameters = [str(value) for value in (parameters or []) if str(value)]
    script = _find_sqlmap_script()
    if script is None:
        return failure(
            "SQLMap", target_url,
            "sqlmap.py was not found under ~/.local/opt/sqlmap. Run initScript.py again.",
            diagnosis="missing_sqlmap_script",
        )

    command = [
        sys.executable, str(script), "-u", target_url,
        "--batch", "--random-agent",
        "--level=2", "--risk=1", "--technique=BEU", "--time-sec=2",
        "--timeout=5", "--retries=0", "--threads=4",
        "--answers=follow=N", "--flush-session",
    ]
    if method != "GET":
        command.append(f"--method={method}")
    if data:
        command.extend(["--data", data])
    if parameters:
        command.extend(["-p", ",".join(dict.fromkeys(parameters))])
    if cookies:
        command.extend(["--cookie", cookies])

    result = run_process(
        "SQLMap",
        command,
        target=target_url,
        timeout=timeout,
        cwd=script.parent,
    )
    text = "\n".join(str(result.get(key, "")) for key in ("stdout", "stderr", "output"))
    findings = _extract_findings(text, target_url, method)
    common = {
        "vulnerabilities": findings,
        "request_method": method,
        "request_data_present": bool(data),
        "tested_parameters": parameters,
        "authenticated": bool(cookies),
        "execution_mode": "direct_python",
        "sqlmap_script": str(script),
    }

    if result.get("diagnosis") == "timeout":
        return partial(
            "SQLMap", target_url,
            f"SQLMap reached its configured time budget. Confirmed findings preserved: {len(findings)}.",
            diagnosis="time_limit_reached",
            timed_out=True,
            time_limit_reached=True,
            duration_seconds=result.get("duration_seconds"),
            stdout=str(result.get("stdout", ""))[-12000:],
            stderr=str(result.get("stderr", ""))[-12000:],
            command=result.get("command", []),
            **common,
        )
    if result.get("status") != "success":
        result.update(common)
        return _trim(result)

    return success(
        "SQLMap", target_url,
        f"SQLMap completed for {method}. Confirmed SQL injection findings: {len(findings)}.",
        sql_injection_found=bool(findings),
        duration_seconds=result.get("duration_seconds"),
        command=result.get("command", []),
        stdout=str(result.get("stdout", ""))[-12000:],
        stderr=str(result.get("stderr", ""))[-12000:],
        **common,
    )


def _once() -> int:
    try:
        arguments = json.loads(os.sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = run_sqlmap_scan(**arguments)
    except Exception as exc:
        result = failure("SQLMap", "", f"One-shot SQLMap execution failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio")