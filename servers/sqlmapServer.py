from __future__ import annotations

import re
from typing import Any

from fastmcp import FastMCP

from utils import partial, run_process

mcp = FastMCP("SQLMap Scanner")


def _extract_finding(text: str, target_url: str, method: str) -> list[dict[str, Any]]:
    if not re.search(
        r"(identified the following injection point|parameter.+is vulnerable|appears to be injectable)",
        text,
        re.IGNORECASE,
    ):
        return []
    parameter = re.search(r"Parameter:\s*([^\s(]+)", text, re.IGNORECASE)
    evidence = []
    for label, pattern in (
        ("Type", r"Type:\s*(.+)"),
        ("Title", r"Title:\s*(.+)"),
        ("Payload", r"Payload:\s*(.+)"),
    ):
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            evidence.append(f"{label}: {match.group(1).strip()}")
    return [{
        "alert": "SQL injection",
        "risk": "high",
        "category": "vulnerability",
        "description": f"SQLMap confirmed SQL injection through an HTTP {method} parameter.",
        "impact": "An attacker may read or modify database data and, depending on privileges and DBMS configuration, potentially compromise the underlying server.",
        "solution": "Use parameterized queries, strict server-side type validation, least-privileged database accounts, and generic error handling.",
        "url": target_url,
        "parameter": parameter.group(1) if parameter else "",
        "method": method,
        "confidence": "high",
        "evidence": "\n".join(evidence) or text[-2500:],
    }]


@mcp.tool()
def run_sqlmap_scan(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    timeout: int = 300,
) -> dict:
    """Run a bounded SQLMap scan against a discovered GET or POST request case."""
    method = method.upper()
    command = [
        "sqlmap", "-u", target_url,
        "--batch", "--random-agent",
        "--level=2", "--risk=1", "--smart",
        "--timeout=5", "--retries=1", "--threads=4",
        "--answers=follow=N",
    ]
    if method != "GET":
        command.append(f"--method={method}")
    if data:
        command.extend(["--data", data])
    if parameters:
        command.extend(["-p", ",".join(dict.fromkeys(parameters))])
    if cookies:
        command.extend(["--cookie", cookies])

    result = run_process("SQLMap", command, target=target_url, timeout=timeout)
    text = "\n".join((result.get("stdout", ""), result.get("stderr", ""), result.get("output", "")))
    findings = _extract_finding(text, target_url, method)
    common = {
        "vulnerabilities": findings,
        "request_method": method,
        "request_data_present": bool(data),
        "tested_parameters": parameters or [],
        "authenticated": bool(cookies),
    }
    if result.get("status") == "error" and result.get("diagnosis") == "timeout" and findings:
        return partial(
            "SQLMap", target_url,
            "SQLMap reached its process timeout after confirming an injection point; remaining tests may be incomplete.",
            diagnosis="timeout_with_confirmed_finding", timed_out=True,
            stdout=result.get("stdout", ""), stderr=result.get("stderr", ""),
            command=result.get("command", []), **common,
        )
    if result.get("status") != "success":
        result.update(common)
        return result
    result.update(
        **common,
        sql_injection_found=bool(findings),
        output=f"SQLMap completed for {method}. Confirmed SQL injection findings: {len(findings)}.",
    )
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")