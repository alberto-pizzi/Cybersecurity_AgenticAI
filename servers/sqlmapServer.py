from __future__ import annotations

import re

from fastmcp import FastMCP

from utils import run_process

mcp = FastMCP("SQLMap Scanner")


@mcp.tool()
def run_sqlmap_scan(target_url: str, cookies: str = "", timeout: int = 300) -> dict:
    """Runs SQLMap non-interactively on a URL that contains query parameters."""
    command = [
        "sqlmap", "-u", target_url,
        "--batch", "--random-agent",
        "--level=2", "--risk=1",
        "--flush-session",
        "--smart",
    ]
    if cookies:
        command.extend(["--cookie", cookies])

    result = run_process("SQLMap", command, target=target_url, timeout=timeout)
    if result["status"] != "success":
        return result

    text = result.get("output", "")
    found = bool(re.search(
        r"(identified the following injection point|parameter.+is vulnerable|appears to be injectable)",
        text,
        re.IGNORECASE,
    ))
    findings = []
    if found:
        parameter = re.search(r"Parameter:\s*([^\s(]+)", text, re.IGNORECASE)
        findings.append({
            "alert": "SQL injection",
            "risk": "high",
            "description": "SQLMap confirmed an injectable HTTP parameter.",
            "solution": "Use parameterized queries and strict server-side validation.",
            "url": target_url,
            "parameter": parameter.group(1) if parameter else "",
        })

    result["sql_injection_found"] = found
    result["vulnerabilities"] = findings
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")