from __future__ import annotations

import re

from fastmcp import FastMCP

from utils import run_process

mcp = FastMCP("Commix Scanner")


@mcp.tool()
def run_commix_scan(target_url: str, cookies: str = "", timeout: int = 300) -> dict:
    """Runs Commix non-interactively on a URL with testable parameters."""
    command = ["commix", "--url", target_url, "--batch", "--level", "1"]
    if cookies:
        command.extend(["--cookie", cookies])

    result = run_process(
        "Commix",
        command,
        target=target_url,
        timeout=timeout,
        accepted_codes=(0, 1),
    )
    if result["status"] != "success":
        return result

    text = result.get("output", "")
    found = bool(re.search(
        r"(parameter.+is vulnerable|injectable parameter|command injection vulnerability)",
        text,
        re.IGNORECASE,
    ))
    findings = []
    if found:
        findings.append({
            "alert": "OS command injection",
            "risk": "critical",
            "description": "Commix reported an injectable command parameter.",
            "solution": "Avoid shell execution and enforce strict allow-list validation.",
            "url": target_url,
            "evidence": text[:2000],
        })

    result["command_injection_found"] = found
    result["vulnerabilities"] = findings
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")