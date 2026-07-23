from __future__ import annotations

import re

from fastmcp import FastMCP

from utils import run_process

mcp = FastMCP("Dalfox Scanner")


@mcp.tool()
def run_dalfox_scan(target_url: str, cookies: str = "", timeout: int = 180) -> dict:
    """Runs Dalfox on a parameterized URL and only reports actual scanner evidence."""
    command = ["dalfox", "url", target_url, "--silence", "--skip-bav"]
    if cookies:
        command.extend(["--cookie", cookies])

    result = run_process(
        "Dalfox",
        command,
        target=target_url,
        timeout=timeout,
        accepted_codes=(0, 1),
    )
    if result["status"] != "success":
        return result

    text = result.get("output", "")
    found = bool(re.search(r"(\[V\]|\[POC\]|verified)", text, re.IGNORECASE))
    findings = []
    if found:
        findings.append({
            "alert": "Cross-site scripting",
            "risk": "high",
            "description": "Dalfox returned a verified or reproducible XSS vector.",
            "solution": "Use contextual output encoding and strict input validation.",
            "url": target_url,
            "evidence": text[:2000],
        })

    result["xss_found"] = found
    result["vulnerabilities"] = findings
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")