from __future__ import annotations

import re
from typing import Any

from fastmcp import FastMCP

from utils import partial, run_process

mcp = FastMCP("Dalfox Scanner")


def _findings(text: str, target_url: str, method: str) -> list[dict[str, Any]]:
    evidence_lines = [line.strip() for line in text.splitlines() if re.search(r"\[V\]|\[POC\]|verified", line, re.I)]
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


@mcp.tool()
def run_dalfox_scan(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    timeout: int = 180,
) -> dict:
    """Scan a discovered GET or POST request for verified XSS evidence."""
    method = method.upper()
    command = ["dalfox", "url", target_url, "--silence", "--skip-bav"]
    if method != "GET":
        command.extend(["--method", method])
    if data:
        command.extend(["--data", data])
    if parameters:
        for parameter in dict.fromkeys(parameters):
            command.extend(["--param", parameter])
    if cookies:
        command.extend(["--cookie", cookies])

    result = run_process("Dalfox", command, target=target_url, timeout=timeout, accepted_codes=(0, 1))
    text = "\n".join((result.get("stdout", ""), result.get("stderr", ""), result.get("output", "")))
    findings = _findings(text, target_url, method)
    common = {
        "vulnerabilities": findings,
        "request_method": method,
        "request_data_present": bool(data),
        "tested_parameters": parameters or [],
    }
    if result.get("status") == "error" and result.get("diagnosis") == "timeout" and findings:
        return partial(
            "Dalfox", target_url,
            "Dalfox timed out after producing verified XSS evidence; remaining parameters may be incomplete.",
            diagnosis="timeout_with_confirmed_finding", **common,
        )
    if result.get("status") != "success":
        result.update(common)
        return result
    result.update(**common, xss_found=bool(findings), output=f"Dalfox completed for {method}. Verified XSS findings: {len(findings)}.")
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")