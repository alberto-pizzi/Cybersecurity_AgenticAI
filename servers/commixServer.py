from __future__ import annotations

import re
from typing import Any

from fastmcp import FastMCP

from utils import partial, run_process

mcp = FastMCP("Commix Scanner")


def _findings(text: str, target_url: str, method: str) -> list[dict[str, Any]]:
    if not re.search(r"(parameter.+is vulnerable|injectable parameter|command injection vulnerability)", text, re.I):
        return []
    evidence = [line.strip() for line in text.splitlines() if re.search(r"vulnerable|injectable|payload", line, re.I)]
    return [{
        "alert": "OS command injection",
        "risk": "critical",
        "category": "vulnerability",
        "description": f"Commix reported that an HTTP {method} parameter can inject operating-system commands.",
        "impact": "A successful attacker may execute commands with the web application's operating-system privileges and compromise the host.",
        "solution": "Avoid shell execution, use safe APIs, enforce strict allow-list validation, and run the service with minimal privileges.",
        "url": target_url,
        "method": method,
        "confidence": "high",
        "evidence": "\n".join(evidence[:30]) or text[-2500:],
    }]


@mcp.tool()
def run_commix_scan(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    timeout: int = 240,
) -> dict:
    """Run Commix non-interactively against a discovered GET or POST request case."""
    method = method.upper()
    command = ["commix", "--url", target_url, "--batch", "--level", "1"]
    if data:
        command.extend(["--data", data])
    if parameters:
        command.extend(["-p", ",".join(dict.fromkeys(parameters))])
    if cookies:
        command.extend(["--cookie", cookies])

    result = run_process("Commix", command, target=target_url, timeout=timeout, accepted_codes=(0, 1))
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
            "Commix", target_url,
            "Commix timed out after reporting command-injection evidence; remaining tests may be incomplete.",
            diagnosis="timeout_with_confirmed_finding", **common,
        )
    if result.get("status") != "success":
        result.update(common)
        return result
    result.update(**common, command_injection_found=bool(findings), output=f"Commix completed for {method}. Confirmed command-injection findings: {len(findings)}.")
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")