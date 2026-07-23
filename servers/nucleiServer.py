from __future__ import annotations

from fastmcp import FastMCP

from utils import read_json_lines, run_process

mcp = FastMCP("Nuclei Scanner")


@mcp.tool()
def run_nuclei_scan(target_url: str, cookies: str = "", timeout: int = 240) -> dict:
    """Runs Nuclei and converts its JSONL output into the shared finding format."""
    command = [
        "nuclei", "-u", target_url,
        "-severity", "info,low,medium,high,critical",
        "-jsonl", "-silent",
        "-disable-update-check",
    ]
    if cookies:
        command.extend(["-H", f"Cookie: {cookies}"])

    result = run_process("Nuclei", command, target=target_url, timeout=timeout)
    if result["status"] != "success":
        return result

    findings = []
    for item in read_json_lines(result.get("stdout", "")):
        info = item.get("info") or {}
        findings.append({
            "alert": info.get("name", item.get("template-id", "Nuclei finding")),
            "risk": str(info.get("severity", "info")).lower(),
            "description": info.get("description", ""),
            "solution": info.get("remediation", ""),
            "url": item.get("matched-at", item.get("host", target_url)),
            "template_id": item.get("template-id", ""),
        })

    result["vulnerabilities"] = findings
    result["output"] = f"Nuclei completed. Findings: {len(findings)}"
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")