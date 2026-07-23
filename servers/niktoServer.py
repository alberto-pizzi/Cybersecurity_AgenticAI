from __future__ import annotations

import csv
import tempfile
from pathlib import Path
from urllib.parse import urljoin

from fastmcp import FastMCP

from utils import run_process

mcp = FastMCP("Nikto Scanner")

@mcp.tool()
def run_nikto_scan(target_url: str, cookies: str = "", timeout: int = 300) -> dict:
    """Runs Nikto and parses its CSV report instead of treating stdout as findings."""
    with tempfile.TemporaryDirectory(prefix="nikto-") as temporary_directory:
        output_file = Path(temporary_directory) / "nikto.csv"
        command = [
            "nikto", "-h", target_url,
            "-nointeractive",
            "-Format", "csv",
            "-output", str(output_file),
        ]
        if cookies:
            command.extend(["-header", f"Cookie: {cookies}"])

        # Nikto commonly returns 1 when findings exist, so both 0 and 1 are valid.
        result = run_process(
            "Nikto",
            command,
            target=target_url,
            timeout=timeout,
            accepted_codes=(0, 1),
        )
        if result["status"] != "success":
            return result

        findings = []
        if output_file.exists():
            with output_file.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                for row in csv.reader(handle):
                    if len(row) < 7 or row[0].startswith("Nikto"):
                        continue
                    # Nikto CSV fields are host, IP, port, reference/id, method, URI, message.
                    uri = row[5].strip() if len(row) > 5 else ""
                    finding_url = uri if uri.startswith(("http://", "https://")) else urljoin(target_url, uri)
                    findings.append({
                        "alert": "Nikto web-server finding",
                        "risk": "info",
                        "description": row[6],
                        "url": finding_url or target_url,
                        "method": row[4] if len(row) > 4 else "",
                        "reference": row[3] if len(row) > 3 else "",
                    })

        result["vulnerabilities"] = findings
        result["output"] = f"Nikto completed. Findings: {len(findings)}"
        return result


if __name__ == "__main__":
    mcp.run(transport="stdio")