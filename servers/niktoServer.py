from __future__ import annotations

import csv
import re
import tempfile
from pathlib import Path
from urllib.parse import urljoin

from fastmcp import FastMCP

from utils import failure, run_process

mcp = FastMCP("Nikto Scanner")


def _severity(message: str) -> str:
    lowered = message.lower()
    if any(word in lowered for word in ("remote code", "command execution", "sql injection", "file inclusion")):
        return "high"
    if any(word in lowered for word in ("outdated", "vulnerable", "directory indexing", "default credentials", "backup", "admin")):
        return "medium"
    if any(word in lowered for word in ("missing", "header", "cookie", "disclosure", "allowed methods")):
        return "low"
    return "info"


@mcp.tool()
def run_nikto_scan(target_url: str, cookies: str = "", timeout: int = 300) -> dict:
    """Run Nikto and reject launcher/dependency failures even when the wrapper exits with code 1."""
    with tempfile.TemporaryDirectory(prefix="nikto-") as temporary_directory:
        output_file = Path(temporary_directory) / "nikto.csv"
        command = ["nikto", "-h", target_url, "-nointeractive", "-Format", "csv", "-output", str(output_file)]
        if cookies:
            command.extend(["-header", f"Cookie: {cookies}"])
        result = run_process("Nikto", command, target=target_url, timeout=timeout, accepted_codes=(0, 1))
        if result.get("status") != "success":
            return result
        combined = "\n".join((result.get("stdout", ""), result.get("stderr", "")))
        if re.search(r"perl.*(?:not recognized|non .? riconosciuto|not found|can't open)", combined, re.I):
            return failure(
                "Nikto", target_url,
                "Nikto could not start because Perl or the Nikto Perl script is unavailable.",
                return_code=result.get("return_code"), stdout=result.get("stdout", ""), stderr=result.get("stderr", ""),
                diagnosis="nikto_perl_unavailable",
            )

        findings = []
        if output_file.exists():
            with output_file.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                for row in csv.reader(handle):
                    if len(row) < 7 or row[0].startswith("Nikto"):
                        continue
                    message = row[6].strip()
                    uri = row[5].strip()
                    findings.append({
                        "alert": "Nikto web-server finding",
                        "risk": _severity(message),
                        "category": "vulnerability" if _severity(message) != "info" else "observation",
                        "description": message,
                        "impact": "The identified server configuration or exposed resource may weaken the security posture and should be manually validated.",
                        "solution": "Apply the relevant server hardening guidance, remove unnecessary resources, and update affected software.",
                        "url": uri if uri.startswith(("http://", "https://")) else urljoin(target_url, uri),
                        "method": row[4].strip(),
                        "reference": row[3].strip(),
                        "confidence": "medium",
                        "evidence": f"Nikto reference={row[3].strip()}; method={row[4].strip()}; message={message}",
                    })
        result.update(vulnerabilities=findings, output=f"Nikto completed. Findings: {len(findings)}.", authenticated=bool(cookies))
        return result


if __name__ == "__main__":
    mcp.run(transport="stdio")