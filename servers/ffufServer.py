from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastmcp import FastMCP

from utils import WORDLISTS_DIR, failure, run_process

mcp = FastMCP("FFUF Scanner")


@mcp.tool()
def run_ffuf_fuzz(
    target_url: str,
    cookies: str = "",
    wordlist: str = "",
    timeout: int = 180,
) -> dict:
    """Discovers web resources with FFUF using a cross-platform wordlist."""
    wordlist_path = Path(wordlist) if wordlist else WORDLISTS_DIR / "common.txt"
    if not wordlist_path.exists():
        return failure("FFUF", target_url, f"Wordlist not found: {wordlist_path}")

    with tempfile.TemporaryDirectory(prefix="ffuf-") as temporary_directory:
        output_file = Path(temporary_directory) / "ffuf.json"
        command = [
            "ffuf",
            "-u", f"{target_url.rstrip('/')}/FUZZ",
            "-w", str(wordlist_path),
            "-of", "json",
            "-o", str(output_file),
            "-ac",
            "-t", "20",
            "-timeout", "10",
            "-noninteractive",
        ]
        if cookies:
            command.extend(["-b", cookies])

        result = run_process("FFUF", command, target=target_url, timeout=timeout)
        if result["status"] != "success":
            return result

        try:
            parsed = json.loads(output_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return failure("FFUF", target_url, f"Cannot parse FFUF JSON: {exc}")

        findings = []
        for item in parsed.get("results", []):
            findings.append({
                "alert": "Discovered web resource",
                "risk": "info",
                "description": f"HTTP {item.get('status')}, {item.get('length')} bytes.",
                "url": item.get("url", ""),
                "status_code": item.get("status"),
            })

        result["vulnerabilities"] = findings
        result["output"] = f"FFUF completed. Resources: {len(findings)}"
        return result


if __name__ == "__main__":
    mcp.run(transport="stdio")