from __future__ import annotations

import json
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from fastmcp import FastMCP

from utils import WORDLISTS_DIR, failure, run_process

mcp = FastMCP("FFUF Scanner")

_SENSITIVE_NAMES = {"admin", "backup", "config", "debug", "server-status", "setup.php", ".env", ".git"}


def _classify(url: str, status: int) -> tuple[str, str, str]:
    name = Path(urlparse(url).path.rstrip("/")).name.lower()
    if name in _SENSITIVE_NAMES and status in {200, 301, 302, 307, 401, 403}:
        return (
            "low",
            "Potentially sensitive resource exposed",
            "Restrict the resource, remove deployment/setup artifacts, and verify that no secrets or administrative functions are publicly reachable.",
        )
    return (
        "info",
        "Discovered web resource",
        "Review whether this resource is intended to be reachable and include it in subsequent authenticated crawling and testing.",
    )


@mcp.tool()
def run_ffuf_fuzz(target_url: str, cookies: str = "", wordlist: str = "", timeout: int = 180) -> dict:
    """Discover web resources and return structured observations for re-crawling."""
    wordlist_path = Path(wordlist) if wordlist else WORDLISTS_DIR / "common.txt"
    if not wordlist_path.exists():
        return failure("FFUF", target_url, f"Wordlist not found: {wordlist_path}", diagnosis="missing_wordlist")

    with tempfile.TemporaryDirectory(prefix="ffuf-") as temporary_directory:
        output_file = Path(temporary_directory) / "ffuf.json"
        command = [
            "ffuf", "-u", f"{target_url.rstrip('/')}/FUZZ",
            "-w", str(wordlist_path),
            "-of", "json", "-o", str(output_file),
            "-ac", "-t", "20", "-timeout", "10", "-noninteractive",
        ]
        if cookies:
            command.extend(["-b", cookies])
        result = run_process("FFUF", command, target=target_url, timeout=timeout)
        if result.get("status") != "success":
            return result
        try:
            parsed = json.loads(output_file.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            return failure("FFUF", target_url, f"Cannot parse FFUF JSON: {exc}", diagnosis="invalid_scanner_output")

        findings = []
        for item in parsed.get("results", []):
            url = str(item.get("url", ""))
            status = int(item.get("status") or 0)
            risk, alert, recommendation = _classify(url, status)
            findings.append({
                "alert": alert,
                "risk": risk,
                "category": "discovery",
                "description": (
                    f"FFUF received HTTP {status} for this resource "
                    f"({item.get('length', 0)} bytes, {item.get('words', 0)} words, {item.get('lines', 0)} lines)."
                ),
                "impact": "The resource expands the known attack surface. Sensitive or unintended paths may expose configuration, setup, or administrative functionality.",
                "solution": recommendation,
                "url": url,
                "status_code": status,
                "content_length": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "redirect_location": item.get("redirectlocation", ""),
                "confidence": "high",
                "evidence": f"HTTP {status}; length={item.get('length')}; words={item.get('words')}; lines={item.get('lines')}",
            })
        result.update(
            vulnerabilities=findings,
            output=f"FFUF completed. Resources: {len(findings)}.",
            discovered_urls=[item["url"] for item in findings if item.get("url")],
            authenticated=bool(cookies),
        )
        return result


if __name__ == "__main__":
    mcp.run(transport="stdio")