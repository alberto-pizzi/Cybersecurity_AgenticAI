from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastmcp import FastMCP

from utils import failure, run_process

mcp = FastMCP("Arjun Scanner")


def collect_parameters(value) -> list[str]:
    """Recursively extracts parameter names from Arjun's JSON variants."""
    found: list[str] = []
    if isinstance(value, list):
        found.extend(str(item) for item in value if isinstance(item, (str, int, float)))
    elif isinstance(value, dict):
        for nested in value.values():
            found.extend(collect_parameters(nested))
    return found


@mcp.tool()
def run_arjun_scan(target_url: str, cookies: str = "", timeout: int = 180) -> dict:
    """Discovers hidden GET parameters without assuming a specific application."""
    with tempfile.TemporaryDirectory(prefix="arjun-") as temporary_directory:
        output_file = Path(temporary_directory) / "arjun.json"
        command = [
            "arjun", "-u", target_url,
            "-m", "GET",
            "-oJ", str(output_file),
            "-t", "10",
            "--stable",
        ]
        if cookies:
            command.extend(["--headers", f"Cookie: {cookies}"])

        result = run_process("Arjun", command, target=target_url, timeout=timeout)
        if result["status"] != "success":
            return result

        try:
            parsed = json.loads(output_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return failure("Arjun", target_url, f"Cannot parse Arjun JSON: {exc}")

        parameters = sorted(set(collect_parameters(parsed)))
        findings = [{
            "alert": "Hidden HTTP parameter",
            "risk": "info",
            "description": f"Parameter discovered: {parameter}",
            "url": target_url,
            "parameter": parameter,
        } for parameter in parameters]

        result["parameters"] = parameters
        result["vulnerabilities"] = findings
        result["output"] = f"Arjun completed. Parameters: {len(parameters)}"
        return result


if __name__ == "__main__":
    mcp.run(transport="stdio")