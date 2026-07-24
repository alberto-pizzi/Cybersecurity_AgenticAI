from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from utils import partial, run_process

mcp = FastMCP("Arjun Scanner")


def collect_parameters(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, list):
        found.extend(str(item) for item in value if isinstance(item, (str, int, float)))
    elif isinstance(value, dict):
        for nested in value.values():
            found.extend(collect_parameters(nested))
    return found


def _load_parameters(path: Path) -> list[str]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    return sorted({item.strip() for item in collect_parameters(parsed) if item.strip()})


@mcp.tool()
def run_arjun_scan(target_url: str, cookies: str = "", timeout: int = 120) -> dict:
    """Discover hidden GET parameters using a bounded, non-stable scan profile."""
    with tempfile.TemporaryDirectory(prefix="arjun-") as temporary_directory:
        output_file = Path(temporary_directory) / "arjun.json"
        command = [
            "arjun", "-u", target_url,
            "-m", "GET",
            "-oJ", str(output_file),
            "-t", "5",
            "-T", "8",
            "-w", "small",
            "-c", "250",
        ]
        if cookies:
            command.extend(["--headers", f"Cookie: {cookies}"])

        result = run_process("Arjun", command, target=target_url, timeout=timeout)
        parameters = _load_parameters(output_file)
        findings = [{
            "alert": "Hidden HTTP parameter discovered",
            "risk": "info",
            "category": "discovery",
            "description": f"Arjun identified the undocumented GET parameter '{parameter}'.",
            "impact": "The parameter increases the application attack surface and should be reviewed by injection and authorization scanners.",
            "solution": "Confirm whether the parameter is intended, validate it server-side, and remove unused parameters.",
            "url": target_url,
            "parameter": parameter,
            "confidence": "medium",
            "evidence": f"Parameter name returned by Arjun: {parameter}",
        } for parameter in parameters]

        if result.get("status") == "error" and result.get("diagnosis") == "timeout" and parameters:
            return partial(
                "Arjun",
                target_url,
                f"Arjun timed out after {timeout} seconds but returned {len(parameters)} parameter names.",
                vulnerabilities=findings,
                parameters=parameters,
                diagnosis="timeout_with_partial_results",
                timed_out=True,
                duration_seconds=result.get("duration_seconds"),
                command=result.get("command", []),
            )
        if result.get("status") != "success":
            result.update(vulnerabilities=findings, parameters=parameters)
            return result

        result.update(
            parameters=parameters,
            vulnerabilities=findings,
            output=f"Arjun completed. Hidden parameters: {len(parameters)}.",
            scan_profile="small wordlist, 5 threads, 8-second request timeout",
        )
        return result


if __name__ == "__main__":
    mcp.run(transport="stdio")