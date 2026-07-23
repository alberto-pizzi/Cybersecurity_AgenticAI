import subprocess
import json
import os
from pathlib import Path
from fastmcp import FastMCP

mcp = FastMCP("FFUF_Server")


@mcp.tool()
def run_ffuf_fuzz(target_url: str) -> dict:
    """Esegue directory e file fuzzing avanzato con estensioni e recursion su ffuf."""
    # Fallback wordlist location check for cross-platform reliability
    wordlist_path = Path("/usr/share/wordlists/dirb/common.txt")
    if not wordlist_path.exists():
        # Fallback to local or built-in small wordlist if default path is missing
        wordlist_path = Path.home() / ".local" / "wordlists" / "common.txt"

    try:
        cmd = [
            "ffuf",
            "-u", f"{target_url}/FUZZ",
            "-w", str(wordlist_path),
            "-e", ".js,.html,.json,.bak,.php",
            "-recursion",
            "-recursion-depth", "2",
            "-json",
            "-s"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        discovered = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    discovered.append({
                        "url": data.get("url"),
                        "status": data.get("status"),
                        "length": data.get("length")
                    })
                except json.JSONDecodeError:
                    continue
        return {"status": "success", "target": target_url, "discovered_endpoints": discovered}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}


if __name__ == "__main__":
    mcp.run(transport="stdio")