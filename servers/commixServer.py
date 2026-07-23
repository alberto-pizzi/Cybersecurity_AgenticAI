import subprocess
import sys
from pathlib import Path
from fastmcp import FastMCP

mcp = FastMCP("Commix_Server")


@mcp.tool()
def run_commix_scan(target_url: str) -> dict:
    """Esegue test command injection con Commix."""
    try:
        # Resolve absolute path to commix.py using sys.executable to avoid WinError 2
        commix_path = Path.home() / ".local" / "opt" / "commix" / "commix.py"

        if commix_path.exists():
            cmd = [sys.executable, str(commix_path), "--url", target_url, "--batch", "--level=1"]
        else:
            cmd = ["commix", "--url", target_url, "--batch"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"status": "success", "target": target_url, "output": result.stdout}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}


if __name__ == "__main__":
    mcp.run(transport="stdio")