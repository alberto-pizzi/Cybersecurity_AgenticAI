import subprocess
import platform
from pathlib import Path
from fastmcp import FastMCP

mcp = FastMCP("Dalfox_Server")

@mcp.tool()
def run_dalfox_scan(target_url: str) -> dict:
    """Esegue analisi XSS automatizzata con Dalfox gestendo i percorsi binari."""
    try:
        bin_name = "dalfox.exe" if platform.system().lower() == "windows" else "dalfox"
        dalfox_path = Path.home() / ".local" / "bin" / bin_name

        cmd = [str(dalfox_path), "url", target_url, "--format", "json"] if dalfox_path.exists() else ["dalfox", "url", target_url, "--format", "json"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"status": "success", "target": target_url, "output": result.stdout}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")