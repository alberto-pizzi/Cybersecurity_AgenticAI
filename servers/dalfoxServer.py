import subprocess
from fastmcp import FastMCP

mcp = FastMCP("Dalfox_Server")

@mcp.tool()
def run_dalfox_scan(target_url: str) -> dict:
    """Esegue analisi XSS automatizzata con Dalfox."""
    try:
        cmd = ["dalfox", "url", target_url, "--format", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"status": "success", "target": target_url, "output": result.stdout}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")