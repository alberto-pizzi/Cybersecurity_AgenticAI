import subprocess
from fastmcp import FastMCP

mcp = FastMCP("Arjun_Server")

@mcp.tool()
def run_arjun_scan(target_url: str) -> dict:
    """Trova parametri HTTP nascosti con Arjun."""
    try:
        cmd = ["arjun", "-u", target_url, "--stable"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"status": "success", "target": target_url, "output": result.stdout}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")