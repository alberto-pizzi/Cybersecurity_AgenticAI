import subprocess
from fastmcp import FastMCP

mcp = FastMCP("Nikto_Server")

@mcp.tool()
def run_nikto_scan(target_url: str) -> dict:
    """Esegue scansioni web server con Nikto."""
    try:
        cmd = ["nikto", "-h", target_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"status": "success", "target": target_url, "output": result.stdout[-1500:]}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")