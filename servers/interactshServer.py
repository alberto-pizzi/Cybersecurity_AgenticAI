import subprocess
from fastmcp import FastMCP

mcp = FastMCP("Interactsh_Server")

@mcp.tool()
def run_interactsh_client() -> dict:
    """Esegue Interactsh per OAST out-of-band checks."""
    try:
        cmd = ["interactsh-client", "-json", "-timeout", "10"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return {"status": "success", "output": result.stdout}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")