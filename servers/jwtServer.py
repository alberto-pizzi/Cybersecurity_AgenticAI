import subprocess
from fastmcp import FastMCP

mcp = FastMCP("JWT_Tool_Server")

@mcp.tool()
def run_jwt_scan(jwt_token: str) -> dict:
    """Analizza token JWT con jwt_tool."""
    try:
        cmd = ["python3", "jwt_tool.py", jwt_token, "-M", "all"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"status": "success", "output": result.stdout[-1500:]}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")