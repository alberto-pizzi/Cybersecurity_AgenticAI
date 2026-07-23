import subprocess
from fastmcp import FastMCP

mcp = FastMCP("JWT_Tool_Server")

@mcp.tool()
def run_jwt_scan(jwt_token: str) -> dict:
    """Analizza in profondità token JWT con jwt_tool testando fuzzing avanzato e attacchi algoritmici."""
    try:
        cmd = ["python3", "jwt_tool.py", jwt_token, "-M", "all", "-T", "-d", "common_secrets.txt"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return {
            "status": "success" if result.returncode == 0 else "error",
            "output": result.stdout[-2000:] if result.stdout else result.stderr
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")