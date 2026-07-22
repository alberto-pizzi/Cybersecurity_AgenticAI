import subprocess
from fastmcp import FastMCP

mcp = FastMCP("SQLMap_Server")

@mcp.tool()
def run_sqlmap_scan(target_url: str) -> dict:
    """Esegue test SQL Injection con SQLmap."""
    try:
        cmd = ["sqlmap", "-u", target_url, "--batch", "--random-agent", "--level=1", "--risk=1"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        is_vuln = "is vulnerable" in result.stdout.lower()
        return {"status": "success", "target": target_url, "sql_injection_found": is_vuln}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")