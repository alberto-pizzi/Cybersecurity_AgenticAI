import subprocess
import json
from fastmcp import FastMCP

mcp = FastMCP("Nuclei_Server")

@mcp.tool()
def run_nuclei_scan(target_url: str) -> dict:
    """Esegue scansioni di vulnerabilità con Nuclei."""
    try:
        cmd = ["nuclei", "-u", target_url, "-json", "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        vulnerabilities = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    vulnerabilities.append({"title": data.get("info", {}).get("name"), "severity": data.get("info", {}).get("severity")})
                except json.JSONDecodeError:
                    continue
        return {"status": "success", "target": target_url, "vulnerabilities": vulnerabilities}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")