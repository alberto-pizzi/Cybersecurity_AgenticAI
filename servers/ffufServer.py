import subprocess
import json
from fastmcp import FastMCP

mcp = FastMCP("FFUF_Server")

@mcp.tool()
def run_ffuf_fuzz(target_url: str) -> dict:
    """Esegue directory fuzzing con ffuf."""
    wordlist_path = "/usr/share/wordlists/dirb/common.txt"
    try:
        cmd = ["ffuf", "-u", f"{target_url}/FUZZ", "-w", wordlist_path, "-json", "-s"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        discovered = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    discovered.append({"url": data.get("url"), "status": data.get("status")})
                except json.JSONDecodeError:
                    continue
        return {"status": "success", "target": target_url, "discovered_endpoints": discovered}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")