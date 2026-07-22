import requests
from fastmcp import FastMCP

mcp = FastMCP("IDOR_Forge_Server")


@mcp.tool()
def run_idor_check(target_url: str, test_id_param: str = "id", low_id: str = "1", high_id: str = "2") -> dict:
    """Esegue test funzionale IDOR alterando i parametri ID di sessione per verificare accessi non autorizzati."""
    findings = []
    try:
        base_endpoint = target_url.rstrip("/")
        resp_low = requests.get(f"{base_endpoint}?{test_id_param}={low_id}", timeout=5)
        resp_high = requests.get(f"{base_endpoint}?{test_id_param}={high_id}", timeout=5)

        if resp_low.status_code == 200 and resp_high.status_code == 200:
            if resp_low.text != resp_high.text:
                findings.append({
                    "vulnerability": "Potential IDOR",
                    "description": f"Different objects returned when switching parameter '{test_id_param}' from {low_id} to {high_id} without explicit authorization enforcement."
                })
        return {"status": "success", "target": target_url, "findings": findings}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}


if __name__ == "__main__":
    mcp.run(transport="stdio")