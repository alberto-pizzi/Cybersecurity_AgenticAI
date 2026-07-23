import requests
from fastmcp import FastMCP

mcp = FastMCP("IDOR_Forge_Server")


@mcp.tool()
def run_idor_check(target_url: str, test_id_param: str = "id", low_id: str = "1", high_id: str = "3") -> dict:
    """Esegue test IDOR approfonditi verificando variazioni di risposta e contenuti sensibili tra ID differenti[cite: 21]."""
    findings = []
    try:
        base_endpoint = target_url.rstrip("/")
        resp_low = requests.get(f"{base_endpoint}?{test_id_param}={low_id}", timeout=5)
        resp_high = requests.get(f"{base_endpoint}?{test_id_param}={high_id}", timeout=5)

        if resp_low.status_code == 200 and resp_high.status_code == 200:
            if resp_low.text != resp_high.text:
                sensitive_keywords = ["email", "password", "role", "admin", "token", "credit"]
                leaks = [kw for kw in sensitive_keywords if kw in resp_low.text.lower() or kw in resp_high.text.lower()]

                findings.append({
                    "vulnerability": "Confirmed Potential IDOR / Unauthorized Object Access",
                    "description": f"Different state/objects returned when switching parameter '{test_id_param}' from {low_id} to {high_id}.",
                    "sensitive_keywords_detected": leaks
                })
        return {"status": "success", "target": target_url, "findings": findings}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}


if __name__ == "__main__":
    mcp.run(transport="stdio")