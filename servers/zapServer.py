import time
import requests
from fastmcp import FastMCP

mcp = FastMCP("ZAP_Automation_Server")
ZAP_BASE_URL = "http://127.0.0.1:8080"
HEADERS = {"Host": "zap"}

@mcp.tool()
def run_pentest_scan(target_url: str = "http://host.docker.internal:3000") -> dict:
    """Esegue spider scan e raccoglie alert tramite REST API di OWASP ZAP."""
    session = requests.Session()
    session.trust_env = False
    session.headers.update(HEADERS)

    try:
        scan_resp = session.get(f"{ZAP_BASE_URL}/JSON/spider/action/scan/", params={"url": target_url}, timeout=10)
        scan_data = scan_resp.json()
        if "scan" not in scan_data:
            return {"status": "error", "target": target_url, "message": str(scan_data)}

        scan_id = scan_data["scan"]
        while True:
            status_resp = session.get(f"{ZAP_BASE_URL}/JSON/spider/view/status/", params={"scanId": scan_id}, timeout=10)
            if int(status_resp.json().get("status", 0)) >= 100:
                break
            time.sleep(2)

        alerts_resp = session.get(f"{ZAP_BASE_URL}/JSON/core/view/alerts/", params={"baseurl": target_url}, timeout=10)
        alerts = alerts_resp.json().get("alerts", [])
        vulnerabilities = [{"title": a.get("alert"), "severity": a.get("risk"), "url": a.get("url")} for a in alerts]

        return {"status": "success", "target": target_url, "vulnerabilities_count": len(vulnerabilities), "vulnerabilities": vulnerabilities}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")