import time
import requests
from fastmcp import FastMCP

mcp = FastMCP("ZAP_Automation_Server")

ZAP_BASE_URL = "http://127.0.0.1:8080"
# Header 'Host: zap' dice a ZAP che si tratta di una chiamata API diretta
HEADERS = {"Host": "zap"}

@mcp.tool()
def run_pentest_scan(target_url: str = "http://host.docker.internal:3000") -> dict:
    """
    Esegue uno spider scan tramite la REST API diretta di OWASP ZAP.
    """
    session = requests.Session()
    session.trust_env = False  # Ignora proxy di sistema Windows/Linux
    session.headers.update(HEADERS)

    try:
        # 1. Avvia lo Spider Scan
        scan_resp = session.get(
            f"{ZAP_BASE_URL}/JSON/spider/action/scan/",
            params={"url": target_url},
            timeout=10
        )
        scan_data = scan_resp.json()

        if "scan" not in scan_data:
            return {
                "status": "error",
                "target": target_url,
                "message": f"Risposta inattesa da ZAP API: {scan_data}"
            }

        scan_id = scan_data["scan"]

        # 2. Monitora lo stato dello scan
        while True:
            status_resp = session.get(
                f"{ZAP_BASE_URL}/JSON/spider/view/status/",
                params={"scanId": scan_id},
                timeout=10
            )
            status_pct = int(status_resp.json().get("status", 0))
            if status_pct >= 100:
                break
            time.sleep(2)

        # 3. Recupera gli alert
        alerts_resp = session.get(
            f"{ZAP_BASE_URL}/JSON/core/view/alerts/",
            params={"baseurl": target_url},
            timeout=10
        )
        alerts = alerts_resp.json().get("alerts", [])

        vulnerabilities = [
            {
                "alert": a.get("alert"),
                "risk": a.get("risk"),
                "confidence": a.get("confidence"),
                "url": a.get("url"),
                "param": a.get("param"),
                "description": a.get("description"),
                "solution": a.get("solution")
            }
            for a in alerts
        ]

        return {
            "status": "success",
            "target": target_url,
            "vulnerabilities_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }

    except Exception as e:
        return {
            "status": "error",
            "target": target_url,
            "message": f"Errore di connessione a OWASP ZAP: {str(e)}"
        }

if __name__ == "__main__":
    mcp.run(transport="stdio")