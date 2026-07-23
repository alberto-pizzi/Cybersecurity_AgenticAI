import time
import re
import requests
from fastmcp import FastMCP

mcp = FastMCP("ZAP_Automation_Server")

ZAP_BASE_URL = "http://127.0.0.1:8080"
HEADERS = {"Host": "zap"}


def get_dvwa_session() -> str:
    """Esegue il login su DVWA tramite l'host e restituisce il cookie di sessione."""
    session = requests.Session()
    auth_url = "http://127.0.0.1"

    try:
        login_page = session.get(f"{auth_url}/login.php", timeout=5)
        user_token = ""
        match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", login_page.text)
        if match:
            user_token = match.group(1)

        login_data = {
            "username": "admin",
            "password": "password",
            "Login": "Login"
        }
        if user_token:
            login_data["user_token"] = user_token

        session.post(f"{auth_url}/login.php", data=login_data, timeout=5)
        session.get(f"{auth_url}/security.php", timeout=5)

        phpsessid = session.cookies.get("PHPSESSID")
        print(f"[+] Autenticazione DVWA riuscita. PHPSESSID: {phpsessid}")
        return phpsessid or ""
    except Exception as e:
        print(f"[-] Errore di autenticazione DVWA: {e}")
        return ""


@mcp.tool()
def run_zap_scan(target_url: str = "http://dvwa") -> dict:
    """Esegue Spider Scan + Active Scan con OWASP ZAP puntando a http://dvwa."""
    session = requests.Session()
    session.trust_env = False
    session.headers.update(HEADERS)

    phpsessid = get_dvwa_session()
    zap_scan_target = "http://dvwa"

    try:
        if phpsessid:
            cookie_header = f"PHPSESSID={phpsessid}; security=low"
            # Nome regola univoco basato su timestamp per evitare errori di duplicazione in ZAP
            rule_description = f"DVWA_Auth_Cookie_{int(time.time())}"

            session.get(
                f"{ZAP_BASE_URL}/JSON/replacer/action/addRule/",
                params={
                    "description": rule_description,
                    "enabled": "true",
                    "matchType": "REQ_HEADER",
                    "matchRegex": "false",
                    "matchString": "Cookie",
                    "replacement": cookie_header
                },
                timeout=5
            )

        # ---------------------------------------------------------
        # 1. SPIDER SCAN
        # ---------------------------------------------------------
        print(f"[*] [ZAP] Avvio Spider Scan su: {zap_scan_target}")
        scan_resp = session.get(
            f"{ZAP_BASE_URL}/JSON/spider/action/scan/",
            params={"url": zap_scan_target},
            timeout=10
        )
        scan_data = scan_resp.json()

        if "scan" not in scan_data:
            return {
                "status": "error",
                "target": zap_scan_target,
                "message": f"Risposta inattesa da ZAP Spider API: {scan_data}"
            }

        spider_id = scan_data["scan"]

        while True:
            status_resp = session.get(
                f"{ZAP_BASE_URL}/JSON/spider/view/status/",
                params={"scanId": spider_id},
                timeout=10
            )
            status_pct = int(status_resp.json().get("status", 0))
            print(f"[*] [ZAP] Spider Scan avanzamento: {status_pct}%")
            if status_pct >= 100:
                break
            time.sleep(2)

        # ---------------------------------------------------------
        # 2. ACTIVE SCAN
        # ---------------------------------------------------------
        print(f"[*] [ZAP] Avvio Active Scan su: {zap_scan_target}")
        ascan_resp = session.get(
            f"{ZAP_BASE_URL}/JSON/ascan/action/scan/",
            params={"url": zap_scan_target, "recurse": "true"},
            timeout=10
        )
        ascan_data = ascan_resp.json()

        if "scan" in ascan_data:
            ascan_id = ascan_data["scan"]
            while True:
                status_resp = session.get(
                    f"{ZAP_BASE_URL}/JSON/ascan/view/status/",
                    params={"scanId": ascan_id},
                    timeout=10
                )
                status_pct = int(status_resp.json().get("status", 0))
                print(f"[*] [ZAP] Active Scan avanzamento: {status_pct}%")
                if status_pct >= 100:
                    break
                time.sleep(3)

        # ---------------------------------------------------------
        # 3. RECUPERO ALERT E VULNERABILITÀ
        # ---------------------------------------------------------
        alerts_resp = session.get(
            f"{ZAP_BASE_URL}/JSON/core/view/alerts/",
            params={"baseurl": zap_scan_target},
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
            "target": zap_scan_target,
            "vulnerabilities_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }

    except Exception as e:
        return {
            "status": "error",
            "target": zap_scan_target,
            "message": f"Errore di connessione a OWASP ZAP: {str(e)}"
        }


if __name__ == "__main__":
    mcp.run(transport="stdio")