import subprocess
import json
import re
import requests
from fastmcp import FastMCP

mcp = FastMCP("Nuclei_Server")

def get_dvwa_session() -> str:
    session = requests.Session()
    auth_url = "http://127.0.0.1"
    try:
        login_page = session.get(f"{auth_url}/login.php", timeout=5)
        user_token = ""
        match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", login_page.text)
        if match:
            user_token = match.group(1)

        login_data = {"username": "admin", "password": "password", "Login": "Login"}
        if user_token:
            login_data["user_token"] = user_token

        session.post(f"{auth_url}/login.php", data=login_data, timeout=5)
        session.get(f"{auth_url}/security.php", timeout=5)
        return session.cookies.get("PHPSESSID") or ""
    except Exception:
        return ""

@mcp.tool()
def run_nuclei_scan(target_url: str) -> dict:
    """Esegue scansioni di vulnerabilità con Nuclei passando i cookie autenticati."""
    phpsessid = get_dvwa_session()
    cookie_header = f"Cookie: PHPSESSID={phpsessid}; security=low" if phpsessid else ""

    try:
        cmd = ["nuclei", "-u", target_url, "-severity", "low,medium,high,critical", "-json", "-silent"]
        if cookie_header:
            cmd.extend(["-header", cookie_header])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        vulnerabilities = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    vulnerabilities.append({
                        "title": data.get("info", {}).get("name"),
                        "severity": data.get("info", {}).get("severity")
                    })
                except json.JSONDecodeError:
                    continue
        return {"status": "success", "target": target_url, "vulnerabilities": vulnerabilities}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")