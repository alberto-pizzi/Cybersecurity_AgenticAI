import subprocess
import re
import requests
from fastmcp import FastMCP

mcp = FastMCP("SQLMap_Server")


def get_dvwa_session() -> str:
    """Esegue il login su DVWA e restituisce il cookie PHPSESSID."""
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
def run_sqlmap_scan(target_url: str) -> dict:
    """Esegue test SQL Injection con SQLmap iniettando il cookie di sessione autenticato."""
    phpsessid = get_dvwa_session()
    cookie_str = f"PHPSESSID={phpsessid}; security=low" if phpsessid else ""

    try:
        cmd = ["sqlmap", "-u", target_url, "--batch", "--random-agent", "--level=1", "--risk=1", "--time-sec=2"]
        if cookie_str:
            cmd.extend(["--cookie", cookie_str])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        is_vuln = "is vulnerable" in result.stdout.lower() or "parameter appears to be" in result.stdout.lower()
        return {"status": "success", "target": target_url, "sql_injection_found": is_vuln,
                "output": result.stdout[-1000:]}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}


if __name__ == "__main__":
    mcp.run(transport="stdio")