import subprocess
import sys
import re
import requests
from pathlib import Path
from fastmcp import FastMCP

mcp = FastMCP("Commix_Server")

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
def run_commix_scan(target_url: str) -> dict:
    """Esegue test command injection con Commix includendo i cookie di sessione."""
    phpsessid = get_dvwa_session()
    cookie_str = f"PHPSESSID={phpsessid}; security=low" if phpsessid else ""

    try:
        commix_path = Path.home() / ".local" / "opt" / "commix" / "commix.py"
        if commix_path.exists():
            cmd = [sys.executable, str(commix_path), "--url", target_url, "--batch", "--level=1"]
        else:
            cmd = ["commix", "--url", target_url, "--batch"]

        if cookie_str:
            cmd.extend(["--cookie", cookie_str])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"status": "success", "target": target_url, "output": result.stdout}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")