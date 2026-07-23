import subprocess
import shutil
import platform
import re
import requests
from fastmcp import FastMCP

mcp = FastMCP("Nikto_Server")


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
def run_nikto_scan(target_url: str) -> dict:
    """Esegue una scansione avanzata con Nikto passando i cookie di autenticazione di DVWA."""
    system = platform.system().lower()
    perl_path = shutil.which("perl")
    nikto_path = shutil.which("nikto") or shutil.which("nikto.pl")

    if not nikto_path:
        return {"status": "error", "message": "Nikto binary/script not found in system PATH."}

    phpsessid = get_dvwa_session()
    tuning_args = ["-Tuning", "1234567890bcpx"]

    if phpsessid:
        tuning_args.extend(["-cookie", f"PHPSESSID={phpsessid}; security=low"])

    if system == "windows" and (nikto_path.endswith(".pl") or not nikto_path.endswith(".exe")):
        if not perl_path:
            return {"status": "error", "message": "Perl runtime missing. Windows requires Perl to run nikto.pl."}
        cmd = [perl_path, nikto_path, "-h", target_url] + tuning_args
    else:
        cmd = [nikto_path, "-h", target_url] + tuning_args

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output_text = result.stdout if result.returncode == 0 else (result.stdout + "\n" + result.stderr)
        return {"status": "success", "target": target_url, "output": output_text[-3000:]}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}


if __name__ == "__main__":
    mcp.run(transport="stdio")