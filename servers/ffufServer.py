import subprocess
import json
import os
import re
import requests
from pathlib import Path
from fastmcp import FastMCP

mcp = FastMCP("FFUF_Server")

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
def run_ffuf_fuzz(target_url: str) -> dict:
    """Esegue directory e file fuzzing avanzato con FFUF passando i cookie autenticati."""
    wordlist_path = Path("/usr/share/wordlists/dirb/common.txt")
    if not wordlist_path.exists():
        wordlist_path = Path.home() / ".local" / "wordlists" / "common.txt"

    phpsessid = get_dvwa_session()
    cookie_str = f"PHPSESSID={phpsessid}; security=low" if phpsessid else ""

    try:
        cmd = [
            "ffuf",
            "-u", f"{target_url}/FUZZ",
            "-w", str(wordlist_path),
            "-e", ".js,.html,.json,.bak,.php",
            "-recursion",
            "-recursion-depth", "2",
            "-json",
            "-s"
        ]
        if cookie_str:
            cmd.extend(["-b", cookie_str])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        discovered = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    discovered.append({
                        "url": data.get("url"),
                        "status": data.get("status"),
                        "length": data.get("length")
                    })
                except json.JSONDecodeError:
                    continue
        return {"status": "success", "target": target_url, "discovered_endpoints": discovered}
    except Exception as e:
        return {"status": "error", "target": target_url, "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")