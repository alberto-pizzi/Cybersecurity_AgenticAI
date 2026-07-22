import subprocess
import shutil
import platform
import json
import logging
import sys
from fastmcp import FastMCP
mcp = FastMCP("Nikto_Server")

# 2. Configure stderr logging (avoid using print statements to protect stdout JSON-RPC)
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s"
)
logger = logging.getLogger("Nikto_Server")

@mcp.tool()
def run_nikto_scan(target_url: str) -> str:
    """Executes a Nikto web scan against the target URL."""
    system = platform.system().lower()

    # Locate executables
    perl_path = shutil.which("perl")
    nikto_path = shutil.which("nikto") or shutil.which("nikto.pl")

    if not nikto_path:
        return json.dumps({
            "status": "error",
            "message": "Nikto binary/script not found in system PATH."
        })

    # Form command array based on OS and extension
    if system == "windows" and (nikto_path.endswith(".pl") or not nikto_path.endswith(".exe")):
        if not perl_path:
            return json.dumps({
                "status": "error",
                "message": "Perl runtime missing. Windows requires Perl to run nikto.pl."
            })
        cmd = [perl_path, nikto_path, "-h", target_url]
    else:
        cmd = [nikto_path, "-h", target_url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})