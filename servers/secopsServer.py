from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# Allow direct execution (python servers/secopsServer.py) as well as orchestrator-managed startup.
SERVERS_DIR = Path(__file__).resolve().parent
ROOT_DIR = SERVERS_DIR.parent
for path in (ROOT_DIR, SERVERS_DIR):
    value = str(path)
    if value not in sys.path:
        sys.path.insert(0, value)

from fastmcp import FastMCP

from utils import run_mcp_http, secops_source_fingerprint

from custom_checks.authorizationServer import mcp as authorization_mcp
from custom_checks.browserServer import mcp as browser_mcp
from custom_checks.jwtServer import mcp as jwt_mcp
from custom_checks.sessionServer import mcp as session_mcp
from custom_checks.traversalServer import mcp as traversal_mcp
from custom_checks.workflowServer import mcp as workflow_mcp
from pentest_tools.discovery.arjunServer import mcp as arjun_mcp
from pentest_tools.discovery.ffufServer import mcp as ffuf_mcp
from pentest_tools.discovery.interactshServer import mcp as interactsh_mcp
from pentest_tools.exploitation.commixServer import mcp as commix_mcp
from pentest_tools.exploitation.dalfoxServer import mcp as dalfox_mcp
from pentest_tools.exploitation.idorForgeServer import mcp as idor_mcp
from pentest_tools.exploitation.sqlmapServer import mcp as sqlmap_mcp
from pentest_tools.scanning.niktoServer import mcp as nikto_mcp
from pentest_tools.scanning.nucleiServer import mcp as nuclei_mcp
from pentest_tools.scanning.zapServer import mcp as zap_mcp
from reporting.reportServer import mcp as report_mcp


mcp = FastMCP(
    "SecOps Unified Security Server",
    instructions=(
        "Single MCP interface for the SecOps assessment platform. It exposes discovery, scanning, "
        "targeted verification, authorization/workflow checks, OAST/JWT analysis and report generation."
    ),
)

# Freeze the source fingerprint when this process starts. If files are updated while an older MCP
# process remains alive, a new orchestrator can detect that the process is stale instead of silently
# using wrappers whose source fingerprint does not match the current orchestrator.
_SERVER_SOURCE_FINGERPRINT = secops_source_fingerprint()

@mcp.tool()
def secops_runtime_identity(check_docker: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "source_fingerprint": _SERVER_SOURCE_FINGERPRINT,
        "root": str(ROOT_DIR.resolve()),
        "python": sys.executable,
        "pid": os.getpid(),
    }
    if check_docker:
        # Run an innocuous Docker API check inside the actual MCP service context.
        # A successful `docker info` in the installer's shell is not sufficient
        # when a systemd service has different sandboxing or environment.
        import shutil
        import subprocess
        diagnostic: dict[str, Any] = {
            "uid": os.geteuid() if hasattr(os, "geteuid") else None,
            "groups": list(os.getgroups()) if hasattr(os, "getgroups") else [],
            "socket_gid": None,
            "ok": False,
            "returncode": None,
            "detail": "",
        }
        if sys.platform.startswith("linux"):
            try:
                diagnostic["socket_gid"] = Path("/var/run/docker.sock").stat().st_gid
            except OSError as exc:
                diagnostic["detail"] = f"Docker socket inspection: {type(exc).__name__}: {exc}"
        if shutil.which("docker"):
            try:
                probe = subprocess.run(
                    ["docker", "info", "--format", "{{.ServerVersion}}"],
                    capture_output=True, text=True, timeout=15, check=False,
                )
                diagnostic["returncode"] = probe.returncode
                diagnostic["ok"] = probe.returncode == 0 and bool(probe.stdout.strip())
                if diagnostic["ok"]:
                    diagnostic["version"] = probe.stdout.strip()
                else:
                    diagnostic["detail"] = (probe.stderr or probe.stdout or "Docker info failed").strip()[-1200:]
            except (OSError, subprocess.TimeoutExpired) as exc:
                diagnostic["detail"] = f"{type(exc).__name__}: {exc}"[-1200:]
        else:
            diagnostic["detail"] = "docker executable not found in MCP PATH"
        result["docker"] = diagnostic
    return result

# Child modules remain independently maintainable, but only this parent owns an HTTP listener.
for child in (
    ffuf_mcp,
    zap_mcp,
    nuclei_mcp,
    session_mcp,
    nikto_mcp,
    arjun_mcp,
    sqlmap_mcp,
    dalfox_mcp,
    commix_mcp,
    traversal_mcp,
    idor_mcp,
    authorization_mcp,
    browser_mcp,
    workflow_mcp,
    jwt_mcp,
    interactsh_mcp,
    report_mcp,
):
    mcp.mount(child)


if __name__ == "__main__":
    run_mcp_http(mcp, "secops")
