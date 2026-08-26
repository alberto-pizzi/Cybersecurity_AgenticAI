from __future__ import annotations

import sys
from pathlib import Path

# Allow direct execution (python servers/secopsServer.py) as well as orchestrator-managed startup.
SERVERS_DIR = Path(__file__).resolve().parent
ROOT_DIR = SERVERS_DIR.parent
for path in (ROOT_DIR, SERVERS_DIR):
    value = str(path)
    if value not in sys.path:
        sys.path.insert(0, value)

from fastmcp import FastMCP

from utils import run_mcp_http

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
