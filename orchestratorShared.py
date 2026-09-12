from __future__ import annotations
import argparse
import atexit
import ast
import asyncio
import functools
import base64
import hashlib
import zlib
import html
import importlib.util
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import sysconfig
import time
import traceback
import uuid
import warnings
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse
warnings.filterwarnings('ignore', message='.*authlib\\.jose.*deprecated.*')
import requests
with warnings.catch_warnings():
    warnings.simplefilter('ignore')
    from fastmcp import Client
from utils import apply_runtime_target_preparation, absolute_url, canonical_cookie_header, cookie_names, load_runtime_config, normalize_url, normalized_origin, parse_cookie_header, ROOT_DIR, same_origin, sanitize_discovered_url, scanner_session_probe, SERVERS_DIR, target_runtime_profile, url_in_authorized_scope as _url_in_explicit_scope, MCP_UNIFIED_SERVICE, mcp_http_port, mcp_http_url
ROOT = Path(ROOT_DIR).resolve()
SERVERS = Path(SERVERS_DIR).resolve()
RUNTIME_FILE = ROOT / '.secops_runtime.json'
UNIFIED_MCP_SERVER = 'secopsServer.py'
LOCAL_BIN = Path.home() / '.local' / 'bin'
MCP_CONNECT_TIMEOUT = float(os.getenv('SECOPS_MCP_CONNECT_TIMEOUT', '20'))
MCP_TOOL_TIMEOUT = float(os.getenv('SECOPS_MCP_TIMEOUT', '1200'))
MCP_REPORT_MAX_BYTES = max(1024 * 1024, int(os.getenv('SECOPS_MCP_REPORT_MAX_BYTES', str(64 * 1024 * 1024))))
MCP_REPORT_INLINE_MAX_BYTES = min(MCP_REPORT_MAX_BYTES, max(65536, int(os.getenv('SECOPS_MCP_REPORT_INLINE_MAX_BYTES', str(128 * 1024)))))
MCP_REPORT_CHUNK_BYTES = min(512 * 1024, max(16384, int(os.getenv('SECOPS_MCP_REPORT_CHUNK_BYTES', str(64 * 1024)))))
MCP_REPORT_MAX_CHUNKS = max(8, int(os.getenv('SECOPS_REPORT_UPLOAD_MAX_CHUNKS', '2048')))
MCP_REPORT_CHUNK_TIMEOUT = max(30.0, float(os.getenv('SECOPS_MCP_REPORT_CHUNK_TIMEOUT', '120')))
MCP_REPORT_TRANSFER_TIMEOUT = max(MCP_REPORT_CHUNK_TIMEOUT, float(os.getenv('SECOPS_MCP_REPORT_TRANSFER_TIMEOUT', '900')))
MCP_REPORT_PDF_TIMEOUT_HINT = max(300.0, float(os.getenv('SECOPS_REPORT_PDF_TIMEOUT', '3600')))
MCP_REPORT_RENDER_TIMEOUT = max(MCP_TOOL_TIMEOUT, MCP_REPORT_PDF_TIMEOUT_HINT + 300.0, float(os.getenv('SECOPS_MCP_REPORT_RENDER_TIMEOUT', '4200')))
MCP_REPORT_RENDER_SECONDS_PER_MIB = max(0.0, float(os.getenv('SECOPS_MCP_REPORT_RENDER_SECONDS_PER_MIB', '60')))
MCP_REPORT_RENDER_TIMEOUT_MAX = max(MCP_REPORT_RENDER_TIMEOUT, float(os.getenv('SECOPS_MCP_REPORT_RENDER_TIMEOUT_MAX', '7200')))
MAX_PARAMETER_ENDPOINTS = max(1, int(os.getenv('SECOPS_MAX_PARAMETER_ENDPOINTS', '5')))
TERMINAL_URL_MAX = max(120, int(os.getenv('SECOPS_TERMINAL_URL_MAX', '240')))

# Keeps terminal output readable without altering the full URL stored in results, JSON or reports.
def compact_log_url(value: Any, max_length: int | None=None) -> str:
    text = str(value or '')
    limit = max(80, int(max_length or TERMINAL_URL_MAX))
    if len(text) <= limit:
        return text
    try:
        parsed = urlparse(text)
        if parsed.scheme and parsed.netloc:
            base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            if pairs:
                names: list[str] = []
                for name, _ in pairs:
                    if name not in names:
                        names.append(name)
                preview = ','.join(names[:5])
                if len(names) > 5:
                    preview += f',+{len(names) - 5}'
                summary = f"{base}?<params={len(pairs)}; query={len(parsed.query)} chars; names={preview}>"
                if len(summary) <= limit:
                    return summary
                base_budget = max(30, limit - 56)
                compact_base = base if len(base) <= base_budget else base[:base_budget - 3] + '...'
                return f"{compact_base}?<params={len(pairs)}; query={len(parsed.query)} chars>"
    except Exception:
        pass
    return text[:limit - 3] + '...'
MAX_ARJUN_ENDPOINTS = max(1, int(os.getenv('SECOPS_MAX_ARJUN_ENDPOINTS', '12')))
MAX_CRAWL_PAGES = max(10, int(os.getenv('SECOPS_MAX_CRAWL_PAGES', '180')))
MAX_SCRIPT_ASSETS = max(4, int(os.getenv('SECOPS_MAX_SCRIPT_ASSETS', '72')))
SCANNER_PROGRESS_INTERVAL = max(10, int(os.getenv('SECOPS_PROGRESS_INTERVAL', '30')))
DISCOVERY_LIMITS = {
    'fast': {'crawl_pages': 35, 'browser_pages': 16, 'browser_pages_max': 32, 'browser_per_origin_pages': 32, 'scripts': 12, 'route_variants': 2, 'per_origin_pages': 24},
    # crawl/browser/per-origin budgets and route_variants were raised for 'balanced': the previous
    # route_variants=3 collapsed every same-shape-different-value route (e.g. a routing parameter
    # like ssoLogin.php?redirect=<module>.php, which selects a different application page per value)
    # down to at most 3 tested variants, so config-driven menus with many distinct redirect/page
    # targets were almost entirely invisible to the specialist selectors regardless of how many were
    # actually discovered. 'deep' keeps a strictly larger route_variants ceiling than 'balanced'.
    'balanced': {'crawl_pages': 140, 'browser_pages': 90, 'browser_pages_max': 160, 'browser_per_origin_pages': 160, 'scripts': 48, 'route_variants': 6, 'per_origin_pages': 90},
    'deep': {'crawl_pages': 180, 'browser_pages': 120, 'browser_pages_max': 240, 'browser_per_origin_pages': 240, 'scripts': 72, 'route_variants': 8, 'per_origin_pages': 120},
}
FINAL_BROWSER_VERIFICATION_LIMITS = {'fast': 8, 'balanced': 40, 'deep': 120}
FINAL_BROWSER_VERIFICATION_MAX_LIMITS = {'fast': 12, 'balanced': 64, 'deep': 180}
JWT_TOKEN_LIMITS = {'fast': 16, 'balanced': 64, 'deep': 192}
# Broad sibling coverage is deliberately smaller than primary-origin coverage in fast/balanced.
# Authorized siblings remain available to specialist selectors even when they are not selected for
# the full ZAP/Nuclei/Nikto baseline. Deep preserves the wider broad sweep.
BROAD_SIBLING_ORIGIN_BASE_LIMITS = {'fast': 1, 'balanced': 3, 'deep': 8}
BROAD_SIBLING_ORIGIN_MAX_LIMITS = {'fast': 2, 'balanced': 5, 'deep': 12}
BROAD_SIBLING_ADAPTIVE_RATIO = 0.75
BROAD_SIBLING_TIMEOUT_FACTORS = {'fast': 0.50, 'balanced': 0.60, 'deep': 0.75}
SCAN_MODES = {
    'fast': {
        'broad': {'zap': 120, 'nuclei': 360, 'nikto': 60, 'ffuf': 50, 'session': 25},
        'parameter': {'sqlmap': 75, 'dalfox': 45, 'commix': 90, 'traversal': 35, 'idor': 18, 'authorization': 30, 'browser': 45, 'workflow': 40},
        'limits': {'sqlmap': 3, 'dalfox': 3, 'commix': 3, 'traversal': 3, 'idor': 3, 'authorization': 4, 'browser': 3, 'workflow': 3},
        'arjun': 45, 'arjun_limit': 3,
    },
    'balanced': {
        'broad': {'zap': 540, 'nuclei': 900, 'nikto': 150, 'ffuf': 120, 'session': 50},
        'parameter': {'sqlmap': 180, 'dalfox': 120, 'commix': 180, 'traversal': 75, 'idor': 45, 'authorization': 70, 'browser': 120, 'workflow': 105},
        # Raised from the previous 8-12 ceiling: each case already runs with its own independent
        # per-case timeout (the 'parameter' timeouts above), so more selected cases means more total
        # wall-clock time for this phase, not less time per case. The previous ceiling was small
        # enough that, on an application with hundreds of discovered parameterized endpoints, only a
        # small fraction of the real attack surface ever reached a specialist tool in 'balanced' mode.
        'limits': {'sqlmap': 15, 'dalfox': 15, 'commix': 12, 'traversal': 15, 'idor': 14, 'authorization': 17, 'browser': 15, 'workflow': 15},
        'arjun': 120, 'arjun_limit': 15,
    },
    'deep': {
        'broad': {'zap': 900, 'nuclei': 1500, 'nikto': 240, 'ffuf': 210, 'session': 90},
        'parameter': {'sqlmap': 300, 'dalfox': 210, 'commix': 300, 'traversal': 120, 'idor': 90, 'authorization': 120, 'browser': 210, 'workflow': 180},
        'limits': {'sqlmap': 18, 'dalfox': 18, 'commix': 14, 'traversal': 18, 'idor': 20, 'authorization': 24, 'browser': 20, 'workflow': 20},
        'arjun': 180, 'arjun_limit': 18,
    },
}
# Specialist budgets have a fixed base and a bounded adaptive overflow. The overflow is
# available only to high-value deferred request contracts selected by deterministic ranking.
ADAPTIVE_SPECIALIST_OVERFLOW = {
    'fast': {'arjun': 1, 'sqlmap': 1, 'dalfox': 1, 'commix': 1, 'traversal': 1, 'idor': 1, 'authorization': 1, 'browser': 1, 'workflow': 1},
    'balanced': {'arjun': 6, 'sqlmap': 6, 'dalfox': 6, 'commix': 5, 'traversal': 6, 'idor': 6, 'authorization': 6, 'browser': 6, 'workflow': 6},
    'deep': {'arjun': 6, 'sqlmap': 6, 'dalfox': 6, 'commix': 5, 'traversal': 6, 'idor': 8, 'authorization': 8, 'browser': 6, 'workflow': 6},
}
ADAPTIVE_HIGH_VALUE_PATH_HINTS = ('/api/', '/admin/', 'management', 'search', 'query', 'upload', 'download', 'callback', 'webhook', 'config', 'settings', 'profile', 'account')
AUTHORIZED_SCOPE_ORIGINS: set[str] = set()
AUTHORIZED_SCOPE_HOST_SUFFIXES: set[str] = set()
PRIMARY_SCOPE_TARGET = ''
CURRENT_SCAN_MODE = 'balanced'
BROAD_SCANNER_TIMEOUTS = dict(SCAN_MODES[CURRENT_SCAN_MODE]['broad'])
PARAMETER_TOOL_TIMEOUTS = dict(SCAN_MODES[CURRENT_SCAN_MODE]['parameter'])
PARAMETER_TOOL_CASE_LIMITS = dict(SCAN_MODES[CURRENT_SCAN_MODE]['limits'])
ARJUN_TIMEOUT = int(SCAN_MODES[CURRENT_SCAN_MODE]['arjun'])
ARJUN_ENDPOINT_LIMIT = int(SCAN_MODES[CURRENT_SCAN_MODE].get('arjun_limit', 1))

# Configures the explicit HTTP scope extension for this process; same-origin remains allowed by default.
def configure_authorized_scope(target: str, origins: list[str] | None=None, host_suffixes: list[str] | None=None) -> None:
    global PRIMARY_SCOPE_TARGET
    PRIMARY_SCOPE_TARGET = normalize_url(target)
    AUTHORIZED_SCOPE_ORIGINS.clear()
    AUTHORIZED_SCOPE_HOST_SUFFIXES.clear()
    for value in origins or []:
        origin = normalized_origin(str(value or '').strip())
        if origin:
            AUTHORIZED_SCOPE_ORIGINS.add(origin)
    for value in host_suffixes or []:
        suffix = str(value or '').strip().lower().lstrip('.').rstrip('.')
        if suffix and '://' not in suffix and '/' not in suffix:
            AUTHORIZED_SCOPE_HOST_SUFFIXES.add(suffix)

# Returns true only for the primary origin or an explicitly authorized origin/host suffix.
def url_in_authorized_scope(target: str, candidate: str) -> bool:
    return _url_in_explicit_scope(target, candidate, AUTHORIZED_SCOPE_ORIGINS, AUTHORIZED_SCOPE_HOST_SUFFIXES)

# Keeps target cookies on the primary origin; sibling origins are discovered and tested without credential leakage.
def scope_cookie_header(candidate: str, cookies: str) -> str:
    if not cookies:
        return ''
    base = PRIMARY_SCOPE_TARGET or candidate
    return cookies if same_origin(base, candidate) else ''

# Loads the timeouts and case limits for the selected scan profile.
def configure_scan_mode(mode: str) -> None:
    global CURRENT_SCAN_MODE, ARJUN_TIMEOUT, ARJUN_ENDPOINT_LIMIT
    selected = str(mode or 'balanced').lower()
    if selected not in SCAN_MODES:
        raise ValueError(f'Unknown scan mode: {mode}')
    CURRENT_SCAN_MODE = selected
    profile = SCAN_MODES[selected]
    BROAD_SCANNER_TIMEOUTS.clear()
    BROAD_SCANNER_TIMEOUTS.update(profile['broad'])
    PARAMETER_TOOL_TIMEOUTS.clear()
    PARAMETER_TOOL_TIMEOUTS.update(profile['parameter'])
    PARAMETER_TOOL_CASE_LIMITS.clear()
    PARAMETER_TOOL_CASE_LIMITS.update(profile['limits'])
    ARJUN_TIMEOUT = int(profile['arjun'])
    ARJUN_ENDPOINT_LIMIT = int(profile.get('arjun_limit', 1))
TIME_LIMIT_DIAGNOSES = {'timeout', 'time_limit_reached', 'timeout_with_partial_results', 'timeout_with_confirmed_finding', 'bounded_partial_scan'}
AUTO_INDEX_PARAMETERS = {'c', 'n', 'm', 's', 'd', 'o'}
OAST_PARAMETER_SCORES = {'url': 120, 'uri': 115, 'host': 115, 'hostname': 115, 'domain': 110, 'callback': 130, 'callback_url': 135, 'webhook': 135, 'webhook_url': 140, 'endpoint': 100, 'target': 95, 'dest': 100, 'destination': 105, 'redirect': 80, 'redirect_url': 90, 'next': 55, 'return': 55, 'fetch': 120, 'resource': 90, 'remote': 100, 'proxy': 105, 'image': 65, 'src': 70, 'file': 75, 'filename': 75, 'path': 60, 'page': 85, 'include': 105, 'template': 80, 'feed': 90, 'avatar': 65, 'document': 65, 'ip': 125, 'cmd': 145, 'command': 145, 'exec': 140, 'shell': 145, 'ping': 130}
OAST_PATH_HINTS = ('ssrf', 'webhook', 'callback', 'fetch', 'proxy', 'redirect', 'remote', 'url', 'include', 'exec', 'command', 'cmd')
OAST_URL_VALUE_PARAMETERS = {'url', 'uri', 'callback', 'callback_url', 'webhook', 'webhook_url', 'endpoint', 'target', 'dest', 'destination', 'redirect', 'redirect_url', 'next', 'return', 'fetch', 'resource', 'remote', 'proxy', 'image', 'src', 'file', 'filename', 'path', 'page', 'include', 'template', 'feed', 'avatar', 'document'}
OAST_COMMAND_PARAMETERS = {'ip', 'host', 'hostname', 'cmd', 'command', 'exec', 'shell', 'ping', 'target', 'domain'}

# Describes one MCP tool together with its server file and runtime dependency.
@dataclass(frozen=True)
class ToolSpec:
    name: str
    server: str
    tool: str
    executable: str = ''
    module: str = ''
    required: bool = True
BASE_TOOLS = (ToolSpec('ffuf', 'pentest_tools/discovery/ffufServer.py', 'run_ffuf_fuzz', 'ffuf'), ToolSpec('zap', 'pentest_tools/scanning/zapServer.py', 'run_zap_scan', module='zapv2'), ToolSpec('nuclei', 'pentest_tools/scanning/nucleiServer.py', 'run_nuclei_scan', 'nuclei'), ToolSpec('session', 'custom_checks/sessionServer.py', 'run_session_scan'), ToolSpec('nikto', 'pentest_tools/scanning/niktoServer.py', 'run_nikto_scan', 'nikto'))
ARJUN_TOOL = ToolSpec('arjun', 'pentest_tools/discovery/arjunServer.py', 'run_arjun_scan', 'arjun')
PARAMETER_TOOLS = (ToolSpec('sqlmap', 'pentest_tools/exploitation/sqlmapServer.py', 'run_sqlmap_scan', 'sqlmap'), ToolSpec('dalfox', 'pentest_tools/exploitation/dalfoxServer.py', 'run_dalfox_scan', 'dalfox'), ToolSpec('commix', 'pentest_tools/exploitation/commixServer.py', 'run_commix_scan', 'commix'), ToolSpec('traversal', 'custom_checks/traversalServer.py', 'run_traversal_scan'), ToolSpec('idor', 'pentest_tools/exploitation/idorForgeServer.py', 'run_idor_check', 'idor-forge'))
AUTHORIZATION_TOOL = ToolSpec('authorization', 'custom_checks/authorizationServer.py', 'run_authorization_scan')
WORKFLOW_TOOLS = (ToolSpec('browser', 'custom_checks/browserServer.py', 'run_browser_scan', module='playwright', required=False), ToolSpec('workflow', 'custom_checks/workflowServer.py', 'run_workflow_scan'))
OPTIONAL_TOOLS = (ToolSpec('jwt', 'custom_checks/jwtServer.py', 'run_jwt_scan', module='jwt'), ToolSpec('interactsh', 'pentest_tools/discovery/interactshServer.py', 'run_interactsh_client', 'interactsh-client', required=False), ToolSpec('report', 'reporting/reportServer.py', 'generate_report', module='weasyprint'))
ALL_TOOLS = (*BASE_TOOLS, ARJUN_TOOL, *PARAMETER_TOOLS, AUTHORIZATION_TOOL, *WORKFLOW_TOOLS, *OPTIONAL_TOOLS)
TOOL_SCOPES = {'ffuf': 'base', 'zap': 'base', 'nuclei': 'base', 'session': 'base', 'nikto': 'base', 'arjun': 'url', 'sqlmap': 'parameterized', 'dalfox': 'parameterized', 'commix': 'parameterized', 'traversal': 'parameterized', 'idor': 'numeric', 'authorization': 'authorization', 'browser': 'browser', 'workflow': 'workflow', 'jwt': 'jwt', 'interactsh': 'oast'}
TOOL_DESCRIPTIONS = {'ffuf': 'Hidden resource and endpoint discovery with credential-isolated path fuzzing.', 'zap': 'Session-aware crawling, passive analysis and prioritized active testing.', 'nuclei': 'Template-based exposure, misconfiguration, known-vulnerability and bounded DAST checks on discovered parameterized URLs.', 'session': 'Cookie flags, bounded session uniqueness and fixation indicators.', 'nikto': 'Web-server hardening and exposed-resource checks.', 'arjun': 'Hidden GET/POST parameter discovery.', 'sqlmap': 'SQL-injection confirmation on discovered request contracts.', 'dalfox': 'Reflected and stored XSS testing.', 'commix': 'Operating-system command-injection testing.', 'traversal': 'Path-traversal and local-file-inclusion verification.', 'idor': 'Single-reference numeric object differential checks.', 'authorization': 'Read-only anonymous and optional two-account authorization differentials on discovered high-value GET requests.', 'browser': 'Chromium verification of DOM, reflected and stored XSS using harmless markers.', 'workflow': 'Bounded CSRF, upload, authentication-throttling and CAPTCHA workflow checks.', 'jwt': 'JWT structure and claim analysis.', 'interactsh': 'Out-of-band callback confirmation.'}

# The agentic registry exposes the MCP tools available to the planner.
def agentic_registry() -> dict[str, tuple[str, str, str, str]]:

    return {spec.name: (spec.server, spec.tool, TOOL_SCOPES[spec.name], TOOL_DESCRIPTIONS[spec.name]) for spec in ALL_TOOLS if spec.name in TOOL_SCOPES}

# Returns the configured fixed specialist base for the active profile.
def specialist_base_limit(tool: str) -> int:

    name = str(tool or '').lower()
    if name == 'arjun':
        return ARJUN_ENDPOINT_LIMIT
    if name in PARAMETER_TOOL_CASE_LIMITS:
        return int(PARAMETER_TOOL_CASE_LIMITS[name])
    return 0

# Returns the maximum specialist action count after bounded adaptive overflow.
def adaptive_tool_max_limit(tool: str) -> int:

    name = str(tool or '').lower()
    base = specialist_base_limit(name)
    return base + int(ADAPTIVE_SPECIALIST_OVERFLOW.get(CURRENT_SCAN_MODE, {}).get(name, 0)) if base else 0

# Final XSS verification has an independent base and adaptive ceiling for every active profile.
def final_browser_verification_limit() -> int:
    return int(FINAL_BROWSER_VERIFICATION_LIMITS.get(CURRENT_SCAN_MODE, 40))

def final_browser_verification_max_limit() -> int:
    base = final_browser_verification_limit()
    return max(base, int(FINAL_BROWSER_VERIFICATION_MAX_LIMITS.get(CURRENT_SCAN_MODE, base)))

# JWT analysis is local/cheap and therefore keeps a generous independent unique-token allowance per profile.
def jwt_token_limit() -> int:
    return int(JWT_TOKEN_LIMITS.get(CURRENT_SCAN_MODE, 64))


# Scores an unresolved XSS candidate for the deterministic final Chromium pass.
def final_xss_verification_priority(finding: dict[str, Any], case: dict[str, Any], context_score: int=0) -> int:
    score = max(0, int(context_score))
    parameter = str(finding.get('parameter') or '').strip().lower()
    parameters = _case_field_names(case)
    if parameter:
        score += 30
    if parameter and parameter in parameters:
        score += 18
    if parameters & XSS_HINTS:
        score += 18
    if case.get('discovery_source') == 'playwright_network':
        score += 18
    if case.get('client_sources') or case.get('client_sinks') or case.get('client_side_evidence'):
        score += 24
    response = case.get('browser_response') if isinstance(case.get('browser_response'), dict) else {}
    if response.get('observed') is True:
        try:
            status = int(response.get('status') or 0)
        except (TypeError, ValueError):
            status = 0
        if 200 <= status < 400:
            score += 15
    if str(case.get('method') or 'GET').upper() == 'POST':
        score += 8
    confidence = str(finding.get('confidence') or '').lower()
    if confidence == 'high':
        score += 16
    elif confidence == 'medium':
        score += 8
    if finding.get('evidence') or finding.get('payload'):
        score += 8
    return max(1, score)

# Extends the final Chromium XSS-verification base only when deferred candidates remain close to
# the deterministic priority cutoff. Every candidate is already an unresolved XSS finding with a
# compatible request contract, so the score threshold is the additional overflow gate.
def select_adaptive_final_xss_candidates(ranked: list[tuple[int, dict[str, Any]]]) -> list[dict[str, Any]]:
    base = max(1, final_browser_verification_limit())
    maximum = max(base, final_browser_verification_max_limit())
    ordered = sorted(ranked, key=lambda item: -int(item[0]))
    selected = [{**case, 'final_xss_priority_score': int(score)} for score, case in ordered[:base]]
    if len(ordered) <= base or len(selected) < base or maximum <= base:
        return selected
    cutoff = int(ordered[base - 1][0])
    threshold = max(1, (cutoff * 3 + 3) // 4)
    for score, case in ordered[base:]:
        if len(selected) >= maximum:
            break
        if int(score) < threshold:
            continue
        selected.append({
            **case,
            'final_xss_priority_score': int(score),
            'adaptive_final_xss_budget': True,
            'adaptive_final_xss_base': base,
            'adaptive_final_xss_max': maximum,
            'adaptive_final_xss_threshold': threshold,
        })
    return selected

# Summarizes how much adaptive specialist overflow was actually used by one selection.
def specialist_budget_diagnostics(tool: str, cases: list[dict[str, Any]]) -> dict[str, int]:

    base = specialist_base_limit(tool)
    maximum = adaptive_tool_max_limit(tool) or base
    adaptive_used = sum(1 for case in cases if isinstance(case, dict) and case.get('adaptive_budget'))
    return {'base': base, 'adaptive_max': maximum, 'selected': len(cases), 'adaptive_used': adaptive_used}

# Per-tool limits define how many actions each scanner may receive in the active profile.
def tool_action_limit(tool: str, include_adaptive: bool=False) -> int:

    name = str(tool or '').lower()
    if name == 'arjun':
        return adaptive_tool_max_limit(name) if include_adaptive else ARJUN_ENDPOINT_LIMIT
    if name == 'interactsh':
        return 3 if CURRENT_SCAN_MODE == 'deep' else 2 if CURRENT_SCAN_MODE == 'balanced' else 1
    if name == 'jwt':
        return jwt_token_limit()
    if name in {'zap', 'nuclei', 'nikto'}:
        return 13 if CURRENT_SCAN_MODE == 'deep' else 7 if CURRENT_SCAN_MODE == 'balanced' else 3
    if name in PARAMETER_TOOL_CASE_LIMITS:
        return adaptive_tool_max_limit(name) if include_adaptive else PARAMETER_TOOL_CASE_LIMITS[name]
    return 1

# Broad scanners follow a stable order chosen to preserve session health and discovery quality.
def broad_tool_order(authenticated: bool) -> tuple[str, ...]:

    return ('ffuf', 'zap', 'nuclei', 'session', 'nikto')

# Gives each tool a rank used to order planned actions.
def tool_execution_rank(tool: str, authenticated: bool) -> int:

    broad = broad_tool_order(authenticated)
    if tool in broad:
        return broad.index(tool)
    phases = {'arjun': 10, 'sqlmap': 20, 'dalfox': 21, 'commix': 22, 'traversal': 23, 'idor': 24, 'authorization': 25, 'browser': 26, 'workflow': 27, 'jwt': 30, 'interactsh': 31}
    return phases.get(str(tool or '').lower(), 99)

# Adds a directory to PATH only when it is not already present.
def _prepend_path(path: Path) -> None:
    if not path.is_dir():
        return
    resolved = str(path.resolve())
    current = [part for part in os.environ.get('PATH', '').split(os.pathsep) if part]
    keys = {os.path.normcase(os.path.abspath(part)) for part in current}
    if os.path.normcase(resolved) not in keys:
        os.environ['PATH'] = resolved + os.pathsep + os.environ.get('PATH', '')

# Rebuilds the runtime PATH so installed scanner launchers can be found.
def configure_runtime_path() -> list[str]:

    runtime = load_runtime_config()
    candidates: list[Path] = [LOCAL_BIN]
    candidates += [Path(value) for value in runtime.get('tool_directories', []) if isinstance(value, str)]
    executables = runtime.get('executables', {})
    if isinstance(executables, dict):
        candidates += [Path(value).expanduser().parent for value in executables.values() if isinstance(value, str)]
    try:
        scripts = sysconfig.get_path('scripts', scheme='nt_user' if os.name == 'nt' else 'posix_user')
        if scripts:
            candidates.append(Path(scripts))
    except (KeyError, ValueError):
        pass
    try:
        import site
        candidates.append(Path(site.USER_BASE) / ('Scripts' if os.name == 'nt' else 'bin'))
    except Exception:
        pass
    added: list[str] = []
    seen: set[str] = set()
    for path in candidates:
        try:
            key = os.path.normcase(str(path.expanduser().resolve()))
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)
        if path.expanduser().is_dir():
            _prepend_path(path.expanduser())
            added.append(str(path.expanduser().resolve()))
    return added

# Finds the executable or launcher used for a scanner.
def resolve_executable(name: str) -> str | None:
    configure_runtime_path()
    found = shutil.which(name)
    if found:
        return str(Path(found).resolve())
    value = load_runtime_config().get('executables', {}).get(name)
    return str(Path(value).resolve()) if isinstance(value, str) and Path(value).is_file() else None

# Reads a server file and lists the functions declared in its source.
def _declared_functions(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding='utf-8', errors='replace'))
    except (OSError, SyntaxError):
        return set()
    return {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}

# Server path lookup resolves a server filename (optionally nested in a subdirectory) inside the project directory.
def resolve_server_path(filename: str, required_tool: str='') -> Path:

    candidate = (SERVERS / filename).resolve()
    if candidate.is_relative_to(SERVERS):
        return candidate
    return (SERVERS / Path(filename).name).resolve()

# Interpreter validation confirms that project dependencies can be imported before a server is launched.
def _python_has_project_deps(python: str) -> bool:

    try:
        probe = subprocess.run([python, '-c', 'import requests, fastmcp, jwt'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30, check=False)
        return probe.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False

# Chooses the Python interpreter used to start MCP servers.
@functools.lru_cache(maxsize=1)
def _server_python() -> str:

    current = sys.executable
    configured = load_runtime_config().get('python_executable')
    if not (isinstance(configured, str) and Path(configured).is_file()):
        return current
    if os.path.normcase(configured) == os.path.normcase(current):
        return current
    if _python_has_project_deps(current):
        return current
    if _python_has_project_deps(configured):
        return configured
    return current

# Builds the environment passed to a new MCP server process.
def _server_env() -> dict[str, str]:
    configure_runtime_path()
    env = {str(key): str(value) for key, value in os.environ.items()}
    paths = [part for part in env.get('PYTHONPATH', '').split(os.pathsep) if part]
    if str(SERVERS) not in paths:
        paths.insert(0, str(SERVERS))
    if str(ROOT) not in paths:
        paths.insert(0, str(ROOT))
    warning_filters = [value for value in env.get('PYTHONWARNINGS', '').split(',') if value]
    authlib_filter = 'ignore:authlib.jose module is deprecated'
    if authlib_filter not in warning_filters:
        warning_filters.append(authlib_filter)
    env.update({'PATH': os.environ.get('PATH', ''), 'PYTHONPATH': os.pathsep.join(paths), 'PYTHONUNBUFFERED': '1', 'PYTHONIOENCODING': 'utf-8', 'PYTHONWARNINGS': ','.join(warning_filters), 'SECOPS_PROJECT_ROOT': str(ROOT)})
    return env
_HTTP_SERVER_PROCESSES: dict[str, subprocess.Popen] = {}
_HTTP_SERVER_LOGS: dict[str, Path] = {}

# Port probing detects whether the unified MCP endpoint is already listening locally.
def _port_open(host: str, port: int, timeout: float=0.25) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False

# The only MCP process log belongs to the unified SecOps interface.
def _http_server_log() -> Path:
    directory = ROOT / '.secops_tmp' / 'mcp-http'
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f'{MCP_UNIFIED_SERVICE}.log'

# Stops the single MCP server process started by this orchestrator.
def _stop_owned_http_server() -> None:
    process = _HTTP_SERVER_PROCESSES.pop(MCP_UNIFIED_SERVICE, None)
    if process is not None and process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

# Stops the unified MCP process owned by the current orchestrator.
def shutdown_mcp_http_servers() -> None:
    _stop_owned_http_server()
atexit.register(shutdown_mcp_http_servers)

# Reads the end of the unified server log to explain a startup failure.
def _server_startup_log() -> str:
    path = _HTTP_SERVER_LOGS.get(MCP_UNIFIED_SERVICE)
    if not path or not path.is_file():
        return ''
    try:
        return path.read_text(encoding='utf-8', errors='replace')[-6000:].strip()
    except OSError:
        return ''

# Returns the latest report-stage progress markers emitted by the unified MCP server.
def _server_report_progress_log() -> str:
    path = _HTTP_SERVER_LOGS.get(MCP_UNIFIED_SERVICE)
    if not path or not path.is_file():
        return ''
    try:
        lines = [line.strip() for line in path.read_text(encoding='utf-8', errors='replace').splitlines() if '[REPORT SERVER]' in line]
    except OSError:
        return ''
    return '\n'.join(lines[-8:])

# Gives report rendering a dedicated budget independent from ordinary scanner calls.
def _report_render_timeout(payload_bytes: int) -> float:
    mib = max(1, math.ceil(max(0, int(payload_bytes)) / float(1024 * 1024)))
    adaptive = MCP_REPORT_RENDER_TIMEOUT + (mib * MCP_REPORT_RENDER_SECONDS_PER_MIB)
    return min(MCP_REPORT_RENDER_TIMEOUT_MAX, max(MCP_REPORT_RENDER_TIMEOUT, adaptive))

# Starts the one MCP process that imports and exposes the complete tool catalogue.
def _ensure_http_server(*, restart: bool=False) -> str:
    server = resolve_server_path(UNIFIED_MCP_SERVER)
    port = mcp_http_port(MCP_UNIFIED_SERVICE)
    url = mcp_http_url(MCP_UNIFIED_SERVICE)
    if not server.is_file():
        raise FileNotFoundError(f'Unified MCP server not found: {server}')
    if restart:
        _stop_owned_http_server()
    if _port_open('127.0.0.1', port):
        return url
    existing = _HTTP_SERVER_PROCESSES.get(MCP_UNIFIED_SERVICE)
    if existing is not None and existing.poll() is None:
        process = existing
    else:
        log_path = _http_server_log()
        _HTTP_SERVER_LOGS[MCP_UNIFIED_SERVICE] = log_path
        log_handle = open(log_path, 'a', encoding='utf-8', buffering=1)
        env = _server_env()
        env.update({'SECOPS_MCP_HOST': '127.0.0.1', 'SECOPS_MCP_PORT': str(port)})
        process = subprocess.Popen([_server_python(), str(server)], cwd=str(ROOT), env=env, stdout=log_handle, stderr=subprocess.STDOUT, text=True)
        log_handle.close()
        _HTTP_SERVER_PROCESSES[MCP_UNIFIED_SERVICE] = process
    deadline = time.monotonic() + max(3.0, MCP_CONNECT_TIMEOUT)
    while time.monotonic() < deadline:
        if _port_open('127.0.0.1', port):
            return url
        if process.poll() is not None:
            detail = _server_startup_log()
            raise RuntimeError('Unified SecOps HTTP MCP server exited during startup' + (f': {detail}' if detail else '.'))
        time.sleep(0.15)
    detail = _server_startup_log()
    raise TimeoutError(f'Timed out waiting for unified MCP HTTP service at {url}' + (f'. Server log: {detail}' if detail else ''))

# Transport diagnosis recognizes failures raised by the MCP HTTP layer.
def _http_transport_failure(exc: BaseException) -> bool:
    text = f'{type(exc).__name__}: {exc}'.lower()
    return any((token in text for token in ('connection refused', 'connecterror', 'connectionerror', 'server disconnected', 'connection closed', 'closedresourceerror', 'brokenresourceerror', 'all connection attempts failed')))

# Extracts the structured tool payload from an MCP response.
def _extract_response(response: Any) -> tuple[Any, bool, str]:
    is_error = bool(getattr(response, 'is_error', False) or getattr(response, 'isError', False))
    for name in ('data', 'structured_content', 'structuredContent'):
        value = getattr(response, name, None)
        if value is not None:
            return (value, is_error, name)
    content = getattr(response, 'content', response)
    if isinstance(content, list):
        values = [getattr(item, 'text', item.get('text') if isinstance(item, dict) else item) for item in content]
        content = values[0] if len(values) == 1 else values
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except json.JSONDecodeError:
            pass
    return (content, is_error, 'content')

# Converts an exception into a short diagnosis used in scan results.
def diagnose_error(text: str) -> str:
    lowered = text.lower()
    rules = ((('no such file', 'not found', 'winerror 2'), 'missing_file_or_executable'), (('no module named', 'modulenotfounderror'), 'missing_python_dependency'), (('connection refused', 'failed to establish'), 'service_unreachable'), (('timed out', 'timeout'), 'timeout'), (('permission denied', 'access is denied'), 'permission_denied'), (('tool not found', 'method not found', 'unknown tool'), 'mcp_tool_name_mismatch'), (('connection closed', 'closedresourceerror', 'end of file'), 'mcp_server_crashed'))
    return next((cause for needles, cause in rules if any((item in lowered for item in needles))), 'scanner_or_mcp_error')

# Result construction keeps tool status, diagnosis, output, and findings in one common shape.
def _result(tool: str, target: str, status: str, output: Any, diagnosis: str='', **extra: Any) -> dict[str, Any]:
    result = {'tool': tool, 'status': status, 'target': target, 'output': output, 'vulnerabilities': []}
    if diagnosis:
        result['diagnosis'] = diagnosis
    result.update(extra)
    return result

# Counts security findings and observations in one tool result.
def _finding_counts(result: dict[str, Any]) -> tuple[int, int, int]:
    findings = [item for item in result.get('vulnerabilities') or [] if isinstance(item, dict)]
    security = 0
    for item in findings:
        category = str(item.get('category', '')).lower()
        risk = str(item.get('risk', 'info')).lower()
        if category in {'vulnerability', 'candidate'} or (not category and risk not in {'', 'info'}):
            security += 1
    return (len(findings), security, len(findings) - security)

# Timeout detection separates budget exhaustion from ordinary tool failures.
def _is_time_limited(result: dict[str, Any]) -> bool:
    diagnosis = str(result.get('diagnosis', '')).lower()
    text = ' '.join((str(result.get(key, '')) for key in ('output', 'stderr', 'stdout'))).lower()
    return bool(result.get('timed_out') or diagnosis in TIME_LIMIT_DIAGNOSES or 'timeout' in diagnosis or ('timed out' in text) or ('time limit' in text) or ('time budget' in text))

# Keeps useful partial results while marking a run that reached its limit.
def _normalize_time_limit(result: dict[str, Any], tool: str, target: str) -> dict[str, Any]:

    # Reporting is an artifact-generation stage, not a scanner. Preserve its concrete
    # renderer/serialization error instead of rewriting it as a scan coverage timeout.
    if str(tool or '').lower() == 'report':
        return result
    if result.get('hard_failure') or not _is_time_limited(result):
        return result
    total, security, observations = _finding_counts(result)
    previous = str(result.get('diagnosis', ''))
    result['status'] = 'partial'
    result['timed_out'] = True
    result['time_limit_reached'] = True
    result['diagnosis'] = 'time_limit_reached'
    if previous and previous != 'time_limit_reached':
        result['original_diagnosis'] = previous
    result.setdefault('tool', tool)
    result.setdefault('target', target)
    result.setdefault('vulnerabilities', [])
    result['output'] = f'Configured scan time budget reached. Findings preserved: {total} (security/candidates: {security}, observations/discovery: {observations}). Coverage is incomplete, but the scanner did not fail.'
    return result

# Brings raw tool output into the common result format.
def _normalize_result(data: Any, spec: ToolSpec, target: str, elapsed: float, is_error: bool, shape: str) -> dict[str, Any]:
    if isinstance(data, dict):
        result = dict(data)
    else:
        result = _result(spec.name, target, 'error' if is_error else 'success', data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, default=str))
    result.setdefault('tool', spec.name)
    result.setdefault('target', target)
    result.setdefault('output', '')
    result.setdefault('vulnerabilities', [])
    status = 'error' if is_error else str(result.get('status', 'success')).lower()
    result['status'] = status if status in {'success', 'error', 'skipped', 'partial'} else 'error'
    result['_meta'] = {'server': spec.server, 'resolved_server': str(resolve_server_path(spec.server, spec.tool)), 'mcp_server': str(resolve_server_path(UNIFIED_MCP_SERVER)), 'duration_seconds': round(elapsed, 3), 'response_shape': shape}
    if result['status'] == 'error':
        result.setdefault('diagnosis', diagnose_error(str(result.get('output', ''))))
    return _normalize_time_limit(result, spec.name, target)

# Calls one MCP tool and returns a normalized result.
async def call_mcp(server_file: str, tool_name: str, arguments: dict[str, Any], timeout_seconds: float=MCP_TOOL_TIMEOUT) -> dict[str, Any]:
    spec = next((item for item in ALL_TOOLS if item.server == server_file and item.tool == tool_name), ToolSpec(tool_name, server_file, tool_name))
    server = resolve_server_path(server_file, tool_name)
    target = str(arguments.get('target_url', ''))
    display_target = compact_log_url(target)
    started = time.monotonic()
    if not server.is_file():
        return _result(spec.name, target, 'error', f'MCP server not found: {server}', 'missing_mcp_server_file')
    effective_arguments = dict(arguments)
    temporary_output: Path | None = None
    report_transfer_meta: dict[str, Any] = {}
    if spec.name == 'nuclei' and (not effective_arguments.get('output_file')):
        temporary_dir = ROOT / '.secops_tmp'
        temporary_dir.mkdir(parents=True, exist_ok=True)
        temporary_output = temporary_dir / f'nuclei-{uuid.uuid4().hex}.jsonl'
        effective_arguments['output_file'] = str(temporary_output)

    async def invoke_report_chunked(client: Client, encoded: bytes) -> tuple[Any, bool, str]:
        if len(encoded) > MCP_REPORT_MAX_BYTES:
            raise ValueError(f'Report MCP payload is {len(encoded)} bytes, above the configured {MCP_REPORT_MAX_BYTES}-byte safety ceiling.')
        compressed = zlib.compress(encoded, level=6)
        upload_id = uuid.uuid4().hex
        digest = hashlib.sha256(compressed).hexdigest()
        minimum_chunk_bytes = max(1, math.ceil(len(compressed) / MCP_REPORT_MAX_CHUNKS))
        chunk_bytes = min(512 * 1024, max(MCP_REPORT_CHUNK_BYTES, minimum_chunk_bytes))
        chunks = [compressed[index:index + chunk_bytes] for index in range(0, len(compressed), chunk_bytes)] or [b'']
        if len(chunks) > MCP_REPORT_MAX_CHUNKS:
            raise ValueError(f'Report MCP payload requires {len(chunks)} chunks, above the configured {MCP_REPORT_MAX_CHUNKS}-chunk safety ceiling.')
        transfer_started = time.monotonic()
        render_timeout = _report_render_timeout(len(encoded))
        print(
            f'[REPORT HTTP] payload={len(encoded)} bytes; compressed={len(compressed)} bytes; chunks={len(chunks)}; chunk_size<={chunk_bytes} bytes; transfer budget={MCP_REPORT_TRANSFER_TIMEOUT:.0f}s; render budget={render_timeout:.0f}s.',
            flush=True,
        )
        try:
            for index, chunk in enumerate(chunks):
                remaining = MCP_REPORT_TRANSFER_TIMEOUT - (time.monotonic() - transfer_started)
                if remaining <= 0:
                    raise TimeoutError(f'Report HTTP chunk transfer exceeded its {MCP_REPORT_TRANSFER_TIMEOUT:.0f}-second budget after {index}/{len(chunks)} chunks.')
                response = await asyncio.wait_for(
                    client.call_tool('upload_report_chunk', {
                        'upload_id': upload_id,
                        'chunk_index': index,
                        'total_chunks': len(chunks),
                        'compressed_sha256': digest,
                        'uncompressed_bytes': len(encoded),
                        'chunk_b64': base64.b64encode(chunk).decode('ascii'),
                    }),
                    timeout=min(MCP_REPORT_CHUNK_TIMEOUT, remaining),
                )
                data, is_error, _ = _extract_response(response)
                if is_error or not isinstance(data, dict) or str(data.get('status', '')).lower() != 'success':
                    raise RuntimeError(f'Report chunk {index + 1}/{len(chunks)} was rejected: {data}')
                print(
                    f'[REPORT HTTP] chunk {index + 1}/{len(chunks)} accepted; compressed bytes received={int(data.get("received_compressed_bytes", 0) or 0)}.',
                    flush=True,
                )
            transfer_elapsed = time.monotonic() - transfer_started
            print(
                f'[REPORT HTTP] upload complete: {len(chunks)}/{len(chunks)} chunks accepted in {transfer_elapsed:.1f}s; requesting reconstruction and report rendering.',
                flush=True,
            )
            render_started = time.monotonic()
            final_response = await asyncio.wait_for(
                client.call_tool('generate_report_from_chunks', {'upload_id': upload_id}),
                timeout=render_timeout,
            )
            render_elapsed = time.monotonic() - render_started
            report_transfer_meta.update({
                'report_payload_transport': 'http_chunked',
                'report_payload_bytes': len(encoded),
                'report_compressed_bytes': len(compressed),
                'report_http_chunks': len(chunks),
                'report_transfer_seconds': round(transfer_elapsed, 3),
                'report_render_seconds': round(render_elapsed, 3),
                'report_render_timeout_seconds': render_timeout,
            })
            print(f'[REPORT HTTP] report service returned after reconstruction/rendering in {render_elapsed:.1f}s.', flush=True)
            return _extract_response(final_response)
        except Exception:
            try:
                await asyncio.wait_for(client.call_tool('discard_report_upload', {'upload_id': upload_id}), timeout=min(30.0, MCP_REPORT_CHUNK_TIMEOUT))
            except Exception:
                pass
            raise

    # Sends MCP requests only through the unified HTTP endpoint. Oversized report inputs are
    # compressed, split into bounded HTTP tool calls, reconstructed in memory by the report
    # service, and then rendered by a final HTTP tool call. No filesystem handoff is used.
    async def invoke(url: str) -> tuple[Any, bool, str]:
        async with Client(url) as client:
            if spec.name == 'report':
                encoded = json.dumps(effective_arguments, ensure_ascii=False, default=str).encode('utf-8')
                if len(encoded) > MCP_REPORT_INLINE_MAX_BYTES:
                    print(
                        f'[INFO] Report MCP input is {len(encoded)} bytes; sending it as bounded HTTP chunks through the unified MCP endpoint.',
                        flush=True,
                    )
                    return await invoke_report_chunked(client, encoded)
                try:
                    render_timeout = _report_render_timeout(len(encoded))
                    print(f'[REPORT HTTP] inline report request; payload={len(encoded)} bytes; render budget={render_timeout:.0f}s.', flush=True)
                    response = await asyncio.wait_for(client.call_tool(tool_name, effective_arguments), timeout=render_timeout)
                    report_transfer_meta.update({'report_payload_transport': 'http_inline', 'report_payload_bytes': len(encoded), 'report_http_chunks': 1, 'report_render_timeout_seconds': render_timeout})
                    return _extract_response(response)
                except Exception as exc:
                    detail = f'{type(exc).__name__}: {exc}'.lower()
                    if '413' not in detail and 'content too large' not in detail and 'request entity too large' not in detail and 'payload too large' not in detail:
                        raise
                    print('[INFO] Inline report request was rejected as too large; retrying the same report through bounded MCP/HTTP chunks.', flush=True)
                    return await invoke_report_chunked(client, encoded)
            return _extract_response(await client.call_tool(tool_name, effective_arguments))
    try:
        url = await asyncio.to_thread(_ensure_http_server)
        operation_timeout = timeout_seconds + MCP_CONNECT_TIMEOUT
        if spec.name == 'report':
            operation_timeout = MCP_REPORT_TRANSFER_TIMEOUT + MCP_REPORT_RENDER_TIMEOUT_MAX + (2 * MCP_CONNECT_TIMEOUT)
        try:
            data, is_error, shape = await asyncio.wait_for(invoke(url), timeout=operation_timeout)
        except Exception as first_exc:
            if not _http_transport_failure(first_exc):
                raise
            url = await asyncio.to_thread(_ensure_http_server, restart=True)
            data, is_error, shape = await asyncio.wait_for(invoke(url), timeout=operation_timeout)
        result = _normalize_result(data, spec, target, time.monotonic() - started, is_error, shape)
        result.setdefault('_meta', {})['mcp_transport'] = 'streamable_http'
        result.setdefault('_meta', {})['mcp_url'] = url
        if report_transfer_meta:
            result.setdefault('_meta', {}).update(report_transfer_meta)
    except (KeyboardInterrupt, asyncio.CancelledError):
        raise
    except Exception as exc:
        exception_text = f'{type(exc).__name__}: {exc}'
        exception_diagnosis = diagnose_error(exception_text)
        if exception_diagnosis == 'timeout':
            if spec.name == 'report':
                progress = _server_report_progress_log()
                message = 'Report generation exceeded its dedicated MCP/HTTP transfer or rendering time budget.'
                if progress:
                    message += f' Last report-server progress:\n{progress}'
                result = _result(spec.name, target, 'partial', message, 'report_time_limit_reached', timed_out=True, time_limit_reached=True, traceback=traceback.format_exc(), _meta={'server': str(server), 'duration_seconds': round(time.monotonic() - started, 3), 'mcp_transport': 'streamable_http', 'mcp_url': mcp_http_url(MCP_UNIFIED_SERVICE)})
            else:
                result = _result(spec.name, target, 'partial', f'{spec.name} reached the orchestrator/MCP HTTP time budget. Coverage is incomplete; this is not classified as a scanner error.', 'time_limit_reached', timed_out=True, time_limit_reached=True, traceback=traceback.format_exc(), _meta={'server': str(server), 'duration_seconds': round(time.monotonic() - started, 3), 'mcp_transport': 'streamable_http', 'mcp_url': mcp_http_url(MCP_UNIFIED_SERVICE)})
        else:
            detail = _server_startup_log()
            message = f'MCP HTTP communication failed: {exception_text}'
            if detail:
                message += f' | server log: {detail}'
            result = _result(spec.name, target, 'error', message, diagnose_error(message), traceback=traceback.format_exc(), _meta={'server': str(server), 'duration_seconds': round(time.monotonic() - started, 3), 'mcp_transport': 'streamable_http', 'mcp_url': mcp_http_url(MCP_UNIFIED_SERVICE)})
    finally:
        if temporary_output:
            temporary_output.unlink(missing_ok=True)
    result = _normalize_time_limit(result, spec.name, target)
    if result.get('status') == 'error':
        print(f"\n[SCANNER ERROR] {spec.name}: {display_target}\n  {result.get('output', '')}", file=sys.stderr)
    return result

# Calls one MCP tool while printing periodic progress messages.
async def call_mcp_with_progress(spec: ToolSpec, arguments: dict[str, Any], *, timeout_seconds: float=MCP_TOOL_TIMEOUT) -> dict[str, Any]:

    target = str(arguments.get('target_url', ''))
    display_target = compact_log_url(target)
    scanner_limit = arguments.get('timeout')
    limit_text = f', scanner limit {scanner_limit}s' if scanner_limit else ''
    print(f'    [RUNNING ] {spec.name}: {display_target}{limit_text}', flush=True)
    started = time.monotonic()
    task = asyncio.create_task(call_mcp(spec.server, spec.tool, arguments, timeout_seconds=timeout_seconds))
    while True:
        done, _ = await asyncio.wait({task}, timeout=SCANNER_PROGRESS_INTERVAL)
        if task in done:
            return await task
        elapsed = int(time.monotonic() - started)
        print(f'    [WAITING ] {spec.name}: still running after {elapsed}s', flush=True)

# Checks one expected tool name against the catalogue exposed by the unified MCP service.
def _tool_live_check(spec: ToolSpec, url: str, names: set[str]) -> dict[str, str]:
    if spec.tool not in names:
        return {'level': 'error' if spec.required else 'warning', 'component': spec.name, 'cause': 'mcp_runtime_tool_missing', 'detail': f'{url} does not expose {spec.tool}()'}
    return {'level': 'ok', 'component': spec.name, 'cause': 'mcp_http_handshake_ok', 'detail': f'{url}: {spec.tool}()'}

# One live handshake validates every tool exposed by the single MCP endpoint.
async def _run_live_checks() -> list[dict[str, str]]:
    try:
        url = await asyncio.to_thread(_ensure_http_server)
        async with Client(url) as client:
            tools = await asyncio.wait_for(client.list_tools(), timeout=MCP_CONNECT_TIMEOUT)
        names = {str(getattr(tool, 'name', '')) for tool in tools}
        return [_tool_live_check(spec, url, names) for spec in ALL_TOOLS]
    except Exception as exc:
        detail = _server_startup_log()
        message = f'{type(exc).__name__}: {exc}' + (f' | server log: {detail}' if detail else '')
        return [
            {'level': 'error' if spec.required else 'warning', 'component': spec.name, 'cause': 'mcp_http_handshake_failed', 'detail': message}
            for spec in ALL_TOOLS
        ]

# Nikto validation confirms that the configured runtime can start successfully.
def _nikto_runtime_check(executable: str) -> tuple[bool, str]:

    try:
        completed = subprocess.run([executable, '-Version'], cwd=str(ROOT), env=_server_env(), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30, shell=False)
    except Exception as exc:
        return (False, f'Nikto runtime probe failed: {type(exc).__name__}: {exc}')
    combined = '\n'.join((completed.stdout or '', completed.stderr or '')).strip()
    fatal = re.compile("(?:can't open perl script|cannot open perl script|invalid argument|required module not found|not recognized|non .? riconosciuto|no such file|modulenotfounderror|traceback|^error:)", re.IGNORECASE | re.MULTILINE)
    if completed.returncode != 0 or fatal.search(combined):
        return (False, combined[-2000:] or f'exit={completed.returncode}')
    if not re.search('nikto|version', combined, re.IGNORECASE):
        return (False, combined[-2000:] or 'Nikto returned no version information.')
    return (True, combined[-1000:])

# Finds duplicate numbered server files that can confuse the runtime.
def _numbered_duplicate_servers() -> list[Path]:
    if not SERVERS.is_dir():
        return []
    pattern = re.compile('.+\\(\\d+\\)\\.py$', re.IGNORECASE)
    return sorted((path.resolve() for path in SERVERS.rglob('*.py') if path.is_file() and pattern.fullmatch(path.name)), key=lambda path: path.name.lower())

# Preflight validation covers dependencies, server files, ports, and live MCP services before scanning.
def run_preflight_checks(*, include_live: bool=True) -> list[dict[str, str]]:
    configure_runtime_path()
    checks: list[dict[str, str]] = []
    numbered_duplicates = _numbered_duplicate_servers()
    checks.append({'level': 'warning' if numbered_duplicates else 'ok', 'component': 'project', 'cause': 'numbered_server_copies_found' if numbered_duplicates else 'canonical_server_filenames', 'detail': 'Move or delete numbered MCP copies: ' + ', '.join((path.name for path in numbered_duplicates)) if numbered_duplicates else 'Only canonical MCP server filenames will be executed.'})
    unified_server = resolve_server_path(UNIFIED_MCP_SERVER)
    checks.append({'level': 'ok' if unified_server.is_file() else 'error', 'component': 'mcp', 'cause': 'unified_server_found' if unified_server.is_file() else 'missing_unified_server', 'detail': str(unified_server)})
    seen_executables: set[str] = set()
    for spec in ALL_TOOLS:
        server = resolve_server_path(spec.server, spec.tool)
        if not server.is_file():
            checks.append({'level': 'error' if spec.required else 'warning', 'component': spec.name, 'cause': 'missing_server', 'detail': str(server)})
            continue
        checks.append({'level': 'ok', 'component': spec.name, 'cause': 'mcp_tool_found', 'detail': f'{server.name}: {spec.tool}()'})
        if spec.tool not in _declared_functions(server):
            checks[-1] = {'level': 'error' if spec.required else 'warning', 'component': spec.name, 'cause': 'mcp_tool_name_mismatch', 'detail': f'{server.name} does not declare {spec.tool}()'}
        if spec.name == 'report':
            docker_image = load_runtime_config().get('report_docker_image', '')
            docker_ready = bool(docker_image) and shutil.which('docker') and (subprocess.run(['docker', 'image', 'inspect', docker_image], capture_output=True, timeout=30, check=False).returncode == 0)
            if docker_ready:
                checks.append({'level': 'ok', 'component': 'report', 'cause': 'report_docker_fallback_ready', 'detail': docker_image})
            else:
                native_ok = importlib.util.find_spec('weasyprint') is not None
                checks.append({'level': 'ok' if native_ok else 'warning', 'component': 'report', 'cause': 'python_dependency_found' if native_ok else 'missing_python_dependency', 'detail': 'weasyprint (Docker fallback unavailable; run initScript.py with Docker present to pull the configured report image)'})
        elif spec.module:
            checks.append({'level': 'ok' if importlib.util.find_spec(spec.module) else 'error' if spec.required else 'warning', 'component': spec.name, 'cause': 'python_dependency_found' if importlib.util.find_spec(spec.module) else 'missing_python_dependency', 'detail': spec.module})
        if spec.executable and spec.executable not in seen_executables:
            seen_executables.add(spec.executable)
            executable = resolve_executable(spec.executable)
            checks.append({'level': 'ok' if executable else 'error' if spec.required else 'warning', 'component': spec.name, 'cause': 'executable_found' if executable else 'missing_executable', 'detail': executable or f'Not found: {spec.executable}; runtime={RUNTIME_FILE}'})
            if spec.name == 'nikto' and executable:
                runtime = load_runtime_config()
                docker_configured = runtime.get('nikto_execution_mode') == 'docker_official_image' or runtime.get('nikto_image') == 'ghcr.io/sullo/nikto:latest'
                docker_available = bool(shutil.which('docker'))
                docker_image_ready = False
                docker_detail = ''
                if docker_available:
                    try:
                        docker_probe = subprocess.run(['docker', 'image', 'inspect', 'ghcr.io/sullo/nikto:latest'], cwd=str(ROOT), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30, check=False)
                        docker_image_ready = docker_probe.returncode == 0
                        docker_detail = 'Official Docker image is available: ghcr.io/sullo/nikto:latest' if docker_image_ready else (docker_probe.stderr or docker_probe.stdout or 'Docker image inspection failed.').strip()[-1500:]
                    except Exception as exc:
                        docker_detail = f'Docker image probe failed: {type(exc).__name__}: {exc}'
                if docker_configured or docker_image_ready:
                    healthy = docker_image_ready
                    cause = 'nikto_docker_fallback_ready' if healthy else 'nikto_docker_image_missing'
                    runtime_detail = docker_detail or 'Docker is unavailable or the image is missing.'
                else:
                    healthy, runtime_detail = _nikto_runtime_check(executable)
                    cause = 'nikto_runtime_ok' if healthy else 'nikto_native_and_docker_unavailable'
                checks.append({'level': 'ok' if healthy else 'error', 'component': 'nikto', 'cause': cause, 'detail': runtime_detail})
    if include_live and (not any((item['level'] == 'error' for item in checks))):
        checks.extend(asyncio.run(_run_live_checks()))
    if not any((item['level'] == 'error' for item in checks)):
        checks.append({'level': 'ok', 'component': 'mcp', 'cause': 'preflight_passed', 'detail': 'All contracts, executables and the unified MCP Streamable HTTP handshake passed.'})
    return checks

# Prints the preflight result in a short operator-friendly format.
def print_preflight_report(checks: list[dict[str, str]], *, show_ok: bool=False) -> int:
    errors = [item for item in checks if item['level'] == 'error']
    warnings = [item for item in checks if item['level'] == 'warning']
    visible = checks if show_ok else [*errors, *warnings]
    if visible:
        print('\n=== SecOps preflight ===')
        for item in visible:
            marker = '+' if item['level'] == 'ok' else '!' if item['level'] == 'warning' else '-'
            stream = sys.stdout if marker in {'+', '!'} else sys.stderr
            print(f"[{marker}] {item['component']}: {item['cause']} — {item['detail']}", file=stream)
    return len(errors)

# Collects links, forms, and field names from HTML pages while discovery is crawling the target.
class LinkFormParser(HTMLParser):

    # Initializes the parser state before HTML tokens are processed.
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.current: dict[str, Any] | None = None

    # Records useful values whenever the parser encounters a relevant start tag.
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        tag = tag.lower()
        if tag == 'a' and values.get('href'):
            self.links.append(str(values['href']))
        elif tag == 'script' and values.get('src'):
            self.scripts.append(str(values['src']))
        elif tag == 'form':
            self.current = {'action': values.get('action', ''), 'method': str(values.get('method', 'get')).lower(), 'enctype': str(values.get('enctype', 'application/x-www-form-urlencoded')).lower(), 'fields': []}
        elif tag in {'input', 'textarea', 'select', 'button'} and self.current and values.get('name'):
            field_type = str(values.get('type', tag)).lower()
            self.current['fields'].append({'name': str(values['name']), 'value': str(values.get('value', '')), 'type': field_type, 'tag': tag})

    # Closes the active form record when the matching end tag is reached.
    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == 'form' and self.current:
            self.forms.append(self.current)
            self.current = None

# Removes fragments and sanitizes stray whitespace from discovered URL authorities.
def _clean_url(url: str) -> str:
    return sanitize_discovered_url(url)

# Fixes links that repeat the target base path by mistake.
def _normalize_redundant_base_path_link(target: str, candidate: str) -> str:

    base = urlparse(target)
    parsed = urlparse(candidate)
    base_path = base.path.rstrip('/')
    if not base_path:
        return candidate
    doubled = base_path + base_path + '/'
    if parsed.path.startswith(doubled):
        return urlunparse(parsed._replace(path=parsed.path[len(base_path):]))
    return candidate

# Crawler filtering keeps only URLs that are safe and useful to follow.
def _crawlable_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return not path.endswith(('.css', '.js', '.mjs', '.map', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.gz', '.tar', '.mp3', '.mp4', '.webm'))

# Route fingerprints ignore changing values so calendars, pagination and cache-busters cannot exhaust discovery budgets.
def _discovery_route_signature(url: str) -> tuple[str, str, tuple[str, ...]]:
    parsed = urlparse(str(url or ''))
    names = tuple(sorted({name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
    return (normalized_origin(url), parsed.path.rstrip('/') or '/', names)

# Generic URL scoring prioritizes interactive surfaces while de-prioritizing repetitive presentation routes.
def _discovery_url_score(url: str) -> int:
    parsed = urlparse(str(url or ''))
    path = parsed.path.lower()
    score = 30 + _risk_terms(path + ' ' + ' '.join(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)))
    if parsed.query:
        score += 14
    if any(token in path for token in ('/api/', '/graphql', '/admin', '/manage', '/account', '/profile', '/search', '/query', '/upload', '/download', '/callback', '/webhook', '/config', '/settings')):
        score += 28
    if any(token in path for token in ('calendar', 'archive', 'page/', 'pagination', 'news/', 'blog/', 'static/', 'assets/')):
        score -= 12
    if len(parsed.query) > 700:
        score -= 18
    return score

# Queue ranking protects the primary target surface without excluding explicitly authorized sibling origins.
def _discovery_queue_score(target: str, url: str) -> int:
    score = _discovery_url_score(url)
    if same_origin(target, url):
        score += 24
    return score

# Script scoring favors application/API code while still allowing a bounded amount of framework/vendor code.
def _script_value_score(url: str) -> int:
    path = urlparse(str(url or '')).path.lower()
    name = path.rsplit('/', 1)[-1]
    score = 20 + _risk_terms(path)
    if any(token in name for token in ('app', 'main', 'client', 'api', 'service', 'auth', 'dashboard', 'admin')):
        score += 24
    if any(token in name for token in ('vendor', 'webpack', 'runtime', 'polyfill', 'chunk', 'bundle')):
        score -= 12
    if name.endswith('.min.js'):
        score -= 6
    return score

DESTRUCTIVE_CRAWL_TOKENS = ('logout', 'log-out', 'signout', 'sign-out', 'logoff', 'disconnect', 'end-session', 'destroy-session', 'session-destroy', 'setup', 'install', 'reinstall', 'uninstall', 'reset', 'create_db', 'create-database', 'createdb', 'drop_db', 'drop-database', 'truncate', 'purge', 'wipe')
STATE_CHANGING_QUERY_KEYS = {'create_db', 'reset', 'action', 'delete', 'remove', 'logout', 'signout', 'logoff', 'disconnect', 'destroy', 'install', 'setup', 'password_new', 'password_conf', 'new_password', 'confirm_password'}

# Detects logout, setup, reset, and other destructive URLs.
def _destructive_crawl_url(url: str) -> bool:
    parsed = urlparse(str(url or ''))
    text = f'{parsed.path}?{parsed.query}'.lower()
    if any((token in text for token in DESTRUCTIVE_CRAWL_TOKENS)):
        return True
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for name, value in pairs:
        lowered_name = name.lower()
        lowered_value = value.lower()
        if lowered_name in STATE_CHANGING_QUERY_KEYS:
            return True
        if any((token in lowered_value for token in DESTRUCTIVE_CRAWL_TOKENS)):
            return True
    return False

# Performs a bounded GET request while blocking destructive navigation.
def _safe_crawl_get(session: requests.Session, requested: str, target: str, *, timeout: tuple[int, int]=(5, 15), max_redirects: int=5, cookies: str='') -> tuple[requests.Response | None, str, str]:

    current = _clean_url(requested)
    seen: set[str] = set()
    response: requests.Response | None = None
    for _ in range(max(0, int(max_redirects)) + 1):
        if not url_in_authorized_scope(target, current):
            return (response, current, f'out_of_scope_url_blocked:{current}')
        if _destructive_crawl_url(current):
            return (response, current, f'destructive_url_blocked:{current}')
        request_headers = {'Cookie': scope_cookie_header(current, cookies)} if scope_cookie_header(current, cookies) else {}
        response = session.get(current, timeout=timeout, allow_redirects=False, headers=request_headers)
        if response.status_code not in {301, 302, 303, 307, 308}:
            return (response, current, '')
        location = str(response.headers.get('Location') or '').strip()
        if not location:
            return (response, current, '')
        try:
            candidate = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(current, location)))
        except Exception:
            return (response, current, 'invalid_redirect_location')
        if not url_in_authorized_scope(target, candidate):
            return (response, current, f'out_of_scope_redirect_blocked:{candidate}')
        if _destructive_crawl_url(candidate):
            return (response, current, f'destructive_redirect_blocked:{candidate}')
        if candidate in seen:
            return (response, current, f'redirect_loop:{candidate}')
        seen.add(current)
        current = candidate
    return (response, current, 'redirect_limit_reached')

# Removes unstable query values from an authentication probe URL.
def _clean_probe_url(url: str) -> str:

    parsed = urlparse(str(url or ''))
    safe_pairs = [(name, value) for name, value in parse_qsl(parsed.query, keep_blank_values=True) if name.lower() not in STATE_CHANGING_QUERY_KEYS]
    return urlunparse(parsed._replace(query=urlencode(safe_pairs), fragment=''))

# Builds the authentication probe URLs configured for the current target.
def _runtime_probe_urls(target: str) -> list[str]:

    profile = target_runtime_profile(target)
    values = profile.get('probe_paths', []) if isinstance(profile, dict) else []
    result: list[str] = []
    for value in values if isinstance(values, list) else []:
        try:
            candidate = _clean_probe_url(absolute_url(target, str(value)))
        except Exception:
            continue
        if same_origin(target, candidate) and (not _destructive_crawl_url(candidate)):
            result.append(candidate)
    return result

# Chooses a stable page that can prove whether authentication still works.
def _stable_auth_probe_url(target: str, discovered_urls: list[str]) -> str:

    candidates = [*_runtime_probe_urls(target)]
    candidates.extend((_clean_probe_url(value) for value in discovered_urls if same_origin(target, value) and (not _destructive_crawl_url(value)) and (not _looks_like_login_path(value))))
    candidates.append(_clean_probe_url(target))

    # Ranks probe pages so authentication checks start from the most stable candidate.
    def score(value: str) -> int:
        parsed = urlparse(value)
        path = parsed.path.lower()
        score = 200
        if value in _runtime_probe_urls(target):
            score += 120
        if path in {'', '/'}:
            score += 30
        if any((token in path for token in ('account', 'profile', 'dashboard', 'home', 'admin', 'settings', 'console', 'portal'))):
            score += 80
        if any((token in path for token in ('login', 'logout', 'reset', 'setup', 'install', 'register'))):
            score -= 300
        if parsed.query:
            score -= 50
        return score
    unique = [value for value in dict.fromkeys(candidates) if value and same_origin(target, value) and (score(value) > 0)]
    return max(unique, key=score) if unique else _clean_probe_url(target)

# Login detection recognizes common authentication paths from the URL alone.
def _looks_like_login_path(url: str) -> bool:
    path = urlparse(str(url or '')).path.lower().rstrip('/')
    return path.endswith(('/login', '/login.php', '/signin', '/sign-in', '/auth'))

# Response inspection detects login pages from both the final URL and page content.
def _looks_like_login(response: requests.Response) -> bool:
    text = response.text[:100000].lower()
    path = urlparse(response.url).path.lower().rstrip('/')
    password_field = bool(re.search('type\\s*=\\s*[\'\\"]password[\'\\"]', text))
    auth_words = any((term in text for term in ('login', 'log in', 'sign in', 'signin', 'authenticate')))
    return path.endswith(('/login', '/login.php', '/signin', '/sign-in', '/auth')) or (password_field and auth_words)

# Converts one HTML form into the request-case format used by scanners.
def _form_case(action: str, method: str, fields: list[dict[str, str]], source_url: str, enctype: str='application/x-www-form-urlencoded') -> dict[str, Any] | None:

    method = method.upper() if method else 'GET'
    if method not in {'GET', 'POST'}:
        return None
    pairs: list[tuple[str, str]] = []
    testable: list[str] = []
    file_parameters: list[str] = []
    token_parameters: list[str] = []
    normalized_fields: list[dict[str, str]] = []
    for field in fields:
        name = str(field.get('name', '')).strip()
        if not name:
            continue
        field_type = str(field.get('type', 'text')).lower()
        tag = str(field.get('tag', 'input')).lower()
        value = str(field.get('value', ''))
        normalized_fields.append({'name': name, 'value': value, 'type': field_type, 'tag': tag})
        lowered = name.lower()
        if re.search('(?:csrf|xsrf|token|nonce|authenticity|request[_-]?verification)', lowered):
            token_parameters.append(name)
        if field_type == 'file':
            file_parameters.append(name)
            continue
        if not value and field_type not in {'hidden', 'submit', 'button'}:
            value = '1'
        pairs.append((name, value))
        if field_type not in {'hidden', 'submit', 'button', 'reset'} and (not re.search('(?:csrf|xsrf|token|nonce)', lowered)):
            testable.append(name)
    if not pairs and (not file_parameters):
        return None
    if not testable and (not file_parameters) and (not token_parameters):
        return None
    encoded = urlencode(pairs)
    if method == 'GET':
        if not pairs:
            return None
        parsed = urlparse(action)
        field_names = {name.lower() for name, _ in pairs}
        existing = [(name, value) for name, value in parse_qsl(parsed.query, keep_blank_values=True) if name.lower() not in field_names]
        url = urlunparse(parsed._replace(query=urlencode([*existing, *pairs])))
        data = ''
    else:
        url, data = (action, encoded)
    return {'url': url, 'method': method, 'data': data, 'parameters': list(dict.fromkeys(testable)), 'file_parameters': list(dict.fromkeys(file_parameters)), 'token_parameters': list(dict.fromkeys(token_parameters)), 'fields': normalized_fields, 'enctype': str(enctype or 'application/x-www-form-urlencoded').lower(), 'source_url': source_url, 'form_action': action}

# Removes duplicate request cases while keeping the best available data.
def _dedupe_request_cases(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for case in cases:
        names = [*[str(value) for value in case.get('parameters', []) if value], *[str(value) for value in case.get('file_parameters', []) if value], *[str(value) for value in case.get('token_parameters', []) if value]]
        key = (str(case.get('method', 'GET')).upper(), str(case.get('url', '')), tuple(sorted(set(names))))
        if not key[1] or not key[2] or key in seen:
            continue
        seen.add(key)
        unique.append(case)
    return unique

# Score how closely a discovered request case matches the non-payload context of one XSS finding.
def xss_verification_context_score(finding_url: str, case_url: str, parameter: str) -> int:

    finding_parsed, case_parsed = urlparse(str(finding_url or '')), urlparse(str(case_url or ''))
    if finding_parsed.path != case_parsed.path:
        return -100000
    source_parameter = str(parameter or '')
    finding_pairs = [(name, value) for name, value in parse_qsl(finding_parsed.query, keep_blank_values=True) if name != source_parameter]
    case_pairs = [(name, value) for name, value in parse_qsl(case_parsed.query, keep_blank_values=True) if name != source_parameter]
    finding_map = {name: value for name, value in finding_pairs}
    case_map = {name: value for name, value in case_pairs}
    score = 0
    for name in set(finding_map) | set(case_map):
        if name in finding_map and name in case_map:
            score += 6 if finding_map[name] == case_map[name] else -2
        else:
            score -= 1
    if finding_pairs == case_pairs:
        score += 20
    return score

# Rechecks whether an authenticated profile is still valid.
def refresh_authenticated_session_state(target: str, cookies: str, probe_url: str='') -> dict[str, Any]:

    if not cookies:
        return {'performed': False, 'authenticated': False, 'usable': True}
    preparation = apply_runtime_target_preparation(target, cookies)
    selected_probe = probe_url or target
    probe = scanner_session_probe(selected_probe, cookies, timeout=10, attempts=3)
    probe_invalid = probe.get('conclusive') is True and probe.get('authenticated') is False
    prep_invalid = preparation.get('conclusive', True) is True and preparation.get('usable', True) is False
    usable = not (probe_invalid or prep_invalid)
    conclusive = bool(probe_invalid or prep_invalid or probe.get('conclusive') is True)
    return {'performed': True, 'authenticated': probe.get('authenticated'), 'conclusive': conclusive, 'preparation': preparation, 'probe': probe, 'usable': usable, 'transient_error': bool(probe.get('transient_error') or preparation.get('transient_error'))}

# Records simple client-side source and sink clues for browser checks.
def _client_side_source_sink_evidence(text: str) -> tuple[list[str], list[str]]:

    value = str(text or '')[:750000]
    source_hits = sorted(set(re.findall('(?:location\\.(?:hash|search|href)|document\\.(?:URL|documentURI|referrer|cookie)|window\\.name)', value, re.I)))
    sink_hits = sorted(set(re.findall('(?:innerHTML|outerHTML|insertAdjacentHTML|document\\.write(?:ln)?|eval\\s*\\(|setTimeout\\s*\\(\\s*[\'\\"]|setInterval\\s*\\(\\s*[\'\\"])', value, re.I)))
    return (source_hits[:12], sink_hits[:12])

# Extracts literal authorized-scope endpoint hints from JavaScript without executing the script.
def _javascript_endpoint_hints(text: str, base_url: str, target: str) -> list[dict[str, str]]:

    value = str(text or '')[:1000000]
    patterns = (
        (re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']\s*,\s*\{[^}]{0,800}?method\s*:\s*[\"'](GET|POST|PUT|PATCH|DELETE)[\"']", re.I | re.S), 'fetch-options'),
        (re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']", re.I), 'fetch-get'),
        (re.compile(r"axios\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']", re.I), 'method-first'),
        (re.compile(r"\.open\s*\(\s*[\"'](GET|POST|PUT|PATCH|DELETE)[\"']\s*,\s*[\"']([^\"']+)[\"']", re.I), 'method-first'),
    )
    hints: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    explicit_fetch_starts = {match.start() for match in patterns[0][0].finditer(value)}
    for pattern, kind in patterns:
        for match in pattern.finditer(value):
            if kind == 'fetch-get' and match.start() in explicit_fetch_starts:
                continue
            if kind == 'fetch-options':
                raw_url, method = match.group(1), match.group(2).upper()
            elif kind == 'fetch-get':
                raw_url, method = match.group(1), 'GET'
            else:
                method, raw_url = match.group(1).upper(), match.group(2)
            if raw_url.startswith(('data:', 'javascript:', '#')) or '{' in raw_url or '}' in raw_url:
                continue
            try:
                url = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(base_url, raw_url)))
            except Exception:
                continue
            if not url_in_authorized_scope(target, url) or _destructive_crawl_url(url):
                continue
            key = (method, url)
            if key in seen:
                continue
            seen.add(key)
            hints.append({'method': method, 'url': url})
            if len(hints) >= 160:
                return hints
    return hints

# Converts one browser-observed request into the normalized request-contract shape.
def _browser_network_case(url: str, method: str, data: str, content_type: str, source_url: str, resource_type: str) -> dict[str, Any] | None:

    method = str(method or 'GET').upper()
    if method not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}:
        return None
    parsed = urlparse(url)
    parameters = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    fields: list[dict[str, str]] = []
    body = str(data or '')
    lowered_type = str(content_type or '').lower()

    def add_json_fields(value: Any, prefix: str='', depth: int=0) -> None:
        if depth > 4 or len(fields) >= 80:
            return
        if isinstance(value, dict):
            for key, nested in value.items():
                name = f'{prefix}.{key}' if prefix else str(key)
                if isinstance(nested, (dict, list)):
                    add_json_fields(nested, name, depth + 1)
                else:
                    parameters.append(name)
                    scalar = nested if isinstance(nested, (str, int, float, bool)) or nested is None else ''
                    fields.append({'name': name, 'value': '' if scalar is None else str(scalar), 'type': 'json', 'tag': 'network'})
        elif isinstance(value, list):
            for index, nested in enumerate(value[:20]):
                add_json_fields(nested, f'{prefix}[{index}]' if prefix else f'[{index}]', depth + 1)

    if body and method != 'GET':
        if 'application/x-www-form-urlencoded' in lowered_type:
            for name, value in parse_qsl(body, keep_blank_values=True):
                parameters.append(name)
                fields.append({'name': name, 'value': value, 'type': 'text', 'tag': 'network'})
        elif 'json' in lowered_type or body.lstrip().startswith(('{', '[')):
            try:
                decoded = json.loads(body)
            except Exception:
                decoded = None
            if decoded is not None:
                add_json_fields(decoded)
    parameters = list(dict.fromkeys((str(name) for name in parameters if str(name))))
    if not parameters:
        return None
    return {
        'url': url, 'method': method, 'data': body, 'parameters': parameters, 'file_parameters': [],
        'token_parameters': [name for name in parameters if re.search('(?:csrf|xsrf|token|nonce|authenticity|request[_-]?verification)', name, re.I)],
        'fields': fields, 'enctype': lowered_type or 'unknown', 'content_type': lowered_type,
        'source_url': source_url or url, 'network_resource_type': resource_type, 'discovery_source': 'playwright_network',
    }

# Uses Chromium as a bounded dynamic discovery queue so rendered navigation and XHR/fetch contracts become scanner inputs.
def _browser_network_discovery(target: str, cookies: str, html_urls: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[dict[str, Any]], dict[str, Any]]:

    limits = DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, DISCOVERY_LIMITS['balanced'])
    navigation_budget = int(limits['browser_pages'])
    navigation_max_budget = max(navigation_budget, int(limits.get('browser_pages_max', navigation_budget)))
    route_variant_limit = int(limits['route_variants'])
    per_origin_limit = int(limits.get('browser_per_origin_pages', limits['per_origin_pages']))
    budget_info: dict[str, Any] = {
        'base_budget': navigation_budget, 'max_budget': navigation_max_budget,
        'attempted': 0, 'adaptive_overflow_used': 0, 'remaining_candidates': 0,
        'adaptive_threshold': None, 'max_saturated': False,
    }
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return ([], [], [], [{'url': target, 'type': 'BrowserDiscoveryUnavailable', 'message': f'{type(exc).__name__}: {exc}'}], budget_info)
    ranked_pages = sorted(
        { _clean_url(value) for value in html_urls if value and url_in_authorized_scope(target, value) },
        key=lambda value: (-_discovery_queue_score(target, value), len(urlparse(value).path), value),
    )
    target_url = _clean_url(target)
    if target_url in ranked_pages:
        ranked_pages.remove(target_url)
    queue: list[str] = []
    queued: set[str] = set()
    queued_signatures: Counter[tuple[str, str, tuple[str, ...]]] = Counter()
    visited_signatures: Counter[tuple[str, str, tuple[str, ...]]] = Counter()
    origin_visits: Counter[str] = Counter()
    navigated: list[str] = []
    visited: set[str] = set()
    observed: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    current_source = {'url': target_url}
    request_rows: dict[int, dict[str, Any]] = {}
    request_cases_by_id: dict[int, dict[str, Any]] = {}

    def enqueue_dynamic(raw_url: str, *, force: bool=False) -> None:
        try:
            candidate = _normalize_redundant_base_path_link(target, _clean_url(raw_url))
        except Exception:
            return
        if not candidate or candidate in queued or candidate in visited:
            return
        if not url_in_authorized_scope(target, candidate) or not _crawlable_url(candidate) or _destructive_crawl_url(candidate):
            return
        signature = _discovery_route_signature(candidate)
        origin = normalized_origin(candidate)
        if not force and queued_signatures[signature] >= route_variant_limit:
            return
        if origin_visits[origin] >= per_origin_limit:
            return
        queued.add(candidate)
        queued_signatures[signature] += 1
        queue.append(candidate)
        queue.sort(key=lambda value: (-_discovery_queue_score(target, value), value))

    enqueue_dynamic(target_url, force=True)
    for value in ranked_pages:
        enqueue_dynamic(value)

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True, user_agent='SecOps-Browser-Discovery/1.0')
            parsed_target = urlparse(target)
            origin = urlunparse(parsed_target._replace(path='/', query='', fragment=''))
            cookie_rows = [{'name': name, 'value': value, 'url': origin} for name, value in parse_cookie_header(cookies)]
            if cookie_rows:
                context.add_cookies(cookie_rows)

            def route_guard(route: Any) -> None:
                request_url = str(route.request.url or '')
                request_method = str(route.request.method or 'GET').upper()
                if _destructive_crawl_url(request_url) or request_method not in {'GET', 'HEAD', 'OPTIONS'}:
                    route.abort()
                else:
                    route.continue_()

            context.route('**/*', route_guard)
            page = context.new_page()

            def record_request(request: Any) -> None:
                url = _clean_url(str(request.url or ''))
                if not url or not url_in_authorized_scope(target, url) or _destructive_crawl_url(url):
                    return
                method = str(request.method or 'GET').upper()
                resource_type = str(request.resource_type or '')
                if resource_type not in {'document', 'xhr', 'fetch'} and not urlparse(url).query:
                    return
                headers = request.headers or {}
                content_type = str(headers.get('content-type') or '')
                data = str(request.post_data or '')
                row = {'url': url, 'method': method, 'resource_type': resource_type, 'content_type': content_type, 'source_url': current_source['url'], 'has_body': bool(data), 'blocked_before_send': method not in {'GET', 'HEAD', 'OPTIONS'}, 'response_observed': False, 'response_status': None, 'response_ok': None, 'response_content_type': '', 'request_failure': ''}
                observed.append(row)
                request_rows[id(request)] = row
                case = _browser_network_case(url, method, data, content_type, current_source['url'], resource_type)
                if case:
                    cases.append(case)
                    request_cases_by_id[id(request)] = case
                if resource_type == 'document' and method == 'GET' and url != current_source['url']:
                    enqueue_dynamic(url)

            def record_response(response: Any) -> None:
                request = response.request
                row = request_rows.get(id(request))
                if row is None:
                    return
                try:
                    status = int(response.status)
                except Exception:
                    status = 0
                try:
                    headers = response.headers or {}
                except Exception:
                    headers = {}
                response_type = str(headers.get('content-type') or '').lower()
                row.update(response_observed=True, response_status=status, response_ok=200 <= status < 400, response_content_type=response_type)
                case = request_cases_by_id.get(id(request))
                if case is not None:
                    case['browser_response'] = {'observed': True, 'status': status, 'ok': 200 <= status < 400, 'content_type': response_type}

            def record_failed(request: Any) -> None:
                row = request_rows.get(id(request))
                if row is None:
                    return
                try:
                    failure = str(request.failure or '')
                except Exception:
                    failure = ''
                row['request_failure'] = failure or ('blocked_before_send' if row.get('blocked_before_send') else 'request_failed')
                case = request_cases_by_id.get(id(request))
                if case is not None:
                    case['browser_response'] = {'observed': False, 'status': None, 'ok': False, 'failure': row['request_failure']}

            page.on('request', record_request)
            page.on('response', record_response)
            page.on('requestfailed', record_failed)
            base_scores: list[int] = []
            adaptive_threshold: int | None = None
            while queue and len(visited) < navigation_max_budget:
                value = queue[0]
                value_score = _discovery_queue_score(target, value)
                if len(visited) >= navigation_budget:
                    if adaptive_threshold is None:
                        cutoff_score = min(base_scores) if base_scores else value_score
                        adaptive_threshold = max(1, int(cutoff_score * 0.75))
                    if value_score < adaptive_threshold:
                        break
                value = queue.pop(0)
                if value in visited:
                    continue
                signature = _discovery_route_signature(value)
                origin_key = normalized_origin(value)
                if visited_signatures[signature] >= route_variant_limit or origin_visits[origin_key] >= per_origin_limit:
                    continue
                visited.add(value)
                visited_signatures[signature] += 1
                origin_visits[origin_key] += 1
                if len(visited) <= navigation_budget and _discovery_route_signature(value) != _discovery_route_signature(target_url):
                    base_scores.append(value_score)
                current_source['url'] = value
                try:
                    response = page.goto(value, wait_until='domcontentloaded', timeout=12000)
                    page.wait_for_timeout(650)
                    response_type = str((response.headers if response else {}).get('content-type') or '').lower()
                    if not response_type or 'html' in response_type:
                        navigated.append(value)
                    for href in page.eval_on_selector_all('a[href]', 'elements => elements.map(element => element.href)'):
                        enqueue_dynamic(str(href or ''))
                    for frame in page.frames:
                        frame_url = str(frame.url or '')
                        if frame_url and frame_url != value:
                            enqueue_dynamic(frame_url)
                except Exception as exc:
                    errors.append({'url': value, 'type': 'BrowserDiscoveryNavigation', 'message': f'{type(exc).__name__}: {exc}'})
            budget_info.update(
                attempted=len(visited),
                adaptive_overflow_used=max(0, len(visited) - navigation_budget),
                remaining_candidates=len(queue),
                adaptive_threshold=adaptive_threshold,
                max_saturated=bool(queue and len(visited) >= navigation_max_budget),
            )
            browser.close()
    except Exception as exc:
        errors.append({'url': target, 'type': 'BrowserDiscoveryRuntime', 'message': f'{type(exc).__name__}: {exc}'})
    unique_observed: list[dict[str, Any]] = []
    seen_observed: set[tuple[str, str, str]] = set()
    for row in observed:
        key = (str(row.get('method') or ''), str(row.get('url') or ''), str(row.get('resource_type') or ''))
        if key in seen_observed:
            continue
        seen_observed.add(key)
        unique_observed.append(row)
    budget_info.update(
        attempted=max(int(budget_info.get('attempted', 0) or 0), len(visited)),
        adaptive_overflow_used=max(int(budget_info.get('adaptive_overflow_used', 0) or 0), max(0, len(visited) - navigation_budget)),
        remaining_candidates=max(int(budget_info.get('remaining_candidates', 0) or 0), len(queue)),
        max_saturated=bool(budget_info.get('max_saturated')) or bool(queue and len(visited) >= navigation_max_budget),
    )
    return (_dedupe_request_cases(cases), unique_observed, list(dict.fromkeys(navigated)), errors, budget_info)

# Crawls the target and records pages, forms, parameters, scripts, browser requests, and auth state.
def discover_target(target: str, cookies: str, max_pages: int=MAX_CRAWL_PAGES, seeds: list[str] | None=None) -> dict[str, Any]:

    session = requests.Session()
    session.headers.update({'User-Agent': 'SecOps-Discovery/2.0', 'Accept': 'text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5'})
    target_preparation = apply_runtime_target_preparation(target, cookies) if cookies else {'performed': False, 'configured': False, 'usable': True}
    limits = DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, DISCOVERY_LIMITS['balanced'])
    page_budget = min(max(1, int(max_pages)), int(limits['crawl_pages']))
    script_budget = min(MAX_SCRIPT_ASSETS, int(limits['scripts']))
    route_variant_limit = int(limits['route_variants'])
    per_origin_limit = int(limits['per_origin_pages'])
    initial = [_clean_url(target), *[_clean_url(value) for value in seeds or []]]
    destructive_skipped: set[str] = set()
    destructive_request_cases: list[dict[str, Any]] = []
    coverage_skipped_cases: list[dict[str, Any]] = []
    queue: list[str] = []
    queued: set[str] = set()
    queued_signatures: Counter[tuple[str, str, tuple[str, ...]]] = Counter()
    visited_signatures: Counter[tuple[str, str, tuple[str, ...]]] = Counter()
    origin_useful_visits: Counter[str] = Counter()
    origin_attempts: Counter[str] = Counter()
    skipped_route_variants = 0
    skipped_origin_budget = 0
    skipped_out_of_scope = 0
    http_attempts = 0
    dead_http_responses = 0
    attempt_budget = max(page_budget, (page_budget * 3 + 1) // 2)
    per_origin_attempt_limit = max(per_origin_limit, (per_origin_limit * 3 + 1) // 2)

    def record_coverage_skip(raw_url: str, reason_code: str, reason: str, *, method: str='GET', source_url: str='') -> None:
        value = str(raw_url or '').strip()
        if not value:
            return
        row = {
            'url': value,
            'method': str(method or 'GET').upper(),
            'reason_code': str(reason_code or '').upper(),
            'reason': str(reason or ''),
            'source_url': str(source_url or ''),
        }
        if row not in coverage_skipped_cases:
            coverage_skipped_cases.append(row)

    def enqueue(raw_url: str, *, force: bool=False, source_url: str='') -> None:
        nonlocal skipped_route_variants, skipped_origin_budget, skipped_out_of_scope
        try:
            value = _normalize_redundant_base_path_link(target, _clean_url(raw_url))
        except Exception:
            return
        if not value or value in queued:
            return
        if not url_in_authorized_scope(target, value):
            skipped_out_of_scope += 1
            record_coverage_skip(value, 'OUT_OF_SCOPE', 'Discovered URL was outside the explicitly authorized HTTP scope.', source_url=source_url)
            return
        if not _crawlable_url(value):
            return
        if _destructive_crawl_url(value):
            destructive_skipped.add(value)
            record_coverage_skip(value, 'STATE_CHANGE_BLOCKED', 'Destructive or state-changing route was excluded by the discovery safety policy.', source_url=source_url)
            return
        signature = _discovery_route_signature(value)
        origin = normalized_origin(value)
        if not force and queued_signatures[signature] >= route_variant_limit:
            skipped_route_variants += 1
            record_coverage_skip(value, 'DUPLICATE_ROUTE_VARIANT', 'Additional value variant of the same route and parameter-name shape was omitted by the anti-saturation limit.', source_url=source_url)
            return
        if origin_useful_visits[origin] >= per_origin_limit:
            skipped_origin_budget += 1
            record_coverage_skip(value, 'BUDGET_LIMIT', 'Per-origin useful-page discovery budget was already saturated.', source_url=source_url)
            return
        queued.add(value)
        queued_signatures[signature] += 1
        queue.append(value)
        queue.sort(key=lambda candidate: (-_discovery_queue_score(target, candidate), candidate))

    for value in dict.fromkeys(initial):
        enqueue(value, force=value == _clean_url(target))

    visited: set[str] = set()
    html_urls: set[str] = set()
    form_urls: set[str] = set()
    parameterized: set[str] = set()
    request_cases: list[dict[str, Any]] = []
    client_side_candidates: list[dict[str, Any]] = []
    script_urls: set[str] = set()
    script_endpoint_hints: list[dict[str, str]] = []
    scanned_script_urls: set[str] = set()
    tokens: set[str] = set()
    errors: list[dict[str, Any]] = []
    initial_login_detected = False
    pages_processed = 0

    while queue and pages_processed < page_budget and http_attempts < attempt_budget:
        requested = queue.pop(0)
        if requested in visited:
            continue
        signature = _discovery_route_signature(requested)
        origin = normalized_origin(requested)
        if visited_signatures[signature] >= route_variant_limit:
            skipped_route_variants += 1
            record_coverage_skip(requested, 'DUPLICATE_ROUTE_VARIANT', 'Additional value variant of the same route and parameter-name shape was omitted by the anti-saturation limit.')
            continue
        if origin_useful_visits[origin] >= per_origin_limit or origin_attempts[origin] >= per_origin_attempt_limit:
            skipped_origin_budget += 1
            record_coverage_skip(requested, 'BUDGET_LIMIT', 'Per-origin discovery page/attempt budget was already saturated.')
            continue
        if _destructive_crawl_url(requested):
            destructive_skipped.add(requested)
            record_coverage_skip(requested, 'STATE_CHANGE_BLOCKED', 'Destructive or state-changing route was excluded by the discovery safety policy.')
            continue
        visited.add(requested)
        visited_signatures[signature] += 1
        origin_attempts[origin] += 1
        http_attempts += 1
        try:
            response, final, redirect_issue = _safe_crawl_get(session, requested, target, timeout=(5, 15), max_redirects=5, cookies=cookies)
        except requests.RequestException as exc:
            errors.append({'url': requested, 'type': type(exc).__name__, 'message': str(exc)})
            continue
        if response is None:
            errors.append({'url': requested, 'type': 'UnsafeURLBlocked', 'message': redirect_issue or final})
            continue
        final = _clean_url(final)
        if redirect_issue:
            errors.append({'url': requested, 'type': 'SafeRedirectGuard', 'message': redirect_issue})
            if redirect_issue.startswith(('destructive_', 'out_of_scope_')):
                code = 'STATE_CHANGE_BLOCKED' if redirect_issue.startswith('destructive_') else 'OUT_OF_SCOPE'
                record_coverage_skip(requested, code, 'Redirect target was blocked by the discovery safety/scope guard.')
                continue
        if not url_in_authorized_scope(target, final):
            errors.append({'url': requested, 'type': 'OutOfScopeRedirect', 'message': final})
            record_coverage_skip(final, 'OUT_OF_SCOPE', 'Redirected URL was outside the explicitly authorized HTTP scope.', source_url=requested)
            continue
        visited.add(final)
        if requested == _clean_url(target) and _looks_like_login(response):
            initial_login_detected = True
        if response.status_code >= 400:
            errors.append({'url': final, 'type': f'HTTP{response.status_code}', 'message': response.reason or 'HTTP error'})
        # A dead 404/410 remains recorded as surface evidence, but it must not consume
        # the useful HTML-page quota or become a Chromium/ZAP HTML seed. A separate
        # bounded attempt budget prevents a broken-link-heavy application from causing
        # unbounded extra requests while useful pages are still being sought.
        if response.status_code in {404, 410}:
            dead_http_responses += 1
            continue
        final_origin = normalized_origin(final)
        if origin_useful_visits[final_origin] >= per_origin_limit:
            skipped_origin_budget += 1
            record_coverage_skip(final, 'BUDGET_LIMIT', 'Per-origin useful-page discovery budget was already saturated.', source_url=requested)
            continue
        pages_processed += 1
        origin_useful_visits[final_origin] += 1
        content_type = response.headers.get('content-type', '').lower()
        if 'html' not in content_type and (not response.text.lstrip().startswith(('<', '<!'))):
            continue
        html_urls.add(final)
        tokens.update(re.findall(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', response.text))
        source_hits, sink_hits = _client_side_source_sink_evidence(response.text)
        if source_hits and sink_hits:
            client_side_candidates.append({'url': final, 'sources': source_hits, 'sinks': sink_hits, 'evidence_source': 'inline_html'})
        parser = LinkFormParser()
        try:
            parser.feed(response.text)
            parser.close()
        except Exception as exc:
            errors.append({'url': final, 'type': type(exc).__name__, 'message': f'HTML parse: {exc}'})
            continue

        ranked_scripts: list[str] = []
        for source in parser.scripts:
            try:
                script_url = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(final, source)))
            except Exception:
                continue
            if not url_in_authorized_scope(target, script_url) or _destructive_crawl_url(script_url) or script_url in scanned_script_urls:
                continue
            ranked_scripts.append(script_url)
        ranked_scripts = sorted(set(ranked_scripts), key=lambda value: (-_script_value_score(value), value))
        for script_url in ranked_scripts:
            if len(scanned_script_urls) >= script_budget:
                break
            scanned_script_urls.add(script_url)
            try:
                script_response, script_final, script_issue = _safe_crawl_get(session, script_url, target, timeout=(4, 12), max_redirects=4, cookies=cookies)
            except requests.RequestException as exc:
                errors.append({'url': script_url, 'type': type(exc).__name__, 'message': f'JavaScript fetch: {exc}'})
                continue
            if script_response is None or script_issue or script_response.status_code >= 400:
                continue
            script_final = _clean_url(script_final)
            if not url_in_authorized_scope(target, script_final):
                continue
            script_urls.add(script_final)
            for hint in _javascript_endpoint_hints(script_response.text, script_final, target):
                if hint not in script_endpoint_hints:
                    script_endpoint_hints.append(hint)
                hinted_url = str(hint.get('url') or '')
                hint_method = str(hint.get('method') or 'GET').upper()
                hint_parameters = [name for name, _ in parse_qsl(urlparse(hinted_url).query, keep_blank_values=True)]
                if hint_parameters and hint_method in {'GET', 'POST'}:
                    request_cases.append({'url': hinted_url, 'method': hint_method, 'data': '', 'parameters': hint_parameters, 'file_parameters': [], 'token_parameters': [], 'fields': [], 'source_url': script_final, 'discovery_source': 'javascript_literal'})
                    if hint_method == 'GET':
                        parameterized.add(hinted_url)
            js_sources, js_sinks = _client_side_source_sink_evidence(script_response.text)
            if js_sources and js_sinks:
                client_side_candidates.append({'url': final, 'script_url': script_final, 'sources': js_sources, 'sinks': js_sinks, 'evidence_source': 'authorized_scope_script'})

        for href in parser.links:
            try:
                candidate = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(final, href)))
            except Exception:
                continue
            if not url_in_authorized_scope(target, candidate):
                skipped_out_of_scope += 1
                record_coverage_skip(candidate, 'OUT_OF_SCOPE', 'Link discovered in HTML was outside the explicitly authorized HTTP scope.', source_url=final)
                continue
            if not _crawlable_url(candidate):
                continue
            if _destructive_crawl_url(candidate):
                destructive_skipped.add(candidate)
                record_coverage_skip(candidate, 'STATE_CHANGE_BLOCKED', 'Destructive or state-changing link was excluded by the discovery safety policy.', source_url=final)
                destructive_request_cases.append({
                    'url': candidate, 'method': 'GET', 'data': '',
                    'parameters': [name for name, _ in parse_qsl(urlparse(candidate).query, keep_blank_values=True)],
                    'fields': [], 'source_url': final, 'destructive_kind': 'logout' if _is_logout_url(candidate) else 'other',
                })
                continue
            if urlparse(candidate).query:
                parameterized.add(candidate)
            if candidate not in visited:
                enqueue(candidate, source_url=final)

        for form in parser.forms:
            try:
                action = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(final, form['action'] or final)))
            except Exception:
                continue
            if not url_in_authorized_scope(target, action):
                skipped_out_of_scope += 1
                record_coverage_skip(action, 'OUT_OF_SCOPE', 'Form action discovered in HTML was outside the explicitly authorized HTTP scope.', method=str(form.get('method', 'get')), source_url=final)
                continue
            if _destructive_crawl_url(action):
                destructive_skipped.add(action)
                record_coverage_skip(action, 'STATE_CHANGE_BLOCKED', 'Destructive or state-changing form action was excluded by the discovery safety policy.', method=str(form.get('method', 'get')), source_url=final)
                fields = [field for field in form.get('fields', []) if isinstance(field, dict)]
                destructive_case = _form_case(action, str(form.get('method', 'get')), fields, final, str(form.get('enctype', '')))
                if destructive_case:
                    destructive_case['destructive_kind'] = 'logout' if _is_logout_url(action) else 'other'
                    destructive_request_cases.append(destructive_case)
                continue
            fields = [field for field in form.get('fields', []) if isinstance(field, dict)]
            if fields:
                form_urls.add(final)
            case = _form_case(action, str(form.get('method', 'get')), fields, final, str(form.get('enctype', '')))
            if case:
                request_cases.append(case)
                if case['method'] == 'GET':
                    parameterized.add(case['url'])

    browser_cases, browser_network_requests, browser_navigation_urls, browser_errors, browser_budget_info = _browser_network_discovery(target, cookies, sorted(html_urls)) if html_urls else ([], [], [], [], {'base_budget': int(limits['browser_pages']), 'max_budget': int(limits.get('browser_pages_max', limits['browser_pages'])), 'attempted': 0, 'adaptive_overflow_used': 0, 'remaining_candidates': 0, 'adaptive_threshold': None, 'max_saturated': False})
    request_cases.extend(browser_cases)
    html_urls.update(browser_navigation_urls)
    visited.update(browser_navigation_urls)
    errors.extend(browser_errors)
    for case in browser_cases:
        if str(case.get('method') or '').upper() == 'GET' and urlparse(str(case.get('url') or '')).query:
            parameterized.add(str(case['url']))

    auth_effective: bool | None = None
    auth_note = 'Anonymous profile.'
    auth_probe: dict[str, Any] = {}
    if cookies:
        probe_url = _stable_auth_probe_url(target, sorted(html_urls))
        try:
            original_headers = dict(session.headers)
            session.headers['Cache-Control'] = 'no-cache'
            probe_response, probe_final, probe_redirect_issue = _safe_crawl_get(session, probe_url, target, timeout=(5, 15), max_redirects=5, cookies=cookies)
            session.headers.clear()
            session.headers.update(original_headers)
            if probe_response is None:
                raise requests.RequestException(probe_redirect_issue or f'Session probe was blocked: {probe_final}')
            probe_response.url = probe_final
            final_login_detected = _looks_like_login(probe_response)
            anonymous_session = requests.Session()
            anonymous_session.headers.update({'User-Agent': 'SecOps-Discovery-Anonymous-Comparison/1.0', 'Cache-Control': 'no-cache'})
            anonymous_response, anonymous_final, anonymous_redirect_issue = _safe_crawl_get(anonymous_session, probe_url, target, timeout=(5, 15), max_redirects=5, cookies='')
            if anonymous_response is None:
                raise requests.RequestException(anonymous_redirect_issue or f'Anonymous probe was blocked: {anonymous_final}')
            anonymous_response.url = anonymous_final
            anonymous_login_detected = _looks_like_login(anonymous_response)
            authenticated_good = not initial_login_detected and (not final_login_detected) and (probe_response.status_code < 400) and (target_preparation.get('usable', True) is not False)
            clear_anonymous_difference = anonymous_login_detected or (anonymous_response.status_code in {401, 403} and probe_response.status_code < 400) or (same_origin(target, probe_response.url) and same_origin(target, anonymous_response.url) and (_clean_url(probe_response.url) != _clean_url(anonymous_response.url)))
            if not authenticated_good:
                auth_effective = False
            elif clear_anonymous_difference:
                auth_effective = True
            else:
                auth_effective = None
            auth_probe = {'url': probe_url, 'status': probe_response.status_code, 'final_url': str(probe_response.url), 'login_detected': final_login_detected, 'anonymous_status': anonymous_response.status_code, 'anonymous_final_url': str(anonymous_response.url), 'anonymous_login_detected': anonymous_login_detected, 'authenticated_redirect_guard': probe_redirect_issue, 'anonymous_redirect_guard': anonymous_redirect_issue, 'authenticated_distinguished_from_anonymous': True if clear_anonymous_difference else None}
        except requests.RequestException as exc:
            auth_effective = None
            auth_probe = {'url': probe_url, 'error': f'{type(exc).__name__}: {exc}', 'conclusive': False}
        auth_note = 'The supplied cookie was distinguished from the anonymous response.' if auth_effective is True else 'The supplied cookie reached a login or authorization failure page.' if auth_effective is False else 'The supplied cookie remained usable, but this target did not expose a conclusive anonymous/authenticated distinction.'

    budget_diagnostics = {
        'mode': CURRENT_SCAN_MODE,
        'http_page_budget': page_budget,
        'http_pages_processed': pages_processed,
        'http_attempt_budget': attempt_budget,
        'http_requests_attempted': http_attempts,
        'http_remaining_candidates': len(queue),
        'http_page_budget_saturated': bool(queue and pages_processed >= page_budget),
        'http_attempt_budget_saturated': bool(queue and http_attempts >= attempt_budget),
        'dead_http_404_410': dead_http_responses,
        'browser_page_budget': int(browser_budget_info.get('base_budget', limits['browser_pages'])),
        'browser_page_max_budget': int(browser_budget_info.get('max_budget', limits.get('browser_pages_max', limits['browser_pages']))),
        'browser_pages_attempted': int(browser_budget_info.get('attempted', 0) or 0),
        'browser_adaptive_overflow_used': int(browser_budget_info.get('adaptive_overflow_used', 0) or 0),
        'browser_remaining_candidates': int(browser_budget_info.get('remaining_candidates', 0) or 0),
        'browser_adaptive_threshold': browser_budget_info.get('adaptive_threshold'),
        'browser_max_budget_saturated': bool(browser_budget_info.get('max_saturated', False)),
        'script_budget': script_budget,
        'scripts_processed': len(scanned_script_urls),
        'route_variant_limit': route_variant_limit,
        'per_origin_page_limit': per_origin_limit,
        'per_origin_attempt_limit': per_origin_attempt_limit,
        'route_variants_skipped': skipped_route_variants,
        'origin_budget_skipped': skipped_origin_budget,
        'out_of_scope_urls_skipped': skipped_out_of_scope,
        'authorized_origins': sorted(AUTHORIZED_SCOPE_ORIGINS),
        'authorized_host_suffixes': sorted(AUTHORIZED_SCOPE_HOST_SUFFIXES),
    }
    return {'urls': sorted(visited), 'html_urls': sorted(html_urls), 'form_urls': sorted(form_urls), 'parameterized_urls': sorted(parameterized), 'request_cases': _dedupe_request_cases(request_cases), 'script_urls': sorted(script_urls), 'script_endpoint_hints': script_endpoint_hints, 'browser_network_requests': browser_network_requests, 'browser_navigation_urls': browser_navigation_urls, 'client_side_candidates': client_side_candidates, 'jwt_tokens': sorted(tokens), 'errors': errors, 'authentication_effective': auth_effective, 'authentication_note': auth_note, 'authentication_probe': auth_probe, 'target_preparation': target_preparation, 'destructive_urls_skipped': sorted(destructive_skipped), 'destructive_request_cases': _dedupe_request_cases(destructive_request_cases), 'coverage_skipped_cases': coverage_skipped_cases, 'budget_diagnostics': budget_diagnostics}

# Orders discovery diagnostics so browser/runtime failures are visible before ordinary dead-link HTTP errors.
def prioritized_discovery_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def priority(row: dict[str, Any]) -> tuple[int, str, str]:
        kind = str(row.get('type') or '')
        if kind.startswith('BrowserDiscovery'):
            rank = 0
        elif kind in {'UnsafeURLBlocked', 'SafeRedirectGuard', 'OutOfScopeRedirect'}:
            rank = 1
        elif kind in {'HTTP401', 'HTTP403'}:
            rank = 2
        elif kind in {'HTTP404', 'HTTP410'}:
            rank = 4
        else:
            rank = 3
        return (rank, kind, str(row.get('url') or ''))
    return sorted((row for row in errors if isinstance(row, dict)), key=priority)

# Returns the Chromium discovery diagnostic when HTML existed but no dynamic navigation completed.
def chromium_discovery_warning(discovery: dict[str, Any]) -> str:
    if not discovery.get('html_urls') or discovery.get('browser_navigation_urls'):
        return ''
    browser_errors = [
        row for row in discovery.get('errors', [])
        if isinstance(row, dict) and str(row.get('type') or '').startswith('BrowserDiscovery')
    ]
    if browser_errors:
        first = prioritized_discovery_errors(browser_errors)[0]
        return f"Chromium dynamic discovery completed 0 navigations; first browser error: {first.get('type')}: {first.get('message')}"
    return 'Chromium dynamic discovery completed 0 navigations even though HTML pages were available; review browser runtime/navigation diagnostics.'

# Returns additional explicitly authorized origins that were actually observed during discovery.

# Runs synchronous discovery safely even if a caller is already inside an asyncio event loop.
# The normal CLI paths are synchronous here, but the worker fallback prevents Playwright Sync API
# failures when this function is reused from async LangGraph/test harnesses.
def discover_target_sync_safe(target: str, cookies: str, max_pages: int=MAX_CRAWL_PAGES, seeds: list[str] | None=None) -> dict[str, Any]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return discover_target(target, cookies, max_pages=max_pages, seeds=seeds)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix='secops-discovery') as executor:
        return executor.submit(discover_target, target, cookies, max_pages, seeds).result()

def _discovered_scope_origin_evidence(discovery: dict[str, Any], target: str) -> dict[str, dict[str, int]]:
    primary = normalized_origin(target)
    evidence: dict[str, dict[str, int]] = {}

    def add(value: str, bonus: int=0, interactive: int=0) -> None:
        value = str(value or '')
        if not value or not url_in_authorized_scope(target, value):
            return
        origin = normalized_origin(value)
        if not origin or origin == primary:
            return
        bucket = evidence.setdefault(origin, {'max_score': -1000, 'observations': 0, 'interactive': 0})
        bucket['max_score'] = max(bucket['max_score'], _discovery_url_score(value) + int(bonus))
        bucket['observations'] += 1
        bucket['interactive'] += int(interactive)

    for key in ('urls', 'html_urls', 'parameterized_urls', 'script_urls'):
        for value in discovery.get(key, []):
            if isinstance(value, str):
                add(value)
    for value in discovery.get('form_urls', []):
        if isinstance(value, str):
            add(value, bonus=10, interactive=2)
    for value in discovery.get('browser_navigation_urls', []):
        if isinstance(value, str):
            add(value, bonus=8, interactive=1)
    for row in discovery.get('request_cases', []):
        if not isinstance(row, dict):
            continue
        method = str(row.get('method') or 'GET').upper()
        params = row.get('parameters') if isinstance(row.get('parameters'), list) else []
        bonus = (12 if method in {'POST', 'PUT', 'PATCH', 'DELETE'} else 4) + min(18, len(params) * 3)
        add(str(row.get('url') or ''), bonus=bonus, interactive=3)
    for row in discovery.get('browser_network_requests', []):
        if isinstance(row, dict):
            add(str(row.get('url') or ''), bonus=14, interactive=3)
    for row in discovery.get('script_endpoint_hints', []):
        if isinstance(row, dict):
            add(str(row.get('url') or ''), bonus=8, interactive=1)
    return evidence


def discovered_scope_origin_ranking(discovery: dict[str, Any], target: str) -> list[tuple[str, int]]:
    ranked: list[tuple[str, int]] = []
    for origin, bucket in _discovered_scope_origin_evidence(discovery, target).items():
        score = int(bucket['max_score']) + min(24, int(bucket['observations'])) + min(24, int(bucket['interactive']))
        ranked.append((origin, score))
    return sorted(ranked, key=lambda item: (-item[1], item[0]))


def sibling_broad_origin_limits() -> tuple[int, int]:
    base = max(0, int(BROAD_SIBLING_ORIGIN_BASE_LIMITS.get(CURRENT_SCAN_MODE, 3)))
    maximum = max(base, int(BROAD_SIBLING_ORIGIN_MAX_LIMITS.get(CURRENT_SCAN_MODE, base)))
    return base, maximum


def select_sibling_broad_origins(discovery: dict[str, Any], target: str) -> dict[str, Any]:
    ranking = discovered_scope_origin_ranking(discovery, target)
    base_limit, max_limit = sibling_broad_origin_limits()
    if not ranking or base_limit <= 0:
        return {'selected': [], 'ranking': ranking, 'base_limit': base_limit, 'max_limit': max_limit, 'overflow': 0, 'cutoff_score': None, 'threshold_score': None}

    selected = list(ranking[:base_limit])
    if len(ranking) <= base_limit or len(selected) >= max_limit:
        return {'selected': selected, 'ranking': ranking, 'base_limit': base_limit, 'max_limit': max_limit, 'overflow': 0, 'cutoff_score': selected[-1][1] if selected else None, 'threshold_score': None}

    cutoff_score = int(selected[-1][1])
    threshold_score = int(math.ceil(cutoff_score * BROAD_SIBLING_ADAPTIVE_RATIO))
    evidence = _discovered_scope_origin_evidence(discovery, target)
    for origin, score in ranking[base_limit:]:
        if len(selected) >= max_limit:
            break
        # Ranking is descending, so once the score falls below the adaptive threshold no later
        # origin can qualify. Non-interactive origins are skipped without consuming overflow slots.
        if int(score) < threshold_score:
            break
        bucket = evidence.get(origin, {})
        if int(bucket.get('interactive', 0)) <= 0:
            continue
        selected.append((origin, score))

    return {
        'selected': selected,
        'ranking': ranking,
        'base_limit': base_limit,
        'max_limit': max_limit,
        'overflow': max(0, len(selected) - min(base_limit, len(ranking))),
        'cutoff_score': cutoff_score,
        'threshold_score': threshold_score,
    }


def sibling_broad_origin_limit() -> int:
    # Backward-compatible helper: returns the adaptive maximum, not the normal base allocation.
    return sibling_broad_origin_limits()[1]


def sibling_broad_timeout(tool: str, base_timeout: float | int | None=None) -> int:
    scanner = str(tool or '').lower()
    if base_timeout is None:
        base_timeout = BROAD_SCANNER_TIMEOUTS.get(scanner, 180)
    factor = float(BROAD_SIBLING_TIMEOUT_FACTORS.get(CURRENT_SCAN_MODE, 0.60))
    return max(45, int(float(base_timeout) * factor))


def discovered_scope_origins(discovery: dict[str, Any], target: str, limit: int | None=None) -> list[str]:
    ranking = discovered_scope_origin_ranking(discovery, target)
    if limit is None:
        return [origin for origin, _ in ranking]
    return [origin for origin, _ in ranking[:max(0, int(limit))]]


# Filters discovery evidence to one origin so broad scanners can test sibling origins independently without sharing cookies.
def discovery_for_origin(discovery: dict[str, Any], origin: str) -> dict[str, Any]:
    filtered: dict[str, Any] = {}
    for key in ('urls', 'html_urls', 'form_urls', 'parameterized_urls', 'script_urls', 'browser_navigation_urls'):
        filtered[key] = [value for value in discovery.get(key, []) if isinstance(value, str) and same_origin(origin, value)]
    for key in ('request_cases', 'browser_network_requests', 'script_endpoint_hints', 'client_side_candidates', 'destructive_request_cases', 'coverage_skipped_cases'):
        rows = []
        for row in discovery.get(key, []):
            if not isinstance(row, dict):
                continue
            row_url = str(row.get('url') or row.get('source_url') or '')
            if row_url and same_origin(origin, row_url):
                rows.append(dict(row))
        filtered[key] = rows
    filtered['jwt_tokens'] = list(discovery.get('jwt_tokens', []))
    filtered['errors'] = []
    filtered['destructive_urls_skipped'] = [value for value in discovery.get('destructive_urls_skipped', []) if isinstance(value, str) and same_origin(origin, value)]
    filtered['authentication_effective'] = None
    filtered['authentication_note'] = 'Sibling authorized origin is scanned without reusing the primary-origin cookie.'
    filtered['authentication_probe'] = {}
    filtered['target_preparation'] = {'performed': False, 'configured': False, 'usable': True}
    filtered['budget_diagnostics'] = dict(discovery.get('budget_diagnostics') or {})
    return filtered


# Combines discovery results without duplicating pages or request cases.
def merge_discovery(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = dict(left)
    for key in ('urls', 'html_urls', 'form_urls', 'parameterized_urls', 'script_urls', 'browser_navigation_urls', 'jwt_tokens'):
        merged[key] = sorted(set(left.get(key, [])) | set(right.get(key, [])))
    merged['request_cases'] = _dedupe_request_cases([*left.get('request_cases', []), *right.get('request_cases', [])])
    coverage_skips: list[dict[str, Any]] = []
    seen_coverage_skips: set[tuple[str, str, str]] = set()
    for row in [*left.get('coverage_skipped_cases', []), *right.get('coverage_skipped_cases', [])]:
        if not isinstance(row, dict):
            continue
        key = (str(row.get('method') or 'GET').upper(), str(row.get('url') or ''), str(row.get('reason_code') or ''))
        if not key[1] or key in seen_coverage_skips:
            continue
        seen_coverage_skips.add(key)
        coverage_skips.append(dict(row))
    merged['coverage_skipped_cases'] = coverage_skips
    for key, identity in (('script_endpoint_hints', lambda row: (str(row.get('method') or ''), str(row.get('url') or ''))), ('browser_network_requests', lambda row: (str(row.get('method') or ''), str(row.get('url') or ''), str(row.get('resource_type') or '')))):
        rows: list[dict[str, Any]] = []
        seen_rows: set[tuple[Any, ...]] = set()
        for row in [*left.get(key, []), *right.get(key, [])]:
            if not isinstance(row, dict):
                continue
            row_key = identity(row)
            if not row_key or row_key in seen_rows:
                continue
            seen_rows.add(row_key)
            rows.append(row)
        merged[key] = rows
    client_rows: list[dict[str, Any]] = []
    seen_client: set[str] = set()
    for row in [*left.get('client_side_candidates', []), *right.get('client_side_candidates', [])]:
        if not isinstance(row, dict):
            continue
        url = str(row.get('url') or '')
        if not url or url in seen_client:
            continue
        seen_client.add(url)
        client_rows.append(row)
    merged['client_side_candidates'] = client_rows
    merged['errors'] = [*left.get('errors', []), *right.get('errors', [])]
    merged['destructive_urls_skipped'] = sorted(set(left.get('destructive_urls_skipped', [])) | set(right.get('destructive_urls_skipped', [])))
    merged['destructive_request_cases'] = _dedupe_request_cases([*left.get('destructive_request_cases', []), *right.get('destructive_request_cases', [])])
    if right.get('authentication_probe'):
        merged['authentication_probe'] = right.get('authentication_probe')
    if right.get('authentication_effective') is not None:
        merged['authentication_effective'] = right.get('authentication_effective')
        merged['authentication_note'] = right.get('authentication_note')
    left_budget = left.get('budget_diagnostics') if isinstance(left.get('budget_diagnostics'), dict) else {}
    right_budget = right.get('budget_diagnostics') if isinstance(right.get('budget_diagnostics'), dict) else {}
    merged['budget_diagnostics'] = {**left_budget, **right_budget}
    return merged

# URL ranking relies on a small set of security-related words to prioritize discovered paths.
def _risk_terms(value: str) -> int:
    text = value.lower()
    tokens = set(re.findall('[a-z0-9]+', text))
    weights = {'cmd': 12, 'command': 12, 'exec': 12, 'shell': 12, 'sql': 11, 'query': 8, 'search': 7, 'file': 10, 'path': 10, 'include': 10, 'template': 9, 'upload': 8, 'url': 9, 'uri': 8, 'redirect': 8, 'callback': 8, 'webhook': 8, 'admin': 8, 'role': 8, 'user': 6, 'uid': 7, 'id': 5, 'token': 7, 'debug': 7, 'api': 5, 'xml': 7, 'deserialize': 10, 'xss': 10, 'sqli': 11, 'ssrf': 11, 'lfi': 11, 'rfi': 11}
    return sum((weight for term, weight in weights.items() if (term in tokens if len(term) <= 3 else term in text)))

# Request classification marks cases that belong to an authentication flow.
def _is_login_case(case: dict[str, Any]) -> bool:
    path = urlparse(str(case.get('url', ''))).path.lower().rstrip('/')
    parameters = {str(value).lower() for value in case.get('parameters', [])}
    identity_provider = (
        '/protocol/openid-connect/' in path
        or '/oauth2/' in path
        or '/oauth/' in path
        or '/auth/realms/' in path
    )
    return path.endswith(('/login', '/login.php', '/signin', '/sign-in', '/auth', '/authorize', '/ssologin', '/ssologin.php', '/sso/login')) or identity_provider or bool({'username', 'password'} <= parameters)

# Logout endpoints are kept out of ordinary fuzzing and are tested only as an authenticated
# session-lifecycle action at the end of the assessment.
def _is_logout_url(value: str) -> bool:
    parsed = urlparse(str(value or ''))
    path = parsed.path.lower().rstrip('/')
    path_tokens = {token for token in re.split(r'[^a-z0-9]+', path) if token}
    logout_tokens = {'logout', 'signout', 'logoff'}
    if path.endswith(('/logout', '/logout.php', '/signout', '/sign-out', '/logoff', '/log-off')) or bool(path_tokens & logout_tokens):
        return True
    for name, raw_value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered_name = name.lower()
        lowered_value = raw_value.lower()
        if lowered_name in logout_tokens or any(token in lowered_value for token in ('logout', 'signout', 'logoff', 'sign-out', 'log-off')):
            return True
    return False

def _is_logout_case(case: dict[str, Any]) -> bool:
    return _is_logout_url(str(case.get('url', '')))

# Discovery never executes logout during normal crawling, but it preserves safe request metadata
# for a final authenticated session-lifecycle check. URL-only discoveries are synthesized as GET.
def select_logout_request_cases(discovery: dict[str, Any], limit: int=3) -> list[dict[str, Any]]:
    cases = [dict(case) for case in discovery.get('destructive_request_cases', []) if isinstance(case, dict) and _is_logout_case(case)]
    known = {(str(case.get('method', 'GET')).upper(), str(case.get('url', '')), str(case.get('data', ''))) for case in cases}
    for value in discovery.get('destructive_urls_skipped', []):
        url = str(value or '')
        if not _is_logout_url(url):
            continue
        key = ('GET', url, '')
        if key in known:
            continue
        known.add(key)
        cases.append({
            'url': url, 'method': 'GET', 'data': '',
            'parameters': [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)],
            'fields': [], 'source_url': url, 'destructive_kind': 'logout',
        })
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for case in cases:
        key = (str(case.get('method', 'GET')).upper(), str(case.get('url', '')), str(case.get('data', '')))
        if key in seen:
            continue
        seen.add(key)
        selected.append(case)
        if len(selected) >= max(1, int(limit)):
            break
    return selected

def select_logout_urls(discovery: dict[str, Any], limit: int=3) -> list[str]:
    return [str(case.get('url', '')) for case in select_logout_request_cases(discovery, limit=limit)]

# Query inspection detects URLs made only of automatic index-style parameters.
def _is_auto_index_url(url: str) -> bool:

    parsed = urlparse(str(url))
    names = {name.lower() for name, _ in parse_qsl(parsed.query.replace(';', '&'), keep_blank_values=True)}
    return bool(names) and names <= AUTO_INDEX_PARAMETERS and parsed.path.endswith('/')

# Parameter inspection detects request cases that contain only automatic index values.
def _is_auto_index_case(case: dict[str, Any]) -> bool:
    names = {str(value).lower() for value in case.get('parameters', [])}
    return _is_auto_index_url(str(case.get('url', ''))) or (bool(names) and names <= AUTO_INDEX_PARAMETERS and urlparse(str(case.get('url', ''))).path.endswith('/'))
SQL_HINTS = {'id', 'uid', 'user', 'user_id', 'userid', 'username', 'email', 'account', 'accountid', 'query', 'search', 'q', 'filter', 'sort', 'page', 'offset', 'limit', 'category', 'product', 'productid', 'item', 'itemid', 'order', 'orderid', 'dashboardid', 'widgetid', 'deviceid', 'modelid', 'serviceid'}
XSS_HINTS = {'name', 'message', 'comment', 'search', 'query', 'q', 'input', 'text', 'title', 'pagetitle', 'html', 'content', 'url', 'linkurl', 'redirect', 'callback', 'fromsubmenu'}
COMMAND_HINTS = {'cmd', 'command', 'exec', 'shell', 'ip', 'host', 'hostname', 'ping', 'target', 'domain'}
# 'redirect'/'linkurl' were added: a parameter that selects which internal page/module to load by
# name (e.g. redirect=devices.php) is a routing-by-filename pattern and a classic local-file-
# inclusion/path-traversal vector, not merely an XSS-reflection surface.
TRAVERSAL_HINTS = {'file', 'filename', 'path', 'page', 'include', 'template', 'document', 'folder', 'dir', 'directory', 'view', 'resource', 'download', 'redirect', 'linkurl'}
IDOR_HINTS = {'id', 'uid', 'user_id', 'userid', 'account_id', 'accountid', 'object_id', 'objectid', 'item_id', 'itemid', 'order_id', 'orderid', 'document_id', 'documentid', 'file_id', 'fileid', 'profile_id', 'profileid', 'dashboardid', 'widgetid', 'deviceid', 'modelid'}
NAVIGATION_PARAMETERS = {'pagetitle', 'linkid', 'fromsubmenu', 'showframe', 'redirect', 'linkurl'}

# Very large generated table/filter requests are poor specialist targets: they create huge
# command lines and long scans while mostly exercising framework/navigation controls.
def _oversized_generated_request(case: dict[str, Any]) -> bool:
    url = str(case.get('url', ''))
    parameters = _case_parameters(case)
    lowered = {name.lower() for name in parameters}
    table_controls = sum(1 for name in lowered if name.startswith(('columns[', 'order[', 'search[')))
    encoded_table_controls = url.lower().count('columns%5b') + url.lower().count('order%5b')
    return len(url) > 2200 or len(parameters) > 45 or table_controls >= 12 or encoded_table_controls >= 12

# Parameter extraction lists the names available in a normalized request case.
def _case_parameters(case: dict[str, Any]) -> set[str]:
    parameters = {str(value).lower() for value in case.get('parameters', []) if str(value)}
    parsed = urlparse(str(case.get('url', '')))
    parameters.update((name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)))
    return parameters

INTERNAL_RESOURCE_VALUE_PATTERN = re.compile(r'\.(php\d?|phtml|jsp|jspx|asp|aspx|cgi|pl|do|action|html?)(?:[/?]|$)')

# Generic (application-agnostic) detector for a parameter whose VALUE, not just its name, selects
# an internal server-side file or module (e.g. redirect=devices.php, page=admin/setup.jsp,
# tpl=../../etc/passwd). Name-based hint sets like TRAVERSAL_HINTS miss this whole vulnerability
# class whenever the application uses an otherwise-unremarkable parameter name (redirect, tab,
# mod, scr, ...) to route to a file by value, which is a common local-file-inclusion and path-
# traversal pattern independent of the specific target application.
def _parameter_values_reference_internal_resource(case: dict[str, Any]) -> bool:
    values: list[str] = [value for _, value in parse_qsl(urlparse(str(case.get('url', ''))).query, keep_blank_values=True)]
    for field in case.get('fields', []) if isinstance(case.get('fields'), list) else []:
        if isinstance(field, dict) and field.get('value'):
            values.append(str(field['value']))
    for raw in values:
        try:
            value = unquote(unquote(str(raw or ''))).lower()
        except Exception:
            value = str(raw or '').lower()
        if not value:
            continue
        if INTERNAL_RESOURCE_VALUE_PATTERN.search(value):
            return True
        if '../' in value or '..%2f' in value or '..\\' in value or value.startswith('/etc/') or value.startswith('file:'):
            return True
    return False

# XSS routing sends DOM-oriented cases to the browser when that gives better coverage.
def _prefer_browser_for_xss_case(case: dict[str, Any]) -> bool:

    method = str(case.get('method', 'GET')).upper()
    fields = [item for item in case.get('fields', []) if isinstance(item, dict)]
    field_types = {str(item.get('type') or item.get('tag') or '').lower() for item in fields}
    names = {str(item.get('name') or '').lower() for item in fields}
    path = urlparse(str(case.get('url', ''))).path.lower()
    stored_shape = method == 'POST' and ('textarea' in field_types or bool(names & {'message', 'comment', 'content', 'body', 'description', 'bio'}) or any((token in path for token in ('guestbook', 'comment', 'message', 'feedback', 'stored'))))
    dom_shape = method == 'GET' and ('select' in field_types or bool(case.get('client_sources')) or bool(case.get('client_side_evidence'))) and any((token in path for token in ('xss', 'dom', 'javascript', 'client')))
    return stored_shape or dom_shape

# Scores one request case for a specific scanner.
def _tool_case_priority(tool: str, case: dict[str, Any], authenticated_profile: bool=False) -> int:

    if _is_auto_index_case(case):
        return -1000
    url = str(case.get('url', ''))
    parsed = urlparse(url)
    path = parsed.path.lower()
    method = str(case.get('method', 'GET')).upper()
    parameters = _case_parameters(case)
    text = ' '.join((path, ' '.join(sorted(parameters))))
    score = _risk_terms(text)
    if method == 'POST':
        score += 10
    if 'json' in str(case.get('content_type') or case.get('enctype') or '').lower():
        score += 6
    if case.get('discovery_source') == 'playwright_network':
        score += 4
    anonymous_login_flow = (not authenticated_profile) and _is_login_case(case)
    if tool in {'sqlmap', 'dalfox', 'commix', 'traversal'} and _is_logout_case(case):
        return -1000
    if tool in {'sqlmap', 'dalfox', 'commix', 'traversal'} and _oversized_generated_request(case):
        return -1000
    browser_response = case.get('browser_response') if isinstance(case.get('browser_response'), dict) else {}
    if browser_response.get('observed') is True:
        status = int(browser_response.get('status') or 0)
        if 200 <= status < 400:
            score += 10
        elif status in {404, 410}:
            score -= 80
        elif status >= 500:
            score += 4
    if tool == 'sqlmap':
        if authenticated_profile and _is_login_case(case):
            return -1000
        score += 45 if any((token in path for token in ('sql', 'query', 'database', 'search'))) else 0
        score += 18 if any((token in path for token in ('/api', 'data', 'device', 'model', 'dashboard', 'widget'))) else 0
        score += 14 * len(parameters & SQL_HINTS)
        score += 16 if method == 'POST' else 0
        score += 12 if 'json' in str(case.get('content_type') or case.get('enctype') or '').lower() else 0
        score += 8 if case.get('discovery_source') == 'playwright_network' else 0
        if parameters and parameters <= NAVIGATION_PARAMETERS and not (parameters & SQL_HINTS) and not anonymous_login_flow:
            score -= 65
        if authenticated_profile and _is_login_case(case) and (not any((token in path for token in ('sql', 'query', 'database')))):
            score -= 100
        if 'brute' in path and (not any((token in path for token in ('sql', 'query', 'database')))):
            score -= 90
        if any((token in path for token in ('xss', '/exec', '/csp'))) and (not parameters & SQL_HINTS):
            score -= 35
        return max(score, 12) if anonymous_login_flow else score
    if tool == 'dalfox':
        if _prefer_browser_for_xss_case(case) or (authenticated_profile and _is_login_case(case)):
            return -1000
        score += 45 if any((token in path for token in ('xss', 'comment', 'message', 'search', 'feedback'))) else 0
        score += 12 * len(parameters & XSS_HINTS)
        score += 10 if case.get('discovery_source') == 'playwright_network' else 0
        if any((token in path for token in ('sqli', '/exec', '/csp'))) and (not parameters & XSS_HINTS):
            score -= 35
        if authenticated_profile and _is_login_case(case):
            score -= 30
        return max(score, 12) if anonymous_login_flow else score
    if tool == 'commix':
        if authenticated_profile and _is_login_case(case):
            return -1000
        score += 55 if any((token in path for token in ('/exec', 'command', 'cmd'))) else 0
        score += 13 * len(parameters & COMMAND_HINTS)
        if any((token in path for token in ('sqli', 'xss', '/csp'))) and (not parameters & COMMAND_HINTS):
            score -= 45
        if authenticated_profile and _is_login_case(case):
            score -= 40
        return max(score, 12) if anonymous_login_flow else score
    if tool == 'traversal':
        if authenticated_profile and _is_login_case(case):
            return -1000
        score += 55 if any((token in path for token in ('include', 'download', 'file', 'template', 'document', 'view'))) else 0
        score += 15 * len(parameters & TRAVERSAL_HINTS)
        # Application-agnostic signal: the parameter VALUE (not its name) already looks like it
        # selects a server-side file/module, e.g. redirect=devices.php. This catches routing-by-
        # filename parameters that a name-only hint list would miss under an unrelated name.
        if _parameter_values_reference_internal_resource(case):
            score += 40
        if any((token in path for token in ('sqli', 'xss', '/exec', '/csp'))) and (not parameters & TRAVERSAL_HINTS):
            score -= 45
        if authenticated_profile and _is_login_case(case):
            score -= 40
        return max(score, 12) if anonymous_login_flow else score
    if tool == 'idor':
        if method != 'GET':
            return -1000
        numeric_pairs = [(name.lower(), value) for name, value in parse_qsl(parsed.query, keep_blank_values=True) if value.isdigit()]
        object_pairs = [(name, value) for name, value in numeric_pairs if name in IDOR_HINTS]
        if not object_pairs or any((token in path for token in ('brute', 'csrf', 'password', 'sqli', 'xss', '/exec', '/csp'))):
            return -1000
        score = 20 + 28 * len(object_pairs)
        score += 25 if any((token in path for token in ('idor', 'object', 'profile', 'account', 'user'))) else 0
        if any((token in path for token in ('sqli', 'xss', '/exec', '/csp'))):
            score -= 60
        return score
    return score

# Explains why a request case should not be sent to a scanner.
def _tool_case_skip_reason(tool: str, case: dict[str, Any], authenticated_profile: bool=False) -> str:
    if not [value for value in case.get('parameters', []) if str(value)]:
        return 'The request has no testable application parameter for this parameter scanner.'
    if _is_auto_index_case(case):
        return 'Directory-index sorting parameters are navigation controls, not application inputs.'
    if tool == 'dalfox' and _prefer_browser_for_xss_case(case):
        return 'Stored or DOM-oriented XSS contracts are delegated to the Chromium verifier, which can execute JavaScript and revisit state.'
    if tool in {'sqlmap', 'dalfox', 'commix', 'traversal'} and _is_logout_case(case):
        return f'{tool} is not sent to logout endpoints; anonymous profiles ignore logout and authenticated profiles validate logout only in the final session-lifecycle check.'
    if authenticated_profile and tool in {'sqlmap', 'dalfox', 'commix', 'traversal'} and _is_login_case(case):
        return f'{tool} is not sent to identity-provider/login/SSO endpoints in the authenticated profile; the anonymous profile remains eligible to test those public flows.'
    if tool in {'sqlmap', 'dalfox', 'commix', 'traversal'} and _oversized_generated_request(case):
        return f'{tool} is not sent to oversized generated table/filter requests; specialist testing is reserved for concise application parameters.'
    if tool == 'sqlmap' and 'brute' in urlparse(str(case.get('url', ''))).path.lower():
        return 'The brute-force handler is an authentication workflow, not a SQL-query request class.'
    if _tool_case_priority(tool, case, authenticated_profile=authenticated_profile) <= 0:
        if CURRENT_SCAN_MODE == 'deep' and case.get('deep_breadth') and tool in {'sqlmap', 'dalfox'}:
            return ''
        return f"The request was not selected because its path and parameters do not match {tool}'s vulnerability class."
    return ''

# Chooses the best request cases for one scanner and scan profile.
def select_tool_request_cases(discovery: dict[str, Any], tool: str, limit: int | None=None, authenticated_profile: bool=False) -> list[dict[str, Any]]:

    effective_limit = int(limit or PARAMETER_TOOL_CASE_LIMITS.get(tool, MAX_PARAMETER_ENDPOINTS))
    cases = [case for case in discovery.get('request_cases', []) if isinstance(case, dict)]
    known = {str(case.get('url') or '') for case in cases}
    for value in discovery.get('parameterized_urls', []):
        url = str(value or '')
        if url and url not in known:
            cases.append({'url': url, 'method': 'GET', 'data': '', 'parameters': [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)], 'source_url': url, 'synthetic_from_parameterized_url': True})
    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            continue
        if str(case.get('method', 'GET')).upper() not in {'GET', 'POST'}:
            continue
        if not [value for value in case.get('parameters', []) if str(value)]:
            continue
        score = _tool_case_priority(tool, case, authenticated_profile=authenticated_profile)
        if score > 0:
            ranked.append((score, -index, case))
    unique_ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    shape_counts: dict[tuple[str, tuple[str, str, tuple[str, ...]], tuple[str, ...]], int] = {}
    variant_cap = max(1, int(DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, {}).get('route_variants', 2)))
    for score, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
        method = str(case.get('method', 'GET')).upper()
        url = str(case.get('url', ''))
        params = tuple(sorted((str(value).lower() for value in case.get('parameters', []) if str(value))))
        key = (method, url, params)
        shape = (method, _discovery_route_signature(url), params)
        if key in seen or shape_counts.get(shape, 0) >= variant_cap:
            continue
        seen.add(key)
        shape_counts[shape] = shape_counts.get(shape, 0) + 1
        unique_ranked.append((int(score), case))

    if CURRENT_SCAN_MODE == 'deep' and tool in {'sqlmap', 'dalfox'} and len(unique_ranked) < effective_limit:
        extra_budget = min(2, effective_limit - len(unique_ranked))
        extras: list[tuple[int, int, dict[str, Any]]] = []
        for index, case in enumerate(cases):
            if not isinstance(case, dict):
                continue
            method = str(case.get('method', 'GET')).upper()
            url = str(case.get('url') or '')
            path = urlparse(url).path.lower()
            params = [str(value) for value in case.get('parameters', []) if str(value)]
            if method != 'GET' or not url or not params or _is_auto_index_case(case) or _destructive_crawl_url(url):
                continue
            if any(token in path for token in ('logout', 'setup', 'reset', 'delete', 'security.php')):
                continue
            if tool == 'sqlmap' and (_is_login_case(case) or 'brute' in path):
                continue
            if tool == 'dalfox' and _prefer_browser_for_xss_case(case):
                continue
            param_key = tuple(sorted(value.lower() for value in params))
            key = (method, url, param_key)
            shape = (method, _discovery_route_signature(url), param_key)
            if key in seen or shape_counts.get(shape, 0) >= variant_cap:
                continue
            generic_score = _risk_terms(path + ' ' + ' '.join(params)) + min(18, len(params) * 4)
            extras.append((generic_score, -index, {**case, 'deep_breadth': True, 'selection_reason': f'deep-generic-{tool}-coverage'}))
        for score, _, case in sorted(extras, key=lambda item: (-item[0], -item[1]))[:extra_budget]:
            method = str(case.get('method', 'GET')).upper()
            url = str(case.get('url', ''))
            param_key = tuple(sorted((str(value).lower() for value in case.get('parameters', []) if str(value))))
            key = (method, url, param_key)
            shape = (method, _discovery_route_signature(url), param_key)
            if shape_counts.get(shape, 0) >= variant_cap:
                continue
            seen.add(key)
            shape_counts[shape] = shape_counts.get(shape, 0) + 1
            unique_ranked.append((int(score), case))
    return _select_with_adaptive_specialist_budget(tool, unique_ranked, effective_limit)

BROWSER_STATIC_SUFFIXES = {'.css', '.js', '.mjs', '.map', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.wav', '.mp4', '.webm', '.pdf', '.zip'}

# Browser XSS checks target rendered application pages, not standalone static assets.
def _browser_static_resource(url: str) -> bool:
    return Path(urlparse(str(url or '')).path.lower()).suffix in BROWSER_STATIC_SUFFIXES

WORKFLOW_STATE_HINTS = {'change', 'update', 'save', 'create', 'submit', 'send', 'comment', 'message', 'feedback', 'upload', 'password', 'email', 'profile', 'settings', 'transfer', 'captcha', 'admin'}
WORKFLOW_DESTRUCTIVE_HINTS = {'logout', 'signout', 'logoff', 'setup', 'install', 'delete', 'remove', 'drop', 'truncate', 'purge', 'wipe', 'reset'}

# Returns evidence labels that justify spending adaptive overflow on a deferred specialist case.
def _adaptive_specialist_evidence(tool: str, case: dict[str, Any]) -> list[str]:

    name = str(tool or '').lower()
    url = str(case.get('url') or '')
    path = urlparse(url).path.lower()
    method = str(case.get('method') or 'GET').upper()
    parameters = _case_parameters(case)
    content_type = str(case.get('content_type') or case.get('enctype') or '').lower()
    class_reasons: list[str] = []
    generic_reasons: list[str] = []
    if method == 'POST':
        generic_reasons.append('POST request contract')
    if 'json' in content_type:
        generic_reasons.append('JSON request body')
    if case.get('discovery_source') == 'playwright_network':
        generic_reasons.append('observed XHR/fetch request')
    response = case.get('browser_response') if isinstance(case.get('browser_response'), dict) else {}
    if response.get('observed') is True:
        try:
            status = int(response.get('status') or 0)
        except (TypeError, ValueError):
            status = 0
        if 200 <= status < 400:
            generic_reasons.append('observed live 2xx/3xx response')
    if any(hint in path for hint in ADAPTIVE_HIGH_VALUE_PATH_HINTS):
        generic_reasons.append('high-value application/API route')
    if name == 'sqlmap':
        if parameters & SQL_HINTS:
            class_reasons.append('SQL-relevant parameter')
        if any(token in path for token in ('sql', 'query', 'database', 'search')):
            class_reasons.append('SQL/data-oriented route')
    elif name == 'dalfox':
        if parameters & XSS_HINTS:
            class_reasons.append('XSS-relevant parameter')
        if any(token in path for token in ('xss', 'comment', 'message', 'search', 'feedback')):
            class_reasons.append('XSS-oriented route')
    elif name == 'commix':
        if parameters & COMMAND_HINTS:
            class_reasons.append('command-execution parameter')
        if any(token in path for token in ('/exec', 'command', '/cmd')):
            class_reasons.append('command-execution route')
    elif name == 'traversal':
        if parameters & TRAVERSAL_HINTS:
            class_reasons.append('file/path parameter')
        if any(token in path for token in ('include', 'download', 'file', 'template', 'document', 'view')):
            class_reasons.append('file/path-oriented route')
    elif name == 'idor':
        numeric_pairs = [(key.lower(), value) for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True) if value.isdigit()]
        if any(key in IDOR_HINTS for key, _ in numeric_pairs):
            class_reasons.append('numeric object-reference parameter')
        if any(token in path for token in ('idor', 'object', 'profile', 'account', 'user', 'dashboard', 'widget', 'device')):
            class_reasons.append('object/resource-oriented route')
    elif name == 'authorization':
        auth_names = parameters & AUTHORIZATION_PARAMETER_HINTS
        path_tokens = {token for token in re.split('[^a-z0-9_-]+', path) if token}
        if auth_names:
            class_reasons.append('authorization/object identifier parameter')
        if path_tokens & AUTHORIZATION_PATH_HINTS:
            class_reasons.append('identity/privileged-resource route')
    elif name == 'browser':
        if parameters & XSS_HINTS:
            class_reasons.append('XSS-relevant parameter')
        if case.get('client_sources') or case.get('client_sinks') or case.get('client_side_evidence'):
            class_reasons.append('client-side source/sink evidence')
    elif name == 'workflow':
        names = _case_field_names(case)
        if case.get('file_parameters') or 'multipart/form-data' in content_type:
            class_reasons.append('upload-capable form')
        if case.get('token_parameters'):
            class_reasons.append('anti-CSRF/token field')
        if any('captcha' in value for value in names) or 'captcha' in path:
            class_reasons.append('CAPTCHA workflow')
        if _is_login_case(case):
            class_reasons.append('authentication workflow')
        if names & WORKFLOW_STATE_HINTS or any(token in path for token in WORKFLOW_STATE_HINTS):
            class_reasons.append('state-changing workflow field')
    elif name == 'arjun':
        if parameters:
            class_reasons.append('existing application parameters')
        if case.get('fields'):
            class_reasons.append('discovered form fields')
        if any(hint in path for hint in ADAPTIVE_HIGH_VALUE_PATH_HINTS):
            class_reasons.append('API/form candidate route')
    return [*class_reasons, *generic_reasons] if class_reasons else []

# Extends a saturated specialist base only for deferred high-value cases near the base cutoff.
def _select_with_adaptive_specialist_budget(tool: str, ranked: list[tuple[int, dict[str, Any]]], base_limit: int) -> list[dict[str, Any]]:

    requested = max(1, int(base_limit))
    configured_base = specialist_base_limit(tool)
    selected = [{**case, 'priority_score': int(score)} for score, case in ranked[:requested]]
    extra_capacity = int(ADAPTIVE_SPECIALIST_OVERFLOW.get(CURRENT_SCAN_MODE, {}).get(str(tool or '').lower(), 0))
    if requested != configured_base or extra_capacity <= 0 or len(ranked) <= requested or len(selected) < requested:
        return selected
    cutoff_score = int(ranked[requested - 1][0])
    threshold = max(1, (cutoff_score * 3 + 3) // 4)
    for score, case in ranked[requested:]:
        if len(selected) >= requested + extra_capacity:
            break
        evidence = _adaptive_specialist_evidence(tool, case)
        if int(score) < threshold or not evidence:
            continue
        selected.append({
            **case,
            'priority_score': int(score),
            'adaptive_budget': True,
            'adaptive_budget_base': requested,
            'adaptive_budget_max': requested + extra_capacity,
            'adaptive_budget_threshold': threshold,
            'adaptive_budget_evidence': evidence,
            'selection_reason': 'adaptive-high-value-overflow',
        })
    return selected

# Collects field names from the query string and request body.
def _case_field_names(case: dict[str, Any]) -> set[str]:
    names = _case_parameters(case)
    names.update((str(value).lower() for value in case.get('file_parameters', []) if str(value)))
    names.update((str(value).lower() for value in case.get('token_parameters', []) if str(value)))
    for field in case.get('fields', []) if isinstance(case.get('fields'), list) else []:
        if isinstance(field, dict) and str(field.get('name') or ''):
            names.add(str(field['name']).lower())
    return names

# Builds a stable key used to remove duplicate browser cases.
def _browser_url_key(value: str) -> tuple[str, str, int, str]:
    try:
        parsed = urlparse(str(value or ''))
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or '').lower()
        if scheme not in {'http', 'https'} or not host:
            return ('', '', 0, '')
        port = parsed.port or (443 if scheme == 'https' else 80)
    except ValueError:
        return ('', '', 0, '')
    path = re.sub('/+', '/', parsed.path or '/')
    if path != '/':
        path = path.rstrip('/')
    return (scheme, host, port, path.lower())

# Scores a request case for browser-based checks.
def _browser_case_priority(case: dict[str, Any], client_keys: set[tuple[str, str, int, str]]) -> int:
    url = str(case.get('url', ''))
    path = urlparse(url).path.lower()
    if _is_auto_index_case(case) or _destructive_crawl_url(url) or _browser_static_resource(url):
        return -1000
    parameters = _case_field_names(case)
    path_match = any((token in path for token in ('xss', 'dom', 'comment', 'message', 'feedback', 'search', 'query', 'profile', 'preview')))
    xss_hits = parameters & XSS_HINTS
    client_match = _browser_url_key(url) in client_keys or _browser_url_key(str(case.get('source_url') or '')) in client_keys or bool(case.get('client_sources'))
    score = 0
    if path_match:
        score += 75
    if CURRENT_SCAN_MODE == 'deep':
        if any(token in path for token in ('csp', 'javascript', 'client', 'redirect', 'callback')):
            score += 70
        elif any(token in path for token in ('upload', 'preview')):
            score += 35
    score += 16 * len(xss_hits)
    if str(case.get('method', 'GET')).upper() == 'POST' and (path_match or xss_hits or client_match):
        score += 18
    if client_match:
        score += 100
    if case.get('client_side_only'):
        score -= 35
    if case.get('parameters'):
        score += 20
    if _is_login_case(case):
        score -= 60
    return score

# Chooses pages and requests that are useful for browser checks.
def select_browser_request_cases(discovery: dict[str, Any], limit: int | None=None) -> list[dict[str, Any]]:

    effective_limit = int(limit or PARAMETER_TOOL_CASE_LIMITS.get('browser', 2))
    raw_client = [dict(item) for item in discovery.get('client_side_candidates', []) if isinstance(item, dict) and str(item.get('url') or '')]
    client_by_key: dict[tuple[str, str, int, str], list[dict[str, Any]]] = {}
    for item in raw_client:
        client_by_key.setdefault(_browser_url_key(str(item.get('url') or '')), []).append(item)
    client_keys = set(client_by_key)
    cases = [dict(case) for case in discovery.get('request_cases', []) if isinstance(case, dict)]
    matched_client_keys: set[tuple[str, str, int, str]] = set()
    for case in cases:
        keys = {_browser_url_key(str(case.get('url') or '')), _browser_url_key(str(case.get('source_url') or ''))}
        evidence = [item for key in keys for item in client_by_key.get(key, [])]
        if not evidence:
            continue
        matched_client_keys.update(keys & client_keys)
        case['client_sources'] = sorted({str(value) for item in evidence for value in item.get('sources', []) if str(value)})
        case['client_sinks'] = sorted({str(value) for item in evidence for value in item.get('sinks', []) if str(value)})
        case['client_side_evidence'] = evidence
    for key, evidence in sorted(client_by_key.items(), key=lambda item: item[0]):
        if key in matched_client_keys:
            continue
        url = str(evidence[0].get('url') or '')
        cases.append({'url': url, 'method': 'GET', 'data': '', 'parameters': [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)], 'fields': [], 'source_url': url, 'client_side_only': True, 'client_sources': sorted({str(value) for item in evidence for value in item.get('sources', []) if str(value)}), 'client_sinks': sorted({str(value) for item in evidence for value in item.get('sinks', []) if str(value)}), 'client_side_evidence': evidence})
    ranked = sorted(((_browser_case_priority(case, client_keys), -index, case) for index, case in enumerate(cases)), key=lambda item: (-item[0], -item[1]))
    unique_ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    shape_counts: dict[tuple[str, tuple[str, str, int, str], tuple[str, ...]], int] = {}
    variant_cap = max(1, int(DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, {}).get('route_variants', 2)))
    for score, _, case in ranked:
        if score <= 0:
            continue
        method = str(case.get('method', 'GET')).upper()
        url = str(case.get('url', ''))
        params = tuple(sorted((str(value).lower() for value in case.get('parameters', []) if str(value))))
        key = (method, url, params)
        shape = (method, _browser_url_key(url), params)
        if key in seen or shape_counts.get(shape, 0) >= variant_cap:
            continue
        seen.add(key)
        shape_counts[shape] = shape_counts.get(shape, 0) + 1
        unique_ranked.append((int(score), case))
    if CURRENT_SCAN_MODE == 'deep' and len(unique_ranked) < effective_limit:
        extras: list[tuple[int, dict[str, Any]]] = []
        for case in cases:
            url = str(case.get('url') or '')
            method = str(case.get('method', 'GET')).upper()
            if not url or method not in {'GET', 'POST'} or _destructive_crawl_url(url) or _is_auto_index_case(case) or _browser_static_resource(url):
                continue
            path = urlparse(url).path.lower()
            if any(token in path for token in ('logout', 'setup', 'reset', 'delete')):
                continue
            params = tuple(sorted(str(value).lower() for value in case.get('parameters', []) if str(value)))
            key = (method, url, params)
            shape = (method, _browser_url_key(url), params)
            if key in seen or shape_counts.get(shape, 0) >= variant_cap:
                continue
            score = _risk_terms(path + ' ' + ' '.join(params))
            if any(token in path for token in ('csp', 'javascript', 'brute', 'csrf', 'upload', 'redirect', 'callback')):
                score += 35
            if case.get('client_sources') or case.get('client_sinks'):
                score += 50
            if params:
                score += 15
            extras.append((score, {**case, 'selection_reason': 'deep-browser-breadth'}))
        for score, case in sorted(extras, key=lambda item: (-item[0], str(item[1].get('url') or '')))[:max(0, effective_limit - len(unique_ranked))]:
            method = str(case.get('method', 'GET')).upper()
            url = str(case.get('url', ''))
            params = tuple(sorted(str(value).lower() for value in case.get('parameters', []) if str(value)))
            shape = (method, _browser_url_key(url), params)
            if shape_counts.get(shape, 0) >= variant_cap:
                continue
            unique_ranked.append((int(score), case))
            seen.add((method, url, params))
            shape_counts[shape] = shape_counts.get(shape, 0) + 1
    return _select_with_adaptive_specialist_budget('browser', unique_ranked, effective_limit)

# Scores a request case for multi-step workflow checks.
def _workflow_case_priority(case: dict[str, Any]) -> int:
    if str(case.get('method', 'GET')).upper() != 'POST':
        return -1000
    url = str(case.get('url', ''))
    path = urlparse(url).path.lower()
    names = _case_field_names(case)
    if _destructive_crawl_url(url) or any((token in path for token in WORKFLOW_DESTRUCTIVE_HINTS)):
        return -1000
    score = 0
    file_parameters = {str(value).lower() for value in case.get('file_parameters', []) if str(value)}
    token_parameters = {str(value).lower() for value in case.get('token_parameters', []) if str(value)}
    if file_parameters or 'multipart/form-data' in str(case.get('enctype', '')).lower():
        score += 120
    if _is_login_case(case) or any((token in path for token in ('login', 'signin', 'brute', 'auth'))):
        score += 90
    if any(('captcha' in value for value in names)) or 'captcha' in path:
        score += 90
    state_hits = {value for value in names if value in WORKFLOW_STATE_HINTS}
    if state_hits or any((token in path for token in WORKFLOW_STATE_HINTS)):
        score += 60
    if not token_parameters and (state_hits or file_parameters):
        score += 35
    if token_parameters:
        score += 15
    return score

# Chooses request cases that are useful for workflow checks.
def select_workflow_request_cases(discovery: dict[str, Any], limit: int | None=None) -> list[dict[str, Any]]:

    effective_limit = int(limit or PARAMETER_TOOL_CASE_LIMITS.get('workflow', 3))
    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for index, case in enumerate(discovery.get('request_cases', [])):
        if not isinstance(case, dict):
            continue
        score = _workflow_case_priority(case)
        if score > 0:
            ranked.append((score, -index, case))
            continue
        if CURRENT_SCAN_MODE == 'deep':
            method = str(case.get('method', 'GET')).upper()
            path = urlparse(str(case.get('url') or '')).path.lower()
            names = _case_field_names(case)
            auth_shape = any(token in path for token in ('brute', 'login', 'signin', 'auth')) or bool({'username', 'password'} <= names)
            if method == 'GET' and auth_shape and not _destructive_crawl_url(str(case.get('url') or '')):
                ranked.append((82 + min(12, len(names) * 2), -index, {**case, 'selection_reason': 'deep-get-auth-workflow'}))
    unique_ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    shape_counts: dict[tuple[str, tuple[str, str, tuple[str, ...]], tuple[str, ...]], int] = {}
    variant_cap = max(1, int(DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, {}).get('route_variants', 2)))
    for score, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
        method = str(case.get('method', 'POST')).upper()
        url = str(case.get('url', ''))
        fields = tuple(sorted(_case_field_names(case)))
        key = (method, url, fields)
        shape = (method, _discovery_route_signature(url), fields)
        if key in seen or shape_counts.get(shape, 0) >= variant_cap:
            continue
        seen.add(key)
        shape_counts[shape] = shape_counts.get(shape, 0) + 1
        unique_ranked.append((int(score), case))
    return _select_with_adaptive_specialist_budget('workflow', unique_ranked, effective_limit)

# Chooses safe endpoints where Arjun can look for hidden parameters.
def select_arjun_candidates(discovery: dict[str, Any], target: str, limit: int=MAX_ARJUN_ENDPOINTS) -> list[str]:

    form_urls = {normalize_url(str(url)) for url in discovery.get('form_urls', [])}
    request_cases = [case for case in discovery.get('request_cases', []) if isinstance(case, dict)]
    case_by_url: dict[str, list[dict[str, Any]]] = {}
    for case in request_cases:
        case_url = normalize_url(str(case.get('url', '')))
        if case_url:
            case_by_url.setdefault(case_url, []).append(case)
    candidates = {normalize_url(str(url)) for url in (*discovery.get('html_urls', []), *discovery.get('form_urls', [])) if str(url)}
    ranked: list[tuple[int, str]] = []
    low_value = ('brute', 'captcha', 'csrf')
    preferred = ('/api/', '/admin/', '/search', '/query', '/upload', '/download', '/callback', '/webhook', '/execute', '/command')
    for url in candidates:
        parsed = urlparse(url)
        path = parsed.path.lower()
        if 'logout' in path or _is_auto_index_url(url) or path.endswith(('/login.php', '/login', '/setup.php')):
            continue
        related_cases = case_by_url.get(url, [])
        has_form = url in form_urls
        has_existing_parameters = bool(parsed.query) or any((case.get('parameters') for case in related_cases))
        directory_utility = '/config/' in path or '/docs/' in path
        if directory_utility and (not has_form) and (not has_existing_parameters):
            continue
        score = _risk_terms(path)
        if has_form:
            score += 14
        if has_existing_parameters:
            score += 10
        if any((token in path for token in preferred)):
            score += 22
        if path.endswith('/login.php') or path.endswith('/login'):
            score -= 100
        if 'setup' in path:
            score += 1 if has_form or has_existing_parameters else -9
        if directory_utility:
            score -= 5
        if any((term in path for term in low_value)):
            score -= 8
        if score <= 0 and (has_form or has_existing_parameters):
            score = 1
        if score > 0:
            ranked.append((score, _clean_url(url)))
    best: dict[str, int] = {}
    for score, url in ranked:
        best[url] = max(score, best.get(url, score))
    return [url for url, _ in sorted(best.items(), key=lambda item: (-item[1], item[0]))[:limit]]
AUTHORIZATION_PATH_HINTS = {'admin', 'account', 'accounts', 'profile', 'profiles', 'user', 'users', 'member', 'members', 'order', 'orders', 'invoice', 'invoices', 'document', 'documents', 'download', 'downloads', 'report', 'reports', 'record', 'records', 'settings', 'manage', 'management', 'role', 'roles', 'permission', 'permissions', 'api', 'private', 'internal', 'dashboard', 'billing', 'payment', 'payments'}
AUTHORIZATION_PARAMETER_HINTS = {'id', 'uid', 'user', 'user_id', 'userid', 'account', 'account_id', 'member', 'member_id', 'profile', 'profile_id', 'order', 'order_id', 'invoice', 'invoice_id', 'document', 'document_id', 'record', 'record_id', 'file', 'file_id', 'download', 'report', 'report_id', 'customer', 'customer_id', 'owner', 'owner_id', 'tenant', 'tenant_id', 'role', 'role_id'}
AUTHORIZATION_EXCLUDED_PATH_HINTS = {'login', 'signin', 'sign-in', 'logout', 'signout', 'logoff', 'setup', 'install', 'reset', 'delete', 'remove', 'drop', 'truncate', 'purge', 'wipe', 'csrf', 'captcha', 'xss', 'sqli', 'exec', 'command', 'docs', 'documentation', 'instructions', 'help', 'about', 'changelog', 'license', 'copying', 'readme', 'static', 'assets'}

# Scores a request case for read-only authorization checks.
def _authorization_case_priority(case: dict[str, Any]) -> int:

    url = str(case.get('url') or '')
    method = str(case.get('method') or 'GET').upper()
    if not url or method != 'GET' or _is_auto_index_case(case) or _destructive_crawl_url(url):
        return -1000
    parsed = urlparse(url)
    path_tokens = {token for token in re.split('[^a-z0-9_-]+', parsed.path.lower()) if token}
    if path_tokens & AUTHORIZATION_EXCLUDED_PATH_HINTS:
        return -1000
    pairs = [(name.lower(), value) for name, value in parse_qsl(parsed.query, keep_blank_values=True)]
    names = {str(value).lower() for value in case.get('parameters', []) if str(value)}
    names.update((name for name, _ in pairs))
    auth_names = names & AUTHORIZATION_PARAMETER_HINTS
    numeric_auth = [(name, value) for name, value in pairs if name in AUTHORIZATION_PARAMETER_HINTS and value.isdigit()]
    path_hits = path_tokens & AUTHORIZATION_PATH_HINTS
    score = 0
    score += 42 * len(numeric_auth)
    score += 18 * len(auth_names)
    score += 16 * len(path_hits)
    if parsed.query:
        score += 8
    if any((value.isdigit() for _, value in pairs)):
        score += 10
    if any((token in parsed.path.lower() for token in ('/api/', '/admin/', '/account', '/profile', '/user', '/order', '/invoice', '/document', '/download'))):
        score += 24
    if not (auth_names or numeric_auth or path_hits):
        return -1000
    return score

# Chooses requests that can be compared for authorization differences.
def select_authorization_request_cases(discovery: dict[str, Any], limit: int | None=None) -> list[dict[str, Any]]:

    effective_limit = int(limit or PARAMETER_TOOL_CASE_LIMITS.get('authorization', 3))
    cases = [dict(case) for case in discovery.get('request_cases', []) if isinstance(case, dict)]
    known = {str(case.get('url') or '') for case in cases}
    for value in discovery.get('parameterized_urls', []):
        url = str(value or '')
        if url and url not in known:
            cases.append({'url': url, 'method': 'GET', 'data': '', 'parameters': [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)], 'source_url': url, 'synthetic_from_parameterized_url': True})

    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for index, case in enumerate(cases):
        score = _authorization_case_priority(case)
        if score > 0:
            ranked.append((score, -index, case))

    unique_ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[str] = set()
    shape_counts: dict[tuple[tuple[str, str, tuple[str, ...]], tuple[str, ...]], int] = {}
    variant_cap = max(1, int(DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, {}).get('route_variants', 2)))
    for score, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
        url = str(case.get('url') or '')
        params = tuple(sorted(str(value).lower() for value in case.get('parameters', []) if str(value)))
        shape = (_discovery_route_signature(url), params)
        if not url or url in seen or shape_counts.get(shape, 0) >= variant_cap:
            continue
        seen.add(url)
        shape_counts[shape] = shape_counts.get(shape, 0) + 1
        unique_ranked.append((int(score), case))

    if CURRENT_SCAN_MODE == 'deep' and len(unique_ranked) < effective_limit:
        extras: list[tuple[int, dict[str, Any]]] = []
        for case in cases:
            url = str(case.get('url') or '')
            if not url or url in seen or str(case.get('method', 'GET')).upper() != 'GET':
                continue
            if _is_auto_index_case(case) or _destructive_crawl_url(url) or _is_login_case(case):
                continue
            path = urlparse(url).path.lower()
            if any(token in path for token in ('logout', 'setup', 'reset', 'delete', 'csrf', 'captcha')):
                continue
            if not list(case.get('parameters') or []) and not urlparse(url).query:
                continue
            params = tuple(sorted(str(value).lower() for value in case.get('parameters', []) if str(value)))
            shape = (_discovery_route_signature(url), params)
            if shape_counts.get(shape, 0) >= variant_cap:
                continue
            score = _risk_terms(path) + (12 if urlparse(url).query else 0)
            extras.append((score, {**case, 'selection_reason': 'deep-readonly-auth-breadth'}))
        for score, case in sorted(extras, key=lambda item: (-item[0], str(item[1].get('url') or '')))[:max(0, min(6, effective_limit - len(unique_ranked)))]:
            url = str(case.get('url') or '')
            params = tuple(sorted(str(value).lower() for value in case.get('parameters', []) if str(value)))
            shape = (_discovery_route_signature(url), params)
            if url in seen or shape_counts.get(shape, 0) >= variant_cap:
                continue
            seen.add(url)
            shape_counts[shape] = shape_counts.get(shape, 0) + 1
            unique_ranked.append((int(score), case))

    return _select_with_adaptive_specialist_budget('authorization', unique_ranked, effective_limit)

# Chooses and limits the endpoints sent to Arjun.
def select_arjun_request_cases(discovery: dict[str, Any], target: str, limit: int=MAX_ARJUN_ENDPOINTS) -> list[dict[str, Any]]:

    effective_limit = int(limit)
    ranked: list[tuple[int, dict[str, Any]]] = []
    represented_paths: set[str] = set()
    for case in discovery.get('request_cases', []):
        if not isinstance(case, dict):
            continue
        url = normalize_url(str(case.get('url') or ''))
        method = str(case.get('method') or 'GET').upper()
        if not url or method not in {'GET', 'POST'} or (not url_in_authorized_scope(target, url)):
            continue
        parsed = urlparse(url)
        path = parsed.path.lower()
        represented_paths.add(path)
        if _destructive_crawl_url(url) or path.endswith(('/login.php', '/login', '/setup.php')):
            continue
        parameters = [str(value) for value in case.get('parameters', []) if str(value)]
        fields = [item for item in case.get('fields', []) if isinstance(item, dict)]
        file_parameters = [str(value) for value in case.get('file_parameters', []) if str(value)]
        enctype = str(case.get('enctype') or '').lower()
        fully_modelled_form = bool(fields and parameters)
        if file_parameters or 'multipart/form-data' in enctype:
            continue
        if method == 'POST' and fully_modelled_form:
            continue
        score = _risk_terms(path)
        score += 18 if any((token in path for token in ('/api/', 'callback', 'webhook', 'debug', 'admin'))) else 0
        score += 8 if not parameters else -min(16, len(parameters) * 4)
        if method == 'POST':
            score += 4
        if score < 12:
            continue
        ranked.append((score, {'url': url, 'method': method, 'data': str(case.get('data') or ''), 'parameters': parameters}))
    for url in select_arjun_candidates(discovery, target, limit=max(effective_limit * 3, 6)):
        parsed = urlparse(url)
        path = parsed.path.lower()
        if path in represented_paths or parsed.query or _destructive_crawl_url(url):
            continue
        score = _risk_terms(path) + (18 if any((token in path for token in ('/api/', 'callback', 'webhook', 'debug', 'admin'))) else 0)
        if score < 12:
            continue
        ranked.append((score, {'url': url, 'method': 'GET', 'data': '', 'parameters': []}))
    if CURRENT_SCAN_MODE in {'balanced', 'deep'} and (not ranked or CURRENT_SCAN_MODE == 'deep'):
        relaxed: list[tuple[int, dict[str, Any]]] = []
        existing_paths = {urlparse(str(item[1].get('url') or '')).path.lower() for item in ranked}
        for raw_url in discovery.get('html_urls', []) or discovery.get('urls', []):
            url = normalize_url(str(raw_url or ''))
            if not url or not url_in_authorized_scope(target, url) or urlparse(url).query or _destructive_crawl_url(url):
                continue
            path = urlparse(url).path.lower()
            if path in existing_paths or path.endswith(('/login.php', '/login', '/setup.php', '/logout.php')):
                continue
            score = _risk_terms(path)
            if any((token in path for token in ('security', 'vulnerabilities', 'admin', 'debug', 'api', 'upload', 'download', 'callback'))):
                score += 8
            threshold = 1 if CURRENT_SCAN_MODE == 'deep' else 6
            if score >= threshold:
                relaxed.append((score, {'url': url, 'method': 'GET', 'data': '', 'parameters': [], 'selection_reason': 'deep-safe-hidden-parameter-breadth' if CURRENT_SCAN_MODE == 'deep' else 'relaxed-safe-hidden-parameter-fallback'}))
        relaxed.sort(key=lambda item: (-item[0], item[1]['url']))
        if CURRENT_SCAN_MODE == 'deep':
            ranked.extend(relaxed[:max(0, effective_limit - len(ranked))])
        elif not ranked and relaxed:
            ranked.append(relaxed[0])
    unique_ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str]] = set()
    for score, case in sorted(ranked, key=lambda item: (-item[0], item[1]['url'])):
        key = (case['method'], urlparse(case['url']).path.lower())
        if key in seen:
            continue
        seen.add(key)
        unique_ranked.append((int(score), case))
    return _select_with_adaptive_specialist_budget('arjun', unique_ranked, max(1, effective_limit))

# Builds report-facing reasons for discovered request contracts that were not selected for
# request-level security testing. The result is deterministic and shared by both orchestrators.
def endpoint_selection_decisions(discovery: dict[str, Any], target: str, authenticated_profile: bool=False) -> list[dict[str, Any]]:
    cases = [dict(case) for case in discovery.get('request_cases', []) if isinstance(case, dict) and str(case.get('url') or '')]
    if not cases:
        return []

    def key(case: dict[str, Any]) -> tuple[str, str]:
        return (str(case.get('method') or 'GET').upper(), _clean_url(str(case.get('url') or '')))

    def shape(case: dict[str, Any]) -> tuple[str, tuple[str, str, tuple[str, ...]], tuple[str, ...]]:
        method = str(case.get('method') or 'GET').upper()
        url = str(case.get('url') or '')
        fields = tuple(sorted(_case_field_names(case)))
        return (method, _discovery_route_signature(url), fields)

    selected_by_tool: dict[str, set[tuple[str, str]]] = {}
    selected_shapes_by_tool: dict[str, set[tuple[str, tuple[str, str, tuple[str, ...]], tuple[str, ...]]]] = {}
    selected_counts: dict[str, int] = {}

    for tool in ('sqlmap', 'dalfox', 'commix', 'traversal', 'idor'):
        selected = select_tool_request_cases(discovery, tool, authenticated_profile=authenticated_profile)
        selected_by_tool[tool] = {key(case) for case in selected}
        selected_shapes_by_tool[tool] = {shape(case) for case in selected}
        selected_counts[tool] = len(selected)

    browser_selected = select_browser_request_cases(discovery)
    workflow_selected = select_workflow_request_cases(discovery)
    authorization_selected = select_authorization_request_cases(discovery) if authenticated_profile else []
    arjun_selected = select_arjun_request_cases(discovery, target)
    for tool, selected in (
        ('browser', browser_selected),
        ('workflow', workflow_selected),
        ('authorization', authorization_selected),
        ('arjun', arjun_selected),
    ):
        selected_by_tool[tool] = {key(case) for case in selected}
        selected_shapes_by_tool[tool] = {shape(case) for case in selected}
        selected_counts[tool] = len(selected)

    raw_client = [item for item in discovery.get('client_side_candidates', []) if isinstance(item, dict)]
    client_keys = {_browser_url_key(str(item.get('url') or '')) for item in raw_client if str(item.get('url') or '')}
    variant_cap = max(1, int(DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, {}).get('route_variants', 2)))
    shape_frequency: Counter[tuple[str, tuple[str, str, tuple[str, ...]], tuple[str, ...]]] = Counter(shape(case) for case in cases)

    decisions: list[dict[str, Any]] = []
    for case in cases:
        method, url = key(case)
        fields = _case_field_names(case)
        selected_tools = sorted(tool for tool, values in selected_by_tool.items() if (method, url) in values)
        eligible_tools: list[str] = []

        if method in {'GET', 'POST'} and not _destructive_crawl_url(url):
            for tool in ('sqlmap', 'dalfox', 'commix', 'traversal', 'idor'):
                if not _tool_case_skip_reason(tool, case, authenticated_profile=authenticated_profile):
                    eligible_tools.append(tool)
            if _browser_case_priority(case, client_keys) > 0:
                eligible_tools.append('browser')
            workflow_score = _workflow_case_priority(case)
            if workflow_score > 0:
                eligible_tools.append('workflow')
            elif CURRENT_SCAN_MODE == 'deep' and method == 'GET':
                path = urlparse(url).path.lower()
                if (any(token in path for token in ('brute', 'login', 'signin', 'auth')) or {'username', 'password'} <= fields) and not _destructive_crawl_url(url):
                    eligible_tools.append('workflow')
            if authenticated_profile and _authorization_case_priority(case) > 0:
                eligible_tools.append('authorization')
            if (method, url) in selected_by_tool.get('arjun', set()):
                eligible_tools.append('arjun')

        reason_code = ''
        reason = ''
        if method not in {'GET', 'POST'}:
            reason_code = 'UNSUPPORTED_METHOD'
            reason = f'{method} was observed during discovery but request-level specialist wrappers accept only supported GET/POST contracts.'
        elif _destructive_crawl_url(url):
            reason_code = 'STATE_CHANGE_BLOCKED'
            reason = 'The request maps to a destructive/state-changing route excluded by the safety policy.'
        elif selected_tools:
            reason_code = 'SELECTED_FOR_SECURITY_TEST'
            reason = 'Deterministic ranking selected this request contract for one or more request-level security tools.'
        elif not fields:
            reason_code = 'NO_COMPATIBLE_PARAMETERS'
            reason = 'No compatible application parameter, form field or client-side input was available for request-level specialist testing.'
        else:
            current_shape = shape(case)
            duplicate_tools = [tool for tool in eligible_tools if current_shape in selected_shapes_by_tool.get(tool, set()) and shape_frequency[current_shape] > variant_cap]
            if duplicate_tools:
                reason_code = 'DUPLICATE_ROUTE_VARIANT'
                reason = 'A higher-ranked value variant with the same method, route and parameter-name shape was retained; this variant was omitted by the anti-saturation cap.'
            elif eligible_tools and any(selected_counts.get(tool, 0) >= adaptive_tool_max_limit(tool) > 0 for tool in eligible_tools):
                reason_code = 'BUDGET_LIMIT'
                reason = 'The request was compatible with a specialist, but that specialist had already reached its bounded adaptive case ceiling for this profile.'
            else:
                reason_code = 'DEFERRED_LOW_PRIORITY'
                reason = 'The request remained below the deterministic specialist cutoff after vulnerability-class ranking and higher-value candidates were preferred.'

        decisions.append({
            'url': url,
            'method': method,
            'parameters': sorted(fields),
            'selected_tools': selected_tools,
            'eligible_tools': sorted(set(eligible_tools)),
            'reason_code': reason_code,
            'reason': reason,
        })
    return decisions

# Selects generic request cases using a score and a fixed limit.
def select_request_cases(discovery: dict[str, Any], limit: int=MAX_PARAMETER_ENDPOINTS) -> list[dict[str, Any]]:

    cases = list(discovery.get('request_cases', []))
    known_urls = {str(case.get('url', '')) for case in cases}
    for url in discovery.get('parameterized_urls', []):
        if url not in known_urls:
            cases.append({'url': url, 'method': 'GET', 'data': '', 'parameters': [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)], 'source_url': url})
    ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for case in cases:
        url = str(case.get('url', ''))
        method = str(case.get('method', 'GET')).upper()
        path = urlparse(url).path.lower()
        if not url or method not in {'GET', 'POST'} or any((part in path for part in ('logout', 'setup'))):
            continue
        if _is_auto_index_case(case):
            continue
        parameters = tuple(sorted((str(value) for value in case.get('parameters', []) if value)))
        key = (method, urlparse(url)._replace(query='').geturl(), parameters)
        if not parameters or key in seen:
            continue
        seen.add(key)
        score = _risk_terms(path + ' ' + ' '.join(parameters))
        score += 12 if method == 'POST' else 3
        if _is_login_case(case):
            score -= 20
        score += min(8, len(parameters) * 2)
        ranked.append((score, {**case, 'method': method, 'parameters': list(parameters), 'priority_score': score}))
    ranked.sort(key=lambda item: (-item[0], str(item[1].get('url', ''))))
    return [case for _, case in ranked[:limit]]

# Replaces one parameter value while keeping the rest of the request unchanged.
def _replace_parameter_value(pairs: list[tuple[str, str]], parameter: str, value: str) -> list[tuple[str, str]]:
    replaced = False
    updated: list[tuple[str, str]] = []
    for name, current in pairs:
        if not replaced and name.lower() == parameter.lower():
            updated.append((name, value))
            replaced = True
        else:
            updated.append((name, current))
    if not replaced:
        updated.append((parameter, value))
    return updated

# Chooses request cases that can support out-of-band callback checks.
def select_oast_request_cases(discovery: dict[str, Any], target: str, limit: int=1) -> list[dict[str, Any]]:

    ranked: list[tuple[int, dict[str, Any]]] = []
    for case in discovery.get('request_cases', []):
        if not isinstance(case, dict):
            continue
        url = str(case.get('url') or '')
        method = str(case.get('method') or 'GET').upper()
        if not url or method not in {'GET', 'POST'} or (not url_in_authorized_scope(target, url)):
            continue
        path = urlparse(url).path.lower()
        if any((token in path for token in ('logout', 'setup', 'install', 'reset', 'delete'))):
            continue
        query_pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
        body_pairs = parse_qsl(str(case.get('data') or ''), keep_blank_values=True) if method == 'POST' else []
        names = {str(value).lower() for value in case.get('parameters', []) if str(value)}
        names.update((name.lower() for name, _ in query_pairs))
        names.update((name.lower() for name, _ in body_pairs))
        strong = [name for name in names if name in OAST_PARAMETER_SCORES]
        path_bonus = 35 if any((hint in path for hint in OAST_PATH_HINTS)) else 0
        if not strong:
            continue
        parameter = max(strong, key=lambda name: OAST_PARAMETER_SCORES[name])
        score = OAST_PARAMETER_SCORES[parameter] + path_bonus + (8 if method == 'POST' else 0)
        command_context = parameter in OAST_COMMAND_PARAMETERS and any((hint in path for hint in ('exec', 'command', 'cmd', 'ping', 'shell')))
        if command_context:
            replacement = '127.0.0.1; ping -c 1 FUZZ' if parameter in {'ip', 'host', 'hostname', 'target', 'domain', 'ping'} else 'ping -c 1 FUZZ'
            score += 45
        else:
            replacement = 'http://FUZZ/' if parameter in OAST_URL_VALUE_PARAMETERS else 'FUZZ'
        if method == 'GET':
            parsed = urlparse(url)
            injected_pairs = _replace_parameter_value(query_pairs, parameter, replacement)
            injection_url = urlunparse(parsed._replace(query=urlencode(injected_pairs), fragment=''))
            injection_data = ''
        else:
            injection_url = url
            injection_data = urlencode(_replace_parameter_value(body_pairs, parameter, replacement))
        ranked.append((score, {'target_url': target, 'source_url': url, 'injection_url': injection_url, 'method': method, 'data': injection_data, 'parameter': parameter, 'parameters': [parameter], 'priority_score': score, 'oast_class': 'command' if command_context else 'remote-fetch'}))
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for _, candidate in sorted(ranked, key=lambda item: (-item[0], item[1]['injection_url'])):
        key = (candidate['method'], candidate['injection_url'], candidate['data'])
        if key in seen:
            continue
        seen.add(key)
        selected.append(candidate)
        if len(selected) >= max(1, int(limit)):
            break
    return selected

# Adds hidden parameters found by Arjun to the discovery data.
def enrich_discovery_with_arjun(discovery: dict[str, Any], result: dict[str, Any], base_url: str) -> tuple[dict[str, Any], list[str]]:
    parameters = {str(item).strip() for item in result.get('parameters', []) if str(item).strip()}
    parameters.update((str(item.get('parameter', '')).strip() for item in result.get('vulnerabilities', []) if isinstance(item, dict)))
    parsed = urlparse(base_url)
    existing = list(parse_qsl(parsed.query, keep_blank_values=True))
    names = {name for name, _ in existing}
    generated = [urlunparse(parsed._replace(query=urlencode([*existing, (name, '1')]), fragment='')) for name in sorted(parameters) if name and name not in names and re.fullmatch('[A-Za-z0-9_.:-]{1,128}', name)]
    updated = dict(discovery)
    updated['parameterized_urls'] = sorted(set(updated.get('parameterized_urls', [])) | set(generated))
    generated_cases = [{'url': url, 'method': 'GET', 'data': '', 'parameters': [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)], 'source_url': base_url} for url in generated]
    updated['request_cases'] = _dedupe_request_cases([*updated.get('request_cases', []), *generated_cases])
    return (updated, generated)

# Adds useful URLs found by FFUF to the discovery data.
def enrich_discovery_with_ffuf(discovery: dict[str, Any], result: dict[str, Any], target: str) -> tuple[dict[str, Any], list[str]]:

    safe_urls: set[str] = set()
    blocked: set[str] = set(discovery.get('destructive_urls_skipped', []))
    for item in result.get('vulnerabilities', []):
        if not isinstance(item, dict):
            continue
        for field in ('url', 'final_url'):
            value = str(item.get(field) or '').strip()
            if not value or not url_in_authorized_scope(target, value):
                continue
            if _destructive_crawl_url(value):
                blocked.add(value)
                continue
            safe_urls.add(_clean_url(value))
    urls = sorted(safe_urls)
    updated = dict(discovery)
    updated['urls'] = sorted(set(updated.get('urls', [])) | set(urls))
    updated['parameterized_urls'] = sorted(set(updated.get('parameterized_urls', [])) | {url for url in urls if urlparse(url).query})
    updated['destructive_urls_skipped'] = sorted(blocked)
    return (updated, urls)

# Skipped runs use a common result shape with an explicit reason.
def make_skipped_result(tool: str, target: str, reason: str) -> dict[str, Any]:
    return _result(tool, target, 'skipped', reason, 'not_applicable')

# Prints ZAP coverage and authentication details from the scan result.
def log_zap_session_diagnostics(result: dict[str, Any]) -> None:
    diagnostics = result.get('session_diagnostics') if isinstance(result.get('session_diagnostics'), dict) else {}
    before = diagnostics.get('before_scan') if isinstance(diagnostics.get('before_scan'), dict) else diagnostics
    after = diagnostics.get('after_scan') if isinstance(diagnostics.get('after_scan'), dict) else {}
    if not before:
        return

    # Prints coverage for the operator.
    def print_coverage() -> None:
        if 'targeted_active_scans_started' not in result:
            return
        policy = result.get('active_scanner_policy') if isinstance(result.get('active_scanner_policy'), dict) else {}
        stats = result.get('zap_alert_stats') if isinstance(result.get('zap_alert_stats'), dict) else {}
        effective_done = result.get('effective_targeted_scans_completed', result.get('targeted_active_scans_completed', 0))
        effective_started = result.get('effective_targeted_scans_started', result.get('targeted_active_scans_started', 0))
        planned_cases = result.get('targeted_active_scans_planned', result.get('targeted_active_scans_started', 0))
        attempted_cases = result.get('targeted_active_scans_attempted', result.get('targeted_active_scans_started', 0))
        started_cases = result.get('targeted_active_scans_started', 0)
        print(f"    [ZAP COVERAGE] seeded URLs={result.get('seeded_urls', 0)}; seeded requests={result.get('seeded_request_cases', 0)}; native targeted={result.get('targeted_active_scans_completed', 0)}/{planned_cases}; attempted={attempted_cases}; started={started_cases}; effective native/proxy={effective_done}/{planned_cases}; configured rules={result.get('active_rules_attempted', 0)}/{result.get('active_rules_planned', 0)} ({result.get('active_rule_coverage_percent', 0)}%); completed-rule coverage={result.get('active_rules_completed', 0)}/{result.get('active_rules_planned', 0)} ({result.get('active_rule_effective_coverage_percent', 0)}%); proxy confirmed={result.get('proxy_assisted_confirmed', 0)}; native security alerts={stats.get('security', 0)}; site-tree URLs={result.get('zap_sites_tree_urls', 0)}")
        if policy:
            if policy.get('active_scan_enabled') is False:
                print(f"    [ZAP ACTIVE POLICY] passive-only by explicit scan mode; catalog rules={policy.get('catalog_rule_count', 0)}")
            else:
                print('    [ZAP ACTIVE POLICY] planned rule IDs=' + (', '.join((str(value) for value in policy.get('planned_rule_ids', []))) or 'none'))
                fallback = policy.get('fallback_active_plan') if isinstance(policy.get('fallback_active_plan'), dict) else {}
                if fallback.get('used'):
                    fallback_urls = fallback.get('urls') if isinstance(fallback.get('urls'), list) else []
                    if len(fallback_urls) > 1:
                        print(f"    [ZAP FALLBACK] generic bounded active targets={len(fallback_urls)}; first={compact_log_url(fallback_urls[0])}; rules={','.join(str(value) for value in fallback.get('rule_ids', []))}")
                    else:
                        print(f"    [ZAP FALLBACK] generic bounded active target={compact_log_url(fallback.get('url', ''))}; rules={','.join(str(value) for value in fallback.get('rule_ids', []))}")
        deferred = result.get('deferred_native_active_cases') if isinstance(result.get('deferred_native_active_cases'), list) else []
        if deferred:
            print('    [ZAP ACTIVE POLICY] deferred in balanced/prioritized: ' + ', '.join((str(item.get('case_class') or item.get('url') or '') for item in deferred if isinstance(item, dict))))
        plan = result.get('prioritized_native_plan') if isinstance(result.get('prioritized_native_plan'), dict) else {}
        for phase in plan.get('phases', []):
            if not isinstance(phase, dict):
                continue
            recursive = phase.get('recursive') if isinstance(phase.get('recursive'), dict) else {}
            print(f"    [ZAP PRIORITY] tier={phase.get('tier')}; rules={phase.get('scanner_count', 0)}; targeted={phase.get('targeted_completed', 0)}/{phase.get('targeted_started', 0)}; recursive={('complete' if recursive.get('completed') else 'partial' if recursive.get('started') else 'not-started')}")
        for item in result.get('targeted_active_scans', []):
            if not isinstance(item, dict):
                continue
            state = 'complete' if item.get('completed') else 'incomplete'
            print(f"    [ZAP ACTIVE CASE] {item.get('method', 'GET')} {compact_log_url(item.get('url', ''))} — {state}; progress={item.get('progress', 0)}%; budget={item.get('budget_seconds', 0)}s")
        preparation = result.get('post_spider_target_preparation')
        if isinstance(preparation, dict) and preparation.get('configured'):
            print(f"    [ZAP TARGET STATE] reapplied={preparation.get('performed')}; usable={preparation.get('usable')}")
        for record in result.get('proxy_assisted_verification', []):
            if not isinstance(record, dict):
                continue
            if record.get('error'):
                print(f"    [ZAP PROXY CHECK] {record.get('method', 'GET')} {compact_log_url(record.get('url', ''))} — error: {record.get('error')}")
                continue
            if record.get('skipped'):
                print(f"    [ZAP PROXY CHECK] {record.get('method', 'GET')} {compact_log_url(record.get('url', ''))} — skipped: {record.get('skipped')}")
                continue
            for test in record.get('tests', []):
                if not isinstance(test, dict):
                    continue
                state = 'confirmed' if test.get('confirmed') else 'not-confirmed'
                print(f"    [ZAP PROXY CHECK] {record.get('method', 'GET')} {compact_log_url(record.get('url', ''))} — {test.get('type', 'probe')}={state}")
    if before.get('anonymous_profile'):
        print_coverage()
        return
    print(f"    [ZAP AUTH] ZAP={result.get('zap_version', before.get('zap_version', 'unknown'))}; Python API={result.get('python_zap_api_version', before.get('python_zap_api_version', 'unknown'))}")
    print(f"    [ZAP AUTH] probe={before.get('probe_url', '')}; cookie names={', '.join(before.get('cookie_names', [])) or 'none'}")
    direct = before.get('direct') if isinstance(before.get('direct'), dict) else {}
    if before.get('conclusive') is False:
        direct_state = 'inconclusive'
    elif before.get('direct_authenticated') is not None:
        direct_state = str(bool(before.get('direct_authenticated')))
    else:
        direct_state = str(bool(before.get('effective')))
    injection_mode = str(result.get('authentication_injection_mode') or before.get('authentication_injection_mode') or '')
    print(f"    [ZAP AUTH] direct authenticated={direct_state}; proxy matches direct={before.get('proxy_matches_direct')}; history cookie exact={before.get('history_cookie_exact')}; mode={injection_mode or 'n/a'}")
    history = before.get('history') if isinstance(before.get('history'), dict) else {}
    if history.get('duplicate_cookie_names'):
        print('    [ZAP AUTH WARNING] duplicate Cookie names: ' + ', '.join(history['duplicate_cookie_names']))
    if before.get('root_cause'):
        print(f"    [ZAP AUTH ROOT CAUSE] {before['root_cause']}")
    if after:
        after_state = 'inconclusive' if after.get('conclusive') is False else str(after.get('effective'))
        print(f"    [ZAP AUTH] session valid after scan={after_state}; proxy matches direct={after.get('proxy_matches_direct')}; history cookie exact={after.get('history_cookie_exact')}")
        if after.get('root_cause'):
            print(f"    [ZAP AUTH ROOT CAUSE] {after['root_cause']}")
    print_coverage()

# Prints one tool result using the same status format across the project.
def log_result(profile: str, name: str, result: dict[str, Any], target: str='') -> None:
    raw_status = str(result.get('status', 'error')).lower()
    limited = raw_status == 'partial' and _is_time_limited(result)
    label = 'LIMITED' if limited else raw_status.upper()
    total, security, observations = _finding_counts(result)
    print(f"    [{label:7}] {name}: {compact_log_url(target or result.get('target', ''))} — findings={total} (security/candidates={security}, observations={observations})")
    detail = str(result.get('output', ''))[:400]
    if raw_status == 'error':
        print(f'              {detail}', file=sys.stderr)
    elif raw_status == 'partial':
        print(f'              {detail}')
    if name == 'ffuf':
        isolated = bool(result.get('cookie_isolated_discovery'))
        credentialed = bool(result.get('credentialed_fuzz_requests_sent'))
        blocked = len(result.get('blocked_destructive_rows') or [])
        if isolated:
            print(f'    [FFUF SESSION] path fuzzing cookie-isolated=True; credentialed fuzz requests={credentialed}; destructive rows blocked={blocked}')
        session_after = result.get('session_after') if isinstance(result.get('session_after'), dict) else {}
        if session_after.get('performed'):
            print(f"    [FFUF SESSION] post-scan authenticated={session_after.get('authenticated')}; conclusive={session_after.get('conclusive')}")
    if name == 'nuclei':
        inventory = result.get('template_inventory') if isinstance(result.get('template_inventory'), dict) else {}
        print(f"    [NUCLEI TEMPLATES] total={inventory.get('count', 0)}; dast={inventory.get('dast_count', 0)}; directory={inventory.get('directory', '') or 'not-resolved'}")
        fingerprint = result.get('technology_fingerprint') if isinstance(result.get('technology_fingerprint'), dict) else {}
        print(f"    [NUCLEI STRATEGY] adaptive=True; technologies={','.join(fingerprint.get('tags') or []) or 'unknown'}; dast_cases={result.get('dast_request_count', 0)}; direct_templates={result.get('custom_template_count', 0)}; evidence_targets={len(result.get('evidence_targets') or [])}; stdin_disabled=True; DAST may overlap specialist classes to provide independent template evidence")
        phases = result.get('phases') if isinstance(result.get('phases'), list) else []
        for phase in phases:
            if not isinstance(phase, dict):
                continue
            print(f"    [NUCLEI PHASE] {phase.get('name', 'unknown')}: status={phase.get('status', 'unknown')}; findings={phase.get('findings', 0)}; templates={phase.get('selected_template_count', 0)}; budget={phase.get('timeout_seconds', 0)}s; input={phase.get('input_mode') or 'list'}; aggression={phase.get('fuzz_aggression') or 'n/a'}; fuzz-param-frequency={phase.get('fuzz_param_frequency') or 'default'}; scope={phase.get('target_scope') or 'focused'}")
            if phase.get('dast_fallback_used'):
                print(f"    [NUCLEI DAST RECOVERY] primary={phase.get('dast_primary_status', 'error')}/{phase.get('dast_primary_diagnosis', '')}; mode={phase.get('dast_fallback_mode') or 'unknown'}; request cases={phase.get('dast_fallback_request_cases', 0) or phase.get('dast_fallback_get_cases', 0)}; final={phase.get('status', 'unknown')}")
            if phase.get('dast_recovery_attempts'):
                attempts = ', '.join(f"{item.get('input_mode')}={item.get('status')}" for item in phase.get('dast_recovery_attempts') if isinstance(item, dict))
                print(f"    [NUCLEI DAST INPUTS] {attempts}")
            if str(phase.get('status') or '').lower() in {'error', 'partial'} and phase.get('stderr_excerpt'):
                compact_error = ' '.join(str(phase.get('stderr_excerpt') or '').split())[-700:]
                print(f"    [NUCLEI DIAGNOSTIC] {compact_error}")
            if phase.get('dast_primary_stderr_excerpt'):
                compact_primary = ' '.join(str(phase.get('dast_primary_stderr_excerpt') or '').split())[-700:]
                print(f"    [NUCLEI DAST PRIMARY ERROR] {compact_primary}")
            if phase.get('template_batch_recovery'):
                print(f"    [NUCLEI RECOVERY] completed exact templates={phase.get('completed_template_count', 0)}; exact rejected={phase.get('invalid_template_count', 0)}; engine tag fallback={phase.get('engine_tag_fallback_success', False)}; global matchers={phase.get('global_matcher_template_count', 0)}; global matchers enabled={phase.get('global_matchers_enabled', False)}; runtime failures={len(phase.get('runtime_template_failures') or [])}; timed out={len(phase.get('timed_out_templates') or [])}")
        if not total:
            print('    [NUCLEI RESULT] No template matcher completed with positive evidence. This does not mean the target is clean; inspect phase status, DAST input count, template inventory and time-limit diagnostics above.')
    if name == 'nikto':
        metrics = result.get('scan_metrics') if isinstance(result.get('scan_metrics'), dict) else {}
        structured = result.get('structured_report') if isinstance(result.get('structured_report'), dict) else {}
        print(f"    [NIKTO COVERAGE] mode={result.get('execution_mode', 'unknown')}; requests={metrics.get('requests', 0)}; reported={metrics.get('items_reported', 0)}; hosts={metrics.get('hosts_tested', 0)}; parsed unique={len(result.get('vulnerabilities') or [])}; raw parsed={result.get('raw_parsed_findings', len(result.get('vulnerabilities') or []))}; cross-source duplicates removed={result.get('cross_source_duplicates_removed', 0)}; parser count consistent={result.get('parser_count_consistent', True)}; report copied={structured.get('copied', False)}; report bytes={structured.get('bytes', 0)}; console fallback={structured.get('console_only', False)}; coverage verified={result.get('coverage_verified', False)}; zero verified={result.get('zero_result_verified', False)}; profile={result.get('scan_profile', 'unknown')}; plugins={result.get('plugins', 'unknown')}; tuning={result.get('safe_tuning', 'unknown')}; cgi_dirs={result.get('cgi_dirs', 'unknown')}")
        retry = result.get('structured_retry') if isinstance(result.get('structured_retry'), dict) else {}
        if retry.get('used'):
            print('    [NIKTO FALLBACK] Structured CSV output was not writable; Nikto was automatically rerun in console-summary mode.')
        docker_state = result.get('docker_state') if isinstance(result.get('docker_state'), dict) else {}
        docker_create = result.get('docker_create') if isinstance(result.get('docker_create'), dict) else {}
        if result.get('execution_mode', '').startswith('official_docker'):
            print(f"    [NIKTO DOCKER] create_rc={docker_create.get('return_code', 'n/a')}; state_available={docker_state.get('available', False)}; exit={docker_state.get('ExitCode', 'n/a')}; state_error={docker_state.get('Error') or 'none'}; report_path={structured.get('path') or 'not-created'}; copy_attempts={len(structured.get('attempts') or [])}")
        baseline = result.get('baseline_probe') if isinstance(result.get('baseline_probe'), dict) else {}
        if baseline.get('performed'):
            print(f"    [NIKTO BASELINE] status={baseline.get('status', 'n/a')}; server={baseline.get('server') or 'not-disclosed'}; signals={baseline.get('signal_count', 0)}; missing headers={','.join(baseline.get('missing_security_headers') or []) or 'none'}")

# Combines repeated tool runs into one summary for the report.
def aggregate_runs(tool: str, target: str, runs: list[dict[str, Any]]) -> dict[str, Any]:
    if not runs:
        return make_skipped_result(tool, target, 'No applicable endpoint was discovered for this tool.')
    normalized = [_normalize_time_limit(dict(run), tool, str(run.get('target', target))) for run in runs]
    statuses = [str(run.get('status', 'error')).lower() for run in normalized]
    successful = sum((status == 'success' for status in statuses))
    errors = sum((status == 'error' for status in statuses))
    partials = sum((status == 'partial' for status in statuses))
    limited = sum((status == 'partial' and _is_time_limited(run) for status, run in zip(statuses, normalized)))
    skipped_count = sum((status == 'skipped' for status in statuses))
    if all((status == 'skipped' for status in statuses)):
        status = 'skipped'
    elif errors == len(normalized):
        status = 'error'
    elif errors or partials:
        status = 'partial'
    else:
        status = 'success'
    vulnerabilities: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, ...]] = set()
    for run in normalized:
        for finding in run.get('vulnerabilities') or []:
            if not isinstance(finding, dict):
                continue
            fingerprint = tuple((str(finding.get(key, '')) for key in ('alert', 'risk', 'category', 'url', 'parameter', 'evidence')))
            if fingerprint not in seen_findings:
                seen_findings.add(fingerprint)
                vulnerabilities.append(finding)
    result = {'tool': tool, 'status': status, 'target': target, 'output': f'Runs: {len(normalized)}; successful: {successful}; time-limited: {limited}; other partial: {max(0, partials - limited)}; errors: {errors}; skipped: {skipped_count}; findings: {len(vulnerabilities)}.', 'vulnerabilities': vulnerabilities, 'runs': normalized, 'diagnosis': 'nested_scanner_errors' if errors else 'time_limit_reached' if limited else 'nested_partial_results' if partials else None, 'timed_out': bool(limited)}
    return result

# Walks nested results and yields the final tool result objects.
def iter_leaf_results(value: Any, path: tuple[str, ...]=()) -> Iterator[tuple[tuple[str, ...], dict[str, Any]]]:
    if isinstance(value, dict) and 'status' in value:
        runs = value.get('runs')
        if isinstance(runs, list):
            for index, run in enumerate(runs):
                yield from iter_leaf_results(run, (*path, f'run[{index}]'))
        else:
            yield (path, value)
    elif isinstance(value, dict):
        for key, nested in value.items():
            yield from iter_leaf_results(nested, (*path, str(key)))

# Recovers normal report artifacts that may already have been written when the final MCP/HTTP
# response is interrupted or reaches its outer time budget. This prevents a second emergency
# report from being created when the primary JSON/HTML report is already usable.
def recover_normal_report_artifacts(output_name: str, report: dict[str, Any]) -> dict[str, Any]:
    stem = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(output_name or '').strip()).strip('._')[:120]
    if not stem:
        return report
    directory = ROOT / 'reports'
    json_path = directory / f'{stem}.json'
    html_path = directory / f'{stem}.html'
    pdf_path = directory / f'{stem}.pdf'
    review_path = directory / f'{stem}.review.json'
    available = {
        'json_filename': json_path if json_path.is_file() else None,
        'html_filename': html_path if html_path.is_file() else None,
        'pdf_filename': pdf_path if pdf_path.is_file() else None,
        'review_snapshot_filename': review_path if review_path.is_file() else None,
    }
    if not any(available.values()):
        return report

    recovered = dict(report or {})
    original_status = str(recovered.get('status') or 'error')
    original_diagnosis = str(recovered.get('diagnosis') or '')
    original_output = str(recovered.get('output') or '').strip()
    for key, path in available.items():
        if path is not None:
            recovered[key] = str(path.resolve())
    recovered['normal_report_artifacts_recovered'] = True
    recovered['local_json_generated'] = bool(available['json_filename'])
    recovered['local_html_generated'] = bool(available['html_filename'])
    recovered['local_pdf_generated'] = bool(available['pdf_filename'])
    recovered['local_review_snapshot_generated'] = bool(available['review_snapshot_filename'])
    recovered['original_report_status'] = original_status
    if original_diagnosis:
        recovered['original_diagnosis'] = original_diagnosis

    payload = None
    if available['json_filename'] is not None:
        try:
            loaded = json.loads(json_path.read_text(encoding='utf-8'))
            payload = loaded if isinstance(loaded, dict) else None
        except (OSError, json.JSONDecodeError):
            payload = None
    if isinstance(payload, dict):
        for key in ('findings_count', 'security_findings_count', 'candidate_findings_count', 'observations_count'):
            if key in payload:
                recovered[key] = payload.get(key)
        summary = payload.get('summary') if isinstance(payload.get('summary'), dict) else {}
        recovered['coverage_constraints_count'] = len(summary.get('coverage_constraints') or [])
        recovered['execution_limitations_count'] = len(summary.get('limitations') or [])
        if 'execution_complete' in summary:
            recovered['execution_complete'] = bool(summary.get('execution_complete'))
        if 'coverage_complete' in summary:
            recovered['coverage_complete'] = bool(summary.get('coverage_complete'))

    if available['pdf_filename'] is not None:
        recovered['status'] = 'success'
        recovered['diagnosis'] = 'report_response_recovered'
        recovered['output'] = 'Normal report artifacts, including the PDF, were recovered after the MCP/HTTP response did not complete normally.'
    else:
        recovered['status'] = 'partial'
        recovered['diagnosis'] = 'normal_report_recovered_without_pdf'
        suffix = f' Original reporting detail: {original_output}' if original_output else ''
        recovered['output'] = 'Normal JSON/HTML report artifacts were recovered after the MCP/HTTP reporting failure; the PDF was not generated.' + suffix
    return recovered

# Writes a small JSON report only when no normal report artifact can be recovered.
def write_emergency_json_report(target: str, results: dict[str, Any], diagnostics: list[dict[str, Any]], reason: str, output_name: str='SecOps_Emergency') -> str | None:
    try:
        directory = ROOT / 'reports'
        directory.mkdir(parents=True, exist_ok=True)
        stem = re.sub('[^A-Za-z0-9_.-]+', '_', output_name).strip('._')
        path = directory / f'{stem}_{datetime.now():%Y%m%d_%H%M%S}.json'
        payload = {'generated_at': datetime.now(timezone.utc).isoformat(), 'target': target, 'reason': reason, 'diagnostics': diagnostics, 'results': results}
        text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
        path.write_text(text, encoding='utf-8')
        path.with_suffix('.html').write_text(f"<!doctype html><meta charset='utf-8'><title>SecOps preview</title><style>body{{font-family:Segoe UI;margin:2rem}}pre{{white-space:pre-wrap;background:#111923;color:#e7eef7;padding:1rem}}</style><h1>SecOps emergency preview</h1><pre>{html.escape(text)}</pre>", encoding='utf-8')
        return str(path.resolve())
    except Exception as exc:
        print(f'[REPORT FALLBACK ERROR] {exc}', file=sys.stderr)
        return None

# Chooses a stable URL used to check the current session.
def select_session_probe_url(discovery: dict[str, Any], target: str) -> str:

    discovered = [str(value) for value in discovery.get('html_urls', []) if isinstance(value, str) and same_origin(target, value) and (not _is_auto_index_url(value))]
    return _stable_auth_probe_url(target, discovered)

# Safety policy decides whether state-changing tests are allowed for the current target.
def state_changing_tests_allowed(target: str, explicit: bool | None=None) -> bool:

    if explicit is not None:
        return bool(explicit)
    return urlparse(target).hostname in {'127.0.0.1', 'localhost', '::1'}

# Adds the command-line options shared by both orchestrators.
def add_common_cli_arguments(parser: argparse.ArgumentParser, *, require_target: bool) -> None:

    if require_target:
        parser.add_argument('--target', required=True)
    else:
        parser.add_argument('--target')
    parser.add_argument('--cookies', default='')
    parser.add_argument('--secondary-cookies', default='', help='Optional second authenticated identity for read-only authorization/BOLA comparison.')
    parser.add_argument('--auth-only', action='store_true')
    parser.add_argument('--authorized', action='store_true')
    parser.add_argument('--authorized-origin', action='append', default=[], help='Additional exact HTTP/HTTPS origin explicitly included in the authorized assessment scope. Repeat as needed.')
    parser.add_argument('--authorized-host-suffix', action='append', default=[], help='Additional authorized host suffix, for example example.org; matches the suffix itself and its subdomains. Repeat as needed.')
    state_change_group = parser.add_mutually_exclusive_group()
    state_change_group.add_argument('--allow-state-changes', dest='allow_state_changes', action='store_true', default=None, help='Explicitly enable bounded POST/upload/stored-XSS workflow probes for this run.')
    state_change_group.add_argument('--no-allow-state-changes', dest='allow_state_changes', action='store_false', help='Explicitly disable bounded state-changing probes, including on local targets.')
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--ignore-preflight-errors', action='store_true')
    parser.add_argument('--interactsh-injection-url', default='')
    parser.add_argument('--mode', choices=('fast', 'balanced', 'deep'), default='balanced', help='Trade coverage for runtime; balanced is the default.')

# Validates the command line and builds target, profile, and cookie settings.
def prepare_cli_context(parser: argparse.ArgumentParser, args: argparse.Namespace) -> tuple[str, list[dict[str, str]], str, str, str]:

    target = normalize_url(args.target)
    local_hosts = {'127.0.0.1', 'localhost', '::1'}
    if urlparse(target).hostname not in local_hosts and (not args.authorized):
        parser.error('Remote targets require --authorized.')
    if (getattr(args, 'authorized_origin', None) or getattr(args, 'authorized_host_suffix', None)) and not args.authorized:
        parser.error('Scope extensions require --authorized.')
    for value in getattr(args, 'authorized_origin', []) or []:
        raw_origin = str(value or '').strip()
        try:
            parsed_origin = urlparse(raw_origin)
            _ = parsed_origin.port
        except ValueError:
            parser.error(f'Invalid --authorized-origin value: {value!r}. Use an absolute HTTP/HTTPS origin.')
        if (not normalized_origin(raw_origin)) or parsed_origin.path not in {'', '/'} or parsed_origin.query or parsed_origin.fragment or parsed_origin.username or parsed_origin.password:
            parser.error(f'Invalid --authorized-origin value: {value!r}. Use only scheme, host and optional port.')
    for value in getattr(args, 'authorized_host_suffix', []) or []:
        suffix = str(value or '').strip().lower().lstrip('.').rstrip('.')
        if not suffix or '://' in suffix or '/' in suffix or ':' in suffix or any(ch.isspace() for ch in suffix):
            parser.error(f'Invalid --authorized-host-suffix value: {value!r}. Use only a DNS host suffix such as example.org.')
    configure_authorized_scope(target, list(getattr(args, 'authorized_origin', []) or []), list(getattr(args, 'authorized_host_suffix', []) or []))
    if AUTHORIZED_SCOPE_ORIGINS or AUTHORIZED_SCOPE_HOST_SUFFIXES:
        print('[*] Authorized scope extensions: origins=' + (', '.join(sorted(AUTHORIZED_SCOPE_ORIGINS)) or 'none') + '; host suffixes=' + (', '.join(sorted(AUTHORIZED_SCOPE_HOST_SUFFIXES)) or 'none'))
    injection_url = str(getattr(args, 'interactsh_injection_url', '') or '').strip()
    if injection_url and (not url_in_authorized_scope(target, injection_url)):
        parser.error('--interactsh-injection-url must be inside the explicitly authorized assessment scope.')
    normalized_cookie = ''
    profiles = [] if args.auth_only else [{'name': 'anonymous', 'cookies': ''}]
    if args.cookies:
        try:
            normalized_cookie = canonical_cookie_header(args.cookies)
        except ValueError as exc:
            parser.error(f'Invalid --cookies value: {exc}')
        print('[*] Authenticated cookie names: ' + ', '.join(cookie_names(normalized_cookie)))
        profiles.append({'name': 'authenticated', 'cookies': normalized_cookie})
    elif args.auth_only:
        parser.error('--auth-only requires --cookies.')
    secondary_cookie = ''
    if args.secondary_cookies:
        if not normalized_cookie:
            parser.error('--secondary-cookies requires a primary --cookies value.')
        try:
            secondary_cookie = canonical_cookie_header(args.secondary_cookies)
        except ValueError as exc:
            parser.error(f'Invalid --secondary-cookies value: {exc}')
        if secondary_cookie == normalized_cookie:
            parser.error('--secondary-cookies must represent a different authenticated identity.')
        print('[*] Secondary identity cookie names: ' + ', '.join(cookie_names(secondary_cookie)))
    return (target, profiles, normalized_cookie, secondary_cookie, injection_url)

# Builds the arguments sent to each MCP tool from discovery data.
def build_tool_arguments(tool: str, target_url: str, cookies: str, discovery: dict[str, Any], *, case: dict[str, Any] | None=None, secondary_cookies: str='', allow_state_changes: bool | None=None, timeout_override: int=0, diagnostic_only: bool=False, single_tool: bool=False) -> dict[str, Any]:

    case = case or {}
    effective_cookies = scope_cookie_header(target_url, cookies)
    arguments: dict[str, Any] = {'target_url': target_url, 'cookies': effective_cookies}
    if tool in BROAD_SCANNER_TIMEOUTS:
        arguments['timeout'] = timeout_override or BROAD_SCANNER_TIMEOUTS[tool]
        if tool == 'ffuf':
            arguments['session_probe_url'] = select_session_probe_url(discovery, target_url)
        elif tool == 'session':
            sample_count = 7 if CURRENT_SCAN_MODE == 'deep' else 5 if CURRENT_SCAN_MODE == 'balanced' else 3
            arguments.update({'probe_url': select_session_probe_url(discovery, target_url), 'sample_count': sample_count})
        elif tool == 'zap':
            if diagnostic_only:
                scan_mode = 'passive'
            elif CURRENT_SCAN_MODE == 'deep':
                scan_mode = 'full'
            elif CURRENT_SCAN_MODE == 'balanced':
                scan_mode = 'prioritized'
            else:
                scan_mode = 'targeted'
            arguments.update({'seed_urls': discovery.get('html_urls', []), 'request_cases': discovery.get('request_cases', []), 'scan_mode': scan_mode, 'session_probe_url': select_session_probe_url(discovery, target_url), 'max_observations': 450 if CURRENT_SCAN_MODE == 'deep' else 220 if CURRENT_SCAN_MODE == 'balanced' or single_tool else 60})
            if single_tool:
                arguments['diagnostic_only'] = diagnostic_only
            elif diagnostic_only:
                arguments['diagnostic_only'] = True
        elif tool == 'nuclei':
            arguments.update({'seed_urls': discovery.get('urls', []), 'request_cases': discovery.get('request_cases', []), 'scan_profile': CURRENT_SCAN_MODE, 'max_targets': 80 if CURRENT_SCAN_MODE == 'deep' else 30 if CURRENT_SCAN_MODE == 'balanced' else 8})
        elif tool == 'nikto':
            arguments['scan_profile'] = CURRENT_SCAN_MODE
        return arguments
    method = str(case.get('method') or 'GET').upper()
    data = str(case.get('data') or '')
    parameters = list(case.get('parameters') or [])
    if tool == 'arjun':
        arguments.update({'method': method, 'data': data, 'known_parameters': parameters, 'timeout': timeout_override or ARJUN_TIMEOUT})
    elif tool in {'sqlmap', 'dalfox', 'commix', 'traversal', 'idor'}:
        arguments.update({'method': method, 'data': data, 'parameters': parameters, 'timeout': timeout_override or PARAMETER_TOOL_TIMEOUTS[tool]})
        if tool == 'dalfox':
            arguments['allow_state_changes'] = state_changing_tests_allowed(target_url, allow_state_changes)
    elif tool == 'authorization':
        arguments.update({'secondary_cookies': secondary_cookies, 'method': 'GET', 'data': '', 'parameters': parameters, 'timeout': timeout_override or PARAMETER_TOOL_TIMEOUTS[tool]})
    elif tool in {'browser', 'workflow'}:
        default_method = 'POST' if tool == 'workflow' else 'GET'
        arguments.update({'method': method if case.get('method') else default_method, 'data': data, 'parameters': parameters, 'source_url': str(case.get('source_url') or ''), 'allow_state_changes': state_changing_tests_allowed(target_url, allow_state_changes), 'timeout': timeout_override or PARAMETER_TOOL_TIMEOUTS[tool]})
        if tool == 'browser':
            if not single_tool:
                arguments.update({'fields': list(case.get('fields', [])), 'client_sources': list(case.get('client_sources', [])), 'client_sinks': list(case.get('client_sinks', []))})
        else:
            arguments.update({'fields': list(case.get('fields', [])), 'file_parameters': list(case.get('file_parameters', [])), 'token_parameters': list(case.get('token_parameters', [])), 'enctype': str(case.get('enctype') or '')})
            if not single_tool:
                arguments['known_urls'] = list(discovery.get('urls', []))
    return arguments

# Counts tool errors, skips, and partial runs across the assessment.
def summarize_results(results: dict[str, Any]) -> tuple[int, int, int]:
    errors = skips = partial = 0
    rows = []
    for path, result in iter_leaf_results(results):
        status = str(result.get('status', 'error'))
        errors += status == 'error'
        skips += status == 'skipped'
        partial += status == 'partial'
        if status == 'error':
            rows.append(('/'.join(path), result.get('diagnosis', 'unknown'), str(result.get('output', ''))))
    if rows:
        print('\n=== Scanner error details ===', file=sys.stderr)
        for path, cause, detail in rows:
            print(f'[-] {path}: {cause} — {detail[:500]}', file=sys.stderr)
    return (errors, skips, partial)

# Reuses the report deduplicator for the terminal finding summary.
def _report_flatten_findings_for_summary(results: dict[str, Any]) -> list[dict[str, Any]]:

    report_path = SERVERS / 'reporting' / 'reportServer.py'
    if not report_path.is_file():
        raise FileNotFoundError(report_path)
    module_name = '_secops_report_summary_runtime'
    module = sys.modules.get(module_name)
    if module is None:
        spec = importlib.util.spec_from_file_location(module_name, report_path)
        if spec is None or spec.loader is None:
            raise ImportError(f'Cannot load report normalizer from {report_path}')
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module


        added_paths = []
        for candidate in (str(SERVERS), str(ROOT)):
            if candidate not in sys.path:
                sys.path.insert(0, candidate)
                added_paths.append(candidate)
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(module_name, None)
            raise
        finally:
            for candidate in added_paths:
                try:
                    sys.path.remove(candidate)
                except ValueError:
                    pass
    flatten = getattr(module, 'flatten_findings', None)
    if not callable(flatten):
        raise AttributeError('reportServer.py does not expose flatten_findings()')
    rows = flatten(results)
    return [row for row in rows if isinstance(row, dict)]


# Prints the deduplicated confirmed findings and candidates at the end.
def print_security_finding_summary(results: dict[str, Any]) -> None:

    try:
        rows = _report_flatten_findings_for_summary(results)
    except Exception as exc:
        print(f"[!] Report deduplicator unavailable for terminal summary: {type(exc).__name__}: {exc}", file=sys.stderr)
        rows = []
        for _, tools in results.items():
            if not isinstance(tools, dict):
                continue
            for _, result in iter_leaf_results(tools):
                tool = str(result.get('tool') or 'unknown')
                for finding in result.get('vulnerabilities') or []:
                    if isinstance(finding, dict):
                        rows.append({**finding, 'tool': tool})
    confirmed = [row for row in rows if str(row.get('category') or '').lower() == 'vulnerability']
    candidates = [row for row in rows if str(row.get('category') or '').lower() == 'candidate']
    print('\n=== Security findings (deduplicated) ===')
    print(f'[+] Confirmed vulnerabilities: {len(confirmed)}')
    for index, row in enumerate(confirmed, 1):
        tools = row.get('tools') if isinstance(row.get('tools'), list) else []
        tool = ','.join(str(value) for value in tools if str(value)) or str(row.get('tool') or 'unknown')
        print(f"    {index}. [{str(row.get('risk') or 'info').upper()}] {row.get('alert') or 'Unnamed finding'} - tool={tool}; parameter={row.get('parameter') or '-'}; url={compact_log_url(row.get('url') or '')}")
    print(f'[+] Candidates requiring validation: {len(candidates)}')
    for index, row in enumerate(candidates, 1):
        tools = row.get('tools') if isinstance(row.get('tools'), list) else []
        tool = ','.join(str(value) for value in tools if str(value)) or str(row.get('tool') or 'unknown')
        print(f"    {index}. [{str(row.get('risk') or 'info').upper()}] {row.get('alert') or 'Unnamed finding'} - tool={tool}; parameter={row.get('parameter') or '-'}; url={compact_log_url(row.get('url') or '')}")

SINGLE_TOOL_CHOICES = tuple((spec.name for spec in ALL_TOOLS if spec.name != 'report'))
