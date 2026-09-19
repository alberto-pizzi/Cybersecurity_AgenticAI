from __future__ import annotations
import argparse
import atexit
import ast
import contextlib
import asyncio
import functools
import base64
import hashlib
import zlib
import html
import importlib.util
import ipaddress
import json
import math
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import sysconfig
import time
import threading
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
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlparse, urlunparse
warnings.filterwarnings('ignore', message='.*authlib\\.jose.*deprecated.*')
import requests
with warnings.catch_warnings():
    warnings.simplefilter('ignore')
    try:
        from fastmcp import Client
    except ModuleNotFoundError:
        # Keep lightweight CLI surfaces such as --help/--list-tools available before the
        # runtime environment is initialized. Live preflight reports the missing dependency.
        Client = None  # type: ignore[assignment,misc]
from utils import apply_runtime_target_preparation, absolute_url, atomic_write_text, canonical_cookie_header, cookie_header_fingerprint, cookie_names, load_runtime_config, normalize_url, normalized_origin, normalized_hostname, parse_cookie_header, request_same_origin_redirects, request_contract_state_change_reason, ROOT_DIR, same_origin, sanitize_discovered_url, scanner_session_probe, secops_source_fingerprint, request_body_fingerprint, SERVERS_DIR, target_runtime_profile, url_in_authorized_scope as _url_in_explicit_scope, MCP_UNIFIED_SERVICE, mcp_http_port, mcp_http_url, scanner_request_rate, runtime_request_rate_policy, MAX_AUTHENTICATED_IDENTITIES, valid_identity_label, safe_int_value, safe_bool_value, safe_float_value
from targetAuth import BrowserLoginError, _capture_storage_state, _looks_like_application_login_entry, browser_oidc_login_session
ROOT = Path(ROOT_DIR).resolve()
SERVERS = Path(SERVERS_DIR).resolve()
RUNTIME_FILE = ROOT / '.secops_runtime.json'
UNIFIED_MCP_SERVER = 'secopsServer.py'
LOCAL_BIN = Path.home() / '.local' / 'bin'
MCP_CONNECT_TIMEOUT = safe_float_value(os.getenv('SECOPS_MCP_CONNECT_TIMEOUT', '20'), 20.0)
MCP_TOOL_TIMEOUT = safe_float_value(os.getenv('SECOPS_MCP_TIMEOUT', '1200'), 1200.0)
MCP_SCANNER_RETURN_GRACE_SECONDS = max(15.0, safe_float_value(os.getenv('SECOPS_MCP_SCANNER_RETURN_GRACE_SECONDS', '60'), 60.0))
MCP_ZAP_RETURN_GRACE_SECONDS = max(30.0, safe_float_value(os.getenv('SECOPS_MCP_ZAP_RETURN_GRACE_SECONDS', '90'), 90.0))
MCP_REPORT_MAX_BYTES = max(1024 * 1024, safe_int_value(os.getenv('SECOPS_MCP_REPORT_MAX_BYTES', str(64 * 1024 * 1024)), 64 * 1024 * 1024))
MCP_REPORT_INLINE_MAX_BYTES = min(MCP_REPORT_MAX_BYTES, max(65536, safe_int_value(os.getenv('SECOPS_MCP_REPORT_INLINE_MAX_BYTES', str(128 * 1024)), 128 * 1024)))
MCP_REPORT_CHUNK_BYTES = min(512 * 1024, max(16384, safe_int_value(os.getenv('SECOPS_MCP_REPORT_CHUNK_BYTES', str(64 * 1024)), 64 * 1024)))
MCP_REPORT_MAX_CHUNKS = max(8, safe_int_value(os.getenv('SECOPS_REPORT_UPLOAD_MAX_CHUNKS', '2048'), 2048))
MCP_REPORT_CHUNK_TIMEOUT = max(30.0, safe_float_value(os.getenv('SECOPS_MCP_REPORT_CHUNK_TIMEOUT', '120'), 120.0))
MCP_REPORT_TRANSFER_TIMEOUT = max(MCP_REPORT_CHUNK_TIMEOUT, safe_float_value(os.getenv('SECOPS_MCP_REPORT_TRANSFER_TIMEOUT', '900'), 900.0))
MCP_REPORT_PDF_TIMEOUT_HINT = max(300.0, safe_float_value(os.getenv('SECOPS_REPORT_PDF_TIMEOUT', '3600'), 3600.0))
MCP_REPORT_RENDER_TIMEOUT = max(MCP_TOOL_TIMEOUT, MCP_REPORT_PDF_TIMEOUT_HINT + 300.0, safe_float_value(os.getenv('SECOPS_MCP_REPORT_RENDER_TIMEOUT', '4200'), 4200.0))
MCP_REPORT_RENDER_SECONDS_PER_MIB = max(0.0, safe_float_value(os.getenv('SECOPS_MCP_REPORT_RENDER_SECONDS_PER_MIB', '60'), 60.0))
MCP_REPORT_RENDER_TIMEOUT_MAX = max(MCP_REPORT_RENDER_TIMEOUT, safe_float_value(os.getenv('SECOPS_MCP_REPORT_RENDER_TIMEOUT_MAX', '7200'), 7200.0))
# TEST verifies that report transport/rendering works, but must never inherit the multi-hour normal
# report watchdog. The report server receives the same scan_mode and applies the render ceiling to
# the actual WeasyPrint subprocess as well, so a cancelled HTTP request cannot leave it running for hours.
TEST_REPORT_TRANSFER_TIMEOUT_SECONDS = max(30.0, safe_float_value(os.getenv('SECOPS_TEST_REPORT_TRANSFER_TIMEOUT', '60'), 60.0))
TEST_REPORT_RENDER_TIMEOUT_SECONDS = max(60.0, safe_float_value(os.getenv('SECOPS_TEST_REPORT_RENDER_TIMEOUT', '180'), 180.0))
# The generic MCP timeout is intentionally generous for normal assessments, but TEST is a smoke
# profile and must not inherit a 20-minute control-plane watchdog. This ceiling applies only to
# the requested MCP wait; scanner cleanup/serialization grace is added separately below.
TEST_MCP_AUX_REQUEST_TIMEOUT_SECONDS = max(30.0, safe_float_value(os.getenv('SECOPS_TEST_MCP_AUX_REQUEST_TIMEOUT', '60'), 60.0))
MCP_ZAP_SHARED_WAIT_MULTIPLIER = max(0.0, safe_float_value(os.getenv('SECOPS_ZAP_SHARED_WAIT_MULTIPLIER', '1.0'), 1.0))
MAX_PARAMETER_ENDPOINTS = max(1, safe_int_value(os.getenv('SECOPS_MAX_PARAMETER_ENDPOINTS', '5'), 5))
TERMINAL_URL_MAX = max(120, safe_int_value(os.getenv('SECOPS_TERMINAL_URL_MAX', '240'), 240))

MAX_REQUEST_RATE = scanner_request_rate()
REQUEST_INTERVAL_SECONDS = 1.0 / MAX_REQUEST_RATE
_LAST_HTTP_REQUEST_AT = 0.0
_HTTP_PACE_LOCK = threading.Lock()

def _pace_http_request(deadline: float | None = None) -> bool:
    global _LAST_HTTP_REQUEST_AT
    # Discovery can run from worker threads. Serialize the pacer itself so two callers cannot
    # both observe the same timestamp and emit an unintended short burst. Deadline-aware callers
    # may decline a request rather than sleeping beyond their enclosing wall-clock budget.
    with _HTTP_PACE_LOCK:
        now = time.monotonic()
        wait = REQUEST_INTERVAL_SECONDS - (now - _LAST_HTTP_REQUEST_AT)
        if deadline is not None and now + max(0.0, wait) >= float(deadline):
            return False
        if wait > 0:
            time.sleep(wait)
        if deadline is not None and time.monotonic() >= float(deadline):
            return False
        _LAST_HTTP_REQUEST_AT = time.monotonic()
        return True


# Converts untrusted numeric metadata without letting a malformed scanner/MCP field abort an
# orchestrator node after the scanner itself has already returned. Booleans are deliberately
# rejected because Python otherwise treats True/False as integers 1/0.
def safe_int_metadata(value: Any, default: int=0) -> int:
    return safe_int_value(value, default)


def safe_bool_metadata(value: Any, default: bool=False) -> bool:
    return safe_bool_value(value, default)


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
MAX_ARJUN_ENDPOINTS = max(1, safe_int_value(os.getenv('SECOPS_MAX_ARJUN_ENDPOINTS', '12'), 12))
MAX_CRAWL_PAGES = max(10, safe_int_value(os.getenv('SECOPS_MAX_CRAWL_PAGES', '2200'), 2200))
MAX_SCRIPT_ASSETS = max(4, safe_int_value(os.getenv('SECOPS_MAX_SCRIPT_ASSETS', '1200'), 1200))
SCANNER_PROGRESS_INTERVAL = max(10, safe_int_value(os.getenv('SECOPS_PROGRESS_INTERVAL', '30'), 30))
TEST_SCANNER_TIMEOUT_SECONDS = 10
TEST_DISCOVERY_TIME_BUDGET_SECONDS = 8

DISCOVERY_LIMITS = {
    'test': {'crawl_pages': 8, 'crawl_pages_max': 12, 'browser_pages': 4, 'browser_pages_max': 6, 'browser_per_origin_pages': 6, 'browser_menu_clicks_per_page': 2, 'browser_dom_passes': 1, 'scripts': 8, 'route_variants': 2, 'per_origin_pages': 8, 'same_host_service_candidates': 32, 'same_host_service_time_budget_seconds': TEST_DISCOVERY_TIME_BUDGET_SECONDS, 'same_host_service_initial_time_budget_seconds': 4, 'same_host_service_expansion_hosts': 2, 'same_host_service_expansion_recrawl_pages': 4},
    'fast': {'crawl_pages': 120, 'crawl_pages_max': 220, 'browser_pages': 72, 'browser_pages_max': 200, 'browser_per_origin_pages': 180, 'browser_menu_clicks_per_page': 16, 'browser_dom_passes': 3, 'scripts': 128, 'route_variants': 8, 'per_origin_pages': 190, 'same_host_service_candidates': 4096, 'same_host_service_time_budget_seconds': 240, 'same_host_service_initial_time_budget_seconds': 120, 'same_host_service_expansion_hosts': 8, 'same_host_service_expansion_recrawl_pages': 24},
    'balanced': {'crawl_pages': 600, 'crawl_pages_max': 1100, 'browser_pages': 400, 'browser_pages_max': 1200, 'browser_per_origin_pages': 1000, 'browser_menu_clicks_per_page': 64, 'browser_dom_passes': 6, 'scripts': 640, 'route_variants': 20, 'per_origin_pages': 900, 'same_host_service_candidates': 32768, 'same_host_service_time_budget_seconds': 720, 'same_host_service_initial_time_budget_seconds': 360, 'same_host_service_expansion_hosts': 32, 'same_host_service_expansion_recrawl_pages': 90},
    'deep': {'crawl_pages': 1200, 'crawl_pages_max': 2200, 'browser_pages': 800, 'browser_pages_max': 2400, 'browser_per_origin_pages': 2000, 'browser_menu_clicks_per_page': 112, 'browser_dom_passes': 9, 'scripts': 1200, 'route_variants': 32, 'per_origin_pages': 1800, 'same_host_service_candidates': 65535, 'same_host_service_time_budget_seconds': 1200, 'same_host_service_initial_time_budget_seconds': 600, 'same_host_service_expansion_hosts': 128, 'same_host_service_expansion_recrawl_pages': 180},
}
HTTP_ATTEMPT_BUDGET_FACTORS = {'test': 1.0, 'fast': 1.75, 'balanced': 2.0, 'deep': 2.0}
SCRIPT_ATTEMPT_BUDGET_FACTORS = {'test': 1.0, 'fast': 1.5, 'balanced': 1.75, 'deep': 1.75}
# Chromium discovery has both a page ceiling and a wall-clock ceiling. The time budget scales with
# the configured base navigation budget instead of being a second unrelated magic-number table.
# Four seconds/base page is intentionally generous for normal local/intranet pages while preventing
# pathological navigation retries or slow SPAs from turning a bounded crawl into an unbounded run.
BROWSER_DISCOVERY_SECONDS_PER_BASE_PAGE = 4.0
BROWSER_DISCOVERY_MIN_SECONDS = 120.0
BROWSER_DISCOVERY_MIN_SECONDS_BY_MODE = {'test': float(TEST_DISCOVERY_TIME_BUDGET_SECONDS)}
FINAL_BROWSER_VERIFICATION_LIMITS = {'test': 2, 'fast': 12, 'balanced': 96, 'deep': 200}
FINAL_BROWSER_VERIFICATION_MAX_LIMITS = {'test': 3, 'fast': 20, 'balanced': 160, 'deep': 320}
JWT_TOKEN_LIMITS = {'test': 4, 'fast': 16, 'balanced': 64, 'deep': 192}
# Deterministic broad scans use bounded sibling-origin reference/adaptive limits.
# Agentic planning receives the complete authorized observed-origin ranking as concrete broad actions;
# execution ceilings are applied only after AI selection.
BROAD_SIBLING_ORIGIN_BASE_LIMITS = {'test': 1, 'fast': 6, 'balanced': 32, 'deep': 64}
BROAD_SIBLING_ORIGIN_MAX_LIMITS = {'test': 2, 'fast': 12, 'balanced': 64, 'deep': 128}
BROAD_SIBLING_ADAPTIVE_RATIO = 0.75
BROAD_SIBLING_TIMEOUT_FACTORS = {'test': 1.0, 'fast': 0.55, 'balanced': 0.75, 'deep': 0.85}
SCAN_MODES = {
    'test': {
        'broad': {'zap': TEST_SCANNER_TIMEOUT_SECONDS, 'nuclei': TEST_SCANNER_TIMEOUT_SECONDS, 'nikto': TEST_SCANNER_TIMEOUT_SECONDS, 'ffuf': TEST_SCANNER_TIMEOUT_SECONDS, 'session': TEST_SCANNER_TIMEOUT_SECONDS},
        'parameter': {'sqlmap': TEST_SCANNER_TIMEOUT_SECONDS, 'dalfox': TEST_SCANNER_TIMEOUT_SECONDS, 'commix': TEST_SCANNER_TIMEOUT_SECONDS, 'traversal': TEST_SCANNER_TIMEOUT_SECONDS, 'idor': TEST_SCANNER_TIMEOUT_SECONDS, 'authorization': TEST_SCANNER_TIMEOUT_SECONDS, 'browser': TEST_SCANNER_TIMEOUT_SECONDS, 'workflow': TEST_SCANNER_TIMEOUT_SECONDS},
        'limits': {'sqlmap': 1, 'dalfox': 1, 'commix': 1, 'traversal': 2, 'idor': 1, 'authorization': 2, 'browser': 2, 'workflow': 1},
        'arjun': TEST_SCANNER_TIMEOUT_SECONDS, 'arjun_limit': 2,
    },
    'fast': {
        'broad': {'zap': 120, 'nuclei': 240, 'nikto': 60, 'ffuf': 50, 'session': 25},
        'parameter': {'sqlmap': 75, 'dalfox': 45, 'commix': 90, 'traversal': 35, 'idor': 18, 'authorization': 30, 'browser': 45, 'workflow': 40},
        'limits': {'sqlmap': 6, 'dalfox': 8, 'commix': 6, 'traversal': 8, 'idor': 6, 'authorization': 10, 'browser': 10, 'workflow': 8},
        'arjun': 45, 'arjun_limit': 12,
    },
    'balanced': {
        'broad': {'zap': 2400, 'nuclei': 3600, 'nikto': 180, 'ffuf': 120, 'session': 50},
        'parameter': {'sqlmap': 180, 'dalfox': 120, 'commix': 180, 'traversal': 75, 'idor': 45, 'authorization': 70, 'browser': 120, 'workflow': 105},
        # Raised from the previous 8-12 ceiling: each case already runs with its own independent
        # per-case timeout (the 'parameter' timeouts above), so more selected cases means more total
        # wall-clock time for this phase, not less time per case. The previous ceiling was small
        # enough that, on an application with hundreds of discovered parameterized endpoints, only a
        # small fraction of the real attack surface ever reached a specialist tool in 'balanced' mode.
        'limits': {'sqlmap': 72, 'dalfox': 96, 'commix': 64, 'traversal': 96, 'idor': 64, 'authorization': 128, 'browser': 128, 'workflow': 96},
        'arjun': 120, 'arjun_limit': 96,
    },
    'deep': {
        'broad': {'zap': 4800, 'nuclei': 7200, 'nikto': 300, 'ffuf': 210, 'session': 90},
        'parameter': {'sqlmap': 300, 'dalfox': 210, 'commix': 300, 'traversal': 120, 'idor': 90, 'authorization': 120, 'browser': 210, 'workflow': 180},
        'limits': {'sqlmap': 128, 'dalfox': 160, 'commix': 112, 'traversal': 160, 'idor': 112, 'authorization': 192, 'browser': 192, 'workflow': 160},
        'arjun': 180, 'arjun_limit': 160,
    },
}
# Specialist budgets have a fixed base and a bounded adaptive overflow. The overflow is
# available only to high-value deferred request contracts selected by deterministic ranking.
ADAPTIVE_SPECIALIST_OVERFLOW = {
    'test': {'arjun': 0, 'sqlmap': 0, 'dalfox': 0, 'commix': 0, 'traversal': 0, 'idor': 0, 'authorization': 0, 'browser': 0, 'workflow': 0},
    'fast': {'arjun': 4, 'sqlmap': 2, 'dalfox': 3, 'commix': 2, 'traversal': 4, 'idor': 2, 'authorization': 4, 'browser': 4, 'workflow': 3},
    'balanced': {'arjun': 64, 'sqlmap': 48, 'dalfox': 64, 'commix': 48, 'traversal': 64, 'idor': 48, 'authorization': 72, 'browser': 72, 'workflow': 56},
    'deep': {'arjun': 112, 'sqlmap': 96, 'dalfox': 112, 'commix': 96, 'traversal': 112, 'idor': 96, 'authorization': 128, 'browser': 128, 'workflow': 112},
}
# Routing parameters that select internal files/modules are a high-confidence traversal/LFI class.
# A separate bounded reserve prevents large menus from starving these contracts behind unrelated
# request variants while retaining the normal specialist ranking for every other case.
ROUTING_TRAVERSAL_RESERVE = {'test': 2, 'fast': 32, 'balanced': 192, 'deep': 320}
# Discovery may retain more value variants so later reasoning can see them, while request-level
# scanners use a smaller cap for equivalent method/path/parameter shapes. Traversal is the explicit
# exception because routing values that select different local resources receive distinct signatures.
SPECIALIST_ROUTE_VARIANT_LIMITS = {'test': 1, 'fast': 2, 'balanced': 4, 'deep': 6}
GENERIC_LIVE_INPUT_RESERVE = {
    'test': {'sqlmap': 1, 'dalfox': 1, 'commix': 1},
    'fast': {'sqlmap': 4, 'dalfox': 6, 'commix': 2},
    'balanced': {'sqlmap': 96, 'dalfox': 128, 'commix': 64},
    'deep': {'sqlmap': 160, 'dalfox': 192, 'commix': 96},
}
SAFE_SURFACE_SWEEP_LIMITS = {'test': 32, 'fast': 800, 'balanced': 6000, 'deep': 15000}
SAFE_SURFACE_SWEEP_TIMEOUT_FACTOR = 0.25
ADAPTIVE_HIGH_VALUE_PATH_HINTS = ('/api/', '/admin/', 'management', 'search', 'query', 'upload', 'download', 'callback', 'webhook', 'config', 'settings', 'profile', 'account')
AUTHORIZED_SCOPE_ORIGINS: set[str] = set()
ALLOW_SAME_HOST_PORTS = False
DISCOVER_SAME_HOST_SERVICES = False
PRIMARY_SCOPE_TARGET = ''
SAME_HOST_SERVICE_DISCOVERY_CACHE: dict[tuple[str, str, int, str, int], dict[str, Any]] = {}
SAME_HOST_SERVICE_DISCOVERY_TIME_SPENT_SECONDS = 0.0
SAME_HOST_SERVICE_DISCOVERY_TIME_LOCK = threading.Lock()
AUTHENTICATED_ORIGIN_COOKIES: dict[tuple[str, str], str] = {}
# A raw Cookie header tried speculatively on another authorized port can be rejected there even
# though it remains valid on the primary origin. Cache that conclusive rejection per cookie value
# and destination origin so later scanners do not repeat the same invalid session attempt.
REJECTED_SPECULATIVE_RAW_COOKIE_KEYS: set[tuple[str, str]] = set()
RUNTIME_TARGET_AUTH: dict[str, Any] = {}  # primary identity compatibility view
RUNTIME_TARGET_AUTH_STATES: dict[str, dict[str, Any]] = {}
RUNTIME_AUTH_COOKIE_TO_REFERENCE: dict[str, str] = {}
RUNTIME_AUTH_AMBIGUOUS_FINGERPRINTS: set[str] = set()
RUNTIME_PRIMARY_IDENTITY_COOKIE = ''
RUNTIME_AUTH_ORIGIN_LIMITS = {'test': 2, 'fast': 12, 'balanced': 32, 'deep': 64}
# One authenticated enrichment pass must be bounded globally; otherwise a 60s browser timeout can
# multiply by every discovered same-host service/application. Deferred origins remain eligible in
# later passes, so this limits wall-clock amplification without marking them permanently failed.
RUNTIME_AUTH_PASS_TIMEOUTS = {'test': TEST_DISCOVERY_TIME_BUDGET_SECONDS, 'fast': 180, 'balanced': 720, 'deep': 1800}
# Candidate application entry points are bounded per origin/root, but the login helper shares one
# total deadline across all entries. This keeps authentication bounded while avoiding an arbitrary
# fixed top-8 window on larger applications.
RUNTIME_AUTH_ENTRY_CANDIDATE_LIMITS = {'test': 2, 'fast': 6, 'balanced': 12, 'deep': 16}
RUNTIME_AUTH_RECRAWL_PAGES = {'test': 4, 'fast': 36, 'balanced': 90, 'deep': 180}
RUNTIME_AUTH_APPLICATION_LIMITS = {'test': 2, 'fast': 6, 'balanced': 18, 'deep': 36}
RUNTIME_AUTH_APPLICATION_RECRAWL_PAGES = {'test': 4, 'fast': 24, 'balanced': 72, 'deep': 150}
RUNTIME_AUTH_APPLICATION_ATTEMPTS: dict[str, dict[str, Any]] = {}
CURRENT_SCAN_MODE = 'balanced'
BROAD_SCANNER_TIMEOUTS = dict(SCAN_MODES[CURRENT_SCAN_MODE]['broad'])
PARAMETER_TOOL_TIMEOUTS = dict(SCAN_MODES[CURRENT_SCAN_MODE]['parameter'])
PARAMETER_TOOL_CASE_LIMITS = dict(SCAN_MODES[CURRENT_SCAN_MODE]['limits'])
ARJUN_TIMEOUT = int(SCAN_MODES[CURRENT_SCAN_MODE]['arjun'])
ARJUN_ENDPOINT_LIMIT = int(SCAN_MODES[CURRENT_SCAN_MODE].get('arjun_limit', 1))


def oast_timeout_seconds(oast_class: str='remote-fetch') -> int:
    """Return the bounded Interactsh action timeout for the active scan profile.

    TEST is deliberately capped at the same 10-second action budget as every other scanner.
    Keeping this policy in one place prevents debug/single-tool paths from silently inheriting
    the normal 45--75 second waits.
    """
    if CURRENT_SCAN_MODE == 'test':
        return TEST_SCANNER_TIMEOUT_SECONDS
    normalized = str(oast_class or 'remote-fetch').strip().lower()
    if normalized == 'explicit':
        return 120 if CURRENT_SCAN_MODE == 'deep' else 75
    if normalized == 'command':
        return 75 if CURRENT_SCAN_MODE == 'deep' else 55
    return 60 if CURRENT_SCAN_MODE == 'deep' else 45

# Configures the explicit HTTP scope extension for this process; same-origin remains allowed by default.
def configure_authorized_scope(
    target: str, origins: list[str] | None=None, *, allow_same_host_ports: bool=False,
    discover_same_host_services: bool=False,
) -> None:
    global PRIMARY_SCOPE_TARGET, ALLOW_SAME_HOST_PORTS, DISCOVER_SAME_HOST_SERVICES, SAME_HOST_SERVICE_DISCOVERY_TIME_SPENT_SECONDS
    PRIMARY_SCOPE_TARGET = normalize_url(target)
    ALLOW_SAME_HOST_PORTS = bool(allow_same_host_ports)
    DISCOVER_SAME_HOST_SERVICES = bool(discover_same_host_services and ALLOW_SAME_HOST_PORTS)
    AUTHORIZED_SCOPE_ORIGINS.clear()
    REJECTED_SPECULATIVE_RAW_COOKIE_KEYS.clear()
    SAME_HOST_SERVICE_DISCOVERY_CACHE.clear()
    with SAME_HOST_SERVICE_DISCOVERY_TIME_LOCK:
        SAME_HOST_SERVICE_DISCOVERY_TIME_SPENT_SECONDS = 0.0
    for value in origins or []:
        origin = normalized_origin(str(value or '').strip())
        if origin:
            AUTHORIZED_SCOPE_ORIGINS.add(origin)

# Returns true for the primary origin, an explicitly authorized exact origin, or (when enabled)
# another HTTP/HTTPS service on an already-authorized exact hostname.
def url_in_authorized_scope(target: str, candidate: str) -> bool:
    return _url_in_explicit_scope(
        target, candidate, AUTHORIZED_SCOPE_ORIGINS, allow_same_host_ports=ALLOW_SAME_HOST_PORTS,
    )

# Registers one application cookie for the exact origin that created it. The authenticated profile
# can therefore carry several independent sibling sessions without ever copying the primary raw header.
def _cookie_fingerprint(cookies: str) -> str:
    if not str(cookies or '').strip():
        return ''
    try:
        return cookie_header_fingerprint(cookies)
    except ValueError:
        # Invalid Cookie headers cannot be sent by normal CLI/config paths. Keep an opaque digest
        # only so malformed direct/internal inputs never alias a valid authenticated identity.
        return hashlib.sha256(str(cookies or '').encode('utf-8', errors='replace')).hexdigest()


def _runtime_identity_reference(cookies: str) -> str:
    fingerprint = _cookie_fingerprint(cookies)
    if not fingerprint or fingerprint in RUNTIME_AUTH_AMBIGUOUS_FINGERPRINTS:
        return ''
    return str(RUNTIME_AUTH_COOKIE_TO_REFERENCE.get(fingerprint) or '')


def _runtime_target_auth_for_cookie(cookies: str='') -> dict[str, Any]:
    if cookies:
        reference = _runtime_identity_reference(cookies)
        state = RUNTIME_TARGET_AUTH_STATES.get(reference) if reference else None
        return state if isinstance(state, dict) else {}
    return RUNTIME_TARGET_AUTH


def _register_runtime_cookie_alias(cookies: str, reference: str) -> None:
    fingerprint = _cookie_fingerprint(cookies)
    if not fingerprint or not reference or reference not in RUNTIME_TARGET_AUTH_STATES:
        return
    if fingerprint in RUNTIME_AUTH_AMBIGUOUS_FINGERPRINTS:
        return
    existing = str(RUNTIME_AUTH_COOKIE_TO_REFERENCE.get(fingerprint) or '')
    if existing and existing != reference:
        # Two configured identities resolved to the same concrete Cookie header. Treat that fingerprint
        # as ambiguous rather than silently binding it to whichever profile was loaded last. This keeps
        # cross-account/BOLA evidence fail-closed when the target collapsed two logins into one session.
        RUNTIME_AUTH_COOKIE_TO_REFERENCE.pop(fingerprint, None)
        RUNTIME_AUTH_AMBIGUOUS_FINGERPRINTS.add(fingerprint)
        return
    RUNTIME_AUTH_COOKIE_TO_REFERENCE[fingerprint] = reference


# Registers one application cookie for the concrete identity/origin that created it.  The registry is
# identity-keyed so two accounts can hold different sessions for the same authorized sibling origin.
def register_authenticated_origin_cookie(origin_or_url: str, cookies: str, identity_cookies: str='') -> None:
    origin = normalized_origin(origin_or_url)
    if not origin or not cookies:
        return
    reference = _runtime_identity_reference(identity_cookies or cookies)
    if not reference:
        return
    AUTHENTICATED_ORIGIN_COOKIES[(reference, origin)] = canonical_cookie_header(cookies)


def authenticated_origin_cookie(origin_or_url: str, identity_cookies: str='') -> str:
    origin = normalized_origin(origin_or_url)
    reference = _runtime_identity_reference(identity_cookies) if identity_cookies else str(RUNTIME_TARGET_AUTH.get('reference') or '')
    if not origin or not reference:
        return ''
    return AUTHENTICATED_ORIGIN_COOKIES.get((reference, origin), '')


def _runtime_storage_cookie_header(candidate: str, identity_cookies: str='') -> str:
    """Build the Cookie header a browser would send to this exact URL from saved storage state.

    Unlike a raw ``Cookie:`` string, Playwright storage state retains Domain, Path, Secure and
    expiry metadata. That lets the runtime reuse legitimate parent-domain/path-scoped SSO cookies
    without assuming that every authorized sibling accepts the primary application's PHP session.
    For duplicate names the longest matching cookie path wins, mirroring the application-specific
    value that a browser places first.
    """
    runtime_state = _runtime_target_auth_for_cookie(identity_cookies)
    storage = runtime_state.get('storage_state') if isinstance(runtime_state.get('storage_state'), dict) else None
    if not storage:
        return ''
    try:
        parsed = urlparse(str(candidate or ''))
        host = normalized_hostname(parsed.hostname or '')
        request_path = str(parsed.path or '/') or '/'
        secure_request = str(parsed.scheme or '').lower() == 'https'
    except ValueError:
        return ''
    if not host:
        return ''

    now = time.time()
    selected: dict[str, tuple[int, str, str]] = {}
    for row in storage.get('cookies') or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get('name') or '').strip()
        value = str(row.get('value') or '')
        # Partitioned third-party cookies (CHIPS) depend on top-level-site context. Direct HTTP
        # scanner requests cannot faithfully reconstruct that browser partition, so never widen
        # them into a manual Cookie header. Browser/OIDC reuse still preserves them in storage_state.
        if str(row.get('partitionKey') or '').strip():
            continue
        raw_domain = str(row.get('domain') or '').strip().lower().rstrip('.')
        domain_cookie = raw_domain.startswith('.')
        domain = raw_domain.lstrip('.')
        cookie_path = str(row.get('path') or '/') or '/'
        if not name or not domain:
            continue
        # Playwright preserves the leading dot used by domain cookies. A host-only cookie must
        # never be widened to sibling hosts merely because its textual domain is a suffix.
        if domain_cookie:
            if host != domain and not host.endswith('.' + domain):
                continue
        elif host != domain:
            continue
        if safe_bool_metadata(row.get('secure'), False) and not secure_request:
            continue
        raw_expires = row.get('expires', -1)
        try:
            expires = -1.0 if raw_expires in (None, '') else float(raw_expires)
        except (TypeError, ValueError):
            expires = -1.0
        # Playwright exposes expiry as Unix seconds; -1 is the browser/session-cookie sentinel.
        # Preserve an explicit 0 instead of treating it as falsy/-1: epoch-expired cookies must never
        # be projected into direct HTTP scanner requests.
        if expires >= 0 and expires <= now:
            continue
        normalized_path = cookie_path if cookie_path.startswith('/') else '/' + cookie_path
        if request_path != normalized_path and not request_path.startswith(normalized_path.rstrip('/') + '/'):
            continue
        key = name.lower()
        candidate_row = (len(normalized_path), name, value)
        if key not in selected or candidate_row[0] > selected[key][0]:
            selected[key] = candidate_row
    ordered = sorted(selected.values(), key=lambda item: (-item[0], item[1].lower()))
    if not ordered:
        return ''
    return canonical_cookie_header('; '.join(f'{name}={value}' for _, name, value in ordered))


def _merge_cookie_headers(base_header: str, overlay_header: str) -> str:
    values: dict[str, tuple[str, str]] = {}
    for header in (base_header, overlay_header):
        if not header:
            continue
        try:
            pairs = parse_cookie_header(header)
        except ValueError:
            continue
        for name, value in pairs:
            values[name.lower()] = (name, value)
    return canonical_cookie_header('; '.join(f'{name}={value}' for name, value in values.values())) if values else ''


def _raw_cookie_reuse_key(candidate: str, cookies: str) -> tuple[str, str]:
    origin = normalized_origin(candidate)
    try:
        digest = cookie_header_fingerprint(cookies) if cookies else ''
    except ValueError:
        digest = hashlib.sha256(str(cookies or '').encode('utf-8', errors='replace')).hexdigest() if cookies else ''
    return origin, digest


def _speculative_same_host_port_raw_cookie(candidate: str, cookies: str) -> bool:
    """True only when the primary raw Cookie header is being tried on another authorized port.

    Browser storage-state cookies and origin-specific sessions are not speculative: they retain
    enough metadata or validation evidence to select the concrete destination correctly.
    """
    if not cookies or not ALLOW_SAME_HOST_PORTS:
        return False
    base = PRIMARY_SCOPE_TARGET or candidate
    if same_origin(base, candidate) or not url_in_authorized_scope(base, candidate):
        return False
    try:
        base_parts = urlparse(base)
        candidate_parts = urlparse(candidate)
    except ValueError:
        return False
    same_host_port_extension = (
        str(base_parts.scheme or '').lower() == str(candidate_parts.scheme or '').lower()
        and normalized_hostname(base_parts.hostname or '') == normalized_hostname(candidate_parts.hostname or '')
        and bool(base_parts.hostname)
        and bool(candidate_parts.hostname)
    )
    if not same_host_port_extension:
        return False
    if runtime_target_auth_available(cookies, candidate) and (_runtime_storage_cookie_header(candidate, cookies) or authenticated_origin_cookie(candidate, cookies)):
        return False
    return _raw_cookie_reuse_key(candidate, cookies) not in REJECTED_SPECULATIVE_RAW_COOKIE_KEYS


def authenticated_application_cookie(candidate: str, identity_cookies: str='') -> str:
    """Return a validated runtime cookie cached for the concrete application scope and identity.

    This is narrower than the origin registry: a refreshed application session is reused only inside
    the same first-path scope that produced it, so a path-specific login cannot widen a flattened
    Cookie header across unrelated applications on the same origin.
    """
    reference = _runtime_identity_reference(identity_cookies)
    if not reference:
        return ''
    scope_key = _runtime_application_scope_key(candidate)
    if not scope_key:
        return ''
    cached = RUNTIME_AUTH_APPLICATION_ATTEMPTS.get(f'{reference}|{scope_key}')
    if not isinstance(cached, dict) or cached.get('status') != 'authenticated':
        return ''
    value = str(cached.get('cookie_header') or '')
    if not value:
        return ''
    try:
        return canonical_cookie_header(value)
    except ValueError:
        return ''


# A raw Cookie header does not carry browser Domain/Path metadata. It is therefore never copied to a
# different hostname. When same-host multi-port scope is explicitly enabled, however, the raw header
# may be tried on another authorized port of the exact same hostname and scheme because HTTP cookies
# themselves are not port-scoped. The session precheck validates that attempt and runtime browser SSO
# or the original username/password can repair it if the application rejects the session on that port.
# Browser storage state remains authoritative whenever Domain/Path/Secure metadata is available.
def scope_cookie_header(candidate: str, cookies: str, *, use_runtime_auth: bool=True) -> str:
    # Runtime OIDC state belongs to an authenticated profile, not to the assessment process as a
    # whole. An explicit no-cookie profile must stay anonymous even when another profile has already
    # established sibling/application sessions in this process.
    if not str(cookies or '').strip():
        return ''
    # Browser/OIDC runtime state is identity-bound. Every configured browser identity may consume
    # its own same-origin storage state. Reuse on another authorized origin/port remains separately
    # controlled by credential.reuse_on_authorized_siblings. This prevents editor/admin comparisons
    # from silently inheriting the primary account while still preserving same-origin localStorage/SSO.
    base = PRIMARY_SCOPE_TARGET or candidate
    identity_state_available = bool(use_runtime_auth and _runtime_identity_reference(cookies))
    runtime_for_identity = bool(
        identity_state_available
        and (same_origin(base, candidate) or runtime_target_auth_available(cookies, candidate))
    )
    runtime_header = _runtime_storage_cookie_header(candidate, cookies) if runtime_for_identity else ''
    application_header = authenticated_application_cookie(candidate, cookies) if runtime_for_identity else ''
    raw_cookie_allowed = same_origin(base, candidate)
    raw_reuse_key = _raw_cookie_reuse_key(candidate, cookies) if cookies else ('', '')
    if cookies and not raw_cookie_allowed and ALLOW_SAME_HOST_PORTS and url_in_authorized_scope(base, candidate):
        try:
            base_parts = urlparse(base)
            candidate_parts = urlparse(candidate)
            raw_cookie_allowed = (
                str(base_parts.scheme or '').lower() == str(candidate_parts.scheme or '').lower()
                and normalized_hostname(base_parts.hostname or '') == normalized_hostname(candidate_parts.hostname or '')
                and bool(base_parts.hostname)
                and bool(candidate_parts.hostname)
                and raw_reuse_key not in REJECTED_SPECULATIVE_RAW_COOKIE_KEYS
            )
        except ValueError:
            raw_cookie_allowed = False
    if cookies and raw_cookie_allowed:
        if not runtime_for_identity:
            return canonical_cookie_header(cookies)
        registered = authenticated_origin_cookie(candidate, cookies)
        # A validated session created specifically for another authorized port/origin must replace
        # the speculative raw-cookie reuse if that first attempt failed. Browser storage metadata
        # remains strongest because it can select path/domain-specific values for the concrete URL.
        if runtime_header:
            return _merge_cookie_headers(cookies, runtime_header)
        if application_header:
            return application_header
        if registered and not same_origin(base, candidate):
            return registered
        return canonical_cookie_header(cookies)

    # An origin registry entry is a compatibility marker/fallback for sessions obtained without a
    # browser storage state. Once storage-state cookie metadata exists, it is authoritative for
    # sibling requests: falling back to the flattened origin header when no cookie matches this path
    # would silently widen a path-scoped cookie.
    if not runtime_for_identity:
        return ''
    runtime_state = _runtime_target_auth_for_cookie(cookies)
    storage = runtime_state.get('storage_state') if isinstance(runtime_state.get('storage_state'), dict) else None
    if storage and storage.get('cookies'):
        return runtime_header
    if application_header:
        return application_header
    return authenticated_origin_cookie(candidate, cookies)


def _load_runtime_target_auth_state() -> dict[str, Any]:
    path = str(os.environ.get('SECOPS_RUNTIME_AUTH_STATE') or '').strip()
    if not path:
        return {}
    try:
        candidate = Path(path).expanduser().resolve()
        payload = json.loads(candidate.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f'[AUTH] Runtime target-auth state could not be loaded: {type(exc).__name__}: {exc}', file=sys.stderr)
        return {}
    if not isinstance(payload, dict) or str(payload.get('kind') or '') not in {'browser_oidc', 'snap4city_oidc', 'browser_oidc_multi'}:
        print('[AUTH] Runtime target-auth state is missing a supported browser/OIDC credential payload.', file=sys.stderr)
        return {}
    return payload


def configure_runtime_target_auth(primary_target: str, primary_cookie: str) -> None:
    global RUNTIME_PRIMARY_IDENTITY_COOKIE
    AUTHENTICATED_ORIGIN_COOKIES.clear()
    RUNTIME_TARGET_AUTH.clear()
    RUNTIME_TARGET_AUTH_STATES.clear()
    RUNTIME_AUTH_COOKIE_TO_REFERENCE.clear()
    RUNTIME_AUTH_AMBIGUOUS_FINGERPRINTS.clear()
    RUNTIME_AUTH_APPLICATION_ATTEMPTS.clear()
    try:
        RUNTIME_PRIMARY_IDENTITY_COOKIE = canonical_cookie_header(primary_cookie) if primary_cookie else ''
    except ValueError:
        RUNTIME_PRIMARY_IDENTITY_COOKIE = str(primary_cookie or '')
    payload = _load_runtime_target_auth_state()
    if not payload:
        return
    primary_origin = normalized_origin(primary_target)
    declared_primary = normalized_origin(str(payload.get('primary_origin') or primary_target))
    if declared_primary and primary_origin and declared_primary != primary_origin:
        print(
            f'[AUTH] Runtime target-auth state belongs to {declared_primary}, not {primary_origin}; additional-origin runtime authentication is disabled.',
            file=sys.stderr,
        )
        return

    if str(payload.get('kind') or '') == 'browser_oidc_multi':
        identity_rows = payload.get('identities')
        if not isinstance(identity_rows, list) or len(identity_rows) > MAX_AUTHENTICATED_IDENTITIES:
            print(
                f'[AUTH] Runtime target-auth state contains an invalid identity list; at most {MAX_AUTHENTICATED_IDENTITIES} browser/OIDC identities are accepted.',
                file=sys.stderr,
            )
            return
        seen_references: set[str] = set()
        for row in identity_rows:
            if not isinstance(row, dict):
                print('[AUTH] Runtime target-auth state contains a malformed identity row; additional-origin runtime authentication is disabled.', file=sys.stderr)
                RUNTIME_TARGET_AUTH_STATES.clear()
                RUNTIME_AUTH_COOKIE_TO_REFERENCE.clear()
                return
            reference = str(row.get('reference') or '').strip()
            fingerprint = str(row.get('cookie_fingerprint') or '').strip().lower()
            credential = row.get('credential') if isinstance(row.get('credential'), dict) else {}
            folded_reference = reference.casefold()
            if (
                not valid_identity_label(reference)
                or folded_reference in seen_references
                or not re.fullmatch(r'[0-9a-f]{64}', fingerprint)
            ):
                print('[AUTH] Runtime target-auth state contains an invalid/duplicate identity reference or cookie fingerprint; additional-origin runtime authentication is disabled.', file=sys.stderr)
                RUNTIME_TARGET_AUTH_STATES.clear()
                RUNTIME_AUTH_COOKIE_TO_REFERENCE.clear()
                return
            seen_references.add(folded_reference)
            state = dict(row)
            state['kind'] = 'browser_oidc'
            state['reference'] = reference
            if not isinstance(state.get('storage_state'), dict):
                state['storage_state'] = None
            RUNTIME_TARGET_AUTH_STATES[reference] = state
            # Register after the state exists so duplicate-session fingerprints are detected fail-closed.
            existing = str(RUNTIME_AUTH_COOKIE_TO_REFERENCE.get(fingerprint) or '')
            if existing and existing != reference:
                RUNTIME_AUTH_COOKIE_TO_REFERENCE.pop(fingerprint, None)
                RUNTIME_AUTH_AMBIGUOUS_FINGERPRINTS.add(fingerprint)
            elif fingerprint not in RUNTIME_AUTH_AMBIGUOUS_FINGERPRINTS:
                RUNTIME_AUTH_COOKIE_TO_REFERENCE[fingerprint] = reference
        primary_reference = str(payload.get('primary_reference') or '').strip()
        if primary_reference and not valid_identity_label(primary_reference):
            print('[AUTH] Runtime target-auth state contains an invalid primary identity reference; additional-origin runtime authentication is disabled.', file=sys.stderr)
            RUNTIME_TARGET_AUTH_STATES.clear()
            RUNTIME_AUTH_COOKIE_TO_REFERENCE.clear()
            return
        # The CLI-primary identity may intentionally be a raw-cookie credential and therefore not
        # have a browser/OIDC state row. Do not fall back to another identity: doing so would bind
        # the primary Cookie header to somebody else's storage state during the compatibility step
        # below. Other browser identities remain available through their own cookie fingerprints.
        if primary_reference and primary_reference in RUNTIME_TARGET_AUTH_STATES:
            RUNTIME_TARGET_AUTH.update(RUNTIME_TARGET_AUTH_STATES[primary_reference])
    else:
        reference = str(payload.get('reference') or 'primary').strip() or 'primary'
        state = dict(payload)
        state['reference'] = reference
        if not isinstance(state.get('storage_state'), dict):
            state['storage_state'] = None
        RUNTIME_TARGET_AUTH_STATES[reference] = state
        RUNTIME_TARGET_AUTH.update(state)
        if primary_cookie:
            _register_runtime_cookie_alias(primary_cookie, reference)

    # The CLI primary Cookie header is authoritative for selecting the primary runtime state even
    # when an older payload did not carry a fingerprint. Multi-identity payloads already map each
    # resolved cookie fingerprint, including the primary.
    if primary_cookie and RUNTIME_TARGET_AUTH:
        primary_reference = str(RUNTIME_TARGET_AUTH.get('reference') or '')
        if primary_reference:
            _register_runtime_cookie_alias(primary_cookie, primary_reference)
            register_authenticated_origin_cookie(primary_target, primary_cookie, primary_cookie)
    if RUNTIME_TARGET_AUTH_STATES:
        refs = ', '.join(RUNTIME_TARGET_AUTH_STATES)
        print(f'[AUTH] Runtime browser/OIDC state loaded for identity-bound additional-origin authentication: {refs}; no child-console credential prompts will be used.')


def _runtime_auth_identity_matches(cookies: str) -> bool:
    return bool(_runtime_identity_reference(cookies))


def runtime_target_auth_available(cookies: str='', candidate: str='') -> bool:
    """Return whether active browser/OIDC repair is allowed for this identity/destination.

    Same-origin refresh is intrinsic to the configured identity and remains available even when
    reuse_on_authorized_siblings=false. Crossing to another authorized origin/port requires that
    explicit credential option in addition to the normal assessment scope policy.
    """
    state = _runtime_target_auth_for_cookie(cookies)
    credential = state.get('credential') if isinstance(state.get('credential'), dict) else {}
    if not state or str(state.get('kind') or '') not in {'browser_oidc', 'snap4city_oidc'}:
        return False
    destination = str(candidate or '').strip()
    if destination and PRIMARY_SCOPE_TARGET and same_origin(PRIMARY_SCOPE_TARGET, destination):
        return True
    return bool(credential.get('reuse_on_authorized_siblings', False))


# Loads the timeouts and case limits for the selected scan profile.
def configure_scan_mode(mode: str) -> None:
    global CURRENT_SCAN_MODE, ARJUN_TIMEOUT, ARJUN_ENDPOINT_LIMIT, SAME_HOST_SERVICE_DISCOVERY_TIME_SPENT_SECONDS
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
    # A scan-mode configuration starts a fresh assessment budget. Reset the host-level service
    # cache together with the wall-clock counter so a second programmatic run in the same Python
    # process cannot combine a fresh time allowance with stale TCP/HTTP classifications. Within
    # one assessment configure_scan_mode() is not called again, so anonymous/authenticated profiles
    # still reuse the same exact-host cache as intended.
    SAME_HOST_SERVICE_DISCOVERY_CACHE.clear()
    with SAME_HOST_SERVICE_DISCOVERY_TIME_LOCK:
        SAME_HOST_SERVICE_DISCOVERY_TIME_SPENT_SECONDS = 0.0
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
TOOL_SCOPES = {'ffuf': 'base', 'zap': 'base', 'nuclei': 'base', 'session': 'base', 'nikto': 'base', 'arjun': 'url', 'sqlmap': 'parameterized', 'dalfox': 'parameterized', 'commix': 'parameterized', 'traversal': 'parameterized', 'idor': 'object-reference', 'authorization': 'authorization', 'browser': 'browser', 'workflow': 'workflow', 'jwt': 'jwt', 'interactsh': 'oast'}
TOOL_DESCRIPTIONS = {'ffuf': 'Hidden resource and endpoint discovery with credential-isolated path fuzzing.', 'zap': 'Session-aware crawling, passive analysis and prioritized active testing.', 'nuclei': 'Template-based exposure, misconfiguration, known-vulnerability and bounded DAST checks on discovered parameterized URLs.', 'session': 'Cookie flags, bounded session uniqueness and fixation indicators.', 'nikto': 'Web-server hardening and exposed-resource checks.', 'arjun': 'Hidden GET/POST parameter discovery.', 'sqlmap': 'SQL-injection confirmation on discovered request contracts.', 'dalfox': 'Reflected and stored XSS testing.', 'commix': 'Operating-system command-injection testing.', 'traversal': 'Path-traversal and local-file-inclusion verification.', 'idor': 'Single-reference object differential checks for numeric, UUID, hexadecimal and digit-bearing opaque identifiers.', 'authorization': 'Read-only anonymous and multi-account cross-identity authorization differentials on discovered high-value GET requests.', 'browser': 'Chromium verification of DOM, reflected and stored XSS using harmless markers.', 'workflow': 'Bounded CSRF, upload, authentication-throttling and CAPTCHA workflow checks.', 'jwt': 'JWT structure and claim analysis.', 'interactsh': 'Out-of-band callback confirmation.'}

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
            status = safe_int_metadata(response.get('status'), 0)
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

    name = str(tool or '').lower()
    base = specialist_base_limit(name)
    adaptive_maximum = adaptive_tool_max_limit(name) or base
    reserve_maximum = int(ROUTING_TRAVERSAL_RESERVE.get(CURRENT_SCAN_MODE, adaptive_maximum)) if name == 'traversal' else adaptive_maximum
    effective_maximum = max(adaptive_maximum, reserve_maximum)
    adaptive_used = sum(1 for case in cases if isinstance(case, dict) and case.get('adaptive_budget'))
    reserve_used = sum(1 for case in cases if isinstance(case, dict) and case.get('coverage_reserve'))
    return {
        'base': base,
        'adaptive_max': adaptive_maximum,
        'coverage_reserve_max': reserve_maximum if name == 'traversal' else 0,
        'effective_max': effective_maximum,
        'selected': len(cases),
        'adaptive_used': adaptive_used,
        'coverage_reserve_used': reserve_used,
    }

# Per-tool limits define how many actions each scanner may receive in the active profile.
def tool_action_limit(tool: str, include_adaptive: bool=False) -> int:

    name = str(tool or '').lower()
    if name == 'arjun':
        return adaptive_tool_max_limit(name) if include_adaptive else ARJUN_ENDPOINT_LIMIT
    if name == 'interactsh':
        return 1 if CURRENT_SCAN_MODE == 'test' else 4 if CURRENT_SCAN_MODE == 'deep' else 3 if CURRENT_SCAN_MODE == 'balanced' else 1
    if name == 'jwt':
        return jwt_token_limit()
    if name in {'zap', 'nuclei', 'nikto'}:
        # One primary-origin run plus the maximum bounded sibling page for this round.
        return 2 if CURRENT_SCAN_MODE == 'test' else 17 if CURRENT_SCAN_MODE == 'deep' else 9 if CURRENT_SCAN_MODE == 'balanced' else 4
    if name in PARAMETER_TOOL_CASE_LIMITS:
        limit = adaptive_tool_max_limit(name) if include_adaptive else PARAMETER_TOOL_CASE_LIMITS[name]
        if name == 'traversal' and include_adaptive:
            limit = max(limit, int(ROUTING_TRAVERSAL_RESERVE.get(CURRENT_SCAN_MODE, limit)))
        return limit
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
_VERIFIED_MCP_FINGERPRINTS: dict[str, str] = {}
_HTTP_SERVER_LOGS: dict[str, Path] = {}
_MCP_PROCESS_LEASE_REGISTERED = False
MCP_LIFECYCLE_LOCK_TIMEOUT = max(5.0, safe_float_value(os.getenv('SECOPS_MCP_LIFECYCLE_LOCK_TIMEOUT', '30'), 30.0))

def _mcp_lifecycle_directory() -> Path:
    directory = ROOT / '.secops_tmp' / 'mcp-http'
    directory.mkdir(parents=True, exist_ok=True)
    return directory

def _mcp_lease_directory() -> Path:
    directory = _mcp_lifecycle_directory() / 'leases'
    directory.mkdir(parents=True, exist_ok=True)
    return directory

def _mcp_lease_path(pid: int | None=None) -> Path:
    return _mcp_lease_directory() / f'{int(pid or os.getpid())}.json'

def _mcp_server_state_path() -> Path:
    return _mcp_lifecycle_directory() / 'server.json'

@contextlib.contextmanager
def _mcp_lifecycle_guard(timeout: float=MCP_LIFECYCLE_LOCK_TIMEOUT):
    """Cross-process guard for MCP singleton startup, leases and shutdown.

    POSIX uses flock; Windows uses msvcrt byte locking. The guard is deliberately tiny and local
    to the project runtime directory, so unrelated checkouts do not block one another.
    """
    path = _mcp_lifecycle_directory() / 'lifecycle.lock'
    handle = open(path, 'a+b')
    deadline = time.monotonic() + max(1.0, float(timeout))
    locked = False
    try:
        if os.name == 'nt':
            import msvcrt
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b'\0')
                handle.flush()
            while not locked:
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    locked = True
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Timed out waiting for the shared MCP lifecycle lock.')
                    time.sleep(0.05)
        else:
            import fcntl
            while not locked:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Timed out waiting for the shared MCP lifecycle lock.')
                    time.sleep(0.05)
        yield
    finally:
        if locked:
            try:
                if os.name == 'nt':
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        handle.close()

def _pid_alive(pid: int) -> bool:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == 'nt':
        try:
            import ctypes
            process_query = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(process_query, False, pid)
            if not handle:
                return False
            try:
                code = ctypes.c_ulong()
                if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return False
                return int(code.value) == 259  # STILL_ACTIVE
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            return True  # fail safe: never kill an uncertain Windows PID
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True

def _prune_mcp_leases_locked() -> list[int]:
    live: list[int] = []
    for path in _mcp_lease_directory().glob('*.json'):
        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
            pid = int(payload.get('pid') or path.stem)
        except Exception:
            path.unlink(missing_ok=True)
            continue
        if _pid_alive(pid):
            live.append(pid)
        else:
            path.unlink(missing_ok=True)
    return sorted(set(live))

def _register_mcp_process_lease_locked() -> None:
    global _MCP_PROCESS_LEASE_REGISTERED
    if _MCP_PROCESS_LEASE_REGISTERED:
        return
    atomic_write_text(
        _mcp_lease_path(),
        json.dumps({
            'pid': os.getpid(),
            'root': str(ROOT),
            'source_fingerprint': secops_source_fingerprint(),
            'registered_at': datetime.now(timezone.utc).isoformat(),
        }, ensure_ascii=False, sort_keys=True),
    )
    _MCP_PROCESS_LEASE_REGISTERED = True

def _write_mcp_server_state_locked(process: subprocess.Popen) -> None:
    atomic_write_text(
        _mcp_server_state_path(),
        json.dumps({
            'pid': int(process.pid),
            'root': str(ROOT),
            'port': int(mcp_http_port(MCP_UNIFIED_SERVICE)),
            'source_fingerprint': secops_source_fingerprint(),
            'started_at': datetime.now(timezone.utc).isoformat(),
        }, ensure_ascii=False, sort_keys=True),
    )

def _posix_pid_is_secops_server(pid: int) -> bool:
    if os.name == 'nt':
        return False
    try:
        command = Path(f'/proc/{int(pid)}/cmdline').read_bytes().replace(b'\0', b' ').decode('utf-8', errors='replace')
    except OSError:
        return False
    return 'secopsServer.py' in command and str(ROOT) in command

def _terminate_recorded_mcp_server_locked() -> None:
    state_path = _mcp_server_state_path()
    try:
        payload = json.loads(state_path.read_text(encoding='utf-8'))
        pid = int(payload.get('pid') or 0)
        root = str(payload.get('root') or '')
        port = int(payload.get('port') or 0)
    except Exception:
        state_path.unlink(missing_ok=True)
        return
    if root != str(ROOT) or port != int(mcp_http_port(MCP_UNIFIED_SERVICE)) or not _pid_alive(pid):
        state_path.unlink(missing_ok=True)
        return
    owned = _HTTP_SERVER_PROCESSES.get(MCP_UNIFIED_SERVICE)
    if owned is not None and int(getattr(owned, 'pid', 0) or 0) == pid:
        _stop_owned_http_server()
        state_path.unlink(missing_ok=True)
        return
    # On the Linux execution VM, verify the exact command line before terminating a server started
    # by a different assessment process. On Windows an unowned singleton is intentionally left alive
    # rather than risking termination of an uncertain PID; source fingerprinting still prevents stale use.
    if _posix_pid_is_secops_server(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            return
        state_path.unlink(missing_ok=True)

def _release_mcp_process_lease() -> None:
    global _MCP_PROCESS_LEASE_REGISTERED
    if not _MCP_PROCESS_LEASE_REGISTERED:
        return
    try:
        with _mcp_lifecycle_guard():
            _mcp_lease_path().unlink(missing_ok=True)
            _MCP_PROCESS_LEASE_REGISTERED = False
            live = _prune_mcp_leases_locked()
            if not live:
                _terminate_recorded_mcp_server_locked()
    except Exception:
        # Process shutdown must never turn a successful assessment into an atexit traceback.
        pass

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
    _VERIFIED_MCP_FINGERPRINTS.pop(mcp_http_url(MCP_UNIFIED_SERVICE), None)
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

# Explicit administrative shutdown remains available to local callers. Normal process exit instead
# releases a shared lease: the MCP singleton is terminated only when the last assessment using this
# checkout exits, so one assessment cannot tear down another assessment's in-flight MCP request.
def shutdown_mcp_http_servers() -> None:
    try:
        with _mcp_lifecycle_guard():
            _stop_owned_http_server()
            _mcp_server_state_path().unlink(missing_ok=True)
    except Exception:
        _stop_owned_http_server()

atexit.register(_release_mcp_process_lease)

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
    if CURRENT_SCAN_MODE == 'test':
        return float(TEST_REPORT_RENDER_TIMEOUT_SECONDS)
    mib = max(1, math.ceil(max(0, int(payload_bytes)) / float(1024 * 1024)))
    adaptive = MCP_REPORT_RENDER_TIMEOUT + (mib * MCP_REPORT_RENDER_SECONDS_PER_MIB)
    return min(MCP_REPORT_RENDER_TIMEOUT_MAX, max(MCP_REPORT_RENDER_TIMEOUT, adaptive))


def _report_transfer_timeout() -> float:
    return float(TEST_REPORT_TRANSFER_TIMEOUT_SECONDS if CURRENT_SCAN_MODE == 'test' else MCP_REPORT_TRANSFER_TIMEOUT)

# Waits for a long report tool call while emitting terminal heartbeats and the latest server stage.
async def _await_report_tool(client: Client, tool_name: str, arguments: dict[str, Any], *, timeout: float, label: str) -> Any:
    task = asyncio.create_task(client.call_tool(tool_name, arguments))
    started = time.monotonic()
    last_stage = ''
    try:
        while True:
            elapsed = time.monotonic() - started
            remaining = float(timeout) - elapsed
            if remaining <= 0:
                raise TimeoutError(f'{label} exceeded its {timeout:.0f}-second report budget.')
            done, _ = await asyncio.wait({task}, timeout=min(float(SCANNER_PROGRESS_INTERVAL), remaining))
            if task in done:
                return await task
            elapsed = time.monotonic() - started
            remaining = max(0.0, float(timeout) - elapsed)
            progress = _server_report_progress_log()
            stage = progress.splitlines()[-1] if progress else ''
            if stage:
                stage = compact_log_url(stage, 420)
            if stage and stage != last_stage:
                print(f'[REPORT WAIT] {label}: elapsed={elapsed:.0f}s; server={stage}', flush=True)
                last_stage = stage
            else:
                print(f'[REPORT WAIT] {label}: still running after {elapsed:.0f}s; remaining budget={remaining:.0f}s.', flush=True)
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

# Verify that a listening MCP endpoint was started from the same SecOps source tree as this
# orchestrator. This is intentionally an MCP-level check rather than a port/PID heuristic, so it
# works consistently on Linux, macOS and Windows and cannot mistake an unrelated process for SecOps.
async def _mcp_runtime_identity(url: str) -> tuple[bool, str]:
    expected = secops_source_fingerprint()
    try:
        async with Client(url) as client:
            tools = await asyncio.wait_for(client.list_tools(), timeout=MCP_CONNECT_TIMEOUT)
            names = {str(getattr(tool, 'name', '')) for tool in tools}
            if 'secops_runtime_identity' not in names:
                return (False, 'runtime identity tool is missing (server is stale or incompatible with this SecOps checkout)')
            response = await asyncio.wait_for(client.call_tool('secops_runtime_identity', {}), timeout=MCP_CONNECT_TIMEOUT)
        data, is_error, _ = _extract_response(response)
        if is_error or not isinstance(data, dict):
            return (False, f'runtime identity call returned an invalid payload: {data!r}')
        observed = str(data.get('source_fingerprint') or '')
        if observed != expected:
            return (False, f'source fingerprint mismatch: expected={expected[:16]} observed={observed[:16] or "missing"}; server_root={data.get("root") or "unknown"}')
        return (True, f'fingerprint={expected[:16]}; server_root={data.get("root") or "unknown"}; pid={data.get("pid") or "unknown"}')
    except Exception as exc:
        return (False, f'{type(exc).__name__}: {exc}')

def _verify_mcp_runtime_identity(url: str, *, force: bool=False) -> tuple[bool, str]:
    expected = secops_source_fingerprint()
    if not force and _VERIFIED_MCP_FINGERPRINTS.get(url) == expected:
        return (True, f'fingerprint={expected[:16]} (cached)')
    try:
        matched, detail = asyncio.run(_mcp_runtime_identity(url))
    except RuntimeError as exc:
        # _ensure_http_server normally runs in a worker thread. Keep a clear failure mode if a
        # future caller invokes it directly from an event-loop thread.
        return (False, f'identity verification could not start its isolated event loop: {exc}')
    if matched:
        _VERIFIED_MCP_FINGERPRINTS[url] = expected
    return (matched, detail)

# Starts the one MCP process that imports and exposes the complete tool catalogue.
def _ensure_http_server(*, restart: bool=False) -> str:
    server = resolve_server_path(UNIFIED_MCP_SERVER)
    port = mcp_http_port(MCP_UNIFIED_SERVICE)
    url = mcp_http_url(MCP_UNIFIED_SERVICE)
    if not server.is_file():
        raise FileNotFoundError(f'Unified MCP server not found: {server}')
    # Serialize singleton discovery/startup across assessment processes. Register the caller lease
    # before checking the port so an owner exiting at the same instant cannot tear the shared server
    # down underneath a second assessment that is about to attach.
    with _mcp_lifecycle_guard():
        _prune_mcp_leases_locked()
        _register_mcp_process_lease_locked()
        if restart:
            _VERIFIED_MCP_FINGERPRINTS.pop(url, None)
            _stop_owned_http_server()
        if _port_open('127.0.0.1', port):
            matched, detail = _verify_mcp_runtime_identity(url, force=True)
            if matched:
                return url
            existing = _HTTP_SERVER_PROCESSES.get(MCP_UNIFIED_SERVICE)
            if existing is not None and existing.poll() is None:
                _stop_owned_http_server()
            else:
                raise RuntimeError(
                    f'Port {port} is already occupied by an incompatible or stale MCP service. {detail}. '
                    'Stop the old SecOps process (or the unrelated service using this port) and rerun the command; '
                    'the current assessment will not silently use code from another checkout/version.'
                )
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
            _write_mcp_server_state_locked(process)
        deadline = time.monotonic() + max(3.0, MCP_CONNECT_TIMEOUT)
        last_identity_detail = ''
        while time.monotonic() < deadline:
            if _port_open('127.0.0.1', port):
                matched, last_identity_detail = _verify_mcp_runtime_identity(url, force=True)
                if matched:
                    return url
            if process.poll() is not None:
                detail = _server_startup_log()
                raise RuntimeError('Unified SecOps HTTP MCP server exited during startup' + (f': {detail}' if detail else '.'))
            time.sleep(0.15)
        detail = _server_startup_log()
        raise TimeoutError(f'Timed out waiting for unified MCP HTTP service at {url}' + (f'. Identity: {last_identity_detail}' if last_identity_detail else '') + (f'. Server log: {detail}' if detail else ''))

# Transport diagnosis recognizes failures raised by the MCP HTTP layer.
def _http_transport_failure(exc: BaseException) -> bool:
    text = f'{type(exc).__name__}: {exc}'.lower()
    return any((token in text for token in ('connection refused', 'connecterror', 'connectionerror', 'server disconnected', 'connection closed', 'closedresourceerror', 'brokenresourceerror', 'all connection attempts failed')))

# Extracts the structured tool payload from an MCP response.
def _extract_response(response: Any) -> tuple[Any, bool, str]:
    raw_is_error = getattr(response, 'is_error', None)
    if raw_is_error is None:
        raw_is_error = getattr(response, 'isError', False)
    is_error = safe_bool_metadata(raw_is_error, False)
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
    return bool(safe_bool_metadata(result.get('timed_out'), False) or diagnosis in TIME_LIMIT_DIAGNOSES or 'timeout' in diagnosis or ('timed out' in text) or ('time limit' in text) or ('time budget' in text))

# Keeps useful partial results while marking a run that reached its limit.
def _normalize_time_limit(result: dict[str, Any], tool: str, target: str) -> dict[str, Any]:

    # Reporting is an artifact-generation stage, not a scanner. Preserve its concrete
    # renderer/serialization error instead of rewriting it as a scan coverage timeout.
    if str(tool or '').lower() == 'report':
        return result
    if safe_bool_metadata(result.get('hard_failure'), False) or not _is_time_limited(result):
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
    contract_warnings: list[str] = []
    raw_vulnerabilities = result.get('vulnerabilities', [])
    if not isinstance(raw_vulnerabilities, list):
        contract_warnings.append(f'vulnerabilities had invalid type {type(raw_vulnerabilities).__name__}; replaced with an empty list')
        raw_vulnerabilities = []
    elif any(not isinstance(item, dict) for item in raw_vulnerabilities):
        invalid_count = sum(1 for item in raw_vulnerabilities if not isinstance(item, dict))
        contract_warnings.append(f'vulnerabilities contained {invalid_count} non-object item(s); invalid items were ignored')
        raw_vulnerabilities = [item for item in raw_vulnerabilities if isinstance(item, dict)]
    result['vulnerabilities'] = raw_vulnerabilities
    for boolean_field in ('timed_out', 'time_limit_reached', 'hard_failure'):
        if boolean_field in result:
            original = result.get(boolean_field)
            normalized = safe_bool_metadata(original, False)
            if not isinstance(original, bool):
                contract_warnings.append(f'{boolean_field} normalized from {original!r} to {normalized!r}')
            result[boolean_field] = normalized
    status = 'error' if is_error else str(result.get('status', 'success')).strip().lower()
    if status not in {'success', 'error', 'skipped', 'partial'}:
        contract_warnings.append(f'unknown status {status!r}; normalized to error')
        status = 'error'
    if contract_warnings and status == 'success':
        status = 'partial'
        result.setdefault('diagnosis', 'tool_result_contract_normalized')
    result['status'] = status
    existing_meta = result.get('_meta') if isinstance(result.get('_meta'), dict) else {}
    result['_meta'] = {**existing_meta, 'server': spec.server, 'resolved_server': str(resolve_server_path(spec.server, spec.tool)), 'mcp_server': str(resolve_server_path(UNIFIED_MCP_SERVER)), 'duration_seconds': round(elapsed, 3), 'response_shape': shape}
    if contract_warnings:
        result['_meta']['contract_warnings'] = contract_warnings
    if result['status'] == 'error':
        result.setdefault('diagnosis', diagnose_error(str(result.get('output', ''))))
    return _normalize_time_limit(result, spec.name, target)

# Loads the latest Nuclei sidecar checkpoint written by the scanner process. This is used only
# when the outer MCP transport times out before the tool can return its normal structured result.
def _recover_nuclei_checkpoint(output_path: Path | None, target: str) -> dict[str, Any] | None:
    if output_path is None:
        return None
    checkpoint = output_path.with_name(output_path.name + '.checkpoint.json')
    if not checkpoint.is_file():
        return None
    try:
        payload = json.loads(checkpoint.read_text(encoding='utf-8', errors='replace'))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    recovered = dict(payload)
    vulnerabilities = recovered.get('vulnerabilities')
    if not isinstance(vulnerabilities, list):
        recovered['vulnerabilities'] = []
    recovered.update({
        'tool': 'nuclei',
        'target': target,
        'status': 'partial',
        'diagnosis': 'time_limit_reached',
        'timed_out': True,
        'time_limit_reached': True,
        'checkpoint_recovered': True,
    })
    phase = str(recovered.get('active_phase') or recovered.get('checkpoint_stage') or 'unknown')
    recovered['output'] = (
        'Nuclei reached the outer MCP time budget. The latest incremental checkpoint was recovered '
        f'instead of discarding completed phase metadata/findings; last checkpoint stage={phase}; '
        f"preserved findings={len(recovered.get('vulnerabilities') or [])}."
    )
    return recovered


def mcp_operation_timeout_seconds(spec_name: str, timeout_seconds: float, scanner_timeout_hint: float=0.0) -> float:
    """Return the outer MCP watchdog for one tool invocation.

    The watchdog is intentionally longer than the scanner's own deadline. A TEST scanner may use
    its complete 10-second action budget and still needs time for MCP connection, process cleanup,
    JSON serialization and the structured partial result to travel back to the orchestrator.
    """
    requested = max(0.0, float(timeout_seconds))
    scanner = max(0.0, float(scanner_timeout_hint))
    normalized_name = str(spec_name or '').lower()
    # call_mcp()/call_mcp_with_progress() default to the generous global 1200s timeout. Without
    # this TEST-specific clamp, a 10s scanner could still leave the smoke test waiting ~20 minutes
    # if the MCP transport or child process stopped returning data. Keep enough time for connection
    # and structured partial-result delivery, while preventing the generic default from leaking in.
    if CURRENT_SCAN_MODE == 'test' and normalized_name != 'report':
        requested = min(requested, TEST_MCP_AUX_REQUEST_TIMEOUT_SECONDS)
    operation_timeout = max(
        requested + MCP_CONNECT_TIMEOUT,
        scanner + MCP_CONNECT_TIMEOUT + MCP_SCANNER_RETURN_GRACE_SECONDS if scanner else 0.0,
    )
    if normalized_name == 'zap' and scanner:
        operation_timeout = max(
            operation_timeout,
            scanner * (1.0 + MCP_ZAP_SHARED_WAIT_MULTIPLIER) + MCP_CONNECT_TIMEOUT + MCP_ZAP_RETURN_GRACE_SECONDS,
        )
    if normalized_name == 'report':
        operation_timeout = _report_transfer_timeout() + _report_render_timeout(0) + (2 * MCP_CONNECT_TIMEOUT)
    return float(operation_timeout)


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
    nuclei_output_path: Path | None = None
    if spec.name == 'nuclei' and str(effective_arguments.get('output_file') or '').strip():
        try:
            nuclei_output_path = Path(str(effective_arguments.get('output_file'))).expanduser().resolve()
        except OSError:
            nuclei_output_path = Path(str(effective_arguments.get('output_file'))).expanduser()

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
        transfer_timeout = _report_transfer_timeout()
        render_timeout = _report_render_timeout(len(encoded))
        print(
            f'[REPORT HTTP] payload={len(encoded)} bytes; compressed={len(compressed)} bytes; chunks={len(chunks)}; chunk_size<={chunk_bytes} bytes; transfer budget={transfer_timeout:.0f}s; render budget={render_timeout:.0f}s.',
            flush=True,
        )
        try:
            for index, chunk in enumerate(chunks):
                remaining = transfer_timeout - (time.monotonic() - transfer_started)
                if remaining <= 0:
                    raise TimeoutError(f'Report HTTP chunk transfer exceeded its {transfer_timeout:.0f}-second budget after {index}/{len(chunks)} chunks.')
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
                    f'[REPORT HTTP] chunk {index + 1}/{len(chunks)} accepted; compressed bytes received={safe_int_metadata(data.get("received_compressed_bytes"), 0)}.',
                    flush=True,
                )
            transfer_elapsed = time.monotonic() - transfer_started
            print(
                f'[REPORT HTTP] upload complete: {len(chunks)}/{len(chunks)} chunks accepted in {transfer_elapsed:.1f}s; requesting reconstruction and report rendering.',
                flush=True,
            )
            render_started = time.monotonic()
            final_response = await _await_report_tool(
                client, 'generate_report_from_chunks', {'upload_id': upload_id},
                timeout=render_timeout, label='chunk reconstruction and report rendering',
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
                    response = await _await_report_tool(
                        client, tool_name, effective_arguments,
                        timeout=render_timeout, label='inline report rendering',
                    )
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
        try:
            scanner_timeout_hint = float(effective_arguments.get('timeout') or 0)
        except (TypeError, ValueError):
            scanner_timeout_hint = 0.0
        # The transport watchdog must never be shorter than the bounded scanner budget that was
        # deliberately selected for this invocation. Otherwise long DEEP/BALANCED scans can be
        # aborted by MCP even though the scanner itself still has valid time remaining.
        operation_timeout = mcp_operation_timeout_seconds(spec.name, timeout_seconds, scanner_timeout_hint)
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
            elif spec.name == 'nuclei':
                recovered = _recover_nuclei_checkpoint(nuclei_output_path, target)
                if recovered is not None:
                    result = recovered
                    result.setdefault('_meta', {}).update({
                        'server': str(server),
                        'duration_seconds': round(time.monotonic() - started, 3),
                        'mcp_transport': 'streamable_http',
                        'mcp_url': mcp_http_url(MCP_UNIFIED_SERVICE),
                        'checkpoint_recovered_after_outer_timeout': True,
                    })
                else:
                    result = _result(spec.name, target, 'partial', 'Nuclei reached the orchestrator/MCP HTTP time budget before a recoverable checkpoint was available. Coverage is incomplete; this is not classified as a scanner error.', 'time_limit_reached', timed_out=True, time_limit_reached=True, traceback=traceback.format_exc(), _meta={'server': str(server), 'duration_seconds': round(time.monotonic() - started, 3), 'mcp_transport': 'streamable_http', 'mcp_url': mcp_http_url(MCP_UNIFIED_SERVICE)})
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
            temporary_output.with_name(temporary_output.name + '.checkpoint.json').unlink(missing_ok=True)
            temporary_output.with_name(temporary_output.name + '.checkpoint.json.tmp').unlink(missing_ok=True)
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
        identity_ok, identity_detail = await _mcp_runtime_identity(url)
        identity_check = {
            'level': 'ok' if identity_ok else 'error', 'component': 'mcp',
            'cause': 'mcp_runtime_identity_ok' if identity_ok else 'mcp_runtime_identity_mismatch',
            'detail': identity_detail,
        }
        return [identity_check, *[_tool_live_check(spec, url, names) for spec in ALL_TOOLS]]
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
        values = {str(name).lower(): value for name, value in attrs if name}
        tag = tag.lower()
        if tag in {'a', 'area'} and values.get('href'):
            self.links.append(str(values['href']))
        elif tag in {'iframe', 'frame'} and values.get('src'):
            self.links.append(str(values['src']))
        elif tag == 'script' and values.get('src'):
            self.scripts.append(str(values['src']))
        elif tag == 'form':
            self.current = {'action': values.get('action', ''), 'method': str(values.get('method', 'get')).lower(), 'enctype': str(values.get('enctype', 'application/x-www-form-urlencoded')).lower(), 'fields': []}
        elif tag in {'input', 'textarea', 'select', 'button'} and self.current and values.get('name'):
            field_type = str(values.get('type', tag)).lower()
            self.current['fields'].append({'name': str(values['name']), 'value': str(values.get('value', '')), 'type': field_type, 'tag': tag})
        for attr in ('data-href', 'data-url', 'data-link', 'data-src', 'formaction'):
            value = str(values.get(attr) or '').strip()
            if value and not value.startswith('#'):
                self.links.append(value)

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

# Route fingerprints ignore ordinary changing values while preserving values that select distinct internal resources.
SEMANTIC_ROUTING_PARAMETERS = {
    'redirect', 'redirect_uri', 'linkurl', 'page', 'view', 'resource', 'file', 'filename',
    'path', 'template', 'module', 'route', 'next', 'return', 'dest', 'destination',
}
SEMANTIC_ROUTING_VALUE_RE = re.compile(r'\.(?:php\d?|phtml|jsp|jspx|asp|aspx|cgi|pl|do|action|html?)(?:[/?#]|$)', re.I)

# Query strings found in HTML/JavaScript occasionally contain an unescaped ampersand inside a
# human-readable value (for example pageTitle="A & B"). urllib.parse then interprets the text
# after that ampersand as a second parameter name. Keep the original URL as evidence, but do not
# promote whitespace-padded/control-character fragments to scanner parameters or route shapes.
# Normal application names such as columns[0][data], no_columns[], foo.bar and a:b remain valid.
def _valid_request_parameter_name(value: Any) -> bool:
    raw = str(value or '')
    return bool(raw) and raw == raw.strip() and not any(ord(char) < 32 or ord(char) == 127 for char in raw)

def _filtered_query_pairs(query: str) -> list[tuple[str, str]]:
    return [(name, value) for name, value in parse_qsl(str(query or ''), keep_blank_values=True) if _valid_request_parameter_name(name)]

def _query_parameter_names(url: str) -> list[str]:
    return [name for name, _ in _filtered_query_pairs(urlparse(str(url or '')).query)]

def _clean_case_parameter_names(values: Any) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values if isinstance(values, (list, tuple, set)) else []:
        name = str(value or '')
        if not _valid_request_parameter_name(name):
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        output.append(name)
    return output

def _semantic_routing_value(raw: str) -> str:
    value = str(raw or '').strip()
    for _ in range(2):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    lowered = value.lower().strip()
    if not lowered or lowered.startswith(('javascript:', 'data:', 'mailto:', 'tel:')):
        return ''
    parsed = urlparse(value)
    absolute_http = parsed.scheme.lower() in {'http', 'https'} and bool(parsed.netloc)
    if not (absolute_http or lowered.startswith(('/', './', '../')) or SEMANTIC_ROUTING_VALUE_RE.search(lowered)):
        return ''
    path = parsed.path or value.split('?', 1)[0]
    query = parsed.query if parsed.query else (value.split('?', 1)[1] if '?' in value else '')
    names = sorted({name.lower() for name, _ in _filtered_query_pairs(query)})
    normalized_path = re.sub(r'/+', '/', path.strip()) or '/'
    suffix = '?' + '&'.join(names) if names else ''
    if absolute_http:
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{normalized_path.lower()}{suffix}"
    return normalized_path.lower() + suffix

def _discovery_route_signature(url: str) -> tuple[str, str, tuple[str, ...]]:
    parsed = urlparse(str(url or ''))
    tokens: set[str] = set()
    for name, value in _filtered_query_pairs(parsed.query):
        lowered_name = name.lower()
        tokens.add(lowered_name)
        semantic = _semantic_routing_value(value)
        if semantic and (lowered_name in SEMANTIC_ROUTING_PARAMETERS or SEMANTIC_ROUTING_VALUE_RE.search(str(value or ''))):
            tokens.add(f'@{lowered_name}:{semantic}')
    return (normalized_origin(url), parsed.path.rstrip('/') or '/', tuple(sorted(tokens)))

# Request-level injection scanners normally care about method/path/parameter shape, not ordinary
# parameter values. Semantic routing values remain distinct only for traversal/LFI, where the value
# can literally choose a different server-side file/module and therefore represents distinct risk.
def _structural_route_signature(url: str) -> tuple[str, str, tuple[str, ...]]:
    parsed = urlparse(str(url or ''))
    names = tuple(sorted({name.lower() for name, _ in _filtered_query_pairs(parsed.query)}))
    return (normalized_origin(url), parsed.path.rstrip('/') or '/', names)

# Canonicalizes only query *encoding*, not semantic values. This collapses equivalent specialist
# actions such as `pageTitle=External+Services` and `pageTitle=External%20Services` while preserving
# different values, duplicate parameters, paths, methods and origins as distinct attack surfaces.
# It is deliberately narrower than the anti-saturation route signature because scanners may need
# multiple value variants when those values are genuinely different.
def _semantic_request_url_key(url: str) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    parsed = urlparse(str(url or ''))
    pairs = tuple(sorted((str(name), str(value)) for name, value in parse_qsl(parsed.query, keep_blank_values=True)))
    return (normalized_origin(url), parsed.path or '/', pairs)

# Public stable representation used by orchestrator action IDs. It canonicalizes only equivalent
# URL encodings (+ vs %20 etc.) while preserving actual parameter names/values and duplicate pairs.
def semantic_request_identity_url(url: str) -> str:
    origin, path, pairs = _semantic_request_url_key(url)
    query = urlencode(list(pairs), doseq=True)
    return f'{origin}{path}' + (f'?{query}' if query else '')

def _specialist_route_signature(tool: str, url: str) -> tuple[str, str, tuple[str, ...]]:
    return _discovery_route_signature(url) if str(tool or '').lower() == 'traversal' else _structural_route_signature(url)

# Request-level scanners need fewer value-only variants than discovery. Keeping this limit separate
# preserves broad discovery evidence without repeatedly executing the same scanner against ephemeral
# values of an otherwise identical request shape.
def _specialist_variant_cap() -> int:
    return max(1, int(SPECIALIST_ROUTE_VARIANT_LIMITS.get(CURRENT_SCAN_MODE, 3)))

# Extracts safe internal navigation destinations carried inside routing parameters.
def _nested_navigation_targets(url: str) -> list[str]:
    parsed = urlparse(str(url or ''))
    result: list[str] = []
    for name, raw in parse_qsl(parsed.query, keep_blank_values=True):
        semantic = _semantic_routing_value(raw)
        if not semantic or name.lower() not in SEMANTIC_ROUTING_PARAMETERS:
            continue
        value = str(raw or '').strip()
        for _ in range(2):
            decoded = unquote(value)
            if decoded == value:
                break
            value = decoded
        try:
            candidate = _clean_url(absolute_url(url, value))
        except Exception:
            continue
        if candidate not in result:
            result.append(candidate)
    return result

# Generic URL scoring prioritizes interactive surfaces while de-prioritizing repetitive presentation routes.
def _discovery_url_score(url: str) -> int:
    parsed = urlparse(str(url or ''))
    path = parsed.path.lower()
    score = 30 + _risk_terms(path + ' ' + ' '.join(name for name, _ in _filtered_query_pairs(parsed.query)))
    if parsed.query:
        score += 14
    if any(token in path for token in ('/api/', '/graphql', '/admin', '/manage', '/account', '/profile', '/search', '/query', '/upload', '/download', '/callback', '/webhook', '/config', '/settings')):
        score += 28
    if any(token in path for token in ('calendar', 'archive', 'page/', 'pagination', 'news/', 'blog/', 'static/', 'assets/')):
        score -= 12
    if len(parsed.query) > 700:
        score -= 18
    return score

EPHEMERAL_IDENTITY_QUERY_KEYS = {
    'state', 'nonce', 'session_code', 'tab_id', 'execution', 'code_challenge',
    'auth_session_id', 'kc_action', 'iss',
}
IDENTITY_CALLBACK_QUERY_KEYS = {'state', 'session_state', 'iss', 'code', 'auth_session_id', 'session_code', 'tab_id', 'execution'}


def _ephemeral_identity_flow_url(url: str) -> bool:
    """Recognize one-shot OAuth/OIDC protocol instances without naming a provider or application."""
    try:
        parsed = urlparse(str(url or ''))
    except ValueError:
        return False
    names = {str(name).lower() for name, _ in _filtered_query_pairs(parsed.query)}
    protocol_names = {'client_id', 'redirect_uri', 'response_type', 'scope', 'code_challenge', 'code_challenge_method'}
    transient = names & EPHEMERAL_IDENTITY_QUERY_KEYS
    # Require both protocol context and a transient value. A stable application login/SSO URL
    # such as /login or ?redirect=/app remains a normal in-scope attack surface.
    return bool(transient and (names & protocol_names or {'state', 'nonce'} <= names or 'session_code' in names))


def _volatile_identity_callback_url(url: str) -> bool:
    """Recognize one-shot OAuth/OIDC callback instances from protocol parameters only."""
    try:
        names = {str(name).lower() for name, _ in _filtered_query_pairs(urlparse(str(url or '')).query)}
    except ValueError:
        return False
    hits = names & IDENTITY_CALLBACK_QUERY_KEYS
    return len(hits) >= 2 and bool(hits & {'state', 'code', 'session_state'})

def _discovery_variant_limit(url: str, default_limit: int) -> int:
    # One representative OAuth/OIDC state/nonce/session-code variant is enough for discovery and
    # workflow classification; retaining many volatile values starves unrelated application routes.
    return 1 if (_ephemeral_identity_flow_url(url) or _volatile_identity_callback_url(url)) else max(1, int(default_limit))


# Queue ranking protects the primary target surface without excluding explicitly authorized sibling origins.
def _discovery_queue_score(target: str, url: str) -> int:
    score = _discovery_url_score(url)
    if same_origin(target, url):
        score += 24
    if _ephemeral_identity_flow_url(url):
        score -= 90
    elif _volatile_identity_callback_url(url):
        score -= 70
    return score


def _application_family_key(url: str) -> tuple[str, str]:
    """Return a generic origin + top-level application family for discovery diversification.

    Large portals often host several applications behind one origin. Ranking only by raw URL score can
    let the first large menu or SPA monopolize a bounded crawl. The first path segment is deliberately
    generic and does not encode any target-specific application name.
    """
    try:
        parsed = urlparse(str(url or ''))
    except ValueError:
        return ('', '/')
    segments = [segment for segment in str(parsed.path or '/').split('/') if segment]
    return (normalized_origin(url), '/' + (segments[0].lower() if segments else ''))


def _discovery_diversity_score(target: str, url: str, family_visits: Counter[tuple[str, str]]) -> int:
    """Favor underrepresented application families without imposing a hard per-family cutoff."""
    visits = int(family_visits.get(_application_family_key(url), 0) or 0)
    # New families receive a modest boost; the bonus decays smoothly over the first ten useful visits.
    # Security-relevant URL scoring remains dominant, so this broadens discovery rather than replacing it.
    diversity_bonus = max(0, 30 - min(30, visits * 3))
    return _discovery_queue_score(target, url) + diversity_bonus

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

STATE_CHANGING_QUERY_KEYS = {'create_db', 'reset', 'delete', 'remove', 'logout', 'signout', 'logoff', 'disconnect', 'destroy', 'install', 'setup', 'password_new', 'password_conf', 'new_password', 'confirm_password'}

# GET discovery safety uses the same central request-contract classifier as scanner helpers.
# Keeping a second crawler-specific destructive-word policy previously caused coverage drift
# (for example navigation parameters and reset-form pages could be suppressed even though the
# concrete GET itself was read-only). Redirect destinations are evaluated independently before
# they are followed, so allowing a navigation parameter does not authorize a later logout/delete hop.
def _destructive_crawl_url(url: str) -> bool:
    return bool(request_contract_state_change_reason({
        'url': str(url or ''), 'method': 'GET', 'data': '', 'parameters': [],
    }))


# Identifies request contracts that can mutate server or account state. When state changes are
# disabled, POST is fail-closed: it remains eligible only when the observed contract contains strong
# read-only evidence (search/query/list/status/preview style API or a GraphQL query operation).
def _request_case_state_change_reason(case: dict[str, Any]) -> str:
    return request_contract_state_change_reason(case)

# Applies the absolute allow_state_changes policy to broad-scanner request contracts without
# discarding read-only POST query/API coverage.
def _request_cases_for_state_policy(cases: list[dict[str, Any]] | None, allow_state_changes: bool) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for case in cases or []:
        if not isinstance(case, dict):
            continue
        if (not allow_state_changes) and _request_case_state_change_reason(case):
            continue
        selected.append(case)
    return selected

# Public policy helpers are reused by both orchestrators so broad and request-level scanners enforce
# the same absolute state-change rule.
def request_case_state_change_reason(case: dict[str, Any]) -> str:
    return _request_case_state_change_reason(case)

def filter_request_cases_for_state_policy(cases: list[dict[str, Any]] | None, allow_state_changes: bool) -> list[dict[str, Any]]:
    return _request_cases_for_state_policy(cases, allow_state_changes)

# Returns true only for certificate/trust validation failures. Protocol negotiation errors are not
# retried with verification disabled, because a wrong-version/cipher failure does not mean that the
# service merely uses an internal or self-signed certificate.
def _tls_certificate_trust_failure(exc: BaseException, url: str) -> bool:
    if urlparse(str(url or '')).scheme.lower() != 'https':
        return False
    text = str(exc or '').lower()
    return any(token in text for token in (
        'certificate verify failed', 'self signed certificate', 'self-signed certificate',
        'unable to get local issuer certificate', 'unable to verify the first certificate',
        'certificate has expired', 'hostname mismatch', 'doesn\'t match', 'does not match',
    ))


def _request_with_tls_trust_retry(
    session: requests.Session, method: str, url: str, **kwargs: Any,
) -> tuple[requests.Response, bool, str]:
    """Execute one request and retry the same authorized HTTPS URL only after trust failure."""
    try:
        return session.request(method, url, **kwargs), False, ''
    except requests.exceptions.SSLError as exc:
        if not _tls_certificate_trust_failure(exc, url):
            raise
        retry_kwargs = dict(kwargs)
        retry_kwargs['verify'] = False
        _pace_http_request()
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', message='Unverified HTTPS request.*')
            response = session.request(method, url, **retry_kwargs)
        setattr(response, '_secops_tls_trust_retry', True)
        setattr(response, '_secops_tls_trust_error', str(exc))
        return response, True, str(exc)


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
        _pace_http_request()
        response, _, _ = _request_with_tls_trust_retry(
            session, 'GET', current, timeout=timeout, allow_redirects=False, headers=request_headers,
        )
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
        key = (str(case.get('method', 'GET')).upper(), _semantic_request_url_key(str(case.get('url', ''))), tuple(sorted(set(names))))
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

# Rechecks whether an authenticated profile is still valid without allowing the precheck itself to
# widen credential scope. This deliberately mirrors build_tool_arguments(): a sibling request that
# receives no scanner cookie also receives no cookie during preparation or session probing.
def refresh_authenticated_session_state(
    target: str, cookies: str, probe_url: str='', *, allow_state_changes: bool=False,
) -> dict[str, Any]:

    selected_probe = probe_url or target
    speculative_raw_cookie = _speculative_same_host_port_raw_cookie(target, cookies)
    effective_cookies = scope_cookie_header(target, cookies)
    runtime_reauth: dict[str, Any] | None = None
    if not effective_cookies and runtime_target_auth_available(cookies, target):
        runtime_reauth = ensure_runtime_authenticated_request(target, cookies, selected_probe)
        effective_cookies = scope_cookie_header(target, cookies) or str(runtime_reauth.get('cookie_header') or '')
    if not effective_cookies:
        return {
            'performed': bool(runtime_reauth and runtime_reauth.get('attempted')),
            'authenticated': False,
            'usable': True,
            'credential_applied': False,
            'runtime_reauthentication': runtime_reauth or {},
        }

    probe_cookies = scope_cookie_header(selected_probe, cookies) or effective_cookies
    if not probe_cookies:
        selected_probe = target
        probe_cookies = effective_cookies
    # Target preparation is configured against the assessment entry point. A concrete same-origin
    # request can still be the scanner/probe target, but preparation must retain the configured
    # base path rather than accidentally looking up a per-endpoint runtime profile.
    preparation_target = PRIMARY_SCOPE_TARGET if PRIMARY_SCOPE_TARGET and same_origin(target, PRIMARY_SCOPE_TARGET) else target
    preparation_cookies = scope_cookie_header(preparation_target, cookies) or effective_cookies
    preparation = apply_runtime_target_preparation(preparation_target, preparation_cookies, allow_state_changes=allow_state_changes)
    probe = scanner_session_probe(selected_probe, probe_cookies, timeout=10, attempts=3)
    probe_invalid = probe.get('conclusive') is True and probe.get('authenticated') is False
    prep_invalid = preparation.get('conclusive', True) is True and preparation.get('usable', True) is False
    usable = not (probe_invalid or prep_invalid)

    # A conclusive rejection on another explicitly allowed port means this raw header is not a
    # usable session for that service. Remember the result before browser/SSO repair so later tools
    # do not repeatedly send the same invalid cookie. This cache is keyed by a SHA-256 digest of the
    # cookie plus destination origin and therefore does not affect another authenticated identity.
    if (probe_invalid or prep_invalid) and speculative_raw_cookie:
        REJECTED_SPECULATIVE_RAW_COOKIE_KEYS.add(_raw_cookie_reuse_key(target, cookies))

    # A valid dashboard session may still be invalid for another application under the same host.
    # When the concrete probe redirects to login, establish that application's own session through
    # saved SSO state instead of treating exact-origin equality as proof that one PHP session is enough.
    if not usable and runtime_target_auth_available(cookies, target) and not (runtime_reauth and runtime_reauth.get('attempted')):
        runtime_reauth = ensure_runtime_authenticated_request(target, effective_cookies, selected_probe)
        repaired_cookie = str(runtime_reauth.get('cookie_header') or '') or scope_cookie_header(target, cookies)
        if runtime_reauth.get('usable') and repaired_cookie:
            effective_cookies = repaired_cookie
            selected_probe = str(runtime_reauth.get('probe_url') or target)
            probe_cookies = scope_cookie_header(selected_probe, cookies) or effective_cookies
            preparation_cookies = scope_cookie_header(preparation_target, cookies) or effective_cookies
            preparation = apply_runtime_target_preparation(preparation_target, preparation_cookies, allow_state_changes=allow_state_changes)
            probe = scanner_session_probe(selected_probe, probe_cookies, timeout=10, attempts=3)
            probe_invalid = probe.get('conclusive') is True and probe.get('authenticated') is False
            prep_invalid = preparation.get('conclusive', True) is True and preparation.get('usable', True) is False
            usable = not (probe_invalid or prep_invalid)

    conclusive = bool(probe_invalid or prep_invalid or probe.get('conclusive') is True)
    return {
        'performed': True,
        'authenticated': probe.get('authenticated'),
        'conclusive': conclusive,
        'preparation': preparation,
        'probe': probe,
        'usable': usable,
        'transient_error': bool(probe.get('transient_error') or preparation.get('transient_error')),
        'credential_applied': True,
        'runtime_reauthentication': runtime_reauth or {},
        'effective_cookie_names': cookie_names(effective_cookies),
    }

# Records simple client-side source and sink clues for browser checks.
def _client_side_source_sink_evidence(text: str) -> tuple[list[str], list[str]]:

    value = str(text or '')[:750000]
    source_hits = sorted(set(re.findall('(?:location\\.(?:hash|search|href)|document\\.(?:URL|documentURI|referrer|cookie)|window\\.name)', value, re.I)))
    sink_hits = sorted(set(re.findall('(?:innerHTML|outerHTML|insertAdjacentHTML|document\\.write(?:ln)?|eval\\s*\\(|setTimeout\\s*\\(\\s*[\'\\"]|setInterval\\s*\\(\\s*[\'\\"])', value, re.I)))
    return (source_hits[:12], sink_hits[:12])

# Normalizes URL-like string literals before they are resolved against a page/script URL.
# JavaScript found in the wild sometimes contains escaped separators such as ``http\\://`` or
# malformed fragments such as ``http\\:/``. A complete escaped HTTP(S) absolute URL is repaired;
# an incomplete scheme-only fragment is rejected instead of being treated as a relative path.
def _normalize_literal_url_token(raw: str) -> str:

    value = str(raw or '').strip().replace('\\/', '/')
    if not value:
        return ''
    if re.match(r'(?i)^https?\\:', value):
        escaped_scheme = re.match(r'(?i)^(https?)\\://([^/?#][^\\s]*)$', value)
        if not escaped_scheme:
            # A broken scheme marker such as ``http\\:/`` or ``http\\:/relative`` is parser
            # noise. Only the unambiguous two-slash absolute form is repaired.
            return ''
        value = f'{escaped_scheme.group(1).lower()}://{escaped_scheme.group(2)}'
    elif re.match(r'(?i)^https?:/*$', value):
        return ''
    return value

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
            raw_url = _normalize_literal_url_token(raw_url)
            if not raw_url or raw_url.startswith(('data:', 'javascript:', '#')) or '{' in raw_url or '}' in raw_url:
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

# Extracts literal navigation targets embedded in HTML, inline JavaScript, JSON menu data, and event handlers.
def _literal_navigation_hints(text: str, base_url: str, target: str, limit: int=320) -> list[dict[str, str]]:

    # html.unescape() accepts several legacy named entities without a terminating semicolon. On raw
    # JavaScript/JSON this corrupts perfectly valid query names such as "&param=" into "¶m=". Decode
    # only explicit semicolon-terminated entities while preserving ordinary ampersands in URLs.
    raw_value = str(text or '')[:1000000]
    value = re.sub(
        r'&(?:#\d+|#x[0-9a-fA-F]+|amp|quot|apos|lt|gt);',
        lambda match: html.unescape(match.group(0)),
        raw_value,
        flags=re.I,
    )
    keyed = re.compile(
        r'''(?ix)\b(?:href|url|uri|link|linkurl|redirect|redirect_uri|page|path|route|target|endpoint|src|action)\b\s*[:=]\s*["']([^"']{1,420})["']'''
    )
    calls = re.compile(
        r'''(?ix)(?:window\.open|location\.assign|location\.replace)\s*\(\s*["']([^"']{1,420})["']'''
    )
    assignments = re.compile(
        r'''(?ix)(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']{1,420})["']'''
    )
    quoted = re.compile(r'''["']([^"'<>\r\n]{2,420})["']''')

    def plausible(raw: str) -> bool:
        candidate = str(raw or '').strip()
        lowered = candidate.lower()
        if not candidate or lowered.startswith(('#', 'javascript:', 'data:', 'mailto:', 'tel:')):
            return False
        if any(token in candidate for token in ('${', '{{', '}}')):
            return False
        if re.search(r'\s', candidate) and not candidate.startswith(('http://', 'https://')):
            return False
        if candidate.startswith(('http://', 'https://', '/', './', '../')):
            return True
        if SEMANTIC_ROUTING_VALUE_RE.search(candidate):
            return True
        return candidate.endswith('/') and '/' in candidate

    raw_values: list[str] = []
    for pattern in (keyed, calls, assignments):
        raw_values.extend(match.group(1) for match in pattern.finditer(value))
    for match in quoted.finditer(value):
        raw = match.group(1)
        if plausible(raw):
            raw_values.append(raw)

    hints: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in raw_values:
        raw = _normalize_literal_url_token(raw)
        if not raw or not plausible(raw):
            continue
        try:
            candidate = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(base_url, raw)))
        except Exception:
            continue
        if not candidate or candidate in seen:
            continue
        if not url_in_authorized_scope(target, candidate) or not _crawlable_url(candidate) or _destructive_crawl_url(candidate):
            continue
        seen.add(candidate)
        hints.append({'method': 'GET', 'url': candidate})
        if len(hints) >= max(1, int(limit)):
            break
    return hints

# Converts one browser-observed request into the normalized request-contract shape.
def _browser_network_case(url: str, method: str, data: str, content_type: str, source_url: str, resource_type: str) -> dict[str, Any] | None:

    method = str(method or 'GET').upper()
    if method not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}:
        return None
    parsed = urlparse(url)
    parameters = [name for name, _ in _filtered_query_pairs(parsed.query)]
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

# Collect ordinary DOM navigation attributes without relying on Playwright's injected selector engine.
# Legacy/XHTML pages can make eval_on_selector_all() fail with `result is not iterable` even when
# their DOM is otherwise usable, so walk elements directly inside page context.
def _browser_dom_navigation_values(page: Any) -> list[Any]:
    values = page.evaluate(
        """() => {
            const attrs = ['href','src','action','formaction','data-href','data-url','data-link','data-src'];
            const out = [];
            const root = document.documentElement;
            if (!root) return out;
            const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
            let element = root;
            while (element) {
                for (const name of attrs) {
                    try {
                        const value = element.getAttribute && element.getAttribute(name);
                        if (value) out.push(value);
                    } catch (_) {}
                }
                element = walker.nextNode();
            }
            return out;
        }"""
    ) or []
    if isinstance(values, list):
        return values
    if isinstance(values, tuple):
        return list(values)
    return []


def _browser_request_state_reason(request: Any, allow_state_changes: bool=False) -> str:
    if allow_state_changes:
        return ''
    request_url = str(getattr(request, 'url', '') or '')
    request_method = str(getattr(request, 'method', 'GET') or 'GET').upper()
    try:
        headers = dict(getattr(request, 'headers', {}) or {})
    except Exception:
        headers = {}
    try:
        data = str(getattr(request, 'post_data', '') or '')
    except Exception:
        data = ''
    content_type = next((str(value) for key, value in headers.items() if str(key).lower() == 'content-type'), '')
    return request_contract_state_change_reason({
        'url': request_url, 'method': request_method, 'data': data,
        'parameters': [], 'headers': headers, 'content_type': content_type,
    })


# Uses Chromium as a bounded dynamic discovery queue so rendered navigation and XHR/fetch contracts become scanner inputs.
def _browser_network_discovery(target: str, cookies: str, html_urls: list[str], forced_urls: list[str] | None=None, priority_urls: list[str] | None=None, allow_state_changes: bool=False) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[dict[str, Any]], dict[str, Any]]:

    limits = DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, DISCOVERY_LIMITS['balanced'])
    forced_set = { _clean_url(value) for value in forced_urls or [] if value and url_in_authorized_scope(target, value) }
    priority_set = forced_set | { _clean_url(value) for value in priority_urls or [] if value and url_in_authorized_scope(target, value) }
    navigation_budget = max(int(limits['browser_pages']), len(forced_set))
    navigation_max_budget = max(navigation_budget, int(limits.get('browser_pages_max', navigation_budget)), len(forced_set))
    route_variant_limit = int(limits['route_variants'])
    per_origin_limit = max(int(limits.get('browser_per_origin_pages', limits['per_origin_pages'])), len(forced_set))
    browser_started = time.monotonic()
    browser_wall_clock_budget = max(
        BROWSER_DISCOVERY_MIN_SECONDS_BY_MODE.get(CURRENT_SCAN_MODE, BROWSER_DISCOVERY_MIN_SECONDS),
        min(
            float(TEST_DISCOVERY_TIME_BUDGET_SECONDS) if CURRENT_SCAN_MODE == 'test' else float('inf'),
            float(navigation_budget) * BROWSER_DISCOVERY_SECONDS_PER_BASE_PAGE,
        ),
    )
    browser_deadline = browser_started + browser_wall_clock_budget
    budget_info: dict[str, Any] = {
        'base_budget': navigation_budget, 'max_budget': navigation_max_budget,
        'wall_clock_budget_seconds': round(browser_wall_clock_budget, 3),
        'wall_clock_elapsed_seconds': 0.0, 'wall_clock_exhausted': False,
        'attempted': 0, 'adaptive_overflow_used': 0, 'remaining_candidates': 0,
        'adaptive_threshold': None, 'max_saturated': False,
        'menu_controls_clicked': 0, 'dom_navigation_candidates': 0,
        'navigation_retries': 0, 'dom_retries': 0,
        'dead_404_410': 0,
        'external_subresource_requests': 0,
        'external_navigation_requests_blocked': 0,
        'external_origins_observed': [],
    }
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return ([], [], [], [{'url': target, 'type': 'BrowserDiscoveryUnavailable', 'message': f'{type(exc).__name__}: {exc}'}], budget_info)
    ranked_pages = sorted(
        { _clean_url(value) for value in html_urls if value and url_in_authorized_scope(target, value) },
        key=lambda value: (0 if value in priority_set else 1, -_discovery_queue_score(target, value), len(urlparse(value).path), value),
    )
    target_url = _clean_url(target)
    if target_url in ranked_pages:
        ranked_pages.remove(target_url)
    queue: list[str] = []
    queued: set[str] = set()
    queued_signatures: Counter[tuple[str, str, tuple[str, ...]]] = Counter()
    visited_signatures: Counter[tuple[str, str, tuple[str, ...]]] = Counter()
    origin_visits: Counter[str] = Counter()
    family_visits: Counter[tuple[str, str]] = Counter()
    navigated: list[str] = []
    visited: set[str] = set()
    observed: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    current_source = {'url': target_url}
    request_rows: dict[int, dict[str, Any]] = {}
    request_cases_by_id: dict[int, dict[str, Any]] = {}
    external_browser_origins: set[str] = set()

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
        variant_limit = _discovery_variant_limit(candidate, route_variant_limit)
        if not force and queued_signatures[signature] >= variant_limit:
            return
        if origin_visits[origin] >= per_origin_limit:
            return
        queued.add(candidate)
        queued_signatures[signature] += 1
        queue.append(candidate)
        queue.sort(key=lambda value: (0 if value in priority_set else 1, -_discovery_diversity_score(target, value, family_visits), value))

    enqueue_dynamic(target_url, force=True)
    for value in sorted(forced_set):
        enqueue_dynamic(value, force=True)
    for value in sorted(priority_set - forced_set):
        enqueue_dynamic(value)
    for value in ranked_pages:
        enqueue_dynamic(value, force=value in forced_set)

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context_kwargs: dict[str, Any] = {
                'ignore_https_errors': True,
                'user_agent': 'SecOps-Browser-Discovery/1.0',
            }
            runtime_state = _runtime_target_auth_for_cookie(cookies) if cookies else {}
            runtime_storage = runtime_state.get('storage_state') if isinstance(runtime_state.get('storage_state'), dict) else None
            if runtime_storage and (runtime_storage.get('cookies') or runtime_storage.get('origins')):
                # Preserve real Domain/Path/Secure cookie metadata and browser storage for authenticated
                # discovery. This is materially more accurate than flattening an OIDC session into one
                # origin-wide Cookie header, especially for multi-application portals and SPAs.
                context_kwargs['storage_state'] = runtime_storage
            context = browser.new_context(**context_kwargs)
            parsed_target = urlparse(target)
            origin = urlunparse(parsed_target._replace(path='/', query='', fragment=''))
            if not runtime_storage:
                cookie_rows = [{'name': name, 'value': value, 'url': origin} for name, value in parse_cookie_header(cookies)]
                if cookie_rows:
                    context.add_cookies(cookie_rows)

            def route_guard(route: Any) -> None:
                request_url = str(route.request.url or '')
                request_method = str(route.request.method or 'GET').upper()
                in_scope = url_in_authorized_scope(target, request_url)
                if not in_scope:
                    observed_origin = normalized_origin(request_url)
                    if observed_origin:
                        external_browser_origins.add(observed_origin)
                # State-change authorization never widens scope. External GET/HEAD/OPTIONS
                # subresources may be needed to render an authorized page, but external navigation
                # and all external non-read requests are always blocked. Inside scope, the same
                # request-contract policy used by scanners decides whether a browser XHR/fetch/POST
                # is safe when allow_state_changes is false; read-only POSTs remain observable.
                if route.request.is_navigation_request() and not in_scope:
                    budget_info['external_navigation_requests_blocked'] = int(budget_info.get('external_navigation_requests_blocked', 0) or 0) + 1
                    route.abort()
                elif not in_scope and request_method not in {'GET', 'HEAD', 'OPTIONS'}:
                    budget_info['external_navigation_requests_blocked'] = int(budget_info.get('external_navigation_requests_blocked', 0) or 0) + 1
                    route.abort()
                elif in_scope and _browser_request_state_reason(route.request, allow_state_changes):
                    route.abort()
                else:
                    if not in_scope:
                        budget_info['external_subresource_requests'] = int(budget_info.get('external_subresource_requests', 0) or 0) + 1
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
                state_reason = _browser_request_state_reason(request, allow_state_changes)
                blocked_before_send = bool(state_reason)
                row = {'url': url, 'method': method, 'resource_type': resource_type, 'content_type': content_type, 'source_url': current_source['url'], 'has_body': bool(data), 'blocked_before_send': blocked_before_send, 'state_policy_reason': state_reason, 'response_observed': False, 'response_status': None, 'response_ok': None, 'response_content_type': '', 'request_failure': ''}
                observed.append(row)
                request_rows[id(request)] = row
                case = None if blocked_before_send else _browser_network_case(url, method, data, content_type, current_source['url'], resource_type)
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

            def transient_browser_error(exc: Exception) -> bool:
                text = f'{type(exc).__name__}: {exc}'.lower()
                return any(token in text for token in (
                    'net::err_aborted', 'timeout', 'execution context was destroyed',
                    'cannot find context with specified id', 'target page, context or browser has been closed',
                ))

            def remaining_browser_ms(cap_ms: int) -> int:
                remaining = max(0.0, browser_deadline - time.monotonic())
                return max(1, min(int(cap_ms), int(remaining * 1000)))

            def navigate_with_retry(value: str) -> Any:
                try:
                    # Pace top-level browser navigations with the same shared policy used by the
                    # HTTP crawler. The pacer and Playwright timeout both honor the global browser deadline.
                    if not _pace_http_request(browser_deadline):
                        raise TimeoutError('Chromium discovery wall-clock budget exhausted before navigation')
                    return page.goto(value, wait_until='domcontentloaded', timeout=remaining_browser_ms(12000))
                except Exception as first_exc:
                    if time.monotonic() >= browser_deadline or not transient_browser_error(first_exc):
                        raise
                    budget_info['navigation_retries'] = int(budget_info.get('navigation_retries', 0) or 0) + 1
                    try:
                        page.wait_for_timeout(min(250, remaining_browser_ms(250)))
                    except Exception:
                        pass
                    if not _pace_http_request(browser_deadline):
                        raise TimeoutError('Chromium discovery wall-clock budget exhausted before retry')
                    response = page.goto(value, wait_until='commit', timeout=remaining_browser_ms(16000))
                    try:
                        page.wait_for_load_state('domcontentloaded', timeout=remaining_browser_ms(4000))
                    except Exception:
                        pass
                    return response
            base_scores: list[int] = []
            adaptive_threshold: int | None = None
            while queue and len(visited) < navigation_max_budget and time.monotonic() < browser_deadline:
                queue.sort(key=lambda candidate: (0 if candidate in priority_set else 1, -_discovery_diversity_score(target, candidate, family_visits), candidate))
                value = queue[0]
                value_score = _discovery_diversity_score(target, value, family_visits)
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
                forced_value = value in forced_set
                variant_limit = _discovery_variant_limit(value, route_variant_limit)
                if (not forced_value and visited_signatures[signature] >= variant_limit) or origin_visits[origin_key] >= per_origin_limit:
                    continue
                visited.add(value)
                visited_signatures[signature] += 1
                origin_visits[origin_key] += 1
                family_visits[_application_family_key(value)] += 1
                if len(visited) <= navigation_budget and _discovery_route_signature(value) != _discovery_route_signature(target_url):
                    base_scores.append(value_score)
                current_source['url'] = value
                try:
                    response = navigate_with_retry(value)
                    page.wait_for_timeout(min(650, remaining_browser_ms(650)))
                    response_type = str((response.headers if response else {}).get('content-type') or '').lower()
                    response_status = int(response.status) if response is not None else 0
                    if response_status in {404, 410}:
                        budget_info['dead_404_410'] = int(budget_info.get('dead_404_410', 0) or 0) + 1
                        continue
                    if not response_type or 'html' in response_type:
                        navigated.append(value)

                    def collect_dom_navigation() -> None:
                        if time.monotonic() >= browser_deadline:
                            return
                        raw_values: list[Any] = []
                        for dom_attempt in range(2):
                            try:
                                raw_values = _browser_dom_navigation_values(page)
                                break
                            except Exception as dom_exc:
                                if dom_attempt or not transient_browser_error(dom_exc):
                                    raise
                                budget_info['dom_retries'] = int(budget_info.get('dom_retries', 0) or 0) + 1
                                try:
                                    page.wait_for_load_state('domcontentloaded', timeout=remaining_browser_ms(3000))
                                except Exception:
                                    pass
                                page.wait_for_timeout(min(180, remaining_browser_ms(180)))
                        for raw in raw_values:
                            if time.monotonic() >= browser_deadline:
                                break
                            text = str(raw or '').strip()
                            if not text or text.startswith('#'):
                                continue
                            try:
                                candidate = absolute_url(str(page.url or value), text)
                            except Exception:
                                continue
                            before = len(queued)
                            enqueue_dynamic(candidate)
                            if len(queued) > before:
                                budget_info['dom_navigation_candidates'] = int(budget_info.get('dom_navigation_candidates', 0) or 0) + 1
                        try:
                            rendered = page.content()
                        except Exception:
                            rendered = ''
                        for hint in _literal_navigation_hints(rendered, str(page.url or value), target):
                            before = len(queued)
                            enqueue_dynamic(str(hint.get('url') or ''))
                            if len(queued) > before:
                                budget_info['dom_navigation_candidates'] = int(budget_info.get('dom_navigation_candidates', 0) or 0) + 1

                    collect_dom_navigation()
                    menu_click_limit = max(0, int(limits.get('browser_menu_clicks_per_page', 0) or 0))
                    dom_pass_limit = max(1, int(limits.get('browser_dom_passes', 1) or 1))
                    if menu_click_limit:
                        selectors = ','.join((
                            '[aria-expanded="false"][aria-controls]',
                            '[data-toggle="collapse"]', '[data-bs-toggle="collapse"]',
                            '[data-toggle="dropdown"]', '[data-bs-toggle="dropdown"]',
                            'button.dropdown-toggle', 'a.dropdown-toggle[href="#"]',
                            '.menu-toggle', '.submenu-toggle',
                        ))
                        toggles = page.locator(selectors)
                        try:
                            toggle_count = min(toggles.count(), menu_click_limit)
                        except Exception:
                            toggle_count = 0
                        clicked = 0
                        for toggle_index in range(toggle_count):
                            if time.monotonic() >= browser_deadline:
                                break
                            toggle = toggles.nth(toggle_index)
                            try:
                                if not toggle.is_visible():
                                    continue
                                if toggle.evaluate("element => Boolean(element.closest('form'))"):
                                    continue
                                text = str(toggle.inner_text(timeout=remaining_browser_ms(500)) or '').strip().lower()
                                if any(token in text for token in ('delete', 'remove', 'reset', 'logout', 'log out', 'sign out', 'save', 'submit', 'create', 'install', 'uninstall', 'drop', 'purge', 'wipe')):
                                    continue
                                href = str(toggle.get_attribute('href') or '').strip()
                                if href and not href.startswith(('#', 'javascript:')):
                                    continue
                                toggle.click(timeout=remaining_browser_ms(1000))
                                page.wait_for_timeout(min(120, remaining_browser_ms(120)))
                                clicked += 1
                            except Exception:
                                continue
                        if clicked:
                            budget_info['menu_controls_clicked'] = int(budget_info.get('menu_controls_clicked', 0) or 0) + clicked
                            # Re-scan the rendered DOM after expansion. Multiple bounded passes help catch
                            # asynchronously populated SPA/dropdown content without re-clicking controls or
                            # issuing state-changing actions. The first collection above counts as pass 1.
                            completed_dom_passes = 1
                            while completed_dom_passes < dom_pass_limit and time.monotonic() < browser_deadline:
                                page.wait_for_timeout(min(120, remaining_browser_ms(120)))
                                collect_dom_navigation()
                                completed_dom_passes += 1
                            budget_info['dom_rescan_passes'] = int(budget_info.get('dom_rescan_passes', 0) or 0) + max(0, completed_dom_passes - 1)
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
                wall_clock_elapsed_seconds=round(time.monotonic() - browser_started, 3),
                wall_clock_exhausted=bool(queue and time.monotonic() >= browser_deadline),
                application_families_visited=len([count for count in family_visits.values() if count > 0]),
            )
            if cookies and runtime_storage is not None:
                try:
                    # The context started from the previous state, so replacing it with the final state
                    # preserves old entries and also captures cookies/localStorage created by silent SSO
                    # while Chromium traversed newly reached application roots.
                    runtime_state['storage_state'] = _capture_storage_state(context)
                except Exception:
                    pass
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
        wall_clock_elapsed_seconds=round(time.monotonic() - browser_started, 3),
        wall_clock_exhausted=bool(budget_info.get('wall_clock_exhausted')) or bool(queue and time.monotonic() >= browser_deadline),
        external_origins_observed=sorted(external_browser_origins),
    )
    return (_dedupe_request_cases(cases), unique_observed, list(dict.fromkeys(navigated)), errors, budget_info)


# Builds a deterministic, target-agnostic port order. A compact generic web/application set is
# always attempted first, then runtime service databases, then a midpoint walk covers the remaining
# TCP space. This makes bounded scans useful early without encoding any target-specific port list.
COMMON_WEB_SERVICE_PORTS = (
    80, 443, 81, 3000, 3001, 3002, 4000, 4200, 5000, 5001, 5601, 6443, 7000, 7001,
    8000, 8001, 8008, 8080, 8081, 8082, 8088, 8090, 8181, 8200, 8280, 8333,
    8443, 8444, 8500, 8880, 8888, 8983, 9000, 9001, 9043, 9080, 9090, 9091,
    9093, 9100, 9200, 9443, 10000, 10250, 10443, 15672, 18080,
)


def _runtime_service_database_ports() -> list[int]:
    candidates = [
        Path('/etc/services'),
        Path('/usr/share/nmap/nmap-services'),
        Path('/usr/local/share/nmap/nmap-services'),
        Path('/opt/homebrew/share/nmap/nmap-services'),
    ]
    ports: list[int] = []
    seen: set[int] = set()
    service_line = re.compile(r'^\s*[^#\s]+\s+(\d{1,5})/(tcp|udp)\b', re.IGNORECASE)
    for path in candidates:
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
                match = service_line.match(line)
                if not match or match.group(2).lower() != 'tcp':
                    continue
                port = int(match.group(1))
                if 1 <= port <= 65535 and port not in seen:
                    seen.add(port)
                    ports.append(port)
        except OSError:
            continue
    return ports


def _stratified_tcp_port_order(limit: int) -> list[int]:
    cap = max(0, min(65535, int(limit)))
    if cap <= 0:
        return []
    result: list[int] = []
    seen: set[int] = set()

    # Common web/application ports come first so a short time-bounded pass still covers the most
    # likely HTTP/HTTPS administration, API and developer surfaces. The list is generic and is not
    # derived from a target inventory, compose file or benchmark dataset.
    for port in COMMON_WEB_SERVICE_PORTS:
        if port not in seen:
            seen.add(port)
            result.append(port)
            if len(result) >= cap:
                return result

    # Runtime service databases broaden the generic priority set according to the host environment.
    for port in _runtime_service_database_ports():
        if port not in seen:
            seen.add(port)
            result.append(port)
            if len(result) >= cap:
                return result

    # Breadth-first interval bisection makes low/mid/high ranges appear early and is deterministic.
    intervals: list[tuple[int, int]] = [(1, 65535)]
    cursor = 0
    while cursor < len(intervals) and len(result) < cap:
        lo, hi = intervals[cursor]
        cursor += 1
        if lo > hi:
            continue
        mid = (lo + hi) // 2
        if mid not in seen:
            seen.add(mid)
            result.append(mid)
            if len(result) >= cap:
                break
        if lo <= mid - 1:
            intervals.append((lo, mid - 1))
        if mid + 1 <= hi:
            intervals.append((mid + 1, hi))
    # If service-database overlap consumed midpoint positions, complete deterministically.
    if len(result) < cap:
        for port in range(1, 65536):
            if port not in seen:
                result.append(port)
                seen.add(port)
                if len(result) >= cap:
                    break
    return result


def _same_host_service_time_limits() -> tuple[float, float]:
    limits = DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, DISCOVERY_LIMITS['balanced'])
    total = max(0.0, float(limits.get('same_host_service_time_budget_seconds', 0) or 0))
    initial = max(0.0, float(limits.get('same_host_service_initial_time_budget_seconds', total) or total))
    return total, min(total, initial)


def _same_host_service_time_remaining_seconds() -> float:
    total, _ = _same_host_service_time_limits()
    with SAME_HOST_SERVICE_DISCOVERY_TIME_LOCK:
        spent = float(SAME_HOST_SERVICE_DISCOVERY_TIME_SPENT_SECONDS)
    return max(0.0, total - spent)


def _consume_same_host_service_time(seconds: float) -> None:
    global SAME_HOST_SERVICE_DISCOVERY_TIME_SPENT_SECONDS
    value = max(0.0, float(seconds or 0.0))
    if value <= 0:
        return
    with SAME_HOST_SERVICE_DISCOVERY_TIME_LOCK:
        SAME_HOST_SERVICE_DISCOVERY_TIME_SPENT_SECONDS += value


def _cached_same_host_service_discovery(hostname: str) -> dict[str, Any] | None:
    """Return the best service scan already completed for one exact hostname in this process.

    Port discovery is host-level, so anonymous/authenticated profiles and later application recrawls
    reuse the same TCP/HTTP classification instead of paying for another sweep with a different cap.
    """
    host = normalized_hostname(hostname)
    matches: list[dict[str, Any]] = []
    for key, value in SAME_HOST_SERVICE_DISCOVERY_CACHE.items():
        if not isinstance(key, tuple) or len(key) < 2 or key[0] != host or key[1] != CURRENT_SCAN_MODE:
            continue
        if isinstance(value, dict):
            matches.append(value)
    if not matches:
        return None
    return dict(max(
        matches,
        key=lambda row: (
            int(row.get('ports_probed', 0) or 0),
            int(row.get('candidate_cap', 0) or 0),
            float(row.get('duration_seconds', 0.0) or 0.0),
        ),
    ))


def _bounded_service_getaddrinfo(hostname: str, timeout: float, *, attempts: int = 2) -> list[tuple[Any, ...]]:
    """Resolve one hostname with bounded retry for transient/timeout resolver failures.

    ``socket.getaddrinfo`` has no portable timeout argument. Each attempt therefore runs in a daemon
    helper thread and receives only its share of the single caller-provided allowance. A timed-out
    helper is ignored forever and cannot extend the assessment deadline. NXDOMAIN/non-transient
    resolver errors fail immediately; EAI_AGAIN/EAI_FAIL and bounded timeouts may consume one retry.
    """
    allowance = max(0.0, float(timeout or 0.0))
    if allowance <= 0:
        raise TimeoutError(f'DNS resolution budget exhausted for {hostname!r}')
    deadline = time.monotonic() + allowance
    max_attempts = max(1, int(attempts))
    last_error: BaseException | None = None

    for attempt_index in range(max_attempts):
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0:
            break
        attempts_left = max_attempts - attempt_index
        # Reserve time for a second try instead of letting the first resolver thread consume the
        # whole DNS allowance. A successful normal resolver returns much earlier than this cap.
        attempt_allowance = remaining if attempts_left <= 1 else max(0.05, remaining / attempts_left)
        done = threading.Event()
        state: dict[str, Any] = {}

        def _resolve() -> None:
            try:
                state['infos'] = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            except BaseException as exc:
                state['error'] = exc
            finally:
                done.set()

        worker = threading.Thread(target=_resolve, name=f'secops-service-dns-{attempt_index + 1}', daemon=True)
        worker.start()
        if not done.wait(attempt_allowance):
            last_error = TimeoutError(
                f'DNS resolution attempt {attempt_index + 1}/{max_attempts} timed out for {hostname!r}'
            )
            continue
        error = state.get('error')
        if isinstance(error, BaseException):
            last_error = error
            transient_codes = {
                value for value in (getattr(socket, 'EAI_AGAIN', None), getattr(socket, 'EAI_FAIL', None))
                if value is not None
            }
            if isinstance(error, socket.gaierror) and getattr(error, 'errno', None) not in transient_codes:
                raise error
            continue
        infos = state.get('infos')
        rows = list(infos) if isinstance(infos, list) else list(infos or [])
        if rows:
            return rows
        last_error = OSError(f'No address resolved for {hostname!r}')

    if isinstance(last_error, BaseException):
        raise last_error
    raise TimeoutError(f'DNS resolution timed out for {hostname!r} after {allowance:.2f}s')


def _resolve_service_discovery_address(
    hostname: str, preferred_port: int=0, *, deadline: float | None=None,
) -> tuple[str, list[str]]:
    remaining = 3.0 if deadline is None else max(0.0, float(deadline) - time.monotonic())
    # DNS is part of the same service-discovery wall-clock budget.  Three seconds is enough for the
    # normal local/university resolver path while preventing resolver retries from violating the
    # advertised 4/12/20 minute global ceilings.
    infos = _bounded_service_getaddrinfo(hostname, min(3.0, remaining))
    addresses: list[str] = []
    for info in infos:
        address = str((info[4] or ('',))[0] or '').strip()
        if address and address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OSError(f'No address resolved for {hostname!r}')
    # Keep one address so the port budget is not multiplied by DNS cardinality, but do not blindly
    # choose getaddrinfo()[0]: on dual-stack/multi-A hosts that address may not be the one serving the
    # configured target. Prefer the first address reachable on the target's original port while the
    # same local deadline still has capacity.
    port = int(preferred_port or 0)
    if 1 <= port <= 65535 and len(addresses) > 1:
        for address in addresses:
            remaining = 0.35 if deadline is None else max(0.0, float(deadline) - time.monotonic())
            if remaining <= 0:
                break
            sock: socket.socket | None = None
            try:
                if not _pace_http_request(deadline):
                    break
                remaining = 0.35 if deadline is None else max(0.0, float(deadline) - time.monotonic())
                if remaining <= 0:
                    break
                sock = socket.create_connection((address, port), timeout=min(0.35, remaining))
                return address, addresses
            except OSError:
                continue
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
    return addresses[0], addresses


def _http_authority_host(hostname: str) -> str:
    """Format one host for an HTTP authority/Host header, including IPv6 brackets."""
    host = str(hostname or '').strip()
    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f'[{host}]' if parsed_ip.version == 6 else host


def _deadline_timeout(deadline: float | None, cap: float) -> float:
    if deadline is None:
        return max(0.0, float(cap))
    return max(0.0, min(float(cap), float(deadline) - time.monotonic()))


def _socket_http_probe(
    address: str, hostname: str, port: int, *, use_tls: bool, timeout: float = 0.45,
    deadline: float | None = None,
) -> tuple[bool, str, bool]:
    """Classify HTTP(S) with HEAD first and a bounded GET fallback.

    Returns ``(confirmed, preview, deferred_by_deadline)``. Every pacing sleep, TCP connect, TLS
    handshake and receive timeout is clipped to the caller deadline so classification cannot silently
    run past the service-discovery wall clock. Some real servers mishandle HEAD; if HEAD yields no
    HTTP status line, one GET request is attempted while budget remains.
    """
    authority_host = _http_authority_host(hostname)
    host_header = authority_host
    default_port = 443 if use_tls else 80
    if int(port) != default_port:
        host_header = f'{authority_host}:{port}'

    def attempt(method: str) -> tuple[bool, str, bool]:
        sock: socket.socket | ssl.SSLSocket | None = None
        try:
            if not _pace_http_request(deadline):
                return False, '', True
            current_timeout = _deadline_timeout(deadline, timeout)
            if current_timeout <= 0:
                return False, '', True
            base = socket.create_connection((address, int(port)), timeout=current_timeout)
            base.settimeout(max(0.001, _deadline_timeout(deadline, timeout)))
            sock = base
            if use_tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    ipaddress.ip_address(hostname)
                except ValueError:
                    server_hostname = hostname
                else:
                    server_hostname = None
                if _deadline_timeout(deadline, timeout) <= 0:
                    return False, '', True
                sock = context.wrap_socket(base, server_hostname=server_hostname)
                sock.settimeout(max(0.001, _deadline_timeout(deadline, timeout)))
            request = (
                f'{method} / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: SecOps-ServiceDiscovery/1.0\r\n'
                'Accept: */*\r\nConnection: close\r\n'
                + ('Range: bytes=0-0\r\n' if method == 'GET' else '')
                + '\r\n'
            ).encode('ascii', errors='ignore')
            sock.sendall(request)
            current_timeout = _deadline_timeout(deadline, timeout)
            if current_timeout <= 0:
                return False, '', True
            sock.settimeout(max(0.001, current_timeout))
            data = sock.recv(128)
            text = data.decode('latin-1', errors='ignore')
            return bool(re.match(r'^HTTP/\d(?:\.\d)?\s+\d{3}\b', text)), text[:96], False
        except (OSError, ssl.SSLError, ValueError):
            return False, '', bool(deadline is not None and time.monotonic() >= float(deadline))
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    confirmed, preview, deferred = attempt('HEAD')
    if confirmed or deferred:
        return confirmed, preview, deferred
    # HEAD can be unsupported or closed without an HTTP response. A minimal GET fallback improves
    # protocol coverage without changing active-test scope or following redirects.
    return attempt('GET')


def _tcp_port_open_any(
    addresses: list[str], port: int, *, deadline: float | None = None, start_index: int = 0,
    timeout: float = 0.30,
) -> tuple[str, int, bool]:
    """Try one candidate port across all resolved addresses without multiplying the port budget.

    Address order rotates by candidate index so multi-A/dual-stack hosts do not permanently favor the
    first resolver result. The candidate itself still counts once; ``attempts`` exposes the real
    connection work and the common deadline bounds high-cardinality DNS answers.
    """
    unique = [value for value in dict.fromkeys(str(v).strip() for v in addresses) if value]
    if not unique:
        return '', 0, False
    shift = int(start_index) % len(unique)
    ordered = unique[shift:] + unique[:shift]
    attempts = 0
    for address in ordered:
        if deadline is not None and time.monotonic() >= float(deadline):
            return '', attempts, True
        if not _pace_http_request(deadline):
            return '', attempts, True
        current_timeout = _deadline_timeout(deadline, timeout)
        if current_timeout <= 0:
            return '', attempts, True
        sock: socket.socket | None = None
        attempts += 1
        try:
            sock = socket.create_connection((address, int(port)), timeout=current_timeout)
            return address, attempts, False
        except OSError:
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return '', attempts, False


def discover_same_host_web_services(
    target: str, candidate_cap: int | None=None, *, time_budget_seconds: float | None=None,
) -> dict[str, Any]:
    parsed = urlparse(normalize_url(target))
    hostname = normalized_hostname(parsed.hostname or '')
    limits = DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, DISCOVERY_LIMITS['balanced'])
    configured_cap = int(limits.get('same_host_service_candidates', 0) or 0)
    cap = configured_cap if candidate_cap is None else max(0, min(configured_cap, int(candidate_cap)))
    original_port = parsed.port or (443 if parsed.scheme.lower() == 'https' else 80)
    # Address preference depends on the configured service port; keep it in the cache identity.
    cache_key = (hostname, CURRENT_SCAN_MODE, int(original_port), str(parsed.scheme or '').lower(), int(cap))
    total_time_budget, initial_time_budget = _same_host_service_time_limits()
    remaining_global = _same_host_service_time_remaining_seconds()
    requested_time_budget = initial_time_budget if time_budget_seconds is None else max(0.0, float(time_budget_seconds))
    local_time_budget = min(remaining_global, requested_time_budget)
    empty = {
        'enabled': False, 'hostname': hostname, 'candidate_cap': cap, 'candidate_ports_planned': 0,
        'ports_probed': 0, 'candidate_ports_deferred': 0, 'tcp_connection_attempts': 0,
        'resolved_address_count': 0, 'web_services': [], 'open_web_unconfirmed_ports': [],
        'classification_deferred_ports': [], 'resolved_addresses': [],
        'time_budget_seconds': round(local_time_budget, 3),
        'global_time_budget_seconds': round(total_time_budget, 3),
        'global_time_remaining_before_seconds': round(remaining_global, 3),
        'common_web_ports_priority_count': min(cap, len(COMMON_WEB_SERVICE_PORTS)),
    }
    if not DISCOVER_SAME_HOST_SERVICES or not ALLOW_SAME_HOST_PORTS or not hostname or cap <= 0:
        return empty
    cached = SAME_HOST_SERVICE_DISCOVERY_CACHE.get(cache_key)
    if not isinstance(cached, dict):
        # The TCP/service sweep is host-level: if another profile or application view already scanned
        # this exact hostname with a different candidate share, reuse that result rather than scanning
        # the host again. Application recrawls still run with the current profile/session later.
        cached = _cached_same_host_service_discovery(hostname)
    if isinstance(cached, dict):
        result = dict(cached)
        previous_ports = int(result.get('ports_probed', 0) or 0)
        previous_duration = float(result.get('duration_seconds', 0.0) or 0.0)
        services: list[dict[str, Any]] = []
        for row in result.get('web_services', []) or []:
            if not isinstance(row, dict):
                continue
            copy = dict(row)
            copy['configured_port'] = (
                int(copy.get('port') or 0) == int(original_port)
                and str(copy.get('scheme') or '') == str(parsed.scheme or '').lower()
            )
            services.append(copy)
        result['web_services'] = services
        result['cache_hit'] = True
        result['host_level_cache_reuse'] = True
        result['requested_candidate_cap'] = cap
        result['reused_ports_probed'] = previous_ports
        result['original_scan_duration_seconds'] = round(previous_duration, 3)
        # These fields describe work performed by this call; the reused scan remains visible above.
        result['ports_probed'] = 0
        result['duration_seconds'] = 0.0
        result['time_budget_seconds'] = 0.0
        result['time_budget_exhausted'] = False
        result['global_time_remaining_before_seconds'] = round(remaining_global, 3)
        result['global_time_remaining_after_seconds'] = round(_same_host_service_time_remaining_seconds(), 3)
        return result
    if local_time_budget <= 0:
        return {
            **empty, 'enabled': True, 'time_budget_exhausted': True, 'cache_hit': False,
            'global_time_remaining_after_seconds': round(remaining_global, 3),
        }

    started = time.monotonic()
    deadline = started + local_time_budget
    try:
        address, addresses = _resolve_service_discovery_address(hostname, original_port, deadline=deadline)
    except (OSError, TimeoutError) as exc:
        elapsed = time.monotonic() - started
        _consume_same_host_service_time(elapsed)
        exhausted = bool(time.monotonic() >= deadline or _same_host_service_time_remaining_seconds() <= 0)
        result = {
            **empty, 'enabled': True, 'error': f'{type(exc).__name__}: {exc}',
            'duration_seconds': round(elapsed, 3), 'cache_hit': False,
            'time_budget_exhausted': exhausted,
            'global_time_remaining_after_seconds': round(_same_host_service_time_remaining_seconds(), 3),
        }
        # No TCP candidate was probed.  Do not freeze a transient DNS/pre-probe failure into the
        # host-level service cache; a later authorized profile may retry if global budget remains.
        return result

    web_services: list[dict[str, Any]] = []
    open_unconfirmed: list[int] = []
    classification_deferred: list[int] = []
    ports = _stratified_tcp_port_order(cap)
    ports_probed = 0
    tcp_connection_attempts = 0
    time_budget_exhausted = False
    probe_addresses = [address, *[value for value in addresses if value != address]]
    # Every TCP-open candidate is classified with BOTH HTTP and HTTPS while deadline remains. A socket
    # being open is only attack-surface inventory; incomplete protocol classification is reported as
    # deferred instead of being mislabeled non-web.
    for index, port in enumerate(ports, start=1):
        if time.monotonic() >= deadline:
            time_budget_exhausted = True
            break
        open_address, attempts, tcp_deferred = _tcp_port_open_any(
            probe_addresses, port, deadline=deadline, start_index=index - 1,
        )
        tcp_connection_attempts += attempts
        if tcp_deferred:
            time_budget_exhausted = True
            break
        ports_probed += 1
        if not open_address:
            continue
        plain_ok, plain_preview, plain_deferred = _socket_http_probe(
            open_address, hostname, port, use_tls=False, deadline=deadline,
        )
        tls_ok, tls_preview, tls_deferred = _socket_http_probe(
            open_address, hostname, port, use_tls=True, deadline=deadline,
        )
        if plain_deferred or tls_deferred:
            classification_deferred.append(port)
            if time.monotonic() >= deadline:
                time_budget_exhausted = True
        if plain_ok:
            authority_host = _http_authority_host(hostname)
            root = f'http://{authority_host}' + ('' if port == 80 else f':{port}') + '/'
            web_services.append({
                'url': root, 'port': port, 'scheme': 'http', 'probe_index': index,
                'response_preview': plain_preview, 'http_confirmed': True, 'https_confirmed': bool(tls_ok),
                'resolved_address': open_address,
            })
        if tls_ok:
            authority_host = _http_authority_host(hostname)
            root = f'https://{authority_host}' + ('' if port == 443 else f':{port}') + '/'
            web_services.append({
                'url': root, 'port': port, 'scheme': 'https', 'probe_index': index,
                'response_preview': tls_preview, 'http_confirmed': bool(plain_ok), 'https_confirmed': True,
                'resolved_address': open_address,
            })
        if not plain_ok and not tls_ok and not plain_deferred and not tls_deferred:
            open_unconfirmed.append(port)
        if time_budget_exhausted:
            break

    elapsed = time.monotonic() - started
    _consume_same_host_service_time(elapsed)
    if ports_probed < len(ports) and time.monotonic() >= deadline:
        time_budget_exhausted = True

    unique_services: list[dict[str, Any]] = []
    seen_roots: set[str] = set()
    for row in web_services:
        root = _clean_url(str(row.get('url') or ''))
        if not root or root in seen_roots or not url_in_authorized_scope(target, root):
            continue
        seen_roots.add(root)
        copy = dict(row)
        copy['url'] = root
        copy['configured_port'] = int(copy.get('port') or 0) == int(original_port) and str(copy.get('scheme') or '') == str(parsed.scheme or '').lower()
        unique_services.append(copy)
    result = {
        'enabled': True, 'hostname': hostname, 'resolved_address': address, 'resolved_addresses': addresses,
        'candidate_cap': cap, 'candidate_ports_planned': len(ports), 'ports_probed': ports_probed,
        'candidate_ports_deferred': max(0, len(ports) - ports_probed),
        'tcp_connection_attempts': tcp_connection_attempts,
        'resolved_address_count': len(addresses),
        'web_services': unique_services, 'open_web_unconfirmed_ports': sorted(set(open_unconfirmed)),
        'classification_deferred_ports': sorted(set(classification_deferred)),
        'duration_seconds': round(elapsed, 3), 'cache_hit': False,
        'time_budget_seconds': round(local_time_budget, 3), 'time_budget_exhausted': bool(time_budget_exhausted),
        'global_time_budget_seconds': round(total_time_budget, 3),
        'global_time_remaining_before_seconds': round(remaining_global, 3),
        'global_time_remaining_after_seconds': round(_same_host_service_time_remaining_seconds(), 3),
        'common_web_ports_priority_count': min(cap, len(COMMON_WEB_SERVICE_PORTS)),
        'candidate_order_policy': 'generic-common-web-ports -> runtime-service-databases -> stratified-full-range',
    }
    SAME_HOST_SERVICE_DISCOVERY_CACHE[cache_key] = dict(result)
    return result

# Crawls the target and records pages, forms, parameters, scripts, browser requests, and auth state.
def discover_target(
    target: str, cookies: str, max_pages: int=MAX_CRAWL_PAGES, seeds: list[str] | None=None,
    forced_seeds: list[str] | None=None, *, expand_authorized_service_hosts: bool=True,
    same_host_service_candidate_cap: int | None=None, allow_state_changes: bool=False,
) -> dict[str, Any]:

    session = requests.Session()
    session.headers.update({'User-Agent': 'SecOps-Discovery/2.0', 'Accept': 'text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5'})
    target_preparation = apply_runtime_target_preparation(target, cookies, allow_state_changes=allow_state_changes) if cookies else {'performed': False, 'configured': False, 'usable': True}
    limits = DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, DISCOVERY_LIMITS['balanced'])
    # TEST is a diagnostic profile: the HTTP crawler owns an explicit short wall-clock budget,
    # independent from the equally bounded service-discovery and Chromium stages. Normal profiles
    # retain their existing page/attempt limits and request timeouts.
    http_discovery_started = time.monotonic()
    http_discovery_deadline = (
        http_discovery_started + float(TEST_DISCOVERY_TIME_BUDGET_SECONDS)
        if CURRENT_SCAN_MODE == 'test' else None
    )

    def discovery_request_timeout(connect_seconds: float, read_seconds: float) -> tuple[float, float]:
        if http_discovery_deadline is None:
            return (connect_seconds, read_seconds)
        remaining = max(0.5, http_discovery_deadline - time.monotonic())
        return (max(0.5, min(connect_seconds, remaining * 0.25)), max(0.5, min(read_seconds, remaining)))

    def http_discovery_time_left() -> bool:
        return http_discovery_deadline is None or time.monotonic() < http_discovery_deadline

    same_host_service_discovery = discover_same_host_web_services(target, candidate_cap=same_host_service_candidate_cap)
    discovered_service_roots = {
        _clean_url(str(row.get('url') or ''))
        for row in same_host_service_discovery.get('web_services', [])
        if isinstance(row, dict) and row.get('url') and url_in_authorized_scope(target, str(row.get('url')))
    }
    ordinary_seed_urls = { _clean_url(value) for value in seeds or [] if value and url_in_authorized_scope(target, value) }
    explicit_seed_urls = { _clean_url(value) for value in forced_seeds or [] if value and url_in_authorized_scope(target, value) }
    priority_seed_urls = ordinary_seed_urls | explicit_seed_urls | discovered_service_roots
    initial = list(dict.fromkeys([_clean_url(target), *sorted(priority_seed_urls)]))
    explicit_seed_count = len(explicit_seed_urls)
    page_budget = max(min(max(1, int(max_pages)), int(limits['crawl_pages'])), min(256, explicit_seed_count))
    page_max_budget = max(
        page_budget,
        min(max(1, int(max_pages)), int(limits.get('crawl_pages_max', limits['crawl_pages']))),
        min(256, explicit_seed_count),
    )
    script_budget = min(MAX_SCRIPT_ASSETS, int(limits['scripts']))
    script_attempt_factor = max(1.0, float(SCRIPT_ATTEMPT_BUDGET_FACTORS.get(CURRENT_SCAN_MODE, 1.5)))
    script_attempt_budget = max(script_budget, int(math.ceil(script_budget * script_attempt_factor)))
    route_variant_limit = int(limits['route_variants'])
    per_origin_limit = max(int(limits['per_origin_pages']), min(256, explicit_seed_count))
    destructive_skipped: set[str] = set()
    destructive_request_cases: list[dict[str, Any]] = []
    coverage_skipped_cases: list[dict[str, Any]] = []
    queue: list[str] = []
    queued: set[str] = set()
    queued_signatures: Counter[tuple[str, str, tuple[str, ...]]] = Counter()
    visited_signatures: Counter[tuple[str, str, tuple[str, ...]]] = Counter()
    origin_useful_visits: Counter[str] = Counter()
    family_useful_visits: Counter[tuple[str, str]] = Counter()
    origin_attempts: Counter[str] = Counter()
    skipped_route_variants = 0
    skipped_origin_budget = 0
    skipped_out_of_scope = 0
    out_of_scope_origins: set[str] = set()
    http_attempts = 0
    dead_http_responses = 0
    attempt_factor = max(1.0, float(HTTP_ATTEMPT_BUDGET_FACTORS.get(CURRENT_SCAN_MODE, 1.5)))
    attempt_budget = max(page_max_budget, int(math.ceil(page_max_budget * attempt_factor)))
    per_origin_attempt_limit = max(per_origin_limit, int(math.ceil(per_origin_limit * attempt_factor)))

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
        if row['reason_code'] == 'OUT_OF_SCOPE':
            try:
                origin = normalized_origin(value)
            except Exception:
                origin = ''
            # Coverage diagnostics must never label an authorized source URL as an external origin.
            # This is a secondary guard around callers that report a blocked redirect destination.
            if origin and not url_in_authorized_scope(target, value):
                out_of_scope_origins.add(origin)

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
        variant_limit = _discovery_variant_limit(value, route_variant_limit)
        if not force and queued_signatures[signature] >= variant_limit:
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
        queue.sort(key=lambda candidate: (0 if candidate in priority_seed_urls else 1, -_discovery_diversity_score(target, candidate, family_useful_visits), candidate))

    for value in initial:
        enqueue(value, force=value in explicit_seed_urls)

    visited: set[str] = set()
    html_urls: set[str] = set()
    form_urls: set[str] = set()
    parameterized: set[str] = set()
    request_cases: list[dict[str, Any]] = []
    client_side_candidates: list[dict[str, Any]] = []
    script_urls: set[str] = set()
    script_endpoint_hints: list[dict[str, str]] = []
    # Attempt and useful-script budgets are separate. Broken/redirected/404 assets must not consume
    # a slot that is intended for a JavaScript body that can actually be inspected for endpoints.
    attempted_script_urls: set[str] = set()
    scanned_script_urls: set[str] = set()
    deferred_script_urls: set[str] = set()
    tokens: set[str] = set()
    errors: list[dict[str, Any]] = []
    tls_trust_fallback_urls: set[str] = set()
    initial_login_detected = False
    pages_processed = 0
    http_base_scores: list[int] = []
    http_adaptive_threshold: int | None = None

    while queue and pages_processed < page_max_budget and http_attempts < attempt_budget and http_discovery_time_left():
        queue.sort(key=lambda candidate: (0 if candidate in priority_seed_urls else 1, -_discovery_diversity_score(target, candidate, family_useful_visits), candidate))
        requested = queue[0]
        requested_score = _discovery_diversity_score(target, requested, family_useful_visits)
        if pages_processed >= page_budget and requested not in explicit_seed_urls:
            if http_adaptive_threshold is None:
                cutoff_score = min(http_base_scores) if http_base_scores else requested_score
                http_adaptive_threshold = max(1, int(cutoff_score * 0.75))
            if requested_score < http_adaptive_threshold:
                break
        requested = queue.pop(0)
        if requested in visited:
            continue
        signature = _discovery_route_signature(requested)
        origin = normalized_origin(requested)
        forced_requested = requested in explicit_seed_urls
        variant_limit = _discovery_variant_limit(requested, route_variant_limit)
        if not forced_requested and visited_signatures[signature] >= variant_limit:
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
        for nested in _nested_navigation_targets(requested):
            if url_in_authorized_scope(target, nested) and _crawlable_url(nested) and not _destructive_crawl_url(nested):
                enqueue(nested, force=forced_requested, source_url=requested)
        try:
            response, final, redirect_issue = _safe_crawl_get(session, requested, target, timeout=discovery_request_timeout(5, 15), max_redirects=5, cookies=cookies)
            if response is not None and bool(getattr(response, '_secops_tls_trust_retry', False)):
                tls_trust_fallback_urls.add(str(final or requested))
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
                # _safe_crawl_get encodes the blocked destination after the first colon. Record that
                # destination, not the authorized page that emitted the redirect, so scope summaries
                # contain only the external/blocked origin that was actually rejected.
                blocked_target = redirect_issue.split(':', 1)[1].strip() if ':' in redirect_issue else final
                if code == 'OUT_OF_SCOPE':
                    skipped_out_of_scope += 1
                record_coverage_skip(blocked_target or final, code, 'Redirect target was blocked by the discovery safety/scope guard.', source_url=requested)
                continue
            if redirect_issue == 'redirect_limit_reached':
                # `final` is the next authorized hop but it has not been requested yet. Re-queue it
                # instead of pairing the previous 3xx response with an unrequested URL. This keeps
                # long in-scope redirect chains discoverable without making one request helper unbounded.
                enqueue(final, force=forced_requested, source_url=requested)
                continue
            if redirect_issue.startswith('redirect_loop:') or redirect_issue == 'invalid_redirect_location':
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
        if urlparse(requested).query:
            parameterized.add(requested)
            query_parameters = _query_parameter_names(requested)
            if query_parameters:
                request_cases.append({
                    'url': requested, 'method': 'GET', 'data': '', 'parameters': query_parameters,
                    'file_parameters': [], 'token_parameters': [], 'fields': [],
                    'source_url': requested,
                    'discovery_source': 'explicit_entry_point' if forced_requested else 'crawler_url',
                })
        final_origin = normalized_origin(final)
        if origin_useful_visits[final_origin] >= per_origin_limit:
            skipped_origin_budget += 1
            record_coverage_skip(final, 'BUDGET_LIMIT', 'Per-origin useful-page discovery budget was already saturated.', source_url=requested)
            continue
        pages_processed += 1
        origin_useful_visits[final_origin] += 1
        family_useful_visits[_application_family_key(final)] += 1
        if pages_processed <= page_budget and _discovery_route_signature(final) != _discovery_route_signature(_clean_url(target)):
            http_base_scores.append(requested_score)
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

        for hint in _literal_navigation_hints(response.text, final, target):
            hinted_url = str(hint.get('url') or '')
            if not hinted_url:
                continue
            literal_hint = {'method': 'GET', 'url': hinted_url, 'source': 'html_or_inline_literal'}
            if literal_hint not in script_endpoint_hints:
                script_endpoint_hints.append(literal_hint)
            hint_parameters = _query_parameter_names(hinted_url)
            if hint_parameters:
                request_cases.append({
                    'url': hinted_url, 'method': 'GET', 'data': '', 'parameters': hint_parameters,
                    'file_parameters': [], 'token_parameters': [], 'fields': [],
                    'source_url': final, 'discovery_source': 'html_or_inline_literal',
                })
                parameterized.add(hinted_url)
            for nested in _nested_navigation_targets(hinted_url):
                if url_in_authorized_scope(target, nested) and _crawlable_url(nested) and not _destructive_crawl_url(nested):
                    enqueue(nested, source_url=hinted_url)
            if hinted_url not in visited:
                enqueue(hinted_url, source_url=final)

        ranked_scripts: list[str] = []
        for source in parser.scripts:
            try:
                script_url = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(final, source)))
            except Exception:
                continue
            if not url_in_authorized_scope(target, script_url) or _destructive_crawl_url(script_url) or script_url in attempted_script_urls:
                continue
            ranked_scripts.append(script_url)
        ranked_scripts = sorted(set(ranked_scripts), key=lambda value: (-_script_value_score(value), value))
        for script_index, script_url in enumerate(ranked_scripts):
            if not http_discovery_time_left():
                deferred_script_urls.update(ranked_scripts[script_index:])
                break
            if len(scanned_script_urls) >= script_budget or len(attempted_script_urls) >= script_attempt_budget:
                deferred_script_urls.update(ranked_scripts[script_index:])
                break
            attempted_script_urls.add(script_url)
            try:
                script_response, script_final, script_issue = _safe_crawl_get(session, script_url, target, timeout=discovery_request_timeout(4, 12), max_redirects=4, cookies=cookies)
                if script_response is not None and bool(getattr(script_response, '_secops_tls_trust_retry', False)):
                    tls_trust_fallback_urls.add(str(script_final or script_url))
            except requests.RequestException as exc:
                errors.append({'url': script_url, 'type': type(exc).__name__, 'message': f'JavaScript fetch: {exc}'})
                continue
            if script_response is None or script_issue or script_response.status_code >= 400:
                continue
            script_final = _clean_url(script_final)
            if not url_in_authorized_scope(target, script_final):
                continue
            scanned_script_urls.add(script_final)
            script_urls.add(script_final)
            script_hints = _javascript_endpoint_hints(script_response.text, script_final, target)
            generic_hints = _literal_navigation_hints(script_response.text, script_final, target)
            for hint in [*script_hints, *generic_hints]:
                hinted_url = str(hint.get('url') or '')
                hint_method = str(hint.get('method') or 'GET').upper()
                recorded_hint = {'method': hint_method, 'url': hinted_url, 'source': 'javascript_literal'}
                if hinted_url and recorded_hint not in script_endpoint_hints:
                    script_endpoint_hints.append(recorded_hint)
                hint_parameters = _query_parameter_names(hinted_url)
                if hint_parameters and hint_method in {'GET', 'POST'}:
                    request_cases.append({'url': hinted_url, 'method': hint_method, 'data': '', 'parameters': hint_parameters, 'file_parameters': [], 'token_parameters': [], 'fields': [], 'source_url': script_final, 'discovery_source': 'javascript_literal'})
                    if hint_method == 'GET':
                        parameterized.add(hinted_url)
                if hint_method == 'GET' and hinted_url:
                    for nested in _nested_navigation_targets(hinted_url):
                        if url_in_authorized_scope(target, nested) and _crawlable_url(nested) and not _destructive_crawl_url(nested):
                            enqueue(nested, source_url=hinted_url)
                    if hinted_url not in visited:
                        enqueue(hinted_url, source_url=script_final)
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
                    'parameters': _query_parameter_names(candidate),
                    'fields': [], 'source_url': final, 'destructive_kind': 'logout' if _is_logout_url(candidate) else 'other',
                })
                continue
            if urlparse(candidate).query:
                parameterized.add(candidate)
            for nested in _nested_navigation_targets(candidate):
                if url_in_authorized_scope(target, nested) and _crawlable_url(nested) and not _destructive_crawl_url(nested):
                    enqueue(nested, source_url=candidate)
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

    browser_cases, browser_network_requests, browser_navigation_urls, browser_errors, browser_budget_info = _browser_network_discovery(target, cookies, sorted(html_urls), sorted(explicit_seed_urls), sorted(priority_seed_urls), allow_state_changes=allow_state_changes) if html_urls or priority_seed_urls else ([], [], [], [], {'base_budget': int(limits['browser_pages']), 'max_budget': int(limits.get('browser_pages_max', limits['browser_pages'])), 'attempted': 0, 'adaptive_overflow_used': 0, 'remaining_candidates': 0, 'adaptive_threshold': None, 'max_saturated': False})
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
            probe_response, probe_final, probe_redirect_issue = _safe_crawl_get(session, probe_url, target, timeout=discovery_request_timeout(5, 15), max_redirects=5, cookies=cookies)
            session.headers.clear()
            session.headers.update(original_headers)
            if probe_response is None:
                raise requests.RequestException(probe_redirect_issue or f'Session probe was blocked: {probe_final}')
            probe_response.url = probe_final
            final_login_detected = _looks_like_login(probe_response)
            anonymous_session = requests.Session()
            anonymous_session.headers.update({'User-Agent': 'SecOps-Discovery-Anonymous-Comparison/1.0', 'Cache-Control': 'no-cache'})
            anonymous_response, anonymous_final, anonymous_redirect_issue = _safe_crawl_get(anonymous_session, probe_url, target, timeout=discovery_request_timeout(5, 15), max_redirects=5, cookies='')
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
        'http_page_max_budget': page_max_budget,
        'http_pages_processed': pages_processed,
        'http_adaptive_overflow_used': max(0, pages_processed - page_budget),
        'http_adaptive_threshold': http_adaptive_threshold,
        'http_attempt_budget': attempt_budget,
        'http_attempt_budget_factor': attempt_factor,
        'http_requests_attempted': http_attempts,
        'http_remaining_candidates': len(queue),
        'http_page_budget_saturated': bool(queue and pages_processed >= page_budget),
        'http_page_max_budget_saturated': bool(queue and pages_processed >= page_max_budget),
        'http_attempt_budget_saturated': bool(queue and http_attempts >= attempt_budget),
        'http_wall_clock_budget_seconds': float(TEST_DISCOVERY_TIME_BUDGET_SECONDS) if CURRENT_SCAN_MODE == 'test' else 0.0,
        'http_wall_clock_elapsed_seconds': round(time.monotonic() - http_discovery_started, 3),
        'http_wall_clock_exhausted': bool(http_discovery_deadline is not None and time.monotonic() >= http_discovery_deadline),
        'dead_http_404_410': dead_http_responses,
        'browser_page_budget': int(browser_budget_info.get('base_budget', limits['browser_pages'])),
        'browser_page_max_budget': int(browser_budget_info.get('max_budget', limits.get('browser_pages_max', limits['browser_pages']))),
        'browser_pages_attempted': int(browser_budget_info.get('attempted', 0) or 0),
        'browser_adaptive_overflow_used': int(browser_budget_info.get('adaptive_overflow_used', 0) or 0),
        'browser_remaining_candidates': int(browser_budget_info.get('remaining_candidates', 0) or 0),
        'browser_adaptive_threshold': browser_budget_info.get('adaptive_threshold'),
        'browser_max_budget_saturated': bool(browser_budget_info.get('max_saturated', False)),
        'browser_wall_clock_budget_seconds': float(browser_budget_info.get('wall_clock_budget_seconds', 0.0) or 0.0),
        'browser_wall_clock_elapsed_seconds': float(browser_budget_info.get('wall_clock_elapsed_seconds', 0.0) or 0.0),
        'browser_wall_clock_exhausted': bool(browser_budget_info.get('wall_clock_exhausted', False)),
        'browser_navigation_retries': int(browser_budget_info.get('navigation_retries', 0) or 0),
        'browser_dom_retries': int(browser_budget_info.get('dom_retries', 0) or 0),
        'browser_dead_404_410': int(browser_budget_info.get('dead_404_410', 0) or 0),
        'browser_external_subresource_requests': int(browser_budget_info.get('external_subresource_requests', 0) or 0),
        'browser_external_navigation_requests_blocked': int(browser_budget_info.get('external_navigation_requests_blocked', 0) or 0),
        'browser_external_origins_observed': list(browser_budget_info.get('external_origins_observed') or []),
        'script_budget': script_budget,
        'scripts_processed': len(scanned_script_urls),
        'script_attempt_budget': script_attempt_budget,
        'script_attempt_budget_factor': script_attempt_factor,
        'script_requests_attempted': len(attempted_script_urls),
        'script_candidates_deferred': len(deferred_script_urls),
        'script_budget_saturated': bool(deferred_script_urls and len(scanned_script_urls) >= script_budget),
        'script_attempt_budget_saturated': bool(deferred_script_urls and len(attempted_script_urls) >= script_attempt_budget),
        'route_variant_limit': route_variant_limit,
        'per_origin_page_limit': per_origin_limit,
        'per_origin_attempt_limit': per_origin_attempt_limit,
        'route_variants_skipped': skipped_route_variants,
        'application_families_visited': len([count for count in family_useful_visits.values() if count > 0]),
        'origin_budget_skipped': skipped_origin_budget,
        'out_of_scope_urls_skipped': skipped_out_of_scope,
        'out_of_scope_origins_observed': sorted(out_of_scope_origins),
        'authorized_origins': sorted(AUTHORIZED_SCOPE_ORIGINS),
        'allow_same_host_ports': ALLOW_SAME_HOST_PORTS,
        'discover_same_host_services': DISCOVER_SAME_HOST_SERVICES,
        'same_host_service_candidate_cap': safe_int_value(same_host_service_discovery.get('candidate_cap'), 0),
        'same_host_service_candidate_ports_planned': safe_int_value(same_host_service_discovery.get('candidate_ports_planned'), 0),
        'same_host_service_ports_probed': safe_int_value(same_host_service_discovery.get('ports_probed'), 0),
        'same_host_service_candidate_ports_deferred': safe_int_value(same_host_service_discovery.get('candidate_ports_deferred'), 0),
        'same_host_service_tcp_connection_attempts': safe_int_value(same_host_service_discovery.get('tcp_connection_attempts'), 0),
        'same_host_service_resolved_address_count': safe_int_value(same_host_service_discovery.get('resolved_address_count'), 0),
        'same_host_service_reused_ports_probed': safe_int_value(same_host_service_discovery.get('reused_ports_probed'), 0),
        'same_host_service_cache_hit': safe_bool_metadata(same_host_service_discovery.get('cache_hit'), False),
        'same_host_service_time_budget_seconds': safe_float_value(same_host_service_discovery.get('time_budget_seconds'), 0.0),
        'same_host_service_time_budget_exhausted': safe_bool_metadata(same_host_service_discovery.get('time_budget_exhausted'), False),
        'same_host_service_global_time_budget_seconds': safe_float_value(same_host_service_discovery.get('global_time_budget_seconds'), 0.0),
        'same_host_service_global_time_remaining_seconds': safe_float_value(same_host_service_discovery.get('global_time_remaining_after_seconds'), 0.0),
        'same_host_service_candidate_order_policy': str(same_host_service_discovery.get('candidate_order_policy') or ''),
        'same_host_web_services_discovered': len(same_host_service_discovery.get('web_services') or []),
        'same_host_open_web_unconfirmed_ports': len(same_host_service_discovery.get('open_web_unconfirmed_ports') or []),
        'same_host_classification_deferred_ports': len(same_host_service_discovery.get('classification_deferred_ports') or []),
        'same_host_service_discovery_seconds': safe_float_value(same_host_service_discovery.get('duration_seconds'), 0.0),
        'tls_trust_fallback_count': len(tls_trust_fallback_urls),
        'tls_trust_fallback_urls': sorted(tls_trust_fallback_urls),
        'explicit_entry_points': len(explicit_seed_urls),
        'priority_discovery_seeds': len(ordinary_seed_urls),
    }
    if skipped_out_of_scope:
        preview = ', '.join(sorted(out_of_scope_origins)[:4]) or 'external origin(s)'
        extra = max(0, len(out_of_scope_origins) - 4)
        suffix = f', +{extra} more' if extra else ''
        print(
            f'[SCOPE] Observed {skipped_out_of_scope} out-of-scope URL(s) across '
            f'{len(out_of_scope_origins)} external origin(s); they were NOT queued for active testing: {preview}{suffix}'
        )
    browser_external_origins = list(browser_budget_info.get('external_origins_observed') or [])
    browser_external_requests = int(browser_budget_info.get('external_subresource_requests', 0) or 0)
    browser_blocked_navigations = int(browser_budget_info.get('external_navigation_requests_blocked', 0) or 0)
    if browser_external_origins or browser_external_requests or browser_blocked_navigations:
        preview = ', '.join(browser_external_origins[:4]) or 'external origin(s)'
        extra = max(0, len(browser_external_origins) - 4)
        suffix = f', +{extra} more' if extra else ''
        print(
            f'[SCOPE] Chromium observed {browser_external_requests} ordinary out-of-scope subresource request(s) '
            f'across {len(browser_external_origins)} external origin(s); these were rendering/auth dependencies only '
            f'and were NOT queued for active testing. Blocked external top-level navigations: '
            f'{browser_blocked_navigations}. Origins: {preview}{suffix}'
        )

    result = {'urls': sorted(visited), 'html_urls': sorted(html_urls), 'form_urls': sorted(form_urls), 'parameterized_urls': sorted(parameterized), 'request_cases': _dedupe_request_cases(request_cases), 'script_urls': sorted(script_urls), 'script_endpoint_hints': script_endpoint_hints, 'browser_network_requests': browser_network_requests, 'browser_navigation_urls': browser_navigation_urls, 'client_side_candidates': client_side_candidates, 'jwt_tokens': sorted(tokens), 'errors': errors, 'authentication_effective': auth_effective, 'authentication_note': auth_note, 'authentication_probe': auth_probe, 'target_preparation': target_preparation, 'destructive_urls_skipped': sorted(destructive_skipped), 'destructive_request_cases': _dedupe_request_cases(destructive_request_cases), 'coverage_skipped_cases': coverage_skipped_cases, 'budget_diagnostics': budget_diagnostics, 'same_host_service_discovery': same_host_service_discovery, 'same_host_service_discoveries': [same_host_service_discovery] if same_host_service_discovery.get('enabled') else [], 'explicit_entry_points': sorted(explicit_seed_urls), 'priority_discovery_seeds': sorted(ordinary_seed_urls), 'proactive_service_roots': sorted(discovered_service_roots)}
    if expand_authorized_service_hosts:
        result = expand_discovered_authorized_host_services(result, target, cookies, max_pages=max_pages, allow_state_changes=allow_state_changes)
    return result

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
def discover_target_sync_safe(
    target: str, cookies: str, max_pages: int=MAX_CRAWL_PAGES, seeds: list[str] | None=None,
    forced_seeds: list[str] | None=None, *, expand_authorized_service_hosts: bool=True,
    same_host_service_candidate_cap: int | None=None, allow_state_changes: bool=False,
) -> dict[str, Any]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return discover_target(
            target, cookies, max_pages=max_pages, seeds=seeds, forced_seeds=forced_seeds,
            expand_authorized_service_hosts=expand_authorized_service_hosts,
            same_host_service_candidate_cap=same_host_service_candidate_cap,
            allow_state_changes=allow_state_changes,
        )
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix='secops-discovery') as executor:
        return executor.submit(
            discover_target, target, cookies, max_pages, seeds, forced_seeds,
            expand_authorized_service_hosts=expand_authorized_service_hosts,
            same_host_service_candidate_cap=same_host_service_candidate_cap,
            allow_state_changes=allow_state_changes,
        ).result()

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


def select_sibling_broad_origins(
    discovery: dict[str, Any], target: str, *,
    allowed_origins: set[str] | None=None, exclude_origins: set[str] | None=None,
) -> dict[str, Any]:
    ranking = discovered_scope_origin_ranking(discovery, target)
    allowed = {normalized_origin(value) for value in (allowed_origins or set()) if normalized_origin(value)} if allowed_origins is not None else None
    excluded = {normalized_origin(value) for value in (exclude_origins or set()) if normalized_origin(value)}
    if allowed is not None:
        ranking = [(origin, score) for origin, score in ranking if origin in allowed]
    if excluded:
        ranking = [(origin, score) for origin, score in ranking if origin not in excluded]
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


def authenticated_broad_target(discovery: dict[str, Any], origin: str, raw_profile_cookie: str='') -> str:
    """Return a safe application URL on an origin where the authenticated cookie is actually applicable.

    Browser sessions can be path-scoped. Treating ``https://host/`` as authenticated merely because
    another path on that host has a valid session either drops coverage or widens a cookie incorrectly.
    Broad authenticated scanners therefore start from the highest-value discovered non-static URL for
    which the same concrete cookie-scope function used by specialists returns a credential.
    """
    normalized = normalized_origin(origin)
    if not normalized:
        return ''
    candidates: list[str] = [normalized + '/']
    for key in ('html_urls', 'browser_navigation_urls', 'parameterized_urls', 'urls'):
        for value in discovery.get(key, []) or []:
            url = str(value or '').strip()
            if url and same_origin(normalized, url):
                candidates.append(url)
    for key in ('request_cases', 'browser_network_requests'):
        for row in discovery.get(key, []) or []:
            if not isinstance(row, dict):
                continue
            url = str(row.get('url') or '').strip()
            if url and same_origin(normalized, url):
                candidates.append(url)

    unique: list[str] = []
    seen: set[str] = set()
    for url in candidates:
        if url in seen or _browser_static_resource(url) or _destructive_crawl_url(url) or _ephemeral_identity_flow_url(url):
            continue
        seen.add(url)
        unique.append(url)
    unique.sort(key=lambda url: (0 if url.rstrip('/') == normalized else 1, -_discovery_url_score(url), len(url), url))
    for url in unique:
        if scope_cookie_header(url, raw_profile_cookie):
            return url
    return ''


def sibling_broad_timeout(tool: str, base_timeout: float | int | None=None) -> int:
    scanner = str(tool or '').lower()
    if base_timeout is None:
        base_timeout = BROAD_SCANNER_TIMEOUTS.get(scanner, 180)
    factor = float(BROAD_SIBLING_TIMEOUT_FACTORS.get(CURRENT_SCAN_MODE, 0.60))
    minimum = TEST_SCANNER_TIMEOUT_SECONDS if CURRENT_SCAN_MODE == 'test' else 45
    return max(minimum, int(float(base_timeout) * factor))


def discovered_scope_origins(discovery: dict[str, Any], target: str, limit: int | None=None) -> list[str]:
    ranking = discovered_scope_origin_ranking(discovery, target)
    if limit is None:
        return [origin for origin, _ in ranking]
    return [origin for origin, _ in ranking[:max(0, int(limit))]]


def _runtime_auth_candidate_urls(discovery: dict[str, Any], origin: str, *, limit: int | None=None) -> list[str]:
    scored: dict[str, int] = {}

    def add(value: Any, bonus: int=0) -> None:
        url = str(value or '').strip()
        if not url or not same_origin(origin, url) or _destructive_crawl_url(url):
            return
        try:
            parsed = urlparse(url)
        except ValueError:
            return
        if _volatile_identity_callback_url(url):
            # The callback values are one-time, but the application login route itself is a useful
            # stable SSO entry point for a fresh browser context.
            url = urlunparse(parsed._replace(query='', fragment=''))
            parsed = urlparse(url)
        path = str(parsed.path or '/').lower()
        suffix = Path(path).suffix.lower()
        if suffix in PARAMETER_SCANNER_STATIC_SUFFIXES or suffix in {'.html.map'}:
            return
        # One-shot OAuth/OIDC transaction URLs are poor reauthentication entry points;
        # keep stable application login/SSO routes instead.
        if _ephemeral_identity_flow_url(url):
            return
        score = _discovery_url_score(url) + int(bonus)
        if _looks_like_application_login_entry(url):
            score += 160
        if any(token in path for token in ('management', 'dashboard', 'editor', 'admin')):
            score += 35
        if parsed.query:
            score += min(20, len(parse_qsl(parsed.query, keep_blank_values=True)) * 3)
        scored[url] = max(scored.get(url, -10_000), score)

    for value in discovery.get('html_urls', []):
        add(value, 45)
    for value in discovery.get('browser_navigation_urls', []):
        add(value, 55)
    for row in discovery.get('request_cases', []):
        if isinstance(row, dict):
            add(row.get('url'), 65)
    for row in discovery.get('browser_network_requests', []):
        if isinstance(row, dict):
            resource_type = str(row.get('resource_type') or '').lower()
            add(row.get('url'), 60 if resource_type in {'document', 'xhr', 'fetch'} else 20)
    for value in discovery.get('urls', []):
        add(value, 10)
    effective_limit = max(1, int(limit if limit is not None else RUNTIME_AUTH_ENTRY_CANDIDATE_LIMITS.get(CURRENT_SCAN_MODE, 12)))
    return [url for url, _ in sorted(scored.items(), key=lambda item: (-item[1], item[0]))[:effective_limit]]


def _runtime_auth_probe(origin: str, cookie: str, probe_url: str) -> dict[str, Any]:
    authenticated = scanner_session_probe(probe_url, cookie, timeout=12, attempts=2)
    if authenticated.get('conclusive') and authenticated.get('authenticated') is False:
        return {
            'usable': False,
            'distinguished_from_anonymous': False,
            'authenticated_probe': authenticated,
            'anonymous_probe': {},
        }
    anonymous: dict[str, Any] = {}
    distinguished: bool | None = None
    try:
        _pace_http_request()
        response = request_same_origin_redirects(
            'GET', probe_url,
            headers={'Cache-Control': 'no-cache', 'User-Agent': 'SecOps-Runtime-Auth-Anonymous/1.0'},
            timeout=(4, 12), allow_state_changes=False,
        )
        anonymous = {
            'status': int(response.status_code),
            'final_url': str(response.url),
            'login_detected': _looks_like_login(response),
            'bytes': len(response.content),
        }
        auth_status = int(authenticated.get('status') or 0)
        auth_final = str(authenticated.get('final_url') or '')
        if anonymous['login_detected'] or (response.status_code in {401, 403} and 0 < auth_status < 400):
            distinguished = True
        elif auth_final and same_origin(origin, auth_final) and same_origin(origin, str(response.url)) and _clean_url(auth_final) != _clean_url(str(response.url)):
            distinguished = True
        else:
            distinguished = None
    except requests.RequestException as exc:
        anonymous = {'error': f'{type(exc).__name__}: {exc}', 'conclusive': False}
    return {
        'usable': authenticated.get('authenticated') is not False,
        'distinguished_from_anonymous': distinguished,
        'authenticated_probe': authenticated,
        'anonymous_probe': anonymous,
    }



def _runtime_application_scope_key(url: str) -> str:
    """Group authentication attempts by generic application root, not by one whole origin.

    Different applications can share scheme/host/port while maintaining independent server-side
    sessions. The first path segment is a conservative, application-agnostic boundary that avoids
    treating every individual endpoint as a separate login while allowing /appA and /appB to obtain
    different sessions when the platform's SSO flow requires it.
    """
    try:
        parsed = urlparse(str(url or ''))
    except ValueError:
        return ''
    origin = normalized_origin(url)
    if not origin:
        return ''
    segments = [segment for segment in str(parsed.path or '/').split('/') if segment]
    scope_path = '/' if not segments else f'/{segments[0]}/'
    return origin + scope_path


def ensure_runtime_authenticated_request(request_url: str, current_cookie: str='', probe_url: str='', timeout_seconds: int | None=None) -> dict[str, Any]:
    """Establish or refresh one authorized application session for the owning identity.

    Runtime browser/OIDC state is selected from the Cookie fingerprint resolved by the parent runner.
    Multiple identities may therefore refresh independently without sharing storage state, credentials
    or application-attempt caches. No child-console prompt occurs.
    """
    url = str(request_url or '').strip()
    runtime_state = _runtime_target_auth_for_cookie(current_cookie)
    identity_ref = str(runtime_state.get('reference') or '') if runtime_state else ''
    if not url or not runtime_target_auth_available(current_cookie, url) or not url_in_authorized_scope(PRIMARY_SCOPE_TARGET or url, url):
        return {'attempted': False, 'usable': bool(scope_cookie_header(url, current_cookie)), 'cookie_header': scope_cookie_header(url, current_cookie)}
    if _destructive_crawl_url(url) or _browser_static_resource(url) or _ephemeral_identity_flow_url(url):
        return {'attempted': False, 'usable': bool(scope_cookie_header(url, current_cookie)), 'cookie_header': scope_cookie_header(url, current_cookie), 'reason': 'request_not_runtime_auth_candidate'}

    scope_key = _runtime_application_scope_key(url)
    if not scope_key:
        return {'attempted': False, 'usable': False, 'cookie_header': '', 'reason': 'invalid_request_origin'}
    attempt_key = f'{identity_ref}|{scope_key}'

    cached = RUNTIME_AUTH_APPLICATION_ATTEMPTS.get(attempt_key)
    cached_cookie = scope_cookie_header(url, current_cookie)
    if isinstance(cached, dict) and cached.get('status') == 'authenticated' and cached_cookie:
        return {**cached, 'attempted': False, 'reused': True, 'cookie_header': cached_cookie}
    previous_attempts = int(cached.get('attempt_count', 0) or 0) if isinstance(cached, dict) else 0
    previous_urls = {str(value) for value in (cached.get('attempted_urls') or [])} if isinstance(cached, dict) else set()
    if isinstance(cached, dict) and cached.get('status') == 'failed' and (previous_attempts >= 3 or url in previous_urls):
        return {**cached, 'attempted': False, 'reused': True, 'cookie_header': cached_cookie}

    credential = dict(runtime_state.get('credential')) if isinstance(runtime_state.get('credential'), dict) else {}
    if timeout_seconds is not None:
        credential['timeout_seconds'] = max(15, int(timeout_seconds))
    username = str(runtime_state.get('username') or '')
    password = str(runtime_state.get('password') or '')
    storage_state = runtime_state.get('storage_state') if isinstance(runtime_state.get('storage_state'), dict) else None
    candidate_urls = [url]
    if probe_url and same_origin(url, probe_url) and str(probe_url) != url:
        candidate_urls.append(str(probe_url))

    try:
        login = browser_oidc_login_session(
            normalized_origin(url),
            username,
            password,
            credential,
            storage_state=storage_state,
            candidate_urls=candidate_urls,
            initial_login=False,
            include_configured_fallbacks=False,
            expected_oidc_issuer=str(runtime_state.get('oidc_issuer') or ''),
        )
    except RuntimeError as exc:
        attempted_urls = (
            list(exc.attempted_candidates)
            if isinstance(exc, BrowserLoginError) and exc.attempted_candidates
            else [url]
        )
        result = {
            'attempted': True,
            'usable': False,
            'status': 'failed',
            'identity_ref': identity_ref,
            'scope_key': scope_key,
            'request_url': url,
            'reason': str(exc)[:1200],
            'cookie_header': '',
            'attempt_count': previous_attempts + 1,
            'attempted_urls': sorted(previous_urls | {str(value) for value in attempted_urls}),
        }
        RUNTIME_AUTH_APPLICATION_ATTEMPTS[attempt_key] = dict(result)
        return result

    if isinstance(login.get('storage_state'), dict):
        runtime_state['storage_state'] = login['storage_state']
    if login.get('oidc_issuer') and not runtime_state.get('oidc_issuer'):
        runtime_state['oidc_issuer'] = str(login.get('oidc_issuer') or '')
    returned_cookie = str(login.get('cookie_header') or '')
    if returned_cookie:
        _register_runtime_cookie_alias(returned_cookie, identity_ref)
    origin = normalized_origin(url)
    if returned_cookie and origin and not same_origin(PRIMARY_SCOPE_TARGET or origin, origin):
        register_authenticated_origin_cookie(origin, returned_cookie, current_cookie)

    effective_cookie = _runtime_storage_cookie_header(url, current_cookie) or returned_cookie
    if not effective_cookie:
        result = {
            'attempted': True,
            'usable': False,
            'status': 'failed',
            'identity_ref': identity_ref,
            'scope_key': scope_key,
            'request_url': url,
            'reason': 'browser authentication completed without a cookie applicable to the concrete request URL',
            'cookie_header': '',
            'attempt_count': previous_attempts + 1,
            'attempted_urls': sorted(previous_urls | {url}),
        }
        RUNTIME_AUTH_APPLICATION_ATTEMPTS[attempt_key] = dict(result)
        return result

    validation_url = str(login.get('final_url') or '')
    if not validation_url or not same_origin(origin, validation_url) or _browser_static_resource(validation_url):
        validation_url = url
    probe = _runtime_auth_probe(origin, effective_cookie, validation_url)
    flow_observed = safe_bool_metadata(login.get('authentication_flow_observed'), False)
    usable = probe.get('usable') is not False and (probe.get('distinguished_from_anonymous') is True or flow_observed)
    result = {
        'attempted': True,
        'usable': bool(usable),
        'status': 'authenticated' if usable else 'failed',
        'identity_ref': identity_ref,
        'scope_key': scope_key,
        'request_url': url,
        'entry_url': str(login.get('entry_url') or ''),
        'final_url': str(login.get('final_url') or ''),
        'probe_url': validation_url,
        'cookie_header': effective_cookie if usable else '',
        'cookie_names': cookie_names(effective_cookie) if usable else [],
        'sso_reused': safe_bool_metadata(login.get('sso_reused'), False),
        'credentials_reused': safe_bool_metadata(login.get('used_credentials'), False),
        'authentication_flow_observed': flow_observed,
        'distinguished_from_anonymous': probe.get('distinguished_from_anonymous'),
        'probe': probe,
        'attempt_count': previous_attempts + 1,
        'attempted_urls': sorted(previous_urls | {url}),
    }
    if not usable:
        result['reason'] = 'runtime authentication did not produce a usable application session'
    RUNTIME_AUTH_APPLICATION_ATTEMPTS[attempt_key] = dict(result)
    return result


def _same_origin_application_auth_candidates(discovery: dict[str, Any], target: str, identity_cookies: str='') -> list[tuple[str, int, list[str]]]:
    """Rank same-origin application roots that expose their own login/SSO entry points."""
    primary_origin = normalized_origin(target)
    runtime_state = _runtime_target_auth_for_cookie(identity_cookies)
    credential = runtime_state.get('credential') if isinstance(runtime_state.get('credential'), dict) else {}
    configured_login = urljoin(target.rstrip('/') + '/', str(credential.get('login_path') or '/').lstrip('/'))
    configured_scope = _runtime_application_scope_key(configured_login)
    buckets: dict[str, dict[str, Any]] = {}

    def add(raw: Any, bonus: int=0) -> None:
        url = str(raw or '').strip()
        if not url or not same_origin(primary_origin, url) or _destructive_crawl_url(url):
            return
        if _browser_static_resource(url) or _ephemeral_identity_flow_url(url):
            return
        if _volatile_identity_callback_url(url):
            parsed_callback = urlparse(url)
            url = urlunparse(parsed_callback._replace(query='', fragment=''))
        scope_key = _runtime_application_scope_key(url)
        if not scope_key or scope_key == configured_scope:
            return
        try:
            path = str(urlparse(url).path or '/').lower()
        except ValueError:
            return
        login_signal = ('ssologin' in path) or any(token in path for token in ('/login', '/signin', '/sign-in'))
        bucket = buckets.setdefault(scope_key, {'score': -1000, 'candidates': [], 'login_signal': False})
        score = _discovery_url_score(url) + int(bonus) + (220 if 'ssologin' in path else 120 if login_signal else 0)
        bucket['score'] = max(int(bucket['score']), score)
        bucket['login_signal'] = bool(bucket['login_signal'] or login_signal)
        if url not in bucket['candidates']:
            bucket['candidates'].append(url)

    for value in discovery.get('html_urls', []):
        add(value, 45)
    for value in discovery.get('browser_navigation_urls', []):
        add(value, 55)
    for row in discovery.get('request_cases', []):
        if isinstance(row, dict):
            add(row.get('url'), 65)
    for row in discovery.get('browser_network_requests', []):
        if isinstance(row, dict):
            resource_type = str(row.get('resource_type') or '').lower()
            add(row.get('url'), 70 if resource_type in {'document', 'xhr', 'fetch'} else 20)

    ranked: list[tuple[str, int, list[str]]] = []
    for scope_key, bucket in buckets.items():
        # Proactive authentication is reserved for roots with an observed login/SSO entry point.
        # Other roots remain eligible for just-in-time reauthentication if a concrete scanner precheck
        # later demonstrates that the current session is not valid there.
        if not bucket.get('login_signal'):
            continue
        candidates = sorted(
            bucket['candidates'],
            key=lambda value: (
                0 if 'ssologin' in urlparse(value).path.lower() else 1,
                -_discovery_url_score(value),
                value,
            ),
        )[:max(1, int(RUNTIME_AUTH_ENTRY_CANDIDATE_LIMITS.get(CURRENT_SCAN_MODE, 12)))]
        ranked.append((scope_key, int(bucket['score']), candidates))
    return sorted(ranked, key=lambda item: (-item[1], item[0]))


def authenticate_discovered_sibling_origins(discovery: dict[str, Any], target: str, primary_cookies: str, *, allow_state_changes: bool=False) -> dict[str, Any]:
    """Create independent sessions for authorized sibling origins observed by authenticated discovery.

    This function never copies the primary Cookie header. It first imports the original browser SSO
    storage state. If the IdP asks for credentials again, it reuses only the username/password already
    resolved by assessmentRunner and never prompts from inside the orchestrator process.
    """
    if not primary_cookies or not runtime_target_auth_available(primary_cookies):
        return discovery

    evidence = _discovered_scope_origin_evidence(discovery, target)
    ranking = discovered_scope_origin_ranking(discovery, target)
    limit = max(1, int(RUNTIME_AUTH_ORIGIN_LIMITS.get(CURRENT_SCAN_MODE, 32)))
    broad_priority_origins = {
        origin for origin, _ in ranking[:max(1, int(BROAD_SIBLING_ORIGIN_MAX_LIMITS.get(CURRENT_SCAN_MODE, 5)))]
    }
    eligible: list[tuple[str, int, list[str]]] = []
    for origin, score in ranking:
        if not url_in_authorized_scope(target, origin):
            continue
        bucket = evidence.get(origin, {})
        candidates = _runtime_auth_candidate_urls(discovery, origin)
        if not candidates:
            continue
        # Static-only sibling origins do not trigger a login. Any interactive evidence or an actual
        # non-static application candidate is sufficient; this remains generic and site-independent.
        if int(bucket.get('interactive', 0) or 0) <= 0 and int(bucket.get('observations', 0) or 0) <= 1:
            continue
        login_signal = any(_looks_like_application_login_entry(url) for url in candidates)
        storage_signal = any(bool(_runtime_storage_cookie_header(url, primary_cookies)) for url in candidates)
        # Do not launch a browser-login attempt for every public sibling merely because it was linked
        # by a large portal. High-ranked broad origins, explicit login/SSO entries and origins already
        # touched by browser SSO state remain eligible; lower-ranked public-only origins can still use
        # the just-in-time path if a concrete authenticated scanner later demonstrates a login gate.
        if origin not in broad_priority_origins and not login_signal and not storage_signal:
            continue
        eligible.append((origin, score, candidates))

    runtime_rows: list[dict[str, Any]] = list(discovery.get('runtime_sibling_authentication') or [])
    known_authenticated = {
        str(row.get('origin') or '') for row in runtime_rows
        if isinstance(row, dict) and row.get('status') in {'authenticated', 'reused'} and str(row.get('origin') or '')
    }
    failed_attempted_urls: dict[str, set[str]] = {}
    for row in runtime_rows:
        if not isinstance(row, dict) or str(row.get('status') or '') not in {'failed', 'failed_validation'}:
            continue
        origin = str(row.get('origin') or '')
        if not origin:
            continue
        values = row.get('attempted_candidates') if isinstance(row.get('attempted_candidates'), list) else []
        failed_attempted_urls.setdefault(origin, set()).update(str(value) for value in values if str(value))
    pending: list[tuple[str, int, list[str]]] = []
    for item in eligible:
        origin, _, candidates = item
        if authenticated_origin_cookie(origin, primary_cookies):
            continue
        attempted = failed_attempted_urls.get(origin, set())
        if attempted and all(candidate in attempted for candidate in candidates):
            continue
        pending.append(item)
    selected = pending[:limit]
    if len(pending) > limit:
        runtime_rows.append({
            'status': 'limit',
            'eligible_origins': len(eligible),
            'pending_origins': len(pending),
            'attempted_origin_limit': limit,
            'message': f'Runtime sibling authentication origin limit reached in {CURRENT_SCAN_MODE}; {len(pending) - limit} lower-ranked unauthenticated origin(s) were not attempted in this pass.',
        })

    runtime_state = _runtime_target_auth_for_cookie(primary_cookies)
    identity_ref = str(runtime_state.get('reference') or '')
    credential = dict(runtime_state.get('credential')) if isinstance(runtime_state.get('credential'), dict) else {}
    username = str(runtime_state.get('username') or '')
    password = str(runtime_state.get('password') or '')
    storage_state = runtime_state.get('storage_state') if isinstance(runtime_state.get('storage_state'), dict) else None
    merged = discovery
    primary_auth_effective = discovery.get('authentication_effective')
    primary_auth_note = discovery.get('authentication_note')
    primary_auth_probe = discovery.get('authentication_probe')
    primary_budget = dict(discovery.get('budget_diagnostics') or {})
    recrawl_minimum = 1 if CURRENT_SCAN_MODE == 'test' else 10
    auth_timeout_minimum = 1 if CURRENT_SCAN_MODE == 'test' else 30
    recrawl_pages = max(recrawl_minimum, int(RUNTIME_AUTH_RECRAWL_PAGES.get(CURRENT_SCAN_MODE, 60)))
    auth_pass_budget = max(auth_timeout_minimum, int(RUNTIME_AUTH_PASS_TIMEOUTS.get(CURRENT_SCAN_MODE, 720)))
    auth_pass_deadline = time.monotonic() + auth_pass_budget

    # Existing origin-specific cookies are retained across repeated enrichment passes without consuming
    # the current authentication-attempt budget.
    for origin, score, _ in eligible:
        existing = authenticated_origin_cookie(origin, primary_cookies)
        if existing and origin not in known_authenticated:
            runtime_rows.append({'origin': origin, 'status': 'reused', 'cookie_names': cookie_names(existing), 'score': score})
            known_authenticated.add(origin)

    attempted_count = 0
    for origin, score, candidates in selected:
        remaining_auth = auth_pass_deadline - time.monotonic()
        if remaining_auth < (2.0 if CURRENT_SCAN_MODE == 'test' else 15.0):
            runtime_rows.append({
                'status': 'time_budget', 'deferred_origins': max(1, len(selected) - attempted_count),
                'attempted_origins': attempted_count, 'time_budget_seconds': auth_pass_budget,
                'message': 'Shared runtime-authentication pass budget exhausted; remaining origins are deferred and remain eligible on a later pass.',
            })
            break
        print(f'    [AUTH SSO] {origin}: attempting origin-specific SSO/session establishment from {len(candidates)} observed application entry point(s).', flush=True)
        attempted_count += 1
        attempt_credential = dict(credential)
        login_minimum = 2 if CURRENT_SCAN_MODE == 'test' else 15
        configured_login_timeout = max(login_minimum, int(attempt_credential.get('timeout_seconds') or 60))
        attempt_credential['timeout_seconds'] = max(login_minimum, min(configured_login_timeout, int(remaining_auth)))
        try:
            login = browser_oidc_login_session(
                origin,
                username,
                password,
                attempt_credential,
                storage_state=storage_state,
                candidate_urls=candidates,
                initial_login=False,
                include_configured_fallbacks=False,
                expected_oidc_issuer=str(runtime_state.get('oidc_issuer') or ''),
            )
        except RuntimeError as exc:
            message = str(exc)
            # Authentication is origin/application specific. Record only entry points the browser
            # actually reached before its shared deadline; unvisited candidates remain eligible on a
            # later enrichment pass instead of being falsely exhausted.
            attempted_candidates = (
                list(exc.attempted_candidates)
                if isinstance(exc, BrowserLoginError) and exc.attempted_candidates
                else list(candidates[:1])
            )
            runtime_rows.append({'origin': origin, 'status': 'failed', 'reason': message[:1000], 'score': score, 'candidate_count': len(candidates), 'attempted_candidates': attempted_candidates})
            print(f'    [AUTH SSO] {origin}: automatic sibling authentication failed: {message}', file=sys.stderr, flush=True)
            continue

        sibling_cookie = str(login.get('cookie_header') or '')
        if not sibling_cookie:
            runtime_rows.append({'origin': origin, 'status': 'failed', 'reason': 'browser login returned no origin cookie', 'score': score, 'attempted_candidates': [str(login.get('entry_url') or candidates[0])] if candidates else []})
            continue
        _register_runtime_cookie_alias(sibling_cookie, identity_ref)
        register_authenticated_origin_cookie(origin, sibling_cookie, primary_cookies)
        if isinstance(login.get('storage_state'), dict):
            storage_state = login['storage_state']
            runtime_state['storage_state'] = storage_state
        if login.get('oidc_issuer') and not runtime_state.get('oidc_issuer'):
            runtime_state['oidc_issuer'] = str(login.get('oidc_issuer') or '')

        probe_url = str(login.get('final_url') or '')
        if not probe_url or not same_origin(origin, probe_url) or _browser_static_resource(probe_url):
            origin_view = discovery_for_origin(merged, origin, primary_cookies)
            probe_url = select_session_probe_url(origin_view, origin)
        probe = _runtime_auth_probe(origin, sibling_cookie, probe_url)
        flow_observed = safe_bool_metadata(login.get('authentication_flow_observed'), False)
        if probe.get('usable') is False or (probe.get('distinguished_from_anonymous') is not True and not flow_observed):
            AUTHENTICATED_ORIGIN_COOKIES.pop((identity_ref, normalized_origin(origin)), None)
            runtime_rows.append({
                'origin': origin,
                'status': 'failed_validation',
                'score': score,
                'probe_url': probe_url,
                'authentication_flow_observed': flow_observed,
                'probe': probe,
                'reason': 'HTTP validation failed or no authentication-flow evidence distinguished this cookie from an incidental public cookie.',
                'attempted_candidates': [str(login.get('entry_url') or candidates[0])] if candidates else [],
            })
            print(f'    [AUTH SSO] {origin}: browser state did not provide sufficient evidence for an authenticated application session.', file=sys.stderr, flush=True)
            continue

        runtime_rows.append({
            'origin': origin,
            'status': 'authenticated',
            'score': score,
            'entry_url': str(login.get('entry_url') or ''),
            'probe_url': probe_url,
            'cookie_names': cookie_names(sibling_cookie),
            'sso_reused': safe_bool_metadata(login.get('sso_reused'), False),
            'credentials_reused': safe_bool_metadata(login.get('used_credentials'), False),
            'authentication_flow_observed': flow_observed,
            'distinguished_from_anonymous': probe.get('distinguished_from_anonymous'),
            'probe': probe,
        })
        mode = 'existing SSO state' if login.get('sso_reused') else 'the original username/password'
        print(f'    [AUTH SSO] {origin}: origin session established using {mode}; cookie names: {", ".join(cookie_names(sibling_cookie)) or "none"}.', flush=True)

        # Revisit the sibling with its own session so protected menus/pages can contribute request
        # contracts that the first anonymous sibling pass could not see. Only evidence from this
        # sibling is merged back, preventing a recursive cross-origin expansion loop.
        try:
            recrawl = discover_target(
                origin, sibling_cookie, max_pages=recrawl_pages, seeds=candidates,
                expand_authorized_service_hosts=False, same_host_service_candidate_cap=0,
                allow_state_changes=allow_state_changes,
            )
            recrawl = discovery_for_origin(recrawl, origin, primary_cookies)
            recrawl['authentication_effective'] = probe.get('distinguished_from_anonymous') if probe.get('distinguished_from_anonymous') is not None else True
            recrawl['authentication_note'] = 'Origin-specific runtime OIDC/SSO session established and used for authenticated sibling re-discovery.'
            recrawl['authentication_probe'] = probe
            merged = merge_discovery(merged, recrawl)
        except Exception as exc:
            runtime_rows[-1]['recrawl_error'] = f'{type(exc).__name__}: {exc}'
            print(f'    [AUTH SSO] {origin}: authenticated re-discovery failed but the validated origin cookie remains available: {type(exc).__name__}: {exc}', file=sys.stderr, flush=True)


    # Applications can also keep independent sessions while sharing the same origin. Proactively
    # revisit application roots that exposed their own login/SSO wrapper; all other paths still have
    # the just-in-time fallback in refresh_authenticated_session_state().
    application_rows: list[dict[str, Any]] = list(discovery.get('runtime_application_authentication') or [])
    app_limit = max(1, int(RUNTIME_AUTH_APPLICATION_LIMITS.get(CURRENT_SCAN_MODE, 18)))
    app_recrawl_minimum = 1 if CURRENT_SCAN_MODE == 'test' else 10
    app_recrawl_pages = max(app_recrawl_minimum, int(RUNTIME_AUTH_APPLICATION_RECRAWL_PAGES.get(CURRENT_SCAN_MODE, 72)))
    app_ranked = _same_origin_application_auth_candidates(merged, target, primary_cookies)
    app_attempted = 0
    app_authenticated = 0
    for scope_key, score, candidates in app_ranked[:app_limit]:
        if not candidates:
            continue
        remaining_auth = auth_pass_deadline - time.monotonic()
        if remaining_auth < (2.0 if CURRENT_SCAN_MODE == 'test' else 15.0):
            application_rows.append({
                'status': 'time_budget', 'attempted_applications': app_attempted,
                'time_budget_seconds': auth_pass_budget,
                'message': 'Shared runtime-authentication pass budget exhausted; remaining application scopes are deferred.',
            })
            break
        entry_url = candidates[0]
        result = ensure_runtime_authenticated_request(
            entry_url, primary_cookies, entry_url, timeout_seconds=max(2 if CURRENT_SCAN_MODE == 'test' else 15, min(60, int(remaining_auth)))
        )
        app_attempted += 1 if result.get('attempted') else 0
        row = {
            'application_scope': scope_key,
            'status': str(result.get('status') or ('authenticated' if result.get('usable') else 'failed')),
            'score': score,
            'entry_url': entry_url,
            'candidate_count': len(candidates),
            'cookie_names': list(result.get('cookie_names') or []),
            'sso_reused': safe_bool_metadata(result.get('sso_reused'), False),
            'credentials_reused': safe_bool_metadata(result.get('credentials_reused'), False),
            'reason': str(result.get('reason') or '')[:1000],
        }
        application_rows.append(row)
        if not result.get('usable'):
            continue
        app_authenticated += 1
        app_cookie = scope_cookie_header(entry_url, primary_cookies) or str(result.get('cookie_header') or '')
        if not app_cookie:
            row['status'] = 'failed_validation'
            row['reason'] = 'No application/path cookie remained applicable after runtime authentication.'
            continue
        try:
            recrawl = discover_target(
                scope_key, app_cookie, max_pages=app_recrawl_pages, seeds=candidates,
                expand_authorized_service_hosts=False, same_host_service_candidate_cap=0,
                allow_state_changes=allow_state_changes,
            )
            recrawl = discovery_for_origin(recrawl, normalized_origin(target), primary_cookies)
            recrawl['authentication_effective'] = True
            recrawl['authentication_note'] = 'Application-specific runtime OIDC/SSO session established and used for same-origin authenticated re-discovery.'
            recrawl['authentication_probe'] = result.get('probe') if isinstance(result.get('probe'), dict) else {}
            merged = merge_discovery(merged, recrawl)
        except Exception as exc:
            row['recrawl_error'] = f'{type(exc).__name__}: {exc}'

    # Authenticated recrawls may expose additional already-authorized hostnames that were invisible
    # to the initial profile discovery. Expand service/port discovery once from the merged surface,
    # after all authentication recrawls, so newly observed hosts are covered without recursive fan-out.
    merged = expand_discovered_authorized_host_services(
        merged, target, primary_cookies, max_pages=recrawl_pages,
        allow_state_changes=allow_state_changes,
    )

    # Sibling recrawls must not overwrite the authentication verdict or the discovery budget of the
    # primary profile. Their state is reported separately below.
    merged['authentication_effective'] = primary_auth_effective
    merged['authentication_note'] = primary_auth_note
    merged['authentication_probe'] = primary_auth_probe
    merged['runtime_sibling_authentication'] = runtime_rows
    merged['runtime_application_authentication'] = application_rows
    auth_origins = {
        str(row.get('origin') or '') for row in runtime_rows
        if isinstance(row, dict) and row.get('status') in {'authenticated', 'reused'} and str(row.get('origin') or '')
    }
    merged['budget_diagnostics'] = {
        **dict(merged.get('budget_diagnostics') or primary_budget),
        'runtime_auth_origin_limit': limit,
        'runtime_auth_origins_eligible': len(eligible),
        'runtime_auth_origins_attempted': attempted_count,
        'runtime_auth_origins_authenticated': len(auth_origins),
        'runtime_auth_application_limit': app_limit,
        'runtime_auth_applications_eligible': len(app_ranked),
        'runtime_auth_applications_attempted': app_attempted,
        'runtime_auth_applications_authenticated': app_authenticated,
    }
    return merged


# Filters discovery evidence to one origin so broad scanners can test sibling origins independently without sharing cookies.
def discovery_for_origin(discovery: dict[str, Any], origin: str, identity_cookies: str='') -> dict[str, Any]:
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
    sibling_cookie = authenticated_origin_cookie(origin, identity_cookies)
    filtered['authentication_effective'] = True if sibling_cookie else None
    filtered['authentication_note'] = 'Sibling authorized origin uses its own runtime OIDC/SSO session.' if sibling_cookie else 'Sibling authorized origin is scanned without reusing the primary-origin cookie.'
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
    merged['explicit_entry_points'] = sorted(set(left.get('explicit_entry_points', [])) | set(right.get('explicit_entry_points', [])))
    merged['priority_discovery_seeds'] = sorted(set(left.get('priority_discovery_seeds', [])) | set(right.get('priority_discovery_seeds', [])))
    if right.get('authentication_probe'):
        merged['authentication_probe'] = right.get('authentication_probe')
    if right.get('authentication_effective') is not None:
        merged['authentication_effective'] = right.get('authentication_effective')
        merged['authentication_note'] = right.get('authentication_note')
    left_budget = left.get('budget_diagnostics') if isinstance(left.get('budget_diagnostics'), dict) else {}
    right_budget = right.get('budget_diagnostics') if isinstance(right.get('budget_diagnostics'), dict) else {}
    merged['budget_diagnostics'] = {**left_budget, **right_budget}
    return merged

# Returns authorized origins actually evidenced by the current discovery snapshot. Port expansion is
# host-level: multiple paths/applications on the same hostname do not trigger duplicate TCP sweeps.
def _observed_authorized_origins(discovery: dict[str, Any], target: str) -> list[str]:
    values: list[str] = [str(target or '')]
    for key in ('urls', 'html_urls', 'form_urls', 'parameterized_urls', 'script_urls', 'browser_navigation_urls', 'explicit_entry_points', 'priority_discovery_seeds', 'proactive_service_roots'):
        values.extend(str(value) for value in discovery.get(key, []) if isinstance(value, str))
    for key in ('request_cases', 'browser_network_requests', 'script_endpoint_hints', 'client_side_candidates'):
        for row in discovery.get(key, []) or []:
            if isinstance(row, dict):
                values.append(str(row.get('url') or ''))
                values.append(str(row.get('source_url') or ''))
    origins: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or not url_in_authorized_scope(target, value):
            continue
        origin = normalized_origin(value)
        if not origin or origin in seen:
            continue
        seen.add(origin)
        origins.append(origin)
    return origins


def _service_expansion_host_ranking(discovery: dict[str, Any], target: str) -> list[tuple[str, str, int]]:
    primary_host = normalized_hostname(urlparse(normalize_url(target)).hostname or '')
    evidence = _discovered_scope_origin_evidence(discovery, target)
    hosts: dict[str, dict[str, Any]] = {}
    for origin in _observed_authorized_origins(discovery, target):
        parsed = urlparse(origin)
        host = normalized_hostname(parsed.hostname or '')
        if not host or host == primary_host:
            continue
        bucket = hosts.setdefault(host, {'origin': origin, 'score': -1000, 'observations': 0})
        origin_evidence = evidence.get(origin, {})
        score = int(origin_evidence.get('max_score', _discovery_url_score(origin)))
        score += min(24, int(origin_evidence.get('observations', 0) or 0))
        score += min(24, int(origin_evidence.get('interactive', 0) or 0))
        bucket['score'] = max(int(bucket['score']), score)
        bucket['observations'] = int(bucket['observations']) + max(1, int(origin_evidence.get('observations', 0) or 0))
        # Prefer an observed origin with stronger application evidence as the HTTP authority used
        # for address selection and the bounded recrawl entry point.
        if score >= int(bucket.get('origin_score', -1000)):
            bucket['origin'] = origin
            bucket['origin_score'] = score
    ranked = [(host, str(row['origin']), int(row['score']) + min(16, int(row['observations']))) for host, row in hosts.items()]
    return sorted(ranked, key=lambda item: (-item[2], item[0], item[1]))


def _service_discovery_row_has_probe_coverage(row: dict[str, Any]) -> bool:
    """Return True only when a prior service-discovery row represents real probe coverage.

    DNS/pre-probe failures and deadline exhaustion before the first candidate remain retryable in a
    later bounded expansion pass. Cached rows and rows that actually probed at least one candidate
    are complete enough to suppress a duplicate sweep of the same exact hostname.
    """
    if not isinstance(row, dict):
        return False
    if safe_bool_metadata(row.get('cache_hit'), False):
        return True
    try:
        ports_probed = int(row.get('ports_probed', 0) or 0)
    except (TypeError, ValueError):
        ports_probed = 0
    try:
        reused_ports = int(row.get('reused_ports_probed', 0) or 0)
    except (TypeError, ValueError):
        reused_ports = 0
    return ports_probed > 0 or reused_ports > 0


def expand_discovered_authorized_host_services(
    discovery: dict[str, Any], target: str, cookies: str, *, max_pages: int=MAX_CRAWL_PAGES,
    allow_state_changes: bool=False,
) -> dict[str, Any]:
    """Expand proactive HTTP/HTTPS port discovery to newly observed, already-authorized hostnames.

    The configured per-mode port candidate budget is reused as one shared expansion budget and is
    divided across the newly observed hostnames. This broadens host coverage without multiplying the
    port-probe budget by the number of discovered origins. No hostname is authorized by this helper.
    """
    if not DISCOVER_SAME_HOST_SERVICES or not ALLOW_SAME_HOST_PORTS:
        return discovery
    limits = DISCOVERY_LIMITS.get(CURRENT_SCAN_MODE, DISCOVERY_LIMITS['balanced'])
    host_limit = max(0, int(limits.get('same_host_service_expansion_hosts', 0) or 0))
    total_candidate_budget = max(0, int(limits.get('same_host_service_candidates', 0) or 0))
    if host_limit <= 0 or total_candidate_budget <= 0:
        return discovery
    ranked = _service_expansion_host_ranking(discovery, target)
    already_scanned_hosts = {
        normalized_hostname(str(row.get('expansion_hostname') or row.get('hostname') or ''))
        for row in discovery.get('same_host_service_discoveries', [])
        if (
            isinstance(row, dict)
            and str(row.get('expansion_hostname') or row.get('hostname') or '').strip()
            and _service_discovery_row_has_probe_coverage(row)
        )
    }
    pending_ranked = [item for item in ranked if item[0] not in already_scanned_hosts]
    selected = pending_ranked[:host_limit]
    if not selected:
        base_budget = dict(discovery.get('budget_diagnostics') or {})
        base_budget.update({
            'same_host_service_expansion_hosts_observed': len(ranked),
            'same_host_service_expansion_hosts_already_scanned': len(ranked) - len(pending_ranked),
            'same_host_service_expansion_hosts_pending': len(pending_ranked),
            'same_host_service_expansion_hosts_scanned': 0,
            'same_host_service_expansion_candidate_budget': total_candidate_budget,
            'same_host_service_expansion_candidate_budget_consumed': 0,
            'same_host_service_expansion_candidate_budget_remaining': total_candidate_budget,
            'same_host_service_expansion_ports_probed': 0,
            'same_host_service_expansion_web_services_discovered': 0,
        })
        result = dict(discovery)
        result['budget_diagnostics'] = base_budget
        return result

    # Cached hosts consume no new TCP candidate/time budget. Split the shared candidate budget only
    # across exact hostnames that have not already been scanned during this assessment process.
    uncached_hosts = [host for host, _, _ in selected if _cached_same_host_service_discovery(host) is None]
    uncached_count = len(uncached_hosts)
    # Candidate capacity is a shared expansion pool just like wall-clock time. Allocate an equal
    # share of what remains to each still-pending uncached host, then subtract only the ports that
    # were actually probed. If DNS fails or a host reaches its time share early, the unused
    # candidate capacity is therefore recycled fairly among the remaining hosts instead of being
    # stranded in an allocation that was never exercised.
    remaining_candidate_budget = total_candidate_budget
    remaining_uncached_hosts = uncached_count
    merged = discovery
    primary_budget = dict(discovery.get('budget_diagnostics') or {})
    primary_auth_effective = discovery.get('authentication_effective')
    primary_auth_note = discovery.get('authentication_note')
    primary_auth_probe = discovery.get('authentication_probe')
    primary_target_preparation = discovery.get('target_preparation')
    all_discoveries = list(discovery.get('same_host_service_discoveries') or [])
    all_roots = set(str(value) for value in discovery.get('proactive_service_roots', []) if str(value))
    ports_probed = 0
    reused_ports = 0
    candidate_ports_deferred = 0
    tcp_connection_attempts = 0
    resolved_address_count = 0
    classification_deferred_ports = 0
    web_services_discovered = 0
    roots_recrawled = 0
    hosts_newly_scanned = 0
    hosts_reused_cached = 0
    hosts_deferred_time_budget = 0
    hosts_failed_before_probe = 0
    scan_errors: list[dict[str, Any]] = []
    recrawl_pages = max(1, min(int(max_pages), int(limits.get('same_host_service_expansion_recrawl_pages', max_pages) or max_pages)))

    for index, (host, origin, score) in enumerate(selected):
        cached_before = _cached_same_host_service_discovery(host) is not None
        if cached_before:
            # Any positive cap reaches the host-level cache; no TCP work is performed.
            host_cap = 1
            host_time_budget = 0.0
        else:
            if remaining_uncached_hosts <= 0 or remaining_candidate_budget <= 0:
                continue
            quotient, remainder = divmod(remaining_candidate_budget, remaining_uncached_hosts)
            host_cap = quotient + (1 if remainder else 0)
            if host_cap <= 0:
                continue
            remaining_time = _same_host_service_time_remaining_seconds()
            # Fairly share BOTH remaining candidate capacity and remaining wall-clock time over
            # the exact hostnames still waiting to be scanned. Unused capacity from this host is
            # recycled after the call based on actual ports_probed.
            host_time_budget = remaining_time / remaining_uncached_hosts if remaining_time > 0 else 0.0
        scan = discover_same_host_web_services(
            origin, candidate_cap=host_cap, time_budget_seconds=host_time_budget,
        )
        scan_row = dict(scan)
        scan_row['expansion_origin'] = origin
        scan_row['expansion_hostname'] = host
        scan_row['evidence_score'] = score
        scan_row['expansion_candidate_cap'] = host_cap
        scan_row['expansion_time_budget_seconds'] = round(host_time_budget, 3)
        scan_row['expansion_allocation_policy'] = 'equal-share-of-remaining-time-and-candidates-with-unused-capacity-recycled'
        all_discoveries.append(scan_row)
        current_ports = int(scan.get('ports_probed', 0) or 0)
        ports_probed += current_ports
        reused_ports += int(scan.get('reused_ports_probed', 0) or 0)
        candidate_ports_deferred += int(scan.get('candidate_ports_deferred', 0) or 0)
        tcp_connection_attempts += int(scan.get('tcp_connection_attempts', 0) or 0)
        resolved_address_count += int(scan.get('resolved_address_count', 0) or 0)
        classification_deferred_ports += len(scan.get('classification_deferred_ports') or [])
        if not cached_before:
            remaining_candidate_budget = max(0, remaining_candidate_budget - current_ports)
            remaining_uncached_hosts = max(0, remaining_uncached_hosts - 1)
        if scan.get('cache_hit'):
            hosts_reused_cached += 1
        elif current_ports > 0:
            # Count a new TCP sweep only when at least one candidate port was actually probed.
            # DNS/address-resolution failures can consume wall-clock time without performing any
            # TCP probe and must not inflate the coverage counter.
            hosts_newly_scanned += 1
        elif scan.get('time_budget_exhausted'):
            hosts_deferred_time_budget += 1
        elif scan.get('error'):
            hosts_failed_before_probe += 1
        roots = [
            _clean_url(str(row.get('url') or ''))
            for row in scan.get('web_services', [])
            if isinstance(row, dict) and row.get('url') and url_in_authorized_scope(target, str(row.get('url')))
        ]
        roots = list(dict.fromkeys(root for root in roots if root))
        web_services_discovered += len(roots)
        all_roots.update(roots)
        if not roots:
            if scan.get('error'):
                scan_errors.append({'url': origin, 'type': 'ServiceDiscoveryExpansion', 'message': str(scan.get('error'))})
            continue
        try:
            # One bounded recrawl per hostname is sufficient; all newly classified service roots are
            # priority seeds. Nested port expansion is disabled to prevent recursive host fan-out.
            recrawl = discover_target(
                origin, cookies, max_pages=recrawl_pages, seeds=roots,
                expand_authorized_service_hosts=False, same_host_service_candidate_cap=0,
                allow_state_changes=allow_state_changes,
            )
            roots_recrawled += len(roots)
            merged = merge_discovery(merged, recrawl)
        except Exception as exc:
            scan_errors.append({'url': origin, 'type': 'ServiceDiscoveryRecrawl', 'message': f'{type(exc).__name__}: {exc}'})

    merged = dict(merged)
    # Expansion recrawls contribute surface only. They must not overwrite the authentication verdict,
    # authentication probe or target-preparation state of the profile that initiated discovery.
    merged['authentication_effective'] = primary_auth_effective
    merged['authentication_note'] = primary_auth_note
    merged['authentication_probe'] = primary_auth_probe
    merged['target_preparation'] = primary_target_preparation
    merged['same_host_service_discoveries'] = all_discoveries
    merged['proactive_service_roots'] = sorted(all_roots)
    if scan_errors:
        merged['errors'] = [*merged.get('errors', []), *scan_errors]
    merged['budget_diagnostics'] = {
        **primary_budget,
        'same_host_service_expansion_hosts_observed': len(ranked),
        'same_host_service_expansion_hosts_already_scanned': len(ranked) - len(pending_ranked),
        'same_host_service_expansion_hosts_pending': len(pending_ranked),
        'same_host_service_expansion_host_limit': host_limit,
        'same_host_service_expansion_hosts_scanned': hosts_newly_scanned,
        'same_host_service_expansion_hosts_reused_cached': hosts_reused_cached,
        'same_host_service_expansion_hosts_deferred_time_budget': hosts_deferred_time_budget,
        'same_host_service_expansion_hosts_failed_before_probe': hosts_failed_before_probe,
        'same_host_service_expansion_hosts_considered': len(selected),
        'same_host_service_expansion_candidate_budget': total_candidate_budget,
        'same_host_service_expansion_candidate_budget_consumed': ports_probed,
        'same_host_service_expansion_candidate_budget_remaining': max(0, remaining_candidate_budget),
        'same_host_service_expansion_ports_probed': ports_probed,
        'same_host_service_expansion_reused_ports_probed': reused_ports,
        'same_host_service_expansion_candidate_ports_deferred': candidate_ports_deferred,
        'same_host_service_expansion_tcp_connection_attempts': tcp_connection_attempts,
        'same_host_service_expansion_resolved_address_count': resolved_address_count,
        'same_host_service_expansion_classification_deferred_ports': classification_deferred_ports,
        'same_host_service_expansion_web_services_discovered': web_services_discovered,
        'same_host_service_expansion_roots_recrawled': roots_recrawled,
        'same_host_service_expansion_time_allocation_policy': 'equal-share-of-remaining-time-and-candidates-with-unused-capacity-recycled',
        'same_host_service_expansion_recrawl_pages_per_host': recrawl_pages,
        'same_host_service_global_time_budget_seconds': _same_host_service_time_limits()[0],
        'same_host_service_global_time_remaining_seconds': round(_same_host_service_time_remaining_seconds(), 3),
    }
    return merged

# URL ranking relies on a small set of security-related words to prioritize discovered paths.
def _risk_terms(value: str) -> int:
    text = value.lower()
    tokens = set(re.findall('[a-z0-9]+', text))
    weights = {'cmd': 12, 'command': 12, 'exec': 12, 'shell': 12, 'sql': 11, 'query': 8, 'search': 7, 'file': 10, 'path': 10, 'include': 10, 'template': 9, 'upload': 8, 'url': 9, 'uri': 8, 'redirect': 8, 'callback': 8, 'webhook': 8, 'admin': 8, 'role': 8, 'user': 6, 'uid': 7, 'id': 5, 'token': 7, 'debug': 7, 'api': 5, 'xml': 7, 'deserialize': 10, 'xss': 10, 'sqli': 11, 'ssrf': 11, 'lfi': 11, 'rfi': 11}
    return sum((weight for term, weight in weights.items() if (term in tokens if len(term) <= 3 else term in text)))

# Request classification marks cases that belong to an authentication flow.
def _is_login_case(case: dict[str, Any]) -> bool:
    parsed = urlparse(str(case.get('url', '')))
    path = str(parsed.path or '').lower()
    parameters = {str(value).lower() for value in case.get('parameters', [])}
    path_tokens = {token for token in re.split(r'[^a-z0-9]+', path) if token}
    protocol_parameters = {str(name).lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    login_tokens = {'login', 'signin', 'authenticate', 'authorize', 'sso'}
    protocol_signal = bool(protocol_parameters & {'client_id', 'redirect_uri', 'response_type', 'code_challenge'})
    return bool(path_tokens & login_tokens) or protocol_signal or bool({'username', 'password'} <= parameters)

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
            'parameters': _query_parameter_names(url),
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
IDOR_HINTS = {'id', 'uid', 'uuid', 'guid', 'user_id', 'userid', 'account_id', 'accountid', 'object_id', 'objectid', 'item_id', 'itemid', 'order_id', 'orderid', 'document_id', 'documentid', 'file_id', 'fileid', 'profile_id', 'profileid', 'dashboardid', 'widgetid', 'deviceid', 'modelid'}
IDOR_PROTOCOL_PARAMETER_NAMES = {'state', 'nonce', 'code', 'session_state', 'execution', 'tab_id', 'auth_session_id', 'session_code'}
IDOR_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')
IDOR_HEX_RE = re.compile(r'^[0-9a-fA-F]{8,64}$')
IDOR_DIGIT_RUN_RE = re.compile(r'\d+')

# Returns a deterministic nearby reference only for bounded object-id shapes. It deliberately
# avoids transient identity-protocol values and does not guess arbitrary free-text identifiers.
def _mutated_object_reference(name: str, value: str) -> str | None:
    key = str(name or '').lower()
    raw = str(value or '')
    if key not in IDOR_HINTS or key in IDOR_PROTOCOL_PARAMETER_NAMES or not raw:
        return None
    if raw.isdigit():
        return str(int(raw) + 1)
    if IDOR_UUID_RE.fullmatch(raw):
        chars = list(raw)
        for index in range(len(chars) - 1, -1, -1):
            if chars[index].lower() in '0123456789abcdef':
                chars[index] = '0' if chars[index].lower() != '0' else '1'
                return ''.join(chars)
    if IDOR_HEX_RE.fullmatch(raw) and any(ch.lower() in 'abcdef' for ch in raw):
        width = len(raw)
        return format((int(raw, 16) + 1) % (16 ** width), f'0{width}x')
    matches = list(IDOR_DIGIT_RUN_RE.finditer(raw))
    if matches:
        match = matches[-1]
        digits = match.group(0)
        replacement = str(int(digits) + 1).zfill(len(digits))
        return raw[:match.start()] + replacement + raw[match.end():]
    return None


def _object_reference_pairs(url: str) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for name, value in parse_qsl(urlparse(str(url or '')).query, keep_blank_values=True):
        mutated = _mutated_object_reference(name, value)
        if mutated is not None and mutated != value:
            rows.append((str(name), str(value), mutated))
    return rows
NAVIGATION_PARAMETERS = {'pagetitle', 'linkid', 'fromsubmenu', 'showframe', 'redirect', 'linkurl'}

PARAMETER_SCANNER_STATIC_SUFFIXES = {
    '.css', '.js', '.mjs', '.map', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.wav', '.mp4', '.webm',
}
DALFOX_NON_HTML_STATIC_SUFFIXES = PARAMETER_SCANNER_STATIC_SUFFIXES - {'.js', '.mjs'}
STATIC_CACHE_PARAMETER_NAMES = {
    'v', 'ver', 'version', 'rev', 'revision', 'hash', 'cb', 'cache', 'cachebust', 'cachebuster',
    'timestamp', 'ts', 't', '_',
}
IDENTITY_PROTOCOL_PARAMETERS = {
    'client_id', 'redirect_uri', 'response_type', 'response_mode', 'scope', 'state', 'nonce',
    'code_challenge', 'code_challenge_method', 'prompt', 'tab_id', 'execution', 'session_code',
    'auth_session_id', 'kc_action', 'kc_locale', 'iss', 'skip_logout',
}

# Static browser assets remain useful discovery evidence. Only obvious cache/version variants are
# globally excluded from request-level injection scanners: a script such as app.js?resource=... can
# still represent a dynamic application surface, while app.js?v=1 or style.css?<blank-cache-key>
# cannot consume specialist breadth merely because the browser recorded it.
def _parameter_scanner_static_asset(case: dict[str, Any]) -> bool:
    url = str(case.get('url') or '')
    suffix = Path(urlparse(url).path.lower()).suffix
    if suffix not in PARAMETER_SCANNER_STATIC_SUFFIXES:
        return False
    pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    if not pairs:
        return True
    return all((not str(value).strip()) or str(name).lower() in STATIC_CACHE_PARAMETER_NAMES for name, value in pairs)

# Dalfox specifically needs an HTML/JavaScript execution context. CSS/font/image/media responses are
# not direct XSS targets even when they expose a functional query parameter; JavaScript with a real
# application parameter remains eligible because reflected script-context injection can be relevant.
def _dalfox_non_html_static_asset(case: dict[str, Any]) -> bool:
    suffix = Path(urlparse(str(case.get('url') or '')).path.lower()).suffix
    return suffix in DALFOX_NON_HTML_STATIC_SUFFIXES

# OAuth/OIDC protocol metadata can contain many volatile values and absolute callback URLs. Keep
# actual login/form inputs eligible, but do not spend injection-scanner budgets on a pure protocol
# negotiation request made only of standard identity metadata.
def _identity_protocol_metadata_only(case: dict[str, Any]) -> bool:
    path = urlparse(str(case.get('url') or '')).path.lower()
    parameters = _case_parameters(case)
    if _volatile_identity_callback_url(str(case.get('url') or '')):
        return True
    protocol_path = any(token in path for token in ('/protocol/openid-connect/', '/oauth2/', '/oauth/', '/authorize', '/login-actions/'))
    return bool(protocol_path and parameters and parameters <= IDENTITY_PROTOCOL_PARAMETERS)

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
    parameters = {value.lower() for value in _clean_case_parameter_names(case.get('parameters', []))}
    parsed = urlparse(str(case.get('url', '')))
    parameters.update((name.lower() for name, _ in _filtered_query_pairs(parsed.query)))
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
            value = unquote(unquote(str(raw or ''))).strip()
        except Exception:
            value = str(raw or '').strip()
        lowered = value.lower()
        if not lowered:
            continue
        if lowered.startswith('file:'):
            return True
        # Absolute/protocol-relative web URLs are navigation or remote-fetch values rather than
        # local-file selectors. Local paths, encoded traversal sequences and file: values remain eligible.
        parsed_value = urlparse(value)
        if lowered.startswith('//') or parsed_value.scheme.lower() in {'http', 'https'} or parsed_value.netloc:
            continue
        if INTERNAL_RESOURCE_VALUE_PATTERN.search(lowered):
            return True
        if '../' in lowered or '..%2f' in lowered or '..\\' in lowered or lowered.startswith('/etc/'):
            return True
    return False

# A redirect/link wrapper whose routing values are exclusively absolute web URLs belongs to open-
# redirect/SSRF/navigation analysis, not local-file traversal. Relative/local values are deliberately
# left eligible because they may still select application resources without a filename extension.
def _traversal_absolute_web_routing_only(case: dict[str, Any]) -> bool:
    routing_names = {'redirect', 'linkurl'}
    pairs = [(name.lower(), str(value or '').strip()) for name, value in parse_qsl(urlparse(str(case.get('url', ''))).query, keep_blank_values=True) if name.lower() in routing_names]
    for field in case.get('fields', []) if isinstance(case.get('fields'), list) else []:
        if isinstance(field, dict) and str(field.get('name') or '').lower() in routing_names:
            pairs.append((str(field.get('name') or '').lower(), str(field.get('value') or '').strip()))
    if not pairs:
        return False
    saw_absolute = False
    for _, raw in pairs:
        try:
            value = unquote(unquote(raw)).strip()
        except Exception:
            value = raw.strip()
        parsed = urlparse(value)
        if value.startswith('//') or parsed.scheme.lower() in {'http', 'https'} or parsed.netloc:
            saw_absolute = True
            continue
        return False
    return saw_absolute

# Traversal/LFI execution requires a parameter-level file/path/routing signal. Generic route risk alone
# is intentionally insufficient: mutating an unrelated dashboard id, role or sort parameter with file
# payloads wastes the reserve without improving LFI coverage. Unknown parameter names remain eligible
# when their observed value already looks like a local resource or traversal sequence.
def _traversal_case_signal(case: dict[str, Any]) -> bool:
    if _parameter_values_reference_internal_resource(case):
        return True
    parameters = _case_parameters(case)
    if parameters & (TRAVERSAL_HINTS - {'redirect', 'linkurl'}):
        return True
    if parameters & {'redirect', 'linkurl'}:
        return not _traversal_absolute_web_routing_only(case)
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
    if tool in {'sqlmap', 'dalfox', 'commix', 'traversal', 'idor'} and _parameter_scanner_static_asset(case):
        return -1000
    if tool == 'dalfox' and _dalfox_non_html_static_asset(case):
        return -1000
    if tool in {'sqlmap', 'dalfox', 'commix', 'traversal'} and _identity_protocol_metadata_only(case):
        return -1000
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
        status = safe_int_metadata(browser_response.get('status'), 0)
        if 200 <= status < 400:
            score += 10
        elif status in {404, 410}:
            score -= 80
        elif status >= 500:
            score += 4
    if tool == 'sqlmap':
        score += 45 if any((token in path for token in ('sql', 'query', 'database', 'search'))) else 0
        score += 18 if any((token in path for token in ('/api', 'data', 'device', 'model', 'dashboard', 'widget'))) else 0
        score += 14 * len(parameters & SQL_HINTS)
        score += 16 if method == 'POST' else 0
        score += 12 if 'json' in str(case.get('content_type') or case.get('enctype') or '').lower() else 0
        score += 8 if case.get('discovery_source') == 'playwright_network' else 0
        if parameters and parameters <= NAVIGATION_PARAMETERS and not (parameters & SQL_HINTS) and not anonymous_login_flow:
            score -= 65
        if 'brute' in path and (not any((token in path for token in ('sql', 'query', 'database')))):
            score -= 90
        if any((token in path for token in ('xss', '/exec', '/csp'))) and (not parameters & SQL_HINTS):
            score -= 35
        return max(score, 12) if anonymous_login_flow else score
    if tool == 'dalfox':
        if _prefer_browser_for_xss_case(case):
            return -1000
        score += 45 if any((token in path for token in ('xss', 'comment', 'message', 'search', 'feedback'))) else 0
        score += 12 * len(parameters & XSS_HINTS)
        score += 10 if case.get('discovery_source') == 'playwright_network' else 0
        if any((token in path for token in ('sqli', '/exec', '/csp'))) and (not parameters & XSS_HINTS):
            score -= 35
        return max(score, 12) if anonymous_login_flow else score
    if tool == 'commix':
        score += 55 if any((token in path for token in ('/exec', 'command', 'cmd'))) else 0
        score += 13 * len(parameters & COMMAND_HINTS)
        if any((token in path for token in ('sqli', 'xss', '/csp'))) and (not parameters & COMMAND_HINTS):
            score -= 45
        return max(score, 12) if anonymous_login_flow else score
    if tool == 'traversal':
        internal_resource_value = _parameter_values_reference_internal_resource(case)
        if not _traversal_case_signal(case):
            return -1000
        score += 55 if any((token in path for token in ('include', 'download', 'file', 'template', 'document', 'view'))) else 0
        score += 15 * len(parameters & TRAVERSAL_HINTS)
        # Application-agnostic signal: the parameter VALUE (not its name) already looks like it
        # selects a server-side file/module, e.g. redirect=devices.php. This catches routing-by-
        # filename parameters that a name-only hint list would miss under an unrelated name.
        if internal_resource_value:
            score += 40
        if any((token in path for token in ('sqli', 'xss', '/exec', '/csp'))) and (not parameters & TRAVERSAL_HINTS):
            score -= 45
        return max(score, 12) if anonymous_login_flow else score
    if tool == 'idor':
        if method != 'GET':
            return -1000
        object_pairs = _object_reference_pairs(str(case.get('url') or ''))
        if not object_pairs or any((token in path for token in ('brute', 'csrf', 'password', 'sqli', 'xss', '/exec', '/csp'))):
            return -1000
        score = 20 + 28 * len(object_pairs)
        score += 25 if any((token in path for token in ('idor', 'object', 'profile', 'account', 'user'))) else 0
        return score
    return score

# Returns only hard compatibility/safety exclusions for a request-level scanner. These rules may
# determine whether a concrete action exists at all; heuristic vulnerability-class ranking must not.
def tool_case_hard_skip_reason(tool: str, case: dict[str, Any]) -> str:
    name = str(tool or '').lower()
    if not _clean_case_parameter_names(case.get('parameters', [])):
        return 'The request has no testable application parameter for this parameter scanner.'
    if _is_auto_index_case(case):
        return 'Directory-index sorting parameters are navigation controls, not application inputs.'
    if name in {'sqlmap', 'dalfox', 'commix', 'traversal', 'idor'} and _parameter_scanner_static_asset(case):
        return 'Static cache/version asset variants are retained for discovery/source analysis but are not direct request-level injection targets.'
    if name == 'dalfox' and _dalfox_non_html_static_asset(case):
        return 'Non-HTML CSS/font/image/media assets are retained for discovery but are not direct Dalfox XSS targets.'
    if name in {'sqlmap', 'dalfox', 'commix', 'traversal'} and _identity_protocol_metadata_only(case):
        return 'Pure OAuth/OIDC protocol metadata is excluded from generic injection scanning; concrete application login/form inputs remain eligible.'
    if name == 'traversal' and not _traversal_case_signal(case):
        if _traversal_absolute_web_routing_only(case):
            return 'Absolute HTTP(S) redirect/link values are navigation/SSRF-style inputs, not local-file traversal targets.'
        return 'Traversal/LFI requires a file/path/routing parameter or an observed local-resource value.'
    if name in {'sqlmap', 'dalfox', 'commix', 'traversal'} and _is_logout_case(case):
        return f'{name} is not sent to logout endpoints; authenticated logout is handled only by the final session-lifecycle check.'
    if name in {'sqlmap', 'dalfox', 'commix', 'traversal'} and _oversized_generated_request(case):
        return f'{name} is not sent to oversized generated table/filter requests because they are unsuitable bounded specialist contracts.'
    if name == 'idor':
        method = str(case.get('method', 'GET')).upper()
        url = str(case.get('url') or '')
        path = urlparse(url).path.lower()
        if method != 'GET' or not _object_reference_pairs(url):
            return 'IDOR requires a read-only GET request containing a concrete object-reference value.'
        if any(token in path for token in ('brute', 'csrf', 'password', 'sqli', 'xss', '/exec', '/csp')):
            return 'The request belongs to a different specialized test class and is not an IDOR object-reference contract.'
    return ''


# Explains why deterministic specialist selection excludes a request. It includes the hard rules above
# plus deterministic routing/ranking preferences used only by the fixed pipeline.
def _tool_case_skip_reason(tool: str, case: dict[str, Any], authenticated_profile: bool=False) -> str:
    hard_reason = tool_case_hard_skip_reason(tool, case)
    if hard_reason:
        return hard_reason
    if tool == 'dalfox' and _prefer_browser_for_xss_case(case):
        return 'Stored or DOM-oriented XSS contracts are delegated to the Chromium verifier, which can execute JavaScript and revisit state.'
    if tool == 'sqlmap' and 'brute' in urlparse(str(case.get('url', ''))).path.lower():
        return 'The brute-force handler is an authentication workflow, not a SQL-query request class.'
    if _tool_case_priority(tool, case, authenticated_profile=authenticated_profile) <= 0:
        if CURRENT_SCAN_MODE == 'deep' and case.get('deep_breadth') and tool in {'sqlmap', 'dalfox'}:
            return ''
        return f"The request was not selected because its path and parameters do not match {tool}'s vulnerability class."
    return ''

# Groups request contracts by origin and leading application path so one very large module cannot
# consume every specialist slot while other discovered application families receive no validation.
def _request_case_family(case: dict[str, Any]) -> tuple[str, str]:
    url = str(case.get('url') or '')
    origin = normalized_origin(url)
    path = urlparse(url).path or '/'
    segments = [segment.lower() for segment in path.split('/') if segment]
    family = '/' + '/'.join(segments[:2]) if segments else '/'
    return origin, family


# Reorders ranked candidates so the highest-ranked case from each discovered application family is
# considered before a second case from the same family. Scores still determine order inside each pass.
def _family_fair_ranked_cases(ranked: list[tuple[int, dict[str, Any]]]) -> list[tuple[int, dict[str, Any]]]:
    if len(ranked) < 2:
        return list(ranked)
    buckets: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = {}
    family_order: list[tuple[str, str]] = []
    for item in ranked:
        family = _request_case_family(item[1])
        if family not in buckets:
            buckets[family] = []
            family_order.append(family)
        buckets[family].append(item)
    if len(family_order) < 2:
        return list(ranked)
    output: list[tuple[int, dict[str, Any]]] = []
    depth = 0
    while True:
        layer = [buckets[family][depth] for family in family_order if depth < len(buckets[family])]
        if not layer:
            break
        layer.sort(key=lambda item: -int(item[0]))
        output.extend(layer)
        depth += 1
    return output


# Generic live-input breadth is separate from vulnerability-class ranking. It admits only concrete
# application traffic so unfamiliar parameter names do not become invisible on large applications.
def _generic_live_input_case(tool: str, case: dict[str, Any]) -> bool:
    name = str(tool or '').lower()
    if name not in {'sqlmap', 'dalfox', 'commix'}:
        return False
    url = str(case.get('url') or '')
    method = str(case.get('method') or 'GET').upper()
    if method not in {'GET', 'POST'} or not url or not _clean_case_parameter_names(case.get('parameters', [])):
        return False
    if _destructive_crawl_url(url) or _is_logout_case(case) or _oversized_generated_request(case):
        return False
    if _parameter_scanner_static_asset(case) or _identity_protocol_metadata_only(case):
        return False
    if name == 'dalfox' and (_dalfox_non_html_static_asset(case) or _prefer_browser_for_xss_case(case)):
        return False
    response = case.get('browser_response') if isinstance(case.get('browser_response'), dict) else {}
    status = safe_int_metadata(response.get('status'), 0)
    observed_live = response.get('observed') is True and 200 <= status < 400
    source = str(case.get('discovery_source') or case.get('source') or '').lower()
    network_live = source in {'playwright_network', 'browser_network', 'xhr', 'fetch'} or any(token in source for token in ('playwright', 'xhr', 'fetch'))
    structured_post = method == 'POST' and bool(str(case.get('data') or '').strip())
    content_type = str(case.get('content_type') or case.get('enctype') or '').lower()
    json_or_form = structured_post and any(token in content_type for token in ('json', 'form'))
    return bool(observed_live or network_live or json_or_form)


def _append_generic_live_input_reserve(
    tool: str, selected: list[dict[str, Any]], candidates: list[dict[str, Any]], *,
    authenticated_profile: bool, credential_cookies: str,
) -> list[dict[str, Any]]:
    reserve = max(0, int(GENERIC_LIVE_INPUT_RESERVE.get(CURRENT_SCAN_MODE, {}).get(str(tool or '').lower(), 0)))
    if reserve <= 0:
        return selected
    output = list(selected)
    known: set[tuple[str, tuple[str, str, tuple[str, ...]], tuple[str, ...]]] = set()
    shape_counts: Counter[tuple[str, tuple[str, str, tuple[str, ...]], tuple[str, ...]]] = Counter()
    variant_cap = _specialist_variant_cap()
    for case in output:
        method = str(case.get('method') or 'GET').upper()
        params = tuple(sorted(str(v).lower() for v in case.get('parameters', []) if str(v)))
        key = (method, _semantic_request_url_key(str(case.get('url') or '')), params)
        known.add(key)
        shape_counts[(method, _specialist_route_signature(tool, str(case.get('url') or '')), params)] += 1
    eligible: list[tuple[int, int, dict[str, Any]]] = []
    for index, raw in enumerate(candidates):
        if not isinstance(raw, dict):
            continue
        params = _clean_case_parameter_names(raw.get('parameters', [])) or _query_parameter_names(str(raw.get('url') or ''))
        case = {**raw, 'parameters': params}
        if not _generic_live_input_case(tool, case):
            continue
        url = str(case.get('url') or '')
        method = str(case.get('method') or 'GET').upper()
        param_key = tuple(sorted(str(v).lower() for v in params if str(v)))
        key = (method, _semantic_request_url_key(url), param_key)
        shape = (method, _specialist_route_signature(tool, url), param_key)
        if key in known or shape_counts[shape] >= variant_cap:
            continue
        response = case.get('browser_response') if isinstance(case.get('browser_response'), dict) else {}
        score = 40
        score += 20 if response.get('observed') is True and 200 <= safe_int_metadata(response.get('status'), 0) < 400 else 0
        score += 18 if method == 'POST' else 0
        score += 14 if str(case.get('discovery_source') or '').lower() == 'playwright_network' else 0
        score += min(16, len(params) * 3)
        eligible.append((score, -index, case))
    added = 0
    fair_ranked = _family_fair_ranked_cases(
        [(score, case) for score, _, case in sorted(eligible, key=lambda row: (-row[0], -row[1]))]
    )
    for score, case in fair_ranked:
        if added >= reserve:
            break
        url = str(case.get('url') or '')
        method = str(case.get('method') or 'GET').upper()
        params = tuple(sorted(str(v).lower() for v in case.get('parameters', []) if str(v)))
        key = (method, _semantic_request_url_key(url), params)
        shape = (method, _specialist_route_signature(tool, url), params)
        if key in known or shape_counts[shape] >= variant_cap:
            continue
        case_authenticated = authenticated_profile and (not credential_cookies or bool(scope_cookie_header(url, credential_cookies)))
        skip_reason = _tool_case_skip_reason(tool, case, authenticated_profile=case_authenticated)
        if skip_reason and not skip_reason.startswith('The request was not selected because'):
            # The generic reserve may bypass only vulnerability-class ranking mismatch. All hard
            # exclusions (logout/static/identity/oversized/auto-index/special workflow cases)
            # remain binding exactly as they are for the ordinary specialist selector.
            continue
        output.append({**case, 'priority_score': int(score), 'coverage_reserve': True, 'selection_reason': 'generic-live-input-reserve'})
        known.add(key); shape_counts[shape] += 1; added += 1
    return output

# Chooses the best request cases for one scanner and scan profile.
def select_tool_request_cases(discovery: dict[str, Any], tool: str, limit: int | None=None, authenticated_profile: bool=False, allow_state_changes: bool=False, credential_cookies: str='', *, agentic_catalog: bool=False) -> list[dict[str, Any]]:

    effective_limit = int(limit or PARAMETER_TOOL_CASE_LIMITS.get(tool, MAX_PARAMETER_ENDPOINTS))
    cases = [case for case in discovery.get('request_cases', []) if isinstance(case, dict)]
    known = {str(case.get('url') or '') for case in cases}
    for value in discovery.get('parameterized_urls', []):
        url = str(value or '')
        if url and url not in known:
            cases.append({'url': url, 'method': 'GET', 'data': '', 'parameters': _query_parameter_names(url), 'source_url': url, 'synthetic_from_parameterized_url': True})
    if not allow_state_changes:
        cases = filter_request_cases_for_state_policy(cases, False)
    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            continue
        clean_parameters = _clean_case_parameter_names(case.get('parameters', []))
        if not clean_parameters:
            clean_parameters = _query_parameter_names(str(case.get('url') or ''))
        case = {**case, 'parameters': clean_parameters}
        browser_response = case.get('browser_response') if isinstance(case.get('browser_response'), dict) else {}
        if browser_response.get('observed') is True and safe_int_metadata(browser_response.get('status'), 0) in {404, 410}:
            continue
        if str(case.get('method', 'GET')).upper() not in {'GET', 'POST'}:
            continue
        if not case.get('parameters'):
            continue
        case_url = str(case.get('url') or '')
        case_authenticated = authenticated_profile and (not credential_cookies or bool(scope_cookie_header(case_url, credential_cookies)))
        score = _tool_case_priority(tool, case, authenticated_profile=case_authenticated)
        if score > 0:
            ranked.append((score, -index, case))
    # Agentic catalog mode exposes every structurally compatible concrete request to the AI.
    # Python may attach a heuristic score as evidence, but that score never decides visibility.
    # Exact request contracts are deduplicated; value variants are preserved because the model may
    # legitimately choose one and reject another. Deterministic mode keeps the bounded ranked selector.
    if agentic_catalog:
        catalog: list[dict[str, Any]] = []
        seen_catalog: set[tuple[str, tuple[str, str, tuple[tuple[str, str], ...]], str, tuple[str, ...]]] = set()
        for index, raw_case in enumerate(cases):
            if not isinstance(raw_case, dict):
                continue
            clean_parameters = _clean_case_parameter_names(raw_case.get('parameters', []))
            if not clean_parameters:
                clean_parameters = _query_parameter_names(str(raw_case.get('url') or ''))
            case = {**raw_case, 'parameters': clean_parameters}
            method = str(case.get('method', 'GET')).upper()
            url = str(case.get('url') or '')
            browser_response = case.get('browser_response') if isinstance(case.get('browser_response'), dict) else {}
            if browser_response.get('observed') is True and safe_int_metadata(browser_response.get('status'), 0) in {404, 410}:
                continue
            if method not in {'GET', 'POST'} or not url or not clean_parameters:
                continue
            if tool_case_hard_skip_reason(tool, case):
                continue
            case_authenticated = authenticated_profile and (not credential_cookies or bool(scope_cookie_header(url, credential_cookies)))
            heuristic = _tool_case_priority(tool, case, authenticated_profile=case_authenticated)
            key = (method, _semantic_request_url_key(url), str(case.get('data') or ''), tuple(sorted(str(v).lower() for v in clean_parameters if str(v))))
            if key in seen_catalog:
                continue
            seen_catalog.add(key)
            catalog.append({**case, 'priority_score': int(heuristic), 'selection_reason': 'agentic-structurally-compatible-candidate'})
        return catalog

    unique_ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    shape_counts: dict[tuple[str, tuple[str, str, tuple[str, ...]], tuple[str, ...]], int] = {}
    variant_cap = _specialist_variant_cap()
    for score, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
        method = str(case.get('method', 'GET')).upper()
        url = str(case.get('url', ''))
        params = tuple(sorted((str(value).lower() for value in case.get('parameters', []) if str(value))))
        key = (method, _semantic_request_url_key(url), params)
        shape = (method, _specialist_route_signature(tool, url), params)
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
            clean_parameters = _clean_case_parameter_names(case.get('parameters', []))
            if not clean_parameters:
                clean_parameters = _query_parameter_names(str(case.get('url') or ''))
            case = {**case, 'parameters': clean_parameters}
            method = str(case.get('method', 'GET')).upper()
            url = str(case.get('url') or '')
            path = urlparse(url).path.lower()
            params = [str(value) for value in case.get('parameters', []) if str(value)]
            if method != 'GET' or not url or not params or _is_auto_index_case(case) or _destructive_crawl_url(url):
                continue
            if _parameter_scanner_static_asset(case) or _identity_protocol_metadata_only(case) or (tool == 'dalfox' and _dalfox_non_html_static_asset(case)):
                continue
            case_authenticated = authenticated_profile and (not credential_cookies or bool(scope_cookie_header(url, credential_cookies)))
            if tool == 'sqlmap' and 'brute' in path:
                continue
            if tool == 'dalfox' and _prefer_browser_for_xss_case(case):
                continue
            param_key = tuple(sorted(value.lower() for value in params))
            key = (method, _semantic_request_url_key(url), param_key)
            shape = (method, _specialist_route_signature(tool, url), param_key)
            if key in seen or shape_counts.get(shape, 0) >= variant_cap:
                continue
            generic_score = _risk_terms(path + ' ' + ' '.join(params)) + min(18, len(params) * 4)
            extras.append((generic_score, -index, {**case, 'deep_breadth': True, 'selection_reason': f'deep-generic-{tool}-coverage'}))
        for score, _, case in sorted(extras, key=lambda item: (-item[0], -item[1]))[:extra_budget]:
            method = str(case.get('method', 'GET')).upper()
            url = str(case.get('url', ''))
            param_key = tuple(sorted((str(value).lower() for value in case.get('parameters', []) if str(value))))
            key = (method, _semantic_request_url_key(url), param_key)
            shape = (method, _specialist_route_signature(tool, url), param_key)
            if shape_counts.get(shape, 0) >= variant_cap:
                continue
            seen.add(key)
            shape_counts[shape] = shape_counts.get(shape, 0) + 1
            unique_ranked.append((int(score), case))
    unique_ranked = _family_fair_ranked_cases(unique_ranked)
    selected = _select_with_adaptive_specialist_budget(tool, unique_ranked, effective_limit)
    selected = _append_generic_live_input_reserve(
        tool, selected, cases, authenticated_profile=authenticated_profile, credential_cookies=credential_cookies,
    )
    if str(tool or '').lower() == 'traversal':
        reserve = max(len(selected), int(ROUTING_TRAVERSAL_RESERVE.get(CURRENT_SCAN_MODE, len(selected))))
        # Any already-selected GET contract whose value names an internal file/module belongs to
        # the same deterministic coverage reserve. Tag it now so Agentic expansion cannot dilute
        # the highest-ranked members of this class before it reaches the additional reserve cases.
        selected = [
            {
                **case,
                **({'coverage_reserve': True, 'selection_reason': 'routing-value-coverage-reserve'}
                   if str(case.get('method', 'GET')).upper() == 'GET'
                   and _parameter_values_reference_internal_resource(case)
                   and not _destructive_crawl_url(str(case.get('url') or ''))
                   else {}),
            }
            for case in selected
        ]
        known = {(str(case.get('method', 'GET')).upper(), str(case.get('url') or '')) for case in selected}
        for score, case in unique_ranked:
            if len(selected) >= reserve:
                break
            key = (str(case.get('method', 'GET')).upper(), str(case.get('url') or ''))
            if key in known or key[0] != 'GET' or not _parameter_values_reference_internal_resource(case):
                continue
            case_authenticated = authenticated_profile and (not credential_cookies or bool(scope_cookie_header(key[1], credential_cookies)))
            if _destructive_crawl_url(key[1]) or _tool_case_skip_reason('traversal', case, authenticated_profile=case_authenticated):
                continue
            selected.append({
                **case,
                'priority_score': int(score),
                'coverage_reserve': True,
                'selection_reason': 'routing-value-coverage-reserve',
            })
            known.add(key)
    return selected


# Structural context for completion accounting. Semantic routing values are retained by
# _semantic_request_url_key while ordinary value-only changes collapse to one context.
def _safe_surface_context_key(case: dict[str, Any]) -> tuple[str, tuple[str, str, tuple[tuple[str, str], ...]], tuple[str, ...]]:
    method = str(case.get('method') or 'GET').upper()
    url = str(case.get('url') or case.get('target_url') or '')
    params = _clean_case_parameter_names(case.get('parameters', [])) or _query_parameter_names(url)
    return method, _semantic_request_url_key(url), tuple(sorted(str(value).lower() for value in params if str(value)))


def _tested_surface_contexts(profile_results: dict[str, Any]) -> set[tuple[str, tuple[str, str, tuple[tuple[str, str], ...]], tuple[str, ...]]]:
    """Return only contexts with concrete evidence that a request-level test completed.

    Generic PARTIAL results do not prove that the attack request ran: partial can mean preflight,
    authentication, startup or timeout. Broad scanners contribute only their explicit completed
    lists when partial, while a fully successful Nuclei phase may also contribute focused targets.
    """
    tested: set[tuple[str, tuple[str, str, tuple[tuple[str, str], ...]], tuple[str, ...]]] = set()
    try:
        leaves = list(iter_leaf_results(profile_results))
    except Exception:
        leaves = []
    for _, result in leaves:
        if not isinstance(result, dict):
            continue
        status = str(result.get('status') or '').lower()
        if status in {'error', 'skipped'}:
            continue
        if status == 'success':
            action = result.get('coverage_action') if isinstance(result.get('coverage_action'), dict) else {}
            if action.get('target_url'):
                tested.add(_safe_surface_context_key(action))
        for row in result.get('dast_completed_request_cases', []) if isinstance(result.get('dast_completed_request_cases'), list) else []:
            if isinstance(row, dict) and row.get('url'):
                tested.add(_safe_surface_context_key(row))
        if status == 'success':
            for value in result.get('focused_targets', []) if isinstance(result.get('focused_targets'), list) else []:
                if str(value):
                    tested.add(_safe_surface_context_key({'url': str(value), 'method': 'GET', 'parameters': _query_parameter_names(str(value))}))
        for row in result.get('targeted_active_scans', []) if isinstance(result.get('targeted_active_scans'), list) else []:
            if isinstance(row, dict) and safe_bool_metadata(row.get('completed'), False) and row.get('url'):
                tested.add(_safe_surface_context_key({
                    'url': str(row.get('url')), 'method': str(row.get('method') or 'GET'),
                    'parameters': list(row.get('parameters') or []),
                }))
        for row in result.get('tested_cases', []) if isinstance(result.get('tested_cases'), list) else []:
            if isinstance(row, dict) and row.get('url'):
                tested.add(_safe_surface_context_key(row))
    return tested


def _safe_surface_candidate(case: dict[str, Any]) -> bool:
    url = str(case.get('url') or '')
    method = str(case.get('method') or 'GET').upper()
    if method not in {'GET', 'POST'} or not url or not url_in_authorized_scope(PRIMARY_SCOPE_TARGET or url, url):
        return False
    if _destructive_crawl_url(url) or _is_logout_case(case) or _oversized_generated_request(case):
        return False
    if _identity_protocol_metadata_only(case) or _parameter_scanner_static_asset(case):
        return False
    response = case.get('browser_response') if isinstance(case.get('browser_response'), dict) else {}
    if response.get('observed') is True and safe_int_metadata(response.get('status'), 0) in {404, 410}:
        return False
    return True


def run_safe_surface_sweep(
    target: str, discovery: dict[str, Any], profile_results: dict[str, Any], cookies: str='', *, limit: int | None=None,
) -> dict[str, Any]:
    """Replay still-untested reachable read-only contexts under one bounded completion deadline.

    This is deliberately not a vulnerability specialist. It records response/CORS/security-header
    observations and completion coverage; reporting keeps sweep-only coverage separate from broad/
    specialist coverage so this phase cannot inflate the latter metric.
    """
    cap = max(0, int(limit if limit is not None else SAFE_SURFACE_SWEEP_LIMITS.get(CURRENT_SCAN_MODE, 0)))
    sweep_minimum = 5.0 if CURRENT_SCAN_MODE == 'test' else 30.0
    total_timeout = max(sweep_minimum, float(BROAD_SCANNER_TIMEOUTS.get('nuclei', 240)) * SAFE_SURFACE_SWEEP_TIMEOUT_FACTOR)
    started = time.monotonic()
    deadline = started + total_timeout
    previously_tested = _tested_surface_contexts(profile_results)
    raw_inputs = discovery.get('request_cases', []) if isinstance(discovery.get('request_cases'), list) else []
    input_request_cases = len(raw_inputs)
    skipped_invalid = 0
    structurally_valid: list[dict[str, Any]] = []
    for raw in raw_inputs:
        if not isinstance(raw, dict):
            skipped_invalid += 1
            continue
        url = str(raw.get('url') or '').strip()
        method = str(raw.get('method') or 'GET').upper().strip()
        if not url or method not in {'GET', 'POST'}:
            skipped_invalid += 1
            continue
        try:
            parsed = urlparse(url)
            _ = parsed.port
        except (TypeError, ValueError):
            skipped_invalid += 1
            continue
        if parsed.scheme.lower() not in {'http', 'https'} or not parsed.hostname:
            skipped_invalid += 1
            continue
        structurally_valid.append(raw)

    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, str, tuple[tuple[str, str], ...]], tuple[str, ...]]] = set()
    for raw in filter_request_cases_for_state_policy(structurally_valid, False):
        params = _clean_case_parameter_names(raw.get('parameters', [])) or _query_parameter_names(str(raw.get('url') or ''))
        case = {**raw, 'parameters': params}
        if not _safe_surface_candidate(case):
            continue
        key = _safe_surface_context_key(case)
        if key in seen or key in previously_tested:
            continue
        seen.add(key)
        candidates.append(case)
    ranked = _family_fair_ranked_cases([
        (_risk_terms(str(case.get('url') or '') + ' ' + ' '.join(case.get('parameters', []))) + (12 if str(case.get('method') or 'GET').upper() == 'POST' else 0), case)
        for case in candidates
    ])
    selected = [case for _, case in ranked[:cap]] if cap else []
    session = requests.Session()
    session.headers.update({'User-Agent': 'SecOps-SafeSurface/1.0', 'Accept': '*/*', 'Origin': 'https://secops.invalid'})
    completed: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    timed_out = False
    tls_fallbacks = 0
    for case in selected:
        if time.monotonic() >= deadline:
            timed_out = True
            break
        url = str(case.get('url') or '')
        method = str(case.get('method') or 'GET').upper()
        headers: dict[str, str] = {}
        applicable_cookie = scope_cookie_header(url, cookies) if cookies else ''
        if applicable_cookie:
            headers['Cookie'] = applicable_cookie
        content_type = str(case.get('content_type') or case.get('enctype') or '').strip()
        if content_type:
            headers['Content-Type'] = content_type
        remaining = max(0.2, deadline - time.monotonic())
        try:
            _pace_http_request()
            response, tls_retry, _ = _request_with_tls_trust_retry(
                session, method, url, data=str(case.get('data') or '') if method == 'POST' else None,
                headers=headers, allow_redirects=False, timeout=(min(4.0, remaining), min(12.0, remaining)),
            )
            tls_fallbacks += int(tls_retry)
            completed.append({
                'url': url, 'method': method, 'parameters': list(case.get('parameters') or []),
                'status_code': int(response.status_code), 'response_content_type': str(response.headers.get('Content-Type') or ''),
                'location': str(response.headers.get('Location') or ''),
                'cors_allow_origin': str(response.headers.get('Access-Control-Allow-Origin') or ''),
                'cors_allow_credentials': str(response.headers.get('Access-Control-Allow-Credentials') or ''),
                'content_security_policy': bool(response.headers.get('Content-Security-Policy')),
                'x_content_type_options': str(response.headers.get('X-Content-Type-Options') or ''),
                'hsts': str(response.headers.get('Strict-Transport-Security') or ''),
                'tls_trust_fallback': bool(tls_retry),
            })
        except requests.RequestException as exc:
            errors.append({'url': url, 'method': method, 'error': f'{type(exc).__name__}: {exc}'})
    elapsed = round(time.monotonic() - started, 3)
    untouched = max(0, len(selected) - len(completed) - len(errors))
    status = 'partial' if timed_out or untouched or errors else 'success'
    diagnosis = 'time_limit_reached' if timed_out else ('partial_completion_sweep' if errors or untouched else '')
    return {
        'tool': 'safe-surface', 'status': status, 'diagnosis': diagnosis,
        'output': (
            f'Completion-driven safe surface sweep tested {len(completed)}/{len(selected)} selected still-untested context(s); '
            f'eligible={len(candidates)}, invalid={skipped_invalid}, cap={cap}, errors={len(errors)}, time_limit={timed_out}.'
        ),
        'target': target, 'vulnerabilities': [], 'tested_cases': completed, 'errors': errors,
        'input_request_cases': input_request_cases, 'selected_request_cases': len(selected),
        'skipped_invalid_request_cases': skipped_invalid, 'tested_request_cases': len(completed),
        'failed_request_cases': len(errors),
        'eligible_contexts': len(candidates), 'selected_contexts': len(selected), 'tested_contexts': len(completed),
        'previously_tested_contexts': len(previously_tested), 'untouched_eligible_contexts': max(0, len(candidates) - len(selected)) + untouched,
        'coverage_class': 'safe_surface_completion_only', 'broad_specialist_coverage': False,
        'timed_out': timed_out, 'time_limit_reached': timed_out, 'duration_seconds': elapsed,
        'tool_timeout_seconds': total_timeout, 'tls_trust_fallback_count': tls_fallbacks,
        'coverage_action': {'tool': 'safe-surface', 'target_url': target, 'method': 'GET', 'parameters': []},
    }

BROWSER_STATIC_SUFFIXES = {'.css', '.js', '.mjs', '.map', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.wav', '.mp4', '.webm', '.pdf', '.zip'}

# Browser XSS checks target rendered application pages, not standalone static assets.
def _browser_static_resource(url: str) -> bool:
    return Path(urlparse(str(url or '')).path.lower()).suffix in BROWSER_STATIC_SUFFIXES

WORKFLOW_STATE_HINTS = {'change', 'update', 'save', 'create', 'submit', 'send', 'comment', 'message', 'feedback', 'upload', 'password', 'email', 'profile', 'settings', 'transfer', 'captcha', 'admin'}
WORKFLOW_ACTION_HINTS = {'logout', 'signout', 'logoff', 'setup', 'install', 'delete', 'remove', 'drop', 'truncate', 'purge', 'wipe', 'reset'}

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
            status = safe_int_metadata(response.get('status'), 0)
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
        object_pairs = _object_reference_pairs(url)
        if object_pairs:
            class_reasons.append('bounded object-reference parameter')
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
        host = normalized_hostname(parsed.hostname or '')
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
    return score

# Chooses pages and requests that are useful for browser checks.
def select_browser_request_cases(discovery: dict[str, Any], limit: int | None=None, *, agentic_catalog: bool=False) -> list[dict[str, Any]]:

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
        cases.append({'url': url, 'method': 'GET', 'data': '', 'parameters': _query_parameter_names(url), 'fields': [], 'source_url': url, 'client_side_only': True, 'client_sources': sorted({str(value) for item in evidence for value in item.get('sources', []) if str(value)}), 'client_sinks': sorted({str(value) for item in evidence for value in item.get('sinks', []) if str(value)}), 'client_side_evidence': evidence})
    ranked = sorted(((_browser_case_priority(case, client_keys), -index, case) for index, case in enumerate(cases)), key=lambda item: (-item[0], -item[1]))
    if agentic_catalog:
        catalog: list[dict[str, Any]] = []
        seen_catalog: set[tuple[str, tuple[str, str, tuple[tuple[str, str], ...]], str, tuple[str, ...]]] = set()
        for score, _, case in ranked:
            # A positive browser score is an applicability signal (XSS/client-side evidence), not an
            # execution priority. Preserve every exact applicable contract for AI choice.
            if score <= 0:
                continue
            method = str(case.get('method', 'GET')).upper()
            url = str(case.get('url') or '')
            if not url or method not in {'GET', 'POST'} or _destructive_crawl_url(url) or _is_auto_index_case(case) or _browser_static_resource(url):
                continue
            params = tuple(sorted(str(value).lower() for value in case.get('parameters', []) if str(value)))
            key = (method, _semantic_request_url_key(url), str(case.get('data') or ''), params)
            if key in seen_catalog:
                continue
            seen_catalog.add(key)
            catalog.append({**case, 'priority_score': int(score), 'selection_reason': 'agentic-browser-applicable-candidate'})
        return catalog
    unique_ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    shape_counts: dict[tuple[str, tuple[str, str, int, str], tuple[str, ...]], int] = {}
    variant_cap = _specialist_variant_cap()
    for score, _, case in ranked:
        if score <= 0:
            continue
        method = str(case.get('method', 'GET')).upper()
        url = str(case.get('url', ''))
        params = tuple(sorted((str(value).lower() for value in case.get('parameters', []) if str(value))))
        key = (method, _semantic_request_url_key(url), params)
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
            params = tuple(sorted(str(value).lower() for value in case.get('parameters', []) if str(value)))
            key = (method, _semantic_request_url_key(url), params)
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
            seen.add((method, _semantic_request_url_key(url), params))
            shape_counts[shape] = shape_counts.get(shape, 0) + 1
    return _select_with_adaptive_specialist_budget('browser', unique_ranked, effective_limit)

# Scores a request case for multi-step workflow checks.
def _workflow_case_priority(case: dict[str, Any]) -> int:
    if str(case.get('method', 'GET')).upper() != 'POST':
        return -1000
    url = str(case.get('url', ''))
    path = urlparse(url).path.lower()
    names = _case_field_names(case)
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
    state_path = any((token in path for token in WORKFLOW_STATE_HINTS | WORKFLOW_ACTION_HINTS))
    auth_shape = _is_login_case(case) or any((token in path for token in ('login', 'signin', 'brute', 'auth')))
    captcha_shape = any(('captcha' in value for value in names)) or 'captcha' in path
    # A generic token parameter alone is not a workflow. API calls frequently contain bearer,
    # pagination or application tokens and were previously spending workflow action slots only to
    # be SKIPPED by the verifier. Require one real CSRF/upload/auth/CAPTCHA/state-change signal.
    if not (file_parameters or state_hits or state_path or auth_shape or captcha_shape):
        return -1000
    if state_hits or state_path:
        score += 60
    if not token_parameters and (state_hits or file_parameters):
        score += 35
    if token_parameters:
        score += 15
    return score

# Chooses request cases that are useful for workflow checks.
def select_workflow_request_cases(discovery: dict[str, Any], limit: int | None=None, *, agentic_catalog: bool=False) -> list[dict[str, Any]]:

    effective_limit = int(limit or PARAMETER_TOOL_CASE_LIMITS.get('workflow', 3))
    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for index, case in enumerate(discovery.get('request_cases', [])):
        if not isinstance(case, dict):
            continue
        if _ephemeral_identity_flow_url(str(case.get('url') or '')) or _volatile_identity_callback_url(str(case.get('url') or '')):
            # OAuth/OIDC state, session_code, nonce and execution URLs are one-time protocol
            # plumbing, not stable application workflows. Testing them wastes the workflow budget
            # and can invalidate a live login transaction.
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
    if agentic_catalog:
        catalog: list[dict[str, Any]] = []
        seen_catalog: set[tuple[str, tuple[str, str, tuple[tuple[str, str], ...]], str, tuple[str, ...]]] = set()
        for score, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
            method = str(case.get('method', 'POST')).upper()
            url = str(case.get('url') or '')
            fields = tuple(sorted(_case_field_names(case)))
            key = (method, _semantic_request_url_key(url), str(case.get('data') or ''), fields)
            if key in seen_catalog:
                continue
            seen_catalog.add(key)
            catalog.append({**case, 'priority_score': int(score), 'selection_reason': 'agentic-workflow-applicable-candidate'})
        return catalog
    unique_ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    shape_counts: dict[tuple[str, tuple[str, str, tuple[str, ...]], tuple[str, ...]], int] = {}
    variant_cap = _specialist_variant_cap()
    for score, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
        method = str(case.get('method', 'POST')).upper()
        url = str(case.get('url', ''))
        fields = tuple(sorted(_case_field_names(case)))
        key = (method, _semantic_request_url_key(url), fields)
        shape = (method, _structural_route_signature(url), fields)
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
        if _destructive_crawl_url(url) or _is_auto_index_url(url) or path.endswith(('/login.php', '/login')):
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
AUTHORIZATION_EXCLUDED_PATH_HINTS = {'login', 'signin', 'sign-in', 'logout', 'signout', 'logoff', 'csrf', 'captcha', 'xss', 'sqli', 'exec', 'command', 'docs', 'documentation', 'instructions', 'help', 'about', 'changelog', 'license', 'copying', 'readme', 'static', 'assets'}

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
def select_authorization_request_cases(discovery: dict[str, Any], limit: int | None=None, *, agentic_catalog: bool=False) -> list[dict[str, Any]]:

    effective_limit = int(limit or PARAMETER_TOOL_CASE_LIMITS.get('authorization', 3))
    cases = [dict(case) for case in discovery.get('request_cases', []) if isinstance(case, dict)]
    known = {str(case.get('url') or '') for case in cases}
    for value in discovery.get('parameterized_urls', []):
        url = str(value or '')
        if url and url not in known:
            cases.append({'url': url, 'method': 'GET', 'data': '', 'parameters': _query_parameter_names(url), 'source_url': url, 'synthetic_from_parameterized_url': True})

    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for index, case in enumerate(cases):
        score = _authorization_case_priority(case)
        if score > 0:
            ranked.append((score, -index, case))

    if agentic_catalog:
        catalog: list[dict[str, Any]] = []
        seen_catalog: set[tuple[str, str, str, tuple[str, ...]]] = set()
        for score, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
            url = str(case.get('url') or '')
            method = str(case.get('method', 'GET')).upper()
            fields = tuple(sorted(_case_field_names(case)))
            key = (method, semantic_request_identity_url(url), str(case.get('data') or ''), fields)
            if not url or key in seen_catalog:
                continue
            seen_catalog.add(key)
            catalog.append({**case, 'priority_score': int(score), 'selection_reason': 'agentic-authorization-applicable-candidate'})
        return catalog

    unique_ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[str] = set()
    shape_counts: dict[tuple[tuple[str, str, tuple[str, ...]], tuple[str, ...]], int] = {}
    variant_cap = _specialist_variant_cap()
    for score, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
        url = str(case.get('url') or '')
        params = tuple(sorted(str(value).lower() for value in case.get('parameters', []) if str(value)))
        shape = (_structural_route_signature(url), params)
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
            if _is_auto_index_case(case) or _destructive_crawl_url(url):
                continue
            path = urlparse(url).path.lower()
            if any(token in path for token in ('csrf', 'captcha')):
                continue
            if not list(case.get('parameters') or []) and not urlparse(url).query:
                continue
            params = tuple(sorted(str(value).lower() for value in case.get('parameters', []) if str(value)))
            shape = (_structural_route_signature(url), params)
            if shape_counts.get(shape, 0) >= variant_cap:
                continue
            score = _risk_terms(path) + (12 if urlparse(url).query else 0)
            extras.append((score, {**case, 'selection_reason': 'deep-readonly-auth-breadth'}))
        for score, case in sorted(extras, key=lambda item: (-item[0], str(item[1].get('url') or '')))[:max(0, min(6, effective_limit - len(unique_ranked)))]:
            url = str(case.get('url') or '')
            params = tuple(sorted(str(value).lower() for value in case.get('parameters', []) if str(value)))
            shape = (_structural_route_signature(url), params)
            if url in seen or shape_counts.get(shape, 0) >= variant_cap:
                continue
            seen.add(url)
            shape_counts[shape] = shape_counts.get(shape, 0) + 1
            unique_ranked.append((int(score), case))

    return _select_with_adaptive_specialist_budget('authorization', unique_ranked, effective_limit)

# Chooses and limits the endpoints sent to Arjun.
def select_arjun_request_cases(discovery: dict[str, Any], target: str, limit: int=MAX_ARJUN_ENDPOINTS, *, allow_state_changes: bool=False, agentic_catalog: bool=False) -> list[dict[str, Any]]:

    effective_limit = int(limit)
    if agentic_catalog:
        catalog: list[dict[str, Any]] = []
        seen_catalog: set[tuple[str, str, str]] = set()
        represented_urls: set[str] = set()
        for raw_case in discovery.get('request_cases', []):
            if not isinstance(raw_case, dict):
                continue
            url = normalize_url(str(raw_case.get('url') or ''))
            method = str(raw_case.get('method') or 'GET').upper()
            if not url or method not in {'GET', 'POST'} or not url_in_authorized_scope(target, url):
                continue
            path = urlparse(url).path.lower()
            if _destructive_crawl_url(url) or _is_auto_index_url(url) or path.endswith(('/login.php', '/login')):
                continue
            if _browser_static_resource(url):
                continue
            file_parameters = [str(value) for value in raw_case.get('file_parameters', []) if str(value)]
            enctype = str(raw_case.get('enctype') or '').lower()
            if file_parameters or 'multipart/form-data' in enctype:
                continue
            data = str(raw_case.get('data') or '')
            if (not allow_state_changes) and request_case_state_change_reason({**raw_case, 'url': url, 'method': method, 'data': data}):
                continue
            key = (method, semantic_request_identity_url(url), data)
            if key in seen_catalog:
                continue
            seen_catalog.add(key)
            represented_urls.add(semantic_request_identity_url(url))
            score = _risk_terms(path) + (18 if any(token in path for token in ('/api/', 'callback', 'webhook', 'debug', 'admin')) else 0)
            catalog.append({**raw_case, 'url': url, 'method': method, 'data': data, 'parameters': [str(value) for value in raw_case.get('parameters', []) if str(value)], 'priority_score': int(score), 'selection_reason': 'agentic-arjun-safe-endpoint-candidate'})
        for raw_url in [*(discovery.get('html_urls', []) or []), *(discovery.get('form_urls', []) or [])]:
            url = normalize_url(str(raw_url or ''))
            if not url or not url_in_authorized_scope(target, url) or semantic_request_identity_url(url) in represented_urls:
                continue
            path = urlparse(url).path.lower()
            if _destructive_crawl_url(url) or _is_auto_index_url(url) or _browser_static_resource(url) or path.endswith(('/login.php', '/login')):
                continue
            key = ('GET', semantic_request_identity_url(url), '')
            if key in seen_catalog:
                continue
            seen_catalog.add(key)
            score = _risk_terms(path) + (18 if any(token in path for token in ('/api/', 'callback', 'webhook', 'debug', 'admin')) else 0)
            catalog.append({'url': url, 'method': 'GET', 'data': '', 'parameters': _query_parameter_names(url), 'priority_score': int(score), 'selection_reason': 'agentic-arjun-safe-page-candidate'})
        return catalog

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
        if _destructive_crawl_url(url) or path.endswith(('/login.php', '/login')):
            continue
        parameters = [str(value) for value in case.get('parameters', []) if str(value)]
        fields = [item for item in case.get('fields', []) if isinstance(item, dict)]
        file_parameters = [str(value) for value in case.get('file_parameters', []) if str(value)]
        enctype = str(case.get('enctype') or '').lower()
        fully_modelled_form = bool(fields and parameters)
        if file_parameters or 'multipart/form-data' in enctype:
            continue
        if (not allow_state_changes) and request_case_state_change_reason({**case, 'url': url, 'method': method}):
            continue
        score = _risk_terms(path)
        score += 18 if any((token in path for token in ('/api/', 'callback', 'webhook', 'debug', 'admin'))) else 0
        score += 8 if not parameters else -min(16, len(parameters) * 4)
        if method == 'POST':
            score += 4
            # A modelled POST form can still expose undocumented server-side parameters. Keep it
            # eligible but rank it below an otherwise equivalent endpoint whose parameter surface
            # is still unknown; blanket exclusion was an unnecessary coverage loss.
            if fully_modelled_form:
                score -= 6
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
            if path in existing_paths or path.endswith(('/login.php', '/login')):
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

# Builds report-facing eligibility decisions for discovered request contracts.
# Deterministic reports use the bounded selector; Agentic reports use the same concrete-action
# catalog eligibility that is presented to the planner.
def endpoint_selection_decisions(
    discovery: dict[str, Any],
    target: str,
    authenticated_profile: bool=False,
    allow_state_changes: bool=False,
    credential_cookies: str='',
    *,
    agentic_catalog: bool=False,
) -> list[dict[str, Any]]:
    cases = [dict(case) for case in discovery.get('request_cases', []) if isinstance(case, dict) and str(case.get('url') or '')]
    if not cases:
        return []

    def key(case: dict[str, Any]) -> tuple[str, str, str]:
        method = str(case.get('method') or 'GET').upper()
        fields = sorted(_case_field_names(case))
        return (method, _clean_url(str(case.get('url') or '')), request_body_fingerprint(method, str(case.get('data') or ''), fields))

    def shape(tool: str, case: dict[str, Any]) -> tuple[str, tuple[Any, ...], tuple[str, ...]]:
        method = str(case.get('method') or 'GET').upper()
        url = str(case.get('url') or '')
        fields = tuple(sorted(_case_field_names(case)))
        lowered = str(tool or '').lower()
        if lowered == 'browser':
            route: tuple[Any, ...] = _browser_url_key(url)
        elif lowered == 'traversal':
            route = _discovery_route_signature(url)
        else:
            route = _structural_route_signature(url)
        return (method, route, fields)

    selected_by_tool: dict[str, set[tuple[str, str, str]]] = {}
    selected_shapes_by_tool: dict[str, set[tuple[str, tuple[Any, ...], tuple[str, ...]]]] = {}
    selected_counts: dict[str, int] = {}

    # The Agentic report must not recreate deterministic cutoffs. The pool limit is sized from the
    # complete discovered surface so selector functions can return every concrete compatible action.
    catalog_limit = max(
        64,
        len(cases)
        + len(discovery.get('parameterized_urls', []) or [])
        + len(discovery.get('html_urls', []) or [])
        + len(discovery.get('form_urls', []) or [])
        + len(discovery.get('client_side_candidates', []) or [])
        + 64,
    )

    for tool in ('sqlmap', 'dalfox', 'commix', 'traversal', 'idor'):
        selected = select_tool_request_cases(
            discovery, tool,
            limit=catalog_limit if agentic_catalog else None,
            authenticated_profile=authenticated_profile,
            allow_state_changes=allow_state_changes,
            credential_cookies=credential_cookies,
            agentic_catalog=agentic_catalog,
        )
        selected_by_tool[tool] = {key(case) for case in selected}
        selected_shapes_by_tool[tool] = {shape(tool, case) for case in selected}
        selected_counts[tool] = len(selected)

    browser_selected = select_browser_request_cases(
        discovery,
        limit=catalog_limit if agentic_catalog else None,
        agentic_catalog=agentic_catalog,
    )
    workflow_selected = select_workflow_request_cases(
        discovery,
        limit=catalog_limit if agentic_catalog else None,
        agentic_catalog=agentic_catalog,
    )
    authorization_selected = [
        case for case in select_authorization_request_cases(
            discovery,
            limit=catalog_limit if agentic_catalog else None,
            agentic_catalog=agentic_catalog,
        )
        if authenticated_profile and (not credential_cookies or scope_cookie_header(str(case.get('url') or ''), credential_cookies))
    ]
    arjun_selected = select_arjun_request_cases(
        discovery, target,
        limit=catalog_limit if agentic_catalog else ARJUN_ENDPOINT_LIMIT,
        allow_state_changes=allow_state_changes,
        agentic_catalog=agentic_catalog,
    )
    for tool, selected in (
        ('browser', browser_selected),
        ('workflow', workflow_selected),
        ('authorization', authorization_selected),
        ('arjun', arjun_selected),
    ):
        selected_by_tool[tool] = {key(case) for case in selected}
        selected_shapes_by_tool[tool] = {shape(tool, case) for case in selected}
        selected_counts[tool] = len(selected)

    raw_client = [item for item in discovery.get('client_side_candidates', []) if isinstance(item, dict)]
    client_keys = {_browser_url_key(str(item.get('url') or '')) for item in raw_client if str(item.get('url') or '')}
    variant_cap = _specialist_variant_cap()
    shape_frequency_by_tool = {tool: Counter(shape(tool, case) for case in cases) for tool in selected_by_tool}

    decisions: list[dict[str, Any]] = []
    for case in cases:
        method, url, body_fingerprint = key(case)
        fields = _case_field_names(case)
        selected_tools = sorted(tool for tool, values in selected_by_tool.items() if (method, url, body_fingerprint) in values)
        eligible_tools: list[str] = []

        state_change_reason = request_case_state_change_reason(case) if not allow_state_changes else ''
        state_safe = not (_destructive_crawl_url(url) or state_change_reason)
        if not state_safe:
            # Workflow remains selectable for structural-only analysis when active state changes are
            # forbidden. Other request-level tools must not be reported as selected merely because
            # their state-agnostic ranking helper saw the same contract.
            selected_tools = [tool for tool in selected_tools if tool == 'workflow']
        if method in {'GET', 'POST'}:
            case_authenticated = authenticated_profile and (not credential_cookies or bool(scope_cookie_header(url, credential_cookies)))
            if state_safe:
                for tool in ('sqlmap', 'dalfox', 'commix', 'traversal', 'idor'):
                    if not _tool_case_skip_reason(tool, case, authenticated_profile=case_authenticated):
                        eligible_tools.append(tool)
                if _browser_case_priority(case, client_keys) > 0:
                    eligible_tools.append('browser')
                if case_authenticated and _authorization_case_priority(case) > 0:
                    eligible_tools.append('authorization')
                if (method, url, body_fingerprint) in selected_by_tool.get('arjun', set()):
                    eligible_tools.append('arjun')
            # Workflow analysis is useful even for a mutating POST: under allow_state_changes=false
            # the wrapper performs structural-only CSRF/upload/auth/CAPTCHA analysis and does not
            # submit the state-changing request. Active workflow probes remain gated inside the tool.
            workflow_score = _workflow_case_priority(case)
            if workflow_score > 0:
                eligible_tools.append('workflow')
            elif CURRENT_SCAN_MODE == 'deep' and method == 'GET':
                path = urlparse(url).path.lower()
                if (any(token in path for token in ('brute', 'login', 'signin', 'auth')) or {'username', 'password'} <= fields) and not _destructive_crawl_url(url):
                    eligible_tools.append('workflow')

        reason_code = ''
        reason = ''
        if method not in {'GET', 'POST'}:
            reason_code = 'UNSUPPORTED_METHOD'
            reason = f'{method} was observed during discovery but request-level specialist wrappers accept only supported GET/POST contracts.'
        elif selected_tools:
            reason_code = 'SELECTED_FOR_SECURITY_TEST'
            if agentic_catalog:
                reason = 'At least one concrete action for this request contract is eligible for Agentic planning.'
            else:
                reason = 'The deterministic selector retained this request contract for one or more request-level security tools.'
        elif (_destructive_crawl_url(url) or state_change_reason) and 'workflow' not in eligible_tools:
            reason_code = 'STATE_CHANGE_BLOCKED'
            reason = 'The request maps to a destructive/state-changing route or request contract excluded from active execution by the safety policy.'
        elif not fields:
            reason_code = 'NO_COMPATIBLE_PARAMETERS'
            reason = 'No compatible application parameter, form field or client-side input was available for request-level specialist testing.'
        elif agentic_catalog:
            reason_code = 'NO_COMPATIBLE_PARAMETERS'
            reason = 'No policy-eligible concrete specialist action can be constructed from this discovered request contract.'
        else:
            duplicate_tools = [
                tool for tool in eligible_tools
                if shape(tool, case) in selected_shapes_by_tool.get(tool, set())
                and shape_frequency_by_tool.get(tool, Counter())[shape(tool, case)] > variant_cap
            ]
            if duplicate_tools:
                reason_code = 'DUPLICATE_ROUTE_VARIANT'
                reason = 'A higher-ranked value variant with the same method, route and parameter-name shape was retained by the deterministic selector.'
            elif eligible_tools and any(selected_counts.get(tool, 0) >= tool_action_limit(tool, include_adaptive=True) > 0 for tool in eligible_tools):
                reason_code = 'BUDGET_LIMIT'
                reason = 'The request was compatible with a specialist, but that deterministic specialist reached its bounded adaptive case ceiling for this profile.'
            else:
                reason_code = 'DEFERRED_LOW_PRIORITY'
                reason = 'The request remained below the deterministic specialist cutoff after vulnerability-class ranking and higher-value candidates were preferred.'

        decisions.append({
            'url': url,
            'method': method,
            'parameters': sorted(fields),
            'body_fingerprint': body_fingerprint,
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
            cases.append({'url': url, 'method': 'GET', 'data': '', 'parameters': _query_parameter_names(url), 'source_url': url})
    ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for case in cases:
        url = str(case.get('url', ''))
        method = str(case.get('method', 'GET')).upper()
        path = urlparse(url).path.lower()
        if not url or method not in {'GET', 'POST'} or request_case_state_change_reason(case):
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
def select_oast_request_cases(discovery: dict[str, Any], target: str, limit: int=1, *, allow_state_changes: bool=False, agentic_catalog: bool=False) -> list[dict[str, Any]]:

    ranked: list[tuple[int, dict[str, Any]]] = []
    for case in discovery.get('request_cases', []):
        if not isinstance(case, dict):
            continue
        url = str(case.get('url') or '')
        method = str(case.get('method') or 'GET').upper()
        if not url or method not in {'GET', 'POST'} or (not url_in_authorized_scope(target, url)):
            continue
        path = urlparse(url).path.lower()
        if (not allow_state_changes) and request_case_state_change_reason({**case, 'url': url, 'method': method}):
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
        if (not agentic_catalog) and len(selected) >= max(1, int(limit)):
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
    generated_cases = [{'url': url, 'method': 'GET', 'data': '', 'parameters': _query_parameter_names(url), 'source_url': base_url} for url in generated]
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
            state = 'complete' if safe_bool_metadata(item.get('completed'), False) else 'incomplete'
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
        isolated = safe_bool_metadata(result.get('cookie_isolated_discovery'), False)
        credentialed = safe_bool_metadata(result.get('credentialed_fuzz_requests_sent'), False)
        blocked = len(result.get('blocked_destructive_rows') or [])
        if isolated:
            print(f'    [FFUF SESSION] path fuzzing cookie-isolated=True; credentialed fuzz requests={credentialed}; destructive rows blocked={blocked}')
        session_after = result.get('session_after') if isinstance(result.get('session_after'), dict) else {}
        if session_after.get('performed'):
            print(f"    [FFUF SESSION] post-scan authenticated={session_after.get('authenticated')}; conclusive={session_after.get('conclusive')}")
    if name == 'nuclei':
        if result.get('checkpoint_recovered'):
            active = result.get('active_phase_snapshot') if isinstance(result.get('active_phase_snapshot'), dict) else {}
            print(
                f"    [NUCLEI CHECKPOINT] recovered after outer timeout; stage={result.get('checkpoint_stage', 'unknown')}; "
                f"active_phase={result.get('active_phase') or active.get('name') or 'unknown'}; "
                f"active_findings={active.get('findings', 'unknown')}; raw_items={result.get('raw_checkpoint_item_count', 'unknown')}"
            )
        inventory_present = isinstance(result.get('template_inventory'), dict)
        inventory = result.get('template_inventory') if inventory_present else {}
        if inventory_present:
            print(
                f"    [NUCLEI TEMPLATES] total={inventory.get('count', 0)}; "
                f"dast={inventory.get('dast_count', 0)}; directory={inventory.get('directory', '') or 'not-resolved'}; "
                f"resolution={inventory.get('resolution', 'runtime-recorded')}"
            )
        else:
            # An outer MCP/watchdog timeout can synthesize a PARTIAL result before the scanner
            # returns its structured metadata. Do not print missing fields as a real zero-template
            # inventory: that previously made transport truncation look like an installation bug.
            print('    [NUCLEI TEMPLATES] inventory=unknown; scanner metadata was not returned before the outer result was finalized')
        fingerprint = result.get('technology_fingerprint') if isinstance(result.get('technology_fingerprint'), dict) else {}
        direct_templates = result.get('custom_template_count') if 'custom_template_count' in result else 'unknown'
        evidence_targets = len(result.get('evidence_targets') or []) if 'evidence_targets' in result else 'unknown'
        dast_cases = result.get('dast_request_count') if 'dast_request_count' in result else 'unknown'
        print(f"    [NUCLEI STRATEGY] adaptive=True; technologies={','.join(fingerprint.get('tags') or []) or 'unknown'}; dast_cases={dast_cases}; direct_templates={direct_templates}; evidence_targets={evidence_targets}; stdin_disabled=True; DAST may overlap specialist classes to provide independent template evidence")
        for gap in result.get('coverage_gaps') or []:
            if isinstance(gap, dict):
                print(f"    [NUCLEI COVERAGE GAP] {gap.get('phase', 'unknown')}: {gap.get('diagnosis', 'partial')} — {gap.get('detail', '')}")
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
            print(f"    [NIKTO REFERENCE] status={baseline.get('status', 'n/a')}; server={baseline.get('server') or 'not-disclosed'}; signals={baseline.get('signal_count', 0)}; missing headers={','.join(baseline.get('missing_security_headers') or []) or 'none'}")

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
            recovered['execution_complete'] = safe_bool_metadata(summary.get('execution_complete'), False)
        if 'coverage_complete' in summary:
            recovered['coverage_complete'] = safe_bool_metadata(summary.get('coverage_complete'), False)

    # The MCP round-trip (HTTP transport/timeout layering) can fail even though the report server
    # already wrote the JSON payload to disk before it ever attempted PDF rendering. Rather than
    # give up on the PDF entirely, render it once more directly in this process from that same
    # payload — bypassing the async MCP transport/watchdog stack that just failed.
    pdf_regeneration_error = ''
    if available['pdf_filename'] is None and isinstance(payload, dict):
        try:
            module = _load_report_server_module()
            render_html = getattr(module, '_render_html', None)
            render_pdf = getattr(module, 'html2pdf', None)
            if not callable(render_html) or not callable(render_pdf):
                raise AttributeError('reportServer.py does not expose _render_html()/html2pdf()')
            pdf_source_path = html_path.with_name(f'{html_path.stem}.pdf-source.html')
            atomic_write_text(pdf_source_path, render_html(payload, for_pdf=True))
            try:
                render_pdf(pdf_source_path, pdf_path)
            finally:
                pdf_source_path.unlink(missing_ok=True)
            if pdf_path.is_file():
                available['pdf_filename'] = pdf_path
                recovered['pdf_filename'] = str(pdf_path.resolve())
                recovered['local_pdf_generated'] = True
                recovered['pdf_regenerated_locally'] = True
        except Exception as exc:
            pdf_regeneration_error = f'{type(exc).__name__}: {exc}'

    if available['pdf_filename'] is not None:
        recovered['status'] = 'success'
        recovered['diagnosis'] = 'report_response_recovered'
        recovered['output'] = 'Normal report artifacts, including the PDF, were recovered after the MCP/HTTP response did not complete normally.'
        if recovered.get('pdf_regenerated_locally'):
            recovered['output'] = 'Normal JSON/HTML artifacts were recovered after the MCP/HTTP reporting failure, and the PDF was regenerated locally from the same report payload.'
    else:
        recovered['status'] = 'partial'
        recovered['diagnosis'] = 'normal_report_recovered_without_pdf'
        suffix = f' Original reporting detail: {original_output}' if original_output else ''
        if pdf_regeneration_error:
            suffix += f' Local PDF regeneration also failed: {pdf_regeneration_error}'
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
        atomic_write_text(path, text)
        atomic_write_text(path.with_suffix('.html'), f"<!doctype html><meta charset='utf-8'><title>SecOps preview</title><style>body{{font-family:Segoe UI;margin:2rem}}pre{{white-space:pre-wrap;background:#111923;color:#e7eef7;padding:1rem}}</style><h1>SecOps emergency preview</h1><pre>{html.escape(text)}</pre>")
        return str(path.resolve())
    except Exception as exc:
        print(f'[REPORT FALLBACK ERROR] {exc}', file=sys.stderr)
        return None

# Chooses a stable URL used to check the current session.
def select_session_probe_url(discovery: dict[str, Any], target: str) -> str:

    discovered = [str(value) for value in discovery.get('html_urls', []) if isinstance(value, str) and same_origin(target, value) and (not _is_auto_index_url(value))]
    return _stable_auth_probe_url(target, discovered)


def select_application_session_probe_url(discovery: dict[str, Any], request_url: str, source_url: str='') -> str:
    """Choose a safe GET authentication probe from the same generic application root.

    A concrete specialist request can be POST/PUT or a mutating GET when state changes were explicitly
    authorized. Session validation must not replay that request merely to check whether cookies are
    still valid, so the fallback is the application root (or origin), never the concrete request URL.
    """
    scope_key = _runtime_application_scope_key(request_url)
    candidates = [
        str(value) for value in discovery.get('html_urls', [])
        if isinstance(value, str)
        and same_origin(request_url, value)
        and _runtime_application_scope_key(value) == scope_key
        and not _is_auto_index_url(value)
        and not _ephemeral_identity_flow_url(value)
        and not request_contract_state_change_reason({'url': str(value), 'method': 'GET', 'data': '', 'parameters': []})
    ]
    if (
        source_url and same_origin(request_url, source_url)
        and _runtime_application_scope_key(source_url) == scope_key
        and not request_contract_state_change_reason({'url': str(source_url), 'method': 'GET', 'data': '', 'parameters': []})
    ):
        candidates.insert(0, str(source_url))
    fallback = scope_key or normalized_origin(request_url) or request_url
    if request_contract_state_change_reason({'url': fallback, 'method': 'GET', 'data': '', 'parameters': []}):
        fallback = normalized_origin(request_url) or request_url
    return _stable_auth_probe_url(fallback, candidates) if candidates else fallback


# Safety policy decides whether state-changing tests are allowed for the current target. The
# default is fail-closed on every host, including loopback: only an explicit true enables them.
def state_changing_tests_allowed(target: str, explicit: bool | None=None) -> bool:

    return bool(explicit) if explicit is not None else False

# Adds the command-line options shared by both orchestrators.
def add_common_cli_arguments(parser: argparse.ArgumentParser, *, require_target: bool) -> None:

    if require_target:
        parser.add_argument('--target', required=True)
    else:
        parser.add_argument('--target')
    parser.add_argument('--cookies', default='')
    parser.add_argument('--primary-identity-name', default='primary', help='Label for the primary authenticated identity used in reports/comparisons.')
    parser.add_argument('--secondary-cookies', default='', help='Optional second authenticated identity for read-only authorization/BOLA comparison.')
    parser.add_argument('--identity-cookie', action='append', default=[], metavar='NAME=COOKIE', help='Additional authenticated identity. Repeat as needed; each identity becomes an independent authenticated profile.')
    parser.add_argument('--auth-only', action='store_true')
    parser.add_argument('--authorized', action='store_true')
    parser.add_argument('--authorized-origin', action='append', default=[], help='Additional exact HTTP/HTTPS origin explicitly included in the authorized assessment scope. Repeat as needed.')
    parser.add_argument('--allow-same-host-ports', action='store_true', help='Authorize HTTP/HTTPS services on other ports of an already-authorized exact hostname without authorizing sibling hostnames.')
    parser.add_argument('--discover-same-host-services', action='store_true', help='Proactively discover responsive HTTP/HTTPS services on the exact authorized hostname. Requires --allow-same-host-ports.')
    parser.add_argument('--authorized-host-suffix', action='append', default=[], help=argparse.SUPPRESS)
    parser.add_argument('--entry-point', action='append', default=[], help='Explicit authorized HTTP/HTTPS entry point that must be included in initial discovery. Repeat as needed.')
    parser.add_argument('--discovery-seed', action='append', default=[], help='Authorized high-priority discovery seed. Unlike --entry-point it remains subject to normal route/budget limits and is not reported as a supplied entry point.')
    state_change_group = parser.add_mutually_exclusive_group()
    state_change_group.add_argument('--allow-state-changes', dest='allow_state_changes', action='store_true', default=None, help='Explicitly enable bounded POST/upload/stored-XSS workflow probes for this run.')
    state_change_group.add_argument('--no-allow-state-changes', dest='allow_state_changes', action='store_false', help='Explicitly disable bounded state-changing probes, including on local targets.')
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--ignore-preflight-errors', action='store_true')
    parser.add_argument('--interactsh-injection-url', default='')
    parser.add_argument('--mode', choices=('test', 'fast', 'balanced', 'deep'), default='balanced', help='Trade coverage for runtime; test is a short diagnostic profile and balanced is the normal default.')

# Validates the command line and builds target, profile, and cookie settings.
def prepare_cli_context(parser: argparse.ArgumentParser, args: argparse.Namespace) -> tuple[str, list[dict[str, str]], str, str, str]:

    target = normalize_url(args.target)
    local_hosts = {'127.0.0.1', 'localhost', '::1'}
    if urlparse(target).hostname not in local_hosts and (not args.authorized):
        parser.error('Remote targets require --authorized.')
    if (getattr(args, 'authorized_origin', None) or getattr(args, 'authorized_host_suffix', None) or getattr(args, 'allow_same_host_ports', False) or getattr(args, 'discover_same_host_services', False)) and not args.authorized:
        parser.error('Scope extensions require --authorized.')
    if getattr(args, 'discover_same_host_services', False) and not getattr(args, 'allow_same_host_ports', False):
        parser.error('--discover-same-host-services requires --allow-same-host-ports.')
    for value in getattr(args, 'authorized_origin', []) or []:
        raw_origin = str(value or '').strip()
        try:
            parsed_origin = urlparse(raw_origin)
            _ = parsed_origin.port
        except ValueError:
            parser.error(f'Invalid --authorized-origin value: {value!r}. Use an absolute HTTP/HTTPS origin.')
        if (not normalized_origin(raw_origin)) or parsed_origin.path not in {'', '/'} or parsed_origin.query or parsed_origin.fragment or parsed_origin.username or parsed_origin.password:
            parser.error(f'Invalid --authorized-origin value: {value!r}. Use only scheme, host and optional port.')
    if getattr(args, 'authorized_host_suffix', None):
        parser.error('--authorized-host-suffix is disabled for active testing; use repeated --authorized-origin with exact origins.')
    configure_authorized_scope(
        target, list(getattr(args, 'authorized_origin', []) or []),
        allow_same_host_ports=bool(getattr(args, 'allow_same_host_ports', False)),
        discover_same_host_services=bool(getattr(args, 'discover_same_host_services', False)),
    )
    if AUTHORIZED_SCOPE_ORIGINS:
        print('[*] Authorized scope extensions: exact origins=' + ', '.join(sorted(AUTHORIZED_SCOPE_ORIGINS)))
    if ALLOW_SAME_HOST_PORTS:
        print('[*] Authorized scope extension: exact-host HTTP/HTTPS multi-port testing ENABLED.')
    if DISCOVER_SAME_HOST_SERVICES:
        print('[*] Proactive same-host HTTP/HTTPS service discovery ENABLED (runtime-derived candidates; no external validation data used).')
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
        profiles.append({'name': 'authenticated', 'cookies': normalized_cookie, 'identity_ref': str(getattr(args, 'primary_identity_name', '') or 'primary')})
    elif args.auth_only:
        parser.error('--auth-only requires --cookies.')
    secondary_cookie = ''
    additional_identities: list[tuple[str, str]] = []
    if args.secondary_cookies:
        if not normalized_cookie:
            parser.error('--secondary-cookies requires a primary --cookies value.')
        try:
            secondary_cookie = canonical_cookie_header(args.secondary_cookies)
        except ValueError as exc:
            parser.error(f'Invalid --secondary-cookies value: {exc}')
        if secondary_cookie == normalized_cookie:
            parser.error('--secondary-cookies must represent a different authenticated identity.')
        print('[*] Secondary comparison-only identity cookie names: ' + ', '.join(cookie_names(secondary_cookie)))
    used_identity_labels: set[str] = set()
    if normalized_cookie:
        primary_label = str(getattr(args, 'primary_identity_name', '') or 'primary').strip()
        if not valid_identity_label(primary_label):
            parser.error('--primary-identity-name must use only letters, digits, dot, underscore or hyphen.')
        used_identity_labels.add(primary_label.casefold())
    for raw_identity in getattr(args, 'identity_cookie', []) or []:
        raw = str(raw_identity or '')
        if '=' not in raw:
            parser.error('--identity-cookie must use NAME=COOKIE syntax.')
        label, raw_cookie = raw.split('=', 1)
        label = label.strip()
        if not valid_identity_label(label):
            parser.error('--identity-cookie identity names must use only letters, digits, dot, underscore or hyphen.')
        if label.casefold() in used_identity_labels:
            parser.error(f'Authenticated identity label {label!r} is duplicated; identity labels must be unique.')
        used_identity_labels.add(label.casefold())
        try:
            value = canonical_cookie_header(raw_cookie)
        except ValueError as exc:
            parser.error(f'Invalid --identity-cookie value for {label!r}: {exc}')
        if value == normalized_cookie or any(existing == value for _, existing in additional_identities):
            parser.error(f'Identity {label!r} duplicates an already configured authenticated session.')
        additional_identities.append((label, value))
    if secondary_cookie and any(value == secondary_cookie for _, value in additional_identities):
        parser.error('--secondary-cookies duplicates a --identity-cookie session; configure that account only once.')
    configured_identity_count = (1 if normalized_cookie else 0) + len(additional_identities) + (1 if secondary_cookie else 0)
    if configured_identity_count > MAX_AUTHENTICATED_IDENTITIES:
        parser.error(
            f'At most {MAX_AUTHENTICATED_IDENTITIES} authenticated identities are supported per target, including the --secondary-cookies identity.'
        )
    used_profile_names = {str(profile.get('name') or '') for profile in profiles}
    for label, value in additional_identities:
        safe_label = re.sub(r'[^a-zA-Z0-9_]+', '_', label).strip('_').lower() or 'identity'
        profile_name = f'authenticated_{safe_label}'
        suffix = 2
        while profile_name in used_profile_names:
            profile_name = f'authenticated_{safe_label}_{suffix}'
            suffix += 1
        used_profile_names.add(profile_name)
        profiles.append({'name': profile_name, 'cookies': value, 'identity_ref': label})
        if not secondary_cookie:
            secondary_cookie = value
        print(f"[*] Authenticated identity {label!r} cookie names: " + ', '.join(cookie_names(value)))
    configure_runtime_target_auth(target, normalized_cookie)
    return (target, profiles, normalized_cookie, secondary_cookie, injection_url)

# Normalizes explicit assessment entry points after the primary target and scope are configured.
def prepare_cli_entry_points(parser: argparse.ArgumentParser, args: argparse.Namespace, target: str) -> list[str]:
    selected: list[str] = []
    for raw in getattr(args, 'entry_point', []) or []:
        value = str(raw or '').strip()
        if not value:
            continue
        try:
            normalized = _clean_url(absolute_url(target, value) if value.startswith('/') else value)
        except Exception:
            parser.error(f'Invalid --entry-point value: {raw!r}. Use an absolute HTTP/HTTPS URL or root-relative path.')
        if not url_in_authorized_scope(target, normalized):
            parser.error(f'--entry-point is outside the explicitly authorized assessment scope: {raw!r}')
        if _destructive_crawl_url(normalized):
            parser.error(f'--entry-point resolves to a destructive navigation that is blocked by policy: {raw!r}')
        if normalized not in selected:
            selected.append(normalized)
    return selected

# Normalizes high-priority discovery seeds without treating them as supplied assessment entry points.
def prepare_cli_discovery_seeds(parser: argparse.ArgumentParser, args: argparse.Namespace, target: str) -> list[str]:
    selected: list[str] = []
    for raw in getattr(args, 'discovery_seed', []) or []:
        value = str(raw or '').strip()
        if not value:
            continue
        try:
            normalized = _clean_url(absolute_url(target, value) if value.startswith('/') else value)
        except Exception:
            parser.error(f'Invalid --discovery-seed value: {raw!r}. Use an absolute HTTP/HTTPS URL or root-relative path.')
        if not url_in_authorized_scope(target, normalized):
            parser.error(f'--discovery-seed is outside the explicitly authorized assessment scope: {raw!r}')
        if _destructive_crawl_url(normalized):
            parser.error(f'--discovery-seed resolves to a destructive navigation that is blocked by policy: {raw!r}')
        if normalized not in selected:
            selected.append(normalized)
    return selected

# Builds the arguments sent to each MCP tool from discovery data.
def build_tool_arguments(tool: str, target_url: str, cookies: str, discovery: dict[str, Any], *, case: dict[str, Any] | None=None, secondary_cookies: str='', comparison_identities: list[dict[str, str]] | None=None, allow_state_changes: bool | None=None, timeout_override: int=0, diagnostic_only: bool=False, single_tool: bool=False) -> dict[str, Any]:

    case = case or {}
    effective_cookies = scope_cookie_header(target_url, cookies)
    arguments: dict[str, Any] = {'target_url': target_url, 'cookies': effective_cookies}
    if tool in {'ffuf', 'nikto', 'nuclei', 'zap', 'arjun', 'sqlmap', 'dalfox', 'commix', 'session', 'traversal', 'authorization', 'workflow', 'browser', 'idor'}:
        # Pass the normalized rate in every MCP call. This keeps per-assessment configuration
        # correct even if a unified MCP process is already listening from another local run.
        arguments['request_rate'] = MAX_REQUEST_RATE
    if tool == 'browser':
        # Browser verification may traverse only exact origins that were explicitly authorized before the run.
        arguments['authorized_origins'] = sorted(AUTHORIZED_SCOPE_ORIGINS)
        arguments['allow_same_host_ports'] = ALLOW_SAME_HOST_PORTS
    if tool in BROAD_SCANNER_TIMEOUTS:
        arguments['timeout'] = timeout_override or BROAD_SCANNER_TIMEOUTS[tool]
        if tool == 'ffuf':
            arguments['session_probe_url'] = select_session_probe_url(discovery, target_url)
            arguments['allow_same_host_ports'] = ALLOW_SAME_HOST_PORTS
            arguments['allow_state_changes'] = state_changing_tests_allowed(target_url, allow_state_changes)
        elif tool == 'session':
            sample_count = 1 if CURRENT_SCAN_MODE == 'test' else 7 if CURRENT_SCAN_MODE == 'deep' else 5 if CURRENT_SCAN_MODE == 'balanced' else 3
            arguments.update({'probe_url': select_session_probe_url(discovery, target_url), 'sample_count': sample_count, 'allow_state_changes': state_changing_tests_allowed(target_url, allow_state_changes)})
        elif tool == 'zap':
            safe_request_cases = _request_cases_for_state_policy(
                discovery.get('request_cases', []),
                state_changing_tests_allowed(target_url, allow_state_changes),
            )
            if diagnostic_only:
                scan_mode = 'passive'
            elif CURRENT_SCAN_MODE == 'deep':
                scan_mode = 'full'
            elif CURRENT_SCAN_MODE == 'balanced':
                scan_mode = 'prioritized'
            else:
                scan_mode = 'targeted'
            arguments.update({
                'seed_urls': discovery.get('html_urls', []),
                'request_cases': safe_request_cases,
                'scan_mode': scan_mode,
                'session_probe_url': select_session_probe_url(discovery, target_url),
                'max_observations': 40 if CURRENT_SCAN_MODE == 'test' else 1400 if CURRENT_SCAN_MODE == 'deep' else 800 if CURRENT_SCAN_MODE == 'balanced' else 180,
                'max_ranked_cases': 20 if CURRENT_SCAN_MODE == 'test' else 640 if CURRENT_SCAN_MODE == 'deep' else 320 if CURRENT_SCAN_MODE == 'balanced' else 80,
                'max_active_cases': 4 if CURRENT_SCAN_MODE == 'test' else 192 if CURRENT_SCAN_MODE == 'deep' else 96 if CURRENT_SCAN_MODE == 'balanced' else 32,
                'allow_state_changes': state_changing_tests_allowed(target_url, allow_state_changes),
            })
            if single_tool:
                arguments['diagnostic_only'] = diagnostic_only
            elif diagnostic_only:
                arguments['diagnostic_only'] = True
        elif tool == 'nuclei':
            state_changes_allowed = state_changing_tests_allowed(target_url, allow_state_changes)
            safe_request_cases = _request_cases_for_state_policy(discovery.get('request_cases', []), state_changes_allowed)
            arguments.update({
                'seed_urls': discovery.get('urls', []),
                'priority_seed_urls': discovery.get('explicit_entry_points', []),
                'request_cases': safe_request_cases,
                'allow_state_changes': state_changes_allowed,
                'scan_profile': CURRENT_SCAN_MODE,
                'max_targets': 32 if CURRENT_SCAN_MODE == 'test' else 2048 if CURRENT_SCAN_MODE == 'deep' else 1024 if CURRENT_SCAN_MODE == 'balanced' else 128,
            })
        elif tool == 'nikto':
            arguments['scan_profile'] = CURRENT_SCAN_MODE
            arguments['allow_same_host_ports'] = ALLOW_SAME_HOST_PORTS
            arguments['allow_state_changes'] = state_changing_tests_allowed(target_url, allow_state_changes)
        return arguments
    method = str(case.get('method') or 'GET').upper()
    data = str(case.get('data') or '')
    parameters = list(case.get('parameters') or [])
    if tool == 'arjun':
        arguments.update({
            'method': method, 'data': data, 'known_parameters': parameters,
            'timeout': timeout_override or ARJUN_TIMEOUT,
            'authorized_origins': sorted(AUTHORIZED_SCOPE_ORIGINS),
            'allow_same_host_ports': ALLOW_SAME_HOST_PORTS,
            'allow_state_changes': state_changing_tests_allowed(target_url, allow_state_changes),
        })
    elif tool in {'sqlmap', 'dalfox', 'commix', 'traversal', 'idor'}:
        arguments.update({'method': method, 'data': data, 'parameters': parameters, 'timeout': timeout_override or PARAMETER_TOOL_TIMEOUTS[tool]})
        if tool in {'sqlmap', 'dalfox', 'commix', 'traversal'}:
            arguments['allow_state_changes'] = state_changing_tests_allowed(target_url, allow_state_changes)
            arguments['session_probe_url'] = select_application_session_probe_url(
                discovery, target_url, str(case.get('source_url') or '')
            )
        if tool == 'traversal':
            arguments['scan_profile'] = CURRENT_SCAN_MODE
    elif tool == 'authorization':
        comparison_rows: list[dict[str, str]] = []
        seen_cookies: set[str] = set()
        for row in comparison_identities or []:
            if not isinstance(row, dict):
                continue
            value = scope_cookie_header(target_url, str(row.get('cookies') or ''), use_runtime_auth=True)
            if not value or value == effective_cookies or value in seen_cookies:
                continue
            seen_cookies.add(value)
            comparison_rows.append({'label': str(row.get('label') or row.get('name') or 'alternate'), 'cookies': value})
        legacy_secondary = scope_cookie_header(target_url, secondary_cookies, use_runtime_auth=False)
        if legacy_secondary and legacy_secondary != effective_cookies and legacy_secondary not in seen_cookies:
            comparison_rows.append({'label': 'secondary', 'cookies': legacy_secondary})
        arguments.update({
            'secondary_cookies': legacy_secondary,
            'identity_cookies': [row['cookies'] for row in comparison_rows],
            'identity_labels': [row['label'] for row in comparison_rows],
            'method': 'GET', 'data': '', 'parameters': parameters,
            'timeout': timeout_override or PARAMETER_TOOL_TIMEOUTS[tool],
        })
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

# Dynamically loads reportServer.py in-process so its rendering/dedup helpers can be reused
# without importing the MCP server module (and its FastMCP app registration) at orchestrator startup.
def _load_report_server_module() -> Any:
    report_path = SERVERS / 'reporting' / 'reportServer.py'
    if not report_path.is_file():
        raise FileNotFoundError(report_path)
    module_name = '_secops_report_summary_runtime'
    module = sys.modules.get(module_name)
    if module is not None:
        return module
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
    return module

# Reuses the report deduplicator for the terminal finding summary.
def _report_flatten_findings_for_summary(results: dict[str, Any]) -> list[dict[str, Any]]:
    module = _load_report_server_module()
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
