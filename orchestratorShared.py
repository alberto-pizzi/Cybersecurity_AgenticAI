from __future__ import annotations
import argparse
import atexit
import ast
import asyncio
import functools
import html
import importlib.util
import json
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
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
warnings.filterwarnings('ignore', message='.*authlib\\.jose.*deprecated.*')
import requests
with warnings.catch_warnings():
    warnings.simplefilter('ignore')
    from fastmcp import Client
from utils import apply_runtime_target_preparation, absolute_url, canonical_cookie_header, cookie_names, load_runtime_config, normalize_url, parse_cookie_header, ROOT_DIR, same_origin, scanner_session_probe, SERVERS_DIR, target_runtime_profile, MCP_UNIFIED_SERVICE, mcp_http_port, mcp_http_url
ROOT = Path(ROOT_DIR).resolve()
SERVERS = Path(SERVERS_DIR).resolve()
RUNTIME_FILE = ROOT / '.secops_runtime.json'
UNIFIED_MCP_SERVER = 'secopsServer.py'
LOCAL_BIN = Path.home() / '.local' / 'bin'
MCP_CONNECT_TIMEOUT = float(os.getenv('SECOPS_MCP_CONNECT_TIMEOUT', '20'))
MCP_TOOL_TIMEOUT = float(os.getenv('SECOPS_MCP_TIMEOUT', '1200'))
MAX_PARAMETER_ENDPOINTS = max(1, int(os.getenv('SECOPS_MAX_PARAMETER_ENDPOINTS', '5')))
MAX_ARJUN_ENDPOINTS = max(1, int(os.getenv('SECOPS_MAX_ARJUN_ENDPOINTS', '3')))
MAX_CRAWL_PAGES = max(10, int(os.getenv('SECOPS_MAX_CRAWL_PAGES', '50')))
MAX_SCRIPT_ASSETS = max(4, int(os.getenv('SECOPS_MAX_SCRIPT_ASSETS', '24')))
SCANNER_PROGRESS_INTERVAL = max(10, int(os.getenv('SECOPS_PROGRESS_INTERVAL', '30')))
SCAN_MODES = {'fast': {'broad': {'zap': 90, 'nuclei': 90, 'nikto': 45, 'ffuf': 40, 'session': 20}, 'parameter': {'sqlmap': 60, 'dalfox': 35, 'commix': 40, 'traversal': 25, 'idor': 12, 'authorization': 25, 'browser': 35, 'workflow': 30}, 'limits': {'sqlmap': 1, 'dalfox': 1, 'commix': 1, 'traversal': 1, 'idor': 1, 'authorization': 1, 'browser': 1, 'workflow': 1}, 'arjun': 30, 'arjun_limit': 1}, 'balanced': {'broad': {'zap': 420, 'nuclei': 480, 'nikto': 105, 'ffuf': 90, 'session': 40}, 'parameter': {'sqlmap': 150, 'dalfox': 105, 'commix': 90, 'traversal': 60, 'idor': 30, 'authorization': 50, 'browser': 90, 'workflow': 75}, 'limits': {'sqlmap': 4, 'dalfox': 4, 'commix': 3, 'traversal': 4, 'idor': 3, 'authorization': 4, 'browser': 4, 'workflow': 4}, 'arjun': 90, 'arjun_limit': 3}, 'deep': {'broad': {'zap': 600, 'nuclei': 900, 'nikto': 180, 'ffuf': 150, 'session': 75}, 'parameter': {'sqlmap': 240, 'dalfox': 150, 'commix': 120, 'traversal': 90, 'idor': 60, 'authorization': 90, 'browser': 150, 'workflow': 120}, 'limits': {'sqlmap': 8, 'dalfox': 8, 'commix': 5, 'traversal': 8, 'idor': 6, 'authorization': 8, 'browser': 10, 'workflow': 10}, 'arjun': 120, 'arjun_limit': 8}}
CURRENT_SCAN_MODE = 'balanced'
BROAD_SCANNER_TIMEOUTS = dict(SCAN_MODES[CURRENT_SCAN_MODE]['broad'])
PARAMETER_TOOL_TIMEOUTS = dict(SCAN_MODES[CURRENT_SCAN_MODE]['parameter'])
PARAMETER_TOOL_CASE_LIMITS = dict(SCAN_MODES[CURRENT_SCAN_MODE]['limits'])
ARJUN_TIMEOUT = int(SCAN_MODES[CURRENT_SCAN_MODE]['arjun'])
ARJUN_ENDPOINT_LIMIT = int(SCAN_MODES[CURRENT_SCAN_MODE].get('arjun_limit', 1))

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

# Per-tool limits define how many actions each scanner may receive in the active profile.
def tool_action_limit(tool: str) -> int:

    name = str(tool or '').lower()
    if name == 'arjun':
        return ARJUN_ENDPOINT_LIMIT
    if name == 'interactsh':
        return 3 if CURRENT_SCAN_MODE == 'deep' else 2 if CURRENT_SCAN_MODE == 'balanced' else 1
    if name in PARAMETER_TOOL_CASE_LIMITS:
        return PARAMETER_TOOL_CASE_LIMITS[name]
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
    started = time.monotonic()
    if not server.is_file():
        return _result(spec.name, target, 'error', f'MCP server not found: {server}', 'missing_mcp_server_file')
    effective_arguments = dict(arguments)
    temporary_output: Path | None = None
    if spec.name == 'nuclei' and (not effective_arguments.get('output_file')):
        temporary_dir = ROOT / '.secops_tmp'
        temporary_dir.mkdir(parents=True, exist_ok=True)
        temporary_output = temporary_dir / f'nuclei-{uuid.uuid4().hex}.jsonl'
        effective_arguments['output_file'] = str(temporary_output)

    # Sends one MCP request to the prepared server URL and returns the normalized response.
    async def invoke(url: str) -> tuple[Any, bool, str]:
        async with Client(url) as client:
            return _extract_response(await client.call_tool(tool_name, effective_arguments))
    try:
        url = await asyncio.to_thread(_ensure_http_server)
        try:
            data, is_error, shape = await asyncio.wait_for(invoke(url), timeout=timeout_seconds + MCP_CONNECT_TIMEOUT)
        except Exception as first_exc:
            if not _http_transport_failure(first_exc):
                raise
            url = await asyncio.to_thread(_ensure_http_server, restart=True)
            data, is_error, shape = await asyncio.wait_for(invoke(url), timeout=timeout_seconds + MCP_CONNECT_TIMEOUT)
        result = _normalize_result(data, spec, target, time.monotonic() - started, is_error, shape)
        result.setdefault('_meta', {})['mcp_transport'] = 'streamable_http'
        result.setdefault('_meta', {})['mcp_url'] = url
    except (KeyboardInterrupt, asyncio.CancelledError):
        raise
    except Exception as exc:
        exception_text = f'{type(exc).__name__}: {exc}'
        exception_diagnosis = diagnose_error(exception_text)
        if exception_diagnosis == 'timeout':
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
        print(f"\n[SCANNER ERROR] {spec.name}: {target}\n  {result.get('output', '')}", file=sys.stderr)
    return result

# Calls one MCP tool while printing periodic progress messages.
async def call_mcp_with_progress(spec: ToolSpec, arguments: dict[str, Any], *, timeout_seconds: float=MCP_TOOL_TIMEOUT) -> dict[str, Any]:

    target = str(arguments.get('target_url', ''))
    scanner_limit = arguments.get('timeout')
    limit_text = f', scanner limit {scanner_limit}s' if scanner_limit else ''
    print(f'    [RUNNING ] {spec.name}: {target}{limit_text}', flush=True)
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

# Removes fragments and returns a clean URL for crawling.
def _clean_url(url: str) -> str:
    return urlunparse(urlparse(url)._replace(fragment=''))

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
    return not path.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.pdf', '.zip', '.gz', '.tar', '.mp4'))
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
def _safe_crawl_get(session: requests.Session, requested: str, target: str, *, timeout: tuple[int, int]=(5, 15), max_redirects: int=5) -> tuple[requests.Response | None, str, str]:

    current = _clean_url(requested)
    seen: set[str] = set()
    response: requests.Response | None = None
    for _ in range(max(0, int(max_redirects)) + 1):
        if _destructive_crawl_url(current):
            return (response, current, f'destructive_url_blocked:{current}')
        response = session.get(current, timeout=timeout, allow_redirects=False)
        if response.status_code not in {301, 302, 303, 307, 308}:
            return (response, current, '')
        location = str(response.headers.get('Location') or '').strip()
        if not location:
            return (response, current, '')
        try:
            candidate = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(current, location)))
        except Exception:
            return (response, current, 'invalid_redirect_location')
        if not same_origin(target, candidate):
            return (response, current, f'cross_origin_redirect_blocked:{candidate}')
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

# Extracts literal same-origin endpoint hints from JavaScript without executing the script.
def _javascript_endpoint_hints(text: str, base_url: str, target: str) -> list[dict[str, str]]:

    value = str(text or '')[:1000000]
    patterns = (
        (re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']", re.I), 'GET'),
        (re.compile(r"axios\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']", re.I), ''),
        (re.compile(r"\.open\s*\(\s*[\"'](GET|POST|PUT|PATCH|DELETE)[\"']\s*,\s*[\"']([^\"']+)[\"']", re.I), ''),
    )
    hints: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for pattern, fixed_method in patterns:
        for match in pattern.finditer(value):
            if fixed_method:
                method, raw_url = fixed_method, match.group(1)
            else:
                method, raw_url = match.group(1).upper(), match.group(2)
            if raw_url.startswith(('data:', 'javascript:', '#')) or '{' in raw_url or '}' in raw_url:
                continue
            try:
                url = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(base_url, raw_url)))
            except Exception:
                continue
            if not same_origin(target, url) or _destructive_crawl_url(url):
                continue
            key = (method, url)
            if key in seen:
                continue
            seen.add(key)
            hints.append({'method': method, 'url': url})
            if len(hints) >= 80:
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
            if isinstance(decoded, dict):
                for name, value in decoded.items():
                    parameters.append(str(name))
                    scalar = value if isinstance(value, (str, int, float, bool)) or value is None else ''
                    fields.append({'name': str(name), 'value': '' if scalar is None else str(scalar), 'type': 'json', 'tag': 'network'})
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
def _browser_network_discovery(target: str, cookies: str, html_urls: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[dict[str, Any]]]:

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return ([], [], [], [{'url': target, 'type': 'BrowserDiscoveryUnavailable', 'message': f'{type(exc).__name__}: {exc}'}])
    navigation_budget = 8 if CURRENT_SCAN_MODE == 'fast' else 30 if CURRENT_SCAN_MODE == 'balanced' else 60
    ranked_pages = sorted(set((_clean_url(value) for value in html_urls if value)), key=lambda value: (-_risk_terms(value), len(urlparse(value).path), value))
    target_url = _clean_url(target)
    if target_url in ranked_pages:
        ranked_pages.remove(target_url)
    queue: list[str] = [target_url, *ranked_pages]
    queued: set[str] = set(queue)
    navigated: list[str] = []
    visited: set[str] = set()
    observed: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    current_source = {'url': target_url}
    request_rows: dict[int, dict[str, Any]] = {}
    request_cases_by_id: dict[int, dict[str, Any]] = {}

    def enqueue_dynamic(raw_url: str) -> None:
        try:
            candidate = _normalize_redundant_base_path_link(target, _clean_url(raw_url))
        except Exception:
            return
        if not candidate or candidate in queued or candidate in visited:
            return
        if not same_origin(target, candidate) or not _crawlable_url(candidate) or _destructive_crawl_url(candidate):
            return
        queued.add(candidate)
        queue.insert(0, candidate)

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
                if same_origin(target, request_url) and (_destructive_crawl_url(request_url) or request_method not in {'GET', 'HEAD', 'OPTIONS'}):
                    route.abort()
                else:
                    route.continue_()

            context.route('**/*', route_guard)
            page = context.new_page()

            def record_request(request: Any) -> None:
                url = _clean_url(str(request.url or ''))
                if not url or not same_origin(target, url) or _destructive_crawl_url(url):
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
            while queue and len(visited) < navigation_budget:
                value = queue.pop(0)
                if value in visited:
                    continue
                visited.add(value)
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
    return (_dedupe_request_cases(cases), unique_observed, list(dict.fromkeys(navigated)), errors)

# Crawls the target and records pages, forms, parameters, scripts, browser requests, and auth state.
def discover_target(target: str, cookies: str, max_pages: int=MAX_CRAWL_PAGES, seeds: list[str] | None=None) -> dict[str, Any]:

    session = requests.Session()
    session.headers.update({'User-Agent': 'SecOps-Discovery/2.0', 'Accept': 'text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5'})
    if cookies:
        session.headers['Cookie'] = cookies
    target_preparation = apply_runtime_target_preparation(target, cookies) if cookies else {'performed': False, 'configured': False, 'usable': True}
    initial = [_clean_url(target), *[_clean_url(value) for value in seeds or []]]
    destructive_skipped: set[str] = set()
    queue: list[str] = []
    for value in dict.fromkeys(initial):
        if not same_origin(target, value) or not _crawlable_url(value):
            continue
        if _destructive_crawl_url(value):
            destructive_skipped.add(value)
            continue
        queue.append(value)
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
    while queue and len(visited) < max_pages:
        requested = queue.pop(0)
        if requested in visited:
            continue
        if _destructive_crawl_url(requested):
            destructive_skipped.add(requested)
            continue
        visited.add(requested)
        try:
            response, final, redirect_issue = _safe_crawl_get(session, requested, target, timeout=(5, 15), max_redirects=5)
        except requests.RequestException as exc:
            errors.append({'url': requested, 'type': type(exc).__name__, 'message': str(exc)})
            continue
        if response is None:
            errors.append({'url': requested, 'type': 'UnsafeURLBlocked', 'message': redirect_issue or final})
            continue
        final = _clean_url(final)
        if redirect_issue:
            errors.append({'url': requested, 'type': 'SafeRedirectGuard', 'message': redirect_issue})
            if redirect_issue.startswith(('destructive_', 'cross_origin_')):
                continue
        if not same_origin(target, final):
            errors.append({'url': requested, 'type': 'CrossOriginRedirect', 'message': final})
            continue
        visited.add(final)
        if requested == _clean_url(target) and _looks_like_login(response):
            initial_login_detected = True
        if response.status_code >= 400:
            errors.append({'url': final, 'type': f'HTTP{response.status_code}', 'message': response.reason or 'HTTP error'})
        content_type = response.headers.get('content-type', '').lower()
        if 'html' not in content_type and (not response.text.lstrip().startswith(('<', '<!'))):
            continue
        html_urls.add(final)
        tokens.update(re.findall('eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*', response.text))
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
        for source in parser.scripts:
            if len(scanned_script_urls) >= MAX_SCRIPT_ASSETS:
                break
            try:
                script_url = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(final, source)))
            except Exception:
                continue
            if not same_origin(target, script_url) or _destructive_crawl_url(script_url) or script_url in scanned_script_urls:
                continue
            scanned_script_urls.add(script_url)
            try:
                script_response, script_final, script_issue = _safe_crawl_get(session, script_url, target, timeout=(4, 12), max_redirects=4)
            except requests.RequestException as exc:
                errors.append({'url': script_url, 'type': type(exc).__name__, 'message': f'JavaScript fetch: {exc}'})
                continue
            if script_response is None or script_issue or script_response.status_code >= 400:
                continue
            script_final = _clean_url(script_final)
            if not same_origin(target, script_final):
                continue
            script_urls.add(script_final)
            for hint in _javascript_endpoint_hints(script_response.text, script_final, target):
                if hint not in script_endpoint_hints:
                    script_endpoint_hints.append(hint)
                if hint.get('method') == 'GET' and urlparse(str(hint.get('url') or '')).query:
                    hinted_url = str(hint['url'])
                    request_cases.append({'url': hinted_url, 'method': 'GET', 'data': '', 'parameters': [name for name, _ in parse_qsl(urlparse(hinted_url).query, keep_blank_values=True)], 'file_parameters': [], 'token_parameters': [], 'fields': [], 'source_url': script_final, 'discovery_source': 'javascript_literal'})
                    parameterized.add(hinted_url)
            js_sources, js_sinks = _client_side_source_sink_evidence(script_response.text)
            if js_sources and js_sinks:
                client_side_candidates.append({'url': final, 'script_url': script_final, 'sources': js_sources, 'sinks': js_sinks, 'evidence_source': 'same_origin_script'})
        for href in parser.links:
            try:
                candidate = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(final, href)))
            except Exception:
                continue
            if not same_origin(target, candidate) or not _crawlable_url(candidate):
                continue
            if _destructive_crawl_url(candidate):
                destructive_skipped.add(candidate)
                continue
            if urlparse(candidate).query:
                parameterized.add(candidate)
            if candidate not in visited and candidate not in queue:
                queue.append(candidate)
        for form in parser.forms:
            try:
                action = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(final, form['action'] or final)))
            except Exception:
                continue
            if not same_origin(target, action):
                continue
            if _destructive_crawl_url(action):
                destructive_skipped.add(action)
                continue
            fields = [field for field in form.get('fields', []) if isinstance(field, dict)]
            if fields:
                form_urls.add(final)
            case = _form_case(action, str(form.get('method', 'get')), fields, final, str(form.get('enctype', '')))
            if case:
                request_cases.append(case)
                if case['method'] == 'GET':
                    parameterized.add(case['url'])
    browser_cases, browser_network_requests, browser_navigation_urls, browser_errors = _browser_network_discovery(target, cookies, sorted(html_urls)) if html_urls else ([], [], [], [])
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
            probe_response, probe_final, probe_redirect_issue = _safe_crawl_get(session, probe_url, target, timeout=(5, 15), max_redirects=5)
            session.headers.clear()
            session.headers.update(original_headers)
            if probe_response is None:
                raise requests.RequestException(probe_redirect_issue or f'Session probe was blocked: {probe_final}')
            probe_response.url = probe_final
            final_login_detected = _looks_like_login(probe_response)
            anonymous_session = requests.Session()
            anonymous_session.headers.update({'User-Agent': 'SecOps-Discovery-Anonymous-Comparison/1.0', 'Cache-Control': 'no-cache'})
            anonymous_response, anonymous_final, anonymous_redirect_issue = _safe_crawl_get(anonymous_session, probe_url, target, timeout=(5, 15), max_redirects=5)
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
    return {'urls': sorted(visited), 'html_urls': sorted(html_urls), 'form_urls': sorted(form_urls), 'parameterized_urls': sorted(parameterized), 'request_cases': _dedupe_request_cases(request_cases), 'script_urls': sorted(script_urls), 'script_endpoint_hints': script_endpoint_hints, 'browser_network_requests': browser_network_requests, 'browser_navigation_urls': browser_navigation_urls, 'client_side_candidates': client_side_candidates, 'jwt_tokens': sorted(tokens), 'errors': errors, 'authentication_effective': auth_effective, 'authentication_note': auth_note, 'authentication_probe': auth_probe, 'target_preparation': target_preparation, 'destructive_urls_skipped': sorted(destructive_skipped)}

# Combines discovery results without duplicating pages or request cases.
def merge_discovery(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = dict(left)
    for key in ('urls', 'html_urls', 'form_urls', 'parameterized_urls', 'script_urls', 'browser_navigation_urls', 'jwt_tokens'):
        merged[key] = sorted(set(left.get(key, [])) | set(right.get(key, [])))
    merged['request_cases'] = _dedupe_request_cases([*left.get('request_cases', []), *right.get('request_cases', [])])
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
    if right.get('authentication_probe'):
        merged['authentication_probe'] = right.get('authentication_probe')
    if right.get('authentication_effective') is not None:
        merged['authentication_effective'] = right.get('authentication_effective')
        merged['authentication_note'] = right.get('authentication_note')
    return merged

# URL ranking relies on a small set of security-related words to prioritize discovered paths.
def _risk_terms(value: str) -> int:
    text = value.lower()
    tokens = set(re.findall('[a-z0-9]+', text))
    weights = {'cmd': 12, 'command': 12, 'exec': 12, 'shell': 12, 'sql': 11, 'query': 8, 'search': 7, 'file': 10, 'path': 10, 'include': 10, 'template': 9, 'upload': 8, 'url': 9, 'uri': 8, 'redirect': 8, 'callback': 8, 'webhook': 8, 'admin': 8, 'role': 8, 'user': 6, 'uid': 7, 'id': 5, 'token': 7, 'debug': 7, 'api': 5, 'xml': 7, 'deserialize': 10, 'xss': 10, 'sqli': 11, 'ssrf': 11, 'lfi': 11, 'rfi': 11}
    return sum((weight for term, weight in weights.items() if (term in tokens if len(term) <= 3 else term in text)))

# Request classification marks cases that belong to an authentication flow.
def _is_login_case(case: dict[str, Any]) -> bool:
    path = urlparse(str(case.get('url', ''))).path.lower()
    parameters = {str(value).lower() for value in case.get('parameters', [])}
    return path.endswith('/login') or path.endswith('/login.php') or bool({'username', 'password'} <= parameters)

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
TRAVERSAL_HINTS = {'file', 'filename', 'path', 'page', 'include', 'template', 'document', 'folder', 'dir', 'directory', 'view', 'resource', 'download'}
IDOR_HINTS = {'id', 'uid', 'user_id', 'userid', 'account_id', 'accountid', 'object_id', 'objectid', 'item_id', 'itemid', 'order_id', 'orderid', 'document_id', 'documentid', 'file_id', 'fileid', 'profile_id', 'profileid', 'dashboardid', 'widgetid', 'deviceid', 'modelid'}
NAVIGATION_PARAMETERS = {'pagetitle', 'linkid', 'fromsubmenu', 'showframe', 'redirect', 'linkurl'}

# Parameter extraction lists the names available in a normalized request case.
def _case_parameters(case: dict[str, Any]) -> set[str]:
    parameters = {str(value).lower() for value in case.get('parameters', []) if str(value)}
    parsed = urlparse(str(case.get('url', '')))
    parameters.update((name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)))
    return parameters

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
def _tool_case_priority(tool: str, case: dict[str, Any]) -> int:

    if _is_auto_index_case(case):
        return -1000
    url = str(case.get('url', ''))
    parsed = urlparse(url)
    path = parsed.path.lower()
    method = str(case.get('method', 'GET')).upper()
    parameters = _case_parameters(case)
    text = ' '.join((path, ' '.join(sorted(parameters))))
    score = _risk_terms(text)
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
        score += 45 if any((token in path for token in ('sql', 'query', 'database', 'search'))) else 0
        score += 18 if any((token in path for token in ('/api', 'data', 'device', 'model', 'dashboard', 'widget'))) else 0
        score += 14 * len(parameters & SQL_HINTS)
        score += 16 if method == 'POST' else 0
        score += 12 if 'json' in str(case.get('content_type') or case.get('enctype') or '').lower() else 0
        score += 8 if case.get('discovery_source') == 'playwright_network' else 0
        if parameters and parameters <= NAVIGATION_PARAMETERS and not (parameters & SQL_HINTS):
            score -= 65
        if _is_login_case(case) and (not any((token in path for token in ('sql', 'query', 'database')))):
            score -= 100
        if 'brute' in path and (not any((token in path for token in ('sql', 'query', 'database')))):
            score -= 90
        if any((token in path for token in ('xss', '/exec', '/csp'))) and (not parameters & SQL_HINTS):
            score -= 35
        return score
    if tool == 'dalfox':
        if _prefer_browser_for_xss_case(case):
            return -1000
        score += 45 if any((token in path for token in ('xss', 'comment', 'message', 'search', 'feedback'))) else 0
        score += 12 * len(parameters & XSS_HINTS)
        score += 10 if case.get('discovery_source') == 'playwright_network' else 0
        if any((token in path for token in ('sqli', '/exec', '/csp'))) and (not parameters & XSS_HINTS):
            score -= 35
        if _is_login_case(case):
            score -= 30
        return score
    if tool == 'commix':
        score += 55 if any((token in path for token in ('/exec', 'command', 'cmd'))) else 0
        score += 13 * len(parameters & COMMAND_HINTS)
        if any((token in path for token in ('sqli', 'xss', '/csp'))) and (not parameters & COMMAND_HINTS):
            score -= 45
        if _is_login_case(case):
            score -= 40
        return score
    if tool == 'traversal':
        score += 55 if any((token in path for token in ('include', 'download', 'file', 'template', 'document', 'view'))) else 0
        score += 15 * len(parameters & TRAVERSAL_HINTS)
        if any((token in path for token in ('sqli', 'xss', '/exec', '/csp'))) and (not parameters & TRAVERSAL_HINTS):
            score -= 45
        if _is_login_case(case):
            score -= 40
        return score
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
def _tool_case_skip_reason(tool: str, case: dict[str, Any]) -> str:
    if not [value for value in case.get('parameters', []) if str(value)]:
        return 'The request has no testable application parameter for this parameter scanner.'
    if _is_auto_index_case(case):
        return 'Directory-index sorting parameters are navigation controls, not application inputs.'
    if tool == 'dalfox' and _prefer_browser_for_xss_case(case):
        return 'Stored or DOM-oriented XSS contracts are delegated to the Chromium verifier, which can execute JavaScript and revisit state.'
    if tool in {'dalfox', 'commix'} and _is_login_case(case):
        return f'{tool} is not suited to the generic login form; SQLMap remains available for SQL-injection checks.'
    if tool == 'sqlmap' and 'brute' in urlparse(str(case.get('url', ''))).path.lower():
        return 'The brute-force handler is an authentication workflow, not a SQL-query request class.'
    if _tool_case_priority(tool, case) <= 0:
        if CURRENT_SCAN_MODE == 'deep' and case.get('deep_breadth') and tool in {'sqlmap', 'dalfox'}:
            return ''
        return f"The request was not selected because its path and parameters do not match {tool}'s vulnerability class."
    return ''

# Chooses the best request cases for one scanner and scan profile.
def select_tool_request_cases(discovery: dict[str, Any], tool: str, limit: int | None=None) -> list[dict[str, Any]]:

    effective_limit = limit or PARAMETER_TOOL_CASE_LIMITS.get(tool, MAX_PARAMETER_ENDPOINTS)
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
        score = _tool_case_priority(tool, case)
        if score > 0:
            ranked.append((score, -index, case))
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for _, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
        key = (str(case.get('method', 'GET')).upper(), str(case.get('url', '')), tuple(sorted((str(value) for value in case.get('parameters', [])))))
        if key in seen:
            continue
        seen.add(key)
        selected.append(case)
        if len(selected) >= effective_limit:
            break


    if CURRENT_SCAN_MODE == 'deep' and tool in {'sqlmap', 'dalfox'} and len(selected) < effective_limit:
        extra_budget = min(2, effective_limit - len(selected))
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
            key = (method, url, tuple(sorted(params)))
            if key in seen:
                continue
            generic_score = _risk_terms(path + ' ' + ' '.join(params)) + min(18, len(params) * 4)
            extras.append((generic_score, -index, {**case, 'deep_breadth': True, 'selection_reason': f'deep-generic-{tool}-coverage'}))
        for _, _, case in sorted(extras, key=lambda item: (-item[0], -item[1]))[:extra_budget]:
            key = (str(case.get('method', 'GET')).upper(), str(case.get('url', '')), tuple(sorted((str(value) for value in case.get('parameters', [])))))
            seen.add(key)
            selected.append(case)
    return selected
BROWSER_STATIC_SUFFIXES = {'.css', '.js', '.mjs', '.map', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.wav', '.mp4', '.webm', '.pdf', '.zip'}

# Browser XSS checks target rendered application pages, not standalone static assets.
def _browser_static_resource(url: str) -> bool:
    return Path(urlparse(str(url or '')).path.lower()).suffix in BROWSER_STATIC_SUFFIXES

WORKFLOW_STATE_HINTS = {'change', 'update', 'save', 'create', 'submit', 'send', 'comment', 'message', 'feedback', 'upload', 'password', 'email', 'profile', 'settings', 'transfer', 'captcha', 'admin'}
WORKFLOW_DESTRUCTIVE_HINTS = {'logout', 'signout', 'logoff', 'setup', 'install', 'delete', 'remove', 'drop', 'truncate', 'purge', 'wipe', 'reset'}

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
    parsed = urlparse(str(value or ''))
    port = parsed.port or (443 if parsed.scheme.lower() == 'https' else 80)
    path = re.sub('/+', '/', parsed.path or '/')
    if path != '/':
        path = path.rstrip('/')
    return (parsed.scheme.lower(), (parsed.hostname or '').lower(), port, path.lower())

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

    effective_limit = limit or PARAMETER_TOOL_CASE_LIMITS.get('browser', 2)
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
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, str, int, str], tuple[str, ...]]] = set()
    for score, _, case in ranked:
        if score <= 0:
            continue
        key = (str(case.get('method', 'GET')).upper(), _browser_url_key(str(case.get('url', ''))), tuple(sorted((str(value) for value in case.get('parameters', [])))))
        if key in seen:
            continue
        seen.add(key)
        selected.append(case)
        if len(selected) >= effective_limit:
            break
    if CURRENT_SCAN_MODE == 'deep' and len(selected) < effective_limit:
        extras: list[tuple[int, dict[str, Any]]] = []
        for case in cases:
            url = str(case.get('url') or '')
            method = str(case.get('method', 'GET')).upper()
            if not url or method not in {'GET', 'POST'} or _destructive_crawl_url(url) or _is_auto_index_case(case) or _browser_static_resource(url):
                continue
            path = urlparse(url).path.lower()
            if any(token in path for token in ('logout', 'setup', 'reset', 'delete')):
                continue
            params = tuple(sorted(str(value) for value in case.get('parameters', []) if str(value)))
            key = (method, _browser_url_key(url), params)
            if key in seen:
                continue
            score = _risk_terms(path + ' ' + ' '.join(params))
            if any(token in path for token in ('csp', 'javascript', 'brute', 'csrf', 'upload', 'redirect', 'callback')):
                score += 35
            if case.get('client_sources') or case.get('client_sinks'):
                score += 50
            if params:
                score += 15
            extras.append((score, {**case, 'selection_reason': 'deep-browser-breadth'}))
        for _, case in sorted(extras, key=lambda item: (-item[0], str(item[1].get('url') or '')))[:max(0, effective_limit - len(selected))]:
            selected.append(case)
            seen.add((str(case.get('method', 'GET')).upper(), _browser_url_key(str(case.get('url', ''))), tuple(sorted(str(value) for value in case.get('parameters', []) if str(value)))))
    return selected

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

    effective_limit = limit or PARAMETER_TOOL_CASE_LIMITS.get('workflow', 3)
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
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for _, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
        key = (str(case.get('method', 'POST')).upper(), str(case.get('url', '')), tuple(sorted(_case_field_names(case))))
        if key in seen:
            continue
        seen.add(key)
        selected.append(case)
        if len(selected) >= effective_limit:
            break
    return selected

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

    effective_limit = limit or PARAMETER_TOOL_CASE_LIMITS.get('authorization', 3)
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
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
        url = str(case.get('url') or '')
        if url in seen:
            continue
        seen.add(url)
        selected.append(case)
        if len(selected) >= effective_limit:
            break
    if CURRENT_SCAN_MODE == 'deep' and len(selected) < effective_limit:


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
            score = _risk_terms(path) + (12 if urlparse(url).query else 0)
            extras.append((score, {**case, 'selection_reason': 'deep-readonly-auth-breadth'}))
        for _, case in sorted(extras, key=lambda item: (-item[0], str(item[1].get('url') or '')))[:max(0, min(3, effective_limit - len(selected)))]:
            seen.add(str(case.get('url') or ''))
            selected.append(case)
    return selected

# Chooses and limits the endpoints sent to Arjun.
def select_arjun_request_cases(discovery: dict[str, Any], target: str, limit: int=MAX_ARJUN_ENDPOINTS) -> list[dict[str, Any]]:

    ranked: list[tuple[int, dict[str, Any]]] = []
    represented_paths: set[str] = set()
    for case in discovery.get('request_cases', []):
        if not isinstance(case, dict):
            continue
        url = normalize_url(str(case.get('url') or ''))
        method = str(case.get('method') or 'GET').upper()
        if not url or method not in {'GET', 'POST'} or (not same_origin(target, url)):
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
    for url in select_arjun_candidates(discovery, target, limit=max(limit * 3, 6)):
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
            if not url or not same_origin(target, url) or urlparse(url).query or _destructive_crawl_url(url):
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
            ranked.extend(relaxed[:max(0, limit - len(ranked))])
        elif not ranked and relaxed:
            ranked.append(relaxed[0])
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for _, case in sorted(ranked, key=lambda item: (-item[0], item[1]['url'])):
        key = (case['method'], urlparse(case['url']).path.lower())
        if key in seen:
            continue
        seen.add(key)
        selected.append(case)
        if len(selected) >= max(1, limit):
            break
    return selected

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
        score += 7 if method == 'POST' else 3
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
        if not url or method not in {'GET', 'POST'} or (not same_origin(target, url)):
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
            if not value or not same_origin(target, value):
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
                        print(f"    [ZAP FALLBACK] generic bounded active targets={len(fallback_urls)}; first={fallback_urls[0]}; rules={','.join(str(value) for value in fallback.get('rule_ids', []))}")
                    else:
                        print(f"    [ZAP FALLBACK] generic bounded active target={fallback.get('url', '')}; rules={','.join(str(value) for value in fallback.get('rule_ids', []))}")
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
            print(f"    [ZAP ACTIVE CASE] {item.get('method', 'GET')} {item.get('url', '')} — {state}; progress={item.get('progress', 0)}%; budget={item.get('budget_seconds', 0)}s")
        preparation = result.get('post_spider_target_preparation')
        if isinstance(preparation, dict) and preparation.get('configured'):
            print(f"    [ZAP TARGET STATE] reapplied={preparation.get('performed')}; usable={preparation.get('usable')}")
        for record in result.get('proxy_assisted_verification', []):
            if not isinstance(record, dict):
                continue
            if record.get('error'):
                print(f"    [ZAP PROXY CHECK] {record.get('method', 'GET')} {record.get('url', '')} — error: {record.get('error')}")
                continue
            if record.get('skipped'):
                print(f"    [ZAP PROXY CHECK] {record.get('method', 'GET')} {record.get('url', '')} — skipped: {record.get('skipped')}")
                continue
            for test in record.get('tests', []):
                if not isinstance(test, dict):
                    continue
                state = 'confirmed' if test.get('confirmed') else 'not-confirmed'
                print(f"    [ZAP PROXY CHECK] {record.get('method', 'GET')} {record.get('url', '')} — {test.get('type', 'probe')}={state}")
    if before.get('anonymous_profile'):
        print_coverage()
        return
    print(f"    [ZAP AUTH] ZAP={result.get('zap_version', before.get('zap_version', 'unknown'))}; Python API={result.get('python_zap_api_version', before.get('python_zap_api_version', 'unknown'))}")
    print(f"    [ZAP AUTH] probe={before.get('probe_url', '')}; cookie names={', '.join(before.get('cookie_names', [])) or 'none'}")
    direct = before.get('direct') if isinstance(before.get('direct'), dict) else {}
    direct_state = 'inconclusive' if before.get('conclusive') is False else str(before.get('effective') is True)
    print(f"    [ZAP AUTH] direct authenticated={direct_state}; proxy matches direct={before.get('proxy_matches_direct')}; history cookie exact={before.get('history_cookie_exact')}")
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
    print(f"    [{label:7}] {name}: {target or result.get('target', '')} — findings={total} (security/candidates={security}, observations={observations})")
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

# Writes a small JSON report if the normal reporting path cannot finish.
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
    injection_url = str(getattr(args, 'interactsh_injection_url', '') or '').strip()
    if injection_url and (not same_origin(target, injection_url)):
        parser.error('--interactsh-injection-url must have the same origin as --target.')
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
    arguments: dict[str, Any] = {'target_url': target_url, 'cookies': cookies}
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
            arguments.update({'seed_urls': discovery.get('html_urls', []), 'request_cases': discovery.get('request_cases', []), 'scan_mode': scan_mode, 'max_observations': 220 if CURRENT_SCAN_MODE == 'deep' else 80 if CURRENT_SCAN_MODE == 'balanced' or single_tool else 25})
            if single_tool:
                arguments['diagnostic_only'] = diagnostic_only
            elif diagnostic_only:
                arguments['diagnostic_only'] = True
        elif tool == 'nuclei':
            arguments.update({'seed_urls': discovery.get('urls', []), 'request_cases': discovery.get('request_cases', []), 'scan_profile': CURRENT_SCAN_MODE, 'max_targets': 40 if CURRENT_SCAN_MODE == 'deep' else 15 if CURRENT_SCAN_MODE == 'balanced' else 5})
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
        print(f"    {index}. [{str(row.get('risk') or 'info').upper()}] {row.get('alert') or 'Unnamed finding'} - tool={tool}; parameter={row.get('parameter') or '-'}; url={row.get('url') or ''}")
    print(f'[+] Candidates requiring validation: {len(candidates)}')
    for index, row in enumerate(candidates, 1):
        tools = row.get('tools') if isinstance(row.get('tools'), list) else []
        tool = ','.join(str(value) for value in tools if str(value)) or str(row.get('tool') or 'unknown')
        print(f"    {index}. [{str(row.get('risk') or 'info').upper()}] {row.get('alert') or 'Unnamed finding'} - tool={tool}; parameter={row.get('parameter') or '-'}; url={row.get('url') or ''}")

SINGLE_TOOL_CHOICES = tuple((spec.name for spec in ALL_TOOLS if spec.name != 'report'))
