from __future__ import annotations

import argparse
import ast
import asyncio
import html
import importlib.util
import json
import os
import re
import shutil
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

warnings.filterwarnings("ignore", message=r"authlib\.jose module is deprecated.*")

import requests
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from utils import (
    apply_runtime_target_preparation, absolute_url, canonical_cookie_header,
    cookie_names, normalize_url, ROOT_DIR, same_origin, scanner_session_probe,
    SERVERS_DIR, target_runtime_profile,
)

ROOT = Path(ROOT_DIR).resolve()
SERVERS = Path(SERVERS_DIR).resolve()
RUNTIME_FILE = ROOT / ".secops_runtime.json"
LOCAL_BIN = Path.home() / ".local" / "bin"
MCP_CONNECT_TIMEOUT = float(os.getenv("SECOPS_MCP_CONNECT_TIMEOUT", "20"))
MCP_TOOL_TIMEOUT = float(os.getenv("SECOPS_MCP_TIMEOUT", "900"))
MAX_PARAMETER_ENDPOINTS = max(1, int(os.getenv("SECOPS_MAX_PARAMETER_ENDPOINTS", "5")))
MAX_ARJUN_ENDPOINTS = max(1, int(os.getenv("SECOPS_MAX_ARJUN_ENDPOINTS", "3")))
MAX_CRAWL_PAGES = max(10, int(os.getenv("SECOPS_MAX_CRAWL_PAGES", "50")))
SCANNER_PROGRESS_INTERVAL = max(10, int(os.getenv("SECOPS_PROGRESS_INTERVAL", "30")))
SCAN_MODES = {
    "fast": {
        "broad": {"zap": 90, "nuclei": 40, "nikto": 45, "ffuf": 40},
        "parameter": {"sqlmap": 60, "dalfox": 35, "commix": 40, "traversal": 25, "idor": 12},
        "limits": {"sqlmap": 1, "dalfox": 1, "commix": 1, "traversal": 1, "idor": 1},
        "arjun": 30,
        "arjun_limit": 1,
    },
    "balanced": {
        "broad": {"zap": 240, "nuclei": 150, "nikto": 90, "ffuf": 75},
        "parameter": {"sqlmap": 120, "dalfox": 90, "commix": 75, "traversal": 45, "idor": 20},
        "limits": {"sqlmap": 3, "dalfox": 3, "commix": 1, "traversal": 2, "idor": 2},
        "arjun": 75,
        "arjun_limit": 2,
    },
    "deep": {
        "broad": {"zap": 480, "nuclei": 300, "nikto": 180, "ffuf": 120},
        "parameter": {"sqlmap": 240, "dalfox": 180, "commix": 150, "traversal": 90, "idor": 45},
        "limits": {"sqlmap": 5, "dalfox": 4, "commix": 2, "traversal": 3, "idor": 3},
        "arjun": 90,
        "arjun_limit": 3,
    },
}
CURRENT_SCAN_MODE = "balanced"
BROAD_SCANNER_TIMEOUTS = dict(SCAN_MODES[CURRENT_SCAN_MODE]["broad"])
PARAMETER_TOOL_TIMEOUTS = dict(SCAN_MODES[CURRENT_SCAN_MODE]["parameter"])
PARAMETER_TOOL_CASE_LIMITS = dict(SCAN_MODES[CURRENT_SCAN_MODE]["limits"])
ARJUN_TIMEOUT = int(SCAN_MODES[CURRENT_SCAN_MODE]["arjun"])
ARJUN_ENDPOINT_LIMIT = int(SCAN_MODES[CURRENT_SCAN_MODE].get("arjun_limit", 1))


def configure_scan_mode(mode: str) -> None:
    global CURRENT_SCAN_MODE, ARJUN_TIMEOUT, ARJUN_ENDPOINT_LIMIT
    selected = str(mode or "balanced").lower()
    if selected not in SCAN_MODES:
        raise ValueError(f"Unknown scan mode: {mode}")
    CURRENT_SCAN_MODE = selected
    profile = SCAN_MODES[selected]
    BROAD_SCANNER_TIMEOUTS.clear(); BROAD_SCANNER_TIMEOUTS.update(profile["broad"])
    PARAMETER_TOOL_TIMEOUTS.clear(); PARAMETER_TOOL_TIMEOUTS.update(profile["parameter"])
    PARAMETER_TOOL_CASE_LIMITS.clear(); PARAMETER_TOOL_CASE_LIMITS.update(profile["limits"])
    ARJUN_TIMEOUT = int(profile["arjun"])
    ARJUN_ENDPOINT_LIMIT = int(profile.get("arjun_limit", 1))

TIME_LIMIT_DIAGNOSES = {
    "timeout", "time_limit_reached", "timeout_with_partial_results",
    "timeout_with_confirmed_finding", "bounded_partial_scan",
}
ONE_SHOT_FALLBACK_TOOLS = {"zap", "nuclei", "nikto", "ffuf", "arjun", "sqlmap", "dalfox", "commix", "traversal", "idor", "jwt", "interactsh", "report"}
AUTO_INDEX_PARAMETERS = {"c", "n", "m", "s", "d", "o"}
OAST_PARAMETER_SCORES = {
    "url": 120, "uri": 115, "host": 115, "hostname": 115, "domain": 110,
    "callback": 130, "callback_url": 135, "webhook": 135, "webhook_url": 140,
    "endpoint": 100, "target": 95, "dest": 100, "destination": 105,
    "redirect": 80, "redirect_url": 90, "next": 55, "return": 55,
    "fetch": 120, "resource": 90, "remote": 100, "proxy": 105,
    "image": 65, "src": 70, "file": 75, "filename": 75, "path": 60,
    "page": 85, "include": 105, "template": 80,
    "feed": 90, "avatar": 65, "document": 65,
    "ip": 125, "cmd": 145, "command": 145, "exec": 140, "shell": 145, "ping": 130,
}
OAST_PATH_HINTS = ("ssrf", "webhook", "callback", "fetch", "proxy", "redirect", "remote", "url", "include", "exec", "command", "cmd")
OAST_URL_VALUE_PARAMETERS = {
    "url", "uri", "callback", "callback_url", "webhook", "webhook_url",
    "endpoint", "target", "dest", "destination", "redirect", "redirect_url",
    "next", "return", "fetch", "resource", "remote", "proxy", "image",
    "src", "file", "filename", "path", "page", "include", "template",
    "feed", "avatar", "document",
}
OAST_COMMAND_PARAMETERS = {"ip", "host", "hostname", "cmd", "command", "exec", "shell", "ping", "target", "domain"}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    server: str
    tool: str
    executable: str = ""
    module: str = ""
    required: bool = True


BASE_TOOLS = (
    # FFUF runs first so its high-value paths can be re-crawled and supplied to
    # ZAP before the active scan.
    ToolSpec("ffuf", "ffufServer.py", "run_ffuf_fuzz", "ffuf"),
    ToolSpec("zap", "zapServer.py", "run_zap_scan", module="zapv2"),
    ToolSpec("nuclei", "nucleiServer.py", "run_nuclei_scan", "nuclei"),
    ToolSpec("nikto", "niktoServer.py", "run_nikto_scan", "nikto"),
)
ARJUN_TOOL = ToolSpec("arjun", "arjunServer.py", "run_arjun_scan", "arjun")
PARAMETER_TOOLS = (
    ToolSpec("sqlmap", "sqlmapServer.py", "run_sqlmap_scan", "sqlmap"),
    ToolSpec("dalfox", "dalfoxServer.py", "run_dalfox_scan", "dalfox"),
    ToolSpec("commix", "commixServer.py", "run_commix_scan", "commix"),
    ToolSpec("traversal", "traversalServer.py", "run_traversal_scan"),
    ToolSpec("idor", "idorForgeServer.py", "run_idor_check"),
)
OPTIONAL_TOOLS = (
    ToolSpec("jwt", "jwtServer.py", "run_jwt_scan", module="jwt"),
    ToolSpec("interactsh", "interactshServer.py", "run_interactsh_client", "interactsh-client", required=False),
    ToolSpec("report", "pwndocServer.py", "generate_report", module="reportlab"),
)
ALL_TOOLS = (*BASE_TOOLS, ARJUN_TOOL, *PARAMETER_TOOLS, *OPTIONAL_TOOLS)

TOOL_SCOPES = {
    "ffuf": "base", "zap": "base", "nuclei": "base", "nikto": "base",
    "arjun": "url", "sqlmap": "parameterized", "dalfox": "parameterized",
    "commix": "parameterized", "traversal": "parameterized",
    "idor": "numeric", "jwt": "jwt", "interactsh": "oast",
}
TOOL_DESCRIPTIONS = {
    "ffuf": "Hidden resource and endpoint discovery.",
    "zap": "Session-aware crawling, passive analysis and prioritized active testing.",
    "nuclei": "Template-based exposure, misconfiguration and known-vulnerability checks.",
    "nikto": "Web-server hardening and exposed-resource checks.",
    "arjun": "Hidden GET/POST parameter discovery.",
    "sqlmap": "SQL-injection confirmation on discovered request contracts.",
    "dalfox": "Reflected and stored XSS testing.",
    "commix": "Operating-system command-injection testing.",
    "traversal": "Path-traversal and local-file-inclusion verification.",
    "idor": "Numeric object-reference differential checks.",
    "jwt": "JWT structure and claim analysis.",
    "interactsh": "Out-of-band callback confirmation.",
}

def agentic_registry() -> dict[str, tuple[str, str, str, str]]:
    """Expose the deterministic tool catalogue to the AI orchestrator."""
    return {
        spec.name: (
            spec.server, spec.tool, TOOL_SCOPES[spec.name],
            TOOL_DESCRIPTIONS[spec.name],
        )
        for spec in ALL_TOOLS
        if spec.name in TOOL_SCOPES
    }


def tool_action_limit(tool: str) -> int:
    """Return the per-profile action limit shared by both orchestrators."""
    name = str(tool or "").lower()
    if name == "arjun":
        return ARJUN_ENDPOINT_LIMIT
    if name == "interactsh":
        return 2 if CURRENT_SCAN_MODE == "deep" else 1
    if name in PARAMETER_TOOL_CASE_LIMITS:
        return PARAMETER_TOOL_CASE_LIMITS[name]
    return 1


def broad_tool_order(authenticated: bool) -> tuple[str, ...]:
    """Keep host-scanner order identical in deterministic and agentic runs."""
    return (
        ("zap", "ffuf", "nuclei", "nikto")
        if authenticated
        else ("ffuf", "zap", "nuclei", "nikto")
    )


def tool_execution_rank(tool: str, authenticated: bool) -> int:
    """Return a stable shared execution phase for a planned tool action."""
    broad = broad_tool_order(authenticated)
    if tool in broad:
        return broad.index(tool)
    phases = {
        "arjun": 10, "sqlmap": 20, "dalfox": 21, "commix": 22,
        "traversal": 23, "idor": 24, "jwt": 30, "interactsh": 31,
    }
    return phases.get(str(tool or "").lower(), 99)


# ---------------------------------------------------------------------------
# Runtime, server and MCP handling
# ---------------------------------------------------------------------------

def _load_runtime() -> dict[str, Any]:
    try:
        value = json.loads(RUNTIME_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _prepend_path(path: Path) -> None:
    if not path.is_dir():
        return
    resolved = str(path.resolve())
    current = [part for part in os.environ.get("PATH", "").split(os.pathsep) if part]
    keys = {os.path.normcase(os.path.abspath(part)) for part in current}
    if os.path.normcase(resolved) not in keys:
        os.environ["PATH"] = resolved + os.pathsep + os.environ.get("PATH", "")


def configure_runtime_path() -> list[str]:
    """Recreate the PATH written by initScript.py in every new process."""
    runtime = _load_runtime()
    candidates: list[Path] = [LOCAL_BIN]
    candidates += [Path(value) for value in runtime.get("tool_directories", []) if isinstance(value, str)]
    executables = runtime.get("executables", {})
    if isinstance(executables, dict):
        candidates += [Path(value).expanduser().parent for value in executables.values() if isinstance(value, str)]
    try:
        scripts = sysconfig.get_path("scripts", scheme="nt_user" if os.name == "nt" else "posix_user")
        if scripts:
            candidates.append(Path(scripts))
    except (KeyError, ValueError):
        pass
    try:
        import site
        candidates.append(Path(site.USER_BASE) / ("Scripts" if os.name == "nt" else "bin"))
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


def resolve_executable(name: str) -> str | None:
    configure_runtime_path()
    found = shutil.which(name)
    if found:
        return str(Path(found).resolve())
    value = _load_runtime().get("executables", {}).get(name)
    return str(Path(value).resolve()) if isinstance(value, str) and Path(value).is_file() else None


def _declared_functions(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return set()
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def resolve_server_path(filename: str, required_tool: str = "") -> Path:
    """
    Resolve only the canonical MCP server filename.

    Numbered browser copies such as nucleiServer(12).py are never executed.
    This prevents stale files from silently overriding the replacement.
    """
    return (SERVERS / Path(filename).name).resolve()


def _server_python() -> str:
    configured = _load_runtime().get("python_executable")
    if isinstance(configured, str) and Path(configured).is_file():
        return str(Path(configured).resolve())
    return str(Path(sys.executable).resolve())


def _server_env() -> dict[str, str]:
    configure_runtime_path()
    env = {str(key): str(value) for key, value in os.environ.items()}
    paths = [part for part in env.get("PYTHONPATH", "").split(os.pathsep) if part]
    if str(ROOT) not in paths:
        paths.insert(0, str(ROOT))
    env.update({
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.pathsep.join(paths),
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
        "SECOPS_PROJECT_ROOT": str(ROOT),
    })
    return env


def _transport(server: Path) -> StdioTransport:
    return StdioTransport(
        command=_server_python(),
        args=[str(server)],
        env=_server_env(),
        cwd=str(ROOT),
        keep_alive=False,
    )


def _extract_response(response: Any) -> tuple[Any, bool, str]:
    is_error = bool(getattr(response, "is_error", False) or getattr(response, "isError", False))
    for name in ("data", "structured_content", "structuredContent"):
        value = getattr(response, name, None)
        if value is not None:
            return value, is_error, name
    content = getattr(response, "content", response)
    if isinstance(content, list):
        values = [getattr(item, "text", item.get("text") if isinstance(item, dict) else item) for item in content]
        content = values[0] if len(values) == 1 else values
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except json.JSONDecodeError:
            pass
    return content, is_error, "content"


def diagnose_error(text: str) -> str:
    lowered = text.lower()
    rules = (
        (("no such file", "not found", "winerror 2"), "missing_file_or_executable"),
        (("no module named", "modulenotfounderror"), "missing_python_dependency"),
        (("connection refused", "failed to establish"), "service_unreachable"),
        (("timed out", "timeout"), "timeout"),
        (("permission denied", "access is denied"), "permission_denied"),
        (("tool not found", "method not found", "unknown tool"), "mcp_tool_name_mismatch"),
        (("connection closed", "closedresourceerror", "end of file"), "mcp_server_crashed"),
    )
    return next((cause for needles, cause in rules if any(item in lowered for item in needles)), "scanner_or_mcp_error")


def _finding_counts(result: dict[str, Any]) -> tuple[int, int, int]:
    findings = [item for item in (result.get("vulnerabilities") or []) if isinstance(item, dict)]
    security = 0
    for item in findings:
        category = str(item.get("category", "")).lower()
        risk = str(item.get("risk", "info")).lower()
        if category in {"vulnerability", "candidate"} or (not category and risk not in {"", "info"}):
            security += 1
    return len(findings), security, len(findings) - security


def _is_time_limited(result: dict[str, Any]) -> bool:
    diagnosis = str(result.get("diagnosis", "")).lower()
    text = " ".join(str(result.get(key, "")) for key in ("output", "stderr", "stdout")).lower()
    return bool(
        result.get("timed_out")
        or diagnosis in TIME_LIMIT_DIAGNOSES
        or "timeout" in diagnosis
        or "timed out" in text
        or "time limit" in text
        or "time budget" in text
    )


def _normalize_time_limit(result: dict[str, Any], tool: str, target: str) -> dict[str, Any]:
    """A configured scan budget is an incomplete result, not an execution error."""
    if result.get("hard_failure") or not _is_time_limited(result):
        return result
    total, security, observations = _finding_counts(result)
    previous = str(result.get("diagnosis", ""))
    result["status"] = "partial"
    result["timed_out"] = True
    result["time_limit_reached"] = True
    result["diagnosis"] = "time_limit_reached"
    if previous and previous != "time_limit_reached":
        result["original_diagnosis"] = previous
    result.setdefault("tool", tool)
    result.setdefault("target", target)
    result.setdefault("vulnerabilities", [])
    result["output"] = (
        f"Configured scan time budget reached. Findings preserved: {total} "
        f"(security/candidates: {security}, observations/discovery: {observations}). "
        "Coverage is incomplete, but the scanner did not fail."
    )
    return result


def _normalize_result(data: Any, spec: ToolSpec, target: str, elapsed: float, is_error: bool, shape: str) -> dict[str, Any]:
    if isinstance(data, dict):
        result = dict(data)
    else:
        result = {
            "tool": spec.name,
            "status": "error" if is_error else "success",
            "target": target,
            "output": data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, default=str),
            "vulnerabilities": [],
        }
    result.setdefault("tool", spec.name)
    result.setdefault("target", target)
    result.setdefault("output", "")
    result.setdefault("vulnerabilities", [])
    status = "error" if is_error else str(result.get("status", "success")).lower()
    result["status"] = status if status in {"success", "error", "skipped", "partial"} else "error"
    result["_meta"] = {
        "server": spec.server,
        "resolved_server": str(resolve_server_path(spec.server, spec.tool)),
        "duration_seconds": round(elapsed, 3),
        "response_shape": shape,
    }
    if result["status"] == "error":
        result.setdefault("diagnosis", diagnose_error(str(result.get("output", ""))))
    return _normalize_time_limit(result, spec.name, target)


def _startup_stderr(server: Path) -> str:
    """Capture immediate import/startup failures without pretending to speak MCP."""
    try:
        process = subprocess.Popen(
            [_server_python(), str(server)],
            cwd=str(ROOT), env=_server_env(), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
        )
        time.sleep(0.5)
        if process.poll() is None:
            process.terminate()
        _, stderr = process.communicate(timeout=3)
        return stderr[-6000:].strip()
    except Exception as exc:
        return f"Startup probe failed: {type(exc).__name__}: {exc}"


def _transport_failure(exc: BaseException) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(token in text for token in (
        "brokenresourceerror", "closedresourceerror", "connection closed",
        "end of file", "client failed to connect", "mcp server crashed",
    ))


def _call_server_once(
    server: Path,
    tool_name: str,
    arguments: dict[str, Any],
    timeout_seconds: float,
    tool: str,
) -> dict[str, Any]:
    """Run a scanner server in an isolated one-shot process after an MCP pipe crash."""
    process_limit = max(45, int(timeout_seconds) + 30)
    try:
        completed = subprocess.run(
            [_server_python(), str(server), "--once"],
            cwd=str(ROOT),
            env=_server_env(),
            input=json.dumps(arguments, ensure_ascii=False),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=process_limit,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "tool": tool,
            "status": "partial",
            "target": str(arguments.get("target_url", "")),
            "output": (
                f"{tool} isolated fallback reached its configured process budget. "
                "No execution failure is implied; coverage is incomplete."
            ),
            "vulnerabilities": [],
            "diagnosis": "time_limit_reached",
            "timed_out": True,
            "time_limit_reached": True,
            "stdout": exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            "stderr": exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
        }
    except OSError as exc:
        return {
            "tool": tool,
            "status": "error",
            "target": str(arguments.get("target_url", "")),
            "output": f"Cannot start {tool} isolated fallback: {exc}",
            "vulnerabilities": [],
            "diagnosis": "process_start_failed",
        }

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        value = {
            "tool": tool,
            "status": "error",
            "target": str(arguments.get("target_url", "")),
            "output": (
                f"{tool} isolated fallback returned invalid JSON. "
                f"Exit code={completed.returncode}; stderr={stderr[-2000:]}"
            ),
            "vulnerabilities": [],
            "diagnosis": "invalid_json_response",
            "stdout": stdout[-4000:],
            "stderr": stderr[-4000:],
        }
    if not isinstance(value, dict):
        value = {
            "tool": tool,
            "status": "error",
            "target": str(arguments.get("target_url", "")),
            "output": f"{tool} isolated fallback returned a non-object JSON value.",
            "vulnerabilities": [],
            "diagnosis": "invalid_json_response",
        }
    value.setdefault("_meta", {})["transport_fallback"] = "one_shot_subprocess"
    value.setdefault("_meta", {})["fallback_exit_code"] = completed.returncode
    if stderr:
        value.setdefault("_meta", {})["fallback_stderr"] = stderr[-2000:]
    return value


async def call_mcp(server_file: str, tool_name: str, arguments: dict[str, Any], timeout_seconds: float = MCP_TOOL_TIMEOUT) -> dict[str, Any]:
    spec = next((item for item in ALL_TOOLS if item.server == server_file and item.tool == tool_name), ToolSpec(tool_name, server_file, tool_name))
    server = resolve_server_path(server_file, tool_name)
    target = str(arguments.get("target_url", ""))
    started = time.monotonic()
    if not server.is_file():
        return {"tool": spec.name, "status": "error", "target": target, "output": f"MCP server not found: {server}", "vulnerabilities": [], "diagnosis": "missing_mcp_server_file"}

    effective_arguments = dict(arguments)
    temporary_output: Path | None = None
    if spec.name == "nuclei" and not effective_arguments.get("output_file"):
        temporary_dir = ROOT / ".secops_tmp"
        temporary_dir.mkdir(parents=True, exist_ok=True)
        temporary_output = temporary_dir / f"nuclei-{uuid.uuid4().hex}.jsonl"
        effective_arguments["output_file"] = str(temporary_output)

    async def invoke() -> tuple[Any, bool, str]:
        async with Client(_transport(server)) as client:
            return _extract_response(await client.call_tool(tool_name, effective_arguments))

    try:
        data, is_error, shape = await asyncio.wait_for(invoke(), timeout=timeout_seconds + MCP_CONNECT_TIMEOUT)
        result = _normalize_result(data, spec, target, time.monotonic() - started, is_error, shape)
    except (KeyboardInterrupt, asyncio.CancelledError):
        raise
    except Exception as exc:
        exception_text = f"{type(exc).__name__}: {exc}"
        exception_diagnosis = diagnose_error(exception_text)
        if exception_diagnosis == "timeout":
            result = {
                "tool": spec.name,
                "status": "partial",
                "target": target,
                "output": (
                    f"{spec.name} reached the orchestrator/MCP time budget. "
                    "Coverage is incomplete; this is not classified as a scanner error."
                ),
                "vulnerabilities": [],
                "diagnosis": "time_limit_reached",
                "timed_out": True,
                "time_limit_reached": True,
                "traceback": traceback.format_exc(),
                "_meta": {"server": str(server), "duration_seconds": round(time.monotonic() - started, 3)},
            }
        elif spec.name in ONE_SHOT_FALLBACK_TOOLS and _transport_failure(exc):
            print(
                f"    [WARNING] {spec.name} MCP channel closed; retrying in an isolated one-shot process.",
                file=sys.stderr,
            )
            internal_limit = float(effective_arguments.get("timeout", timeout_seconds))
            result = await asyncio.to_thread(
                _call_server_once,
                server,
                spec.tool,
                effective_arguments,
                min(internal_limit, timeout_seconds),
                spec.name,
            )
            result.setdefault("_meta", {})["mcp_failure"] = exception_text
        else:
            stderr = _startup_stderr(server)
            message = f"MCP communication failed: {exception_text}"
            if stderr:
                message += f" | server stderr: {stderr}"
            result = {
                "tool": spec.name, "status": "error", "target": target,
                "output": message, "vulnerabilities": [],
                "diagnosis": diagnose_error(message),
                "traceback": traceback.format_exc(),
                "_meta": {"server": str(server), "duration_seconds": round(time.monotonic() - started, 3)},
            }
    finally:
        if temporary_output:
            temporary_output.unlink(missing_ok=True)

    result = _normalize_time_limit(result, spec.name, target)
    if result.get("status") == "error":
        print(f"\n[SCANNER ERROR] {spec.name}: {target}\n  {result.get('output', '')}", file=sys.stderr)
    return result


async def call_mcp_with_progress(
    spec: ToolSpec,
    arguments: dict[str, Any],
    *,
    timeout_seconds: float = MCP_TOOL_TIMEOUT,
) -> dict[str, Any]:
    """Run one MCP scanner while showing which tool is active."""
    target = str(arguments.get("target_url", ""))
    scanner_limit = arguments.get("timeout")
    limit_text = f", scanner limit {scanner_limit}s" if scanner_limit else ""
    print(f"    [RUNNING ] {spec.name}: {target}{limit_text}", flush=True)

    started = time.monotonic()
    task = asyncio.create_task(
        call_mcp(spec.server, spec.tool, arguments, timeout_seconds=timeout_seconds)
    )
    while True:
        done, _ = await asyncio.wait({task}, timeout=SCANNER_PROGRESS_INTERVAL)
        if task in done:
            return await task
        elapsed = int(time.monotonic() - started)
        print(f"    [WAITING ] {spec.name}: still running after {elapsed}s", flush=True)


async def _live_server_check(spec: ToolSpec) -> dict[str, str]:
    server = resolve_server_path(spec.server, spec.tool)
    try:
        async def check() -> list[str]:
            async with Client(_transport(server)) as client:
                tools = await client.list_tools()
                return [str(getattr(tool, "name", "")) for tool in tools]
        names = await asyncio.wait_for(check(), timeout=MCP_CONNECT_TIMEOUT)
        if spec.tool not in names:
            return {"level": "error", "component": spec.name, "cause": "mcp_runtime_tool_missing", "detail": f"{server.name} exposed {names!r}"}
        return {"level": "ok", "component": spec.name, "cause": "mcp_stdio_handshake_ok", "detail": f"{server.name}: {spec.tool}()"}
    except Exception as exc:
        stderr = _startup_stderr(server)
        detail = f"{type(exc).__name__}: {exc}" + (f" | server stderr: {stderr}" if stderr else "")
        return {
            "level": "error" if spec.required else "warning",
            "component": spec.name,
            "cause": "mcp_stdio_handshake_failed",
            "detail": detail,
        }


def _nikto_runtime_check(executable: str) -> tuple[bool, str]:
    """Reject Nikto launchers that print Perl/module errors even when cmd.exe returns zero."""
    try:
        completed = subprocess.run(
            [executable, "-Version"],
            cwd=str(ROOT),
            env=_server_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            shell=False,
        )
    except Exception as exc:
        return False, f"Nikto runtime probe failed: {type(exc).__name__}: {exc}"

    combined = "\n".join((completed.stdout or "", completed.stderr or "")).strip()
    fatal = re.compile(
        r"(?:can't open perl script|cannot open perl script|invalid argument|required module not found|"
        r"not recognized|non .? riconosciuto|no such file|modulenotfounderror|traceback|^error:)",
        re.IGNORECASE | re.MULTILINE,
    )
    if completed.returncode != 0 or fatal.search(combined):
        return False, combined[-2000:] or f"exit={completed.returncode}"
    if not re.search(r"nikto|version", combined, re.IGNORECASE):
        return False, combined[-2000:] or "Nikto returned no version information."
    return True, combined[-1000:]


def _numbered_duplicate_servers() -> list[Path]:
    if not SERVERS.is_dir():
        return []
    pattern = re.compile(r".+\(\d+\)\.py$", re.IGNORECASE)
    return sorted(
        (
            path.resolve()
            for path in SERVERS.iterdir()
            if path.is_file() and pattern.fullmatch(path.name)
        ),
        key=lambda path: path.name.lower(),
    )


def run_preflight_checks(*, include_live: bool = True) -> list[dict[str, str]]:
    configure_runtime_path()
    checks: list[dict[str, str]] = []

    numbered_duplicates = _numbered_duplicate_servers()
    checks.append({
        "level": "warning" if numbered_duplicates else "ok",
        "component": "project",
        "cause": (
            "numbered_server_copies_found"
            if numbered_duplicates
            else "canonical_server_filenames"
        ),
        "detail": (
            "Move or delete numbered MCP copies: "
            + ", ".join(path.name for path in numbered_duplicates)
            if numbered_duplicates
            else "Only canonical MCP server filenames will be executed."
        ),
    })
    seen_executables: set[str] = set()
    for spec in ALL_TOOLS:
        server = resolve_server_path(spec.server, spec.tool)
        if not server.is_file():
            checks.append({"level": "error" if spec.required else "warning", "component": spec.name, "cause": "missing_server", "detail": str(server)})
            continue
        checks.append({"level": "ok", "component": spec.name, "cause": "mcp_tool_found", "detail": f"{server.name}: {spec.tool}()"})
        if spec.tool not in _declared_functions(server):
            checks[-1] = {"level": "error" if spec.required else "warning", "component": spec.name, "cause": "mcp_tool_name_mismatch", "detail": f"{server.name} does not declare {spec.tool}()"}
        if spec.module:
            checks.append({
                "level": "ok" if importlib.util.find_spec(spec.module) else ("error" if spec.required else "warning"),
                "component": spec.name,
                "cause": "python_dependency_found" if importlib.util.find_spec(spec.module) else "missing_python_dependency",
                "detail": spec.module,
            })
        if spec.executable and spec.executable not in seen_executables:
            seen_executables.add(spec.executable)
            executable = resolve_executable(spec.executable)
            checks.append({
                "level": "ok" if executable else ("error" if spec.required else "warning"),
                "component": spec.name,
                "cause": "executable_found" if executable else "missing_executable",
                "detail": executable or f"Not found: {spec.executable}; runtime={RUNTIME_FILE}",
            })
            if spec.name == "nikto" and executable:
                runtime = _load_runtime()
                docker_configured = (
                    runtime.get("nikto_execution_mode") == "docker_official_image"
                    or runtime.get("nikto_image") == "ghcr.io/sullo/nikto:latest"
                )
                docker_available = bool(shutil.which("docker"))
                docker_image_ready = False
                docker_detail = ""
                if docker_available:
                    try:
                        docker_probe = subprocess.run(
                            ["docker", "image", "inspect", "ghcr.io/sullo/nikto:latest"],
                            cwd=str(ROOT), capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=30, check=False,
                        )
                        docker_image_ready = docker_probe.returncode == 0
                        docker_detail = (
                            "Official Docker image is available: ghcr.io/sullo/nikto:latest"
                            if docker_image_ready
                            else (docker_probe.stderr or docker_probe.stdout or "Docker image inspection failed.").strip()[-1500:]
                        )
                    except Exception as exc:
                        docker_detail = f"Docker image probe failed: {type(exc).__name__}: {exc}"

                # initScript v21.2+ writes a Docker-backed nikto.bat marker. Do
                # not execute that batch file as though it were native Perl; its
                # source text previously produced the misleading 'runtime_ok' line.
                if docker_configured or docker_image_ready:
                    healthy = docker_image_ready
                    cause = "nikto_docker_fallback_ready" if healthy else "nikto_docker_image_missing"
                    runtime_detail = docker_detail or "Docker is unavailable or the image is missing."
                else:
                    healthy, runtime_detail = _nikto_runtime_check(executable)
                    cause = "nikto_runtime_ok" if healthy else "nikto_native_and_docker_unavailable"

                checks.append({
                    "level": "ok" if healthy else "error",
                    "component": "nikto",
                    "cause": cause,
                    "detail": runtime_detail,
                })
    if include_live and not any(item["level"] == "error" for item in checks):
        checks.extend(asyncio.run(_run_live_checks()))
    if not any(item["level"] == "error" for item in checks):
        checks.append({"level": "ok", "component": "mcp", "cause": "preflight_passed", "detail": "All contracts, executables and MCP STDIO handshakes passed."})
    return checks


async def _run_live_checks() -> list[dict[str, str]]:
    return [await _live_server_check(spec) for spec in ALL_TOOLS]


def print_preflight_report(checks: list[dict[str, str]], *, show_ok: bool = False) -> int:
    errors = [item for item in checks if item["level"] == "error"]
    warnings = [item for item in checks if item["level"] == "warning"]
    visible = checks if show_ok else [*errors, *warnings]
    if visible:
        print("\n=== SecOps preflight ===")
        for item in visible:
            marker = "+" if item["level"] == "ok" else ("!" if item["level"] == "warning" else "-")
            stream = sys.stdout if marker in {"+", "!"} else sys.stderr
            print(f"[{marker}] {item['component']}: {item['cause']} — {item['detail']}", file=stream)
    return len(errors)


# ---------------------------------------------------------------------------
# Discovery and result helpers
# ---------------------------------------------------------------------------

class LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        tag = tag.lower()
        if tag == "a" and values.get("href"):
            self.links.append(str(values["href"]))
        elif tag == "form":
            self.current = {
                "action": values.get("action", ""),
                "method": str(values.get("method", "get")).lower(),
                "fields": [],
            }
        elif tag in {"input", "textarea", "select", "button"} and self.current and values.get("name"):
            field_type = str(values.get("type", tag)).lower()
            self.current["fields"].append({
                "name": str(values["name"]),
                "value": str(values.get("value", "")),
                "type": field_type,
            })

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.current:
            self.forms.append(self.current)
            self.current = None


def _clean_url(url: str) -> str:
    return urlunparse(urlparse(url)._replace(fragment=""))


def _normalize_redundant_base_path_link(target: str, candidate: str) -> str:
    """Normalize links that accidentally repeat the target base path.

    Some training applications are mounted at a path such as `/academy` but
    emit links like `/academy/academy/login`. The correction is structural and
    does not depend on a product name.
    """
    base = urlparse(target)
    parsed = urlparse(candidate)
    base_path = base.path.rstrip("/")
    if not base_path:
        return candidate
    doubled = base_path + base_path + "/"
    if parsed.path.startswith(doubled):
        return urlunparse(parsed._replace(path=parsed.path[len(base_path):]))
    return candidate


def _crawlable_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return not path.endswith((
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".gz", ".tar", ".mp4",
    ))


DESTRUCTIVE_CRAWL_TOKENS = (
    "logout",
    "signout",
    "logoff",
    "setup",
    "install",
    "reset",
    "create_db",
    "create-database",
    "createdb",
    "drop_db",
    "drop-database",
)
STATE_CHANGING_QUERY_KEYS = {
    "create_db", "reset", "action", "delete", "remove", "logout",
    "password_new", "password_conf", "new_password", "confirm_password",
}


def _destructive_crawl_url(url: str) -> bool:
    parsed = urlparse(str(url or ""))
    text = f"{parsed.path}?{parsed.query}".lower()
    if any(token in text for token in DESTRUCTIVE_CRAWL_TOKENS):
        return True
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for name, value in pairs:
        lowered_name = name.lower()
        lowered_value = value.lower()
        if lowered_name in STATE_CHANGING_QUERY_KEYS:
            return True
    return False


def _clean_probe_url(url: str) -> str:
    """Remove fragments and state-changing query fields from a probe URL."""
    parsed = urlparse(str(url or ""))
    safe_pairs = [
        (name, value)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        if name.lower() not in STATE_CHANGING_QUERY_KEYS
    ]
    return urlunparse(parsed._replace(query=urlencode(safe_pairs), fragment=""))


def _runtime_probe_urls(target: str) -> list[str]:
    """Resolve optional exact-origin probe paths written by the initializer."""
    profile = target_runtime_profile(target)
    values = profile.get("probe_paths", []) if isinstance(profile, dict) else []
    result: list[str] = []
    for value in values if isinstance(values, list) else []:
        try:
            candidate = _clean_probe_url(absolute_url(target, str(value)))
        except Exception:
            continue
        if same_origin(target, candidate) and not _destructive_crawl_url(candidate):
            result.append(candidate)
    return result


def _stable_auth_probe_url(target: str, discovered_urls: list[str]) -> str:
    """Choose a stable same-origin page for session validation."""
    candidates = [*_runtime_probe_urls(target)]
    candidates.extend(
        _clean_probe_url(value)
        for value in discovered_urls
        if same_origin(target, value)
        and not _destructive_crawl_url(value)
        and not _looks_like_login_path(value)
    )
    candidates.append(_clean_probe_url(target))

    def score(value: str) -> int:
        parsed = urlparse(value)
        path = parsed.path.lower()
        score = 200
        if value in _runtime_probe_urls(target):
            score += 120
        if path in {"", "/"}:
            score += 30
        if any(token in path for token in ("account", "profile", "dashboard", "home", "admin", "settings", "console", "portal")):
            score += 80
        if any(token in path for token in ("login", "logout", "reset", "setup", "install", "register")):
            score -= 300
        if parsed.query:
            score -= 50
        return score

    unique = [
        value for value in dict.fromkeys(candidates)
        if value and same_origin(target, value) and score(value) > 0
    ]
    return max(unique, key=score) if unique else _clean_probe_url(target)


def _looks_like_login_path(url: str) -> bool:
    path = urlparse(str(url or "")).path.lower().rstrip("/")
    return path.endswith(("/login", "/login.php", "/signin", "/sign-in", "/auth"))


def _looks_like_login(response: requests.Response) -> bool:
    text = response.text[:100_000].lower()
    path = urlparse(response.url).path.lower().rstrip("/")
    password_field = bool(re.search(r"type\s*=\s*['\"]password['\"]", text))
    auth_words = any(term in text for term in ("login", "log in", "sign in", "signin", "authenticate"))
    return (
        path.endswith(("/login", "/login.php", "/signin", "/sign-in", "/auth"))
        or (password_field and auth_words)
    )


def _form_case(action: str, method: str, fields: list[dict[str, str]], source_url: str) -> dict[str, Any] | None:
    """Build a conservative GET/POST request case from one HTML form."""
    method = method.upper() if method else "GET"
    if method not in {"GET", "POST"}:
        return None
    pairs: list[tuple[str, str]] = []
    testable: list[str] = []
    for field in fields:
        name = str(field.get("name", "")).strip()
        if not name:
            continue
        field_type = str(field.get("type", "text")).lower()
        value = str(field.get("value", ""))
        if not value and field_type not in {"hidden", "submit", "button"}:
            value = "1"
        pairs.append((name, value))
        lowered = name.lower()
        if field_type not in {"hidden", "submit", "button", "reset", "file"} and not re.search(r"(?:csrf|token|nonce)", lowered):
            testable.append(name)
    if not pairs or not testable:
        return None
    encoded = urlencode(pairs)
    if method == "GET":
        parsed = urlparse(action)
        existing = list(parse_qsl(parsed.query, keep_blank_values=True))
        url = urlunparse(parsed._replace(query=urlencode([*existing, *pairs])))
        data = ""
    else:
        url, data = action, encoded
    return {
        "url": url, "method": method, "data": data,
        "parameters": list(dict.fromkeys(testable)), "source_url": source_url,
    }



def _dedupe_request_cases(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for case in cases:
        key = (
            str(case.get("method", "GET")).upper(),
            str(case.get("url", "")),
            tuple(sorted(str(value) for value in case.get("parameters", []) if value)),
        )
        if not key[1] or not key[2] or key in seen:
            continue
        seen.add(key)
        unique.append(case)
    return unique

def refresh_authenticated_session_state(
    target: str,
    cookies: str,
    probe_url: str = "",
) -> dict[str, Any]:
    """Reassert a generic authenticated session before a scanner.

    Optional target-specific preparation is read from initializer-generated
    runtime metadata. The orchestrator itself never contains product-specific
    requests or paths.
    """
    if not cookies:
        return {"performed": False, "authenticated": False, "usable": True}
    preparation = apply_runtime_target_preparation(target, cookies)
    selected_probe = probe_url or target
    probe = scanner_session_probe(selected_probe, cookies, timeout=10, attempts=3)
    usable = not (
        probe.get("conclusive") is True
        and probe.get("authenticated") is False
    ) and preparation.get("usable", True) is not False
    return {
        "performed": True,
        "authenticated": probe.get("authenticated"),
        "conclusive": probe.get("conclusive"),
        "preparation": preparation,
        "probe": probe,
        "usable": usable,
    }


def discover_target(
    target: str,
    cookies: str,
    max_pages: int = MAX_CRAWL_PAGES,
    seeds: list[str] | None = None,
) -> dict[str, Any]:
    """Crawl same-origin pages, forms and links while recording authentication quality."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SecOps-Discovery/2.0",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
    })
    if cookies:
        session.headers["Cookie"] = cookies

    target_preparation = (
        apply_runtime_target_preparation(target, cookies)
        if cookies
        else {"performed": False, "configured": False, "usable": True}
    )

    initial = [_clean_url(target), *[_clean_url(value) for value in (seeds or [])]]
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
            response = session.get(requested, timeout=(5, 15), allow_redirects=True)
        except requests.RequestException as exc:
            errors.append({"url": requested, "type": type(exc).__name__, "message": str(exc)})
            continue

        final = _clean_url(response.url)
        if not same_origin(target, final):
            errors.append({"url": requested, "type": "CrossOriginRedirect", "message": final})
            continue
        visited.add(final)
        if requested == _clean_url(target) and _looks_like_login(response):
            initial_login_detected = True
        if response.status_code >= 400:
            errors.append({"url": final, "type": f"HTTP{response.status_code}", "message": response.reason or "HTTP error"})

        content_type = response.headers.get("content-type", "").lower()
        if "html" not in content_type and not response.text.lstrip().startswith(("<", "<!")):
            continue
        html_urls.add(final)
        tokens.update(re.findall(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", response.text))

        parser = LinkFormParser()
        try:
            parser.feed(response.text)
            parser.close()
        except Exception as exc:
            errors.append({"url": final, "type": type(exc).__name__, "message": f"HTML parse: {exc}"})
            continue

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
                action = _normalize_redundant_base_path_link(target, _clean_url(absolute_url(final, form["action"] or final)))
            except Exception:
                continue
            if not same_origin(target, action):
                continue
            if _destructive_crawl_url(action):
                destructive_skipped.add(action)
                continue
            fields = [field for field in form.get("fields", []) if isinstance(field, dict)]
            if fields:
                form_urls.add(final)
            case = _form_case(action, str(form.get("method", "get")), fields, final)
            if case:
                request_cases.append(case)
                if case["method"] == "GET":
                    parameterized.add(case["url"])

    auth_effective: bool | None = None
    auth_note = "Anonymous profile."
    auth_probe: dict[str, Any] = {}
    if cookies:
        probe_url = _stable_auth_probe_url(target, sorted(html_urls))
        try:
            probe_response = session.get(
                probe_url,
                timeout=(5, 15),
                allow_redirects=True,
                headers={"Cache-Control": "no-cache"},
            )
            final_login_detected = _looks_like_login(probe_response)
            anonymous_response = requests.get(
                probe_url,
                timeout=(5, 15),
                allow_redirects=True,
                headers={
                    "User-Agent": "SecOps-Discovery-Anonymous-Comparison/1.0",
                    "Cache-Control": "no-cache",
                },
            )
            anonymous_login_detected = _looks_like_login(anonymous_response)
            authenticated_good = (
                not initial_login_detected
                and not final_login_detected
                and probe_response.status_code < 400
                and target_preparation.get("usable", True) is not False
            )
            clear_anonymous_difference = (
                anonymous_login_detected
                or (anonymous_response.status_code in {401, 403} and probe_response.status_code < 400)
                or (
                    same_origin(target, probe_response.url)
                    and same_origin(target, anonymous_response.url)
                    and _clean_url(probe_response.url) != _clean_url(anonymous_response.url)
                )
            )
            if not authenticated_good:
                auth_effective = False
            elif clear_anonymous_difference:
                auth_effective = True
            else:
                # A public page can look healthy with any cookie. Keep the
                # profile usable, but do not falsely claim proven authentication.
                auth_effective = None
            auth_probe = {
                "url": probe_url,
                "status": probe_response.status_code,
                "final_url": str(probe_response.url),
                "login_detected": final_login_detected,
                "anonymous_status": anonymous_response.status_code,
                "anonymous_final_url": str(anonymous_response.url),
                "anonymous_login_detected": anonymous_login_detected,
                "authenticated_distinguished_from_anonymous": (
                    True if clear_anonymous_difference else None
                ),
            }
        except requests.RequestException as exc:
            # Network errors make the check inconclusive. They do not prove that
            # a supplied session is invalid.
            auth_effective = None
            auth_probe = {
                "url": probe_url,
                "error": f"{type(exc).__name__}: {exc}",
                "conclusive": False,
            }

        auth_note = (
            "The supplied cookie was distinguished from the anonymous response."
            if auth_effective is True else
            "The supplied cookie reached a login or authorization failure page."
            if auth_effective is False else
            "The supplied cookie remained usable, but this target did not expose a conclusive anonymous/authenticated distinction."
        )
    return {
        "urls": sorted(visited),
        "html_urls": sorted(html_urls),
        "form_urls": sorted(form_urls),
        "parameterized_urls": sorted(parameterized),
        "request_cases": _dedupe_request_cases(request_cases),
        "jwt_tokens": sorted(tokens),
        "errors": errors,
        "authentication_effective": auth_effective,
        "authentication_note": auth_note,
        "authentication_probe": auth_probe,
        "target_preparation": target_preparation,
        "destructive_urls_skipped": sorted(destructive_skipped),
    }


def merge_discovery(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = dict(left)
    for key in ("urls", "html_urls", "form_urls", "parameterized_urls", "jwt_tokens"):
        merged[key] = sorted(set(left.get(key, [])) | set(right.get(key, [])))
    merged["request_cases"] = _dedupe_request_cases([*left.get("request_cases", []), *right.get("request_cases", [])])
    merged["errors"] = [*left.get("errors", []), *right.get("errors", [])]
    merged["destructive_urls_skipped"] = sorted(
        set(left.get("destructive_urls_skipped", []))
        | set(right.get("destructive_urls_skipped", []))
    )
    if right.get("authentication_probe"):
        merged["authentication_probe"] = right.get("authentication_probe")
    if right.get("authentication_effective") is not None:
        merged["authentication_effective"] = right.get("authentication_effective")
        merged["authentication_note"] = right.get("authentication_note")
    return merged


def _risk_terms(value: str) -> int:
    text = value.lower()
    tokens = set(re.findall(r"[a-z0-9]+", text))
    weights = {
        "cmd": 12, "command": 12, "exec": 12, "shell": 12,
        "sql": 11, "query": 8, "search": 7,
        "file": 10, "path": 10, "include": 10, "template": 9, "upload": 8,
        "url": 9, "uri": 8, "redirect": 8, "callback": 8, "webhook": 8,
        "admin": 8, "role": 8, "user": 6, "uid": 7, "id": 5,
        "token": 7, "debug": 7, "api": 5, "xml": 7, "deserialize": 10,
        "xss": 10, "sqli": 11, "ssrf": 11, "lfi": 11, "rfi": 11,
    }
    return sum(
        weight for term, weight in weights.items()
        if (term in tokens if len(term) <= 3 else term in text)
    )


def _is_login_case(case: dict[str, Any]) -> bool:
    path = urlparse(str(case.get("url", ""))).path.lower()
    parameters = {str(value).lower() for value in case.get("parameters", [])}
    return (
        path.endswith("/login")
        or path.endswith("/login.php")
        or bool({"username", "password"} <= parameters)
    )


def _is_auto_index_url(url: str) -> bool:
    """Identify Apache/nginx directory-list sorting links such as ?C=D;O=A."""
    parsed = urlparse(str(url))
    names = {
        name.lower()
        for name, _ in parse_qsl(parsed.query.replace(";", "&"), keep_blank_values=True)
    }
    return bool(names) and names <= AUTO_INDEX_PARAMETERS and parsed.path.endswith("/")


def _is_auto_index_case(case: dict[str, Any]) -> bool:
    names = {str(value).lower() for value in case.get("parameters", [])}
    return _is_auto_index_url(str(case.get("url", ""))) or (
        bool(names)
        and names <= AUTO_INDEX_PARAMETERS
        and urlparse(str(case.get("url", ""))).path.endswith("/")
    )


SQL_HINTS = {
    "id", "uid", "user", "user_id", "username", "email", "account",
    "query", "search", "q", "category", "product", "item", "order",
}
XSS_HINTS = {
    "name", "message", "comment", "search", "query", "q", "input",
    "text", "title", "url", "redirect", "callback",
}
COMMAND_HINTS = {
    "cmd", "command", "exec", "shell", "ip", "host", "hostname",
    "ping", "target", "domain",
}
TRAVERSAL_HINTS = {
    "file", "filename", "path", "page", "include", "template", "document",
    "folder", "dir", "directory", "view", "resource", "download",
}
IDOR_HINTS = {
    "id", "uid", "user_id", "account_id", "object_id", "item_id",
    "order_id", "document_id", "file_id", "profile_id",
}


def _case_parameters(case: dict[str, Any]) -> set[str]:
    parameters = {str(value).lower() for value in case.get("parameters", []) if str(value)}
    parsed = urlparse(str(case.get("url", "")))
    parameters.update(name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    return parameters


def _tool_case_priority(tool: str, case: dict[str, Any]) -> int:
    """Score request cases for the scanner that is actually suited to them."""
    if _is_auto_index_case(case):
        return -1000

    url = str(case.get("url", ""))
    parsed = urlparse(url)
    path = parsed.path.lower()
    method = str(case.get("method", "GET")).upper()
    parameters = _case_parameters(case)
    text = " ".join((path, " ".join(sorted(parameters))))
    score = _risk_terms(text)

    if tool == "sqlmap":
        score += 45 if any(token in path for token in ("sql", "query", "database", "search")) else 0
        score += 9 * len(parameters & SQL_HINTS)
        score += 12 if _is_login_case(case) else 0
        if any(token in path for token in ("xss", "/exec", "/csp")) and not (parameters & SQL_HINTS):
            score -= 35
        return score

    if tool == "dalfox":
        score += 45 if any(token in path for token in ("xss", "comment", "message", "search", "feedback")) else 0
        score += 10 * len(parameters & XSS_HINTS)
        if any(token in path for token in ("sqli", "/exec", "/csp")) and not (parameters & XSS_HINTS):
            score -= 35
        if _is_login_case(case):
            score -= 30
        return score

    if tool == "commix":
        score += 55 if any(token in path for token in ("/exec", "command", "cmd")) else 0
        score += 13 * len(parameters & COMMAND_HINTS)
        if any(token in path for token in ("sqli", "xss", "/csp")) and not (parameters & COMMAND_HINTS):
            score -= 45
        if _is_login_case(case):
            score -= 40
        return score

    if tool == "traversal":
        score += 55 if any(token in path for token in ("include", "download", "file", "template", "document", "view")) else 0
        score += 15 * len(parameters & TRAVERSAL_HINTS)
        if any(token in path for token in ("sqli", "xss", "/exec", "/csp")) and not (parameters & TRAVERSAL_HINTS):
            score -= 45
        if _is_login_case(case):
            score -= 40
        return score

    if tool == "idor":
        if method != "GET":
            return -1000
        numeric_pairs = [
            (name.lower(), value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
            if value.isdigit()
        ]
        object_pairs = [(name, value) for name, value in numeric_pairs if name in IDOR_HINTS]
        if not object_pairs or any(token in path for token in ("brute", "csrf", "password", "sqli", "xss", "/exec", "/csp")):
            return -1000
        score = 20 + 28 * len(object_pairs)
        score += 25 if any(token in path for token in ("idor", "object", "profile", "account", "user")) else 0
        if any(token in path for token in ("sqli", "xss", "/exec", "/csp")):
            score -= 60
        return score

    return score


def _tool_case_skip_reason(tool: str, case: dict[str, Any]) -> str:
    if _is_auto_index_case(case):
        return "Directory-index sorting parameters are navigation controls, not application inputs."
    if tool in {"dalfox", "commix"} and _is_login_case(case):
        return f"{tool} is not suited to the generic login form; SQLMap remains available for SQL-injection checks."
    if _tool_case_priority(tool, case) <= 0:
        return f"The request was not selected because its path and parameters do not match {tool}'s vulnerability class."
    return ""


def select_tool_request_cases(
    discovery: dict[str, Any],
    tool: str,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Choose the highest-value request cases separately for each scanner."""
    effective_limit = limit or PARAMETER_TOOL_CASE_LIMITS.get(tool, MAX_PARAMETER_ENDPOINTS)
    cases = [case for case in discovery.get("request_cases", []) if isinstance(case, dict)]
    known = {str(case.get("url") or "") for case in cases}
    for value in discovery.get("parameterized_urls", []):
        url = str(value or "")
        if url and url not in known:
            cases.append({
                "url": url,
                "method": "GET",
                "data": "",
                "parameters": [
                    name for name, _ in parse_qsl(
                        urlparse(url).query, keep_blank_values=True
                    )
                ],
                "source_url": url,
                "synthetic_from_parameterized_url": True,
            })
    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            continue
        score = _tool_case_priority(tool, case)
        if score > 0:
            ranked.append((score, -index, case))

    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for _, _, case in sorted(ranked, key=lambda item: (-item[0], -item[1])):
        key = (
            str(case.get("method", "GET")).upper(),
            str(case.get("url", "")),
            tuple(sorted(str(value) for value in case.get("parameters", []))),
        )
        if key in seen:
            continue
        seen.add(key)
        selected.append(case)
        if len(selected) >= effective_limit:
            break
    return selected


def select_arjun_candidates(discovery: dict[str, Any], target: str, limit: int = MAX_ARJUN_ENDPOINTS) -> list[str]:
    """
    Rank Arjun targets by likely security value without blanket-excluding useful pages.

    - logout endpoints are excluded because probing them can destroy the session;
    - authentication and setup endpoints are excluded because they are already
      modeled by discovery and may change session state;
    - plain directory indexes are skipped;
    - input-bearing API and application handlers are ranked first.
    """
    form_urls = {normalize_url(str(url)) for url in discovery.get("form_urls", [])}
    request_cases = [
        case for case in discovery.get("request_cases", [])
        if isinstance(case, dict)
    ]
    case_by_url: dict[str, list[dict[str, Any]]] = {}
    for case in request_cases:
        case_url = normalize_url(str(case.get("url", "")))
        if case_url:
            case_by_url.setdefault(case_url, []).append(case)

    candidates = {
        normalize_url(str(url))
        for url in (*discovery.get("html_urls", []), *discovery.get("form_urls", []))
        if str(url)
    }
    ranked: list[tuple[int, str]] = []
    low_value = ("brute", "captcha", "csrf")
    preferred = (
        "/api/", "/admin/", "/search", "/query", "/upload", "/download",
        "/callback", "/webhook", "/execute", "/command",
    )

    for url in candidates:
        parsed = urlparse(url)
        path = parsed.path.lower()
        if (
            "logout" in path
            or _is_auto_index_url(url)
            or path.endswith(("/login.php", "/login", "/setup.php"))
        ):
            continue

        related_cases = case_by_url.get(url, [])
        has_form = url in form_urls
        has_existing_parameters = bool(parsed.query) or any(
            case.get("parameters") for case in related_cases
        )

        # Directory indexes such as /config/?C=D;O=A are navigation pages, not
        # useful hidden-parameter targets. A real form/API under those paths is
        # still retained.
        directory_utility = "/config/" in path or "/docs/" in path
        if directory_utility and not has_form and not has_existing_parameters:
            continue

        score = _risk_terms(path)
        if has_form:
            score += 14
        if has_existing_parameters:
            score += 10
        if any(token in path for token in preferred):
            score += 22

        if path.endswith("/login.php") or path.endswith("/login"):
            # Login forms are already covered by discovery and SQLMap. Hidden
            # parameter mining here consumed the full Arjun budget with very
            # little security value.
            score -= 100
        if "setup" in path:
            score += 1 if has_form or has_existing_parameters else -9
        if directory_utility:
            score -= 5
        if any(term in path for term in low_value):
            score -= 8

        # Keep actual input handlers even when their path name has no risk term.
        if score <= 0 and (has_form or has_existing_parameters):
            score = 1
        if score > 0:
            ranked.append((score, _clean_url(url)))

    # De-duplicate while preserving the highest score for each clean URL.
    best: dict[str, int] = {}
    for score, url in ranked:
        best[url] = max(score, best.get(url, score))
    return [
        url for url, _ in sorted(best.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]

def select_arjun_request_cases(
    discovery: dict[str, Any],
    target: str,
    limit: int = MAX_ARJUN_ENDPOINTS,
) -> list[dict[str, Any]]:
    """Select real GET/POST request contracts for Arjun.

    Existing code passed POST-only handlers to Arjun while forcing `-m GET`.
    This function preserves the discovered method and form body and excludes
    login/state-changing utility pages.
    """
    ranked: list[tuple[int, dict[str, Any]]] = []
    for case in discovery.get("request_cases", []):
        if not isinstance(case, dict):
            continue
        url = normalize_url(str(case.get("url") or ""))
        method = str(case.get("method") or "GET").upper()
        if not url or method not in {"GET", "POST"} or not same_origin(target, url):
            continue
        path = urlparse(url).path.lower()
        if _destructive_crawl_url(url) or path.endswith(("/login.php", "/login", "/setup.php")):
            continue
        parameters = [str(value) for value in case.get("parameters", []) if str(value)]
        # Existing parameters reduce the value of hidden-name discovery, while
        # POST contracts remain important for generic applications.
        score = _risk_terms(path) + (15 if method == "POST" else 5)
        score -= min(20, len(parameters) * 4)
        ranked.append((score, {
            "url": url,
            "method": method,
            "data": str(case.get("data") or ""),
            "parameters": parameters,
        }))
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for _, case in sorted(ranked, key=lambda item: -item[0]):
        key = (case["method"], urlparse(case["url"]).path.lower())
        if key in seen:
            continue
        seen.add(key)
        selected.append(case)
        if len(selected) >= max(1, limit):
            break
    return selected


def select_request_cases(discovery: dict[str, Any], limit: int = MAX_PARAMETER_ENDPOINTS) -> list[dict[str, Any]]:
    """Select non-destructive cases, ranking likely injection/authorization inputs first."""
    cases = list(discovery.get("request_cases", []))
    known_urls = {str(case.get("url", "")) for case in cases}
    for url in discovery.get("parameterized_urls", []):
        if url not in known_urls:
            cases.append({
                "url": url, "method": "GET", "data": "",
                "parameters": [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)],
                "source_url": url,
            })

    ranked: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for case in cases:
        url = str(case.get("url", ""))
        method = str(case.get("method", "GET")).upper()
        path = urlparse(url).path.lower()
        if not url or method not in {"GET", "POST"} or any(part in path for part in ("logout", "setup")):
            continue
        if _is_auto_index_case(case):
            continue
        parameters = tuple(sorted(str(value) for value in case.get("parameters", []) if value))
        key = (method, urlparse(url)._replace(query="").geturl(), parameters)
        if not parameters or key in seen:
            continue
        seen.add(key)
        score = _risk_terms(path + " " + " ".join(parameters))
        score += 7 if method == "POST" else 3
        if _is_login_case(case):
            score -= 20
        score += min(8, len(parameters) * 2)
        ranked.append((score, {**case, "method": method, "parameters": list(parameters), "priority_score": score}))
    ranked.sort(key=lambda item: (-item[0], str(item[1].get("url", ""))))
    return [case for _, case in ranked[:limit]]

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


def select_oast_request_cases(
    discovery: dict[str, Any],
    target: str,
    limit: int = 1,
) -> list[dict[str, Any]]:
    """Select concrete GET/POST inputs suitable for an Interactsh OAST probe.

    Interactsh is not launched blindly. It is automatically used when discovery
    exposes a parameter whose name or path indicates a server-side URL fetch,
    callback, webhook, redirect, proxy, remote-file, or XML processing path.
    """
    ranked: list[tuple[int, dict[str, Any]]] = []
    for case in discovery.get("request_cases", []):
        if not isinstance(case, dict):
            continue
        url = str(case.get("url") or "")
        method = str(case.get("method") or "GET").upper()
        if not url or method not in {"GET", "POST"} or not same_origin(target, url):
            continue
        path = urlparse(url).path.lower()
        if any(token in path for token in ("logout", "setup", "install", "reset", "delete")):
            continue

        query_pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
        body_pairs = parse_qsl(str(case.get("data") or ""), keep_blank_values=True) if method == "POST" else []
        names = {str(value).lower() for value in case.get("parameters", []) if str(value)}
        names.update(name.lower() for name, _ in query_pairs)
        names.update(name.lower() for name, _ in body_pairs)
        strong = [name for name in names if name in OAST_PARAMETER_SCORES]
        path_bonus = 35 if any(hint in path for hint in OAST_PATH_HINTS) else 0
        if not strong:
            continue
        parameter = max(strong, key=lambda name: OAST_PARAMETER_SCORES[name])
        score = OAST_PARAMETER_SCORES[parameter] + path_bonus + (8 if method == "POST" else 0)

        command_context = parameter in OAST_COMMAND_PARAMETERS and any(
            hint in path for hint in ("exec", "command", "cmd", "ping", "shell")
        )
        if command_context:
            replacement = (
                "127.0.0.1; ping -c 1 FUZZ"
                if parameter in {"ip", "host", "hostname", "target", "domain", "ping"}
                else "ping -c 1 FUZZ"
            )
            score += 45
        else:
            replacement = "http://FUZZ/" if parameter in OAST_URL_VALUE_PARAMETERS else "FUZZ"
        if method == "GET":
            parsed = urlparse(url)
            injected_pairs = _replace_parameter_value(query_pairs, parameter, replacement)
            injection_url = urlunparse(parsed._replace(query=urlencode(injected_pairs), fragment=""))
            injection_data = ""
        else:
            injection_url = url
            injection_data = urlencode(_replace_parameter_value(body_pairs, parameter, replacement))

        ranked.append((score, {
            "target_url": target,
            "source_url": url,
            "injection_url": injection_url,
            "method": method,
            "data": injection_data,
            "parameter": parameter,
            "parameters": [parameter],
            "priority_score": score,
        }))

    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for _, candidate in sorted(ranked, key=lambda item: (-item[0], item[1]["injection_url"])):
        key = (candidate["method"], candidate["injection_url"], candidate["data"])
        if key in seen:
            continue
        seen.add(key)
        selected.append(candidate)
        if len(selected) >= max(1, int(limit)):
            break
    return selected


def enrich_discovery_with_arjun(discovery: dict[str, Any], result: dict[str, Any], base_url: str) -> tuple[dict[str, Any], list[str]]:
    parameters = {str(item).strip() for item in result.get("parameters", []) if str(item).strip()}
    parameters.update(str(item.get("parameter", "")).strip() for item in result.get("vulnerabilities", []) if isinstance(item, dict))
    parsed = urlparse(base_url)
    existing = list(parse_qsl(parsed.query, keep_blank_values=True))
    names = {name for name, _ in existing}
    generated = [urlunparse(parsed._replace(query=urlencode([*existing, (name, "1")]), fragment="")) for name in sorted(parameters) if name and name not in names and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", name)]
    updated = dict(discovery)
    updated["parameterized_urls"] = sorted(set(updated.get("parameterized_urls", [])) | set(generated))
    generated_cases = [{
        "url": url, "method": "GET", "data": "",
        "parameters": [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)],
        "source_url": base_url,
    } for url in generated]
    updated["request_cases"] = _dedupe_request_cases([*updated.get("request_cases", []), *generated_cases])
    return updated, generated


def enrich_discovery_with_ffuf(discovery: dict[str, Any], result: dict[str, Any], target: str) -> tuple[dict[str, Any], list[str]]:
    urls = sorted({str(item.get("url", "")) for item in result.get("vulnerabilities", []) if isinstance(item, dict) and item.get("url") and same_origin(target, str(item["url"]))})
    updated = dict(discovery)
    updated["urls"] = sorted(set(updated.get("urls", [])) | set(urls))
    updated["parameterized_urls"] = sorted(set(updated.get("parameterized_urls", [])) | {url for url in urls if urlparse(url).query})
    return updated, urls


def make_skipped_result(tool: str, target: str, reason: str) -> dict[str, Any]:
    return {"tool": tool, "status": "skipped", "target": target, "output": reason, "vulnerabilities": [], "diagnosis": "not_applicable"}


def log_zap_session_diagnostics(result: dict[str, Any]) -> None:
    diagnostics = (
        result.get("session_diagnostics")
        if isinstance(result.get("session_diagnostics"), dict)
        else {}
    )
    before = (
        diagnostics.get("before_scan")
        if isinstance(diagnostics.get("before_scan"), dict)
        else diagnostics
    )
    after = (
        diagnostics.get("after_scan")
        if isinstance(diagnostics.get("after_scan"), dict)
        else {}
    )
    if not before:
        return

    def print_coverage() -> None:
        if "targeted_active_scans_started" not in result:
            return
        policy = (
            result.get("active_scanner_policy")
            if isinstance(result.get("active_scanner_policy"), dict)
            else {}
        )
        stats = (
            result.get("zap_alert_stats")
            if isinstance(result.get("zap_alert_stats"), dict)
            else {}
        )
        print(
            "    [ZAP COVERAGE] "
            f"seeded URLs={result.get('seeded_urls', 0)}; "
            f"seeded requests={result.get('seeded_request_cases', 0)}; "
            f"targeted active={result.get('targeted_active_scans_completed', 0)}/"
            f"{result.get('targeted_active_scans_started', 0)}; "
            f"active rules={result.get('active_rules_attempted', 0)}/"
            f"{result.get('active_rules_planned', 0)} "
            f"({result.get('active_rule_coverage_percent', 0)}%); "
            f"proxy confirmed={result.get('proxy_assisted_confirmed', 0)}; "
            f"native security alerts={stats.get('security', 0)}; "
            f"site-tree URLs={result.get('zap_sites_tree_urls', 0)}"
        )
        if policy:
            print(
                "    [ZAP ACTIVE POLICY] first-tier rule IDs="
                + (", ".join(policy.get("enabled_ids", [])) or "none")
            )
        plan = result.get("prioritized_native_plan") if isinstance(result.get("prioritized_native_plan"), dict) else {}
        for phase in plan.get("phases", []):
            if not isinstance(phase, dict):
                continue
            recursive = phase.get("recursive") if isinstance(phase.get("recursive"), dict) else {}
            print(
                "    [ZAP PRIORITY] "
                f"tier={phase.get('tier')}; rules={phase.get('scanner_count', 0)}; "
                f"targeted={phase.get('targeted_completed', 0)}/{phase.get('targeted_started', 0)}; "
                f"recursive={'complete' if recursive.get('completed') else 'partial' if recursive.get('started') else 'not-started'}"
            )
        for item in result.get("targeted_active_scans", []):
            if not isinstance(item, dict):
                continue
            state = "complete" if item.get("completed") else "incomplete"
            print(
                "    [ZAP ACTIVE CASE] "
                f"{item.get('method', 'GET')} {item.get('url', '')} — "
                f"{state}; progress={item.get('progress', 0)}%; "
                f"budget={item.get('budget_seconds', 0)}s"
            )
        preparation = result.get("post_spider_target_preparation")
        if isinstance(preparation, dict) and preparation.get("configured"):
            print(
                "    [ZAP TARGET STATE] "
                f"reapplied={preparation.get('performed')}; usable={preparation.get('usable')}"
            )
        for record in result.get("proxy_assisted_verification", []):
            if not isinstance(record, dict):
                continue
            if record.get("error"):
                print(
                    "    [ZAP PROXY CHECK] "
                    f"{record.get('method', 'GET')} {record.get('url', '')} — error: {record.get('error')}"
                )
                continue
            if record.get("skipped"):
                print(
                    "    [ZAP PROXY CHECK] "
                    f"{record.get('method', 'GET')} {record.get('url', '')} — skipped: {record.get('skipped')}"
                )
                continue
            for test in record.get("tests", []):
                if not isinstance(test, dict):
                    continue
                state = "confirmed" if test.get("confirmed") else "not-confirmed"
                print(
                    "    [ZAP PROXY CHECK] "
                    f"{record.get('method', 'GET')} {record.get('url', '')} — "
                    f"{test.get('type', 'probe')}={state}"
                )

    if before.get("anonymous_profile"):
        print_coverage()
        return

    print(
        "    [ZAP AUTH] "
        f"ZAP={result.get('zap_version', before.get('zap_version', 'unknown'))}; "
        f"Python API={result.get('python_zap_api_version', before.get('python_zap_api_version', 'unknown'))}"
    )
    print(
        "    [ZAP AUTH] "
        f"probe={before.get('probe_url', '')}; "
        f"cookie names={', '.join(before.get('cookie_names', [])) or 'none'}"
    )
    direct = before.get("direct") if isinstance(before.get("direct"), dict) else {}
    direct_state = (
        "inconclusive"
        if before.get("conclusive") is False
        else str(before.get("effective") is True)
    )
    print(
        "    [ZAP AUTH] "
        f"direct authenticated={direct_state}; "
        f"proxy matches direct={before.get('proxy_matches_direct')}; "
        f"history cookie exact={before.get('history_cookie_exact')}"
    )
    history = before.get("history") if isinstance(before.get("history"), dict) else {}
    if history.get("duplicate_cookie_names"):
        print(
            "    [ZAP AUTH WARNING] duplicate Cookie names: "
            + ", ".join(history["duplicate_cookie_names"])
        )
    if before.get("root_cause"):
        print(f"    [ZAP AUTH ROOT CAUSE] {before['root_cause']}")
    if after:
        after_state = (
            "inconclusive"
            if after.get("conclusive") is False
            else str(after.get("effective"))
        )
        print(
            "    [ZAP AUTH] "
            f"session valid after scan={after_state}; "
            f"proxy matches direct={after.get('proxy_matches_direct')}; "
            f"history cookie exact={after.get('history_cookie_exact')}"
        )
        if after.get("root_cause"):
            print(f"    [ZAP AUTH ROOT CAUSE] {after['root_cause']}")
    print_coverage()


def log_result(profile: str, name: str, result: dict[str, Any], target: str = "") -> None:
    raw_status = str(result.get("status", "error")).lower()
    limited = raw_status == "partial" and _is_time_limited(result)
    label = "LIMITED" if limited else raw_status.upper()
    total, security, observations = _finding_counts(result)
    print(
        f"    [{label:7}] {name}: {target or result.get('target', '')} — "
        f"findings={total} (security/candidates={security}, observations={observations})"
    )
    detail = str(result.get("output", ""))[:400]
    if raw_status == "error":
        print(f"              {detail}", file=sys.stderr)
    elif raw_status == "partial":
        print(f"              {detail}")

def aggregate_runs(tool: str, target: str, runs: list[dict[str, Any]]) -> dict[str, Any]:
    if not runs:
        return make_skipped_result(tool, target, "No applicable endpoint was discovered for this tool.")
    normalized = [_normalize_time_limit(dict(run), tool, str(run.get("target", target))) for run in runs]
    statuses = [str(run.get("status", "error")).lower() for run in normalized]
    successful = sum(status == "success" for status in statuses)
    errors = sum(status == "error" for status in statuses)
    partials = sum(status == "partial" for status in statuses)
    limited = sum(status == "partial" and _is_time_limited(run) for status, run in zip(statuses, normalized))
    skipped_count = sum(status == "skipped" for status in statuses)
    if all(status == "skipped" for status in statuses):
        status = "skipped"
    elif errors == len(normalized):
        status = "error"
    elif errors or partials:
        status = "partial"
    else:
        status = "success"
    vulnerabilities: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, ...]] = set()
    for run in normalized:
        for finding in run.get("vulnerabilities") or []:
            if not isinstance(finding, dict):
                continue
            fingerprint = tuple(str(finding.get(key, "")) for key in (
                "alert", "risk", "category", "url", "parameter", "evidence"
            ))
            if fingerprint not in seen_findings:
                seen_findings.add(fingerprint)
                vulnerabilities.append(finding)
    result = {
        "tool": tool, "status": status, "target": target,
        "output": (
            f"Runs: {len(normalized)}; successful: {successful}; time-limited: {limited}; "
            f"other partial: {max(0, partials-limited)}; errors: {errors}; skipped: {skipped_count}; "
            f"findings: {len(vulnerabilities)}."
        ),
        "vulnerabilities": vulnerabilities, "runs": normalized,
        "diagnosis": (
            "nested_scanner_errors" if errors else
            "time_limit_reached" if limited else
            "nested_partial_results" if partials else None
        ),
        "timed_out": bool(limited),
    }
    return result

def iter_leaf_results(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], dict[str, Any]]]:
    if isinstance(value, dict) and "status" in value:
        runs = value.get("runs")
        if isinstance(runs, list):
            for index, run in enumerate(runs):
                yield from iter_leaf_results(run, (*path, f"run[{index}]"))
        else:
            yield path, value
    elif isinstance(value, dict):
        for key, nested in value.items():
            yield from iter_leaf_results(nested, (*path, str(key)))


def write_emergency_json_report(target: str, results: dict[str, Any], diagnostics: list[dict[str, Any]], reason: str, output_name: str = "SecOps_Emergency") -> str | None:
    try:
        directory = ROOT / "reports"
        directory.mkdir(parents=True, exist_ok=True)
        stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", output_name).strip("._")
        path = directory / f"{stem}_{datetime.now():%Y%m%d_%H%M%S}.json"
        payload = {"generated_at": datetime.now(timezone.utc).isoformat(), "target": target, "reason": reason, "diagnostics": diagnostics, "results": results}
        text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
        path.write_text(text, encoding="utf-8")
        path.with_suffix(".html").write_text(f"<!doctype html><meta charset='utf-8'><title>SecOps preview</title><style>body{{font-family:Segoe UI;margin:2rem}}pre{{white-space:pre-wrap;background:#111923;color:#e7eef7;padding:1rem}}</style><h1>SecOps emergency preview</h1><pre>{html.escape(text)}</pre>", encoding="utf-8")
        return str(path.resolve())
    except Exception as exc:
        print(f"[REPORT FALLBACK ERROR] {exc}", file=sys.stderr)
        return None


def select_session_probe_url(discovery: dict[str, Any], target: str) -> str:
    """Choose a stable non-destructive page for session checks."""
    discovered = [
        str(value)
        for value in discovery.get("html_urls", [])
        if isinstance(value, str)
        and same_origin(target, value)
        and not _is_auto_index_url(value)
    ]
    return _stable_auth_probe_url(target, discovered)



# ---------------------------------------------------------------------------
# Deterministic pipeline
# ---------------------------------------------------------------------------

async def run_pipeline(target: str, profiles: list[dict[str, str]], injection_url: str) -> dict[str, Any]:
    print("\n[*] Discovery anonima e autenticata...")
    discovery: dict[str, dict[str, Any]] = {}
    diagnostics: list[dict[str, Any]] = []
    results = {profile["name"]: {} for profile in profiles}

    for profile in profiles:
        name = profile["name"]
        found = discover_target(target, profile["cookies"])
        discovery[name] = found
        diagnostics.extend({"phase": "discovery", "profile": name, **item} for item in found["errors"])
        print(
            f"    {name}: {len(found['html_urls'])} pagine HTML, "
            f"{len(found['request_cases'])} casi GET/POST, {len(found['errors'])} errori"
        )
        for error in found["errors"][:5]:
            print(
                f"      [CRAWL WARNING] {error.get('type', 'error')}: "
                f"{error.get('url', '')} — {error.get('message', '')}"
            )
        if len(found["errors"]) > 5:
            print(f"      [CRAWL WARNING] altri {len(found['errors']) - 5} errori sono inclusi nel report.")
        if found.get("authentication_effective") is False:
            print(f"    [WARNING] {name}: {found.get('authentication_note')}", file=sys.stderr)

    has_authenticated_profile = any(bool(profile.get("cookies")) for profile in profiles)

    # Broad scanners. Arjun is intentionally delayed until crawling and FFUF have produced useful endpoints.
    profile_session_state: dict[str, bool] = {
        profile["name"]: discovery[profile["name"]].get("authentication_effective") is not False
        for profile in profiles
    }
    for profile in profiles:
        name, cookies = profile["name"], profile["cookies"]
        print(f"\n[*] Scanner generali - profilo: {name}")
        # Authenticated ZAP runs before authenticated FFUF so a broad resource
        # discovery pass cannot invalidate or alter the session first.
        broad_order = broad_tool_order(bool(cookies))
        broad_specs = {
            spec.name: spec
            for spec in BASE_TOOLS
        }

        # Reuse anonymous FFUF discoveries as authenticated ZAP seeds without
        # sending the authenticated cookie through the dangerous FFUF list.
        if cookies and "anonymous" in results:
            anonymous_ffuf = results.get("anonymous", {}).get("ffuf", {})
            if isinstance(anonymous_ffuf, dict):
                _, anonymous_urls = enrich_discovery_with_ffuf(
                    discovery[name], anonymous_ffuf, target
                )
                if anonymous_urls:
                    authenticated_recrawl = discover_target(
                        target, cookies, seeds=anonymous_urls
                    )
                    discovery[name] = merge_discovery(
                        discovery[name], authenticated_recrawl
                    )
                    diagnostics.extend(
                        {
                            "phase": "anonymous_ffuf_authenticated_recrawl",
                            "profile": name,
                            **item,
                        }
                        for item in authenticated_recrawl["errors"]
                    )

        profile_session_valid = discovery[name].get("authentication_effective") is not False
        session_probe_url = select_session_probe_url(discovery[name], target)

        for scanner_name in broad_order:
            spec = broad_specs[scanner_name]
            scanner_timeout = BROAD_SCANNER_TIMEOUTS.get(spec.name, 180)
            if cookies and spec.name == "ffuf" and CURRENT_SCAN_MODE == "balanced":
                scanner_timeout = min(scanner_timeout, 35)
            if name == "anonymous" and has_authenticated_profile and CURRENT_SCAN_MODE != "deep" and spec.name in {"nikto"}:
                result = make_skipped_result(spec.name, target, "Balanced mode runs this host-level scanner once on the authenticated profile to avoid duplicate time and traffic.")
                results[name][spec.name] = result
                log_result(name, spec.name, result, target)
                continue
            if cookies and not profile_session_valid:
                result = make_skipped_result(
                    spec.name,
                    target,
                    "Authenticated session is no longer valid; this run was skipped to avoid reporting anonymous coverage as authenticated.",
                )
                results[name][spec.name] = result
                log_result(name, spec.name, result, target)
                continue

            arguments: dict[str, Any] = {
                "target_url": target,
                "cookies": cookies,
                "timeout": scanner_timeout,
            }
            if spec.name == "ffuf":
                arguments["session_probe_url"] = session_probe_url
            if spec.name == "zap":
                # ZAP's own spider previously started only from the root URL. Pass
                # the already authenticated discovery surface so ZAP can import
                # forms, POST requests and parameterized endpoints before active scan.
                arguments.update({
                    "seed_urls": discovery[name].get("html_urls", []),
                    "request_cases": discovery[name].get("request_cases", []),
                    "scan_mode": (
                        "full"
                        if bool(cookies) and CURRENT_SCAN_MODE == "deep"
                        else "prioritized"
                        if bool(cookies) and CURRENT_SCAN_MODE == "balanced"
                        else "passive"
                    ),
                    "max_observations": (100 if CURRENT_SCAN_MODE == "deep" else 50 if CURRENT_SCAN_MODE == "balanced" else 25),
                })
            if spec.name == "nuclei":
                arguments["seed_urls"] = discovery[name].get("html_urls", [])
                arguments["scan_profile"] = CURRENT_SCAN_MODE
                arguments["max_targets"] = (
                    8 if CURRENT_SCAN_MODE == "deep"
                    else 4 if CURRENT_SCAN_MODE == "balanced"
                    else 1
                )
            result = await call_mcp_with_progress(spec, arguments)
            results[name][spec.name] = result
            log_result(name, spec.name, result, target)
            if spec.name == "zap":
                log_zap_session_diagnostics(result)
                if cookies:
                    recovery = scanner_session_probe(
                        session_probe_url, cookies, timeout=10, attempts=4
                    )
                    result["downstream_session_recovery"] = recovery
                    state_refresh = refresh_authenticated_session_state(target, cookies, session_probe_url)
                    result["downstream_session_state_refresh"] = state_refresh
                    if state_refresh.get("usable") is False:
                        profile_session_valid = False
                        print(
                            "    [AUTH SESSION ROOT CAUSE] The authenticated session could not be restored after ZAP.",
                            file=sys.stderr,
                        )
                    if recovery.get("conclusive") and recovery.get("authenticated") is False:
                        profile_session_valid = False
                        print(
                            "    [AUTH SESSION ROOT CAUSE] Direct recovery probe conclusively reached the login page after ZAP.",
                            file=sys.stderr,
                        )
                    elif recovery.get("conclusive") is False:
                        print(
                            "    [WARNING] Target recovery remained temporarily inconclusive; downstream scanners will still run because no logout was proven.",
                            file=sys.stderr,
                        )
            if spec.name == "ffuf" and result.get("status") in {"success", "partial"}:
                discovery[name], discovered_urls = enrich_discovery_with_ffuf(discovery[name], result, target)
                if discovered_urls:
                    recrawl = discover_target(target, cookies, seeds=discovered_urls)
                    discovery[name] = merge_discovery(discovery[name], recrawl)
                    diagnostics.extend({"phase": "ffuf_recrawl", "profile": name, **item} for item in recrawl["errors"])
                    print(
                        f"    [INFO   ] FFUF re-crawl: {len(discovery[name]['html_urls'])} HTML pages, "
                        f"{len(discovery[name]['request_cases'])} GET/POST cases"
                    )
                    if cookies and recrawl.get("authentication_effective") is False:
                        profile_session_valid = False
                        print(
                            "    [AUTH SESSION ROOT CAUSE] The authenticated session became invalid after FFUF. "
                            "Remaining authenticated scanners will be skipped.",
                            file=sys.stderr,
                        )
                if cookies and result.get("diagnosis") == "authentication_lost_during_ffuf":
                    profile_session_valid = False

        arjun_cases = select_arjun_request_cases(
            discovery[name], target,
            limit=ARJUN_ENDPOINT_LIMIT,
        )
        arjun_runs: list[dict[str, Any]] = []
        if arjun_cases:
            print(f"    [INFO   ] Arjun request cases selected: {len(arjun_cases)}")
            for arjun_case in arjun_cases:
                endpoint = str(arjun_case.get("url") or target)
                state_refresh = refresh_authenticated_session_state(target, cookies, session_probe_url) if cookies else {"performed": False, "usable": True}
                result = await call_mcp_with_progress(
                    ARJUN_TOOL,
                    {
                        "target_url": endpoint,
                        "cookies": cookies,
                        "method": arjun_case.get("method", "GET"),
                        "data": arjun_case.get("data", ""),
                        "known_parameters": arjun_case.get("parameters", []),
                        "timeout": ARJUN_TIMEOUT,
                    },
                )
                result["session_state_refresh"] = state_refresh
                arjun_runs.append(result)
                log_result(name, "arjun", result, endpoint)
                if result.get("status") in {"success", "partial"}:
                    discovery[name], _ = enrich_discovery_with_arjun(discovery[name], result, endpoint)
        profile_session_state[name] = profile_session_valid
        results[name]["arjun"] = aggregate_runs("arjun", target, arjun_runs) if arjun_runs else make_skipped_result(
            "arjun", target, "No suitable HTML/form endpoint was available for hidden-parameter discovery."
        )

    # Parameter tools are selected independently by vulnerability class.
    parameter_selection_summary: dict[str, dict[str, list[dict[str, Any]]]] = {}
    semaphore = asyncio.Semaphore(1)

    async def run_parameter_tool(
        spec: ToolSpec,
        case: dict[str, Any],
        cookies: str,
        probe_url: str,
    ) -> dict[str, Any]:
        url = str(case.get("url", ""))
        method = str(case.get("method", "GET")).upper()
        skip_reason = _tool_case_skip_reason(spec.name, case)
        if skip_reason:
            return make_skipped_result(spec.name, url, skip_reason)

        scanner_timeout = PARAMETER_TOOL_TIMEOUTS.get(spec.name, 120)
        if spec.name == "idor":
            # IDOR's MCP contract accepts only the request URL, cookies and timeout.
            arguments: dict[str, Any] = {
                "target_url": url,
                "cookies": cookies,
                "timeout": scanner_timeout,
            }
        else:
            arguments = {
                "target_url": url,
                "cookies": cookies,
                "method": method,
                "data": str(case.get("data", "")),
                "parameters": list(case.get("parameters", [])),
                "timeout": scanner_timeout,
            }
            if spec.name == "dalfox":
                arguments["allow_state_changes"] = urlparse(target).hostname in {"127.0.0.1", "localhost", "::1"}

        async with semaphore:
            state_refresh = refresh_authenticated_session_state(target, cookies, probe_url) if cookies else {"performed": False, "usable": True}
            if state_refresh.get("usable") is False:
                return make_skipped_result(
                    spec.name,
                    url,
                    "The authenticated session could not be restored before this scanner.",
                ) | {"session_state_refresh": state_refresh}
            result = await call_mcp(
                spec.server,
                spec.tool,
                arguments,
                timeout_seconds=scanner_timeout + 35,
            )
            result["session_state_refresh"] = state_refresh
            return result

    for profile in profiles:
        name, cookies = profile["name"], profile["cookies"]
        print(f"\n[*] Scanner su parametri - profilo: {name}")
        parameter_selection_summary[name] = {}
        if name == "anonymous" and has_authenticated_profile:
            for spec in PARAMETER_TOOLS:
                results[name][spec.name] = make_skipped_result(spec.name, target, "Active parameter testing uses the richer authenticated request surface; repeating it against the anonymous authentication form is non-applicable and wastes the scan budget.")
                log_result(name, spec.name, results[name][spec.name], target)
            continue
        if cookies and not profile_session_state.get(name, True):
            for spec in PARAMETER_TOOLS:
                results[name][spec.name] = make_skipped_result(
                    spec.name,
                    target,
                    "Authenticated session became invalid before parameter testing.",
                )
                log_result(name, spec.name, results[name][spec.name], target)
            continue
        grouped = {spec.name: [] for spec in PARAMETER_TOOLS}
        tasks: list[tuple[ToolSpec, dict[str, Any], asyncio.Task[dict[str, Any]]]] = []
        profile_probe_url = select_session_probe_url(discovery[name], target)

        for spec in PARAMETER_TOOLS:
            cases = select_tool_request_cases(discovery[name], spec.name)
            get_count = sum(str(case.get("method", "GET")).upper() == "GET" for case in cases)
            post_count = len(cases) - get_count
            parameter_selection_summary[name][spec.name] = [
                {
                    "method": str(case.get("method", "GET")).upper(),
                    "url": str(case.get("url", "")),
                    "parameters": list(case.get("parameters", [])),
                }
                for case in cases
            ]
            print(
                f"    [INFO   ] {spec.name}: casi selezionati={len(cases)} "
                f"(GET={get_count}, POST={post_count})"
            )
            for case in cases:
                tasks.append(
                    (spec, case, asyncio.create_task(
                        run_parameter_tool(spec, case, cookies, profile_probe_url)
                    ))
                )

        for spec, case, task in tasks:
            result = await task
            grouped[spec.name].append(result)
            label = f"{case.get('method', 'GET')} {case.get('url', '')}"
            log_result(name, spec.name, result, label)

        for spec in PARAMETER_TOOLS:
            runs = grouped[spec.name]
            results[name][spec.name] = (
                aggregate_runs(spec.name, target, runs)
                if runs
                else make_skipped_result(
                    spec.name,
                    target,
                    f"No discovered request matched {spec.name}'s vulnerability class.",
                )
            )

    oast_selection_summary: dict[str, list[dict[str, Any]]] = {}
    for profile in profiles:
        name = profile["name"]
        token = (discovery[name].get("jwt_tokens") or [""])[0]
        jwt_result = (
            await call_mcp("jwtServer.py", "run_jwt_scan", {"jwt_token": token, "target_url": target})
            if token else make_skipped_result("jwt", target, "No JWT was discovered in crawled responses.")
        )

        if injection_url:
            oast_cases = [{
                "target_url": target,
                "source_url": injection_url,
                "injection_url": injection_url,
                "method": "GET",
                "data": "",
                "parameter": "explicit",
                "parameters": ["explicit"],
                "priority_score": 1000,
            }]
        else:
            oast_cases = select_oast_request_cases(
                discovery[name],
                target,
                limit=2 if CURRENT_SCAN_MODE == "deep" else 1,
            )
        oast_selection_summary[name] = oast_cases
        interactsh_runs: list[dict[str, Any]] = []
        for oast_case in oast_cases:
            result = await call_mcp(
                "interactshServer.py",
                "run_interactsh_client",
                {
                    "target_url": target,
                    "injection_url": oast_case["injection_url"],
                    "cookies": profile["cookies"],
                    "method": oast_case.get("method", "GET"),
                    "data": oast_case.get("data", ""),
                    "parameter": oast_case.get("parameter", ""),
                    "timeout": 120 if CURRENT_SCAN_MODE == "deep" else 75,
                },
                timeout_seconds=155 if CURRENT_SCAN_MODE == "deep" else 110,
            )
            interactsh_runs.append(result)
            log_result(name, "interactsh", result, oast_case.get("source_url", target))
        interactsh_result = (
            aggregate_runs("interactsh", target, interactsh_runs)
            if interactsh_runs
            else make_skipped_result(
                "interactsh",
                target,
                "No discovered OAST-capable input was available. Interactsh is functional, but no URL/host/callback/webhook/proxy/remote-resource or command-execution insertion point was found.",
            )
        )
        results[name].update(jwt=jwt_result, interactsh=interactsh_result)
        log_result(name, "jwt", jwt_result, target)
        if not interactsh_runs:
            log_result(name, "interactsh", interactsh_result, target)

    context = {
        "profiles": [{"name": profile["name"], "authenticated": bool(profile["cookies"])} for profile in profiles],
        "expected_tools": [spec.name for spec in (*BASE_TOOLS, ARJUN_TOOL, *PARAMETER_TOOLS, OPTIONAL_TOOLS[0], OPTIONAL_TOOLS[1])],
        "discovery": discovery,
        "diagnostics": diagnostics,
        "parameter_endpoint_limit": MAX_PARAMETER_ENDPOINTS,
        "request_case_counts": {name: {
            "GET": sum(str(case.get("method", "GET")).upper() == "GET" for case in found.get("request_cases", [])),
            "POST": sum(str(case.get("method", "GET")).upper() == "POST" for case in found.get("request_cases", [])),
        } for name, found in discovery.items()},
        "arjun_endpoint_limit": ARJUN_ENDPOINT_LIMIT,
        "parameter_selection": parameter_selection_summary,
        "oast_selection": oast_selection_summary,
        "parameter_tool_timeouts": PARAMETER_TOOL_TIMEOUTS,
        "broad_scanner_timeouts": BROAD_SCANNER_TIMEOUTS,
        "scan_mode": CURRENT_SCAN_MODE,
    }
    print("\n[*] Generazione report...")
    report = await call_mcp("pwndocServer.py", "generate_report", {
        "findings_summary": results,
        "target_url": target,
        "assessment_context": context,
    })
    if report.get("status") != "success" and not report.get("json_filename"):
        fallback = write_emergency_json_report(target, results, diagnostics, str(report.get("output", "Report MCP failed.")))
        if fallback:
            report.update(json_filename=fallback, html_filename=str(Path(fallback).with_suffix(".html")), local_json_fallback=True)
    return {"results": results, "discovery": discovery, "diagnostics": diagnostics, "report_status": report}


def summarize_results(results: dict[str, Any]) -> tuple[int, int, int]:
    errors = skips = partial = 0
    rows = []
    for path, result in iter_leaf_results(results):
        status = str(result.get("status", "error"))
        errors += status == "error"
        skips += status == "skipped"
        partial += status == "partial"
        if status == "error":
            rows.append(("/".join(path), result.get("diagnosis", "unknown"), str(result.get("output", ""))))
    if rows:
        print("\n=== Scanner error details ===", file=sys.stderr)
        for path, cause, detail in rows:
            print(f"[-] {path}: {cause} — {detail[:500]}", file=sys.stderr)
    return errors, skips, partial


def print_security_finding_summary(results: dict[str, Any]) -> None:
    confirmed: list[tuple[str, str, str, str, str]] = []
    candidates: list[tuple[str, str, str, str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for _, tools in results.items():
        if not isinstance(tools, dict):
            continue
        for _, result in iter_leaf_results(tools):
            tool = str(result.get("tool") or "unknown")
            for finding in result.get("vulnerabilities") or []:
                if not isinstance(finding, dict):
                    continue
                category = str(finding.get("category") or ("observation" if str(finding.get("risk", "info")).lower() == "info" else "candidate")).lower()
                if category not in {"vulnerability", "candidate"}:
                    continue
                item = (
                    str(finding.get("alert") or "Unnamed finding"),
                    str(finding.get("risk") or "info").upper(),
                    tool,
                    str(finding.get("url") or ""),
                    str(finding.get("parameter") or "-"),
                )
                key = (item[0], item[2], item[3], item[4])
                if key in seen:
                    continue
                seen.add(key)
                (confirmed if category == "vulnerability" else candidates).append(item)
    print("\n=== Security findings ===")
    print(f"[+] Confirmed vulnerabilities: {len(confirmed)}")
    for index, (title, risk, tool, url, parameter) in enumerate(confirmed, 1):
        print(f"    {index}. [{risk}] {title} - tool={tool}; parameter={parameter}; url={url}")
    print(f"[+] Candidates requiring validation: {len(candidates)}")
    for index, (title, risk, tool, url, parameter) in enumerate(candidates, 1):
        print(f"    {index}. [{risk}] {title} - tool={tool}; parameter={parameter}; url={url}")



SINGLE_TOOL_CHOICES = tuple(spec.name for spec in ALL_TOOLS if spec.name != "report")


def _parse_parameter_argument(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _single_tool_case(
    discovery: dict[str, Any],
    tool: str,
    target: str,
    explicit_url: str,
    method: str,
    data: str,
    parameters: list[str],
) -> dict[str, Any] | None:
    if explicit_url:
        url = normalize_url(explicit_url)
        if not same_origin(target, url):
            raise ValueError("--tool-url must have the same origin as --target.")
        effective_parameters = list(parameters)
        if not effective_parameters:
            source = urlparse(url).query if method == "GET" else data
            effective_parameters = [
                name for name, _ in parse_qsl(source, keep_blank_values=True)
            ]
        return {
            "url": url,
            "method": method,
            "data": data,
            "parameters": effective_parameters,
            "source_url": url,
        }
    if tool == "arjun":
        cases = select_arjun_request_cases(discovery, target, limit=1)
        return cases[0] if cases else None
    cases = select_tool_request_cases(discovery, tool, limit=1)
    return cases[0] if cases else None


def _single_tool_preflight_errors(
    checks: list[dict[str, str]],
    tool: str,
) -> list[dict[str, str]]:
    """Return only errors that can prevent the selected isolated tool."""
    allowed = {"project", "mcp", tool}
    return [
        item for item in checks
        if item.get("level") == "error" and item.get("component") in allowed
    ]


async def run_single_tool_debug(
    *,
    tool: str,
    target: str,
    cookies: str,
    mode: str,
    explicit_url: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    jwt_token: str = "",
    injection_url: str = "",
    timeout_override: int = 0,
    diagnostic_only: bool = False,
) -> dict[str, Any]:
    """Run exactly one canonical MCP server through normal production transport."""
    configure_scan_mode(mode)
    method = str(method or "GET").upper()
    parameters = [str(value) for value in (parameters or []) if str(value)]
    if method not in {"GET", "POST"}:
        raise ValueError("--method must be GET or POST.")
    if timeout_override < 0:
        raise ValueError("--tool-timeout cannot be negative.")

    discovery = discover_target(target, cookies)
    spec = next(item for item in ALL_TOOLS if item.name == tool)
    selected_target = target
    arguments: dict[str, Any]

    if tool in {"ffuf", "zap", "nuclei", "nikto"}:
        timeout = timeout_override or BROAD_SCANNER_TIMEOUTS[tool]
        arguments = {"target_url": target, "cookies": cookies, "timeout": timeout}
        if tool == "ffuf":
            arguments["session_probe_url"] = select_session_probe_url(
                discovery, target
            )
        elif tool == "zap":
            arguments.update({
                "seed_urls": discovery.get("html_urls", []),
                "request_cases": discovery.get("request_cases", []),
                # A single authenticated ZAP debug run should actually exercise
                # the bounded active path in both balanced and deep modes.
                "scan_mode": (
                    "full" if cookies and mode == "deep" and not diagnostic_only
                    else "prioritized" if cookies and mode == "balanced" and not diagnostic_only
                    else "targeted" if cookies and not diagnostic_only
                    else "passive"
                ),
                "max_observations": 100 if mode == "deep" else 50,
                "diagnostic_only": diagnostic_only,
            })
        elif tool == "nuclei":
            arguments.update({
                "seed_urls": discovery.get("html_urls", []),
                "scan_profile": mode,
                "max_targets": 8 if mode == "deep" else 4 if mode == "balanced" else 1,
            })
    elif tool == "arjun":
        case = _single_tool_case(
            discovery, tool, target, explicit_url, method, data, parameters
        )
        if not case:
            return make_skipped_result(
                tool, target, "No suitable endpoint was discovered for Arjun."
            )
        selected_target = str(case["url"])
        arguments = {
            "target_url": selected_target,
            "cookies": cookies,
            "method": str(case.get("method") or method).upper(),
            "data": str(case.get("data") or data),
            "known_parameters": list(
                case.get("parameters") or parameters
            ),
            "timeout": timeout_override or ARJUN_TIMEOUT,
        }
    elif tool in {"sqlmap", "dalfox", "commix", "traversal", "idor"}:
        case = _single_tool_case(
            discovery, tool, target, explicit_url, method, data, parameters
        )
        if not case:
            return make_skipped_result(
                tool, target,
                f"No request matched {tool}'s vulnerability class."
            )
        selected_target = str(case["url"])
        effective_method = str(case.get("method") or method).upper()
        state_refresh = (
            refresh_authenticated_session_state(target, cookies, select_session_probe_url(discovery, target))
            if cookies else {"performed": False, "usable": True}
        )
        if state_refresh.get("usable") is False:
            return {
                "tool": tool,
                "status": "partial",
                "target": selected_target,
                "output": (
                    "The authenticated session could not be restored before the "
                    "isolated scanner run."
                ),
                "vulnerabilities": [],
                "diagnosis": "authentication_precheck_failed",
                "state_refresh": state_refresh,
            }
        if tool == "idor":
            arguments = {
                "target_url": selected_target,
                "cookies": cookies,
                "method": effective_method,
                "data": str(case.get("data") or data),
                "parameters": list(case.get("parameters") or parameters),
                "timeout": timeout_override or PARAMETER_TOOL_TIMEOUTS[tool],
            }
        else:
            arguments = {
                "target_url": selected_target,
                "cookies": cookies,
                "method": effective_method,
                "data": str(case.get("data") or data),
                "parameters": list(case.get("parameters") or parameters),
                "timeout": timeout_override or PARAMETER_TOOL_TIMEOUTS[tool],
            }
            if tool == "dalfox":
                arguments["allow_state_changes"] = urlparse(target).hostname in {
                    "127.0.0.1", "localhost", "::1"
                }
    elif tool == "jwt":
        token = jwt_token or next(iter(discovery.get("jwt_tokens", [])), "")
        if not token:
            return make_skipped_result(
                "jwt", target, "No JWT was supplied or discovered."
            )
        arguments = {"jwt_token": token, "target_url": target}
    elif tool == "interactsh":
        if injection_url:
            selected = {
                "injection_url": injection_url,
                "method": method,
                "data": data,
                "parameter": parameters[0] if parameters else "explicit",
            }
        else:
            cases = select_oast_request_cases(discovery, target, limit=1)
            if not cases:
                return make_skipped_result(
                    "interactsh", target,
                    "No OAST-capable input was discovered."
                )
            selected = cases[0]
        arguments = {
            "target_url": target,
            "injection_url": selected["injection_url"],
            "cookies": cookies,
            "method": selected.get("method", "GET"),
            "data": selected.get("data", ""),
            "parameter": selected.get("parameter", ""),
            "timeout": timeout_override or (120 if mode == "deep" else 75),
        }
    else:
        raise ValueError(f"Unsupported single tool: {tool}")

    scanner_limit = float(arguments.get("timeout", 180))
    result = await call_mcp_with_progress(
        spec,
        arguments,
        timeout_seconds=scanner_limit + 45,
    )
    result.setdefault("single_tool_debug", True)
    result.setdefault("selected_target", selected_target)
    result.setdefault("arguments_summary", {
        "method": arguments.get("method", ""),
        "parameters": arguments.get("parameters", arguments.get("known_parameters", [])),
        "timeout": arguments.get("timeout", 0),
        "scan_mode": arguments.get("scan_mode", ""),
    })
    result.setdefault("discovery_summary", {
        "html_urls": len(discovery.get("html_urls", [])),
        "request_cases": len(discovery.get("request_cases", [])),
        "authentication_effective": discovery.get("authentication_effective"),
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic FastMCP web-security orchestrator."
    )
    parser.add_argument("--target")
    parser.add_argument("--cookies", default="")
    parser.add_argument("--auth-only", action="store_true")
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--ignore-preflight-errors", action="store_true")
    parser.add_argument("--interactsh-injection-url", default="")
    parser.add_argument(
        "--mode", choices=("fast", "balanced", "deep"), default="balanced",
        help="Trade coverage for runtime; balanced is the default."
    )
    parser.add_argument(
        "--list-tools", action="store_true",
        help="List canonical MCP tools and exit."
    )
    parser.add_argument(
        "--tool", choices=SINGLE_TOOL_CHOICES,
        help="Run exactly one scanner for isolated debugging."
    )
    parser.add_argument(
        "--tool-url", default="",
        help="Explicit same-origin URL for the selected single tool."
    )
    parser.add_argument(
        "--tool-timeout", type=int, default=0,
        help="Override the selected scanner timeout in seconds."
    )
    parser.add_argument("--method", choices=("GET", "POST"), default="GET")
    parser.add_argument(
        "--data", default="",
        help="POST form body for a single parameter tool."
    )
    parser.add_argument(
        "--parameters", default="",
        help="Comma-separated parameters for a single parameter tool."
    )
    parser.add_argument("--jwt-token", default="", help="JWT value for --tool jwt.")
    parser.add_argument(
        "--diagnostic-only", action="store_true",
        help="For --tool zap, validate session/proxy without scanning."
    )
    args = parser.parse_args()

    if args.list_tools:
        print("Canonical SecOps MCP tools:")
        for spec in ALL_TOOLS:
            if spec.name != "report":
                print(f"  {spec.name:11} {spec.server}:{spec.tool}")
        return 0
    if not args.target:
        parser.error("--target is required unless --list-tools is used.")
    if args.diagnostic_only and args.tool != "zap":
        parser.error("--diagnostic-only is valid only with --tool zap.")
    configure_scan_mode(args.mode)

    checks = run_preflight_checks(include_live=True)
    if args.tool:
        # Show all warnings/errors, but isolate blocking to the selected server
        # and the project contract so unrelated optional tools do not prevent
        # a debugging run.
        print_preflight_report(checks, show_ok=args.preflight_only)
        selected_errors = _single_tool_preflight_errors(checks, args.tool)
        preflight_errors = len(selected_errors)
        if selected_errors:
            print("\n=== Selected-tool preflight blockers ===", file=sys.stderr)
            for item in selected_errors:
                print(
                    f"[-] {item['component']}: {item['cause']} — {item['detail']}",
                    file=sys.stderr,
                )
    else:
        preflight_errors = print_preflight_report(
            checks, show_ok=args.preflight_only
        )
    if args.preflight_only:
        return 0 if not preflight_errors else 3
    if preflight_errors and not args.ignore_preflight_errors:
        return 3

    target = normalize_url(args.target)
    if (
        urlparse(target).hostname not in {"127.0.0.1", "localhost", "::1"}
        and not args.authorized
    ):
        parser.error("Remote targets require --authorized.")
    injection_url = args.interactsh_injection_url.strip()
    if injection_url and not same_origin(target, injection_url):
        parser.error(
            "--interactsh-injection-url must have the same origin as --target."
        )

    normalized_cookie = ""
    profiles = [] if args.auth_only else [{"name": "anonymous", "cookies": ""}]
    if args.cookies:
        try:
            normalized_cookie = canonical_cookie_header(args.cookies)
        except ValueError as exc:
            parser.error(f"Invalid --cookies value: {exc}")
        print(
            "[*] Authenticated cookie names: "
            + ", ".join(cookie_names(normalized_cookie))
        )
        profiles.append({"name": "authenticated", "cookies": normalized_cookie})
    elif args.auth_only:
        parser.error("--auth-only requires --cookies.")

    if args.tool:
        try:
            result = asyncio.run(run_single_tool_debug(
                tool=args.tool,
                target=target,
                cookies=normalized_cookie,
                mode=args.mode,
                explicit_url=args.tool_url,
                method=args.method,
                data=args.data,
                parameters=_parse_parameter_argument(args.parameters),
                jwt_token=args.jwt_token,
                injection_url=injection_url,
                timeout_override=args.tool_timeout,
                diagnostic_only=args.diagnostic_only,
            ))
        except (ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        profile_name = "authenticated" if normalized_cookie else "anonymous"
        log_result(
            profile_name, args.tool, result,
            str(result.get("selected_target") or target),
        )
        if args.tool == "zap":
            log_zap_session_diagnostics(result)
        print_security_finding_summary({profile_name: {args.tool: result}})
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return 2 if result.get("status") == "error" else 0

    print("=== FastMCP Deterministic Security Pipeline ===")
    print(
        f"[*] Target: {target}\n[*] Mode: {CURRENT_SCAN_MODE}\n"
        f"[*] Profiles: {', '.join(profile['name'] for profile in profiles)}"
    )
    started = time.time()
    try:
        final = asyncio.run(run_pipeline(target, profiles, injection_url))
    except KeyboardInterrupt:
        print("\n[!] Workflow interrupted by the operator.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[-] Workflow failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    report = final["report_status"]
    errors, skips, partial = summarize_results(final["results"])
    print(f"\n=== Completed in {time.time() - started:.2f} seconds ===")
    print_security_finding_summary(final["results"])
    print(f"[+] PDF: {report.get('pdf_filename') or 'not generated'}")
    print(f"[+] HTML preview: {report.get('html_filename') or 'not generated'}")
    print(f"[+] JSON: {report.get('json_filename') or 'not generated'}")
    print(
        f"[+] Scanner run errors: {errors}\n"
        f"[+] Time-limited/partial scanner runs: {partial}\n"
        f"[+] Scanner run skips: {skips}"
    )
    return 1 if report.get("status") != "success" else 0


if __name__ == "__main__":
    raise SystemExit(main())