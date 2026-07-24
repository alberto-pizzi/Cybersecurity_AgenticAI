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
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from utils import ROOT_DIR, SERVERS_DIR, absolute_url, normalize_url, same_origin

ROOT = Path(ROOT_DIR).resolve()
SERVERS = Path(SERVERS_DIR).resolve()
RUNTIME_FILE = ROOT / ".secops_runtime.json"
LOCAL_BIN = Path.home() / ".local" / "bin"
MCP_CONNECT_TIMEOUT = float(os.getenv("SECOPS_MCP_CONNECT_TIMEOUT", "20"))
MCP_TOOL_TIMEOUT = float(os.getenv("SECOPS_MCP_TIMEOUT", "900"))
MAX_PARAMETER_ENDPOINTS = max(1, int(os.getenv("SECOPS_MAX_PARAMETER_ENDPOINTS", "5")))
MAX_ARJUN_ENDPOINTS = max(1, int(os.getenv("SECOPS_MAX_ARJUN_ENDPOINTS", "2")))
MAX_CRAWL_PAGES = max(10, int(os.getenv("SECOPS_MAX_CRAWL_PAGES", "50")))
SCANNER_PROGRESS_INTERVAL = max(10, int(os.getenv("SECOPS_PROGRESS_INTERVAL", "30")))
BROAD_SCANNER_TIMEOUTS = {
    "zap": 300,
    "nuclei": 180,
    "nikto": 180,
    "ffuf": 120,
}
PARAMETER_TOOL_TIMEOUTS = {
    "sqlmap": 180,
    "dalfox": 120,
    "commix": 150,
    "idor": 20,
}
TIME_LIMIT_DIAGNOSES = {
    "timeout", "time_limit_reached", "timeout_with_partial_results",
    "timeout_with_confirmed_finding", "bounded_partial_scan",
}
ONE_SHOT_FALLBACK_TOOLS = {"nuclei", "nikto", "arjun", "sqlmap", "dalfox", "commix", "ffuf"}
AUTO_INDEX_PARAMETERS = {"c", "n", "m", "s", "d", "o"}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    server: str
    tool: str
    executable: str = ""
    module: str = ""
    required: bool = True


BASE_TOOLS = (
    ToolSpec("zap", "zapServer.py", "run_zap_scan", module="zapv2"),
    ToolSpec("nuclei", "nucleiServer.py", "run_nuclei_scan", "nuclei"),
    ToolSpec("nikto", "niktoServer.py", "run_nikto_scan", "nikto"),
    ToolSpec("ffuf", "ffufServer.py", "run_ffuf_fuzz", "ffuf"),
)
ARJUN_TOOL = ToolSpec("arjun", "arjunServer.py", "run_arjun_scan", "arjun")
PARAMETER_TOOLS = (
    ToolSpec("sqlmap", "sqlmapServer.py", "run_sqlmap_scan", "sqlmap"),
    ToolSpec("dalfox", "dalfoxServer.py", "run_dalfox_scan", "dalfox"),
    ToolSpec("commix", "commixServer.py", "run_commix_scan", "commix"),
    ToolSpec("idor", "idorForgeServer.py", "run_idor_check"),
)
OPTIONAL_TOOLS = (
    ToolSpec("jwt", "jwtServer.py", "run_jwt_scan", module="jwt"),
    ToolSpec("interactsh", "interactshServer.py", "run_interactsh_client", "interactsh-client", required=False),
    ToolSpec("report", "pwndocServer.py", "generate_report", module="reportlab"),
)
ALL_TOOLS = (*BASE_TOOLS, ARJUN_TOOL, *PARAMETER_TOOLS, *OPTIONAL_TOOLS)


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
    """Prefer a file that really declares the requested tool, including name(2).py copies."""
    requested = Path(filename)
    pattern = re.compile(
        rf"^{re.escape(requested.stem)}\s*(?:\(\d+\))?{re.escape(requested.suffix or '.py')}$",
        re.IGNORECASE,
    )
    candidates = [path.resolve() for path in SERVERS.iterdir() if path.is_file() and pattern.fullmatch(path.name)] if SERVERS.is_dir() else []
    exact = (SERVERS / requested.name).resolve()
    if exact.is_file() and exact not in candidates:
        candidates.insert(0, exact)
    if required_tool:
        valid = [path for path in candidates if required_tool in _declared_functions(path)]
        if exact in valid:
            return exact
        if valid:
            return max(valid, key=lambda path: path.stat().st_mtime)
    return exact if exact.is_file() else (max(candidates, key=lambda path: path.stat().st_mtime) if candidates else exact)


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


def run_preflight_checks(*, include_live: bool = True) -> list[dict[str, str]]:
    configure_runtime_path()
    checks: list[dict[str, str]] = []
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
                healthy, detail = _nikto_runtime_check(executable)
                checks.append({
                    "level": "ok" if healthy else "error",
                    "component": "nikto",
                    "cause": "nikto_runtime_ok" if healthy else "nikto_perl_unavailable",
                    "detail": detail,
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


def _crawlable_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return not path.endswith((
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".gz", ".tar", ".mp4",
    ))


def _looks_like_login(response: requests.Response) -> bool:
    text = response.text[:100_000].lower()
    path = urlparse(response.url).path.lower()
    password_field = bool(re.search(r"type\s*=\s*['\"]password['\"]", text))
    return path.endswith("/login") or path.endswith("/login.php") or (password_field and "login" in text)


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

def discover_target(
    target: str,
    cookies: str,
    max_pages: int = MAX_CRAWL_PAGES,
    seeds: list[str] | None = None,
) -> dict[str, Any]:
    """Crawl same-origin pages, forms and links while recording authentication quality."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SecOpsAgent-University/1.3",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
    })
    if cookies:
        session.headers["Cookie"] = cookies

    initial = [_clean_url(target), *[_clean_url(value) for value in (seeds or [])]]
    queue = list(dict.fromkeys(value for value in initial if same_origin(target, value) and _crawlable_url(value)))
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
                candidate = _clean_url(absolute_url(final, href))
            except Exception:
                continue
            if not same_origin(target, candidate) or not _crawlable_url(candidate):
                continue
            if urlparse(candidate).query:
                parameterized.add(candidate)
            if candidate not in visited and candidate not in queue:
                queue.append(candidate)

        for form in parser.forms:
            try:
                action = _clean_url(absolute_url(final, form["action"] or final))
            except Exception:
                continue
            if not same_origin(target, action):
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
    if cookies:
        auth_effective = not initial_login_detected
        auth_note = (
            "The supplied cookie reached a non-login landing page."
            if auth_effective else
            "The supplied cookie was redirected to or rendered a login page; authenticated coverage is probably ineffective or expired."
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
    }


def merge_discovery(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = dict(left)
    for key in ("urls", "html_urls", "form_urls", "parameterized_urls", "jwt_tokens"):
        merged[key] = sorted(set(left.get(key, [])) | set(right.get(key, [])))
    merged["request_cases"] = _dedupe_request_cases([*left.get("request_cases", []), *right.get("request_cases", [])])
    merged["errors"] = [*left.get("errors", []), *right.get("errors", [])]
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


def _is_auto_index_case(case: dict[str, Any]) -> bool:
    """Identify Apache-style directory sorting links such as ?C=D;O=A."""
    parsed = urlparse(str(case.get("url", "")))
    names = {name.lower() for name, _ in parse_qsl(parsed.query.replace(";", "&"), keep_blank_values=True)}
    parameters = {str(value).lower() for value in case.get("parameters", [])}
    names |= parameters
    path = parsed.path.lower()
    return bool(names) and names <= AUTO_INDEX_PARAMETERS and (
        path.endswith("/") or "/config/" in path or "/docs/" in path
    )


def _tool_case_skip_reason(tool: str, case: dict[str, Any]) -> str:
    if _is_auto_index_case(case):
        return "Apache directory-index sorting parameters are navigation controls, not application inputs."
    if tool in {"dalfox", "commix"} and _is_login_case(case):
        return f"{tool} is not prioritized against the generic login form; SQLMap remains available for SQL-injection checks."
    return ""


def select_arjun_candidates(discovery: dict[str, Any], target: str, limit: int = MAX_ARJUN_ENDPOINTS) -> list[str]:
    """Prefer high-impact input handlers and avoid configuration/login utility pages."""
    form_urls = set(discovery.get("form_urls", []))
    candidates = set(form_urls) | set(discovery.get("html_urls", []))
    ranked: list[tuple[int, str]] = []
    excluded = ("login", "logout", "setup", "security.php", "/config/", "/docs/")
    low_value = ("brute", "captcha", "csrf")
    for url in candidates:
        path = urlparse(url).path.lower()
        if any(name in path for name in excluded):
            continue
        clean = _clean_url(url)
        score = _risk_terms(path)
        if url in form_urls:
            score += 12
        if urlparse(url).query:
            score += 8
        if "/vulnerabilities/" in path:
            score += 12
        if any(term in path for term in low_value):
            score -= 10
        if score <= 0:
            continue
        ranked.append((score, clean))
    return [url for _, url in sorted(set(ranked), key=lambda item: (-item[0], item[1]))[:limit]]

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

    # Broad scanners. Arjun is intentionally delayed until crawling and FFUF have produced useful endpoints.
    for profile in profiles:
        name, cookies = profile["name"], profile["cookies"]
        print(f"\n[*] Scanner generali - profilo: {name}")
        for spec in BASE_TOOLS:
            scanner_timeout = BROAD_SCANNER_TIMEOUTS.get(spec.name, 180)
            result = await call_mcp_with_progress(
                spec,
                {
                    "target_url": target,
                    "cookies": cookies,
                    "timeout": scanner_timeout,
                },
            )
            results[name][spec.name] = result
            log_result(name, spec.name, result, target)
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

        candidates = select_arjun_candidates(discovery[name], target)
        arjun_runs: list[dict[str, Any]] = []
        if candidates:
            print(f"    [INFO   ] Arjun endpoints selected: {len(candidates)}")
            for endpoint in candidates:
                result = await call_mcp_with_progress(
                    ARJUN_TOOL,
                    {"target_url": endpoint, "cookies": cookies, "timeout": 120},
                )
                arjun_runs.append(result)
                log_result(name, "arjun", result, endpoint)
                if result.get("status") in {"success", "partial"}:
                    discovery[name], _ = enrich_discovery_with_arjun(discovery[name], result, endpoint)
        results[name]["arjun"] = aggregate_runs("arjun", target, arjun_runs) if arjun_runs else make_skipped_result(
            "arjun", target, "No suitable HTML/form endpoint was available for hidden-parameter discovery."
        )

    # Parameter tools are independent and run with bounded concurrency to reduce total duration.
    semaphore = asyncio.Semaphore(2)

    async def run_parameter_tool(spec: ToolSpec, case: dict[str, Any], cookies: str) -> dict[str, Any]:
        url = str(case.get("url", ""))
        method = str(case.get("method", "GET")).upper()
        skip_reason = _tool_case_skip_reason(spec.name, case)
        if skip_reason:
            return make_skipped_result(spec.name, url, skip_reason)
        if spec.name == "idor":
            if method != "GET":
                return make_skipped_result("idor", url, "IDOR differential checks currently require a numeric GET parameter.")
            if not any(value.isdigit() for _, value in parse_qsl(urlparse(url).query, keep_blank_values=True)):
                return make_skipped_result("idor", url, "No numeric query parameter was available.")
        scanner_timeout = PARAMETER_TOOL_TIMEOUTS.get(spec.name, 120)
        arguments = {
            "target_url": url, "cookies": cookies,
            "method": method, "data": str(case.get("data", "")),
            "parameters": list(case.get("parameters", [])),
            "timeout": scanner_timeout,
        }
        async with semaphore:
            return await call_mcp(
                spec.server,
                spec.tool,
                arguments,
                timeout_seconds=scanner_timeout + 35,
            )

    for profile in profiles:
        name, cookies = profile["name"], profile["cookies"]
        cases = select_request_cases(discovery[name])
        get_count = sum(str(case.get("method", "GET")).upper() == "GET" for case in cases)
        post_count = len(cases) - get_count
        print(f"\n[*] Scanner su parametri - profilo: {name}\n    [INFO   ] casi selezionati: {len(cases)} (GET={get_count}, POST={post_count})")
        grouped = {spec.name: [] for spec in PARAMETER_TOOLS}
        tasks: list[tuple[ToolSpec, dict[str, Any], asyncio.Task[dict[str, Any]]]] = []
        for case in cases:
            for spec in PARAMETER_TOOLS:
                tasks.append((spec, case, asyncio.create_task(run_parameter_tool(spec, case, cookies))))
        for spec, case, task in tasks:
            result = await task
            grouped[spec.name].append(result)
            label = f"{case.get('method', 'GET')} {case.get('url', '')}"
            log_result(name, spec.name, result, label)
        for spec in PARAMETER_TOOLS:
            results[name][spec.name] = aggregate_runs(spec.name, target, grouped[spec.name])

    for profile in profiles:
        name = profile["name"]
        token = (discovery[name].get("jwt_tokens") or [""])[0]
        jwt_result = (
            await call_mcp("jwtServer.py", "run_jwt_scan", {"jwt_token": token, "target_url": target})
            if token else make_skipped_result("jwt", target, "No JWT was discovered in crawled responses.")
        )
        interactsh_result = (
            await call_mcp("interactshServer.py", "run_interactsh_client", {
                "target_url": target, "injection_url": injection_url, "cookies": profile["cookies"]
            })
            if injection_url else make_skipped_result(
                "interactsh", target, "No explicit OAST injection URL containing FUZZ was supplied."
            )
        )
        results[name].update(jwt=jwt_result, interactsh=interactsh_result)
        log_result(name, "jwt", jwt_result, target)
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
        "arjun_endpoint_limit": MAX_ARJUN_ENDPOINTS,
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic FastMCP web-security orchestrator.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--cookies", default="")
    parser.add_argument("--auth-only", action="store_true")
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--ignore-preflight-errors", action="store_true")
    parser.add_argument("--interactsh-injection-url", default="")
    args = parser.parse_args()

    checks = run_preflight_checks(include_live=True)
    preflight_errors = print_preflight_report(checks, show_ok=args.preflight_only)
    if args.preflight_only:
        return 0 if not preflight_errors else 3
    if preflight_errors and not args.ignore_preflight_errors:
        return 3

    target = normalize_url(args.target)
    if urlparse(target).hostname not in {"127.0.0.1", "localhost", "dvwa"} and not args.authorized:
        parser.error("Remote targets require --authorized.")
    injection_url = args.interactsh_injection_url.strip()
    if injection_url and not same_origin(target, injection_url):
        parser.error("--interactsh-injection-url must have the same origin as --target.")

    profiles = [] if args.auth_only else [{"name": "anonymous", "cookies": ""}]
    if args.cookies:
        profiles.append({"name": "authenticated", "cookies": args.cookies})
    elif args.auth_only:
        parser.error("--auth-only requires --cookies.")

    print("=== FastMCP Deterministic Security Pipeline ===")
    print(f"[*] Target: {target}\n[*] Profiles: {', '.join(profile['name'] for profile in profiles)}")
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
    print(f"[+] PDF: {report.get('pdf_filename') or 'not generated'}")
    print(f"[+] HTML preview: {report.get('html_filename') or 'not generated'}")
    print(f"[+] JSON: {report.get('json_filename') or 'not generated'}")
    print(f"[+] Scanner run errors: {errors}\n[+] Time-limited/partial scanner runs: {partial}\n[+] Scanner run skips: {skips}")
    return 1 if report.get("status") != "success" else 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())