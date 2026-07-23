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


@dataclass(frozen=True)
class ToolSpec:
    name: str
    server: str
    tool: str
    executable: str = ""
    module: str = ""


BASE_TOOLS = (
    ToolSpec("zap", "zapServer.py", "run_zap_scan", module="zapv2"),
    ToolSpec("nuclei", "nucleiServer.py", "run_nuclei_scan", "nuclei"),
    ToolSpec("nikto", "niktoServer.py", "run_nikto_scan", "nikto"),
    ToolSpec("ffuf", "ffufServer.py", "run_ffuf_fuzz", "ffuf"),
    ToolSpec("arjun", "arjunServer.py", "run_arjun_scan", "arjun"),
)
PARAMETER_TOOLS = (
    ToolSpec("sqlmap", "sqlmapServer.py", "run_sqlmap_scan", "sqlmap"),
    ToolSpec("dalfox", "dalfoxServer.py", "run_dalfox_scan", "dalfox"),
    ToolSpec("commix", "commixServer.py", "run_commix_scan", "commix"),
    ToolSpec("idor", "idorForgeServer.py", "run_idor_check"),
)
OPTIONAL_TOOLS = (
    ToolSpec("jwt", "jwtServer.py", "run_jwt_scan", module="jwt"),
    ToolSpec("interactsh", "interactshServer.py", "run_interactsh_client", "interactsh-client"),
    ToolSpec("report", "pwndocServer.py", "generate_report", module="reportlab"),
)
ALL_TOOLS = (*BASE_TOOLS, *PARAMETER_TOOLS, *OPTIONAL_TOOLS)


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
    return result


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


async def call_mcp(server_file: str, tool_name: str, arguments: dict[str, Any], timeout_seconds: float = MCP_TOOL_TIMEOUT) -> dict[str, Any]:
    spec = next((item for item in ALL_TOOLS if item.server == server_file and item.tool == tool_name), ToolSpec(tool_name, server_file, tool_name))
    server = resolve_server_path(server_file, tool_name)
    target = str(arguments.get("target_url", ""))
    started = time.monotonic()
    if not server.is_file():
        return {"tool": spec.name, "status": "error", "target": target, "output": f"MCP server not found: {server}", "vulnerabilities": [], "diagnosis": "missing_mcp_server_file"}

    async def invoke() -> tuple[Any, bool, str]:
        async with Client(_transport(server)) as client:
            return _extract_response(await client.call_tool(tool_name, arguments))

    try:
        data, is_error, shape = await asyncio.wait_for(invoke(), timeout=timeout_seconds + MCP_CONNECT_TIMEOUT)
        result = _normalize_result(data, spec, target, time.monotonic() - started, is_error, shape)
    except (KeyboardInterrupt, asyncio.CancelledError):
        raise
    except Exception as exc:
        stderr = _startup_stderr(server)
        message = f"MCP communication failed: {type(exc).__name__}: {exc}"
        if stderr:
            message += f" | server stderr: {stderr}"
        result = {
            "tool": spec.name, "status": "error", "target": target,
            "output": message, "vulnerabilities": [],
            "diagnosis": diagnose_error(message),
            "traceback": traceback.format_exc(),
            "_meta": {"server": str(server), "duration_seconds": round(time.monotonic() - started, 3)},
        }
    if result.get("status") == "error":
        print(f"\n[SCANNER ERROR] {spec.name}: {target}\n  {result.get('output', '')}", file=sys.stderr)
    return result


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
        return {"level": "error", "component": spec.name, "cause": "mcp_stdio_handshake_failed", "detail": detail}


def run_preflight_checks(*, include_live: bool = True) -> list[dict[str, str]]:
    configure_runtime_path()
    checks: list[dict[str, str]] = []
    seen_executables: set[str] = set()
    for spec in ALL_TOOLS:
        server = resolve_server_path(spec.server, spec.tool)
        if not server.is_file():
            checks.append({"level": "error", "component": spec.name, "cause": "missing_server", "detail": str(server)})
            continue
        checks.append({"level": "ok", "component": spec.name, "cause": "mcp_tool_found", "detail": f"{server.name}: {spec.tool}()"})
        if spec.tool not in _declared_functions(server):
            checks[-1] = {"level": "error", "component": spec.name, "cause": "mcp_tool_name_mismatch", "detail": f"{server.name} does not declare {spec.tool}()"}
        if spec.module:
            checks.append({
                "level": "ok" if importlib.util.find_spec(spec.module) else "error",
                "component": spec.name,
                "cause": "python_dependency_found" if importlib.util.find_spec(spec.module) else "missing_python_dependency",
                "detail": spec.module,
            })
        if spec.executable and spec.executable not in seen_executables:
            seen_executables.add(spec.executable)
            executable = resolve_executable(spec.executable)
            checks.append({
                "level": "ok" if executable else "error",
                "component": spec.name,
                "cause": "executable_found" if executable else "missing_executable",
                "detail": executable or f"Not found: {spec.executable}; runtime={RUNTIME_FILE}",
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
    visible = checks if show_ok else errors
    if visible:
        print("\n=== SecOps preflight ===")
        for item in visible:
            marker = "+" if item["level"] == "ok" else "-"
            print(f"[{marker}] {item['component']}: {item['cause']} — {item['detail']}", file=sys.stdout if marker == "+" else sys.stderr)
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
            self.current = {"action": values.get("action", ""), "method": str(values.get("method", "get")).lower(), "parameters": []}
        elif tag in {"input", "textarea", "select", "button"} and self.current and values.get("name"):
            self.current["parameters"].append(str(values["name"]))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.current:
            self.forms.append(self.current)
            self.current = None


def _clean_url(url: str) -> str:
    return urlunparse(urlparse(url)._replace(fragment=""))


def discover_target(target: str, cookies: str, max_pages: int = 25) -> dict[str, Any]:
    session = requests.Session()
    session.headers.update({"User-Agent": "SecOpsAgent-University/1.2", "Accept": "text/html,*/*;q=0.5"})
    if cookies:
        session.headers["Cookie"] = cookies
    queue, visited = [_clean_url(target)], set()
    parameterized, tokens, errors = set(), set(), []
    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            response = session.get(url, timeout=(5, 15), allow_redirects=True)
        except requests.RequestException as exc:
            errors.append({"url": url, "type": type(exc).__name__, "message": str(exc)})
            continue
        final = _clean_url(response.url)
        if not same_origin(target, final):
            errors.append({"url": url, "type": "CrossOriginRedirect", "message": final})
            continue
        if response.status_code >= 400:
            errors.append({"url": final, "type": f"HTTP{response.status_code}", "message": response.reason})
        if "html" not in response.headers.get("content-type", "").lower() and not response.text.lstrip().startswith("<"):
            continue
        tokens.update(re.findall(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", response.text))
        parser = LinkFormParser()
        try:
            parser.feed(response.text)
        except Exception as exc:
            errors.append({"url": final, "type": type(exc).__name__, "message": f"HTML parse: {exc}"})
            continue
        for href in parser.links:
            try:
                candidate = _clean_url(absolute_url(final, href))
            except Exception:
                continue
            if same_origin(target, candidate):
                if urlparse(candidate).query:
                    parameterized.add(candidate)
                if candidate not in visited and candidate not in queue:
                    queue.append(candidate)
        for form in parser.forms:
            action = _clean_url(absolute_url(final, form["action"] or final))
            if not same_origin(target, action) or form["method"] != "get":
                continue
            values = dict(parse_qsl(urlparse(action).query, keep_blank_values=True))
            for name in dict.fromkeys(form["parameters"]):
                values.setdefault(name, "1")
            if values:
                parameterized.add(urlunparse(urlparse(action)._replace(query=urlencode(values))))
    return {"urls": sorted(visited), "parameterized_urls": sorted(parameterized), "jwt_tokens": sorted(tokens), "errors": errors}


def select_parameterized_urls(urls: list[str], limit: int = MAX_PARAMETER_ENDPOINTS) -> list[str]:
    selected, seen = [], set()
    for url in sorted(urls):
        parsed = urlparse(url)
        signature = (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, tuple(sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})))
        if not signature[3] or signature in seen:
            continue
        seen.add(signature)
        selected.append(url)
        if len(selected) == limit:
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
    status = str(result.get("status", "error")).upper()
    print(f"    [{status:7}] {name}: {target or result.get('target', '')}")
    if status in {"ERROR", "PARTIAL"}:
        print(f"              {str(result.get('output', ''))[:300]}", file=sys.stderr)


def aggregate_runs(tool: str, target: str, runs: list[dict[str, Any]]) -> dict[str, Any]:
    if not runs:
        return make_skipped_result(tool, target, "No applicable parameterized URL was discovered.")
    statuses = [str(run.get("status", "error")) for run in runs]
    successful = sum(status == "success" for status in statuses)
    errors = sum(status == "error" for status in statuses)
    status = "skipped" if all(value == "skipped" for value in statuses) else "error" if errors == len(runs) else "partial" if errors else "success"
    return {
        "tool": tool, "status": status, "target": target,
        "output": f"Runs: {len(runs)}, successful: {successful}, errors: {errors}.",
        "vulnerabilities": [finding for run in runs for finding in run.get("vulnerabilities", [])],
        "runs": runs,
    }


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
        found = discover_target(target, profile["cookies"])
        discovery[profile["name"]] = found
        diagnostics.extend({"phase": "discovery", "profile": profile["name"], **item} for item in found["errors"])
        print(f"    {profile['name']}: {len(found['urls'])} pagine, {len(found['parameterized_urls'])} URL parametrizzati, {len(found['errors'])} errori")

    for profile in profiles:
        name, cookies = profile["name"], profile["cookies"]
        print(f"\n[*] Scanner generali - profilo: {name}")
        for spec in BASE_TOOLS:
            result = await call_mcp(spec.server, spec.tool, {"target_url": target, "cookies": cookies})
            results[name][spec.name] = result
            log_result(name, spec.name, result, target)
            if spec.name == "ffuf" and result.get("status") == "success":
                discovery[name], _ = enrich_discovery_with_ffuf(discovery[name], result, target)
            if spec.name == "arjun" and result.get("status") == "success":
                discovery[name], _ = enrich_discovery_with_arjun(discovery[name], result, target)

    for profile in profiles:
        name, cookies = profile["name"], profile["cookies"]
        urls = select_parameterized_urls(discovery[name].get("parameterized_urls", []))
        print(f"\n[*] Scanner su parametri - profilo: {name}\n    [INFO   ] endpoint unici selezionati: {len(urls)}")
        grouped = {spec.name: [] for spec in PARAMETER_TOOLS}
        for url in urls:
            for spec in PARAMETER_TOOLS:
                if spec.name == "idor" and not any(value.isdigit() for _, value in parse_qsl(urlparse(url).query, keep_blank_values=True)):
                    result = make_skipped_result("idor", url, "No numeric query parameter was available.")
                else:
                    result = await call_mcp(spec.server, spec.tool, {"target_url": url, "cookies": cookies})
                grouped[spec.name].append(result)
                log_result(name, spec.name, result, url)
        for spec in PARAMETER_TOOLS:
            results[name][spec.name] = aggregate_runs(spec.name, target, grouped[spec.name])

    for profile in profiles:
        name = profile["name"]
        token = (discovery[name].get("jwt_tokens") or [""])[0]
        jwt_result = await call_mcp("jwtServer.py", "run_jwt_scan", {"jwt_token": token, "target_url": target}) if token else make_skipped_result("jwt", target, "No JWT was discovered.")
        interactsh_result = await call_mcp("interactshServer.py", "run_interactsh_client", {"target_url": target, "injection_url": injection_url, "cookies": profile["cookies"]}) if injection_url else make_skipped_result("interactsh", target, "No OAST injection URL was supplied.")
        results[name].update(jwt=jwt_result, interactsh=interactsh_result)
        log_result(name, "jwt", jwt_result, target)
        log_result(name, "interactsh", interactsh_result, target)

    print("\n[*] Generazione report...")
    report = await call_mcp("pwndocServer.py", "generate_report", {"findings_summary": results, "target_url": target})
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
    print(f"[+] Scanner errors: {errors}\n[+] Scanner partial results: {partial}\n[+] Scanner skips: {skips}")
    return 1 if report.get("status") != "success" else 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())