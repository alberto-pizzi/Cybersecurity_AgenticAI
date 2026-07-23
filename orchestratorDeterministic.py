from __future__ import annotations

import argparse
import ast
import asyncio
import html as html_lib
import importlib.util
import json
import os
import re
import shutil
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterator, TypedDict
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
from fastmcp import Client
from langgraph.graph import END, START, StateGraph

from utils import ROOT_DIR, SERVERS_DIR, absolute_url, normalize_url, same_origin


DEFAULT_MCP_TIMEOUT = float(os.getenv("SECOPS_MCP_TIMEOUT", "900"))
MAX_PARAMETER_ENDPOINTS = max(1, int(os.getenv("SECOPS_MAX_PARAMETER_ENDPOINTS", "5")))


class LinkFormParser(HTMLParser):
    """Small dependency-free HTML parser used for same-origin discovery."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        normalized_tag = tag.lower()
        if normalized_tag == "a" and values.get("href"):
            self.links.append(str(values["href"]))
        elif normalized_tag == "form":
            self._current_form = {
                "action": values.get("action", ""),
                "method": str(values.get("method", "get")).lower(),
                "parameters": [],
            }
        elif normalized_tag in {"input", "textarea", "select", "button"} and self._current_form is not None:
            name = values.get("name")
            if name:
                self._current_form["parameters"].append(str(name))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class OrchestratorState(TypedDict):
    target: str
    profiles: list[dict[str, str]]
    discovery_by_profile: dict[str, dict[str, Any]]
    discovered_urls: list[str]
    parameterized_urls: list[str]
    jwt_tokens: list[str]
    interactsh_injection_url: str
    results: dict[str, dict[str, Any]]
    diagnostics: list[dict[str, Any]]
    report_status: dict[str, Any]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    server: str
    tool: str
    executable: str = ""


TOOLS = [
    ToolSpec("zap", "zapServer.py", "run_zap_scan"),
    ToolSpec("nuclei", "nucleiServer.py", "run_nuclei_scan", "nuclei"),
    ToolSpec("nikto", "niktoServer.py", "run_nikto_scan", "nikto"),
    ToolSpec("ffuf", "ffufServer.py", "run_ffuf_fuzz", "ffuf"),
    ToolSpec("arjun", "arjunServer.py", "run_arjun_scan", "arjun"),
]

PARAMETER_TOOLS = [
    ToolSpec("sqlmap", "sqlmapServer.py", "run_sqlmap_scan", "sqlmap"),
    ToolSpec("dalfox", "dalfoxServer.py", "run_dalfox_scan", "dalfox"),
    ToolSpec("commix", "commixServer.py", "run_commix_scan", "commix"),
    ToolSpec("idor", "idorForgeServer.py", "run_idor_check"),
]

OPTIONAL_TOOL_SPECS = [
    ToolSpec("jwt", "jwtServer.py", "run_jwt_scan"),
    ToolSpec("interactsh", "interactshServer.py", "run_interactsh_client", "interactsh-client"),
    ToolSpec("report", "pwndocServer.py", "generate_report"),
]

ALL_TOOL_SPECS = [*TOOLS, *PARAMETER_TOOLS, *OPTIONAL_TOOL_SPECS]
SERVER_PYTHON_MODULES = {
    "zapServer.py": "zapv2",
    "jwtServer.py": "jwt",
    "pwndocServer.py": "reportlab",
}


def resolve_server_path(server_file: str) -> Path:
    """Resolve normal server names and uploaded duplicate names such as ``name(2).py``."""
    requested = Path(server_file).name
    exact = (SERVERS_DIR / requested).resolve()
    if exact.is_file():
        return exact

    stem = Path(requested).stem
    suffix = Path(requested).suffix or ".py"
    candidates = [
        (SERVERS_DIR / f"{stem}(2){suffix}").resolve(),
        (SERVERS_DIR / f"{stem} (2){suffix}").resolve(),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    if Path(SERVERS_DIR).is_dir():
        wanted = requested.casefold()
        duplicate_prefix = f"{stem}(".casefold()
        for candidate in Path(SERVERS_DIR).iterdir():
            name = candidate.name.casefold()
            if candidate.is_file() and (name == wanted or (name.startswith(duplicate_prefix) and name.endswith(suffix.casefold()))):
                return candidate.resolve()
    return exact


def _declared_function_names(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except (OSError, SyntaxError):
        return set()
    return {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def run_preflight_checks() -> list[dict[str, str]]:
    """Statically verify server files, MCP function names, modules and CLI executables."""
    checks: list[dict[str, str]] = []
    seen_executables: set[str] = set()
    for spec in ALL_TOOL_SPECS:
        path = resolve_server_path(spec.server)
        if not path.is_file():
            checks.append({"level": "error", "component": spec.name, "cause": "missing_server", "detail": str(path)})
            continue
        names = _declared_function_names(path)
        if spec.tool not in names:
            checks.append({
                "level": "error",
                "component": spec.name,
                "cause": "mcp_tool_name_mismatch",
                "detail": f"{path.name} does not declare {spec.tool}()",
            })
        module = SERVER_PYTHON_MODULES.get(spec.server)
        if module and importlib.util.find_spec(module) is None:
            checks.append({
                "level": "error",
                "component": spec.name,
                "cause": "missing_python_dependency",
                "detail": f"Python module not installed: {module}",
            })
        if spec.executable and spec.executable not in seen_executables:
            seen_executables.add(spec.executable)
            resolved = shutil.which(spec.executable)
            if resolved is None:
                checks.append({
                    "level": "error",
                    "component": spec.name,
                    "cause": "missing_executable",
                    "detail": f"Executable not found in PATH: {spec.executable}",
                })
            else:
                checks.append({
                    "level": "ok",
                    "component": spec.name,
                    "cause": "executable_found",
                    "detail": resolved,
                })
    if not any(item["level"] == "error" for item in checks):
        checks.append({"level": "ok", "component": "mcp", "cause": "preflight_passed", "detail": "All server contracts were found."})
    return checks


def print_preflight_report(checks: list[dict[str, str]], *, show_ok: bool = False) -> int:
    errors = [item for item in checks if item["level"] == "error"]
    visible = checks if show_ok else errors
    if visible:
        print("\n=== SecOps preflight ===")
        for item in visible:
            marker = "+" if item["level"] == "ok" else "-"
            stream = sys.stdout if item["level"] == "ok" else sys.stderr
            print(
                f"[{marker}] {item['component']}: {item['cause']} — {item['detail']}",
                file=stream,
            )
    return len(errors)


def cookie_string(cookie_jar: requests.cookies.RequestsCookieJar) -> str:
    return "; ".join(f"{cookie.name}={cookie.value}" for cookie in cookie_jar)


def _without_fragment(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def discover_target(target: str, cookies: str, max_pages: int = 25) -> dict[str, Any]:
    """Crawl same-origin HTML pages and return URLs, parameters, JWTs and crawl errors."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SecOpsAgent-University/1.1",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
    })
    if cookies:
        session.headers["Cookie"] = cookies

    queue = [_without_fragment(target)]
    visited: set[str] = set()
    parameterized: set[str] = set()
    jwt_tokens: set[str] = set()
    errors: list[dict[str, str]] = []

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            response = session.get(url, timeout=(5, 15), allow_redirects=True)
        except requests.RequestException as exc:
            errors.append({
                "url": url,
                "type": type(exc).__name__,
                "message": str(exc),
            })
            continue

        final_url = _without_fragment(response.url)
        if not same_origin(target, final_url):
            errors.append({
                "url": url,
                "type": "CrossOriginRedirect",
                "message": f"Redirected outside target origin: {final_url}",
            })
            continue

        if response.status_code >= 400:
            errors.append({
                "url": final_url,
                "type": f"HTTP{response.status_code}",
                "message": response.reason or "HTTP error",
            })

        content_type = response.headers.get("content-type", "").lower()
        looks_like_html = "html" in content_type or response.text.lstrip().startswith(("<", "<!"))
        if not looks_like_html:
            continue

        for token in re.findall(
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
            response.text,
        ):
            jwt_tokens.add(token)

        parser = LinkFormParser()
        try:
            parser.feed(response.text)
            parser.close()
        except Exception as exc:
            errors.append({
                "url": final_url,
                "type": type(exc).__name__,
                "message": f"HTML parsing failed: {exc}",
            })
            continue

        for candidate in parser.links:
            try:
                absolute = _without_fragment(absolute_url(final_url, candidate))
            except Exception as exc:
                errors.append({
                    "url": final_url,
                    "type": type(exc).__name__,
                    "message": f"Invalid discovered link {candidate!r}: {exc}",
                })
                continue
            if not same_origin(target, absolute):
                continue
            if urlparse(absolute).query:
                parameterized.add(absolute)
            if absolute not in visited and absolute not in queue:
                queue.append(absolute)

        for form in parser.forms:
            try:
                action = _without_fragment(absolute_url(final_url, form["action"] or final_url))
            except Exception as exc:
                errors.append({
                    "url": final_url,
                    "type": type(exc).__name__,
                    "message": f"Invalid form action: {exc}",
                })
                continue
            if not same_origin(target, action):
                continue
            parameters = list(dict.fromkeys(form["parameters"]))
            if form["method"] == "get" and parameters:
                parsed = urlparse(action)
                existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
                for name in parameters:
                    existing.setdefault(name, "1")
                parameterized.add(urlunparse(parsed._replace(query=urlencode(existing))))

    return {
        "urls": sorted(visited),
        "parameterized_urls": sorted(parameterized),
        "jwt_tokens": sorted(jwt_tokens),
        "errors": errors,
    }


def parameter_signature(url: str) -> tuple[str, str, str, tuple[str, ...]]:
    parsed = urlparse(url)
    names = tuple(sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
    return parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, names


def select_parameterized_urls(urls: list[str], limit: int = MAX_PARAMETER_ENDPOINTS) -> list[str]:
    """Keep one representative per endpoint/parameter-name combination."""
    selected: list[str] = []
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    for url in sorted(urls):
        signature = parameter_signature(url)
        if not signature[3] or signature in seen:
            continue
        seen.add(signature)
        selected.append(url)
        if len(selected) >= limit:
            break
    return selected


def build_parameterized_urls(base_url: str, parameters: list[str], limit: int = 20) -> list[str]:
    """Convert Arjun parameter names into concrete same-origin URLs for downstream tools."""
    parsed = urlparse(base_url)
    existing = list(parse_qsl(parsed.query, keep_blank_values=True))
    existing_names = {name for name, _ in existing}
    generated: list[str] = []
    seen: set[str] = set()
    for raw_name in parameters:
        name = str(raw_name).strip()
        if not name or name in existing_names or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", name):
            continue
        query = urlencode([*existing, (name, "1")])
        candidate = urlunparse(parsed._replace(query=query, fragment=""))
        if candidate not in seen:
            seen.add(candidate)
            generated.append(candidate)
        if len(generated) >= limit:
            break
    return generated


def extract_arjun_parameters(result: dict[str, Any]) -> list[str]:
    parameters = result.get("parameters") or []
    collected = [str(value) for value in parameters if isinstance(value, (str, int, float))]
    for finding in result.get("vulnerabilities") or []:
        if isinstance(finding, dict) and finding.get("parameter"):
            collected.append(str(finding["parameter"]))
    return sorted(set(value.strip() for value in collected if value.strip()))


def enrich_discovery_with_arjun(
    discovery: dict[str, Any],
    arjun_result: dict[str, Any],
    base_url: str,
) -> tuple[dict[str, Any], list[str]]:
    """Merge successful Arjun discoveries into the profile-specific discovery surface."""
    updated = dict(discovery)
    if str(arjun_result.get("status", "")).lower() != "success":
        return updated, []
    generated = build_parameterized_urls(base_url, extract_arjun_parameters(arjun_result))
    if not generated:
        return updated, []
    updated["parameterized_urls"] = sorted(set(updated.get("parameterized_urls", [])) | set(generated))
    return updated, generated


def enrich_discovery_with_ffuf(
    discovery: dict[str, Any],
    ffuf_result: dict[str, Any],
    target: str,
) -> tuple[dict[str, Any], list[str]]:
    """Add same-origin resources returned by FFUF to the discovery surface."""
    updated = dict(discovery)
    if str(ffuf_result.get("status", "")).lower() != "success":
        return updated, []
    discovered: list[str] = []
    for finding in ffuf_result.get("vulnerabilities") or []:
        if not isinstance(finding, dict):
            continue
        candidate = str(finding.get("url", "")).strip()
        if candidate and same_origin(target, candidate):
            candidate = _without_fragment(candidate)
            discovered.append(candidate)
    if not discovered:
        return updated, []
    updated["urls"] = sorted(set(updated.get("urls", [])) | set(discovered))
    parameterized = {url for url in discovered if urlparse(url).query}
    if parameterized:
        updated["parameterized_urls"] = sorted(
            set(updated.get("parameterized_urls", [])) | parameterized
        )
    return updated, sorted(set(discovered))


def is_idor_candidate(url: str) -> bool:
    """Match the current IDOR server contract: it mutates numeric query values only."""
    return any(value.isdigit() for _, value in parse_qsl(urlparse(url).query, keep_blank_values=True))


def make_skipped_result(tool: str, target: str, reason: str) -> dict[str, Any]:
    return {
        "tool": tool,
        "status": "skipped",
        "target": target,
        "output": reason,
        "vulnerabilities": [],
        "diagnosis": "not_applicable",
    }


def diagnose_error(message: str) -> str:
    lowered = message.lower()
    patterns = [
        (("no such file", "not found", "winerror 2", "errno 2"), "missing_file_or_executable"),
        (("modulenotfounderror", "no module named"), "missing_python_dependency"),
        (("connection refused", "failed to establish a new connection"), "service_unreachable"),
        (("timed out", "timeout", "timeouterror"), "timeout"),
        (("permission denied", "access is denied", "winerror 5"), "permission_denied"),
        (("unknown tool", "tool not found", "method not found"), "mcp_tool_name_mismatch"),
        (("jsondecodeerror", "invalid json"), "invalid_json_response"),
        (("api key", "unauthorized", "forbidden", "401", "403"), "authentication_or_api_key"),
        (("cannot import name", "importerror"), "incompatible_python_dependency"),
        (("closedresourceerror", "connection closed", "end of file"), "mcp_server_crashed"),
    ]
    for needles, cause in patterns:
        if any(needle in lowered for needle in needles):
            return cause
    return "scanner_or_mcp_error"


def _ensure_project_pythonpath() -> None:
    root = str(Path(ROOT_DIR).resolve())
    existing = os.environ.get("PYTHONPATH", "")
    parts = [part for part in existing.split(os.pathsep) if part]
    if root not in parts:
        os.environ["PYTHONPATH"] = os.pathsep.join([root, *parts])


def _json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, default=str))
    except Exception:
        return str(value)


def _parse_text_payload(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return ""
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        return stripped


def _extract_mcp_response(response: Any) -> tuple[Any, bool, str]:
    """Support FastMCP response shapes both before and after the `.data` API."""
    is_error = bool(getattr(response, "is_error", False) or getattr(response, "isError", False))

    for attribute in ("data", "structured_content", "structuredContent"):
        if hasattr(response, attribute):
            value = getattr(response, attribute)
            if value is not None:
                return value, is_error, attribute

    content = getattr(response, "content", None)
    if content is not None:
        if isinstance(content, str):
            return _parse_text_payload(content), is_error, "content"
        if isinstance(content, list):
            texts: list[str] = []
            objects: list[Any] = []
            for item in content:
                if isinstance(item, dict):
                    if "text" in item:
                        texts.append(str(item["text"]))
                    else:
                        objects.append(item)
                else:
                    text = getattr(item, "text", None)
                    if text is not None:
                        texts.append(str(text))
                    else:
                        objects.append(item)
            if len(texts) == 1 and not objects:
                return _parse_text_payload(texts[0]), is_error, "content.text"
            if texts or objects:
                return [_parse_text_payload(text) for text in texts] + objects, is_error, "content[]"

    if isinstance(response, dict):
        return response, is_error, "mapping"
    return str(response), is_error, "stringified_response"


def _normalize_mcp_result(
    data: Any,
    *,
    tool_name: str,
    server_file: str,
    target: str,
    elapsed: float,
    response_shape: str,
    mcp_is_error: bool,
) -> dict[str, Any]:
    safe_data = _json_safe(data)
    if isinstance(safe_data, dict):
        result = dict(safe_data)
    else:
        result = {
            "tool": tool_name,
            "status": "error" if mcp_is_error else "success",
            "target": target,
            "output": safe_data if isinstance(safe_data, str) else json.dumps(safe_data, ensure_ascii=False),
            "vulnerabilities": [],
        }

    result.setdefault("tool", tool_name)
    result.setdefault("target", target)
    result.setdefault("output", "")
    result.setdefault("vulnerabilities", [])
    status = str(result.get("status", "error" if mcp_is_error else "success")).lower()
    if mcp_is_error:
        status = "error"
    if status not in {"success", "error", "skipped", "partial"}:
        status = "error" if mcp_is_error else "success"
    result["status"] = status
    result["_meta"] = {
        "server": server_file,
        "requested_tool": tool_name,
        "duration_seconds": round(elapsed, 3),
        "response_shape": response_shape,
        "mcp_is_error": mcp_is_error,
    }
    if status == "error":
        diagnostic_text = "\n".join(
            str(result.get(field, ""))
            for field in ("output", "stderr", "stdout", "error", "message")
            if result.get(field)
        )
        result.setdefault("diagnosis", diagnose_error(diagnostic_text))
    return result


async def call_mcp(
    server_file: str,
    tool_name: str,
    arguments: dict[str, Any],
    timeout_seconds: float = DEFAULT_MCP_TIMEOUT,
) -> dict[str, Any]:
    """Call one scanner over MCP and always return a structured, diagnosable result."""
    server_path = resolve_server_path(server_file)
    target = str(arguments.get("target_url", ""))
    started = time.monotonic()

    if not server_path.is_file():
        message = f"MCP server file does not exist: {server_path}"
        return {
            "tool": tool_name,
            "status": "error",
            "target": target,
            "output": message,
            "vulnerabilities": [],
            "diagnosis": "missing_mcp_server_file",
            "_meta": {"server": server_file, "requested_tool": tool_name, "duration_seconds": 0.0},
        }

    _ensure_project_pythonpath()

    async def invoke() -> tuple[Any, bool, str]:
        async with Client(str(server_path)) as client:
            response = await client.call_tool(tool_name, arguments)
            return _extract_mcp_response(response)

    try:
        data, mcp_is_error, response_shape = await asyncio.wait_for(
            invoke(), timeout=max(1.0, float(timeout_seconds))
        )
        result = _normalize_mcp_result(
            data,
            tool_name=tool_name,
            server_file=server_file,
            target=target,
            elapsed=time.monotonic() - started,
            response_shape=response_shape,
            mcp_is_error=mcp_is_error,
        )
        result.setdefault("_meta", {})["resolved_server"] = str(server_path)
    except asyncio.TimeoutError:
        message = f"MCP call exceeded {timeout_seconds:.0f} seconds."
        result = {
            "tool": tool_name,
            "status": "error",
            "target": target,
            "output": message,
            "vulnerabilities": [],
            "diagnosis": "timeout",
            "_meta": {
                "server": server_file,
                "requested_tool": tool_name,
                "duration_seconds": round(time.monotonic() - started, 3),
            },
        }
    except Exception as exc:
        message = f"MCP communication failed: {type(exc).__name__}: {exc}"
        result = {
            "tool": tool_name,
            "status": "error",
            "target": target,
            "output": message,
            "vulnerabilities": [],
            "diagnosis": diagnose_error(message),
            "exception_type": type(exc).__name__,
            "traceback": traceback.format_exc(),
            "_meta": {
                "server": server_file,
                "requested_tool": tool_name,
                "duration_seconds": round(time.monotonic() - started, 3),
            },
        }

    if result.get("status") == "error":
        print(
            f"\n[SCANNER ERROR] server={server_file} tool={tool_name} target={target}\n"
            f"  cause={result.get('diagnosis', 'unknown')}\n"
            f"  detail={result.get('output', '')}",
            file=sys.stderr,
        )
    return result


def run_async(coroutine: Any) -> Any:
    """Run a coroutine from sync LangGraph nodes, including hosts with a running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coroutine).result()


def log_result(profile: str, name: str, result: dict[str, Any], target: str = "") -> None:
    status = str(result.get("status", "error")).upper()
    detail = str(result.get("output", "")).replace("\n", " ")[:180]
    destination = target or str(result.get("target", ""))
    print(f"    [{status:7}] {name}: {destination}")
    if status in {"ERROR", "PARTIAL"} and detail:
        print(f"              {detail}", file=sys.stderr)


def aggregate_runs(tool: str, target: str, runs: list[dict[str, Any]]) -> dict[str, Any]:
    if not runs:
        return make_skipped_result(tool, target, "No applicable parameterized URL was discovered.")
    statuses = [str(run.get("status", "error")).lower() for run in runs]
    errors = sum(status == "error" for status in statuses)
    skipped = sum(status == "skipped" for status in statuses)
    successes = sum(status == "success" for status in statuses)
    if errors:
        status = "error" if successes == 0 else "partial"
    elif successes:
        status = "success"
    else:
        status = "skipped"
    vulnerabilities = [
        finding
        for run in runs
        for finding in (run.get("vulnerabilities") or [])
        if isinstance(finding, dict)
    ]
    return {
        "tool": tool,
        "status": status,
        "target": target,
        "output": (
            f"Runs: {len(runs)}; successful: {successes}; errors: {errors}; "
            f"skipped: {skipped}; findings: {len(vulnerabilities)}."
        ),
        "vulnerabilities": vulnerabilities,
        "runs": runs,
        "diagnosis": "nested_scanner_errors" if errors else None,
    }


def iter_leaf_results(results: dict[str, Any], path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], dict[str, Any]]]:
    for key, value in results.items():
        current = (*path, str(key))
        if not isinstance(value, dict):
            continue
        runs = value.get("runs")
        if isinstance(runs, list):
            for index, run in enumerate(runs, start=1):
                if isinstance(run, dict):
                    yield (*current, str(index)), run
            continue
        if "status" in value:
            yield current, value
        else:
            yield from iter_leaf_results(value, current)


def discovery_node(state: OrchestratorState) -> dict[str, Any]:
    print("\n[*] Discovery anonima e autenticata...")
    discovery_by_profile: dict[str, dict[str, Any]] = {}
    urls: set[str] = set()
    parameterized: set[str] = set()
    tokens: set[str] = set()
    diagnostics = list(state.get("diagnostics", []))

    for profile in state["profiles"]:
        name = profile["name"]
        found = discover_target(state["target"], profile["cookies"])
        discovery_by_profile[name] = found
        urls.update(found["urls"])
        parameterized.update(found["parameterized_urls"])
        tokens.update(found["jwt_tokens"])
        for error in found.get("errors", []):
            diagnostics.append({"phase": "discovery", "profile": name, **error})
        print(
            f"    {name}: {len(found['urls'])} pagine, "
            f"{len(found['parameterized_urls'])} URL parametrizzati, "
            f"{len(found.get('errors', []))} errori HTTP/crawl"
        )

    return {
        "discovery_by_profile": discovery_by_profile,
        "discovered_urls": sorted(urls),
        "parameterized_urls": sorted(parameterized),
        "jwt_tokens": sorted(tokens),
        "diagnostics": diagnostics,
    }


def base_scanners_node(state: OrchestratorState) -> dict[str, Any]:
    all_results = {profile: dict(values) for profile, values in state["results"].items()}
    discovery_by_profile = {
        profile: dict(values) for profile, values in state["discovery_by_profile"].items()
    }
    all_parameterized = set(state.get("parameterized_urls", []))

    for profile in state["profiles"]:
        profile_name = profile["name"]
        cookies = profile["cookies"]
        profile_results = dict(all_results.get(profile_name, {}))
        print(f"\n[*] Scanner generali - profilo: {profile_name}")
        for spec in TOOLS:
            result = run_async(call_mcp(
                spec.server,
                spec.tool,
                {"target_url": state["target"], "cookies": cookies},
            ))
            profile_results[spec.name] = result
            log_result(profile_name, spec.name, result, state["target"])

            if spec.name == "ffuf":
                current = discovery_by_profile.get(profile_name, {})
                enriched, generated_resources = enrich_discovery_with_ffuf(
                    current, result, state["target"]
                )
                discovery_by_profile[profile_name] = enriched
                all_parameterized.update(
                    url for url in generated_resources if urlparse(url).query
                )
                if generated_resources:
                    print(f"    [INFO   ] ffuf aggiunge {len(generated_resources)} risorse al profilo {profile_name}")

            if spec.name == "arjun":
                current = discovery_by_profile.get(profile_name, {})
                enriched, generated = enrich_discovery_with_arjun(current, result, state["target"])
                discovery_by_profile[profile_name] = enriched
                all_parameterized.update(generated)
                if generated:
                    print(f"    [INFO   ] arjun aggiunge {len(generated)} URL parametrizzati al profilo {profile_name}")

        all_results[profile_name] = profile_results
    return {
        "results": all_results,
        "discovery_by_profile": discovery_by_profile,
        "parameterized_urls": sorted(all_parameterized),
    }


def parameter_scanners_node(state: OrchestratorState) -> dict[str, Any]:
    """Run parameter tools only on URLs discovered in the same access profile."""
    all_results = {profile: dict(values) for profile, values in state["results"].items()}

    for profile in state["profiles"]:
        profile_name = profile["name"]
        cookies = profile["cookies"]
        profile_results = dict(all_results.get(profile_name, {}))
        discovered = state["discovery_by_profile"].get(profile_name, {})
        test_urls = select_parameterized_urls(discovered.get("parameterized_urls", []))
        print(f"\n[*] Scanner su parametri - profilo: {profile_name}")
        print(f"    [INFO   ] endpoint unici selezionati: {len(test_urls)}")

        grouped: dict[str, list[dict[str, Any]]] = {spec.name: [] for spec in PARAMETER_TOOLS}
        for url in test_urls:
            for spec in PARAMETER_TOOLS:
                if spec.name == "idor" and not is_idor_candidate(url):
                    skipped = make_skipped_result(
                        "idor", url, "No numeric or identifier-like parameter was found."
                    )
                    grouped[spec.name].append(skipped)
                    log_result(profile_name, spec.name, skipped, url)
                    continue
                result = run_async(call_mcp(
                    spec.server,
                    spec.tool,
                    {"target_url": url, "cookies": cookies},
                ))
                grouped[spec.name].append(result)
                log_result(profile_name, spec.name, result, url)

        for key, runs in grouped.items():
            profile_results[key] = aggregate_runs(key, state["target"], runs)
        all_results[profile_name] = profile_results

    return {"results": all_results}


def optional_scanners_node(state: OrchestratorState) -> dict[str, Any]:
    all_results = {profile: dict(values) for profile, values in state["results"].items()}
    for profile in state["profiles"]:
        profile_name = profile["name"]
        profile_results = dict(all_results.get(profile_name, {}))
        found = state["discovery_by_profile"].get(profile_name, {})
        tokens = found.get("jwt_tokens", [])

        if tokens:
            jwt_result = run_async(call_mcp(
                "jwtServer.py",
                "run_jwt_scan",
                {"jwt_token": tokens[0], "target_url": state["target"]},
            ))
        else:
            jwt_result = make_skipped_result("jwt", state["target"], "No JWT was discovered for this profile.")
        profile_results["jwt"] = jwt_result
        log_result(profile_name, "jwt", jwt_result, state["target"])

        injection_url = state.get("interactsh_injection_url", "").strip()
        if injection_url:
            interactsh_result = run_async(call_mcp(
                "interactshServer.py",
                "run_interactsh_client",
                {
                    "target_url": state["target"],
                    "injection_url": injection_url,
                    "cookies": profile["cookies"],
                },
            ))
        else:
            interactsh_result = make_skipped_result(
                "interactsh",
                state["target"],
                "No target-specific OAST injection URL was supplied. Use --interactsh-injection-url.",
            )
        profile_results["interactsh"] = interactsh_result
        log_result(profile_name, "interactsh", interactsh_result, state["target"])
        all_results[profile_name] = profile_results

    return {"results": all_results}


def write_emergency_json_report(
    target: str,
    results: dict[str, Any],
    diagnostics: list[dict[str, Any]],
    reason: str,
    output_name: str = "",
) -> str | None:
    try:
        reports_dir = Path(ROOT_DIR) / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", output_name).strip("._")
        filename = f"{safe_name or 'SecOps_Emergency'}_{stamp}.json"
        path = reports_dir / filename
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "report_mode": "orchestrator_emergency_json",
            "reason": reason,
            "diagnostics": diagnostics,
            "results": _json_safe(results),
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        html_path = path.with_suffix(".html")
        escaped = html_lib.escape(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        html_path.write_text(
            "<!doctype html><html><head><meta charset='utf-8'><title>SecOps emergency preview</title>"
            "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;max-width:1200px}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#111923;color:#e7eef7;padding:1rem;border-radius:10px}</style>"
            f"</head><body><h1>SecOps emergency preview</h1><p><b>Target:</b> {html_lib.escape(target)}</p>"
            f"<p><b>Reason:</b> {html_lib.escape(reason)}</p><pre>{escaped}</pre></body></html>",
            encoding="utf-8",
        )
        print(f"[+] Emergency JSON report generated: {path.resolve()}")
        print(f"[+] Emergency HTML preview generated: {html_path.resolve()}")
        return str(path.resolve())
    except Exception as exc:
        print(f"[REPORT FALLBACK ERROR] {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return None


def report_node(state: OrchestratorState) -> dict[str, Any]:
    print("\n[*] Generazione report...")
    report = run_async(call_mcp(
        "pwndocServer.py",
        "generate_report",
        {
            "findings_summary": state["results"],
            "target_url": state["target"],
        },
    ))
    if report.get("status") != "success" and not report.get("json_filename"):
        fallback_path = write_emergency_json_report(
            state["target"],
            state["results"],
            state.get("diagnostics", []),
            str(report.get("output", "PwnDoc MCP report failed.")),
        )
        if fallback_path:
            report["json_filename"] = fallback_path
            preview_path = str(Path(fallback_path).with_suffix(".html"))
            if Path(preview_path).is_file():
                report["html_filename"] = preview_path
            report["local_json_fallback"] = True
    if report.get("status") == "error":
        print(
            f"[REPORT ERROR] cause={report.get('diagnosis', 'unknown')} "
            f"detail={report.get('output', '')}",
            file=sys.stderr,
        )
    return {"report_status": report}


def build_graph() -> Any:
    graph = StateGraph(OrchestratorState)
    graph.add_node("discovery", discovery_node)
    graph.add_node("base_scanners", base_scanners_node)
    graph.add_node("parameter_scanners", parameter_scanners_node)
    graph.add_node("optional_scanners", optional_scanners_node)
    graph.add_node("report", report_node)
    graph.add_edge(START, "discovery")
    graph.add_edge("discovery", "base_scanners")
    graph.add_edge("base_scanners", "parameter_scanners")
    graph.add_edge("parameter_scanners", "optional_scanners")
    graph.add_edge("optional_scanners", "report")
    graph.add_edge("report", END)
    return graph.compile()


def print_error_summary(results: dict[str, Any]) -> tuple[int, int, int]:
    errors = 0
    skips = 0
    partial = 0
    error_rows: list[tuple[str, str, str]] = []
    for path, result in iter_leaf_results(results):
        status = str(result.get("status", "error")).lower()
        if status == "error":
            errors += 1
            error_rows.append(("/".join(path), str(result.get("diagnosis", "unknown")), str(result.get("output", ""))))
        elif status == "skipped":
            skips += 1
        elif status == "partial":
            partial += 1
    if error_rows:
        print("\n=== Scanner error details ===", file=sys.stderr)
        for path, cause, output in error_rows:
            print(f"[-] {path}: {cause} — {output[:500]}", file=sys.stderr)
    return errors, skips, partial


def main() -> int:
    parser = argparse.ArgumentParser(description="Generic deterministic FastMCP web-security orchestrator.")
    parser.add_argument("--target", required=True, help="Authorized HTTP/HTTPS target.")
    parser.add_argument("--cookies", default="", help="Authenticated session cookies.")
    parser.add_argument("--auth-only", action="store_true", help="Test only with supplied cookies.")
    parser.add_argument("--authorized", action="store_true", help="Confirms explicit authorization for a remote target.")
    parser.add_argument("--preflight-only", action="store_true", help="Validate MCP files, function names, Python modules and scanner executables, then exit.")
    parser.add_argument(
        "--interactsh-injection-url",
        default="",
        help="Optional same-target URL/endpoint where an OAST payload can be inserted.",
    )
    args = parser.parse_args()

    preflight_checks = run_preflight_checks()
    preflight_errors = print_preflight_report(preflight_checks, show_ok=args.preflight_only)
    if args.preflight_only:
        return 0 if preflight_errors == 0 else 3

    target = normalize_url(args.target)
    is_local = urlparse(target).hostname in {"127.0.0.1", "localhost", "dvwa"}
    if not is_local and not args.authorized:
        parser.error("Remote targets require --authorized.")

    injection_url = args.interactsh_injection_url.strip()
    if injection_url and not same_origin(target, injection_url):
        parser.error("--interactsh-injection-url must have the same origin as --target.")

    profiles: list[dict[str, str]] = []
    if not args.auth_only:
        profiles.append({"name": "anonymous", "cookies": ""})
    if args.cookies:
        profiles.append({"name": "authenticated", "cookies": args.cookies})
    elif args.auth_only:
        parser.error("--auth-only requires --cookies.")

    print("=== FastMCP Deterministic Security Pipeline ===")
    print(f"[*] Target: {target}")
    print(f"[*] Profiles: {', '.join(profile['name'] for profile in profiles)}")
    started = time.time()

    initial: OrchestratorState = {
        "target": target,
        "profiles": profiles,
        "discovery_by_profile": {},
        "discovered_urls": [],
        "parameterized_urls": [],
        "jwt_tokens": [],
        "interactsh_injection_url": injection_url,
        "results": {profile["name"]: {} for profile in profiles},
        "diagnostics": [],
        "report_status": {},
    }

    try:
        final = build_graph().invoke(initial)
    except Exception as exc:
        detail = f"Workflow failed: {type(exc).__name__}: {exc}"
        print(f"[-] {detail}", file=sys.stderr)
        traceback.print_exc()
        emergency = write_emergency_json_report(target, initial["results"], initial["diagnostics"], detail)
        print(f"[+] JSON: {emergency or 'not generated'}")
        return 1

    report = final.get("report_status", {})
    errors, skips, partial = print_error_summary(final.get("results", {}))

    print(f"\n=== Completed in {time.time() - started:.2f} seconds ===")
    print(f"[+] PDF: {report.get('pdf_filename') or 'not generated'}")
    print(f"[+] HTML preview: {report.get('html_filename') or 'not generated'}")
    print(f"[+] JSON: {report.get('json_filename') or 'not generated'}")
    print(f"[+] Scanner errors: {errors}")
    print(f"[+] Scanner partial results: {partial}")
    print(f"[+] Scanner skips: {skips}")
    print(f"[+] Discovery diagnostics: {len(final.get('diagnostics', []))}")

    if report.get("status") != "success":
        return 1
    if errors:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())