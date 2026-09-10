from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse, urlunparse

import requests

ROOT_DIR = Path(__file__).resolve().parent
SERVERS_DIR = ROOT_DIR / "servers"
REPORTS_DIR = ROOT_DIR / "reports"
WORDLISTS_DIR = ROOT_DIR / "wordlists"
LOCAL_BIN = Path.home() / ".local" / "bin"


MCP_HTTP_HOST = "127.0.0.1"
MCP_HTTP_PATH = "/mcp"
MCP_UNIFIED_SERVICE = "secops"
MCP_SERVER_PORTS: dict[str, int] = {MCP_UNIFIED_SERVICE: 8100}


# The complete security catalogue is exposed through one local MCP service.
def mcp_http_port(service_name: str = MCP_UNIFIED_SERVICE) -> int:
    name = str(service_name or MCP_UNIFIED_SERVICE).strip().lower()
    if name not in MCP_SERVER_PORTS:
        raise KeyError(f"Unknown MCP HTTP service: {service_name}")
    return int(MCP_SERVER_PORTS[name])


# Builds the local URL of the unified MCP security service.
def mcp_http_url(service_name: str = MCP_UNIFIED_SERVICE, host: str = MCP_HTTP_HOST) -> str:
    return f"http://{host}:{mcp_http_port(service_name)}{MCP_HTTP_PATH}"


# Only the unified interface is allowed to own an MCP HTTP listener.
def run_mcp_http(mcp: Any, service_name: str = MCP_UNIFIED_SERVICE) -> None:
    name = str(service_name or MCP_UNIFIED_SERVICE).strip().lower()
    if name != MCP_UNIFIED_SERVICE:
        raise RuntimeError(
            f"Standalone MCP service '{service_name}' is disabled; run servers/secopsServer.py instead."
        )
    host = os.getenv("SECOPS_MCP_HOST", MCP_HTTP_HOST).strip() or MCP_HTTP_HOST
    port = int(os.getenv("SECOPS_MCP_PORT", str(mcp_http_port(MCP_UNIFIED_SERVICE))))
    mcp.run(transport="http", host=host, port=port)

_FATAL_STARTUP_PATTERNS = (
    r"is not recognized as an internal or external command",
    r"non .? riconosciuto come comando interno o esterno",
    r"can't open perl script",
    r"cannot open perl script",
    r"modulenotfounderror",
    r"traceback \(most recent call last\)",
    r"createprocess error",
    r"/usr/bin/env:.*no such file",
)


_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


# Parses a Cookie header and rejects invalid or duplicate cookie names.
def parse_cookie_header(value: str) -> list[tuple[str, str]]:


    text = str(value or "").strip()
    if not text:
        return []
    if "\r" in text or "\n" in text:
        raise ValueError("Cookie header contains a prohibited control character.")

    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"Invalid cookie pair without '=': {part!r}")
        name, cookie_value = part.split("=", 1)
        name = name.strip()
        cookie_value = cookie_value.strip()
        if not name or not _COOKIE_NAME_RE.fullmatch(name):
            raise ValueError(f"Invalid cookie name: {name!r}")
        lowered = name.lower()
        if lowered in seen:
            raise ValueError(f"Duplicate cookie name: {name}")
        seen.add(lowered)
        pairs.append((name, cookie_value))
    return pairs


# Cookie normalization rebuilds the header in a single consistent format.
def canonical_cookie_header(value: str) -> str:
    return "; ".join(f"{name}={cookie_value}" for name, cookie_value in parse_cookie_header(value))


# Cookie-name extraction exposes only the names present in the supplied header.
def cookie_names(value: str) -> list[str]:
    return [name for name, _ in parse_cookie_header(value)]


# Login-page detection uses the final URL and form content to recognize authentication screens.
def response_looks_like_login(response: Any) -> bool:

    try:
        final_url = str(response.url).lower()
        text = str(response.text)[:100_000].lower()
    except Exception:
        return False
    path = urlparse(final_url).path.rstrip("/")
    password_field = "type=\"password\"" in text or "type='password'" in text
    auth_words = any(term in text for term in ("login", "log in", "sign in", "signin", "authenticate"))
    return (
        path.endswith(("/login", "/login.php", "/signin", "/sign-in", "/auth"))
        or (password_field and auth_words)
    )


# Loads the local runtime file when it exists.
def load_runtime_config() -> dict[str, Any]:

    path = ROOT_DIR / ".secops_runtime.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


# Parses an HTTP/HTTPS origin without allowing malformed authority/port text to escape as an exception.
def _url_origin_parts(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlparse(str(url or "").strip())
        scheme = str(parsed.scheme or "").lower()
        host = str(parsed.hostname or "").lower()
        if scheme not in {"http", "https"} or not host:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
    except (TypeError, ValueError):
        return None
    return scheme, host, int(port)


# Converts a URL into the scheme, host, and port key used by runtime profiles.
def origin_key(url: str) -> str:
    parts = _url_origin_parts(url)
    if parts is None:
        return ""
    scheme, host, port = parts
    return f"{scheme}://{host}:{port}"


# Runtime profile lookup only accepts settings bound to the exact target origin and path.
def target_runtime_profile(target: str) -> dict[str, Any]:

    profiles = load_runtime_config().get("target_profiles", {})
    if not isinstance(profiles, dict):
        return {}
    value = profiles.get(origin_key(target), {})
    if not isinstance(value, dict):
        return {}
    configured_target = str(value.get("target_url") or "").strip()
    if configured_target:
        configured = urlparse(configured_target)
        requested = urlparse(str(target or ""))
        configured_path = (configured.path or "/").rstrip("/") or "/"
        requested_path = (requested.path or "/").rstrip("/") or "/"
        if origin_key(configured_target) != origin_key(target) or configured_path != requested_path:
            return {}
    return value


# Docker routing resolves the optional internal route configured for the current target.
def runtime_container_route(target: str, scanner_container: str = "") -> dict[str, Any]:

    profile = target_runtime_profile(target)
    route = profile.get("container_route", {})
    if not isinstance(route, dict):
        return {}
    allowed = str(route.get("scanner_container") or "")
    if allowed and scanner_container and allowed != scanner_container:
        return {}
    return route


# Applies target-specific preparation requests before a scanner starts.
def apply_runtime_target_preparation(target: str, cookies: str) -> dict[str, Any]:


    profile = target_runtime_profile(target)
    requests_spec = profile.get("pre_scan_requests", [])
    if not cookies or not isinstance(requests_spec, list) or not requests_spec:
        return {"performed": False, "configured": bool(requests_spec), "usable": True}
    session = requests.Session()
    session.headers.update({
        "Cookie": cookies,
        "Cache-Control": "no-cache",
        "User-Agent": "SecOps-Target-Preparation/1.0",
    })
    outcomes: list[dict[str, Any]] = []
    usable = True
    conclusive = True
    transient_errors: list[str] = []
    for item in requests_spec[:8]:
        if not isinstance(item, dict):
            continue
        method = str(item.get("method") or "GET").upper()
        path = str(item.get("path") or "").strip()
        if method not in {"GET", "POST"} or not path:
            continue
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        if origin_key(url) != origin_key(target):
            usable = False
            outcomes.append({"url": url, "error": "cross-origin preparation request rejected"})
            continue
        try:
            response = session.request(
                method, url, data=str(item.get("data") or "") if method == "POST" else None,
                timeout=(4, 15), allow_redirects=True,
            )
            accepted = item.get("accepted_statuses", [200, 204, 302])
            accepted_set = {int(value) for value in accepted if str(value).isdigit()}
            ok = response.status_code in accepted_set if accepted_set else response.status_code < 400
            usable = usable and ok
            outcomes.append({
                "method": method, "url": url, "status": response.status_code,
                "final_url": str(response.url), "accepted": ok,
            })
        except requests.RequestException as exc:


            conclusive = False
            error = f"{type(exc).__name__}: {exc}"
            transient_errors.append(error)
            outcomes.append({"method": method, "url": url, "error": error, "transient": True})
    return {
        "performed": bool(outcomes), "configured": True, "usable": usable,
        "conclusive": conclusive, "transient_error": bool(transient_errors),
        "transient_errors": transient_errors[-5:], "requests": outcomes,
    }


# Sends an HTTP request again after short temporary failures.
def request_with_retries(
    method: str,
    url: str,
    *,
    attempts: int = 3,
    backoff_seconds: float = 0.65,
    **kwargs: Any,
) -> tuple[requests.Response | None, list[str]]:


    errors: list[str] = []
    for attempt in range(max(1, int(attempts))):
        try:
            return requests.request(method=method, url=url, **kwargs), errors
        except (requests.Timeout, requests.ConnectionError) as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            if attempt + 1 < attempts:
                time.sleep(backoff_seconds * (attempt + 1))
        except requests.RequestException as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            break
    return None, errors


# Session probing confirms that a scanner still reaches the target as the authenticated user.
def scanner_session_probe(
    url: str,
    cookies: str,
    method: str = "GET",
    data: str = "",
    timeout: int = 12,
    attempts: int = 3,
) -> dict[str, Any]:


    if not cookies:
        return {"performed": False, "authenticated": None, "conclusive": True}
    response, errors = request_with_retries(
        str(method or "GET").upper(),
        url,
        attempts=attempts,
        data=data if str(method).upper() != "GET" else None,
        headers={"Cookie": cookies, "Cache-Control": "no-cache"},
        timeout=(4, max(6, int(timeout))),
        allow_redirects=True,
    )
    if response is None:
        return {
            "performed": True,
            "authenticated": None,
            "conclusive": False,
            "transient_error": True,
            "errors": errors,
            "error": errors[-1] if errors else "request failed",
        }
    login = response_looks_like_login(response)
    authenticated = response.status_code < 400 and not login
    return {
        "performed": True,
        "authenticated": authenticated,
        "conclusive": True,
        "transient_error": False,
        "status": int(response.status_code),
        "final_url": str(response.url),
        "login_detected": login,
        "bytes": len(response.content),
        "attempt_errors": errors,
    }

# Adds the project tool folders to PATH for the current process.
def setup_path() -> None:

    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    parts = [item for item in os.environ.get("PATH", "").split(os.pathsep) if item]
    if str(LOCAL_BIN) not in parts:
        os.environ["PATH"] = str(LOCAL_BIN) + os.pathsep + os.environ.get("PATH", "")


# Finds an executable by checking the project tool folder and system PATH.
def find_executable(name: str) -> str | None:
    setup_path()
    return shutil.which(name) or shutil.which(f"{name}.bat") or shutil.which(f"{name}.exe")


# URL normalization removes fragments and trailing path separators without altering query values.
def normalize_url(url: str) -> str:
    try:
        parsed = urlparse(sanitize_discovered_url(url))
    except ValueError as exc:
        raise ValueError("The target must be a valid absolute HTTP/HTTPS URL.") from exc
    if _url_origin_parts(url) is None:
        raise ValueError("The target must be a valid absolute HTTP/HTTPS URL with a valid port.")
    path = parsed.path
    if len(path) > 1:
        path = path.rstrip("/")
    elif path == "/" and not parsed.query:
        path = ""
    return urlunparse(parsed._replace(path=path, fragment=""))


# Origin comparison requires the same scheme, host, and effective port; malformed discovered URLs are out of scope.
def same_origin(left: str, right: str) -> bool:
    a = _url_origin_parts(left)
    b = _url_origin_parts(right)
    return a is not None and b is not None and a == b


# Converts an absolute HTTP/HTTPS URL into a stable origin string.
def normalized_origin(url: str) -> str:
    parts = _url_origin_parts(url)
    if parts is None:
        return ""
    scheme, host, port = parts
    default_port = 80 if scheme == "http" else 443
    port_fragment = "" if port == default_port else f":{port}"
    host_fragment = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{host_fragment}{port_fragment}"


# Host-suffix matching is boundary-aware so example.org never authorizes notexample.org.
def host_matches_authorized_suffix(host: str, suffix: str) -> bool:
    candidate = str(host or "").strip().lower().rstrip(".")
    allowed = str(suffix or "").strip().lower().lstrip(".").rstrip(".")
    if not candidate or not allowed or "/" in allowed or "://" in allowed:
        return False
    return candidate == allowed or candidate.endswith("." + allowed)


# Explicit assessment scope may extend beyond one origin without implicitly trusting unrelated external hosts.
def url_in_authorized_scope(
    target: str,
    candidate: str,
    authorized_origins: list[str] | tuple[str, ...] | set[str] | None = None,
    authorized_host_suffixes: list[str] | tuple[str, ...] | set[str] | None = None,
) -> bool:
    if same_origin(target, candidate):
        return True
    candidate_parts = _url_origin_parts(candidate)
    if candidate_parts is None:
        return False
    candidate_origin = normalized_origin(candidate)
    exact_origins = {normalized_origin(value) for value in (authorized_origins or []) if normalized_origin(value)}
    if candidate_origin in exact_origins:
        return True
    host = candidate_parts[1]
    return any(host_matches_authorized_suffix(host, suffix) for suffix in (authorized_host_suffixes or []))


# Response previews keep a short printable body excerpt for diagnostics.
def response_excerpt(text: str, marker: str = "", limit: int = 900) -> str:
    value = str(text or "")
    index = value.find(marker) if marker else -1
    if index < 0:
        return value[:limit]
    start = max(0, index - limit // 3)
    return value[start:start + limit]


# Keeps the useful end of long process output for diagnostics.
def trim_process_output(result: dict[str, Any], limit: int) -> dict[str, Any]:
    for key in ("stdout", "stderr"):
        value = str(result.get(key, ""))
        if len(value) > limit:
            result[key] = value[-limit:]
            result[f"{key}_truncated"] = True
    return result


# Removes stray whitespace from discovered URL authorities without touching path/query data.
def sanitize_discovered_url(url: str) -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    netloc = str(parsed.netloc or "").strip()
    if netloc:
        userinfo = ""
        hostport = netloc
        if "@" in hostport:
            userinfo, hostport = hostport.rsplit("@", 1)
        host = hostport
        port_fragment = ""
        if hostport.startswith("["):
            closing = hostport.find("]")
            if closing >= 0:
                host = hostport[: closing + 1]
                port_fragment = hostport[closing + 1 :]
        elif ":" in hostport:
            maybe_host, maybe_port = hostport.rsplit(":", 1)
            if maybe_port.isdigit():
                host, port_fragment = maybe_host, ":" + maybe_port
        host = re.sub(r"(?i)(?:%20|%09|%0a|%0d)+$", "", host.strip())
        hostport = host + port_fragment
        netloc = (userinfo + "@" if userinfo else "") + hostport
    return urlunparse(parsed._replace(netloc=netloc, fragment=""))


# Resolves a discovered link against its base URL and sanitizes stray authority whitespace.
def absolute_url(base: str, candidate: str) -> str:
    return sanitize_discovered_url(urljoin(str(base or "").strip(), str(candidate or "").strip()))


# Server tools share one result structure for status, findings, output, and diagnostics.
def make_result(
    tool: str,
    status: str,
    target: str = "",
    output: str = "",
    vulnerabilities: list[dict[str, Any]] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "tool": tool,
        "status": status,
        "target": target,
        "output": output,
        "vulnerabilities": vulnerabilities or [],
    }
    result.update(extra)
    return result


# Successful runs are wrapped in the common server result format.
def success(tool: str, target: str = "", output: str = "", **extra: Any) -> dict[str, Any]:
    return make_result(tool, "success", target, output, **extra)


# Partial runs preserve useful findings while using the common server result format.
def partial(tool: str, target: str, output: str, **extra: Any) -> dict[str, Any]:
    return make_result(tool, "partial", target, output, **extra)


# Skipped runs keep a clear reason in the common server result format.
def skipped(tool: str, target: str, reason: str, **extra: Any) -> dict[str, Any]:
    return make_result(tool, "skipped", target, reason, **extra)


# Failed runs include process details that help explain why the tool did not complete.
def failure(
    tool: str,
    target: str,
    message: str,
    *,
    return_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
    diagnosis: str = "scanner_error",
    **extra: Any,
) -> dict[str, Any]:
    return make_result(
        tool,
        "error",
        target,
        message,
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        diagnosis=diagnosis,
        **extra,
    )


# Converts timeout output into normal text for diagnostics.
def _decode_timeout_output(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


# Startup diagnosis scans process output for errors that show the scanner never launched correctly.
def _fatal_startup_error(text: str) -> str:
    lowered = text.lower()
    return next((pattern for pattern in _FATAL_STARTUP_PATTERNS if re.search(pattern, lowered, re.I)), "")


# While external scanners run, the process wrapper enforces time limits and preserves useful partial output.
def run_process(
    tool: str,
    command: list[str],
    *,
    target: str,
    timeout: int = 180,
    accepted_codes: Iterable[int] = (0,),
    cwd: Path | None = None,
) -> dict[str, Any]:

    executable = find_executable(command[0])
    if not executable:
        return failure(tool, target, f"Executable not found: {command[0]}", diagnosis="missing_executable")

    resolved_command = [executable, *command[1:]]
    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    started = time.monotonic()
    try:
        completed = subprocess.run(
            resolved_command,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(timeout)),
            shell=False,
        )
    # A timeout keeps any useful output instead of hiding work the scanner already completed.
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_timeout_output(exc.stdout)
        stderr = _decode_timeout_output(exc.stderr)
        return failure(
            tool,
            target,
            f"Timeout after {timeout} seconds",
            stdout=stdout,
            stderr=stderr,
            diagnosis="timeout",
            timed_out=True,
            duration_seconds=round(time.monotonic() - started, 3),
            command=resolved_command,
        )
    except OSError as exc:
        return failure(
            tool,
            target,
            f"Cannot start process: {exc}",
            diagnosis="process_start_failed",
            duration_seconds=round(time.monotonic() - started, 3),
            command=resolved_command,
        )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    combined = "\n".join(value.strip() for value in (stdout, stderr) if value.strip()).strip()
    fatal_pattern = _fatal_startup_error(combined)
    if fatal_pattern:
        return failure(
            tool,
            target,
            "The scanner launcher failed before the scan started.",
            return_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            diagnosis="scanner_runtime_dependency_missing",
            duration_seconds=round(time.monotonic() - started, 3),
            command=resolved_command,
            matched_startup_error=fatal_pattern,
        )

    if completed.returncode not in set(accepted_codes):
        return failure(
            tool,
            target,
            f"Process exited with code {completed.returncode}",
            return_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            diagnosis="unexpected_exit_code",
            duration_seconds=round(time.monotonic() - started, 3),
            command=resolved_command,
        )

    return success(
        tool,
        target,
        combined or "Command completed without textual output.",
        return_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        command=resolved_command,
        duration_seconds=round(time.monotonic() - started, 3),
    )


# Reads JSONL output and ignores lines that are not valid JSON.
def read_json_lines(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        try:
            value = json.loads(raw_line.strip())
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows