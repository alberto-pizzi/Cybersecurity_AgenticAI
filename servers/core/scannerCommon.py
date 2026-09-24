from __future__ import annotations

import json
from difflib import SequenceMatcher
import time
import threading
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from fastmcp import FastMCP

from utils import ROOT_DIR, RequestRatePacer, deadline_bounded_request_timeout, request_invocation_state_change_reason, request_same_origin_redirects, runtime_container_route, safe_port_value

_CONNECTION_POOL_LOCAL = threading.local()

class _StatelessCookieSession(requests.Session):
    """Reuse TCP/TLS pools without silently carrying response cookies between scanner actions."""
    def request(self, method: str | bytes, url: str | bytes, **kwargs: Any) -> requests.Response:
        self.cookies.clear()
        try:
            return super().request(method, url, **kwargs)
        finally:
            self.cookies.clear()

def connection_pool_session() -> requests.Session:
    session = getattr(_CONNECTION_POOL_LOCAL, 'session', None)
    if session is None:
        session = _StatelessCookieSession()
        _CONNECTION_POOL_LOCAL.session = session
    return session

# Creates a composable child FastMCP registry; only secopsServer.py owns the HTTP listener.
def service(label: str, key: str) -> tuple[FastMCP, Callable[[], None]]:

    mcp = FastMCP(label)

    # Child modules contain tool implementations only; direct execution must never create another MCP endpoint.
    def _standalone_disabled() -> None:
        raise RuntimeError(
            f"'{key}' is a child tool module. Start servers/secopsServer.py for the unified MCP endpoint."
        )

    return mcp, _standalone_disabled

# Normalize strings while preserving first-seen order.
def unique_strings(values: Iterable[Any] | None) -> list[str]:

    return list(dict.fromkeys(str(value).strip() for value in (values or []) if str(value).strip()))

# Convert one tool-level timeout into phase budgets without scattering absolute second values.
def proportional_budget(total_seconds: int | float, ratio: float, *, minimum: int = 1, maximum: int | None = None) -> int:

    total = max(1.0, float(total_seconds))
    value = max(int(minimum), int(round(total * max(0.0, float(ratio)))))
    if maximum is not None:
        value = min(value, int(maximum))
    return max(1, value)

# Create one monotonic wall-clock deadline shared by all phases/fallbacks of a scanner action.
def wall_clock_deadline(total_seconds: int | float) -> float:

    return time.monotonic() + max(1.0, float(total_seconds))

# Return the seconds still available before a shared scanner deadline.
def remaining_budget(deadline: float, *, minimum: float = 0.0) -> float:

    return max(float(minimum), float(deadline) - time.monotonic())

# Compare two response bodies with bounded work so proxy/session validation does not depend on full-page byte equality.
def bounded_text_similarity(left: Any, right: Any, *, text_limit: int = 80_000, chunk_size: int = 128) -> float:

    limit = max(1, int(text_limit))
    width = max(16, int(chunk_size))

    def chunks(value: Any) -> list[str]:
        text = " ".join(str(value or "")[:limit].split())
        return [text[index:index + width] for index in range(0, len(text), width)]

    left_chunks, right_chunks = chunks(left), chunks(right)
    if not left_chunks and not right_chunks:
        return 1.0
    if not left_chunks or not right_chunks:
        return 0.0
    return float(SequenceMatcher(None, left_chunks, right_chunks, autojunk=False).ratio())

# Shared login-page detector with per-scanner compatibility knobs.
def looks_like_login(
    response: requests.Response, *,
    text_limit: int = 100_000, paths: tuple[str, ...] = ("/login", "/login.php", "/signin", "/sign-in", "/auth"),
    words: tuple[str, ...] = ("login", "log in", "sign in", "authenticate"), strip_trailing_slash: bool = True,
) -> bool:

    text = response.text[:text_limit].lower()
    path = urlparse(str(response.url)).path.lower()
    if strip_trailing_slash:
        path = path.rstrip("/")
    password = "type=\"password\"" in text or "type='password'" in text
    return path.endswith(paths) or (password and any(word in text for word in words))

CONTROL_PARAMETERS = {"submit", "login", "change", "user_token", "csrf", "button"}

# Filter control parameters to keep only values safe and relevant to the current scan.
def filter_control_parameters(values: Iterable[Any] | None) -> list[str]:
    return [value for value in unique_strings(values) if value.lower() not in CONTROL_PARAMETERS]

# Find an initializer-managed Python scanner without depending on PATH.
def find_repo_script(tool: str, filename: str) -> Path | None:

    import re
    candidates = [Path.home() / ".local" / "opt" / tool / filename, Path(ROOT_DIR) / "tools" / tool / filename]
    launcher = Path.home() / ".local" / "bin" / f"{tool}.bat"
    if launcher.is_file():
        text = launcher.read_text(encoding="utf-8", errors="replace")
        escaped = re.escape(filename)
        match = re.search(rf'"([^"\r\n]*{escaped})"|([A-Za-z]:\\[^\r\n]*?{escaped})', text, re.I)
        if match:
            candidates.insert(0, Path(match.group(1) or match.group(2)))
    return next((path.resolve() for path in candidates if path.is_file()), None)

# Append method, cookie and body arguments shared by scanner CLI wrappers.
def extend_request_cli(command: list[str], data: str, parameters: Iterable[Any] | None, cookies: str) -> None:
    if data:
        command.extend(["--data", data])
    values = unique_strings(parameters)
    if values:
        command.extend(["-p", ",".join(values)])
    if cookies:
        command.extend(["--cookie", cookies])

# Combine process stdout, stderr and diagnostics into one searchable text block.
def process_text(result: dict[str, Any]) -> str:
    return "\n".join(str(result.get(key, "")) for key in ("stdout", "stderr", "output"))

# Replace one query/form parameter without changing the rest of the request.
def mutate_parameter(
    url: str, method: str, data: str, parameter: str, value: str, *, case_insensitive: bool = False, clear_fragment: bool = False,
    append_if_missing: bool = True, replace_all: bool = False,
) -> tuple[str, str]:

    method = method.upper()
    parsed = urlparse(url)
    source = parsed.query if method == "GET" else data
    pairs = parse_qsl(source, keep_blank_values=True)
    key = parameter.lower() if case_insensitive else parameter
    changed: list[tuple[str, str]] = []
    replaced = False
    for name, current in pairs:
        candidate = name.lower() if case_insensitive else name
        if candidate == key and (replace_all or not replaced):
            current, replaced = value, True
        changed.append((name, current))
    if not replaced and append_if_missing:
        changed.append((parameter, value))
    encoded = urlencode(changed, doseq=True)
    if method == "GET":
        fragment = "" if clear_fragment else parsed.fragment
        return urlunparse(parsed._replace(query=encoded, fragment=fragment)), ""
    return url, encoded

# Retry transient transport failures and re-raise the last Requests error.
def request_retry(
    method: str, url: str, *, attempts: int = 3, backoff: float = 0.7,
    pacer: RequestRatePacer | None = None, request_rate: Any = None, deadline: float | None = None,
    allow_state_changes: bool = False, **kwargs: Any,
) -> requests.Response:

    last: requests.RequestException | None = None
    active_pacer = pacer or RequestRatePacer(request_rate)
    session = connection_pool_session()
    for attempt in range(max(1, int(attempts))):
        try:
            if deadline is not None:
                left = remaining_budget(deadline)
                if left <= 0:
                    raise requests.Timeout("shared scanner deadline reached")
                kwargs["timeout"] = deadline_bounded_request_timeout(kwargs.get("timeout"), float(deadline))
            if kwargs.get("allow_redirects"):
                return request_same_origin_redirects(
                    method, url, session=session, pacer=active_pacer, deadline=deadline,
                    allow_state_changes=allow_state_changes, **kwargs,
                )
            # Keep retry behavior deterministic: no implicit Requests redirect follow. Callers that
            # opt in to redirects are handled above by the project same-origin guard.
            kwargs["allow_redirects"] = False
            if not allow_state_changes:
                state_reason = request_invocation_state_change_reason(
                    method, url, data=kwargs.get("data"), json_body=kwargs.get("json"),
                    params=kwargs.get("params"), files=kwargs.get("files"), headers=kwargs.get("headers"),
                )
                if state_reason:
                    raise requests.RequestException(f"state-change policy blocked request before send: {state_reason}")
            active_pacer.wait()
            return session.request(method, url, **kwargs)
        except (requests.Timeout, requests.ConnectionError) as exc:
            last = exc
            if attempt + 1 < attempts:
                delay = backoff * (attempt + 1)
                if deadline is not None:
                    delay = min(delay, remaining_budget(deadline))
                if delay > 0:
                    time.sleep(delay)
        except requests.RequestException:
            raise
    assert last is not None
    raise last

# Translate a localhost target for an official scanner container.
def docker_target(url: str) -> tuple[str, list[str], str]:

    import os
    import sys

    parsed = urlparse(str(url or ""))
    if (parsed.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}:
        return url, [], "same_target"
    route = runtime_container_route(url)
    if not route:

        origin = urlunparse(parsed._replace(path="", params="", query="", fragment=""))
        route = runtime_container_route(origin)
    alias, network = str(route.get("alias") or ""), str(route.get("network") or "")
    if alias and network:
        default_port = 443 if parsed.scheme == "https" else 80
        internal = safe_port_value(route.get("internal_port"), default_port)
        netloc = alias if internal in {80, 443} else f"{alias}:{internal}"
        return urlunparse(parsed._replace(netloc=netloc)), ["--network", network], "runtime_network_alias"
    netloc = "host.docker.internal" + (f":{parsed.port}" if parsed.port else "")
    args = [] if os.name == "nt" or sys.platform == "darwin" else ["--add-host", "host.docker.internal:host-gateway"]
    return urlunparse(parsed._replace(netloc=netloc)), args, "host_gateway"

# Return a unique, recognizable name for a short-lived scanner container.
def docker_container_name(prefix: str) -> str:

    import os
    import re
    import uuid
    safe = re.sub(r"[^a-z0-9-]+", "-", str(prefix or "scanner").lower()).strip("-") or "scanner"
    return f"secops-{safe}-{os.getpid()}-{uuid.uuid4().hex[:8]}"

# Best-effort cleanup after a docker CLI timeout.
def cleanup_docker_container(name: str) -> bool:

    if not str(name or "").strip():
        return False
    import shutil
    import subprocess
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        completed = subprocess.run(
            [docker, "rm", "-f", name], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=8, shell=False,
        )
        text = f"{completed.stdout}\n{completed.stderr}".lower()
        return completed.returncode == 0 or "no such container" in text
    except (OSError, subprocess.SubprocessError):
        return False

# Read json from scanner output or runtime state for downstream processing.
def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return default

# Load a JSON runtime config, honoring the optional environment override.
def load_config(default_path: Path, env_name: str = "SECOPS_RUNTIME_CONFIG") -> dict[str, Any]:

    import os
    configured = os.environ.get(env_name, "").strip()
    value = read_json(Path(configured).expanduser() if configured else default_path, {})
    return value if isinstance(value, dict) else {}
