from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from fastmcp import FastMCP

from utils import ROOT_DIR, run_mcp_http, runtime_container_route

def service(label: str, key: str) -> tuple[FastMCP, Callable[[], None]]:
    """Create a FastMCP service and its direct-run entrypoint."""
    mcp = FastMCP(label)
    return mcp, lambda: run_mcp_http(mcp, key)

def unique_strings(values: Iterable[Any] | None) -> list[str]:
    """Normalize strings while preserving first-seen order."""
    return list(dict.fromkeys(str(value).strip() for value in (values or []) if str(value).strip()))

def looks_like_login(
    response: requests.Response, *,
    text_limit: int = 100_000, paths: tuple[str, ...] = ("/login", "/login.php", "/signin", "/sign-in", "/auth"),
    words: tuple[str, ...] = ("login", "log in", "sign in", "authenticate"), strip_trailing_slash: bool = True,
) -> bool:
    """Shared login-page detector with per-scanner compatibility knobs."""
    text = response.text[:text_limit].lower()
    path = urlparse(str(response.url)).path.lower()
    if strip_trailing_slash:
        path = path.rstrip("/")
    password = "type=\"password\"" in text or "type='password'" in text
    return path.endswith(paths) or (password and any(word in text for word in words))

CONTROL_PARAMETERS = {"submit", "login", "change", "user_token", "csrf", "button"}

def filter_control_parameters(values: Iterable[Any] | None) -> list[str]:
    return [value for value in unique_strings(values) if value.lower() not in CONTROL_PARAMETERS]

def find_repo_script(tool: str, filename: str) -> Path | None:
    """Find an initializer-managed Python scanner without depending on PATH."""
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

def extend_request_cli(command: list[str], data: str, parameters: Iterable[Any] | None, cookies: str) -> None:
    if data:
        command.extend(["--data", data])
    values = unique_strings(parameters)
    if values:
        command.extend(["-p", ",".join(values)])
    if cookies:
        command.extend(["--cookie", cookies])

def process_text(result: dict[str, Any]) -> str:
    return "\n".join(str(result.get(key, "")) for key in ("stdout", "stderr", "output"))

def mutate_parameter(
    url: str, method: str, data: str, parameter: str, value: str, *, case_insensitive: bool = False, clear_fragment: bool = False,
    append_if_missing: bool = True, replace_all: bool = False,
) -> tuple[str, str]:
    """Replace one query/form parameter without changing the rest of the request."""
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

def request_retry(
    method: str, url: str, *, attempts: int = 3, backoff: float = 0.7, **kwargs: Any,
) -> requests.Response:
    """Retry transient transport failures and re-raise the last Requests error."""
    last: requests.RequestException | None = None
    for attempt in range(max(1, int(attempts))):
        try:
            return requests.request(method, url, **kwargs)
        except (requests.Timeout, requests.ConnectionError) as exc:
            last = exc
            if attempt + 1 < attempts:
                time.sleep(backoff * (attempt + 1))
        except requests.RequestException:
            raise
    assert last is not None
    raise last


def docker_target(url: str) -> tuple[str, list[str], str]:
    """Translate a localhost target for an official scanner container.

    Prefer the initializer-declared lab network/alias; fall back to Docker
    Desktop's host gateway only when no exact runtime route is available.
    """
    import os
    import sys

    parsed = urlparse(str(url or ""))
    if (parsed.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}:
        return url, [], "same_target"
    route = runtime_container_route(url)
    if not route:
        # Target profiles are bound to the initialized root path, while scanner
        # inputs usually contain child endpoints. Container routing is origin-wide.
        origin = urlunparse(parsed._replace(path="", params="", query="", fragment=""))
        route = runtime_container_route(origin)
    alias, network = str(route.get("alias") or ""), str(route.get("network") or "")
    if alias and network:
        internal = int(route.get("internal_port") or (443 if parsed.scheme == "https" else 80))
        netloc = alias if internal in {80, 443} else f"{alias}:{internal}"
        return urlunparse(parsed._replace(netloc=netloc)), ["--network", network], "runtime_network_alias"
    netloc = "host.docker.internal" + (f":{parsed.port}" if parsed.port else "")
    args = [] if os.name == "nt" or sys.platform == "darwin" else ["--add-host", "host.docker.internal:host-gateway"]
    return urlunparse(parsed._replace(netloc=netloc)), args, "host_gateway"

def docker_container_name(prefix: str) -> str:
    """Return a unique, recognizable name for a short-lived scanner container."""
    import os
    import re
    import uuid
    safe = re.sub(r"[^a-z0-9-]+", "-", str(prefix or "scanner").lower()).strip("-") or "scanner"
    return f"secops-{safe}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def cleanup_docker_container(name: str) -> bool:
    """Best-effort cleanup after a docker CLI timeout.

    Killing the local ``docker`` client does not necessarily stop the container
    that the daemon already started, so scanner wrappers explicitly remove their
    named container in ``finally`` blocks.
    """
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


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return default

def load_config(default_path: Path, env_name: str = "SECOPS_RUNTIME_CONFIG") -> dict[str, Any]:
    """Load a JSON runtime config, honoring the optional environment override."""
    import os
    configured = os.environ.get(env_name, "").strip()
    value = read_json(Path(configured).expanduser() if configured else default_path, {})
    return value if isinstance(value, dict) else {}
