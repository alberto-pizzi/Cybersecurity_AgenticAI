from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlparse, urlunparse

import requests

ROOT_DIR = Path(__file__).resolve().parent
SERVERS_DIR = ROOT_DIR / "servers"
REPORTS_DIR = ROOT_DIR / "reports"
WORDLISTS_DIR = ROOT_DIR / "wordlists"
LOCAL_BIN = Path.home() / ".local" / "bin"

# Shared assessment traffic policy. The assessment configuration selects the effective
# per-active-scanner request rate. Ten requests/second is the project default. Integer values
# from 1 through 50 are accepted. Invalid, fractional, non-finite, non-positive or above-cap values fall back
# to the default instead of being silently clamped, so an accidental value cannot create a
# substantially different traffic profile than the operator intended.
DEFAULT_REQUEST_RATE = 10.0
REQUEST_RATE_HARD_CAP = 50.0
_REQUEST_RATE_UNSET = object()

def scanner_request_rate_policy(value: Any = _REQUEST_RATE_UNSET) -> dict[str, Any]:
    use_environment = value is _REQUEST_RATE_UNSET
    env_value = os.getenv("SECOPS_MAX_REQUEST_RATE") if use_environment else None
    raw = env_value if env_value not in (None, "") else (DEFAULT_REQUEST_RATE if use_environment else value)
    fallback_reason = ""
    try:
        if isinstance(raw, bool):
            raise ValueError("boolean request rate is not valid")
        rate = float(raw)
    except (TypeError, ValueError):
        rate = DEFAULT_REQUEST_RATE
        fallback_reason = "invalid request-rate value"
    if not math.isfinite(rate):
        rate = DEFAULT_REQUEST_RATE
        fallback_reason = "non-finite request-rate value"
    elif not rate.is_integer():
        rate = DEFAULT_REQUEST_RATE
        fallback_reason = "request rate must be an integer number of requests/second"
    elif rate < 1.0:
        rate = DEFAULT_REQUEST_RATE
        fallback_reason = "request rate must be at least 1 request/second"
    elif rate > REQUEST_RATE_HARD_CAP:
        rate = DEFAULT_REQUEST_RATE
        fallback_reason = f"request rate exceeds the maximum of {REQUEST_RATE_HARD_CAP:g} requests/second"
    return {
        "requested": raw,
        "effective": rate,
        "default": DEFAULT_REQUEST_RATE,
        "hard_cap": REQUEST_RATE_HARD_CAP,
        "fallback_applied": bool(fallback_reason),
        "fallback_reason": fallback_reason,
    }

def scanner_request_rate(value: Any = _REQUEST_RATE_UNSET) -> float:
    return float(scanner_request_rate_policy(value)["effective"])


class RequestRatePacer:
    """Per-tool-call HTTP pacer shared by project-controlled request helpers.

    The orchestrators execute specialist tools sequentially, but one custom checker can issue
    several requests of its own. Reusing one pacer for the whole checker keeps those requests
    under the configured assessment rate, including each redirect hop and retry.
    """

    def __init__(self, request_rate: Any = _REQUEST_RATE_UNSET) -> None:
        self.rate = scanner_request_rate(request_rate)
        self.interval_seconds = 1.0 / self.rate
        self._last_request_at = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self.interval_seconds - (now - self._last_request_at)
            if delay > 0:
                time.sleep(delay)
            self._last_request_at = time.monotonic()


def runtime_request_rate_policy() -> dict[str, Any]:
    policy = scanner_request_rate_policy()
    requested = os.getenv("SECOPS_REQUEST_RATE_REQUESTED")
    if requested not in (None, ""):
        policy["requested"] = requested
    configured = os.getenv("SECOPS_REQUEST_RATE_CONFIGURED")
    if configured is not None:
        policy["configured"] = configured == "1"
        policy["source"] = "execution.request_rate" if policy["configured"] else "default"
    fallback = os.getenv("SECOPS_REQUEST_RATE_FALLBACK")
    if fallback is not None:
        policy["fallback_applied"] = fallback == "1"
    reason = os.getenv("SECOPS_REQUEST_RATE_FALLBACK_REASON")
    if reason is not None:
        policy["fallback_reason"] = reason
    return policy


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
        # A terminal DNS dot denotes the same absolute hostname (example.com. == example.com).
        # Normalize it centrally so exact-origin and same-host-port decisions do not disagree with
        # browser/DNS semantics merely because one discovered URL used the absolute form.
        host = str(parsed.hostname or "").lower().rstrip(".")
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
            response = request_same_origin_redirects(
                method, url, session=session, data=str(item.get("data") or "") if method == "POST" else None,
                timeout=(4, 15),
            )
            accepted = item.get("accepted_statuses", [200, 204, 302])
            accepted_set = {int(value) for value in accepted if str(value).isdigit()}
            redirect_guard = str(response.headers.get("X-SecOps-Redirect-Guard") or "")
            ok = (not redirect_guard) and (response.status_code in accepted_set if accepted_set else response.status_code < 400)
            usable = usable and ok
            outcomes.append({
                "method": method, "url": url, "status": response.status_code,
                "final_url": str(response.url), "accepted": ok,
                "redirect_guard": redirect_guard,
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
    pacer: RequestRatePacer | None = None,
    request_rate: Any = _REQUEST_RATE_UNSET,
    deadline: float | None = None,
    **kwargs: Any,
) -> tuple[requests.Response | None, list[str]]:


    errors: list[str] = []
    active_pacer = pacer or RequestRatePacer(request_rate)
    for attempt in range(max(1, int(attempts))):
        try:
            if deadline is not None:
                left = float(deadline) - time.monotonic()
                if left <= 0:
                    errors.append("Timeout: shared scanner deadline reached")
                    break
                configured = kwargs.get("timeout")
                if isinstance(configured, tuple) and len(configured) == 2:
                    kwargs["timeout"] = (min(float(configured[0]), left), min(float(configured[1]), left))
                elif configured is not None:
                    kwargs["timeout"] = min(float(configured), left)
                else:
                    kwargs["timeout"] = left
            if kwargs.get("allow_redirects"):
                return request_same_origin_redirects(method, url, pacer=active_pacer, deadline=deadline, **kwargs), errors
            # Scanner helpers never inherit Requests' method-dependent redirect defaults. A caller
            # must opt in explicitly; opt-in follow is always routed through the same-origin guard.
            kwargs["allow_redirects"] = False
            active_pacer.wait()
            return requests.request(method=method, url=url, **kwargs), errors
        except (requests.Timeout, requests.ConnectionError) as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            if attempt + 1 < attempts:
                delay = backoff_seconds * (attempt + 1)
                if deadline is not None:
                    delay = min(delay, max(0.0, float(deadline) - time.monotonic()))
                if delay > 0:
                    time.sleep(delay)
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
    *,
    pacer: RequestRatePacer | None = None,
    request_rate: Any = _REQUEST_RATE_UNSET,
    deadline: float | None = None,
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
        pacer=pacer,
        request_rate=request_rate,
        deadline=deadline,
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
    redirect_guard = str(response.headers.get("X-SecOps-Redirect-Guard") or "")
    login = response_looks_like_login(response)
    if redirect_guard:
        diagnosis = "cross_origin_redirect_blocked" if redirect_guard == "cross-origin-blocked" else "redirect_limit_reached"
        return {
            "performed": True,
            "authenticated": None,
            "conclusive": False,
            "transient_error": False,
            "diagnosis": diagnosis,
            "status": int(response.status_code),
            "final_url": str(response.url),
            "login_detected": login,
            "redirect_guard": redirect_guard,
            "location": str(response.headers.get("Location") or ""),
            "bytes": len(response.content),
            "attempt_errors": errors,
        }
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


# Builds an anchored regular expression for exactly one HTTP origin. Default ports are
# accepted in both implicit and explicit form because they represent the same effective origin.
def exact_origin_authority_regex(url: str) -> str:
    parts = _url_origin_parts(url)
    if parts is None:
        return r"(?!)"
    scheme, host, port = parts
    host_fragment = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 80 if scheme == "http" else 443
    port_fragment = rf"(?::{port})?" if port == default_port else re.escape(f":{port}")
    return rf"(?i:{re.escape(scheme)}://{re.escape(host_fragment)}{port_fragment})"


# Matches only URLs on the exact scheme/host/effective-port origin, never hostname prefixes.
def exact_origin_url_regex(url: str) -> str:
    return rf"^{exact_origin_authority_regex(url)}(?:[/?#].*)?$"


# Follows redirect chains only while every hop remains on the starting origin.
def request_same_origin_redirects(
    method: str, url: str, *, max_redirects: int = 5, session: requests.Session | None = None,
    pacer: RequestRatePacer | None = None, request_rate: Any = _REQUEST_RATE_UNSET,
    deadline: float | None = None, **kwargs: Any,
) -> requests.Response:
    """Send one HTTP request and follow redirects only while they remain on the starting origin.

    A redirect to another origin is returned as the final response and is never requested. This keeps
    normal application redirects working without allowing a scanner helper to escape the authorized
    target merely because the server emitted a Location header.
    """
    start = str(url or '')
    current = start
    kwargs = dict(kwargs)
    kwargs.pop('allow_redirects', None)
    configured_timeout = kwargs.get('timeout')
    response: requests.Response | None = None
    active_pacer = pacer or RequestRatePacer(request_rate)
    for _ in range(max(0, int(max_redirects)) + 1):
        requester = session.request if session is not None else requests.request
        if deadline is not None and float(deadline) - time.monotonic() <= 0:
            raise requests.Timeout("shared scanner deadline reached")
        active_pacer.wait()
        if deadline is not None:
            left = float(deadline) - time.monotonic()
            if left <= 0:
                raise requests.Timeout("shared scanner deadline reached")
            if isinstance(configured_timeout, tuple) and len(configured_timeout) == 2:
                kwargs['timeout'] = (min(float(configured_timeout[0]), left), min(float(configured_timeout[1]), left))
            elif configured_timeout is not None:
                kwargs['timeout'] = min(float(configured_timeout), left)
            else:
                kwargs['timeout'] = left
        response = requester(method, current, allow_redirects=False, **kwargs)
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = str(response.headers.get('Location') or '').strip()
        if not location:
            return response
        candidate = urljoin(current, location)
        if not same_origin(start, candidate):
            response.headers['X-SecOps-Redirect-Guard'] = 'cross-origin-blocked'
            return response
        method_upper = str(method).upper()
        # Match Requests/browser redirect method rebuilding: 303 and 302 become GET for every
        # non-HEAD method; historical 301 changes POST to GET; 307/308 preserve method/body.
        switch_to_get = (
            (response.status_code == 303 and method_upper != 'HEAD')
            or (response.status_code == 302 and method_upper != 'HEAD')
            or (response.status_code == 301 and method_upper == 'POST')
        )
        if switch_to_get:
            method = 'GET'
            kwargs.pop('data', None)
            kwargs.pop('json', None)
            headers = kwargs.get('headers')
            if isinstance(headers, dict):
                # A redirected GET must not inherit entity headers from the original request.
                headers = dict(headers)
                for header_name in list(headers):
                    if str(header_name).lower() in {'content-length', 'content-type', 'transfer-encoding'}:
                        headers.pop(header_name, None)
                kwargs['headers'] = headers
        current = candidate
    assert response is not None
    response.headers['X-SecOps-Redirect-Guard'] = 'redirect-limit-reached'
    return response


# Explicit assessment scope may extend beyond one origin without implicitly trusting unrelated external hosts.
def url_in_authorized_scope(
    target: str,
    candidate: str,
    authorized_origins: list[str] | tuple[str, ...] | set[str] | None = None,
    allow_same_host_ports: bool = False,
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
    if allow_same_host_ports:
        candidate_scheme, candidate_host, _ = candidate_parts
        bases = [target, *(authorized_origins or [])]
        for value in bases:
            parts = _url_origin_parts(str(value or ''))
            if parts is None:
                continue
            scheme, host, _ = parts
            # Multi-port authorization expands only the port for an already authorized exact
            # hostname on the same HTTP scheme. It never authorizes sibling/prefix domains or
            # an HTTP<->HTTPS protocol change implicitly.
            if scheme == candidate_scheme and host == candidate_host:
                return True
    # DNS suffixes are intentionally not an active-attack authorization mechanism.
    # A discovered sibling host must be listed as an exact authorized origin before it can be tested.
    return False


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
    basename = str(parsed.path or '').rstrip('/').rsplit('/', 1)[-1]
    if re.fullmatch(r'\.(?:php|phtml|jsp|jspx|asp|aspx|html?|cgi|pl|py|rb)', basename, re.I):
        # Dynamic source extraction can occasionally concatenate an empty route stem with a file
        # extension (for example '/.php'). Such a path is a synthetic artefact, not a meaningful
        # endpoint. Reject only the extension-only basename; legitimate dotfiles remain untouched.
        return ""
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
    progress_callback: Callable[[], None] | None = None,
    progress_interval: float = 5.0,
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
        if progress_callback is None:
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
        else:
            # A progress callback is used by scanners such as Nuclei that write structured
            # findings incrementally to disk. Polling communicate() lets the wrapper snapshot
            # those artifacts while the child is still running without introducing scanner
            # concurrency or changing its stdout/stderr contract.
            process = subprocess.Popen(
                resolved_command,
                cwd=str(cwd) if cwd else None,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
            stdout = stderr = ""
            timeout_seconds = max(1.0, float(timeout))
            interval = max(0.5, min(float(progress_interval), timeout_seconds))
            while True:
                remaining = timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    process.kill()
                    stdout, stderr = process.communicate()
                    raise subprocess.TimeoutExpired(resolved_command, timeout_seconds, output=stdout, stderr=stderr)
                try:
                    stdout, stderr = process.communicate(timeout=min(interval, remaining))
                    break
                except subprocess.TimeoutExpired:
                    try:
                        progress_callback()
                    except Exception:
                        # Checkpointing/telemetry must never abort the scanner itself.
                        pass
            completed = subprocess.CompletedProcess(resolved_command, process.returncode, stdout or "", stderr or "")
    # A timeout keeps any useful output instead of hiding work the scanner already completed.
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_timeout_output(exc.stdout)
        stderr = _decode_timeout_output(exc.stderr)
        if progress_callback is not None:
            try:
                progress_callback()
            except Exception:
                pass
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