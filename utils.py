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


def parse_cookie_header(value: str) -> list[tuple[str, str]]:
    """
    Parse a Cookie header without silently accepting duplicate names.

    Cookie values are treated as opaque strings. Control characters and
    duplicate cookie names are rejected because they can produce ambiguous
    behaviour across Requests, ZAP, SQLMap, Commix and the target application.
    """
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


def canonical_cookie_header(value: str) -> str:
    return "; ".join(f"{name}={cookie_value}" for name, cookie_value in parse_cookie_header(value))


def cookie_names(value: str) -> list[str]:
    return [name for name, _ in parse_cookie_header(value)]


def redact_cookie_header(value: str) -> str:
    return "; ".join(f"{name}=<redacted>" for name, _ in parse_cookie_header(value))


def response_looks_like_login(response: Any) -> bool:
    """Conservative login-page detector shared by authenticated scanners."""
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


def load_runtime_config() -> dict[str, Any]:
    """Load initializer-generated runtime metadata without assuming a target product."""
    path = ROOT_DIR / ".secops_runtime.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def origin_key(url: str) -> str:
    parsed = urlparse(str(url or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default_port
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}:{port}"


def target_runtime_profile(target: str) -> dict[str, Any]:
    """Return optional metadata bound to the exact initialized target URL."""
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


def runtime_container_route(target: str, scanner_container: str = "") -> dict[str, Any]:
    """Resolve an optional Docker-network route for a configured local target."""
    profile = target_runtime_profile(target)
    route = profile.get("container_route", {})
    if not isinstance(route, dict):
        return {}
    allowed = str(route.get("scanner_container") or "")
    if allowed and scanner_container and allowed != scanner_container:
        return {}
    return route


def apply_runtime_target_preparation(target: str, cookies: str) -> dict[str, Any]:
    """Apply initializer-declared, exact-origin preparation requests.

    The orchestrators contain no application-specific actions. A local lab may
    declare safe preparation requests in `.secops_runtime.json`; arbitrary
    targets receive no special requests.
    """
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
            usable = False
            outcomes.append({"method": method, "url": url, "error": f"{type(exc).__name__}: {exc}"})
    return {"performed": bool(outcomes), "configured": True, "usable": usable, "requests": outcomes}


def request_with_retries(
    method: str,
    url: str,
    *,
    attempts: int = 3,
    backoff_seconds: float = 0.65,
    **kwargs: Any,
) -> tuple[requests.Response | None, list[str]]:
    """Issue a bounded HTTP request and distinguish transient transport failure.

    The caller decides whether a missing response is fatal. This helper never
    converts a timeout into an authentication failure.
    """
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


def scanner_session_probe(
    url: str,
    cookies: str,
    method: str = "GET",
    data: str = "",
    timeout: int = 12,
    attempts: int = 3,
) -> dict[str, Any]:
    """Verify authentication without treating service saturation as logout.

    ``authenticated`` is True/False only when the response is conclusive. It is
    None when all attempts failed at the transport layer.
    """
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
def setup_path() -> None:
    """Add the project-managed executable directory to PATH once."""
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    parts = [item for item in os.environ.get("PATH", "").split(os.pathsep) if item]
    if str(LOCAL_BIN) not in parts:
        os.environ["PATH"] = str(LOCAL_BIN) + os.pathsep + os.environ.get("PATH", "")


def find_executable(name: str) -> str | None:
    setup_path()
    return shutil.which(name) or shutil.which(f"{name}.bat") or shutil.which(f"{name}.exe")


def normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("The target must be an absolute HTTP/HTTPS URL.")
    return url.rstrip("/")


def same_origin(left: str, right: str) -> bool:
    a, b = urlparse(left), urlparse(right)
    return (a.scheme.lower(), a.hostname, a.port) == (b.scheme.lower(), b.hostname, b.port)


def absolute_url(base: str, candidate: str) -> str:
    return urlparse(urljoin(base, candidate))._replace(fragment="").geturl()


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


def success(tool: str, target: str = "", output: str = "", **extra: Any) -> dict[str, Any]:
    return make_result(tool, "success", target, output, **extra)


def partial(tool: str, target: str, output: str, **extra: Any) -> dict[str, Any]:
    return make_result(tool, "partial", target, output, **extra)


def skipped(tool: str, target: str, reason: str, **extra: Any) -> dict[str, Any]:
    return make_result(tool, "skipped", target, reason, **extra)


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


def _decode_timeout_output(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def _fatal_startup_error(text: str) -> str:
    lowered = text.lower()
    return next((pattern for pattern in _FATAL_STARTUP_PATTERNS if re.search(pattern, lowered, re.I)), "")


def run_process(
    tool: str,
    command: list[str],
    *,
    target: str,
    timeout: int = 180,
    accepted_codes: Iterable[int] = (0,),
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Run a CLI and return a truthful common result, including partial timeout output."""
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