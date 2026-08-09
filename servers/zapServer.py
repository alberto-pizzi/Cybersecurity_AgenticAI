from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from fastmcp import FastMCP
from zapv2 import ZAPv2

from utils import (
    apply_runtime_target_preparation,
    canonical_cookie_header,
    cookie_names,
    failure,
    parse_cookie_header,
    partial,
    runtime_container_route,
    same_origin,
    success,
    target_runtime_profile,
)

from utils import run_mcp_http

mcp = FastMCP("OWASP ZAP Scanner")

COOKIE_RULE_NAME = "secops-session-cookie-v15"
DESTRUCTIVE_PATH_WORDS = (
    "logout", "log-out", "signout", "sign-out", "logoff", "disconnect",
    "end-session", "destroy-session", "session-destroy",
    "setup", "install", "reinstall", "uninstall", "reset",
    "create_db", "create-database", "drop_db", "drop-database",
    "truncate", "purge", "wipe",
)
STATE_CHANGING_QUERY_KEYS = {
    "create_db", "reset", "action", "delete", "remove", "logout",
    "password_new", "password_conf", "new_password", "confirm_password",
}
HIGH_VALUE_PATH_WORDS = (
    "sqli",
    "xss",
    "exec",
    "command",
    "file",
    "upload",
    "ssrf",
    "xxe",
    "idor",
    "csrf",
    "csp",
)
COOKIE_LINE_RE = re.compile(r"(?im)^Cookie:\s*(.+?)\s*$")
BOUNDED_ACTIVE_SCANNER_IDS = ("40018", "40012", "40014", "6", "90020")
BOUNDED_ACTIVE_SCANNER_NAMES = {
    "40018": "SQL Injection",
    "40012": "Cross Site Scripting (Reflected)",
    "40014": "Cross Site Scripting (Persistent)",
    "6": "Path Traversal",
    "90020": "Remote OS Command Injection",
}
# Deep mode does not merely enable a short hard-coded list.  The ZAP API
# inventory is divided dynamically into ordered batches so that the most
# consequential checks run first, while every installed active rule is still
# attempted when the configured budget permits.
ACTIVE_PRIORITY_KEYWORDS = {
    "critical": (
        "sql injection", "cross site scripting", "xss", "command injection",
        "code injection", "remote code", "path traversal", "file inclusion",
        "template injection", "deserial", "external entity", "xxe", "ssrf",
        "server side request forgery", "server-side request forgery",
    ),
    "high": (
        "csrf", "request forgery", "ldap injection", "xpath injection",
        "nosql", "file upload", "source code", "open redirect", "header injection",
        "http parameter pollution", "authentication", "session", "cookie",
        "format string", "buffer overflow", "server side include", "ssi",
    ),
}


def risk_name(value: Any) -> str:
    return {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
    }.get(str(value), str(value or "info").lower())


def _docker_networks(container: str) -> set[str]:
    if not shutil.which("docker"):
        return set()
    try:
        completed = subprocess.run(
            [
                "docker", "inspect",
                "--format", "{{json .NetworkSettings.Networks}}",
                container,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
        if completed.returncode:
            return set()
        value = json.loads((completed.stdout or "{}").strip() or "{}")
        return set(value) if isinstance(value, dict) else set()
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return set()


def _zap_reachable_target(target_url: str) -> tuple[str, dict[str, Any]]:
    """Translate a host-loopback target for a containerized ZAP daemon.

    An initializer may declare an exact-origin Docker route in runtime metadata.
    Otherwise Docker Desktop's host gateway is used.
    """
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    details: dict[str, Any] = {
        "external_target": target_url, "translated": False, "mode": "unchanged",
    }
    if hostname not in {"127.0.0.1", "localhost", "::1"}:
        details["zap_target"] = target_url
        return target_url, details

    route = runtime_container_route(target_url, "zap_mcp")
    alias = str(route.get("alias") or "").strip()
    target_container = str(route.get("target_container") or "").strip()
    network = str(route.get("network") or "").strip()
    if alias and target_container:
        zap_networks = _docker_networks("zap_mcp")
        target_networks = _docker_networks(target_container)
        shared = sorted(zap_networks & target_networks)
        if not network or network in shared:
            port = int(route.get("internal_port") or (443 if parsed.scheme == "https" else 80))
            netloc = alias if port in {80, 443} else f"{alias}:{port}"
            translated = urlunparse(parsed._replace(netloc=netloc))
            details.update({
                "translated": True, "mode": "configured_docker_route",
                "shared_networks": shared, "zap_target": translated,
                "container_alias": alias,
            })
            return translated, details

    port = parsed.port
    netloc = "host.docker.internal" + (f":{port}" if port else "")
    translated = urlunparse(parsed._replace(netloc=netloc))
    details.update({
        "translated": True, "mode": "docker_desktop_host_gateway",
        "zap_target": translated, "container_alias": "host.docker.internal",
    })
    return translated, details


def _translate_url(
    value: str,
    external_base: str,
    zap_base: str,
) -> str:
    parsed = urlparse(str(value or ""))
    external = urlparse(external_base)
    internal = urlparse(zap_base)
    if (
        parsed.scheme.lower() == external.scheme.lower()
        and parsed.hostname == external.hostname
        and parsed.port == external.port
    ):
        return urlunparse(
            parsed._replace(
                scheme=internal.scheme,
                netloc=internal.netloc,
            )
        )
    return value


def _externalize_url(
    value: str,
    zap_base: str,
    external_base: str,
) -> str:
    parsed = urlparse(str(value or ""))
    internal = urlparse(zap_base)
    external = urlparse(external_base)
    if (
        parsed.scheme.lower() == internal.scheme.lower()
        and parsed.hostname == internal.hostname
        and parsed.port == internal.port
    ):
        return urlunparse(
            parsed._replace(
                scheme=external.scheme,
                netloc=external.netloc,
            )
        )
    return value



def _valid_http_url(value: str) -> bool:
    parsed = urlparse(str(value or ""))
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _runtime_excluded_query_keys(target_url: str) -> set[str]:
    """Return exact-target query fields that must never be crawled or scanned.

    Product-specific state controls are supplied by initializer-generated
    runtime metadata. The ZAP server therefore remains generic for arbitrary
    targets while preserving safe behaviour for configured training labs.
    """
    profile = target_runtime_profile(target_url)
    configured = profile.get("excluded_query_keys", []) if isinstance(profile, dict) else []
    return {
        str(value).strip().lower()
        for value in configured if str(value).strip()
    }


def _safe_path(url: str, target_url: str = "") -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if any(word in path for word in DESTRUCTIVE_PATH_WORDS):
        return False
    blocked = set(STATE_CHANGING_QUERY_KEYS)
    blocked.update(_runtime_excluded_query_keys(target_url or url))
    for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered_name = name.lower()
        if lowered_name in blocked:
            return False
    return True


def _scan_id(value: Any, phase: str) -> str:
    scan_id = str(value or "").strip()
    if not scan_id.isdigit():
        raise RuntimeError(f"ZAP did not return a valid {phase} scan id: {value!r}")
    return scan_id


def _wait_scan(
    status_function: Any,
    scan_id: str,
    deadline: float,
    phase: str,
    interval: float,
) -> tuple[bool, int]:
    last_progress = 0
    while time.monotonic() < deadline:
        raw = status_function(scan_id)
        try:
            progress = int(str(raw))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Invalid ZAP {phase} status for scan {scan_id}: {raw!r}"
            ) from exc
        if progress < 0:
            raise RuntimeError(f"ZAP {phase} returned negative progress: {progress}")
        last_progress = progress
        if progress >= 100:
            return True, progress
        time.sleep(interval)
    return False, last_progress


def _passive_queue(zap: ZAPv2) -> int:
    try:
        return max(0, int(str(zap.pscan.records_to_scan)))
    except (TypeError, ValueError, AttributeError):
        return 0


def _wait_passive(zap: ZAPv2, deadline: float) -> tuple[bool, int]:
    remaining = _passive_queue(zap)
    while remaining > 0 and time.monotonic() < deadline:
        time.sleep(1)
        remaining = _passive_queue(zap)
    return remaining == 0, remaining


def _remove_cookie_rule(zap: ZAPv2) -> None:
    try:
        zap.replacer.remove_rule(COOKIE_RULE_NAME)
    except Exception:
        pass


def _looks_like_login(response: requests.Response) -> bool:
    text = response.text[:100_000].lower()
    path = urlparse(response.url).path.lower()
    return (
        path.endswith("/login")
        or path.endswith("/login.php")
        or ("type=\"password\"" in text and "login" in text)
        or ("type='password'" in text and "login" in text)
    )


def _response_digest(response: requests.Response) -> str:
    return hashlib.sha256(response.content).hexdigest()


def _response_summary(response: requests.Response) -> dict[str, Any]:
    return {
        "status": int(response.status_code),
        "final_url": str(response.url),
        "login_detected": _looks_like_login(response),
        "bytes": len(response.content),
        "sha256": _response_digest(response),
    }


def _request(
    url: str,
    cookie_header: str,
    *,
    zap_url: str = "",
    method: str = "GET",
    data: str = "",
    timeout: tuple[int, int] = (4, 12),
) -> requests.Response:
    headers = {
        "User-Agent": "SecOpsAgent-ZAP-SessionProbe/3.0",
        "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.5",
        "Cache-Control": "no-cache",
    }
    if cookie_header:
        headers["Cookie"] = cookie_header

    proxies = {"http": zap_url, "https": zap_url} if zap_url else None
    return requests.request(
        method=method,
        url=url,
        data=data if method.upper() == "POST" else None,
        headers=headers,
        proxies=proxies,
        verify=False,
        timeout=timeout,
        allow_redirects=True,
    )


def _probe_score(url: str, target_url: str = "") -> int:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if not _safe_path(url, target_url) or path.endswith(("/login.php", "/login")):
        return -1000
    score = 200
    if path in {"", "/"}:
        score += 30
    if any(word in path for word in ("account", "profile", "dashboard", "home", "settings", "admin")):
        score += 100
    if any(word in path for word in HIGH_VALUE_PATH_WORDS):
        score += 25
    if parsed.query:
        score -= 70
    return score


def _select_probe_url(
    target_url: str,
    seed_urls: list[str],
    request_cases: list[dict[str, Any]],
) -> str:
    candidates = [target_url]
    runtime_profile = target_runtime_profile(target_url)
    probe_paths = runtime_profile.get("probe_paths", []) if isinstance(runtime_profile, dict) else []
    for value in probe_paths if isinstance(probe_paths, list) else []:
        try:
            candidates.append(urljoin(target_url.rstrip("/") + "/", str(value).lstrip("/")))
        except Exception:
            continue
    candidates.extend(str(value) for value in seed_urls)
    candidates.extend(
        str(case.get("url") or "")
        for case in request_cases
        if isinstance(case, dict)
    )
    preferred_urls: set[str] = set()
    preferred_paths = runtime_profile.get("preferred_probe_paths", []) if isinstance(runtime_profile, dict) else []
    for value in preferred_paths if isinstance(preferred_paths, list) else []:
        try:
            preferred_urls.add(urljoin(target_url.rstrip("/") + "/", str(value).lstrip("/")))
        except Exception:
            continue

    normalized_candidates: set[str] = set()
    for value in candidates:
        if not _valid_http_url(value) or not same_origin(target_url, value):
            continue
        parsed = urlparse(value)
        blocked = set(STATE_CHANGING_QUERY_KEYS)
        blocked.update(_runtime_excluded_query_keys(target_url))
        safe_query = urlencode([
            (name, item)
            for name, item in parse_qsl(parsed.query, keep_blank_values=True)
            if name.lower() not in blocked
        ])
        value = urlunparse(parsed._replace(query=safe_query, fragment=""))
        if _safe_path(value, target_url):
            normalized_candidates.add(value)
    safe_preferred = normalized_candidates & preferred_urls
    if safe_preferred:
        return max(safe_preferred, key=lambda value: _probe_score(value, target_url))
    return (
        max(normalized_candidates, key=lambda value: _probe_score(value, target_url))
        if normalized_candidates else target_url
    )


def _cookie_values_from_request_header(header: str) -> tuple[dict[str, str], list[str]]:
    combined: dict[str, str] = {}
    duplicate_names: list[str] = []
    for cookie_line in COOKIE_LINE_RE.findall(str(header or "")):
        for part in cookie_line.split(";"):
            if "=" not in part:
                continue
            name, value = part.strip().split("=", 1)
            lowered = name.strip().lower()
            if lowered in combined:
                duplicate_names.append(name.strip())
            combined[lowered] = value.strip()
    return combined, sorted(set(duplicate_names), key=str.lower)


def _history_cookie_diagnostics(
    zap: ZAPv2,
    probe_url: str,
    expected_pairs: list[tuple[str, str]],
) -> dict[str, Any]:
    expected = {name.lower(): value for name, value in expected_pairs}
    for _ in range(6):
        try:
            messages = zap.core.messages(baseurl=probe_url, start=0, count=100)
        except Exception as exc:
            return {
                "supported": False,
                "message_found": False,
                "cookie_header_present": False,
                "exact_values_match": False,
                "duplicate_cookie_names": [],
                "unexpected_cookie_names": [],
                "error": f"{type(exc).__name__}: {exc}",
            }

        if isinstance(messages, list):
            for message in reversed(messages):
                if not isinstance(message, dict):
                    continue
                request_header = str(
                    message.get("requestHeader")
                    or message.get("request_header")
                    or ""
                )
                if not request_header:
                    continue
                values, duplicates = _cookie_values_from_request_header(
                    request_header
                )
                if not values:
                    continue
                exact = all(values.get(name) == value for name, value in expected.items())
                return {
                    "supported": True,
                    "message_found": True,
                    "cookie_header_present": True,
                    "exact_values_match": exact,
                    "expected_cookie_names": sorted(
                        name for name, _ in expected_pairs
                    ),
                    "observed_cookie_names": sorted(values),
                    "duplicate_cookie_names": duplicates,
                    "unexpected_cookie_names": sorted(
                        name for name in values if name not in expected
                    ),
                }
        time.sleep(0.35)

    return {
        "supported": True,
        "message_found": False,
        "cookie_header_present": False,
        "exact_values_match": False,
        "expected_cookie_names": sorted(name for name, _ in expected_pairs),
        "observed_cookie_names": [],
        "duplicate_cookie_names": [],
        "unexpected_cookie_names": [],
    }


def _configure_http_sessions(
    zap: ZAPv2,
    target_url: str,
    cookie_pairs: list[tuple[str, str]],
) -> dict[str, Any]:
    if not cookie_pairs:
        return {
            "supported": True,
            "configured": False,
            "reason": "anonymous profile",
        }

    parsed = urlparse(target_url)
    wanted = {parsed.netloc.lower(), (parsed.hostname or "").lower()}
    try:
        sites = list(zap.httpsessions.sites or [])
        site = next(
            (
                str(value)
                for value in sites
                if str(value).lower() in wanted
                or parsed.netloc.lower() in str(value).lower()
            ),
            parsed.netloc,
        )
        session_name = f"secops-auth-{int(time.time())}"
        for name, _ in cookie_pairs:
            try:
                zap.httpsessions.add_session_token(site, name)
            except Exception:
                # Existing tokens are harmless.
                pass
        zap.httpsessions.create_empty_session(site, session_name)
        for name, value in cookie_pairs:
            zap.httpsessions.set_session_token_value(
                site, session_name, name, value
            )
        zap.httpsessions.set_active_session(site, session_name)
        active = str(zap.httpsessions.active_session(site) or "")
        return {
            "supported": True,
            "configured": active == session_name,
            "site": site,
            "session_name": session_name,
            "active_session": active,
            "token_names": sorted(name for name, _ in cookie_pairs),
        }
    except Exception as exc:
        return {
            "supported": False,
            "configured": False,
            "reason": f"{type(exc).__name__}: {exc}",
            "token_names": sorted(name for name, _ in cookie_pairs),
        }


def _configure_context(
    zap: ZAPv2,
    target_url: str,
    external_target_url: str = "",
) -> dict[str, Any]:
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    context_name = f"secops-scope-{int(time.time())}"
    context_id = ""
    excluded_regex = (
        rf"^{re.escape(origin)}/.*(?:logout|log[_-]?out|sign[_-]?out|logoff|disconnect|"
        rf"end[_-]?session|destroy[_-]?session|setup|re?install|uninstall|reset|"
        rf"create[_-]?db|drop[_-]?db|truncate|purge|wipe)"
        rf"(?:[^A-Za-z0-9].*)?$"
    )
    blocked_query_keys = set(STATE_CHANGING_QUERY_KEYS)
    blocked_query_keys.update(_runtime_excluded_query_keys(external_target_url or target_url))
    blocked_pattern = "|".join(re.escape(value) for value in sorted(blocked_query_keys))
    state_change_regex = (
        rf"^{re.escape(origin)}/.*[?&](?:{blocked_pattern})=.*$"
        if blocked_pattern else rf"a^"
    )
    capabilities: dict[str, Any] = {
        "context_supported": False,
        "spider_logout_avoidance_supported": False,
        "spider_cookie_acceptance_disabled": False,
        "destructive_regex": excluded_regex,
        "state_change_regex": state_change_regex,
    }

    try:
        context_id = str(zap.context.new_context(context_name))
        zap.context.include_in_context(
            context_name,
            rf"^{re.escape(origin)}(?:/.*)?$",
        )
        zap.context.exclude_from_context(context_name, excluded_regex)
        zap.context.exclude_from_context(context_name, state_change_regex)
        zap.context.set_context_in_scope(context_name, True)
        capabilities["context_supported"] = True
    except Exception as exc:
        capabilities["context_error"] = f"{type(exc).__name__}: {exc}"

    try:
        zap.spider.exclude_from_scan(excluded_regex)
        zap.ascan.exclude_from_scan(excluded_regex)
        zap.spider.exclude_from_scan(state_change_regex)
        zap.ascan.exclude_from_scan(state_change_regex)
    except Exception as exc:
        capabilities["scan_exclusion_error"] = f"{type(exc).__name__}: {exc}"

    try:
        zap.spider.set_option_logout_avoidance(True)
        capabilities["spider_logout_avoidance_supported"] = True
    except Exception as exc:
        capabilities["logout_avoidance_error"] = f"{type(exc).__name__}: {exc}"

    try:
        # The exact Cookie header is injected by Replacer/HTTP Sessions.
        # Do not allow spider Set-Cookie responses to rotate the session.
        zap.spider.set_option_accept_cookies(False)
        capabilities["spider_cookie_acceptance_disabled"] = True
    except Exception as exc:
        capabilities["accept_cookies_error"] = f"{type(exc).__name__}: {exc}"

    return {
        "context_name": context_name,
        "context_id": context_id,
        "capabilities": capabilities,
    }


def _validate_session(
    zap: ZAPv2,
    target_url: str,
    zap_target_url: str,
    zap_url: str,
    cookie_header: str,
    cookie_pairs: list[tuple[str, str]],
    probe_url: str,
    attempts: int = 3,
) -> dict[str, Any]:
    """Validate the direct and proxied session without misclassifying timeouts.

    A timeout after an active scan is an inconclusive health check, not proof
    that the authenticated session was invalidated.
    """
    zap_probe_url = _translate_url(probe_url, target_url, zap_target_url)
    request_errors: dict[str, list[str]] = {}

    def probe(label: str, url: str, cookie: str, proxy: str = "") -> requests.Response | None:
        errors: list[str] = []
        for attempt in range(max(1, attempts)):
            try:
                return _request(url, cookie, zap_url=proxy, timeout=(4, 16))
            except (requests.Timeout, requests.ConnectionError) as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
                if attempt + 1 < attempts:
                    time.sleep(0.7 * (attempt + 1))
            except requests.RequestException as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
                break
        request_errors[label] = errors
        return None

    # Check the supplied authenticated cookie first. Anonymous/proxy comparisons
    # are useful diagnostics but cannot turn a direct transport timeout into a
    # conclusive logout result.
    direct = probe("direct", probe_url, cookie_header)
    if direct is None:
        return {
            "effective": None,
            "conclusive": False,
            "transient_error": True,
            "proxy_matches_direct": None,
            "history_cookie_exact": None,
            "probe_url": probe_url,
            "zap_probe_url": zap_probe_url,
            "request_errors": request_errors,
            "root_cause": "session postcheck was inconclusive because the target did not answer after bounded retries",
        }

    direct_summary = _response_summary(direct)
    direct_authenticated = (
        direct.status_code < 400
        and not direct_summary["login_detected"]
        and same_origin(target_url, direct.url)
    )
    if not direct_authenticated:
        return {
            "effective": False,
            "conclusive": True,
            "transient_error": False,
            "proxy_matches_direct": None,
            "history_cookie_exact": None,
            "probe_url": probe_url,
            "zap_probe_url": zap_probe_url,
            "direct": direct_summary,
            "request_errors": request_errors,
            "root_cause": "the supplied cookie is not authenticated when used directly",
        }

    anonymous = probe("anonymous", probe_url, "")
    proxied = probe("proxied", zap_probe_url, cookie_header, zap_url)
    if anonymous is None or proxied is None:
        return {
            "effective": None,
            "conclusive": False,
            "transient_error": True,
            "direct_authenticated": True,
            "proxy_matches_direct": None,
            "history_cookie_exact": None,
            "probe_url": probe_url,
            "zap_probe_url": zap_probe_url,
            "direct": direct_summary,
            "request_errors": request_errors,
            "root_cause": "the direct authenticated session remained valid, but the comparison/proxy probe was temporarily unavailable",
        }

    anonymous_summary = _response_summary(anonymous)
    proxy_summary = _response_summary(proxied)
    similarity = SequenceMatcher(None, direct.text[:100_000], proxied.text[:100_000]).ratio()
    history = _history_cookie_diagnostics(zap, zap_probe_url, cookie_pairs)
    distinguished_from_anonymous = (
        anonymous_summary["login_detected"]
        or anonymous_summary["final_url"] != direct_summary["final_url"]
        or anonymous_summary["sha256"] != direct_summary["sha256"]
    )
    proxy_effective = (
        proxied.status_code < 400
        and not proxy_summary["login_detected"]
        and urlparse(proxied.url).path == urlparse(direct.url).path
    )
    proxy_matches_direct = (
        direct.status_code == proxied.status_code
        and urlparse(direct.url).path == urlparse(proxied.url).path
        and (
            direct_summary["sha256"] == proxy_summary["sha256"]
            or similarity >= 0.80
        )
    )
    history_requirement_met = (
        history.get("exact_values_match") is True
        if history.get("supported")
        else proxy_matches_direct
    )
    effective = (
        direct_authenticated
        and distinguished_from_anonymous
        and proxy_effective
        and proxy_matches_direct
        and history_requirement_met
        and not history.get("duplicate_cookie_names")
    )
    reasons: list[str] = []
    if not distinguished_from_anonymous:
        reasons.append("the selected page does not distinguish authenticated and anonymous responses")
    if not proxy_effective:
        reasons.append("the authenticated request becomes unauthenticated through ZAP")
    if not proxy_matches_direct:
        reasons.append("the proxied response does not match the direct authenticated response")
    if history.get("supported") and not history.get("exact_values_match"):
        reasons.append("ZAP history does not contain the exact supplied cookie values")
    if history.get("duplicate_cookie_names"):
        reasons.append("ZAP emitted duplicate Cookie names")
    return {
        "effective": effective,
        "conclusive": True,
        "transient_error": False,
        "root_cause": "; ".join(reasons),
        "probe_url": probe_url,
        "zap_probe_url": zap_probe_url,
        "cookie_names": sorted(name for name, _ in cookie_pairs),
        "cookie_pair_count": len(cookie_pairs),
        "direct": direct_summary,
        "anonymous": anonymous_summary,
        "proxied": proxy_summary,
        "authenticated_distinguished_from_anonymous": distinguished_from_anonymous,
        "proxy_matches_direct": proxy_matches_direct,
        "direct_proxy_similarity": round(similarity, 4),
        "history": history,
        "history_cookie_exact": history_requirement_met,
        "request_errors": request_errors,
    }

def _seed_zap_history(
    zap_url: str,
    target_url: str,
    zap_target_url: str,
    cookie_header: str,
    seed_urls: list[str],
    request_cases: list[dict[str, Any]],
    deadline: float,
) -> dict[str, Any]:
    unique_urls: list[str] = []
    for value in [target_url, *seed_urls]:
        value = str(value or "")
        if (
            _valid_http_url(value)
            and same_origin(target_url, value)
            and _safe_path(value, target_url)
            and value not in unique_urls
        ):
            unique_urls.append(value)

    seeded_urls = 0
    seeded_cases = 0
    errors: list[dict[str, str]] = []

    for url in unique_urls[:80]:
        if time.monotonic() >= deadline:
            break
        try:
            _request(
                _translate_url(url, target_url, zap_target_url),
                cookie_header,
                zap_url=zap_url,
            )
            seeded_urls += 1
        except requests.RequestException as exc:
            errors.append({
                "url": url,
                "type": type(exc).__name__,
                "message": str(exc),
            })

    for case in request_cases[:50]:
        if time.monotonic() >= deadline:
            break
        if not isinstance(case, dict):
            continue
        url = str(case.get("url") or "")
        if (
            not _valid_http_url(url)
            or not same_origin(target_url, url)
            or not _safe_path(url, target_url)
        ):
            continue
        method = str(case.get("method") or "GET").upper()
        if method not in {"GET", "POST"}:
            continue
        try:
            _request(
                _translate_url(url, target_url, zap_target_url),
                cookie_header,
                zap_url=zap_url,
                method=method,
                data=str(case.get("data") or ""),
            )
            seeded_cases += 1
        except requests.RequestException as exc:
            errors.append({
                "url": url,
                "type": type(exc).__name__,
                "message": str(exc),
            })

    return {
        "seeded_urls": seeded_urls,
        "seeded_request_cases": seeded_cases,
        "seed_errors": errors[:30],
    }


def _targeted_cases(
    target_url: str,
    request_cases: list[dict[str, Any]],
    limit: int = 4,
) -> list[dict[str, Any]]:
    """Select diverse safe GET and POST request contracts for active testing."""
    ranked: list[tuple[int, dict[str, Any]]] = []
    excluded_paths = ("/login", "/logout", "/setup", "/security")
    parameter_hints = {
        "id": 55, "name": 50, "message": 55, "mtxmessage": 60,
        "page": 60, "file": 60, "path": 60, "include": 60,
        "q": 30, "search": 30, "url": 40, "ip": 65, "host": 55,
        "cmd": 70, "command": 70,
    }

    def parameters_for(case: dict[str, Any], parsed: Any) -> set[str]:
        values = {
            str(value).lower()
            for value in case.get("parameters", [])
            if str(value)
        }
        values.update(name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
        if str(case.get("method") or "GET").upper() == "POST":
            values.update(name.lower() for name, _ in parse_qsl(str(case.get("data") or ""), keep_blank_values=True))
        return values - {"submit", "login", "change", "user_token", "csrf", "btnsign"}

    def vulnerability_class(case: dict[str, Any]) -> str:
        path = urlparse(str(case.get("url") or "")).path.lower()
        method = str(case.get("method") or "GET").upper()
        if "sqli_blind" in path:
            return "sqli"
        if "/sqli" in path:
            return "sqli"
        if "xss_s" in path or ("xss" in path and method == "POST"):
            return "xss_stored"
        if "xss_r" in path or "xss" in path:
            return "xss_reflected"
        if "/exec" in path or "command" in path or "cmd" in path:
            return "command"
        if "/fi" in path or "travers" in path or "include" in path:
            return "traversal"
        if "/csrf" in path:
            return "csrf"
        return "other"

    class_scores = {
        "sqli": 390, "xss_reflected": 380,
        "xss_stored": 370, "command": 385, "traversal": 365,
        "csrf": 180, "other": 100,
    }
    for case in request_cases:
        if not isinstance(case, dict):
            continue
        url = str(case.get("url") or "")
        method = str(case.get("method") or "GET").upper()
        if (
            method not in {"GET", "POST"}
            or not _valid_http_url(url)
            or not same_origin(target_url, url)
            or not _safe_path(url, target_url)
        ):
            continue
        parsed = urlparse(url)
        path = parsed.path.lower()
        if any(token in path for token in excluded_paths):
            continue
        parameters = parameters_for(case, parsed)
        if not parameters:
            continue
        class_name = vulnerability_class(case)
        score = class_scores[class_name] + sum(parameter_hints.get(name, 10) for name in parameters)
        if "sqli_blind" in path:
            score -= 15
        if method == "POST":
            score += 20
        ranked.append((score, case))

    ordered = sorted(ranked, key=lambda item: -item[0])
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    selected_classes: set[str] = set()

    def case_key(case: dict[str, Any]) -> tuple[str, str, tuple[str, ...]]:
        parsed = urlparse(str(case.get("url") or ""))
        params = parameters_for(case, parsed)
        return (str(case.get("method") or "GET").upper(), parsed.path.lower(), tuple(sorted(params)))

    for _, case in ordered:
        class_name = vulnerability_class(case)
        key = case_key(case)
        if class_name in selected_classes or key in seen:
            continue
        seen.add(key)
        selected_classes.add(class_name)
        selected.append(case)
        if len(selected) >= max(1, limit):
            return selected

    for _, case in ordered:
        key = case_key(case)
        if key in seen:
            continue
        seen.add(key)
        selected.append(case)
        if len(selected) >= max(1, limit):
            break
    return selected



def _request_case_class(case: dict[str, Any]) -> str:
    """Classify a request contract so critical ZAP rules are not run blindly."""
    url = str(case.get("url") or "")
    parsed = urlparse(url)
    path = parsed.path.lower()
    method = str(case.get("method") or "GET").upper()
    parameters = {
        str(value).lower()
        for value in case.get("parameters", [])
        if str(value)
    }
    parameters.update(name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    if method == "POST":
        parameters.update(
            name.lower()
            for name, _ in parse_qsl(str(case.get("data") or ""), keep_blank_values=True)
        )

    if "sqli" in path or parameters & {"id", "uid", "user_id", "query", "search"}:
        return "sqli"
    if "xss_s" in path or ("xss" in path and method == "POST"):
        return "xss_stored"
    if "xss_r" in path or "xss" in path:
        return "xss_reflected"
    if "/exec" in path or "command" in path or parameters & {"cmd", "command", "exec", "shell", "ip", "host"}:
        return "command"
    if "/fi" in path or "travers" in path or parameters & {"file", "filename", "path", "page", "include", "template"}:
        return "traversal"
    if parameters & {"url", "uri", "callback", "webhook", "redirect", "host", "domain"}:
        return "ssrf"
    if parameters & {"xml", "doctype", "entity"}:
        return "xxe"
    return "other"


def _scanner_rule_tags(scanner_id: str, scanner_name: str) -> set[str]:
    """Map an installed ZAP active rule to the request classes it can test."""
    lowered = scanner_name.lower()
    tags: set[str] = set()
    if "sql injection" in lowered or scanner_id in {"40018", "40019", "40020", "40021", "40022", "40027"}:
        tags.add("sqli")
    if "cross site scripting" in lowered or "cross-site scripting" in lowered or "xss" in lowered or scanner_id in {"40012", "40014"}:
        tags.update({"xss_reflected", "xss_stored"})
    if any(value in lowered for value in ("command injection", "remote os command", "code injection", "shell injection")) or scanner_id == "90020":
        tags.add("command")
    if any(value in lowered for value in ("path traversal", "file inclusion", "local file inclusion", "remote file inclusion")) or scanner_id in {"6", "7"}:
        tags.add("traversal")
    if "server side request forgery" in lowered or "server-side request forgery" in lowered or "ssrf" in lowered:
        tags.add("ssrf")
    if "external entity" in lowered or "xxe" in lowered or "xml injection" in lowered:
        tags.add("xxe")
    if "template injection" in lowered or "ssti" in lowered:
        tags.add("ssti")
    if "deserial" in lowered:
        tags.add("deserialization")
    return tags


def _critical_scanners_for_case(
    case: dict[str, Any],
    scanner_ids: list[str],
    scanner_names: list[str],
) -> list[str]:
    case_class = _request_case_class(case)
    names = {
        scanner_id: scanner_names[index] if index < len(scanner_names) else scanner_id
        for index, scanner_id in enumerate(scanner_ids)
    }
    matched = [
        scanner_id
        for scanner_id in scanner_ids
        if case_class in _scanner_rule_tags(scanner_id, names.get(scanner_id, scanner_id))
    ]
    if matched:
        return matched
    # Compatibility floor for older ZAP builds whose inventory omits names.
    fallback = {
        "sqli": {"40018", "40019", "40020", "40021", "40022", "40027"},
        "xss_reflected": {"40012"},
        "xss_stored": {"40014", "40012"},
        "command": {"90020"},
        "traversal": {"6", "7"},
    }.get(case_class, set())
    return [value for value in scanner_ids if value in fallback]

def _stop_active_scans(zap: ZAPv2, scan_ids: list[str]) -> dict[str, Any]:
    stopped: list[str] = []
    errors: list[str] = []
    for scan_id in dict.fromkeys(value for value in scan_ids if value):
        try:
            zap.ascan.stop(scan_id)
            stopped.append(scan_id)
        except Exception as exc:
            errors.append(f"{scan_id}: {type(exc).__name__}: {exc}")
    try:
        zap.ascan.stop_all_scans()
    except Exception:
        pass
    return {"stopped_scan_ids": stopped, "errors": errors}


def _wait_target_recovery(url: str, cookies: str, seconds: int = 18) -> dict[str, Any]:
    deadline = time.monotonic() + max(3, seconds)
    errors: list[str] = []
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            response = _request(url, cookies, timeout=(3, 7))
            if response.status_code < 500:
                return {
                    "recovered": True,
                    "attempts": attempts,
                    "status": response.status_code,
                    "final_url": str(response.url),
                    "login_detected": _looks_like_login(response),
                    "errors": errors,
                }
        except requests.RequestException as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        time.sleep(1.0)
    return {"recovered": False, "attempts": attempts, "errors": errors[-5:]}


def _active_scanner_inventory(zap: ZAPv2) -> list[dict[str, Any]]:
    try:
        value = zap.ascan.scanners()
    except TypeError:
        try:
            value = zap.ascan.scanners
        except Exception:
            value = []
    except Exception:
        value = []
    return [item for item in (value or []) if isinstance(item, dict)]


def _scanner_inventory_id(item: dict[str, Any]) -> str:
    return str(item.get("id") or item.get("pluginId") or item.get("pluginid") or "").strip()


def _scanner_inventory_name(item: dict[str, Any]) -> str:
    return str(item.get("name") or item.get("pluginName") or item.get("description") or "").strip()


def _prioritized_active_batches(inventory: list[dict[str, Any]], scan_mode: str) -> list[dict[str, Any]]:
    """Return ordered rule batches; prioritized covers critical/high, full covers all."""
    records: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in inventory:
        scanner_id = _scanner_inventory_id(item)
        if not scanner_id or scanner_id in seen:
            continue
        seen.add(scanner_id)
        records.append((scanner_id, _scanner_inventory_name(item)))

    # Some ZAP builds expose an empty inventory until an active scanner API is
    # touched. Keep the known critical rules as a safe compatibility floor.
    if not records:
        records = [(value, BOUNDED_ACTIVE_SCANNER_NAMES.get(value, value)) for value in BOUNDED_ACTIVE_SCANNER_IDS]

    critical: list[str] = []
    high: list[str] = []
    remaining: list[str] = []
    names = {scanner_id: name for scanner_id, name in records}
    for scanner_id, name in records:
        lowered = name.lower()
        if scanner_id in BOUNDED_ACTIVE_SCANNER_IDS or any(word in lowered for word in ACTIVE_PRIORITY_KEYWORDS["critical"]):
            critical.append(scanner_id)
        elif any(word in lowered for word in ACTIVE_PRIORITY_KEYWORDS["high"]):
            high.append(scanner_id)
        else:
            remaining.append(scanner_id)

    def unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    critical = unique(critical)
    high = [value for value in unique(high) if value not in critical]
    remaining = [value for value in unique(remaining) if value not in critical and value not in high]

    batches = [{
        "tier": "critical",
        "scanner_ids": critical,
        "scanner_names": [names.get(value, BOUNDED_ACTIVE_SCANNER_NAMES.get(value, value)) for value in critical],
        "strength": "HIGH" if scan_mode in {"prioritized", "full"} else "MEDIUM",
        "recursive": False,
    }]
    if scan_mode in {"prioritized", "full"}:
        batches.append({
            "tier": "high",
            "scanner_ids": high,
            "scanner_names": [names.get(value, value) for value in high],
            "strength": "MEDIUM",
            "recursive": True,
        })
    if scan_mode == "full":
        batches.extend([
            {
                "tier": "remaining",
                "scanner_ids": remaining,
                "scanner_names": [names.get(value, value) for value in remaining],
                "strength": "LOW",
                "recursive": True,
            },
        ])
    return [batch for batch in batches if batch["scanner_ids"]]


def _apply_active_scanner_batch(
    zap: ZAPv2,
    scanner_ids: list[str],
    *,
    strength: str,
) -> list[str]:
    errors: list[str] = []
    try:
        zap.ascan.disable_all_scanners()
    except Exception as exc:
        errors.append(f"disable_all_scanners: {type(exc).__name__}: {exc}")
    if scanner_ids:
        try:
            zap.ascan.enable_scanners(",".join(scanner_ids))
        except Exception as exc:
            errors.append(f"enable_scanners: {type(exc).__name__}: {exc}")
    for scanner_id in scanner_ids:
        try:
            zap.ascan.set_scanner_alert_threshold(scanner_id, "LOW")
        except Exception as exc:
            errors.append(f"threshold {scanner_id}: {type(exc).__name__}: {exc}")
        try:
            zap.ascan.set_scanner_attack_strength(scanner_id, strength)
        except Exception as exc:
            errors.append(f"strength {scanner_id}: {type(exc).__name__}: {exc}")
    return errors


def _configure_bounded_active_policy(zap: ZAPv2, scan_mode: str = "targeted") -> dict[str, Any]:
    """Build a priority plan and enable its first, highest-value batch."""
    inventory = _active_scanner_inventory(zap)
    batches = _prioritized_active_batches(inventory, scan_mode)
    errors: list[str] = []
    if batches:
        errors.extend(_apply_active_scanner_batch(
            zap,
            list(batches[0]["scanner_ids"]),
            strength=str(batches[0]["strength"]),
        ))
    planned = [scanner_id for batch in batches for scanner_id in batch["scanner_ids"]]
    return {
        "inventory_count": len(inventory),
        "available_ids": sorted({_scanner_inventory_id(item) for item in inventory if _scanner_inventory_id(item)}),
        "enabled_ids": list(batches[0]["scanner_ids"]) if batches else [],
        "enabled_names": list(batches[0]["scanner_names"]) if batches else [],
        "batches": batches,
        "planned_rule_ids": planned,
        "planned_rule_count": len(planned),
        "coverage_goal": (
            "all installed active rules" if scan_mode == "full"
            else "critical and high-priority active rules" if scan_mode == "prioritized"
            else "highest-value active rules"
        ),
        "errors": errors,
    }

def _restore_active_policy(zap: ZAPv2) -> None:
    try:
        zap.ascan.enable_all_scanners()
    except Exception:
        pass


def _mutate_get_parameter(url: str, parameter: str, replacement: str) -> str:
    parsed = urlparse(url)
    changed: list[tuple[str, str]] = []
    replaced = False
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if not replaced and name.lower() == parameter.lower():
            changed.append((name, replacement))
            replaced = True
        else:
            changed.append((name, value))
    if not replaced:
        changed.append((parameter, replacement))
    return urlunparse(parsed._replace(query=urlencode(changed)))


def _proxy_verification_finding(
    *,
    alert: str,
    risk: str,
    url: str,
    scanner_url: str,
    method: str,
    parameter: str,
    verification_status: str,
    description: str,
    evidence: str,
    payloads: list[str],
    cwe_id: str,
    owasp_category: str,
    solution: str,
    impact: str,
) -> dict[str, Any]:
    return {
        "alert": alert,
        "risk": risk,
        "category": "vulnerability",
        "verification_status": verification_status,
        "confidence": "high",
        "description": description,
        "impact": impact,
        "solution": solution,
        "url": url,
        "scanner_url": scanner_url,
        "method": method,
        "parameter": parameter,
        "payloads": payloads,
        "evidence": evidence,
        "cwe_id": cwe_id,
        "owasp_category": owasp_category,
        "plugin_id": "secops-zap-proxy-verifier",
        "detection_method": "bounded requests routed through the ZAP proxy",
        "technical_details": (
            "The native ZAP active-rule queue was supplemented by bounded "
            "response verification. Every confirming request traversed the ZAP "
            "proxy and was retained in its history. This is reported separately "
            "from a native ZAP active-rule alert."
        ),
    }


def _mutate_form_parameter(data: str, parameter: str, replacement: str) -> str:
    pairs = list(parse_qsl(str(data or ""), keep_blank_values=True))
    changed: list[tuple[str, str]] = []
    replaced = False
    for name, value in pairs:
        if not replaced and name.lower() == parameter.lower():
            changed.append((name, replacement))
            replaced = True
        else:
            changed.append((name, value))
    if not replaced:
        changed.append((parameter, replacement))
    return urlencode(changed)


def _proxy_verification_priority(case: dict[str, Any]) -> tuple[int, int, str]:
    """Run fast, deterministic response differentials before slower POST cases."""
    url = str(case.get("url") or "")
    method = str(case.get("method") or "GET").upper()
    path = urlparse(url).path.lower()
    if method == "GET" and "/sqli" in path and "sqli_blind" not in path:
        return (0, 0, url)
    if method == "GET" and "xss_r" in path:
        return (1, 0, url)
    if method == "GET" and "/fi" in path:
        return (2, 0, url)
    if method == "GET" and "sqli_blind" in path:
        return (3, 0, url)
    if method == "POST" and ("/exec" in path or "command" in path):
        return (4, 1, url)
    if method == "POST" and "xss_s" in path:
        return (5, 1, url)
    return (9, 1 if method == "POST" else 0, url)


def _run_proxy_assisted_verification(
    cases: list[dict[str, Any]],
    target_url: str,
    zap_target_url: str,
    zap_url: str,
    cookies: str,
    deadline: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Confirm high-value GET and POST behaviours through the ZAP proxy."""
    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    ordered_cases = sorted(
        [case for case in cases if isinstance(case, dict)],
        key=_proxy_verification_priority,
    )
    for case in ordered_cases:
        remaining_global = deadline - time.monotonic()
        if remaining_global < 6:
            diagnostics.append({
                "url": str(case.get("url") or ""),
                "method": str(case.get("method") or "GET").upper(),
                "tests": [],
                "skipped": "proxy verification budget exhausted before this case",
            })
            continue
        external_url = str(case.get("url") or "")
        scanner_url = _translate_url(external_url, target_url, zap_target_url)
        method = str(case.get("method") or "GET").upper()
        base_data = str(case.get("data") or "")
        parsed = urlparse(external_url)
        path = parsed.path.lower()
        query_pairs = list(parse_qsl(parsed.query, keep_blank_values=True))
        data_pairs = list(parse_qsl(base_data, keep_blank_values=True))
        parameters = [str(value) for value in case.get("parameters", []) if str(value)]
        if not parameters:
            parameters = [name for name, _ in (data_pairs if method == "POST" else query_pairs)]
        record: dict[str, Any] = {"url": external_url, "method": method, "tests": []}

        case_deadline = min(
            deadline,
            time.monotonic() + (28 if method == "POST" else 22),
        )

        def send(url: str = external_url, *, request_method: str = method, data: str = base_data) -> requests.Response:
            last: requests.RequestException | None = None
            for attempt in range(2):
                remaining = case_deadline - time.monotonic()
                if remaining < 2:
                    break
                read_timeout = max(2, min(10, int(remaining) - 1))
                try:
                    response = _request(
                        _translate_url(url, target_url, zap_target_url),
                        cookies,
                        zap_url=zap_url,
                        method=request_method,
                        data=data,
                        timeout=(3, read_timeout),
                    )
                    record.setdefault("requests", []).append({
                        "method": request_method,
                        "url": url,
                        "status": response.status_code,
                        "bytes": len(response.content),
                    })
                    return response
                except (requests.Timeout, requests.ConnectionError) as exc:
                    last = exc
                    record.setdefault("request_errors", []).append(
                        f"attempt {attempt + 1}: {type(exc).__name__}: {exc}"
                    )
                    if attempt == 0 and case_deadline - time.monotonic() >= 3:
                        time.sleep(0.25)
            if last is None:
                last = requests.Timeout("per-case ZAP proxy verification budget exhausted")
            raise last

        def original_value(parameter: str, default: str = "1") -> str:
            source = data_pairs if method == "POST" else query_pairs
            for name, value in source:
                if name.lower() == parameter.lower():
                    return value or default
            return default

        def mutated_request(parameter: str, replacement: str) -> tuple[str, str]:
            if method == "POST":
                return external_url, _mutate_form_parameter(base_data, parameter, replacement)
            return _mutate_get_parameter(external_url, parameter, replacement), base_data

        try:
            if "sqli" in path and any(value.lower() == "id" for value in parameters):
                parameter = next(value for value in parameters if value.lower() == "id")
                original = original_value(parameter)
                true_payload = f"{original}' OR '1'='1' #"
                false_payload = f"{original}' AND '1'='2' #"
                quote_payload = f"{original}'"
                baseline = send()
                true_url, true_data = mutated_request(parameter, true_payload)
                false_url, false_data = mutated_request(parameter, false_payload)
                quote_url, quote_data = mutated_request(parameter, quote_payload)
                true_response = send(true_url, data=true_data)
                false_response = send(false_url, data=false_data)
                quote_response = send(quote_url, data=quote_data)
                low_base, low_true, low_false, low_quote = (
                    baseline.text.lower(), true_response.text.lower(),
                    false_response.text.lower(), quote_response.text.lower(),
                )
                count = lambda value: value.count("first name:") + value.count("surname:")
                normal = count(low_true) > count(low_false) and count(low_true) >= max(2, count(low_base) + 1)
                blind = (
                    "user id exists in the database" in low_true
                    and "user id is missing from the database" in low_false
                )
                error = "sql syntax" in low_quote and "sql syntax" not in low_base
                confirmed = normal or blind or (error and abs(len(true_response.content) - len(false_response.content)) > 40)
                record["tests"].append({"type": "sqli", "confirmed": confirmed})
                if confirmed:
                    findings.append(_proxy_verification_finding(
                        alert=f"SQL injection in parameter '{parameter}'",
                        risk="high", url=external_url, scanner_url=scanner_url,
                        method=method, parameter=parameter,
                        verification_status="zap-proxy-boolean-differential-confirmed",
                        description="Boolean true and false SQL payloads produced a repeatable response differential while routed through ZAP.",
                        evidence=(
                            f"Baseline bytes={len(baseline.content)}; true bytes={len(true_response.content)}; "
                            f"false bytes={len(false_response.content)}; normal_markers={normal}; "
                            f"blind_markers={blind}; quote_error={error}."
                        ),
                        payloads=[true_payload, false_payload, quote_payload],
                        cwe_id="89", owasp_category="A03:2021 Injection",
                        solution="Use parameterized database queries, strict input typing and a least-privileged database account.",
                        impact="An attacker may alter database queries and access or modify data available to the application account.",
                    ))

            if method == "GET" and "xss_r" in path and parameters:
                candidates = [value for value in parameters if value.lower() in {"name", "q", "search", "query"}]
                if candidates:
                    parameter = candidates[0]
                    payload = '<svg id="SECOPS_ZAP_XSS_26" onload="void(0)"></svg>'
                    response = send(_mutate_get_parameter(external_url, parameter, payload))
                    content_type = response.headers.get("Content-Type", "").lower()
                    confirmed = payload in response.text and "html" in content_type
                    record["tests"].append({"type": "xss_reflected", "confirmed": confirmed})
                    if confirmed:
                        findings.append(_proxy_verification_finding(
                            alert=f"Reflected cross-site scripting in parameter '{parameter}'",
                            risk="high", url=external_url, scanner_url=scanner_url,
                            method="GET", parameter=parameter,
                            verification_status="zap-proxy-unescaped-html-confirmed",
                            description="An executable SVG event-handler payload was returned unescaped in an HTML response routed through ZAP.",
                            evidence=f"HTTP {response.status_code}; exact payload returned=True; response bytes={len(response.content)}.",
                            payloads=[payload], cwe_id="79", owasp_category="A03:2021 Injection",
                            solution="Apply context-aware output encoding and use safe DOM APIs; add Content Security Policy as defence in depth.",
                            impact="Attacker-controlled JavaScript can execute in the application origin in a victim browser.",
                        ))

            if method == "POST" and "xss_s" in path and parameters:
                candidates = [value for value in parameters if value.lower() in {"mtxmessage", "message", "comment", "content"}]
                if candidates:
                    parameter = candidates[0]
                    # Keep the payload below common guestbook/message length
                    # limits. The previous long unique-ID payload was truncated
                    # by DVWA and therefore could never be confirmed exactly.
                    payload = '<svg id=sx onload=void(0)></svg>'
                    baseline = send(external_url, request_method="GET", data="")
                    probe_data = _mutate_form_parameter(base_data, parameter, payload)
                    post_response = send(data=probe_data)
                    verify_response = send(external_url, request_method="GET", data="")
                    content_type = verify_response.headers.get("Content-Type", "").lower()
                    confirmed = (
                        payload not in baseline.text
                        and "html" in content_type
                        and (payload in post_response.text or payload in verify_response.text)
                    )
                    record["tests"].append({
                        "type": "xss_stored", "confirmed": confirmed,
                        "payload_length": len(payload),
                    })
                    if confirmed:
                        findings.append(_proxy_verification_finding(
                            alert=f"Stored cross-site scripting in parameter '{parameter}'",
                            risk="high", url=external_url, scanner_url=scanner_url,
                            method="POST", parameter=parameter,
                            verification_status="zap-proxy-stored-persistence-confirmed",
                            description="A compact SVG event-handler payload submitted through a POST form persisted and was returned unescaped through ZAP.",
                            evidence=(
                                f"POST HTTP {post_response.status_code}; follow-up HTTP {verify_response.status_code}; "
                                f"payload length={len(payload)}; payload absent from baseline=True; persisted unescaped=True."
                            ),
                            payloads=[payload], cwe_id="79", owasp_category="A03:2021 Injection",
                            solution="Encode stored data at every HTML sink, validate input and deploy a restrictive Content Security Policy.",
                            impact="Stored attacker-controlled JavaScript can execute for every user who views the affected page.",
                        ))

            if method == "POST" and ("/exec" in path or "command" in path) and parameters:
                candidates = [value for value in parameters if value.lower() in {"ip", "host", "cmd", "command", "exec", "shell"}]
                if candidates:
                    parameter = candidates[0]
                    marker = "S3C0PSZAP"
                    original = original_value(parameter, "127.0.0.1")
                    baseline = send()
                    payloads = [
                        f"{original};echo {marker}",
                        f"{original}&&echo {marker}",
                        f"{original} & echo {marker}",
                    ]
                    response = baseline
                    confirmed_payload = ""
                    for payload in payloads:
                        probe_data = _mutate_form_parameter(base_data, parameter, payload)
                        response = send(data=probe_data)
                        if marker in response.text and marker not in baseline.text:
                            confirmed_payload = payload
                            break
                    confirmed = bool(confirmed_payload)
                    record["tests"].append({
                        "type": "command_injection", "confirmed": confirmed,
                        "payloads_attempted": len(payloads if not confirmed else payloads[:payloads.index(confirmed_payload) + 1]),
                    })
                    if confirmed:
                        findings.append(_proxy_verification_finding(
                            alert=f"OS command injection in parameter '{parameter}'",
                            risk="critical", url=external_url, scanner_url=scanner_url,
                            method="POST", parameter=parameter,
                            verification_status="zap-proxy-unique-command-marker-confirmed",
                            description="A bounded benign echo command appended to the selected POST parameter produced a unique server-side response marker through ZAP.",
                            evidence=f"HTTP {response.status_code}; unique marker={marker}; marker absent from baseline=True.",
                            payloads=[confirmed_payload], cwe_id="78", owasp_category="A03:2021 Injection",
                            solution="Avoid shell construction, use safe process APIs with fixed arguments, validate input and run with least privilege.",
                            impact="An attacker may execute operating-system commands with the web-server process privileges.",
                        ))

            if method == "GET" and "/fi" in path and parameters:
                candidates = [value for value in parameters if value.lower() in {"page", "file", "path", "include", "template"}]
                if candidates:
                    parameter = candidates[0]
                    payload = "../../../../../../etc/passwd"
                    baseline = send()
                    response = send(_mutate_get_parameter(external_url, parameter, payload))
                    marker = "root:x:0:0:" in response.text and "root:x:0:0:" not in baseline.text
                    record["tests"].append({"type": "traversal", "confirmed": marker})
                    if marker:
                        findings.append(_proxy_verification_finding(
                            alert=f"Local file inclusion/path traversal in parameter '{parameter}'",
                            risk="high", url=external_url, scanner_url=scanner_url,
                            method="GET", parameter=parameter,
                            verification_status="zap-proxy-local-file-marker-confirmed",
                            description="A traversal payload returned a Linux /etc/passwd marker absent from the baseline response.",
                            evidence=f"HTTP {response.status_code}; /etc/passwd marker returned=True; response bytes={len(response.content)}.",
                            payloads=[payload], cwe_id="22", owasp_category="A01:2021 Broken Access Control",
                            solution="Map user choices to server-side identifiers and enforce that canonical paths remain inside an allow-listed directory.",
                            impact="An attacker may read local files accessible to the web-server account.",
                        ))
        except requests.RequestException as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
        diagnostics.append(record)
    return findings, diagnostics

def _run_targeted_active_scans(
    zap: ZAPv2,
    cases: list[dict[str, Any]],
    target_url: str,
    zap_target_url: str,
    context_id: str,
    deadline: float,
    *,
    tier: str = "critical",
    scanner_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    total = len(cases)
    for index, case in enumerate(cases):
        remaining = deadline - time.monotonic()
        cases_left = max(1, total - index)
        if remaining < 20:
            break
        # Divide the actual remaining budget among the remaining cases. The old
        # fixed 18-second window did not allow several active rules to complete.
        case_budget = max(35.0, min(120.0, remaining / cases_left))
        url = str(case.get("url") or "")
        scan_url = _translate_url(url, target_url, zap_target_url)
        method = str(case.get("method") or "GET").upper()
        data = str(case.get("data") or "")
        try:
            try:
                raw_scan_id = zap.ascan.scan(
                    url=scan_url,
                    recurse=False,
                    inscopeonly=False,
                    method=method,
                    postdata=data if method == "POST" else None,
                )
            except TypeError:
                raw_scan_id = zap.ascan.scan(
                    url=scan_url,
                    recurse=False,
                    method=method,
                    postdata=data if method == "POST" else None,
                )
            scan_id = _scan_id(raw_scan_id, f"targeted active scan {method} {url}")
            completed, progress = _wait_scan(
                zap.ascan.status,
                scan_id,
                min(deadline, time.monotonic() + case_budget),
                f"targeted active scan {method} {url}",
                2.0,
            )
            if not completed:
                try:
                    zap.ascan.stop(scan_id)
                except Exception:
                    pass
            results.append({
                "url": url,
                "scan_url": scan_url,
                "method": method,
                "scan_id": scan_id,
                "completed": completed,
                "progress": progress,
                "budget_seconds": round(case_budget, 2),
                "parameters": list(case.get("parameters", [])),
                "priority_tier": tier,
                "scanner_ids": list(scanner_ids or []),
            })
        except Exception as exc:
            results.append({
                "url": url,
                "scan_url": scan_url,
                "method": method,
                "completed": False,
                "progress": 0,
                "budget_seconds": round(case_budget, 2),
                "error": f"{type(exc).__name__}: {exc}",
                "priority_tier": tier,
                "scanner_ids": list(scanner_ids or []),
            })
    return results



def _run_recursive_active_scan(
    zap: ZAPv2,
    zap_target_url: str,
    context_id: str,
    deadline: float,
    *,
    tier: str,
    scanner_ids: list[str],
) -> dict[str, Any]:
    if deadline - time.monotonic() < 18:
        return {
            "tier": tier, "started": False, "completed": False, "progress": 0,
            "scanner_ids": list(scanner_ids), "reason": "insufficient_remaining_budget",
        }
    try:
        try:
            raw_scan_id = zap.ascan.scan(
                url=zap_target_url,
                recurse=True,
                inscopeonly=True,
                contextid=context_id or None,
            )
        except TypeError:
            raw_scan_id = zap.ascan.scan(url=zap_target_url, recurse=True, inscopeonly=True)
        scan_id = _scan_id(raw_scan_id, f"{tier} recursive active scan")
        completed, progress = _wait_scan(
            zap.ascan.status,
            scan_id,
            deadline,
            f"{tier} recursive active scan",
            2.0,
        )
        if not completed:
            try:
                zap.ascan.stop(scan_id)
            except Exception:
                pass
        return {
            "tier": tier, "started": True, "scan_id": scan_id,
            "completed": completed, "progress": progress,
            "scanner_ids": list(scanner_ids),
        }
    except Exception as exc:
        return {
            "tier": tier, "started": False, "completed": False, "progress": 0,
            "scanner_ids": list(scanner_ids),
            "error": f"{type(exc).__name__}: {exc}",
        }



def _critical_case_subset(
    cases: list[dict[str, Any]],
    scan_mode: str,
) -> list[dict[str, Any]]:
    """Keep diverse critical coverage without spending the whole budget on duplicates."""
    per_class_limit = 2 if scan_mode == "full" else 1
    grouped: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        class_name = _request_case_class(case)
        if class_name == "other":
            continue
        grouped.setdefault(class_name, []).append(case)
    selected: list[dict[str, Any]] = []
    preferred_order = (
        "sqli", "command", "xss_reflected", "xss_stored",
        "traversal", "ssrf", "xxe", "ssti", "deserialization",
    )
    for class_name in preferred_order:
        selected.extend(grouped.get(class_name, [])[:per_class_limit])
    for class_name, values in grouped.items():
        if class_name in preferred_order:
            continue
        selected.extend(values[:per_class_limit])
    return selected[:12 if scan_mode == "full" else 8]


def _run_prioritized_native_plan(
    zap: ZAPv2,
    cases: list[dict[str, Any]],
    target_url: str,
    zap_target_url: str,
    context_id: str,
    deadline: float,
    scan_mode: str,
    active_policy: dict[str, Any],
) -> dict[str, Any]:
    """Run relevant critical rules first, then broader installed-rule tiers.

    The previous implementation enabled every critical rule for every request.
    In the observed deep run, all seven critical request scans stopped at 39-56%
    while less important tiers completed. Critical rules are now matched to the
    request class (SQLi, XSS, command injection, traversal, SSRF/XXE), preserving
    budget for the checks that can actually apply to that endpoint.
    """
    batches = [item for item in active_policy.get("batches", []) if isinstance(item, dict)]
    targeted_results: list[dict[str, Any]] = []
    recursive_results: list[dict[str, Any]] = []
    phase_results: list[dict[str, Any]] = []
    attempted_ids: set[str] = set()
    all_planned = {
        str(value)
        for batch in batches
        for value in batch.get("scanner_ids", [])
        if str(value)
    }
    # Deep mode should favor vulnerability-confirming rules. High/remaining
    # inventories still run, but only after the critical request contracts.
    weights = {"critical": 0.75, "high": 0.17, "remaining": 0.08}

    for index, batch in enumerate(batches):
        if deadline - time.monotonic() < 20:
            break
        tier = str(batch.get("tier") or f"tier-{index + 1}")
        scanner_ids = [str(value) for value in batch.get("scanner_ids", []) if str(value)]
        scanner_names = [str(value) for value in batch.get("scanner_names", [])]
        if not scanner_ids:
            continue
        remaining_batches = batches[index:]
        denominator = sum(weights.get(str(item.get("tier")), 0.10) for item in remaining_batches) or 1.0
        available = max(0.0, deadline - time.monotonic())
        tier_budget = max(28.0, available * weights.get(tier, 0.10) / denominator)
        tier_deadline = min(deadline, time.monotonic() + tier_budget)
        configure_errors: list[str] = []
        tier_targeted: list[dict[str, Any]] = []
        recursive: dict[str, Any] | None = None

        if tier == "critical":
            selected_cases = _critical_case_subset(cases, scan_mode)
            matched_ids: set[str] = set()
            for case_index, case in enumerate(selected_cases):
                remaining = tier_deadline - time.monotonic()
                cases_left = max(1, len(selected_cases) - case_index)
                if remaining < 22:
                    break
                relevant_ids = _critical_scanners_for_case(case, scanner_ids, scanner_names)
                if not relevant_ids:
                    continue
                matched_ids.update(relevant_ids)
                configure_errors.extend(
                    _apply_active_scanner_batch(
                        zap,
                        relevant_ids,
                        strength=str(batch.get("strength") or "HIGH"),
                    )
                )
                attempted_ids.update(relevant_ids)
                # One endpoint receives only its relevant scanner family, so a
                # 30-70 second window can complete where 22 mixed rules could not.
                case_budget = max(45.0, min(120.0, remaining / cases_left))
                tier_targeted.extend(
                    _run_targeted_active_scans(
                        zap,
                        [case],
                        target_url,
                        zap_target_url,
                        context_id,
                        min(tier_deadline, time.monotonic() + case_budget),
                        tier=tier,
                        scanner_ids=relevant_ids,
                    )
                )

            # Rules that could not be classified from the installed inventory
            # are still attempted once on the highest-value request when budget
            # remains, rather than being silently counted as covered.
            unmatched = [value for value in scanner_ids if value not in matched_ids]
            if unmatched and selected_cases and tier_deadline - time.monotonic() >= 24:
                configure_errors.extend(
                    _apply_active_scanner_batch(
                        zap,
                        unmatched,
                        strength=str(batch.get("strength") or "HIGH"),
                    )
                )
                attempted_ids.update(unmatched)
                tier_targeted.extend(
                    _run_targeted_active_scans(
                        zap,
                        [selected_cases[0]],
                        target_url,
                        zap_target_url,
                        context_id,
                        min(tier_deadline, time.monotonic() + 50.0),
                        tier="critical-generic",
                        scanner_ids=unmatched,
                    )
                )
        else:
            selected_cases = (
                cases[: min(4, len(cases))]
                if tier == "high"
                else cases[: min(2, len(cases))]
            )
            configure_errors.extend(
                _apply_active_scanner_batch(
                    zap,
                    scanner_ids,
                    strength=str(batch.get("strength") or "MEDIUM"),
                )
            )
            attempted_ids.update(scanner_ids)
            targeted_deadline = tier_deadline
            if batch.get("recursive") and tier_deadline - time.monotonic() > 35:
                targeted_deadline = time.monotonic() + max(
                    20.0, (tier_deadline - time.monotonic()) * 0.40
                )
            tier_targeted = _run_targeted_active_scans(
                zap,
                selected_cases,
                target_url,
                zap_target_url,
                context_id,
                min(tier_deadline, targeted_deadline),
                tier=tier,
                scanner_ids=scanner_ids,
            ) if selected_cases else []

            if batch.get("recursive") and tier_deadline - time.monotonic() >= 18:
                recursive = _run_recursive_active_scan(
                    zap,
                    zap_target_url,
                    context_id,
                    tier_deadline,
                    tier=tier,
                    scanner_ids=scanner_ids,
                )
                recursive_results.append(recursive)

        targeted_results.extend(tier_targeted)
        phase_results.append({
            "tier": tier,
            "scanner_count": len(scanner_ids),
            "scanner_ids": scanner_ids,
            "scanner_names": scanner_names,
            "strength": batch.get("strength"),
            "configure_errors": configure_errors,
            "targeted_started": len(tier_targeted),
            "targeted_completed": sum(bool(item.get("completed")) for item in tier_targeted),
            "recursive": recursive,
            "budget_seconds": round(tier_budget, 2),
        })

    completed_ids: set[str] = set()
    for item in targeted_results:
        if isinstance(item, dict) and item.get("completed"):
            completed_ids.update(str(value) for value in item.get("scanner_ids", []) if str(value))
    for item in recursive_results:
        if isinstance(item, dict) and item.get("completed"):
            completed_ids.update(str(value) for value in item.get("scanner_ids", []) if str(value))

    unattempted = sorted(all_planned - attempted_ids)
    coverage_percent = round((100.0 * len(attempted_ids) / len(all_planned)), 2) if all_planned else 100.0
    effective_percent = round((100.0 * len(completed_ids) / len(all_planned)), 2) if all_planned else 100.0
    critical_results = [
        item for item in targeted_results
        if str(item.get("priority_tier", "")).startswith("critical")
    ]
    return {
        "targeted_results": targeted_results,
        "recursive_results": recursive_results,
        "phases": phase_results,
        "planned_rule_ids": sorted(all_planned),
        "planned_rule_count": len(all_planned),
        "attempted_rule_ids": sorted(attempted_ids),
        "attempted_rule_count": len(attempted_ids),
        "completed_rule_ids": sorted(completed_ids),
        "completed_rule_count": len(completed_ids),
        "unattempted_rule_ids": unattempted,
        "rule_coverage_percent": coverage_percent,
        "effective_rule_coverage_percent": effective_percent,
        "critical_targeted_started": len(critical_results),
        "critical_targeted_completed": sum(bool(item.get("completed")) for item in critical_results),
        "coverage_complete": not unattempted and len(completed_ids) == len(all_planned),
        "priority_order": [str(item.get("tier")) for item in batches],
        "scan_mode": scan_mode,
    }

def _message_details(zap: ZAPv2, alert: dict[str, Any]) -> dict[str, str]:
    message_id = str(
        alert.get("messageId")
        or alert.get("messageid")
        or ""
    ).strip()
    if not message_id:
        return {}
    try:
        message = zap.core.message(message_id)
    except Exception:
        return {"message_id": message_id}
    if not isinstance(message, dict):
        return {"message_id": message_id}
    # Never include Cookie values in the report.
    request_header = re.sub(
        r"(?im)^Cookie:\s*.+$",
        "Cookie: <redacted>",
        str(message.get("requestHeader") or ""),
    )
    return {
        "message_id": message_id,
        "request_header": request_header[:5000],
        "request_body": str(message.get("requestBody") or "")[:5000],
        "response_header": str(message.get("responseHeader") or "")[:5000],
        "response_body_excerpt": str(message.get("responseBody") or "")[:2500],
    }


def _findings(
    zap: ZAPv2,
    zap_target_url: str,
    target_url: str,
    max_observations: int = 40,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    scoped = zap.core.alerts(baseurl=zap_target_url)
    try:
        global_alerts = zap.core.alerts()
    except Exception:
        global_alerts = []
    alerts: list[dict[str, Any]] = []
    seen_raw: set[tuple[str, str, str, str, str]] = set()
    for alert in [*(scoped if isinstance(scoped, list) else []), *(global_alerts if isinstance(global_alerts, list) else [])]:
        if not isinstance(alert, dict):
            continue
        scanner_url = str(alert.get("url") or "")
        if scanner_url and not (
            same_origin(zap_target_url, scanner_url)
            or same_origin(target_url, scanner_url)
        ):
            continue
        raw_key = (
            str(alert.get("pluginId") or alert.get("pluginid") or ""),
            scanner_url,
            str(alert.get("param") or ""),
            str(alert.get("attack") or ""),
            str(alert.get("messageId") or alert.get("messageid") or ""),
        )
        if raw_key in seen_raw:
            continue
        seen_raw.add(raw_key)
        alerts.append(alert)
    if not isinstance(alerts, list):
        return [], {"raw": 0, "returned": 0, "suppressed": 0}

    security: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    seen_security: set[tuple[str, str, str, str]] = set()
    seen_info: set[tuple[str, str, str, str]] = set()
    suppressed = 0

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        risk = risk_name(alert.get("riskcode"))
        plugin_id = str(alert.get("pluginId") or alert.get("pluginid") or "")
        title = str(alert.get("alert") or "ZAP finding")
        scanner_url = str(alert.get("url") or zap_target_url)
        url = _externalize_url(scanner_url, zap_target_url, target_url)
        parameter = str(alert.get("param") or "")
        method = str(alert.get("method") or "")
        attack = str(alert.get("attack") or "")
        evidence_value = str(alert.get("evidence") or "")

        if risk == "info":
            # Active User-Agent variants were responsible for hundreds of near-
            # identical pages and do not add useful assessment information.
            if plugin_id == "10104" or "user agent fuzzer" in title.lower():
                suppressed += 1
                continue
            key = (plugin_id, url, parameter, method)
            if key in seen_info:
                suppressed += 1
                continue
            seen_info.add(key)
        else:
            key = (plugin_id, url, parameter, attack)
            if key in seen_security:
                suppressed += 1
                continue
            seen_security.add(key)

        details = _message_details(zap, alert)
        response_excerpt = details.get("response_body_excerpt", "")
        if risk == "info" and 'type="password"' in response_excerpt.lower() and "/login" not in url.lower():
            suppressed += 1
            continue
        if risk == "info":
            details["response_body_excerpt"] = response_excerpt[:500]
            details["request_header"] = details.get("request_header", "")[:1200]
            details["response_header"] = details.get("response_header", "")[:1200]

        evidence_parts = [
            f"Matched evidence: {evidence_value}" if evidence_value else "",
            f"Attack payload: {attack}" if attack else "",
            f"Request header:\n{details.get('request_header', '')}" if details.get("request_header") else "",
            f"Request body:\n{details.get('request_body', '')}" if details.get("request_body") else "",
            f"Response header:\n{details.get('response_header', '')}" if details.get("response_header") else "",
            f"Response body excerpt:\n{details.get('response_body_excerpt', '')}" if details.get("response_body_excerpt") else "",
        ]
        references = [value.strip() for value in str(alert.get("reference") or "").splitlines() if value.strip()]
        confidence = str(alert.get("confidence") or "medium").lower()
        finding = {
            "alert": title,
            "risk": risk,
            "category": "observation" if risk == "info" else "candidate",
            "verification_status": "automated-candidate" if risk != "info" else "passive-observation",
            "confidence": confidence,
            "description": str(alert.get("description") or "").strip(),
            "impact": "",
            "other_information": str(alert.get("other") or "").strip(),
            "solution": str(alert.get("solution") or "").strip(),
            "url": url,
            "scanner_url": scanner_url,
            "method": method,
            "parameter": parameter,
            "attack": attack,
            "evidence": "\n\n".join(part for part in evidence_parts if part),
            "references": references,
            "cwe_id": str(alert.get("cweid") or ""),
            "wasc_id": str(alert.get("wascid") or ""),
            "plugin_id": plugin_id,
            "source_id": str(alert.get("sourceid") or ""),
            "message_id": details.get("message_id", ""),
            "technical_details": f"ZAP plugin={plugin_id or 'unknown'}; risk={risk}; confidence={confidence}; parameter={parameter or 'not specified'}.",
            **details,
        }
        (observations if risk == "info" else security).append(finding)

    observations = observations[:max_observations]
    suppressed += max(0, len(seen_info) - len(observations))
    findings = [*security, *observations]
    return findings, {
        "raw": len(alerts),
        "security": len(security),
        "observations": len(observations),
        "returned": len(findings),
        "suppressed": suppressed,
    }


def _new_zap_client(
    zap_url: str,
    api_key: str,
) -> tuple[ZAPv2, str]:
    try:
        import zapv2
        python_api_version = str(getattr(zapv2, "__version__", "unknown"))
    except Exception:
        python_api_version = "unknown"

    try:
        zap = ZAPv2(
            apikey=api_key,
            proxies={"http": zap_url, "https": zap_url},
            validate_status_code=True,
        )
    except TypeError:
        zap = ZAPv2(
            apikey=api_key,
            proxies={"http": zap_url, "https": zap_url},
        )
    return zap, python_api_version


@mcp.tool()
def run_zap_scan(
    target_url: str,
    cookies: str = "",
    zap_url: str = "http://127.0.0.1:8080",
    timeout: int = 360,
    api_key: str = "",
    seed_urls: list[str] | None = None,
    request_cases: list[dict[str, Any]] | None = None,
    diagnostic_only: bool = False,
    scan_mode: str = "targeted",
    max_observations: int = 40,
) -> dict:
    """
    Verify the supplied session both directly and through ZAP, then run bounded
    high-value active scans and proxy-assisted response verification while
    keeping destructive logout/reset paths out of scope.
    """
    if not _valid_http_url(target_url):
        return failure(
            "OWASP ZAP",
            target_url,
            "target_url must be a valid HTTP or HTTPS URL.",
        )
    if not _valid_http_url(zap_url):
        return failure(
            "OWASP ZAP",
            target_url,
            "zap_url must be a valid HTTP or HTTPS URL.",
        )
    scan_mode = str(scan_mode or "targeted").lower()
    if scan_mode not in {"passive", "targeted", "prioritized", "full"}:
        return failure("OWASP ZAP", target_url, "scan_mode must be passive, targeted, prioritized, or full.")
    max_observations = max(5, min(int(max_observations), 100))
    if timeout < 45:
        return failure(
            "OWASP ZAP",
            target_url,
            "timeout must be at least 45 seconds.",
        )

    try:
        canonical_cookies = canonical_cookie_header(cookies)
        cookie_pairs = parse_cookie_header(canonical_cookies)
    except ValueError as exc:
        return failure(
            "OWASP ZAP",
            target_url,
            f"Invalid Cookie header: {exc}",
            diagnosis="invalid_cookie_header",
        )

    zap_target_url, target_mapping = _zap_reachable_target(
        target_url
    )

    started = time.monotonic()
    deadline = started + timeout
    zap: ZAPv2 | None = None
    context: dict[str, Any] = {}
    seed_summary: dict[str, Any] = {}
    pre_session: dict[str, Any] = {}
    post_session: dict[str, Any] = {}
    targeted_results: list[dict[str, Any]] = []
    broad_active: dict[str, Any] = {}
    alert_stats: dict[str, int] = {}
    active_policy: dict[str, Any] = {}
    proxy_verification_findings: list[dict[str, Any]] = []
    proxy_verification_diagnostics: list[dict[str, Any]] = []
    post_spider_target_preparation: dict[str, Any] = {
        "performed": False, "configured": False, "usable": True,
    }
    native_plan: dict[str, Any] = {}
    phase = "startup"

    try:
        zap, python_api_version = _new_zap_client(
            zap_url,
            api_key or os.getenv("ZAP_API_KEY", ""),
        )
        zap_version = str(zap.core.version)
        if not zap_version:
            raise RuntimeError("ZAP API returned an empty version.")

        _remove_cookie_rule(zap)
        zap.core.new_session(
            name=f"secops-v15-{int(time.time())}",
            overwrite=True,
        )

        replacer = {
            "supported": True,
            "configured": False,
        }
        if canonical_cookies:
            try:
                zap.replacer.add_rule(
                    description=COOKIE_RULE_NAME,
                    enabled=True,
                    matchtype="REQ_HEADER",
                    matchregex=False,
                    matchstring="Cookie",
                    replacement=canonical_cookies,
                    initiators="",
                )
                replacer["configured"] = True
            except Exception as exc:
                replacer = {
                    "supported": False,
                    "configured": False,
                    "reason": f"{type(exc).__name__}: {exc}",
                }

        context = _configure_context(zap, zap_target_url, target_url)
        context_name = str(context.get("context_name") or "")
        context_id = str(context.get("context_id") or "")

        try:
            zap.pscan.enable_all_scanners()
        except Exception:
            pass
        active_policy = _configure_bounded_active_policy(zap, scan_mode)

        probe_url = _select_probe_url(
            target_url,
            list(seed_urls or []),
            [
                case
                for case in (request_cases or [])
                if isinstance(case, dict)
            ],
        )

        phase = "session_precheck"
        # First proxied request creates the ZAP HTTP Sessions site entry.
        if canonical_cookies:
            _request(
                _translate_url(
                    probe_url,
                    target_url,
                    zap_target_url,
                ),
                canonical_cookies,
                zap_url=zap_url,
            )
        http_sessions = _configure_http_sessions(
            zap,
            zap_target_url,
            cookie_pairs,
        )
        pre_session = _validate_session(
            zap,
            target_url,
            zap_target_url,
            zap_url,
            canonical_cookies,
            cookie_pairs,
            probe_url,
        ) if canonical_cookies else {
            "effective": True,
            "probe_url": probe_url,
            "cookie_names": [],
            "root_cause": "",
            "anonymous_profile": True,
        }

        session_methods_ok = (
            not canonical_cookies
            or replacer.get("configured")
            or http_sessions.get("configured")
        )
        pre_session["cookie_injection_method_available"] = session_methods_ok
        pre_session["replacer"] = replacer
        pre_session["http_sessions"] = http_sessions
        pre_session["zap_version"] = zap_version
        pre_session["python_zap_api_version"] = python_api_version

        if canonical_cookies and (
            not session_methods_ok
            or pre_session.get("effective") is not True
        ):
            return partial(
                "OWASP ZAP",
                target_url,
                (
                    "Authenticated ZAP scan was not started because the session "
                    "precheck failed. "
                    f"Root cause: {pre_session.get('root_cause') or 'cookie injection unavailable'}."
                ),
                diagnosis="authentication_precheck_failed",
                timed_out=False,
                time_limit_reached=False,
                vulnerabilities=[],
                authenticated=True,
                authentication_effective=False,
                session_diagnostics=pre_session,
                duration_seconds=round(time.monotonic() - started, 3),
                zap_version=zap_version,
                python_zap_api_version=python_api_version,
                zap_target_url=zap_target_url,
                target_mapping=target_mapping,
            )

        if diagnostic_only:
            return success(
                "OWASP ZAP",
                target_url,
                (
                    "ZAP session diagnostic completed successfully. "
                    f"Probe={probe_url}; cookie names="
                    f"{', '.join(cookie_names(canonical_cookies)) or 'none'}."
                ),
                vulnerabilities=[],
                authenticated=bool(canonical_cookies),
                authentication_effective=pre_session.get("effective"),
                session_diagnostics=pre_session,
                context=context,
                duration_seconds=round(time.monotonic() - started, 3),
                zap_version=zap_version,
                python_zap_api_version=python_api_version,
                diagnostic_only=True,
                zap_target_url=zap_target_url,
                target_mapping=target_mapping,
            )

        phase = "authenticated_surface_seeding"
        seed_deadline = min(
            deadline,
            time.monotonic() + min(60, max(25, int(timeout * 0.16))),
        )
        seed_summary = _seed_zap_history(
            zap_url,
            target_url,
            zap_target_url,
            canonical_cookies,
            list(seed_urls or []),
            [
                case
                for case in (request_cases or [])
                if isinstance(case, dict)
            ],
            seed_deadline,
        )
        zap.urlopen(zap_target_url)
        _wait_passive(
            zap,
            min(deadline, time.monotonic() + 12),
        )

        phase = "spider"
        if canonical_cookies:
            # The application was already crawled directly with the authenticated
            # session and imported into ZAP. Re-spidering through ZAP can follow
            # logout/state-changing links and invalidate the live session.
            spider_scan_id = "authenticated-seed-only"
            spider_completed = True
            spider_progress = 100
        else:
            try:
                spider_scan_id = _scan_id(
                    zap.spider.scan(
                        url=zap_target_url,
                        recurse=True,
                        contextname=context_name or None,
                        subtreeonly=False,
                    ),
                    "spider",
                )
            except Exception:
                spider_scan_id = _scan_id(
                    zap.spider.scan(zap_target_url),
                    "spider",
                )
            spider_completed, spider_progress = _wait_scan(
                zap.spider.status,
                spider_scan_id,
                min(deadline, time.monotonic() + min(65, timeout * 0.18)),
                "spider",
                2.0,
            )
            if not spider_completed:
                try:
                    zap.spider.stop(spider_scan_id)
                except Exception:
                    pass

        phase = "session_after_spider"
        mid_session = _validate_session(
            zap,
            target_url,
            zap_target_url,
            zap_url,
            canonical_cookies,
            cookie_pairs,
            probe_url,
        ) if canonical_cookies else {"effective": True}

        if canonical_cookies and mid_session.get("conclusive") and mid_session.get("effective") is False:
            findings, alert_stats = _findings(zap, zap_target_url, target_url, max_observations)
            return partial(
                "OWASP ZAP",
                target_url,
                (
                    "The authenticated session was valid before spidering but "
                    "was lost during the spider phase. Active scanning was stopped."
                ),
                diagnosis="authentication_lost_during_spider",
                timed_out=False,
                time_limit_reached=False,
                vulnerabilities=findings,
                zap_alert_stats=alert_stats,
                authenticated=True,
                authentication_effective=False,
                session_diagnostics={
                    "before_scan": pre_session,
                    "after_spider": mid_session,
                },
                context=context,
                seed_summary=seed_summary,
                spider_scan_id=spider_scan_id,
                spider_completed=spider_completed,
                spider_progress=spider_progress,
                duration_seconds=round(time.monotonic() - started, 3),
                zap_version=zap_version,
                python_zap_api_version=python_api_version,
            )

        phase = "post_spider_target_preparation"
        if canonical_cookies:
            post_spider_target_preparation = apply_runtime_target_preparation(
                target_url,
                canonical_cookies,
            )
            # Re-seed the clean authentication probe through ZAP after any
            # configured target-state reset. This keeps proxy history and the
            # target session aligned before bounded verification begins.
            try:
                _request(
                    _translate_url(probe_url, target_url, zap_target_url),
                    canonical_cookies,
                    zap_url=zap_url,
                    timeout=(3, 10),
                )
            except requests.RequestException:
                pass

        phase = "target_selection"
        targeted = [] if scan_mode == "passive" else _targeted_cases(
            target_url,
            [case for case in (request_cases or []) if isinstance(case, dict)],
            limit=(10 if scan_mode == "full" else 6 if scan_mode == "prioritized" else 4) if canonical_cookies else 1,
        )

        # Confirm bounded high-value behavior through the ZAP proxy BEFORE the
        # native active-rule queue. A previous local-lab run showed that a native
        # rule could occupy the whole outer timeout and prevent any security
        # result from being returned. Proxy-assisted findings are explicitly
        # labelled and never represented as native ZAP plugin alerts.
        phase = "proxy_assisted_verification"
        if scan_mode != "passive" and targeted:
            proxy_verification_findings, proxy_verification_diagnostics = _run_proxy_assisted_verification(
                targeted,
                target_url,
                zap_target_url,
                zap_url,
                canonical_cookies,
                min(
                    deadline - 35,
                    time.monotonic() + (
                        120 if scan_mode == "full"
                        else 75 if scan_mode == "prioritized"
                        else 45
                    ),
                ),
            )

        phase = "prioritized_native_active_plan"
        # Deep/full mode now attempts the complete installed active-rule inventory
        # in ordered batches. Critical injection/RCE rules always run first;
        # broader and remaining rules use the residual budget and recursive site
        # passes. This preserves early findings without pretending that an
        # unfinished full inventory was complete.
        native_budget = (
            max(180, timeout - 150) if scan_mode == "full"
            else max(120, timeout - 105) if scan_mode == "prioritized"
            else 75
        )
        native_deadline = min(deadline - 35, time.monotonic() + native_budget)
        native_plan = _run_prioritized_native_plan(
            zap, targeted, target_url, zap_target_url, context_id,
            native_deadline, scan_mode, active_policy,
        ) if targeted else {
            "targeted_results": [], "recursive_results": [], "phases": [],
            "planned_rule_ids": active_policy.get("planned_rule_ids", []),
            "planned_rule_count": active_policy.get("planned_rule_count", 0),
            "attempted_rule_ids": [], "attempted_rule_count": 0,
            "completed_rule_ids": [], "completed_rule_count": 0,
            "unattempted_rule_ids": active_policy.get("planned_rule_ids", []),
            "rule_coverage_percent": 0.0,
            "effective_rule_coverage_percent": 0.0,
            "critical_targeted_started": 0,
            "critical_targeted_completed": 0,
            "coverage_complete": False,
            "priority_order": [], "scan_mode": scan_mode,
        }
        targeted_results = list(native_plan.get("targeted_results", []))
        recursive_results = list(native_plan.get("recursive_results", []))
        broad_scan_id = ""
        broad_completed = all(
            bool(item.get("completed"))
            for item in recursive_results
            if item.get("started")
        ) if recursive_results else True
        broad_progress = min(
            [int(item.get("progress") or 0) for item in recursive_results if item.get("started")]
            or [100]
        )
        broad_active.update({
            "scan_id": broad_scan_id,
            "completed": broad_completed,
            "progress": broad_progress,
            "skipped": not bool(recursive_results),
            "priority_phases": native_plan.get("phases", []),
            "recursive_runs": recursive_results,
            "rule_coverage_percent": native_plan.get("rule_coverage_percent", 0.0),
            "effective_rule_coverage_percent": native_plan.get("effective_rule_coverage_percent", 0.0),
            "coverage_complete": native_plan.get("coverage_complete", False),
        })

        phase = "active_scan_cleanup"
        active_scan_ids = [
            str(item.get("scan_id") or "")
            for item in targeted_results
            if isinstance(item, dict)
        ]
        active_scan_ids.extend(
            str(item.get("scan_id") or "")
            for item in native_plan.get("recursive_results", [])
            if isinstance(item, dict) and item.get("scan_id")
        )
        if broad_scan_id:
            active_scan_ids.append(broad_scan_id)
        active_scan_cleanup = _stop_active_scans(zap, active_scan_ids)
        _restore_active_policy(zap)

        phase = "passive_scan_drain"
        passive_completed, passive_remaining = _wait_passive(
            zap,
            min(deadline, time.monotonic() + 15),
        )

        phase = "target_recovery"
        target_recovery = (
            _wait_target_recovery(probe_url, canonical_cookies, seconds=18)
            if canonical_cookies else {"recovered": True, "attempts": 0}
        )

        phase = "session_postcheck"
        if canonical_cookies:
            # Active scanners and target responses may rotate ZAP's internal
            # session state. Re-assert the exact caller-supplied Cookie header
            # before the final validation so a valid external session is not
            # reported as lost merely because ZAP cached a replacement token.
            _remove_cookie_rule(zap)
            try:
                zap.replacer.add_rule(
                    description=COOKIE_RULE_NAME,
                    enabled=True,
                    matchtype="REQ_HEADER",
                    matchregex=False,
                    matchstring="Cookie",
                    replacement=canonical_cookies,
                    initiators="",
                )
            except Exception:
                pass
            _configure_http_sessions(zap, zap_target_url, cookie_pairs)
        post_session = _validate_session(
            zap,
            target_url,
            zap_target_url,
            zap_url,
            canonical_cookies,
            cookie_pairs,
            probe_url,
        ) if canonical_cookies else {"effective": True}

        findings, alert_stats = _findings(
            zap,
            zap_target_url,
            target_url,
            max_observations,
        )
        existing_keys = {
            (
                str(item.get("alert") or "").lower(),
                urlparse(str(item.get("url") or "")).path.lower(),
                str(item.get("parameter") or "").lower(),
            )
            for item in findings
            if isinstance(item, dict) and item.get("category") != "observation"
        }
        for item in proxy_verification_findings:
            key = (
                str(item.get("alert") or "").lower(),
                urlparse(str(item.get("url") or "")).path.lower(),
                str(item.get("parameter") or "").lower(),
            )
            if key not in existing_keys:
                findings.insert(0, item)
                existing_keys.add(key)
        alert_stats["proxy_assisted_confirmed"] = len(proxy_verification_findings)
        alert_stats["security_total_returned"] = sum(
            1 for item in findings if item.get("category") in {"vulnerability", "candidate"}
        )
        try:
            site_tree_urls = list(
                zap.core.urls(baseurl=zap_target_url) or []
            )
        except Exception:
            site_tree_urls = []

        targeted_completed = sum(
            bool(item.get("completed"))
            for item in targeted_results
        )
        targeted_started = len(targeted_results)
        native_incomplete = (
            any(not item.get("completed") for item in targeted_results)
            or any(
                item.get("started") and not item.get("completed")
                for item in native_plan.get("recursive_results", [])
                if isinstance(item, dict)
            )
            or not bool(native_plan.get("coverage_complete", scan_mode != "full"))
        )
        # Native active rules are deliberately bounded and stopped. They are a
        # coverage note, not a tool-level timeout, as long as the controlled
        # phases, alert collection and session checks complete.
        incomplete = (
            not spider_completed
            or not passive_completed
            or (broad_scan_id and not broad_completed)
            or (scan_mode == "full" and native_incomplete)
        )
        postcheck_inconclusive = post_session.get("conclusive") is False
        authentication_effective = bool(
            pre_session.get("effective") is True
            and (post_session.get("effective") is True or postcheck_inconclusive)
        )

        common = {
            "vulnerabilities": findings,
            "zap_alert_stats": alert_stats,
            "scan_mode": scan_mode,
            "zap_version": zap_version,
            "python_zap_api_version": python_api_version,
            "zap_target_url": zap_target_url,
            "target_mapping": target_mapping,
            "duration_seconds": round(
                time.monotonic() - started,
                3,
            ),
            "authenticated": bool(canonical_cookies),
            "authentication_effective": authentication_effective,
            "session_diagnostics": {
                "before_scan": pre_session,
                "after_scan": post_session,
            },
            "context": context,
            "seeded_urls": seed_summary.get(
                "seeded_urls",
                0,
            ),
            "seeded_request_cases": seed_summary.get(
                "seeded_request_cases",
                0,
            ),
            "seed_errors": seed_summary.get(
                "seed_errors",
                [],
            ),
            "spider_scan_id": spider_scan_id,
            "spider_completed": spider_completed,
            "spider_progress": spider_progress,
            "targeted_active_scans": targeted_results,
            "targeted_active_scans_started": targeted_started,
            "targeted_active_scans_completed": targeted_completed,
            "native_active_coverage_incomplete": native_incomplete,
            "active_scanner_policy": active_policy,
            "prioritized_native_plan": native_plan,
            "active_rules_planned": native_plan.get("planned_rule_count", active_policy.get("planned_rule_count", 0)),
            "active_rules_attempted": native_plan.get("attempted_rule_count", 0),
            "active_rules_completed": native_plan.get("completed_rule_count", 0),
            "active_rule_coverage_percent": native_plan.get("rule_coverage_percent", 0.0),
            "active_rule_effective_coverage_percent": native_plan.get("effective_rule_coverage_percent", 0.0),
            "critical_targeted_scans_started": native_plan.get("critical_targeted_started", 0),
            "critical_targeted_scans_completed": native_plan.get("critical_targeted_completed", 0),
            "active_rules_unattempted": native_plan.get("unattempted_rule_ids", []),
            "proxy_assisted_verification": proxy_verification_diagnostics,
            "proxy_assisted_confirmed": len(proxy_verification_findings),
            "post_spider_target_preparation": post_spider_target_preparation,
            "recursive_active_scan": broad_active,
            "passive_scan_completed": passive_completed,
            "passive_records_remaining": passive_remaining,
            "active_scan_cleanup": active_scan_cleanup,
            "target_recovery": target_recovery,
            "session_postcheck_inconclusive": postcheck_inconclusive,
            "zap_sites_tree_urls": len(site_tree_urls),
            "destructive_paths_excluded": list(
                DESTRUCTIVE_PATH_WORDS
            ),
            "scan_scope": (
                "Crawler URLs and request cases were imported through ZAP. "
                "Passive mode performs traffic/passive analysis only. Targeted "
                "Targeted mode runs the highest-value active rules. Full mode "
                "runs the complete installed active-rule inventory in critical, "
                "high and remaining priority tiers, with bounded recursive site "
                "passes and explicit coverage accounting."
            ),
        }

        if canonical_cookies and post_session.get("conclusive") and post_session.get("effective") is False:
            return partial(
                "OWASP ZAP",
                target_url,
                (
                    "ZAP preserved its findings, but the authenticated session "
                    "was not valid at the final verification. "
                    f"Findings: {len(findings)}."
                ),
                diagnosis="authentication_lost_during_scan",
                timed_out=False,
                time_limit_reached=False,
                **common,
            )

        if canonical_cookies and postcheck_inconclusive:
            return partial(
                "OWASP ZAP",
                target_url,
                (
                    "ZAP preserved its findings. The final session check was "
                    "temporarily inconclusive after bounded retries; the direct "
                    "session had been valid before scanning and was not classified "
                    f"as logged out. Findings: {len(findings)}."
                ),
                diagnosis="session_postcheck_inconclusive",
                timed_out=False,
                time_limit_reached=False,
                **common,
            )

        if incomplete:
            budget_exhausted = time.monotonic() >= deadline - 1.0
            diagnosis = "time_limit_reached" if budget_exhausted else "active_coverage_incomplete"
            return partial(
                "OWASP ZAP",
                target_url,
                (
                    f"ZAP preserved {len(findings)} findings with incomplete bounded active coverage. "
                    f"Seeded URLs={common['seeded_urls']}; "
                    f"request cases={common['seeded_request_cases']}; "
                    f"targeted scans={targeted_completed}/{targeted_started}; "
                    f"configured rules={common['active_rules_attempted']}/{common['active_rules_planned']} "
                    f"({common['active_rule_coverage_percent']}%); "
                    f"rules with at least one completed scan={common['active_rules_completed']} "
                    f"({common['active_rule_effective_coverage_percent']}%); "
                    f"critical cases={common['critical_targeted_scans_completed']}/"
                    f"{common['critical_targeted_scans_started']}; "
                    f"site-tree URLs={common['zap_sites_tree_urls']}."
                ),
                diagnosis=diagnosis,
                timed_out=budget_exhausted,
                time_limit_reached=budget_exhausted,
                time_limit_phase=phase if budget_exhausted else "",
                **common,
            )

        return success(
            "OWASP ZAP",
            target_url,
            (
                f"ZAP authenticated/session-aware scan completed. "
                f"Findings: {len(findings)}; "
                f"seeded URLs={common['seeded_urls']}; "
                f"request cases={common['seeded_request_cases']}; "
                f"targeted scans={targeted_completed}/{targeted_started}; "
                f"configured rules={common['active_rules_attempted']}/{common['active_rules_planned']} "
                f"({common['active_rule_coverage_percent']}%); "
                f"rules with completed scans={common['active_rules_completed']} "
                f"({common['active_rule_effective_coverage_percent']}%); "
                f"critical cases={common['critical_targeted_scans_completed']}/"
                f"{common['critical_targeted_scans_started']}; "
                f"site-tree URLs={common['zap_sites_tree_urls']}."
            ),
            timed_out=False,
            time_limit_reached=False,
            **common,
        )
    except requests.RequestException as exc:
        result = failure(
            "OWASP ZAP",
            target_url,
            f"ZAP HTTP operation failed: {type(exc).__name__}: {exc}",
            diagnosis="zap_http_operation_failed",
        )
        result.update(
            duration_seconds=round(
                time.monotonic() - started,
                3,
            ),
            phase=phase,
            session_diagnostics={
                "before_scan": pre_session,
                "after_scan": post_session,
            },
        )
        return result
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"
        lowered = message.lower()
        if (
            "connection refused" in lowered
            or "failed to establish" in lowered
        ):
            diagnosis = "zap_service_unreachable"
        elif (
            "api key" in lowered
            or "unauthorized" in lowered
            or "forbidden" in lowered
        ):
            diagnosis = "zap_api_key_or_permissions"
        elif "scan id" in lowered:
            diagnosis = "zap_scan_not_started"
        else:
            diagnosis = "zap_api_error"
        result = failure(
            "OWASP ZAP",
            target_url,
            message,
            diagnosis=diagnosis,
        )
        result.update(
            duration_seconds=round(
                time.monotonic() - started,
                3,
            ),
            phase=phase,
            context=context,
            seed_summary=seed_summary,
            session_diagnostics={
                "before_scan": pre_session,
                "after_scan": post_session,
            },
        )
        return result
    finally:
        if zap is not None:
            _remove_cookie_rule(zap)


if __name__ == "__main__":
    run_mcp_http(mcp, "zap")
