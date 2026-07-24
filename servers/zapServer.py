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
from urllib.parse import parse_qsl, urlparse, urlunparse

import requests
from fastmcp import FastMCP
from zapv2 import ZAPv2

from utils import (
    canonical_cookie_header,
    cookie_names,
    failure,
    parse_cookie_header,
    partial,
    success,
)

mcp = FastMCP("OWASP ZAP Scanner")

COOKIE_RULE_NAME = "secops-session-cookie-v15"
DESTRUCTIVE_PATH_WORDS = (
    "logout",
    "setup",
    "install",
    "reset",
    "create_db",
    "create-database",
)
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
    """
    Convert a Windows-host loopback URL into a hostname reachable from the ZAP
    Docker container. The project initializer places zap_mcp and dvwa on
    secops-net, where the DVWA service name is `dvwa`.
    """
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    details: dict[str, Any] = {
        "external_target": target_url,
        "translated": False,
        "mode": "unchanged",
    }
    if hostname not in {"127.0.0.1", "localhost", "::1"}:
        details["zap_target"] = target_url
        return target_url, details

    zap_networks = _docker_networks("zap_mcp")
    dvwa_networks = _docker_networks("dvwa")
    shared = sorted(zap_networks & dvwa_networks)
    if shared:
        internal_port = 443 if parsed.scheme == "https" else 80
        netloc = "dvwa" if internal_port in {80, 443} else f"dvwa:{internal_port}"
        translated = urlunparse(parsed._replace(netloc=netloc))
        details.update({
            "translated": True,
            "mode": "shared_docker_network",
            "shared_networks": shared,
            "zap_target": translated,
            "container_alias": "dvwa",
        })
        return translated, details

    # Docker Desktop normally provides this hostname even without an explicit
    # shared user-defined network.
    port = parsed.port
    netloc = "host.docker.internal"
    if port:
        netloc += f":{port}"
    translated = urlunparse(parsed._replace(netloc=netloc))
    details.update({
        "translated": True,
        "mode": "docker_desktop_host_gateway",
        "zap_target": translated,
        "container_alias": "host.docker.internal",
        "shared_networks": shared,
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


def _same_origin(left: str, right: str) -> bool:
    a, b = urlparse(left), urlparse(right)
    return (a.scheme.lower(), a.hostname, a.port) == (
        b.scheme.lower(),
        b.hostname,
        b.port,
    )


def _safe_path(url: str) -> bool:
    path = urlparse(url).path.lower()
    return not any(word in path for word in DESTRUCTIVE_PATH_WORDS)


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
        or "login :: damn vulnerable web application" in text
    )


def _looks_like_dvwa(response: requests.Response) -> bool:
    text = response.text[:100_000].lower()
    return (
        "damn vulnerable web application" in text
        or "<title>dvwa" in text
        or "dvwa security" in text
    )


def _response_digest(response: requests.Response) -> str:
    return hashlib.sha256(response.content).hexdigest()


def _response_summary(response: requests.Response) -> dict[str, Any]:
    return {
        "status": int(response.status_code),
        "final_url": str(response.url),
        "login_detected": _looks_like_login(response),
        "dvwa_detected": _looks_like_dvwa(response),
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


def _probe_score(url: str) -> int:
    path = urlparse(url).path.lower()
    if not _safe_path(url) or path.endswith("/login.php") or path.endswith("/login"):
        return -1000
    score = 0
    # Stable session/account pages are better authentication probes than
    # vulnerability demonstrations whose dynamic content can change.
    if path.endswith("/security.php"):
        score += 400
    if path.endswith("/index.php"):
        score += 300
    if path == "/":
        score += 250
    if "/vulnerabilities/" in path:
        score += 100
    if any(word in path for word in HIGH_VALUE_PATH_WORDS):
        score += 35
    if urlparse(url).query:
        score += 8
    return score


def _select_probe_url(
    target_url: str,
    seed_urls: list[str],
    request_cases: list[dict[str, Any]],
) -> str:
    candidates = [target_url]
    candidates.extend(str(value) for value in seed_urls)
    candidates.extend(
        str(case.get("url") or "")
        for case in request_cases
        if isinstance(case, dict)
    )
    valid = {
        value
        for value in candidates
        if _valid_http_url(value)
        and _same_origin(target_url, value)
        and _safe_path(value)
    }
    return max(valid, key=_probe_score) if valid else target_url


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
) -> dict[str, Any]:
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    context_name = f"secops-scope-{int(time.time())}"
    context_id = ""
    excluded_regex = (
        rf"^{re.escape(origin)}/.*"
        rf"(?:logout|setup|install|reset|create[_-]?db)"
        rf"(?:[^A-Za-z0-9].*)?$"
    )
    capabilities: dict[str, Any] = {
        "context_supported": False,
        "spider_logout_avoidance_supported": False,
        "spider_cookie_acceptance_disabled": False,
        "destructive_regex": excluded_regex,
    }

    try:
        context_id = str(zap.context.new_context(context_name))
        zap.context.include_in_context(
            context_name,
            rf"^{re.escape(origin)}(?:/.*)?$",
        )
        zap.context.exclude_from_context(context_name, excluded_regex)
        zap.context.set_context_in_scope(context_name, True)
        capabilities["context_supported"] = True
    except Exception as exc:
        capabilities["context_error"] = f"{type(exc).__name__}: {exc}"

    try:
        zap.spider.exclude_from_scan(excluded_regex)
        zap.ascan.exclude_from_scan(excluded_regex)
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
) -> dict[str, Any]:
    try:
        zap_probe_url = _translate_url(
            probe_url,
            target_url,
            zap_target_url,
        )
        anonymous = _request(probe_url, "")
        direct = _request(probe_url, cookie_header)
        proxied = _request(
            zap_probe_url,
            cookie_header,
            zap_url=zap_url,
        )
    except requests.RequestException as exc:
        return {
            "effective": False,
            "proxy_matches_direct": False,
            "history_cookie_exact": False,
            "probe_url": probe_url,
            "root_cause": f"session probe request failed: {type(exc).__name__}: {exc}",
        }

    anonymous_summary = _response_summary(anonymous)
    direct_summary = _response_summary(direct)
    proxy_summary = _response_summary(proxied)
    direct_text = direct.text[:100_000]
    proxy_text = proxied.text[:100_000]
    similarity = SequenceMatcher(None, direct_text, proxy_text).ratio()

    history = _history_cookie_diagnostics(zap, zap_probe_url, cookie_pairs)
    names_lower = {name.lower() for name, _ in cookie_pairs}
    dvwa_detected = any(
        summary.get("dvwa_detected")
        for summary in (anonymous_summary, direct_summary, proxy_summary)
    )
    dvwa_cookie_complete = (
        {"phpsessid", "security"} <= names_lower
        if dvwa_detected
        else True
    )

    # Calculate the anonymous/authenticated difference before it is used by
    # direct_effective. v17 evaluated direct_effective first, causing an
    # UnboundLocalError during every authenticated ZAP precheck.
    distinguished_from_anonymous = (
        anonymous_summary["login_detected"]
        or anonymous_summary["final_url"] != direct_summary["final_url"]
        or anonymous_summary["sha256"] != direct_summary["sha256"]
    )
    direct_effective = (
        direct.status_code < 400
        and not direct_summary["login_detected"]
        and _same_origin(target_url, direct.url)
        and distinguished_from_anonymous
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
            or (
                direct_summary["dvwa_detected"]
                and proxy_summary["dvwa_detected"]
            )
        )
    )

    history_requirement_met = (
        history.get("exact_values_match") is True
        if history.get("supported")
        else proxy_matches_direct
    )
    effective = (
        direct_effective
        and proxy_effective
        and proxy_matches_direct
        and history_requirement_met
        and not history.get("duplicate_cookie_names")
        and dvwa_cookie_complete
    )

    reasons: list[str] = []
    if not distinguished_from_anonymous:
        reasons.append("the selected page does not distinguish authenticated and anonymous responses")
    if not direct_effective:
        reasons.append("the supplied cookie is not authenticated when used directly")
    if not proxy_effective:
        reasons.append("the authenticated request becomes unauthenticated through ZAP")
    if not proxy_matches_direct:
        reasons.append("the proxied response does not match the direct authenticated response")
    if history.get("supported") and not history.get("exact_values_match"):
        reasons.append("ZAP history does not contain the exact supplied cookie values")
    if history.get("duplicate_cookie_names"):
        reasons.append("ZAP emitted duplicate Cookie names")
    if not dvwa_cookie_complete:
        reasons.append("DVWA requires both PHPSESSID and security cookies")

    return {
        "effective": effective,
        "root_cause": "; ".join(reasons) if reasons else "",
        "probe_url": probe_url,
        "zap_probe_url": zap_probe_url,
        "cookie_names": sorted(name for name, _ in cookie_pairs),
        "cookie_pair_count": len(cookie_pairs),
        "dvwa_detected": dvwa_detected,
        "dvwa_cookie_complete": dvwa_cookie_complete,
        "direct": direct_summary,
        "anonymous": anonymous_summary,
        "proxied": proxy_summary,
        "authenticated_distinguished_from_anonymous": distinguished_from_anonymous,
        "proxy_matches_direct": proxy_matches_direct,
        "direct_proxy_similarity": round(similarity, 4),
        "history": history,
        "history_cookie_exact": history_requirement_met,
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
            and _same_origin(target_url, value)
            and _safe_path(value)
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
            or not _same_origin(target_url, url)
            or not _safe_path(url)
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
    ranked: list[tuple[int, dict[str, Any]]] = []
    for case in request_cases:
        if not isinstance(case, dict):
            continue
        url = str(case.get("url") or "")
        method = str(case.get("method") or "GET").upper()
        if (
            not _valid_http_url(url)
            or not _same_origin(target_url, url)
            or not _safe_path(url)
            or method not in {"GET", "POST"}
        ):
            continue
        path = urlparse(url).path.lower()
        parameters = {
            str(value).lower()
            for value in case.get("parameters", [])
            if str(value)
        }
        parameters.update(
            name.lower()
            for name, _ in parse_qsl(
                urlparse(url).query,
                keep_blank_values=True,
            )
        )
        score = 0
        score += 70 if any(word in path for word in HIGH_VALUE_PATH_WORDS) else 0
        score += 10 * len(
            parameters
            & {
                "id", "name", "message", "q", "search", "ip", "host",
                "cmd", "command", "file", "path", "url", "redirect",
            }
        )
        score += 8 if method == "POST" else 0
        if score > 0:
            ranked.append((score, case))

    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for _, case in sorted(ranked, key=lambda item: -item[0]):
        key = (
            str(case.get("method") or "GET").upper(),
            str(case.get("url") or ""),
            str(case.get("data") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        selected.append(case)
        if len(selected) >= limit:
            break
    return selected


def _run_targeted_active_scans(
    zap: ZAPv2,
    cases: list[dict[str, Any]],
    target_url: str,
    zap_target_url: str,
    context_id: str,
    deadline: float,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        remaining = deadline - time.monotonic()
        if remaining < 15:
            break
        url = str(case.get("url") or "")
        method = str(case.get("method") or "GET").upper()
        data = str(case.get("data") or "")
        try:
            scan_id = _scan_id(
                zap.ascan.scan(
                    url=scan_url,
                    recurse=False,
                    method=method,
                    postdata=data if method == "POST" else None,
                    contextid=context_id or None,
                ),
                f"targeted active scan {method} {url}",
            )
            completed, progress = _wait_scan(
                zap.ascan.status,
                scan_id,
                min(deadline, time.monotonic() + min(45, remaining)),
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
                "parameters": list(case.get("parameters", [])),
            })
        except Exception as exc:
            results.append({
                "url": url,
                "scan_url": scan_url,
                "method": method,
                "completed": False,
                "progress": 0,
                "error": f"{type(exc).__name__}: {exc}",
            })
    return results


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
        "response_body_excerpt": str(message.get("responseBody") or "")[:7000],
    }


def _findings(zap: ZAPv2, zap_target_url: str, target_url: str) -> list[dict[str, Any]]:
    alerts = zap.core.alerts(baseurl=zap_target_url)
    if not isinstance(alerts, list):
        return []

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        risk = risk_name(alert.get("riskcode"))
        plugin_id = str(alert.get("pluginId") or alert.get("pluginid") or "")
        scanner_url = str(alert.get("url") or zap_target_url)
        url = _externalize_url(
            scanner_url,
            zap_target_url,
            target_url,
        )
        parameter = str(alert.get("param") or "")
        attack = str(alert.get("attack") or "")
        evidence_value = str(alert.get("evidence") or "")
        key = (plugin_id, url, parameter, attack, evidence_value)
        if key in seen:
            continue
        seen.add(key)

        details = _message_details(zap, alert)
        evidence_parts = [
            f"Matched evidence: {evidence_value}" if evidence_value else "",
            f"Attack payload: {attack}" if attack else "",
            (
                f"Request header:\n{details.get('request_header', '')}"
                if details.get("request_header")
                else ""
            ),
            (
                f"Request body:\n{details.get('request_body', '')}"
                if details.get("request_body")
                else ""
            ),
            (
                f"Response header:\n{details.get('response_header', '')}"
                if details.get("response_header")
                else ""
            ),
            (
                f"Response body excerpt:\n"
                f"{details.get('response_body_excerpt', '')}"
                if details.get("response_body_excerpt")
                else ""
            ),
        ]
        references = [
            value.strip()
            for value in str(alert.get("reference") or "").splitlines()
            if value.strip()
        ]
        confidence = str(alert.get("confidence") or "medium").lower()

        findings.append({
            "alert": str(alert.get("alert") or "ZAP finding"),
            "risk": risk,
            "category": "observation" if risk == "info" else "candidate",
            "verification_status": (
                "automated-candidate"
                if risk != "info"
                else "passive-observation"
            ),
            "confidence": confidence,
            "description": str(alert.get("description") or "").strip(),
            "impact": "",
            "other_information": str(alert.get("other") or "").strip(),
            "solution": str(alert.get("solution") or "").strip(),
            "url": url,
            "scanner_url": scanner_url,
            "method": str(alert.get("method") or ""),
            "parameter": parameter,
            "attack": attack,
            "evidence": "\n\n".join(
                part for part in evidence_parts if part
            ),
            "references": references,
            "cwe_id": str(alert.get("cweid") or ""),
            "wasc_id": str(alert.get("wascid") or ""),
            "plugin_id": plugin_id,
            "source_id": str(alert.get("sourceid") or ""),
            "message_id": details.get("message_id", ""),
            "technical_details": (
                f"ZAP plugin={plugin_id or 'unknown'}; risk={risk}; "
                f"confidence={confidence}; "
                f"parameter={parameter or 'not specified'}."
            ),
            **details,
        })
    return findings


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
) -> dict:
    """
    Verify the supplied session both directly and through ZAP, then run bounded
    targeted and recursive scans while keeping destructive logout/reset paths
    out of scope.
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
    if timeout < 60:
        return failure(
            "OWASP ZAP",
            target_url,
            "timeout must be at least 60 seconds.",
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

        context = _configure_context(zap, zap_target_url)
        context_name = str(context.get("context_name") or "")
        context_id = str(context.get("context_id") or "")

        for manager in (
            getattr(zap, "ascan", None),
            getattr(zap, "pscan", None),
        ):
            try:
                manager.enable_all_scanners()
            except Exception:
                pass

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
            or not pre_session.get("effective")
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

        if canonical_cookies and not mid_session.get("effective"):
            findings = _findings(zap, zap_target_url, target_url)
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

        phase = "targeted_active_scans"
        targeted = _targeted_cases(
            target_url,
            [
                case
                for case in (request_cases or [])
                if isinstance(case, dict)
            ],
        )
        targeted_deadline = min(
            deadline - 55,
            time.monotonic() + min(150, max(50, timeout * 0.38)),
        )
        targeted_results = _run_targeted_active_scans(
            zap,
            targeted,
            target_url,
            zap_target_url,
            context_id,
            targeted_deadline,
        )

        phase = "recursive_active_scan"
        broad_completed = False
        broad_progress = 0
        broad_scan_id = ""
        if deadline - time.monotonic() > 35:
            try:
                broad_scan_id = _scan_id(
                    zap.ascan.scan(
                        url=zap_target_url,
                        recurse=True,
                        inscopeonly=True if not context_id else None,
                        contextid=context_id or None,
                    ),
                    "recursive active scan",
                )
                broad_completed, broad_progress = _wait_scan(
                    zap.ascan.status,
                    broad_scan_id,
                    deadline - 22,
                    "recursive active scan",
                    3.0,
                )
                if not broad_completed:
                    try:
                        zap.ascan.stop(broad_scan_id)
                    except Exception:
                        pass
            except Exception as exc:
                broad_active["error"] = (
                    f"{type(exc).__name__}: {exc}"
                )

        broad_active.update({
            "scan_id": broad_scan_id,
            "completed": broad_completed,
            "progress": broad_progress,
        })

        phase = "passive_scan_drain"
        passive_completed, passive_remaining = _wait_passive(
            zap,
            deadline,
        )

        phase = "session_postcheck"
        post_session = _validate_session(
            zap,
            target_url,
            zap_url,
            canonical_cookies,
            cookie_pairs,
            probe_url,
        ) if canonical_cookies else {"effective": True}

        findings = _findings(zap, target_url)
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
        incomplete = (
            not spider_completed
            or not passive_completed
            or (
                broad_scan_id
                and not broad_completed
            )
            or any(
                not item.get("completed")
                for item in targeted_results
            )
        )
        authentication_effective = (
            pre_session.get("effective")
            and post_session.get("effective")
        )

        common = {
            "vulnerabilities": findings,
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
            "recursive_active_scan": broad_active,
            "passive_scan_completed": passive_completed,
            "passive_records_remaining": passive_remaining,
            "zap_sites_tree_urls": len(site_tree_urls),
            "destructive_paths_excluded": list(
                DESTRUCTIVE_PATH_WORDS
            ),
            "scan_scope": (
                "FFUF/crawler URLs and GET/POST cases were proxied through "
                "ZAP. High-value request cases were actively scanned "
                "individually before the bounded recursive scan."
            ),
        }

        if canonical_cookies and not authentication_effective:
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

        if incomplete:
            return partial(
                "OWASP ZAP",
                target_url,
                (
                    f"ZAP reached the bounded scan budget with findings preserved: "
                    f"{len(findings)}. Seeded URLs={common['seeded_urls']}; "
                    f"request cases={common['seeded_request_cases']}; "
                    f"targeted scans={targeted_completed}/{targeted_started}; "
                    f"site-tree URLs={common['zap_sites_tree_urls']}."
                ),
                diagnosis="time_limit_reached",
                timed_out=True,
                time_limit_reached=True,
                time_limit_phase=phase,
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
    mcp.run(transport="stdio")