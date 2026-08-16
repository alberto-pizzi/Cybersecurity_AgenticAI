from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import subprocess
import time
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlparse, urlunparse

import requests
from zapv2 import ZAPv2

from scannerCommon import service
from utils import (
    apply_runtime_target_preparation, canonical_cookie_header, cookie_names, failure, parse_cookie_header,
    response_looks_like_login, runtime_container_route, same_origin, success, partial,
)
from zapVerification import select_cases, verify_cases

mcp, _serve = service("OWASP ZAP Scanner", "zap")
COOKIE_RULE_NAME = "secops-auth-cookie"
DESTRUCTIVE_PATH_WORDS = ("logout", "reset", "delete", "destroy", "setup", "security")


def _valid_url(value: str) -> bool:
    parsed = urlparse(str(value or ""))
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _docker_networks(container: str) -> set[str]:
    if not shutil.which("docker"):
        return set()
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, check=False,
        )
        value = json.loads((result.stdout or "{}").strip() or "{}") if result.returncode == 0 else {}
        return set(value) if isinstance(value, dict) else set()
    except Exception:
        return set()


def _zap_target(target_url: str) -> tuple[str, dict[str, Any]]:
    parsed = urlparse(target_url)
    details: dict[str, Any] = {"external_target": target_url, "translated": False, "mode": "unchanged"}
    if (parsed.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}:
        details["zap_target"] = target_url
        return target_url, details
    route = runtime_container_route(target_url, "zap_mcp")
    alias, container, network = (str(route.get(k) or "").strip() for k in ("alias", "target_container", "network"))
    if alias and container:
        shared = sorted(_docker_networks("zap_mcp") & _docker_networks(container))
        if not network or network in shared:
            port = int(route.get("internal_port") or (443 if parsed.scheme == "https" else 80))
            internal = urlunparse(parsed._replace(netloc=alias if port in {80, 443} else f"{alias}:{port}"))
            details.update(translated=True, mode="configured_docker_route", shared_networks=shared, zap_target=internal, container_alias=alias)
            return internal, details
    netloc = "host.docker.internal" + (f":{parsed.port}" if parsed.port else "")
    internal = urlunparse(parsed._replace(netloc=netloc))
    details.update(translated=True, mode="docker_desktop_host_gateway", zap_target=internal, container_alias="host.docker.internal")
    return internal, details


def _translate(url: str, external_base: str, internal_base: str) -> str:
    cur, ext, internal = urlparse(str(url or "")), urlparse(external_base), urlparse(internal_base)
    if (cur.scheme.lower(), cur.hostname, cur.port) == (ext.scheme.lower(), ext.hostname, ext.port):
        return urlunparse(cur._replace(scheme=internal.scheme, netloc=internal.netloc))
    return url


def _externalize(url: str, internal_base: str, external_base: str) -> str:
    cur, internal, ext = urlparse(str(url or "")), urlparse(internal_base), urlparse(external_base)
    if (cur.scheme.lower(), cur.hostname, cur.port) == (internal.scheme.lower(), internal.hostname, internal.port):
        return urlunparse(cur._replace(scheme=ext.scheme, netloc=ext.netloc))
    return url


def _client(zap_url: str, api_key: str) -> tuple[ZAPv2, str]:
    try:
        import zapv2
        version = str(getattr(zapv2, "__version__", "unknown"))
    except Exception:
        version = "unknown"
    kwargs = {"apikey": api_key, "proxies": {"http": zap_url, "https": zap_url}}
    try:
        return ZAPv2(validate_status_code=True, **kwargs), version
    except TypeError:
        return ZAPv2(**kwargs), version


def _remove_cookie_rule(zap: ZAPv2) -> None:
    try:
        zap.replacer.remove_rule(COOKIE_RULE_NAME)
    except Exception:
        pass


def _configure_cookie(zap: ZAPv2, cookies: str) -> dict[str, Any]:
    _remove_cookie_rule(zap)
    if not cookies:
        return {"supported": True, "configured": False}
    try:
        zap.replacer.add_rule(
            description=COOKIE_RULE_NAME, enabled=True, matchtype="REQ_HEADER", matchregex=False,
            matchstring="Cookie", replacement=cookies, initiators="",
        )
        return {"supported": True, "configured": True}
    except Exception as exc:
        return {"supported": False, "configured": False, "reason": f"{type(exc).__name__}: {exc}"}


def _configure_http_sessions(zap: ZAPv2, target: str, cookie_pairs: list[tuple[str, str]]) -> dict[str, Any]:
    if not cookie_pairs:
        return {"supported": True, "configured": False, "anonymous_profile": True}
    parsed = urlparse(target)
    wanted = {parsed.netloc.lower(), (parsed.hostname or "").lower()}
    try:
        sites = list(zap.httpsessions.sites or [])
        site = next((str(v) for v in sites if str(v).lower() in wanted), parsed.netloc)
        session_name = f"secops-auth-{int(time.time())}"
        for name, _ in cookie_pairs:
            try: zap.httpsessions.add_session_token(site, name)
            except Exception: pass
        zap.httpsessions.create_empty_session(site, session_name)
        for name, value in cookie_pairs:
            zap.httpsessions.set_session_token_value(site, session_name, name, value)
        zap.httpsessions.set_active_session(site, session_name)
        active = str(zap.httpsessions.active_session(site) or "")
        return {"supported": True, "configured": active == session_name, "site": site, "session_name": session_name,
                "active_session": active, "token_names": [name for name, _ in cookie_pairs]}
    except Exception as exc:
        return {"supported": False, "configured": False, "reason": f"{type(exc).__name__}: {exc}"}


def _scanner_inventory(zap: ZAPv2) -> list[dict[str, Any]]:
    try:
        value = zap.ascan.scanners
        value = value() if callable(value) else value
        return value if isinstance(value, list) else []
    except Exception:
        return []


def _scanner_id(item: dict[str, Any]) -> str:
    return str(item.get("id") or item.get("pluginId") or item.get("pluginid") or "").strip()


def _scanner_name(item: dict[str, Any]) -> str:
    return str(item.get("name") or item.get("pluginName") or item.get("description") or "").strip()


def _rule_tags(scanner_id: str, scanner_name: str) -> set[str]:
    """Classify installed ZAP rules using the official scanner inventory."""
    text = scanner_name.lower()
    tags: set[str] = set()
    if "sql injection" in text or scanner_id in {"40018", "40019", "40020", "40021", "40022", "40027"}:
        tags.update({"sqli", "sqli_blind"})
    if any(v in text for v in ("cross site scripting", "cross-site scripting", "xss")) or scanner_id in {"40012", "40014"}:
        tags.update({"xss_reflected", "xss_stored"})
    if any(v in text for v in ("command injection", "remote os command", "code injection", "shell injection")) or scanner_id == "90020":
        tags.add("command")
    if any(v in text for v in ("path traversal", "file inclusion", "local file inclusion", "remote file inclusion")) or scanner_id in {"6", "7"}:
        tags.add("traversal")
    return tags


def _rules_for_case(case: dict[str, Any], scanners: list[dict[str, Any]]) -> list[str]:
    case_class = str(case.get("zap_case_class") or "other")
    matched = [sid for item in scanners if (sid := _scanner_id(item)) and case_class in _rule_tags(sid, _scanner_name(item))]
    if matched:
        return list(dict.fromkeys(matched))
    fallback = {
        "sqli": ("40018", "40019", "40020", "40021", "40022", "40027"),
        "sqli_blind": ("40018", "40019", "40020", "40021", "40022", "40027"),
        "xss_reflected": ("40012",), "xss_stored": ("40014", "40012"),
        "command": ("90020",), "traversal": ("6", "7"),
    }.get(case_class, ())
    installed = {_scanner_id(item) for item in scanners}
    return [sid for sid in fallback if sid in installed]


def _native_plan(targeted: list[dict[str, Any]], case_rules: dict[str, list[str]], scan_mode: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    deferred = [case for case in targeted if scan_mode == "prioritized" and case.get("zap_case_class") == "xss_stored"]
    native = [case for case in targeted if case not in deferred and case_rules.get(str(case.get("url") or ""))]
    rule_ids = sorted({sid for case in native for sid in case_rules.get(str(case.get("url") or ""), [])})
    return native, deferred, rule_ids

def _configure_active_rules(zap: ZAPv2, scanner_ids: list[str], strength: str) -> list[str]:
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
                zap.ascan.set_scanner_attack_strength(scanner_id, strength)
            except Exception as exc:
                errors.append(f"strength {scanner_id}: {type(exc).__name__}: {exc}")
    return errors


def _stop_active_scans(zap: ZAPv2, scan_ids: list[str]) -> dict[str, Any]:
    stopped, errors = [], []
    for scan_id in dict.fromkeys(v for v in scan_ids if v):
        try:
            zap.ascan.stop(scan_id); stopped.append(scan_id)
        except Exception as exc:
            errors.append(f"{scan_id}: {type(exc).__name__}: {exc}")
    try:
        zap.ascan.stop_all_scans()
    except Exception as exc:
        errors.append(f"stop_all_scans: {type(exc).__name__}: {exc}")
    return {"stopped_scan_ids": stopped, "errors": errors}


def _wait_target_recovery(url: str, cookies: str, seconds: int = 20) -> dict[str, Any]:
    """Wait for the application after ZAP load; transport failure is not logout."""
    deadline, attempts, errors = time.monotonic() + max(3, seconds), 0, []
    while time.monotonic() < deadline:
        attempts += 1
        try:
            response = requests.get(url, headers={"Cookie": cookies, "Cache-Control": "no-cache"} if cookies else {"Cache-Control": "no-cache"}, timeout=(3, 7), allow_redirects=True)
            if response.status_code < 500:
                return {"recovered": True, "attempts": attempts, "status": response.status_code, "final_url": str(response.url), "login_detected": response_looks_like_login(response), "errors": errors[-5:]}
        except requests.RequestException as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        time.sleep(1)
    return {"recovered": False, "attempts": attempts, "conclusive": False, "transient_error": True, "errors": errors[-5:]}


def _configure_context(zap: ZAPv2, target: str) -> dict[str, Any]:
    name = f"secops-{int(time.time())}"
    context_id = str(zap.context.new_context(name))
    parsed = urlparse(target)
    origin = re.escape(f"{parsed.scheme}://{parsed.netloc}")
    include = rf"{origin}.*"
    zap.context.include_in_context(name, include)
    try: zap.context.set_context_in_scope(name, True)
    except Exception: pass
    excluded: list[str] = []
    for token in DESTRUCTIVE_PATH_WORDS:
        pattern = rf"{origin}.*/{token}(?:[/?#].*)?$"
        excluded.append(pattern)
        try: zap.context.exclude_from_context(name, pattern)
        except Exception: pass
        try: zap.spider.exclude_from_scan(pattern)
        except Exception: pass
        try: zap.ascan.exclude_from_scan(pattern)
        except Exception: pass
    try: zap.spider.set_option_logout_avoidance(True)
    except Exception: pass
    try: zap.spider.set_option_accept_cookies(False)
    except Exception: pass
    return {"context_name": name, "context_id": context_id, "include_regex": include, "excluded_regexes": excluded}


def _safe(url: str, target: str) -> bool:
    return same_origin(url, target) and not any(token in urlparse(url).path.lower() for token in DESTRUCTIVE_PATH_WORDS)


def _proxy_request(zap_url: str, url: str, cookies: str, method: str = "GET", data: str = "") -> requests.Response:
    headers = {"Cache-Control": "no-cache"}
    if cookies:
        headers["Cookie"] = cookies
    return requests.request(
        method, url, data=data if method != "GET" else None, headers=headers,
        proxies={"http": zap_url, "https": zap_url}, timeout=(3, 12), allow_redirects=True,
    )


def _probe_url(target: str, seeds: list[str] | None, cases: list[dict[str, Any]] | None) -> str:
    candidates = [*(seeds or []), *(str(c.get("url") or "") for c in (cases or []) if isinstance(c, dict)), target]
    return next((u for u in candidates if _valid_url(u) and _safe(u, target) and "/login" not in urlparse(u).path.lower()), target)


def _response_summary(response: requests.Response) -> dict[str, Any]:
    return {
        "status": response.status_code, "final_url": str(response.url), "login_detected": response_looks_like_login(response),
        "bytes": len(response.content), "sha256": hashlib.sha256(response.content).hexdigest(),
    }


def _history_cookie_diagnostics(zap: ZAPv2, probe_url: str, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    expected = {name.lower(): value for name, value in pairs}
    try:
        messages = zap.core.messages(baseurl=probe_url, start=0, count=100) or []
    except Exception as exc:
        return {"supported": False, "exact_values_match": False, "duplicate_cookie_names": [], "error": f"{type(exc).__name__}: {exc}"}
    for message in reversed(messages if isinstance(messages, list) else []):
        header = str(message.get("requestHeader") or message.get("request_header") or "") if isinstance(message, dict) else ""
        lines = re.findall(r"(?im)^Cookie:\s*([^\r\n]+)", header)
        if not lines:
            continue
        values: dict[str, str] = {}; duplicates: list[str] = []
        for line in lines:
            for part in line.split(";"):
                if "=" not in part: continue
                name, value = (v.strip() for v in part.split("=", 1)); key = name.lower()
                if key in values: duplicates.append(name)
                values[key] = value
        return {
            "supported": True, "message_found": True, "cookie_header_present": bool(values),
            "exact_values_match": all(values.get(k) == v for k, v in expected.items()),
            "expected_cookie_names": sorted(expected), "observed_cookie_names": sorted(values),
            "duplicate_cookie_names": sorted(set(duplicates), key=str.lower),
            "unexpected_cookie_names": sorted(k for k in values if k not in expected),
        }
    return {"supported": True, "message_found": False, "cookie_header_present": False, "exact_values_match": False,
            "expected_cookie_names": sorted(expected), "observed_cookie_names": [], "duplicate_cookie_names": [], "unexpected_cookie_names": []}


def _validate_session(zap: ZAPv2, zap_url: str, external_probe: str, internal_probe: str, cookies: str, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    if not cookies:
        return {"effective": True, "conclusive": True, "anonymous_profile": True, "probe_url": external_probe, "cookie_names": []}
    result: dict[str, Any] = {"probe_url": external_probe, "zap_probe_url": internal_probe, "cookie_names": cookie_names(cookies)}
    try:
        direct = requests.get(external_probe, headers={"Cookie": cookies, "Cache-Control": "no-cache"}, timeout=(3, 10), allow_redirects=True)
        anonymous = requests.get(external_probe, headers={"Cache-Control": "no-cache"}, timeout=(3, 10), allow_redirects=True)
        proxied = _proxy_request(zap_url, internal_probe, cookies)
    except requests.RequestException as exc:
        result.update(effective=None, conclusive=False, transient_error=True, proxy_matches_direct=None, history_cookie_exact=None,
                      root_cause=f"session probe transport error: {type(exc).__name__}: {exc}")
        return result
    direct_s, anonymous_s, proxied_s = map(_response_summary, (direct, anonymous, proxied))
    direct_ok = direct.status_code < 400 and not direct_s["login_detected"]
    proxy_ok = proxied.status_code < 400 and not proxied_s["login_detected"]
    similarity = SequenceMatcher(None, direct.text[:100_000], proxied.text[:100_000]).ratio()
    proxy_match = direct.status_code == proxied.status_code and urlparse(direct.url).path == urlparse(proxied.url).path and (direct_s["sha256"] == proxied_s["sha256"] or similarity >= 0.80)
    distinguished = anonymous_s["login_detected"] or anonymous_s["final_url"] != direct_s["final_url"] or anonymous_s["sha256"] != direct_s["sha256"]
    history = _history_cookie_diagnostics(zap, internal_probe, pairs)
    history_ok = history.get("exact_values_match") is True if history.get("supported") else proxy_match
    duplicates = history.get("duplicate_cookie_names") or []
    effective = bool(direct_ok and proxy_ok and proxy_match and distinguished and history_ok and not duplicates)
    reasons = []
    if not direct_ok: reasons.append("the supplied cookie is not authenticated when used directly")
    if not distinguished: reasons.append("authenticated and anonymous responses are indistinguishable")
    if not proxy_ok: reasons.append("the request becomes unauthenticated through ZAP")
    if not proxy_match: reasons.append("the proxied response differs from the direct authenticated response")
    if history.get("supported") and not history_ok: reasons.append("ZAP history does not contain the supplied cookie values")
    if duplicates: reasons.append("ZAP emitted duplicate Cookie names")
    result.update(
        effective=effective, conclusive=True, transient_error=False, root_cause="; ".join(reasons),
        direct_authenticated=direct_ok, proxy_authenticated=proxy_ok, direct=direct_s, anonymous=anonymous_s, proxied=proxied_s,
        authenticated_distinguished_from_anonymous=distinguished, proxy_matches_direct=proxy_match, direct_proxy_similarity=round(similarity, 4),
        history=history, history_cookie_exact=history_ok,
    )
    return result


def _seed(zap_url: str, external: str, internal: str, cookies: str, seeds: list[str] | None, cases: list[dict[str, Any]] | None, deadline: float) -> dict[str, Any]:
    seeded_urls = seeded_cases = 0
    errors: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for url in [external, *(seeds or [])]:
        if time.monotonic() >= deadline or not _valid_url(url) or not _safe(url, external):
            continue
        key = ("GET", url, "")
        if key in seen:
            continue
        seen.add(key)
        try:
            _proxy_request(zap_url, _translate(url, external, internal), cookies)
            seeded_urls += 1
        except requests.RequestException as exc:
            errors.append(f"GET {url}: {type(exc).__name__}: {exc}")
    for case in cases or []:
        if time.monotonic() >= deadline or not isinstance(case, dict):
            break
        url, method, data = str(case.get("url") or ""), str(case.get("method") or "GET").upper(), str(case.get("data") or "")
        if method not in {"GET", "POST"} or not _valid_url(url) or not _safe(url, external):
            continue
        key = (method, url, data)
        if key in seen:
            continue
        seen.add(key)
        try:
            _proxy_request(zap_url, _translate(url, external, internal), cookies, method, data)
            seeded_cases += 1
        except requests.RequestException as exc:
            errors.append(f"{method} {url}: {type(exc).__name__}: {exc}")
    return {"seeded_urls": seeded_urls, "seeded_request_cases": seeded_cases, "seed_errors": errors[:20]}


def _wait(status_fn, scan_id: str, deadline: float, interval: float = 1.5) -> tuple[bool, int]:
    progress = 0
    while time.monotonic() < deadline:
        try:
            progress = int(str(status_fn(scan_id) or "0"))
        except Exception:
            progress = 0
        if progress >= 100:
            return True, progress
        time.sleep(interval)
    return False, progress


def _wait_passive(zap: ZAPv2, deadline: float) -> tuple[bool, int]:
    remaining = 0
    while time.monotonic() < deadline:
        try:
            remaining = int(str(zap.pscan.records_to_scan or "0"))
        except Exception:
            return True, 0
        if remaining <= 0:
            return True, 0
        time.sleep(1)
    return False, remaining


def _active_scan(zap: ZAPv2, case: dict[str, Any], external: str, internal: str, deadline: float, scanner_ids: list[str], strength: str) -> dict[str, Any]:
    url, method, data = str(case.get("url") or ""), str(case.get("method") or "GET").upper(), str(case.get("data") or "")
    scan_url = _translate(url, external, internal)
    case_class = str(case.get("zap_case_class") or "other")
    if not scanner_ids:
        return {"url": url, "scan_url": scan_url, "method": method, "started": False, "completed": True, "progress": 100, "skipped": True, "reason": "no relevant installed ZAP active rule", "case_class": case_class, "scanner_ids": []}
    configure_errors = _configure_active_rules(zap, scanner_ids, strength)
    try:
        try:
            raw = zap.ascan.scan(url=scan_url, recurse=False, inscopeonly=False, method=method, postdata=data if method == "POST" else None)
        except TypeError:
            raw = zap.ascan.scan(url=scan_url, recurse=False, method=method, postdata=data if method == "POST" else None)
        scan_id = str(raw)
        completed, progress = _wait(zap.ascan.status, scan_id, deadline)
        if not completed:
            try: zap.ascan.stop(scan_id)
            except Exception: pass
        return {"url": url, "scan_url": scan_url, "method": method, "scan_id": scan_id, "started": True, "completed": completed, "progress": progress, "parameters": list(case.get("parameters", [])), "case_class": case_class, "scanner_ids": scanner_ids, "configure_errors": configure_errors}
    except Exception as exc:
        return {"url": url, "scan_url": scan_url, "method": method, "started": False, "completed": False, "progress": 0, "case_class": case_class, "scanner_ids": scanner_ids, "configure_errors": configure_errors, "error": f"{type(exc).__name__}: {exc}"}


def _recursive_scan(zap: ZAPv2, target: str, context_id: str, deadline: float) -> dict[str, Any]:
    try:
        try:
            raw = zap.ascan.scan(url=target, recurse=True, inscopeonly=True, contextid=context_id or None)
        except TypeError:
            raw = zap.ascan.scan(url=target, recurse=True, inscopeonly=True)
        scan_id = str(raw)
        completed, progress = _wait(zap.ascan.status, scan_id, deadline)
        if not completed:
            try: zap.ascan.stop(scan_id)
            except Exception: pass
        return {"started": True, "scan_id": scan_id, "completed": completed, "progress": progress}
    except Exception as exc:
        return {"started": False, "completed": False, "progress": 0, "error": f"{type(exc).__name__}: {exc}"}


def _risk(value: Any) -> str:
    return {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}.get(str(value), str(value or "info").lower())


def _findings(zap: ZAPv2, internal: str, external: str, max_observations: int) -> tuple[list[dict[str, Any]], dict[str, int]]:
    raw = zap.core.alerts(baseurl=internal) or []
    security: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    suppressed = 0
    for alert in raw:
        if not isinstance(alert, dict):
            continue
        scanner_url = str(alert.get("url") or internal)
        if scanner_url and not same_origin(scanner_url, internal):
            continue
        risk, plugin, parameter = _risk(alert.get("riskcode")), str(alert.get("pluginId") or alert.get("pluginid") or ""), str(alert.get("param") or "")
        url = _externalize(scanner_url, internal, external)
        key = (plugin, url, parameter, str(alert.get("attack") or ""))
        if key in seen:
            suppressed += 1; continue
        seen.add(key)
        if risk == "info" and (plugin == "10104" or "user agent fuzzer" in str(alert.get("alert") or "").lower()):
            suppressed += 1; continue
        finding = {
            "alert": str(alert.get("alert") or "ZAP finding"), "risk": risk,
            "category": "observation" if risk == "info" else "candidate",
            "verification_status": "passive-observation" if risk == "info" else "zap-native-alert",
            "confidence": str(alert.get("confidence") or "medium").lower(), "description": str(alert.get("description") or "").strip(),
            "solution": str(alert.get("solution") or "").strip(), "url": url, "scanner_url": scanner_url,
            "method": str(alert.get("method") or ""), "parameter": parameter, "attack": str(alert.get("attack") or ""),
            "evidence": str(alert.get("evidence") or ""), "references": [v.strip() for v in str(alert.get("reference") or "").splitlines() if v.strip()],
            "cwe_id": str(alert.get("cweid") or ""), "wasc_id": str(alert.get("wascid") or ""), "plugin_id": plugin,
        }
        (observations if risk == "info" else security).append(finding)
    observations = observations[:max_observations]
    return [*security, *observations], {"raw": len(raw), "security": len(security), "observations": len(observations), "returned": len(security) + len(observations), "suppressed": suppressed}


@mcp.tool()
def run_zap_scan(
    target_url: str, cookies: str = "", zap_url: str = "http://127.0.0.1:8080", timeout: int = 360,
    api_key: str = "", seed_urls: list[str] | None = None, request_cases: list[dict[str, Any]] | None = None,
    diagnostic_only: bool = False, scan_mode: str = "targeted", max_observations: int = 40,
) -> dict:
    """Drive ZAP through its official Python/JSON API; keep only project-specific verification outside ZAP."""
    if not _valid_url(target_url) or not _valid_url(zap_url):
        return failure("OWASP ZAP", target_url, "target_url and zap_url must be valid HTTP/HTTPS URLs.")
    scan_mode = str(scan_mode or "targeted").lower()
    if scan_mode not in {"passive", "targeted", "prioritized", "full"}:
        return failure("OWASP ZAP", target_url, "scan_mode must be passive, targeted, prioritized, or full.")
    timeout, max_observations = max(45, int(timeout)), max(5, min(int(max_observations), 100))
    try:
        cookies = canonical_cookie_header(cookies)
        parse_cookie_header(cookies)
    except ValueError as exc:
        return failure("OWASP ZAP", target_url, f"Invalid Cookie header: {exc}", diagnosis="invalid_cookie_header")

    started, deadline, phase = time.monotonic(), time.monotonic() + timeout, "startup"
    internal, mapping = _zap_target(target_url)
    zap: ZAPv2 | None = None
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    try:
        zap, py_version = _client(zap_url, api_key or os.getenv("ZAP_API_KEY", ""))
        zap_version = str(zap.core.version)
        if not zap_version:
            raise RuntimeError("ZAP API returned an empty version")
        zap.core.new_session(name=f"secops-{int(time.time())}", overwrite=True)
        replacer = _configure_cookie(zap, cookies)
        context = _configure_context(zap, internal)
        try: zap.pscan.enable_all_scanners()
        except Exception: pass
        try: zap.ascan.enable_all_scanners()
        except Exception: pass
        scanners = _scanner_inventory(zap)
        planned_rules = len(scanners) if isinstance(scanners, list) else 0
        strength = "MEDIUM" if scan_mode == "targeted" else "HIGH"
        for scanner in scanners if isinstance(scanners, list) else []:
            sid = str(scanner.get("id") or "") if isinstance(scanner, dict) else ""
            if sid:
                try: zap.ascan.set_scanner_attack_strength(sid, strength)
                except Exception: pass
        active_policy = {"source": "official_zap_ascan_api", "strength": strength, "planned_rule_count": planned_rules, "planned_rule_ids": [str(v.get("id") or "") for v in scanners if isinstance(v, dict)]}

        probe = _probe_url(target_url, seed_urls, request_cases)
        internal_probe = _translate(probe, target_url, internal)
        phase = "session_precheck"
        if cookies:
            try: _proxy_request(zap_url, internal_probe, cookies)
            except requests.RequestException: pass
        http_sessions = _configure_http_sessions(zap, internal, parse_cookie_header(cookies))
        before = _validate_session(zap, zap_url, probe, internal_probe, cookies, parse_cookie_header(cookies))
        before.update(replacer=replacer, http_sessions=http_sessions, zap_version=zap_version, python_zap_api_version=py_version)
        injection_ready = not cookies or replacer.get("configured") or http_sessions.get("configured")
        if cookies and (not injection_ready or before.get("effective") is not True):
            return partial(
                "OWASP ZAP", target_url, f"Authenticated ZAP scan was not started because the session precheck failed. Root cause: {before.get('root_cause') or 'cookie injection unavailable'}.",
                diagnosis="authentication_precheck_failed", timed_out=False, time_limit_reached=False, vulnerabilities=[], authenticated=True,
                authentication_effective=False, session_diagnostics=before, duration_seconds=round(time.monotonic() - started, 3),
                zap_version=zap_version, python_zap_api_version=py_version, zap_target_url=internal, target_mapping=mapping,
            )
        if diagnostic_only:
            return success(
                "OWASP ZAP", target_url, f"ZAP session diagnostic completed successfully. Probe={probe}; cookie names={', '.join(cookie_names(cookies)) or 'none'}.",
                vulnerabilities=[], authenticated=bool(cookies), authentication_effective=before.get("effective"), session_diagnostics=before,
                context=context, duration_seconds=round(time.monotonic() - started, 3), zap_version=zap_version,
                python_zap_api_version=py_version, diagnostic_only=True, zap_target_url=internal, target_mapping=mapping,
            )

        phase = "authenticated_surface_seeding"
        seed_summary = _seed(zap_url, target_url, internal, cookies, seed_urls, request_cases, min(deadline, time.monotonic() + 60))
        try: zap.urlopen(internal)
        except Exception: pass
        _wait_passive(zap, min(deadline, time.monotonic() + 12))

        phase = "spider"
        spider_id, spider_completed, spider_progress = "authenticated-seed-only", True, 100
        if not cookies:
            raw = zap.spider.scan(url=internal, recurse=True, contextname=context["context_name"], subtreeonly=False)
            spider_id = str(raw)
            spider_completed, spider_progress = _wait(zap.spider.status, spider_id, min(deadline, time.monotonic() + min(65, timeout * 0.2)))
            if not spider_completed:
                try: zap.spider.stop(spider_id)
                except Exception: pass

        post_prepare = apply_runtime_target_preparation(target_url, cookies) if cookies else {"performed": False, "configured": False, "usable": True}
        case_limit = 12 if scan_mode == "full" else 8 if scan_mode == "prioritized" else 6
        targeted = [] if scan_mode == "passive" else select_cases(target_url, request_cases, case_limit)
        case_rules = {str(case.get("url") or ""): _rules_for_case(case, scanners) for case in targeted}
        # Persistent XSS re-spiders the application. Keep that native rule for
        # full/deep, while balanced/prioritized still runs proxy verification.
        native_cases, deferred_native, priority_rule_ids = _native_plan(targeted, case_rules, scan_mode)
        if scan_mode != "full":
            active_policy["planned_rule_ids"] = priority_rule_ids
            active_policy["planned_rule_count"] = len(priority_rule_ids)
            planned_rules = len(priority_rule_ids)

        phase = "proxy_assisted_verification"
        proxy_findings, proxy_diagnostics = ([], [])
        if targeted:
            proxy_findings, proxy_diagnostics = verify_cases(targeted, target_url, internal, zap_url, cookies, min(deadline - 30, time.monotonic() + (120 if scan_mode == "full" else 75 if scan_mode == "prioritized" else 45)))

        phase = "official_zap_active_scan"
        targeted_results: list[dict[str, Any]] = []
        if scan_mode != "passive":
            reserve = 50 if cookies else 30
            active_deadline = min(deadline - reserve, time.monotonic() + max(55, timeout * (0.42 if scan_mode == "prioritized" else 0.58)))
            strength = "HIGH" if scan_mode in {"prioritized", "full"} else "MEDIUM"
            # The reflected-XSS rule is consistently the slowest targeted rule on
            # authenticated DVWA. Run expensive cases first and reserve a small
            # per-case slice so fast SQLi/CMDi checks cannot consume its budget.
            class_budget = {"xss_reflected": 55.0, "sqli_blind": 32.0, "sqli": 32.0, "command": 26.0, "traversal": 30.0}
            ordered_cases = list(native_cases)
            if scan_mode == "prioritized":
                ordered_cases.sort(key=lambda c: 0 if c.get("zap_case_class") == "xss_reflected" else 1)
            for index, case in enumerate(ordered_cases):
                now = time.monotonic()
                if now + 10 >= active_deadline:
                    break
                remaining = ordered_cases[index + 1:]
                reserve_after = sum(min(class_budget.get(str(item.get("zap_case_class") or ""), 22.0), 32.0) for item in remaining)
                available = max(10.0, active_deadline - now - reserve_after)
                preferred = class_budget.get(str(case.get("zap_case_class") or ""), 28.0)
                per_case = min(75.0 if scan_mode == "full" else 55.0, max(20.0, min(preferred, available)))
                targeted_results.append(_active_scan(zap, case, target_url, internal, min(active_deadline, now + per_case), case_rules.get(str(case.get("url") or ""), []), strength))

        recursive = {"started": False, "completed": True, "progress": 100, "skipped": True}
        if scan_mode == "full" and time.monotonic() + 35 < deadline - 35:
            try: zap.ascan.enable_all_scanners()
            except Exception: pass
            recursive = _recursive_scan(zap, internal, context["context_id"], deadline - 35)
            recursive["skipped"] = False

        cleanup = _stop_active_scans(zap, [str(v.get("scan_id") or "") for v in targeted_results])
        try: zap.ascan.enable_all_scanners()
        except Exception: pass
        passive_completed, passive_remaining = _wait_passive(zap, min(deadline - 20, time.monotonic() + 12))
        phase = "target_recovery"
        recovery = _wait_target_recovery(probe, cookies, min(20, max(5, int(deadline - time.monotonic() - 12))))

        phase = "session_postcheck"
        _configure_cookie(zap, cookies)
        after = _validate_session(zap, zap_url, probe, internal_probe, cookies, parse_cookie_header(cookies))
        findings, stats = _findings(zap, internal, target_url, max_observations)
        existing = {(str(v.get("alert") or "").lower(), str(v.get("url") or ""), str(v.get("parameter") or "").lower()) for v in findings}
        for item in proxy_findings:
            key = (str(item.get("alert") or "").lower(), str(item.get("url") or ""), str(item.get("parameter") or "").lower())
            if key not in existing:
                findings.insert(0, item); existing.add(key)
        stats["proxy_assisted_confirmed"] = len(proxy_findings)
        stats["security_total_returned"] = sum(1 for v in findings if v.get("category") in {"vulnerability", "candidate"})
        try: site_urls = list(zap.core.urls(baseurl=internal) or [])
        except Exception: site_urls = []

        started_targets = sum(bool(v.get("started", True)) for v in targeted_results)
        completed_targets = sum(bool(v.get("completed")) for v in targeted_results if v.get("started", True))
        all_targeted_completed = completed_targets == started_targets
        recursive_completed = bool(recursive.get("completed"))
        timed_out = time.monotonic() >= deadline - 1
        coverage_complete = all_targeted_completed and recursive_completed and spider_completed and passive_completed
        attempted_ids = sorted({sid for v in targeted_results if v.get("started", True) for sid in v.get("scanner_ids", [])})
        completed_ids = sorted({sid for v in targeted_results if v.get("completed") for sid in v.get("scanner_ids", [])})
        if recursive.get("started") and scan_mode == "full":
            attempted_ids = list(active_policy["planned_rule_ids"])
            if recursive.get("completed"):
                completed_ids = list(active_policy["planned_rule_ids"])
        attempted_rules, completed_rules = len(attempted_ids), len(completed_ids)
        coverage = round(100.0 * attempted_rules / planned_rules, 2) if planned_rules else 100.0
        effective_coverage = round(100.0 * completed_rules / planned_rules, 2) if planned_rules else 100.0
        native_plan = {
            "source": "official_zap_ascan_api", "targeted_results": targeted_results, "recursive_results": [recursive] if recursive.get("started") else [],
            "planned_rule_ids": active_policy["planned_rule_ids"], "planned_rule_count": planned_rules,
            "attempted_rule_ids": attempted_ids, "attempted_rule_count": attempted_rules,
            "completed_rule_ids": completed_ids, "completed_rule_count": completed_rules,
            "unattempted_rule_ids": sorted(set(active_policy["planned_rule_ids"]) - set(attempted_ids)), "rule_coverage_percent": coverage,
            "effective_rule_coverage_percent": effective_coverage, "critical_targeted_started": started_targets,
            "critical_targeted_completed": completed_targets, "coverage_complete": coverage_complete, "scan_mode": scan_mode,
        }
        common = {
            "vulnerabilities": findings, "zap_alert_stats": stats, "scan_mode": scan_mode, "zap_version": zap_version,
            "python_zap_api_version": py_version, "zap_target_url": internal, "target_mapping": mapping,
            "duration_seconds": round(time.monotonic() - started, 3), "authenticated": bool(cookies),
            "authentication_effective": before.get("effective") is True and (after.get("effective") is True or after.get("conclusive") is False),
            "session_diagnostics": {"before_scan": before, "after_scan": after}, "context": context,
            **seed_summary, "spider_scan_id": spider_id, "spider_completed": spider_completed, "spider_progress": spider_progress,
            "targeted_active_scans": targeted_results, "targeted_active_scans_started": started_targets,
            "targeted_active_scans_completed": completed_targets, "native_active_coverage_incomplete": not coverage_complete,
            "active_scanner_policy": active_policy, "prioritized_native_plan": native_plan, "active_rules_planned": planned_rules,
            "active_rules_attempted": attempted_rules, "active_rules_completed": completed_rules, "active_rule_coverage_percent": coverage,
            "active_rule_effective_coverage_percent": effective_coverage, "critical_targeted_scans_started": started_targets,
            "critical_targeted_scans_completed": completed_targets, "active_rules_unattempted": native_plan["unattempted_rule_ids"],
            "proxy_assisted_verification": proxy_diagnostics, "proxy_assisted_confirmed": len(proxy_findings),
            "post_spider_target_preparation": post_prepare, "recursive_active_scan": recursive,
            "passive_scan_completed": passive_completed, "passive_records_remaining": passive_remaining,
            "active_scan_cleanup": cleanup, "target_recovery": recovery,
            "session_postcheck_inconclusive": after.get("conclusive") is False, "zap_sites_tree_urls": len(site_urls),
            "destructive_paths_excluded": list(DESTRUCTIVE_PATH_WORDS),
            "deferred_native_active_cases": [{"url": str(case.get("url") or ""), "case_class": str(case.get("zap_case_class") or ""), "reason": "persistent XSS native rule deferred to full/deep; proxy verification still executed"} for case in deferred_native],
            "scan_scope": "Crawler/request traffic is seeded through ZAP. Native spider, passive scan and active scan are driven by the official ZAP API; project-specific response verification is reported separately.",
        }
        if cookies and after.get("conclusive") and after.get("effective") is False:
            return partial("OWASP ZAP", target_url, f"ZAP preserved {len(findings)} findings, but the authenticated session was not valid at final verification.", diagnosis="authentication_lost_during_scan", timed_out=False, time_limit_reached=False, **common)
        if timed_out or not coverage_complete:
            return partial("OWASP ZAP", target_url, f"ZAP preserved {len(findings)} findings with incomplete bounded coverage. Targeted scans={completed_targets}/{started_targets}; site-tree URLs={len(site_urls)}.", diagnosis="time_limit_reached" if timed_out else "active_coverage_incomplete", timed_out=timed_out, time_limit_reached=timed_out, time_limit_phase=phase if timed_out else "", **common)
        return success("OWASP ZAP", target_url, f"ZAP API scan completed. Findings: {len(findings)}; targeted scans={completed_targets}/{started_targets}; site-tree URLs={len(site_urls)}.", timed_out=False, time_limit_reached=False, **common)
    except requests.RequestException as exc:
        result = failure("OWASP ZAP", target_url, f"ZAP HTTP operation failed: {type(exc).__name__}: {exc}", diagnosis="zap_http_operation_failed")
        result.update(duration_seconds=round(time.monotonic() - started, 3), phase=phase, session_diagnostics={"before_scan": before, "after_scan": after})
        return result
    except Exception as exc:
        text = f"{type(exc).__name__}: {exc}"
        low = text.lower()
        diagnosis = "zap_service_unreachable" if "connection refused" in low or "failed to establish" in low else "zap_api_key_or_permissions" if "api key" in low or "unauthorized" in low or "forbidden" in low else "zap_api_error"
        result = failure("OWASP ZAP", target_url, text, diagnosis=diagnosis)
        result.update(duration_seconds=round(time.monotonic() - started, 3), phase=phase, session_diagnostics={"before_scan": before, "after_scan": after})
        return result
    finally:
        if zap is not None:
            _remove_cookie_rule(zap)


if __name__ == "__main__":
    _serve()
