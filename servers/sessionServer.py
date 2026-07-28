from __future__ import annotations

import argparse
import json
import math
import re
import secrets
import sys
from collections import Counter
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlparse

import requests
from fastmcp import FastMCP

from utils import failure, parse_cookie_header, skipped, success

mcp = FastMCP("Session Security Analyzer")




SESSION_COOKIE_RE = re.compile(
    r"(?:^|[_\-.])(?:session|sess|sid|phpsessid|jsessionid|connect\.sid|auth|identity|remember|login)(?:$|[_\-.])",
    re.I,
)
NON_SESSION_COOKIE_NAMES = {
    "security", "theme", "lang", "language", "locale", "consent",
    "csrftoken", "csrf", "xsrf-token", "timezone", "tz", "preferences",
}


def _is_session_cookie_name(name: str) -> bool:
    lowered = str(name or "").strip().lower()
    if not lowered or lowered in NON_SESSION_COOKIE_NAMES:
        return False
    return bool(SESSION_COOKIE_RE.search(lowered))


def _session_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if _is_session_cookie_name(str(row.get("name") or ""))]

def _same_origin(left: str, right: str) -> bool:
    a, b = urlparse(left), urlparse(right)
    return (a.scheme.lower(), a.hostname, a.port or (443 if a.scheme == "https" else 80)) == (
        b.scheme.lower(), b.hostname, b.port or (443 if b.scheme == "https" else 80)
    )


def _looks_like_login(response: requests.Response) -> bool:
    text = response.text[:60_000].lower()
    path = urlparse(str(response.url)).path.lower().rstrip("/")
    return path.endswith(("/login", "/login.php", "/signin", "/auth")) or (
        ("type=\"password\"" in text or "type='password'" in text) and any(word in text for word in ("login", "sign in", "authenticate"))
    )


def _set_cookie_headers(response: requests.Response) -> list[str]:
    raw = getattr(response.raw, "headers", None)
    if raw is not None and hasattr(raw, "get_all"):
        values = raw.get_all("Set-Cookie") or []
        if values:
            return [str(value) for value in values]
    value = response.headers.get("Set-Cookie")
    return [str(value)] if value else []


def _parse_set_cookie(header: str) -> list[dict[str, Any]]:
    cookie = SimpleCookie()
    try:
        cookie.load(header)
    except Exception:
        return []
    rows: list[dict[str, Any]] = []
    for name, morsel in cookie.items():
        rows.append({
            "name": name,
            "value_length": len(morsel.value),
            "secure": bool(morsel["secure"]),
            "httponly": bool(morsel["httponly"]),
            "samesite": str(morsel["samesite"] or ""),
            "path": str(morsel["path"] or ""),
            "domain": str(morsel["domain"] or ""),
            "max_age": str(morsel["max-age"] or ""),
            "expires": str(morsel["expires"] or ""),
        })
    return rows


def _entropy_per_character(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _cookie_attribute_findings(url: str, rows: list[dict[str, Any]], https: bool) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for row in _session_rows(rows):
        name = str(row.get("name") or "")
        if not name:
            continue
        evidence = (
            f"cookie={name}; Secure={row.get('secure')}; HttpOnly={row.get('httponly')}; "
            f"SameSite={row.get('samesite') or 'not supplied'}; Path={row.get('path') or 'not supplied'}; "
            f"Domain={row.get('domain') or 'host-only'}"
        )
        if not row.get("httponly"):
            findings.append({
                "alert": f"Session cookie '{name}' lacks HttpOnly",
                "risk": "low",
                "category": "candidate",
                "verification_status": "response-header-observation",
                "confidence": "high",
                "description": "A cookie issued by the application did not include the HttpOnly attribute.",
                "impact": "Client-side script execution could read the cookie, increasing the impact of cross-site scripting.",
                "solution": "Set HttpOnly on session and authentication cookies unless client-side access is explicitly required.",
                "url": url,
                "method": "GET",
                "parameter": name,
                "evidence": evidence,
                "owasp_category": "A07:2021 Identification and Authentication Failures",
                "cwe_id": "1004",
            })
        if https and not row.get("secure"):
            findings.append({
                "alert": f"Session cookie '{name}' lacks Secure",
                "risk": "medium",
                "category": "candidate",
                "verification_status": "response-header-observation",
                "confidence": "high",
                "description": "A cookie issued over HTTPS did not include the Secure attribute.",
                "impact": "The cookie may be transmitted over an unencrypted HTTP connection if the application or browser is directed to one.",
                "solution": "Set Secure on session and authentication cookies and enforce HTTPS.",
                "url": url,
                "method": "GET",
                "parameter": name,
                "evidence": evidence,
                "owasp_category": "A07:2021 Identification and Authentication Failures",
                "cwe_id": "614",
            })
        if not str(row.get("samesite") or "").strip():
            findings.append({
                "alert": f"Session cookie '{name}' lacks SameSite",
                "risk": "low",
                "category": "candidate",
                "verification_status": "response-header-observation",
                "confidence": "high",
                "description": "A cookie issued by the application did not declare a SameSite policy.",
                "impact": "Cross-site requests may include the cookie depending on browser defaults, increasing CSRF exposure.",
                "solution": "Set SameSite=Lax or Strict where compatible; use SameSite=None only with Secure when cross-site use is required.",
                "url": url,
                "method": "GET",
                "parameter": name,
                "evidence": evidence,
                "owasp_category": "A01:2021 Broken Access Control",
                "cwe_id": "1275",
            })
    return findings


@mcp.tool()
def run_session_scan(
    target_url: str,
    cookies: str = "",
    probe_url: str = "",
    timeout: int = 30,
    sample_count: int = 5,
) -> dict:
    """Analyze cookie flags, bounded anonymous session uniqueness and fixation indicators."""
    selected_probe = probe_url or target_url
    if not _same_origin(target_url, selected_probe):
        selected_probe = target_url
    timeout = max(5, min(int(timeout), 60))
    sample_count = max(3, min(int(sample_count), 10))
    findings: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {"probe_url": selected_probe, "sample_count": sample_count}

    try:
        baseline = requests.get(
            selected_probe,
            timeout=(4, timeout),
            allow_redirects=True,
            headers={"User-Agent": "SecOps-Session-Analyzer/1.0", "Cache-Control": "no-cache"},
        )
    except requests.RequestException as exc:
        return failure("Session Security Analyzer", target_url, f"Anonymous session probe failed: {exc}", diagnosis="request_failed")

    set_cookie_rows: list[dict[str, Any]] = []
    for header in _set_cookie_headers(baseline):
        set_cookie_rows.extend(_parse_set_cookie(header))
    diagnostics["anonymous_set_cookie"] = set_cookie_rows
    findings.extend(_cookie_attribute_findings(str(baseline.url), set_cookie_rows, urlparse(str(baseline.url)).scheme == "https"))

    supplied_names = [name for name, _ in parse_cookie_header(cookies)] if cookies else []
    supplied_session_names = [name for name in supplied_names if _is_session_cookie_name(name)]
    diagnostics["supplied_cookie_names"] = supplied_names
    diagnostics["supplied_session_cookie_names"] = supplied_session_names
    if cookies:
        try:
            authenticated = requests.get(
                selected_probe,
                timeout=(4, timeout),
                allow_redirects=True,
                headers={
                    "User-Agent": "SecOps-Session-Analyzer/1.0",
                    "Cache-Control": "no-cache",
                    "Cookie": cookies,
                },
            )
            authenticated_rows: list[dict[str, Any]] = []
            for header in _set_cookie_headers(authenticated):
                authenticated_rows.extend(_parse_set_cookie(header))
            diagnostics["authenticated_probe"] = {
                "status": authenticated.status_code,
                "final_url": str(authenticated.url),
                "login_detected": _looks_like_login(authenticated),
                "set_cookie": authenticated_rows,
            }
            findings.extend(_cookie_attribute_findings(str(authenticated.url), authenticated_rows, urlparse(str(authenticated.url)).scheme == "https"))
        except requests.RequestException as exc:
            diagnostics["authenticated_probe_error"] = f"{type(exc).__name__}: {exc}"

    samples: dict[str, list[str]] = {}
    for _ in range(sample_count):
        session = requests.Session()
        try:
            response = session.get(
                selected_probe,
                timeout=(4, timeout),
                allow_redirects=True,
                headers={"User-Agent": "SecOps-Session-Analyzer/1.0", "Cache-Control": "no-cache"},
            )
        except requests.RequestException:
            continue
        for cookie in session.cookies:
            samples.setdefault(str(cookie.name), []).append(str(cookie.value))
    diagnostics["anonymous_cookie_samples"] = {
        name: {
            "count": len(values),
            "unique": len(set(values)),
            "lengths": sorted(set(len(value) for value in values)),
            "minimum_entropy_per_character": round(min((_entropy_per_character(value) for value in values), default=0.0), 3),
        }
        for name, values in samples.items()
    }

    for name, values in samples.items():
        if not _is_session_cookie_name(name):
            continue
        if len(values) >= 3 and len(set(values)) < len(values):
            findings.append({
                "alert": f"Repeated session identifier observed for cookie '{name}'",
                "risk": "high",
                "category": "candidate",
                "verification_status": "bounded-session-sampling",
                "confidence": "medium",
                "description": "Multiple fresh anonymous sessions received a repeated cookie value during bounded sampling.",
                "impact": "Predictable or reused session identifiers can enable session hijacking or user-session collisions.",
                "solution": "Generate session identifiers with a cryptographically secure random generator and rotate them at authentication boundaries.",
                "url": selected_probe,
                "method": "GET",
                "parameter": name,
                "evidence": f"samples={len(values)}; unique={len(set(values))}; lengths={sorted(set(len(value) for value in values))}",
                "owasp_category": "A07:2021 Identification and Authentication Failures",
                "cwe_id": "330",
            })
        elif values and min(len(value) for value in values) < 16:
            findings.append({
                "alert": f"Short session identifier observed for cookie '{name}'",
                "risk": "low",
                "category": "candidate",
                "verification_status": "bounded-session-sampling",
                "confidence": "low",
                "description": "Fresh anonymous session identifiers were shorter than 16 characters. Length alone does not establish predictability.",
                "impact": "A small effective identifier space may make guessing more practical if generation is also weak.",
                "solution": "Use framework-provided cryptographically secure session identifiers with sufficient entropy.",
                "url": selected_probe,
                "method": "GET",
                "parameter": name,
                "evidence": f"lengths={sorted(set(len(value) for value in values))}; unique={len(set(values))}/{len(values)}",
                "owasp_category": "A07:2021 Identification and Authentication Failures",
            })

    # Bounded anonymous fixation indicator: check whether an arbitrary supplied value is
    # accepted without rotation. This is not a full fixation proof because no login is performed.
    if supplied_session_names:
        fixation_rows: list[dict[str, Any]] = []
        for name in supplied_session_names[:3]:
            chosen = "SECOPS" + secrets.token_hex(12)
            try:
                response = requests.get(
                    selected_probe,
                    timeout=(4, timeout),
                    allow_redirects=True,
                    headers={
                        "User-Agent": "SecOps-Session-Analyzer/1.0",
                        "Cache-Control": "no-cache",
                        "Cookie": f"{name}={chosen}",
                    },
                )
            except requests.RequestException:
                continue
            returned = response.cookies.get(name, "")
            rotated = bool(returned and returned != chosen)
            echoed = bool(returned and returned == chosen)
            fixation_rows.append({
                "cookie": name,
                "status": response.status_code,
                "returned_cookie": bool(returned),
                "rotated": rotated,
                "echoed_attacker_value": echoed,
            })
            if echoed:
                findings.append({
                    "alert": f"Potential session fixation behavior for cookie '{name}'",
                    "risk": "medium",
                    "category": "candidate",
                    "verification_status": "server-echoed-attacker-session-id-needs-login-validation",
                    "confidence": "medium",
                    "description": "The server explicitly returned the attacker-chosen session identifier instead of rotating it. A full fixation proof still requires authentication with that identifier.",
                    "impact": "If the identifier survives authentication, an attacker who planted it could reuse the victim's authenticated session.",
                    "solution": "Regenerate the session identifier after authentication and privilege changes, and reject unknown externally supplied identifiers.",
                    "url": selected_probe,
                    "method": "GET",
                    "parameter": name,
                    "evidence": f"HTTP {response.status_code}; response Set-Cookie echoed the attacker value; login_detected={_looks_like_login(response)}",
                    "owasp_category": "A07:2021 Identification and Authentication Failures",
                    "cwe_id": "384",
                })
        diagnostics["fixation_indicators"] = fixation_rows

    if not _session_rows(set_cookie_rows) and not any(_is_session_cookie_name(name) for name in samples) and not supplied_session_names:
        return skipped("Session Security Analyzer", target_url, "No cookie or session identifier was observed or supplied.")

    return success(
        "Session Security Analyzer",
        target_url,
        f"Session analysis completed. Findings: {len(findings)}.",
        vulnerabilities=findings,
        diagnostics=diagnostics,
    )


def _once() -> int:
    try:
        arguments = json.loads(sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = run_session_scan(**arguments)
    except Exception as exc:
        result = failure("Session Security Analyzer", "", f"One-shot session analysis failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio", show_banner=False)
