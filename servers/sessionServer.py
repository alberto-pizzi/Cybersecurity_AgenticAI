from __future__ import annotations

import math
import re
import secrets
import time
from collections import Counter
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlparse

import requests

from utils import parse_cookie_header, skipped, success

from utils import same_origin

from scannerCommon import looks_like_login, request_retry, service

mcp, _serve = service("Session Security Analyzer", "session")

SESSION_COOKIE_RE = re.compile(
    r"(?:^|[_\-.])(?:session|sess|sid|phpsessid|jsessionid|connect\.sid|auth|identity|remember|login)(?:$|[_\-.])", re.I,
)
NON_SESSION_COOKIE_NAMES = {
    "security", "theme", "lang", "language", "locale", "consent",
    "csrftoken", "csrf", "xsrf-token", "timezone", "tz", "preferences",
}

# Check whether session cookie name matches the condition required by this scan path.
def _is_session_cookie_name(name: str) -> bool:
    lowered = str(name or "").strip().lower()
    if not lowered or lowered in NON_SESSION_COOKIE_NAMES:
        return False
    return bool(SESSION_COOKIE_RE.search(lowered))

# Extract session-cookie rows from response metadata for bounded session analysis.
def _session_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if _is_session_cookie_name(str(row.get("name") or ""))]

# Process set cookie headers for authenticated scanner requests and session analysis.
def _set_cookie_headers(response: requests.Response) -> list[str]:
    raw = getattr(response.raw, "headers", None)
    if raw is not None and hasattr(raw, "get_all"):
        values = raw.get_all("Set-Cookie") or []
        if values:
            return [str(value) for value in values]
    value = response.headers.get("Set-Cookie")
    return [str(value)] if value else []

# Parse set cookie into normalized data used by the scanner wrapper.
def _parse_set_cookie(header: str) -> list[dict[str, Any]]:
    cookie = SimpleCookie()
    try:
        cookie.load(header)
    except Exception:
        return []
    rows: list[dict[str, Any]] = []
    for name, morsel in cookie.items():
        rows.append({
            "name": name, "value_length": len(morsel.value), "secure": bool(morsel["secure"]), "httponly": bool(morsel["httponly"]),
            "samesite": str(morsel["samesite"] or ""), "path": str(morsel["path"] or ""),
            "domain": str(morsel["domain"] or ""), "max_age": str(morsel["max-age"] or ""), "expires": str(morsel["expires"] or ""),
        })
    return rows

# Estimate per-character entropy to flag weak or predictable session identifiers.
def _entropy_per_character(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())

# Create findings for missing or weak security attributes on session cookies.
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
                "alert": f"Session cookie '{name}' lacks HttpOnly", "risk": "low",
                "category": "candidate", "verification_status": "response-header-observation", "confidence": "high",
                "description": "A cookie issued by the application did not include the HttpOnly attribute.",
                "impact": "Client-side script execution could read the cookie, increasing the impact of cross-site scripting.",
                "solution": "Set HttpOnly on session and authentication cookies unless client-side access is explicitly required.",
                "url": url, "method": "GET", "parameter": name, "evidence": evidence,
                "owasp_category": "A07:2021 Identification and Authentication Failures", "cwe_id": "1004",
            })
        if https and not row.get("secure"):
            findings.append({
                "alert": f"Session cookie '{name}' lacks Secure", "risk": "medium",
                "category": "candidate", "verification_status": "response-header-observation", "confidence": "high",
                "description": "A cookie issued over HTTPS did not include the Secure attribute.",
                "impact": "The cookie may be transmitted over an unencrypted HTTP connection if the application or browser is directed to one.",
                "solution": "Set Secure on session and authentication cookies and enforce HTTPS.", "url": url,
                "method": "GET", "parameter": name,
                "evidence": evidence, "owasp_category": "A07:2021 Identification and Authentication Failures", "cwe_id": "614",
            })
        if not str(row.get("samesite") or "").strip():
            findings.append({
                "alert": f"Session cookie '{name}' lacks SameSite", "risk": "low",
                "category": "candidate", "verification_status": "response-header-observation", "confidence": "high",
                "description": "A cookie issued by the application did not declare a SameSite policy.",
                "impact": "Cross-site requests may include the cookie depending on browser defaults, increasing CSRF exposure.",
                "solution": "Set SameSite=Lax or Strict where compatible; use SameSite=None only with Secure when cross-site use is required.",
                "url": url, "method": "GET", "parameter": name, "evidence": evidence,
                "owasp_category": "A01:2021 Broken Access Control", "cwe_id": "1275",
            })
    return findings

# Analyze cookie flags, bounded anonymous session uniqueness and fixation indicators.
@mcp.tool()
def run_session_scan(
    target_url: str, cookies: str = "", probe_url: str = "", timeout: int = 30, sample_count: int = 5,
) -> dict:

    selected_probe = probe_url or target_url
    if not same_origin(target_url, selected_probe):
        selected_probe = target_url
    timeout = max(5, min(int(timeout), 60))
    sample_count = max(3, min(int(sample_count), 10))

    deadline = time.monotonic() + max(4.0, timeout - 5.0)
    request_timeout = max(2.0, min(3.0, (timeout - 6.0) / max(5, sample_count + 3)))
    request_cost = 2.0 + request_timeout
    findings: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {"probe_url": selected_probe, "sample_count": sample_count, "request_timeout": round(request_timeout, 2)}

    # Evaluate cookie attributes first, then use bounded samples for uniqueness and fixation indicators.
    baseline: requests.Response | None = None
    try:
        baseline = request_retry(
            "GET", selected_probe, attempts=2, backoff=0.25, timeout=(2, request_timeout), allow_redirects=True,
            headers={"User-Agent": "SecOps-Session-Analyzer/1.0", "Cache-Control": "no-cache"},
        )
    except requests.RequestException as exc:
        diagnostics["anonymous_probe_error"] = f"{type(exc).__name__}: {exc}"

    set_cookie_rows: list[dict[str, Any]] = []
    if baseline is not None:
        for header in _set_cookie_headers(baseline):
            set_cookie_rows.extend(_parse_set_cookie(header))
        findings.extend(_cookie_attribute_findings(str(baseline.url), set_cookie_rows, urlparse(str(baseline.url)).scheme == "https"))
    diagnostics["anonymous_set_cookie"] = set_cookie_rows

    supplied_names = [name for name, _ in parse_cookie_header(cookies)] if cookies else []
    supplied_session_names = [name for name in supplied_names if _is_session_cookie_name(name)]
    diagnostics["supplied_cookie_names"] = supplied_names
    diagnostics["supplied_session_cookie_names"] = supplied_session_names
    if cookies:
        try:
            authenticated = request_retry(
                "GET", selected_probe, attempts=2, backoff=0.2, timeout=(2, request_timeout), allow_redirects=True,
                headers={"User-Agent": "SecOps-Session-Analyzer/1.0", "Cache-Control": "no-cache", "Cookie": cookies},
            )
            authenticated_rows: list[dict[str, Any]] = []
            for header in _set_cookie_headers(authenticated):
                authenticated_rows.extend(_parse_set_cookie(header))
            diagnostics["authenticated_probe"] = {
                "status": authenticated.status_code, "final_url": str(authenticated.url),
                "login_detected": looks_like_login(authenticated, text_limit=60_000, paths=("/login", "/login.php", "/signin", "/auth"), words=("login", "sign in", "authenticate")),
                "set_cookie": authenticated_rows,
            }
            findings.extend(_cookie_attribute_findings(str(authenticated.url), authenticated_rows, urlparse(str(authenticated.url)).scheme == "https"))
        except requests.RequestException as exc:
            diagnostics["authenticated_probe_error"] = f"{type(exc).__name__}: {exc}"

    # Sample fresh anonymous sessions to detect obvious reuse, short identifiers or weak entropy.
    samples: dict[str, list[str]] = {}
    for _ in range(sample_count):
        if time.monotonic() + request_cost >= deadline:
            break
        session = requests.Session()
        try:
            response = session.get(
                selected_probe, timeout=(2, request_timeout), allow_redirects=True,
                headers={"User-Agent": "SecOps-Session-Analyzer/1.0", "Cache-Control": "no-cache"},
            )
        except requests.RequestException:
            continue
        for cookie in session.cookies:
            samples.setdefault(str(cookie.name), []).append(str(cookie.value))
    diagnostics["anonymous_cookie_samples"] = {
        name: {
            "count": len(values), "unique": len(set(values)), "lengths": sorted(set(len(value) for value in values)),
            "minimum_entropy_per_character": round(min((_entropy_per_character(value) for value in values), default=0.0), 3),
        }
        for name, values in samples.items()
    }

    for name, values in samples.items():
        if not _is_session_cookie_name(name):
            continue
        if len(values) >= 3 and len(set(values)) < len(values):
            findings.append({
                "alert": f"Repeated session identifier observed for cookie '{name}'", "risk": "high",
                "category": "candidate", "verification_status": "bounded-session-sampling", "confidence": "medium",
                "description": "Multiple fresh anonymous sessions received a repeated cookie value during bounded sampling.",
                "impact": "Predictable or reused session identifiers can enable session hijacking or user-session collisions.",
                "solution": "Generate session identifiers with a cryptographically secure random generator and rotate them at authentication boundaries.",
                "url": selected_probe, "method": "GET", "parameter": name,
                "evidence": f"samples={len(values)}; unique={len(set(values))}; lengths={sorted(set(len(value) for value in values))}",
                "owasp_category": "A07:2021 Identification and Authentication Failures", "cwe_id": "330",
            })
        elif values and min(len(value) for value in values) < 16:
            findings.append({
                "alert": f"Short session identifier observed for cookie '{name}'", "risk": "low",
                "category": "candidate", "verification_status": "bounded-session-sampling", "confidence": "low",
                "description": "Fresh anonymous session identifiers were shorter than 16 characters. Length alone does not establish predictability.",
                "impact": "A small effective identifier space may make guessing more practical if generation is also weak.",
                "solution": "Use framework-provided cryptographically secure session identifiers with sufficient entropy.",
                "url": selected_probe, "method": "GET", "parameter": name,
                "evidence": f"lengths={sorted(set(len(value) for value in values))}; unique={len(set(values))}/{len(values)}",
                "owasp_category": "A07:2021 Identification and Authentication Failures",
            })

    if supplied_session_names:
        fixation_rows: list[dict[str, Any]] = []
        for name in supplied_session_names[:3]:
            if time.monotonic() + request_cost >= deadline:
                break
            chosen = "SECOPS" + secrets.token_hex(12)
            try:
                response = requests.get(
                    selected_probe, timeout=(2, request_timeout), allow_redirects=True,
                    headers={
                        "User-Agent": "SecOps-Session-Analyzer/1.0", "Cache-Control": "no-cache", "Cookie": f"{name}={chosen}",
                    },
                )
            except requests.RequestException:
                continue
            returned = response.cookies.get(name, "")
            rotated = bool(returned and returned != chosen)
            echoed = bool(returned and returned == chosen)
            fixation_rows.append({
                "cookie": name, "status": response.status_code, "returned_cookie": bool(returned), "rotated": rotated,
                "echoed_attacker_value": echoed,
            })
            if echoed:
                findings.append({
                    "alert": f"Potential session fixation behavior for cookie '{name}'", "risk": "medium", "category": "candidate",
                    "verification_status": "server-echoed-attacker-session-id-needs-login-validation", "confidence": "medium",
                    "description": "The server explicitly returned the attacker-chosen session identifier instead of rotating it. A full fixation proof still requires authentication with that identifier.",
                    "impact": "If the identifier survives authentication, an attacker who planted it could reuse the victim's authenticated session.",
                    "solution": "Regenerate the session identifier after authentication and privilege changes, and reject unknown externally supplied identifiers.",
                    "url": selected_probe, "method": "GET", "parameter": name,
                    "evidence": f"HTTP {response.status_code}; response Set-Cookie echoed the attacker value; login_detected={looks_like_login(response, text_limit=60_000, paths=("/login", "/login.php", "/signin", "/auth"), words=("login", "sign in", "authenticate"))}",
                    "owasp_category": "A07:2021 Identification and Authentication Failures", "cwe_id": "384",
                })
        diagnostics["fixation_indicators"] = fixation_rows

    diagnostics["completed_anonymous_samples"] = sum(len(values) for values in samples.values())
    diagnostics["budget_exhausted"] = time.monotonic() >= deadline

    if not _session_rows(set_cookie_rows) and not any(_is_session_cookie_name(name) for name in samples) and not supplied_session_names:
        return skipped("Session Security Analyzer", target_url, "No cookie or session identifier was observed or supplied.")

    return success(
        "Session Security Analyzer", target_url,
        f"Session analysis completed. Findings: {len(findings)}.", vulnerabilities=findings, diagnostics=diagnostics,
    )

if __name__ == "__main__":
    _serve()
