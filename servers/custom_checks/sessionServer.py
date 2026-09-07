from __future__ import annotations

import math
import re
import secrets
import time
from collections import Counter
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qsl, urlparse

import requests

from utils import parse_cookie_header, partial, skipped, success

from utils import same_origin

from core.scannerCommon import bounded_text_similarity, looks_like_login, request_retry, service

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


# Verifies that an authenticated logout endpoint invalidates the old session identifier.
# This check is intentionally called only at the end of an assessment because a successful
# logout can invalidate the server-side session used by the remaining authenticated tools.
@mcp.tool()
def run_logout_check(
    target_url: str, logout_url: str, cookies: str = "", probe_url: str = "",
    method: str = "GET", data: str = "", timeout: int = 20,
) -> dict:

    selected_probe = probe_url or target_url
    if not cookies:
        return skipped("Session Logout Verifier", target_url, "No authenticated session cookie was supplied.")
    if not same_origin(target_url, logout_url) or not same_origin(target_url, selected_probe):
        return skipped("Session Logout Verifier", target_url, "Logout and probe URLs must remain on the assessment target origin.")

    parsed_logout = urlparse(logout_url)
    logout_path = parsed_logout.path.lower()
    logout_query = parse_qsl(parsed_logout.query, keep_blank_values=True)
    logout_shape = (
        bool(re.search(r"(?:^|[-_/])(logout|signout|logoff)(?:\.php)?(?:$|[-_/])", logout_path))
        or any(name.lower() in {"logout", "signout", "logoff"} for name, _ in logout_query)
        or any(any(token in value.lower() for token in ("logout", "signout", "logoff", "sign-out", "log-off")) for _, value in logout_query)
    )
    if not logout_shape:
        return skipped("Session Logout Verifier", logout_url, "The discovered URL is not a recognized logout/signout/logoff endpoint.")
    method = str(method or "GET").upper()
    if method not in {"GET", "POST"}:
        return skipped("Session Logout Verifier", logout_url, "The discovered logout contract is not a bounded GET/POST request.")

    timeout = max(8, min(int(timeout), 40))
    request_timeout = max(3.0, min(8.0, timeout / 4.0))
    common_headers = {"User-Agent": "SecOps-Session-Logout-Verifier/1.0", "Cache-Control": "no-cache"}
    auth_headers = {**common_headers, "Cookie": cookies}

    def fetch(url: str, *, authenticated: bool) -> requests.Response:
        return requests.get(
            url, headers=auth_headers if authenticated else common_headers,
            timeout=(3, request_timeout), allow_redirects=True,
        )

    diagnostics: dict[str, Any] = {"logout_url": logout_url, "probe_url": selected_probe, "method": method}
    try:
        baseline = fetch(selected_probe, authenticated=True)
        anonymous = fetch(selected_probe, authenticated=False)
    except requests.RequestException as exc:
        return partial(
            "Session Logout Verifier", logout_url,
            f"The authenticated/anonymous logout baseline could not be established: {type(exc).__name__}: {exc}",
            diagnosis="logout_baseline_request_failed", vulnerabilities=[], diagnostics=diagnostics,
        )

    baseline_login = looks_like_login(baseline, text_limit=80_000)
    anonymous_login = looks_like_login(anonymous, text_limit=80_000)
    baseline_vs_anonymous = bounded_text_similarity(baseline.text, anonymous.text, text_limit=80_000)
    baseline_distinguished = (
        baseline.status_code < 400 and not baseline_login and (
            anonymous_login
            or anonymous.status_code in {401, 403}
            or str(baseline.url) != str(anonymous.url)
            or baseline_vs_anonymous < 0.92
        )
    )
    diagnostics["baseline"] = {
        "authenticated_status": baseline.status_code, "authenticated_final_url": str(baseline.url),
        "authenticated_login_detected": baseline_login, "anonymous_status": anonymous.status_code,
        "anonymous_final_url": str(anonymous.url), "anonymous_login_detected": anonymous_login,
        "authenticated_vs_anonymous_similarity": round(baseline_vs_anonymous, 4),
        "distinguished": baseline_distinguished,
    }
    if not baseline_distinguished:
        return partial(
            "Session Logout Verifier", logout_url,
            "Logout validation is inconclusive because the supplied authenticated session cannot be reliably distinguished from the anonymous probe before logout.",
            diagnosis="logout_baseline_inconclusive", vulnerabilities=[], diagnostics=diagnostics,
        )

    try:
        logout_response = requests.request(
            method, logout_url, data=data if method == "POST" else None, headers=auth_headers,
            timeout=(3, request_timeout), allow_redirects=True,
        )
    except requests.RequestException as exc:
        return partial(
            "Session Logout Verifier", logout_url,
            f"The logout request could not be completed: {type(exc).__name__}: {exc}",
            diagnosis="logout_request_failed", vulnerabilities=[], diagnostics=diagnostics,
        )
    diagnostics["logout"] = {
        "status": logout_response.status_code, "final_url": str(logout_response.url),
        "login_detected": looks_like_login(logout_response, text_limit=80_000),
        "set_cookie": _set_cookie_headers(logout_response)[:6],
    }
    if logout_response.status_code >= 400:
        return partial(
            "Session Logout Verifier", logout_url,
            f"The discovered logout request returned HTTP {logout_response.status_code}; the recorded logout workflow could not be completed safely.",
            diagnosis="logout_endpoint_not_executable", vulnerabilities=[], diagnostics=diagnostics,
        )

    # Replay the exact pre-logout Cookie header. A client-side deletion alone is insufficient: the
    # old identifier must also stop authorizing requests on the server.
    try:
        replay = fetch(selected_probe, authenticated=True)
    except requests.RequestException as exc:
        return partial(
            "Session Logout Verifier", logout_url,
            f"The old session could not be replayed after logout: {type(exc).__name__}: {exc}",
            diagnosis="logout_replay_request_failed", vulnerabilities=[], diagnostics=diagnostics,
        )

    replay_login = looks_like_login(replay, text_limit=80_000)
    replay_vs_baseline = bounded_text_similarity(replay.text, baseline.text, text_limit=80_000)
    replay_vs_anonymous = bounded_text_similarity(replay.text, anonymous.text, text_limit=80_000)
    invalidated = (
        replay.status_code in {401, 403}
        or replay_login
        or (replay_vs_anonymous >= 0.97 and replay_vs_baseline < 0.94)
    )
    still_authenticated = (
        replay.status_code < 400 and not replay_login and replay_vs_baseline >= 0.94
        and (anonymous_login or anonymous.status_code in {401, 403} or replay_vs_baseline > replay_vs_anonymous + 0.04)
    )
    diagnostics["replay"] = {
        "status": replay.status_code, "final_url": str(replay.url), "login_detected": replay_login,
        "vs_authenticated_baseline_similarity": round(replay_vs_baseline, 4),
        "vs_anonymous_similarity": round(replay_vs_anonymous, 4),
        "invalidated": invalidated, "still_authenticated": still_authenticated,
    }

    if invalidated:
        return success(
            "Session Logout Verifier", logout_url,
            "Logout invalidated the previously authenticated session identifier; replaying the old Cookie header no longer reached the authenticated probe.",
            vulnerabilities=[], diagnostics=diagnostics, logout_verified=True,
        )

    if still_authenticated:
        finding = {
            "alert": "Authenticated session remains usable after logout", "risk": "medium",
            "category": "vulnerability", "verification_status": "logout-old-session-replay-confirmed", "confidence": "high",
            "description": "The application accepted the exact pre-logout session cookie after the logout endpoint completed, and the protected probe remained equivalent to its authenticated baseline.",
            "impact": "A copied or stolen session identifier can remain valid after the user logs out, extending the window for session hijacking and preventing logout from reliably terminating access.",
            "solution": "Invalidate the server-side session on logout, expire the client cookie, and reject replay of the previous session identifier. Add a regression test that reuses the old cookie after logout and expects an unauthenticated response.",
            "url": logout_url, "method": method, "parameter": ",".join(name for name, _ in parse_cookie_header(cookies)),
            "evidence": f"logout_status={logout_response.status_code}; replay_status={replay.status_code}; replay_login_detected={replay_login}; replay_vs_authenticated_baseline={replay_vs_baseline:.3f}; replay_vs_anonymous={replay_vs_anonymous:.3f}",
            "owasp_category": "A07:2021 Identification and Authentication Failures", "cwe_id": "613",
        }
        return success(
            "Session Logout Verifier", logout_url,
            "Logout completed, but replay of the old authenticated session remained valid.",
            vulnerabilities=[finding], diagnostics=diagnostics, logout_verified=True,
        )

    return partial(
        "Session Logout Verifier", logout_url,
        "Logout completed, but the post-logout replay response was not sufficiently similar to either the authenticated or anonymous baseline for a deterministic conclusion.",
        diagnosis="logout_replay_inconclusive", vulnerabilities=[], diagnostics=diagnostics,
    )

if __name__ == "__main__":
    _serve()
