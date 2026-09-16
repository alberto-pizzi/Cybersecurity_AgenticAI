from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

from utils import MAX_AUTHENTICATED_IDENTITIES, RequestRatePacer, canonical_cookie_header, cookie_header_fingerprint, partial, request_contract_state_change_reason, skipped, success

from utils import same_origin

from core.scannerCommon import bounded_text_similarity, looks_like_login, proportional_budget, remaining_budget, service, wall_clock_deadline

mcp, _serve = service("Authorization Differential Verifier", "authorization")

AUTHORIZATION_IDENTITY_RATIO = 0.30

PUBLIC_CONTENT_RE = re.compile(
    r"(?:^|/)(?:docs?|documentation|instructions?|help|about|changelog|license|copying|readme|static|assets?)(?:/|$)", re.I,
)
AUTHZ_PATH_RE = re.compile(
    r"(?:^|/)(?:admin|accounts?|profiles?|users?|members?|orders?|invoices?|documents?|downloads?|reports?|records?|settings|manage(?:ment)?|roles?|permissions?|api|private|internal|dashboard|billing|payments?)(?:/|$)",
    re.I,
)
AUTHZ_PARAMETER_RE = re.compile(
    r"^(?:id|uid|user_id|userid|account_id|member_id|profile_id|order_id|invoice_id|document_id|record_id|file_id|report_id|customer_id|owner_id|tenant_id|role_id)$",
    re.I,
)

# Score request contracts so authorization-sensitive endpoints are checked first.
def _authorization_relevance(target_url: str, parameters: list[str] | None) -> tuple[int, list[str]]:
    parsed = urlparse(target_url)
    reasons: list[str] = []
    score = 0
    if PUBLIC_CONTENT_RE.search(parsed.path):
        reasons.append("public-content-path")
        score -= 100
    if AUTHZ_PATH_RE.search(parsed.path):
        reasons.append("authorization-sensitive-path")
        score += 45
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    names = {str(value).lower() for value in (parameters or []) if str(value)}
    names.update(name.lower() for name, _ in pairs)
    auth_names = sorted(name for name in names if AUTHZ_PARAMETER_RE.fullmatch(name))
    if auth_names:
        reasons.append("object-identifier-parameter=" + ",".join(auth_names))
        score += 35 + 8 * len(auth_names)
    if any(value.isdigit() and AUTHZ_PARAMETER_RE.fullmatch(name) for name, value in pairs):
        reasons.append("numeric-object-reference")
        score += 25
    return score, reasons

# Issue a read-only GET for one identity while keeping the request bounded and same-origin.
def _safe_get(url: str, cookies: str, request_budget: float, pacer: RequestRatePacer, deadline: float) -> tuple[requests.Response | None, str]:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SecOps-Authorization-Differential/1.0",
        "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.5", "Cache-Control": "no-cache",
    })
    if cookies:
        session.headers["Cookie"] = cookies
    current, seen = url, set()
    for _ in range(3):
        if remaining_budget(deadline) <= 0:
            return None, "time_limit_reached"
        if not same_origin(url, current):
            return None, "cross_origin_blocked"
        state_reason = request_contract_state_change_reason({"url": current, "method": "GET", "data": "", "parameters": []})
        if state_reason:
            return None, "state_change_target_blocked:" + state_reason
        try:
            pacer.wait()
            left = max(1.0, min(float(request_budget), remaining_budget(deadline)))
            response = session.get(current, timeout=(max(1.0, left * 0.25), left), allow_redirects=False)
        except requests.RequestException as exc:
            return None, f"transport_unavailable:{type(exc).__name__}"
        if response.status_code not in {301, 302, 303, 307, 308}:
            response.url = current
            return response, ""
        location = str(response.headers.get("Location") or "").strip()
        if not location:
            response.url = current
            return response, ""
        candidate = urljoin(current, location)
        if not same_origin(url, candidate):
            response.url = current
            return response, "cross_origin_redirect_blocked"
        state_reason = request_contract_state_change_reason({"url": candidate, "method": "GET", "data": "", "parameters": []})
        if state_reason:
            response.url = current
            return response, "state_change_redirect_blocked:" + state_reason
        if candidate in seen:
            response.url = current
            return response, "redirect_loop"
        seen.add(current)
        current = candidate
    response.url = current
    return response, "redirect_limit"

# Build a compact summary used for differential checks and execution diagnostics.
def _summary(response: requests.Response | None, guard: str) -> dict[str, Any]:
    if response is None:
        return {"available": False, "guard": guard}
    content = response.content
    return {
        "available": True, "status": response.status_code, "final_url": str(response.url), "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "login_detected": looks_like_login(response, text_limit=80_000), "guard": guard,
        "content_type": str(response.headers.get("Content-Type") or ""),
    }

# Measure response similarity to support bounded authorization and differential checks.
def _similarity(left: requests.Response, right: requests.Response) -> float:
    if left.content == right.content:
        return 1.0
    return bounded_text_similarity(left.text, right.text, text_limit=80_000, chunk_size=128)

# Compare access to determine whether the expected access behavior is present.
def _matching_access(
    primary: requests.Response, alternate: requests.Response,
) -> tuple[bool, float, float]:
    similarity = _similarity(primary, alternate)
    length_ratio = (
        min(len(primary.content), len(alternate.content))
        / max(1, max(len(primary.content), len(alternate.content)))
    )
    accepted = (
        primary.status_code < 400
        and alternate.status_code < 400
        and not looks_like_login(primary, text_limit=80_000)
        and not looks_like_login(alternate, text_limit=80_000)
        and similarity >= 0.965
        and length_ratio >= 0.90
    )
    return accepted, similarity, length_ratio

# Convert scanner evidence into a normalized security finding.
def _finding(
    target_url: str, alternate_label: str, primary: requests.Response, alternate: requests.Response,
    similarity: float, length_ratio: float,
) -> dict[str, Any]:
    anonymous = alternate_label == "anonymous"
    return {
        "alert": (
            "Potential missing authentication or object authorization"
            if anonymous
            else "Potential cross-account authorization weakness"
        ),
        "risk": "medium", "category": "candidate",
        "verification_status": (
            "anonymous-authenticated-response-equivalence-needs-resource-validation"
            if anonymous
            else "two-account-response-equivalence-needs-ownership-validation"
        ),
        "confidence": "medium" if not anonymous else "low",
        "description": (
            "The anonymous request returned a successful response closely matching the authenticated response on a high-value discovered endpoint."
            if anonymous
            else "A second authenticated identity returned a successful response closely matching the primary identity for the same high-value object request."
        ),
        "impact": (
            "If the endpoint is intended to require authentication or object ownership, an attacker may access protected data or functions without the required identity."
            if anonymous
            else "If the requested object belongs only to the primary identity, another authenticated user may be able to access it without object-level authorization."
        ),
        "solution": "Enforce authentication and object/function-level authorization on every request, deny by default, and validate with accounts that own different objects and roles.",
        "url": target_url, "method": "GET",
        "evidence": (
            f"alternate={alternate_label}; primary_status={primary.status_code}; "
            f"alternate_status={alternate.status_code}; response_similarity={similarity:.4f}; "
            f"length_ratio={length_ratio:.4f}; primary_bytes={len(primary.content)}; "
            f"alternate_bytes={len(alternate.content)}"
        ),
        "owasp_category": "A01:2021 Broken Access Control", "cwe_id": "639" if not anonymous else "862",
    }

# Compare a read-only GET under primary, secondary and anonymous identities.
@mcp.tool()
def run_authorization_scan(
    target_url: str, cookies: str = "", secondary_cookies: str = "", identity_cookies: list[str] | None = None,
    identity_labels: list[str] | None = None, method: str = "GET", data: str = "", parameters: list[str] | None = None,
    timeout: int = 30, request_rate: float | None = None,
) -> dict:

    method = str(method or "GET").upper()
    if method != "GET":
        return skipped(
            "Authorization Differential Verifier", target_url,
            "Authorization differential checks are intentionally limited to read-only GET requests.",
        )
    state_reason = request_contract_state_change_reason({"url": target_url, "method": "GET", "data": "", "parameters": parameters or []})
    if state_reason:
        return skipped(
            "Authorization Differential Verifier", target_url,
            f"Authorization request blocked by read-only state policy: {state_reason}.", diagnosis="state_change_policy_blocked",
        )
    if not cookies:
        return skipped(
            "Authorization Differential Verifier", target_url,
            "A primary authenticated Cookie header is required for authorization comparison.",
        )
    timeout = max(5, min(int(timeout), 180))
    deadline = wall_clock_deadline(timeout)
    pacer = RequestRatePacer(request_rate)
    relevance_score, relevance_reasons = _authorization_relevance(target_url, parameters)
    raw_identity_cookies = list(identity_cookies or [])
    raw_identity_labels = list(identity_labels or [])
    alternate_pairs: list[tuple[str, str]] = []
    seen_alternate_sessions: set[str] = set()
    try:
        primary_canonical = canonical_cookie_header(cookies)
        primary_fingerprint = cookie_header_fingerprint(primary_canonical)
    except ValueError as exc:
        return skipped(
            "Authorization Differential Verifier", target_url,
            f"Primary Cookie header is invalid: {exc}", diagnosis="invalid_cookie_header",
        )
    invalid_alternate_labels: list[str] = []
    for index, raw_cookie in enumerate(raw_identity_cookies):
        value = str(raw_cookie or "").strip()
        if not value:
            continue
        label = str(raw_identity_labels[index] if index < len(raw_identity_labels) else "").strip() or f"identity_{index + 2}"
        try:
            canonical = canonical_cookie_header(value)
            fingerprint = cookie_header_fingerprint(canonical)
        except ValueError:
            invalid_alternate_labels.append(label)
            continue
        if not canonical or fingerprint == primary_fingerprint or fingerprint in seen_alternate_sessions:
            continue
        alternate_pairs.append((label, canonical))
        seen_alternate_sessions.add(fingerprint)
    if secondary_cookies:
        try:
            secondary_canonical = canonical_cookie_header(secondary_cookies)
            secondary_fingerprint = cookie_header_fingerprint(secondary_canonical)
        except ValueError:
            secondary_canonical = ""
            secondary_fingerprint = ""
            invalid_alternate_labels.append("secondary")
        if secondary_canonical and secondary_fingerprint != primary_fingerprint and secondary_fingerprint not in seen_alternate_sessions:
            alternate_pairs.append(("secondary", secondary_canonical))
            seen_alternate_sessions.add(secondary_fingerprint)
    max_alternates = max(0, MAX_AUTHENTICATED_IDENTITIES - 1)
    if len(alternate_pairs) > max_alternates:
        return skipped(
            "Authorization Differential Verifier", target_url,
            f"Too many alternate authenticated identities ({len(alternate_pairs)}); at most {max_alternates} alternates plus the primary identity are supported.",
            diagnosis="authenticated_identity_limit_exceeded",
        )
    labels = [label for label, _ in alternate_pairs]
    supplied_alternates = [value for _, value in alternate_pairs]
    if relevance_score <= 0 and not supplied_alternates:
        return skipped(
            "Authorization Differential Verifier", target_url,
            "The request resembles public/static documentation and has no object or identity reference suitable for an authorization differential.",
            diagnosis="authorization_candidate_not_relevant", relevance_score=relevance_score, relevance_reasons=relevance_reasons,
        )
    planned_identity_requests = max(2, 2 + len(supplied_alternates))
    # Keep the action wall-clock bounded while giving every configured identity a fair chance.
    # For the historical primary+anonymous(+one alternate) case this stays close to the previous
    # 30% per-request budget; with many identities it contracts automatically instead of letting
    # the first accounts consume the entire action timeout.
    fair_request_budget = max(2.0, min(
        proportional_budget(timeout, AUTHORIZATION_IDENTITY_RATIO),
        (float(timeout) * 0.85) / float(planned_identity_requests),
    ))
    primary, primary_guard = _safe_get(target_url, cookies, fair_request_budget, pacer, deadline)
    anonymous, anonymous_guard = _safe_get(target_url, "", fair_request_budget, pacer, deadline)
    alternate_responses: list[tuple[str, requests.Response | None, str]] = []
    for index, alternate_cookie in enumerate(supplied_alternates):
        if remaining_budget(deadline) <= 0:
            alternate_responses.append((labels[index], None, "time_limit_reached"))
            break
        response, guard = _safe_get(target_url, alternate_cookie, fair_request_budget, pacer, deadline)
        alternate_responses.append((labels[index], response, str(guard or "")))

    if primary is None or primary.status_code >= 400 or looks_like_login(primary, text_limit=80_000):
        timed_out = primary_guard == "time_limit_reached"
        return partial(
            "Authorization Differential Verifier", target_url,
            "The authorization action reached its shared time budget before the primary identity could be checked." if timed_out else
            "The primary authenticated identity did not obtain a usable protected response.",
            diagnosis="time_limit_reached" if timed_out else "authentication_precheck_failed", timed_out=timed_out,
            time_limit_reached=timed_out, vulnerabilities=[], primary=_summary(primary, primary_guard),
        )

    findings: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {
        "parameters": [str(value) for value in (parameters or [])], "primary": _summary(primary, primary_guard),
        "anonymous": _summary(anonymous, anonymous_guard), "secondary_supplied": bool(supplied_alternates),
        "identity_comparison_count": len(supplied_alternates),
        "identity_labels": labels[:len(supplied_alternates)],
        "invalid_identity_labels": invalid_alternate_labels,
        "relevance_score": relevance_score, "relevance_reasons": relevance_reasons,
        "tool_timeout_seconds": timeout,
        "identity_request_budget_seconds": round(fair_request_budget, 3),
        "phase_ratio_policy": {"identity_request_max_ratio": AUTHORIZATION_IDENTITY_RATIO, "shared_budget_fraction": 0.85},
    }
    if anonymous is not None:
        accepted, similarity, length_ratio = _matching_access(primary, anonymous)
        diagnostics["anonymous_comparison"] = {
            "accepted_equivalent": accepted, "similarity": round(similarity, 4), "length_ratio": round(length_ratio, 4),
        }
        if accepted and relevance_score > 0:
            findings.append(_finding(
                target_url, "anonymous", primary, anonymous, similarity, length_ratio
            ))
    diagnostics["identity_comparisons"] = []
    alternate_timeout = False
    for label, alternate, alternate_guard in alternate_responses:
        row = {"label": label, "response": _summary(alternate, alternate_guard)}
        if alternate_guard == "time_limit_reached":
            alternate_timeout = True
        if isinstance(alternate, requests.Response):
            accepted, similarity, length_ratio = _matching_access(primary, alternate)
            row.update({
                "accepted_equivalent": accepted, "similarity": round(similarity, 4),
                "length_ratio": round(length_ratio, 4),
            })
            if accepted:
                findings.append(_finding(
                    target_url, f"authenticated_identity:{label}", primary, alternate, similarity, length_ratio,
                ))
        diagnostics["identity_comparisons"].append(row)

    if remaining_budget(deadline) <= 0 or anonymous_guard == "time_limit_reached" or alternate_timeout:
        return partial(
            "Authorization Differential Verifier", target_url,
            f"Authorization differential reached its shared action time budget. Findings preserved: {len(findings)}.",
            diagnosis="time_limit_reached", timed_out=True, time_limit_reached=True, vulnerabilities=findings, diagnostics=diagnostics,
        )
    return success(
        "Authorization Differential Verifier", target_url,
        f"Read-only authorization differential completed. Findings: {len(findings)}.", vulnerabilities=findings,
        diagnostics=diagnostics,
    )

if __name__ == "__main__":
    _serve()
