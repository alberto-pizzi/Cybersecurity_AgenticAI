from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse

import requests
from fastmcp import FastMCP

from utils import failure, partial, skipped, success

mcp = FastMCP("Authorization Differential Verifier")

DESTRUCTIVE_RE = re.compile(
    r"(?:logout|signout|logoff|setup|install|delete|remove|drop|truncate|purge|wipe|reset)",
    re.I,
)



PUBLIC_CONTENT_RE = re.compile(
    r"(?:^|/)(?:docs?|documentation|instructions?|help|about|changelog|license|copying|readme|static|assets?)(?:/|$)",
    re.I,
)
AUTHZ_PATH_RE = re.compile(
    r"(?:^|/)(?:admin|accounts?|profiles?|users?|members?|orders?|invoices?|documents?|downloads?|reports?|records?|settings|manage(?:ment)?|roles?|permissions?|api|private|internal|dashboard|billing|payments?)(?:/|$)",
    re.I,
)
AUTHZ_PARAMETER_RE = re.compile(
    r"^(?:id|uid|user_id|userid|account_id|member_id|profile_id|order_id|invoice_id|document_id|record_id|file_id|report_id|customer_id|owner_id|tenant_id|role_id)$",
    re.I,
)


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

def _same_origin(left: str, right: str) -> bool:
    a, b = urlparse(left), urlparse(right)
    return (a.scheme.lower(), a.hostname, a.port or (443 if a.scheme == "https" else 80)) == (
        b.scheme.lower(), b.hostname, b.port or (443 if b.scheme == "https" else 80)
    )


def _looks_like_login(response: requests.Response) -> bool:
    text = response.text[:80_000].lower()
    path = urlparse(str(response.url)).path.lower().rstrip("/")
    return path.endswith(("/login", "/login.php", "/signin", "/sign-in", "/auth")) or (
        ("type=\"password\"" in text or "type='password'" in text)
        and any(word in text for word in ("login", "log in", "sign in", "authenticate"))
    )


def _safe_get(url: str, cookies: str, timeout: int) -> tuple[requests.Response | None, str]:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SecOps-Authorization-Differential/1.0",
        "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.5",
        "Cache-Control": "no-cache",
    })
    if cookies:
        session.headers["Cookie"] = cookies
    current = url
    seen: set[str] = set()
    for _ in range(5):
        if not _same_origin(url, current):
            return None, "cross_origin_blocked"
        response = session.get(current, timeout=(4, timeout), allow_redirects=False)
        if response.status_code not in {301, 302, 303, 307, 308}:
            response.url = current
            return response, ""
        location = str(response.headers.get("Location") or "").strip()
        if not location:
            response.url = current
            return response, ""
        candidate = urljoin(current, location)
        if not _same_origin(url, candidate):
            response.url = current
            return response, "cross_origin_redirect_blocked"
        if DESTRUCTIVE_RE.search(urlparse(candidate).path):
            response.url = current
            return response, "destructive_redirect_blocked"
        if candidate in seen:
            response.url = current
            return response, "redirect_loop"
        seen.add(current)
        current = candidate
    response.url = current
    return response, "redirect_limit"


def _summary(response: requests.Response | None, guard: str) -> dict[str, Any]:
    if response is None:
        return {"available": False, "guard": guard}
    content = response.content
    return {
        "available": True,
        "status": response.status_code,
        "final_url": str(response.url),
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "login_detected": _looks_like_login(response),
        "guard": guard,
        "content_type": str(response.headers.get("Content-Type") or ""),
    }


def _similarity(left: requests.Response, right: requests.Response) -> float:
    if left.content == right.content:
        return 1.0
    left_text = left.text[:120_000]
    right_text = right.text[:120_000]
    if not left_text and not right_text:
        return 1.0
    return SequenceMatcher(None, left_text, right_text).ratio()


def _matching_access(
    primary: requests.Response,
    alternate: requests.Response,
) -> tuple[bool, float, float]:
    similarity = _similarity(primary, alternate)
    length_ratio = (
        min(len(primary.content), len(alternate.content))
        / max(1, max(len(primary.content), len(alternate.content)))
    )
    accepted = (
        primary.status_code < 400
        and alternate.status_code < 400
        and not _looks_like_login(primary)
        and not _looks_like_login(alternate)
        and similarity >= 0.965
        and length_ratio >= 0.90
    )
    return accepted, similarity, length_ratio


def _finding(
    target_url: str,
    alternate_label: str,
    primary: requests.Response,
    alternate: requests.Response,
    similarity: float,
    length_ratio: float,
) -> dict[str, Any]:
    anonymous = alternate_label == "anonymous"
    return {
        "alert": (
            "Potential missing authentication or object authorization"
            if anonymous
            else "Potential cross-account authorization weakness"
        ),
        "risk": "medium",
        "category": "candidate",
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
        "url": target_url,
        "method": "GET",
        "evidence": (
            f"alternate={alternate_label}; primary_status={primary.status_code}; "
            f"alternate_status={alternate.status_code}; response_similarity={similarity:.4f}; "
            f"length_ratio={length_ratio:.4f}; primary_bytes={len(primary.content)}; "
            f"alternate_bytes={len(alternate.content)}"
        ),
        "owasp_category": "A01:2021 Broken Access Control",
        "cwe_id": "639" if not anonymous else "862",
    }


@mcp.tool()
def run_authorization_scan(
    target_url: str,
    cookies: str = "",
    secondary_cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    timeout: int = 30,
) -> dict:
    """Compare a read-only GET under primary, secondary and anonymous identities."""
    method = str(method or "GET").upper()
    if method != "GET":
        return skipped(
            "Authorization Differential Verifier",
            target_url,
            "Authorization differential checks are intentionally limited to read-only GET requests.",
        )
    if not cookies:
        return skipped(
            "Authorization Differential Verifier",
            target_url,
            "A primary authenticated Cookie header is required for authorization comparison.",
        )
    if DESTRUCTIVE_RE.search(urlparse(target_url).path):
        return skipped(
            "Authorization Differential Verifier",
            target_url,
            "Destructive logout, setup, reset or deletion routes are excluded.",
        )
    timeout = max(5, min(int(timeout), 60))
    relevance_score, relevance_reasons = _authorization_relevance(target_url, parameters)
    if relevance_score <= 0 and not secondary_cookies:
        return skipped(
            "Authorization Differential Verifier",
            target_url,
            "The request resembles public/static documentation and has no object or identity reference suitable for an authorization differential.",
            diagnosis="authorization_candidate_not_relevant",
            relevance_score=relevance_score,
            relevance_reasons=relevance_reasons,
        )
    try:
        primary, primary_guard = _safe_get(target_url, cookies, timeout)
        anonymous, anonymous_guard = _safe_get(target_url, "", timeout)
        secondary = secondary_guard = None
        if secondary_cookies:
            secondary, secondary_guard = _safe_get(target_url, secondary_cookies, timeout)
    except requests.Timeout as exc:
        return partial(
            "Authorization Differential Verifier",
            target_url,
            f"Authorization comparison reached its request budget: {exc}",
            diagnosis="time_limit_reached",
            timed_out=True,
            vulnerabilities=[],
        )
    except requests.RequestException as exc:
        return failure(
            "Authorization Differential Verifier",
            target_url,
            f"Authorization comparison failed: {exc}",
            diagnosis="request_failed",
        )

    if primary is None or primary.status_code >= 400 or _looks_like_login(primary):
        return partial(
            "Authorization Differential Verifier",
            target_url,
            "The primary authenticated identity did not obtain a usable protected response.",
            diagnosis="authentication_precheck_failed",
            timed_out=False,
            vulnerabilities=[],
            primary=_summary(primary, primary_guard),
        )

    findings: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {
        "parameters": [str(value) for value in (parameters or [])],
        "primary": _summary(primary, primary_guard),
        "anonymous": _summary(anonymous, anonymous_guard),
        "secondary_supplied": bool(secondary_cookies),
        "relevance_score": relevance_score,
        "relevance_reasons": relevance_reasons,
    }
    if anonymous is not None:
        accepted, similarity, length_ratio = _matching_access(primary, anonymous)
        diagnostics["anonymous_comparison"] = {
            "accepted_equivalent": accepted,
            "similarity": round(similarity, 4),
            "length_ratio": round(length_ratio, 4),
        }
        if accepted and relevance_score > 0:
            findings.append(_finding(
                target_url, "anonymous", primary, anonymous, similarity, length_ratio
            ))
    if isinstance(secondary, requests.Response):
        accepted, similarity, length_ratio = _matching_access(primary, secondary)
        diagnostics["secondary"] = _summary(secondary, str(secondary_guard or ""))
        diagnostics["secondary_comparison"] = {
            "accepted_equivalent": accepted,
            "similarity": round(similarity, 4),
            "length_ratio": round(length_ratio, 4),
        }
        if accepted:
            findings.append(_finding(
                target_url, "secondary_authenticated", primary, secondary,
                similarity, length_ratio,
            ))

    return success(
        "Authorization Differential Verifier",
        target_url,
        f"Read-only authorization differential completed. Findings: {len(findings)}.",
        vulnerabilities=findings,
        diagnostics=diagnostics,
    )


def _once() -> int:
    try:
        arguments = json.loads(sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = run_authorization_scan(**arguments)
    except Exception as exc:
        result = failure(
            "Authorization Differential Verifier",
            "",
            f"One-shot authorization scan failed: {type(exc).__name__}: {exc}",
        )
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio", show_banner=False)
