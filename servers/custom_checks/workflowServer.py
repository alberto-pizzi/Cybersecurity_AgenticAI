from __future__ import annotations

import html
import json
import re
import secrets
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

from utils import skipped, success

from utils import same_origin

from core.scannerCommon import looks_like_login, service

mcp, _serve = service("Web Workflow Verifier", "workflow")

TOKEN_RE = re.compile(r"(?:csrf|xsrf|token|nonce|authenticity|request[_-]?verification)", re.I)
DESTRUCTIVE_RE = re.compile(r"(?:logout|signout|logoff|setup|install|delete|remove|drop|truncate|purge|wipe|reset)", re.I)
STATE_CHANGE_RE = re.compile(
    r"(?:change|update|save|create|submit|send|comment|message|feedback|upload|password|email|profile|settings|transfer|captcha|admin)",
    re.I,
)
AUTH_RE = re.compile(r"(?:login|signin|sign-in|authenticate|brute)", re.I)
CAPTCHA_RE = re.compile(r"(?:captcha|recaptcha|hcaptcha)", re.I)
ERROR_RE = re.compile(r"(?:invalid|error|failed|required|denied|forbidden|incorrect)", re.I)

# Normalize field rows from the discovered request contract for workflow testing.
def _field_rows(fields: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for field in fields or []:
        if not isinstance(field, dict):
            continue
        name = str(field.get("name") or "").strip()
        if not name:
            continue
        rows.append({
            "name": name, "value": str(field.get("value") or ""),
            "type": str(field.get("type") or "text").lower(), "tag": str(field.get("tag") or "input").lower(),
        })
    return rows

# Normalize pairs from case from the discovered request contract for workflow testing.
def _pairs_from_case(data: str, fields: list[dict[str, str]]) -> list[tuple[str, str]]:
    pairs = list(parse_qsl(str(data or ""), keep_blank_values=True))
    if pairs:
        return pairs
    result: list[tuple[str, str]] = []
    for field in fields:
        if field["type"] in {"file", "reset"}:
            continue
        value = field["value"]
        if not value and field["type"] not in {"hidden", "submit", "button"}:
            value = "1"
        result.append((field["name"], value))
    return result

# Create an authenticated requests session for bounded workflow checks.
def _session(cookies: str) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SecOps-Workflow-Verifier/1.0",
        "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.5", "Cache-Control": "no-cache",
    })
    if cookies:
        session.headers["Cookie"] = cookies
    return session

# Check whether state-changing requests enforce the discovered anti-CSRF token.
def _csrf_check(
    target_url: str, source_url: str, cookies: str, data: str,
    fields: list[dict[str, str]], token_parameters: list[str], timeout: int, allow_state_changes: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    diagnostic: dict[str, Any] = {"applicable": False}
    parsed = urlparse(target_url)
    names = [field["name"] for field in fields]
    text = " ".join([parsed.path, parsed.query, *names])
    if not STATE_CHANGE_RE.search(text) or AUTH_RE.search(text) or DESTRUCTIVE_RE.search(text):
        return findings, diagnostic
    diagnostic["applicable"] = True
    tokens = list(dict.fromkeys([*token_parameters, *[name for name in names if TOKEN_RE.search(name)]]))
    diagnostic["token_parameters"] = tokens
    evidence = f"POST form action={target_url}; source={source_url or 'not supplied'}; token_parameters={tokens or 'none'}"

    if not tokens:
        findings.append({
            "alert": "Potential CSRF protection missing on state-changing form", "risk": "medium",
            "category": "candidate", "verification_status": "form-structure-candidate", "confidence": "medium",
            "description": "A state-changing POST form was discovered without a recognized anti-CSRF token field.",
            "impact": "If the server also accepts cross-site requests, an attacker may cause an authenticated user to perform unintended actions.",
            "solution": "Require an unpredictable per-session or per-request CSRF token, validate Origin/Referer where appropriate and use SameSite cookies as defence in depth.",
            "url": target_url, "method": "POST",
            "evidence": evidence, "owasp_category": "A01:2021 Broken Access Control", "cwe_id": "352",
        })
        return findings, diagnostic

    if not allow_state_changes:
        return findings, diagnostic

    pairs = _pairs_from_case(data, fields)
    original = [(name, value) for name, value in pairs]
    stripped = [(name, value) for name, value in pairs if name not in set(tokens)]
    if stripped == original:
        return findings, diagnostic

    session = _session(cookies)
    try:
        baseline = session.post(
            target_url, data=original, timeout=(4, timeout), allow_redirects=True,
            headers={"Referer": source_url or target_url, "Origin": f"{parsed.scheme}://{parsed.netloc}"},
        )
        without_token = session.post(
            target_url, data=stripped, timeout=(4, timeout), allow_redirects=True, headers={"Sec-Fetch-Site": "cross-site"},
        )
    except requests.RequestException as exc:
        diagnostic["error"] = f"{type(exc).__name__}: {exc}"
        return findings, diagnostic

    similarity = SequenceMatcher(None, baseline.text[:80_000], without_token.text[:80_000]).ratio()
    accepted = (
        without_token.status_code < 400
        and not looks_like_login(without_token, text_limit=80_000, paths=("/login", "/login.php", "/signin", "/auth"), words=("login", "sign in", "authenticate"))
        and similarity >= 0.88
        and not (ERROR_RE.search(without_token.text[:20_000]) and not ERROR_RE.search(baseline.text[:20_000]))
    )
    diagnostic.update({
        "baseline_status": baseline.status_code, "without_token_status": without_token.status_code,
        "response_similarity": round(similarity, 4), "accepted_without_token": accepted,
    })
    if accepted:
        findings.append({
            "alert": "Anti-CSRF token appears unenforced", "risk": "high",
            "category": "candidate", "verification_status": "token-removal-differential-needs-impact-validation",
            "confidence": "medium",
            "description": "Removing the recognized anti-CSRF token produced a successful response highly similar to the token-bearing request.",
            "impact": "The affected state-changing action may be triggerable cross-site in a victim's authenticated browser.",
            "solution": "Reject missing or invalid CSRF tokens server-side and validate request origin for sensitive actions.",
            "url": target_url, "method": "POST", "parameter": ", ".join(tokens),
            "evidence": (
                f"baseline_status={baseline.status_code}; without_token_status={without_token.status_code}; "
                f"similarity={similarity:.4f}; final_url={without_token.url}"
            ),
            "owasp_category": "A01:2021 Broken Access Control", "cwe_id": "352",
        })
    return findings, diagnostic

# Exercise a bounded file-upload workflow and verify whether uploaded content becomes web-accessible.
def _upload_check(
    target_url: str, source_url: str, cookies: str, fields: list[dict[str, str]],
    file_parameters: list[str], timeout: int, allow_state_changes: bool, known_urls: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    diagnostic: dict[str, Any] = {"applicable": bool(file_parameters)}
    if not file_parameters or not allow_state_changes or DESTRUCTIVE_RE.search(urlparse(target_url).path):
        return findings, diagnostic

    # Upload a uniquely named harmless marker so later same-origin retrieval is unambiguous.
    marker = "SECOPS_UPLOAD_" + secrets.token_hex(8)
    filename = f"secops_probe_{secrets.token_hex(4)}.html"
    content = f"<!doctype html><html><body>{marker}</body></html>".encode("utf-8")
    form_data: dict[str, str] = {}
    for field in fields:
        if field["type"] in {"file", "reset"}:
            continue
        value = field["value"]
        if not value and field["type"] not in {"hidden", "submit", "button"}:
            value = "secops"
        form_data[field["name"]] = value
    files = {file_parameters[0]: (filename, content, "text/html")}
    session = _session(cookies)
    try:
        response = session.post(
            target_url, data=form_data, files=files, timeout=(4, timeout),
            allow_redirects=True, headers={"Referer": source_url or target_url},
        )
    except requests.RequestException as exc:
        diagnostic["error"] = f"{type(exc).__name__}: {exc}"
        return findings, diagnostic

    diagnostic.update({"status": response.status_code, "final_url": str(response.url), "filename": filename})
    candidates: list[str] = []
    for match in re.findall(r"(?:href|src)\s*=\s*['\"]([^'\"]+)['\"]", response.text, re.I):
        if filename.lower() in match.lower():
            candidates.append(urljoin(str(response.url), html.unescape(match)))
    for match in re.findall(r"https?://[^\s'\"<>]+", response.text, re.I):
        if filename.lower() in match.lower():
            candidates.append(html.unescape(match))

    path_pattern = re.compile(
        r"([A-Za-z0-9_./\\-]{0,240}" + re.escape(filename) + r")", re.I,
    )
    for match in path_pattern.findall(html.unescape(response.text)):
        cleaned = match.replace("\\", "/")
        candidates.append(urljoin(str(response.url), cleaned))
    base = source_url or target_url
    if filename.lower() in response.text.lower() and not candidates:
        for prefix in ("uploads/", "upload/", "files/", "media/", "attachments/", "images/"):
            candidates.append(urljoin(base, prefix + filename))

    directory_candidates: list[str] = []
    for known in known_urls or []:
        value = str(known or "").strip()
        if not value or not same_origin(target_url, value):
            continue
        parsed_known = urlparse(value)
        lowered = parsed_known.path.lower()
        if any(token in lowered for token in ("upload", "files", "media", "attachment", "image", "document")):
            directory = value if value.endswith("/") else urljoin(value, "../")
            directory_candidates.append(directory)
            candidates.append(urljoin(directory, filename))

    directory_searches: list[dict[str, Any]] = []
    for directory in list(dict.fromkeys(directory_candidates))[:10]:
        try:
            listing = session.get(directory, timeout=(4, timeout), allow_redirects=True)
        except requests.RequestException as exc:
            directory_searches.append({"url": directory, "error": f"{type(exc).__name__}: {exc}"})
            continue
        discovered_links: list[str] = []
        for match in re.findall(r"(?:href|src)\s*=\s*['\"]([^'\"]+)['\"]", listing.text, re.I):
            resolved = urljoin(str(listing.url), html.unescape(match))
            if filename.lower() in resolved.lower() and same_origin(target_url, resolved):
                candidates.append(resolved)
                discovered_links.append(resolved)
        directory_searches.append({
            "url": str(listing.url), "status": listing.status_code,
            "filename_present": filename.lower() in listing.text.lower(), "matching_links": discovered_links,
        })

    # Verify candidate URLs and report exposure only when the uploaded marker is retrieved.
    candidates = [value for value in dict.fromkeys(candidates) if same_origin(target_url, value)]
    retrieved: list[dict[str, Any]] = []
    for candidate in candidates[:8]:
        try:
            probe = session.get(candidate, timeout=(4, timeout), allow_redirects=True)
        except requests.RequestException:
            continue
        present = marker in probe.text
        retrieved.append({
            "url": str(probe.url), "status": probe.status_code,
            "marker_present": present, "content_type": probe.headers.get("Content-Type", ""),
        })
        if present:
            html_served = "html" in str(probe.headers.get("Content-Type") or "").lower()
            findings.append({
                "alert": "User-controlled HTML file upload is web-accessible" if html_served else "Uploaded user-controlled file is web-accessible",
                "risk": "high" if html_served else "medium", "category": "candidate",
                "verification_status": "harmless-upload-and-retrieval-confirmed", "confidence": "high",
                "description": "A harmless marker file was accepted by the upload workflow and retrieved from the same web origin.",
                "impact": (
                    "Serving attacker-controlled HTML from the application origin can enable stored script execution or trusted-origin phishing."
                    if html_served else
                    "Retrievable arbitrary files may enable content hosting, stored client-side attacks or further exploitation depending on allowed file types and server handling."
                ),
                "solution": "Allow-list required file types, validate content, generate server-side names, store uploads outside the web root and serve them with safe content-disposition and content-type headers.",
                "url": str(probe.url), "method": "POST", "parameter": file_parameters[0],
                "evidence": (
                    f"upload_status={response.status_code}; upload_final_url={response.url}; filename={filename}; "
                    f"retrieval_status={probe.status_code}; content_type={probe.headers.get('Content-Type', '')}; marker_present=True"
                ),
                "owasp_category": "A04:2021 Insecure Design", "cwe_id": "434",
            })
            break
    diagnostic["directory_searches"] = directory_searches
    diagnostic["retrieval_candidates"] = candidates[:20]
    diagnostic["retrieval_attempts"] = retrieved
    if response.status_code < 400 and not findings:
        findings.append({
            "alert": "File upload workflow accepted a harmless HTML probe", "risk": "low",
            "category": "observation", "verification_status": "upload-accepted-location-not-confirmed", "confidence": "medium",
            "description": "The upload endpoint accepted the bounded harmless file, but the scanner could not confirm a public retrieval URL.",
            "url": target_url, "method": "POST", "parameter": file_parameters[0],
            "evidence": f"HTTP {response.status_code}; final_url={response.url}; filename={filename}",
        })
    return findings, diagnostic

# Run bounded authentication attempts to detect missing throttling or challenge behavior.
def _authentication_check(
    target_url: str, fields: list[dict[str, str]], timeout: int, method: str = "POST",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    names = {field["name"].lower(): field for field in fields}
    username_name = next((name for name in names if name in {"username", "user", "email", "login"}), "")
    password_name = next((name for name, field in names.items() if field["type"] == "password" or "password" in name), "")
    applicable = bool(username_name and password_name) or bool(AUTH_RE.search(urlparse(target_url).path))
    diagnostic: dict[str, Any] = {"applicable": applicable}
    if not applicable:
        return findings, diagnostic

    session = _session("")
    attempts: list[dict[str, Any]] = []
    throttled = False
    challenge = False
    for index in range(3):
        payload: dict[str, str] = {}
        for field in fields:
            if field["type"] in {"file", "reset"}:
                continue
            payload[field["name"]] = field["value"] or "1"
        if username_name:
            payload[username_name] = f"secops_invalid_{secrets.token_hex(4)}"
        if password_name:
            payload[password_name] = secrets.token_urlsafe(12)
        try:
            if str(method or "POST").upper() == "GET":
                response = session.get(target_url, params=payload, timeout=(4, timeout), allow_redirects=True)
            else:
                response = session.post(target_url, data=payload, timeout=(4, timeout), allow_redirects=True)
        except requests.RequestException as exc:
            attempts.append({"error": f"{type(exc).__name__}: {exc}"})
            break
        text = response.text[:50_000]
        retry_after = response.headers.get("Retry-After", "")
        is_throttled = response.status_code == 429 or bool(retry_after) or bool(re.search(r"(?:too many|rate limit|try again later|locked)", text, re.I))
        has_challenge = bool(CAPTCHA_RE.search(text))
        throttled = throttled or is_throttled
        challenge = challenge or has_challenge
        attempts.append({
            "attempt": index + 1, "status": response.status_code, "final_url": str(response.url), "retry_after": retry_after,
            "throttled": is_throttled, "captcha": has_challenge, "bytes": len(response.content),
        })
        if is_throttled or has_challenge:
            break
    diagnostic["attempts"] = attempts
    if len(attempts) >= 3 and not throttled and not challenge:
        findings.append({
            "alert": "No observable login throttling in bounded test", "risk": "low",
            "category": "candidate", "verification_status": "three-attempt-bounded-observation", "confidence": "low",
            "description": "Three invalid authentication attempts completed without an HTTP 429 response, Retry-After header, visible lockout or CAPTCHA challenge.",
            "impact": "A missing or weak rate limit can make credential guessing and password spraying more practical. Three attempts are insufficient to prove that no longer-window control exists.",
            "solution": "Apply account- and source-aware throttling, progressive delays, monitoring and MFA for sensitive accounts.",
            "url": target_url, "method": str(method or "POST").upper(), "evidence": json.dumps(attempts, ensure_ascii=False),
            "owasp_category": "A07:2021 Identification and Authentication Failures", "cwe_id": "307",
        })
    return findings, diagnostic

# Inspect the CAPTCHA workflow for recognizable challenge fields and bypass indicators.
def _captcha_check(
    target_url: str, cookies: str, data: str, fields: list[dict[str, str]], timeout: int, allow_state_changes: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    names = [field["name"] for field in fields]
    applicable = bool(CAPTCHA_RE.search(" ".join([urlparse(target_url).path, *names])))
    diagnostic: dict[str, Any] = {"applicable": applicable}
    findings: list[dict[str, Any]] = []
    if not applicable:
        return findings, diagnostic
    captcha_names = [name for name in names if CAPTCHA_RE.search(name)]
    if not captcha_names:
        findings.append({
            "alert": "CAPTCHA workflow lacks a recognized challenge response field", "risk": "medium",
            "category": "candidate", "verification_status": "workflow-structure-candidate", "confidence": "low",
            "description": "A CAPTCHA-related workflow was discovered without a recognized server-submitted challenge response field.",
            "impact": "The anti-automation control may be client-side only or bypassable through a direct request to a later workflow step.",
            "solution": "Validate a single-use challenge response server-side and bind it to the session and protected action.",
            "url": target_url, "method": "POST", "evidence": f"fields={names}", "owasp_category": "A04:2021 Insecure Design",
        })
        return findings, diagnostic
    if not allow_state_changes:
        return findings, diagnostic
    pairs = _pairs_from_case(data, fields)
    stripped = [(name, value) for name, value in pairs if name not in set(captcha_names)]
    session = _session(cookies)
    try:
        response = session.post(target_url, data=stripped, timeout=(4, timeout), allow_redirects=True)
    except requests.RequestException as exc:
        diagnostic["error"] = f"{type(exc).__name__}: {exc}"
        return findings, diagnostic
    accepted = response.status_code < 400 and not looks_like_login(response, text_limit=80_000, paths=("/login", "/login.php", "/signin", "/auth"), words=("login", "sign in", "authenticate")) and not ERROR_RE.search(response.text[:30_000])
    diagnostic.update({"status": response.status_code, "accepted_without_captcha": accepted})
    if accepted:
        findings.append({
            "alert": "CAPTCHA response appears unenforced", "risk": "medium",
            "category": "candidate", "verification_status": "challenge-field-removal-candidate", "confidence": "medium",
            "description": "The workflow returned a successful response after recognized CAPTCHA fields were removed.",
            "impact": "Automated abuse may be possible by submitting the protected action directly without solving the challenge.",
            "solution": "Require and validate a single-use CAPTCHA response server-side for every protected action.",
            "url": target_url, "method": "POST", "parameter": ", ".join(captcha_names),
            "evidence": f"HTTP {response.status_code}; final_url={response.url}; removed_fields={captcha_names}",
            "owasp_category": "A04:2021 Insecure Design",
        })
    return findings, diagnostic

# Run bounded generic CSRF, upload, authentication and CAPTCHA workflow checks.
@mcp.tool()
def run_workflow_scan(
    target_url: str, cookies: str = "", method: str = "GET", data: str = "",
    parameters: list[str] | None = None, fields: list[dict[str, Any]] | None = None,
    file_parameters: list[str] | None = None, token_parameters: list[str] | None = None,
    source_url: str = "", enctype: str = "", timeout: int = 45, allow_state_changes: bool = False,
    known_urls: list[str] | None = None,
) -> dict:

    method = str(method or "GET").upper()
    rows = _field_rows(fields)
    if not rows and parameters:
        rows = [
            {
                "name": str(name),
                "type": "password" if "pass" in str(name).lower() else "text",
                "value": "",
            }
            for name in parameters
            if str(name)
        ]
    file_parameters = [str(value) for value in (file_parameters or []) if str(value)]
    token_parameters = [str(value) for value in (token_parameters or []) if str(value)]
    timeout = max(5, min(int(timeout), 90))
    if method not in {"GET", "POST"}:
        return skipped("Web Workflow Verifier", target_url, "The current workflow checks require a discovered GET/POST form contract.")
    if DESTRUCTIVE_RE.search(urlparse(target_url).path):
        return skipped("Web Workflow Verifier", target_url, "Destructive setup, deletion, reset or logout workflows are deliberately excluded.")

    findings: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {
        "method": method, "source_url": source_url, "enctype": enctype, "allow_state_changes": bool(allow_state_changes),
        "parameters": list(parameters or []), "file_parameters": file_parameters,
        "token_parameters": token_parameters, "known_url_count": len(known_urls or []),
    }

    if method == "POST":
        csrf_findings, csrf_diag = _csrf_check(
            target_url, source_url, cookies, data, rows, token_parameters, timeout, allow_state_changes,
        )
        upload_findings, upload_diag = _upload_check(
            target_url, source_url, cookies, rows, file_parameters, timeout, allow_state_changes, known_urls,
        )
        captcha_findings, captcha_diag = _captcha_check(
            target_url, cookies, data, rows, timeout, allow_state_changes,
        )
    else:
        csrf_findings, csrf_diag = [], {"applicable": False, "reason": "GET authentication workflow"}
        upload_findings, upload_diag = [], {"applicable": False, "reason": "GET authentication workflow"}
        captcha_findings, captcha_diag = [], {"applicable": False, "reason": "GET authentication workflow"}
    findings.extend(csrf_findings)
    findings.extend(upload_findings)
    findings.extend(captcha_findings)
    diagnostics["csrf"] = csrf_diag
    diagnostics["upload"] = upload_diag
    diagnostics["captcha"] = captcha_diag

    auth_findings, auth_diag = _authentication_check(target_url, rows, timeout, method)
    findings.extend(auth_findings)
    diagnostics["authentication"] = auth_diag

    applicable = any(bool(value.get("applicable")) for value in (csrf_diag, upload_diag, auth_diag, captcha_diag))
    if not applicable:
        return skipped("Web Workflow Verifier", target_url, "The discovered form did not match CSRF, upload, authentication or CAPTCHA workflow classes.")

    return success(
        "Web Workflow Verifier", target_url,
        f"Bounded workflow checks completed. Findings: {len(findings)}.", vulnerabilities=findings, diagnostics=diagnostics,
    )

if __name__ == "__main__":
    _serve()
