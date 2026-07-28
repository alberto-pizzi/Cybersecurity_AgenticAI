from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from fastmcp import FastMCP

from utils import failure, skipped, success

mcp = FastMCP("Sensitive Exposure Verifier")

BACKUP_SUFFIXES = (
    ".bak", ".backup", ".old", ".orig", ".save", ".copy", ".dist",
    ".sample", ".example", ".swp", ".swo", ".tmp", ".temp", "~",
)
SENSITIVE_BASENAMES = {
    ".env", ".git/HEAD", ".git/config", "web.config", "phpinfo.php",
    "config.php", "configuration.php", "settings.php", "database.yml",
    "application.properties", "application.yml", "application.yaml",
    "composer.json", "package-lock.json", "docker-compose.yml",
    "docker-compose.yaml", "id_rsa", "authorized_keys",
}
SOURCE_MARKERS = (
    "<?php", "#!/usr/bin/env", "import ", "from ", "class ", "def ",
    "function ", "public class ", "private class ", "namespace ",
)
CONFIG_MARKERS = (
    "db_password", "db_pass", "database_password", "database_url",
    "db_username", "db_user", "secret_key", "api_key", "access_key",
    "client_secret", "private_key", "smtp_password", "redis_url",
    "mysql_password", "postgres_password", "jwt_secret", "app_secret",
)
DIRECTORY_INDEX_MARKERS = (
    "<title>index of /", "<h1>index of /", "directory listing for",
)
PHPINFO_MARKERS = ("php version", "phpinfo()", "configuration file (php.ini) path")
GIT_HEAD_RE = re.compile(r"^ref:\s+refs/heads/", re.I | re.M)
ENV_LINE_RE = re.compile(r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+$")
SECRET_REDACTIONS = (
    (re.compile(r"(?im)^\s*((?:db_|database_|mysql_|postgres_|redis_|smtp_)?(?:password|passwd|pass|secret|token|api_key|access_key|private_key|client_secret)\s*[=:]\s*)[^\r\n]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(\[\s*['\"]?(?:db_password|db_pass|database_password|db_user|db_username|api_key|secret_key|client_secret|private_key|token)['\"]?\s*\]\s*=\s*['\"])[^'\"]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/-]+"), r"\1<redacted>"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "<redacted-jwt>"),
)
AUTO_INDEX_QUERY_KEYS = {"c", "n", "m", "s", "d", "o"}


def _same_origin(left: str, right: str) -> bool:
    a, b = urlparse(left), urlparse(right)
    return (a.scheme.lower(), a.hostname, a.port or (443 if a.scheme == "https" else 80)) == (
        b.scheme.lower(), b.hostname, b.port or (443 if b.scheme == "https" else 80)
    )


def _redact(text: str, limit: int = 2500) -> str:
    value = str(text or "")[: max(0, limit)]
    for pattern, replacement in SECRET_REDACTIONS:
        value = pattern.sub(replacement, value)
    return value




def _canonical_resource_url(url: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = "" if pairs and {name.lower() for name, _ in pairs} <= AUTO_INDEX_QUERY_KEYS else urlencode(pairs)
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for finding in findings:
        canonical = _canonical_resource_url(str(finding.get("url") or ""))
        key = (str(finding.get("alert") or "").lower(), str(finding.get("category") or ""), canonical)
        row = dict(finding)
        row["url"] = canonical
        existing = merged.get(key)
        if existing is None:
            row["affected_urls"] = [str(finding.get("url") or canonical)]
            merged[key] = row
            continue
        urls = existing.setdefault("affected_urls", [existing.get("url", canonical)])
        original = str(finding.get("url") or canonical)
        if original not in urls:
            urls.append(original)
        existing["occurrence_count"] = int(existing.get("occurrence_count", 1)) + 1
    return list(merged.values())

def _candidate_score(url: str) -> int:
    parsed = urlparse(url)
    path = parsed.path
    lowered = path.lower()
    basename = Path(path).name.lower()
    score = 0
    if basename in {value.lower() for value in SENSITIVE_BASENAMES}:
        score += 120
    if any(lowered.endswith(suffix.lower()) for suffix in BACKUP_SUFFIXES):
        score += 100
    if any(token in lowered for token in ("/.git/", "/config/", "/backup", "/debug", "/logs", "/admin", "/docs/")):
        score += 45
    if basename.endswith((".sql", ".env", ".ini", ".conf", ".yaml", ".yml", ".json", ".xml")):
        score += 35
    if parsed.query and set(name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)) <= {"c", "n", "m", "s", "d", "o"}:
        score += 20
    # Directory indexes are commonly exposed on otherwise ordinary trailing-slash
    # paths (for example /docs/). Check a bounded subset instead of limiting
    # verification to names that already look sensitive.
    if path.endswith("/") and path not in {"", "/"}:
        score += 12
    return score


def _safe_get(session: requests.Session, base: str, url: str, timeout: int) -> tuple[requests.Response | None, str]:
    current = url
    seen: set[str] = set()
    for _ in range(5):
        if not _same_origin(base, current):
            return None, "cross_origin_blocked"
        response = session.get(current, timeout=(4, timeout), allow_redirects=False, headers={"Cache-Control": "no-cache"})
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response, ""
        location = str(response.headers.get("Location") or "").strip()
        if not location:
            return response, ""
        candidate = urljoin(current, location)
        if not _same_origin(base, candidate):
            return response, "cross_origin_redirect_blocked"
        lowered = urlparse(candidate).path.lower()
        if any(token in lowered for token in ("logout", "signout", "logoff", "reset", "setup", "install", "delete")):
            return response, "destructive_redirect_blocked"
        if candidate in seen:
            return response, "redirect_loop"
        seen.add(current)
        current = candidate
    return response, "redirect_limit"


def _finding_for_response(url: str, response: requests.Response, redirect_guard: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    text = response.text[:100_000]
    lowered = text.lower()
    path = urlparse(str(response.url or url)).path
    basename = Path(path).name.lower()
    content_type = str(response.headers.get("Content-Type") or "").lower()
    evidence_prefix = (
        f"HTTP {response.status_code}; final_url={response.url}; content_type={content_type or 'not supplied'}; "
        f"bytes={len(response.content)}; redirect_guard={redirect_guard or 'not-triggered'}"
    )

    directory_index = any(marker in lowered for marker in DIRECTORY_INDEX_MARKERS)
    if directory_index:
        findings.append({
            "alert": "Directory listing reachable",
            "risk": "low",
            "category": "candidate",
            "verification_status": "content-verified-directory-index",
            "confidence": "high",
            "description": "A same-origin directory index was retrieved and exposes file names and navigation entries.",
            "impact": "Directory indexes can reveal backups, source artifacts, configuration files, internal naming conventions and resources not intended for enumeration.",
            "solution": "Disable directory indexing and publish only explicitly required files.",
            "url": str(response.url or url),
            "method": "GET",
            "evidence": evidence_prefix + "\n" + _redact(text, 1400),
            "owasp_category": "A05:2021 Security Misconfiguration",
            "cwe_id": "548",
        })

    phpinfo = any(marker in lowered for marker in PHPINFO_MARKERS)
    if phpinfo:
        findings.append({
            "alert": "PHP diagnostic page exposed",
            "risk": "medium",
            "category": "vulnerability",
            "verification_status": "content-verified",
            "confidence": "high",
            "description": "A PHP information page disclosed runtime, extension and server configuration details.",
            "impact": "The page can disclose versions, filesystem paths, loaded modules, environment values and security-relevant configuration.",
            "solution": "Remove the diagnostic page or restrict it to a trusted administrative network.",
            "url": str(response.url or url),
            "method": "GET",
            "evidence": evidence_prefix,
            "owasp_category": "A05:2021 Security Misconfiguration",
        })

    git_head = bool(GIT_HEAD_RE.search(text))
    env_file = basename == ".env" or (ENV_LINE_RE.search(text) and any(term in lowered for term in CONFIG_MARKERS))
    backup_name = any(path.lower().endswith(suffix.lower()) for suffix in BACKUP_SUFFIXES)
    source_code = any(marker.lower() in lowered for marker in SOURCE_MARKERS)
    config_content = any(marker in lowered for marker in CONFIG_MARKERS)
    sensitive_name = basename in {value.lower() for value in SENSITIVE_BASENAMES} and basename != "phpinfo.php"

    if git_head:
        findings.append({
            "alert": "Git repository metadata exposed",
            "risk": "high",
            "category": "vulnerability",
            "verification_status": "content-verified-git-metadata",
            "confidence": "high",
            "description": "The Git HEAD reference was directly retrievable from the web origin.",
            "impact": "Exposed repository metadata can allow reconstruction of source history, secrets and unpublished files.",
            "solution": "Block all access to .git directories and remove repository metadata from the web root.",
            "url": str(response.url or url),
            "method": "GET",
            "evidence": evidence_prefix + "\n" + _redact(text, 500),
            "owasp_category": "A05:2021 Security Misconfiguration",
            "cwe_id": "552",
        })
    elif env_file:
        findings.append({
            "alert": "Environment configuration file exposed",
            "risk": "high",
            "category": "vulnerability",
            "verification_status": "content-verified-configuration-disclosure",
            "confidence": "high",
            "description": "A dotenv-style configuration file was directly retrievable from the web origin.",
            "impact": "Environment files commonly contain database credentials, signing secrets, API keys and internal service addresses.",
            "solution": "Move environment files outside the document root, deny web access and rotate any disclosed secrets.",
            "url": str(response.url or url),
            "method": "GET",
            "evidence": evidence_prefix + "\n" + _redact(text, 1600),
            "owasp_category": "A02:2021 Cryptographic Failures",
            "cwe_id": "200",
        })
    elif (backup_name or sensitive_name) and (source_code or config_content):
        risk = "high" if config_content or "<?php" in lowered else "medium"
        findings.append({
            "alert": "Backup configuration or source file publicly exposed",
            "risk": risk,
            "category": "vulnerability",
            "verification_status": "content-verified-source-disclosure",
            "confidence": "high",
            "description": "A backup, distribution or configuration artifact was directly retrievable and contained source or configuration content.",
            "impact": "Source and configuration disclosure can reveal credentials, internal paths, implementation details and security controls that materially aid further attacks.",
            "solution": "Remove backup and source artifacts from the web root, deny access by extension and rotate any credentials present in the exposed file.",
            "url": str(response.url or url),
            "method": "GET",
            "evidence": evidence_prefix + "\n" + _redact(text, 2000),
            "owasp_category": "A05:2021 Security Misconfiguration",
            "cwe_id": "552",
        })
    elif backup_name or sensitive_name:
        findings.append({
            "alert": "Potentially sensitive backup or configuration artifact reachable",
            "risk": "medium",
            "category": "candidate",
            "verification_status": "resource-content-needs-manual-review",
            "confidence": "medium",
            "description": "A sensitive-looking backup or configuration filename returned a successful response, but the automated parser did not identify a conclusive source or secret marker.",
            "impact": "The resource may expose implementation details or secrets depending on its actual content.",
            "solution": "Review the resource, remove unnecessary artifacts and block access to backup/configuration extensions.",
            "url": str(response.url or url),
            "method": "GET",
            "evidence": evidence_prefix + "\n" + _redact(text, 1000),
            "owasp_category": "A05:2021 Security Misconfiguration",
        })

    return findings


@mcp.tool()
def run_exposure_scan(
    target_url: str,
    cookies: str = "",
    discovered_urls: list[str] | None = None,
    timeout: int = 45,
    max_urls: int = 40,
) -> dict:
    """Verify same-origin backup, source, configuration and directory-index exposures."""
    urls = [str(value) for value in (discovered_urls or []) if str(value).startswith(("http://", "https://"))]
    urls = [url for url in dict.fromkeys([target_url, *urls]) if _same_origin(target_url, url)]
    canonical_candidates: dict[str, str] = {}
    for value in urls:
        canonical = _canonical_resource_url(value)
        current = canonical_candidates.get(canonical)
        if current is None or _candidate_score(value) > _candidate_score(current):
            canonical_candidates[canonical] = value
    urls = list(canonical_candidates.values())
    ranked = sorted(urls, key=lambda value: (_candidate_score(value), value), reverse=True)
    candidates = [url for url in ranked if _candidate_score(url) > 0][: max(1, min(int(max_urls), 100))]
    if not candidates:
        return skipped("Sensitive Exposure Verifier", target_url, "No discovered URL matched backup, source, configuration or directory-index exposure patterns.")

    session = requests.Session()
    session.headers.update({"User-Agent": "SecOps-Exposure-Verifier/1.0", "Accept": "*/*"})
    if cookies:
        session.headers["Cookie"] = cookies

    findings: list[dict[str, Any]] = []
    checked: list[dict[str, Any]] = []
    errors: list[str] = []
    per_request_timeout = max(3, min(int(timeout), 20))
    for url in candidates:
        try:
            response, guard = _safe_get(session, target_url, url, per_request_timeout)
            if response is None:
                checked.append({"url": url, "status": "blocked", "guard": guard})
                continue
            checked.append({
                "url": url,
                "status": response.status_code,
                "final_url": str(response.url),
                "bytes": len(response.content),
                "guard": guard,
            })
            if response.status_code < 400:
                findings.extend(_finding_for_response(url, response, guard))
        except requests.RequestException as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")

    return success(
        "Sensitive Exposure Verifier",
        target_url,
        f"Verified {len(checked)} high-value discovered resource(s). Findings: {len(_deduplicate_findings(findings))}.",
        vulnerabilities=_deduplicate_findings(findings),
        checked_resources=checked,
        request_errors=errors,
        authenticated=bool(cookies),
    )


def _once() -> int:
    try:
        arguments = json.loads(sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = run_exposure_scan(**arguments)
    except Exception as exc:
        result = failure("Sensitive Exposure Verifier", "", f"One-shot exposure verification failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio", show_banner=False)
