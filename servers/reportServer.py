from __future__ import annotations

import sys
import html
import json
import os
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
from fastmcp import FastMCP

from utils import REPORTS_DIR, failure, run_mcp_http, success


mcp = FastMCP("SecOps Report Server")

# Report info
REPORT_TITLE = "SecOps Penetration-Test Report"
REPORT_VERSION = "1.0"
AUTHORS = ["Alberto Pizzi", "Tommaso Ciccotti"]
REPORT_CLASSIFICATION = "Confidential"
CLIENT_NAME = "CLIENT NAME"

_MONTHS_EN = {
    1: "January", 2: "February", 3: "March", 4: "April", 5: "May", 6: "June",
    7: "July", 8: "August", 9: "September", 10: "October", 11: "November", 12: "December",
}

RISK_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
TOOL_PURPOSES = {
    "zap": "Traffic import, session handling, spider/site-tree population, passive analysis, and bounded high-value active checks when enabled.",
    "nuclei": "Adaptive fingerprint-driven template checks for CVEs, exposures and misconfigurations, plus bounded DAST only for specialist coverage gaps.",
    "nikto": "Web-server hardening, exposed resource and outdated component checks.",
    "ffuf": "High-value path and resource discovery with content verification for selected sensitive paths.",
    "exposure": "Read-only verification of exposed backups, source files, configuration artifacts and directory indexes.",
    "session": "Cookie-attribute, bounded session-identifier and fixation-indicator analysis.",
    "browser": "Chromium-based verification of DOM, reflected and stored XSS using harmless execution markers.",
    "workflow": "Bounded CSRF, file-upload, authentication-throttling and CAPTCHA workflow checks.",
    "arjun": "Hidden GET/POST parameter discovery using the discovered request contract.",
    "sqlmap": "SQL injection confirmation on discovered GET and POST requests.",
    "dalfox": "XSS reflection, AST and verified-vector testing.",
    "commix": "Operating-system command injection confirmation.",
    "traversal": "Bounded path traversal and local-file-inclusion verification on file-like parameters.",
    "idor": "Single-reference numeric object differential checks requiring manual ownership validation.",
    "authorization": "Read-only anonymous and optional two-account authorization/BOLA differentials on discovered high-value GET requests.",
    "jwt": "JWT structural analysis; it does not prove server acceptance of modified tokens.",
    "interactsh": "Explicit out-of-band callback confirmation for a supplied insertion point.",
}
SECRET_PATTERNS = (
    (re.compile(r"(?i)((?:session(?:_?id)?|sid|jsessionid|connect\.sid|asp\.net_sessionid)=)[^;\s]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(Cookie:\s*)[^\r\n]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(STATIC-COOKIE=)[^\s,\]]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9._~-]+"), r"\1<redacted>"),
    (re.compile(r"(?im)^\s*((?:db_|database_|mysql_|postgres_|redis_|smtp_)?(?:password|passwd|pass|secret|token|api_key|access_key|private_key|client_secret)\s*[=:]\s*)[^\r\n]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(\[\s*['\"]?(?:db_password|db_pass|database_password|db_user|db_username|api_key|secret_key|client_secret|private_key|token)['\"]?\s*\]\s*=\s*['\"])[^'\"]+"), r"\1<redacted>"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "<redacted-jwt>"),
)


def _format_date_en(dt: datetime) -> str:

    if 10 < dt.day % 100 < 14:  # eccezione: 11, 12, 13
        suffix = "th"

    last_digit = dt.day % 10

    if last_digit == 1:
        suffix = "st"
    elif last_digit == 2:
        suffix = "nd"
    elif last_digit == 3:
        suffix = "rd"
    else:
        suffix = "th"

    return f"{_MONTHS_EN[dt.month]} {dt.day}{suffix} {dt.year}"

def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip()).strip("._")[:120]


def _as_dict(value: dict | str | None) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("Expected a JSON object.")
    return parsed


def _redact_text(value: Any) -> str:
    text = str(value or "")
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_redact_value(child) for child in value]
    if isinstance(value, tuple):
        return [_redact_value(child) for child in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _iter_leaf_results(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], dict[str, Any]]]:
    if isinstance(value, dict) and "status" in value:
        runs = value.get("runs")
        if isinstance(runs, list) and runs:
            for index, run in enumerate(runs, start=1):
                if isinstance(run, dict):
                    yield (*path, f"run[{index}]"), run
        else:
            yield path, value
        return
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_leaf_results(child, (*path, str(key)))


def _category(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("category") or "").lower()
    if explicit in {"vulnerability", "candidate", "discovery", "observation"}:
        return explicit
    return "observation" if str(finding.get("risk") or "info").lower() == "info" else "candidate"


def _references(raw: dict[str, Any]) -> list[str]:
    value = raw.get("references") or raw.get("reference") or []
    values = value if isinstance(value, list) else [value]
    return list(dict.fromkeys(_redact_text(item).strip() for item in values if str(item).strip()))


def _identifier_lines(raw: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key, label in (
        ("template_id", "Nuclei template"),
        ("plugin_id", "ZAP plugin"),
        ("cwe_id", "CWE"),
        ("wasc_id", "WASC"),
        ("cvss_score", "CVSS score"),
        ("cvss_metrics", "CVSS vector"),
    ):
        if raw.get(key) not in (None, "", []):
            values.append(f"{label}: {_redact_text(raw.get(key))}")
    for key, label in (("cve_ids", "CVE"), ("cwe_ids", "CWE")):
        items = raw.get(key) or []
        if not isinstance(items, list):
            items = [items]
        if items:
            values.append(f"{label}: {', '.join(_redact_text(item) for item in items)}")
    return list(dict.fromkeys(values))


def _verification_status(raw: dict[str, Any], category: str) -> str:
    explicit = str(raw.get("verification_status") or "").strip()
    if explicit:
        return explicit
    return {
        "vulnerability": "scanner-confirmed",
        "candidate": "requires-manual-validation",
        "discovery": "discovery-only",
        "observation": "observation",
    }.get(category, "unspecified")


def _normalize_finding(raw: dict[str, Any], profile: str, tool: str) -> dict[str, Any]:
    risk = str(raw.get("risk") or "info").lower()
    category = _category(raw)
    alert = _redact_text(raw.get("alert") or "Unnamed scanner finding").strip()
    url = _redact_text(raw.get("url") or "").strip()
    description = _redact_text(raw.get("description") or "").strip()
    impact = _redact_text(raw.get("impact") or "").strip()
    solution = _redact_text(raw.get("solution") or "").strip()
    evidence = _redact_text(raw.get("evidence") or "").strip()
    if category in {"observation", "discovery"} and len(evidence) > 1200:
        evidence = evidence[:1200] + "\n[Evidence truncated in human-readable report.]"
    technical = _redact_text(raw.get("technical_details") or raw.get("other_information") or "").strip()
    reproduction = _redact_text(raw.get("reproduction") or "").strip()
    attack_preconditions = _redact_text(raw.get("attack_preconditions") or raw.get("preconditions") or "").strip()
    owasp_category = _redact_text(raw.get("owasp_category") or "").strip()
    payload = _redact_text(raw.get("payload") or "").strip()
    payloads = raw.get("payloads") or []
    if not isinstance(payloads, list):
        payloads = [payloads]
    payloads = [_redact_text(value) for value in payloads if str(value)]

    data_quality_notes: list[str] = []
    if not description:
        data_quality_notes.append(
            "The scanner did not supply a narrative description; the report retained only the actual structured fields and evidence."
        )
    if not impact:
        data_quality_notes.append("The scanner did not provide a separate impact statement; the report did not infer one.")
    if not solution:
        data_quality_notes.append("The scanner did not provide remediation guidance; the report did not invent a recommendation.")
    if not evidence:
        data_quality_notes.append("No request, response, payload, matcher, or other evidence was supplied by the scanner.")

    preserved = {
        key: _redact_value(value)
        for key, value in raw.items()
        if key not in {
            "alert", "risk", "category", "verification_status", "confidence",
            "description", "impact", "solution", "url", "method", "parameter",
            "evidence", "technical_details", "other_information", "reproduction",
            "references", "reference", "attack_preconditions", "preconditions",
            "owasp_category", "payload", "payloads",
        }
        and value not in (None, "", [], {})
    }
    return {
        "profile": profile,
        "tool": tool,
        "alert": alert,
        "risk": risk,
        "category": category,
        "verification_status": _verification_status(raw, category),
        "confidence": _redact_text(raw.get("confidence") or "not supplied"),
        "url": url,
        "method": _redact_text(raw.get("method") or raw.get("request_method") or ""),
        "parameter": _redact_text(raw.get("parameter") or ""),
        "description": description,
        "technical_details": technical,
        "evidence": evidence,
        "impact": impact,
        "solution": solution,
        "reproduction": reproduction,
        "attack_preconditions": attack_preconditions,
        "owasp_category": owasp_category,
        "payload": payload,
        "payloads": payloads,
        "references": _references(raw),
        "identifiers": _identifier_lines(raw),
        "data_quality_notes": data_quality_notes,
        "scanner_fields": preserved,
    }


AUTO_INDEX_QUERY_KEYS = {"c", "n", "m", "s", "d", "o"}


def _canonical_finding_url(value: str) -> str:
    parsed = urlparse(str(value or ""))
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = "" if pairs and {name.lower() for name, _ in pairs} <= AUTO_INDEX_QUERY_KEYS else urlencode(pairs)
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))


def _finding_route_key(value: str) -> str:
    """Normalize a finding URL by route and parameter names, not test values.

    Corroborating scanners often use different payload values for the same
    endpoint/parameter.  Using the raw query string made those confirmations
    appear as separate vulnerabilities (and also split repeated LFI examples).
    """
    parsed = urlparse(str(value or ""))
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    names = sorted({name.lower() for name, _ in pairs if name})
    if names and set(names) <= AUTO_INDEX_QUERY_KEYS:
        query = ""
    else:
        query = urlencode([(name, "*") for name in names])
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))


def _finding_family(row: dict[str, Any]) -> str:
    alert = str(row.get("alert") or "").lower()
    verification = str(row.get("verification_status") or "").lower()
    if "php diagnostic" in alert or "phpinfo" in alert:
        return "php-diagnostic-exposure"
    if "directory listing" in alert or "directory indexing" in alert or "directory-index" in verification:
        return "directory-listing"
    if "backup configuration or source" in alert or "source-disclosure" in verification:
        return "source-configuration-disclosure"
    if "environment configuration" in alert:
        return "environment-file-disclosure"
    if "git repository" in alert or "git-metadata" in verification:
        return "git-metadata-disclosure"
    if "sql injection" in alert:
        return "sql-injection"
    if "stored xss" in alert or "stored-marker" in verification:
        return "stored-xss"
    if "dom xss" in alert or "url fragment" in alert:
        return "dom-xss"
    if "reflected" in alert and ("xss" in alert or "cross-site scripting" in alert):
        return "reflected-xss"
    if "cross-site scripting" in alert or re.search(r"\bxss\b", alert):
        return "xss"
    if "path traversal" in alert or "local file inclusion" in alert:
        return "path-traversal-lfi"
    if "out-of-band interaction" in alert:
        return "oast-interaction"
    if "csrf" in alert or "anti-csrf" in alert:
        return "csrf"
    if "session fixation" in alert:
        return "session-fixation"
    if "lacks httponly" in alert:
        return "cookie-httponly"
    if "lacks secure" in alert:
        return "cookie-secure"
    if "lacks samesite" in alert:
        return "cookie-samesite"
    normalized = re.sub(r"\s+in parameter ['\"][^'\"]+['\"]$", "", alert)
    return normalized


def _finding_strength(row: dict[str, Any]) -> tuple[int, int, int, int]:
    category_score = {"vulnerability": 3, "candidate": 2, "observation": 1, "discovery": 0}.get(str(row.get("category") or ""), 0)
    confidence_score = {"high": 3, "medium": 2, "low": 1}.get(str(row.get("confidence") or "").lower(), 0)
    return (category_score, RISK_ORDER.get(str(row.get("risk") or "info"), 0), confidence_score, len(str(row.get("evidence") or "")))


def _merge_finding_rows(existing: dict[str, Any], row: dict[str, Any], profile: str, tool: str) -> None:
    profiles = existing.setdefault("profiles", [])
    if profile not in profiles:
        profiles.append(profile)
    tools = existing.setdefault("tools", [existing.get("tool", "unknown")])
    if tool not in tools:
        tools.append(tool)
    affected_urls = existing.setdefault("affected_urls", [existing.get("url", "")])
    if row.get("url") and row.get("url") not in affected_urls:
        affected_urls.append(row.get("url"))
    corroboration = existing.setdefault("corroborating_findings", [])
    corroboration.append({
        "tool": tool,
        "profile": profile,
        "verification_status": row.get("verification_status", ""),
        "risk": row.get("risk", ""),
        "url": row.get("url", ""),
    })
    if _finding_strength(row) > _finding_strength(existing):
        for key in (
            "alert", "risk", "category", "verification_status", "confidence",
            "description", "technical_details", "evidence", "impact", "solution",
            "reproduction", "attack_preconditions", "owasp_category", "payload",
            "payloads", "references", "identifiers", "data_quality_notes", "scanner_fields",
            "method", "parameter",
        ):
            if row.get(key) not in (None, "", [], {}):
                existing[key] = row[key]
    existing["tool"] = ", ".join(sorted(set(str(value) for value in tools if value)))
    existing["profile"] = ", ".join(sorted(set(profiles)))
    existing["occurrence_count"] = int(existing.get("occurrence_count", 1)) + 1


def flatten_findings(results: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize and semantically merge corroborating findings from all tools."""
    merged: dict[tuple[str, ...], dict[str, Any]] = {}
    for path, result in _iter_leaf_results(results):
        profile = path[0] if path else str(result.get("profile") or "unknown")
        tool = path[1].split(":", 1)[0] if len(path) > 1 else str(result.get("tool") or "unknown")
        for raw in result.get("vulnerabilities") or []:
            if not isinstance(raw, dict):
                continue
            row = _normalize_finding(raw, profile, tool)
            canonical_url = _canonical_finding_url(str(row.get("url") or ""))
            if row.get("category") in {"vulnerability", "candidate"}:
                family = _finding_family(row)
                parameter = str(row.get("parameter") or "").lower()
                fingerprint = (family, _finding_route_key(str(row.get("url") or "")), parameter)
            else:
                fingerprint = (
                    str(row.get("tool") or ""),
                    str(row.get("alert") or ""),
                    str(row.get("risk") or ""),
                    str(row.get("category") or ""),
                    canonical_url,
                    str(row.get("parameter") or "").lower(),
                    str(row.get("verification_status") or ""),
                )
            existing = merged.get(fingerprint)
            if existing is None:
                row["profiles"] = [profile]
                row["tools"] = [tool]
                row["canonical_url"] = canonical_url
                row["affected_urls"] = [row.get("url", "")] if row.get("url") else []
                row["corroborating_findings"] = []
                merged[fingerprint] = row
            else:
                _merge_finding_rows(existing, row, profile, tool)

    rows = list(merged.values())
    for row in rows:
        row["profiles"] = sorted(set(row.get("profiles") or [row.get("profile", "unknown")]))
        row["profile"] = ", ".join(row["profiles"])
        row["tools"] = sorted(set(str(value) for value in row.get("tools", []) if value))
        row["tool"] = ", ".join(row["tools"]) or str(row.get("tool") or "unknown")
    return sorted(
        rows,
        key=lambda row: (
            row["category"] == "vulnerability",
            row["category"] == "candidate",
            RISK_ORDER.get(row["risk"], 0),
            row["alert"],
        ),
        reverse=True,
    )


def _finding_groups(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return {
        "vulnerability": [item for item in findings if item.get("category") == "vulnerability"],
        "candidate": [item for item in findings if item.get("category") == "candidate"],
        "observation": [item for item in findings if item.get("category") == "observation"],
        "discovery": [item for item in findings if item.get("category") == "discovery"],
    }


def _truncate_human_value(value: Any, *, string_limit: int = 1400, list_limit: int = 25) -> Any:
    """Bound HTML-only structured detail while preserving complete JSON data."""
    if isinstance(value, dict):
        return {
            str(key): _truncate_human_value(child, string_limit=string_limit, list_limit=list_limit)
            for key, child in list(value.items())[:list_limit]
        }
    if isinstance(value, list):
        return [
            _truncate_human_value(child, string_limit=string_limit, list_limit=list_limit)
            for child in value[:list_limit]
        ]
    if isinstance(value, tuple):
        return [
            _truncate_human_value(child, string_limit=string_limit, list_limit=list_limit)
            for child in list(value)[:list_limit]
        ]
    if isinstance(value, str) and len(value) > string_limit:
        return value[:string_limit] + "\n[Structured field truncated in human-readable report.]"
    return value


def _human_readable_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Keep all vulnerabilities/candidates while bounding repetitive low-value detail."""
    limits = {"observation": 35, "discovery": 25}
    kept: list[dict[str, Any]] = []
    omitted = {"observation": 0, "discovery": 0}
    counters = {"observation": 0, "discovery": 0}
    for item in findings:
        category = str(item.get("category") or "")
        if category in limits:
            if counters[category] >= limits[category]:
                omitted[category] += 1
                continue
            counters[category] += 1
        human_item = dict(item)
        human_item["scanner_fields"] = _truncate_human_value(
            item.get("scanner_fields") or {}
        )
        kept.append(human_item)
    return kept, omitted


FINDING_SECTION_META = {
    "vulnerability": (
        "Confirmed vulnerabilities",
        "The scanner supplied a bounded payload and response evidence satisfying the tool-specific confirmation rule. Each entry includes preconditions, technical reasoning, impact, remediation and reproduction details when available.",
    ),
    "candidate": (
        "Candidates requiring manual validation",
        "Automated evidence indicates a possible issue, but the report does not present it as confirmed exploitation.",
    ),
    "observation": (
        "Security observations and hardening",
        "Configuration, protocol, or exposure observations that may weaken security but are not confirmed application vulnerabilities.",
    ),
    "discovery": (
        "Discovered attack surface",
        "Reachable paths and parameters retained to explain coverage and guide further testing; these entries are not vulnerabilities.",
    ),
}


def _effective_status(result: dict[str, Any]) -> tuple[str, str]:
    status = str(result.get("status") or "unknown").lower()
    diagnosis = str(result.get("diagnosis") or "").lower()
    combined = "\n".join(str(result.get(key) or "") for key in ("output", "stdout", "stderr"))
    if result.get("hard_failure"):
        return (
            "error" if status == "error" else "partial",
            "At least one sub-scan ended with a real execution failure; any time-limited sub-scans and preserved findings are reported separately.",
        )
    if result.get("timed_out") or result.get("time_limit_reached") or "timeout" in diagnosis or "time limit" in combined.lower():
        return "time_limit", "Configured scan budget reached; retained findings are valid but coverage is incomplete."
    if status == "success" and re.search(
        r"(?:not recognized as an internal or external command|non .? riconosciuto come comando interno o esterno|can't open perl script|modulenotfounderror|traceback \(most recent call last\))",
        combined,
        re.I,
    ):
        return "error", "Result claimed success, but process output contains a launcher or dependency failure."
    return status, ""


def _duration(result: dict[str, Any]) -> float:
    if isinstance(result.get("runs"), list):
        return sum(_duration(run) for run in result["runs"] if isinstance(run, dict))
    meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
    value = result.get("duration_seconds", meta.get("duration_seconds", 0))
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _tool_result(tools: dict[str, Any], tool: str) -> dict[str, Any] | None:
    exact = tools.get(tool)
    if isinstance(exact, dict):
        return exact
    matches = [value for key, value in tools.items() if (key == tool or key.startswith(f"{tool}:")) and isinstance(value, dict)]
    if not matches:
        return None
    statuses = [_effective_status(item)[0] for item in matches]
    if all(status == "error" for status in statuses):
        status = "error"
    elif any(status == "error" for status in statuses) or any(status == "partial" for status in statuses):
        status = "partial"
    elif any(status == "time_limit" for status in statuses):
        status = "time_limit"
    elif any(status == "success" for status in statuses):
        status = "success"
    else:
        status = "skipped"
    findings = [finding for item in matches for finding in (item.get("vulnerabilities") or []) if isinstance(finding, dict)]
    return {
        "tool": tool,
        "status": status,
        "target": matches[0].get("target", ""),
        "output": f"Runs={len(matches)}; statuses={Counter(statuses)}.",
        "vulnerabilities": findings,
        "runs": matches,
    }


def build_coverage(results: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    expected = context.get("expected_tools") if isinstance(context.get("expected_tools"), list) else list(TOOL_PURPOSES)
    profiles = context.get("profiles") if isinstance(context.get("profiles"), list) else list(results)
    profile_names = [item.get("name", item) if isinstance(item, dict) else item for item in profiles]
    for profile in profile_names:
        tools = results.get(profile, {}) if isinstance(results.get(profile), dict) else {}
        for tool in expected:
            result = _tool_result(tools, str(tool))
            if result is None:
                rows.append({
                    "profile": profile,
                    "tool": tool,
                    "status": "not_run",
                    "targets": 0,
                    "findings": 0,
                    "confirmed": 0,
                    "candidates": 0,
                    "observations": 0,
                    "duration_seconds": 0.0,
                    "purpose": TOOL_PURPOSES.get(str(tool), "Security assessment tool."),
                    "details": "No result object was produced for this tool.",
                })
                continue
            status, status_note = _effective_status(result)
            runs = result.get("runs") if isinstance(result.get("runs"), list) else [result]
            details = _redact_text(result.get("output") or status_note)
            raw_findings = [item for item in (result.get("vulnerabilities") or []) if isinstance(item, dict)]
            category_counts = Counter(_category(item) for item in raw_findings)
            rows.append({
                "profile": profile,
                "tool": tool,
                "status": status,
                "targets": len(runs),
                "findings": len(raw_findings),
                "confirmed": category_counts.get("vulnerability", 0),
                "candidates": category_counts.get("candidate", 0),
                "observations": category_counts.get("observation", 0) + category_counts.get("discovery", 0),
                "duration_seconds": round(_duration(result), 2),
                "purpose": TOOL_PURPOSES.get(str(tool), "Security assessment tool."),
                "details": details[:1000],
            })
    return rows


def _coverage_constraints(
    results: dict[str, Any],
    findings: list[dict[str, Any]],
    coverage: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[dict[str, str]]:
    """Describe meaningful untested classes separately from scanner failures.

    A successful or deliberately skipped tool run can still leave a class of
    behaviour unverified (for example, BOLA without a second identity).  These
    rows must not be mixed with execution errors, but they should be visible in
    PDF/HTML/JSON so that a clean execution summary is not mistaken for total
    security coverage.
    """
    constraints: list[dict[str, str]] = []

    def add(area: str, reason: str, next_step: str) -> None:
        key = (area.strip().lower(), reason.strip().lower())
        if not area or not reason:
            return
        if any((row["area"].lower(), row["reason"].lower()) == key for row in constraints):
            return
        constraints.append({"area": area, "reason": reason, "recommended_next_step": next_step})

    profiles = context.get("profiles") if isinstance(context.get("profiles"), list) else []
    authenticated_profiles = [
        row for row in profiles
        if isinstance(row, dict) and bool(row.get("authenticated"))
    ]
    anonymous_profiles = [
        row for row in profiles
        if isinstance(row, dict) and not bool(row.get("authenticated"))
    ]
    if authenticated_profiles and not anonymous_profiles:
        add(
            "Anonymous attack surface",
            "The assessment was run with authenticated profiles only, so unauthenticated exposure and access-control differences were not compared.",
            "Repeat the assessment without --auth-only or include both anonymous and authenticated profiles.",
        )

    if authenticated_profiles and not bool(context.get("secondary_identity_supplied")):
        add(
            "Authorization / BOLA",
            "Only one authenticated identity was supplied. Horizontal and vertical authorization differences between users or roles could not be confirmed.",
            "Provide --secondary-cookies for an account with different ownership or privileges and repeat the read-only authorization checks.",
        )

    coverage_by_tool = {
        str(row.get("tool") or "").lower(): row
        for row in coverage if isinstance(row, dict)
    }
    arjun = coverage_by_tool.get("arjun")
    if arjun and arjun.get("status") == "skipped":
        add(
            "Hidden HTTP parameters",
            "No Arjun-compatible request contract was exercised, so undocumented parameter names were not actively searched.",
            "Review the relaxed Arjun candidate selected in deep/balanced mode or provide an explicit --tool-url for a safe endpoint.",
        )
    idor = coverage_by_tool.get("idor")
    if idor and idor.get("status") == "skipped":
        add(
            "Object-level authorization",
            "No compatible numeric object reference was discovered. UUID, path-segment, JSON-body and multi-step ownership checks remain outside the bounded IDOR verifier.",
            "Supply representative object endpoints and two identities, then perform manual ownership validation.",
        )
    jwt = coverage_by_tool.get("jwt")
    if jwt and jwt.get("status") == "skipped":
        add(
            "JWT validation",
            "No JWT was discovered in the crawled traffic, so token algorithm, lifetime and claim structure were not analysed.",
            "Provide a representative JWT or capture an authenticated API flow if the application uses bearer tokens.",
        )

    for row in findings:
        verification = str(row.get("verification_status") or "").lower()
        if verification == "upload-accepted-location-not-confirmed":
            add(
                "File-upload retrieval and execution",
                "A harmless file was accepted, but no same-origin retrieval URL was confirmed.",
                "Inspect the upload response and discovered upload directories, then verify storage, MIME type and retrieval with a harmless marker.",
            )
            break

    remaining = int(context.get("remaining_eligible_actions_at_report", 0) or 0)
    if remaining:
        add(
            "Agentic execution plan",
            f"{remaining} applicable discovery-derived action(s) remained when the report was created.",
            "Increase --max-rounds or review the agentic planning audit and rerun the omitted applicable actions.",
        )
    planner_audit = context.get("planner_audit") if isinstance(context.get("planner_audit"), list) else []
    if any(isinstance(item, dict) and item.get("remaining_coverage_gaps") for item in planner_audit):
        add(
            "Agentic coverage contract",
            "At least one planner round ended with unresolved applicable tool groups.",
            "Review the round-level coverage gaps and rerun with a stronger model, more rounds or the deterministic baseline.",
        )

    return constraints


def summarize(results: dict[str, Any], findings: list[dict[str, Any]], coverage: list[dict[str, Any]], context: dict[str, Any]) -> dict[str, Any]:
    limitations: list[dict[str, Any]] = []
    for path, result in _iter_leaf_results(results):
        status, note = _effective_status(result)
        if status in {"error", "partial", "time_limit"}:
            limitations.append({
                "path": "/".join(path),
                "status": status,
                "cause": str(result.get("diagnosis") or "unspecified"),
                "explanation": _redact_text(result.get("output") or note),
            })
    risks = Counter(item["risk"] for item in findings)
    categories = Counter(item["category"] for item in findings)
    discovery = context.get("discovery") if isinstance(context.get("discovery"), dict) else {}
    constraints = _coverage_constraints(results, findings, coverage, context)
    execution_complete = not any(row["status"] in {"error", "partial", "time_limit", "not_run"} for row in coverage)
    return {
        "risk_counts": dict(risks),
        "category_counts": dict(categories),
        "limitations": limitations,
        "coverage_constraints": constraints,
        "execution_complete": execution_complete,
        "coverage_complete": execution_complete and not constraints,
        "discovery": discovery,
    }


def _executive_text(summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    confirmed = sum(item["category"] == "vulnerability" for item in findings)
    candidates = sum(item["category"] == "candidate" for item in findings)
    observations = sum(item["category"] in {"observation", "discovery"} for item in findings)
    limits = len(summary["limitations"])
    constraints = len(summary.get("coverage_constraints") or [])
    return (
        f"The automated assessment produced {confirmed} scanner-confirmed findings, {candidates} candidates requiring manual validation, "
        f"and {observations} discovery or hardening observations. {limits} execution limitation(s) and {constraints} coverage constraint(s) were recorded. "
        "The report preserves scanner evidence and metadata; it does not invent unsupported exploitability claims. Confirmed findings include the exact tested parameter, bounded payload, response evidence, impact, remediation and reproduction steps when supplied by the scanner. Repetitive informational details may be summarized in PDF/HTML while the complete normalized set remains in JSON."
    )

# This method is used for convert html file generated into pdf file with Weasyprint
def html2pdf(html_path,pdf_path):
    html_path = Path(html_path).resolve()
    pdf_path = Path(pdf_path).resolve()

    # Keep conversion diagnostics on stderr so the MCP response channel stays clean.
    print("HTML path received:", html_path, file=sys.stderr)
    print("PDF path received:", pdf_path, file=sys.stderr)

    print("Starting HTML2PDF...", file=sys.stderr)

    if not html_path.exists():
        raise FileNotFoundError(f"HTML file not found: {html_path}")

    try:
        # Import lazily: the MCP HTTP service must still start when WeasyPrint is
        # intentionally provided only by the local report Docker image.
        from weasyprint import HTML

        HTML(
            filename=str(html_path),
            base_url=str(html_path.parent)
        ).write_pdf(
            str(pdf_path)
        )
        print("Weasyprint: PDF converted into", pdf_path, file=sys.stderr)
        return
    except (ImportError, OSError) as native_error:
        docker = shutil.which("docker")
        image = os.getenv("SECOPS_REPORT_DOCKER_IMAGE", "secops/report:local").strip() or "secops/report:local"
        if not docker:
            raise RuntimeError(
                "WeasyPrint is unavailable natively and Docker is not available for the report fallback."
            ) from native_error

        inspect = subprocess.run(
            [docker, "image", "inspect", image],
            cwd=str(Path(__file__).resolve().parents[1]),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        if inspect.returncode != 0:
            detail = (inspect.stderr or inspect.stdout or "").strip()
            raise RuntimeError(
                f"WeasyPrint is unavailable natively and report Docker image {image!r} is not ready. "
                f"{detail[-1200:]}"
            ) from native_error

        input_dir = html_path.parent
        output_dir = pdf_path.parent
        output_dir.mkdir(parents=True, exist_ok=True)

        command = [docker, "run", "--rm"]
        if input_dir == output_dir:
            command += [
                "-v", f"{input_dir}:/reports",
                image,
                "python", "-m", "weasyprint",
                f"/reports/{html_path.name}",
                f"/reports/{pdf_path.name}",
            ]
        else:
            command += [
                "-v", f"{input_dir}:/input:ro",
                "-v", f"{output_dir}:/output",
                image,
                "python", "-m", "weasyprint",
                f"/input/{html_path.name}",
                f"/output/{pdf_path.name}",
            ]

        converted = subprocess.run(
            command,
            cwd=str(Path(__file__).resolve().parents[1]),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
        if converted.returncode != 0 or not pdf_path.is_file():
            detail = "\n".join(
                part for part in ((converted.stdout or "").strip(), (converted.stderr or "").strip())
                if part
            )
            raise RuntimeError(
                f"Report Docker conversion failed with exit code {converted.returncode}. "
                f"{detail[-2000:]}"
            ) from native_error

        print("Weasyprint Docker fallback: PDF converted into", pdf_path, file=sys.stderr)

def _esc(value: Any) -> str:
    return html.escape(_redact_text(value))


def _render_list(values: list[str]) -> str:
    return "" if not values else "<ul>" + "".join(f"<li>{_esc(value)}</li>" for value in values) + "</ul>"


def _field(label: str, value: Any, *, pre: bool = False) -> str:
    if value in (None, "", [], {}):
        return ""
    rendered = f"<pre>{_esc(value)}</pre>" if pre else _esc(value)
    return f"<dt>{_esc(label)}</dt><dd>{rendered}</dd>"


def _slugify(text: str, existing: set[str] = frozenset()) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-") or "section"
    if base not in existing:
        return base
    n = 2
    while f"{base}-{n}" in existing:
        n += 1
    return f"{base}-{n}"


def _heading(
    level: int,
    text: str,
    toc: list[tuple[int, str, str]],
    *,
    in_toc: bool = True,
    anchor: str | None = None,
    extra: str = "",
) -> str:
    """Render an <hN> heading and, LaTeX-style, register it into `toc` at the
    moment it is written — writing the heading here is what puts it in the
    table of contents, in this position, in document order. No separate
    list to keep in sync by hand.

    `in_toc=False` is the equivalent of LaTeX's starred `\\section*{}`: the
    heading still gets an anchor (so it can still be linked to), it just
    doesn't get an index entry. Use it for headings that repeat once per
    data row (e.g. one <h3> per finding) — there can be hundreds of those,
    and listing each one would make the index useless for navigation.

    `extra` is raw HTML appended after the escaped title, inside the same
    tag (e.g. a count badge <span>), without leaking into the TOC label.
    """
    slug = anchor or _slugify(text, {a for _, _, a in toc})
    if in_toc:
        toc.append((level, text, slug))
    return f'<h{level} id="{slug}">{_esc(text)}{extra}</h{level}>'


def _render_toc(toc: list[tuple[int, str, str]]) -> str:
    """Render registered (level, text, anchor) entries as nested <ul> lists,
    matching how headings were nested when they were written (h2 under h2,
    h3 nested one level deeper under the preceding h2, etc.) - the same
    structure a LaTeX \\tableofcontents would produce from \\section /
    \\subsection.
    """
    def build(entries: list[tuple[int, str, str]]) -> list[dict]:
        nodes: list[dict] = []
        i = 0
        while i < len(entries):
            level, text, anchor = entries[i]
            j = i + 1
            while j < len(entries) and entries[j][0] > level:
                j += 1
            nodes.append({"text": text, "anchor": anchor, "children": build(entries[i + 1:j])})
            i = j
        return nodes

    def render(nodes: list[dict]) -> str:
        if not nodes:
            return ""
        items = "".join(
            f'<li><a href="#{n["anchor"]}">{_esc(n["text"])}</a>{render(n["children"])}</li>'
            for n in nodes
        )
        return f"<ul>{items}</ul>"

    return render(build(toc))

# Schematic data summary of long json
def _context_summary_html(context: dict[str, Any], toc: list[tuple[int, str, str]]) -> str:

    if not isinstance(context, dict) or not context:
        return "<p>No assessment context was supplied.</p>"

    def dl(rows: list[tuple[str, str]]) -> str:
        return "<dl>" + "".join(f"<dt>{_esc(l)}</dt><dd>{v}</dd>" for l, v in rows) + "</dl>"

    parts: list[str] = []

    # --- Run configuration --------------------------------------------
    run_rows: list[tuple[str, str]] = []
    if context.get("scan_mode"):
        run_rows.append(("Scan mode", _esc(context["scan_mode"])))
    orchestration = context.get("orchestration") if isinstance(context.get("orchestration"), dict) else {}
    if orchestration.get("engine"):
        run_rows.append(("Orchestration engine", _esc(orchestration["engine"])))
    if orchestration.get("mode"):
        run_rows.append(("Orchestration mode", _esc(orchestration["mode"])))
    if orchestration.get("nodes"):
        run_rows.append(("Pipeline phases", _esc(" -> ".join(str(n) for n in orchestration["nodes"]))))
    if context.get("secondary_identity_supplied") is not None:
        run_rows.append((
            "Secondary identity supplied",
            "Yes" if context["secondary_identity_supplied"]
            else "No - authorization/BOLA differentials could not be tested",
        ))
    if context.get("expected_tools"):
        run_rows.append(("Expected tools", _esc(", ".join(str(t) for t in context["expected_tools"]))))
    if run_rows:
        parts.append(_heading(3, "Run configuration", toc) + dl(run_rows))

    # --- Configured limits and timeouts --------------------------------
    limit_rows: list[tuple[str, str]] = []
    if context.get("parameter_endpoint_limit") is not None:
        limit_rows.append(("Endpoints tested per parameter-driven tool", _esc(context["parameter_endpoint_limit"])))
    if context.get("arjun_endpoint_limit") is not None:
        limit_rows.append(("Endpoints tested for hidden-parameter discovery (Arjun)", _esc(context["arjun_endpoint_limit"])))
    for key, label in (
        ("broad_scanner_timeouts", "Broad-scanner timeouts"),
        ("parameter_tool_timeouts", "Parameter-driven tool timeouts"),
    ):
        timeouts = context.get(key)
        if isinstance(timeouts, dict) and timeouts:
            limit_rows.append((label, _esc(", ".join(f"{tool}: {seconds}s" for tool, seconds in timeouts.items()))))
    if limit_rows:
        parts.append(_heading(3, "Configured limits", toc) + dl(limit_rows))

    # --- Per-profile discovery summary ---------------------------------
    profiles_meta = {
        str(row.get("name")): row
        for row in (context.get("profiles") or [])
        if isinstance(row, dict) and row.get("name")
    }
    discovery = context.get("discovery") if isinstance(context.get("discovery"), dict) else {}
    profile_cards: list[str] = []
    for profile_name, data in discovery.items():
        if not isinstance(data, dict):
            continue
        meta = profiles_meta.get(profile_name, {})
        auth_label = "authenticated" if meta.get("authenticated") else "anonymous"
        rows: list[tuple[str, str]] = [("Profile", f"{_esc(profile_name)} ({auth_label})")]

        auth_effective = data.get("authentication_effective")
        if auth_effective is not None:
            rows.append((
                "Authentication verified",
                "Yes - distinguished from the anonymous response" if auth_effective
                else "No - could not be confirmed",
            ))
        prep = data.get("target_preparation") if isinstance(data.get("target_preparation"), dict) else {}
        if prep:
            status = "performed and usable" if prep.get("usable") else ("performed" if prep.get("performed") else "not required")
            rows.append(("Target preparation", _esc(status)))

        counts = [
            f"{label}: {len(data[key])}"
            for key, label in (
                ("urls", "URLs discovered"),
                ("html_urls", "HTML pages"),
                ("form_urls", "Forms"),
                ("parameterized_urls", "Parameterized endpoints"),
                ("request_cases", "Normalized request cases"),
                ("client_side_candidates", "Client-side sink candidates"),
                ("jwt_tokens", "JWTs discovered"),
                ("errors", "Discovery errors"),
            )
            if isinstance(data.get(key), list)
        ]
        if counts:
            rows.append(("Discovered surface", _esc(" | ".join(counts))))

        skipped = data.get("destructive_urls_skipped")
        if isinstance(skipped, list) and skipped:
            rows.append((
                f"Destructive URLs deliberately skipped ({len(skipped)})",
                _render_list([str(u) for u in skipped]),
            ))

        profile_cards.append(f'<div class="card">{dl(rows)}</div>')

    if profile_cards:
        parts.append(_heading(3, "Discovery summary", toc) + "".join(profile_cards))

    return "".join(parts) or "<p>No assessment context was supplied.</p>"


def _render_html(payload: dict[str, Any], *, for_pdf: bool = False) -> str:
    summary = payload["summary"]
    risks = summary["risk_counts"]
    omitted = payload["summary"].get("omitted_human_readable_detail", {})
    detail_cap_note = (
        '<p class="section-note">'
        f"Human-readable detail cap: {omitted.get('observation', 0)} repetitive observations "
        f"and {omitted.get('discovery', 0)} discovery entries were omitted from detailed pages. "
        "Aggregate counts remain in the executive summary and the complete normalized set remains in JSON."
        "</p>"
        if any(omitted.values())
        else ""
    )
    groups = _finding_groups(payload["findings"])

    coverage_rows = "".join(
        "<tr>"
        f'<td class="idx">{index}</td>'
        f"<td>{_esc(row['profile'])}</td>"
        f"<td><b>{_esc(row['tool'])}</b><br><small>{_esc(row.get('purpose', ''))}</small></td>"
        f"<td>{_esc(row['status'])}</td>"
        f"<td>{row['targets']}</td><td>{row.get('confirmed',0)}</td>"
        f"<td>{row.get('candidates',0)}</td><td>{row.get('observations',0)}</td>"
        f"<td>{row['duration_seconds']}</td>"
        "</tr>"
        for index, row in enumerate(payload["coverage"], start=1)
    ) or '<tr><td colspan="9">No execution data.</td></tr>'

    execution_detail_items = "".join(
        f"<li>{_esc(row['details'])}</li>"
        for row in payload["coverage"]
    )
    execution_details_html = (
        f"<ol>{execution_detail_items}</ol>"
        if execution_detail_items
        else "<p>No execution details recorded.</p>"
    )

    limitation_rows = "".join(
        f"<tr><td>{_esc(row['path'])}</td><td>{_esc(row['status'])}</td><td>{_esc(row['cause'])}</td><td>{_esc(row['explanation'])}</td></tr>"
        for row in summary["limitations"]
    ) or '<tr><td colspan="4">No recorded execution limitations.</td></tr>'
    constraint_rows = "".join(
        f"<tr><td>{_esc(row['area'])}</td><td>{_esc(row['reason'])}</td><td>{_esc(row['recommended_next_step'])}</td></tr>"
        for row in summary.get("coverage_constraints", [])
    ) or '<tr><td colspan="3">No additional coverage constraints were recorded.</td></tr>'

    context_value = _redact_value(payload.get("assessment_context") or {})

    toc: list[tuple[int, str, str]] = []

    # --- Cover page -----------------------------------------------------
    generated_at = payload.get("generated_at")
    generated_display = _format_date_en(generated_at) if isinstance(generated_at, datetime) else _esc(generated_at)

    profiles = context_value.get("profiles") if isinstance(context_value, dict) else None
    authenticated = any(isinstance(p, dict) and p.get("authenticated") for p in (profiles or []))
    assessment_type = payload.get("assessment_type") or (
        "Authenticated Web Application Penetration Test" if authenticated else "Web Application Penetration Test"
    )

    client_display = payload.get("client_name") or payload["target"]
    assessor_display = payload.get("assessor") or "SecOps Automated Assessment Platform"
    report_version = payload.get("report_version") or "n/a"
    report_id = payload.get("report_id") or "n/a"

    assessment_start = payload.get("assessment_start") or ""
    assessment_end = payload.get("assessment_end") or ""
    if assessment_start and assessment_end and assessment_start != assessment_end:
        assessment_dates = f"{assessment_start} \u2013 {assessment_end}"
    else:
        assessment_dates = assessment_start or assessment_end or generated_display

    cover_rows: list[tuple[str, str]] = [
        ("Client", _esc(CLIENT_NAME)),
        ("Target", _esc(client_display)),
        ("Assessor / team", _esc(assessor_display)),
        ("Assessment date(s)", _esc(assessment_dates)),
        ("Report issue date", generated_display),
        ("Report version / ID", _esc(f"{report_version} / {report_id}")),
    ]

    cover_html = (
        '<section class="cover">'
        f'<div class="cover-classification">{_esc(REPORT_CLASSIFICATION)}</div>'
        '<div class="cover-body">'
        '<div class="cover-kicker">Security Assessment Report</div>'
        f'<h1 class="cover-title">{_esc(REPORT_TITLE)}</h1>'
        f'<div class="cover-subtitle">{_esc(assessment_type)}</div>'
        "</div>"
        '<table class="cover-meta">'
        + "".join(f"<tr><th>{_esc(label)}</th><td>{value}</td></tr>" for label, value in cover_rows)
        + "</table>"
        "</section>"
    )

    def finding_card(item: dict[str, Any], index: int) -> str:
        notes = item.get("data_quality_notes") or []
        scanner_fields = json.dumps(
            item.get("scanner_fields") or {},
            indent=2,
            ensure_ascii=False,
            default=str,
        )
        heading = _heading(
            3, f"{index}. {item['alert']}", toc,
            in_toc=False,  # one h3 per finding: too many to list in the index (LaTeX \subsection* equivalent)
            anchor=f"finding-{index}",
            extra=f' <span>{_esc(item["risk"]).upper()}</span>',
        )
        return f"""
<article class="finding risk-{_esc(item['risk'])}">
{heading}
<div class="badges">
<b><span class="cat">Status</span><span class="val">{_esc(item['verification_status'])}</span></b>
<b><span class="cat">Confidence</span><span class="val">{_esc(item['confidence'])}</span></b>
<b><span class="cat">Profiles</span><span class="val">{_esc(', '.join(item.get('profiles') or [item['profile']]))}</span></b>
<b><span class="cat">Tool</span><span class="val">{_esc(item['tool'])}</span></b>
</div>
<dl>
{_field('Affected URL', item.get('url'))}
{_field('HTTP method', item.get('method'))}
{_field('Parameter', item.get('parameter'))}
{_field('Description', item.get('description'))}
{_field('Why the evidence confirms or suggests the issue', item.get('technical_details'))}
{_field('Attack preconditions', item.get('attack_preconditions'))}
{_field('Payload / test input', item.get('payload') or '; '.join(item.get('payloads') or []), pre=True)}
{_field('Evidence', item.get('evidence'), pre=True)}
{_field('Security impact', item.get('impact'))}
{_field('Recommended remediation', item.get('solution'))}
{_field('Reproduction / validation steps', item.get('reproduction'), pre=True)}
{_field('OWASP classification', item.get('owasp_category'))}
</dl>
{('<p class="field-label">Identifiers</p>' + _render_list(item.get('identifiers') or [])) if item.get('identifiers') else ''}
{('<p class="field-label">References</p>' + _render_list(item.get('references') or [])) if item.get('references') else ''}
{('<div class="quality"><b>Data-quality notes</b>' + _render_list(notes) + '</div>') if notes else ''}
<details><summary>Additional structured scanner fields</summary><pre>{_esc(scanner_fields)}</pre></details>
</article>"""

    finding_bodies: dict[str, str] = {}
    global_index = 1
    for category in ("vulnerability", "candidate", "observation", "discovery"):
        items = groups[category]
        cards = "".join(
            finding_card(item, index)
            for index, item in enumerate(items, start=global_index)
        )
        global_index += len(items)
        finding_bodies[category] = cards or "<p>No entries in this category.</p>"

    def render_finding_section(category: str) -> str:
        # Registers its own <h2> into `toc` at render time, so it lands in
        # the index exactly where it's written below - last, after the
        # coverage-constraints section.
        title, explanation = FINDING_SECTION_META[category]
        heading = _heading(
            2, title, toc,
            anchor=f"findings-{category}",
            extra=f' <span class="count">{len(groups[category])}</span>',
        )
        return f'<section>{heading}<p class="section-note">{_esc(explanation)}</p>{finding_bodies[category]}</section>'

    glance_items = [
        item for item in payload["findings"]
        if item.get("category") in {"vulnerability", "candidate"}
    ]
    glance_rows = "".join(
        "<tr>"
        f'<td class="idx">{index}</td><td class="no-wrap">{_esc(item.get('risk','info')).upper()}</td>'
        f"<td><b>{_esc(item.get('alert','Unnamed finding'))}</b></td>"
        f"<td>{_esc(item.get('tool',''))}</td>"
        f"<td>{_esc(item.get('url',''))}<br><small>parameter: {_esc(item.get('parameter') or '-')}</small></td>"
        "</tr>"
        for index, item in enumerate(glance_items, 1)
    )
    def render_glance() -> str:
        heading = _heading(2, "Security findings at a glance", toc, anchor="glance")
        if not glance_items:
            return f"{heading}<p>No confirmed vulnerabilities or validation candidates were recorded.</p>"
        return (
            f"{heading}"
            "<p class='section-note'>Confirmed vulnerabilities and candidates are named here before execution details.</p>"
            "<table><thead><tr><th class=\"idx\">#</th><th>Severity</th><th>Finding</th><th>Tool</th><th>Affected endpoint</th></tr></thead>"
            f"<tbody>{glance_rows}</tbody></table>"
        )

    context_json = json.dumps(
        context_value,
        indent=2,
        ensure_ascii=False,
        default=str,
    )
    planner_audit = context_value.get("planner_audit", []) if isinstance(context_value, dict) else []
    audit_rows = ""
    audit_details: list[str] = []
    for item in planner_audit if isinstance(planner_audit, list) else []:
        if not isinstance(item, dict):
            continue
        outcomes = item.get("execution_outcomes", []) if isinstance(item.get("execution_outcomes"), list) else []
        audit_rows += (
            "<tr>"
            f"<td>{_esc(item.get('round',''))}</td>"
            f"<td>{_esc(item.get('planner_source',''))}</td>"
            f"<td>{_esc(item.get('eligible_action_count',0))}</td>"
            f"<td>{_esc(item.get('ai_selected_action_count',0))}</td>"
            f"<td>{_esc(item.get('selected_action_count',0))}</td>"
            f"<td>{_esc(len(item.get('remaining_coverage_gaps',[]) or []))}</td>"
            f"<td>{_esc(len(outcomes))}</td>"
            "</tr>"
        )
        audit_details.append(
            f"<details><summary>Round {_esc(item.get('round',''))}: {_esc(item.get('planner_source',''))}</summary>"
            f"<p><b>Planner summary:</b> {_esc(item.get('reasoning_summary',''))}</p>"
            f"<pre>{_esc(json.dumps(item, indent=2, ensure_ascii=False, default=str))}</pre></details>"
        )
    def render_agentic_audit() -> str:
        if not audit_rows:
            return ""
        heading = _heading(2, "Agentic planning audit", toc, anchor="agentic-audit")
        return (
            f"{heading}"
            "<p class='section-note'>This section records model-selected actions, coverage repair, fallback use and execution outcomes. It contains concise planner summaries, not hidden chain-of-thought.</p>"
            "<table><thead><tr><th>Round</th><th>Planner</th><th>Eligible</th><th>AI selected</th><th>Executed plan</th><th>Gaps</th><th>Outcomes</th></tr></thead>"
            f"<tbody>{audit_rows}</tbody></table>{''.join(audit_details)}"
        )

    # Phase 1: render the body. Every _heading()/render_*() call below fires
    # in the exact order it's written here, appending to `toc` as it goes -
    # this is what makes the index "automatic": you don't edit a separate
    # list, you just write (or move) a heading and the index follows.
    body_html = f"""
{_heading(2, "Executive summary", toc, anchor="executive")}<div class="card">{_esc(payload['executive_summary'])}</div>
{render_glance()}
<div class="grid">{''.join(f'<div class="card"><div class="value">{risks.get(risk,0)}</div><div>{risk.title()}</div></div>' for risk in ('critical','high','medium','low'))}<div class="card"><div class="value">{len(summary['limitations'])}</div><div>Execution limitations</div><div class="value">{len(summary.get('coverage_constraints', []))}</div><div>Coverage constraints</div></div></div>

{detail_cap_note}
{_heading(2, "Scope and assessment context", toc, anchor="scope")}
{_context_summary_html(context_value, toc)}
{"" if for_pdf else f'<details><summary>Raw assessment context (JSON)</summary><pre>{_esc(context_json)}</pre></details>'}
{'<p class="section-note">The full technical context (discovered URLs, normalized request cases, client-side sink candidates) is available in the attached JSON report.</p>' if for_pdf else ""}
{render_agentic_audit()}

{_heading(2, "Assessment execution", toc, anchor="execution")}
<p class="section-note">This section records tools, targets, duration and execution status. It is deliberately separate from security findings.</p>
<table><colgroup><col style="width:2%"><col style="width:10%"><col style="width:26%"><col style="width:10%"><col style="width:8%"><col style="width:10%"><col style="width:11%"><col style="width:15%"><col style="width:8%"></colgroup><thead><tr><th>#</th><th>Profile</th><th>Tool and purpose</th><th>Status</th><th>Targets</th><th>Confirmed</th><th>Candidates</th><th>Info/discovery</th><th>Seconds</th></tr></thead><tbody>{coverage_rows}</tbody></table>

{_heading(3, "Execution details", toc, anchor="execution-details")}
<p class="section-note">Raw execution output per row, numbered to match the table above.</p>
{execution_details_html}

{_heading(2, "Execution limitations", toc, anchor="limitations")}
<table><thead><tr><th>Run</th><th>Status</th><th>Cause</th><th>Explanation</th></tr></thead><tbody>{limitation_rows}</tbody></table>

{_heading(2, "Coverage constraints and untested classes", toc, anchor="constraints")}
<p class="section-note">These rows are not scanner failures. They identify security classes that could not be fully validated with the supplied identities, traffic and request contracts.</p>
<table><thead><tr><th>Area</th><th>Reason</th><th>Recommended next step</th></tr></thead><tbody>{constraint_rows}</tbody></table>

{''.join(render_finding_section(category) for category in ("vulnerability", "candidate", "observation", "discovery"))}
"""
    # toc[] is now fully populated -> Phase 2: render the index from it.
    # (Same reason LaTeX needs two compilation passes: the ToC appears
    # before the content it points to, so it can only be built after that
    # content has already been rendered once.)
    toc_html = _render_toc(toc)

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>SecOps Assessment Report</title>
<style>
@page {{
    size: A4;
    margin: 10mm 0;
    background-color: #f4f6f8;
    @bottom-center {{
        content: counter(page);
    }}
}}
.toc a::after {{
    content: leader('.') target-counter(attr(href), page);
}}

.toc {{
    break-after: page;
}}
body{{font-family:Arial,sans-serif;background:#f4f6f8;color:#17212b;margin:0}}
main{{max-width:1220px;margin:auto;padding:28px}}
h1,h2,h3{{color:#173b5e}}h2{{margin-top:32px}}
.meta,.card,.finding{{background:white;border:1px solid #d7dee5;border-radius:10px;padding:16px;margin:12px 0}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}}
.value{{font-size:2rem;font-weight:700}}
table{{table-layout:auto;width:100%;border-collapse:collapse;background:white;font-size:.74rem}}
th,td{{padding:5px 6px;border:1px solid #cbd5df;overflow-wrap:anywhere;word-break:break-word}}
th{{background:#24476b;color:white;position:sticky;top:0;white-space:nowrap}}
.no-wrap{{white-space:nowrap}}
.idx{{white-space:nowrap;width:1%;text-align:center}}
small{{color:#4f6273}}.finding{{border-left:7px solid #4b86b4}}
.risk-critical,.risk-high{{border-left-color:#a90000}}.risk-medium{{border-left-color:#d98200}}.risk-low{{border-left-color:#b49b00}}
.badges{{display: flex;flex-wrap: wrap;gap: 6px;justify-content: center;align-items: center;}}
.badges b{{display: inline-flex;align-items: stretch;overflow: hidden;border-radius: 12px;font-size: .82rem;font-weight: normal;box-shadow: 0 0 0 1px #d3dde5;margin: 5px}}
.badges .cat{{background: #3b5b7a;color: #fff;font-weight: 600;padding: 4px 8px;text-transform: uppercase;letter-spacing: .03em;font-size: .72rem;display: flex;align-items: center;}}
.badges .val {{background: #e8eef4;color: #1f2d3a;padding: 4px 8px;display: flex;align-items: center;}}
dl{{display:grid;grid-template-columns:190px minmax(0,1fr);gap:8px 14px}}
dt{{font-weight:700;overflow-wrap:anywhere;min-width:0}}
dd{{margin:0;overflow-wrap:anywhere;word-break:break-word;min-width:0}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;background:#101821;color:#e5edf5;padding:12px;border-radius:8px}}
.quality{{background:#fff8dc;border:1px solid #e1cb73;padding:10px;border-radius:8px}}
details{{margin-top:14px}}.section-note{{background:#eaf1f7;border-left:4px solid #527ca3;padding:10px}}
.count{{font-size:.85rem;background:#dce8f3;border-radius:12px;padding:3px 8px}}
.toc a{{color: black;text-decoration: none;}}
.toc ul{{list-style: none;padding-left: 0;}}
.toc ul ul{{padding-left: 22px;}}
.toc-title{{margin-top:0}}
ol li::marker{{font-weight:bold;}}
.field-label{{font-weight:700;margin:14px 0 6px;color:#173b5e}}
.cover{{break-after:page;min-height:250mm;display:flex;flex-direction:column;justify-content:space-between;background:white;border:1px solid #d7dee5;border-radius:10px;padding:40px;margin:0 0 12px}}
.cover-classification{{align-self:flex-end;background:#8a1f1f;color:white;font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:.85rem;padding:6px 14px;border-radius:4px}}
.cover-body{{margin-top:70px}}
.cover-kicker{{color:#4b86b4;font-weight:700;letter-spacing:.12em;text-transform:uppercase;font-size:.95rem;margin-bottom:14px}}
.cover-title{{font-size:2.6rem;line-height:1.15;margin:0 0 14px;max-width:80%}}
.cover-subtitle{{font-size:1.3rem;color:#4f6273;font-weight:600}}
.cover-meta{{table-layout:auto;width:auto;font-size:.9rem;margin-top:50px}}
.cover-meta th{{background:none;color:#4f6273;text-align:left;white-space:nowrap;border:none;border-top:1px solid #d7dee5;padding:10px 24px 10px 0}}
.cover-meta td{{border:none;border-top:1px solid #d7dee5;padding:10px 0;font-weight:600;overflow-wrap:anywhere;word-break:break-word}}
</style></head><body><main>
{cover_html}

<div class="toc">
<h2 class="toc-title" id="index">Index</h2>
{toc_html}
</div>
{body_html}
</main></body></html>"""



def _p(value: Any) -> str:
    return html.escape(_redact_text(value)).replace("\n", "<br/>")


@mcp.tool()
def generate_report(
    findings_summary: dict | str,
    target_url: str,
    output_name: str = "",
    assessment_context: dict | str | None = None,
    client_name: str = "",
    assessor: str = "",
    assessment_type: str = "",
    assessment_start: str = "",
    assessment_end: str = "",
    report_version: str = "1.0",
) -> dict:
    """Generate scanner-grounded JSON, HTML and PDF penetration-test reports.

    client_name, assessor, assessment_type, assessment_start/end and
    report_version are optional cover-page fields. Any left blank fall back
    to a neutral, non-fabricated default (e.g. target for client_name) -
    see _render_html's cover section.
    """
    try:
        results = _as_dict(findings_summary)
        context = _as_dict(assessment_context)
    except (json.JSONDecodeError, ValueError) as exc:
        return failure("Report Generator", target_url, f"Invalid report input: {exc}", diagnosis="invalid_report_input")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    base = _safe_name(output_name) or f"SecOps_Assessment_{datetime.now():%Y%m%d_%H%M%S}"
    json_path = Path(REPORTS_DIR) / f"{base}.json"
    html_path = Path(REPORTS_DIR) / f"{base}.html"
    pdf_path = Path(REPORTS_DIR) / f"{base}.pdf"
    all_findings = flatten_findings(results)
    findings, omitted_detail = _human_readable_findings(all_findings)
    coverage = build_coverage(results, context)
    summary = summarize(results, all_findings, coverage, context)
    summary["omitted_human_readable_detail"] = omitted_detail
    payload = {
        "generated_at": datetime.now(timezone.utc),
        "target": target_url,
        "reporting_policy": "Scanner-grounded: missing claims are identified, not invented.",
        "executive_summary": _executive_text(summary, findings),
        "summary": summary,
        "coverage": coverage,
        "security_findings_count": sum(item["category"] == "vulnerability" for item in findings),
        "candidate_findings_count": sum(item["category"] == "candidate" for item in findings),
        "observations_count": sum(item["category"] in {"discovery", "observation"} for item in findings),
        "findings_count": len(findings),
        "findings": findings,
        "all_findings": all_findings,
        "findings_by_category": _finding_groups(findings),
        "assessment_context": _redact_value(context),
        "results": _redact_value(results),
        "client_name": client_name,
        "assessor": assessor,
        "assessment_type": assessment_type,
        "assessment_start": assessment_start,
        "assessment_end": assessment_end,
        "report_version": report_version,
        "report_id": base,
    }

    try:
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        html_path.write_text(_render_html(payload), encoding="utf-8")
    except Exception as exc:
        return failure("Report Generator", target_url, f"JSON/HTML report creation failed: {type(exc).__name__}: {exc}", diagnosis="report_serialization_failed")

    # The PDF is rendered from a separate, PDF-only HTML render (for_pdf=True):
    # same content, minus sections that only make sense in an interactive
    # browser (e.g. the raw JSON context dump, which WeasyPrint can't
    # collapse into a <details> the way a browser does). The full HTML
    # served to the user (html_path, written above) is unaffected.
    pdf_source_path = html_path.with_name(f"{html_path.stem}.pdf-source.html")
    try:
        pdf_source_path.write_text(_render_html(payload, for_pdf=True), encoding="utf-8")
        html2pdf(pdf_source_path, pdf_path)
    except Exception as exc:
        result = failure("Report Generator", target_url, f"PDF report creation failed: {type(exc).__name__}: {exc}", diagnosis="pdf_generation_failed")
        result.update(json_filename=str(json_path.resolve()), html_filename=str(html_path.resolve()), pdf_filename=None, findings_count=len(findings))
        return result
    finally:
        pdf_source_path.unlink(missing_ok=True)

    pwndoc_url = os.getenv("PWNDOC_URL", "").rstrip("/")
    pwndoc_status = "not_configured"
    if pwndoc_url:
        try:
            response = requests.get(pwndoc_url, timeout=4, verify=os.getenv("PWNDOC_VERIFY_TLS", "true").lower() not in {"0", "false", "no"})
            pwndoc_status = "reachable" if response.status_code < 500 else "unhealthy"
        except requests.RequestException:
            pwndoc_status = "offline"

    return success(
        "Report Generator",
        target_url,
        (
            f"Scanner-grounded PDF, HTML and JSON reports generated. "
            f"Confirmed findings: {payload['security_findings_count']}; "
            f"candidates: {payload['candidate_findings_count']}; observations: {payload['observations_count']}."
        ),
        pdf_filename=str(pdf_path.resolve()),
        html_filename=str(html_path.resolve()),
        json_filename=str(json_path.resolve()),
        local_pdf_generated=True,
        local_html_generated=True,
        local_json_generated=True,
        findings_count=len(findings),
        security_findings_count=payload["security_findings_count"],
        candidate_findings_count=payload["candidate_findings_count"],
        observations_count=payload["observations_count"],
        execution_limitations_count=len(summary.get("limitations") or []),
        coverage_constraints_count=len(summary.get("coverage_constraints") or []),
        execution_complete=bool(summary.get("execution_complete")),
        coverage_complete=bool(summary.get("coverage_complete")),
        pwndoc_status=pwndoc_status,
    )


if __name__ == "__main__":
    run_mcp_http(mcp, "report")