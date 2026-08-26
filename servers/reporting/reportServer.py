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
CLIENT_NAME = ""

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

    ai_analysis_raw = raw.get("ai_analysis") if isinstance(raw.get("ai_analysis"), dict) else {}
    ai_analysis = _redact_value(ai_analysis_raw) if ai_analysis_raw else {}
    scanner_risk = _redact_text(raw.get("scanner_risk") or "").strip()
    scanner_confidence = _redact_text(
        raw.get("scanner_confidence") or raw.get("confidence") or "not supplied"
    ).strip()
    scanner_description = _redact_text(raw.get("scanner_description") or "").strip()
    scanner_impact = _redact_text(raw.get("scanner_impact") or "").strip()
    scanner_solution = _redact_text(raw.get("scanner_solution") or "").strip()

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
            "scanner_risk", "scanner_confidence", "scanner_description",
            "scanner_impact", "scanner_solution", "ai_analysis",
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
        "scanner_confidence": scanner_confidence,
        "ai_analysis": ai_analysis,
        "scanner_risk": scanner_risk,
        "scanner_description": scanner_description,
        "scanner_impact": scanner_impact,
        "scanner_solution": scanner_solution,
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


# Bounds verbose human-readable evidence while the complete data remains in JSON.
def _report_excerpt(value: Any, *, max_chars: int = 2200, max_lines: int = 28) -> str:
    text = _redact_text(value).strip()
    if not text:
        return ""
    lines = text.splitlines()
    clipped = len(text) > max_chars or len(lines) > max_lines
    if len(lines) > max_lines:
        text = "\n".join(lines[:max_lines])
    if len(text) > max_chars:
        text = text[:max_chars].rstrip()
    if clipped:
        text += "\n[Excerpt shortened in PDF/HTML; complete evidence is preserved in JSON.]"
    return text


def _field(label: str, value: Any, *, pre: bool = False, max_chars: int = 2200, max_lines: int = 28) -> str:
    if value in (None, "", [], {}):
        return ""
    rendered_value = _report_excerpt(value, max_chars=max_chars, max_lines=max_lines) if pre else _redact_text(value).strip()
    if not rendered_value:
        return ""
    rendered = f"<pre>{_esc(rendered_value)}</pre>" if pre else _esc(rendered_value)
    return f"<dt>{_esc(label)}</dt><dd>{rendered}</dd>"


def _render_html(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    risks = summary["risk_counts"]
    context = _redact_value(payload.get("assessment_context") or {})
    groups = _finding_groups(payload["findings"])
    is_agentic = str((context.get("orchestration") or {}).get("mode") or "").lower() == "agentic" or bool(context.get("ai_analysis"))
    generated = payload.get("generated_at")
    generated_dt = generated if isinstance(generated, datetime) else datetime.now(timezone.utc)
    report_date = _format_date_en(generated_dt.astimezone())
    report_id = str(payload.get("report_id") or context.get("report_id") or "").strip() or f"SecOps_Assessment_{generated_dt:%Y%m%d_%H%M%S}"
    client = str(context.get("client_name") or CLIENT_NAME or "CLIENT NAME")
    profiles = context.get("profiles") if isinstance(context.get("profiles"), list) else []
    authenticated = any(bool(row.get("authenticated")) for row in profiles if isinstance(row, dict))
    subtitle = "Authenticated Web Application Penetration Test" if authenticated else "Web Application Penetration Test"

    security_findings = [item for item in payload["findings"] if item.get("category") in {"vulnerability", "candidate"}]
    confirmed = [item for item in payload["findings"] if item.get("category") == "vulnerability"]
    risk_source = confirmed or security_findings
    overall_risk = max(
        (str(item.get("risk") or "info").lower() for item in risk_source),
        key=lambda value: RISK_ORDER.get(value, 0),
        default="info",
    )
    overall_label = overall_risk.upper()

    omitted = summary.get("omitted_human_readable_detail", {})
    detail_cap_note = (
        '<p class="section-note">'
        f"Human-readable detail cap: {omitted.get('observation', 0)} repetitive observations "
        f"and {omitted.get('discovery', 0)} discovery entries were omitted from detailed pages. "
        "Aggregate counts remain in the executive summary and the complete normalized set remains in JSON."
        "</p>"
        if any(omitted.values()) else ""
    )

    methodology_intro = (
        "Severity shown in detailed findings is the final evidence-grounded AI assessment. It starts from the scanner-supplied "
        "rating and may be adjusted only from preserved scanner or verifier evidence. Original scanner severity and narrative remain "
        "available as a secondary audit view. Finding category, verification status, affected request and evidence are not changed by AI."
        if is_agentic else
        "Severity is the risk rating supplied by the originating scanner for each finding, escalated to a confirmed vulnerability only "
        "when the tool-specific evidence rule described in Methodology is satisfied. The definitions below describe what each rating "
        "means for prioritization; they are not recalculated per finding."
    )

    risk_definitions = (
        ("Critical", "Immediate, severe threat to confidentiality, integrity or availability with demonstrated catastrophic impact (for example unauthenticated remote code execution or full data-store compromise). Requires emergency remediation, typically within 24-48 hours."),
        ("High", "Significant security impact that is straightforward to exploit or undermines a core security control (for example confirmed SQL injection or authentication bypass). Requires urgent remediation, typically within one to two weeks."),
        ("Medium", "Meaningful weakness with more constrained impact or exploitability (for example reflected XSS or missing authorization checks on non-critical functions). Should be remediated within the next release cycle."),
        ("Low", "Limited security impact, often requiring specific preconditions or giving only marginal advantage to an attacker. Should be scheduled for remediation."),
        ("Info", "Observations, hardening opportunities or discovered attack surface that do not constitute a confirmed vulnerability but support defense-in-depth and future testing."),
    )
    risk_table_rows = "".join(
        f'<tr><td><span class="risk-dot risk-dot-{name.lower()}"></span><b>{name}</b></td><td>{_esc(text)}</td></tr>'
        for name, text in risk_definitions
    )

    priority_items = [item for item in security_findings if item.get("solution")][:10]
    priority_html = "".join(
        f'<li><b>[{_esc(item.get("risk", "info")).upper()}] {_esc(item.get("alert", "Finding"))}</b> - {_esc(item.get("url") or payload["target"])}'
        f'<div>{_esc(_report_excerpt(item.get("solution"), max_chars=420, max_lines=5))}</div></li>'
        for item in priority_items
    ) or '<li>No confirmed vulnerability or validation candidate supplied remediation guidance.</li>'

    glance_rows = "".join(
        "<tr>"
        f'<td>{index}</td><td class="severity-cell severity-{_esc(item.get("risk", "info"))}">{_esc(item.get("risk", "info")).upper()}</td>'
        f'<td><b>{_esc(item.get("alert", "Unnamed finding"))}</b></td>'
        f'<td>{_esc(item.get("tool", ""))}</td>'
        f'<td>{_esc(item.get("url", ""))}<br><span class="muted">parameter: {_esc(item.get("parameter") or "-")}</span></td>'
        "</tr>"
        for index, item in enumerate(security_findings[:20], 1)
    ) or '<tr><td colspan="5">No confirmed vulnerabilities or validation candidates were recorded.</td></tr>'
    glance_note = (
        f'<p class="small-note">Only the first 20 of {len(security_findings)} security findings are shown here; all detailed entries follow later.</p>'
        if len(security_findings) > 20 else ""
    )

    orchestration = context.get("orchestration") if isinstance(context.get("orchestration"), dict) else {}
    nodes = orchestration.get("nodes") if isinstance(orchestration.get("nodes"), list) else []
    pipeline = " -> ".join(str(value) for value in nodes) if nodes else str(context.get("pipeline_phases") or "not supplied")
    expected_tools = context.get("expected_tools") if isinstance(context.get("expected_tools"), list) else []
    secondary_identity = "Yes" if context.get("secondary_identity_supplied") else "No - authorization/BOLA differentials may be constrained"
    run_config_rows = "".join((
        f'<tr><th>Scan mode</th><td>{_esc(context.get("scan_mode") or "not supplied")}</td></tr>',
        f'<tr><th>Orchestration engine</th><td>{_esc(orchestration.get("engine") or "not supplied")}</td></tr>',
        f'<tr><th>Orchestration mode</th><td>{_esc(orchestration.get("mode") or "not supplied")}</td></tr>',
        f'<tr><th>Pipeline phases</th><td>{_esc(pipeline)}</td></tr>',
        f'<tr><th>Secondary identity supplied</th><td>{_esc(secondary_identity)}</td></tr>',
        f'<tr><th>Expected tools</th><td>{_esc(", ".join(str(value) for value in expected_tools) or "not supplied")}</td></tr>',
    ))

    configured_limit_keys = (
        ("parameter_tool_endpoint_limit", "Endpoints tested per parameter-driven tool"),
        ("arjun_endpoint_limit", "Endpoints tested for hidden-parameter discovery (Arjun)"),
        ("broad_scanner_timeouts", "Broad-scanner timeouts"),
        ("parameter_tool_timeouts", "Parameter-driven tool timeouts"),
    )
    configured_rows = "".join(
        f'<tr><th>{_esc(label)}</th><td>{_esc(json.dumps(context.get(key), ensure_ascii=False, default=str) if isinstance(context.get(key), (dict, list)) else context.get(key))}</td></tr>'
        for key, label in configured_limit_keys if context.get(key) not in (None, "", [], {})
    )
    configured_html = f'<h3>Configured limits</h3><table class="kv-table">{configured_rows}</table>' if configured_rows else ""

    discovery = context.get("discovery") if isinstance(context.get("discovery"), dict) else {}
    discovery_cards: list[str] = []
    for profile_name, found in discovery.items():
        if not isinstance(found, dict):
            continue
        prep = found.get("target_preparation") if isinstance(found.get("target_preparation"), dict) else {}
        prep_text = "performed and usable" if prep.get("performed") and prep.get("usable", True) else ("not required" if not prep.get("performed") else "performed with limitations")
        auth = found.get("authentication_effective")
        auth_text = "Yes" if auth is True else ("No" if auth is False else "Not determined")
        auth_note = str(found.get("authentication_note") or "").strip()
        skipped = found.get("destructive_urls_skipped") or found.get("destructive_urls") or []
        discovery_cards.append(
            '<div class="discovery-card">'
            f'<div class="discovery-label">Profile</div><div><b>{_esc(profile_name)}</b> ({"authenticated" if auth is True else "profile"})</div>'
            f'<div class="discovery-label">Authentication verified</div><div>{_esc(auth_text)}{(" - " + _esc(auth_note)) if auth_note else ""}</div>'
            f'<div class="discovery-label">Target preparation</div><div>{_esc(prep_text)}</div>'
            '<div class="discovery-label">Discovered surface</div>'
            f'<div>URLs discovered: {len(found.get("urls") or [])} | HTML pages: {len(found.get("html_urls") or [])} | Forms: {len(found.get("forms") or [])} | '
            f'Parameterized endpoints: {len(found.get("parameterized_urls") or [])} | Normalized request cases: {len(found.get("request_cases") or [])} | '
            f'Client-side sink candidates: {len(found.get("client_side_candidates") or [])} | JWTs discovered: {len(found.get("jwt_tokens") or [])} | Discovery errors: {len(found.get("errors") or [])}</div>'
            + (f'<div class="discovery-label">Destructive URLs deliberately skipped</div><div>{_render_list([str(value) for value in skipped[:8]])}</div>' if skipped else '')
            + '</div>'
        )
    discovery_html = "".join(discovery_cards) or '<p>No discovery summary was supplied.</p>'

    severity_max = max((int(risks.get(name, 0) or 0) for name in ("critical", "high", "medium", "low", "info")), default=1) or 1
    severity_bars = "".join(
        f'<div class="bar-row"><span>{name.title()}</span><div class="bar-track"><div class="bar-fill bar-{name}" style="width:{max(0, min(100, int((int(risks.get(name, 0) or 0) / severity_max) * 100)))}%"></div></div><b>{int(risks.get(name, 0) or 0)}</b></div>'
        for name in ("critical", "high", "medium", "low", "info")
    )
    pipeline_steps = '<span class="pipeline-arrow">-></span>'.join(
        f'<span class="pipeline-step">{_esc(value)}</span>' for value in nodes
    )

    coverage_rows = "".join(
        "<tr>"
        f'<td>{index}</td><td>{_esc(row["profile"])}</td>'
        f'<td><b>{_esc(row["tool"])}</b><br><span class="muted">{_esc(row.get("purpose", ""))}</span></td>'
        f'<td>{_esc(row["status"])}</td><td>{row["targets"]}</td><td>{row.get("confirmed", 0)}</td>'
        f'<td>{row.get("candidates", 0)}</td><td>{row.get("observations", 0)}</td><td>{row["duration_seconds"]}</td>'
        "</tr>"
        for index, row in enumerate(payload["coverage"], 1)
    ) or '<tr><td colspan="9">No execution data.</td></tr>'
    execution_details = "".join(
        f'<li><b>{_esc(row.get("tool", "tool"))}:</b> {_esc(_report_excerpt(row.get("details") or "No execution detail supplied.", max_chars=280, max_lines=3))}</li>'
        for row in payload["coverage"]
    ) or '<li>No execution details were recorded.</li>'

    planner_audit = context.get("planner_audit") if isinstance(context.get("planner_audit"), list) else []
    audit_rows: list[str] = []
    audit_notes: list[str] = []
    for item in planner_audit:
        if not isinstance(item, dict):
            continue
        outcomes = item.get("execution_outcomes") if isinstance(item.get("execution_outcomes"), list) else []
        audit_rows.append(
            '<tr>'
            f'<td>{_esc(item.get("round", ""))}</td><td>{_esc(item.get("planner_source", ""))}</td>'
            f'<td>{_esc(item.get("eligible_action_count", 0))}</td><td>{_esc(item.get("ai_selected_action_count", 0))}</td>'
            f'<td>{_esc(item.get("selected_action_count", 0))}</td><td>{_esc(len(item.get("remaining_coverage_gaps") or []))}</td><td>{_esc(len(outcomes))}</td>'
            '</tr>'
        )
        reasoning = _report_excerpt(item.get("reasoning_summary") or "", max_chars=340, max_lines=4)
        if reasoning:
            audit_notes.append(f'<li><b>Round {_esc(item.get("round", ""))}:</b> {_esc(reasoning)}</li>')
    agentic_audit_html = ""
    if audit_rows:
        agentic_audit_html = (
            '<h2 id="agentic-audit">Agentic planning audit</h2>'
            '<p class="section-note">This section records model-selected actions and execution outcomes in compact form. Full structured planner audit data remains in JSON.</p>'
            '<table class="compact-table"><thead><tr><th>Round</th><th>Planner</th><th>Eligible</th><th>AI selected</th><th>Executed plan</th><th>Gaps</th><th>Outcomes</th></tr></thead>'
            f'<tbody>{"".join(audit_rows)}</tbody></table>'
            + (f'<h3>Planner summaries</h3><ol class="compact-list">{"".join(audit_notes)}</ol>' if audit_notes else '')
        )

    limitation_rows = "".join(
        f'<tr><td>{_esc(row["path"])}</td><td>{_esc(row["status"])}</td><td>{_esc(row["cause"])}</td><td>{_esc(_report_excerpt(row["explanation"], max_chars=520, max_lines=6))}</td></tr>'
        for row in summary["limitations"]
    ) or '<tr><td colspan="4">No recorded execution limitations.</td></tr>'
    constraint_rows = "".join(
        f'<tr><td>{_esc(row["area"])}</td><td>{_esc(row["reason"])}</td><td>{_esc(row["recommended_next_step"])}</td></tr>'
        for row in summary.get("coverage_constraints", [])
    ) or '<tr><td colspan="3">No additional coverage constraints were recorded.</td></tr>'

    host_issues: dict[str, list[str]] = {}
    for item in security_findings:
        host = urlparse(str(item.get("url") or payload["target"])).hostname or "unknown-host"
        host_issues.setdefault(host, []).append(_finding_family(item))
    chaining_rows = "".join(
        f'<li><b>{_esc(host)}</b> - {len(issues)} finding(s) across distinct issue types: {_esc(", ".join(sorted(set(issues))))}.</li>'
        for host, issues in host_issues.items() if len(set(issues)) > 1
    ) or '<li>No host in this report contains multiple distinct confirmed/candidate issue families.</li>'

    def finding_card(item: dict[str, Any], index: int) -> str:
        notes = item.get("data_quality_notes") or []
        ai_analysis = item.get("ai_analysis") if isinstance(item.get("ai_analysis"), dict) else {}
        has_ai = bool(ai_analysis)
        ai_confidence = str(ai_analysis.get("analysis_confidence") or ai_analysis.get("confidence") or "not supplied")
        scanner_confidence = str(item.get("scanner_confidence") or item.get("confidence") or "not supplied")
        scanner_risk = str(item.get("scanner_risk") or "").lower()
        confidence_badge = (
            f'<span><b>AI ASSESSMENT CONFIDENCE</b> {_esc(ai_confidence)}</span>' if has_ai
            else f'<span><b>CONFIDENCE</b> {_esc(scanner_confidence)}</span>'
        )

        scanner_rows = ""
        if has_ai:
            scanner_rows += _field("Scanner severity", scanner_risk or "not supplied")
            scanner_rows += _field("Scanner confidence", scanner_confidence)
            if str(item.get("scanner_description") or "").strip() and str(item.get("scanner_description") or "").strip() != str(item.get("description") or "").strip():
                scanner_rows += _field("Scanner description", item.get("scanner_description"))
            if str(item.get("scanner_impact") or "").strip() and str(item.get("scanner_impact") or "").strip() != str(item.get("impact") or "").strip():
                scanner_rows += _field("Scanner security impact", item.get("scanner_impact"))
            if str(item.get("scanner_solution") or "").strip() and str(item.get("scanner_solution") or "").strip() != str(item.get("solution") or "").strip():
                scanner_rows += _field("Scanner recommended remediation", item.get("scanner_solution"))
        original_scanner = (
            f'<div class="scanner-original"><h4>Original scanner assessment <span>(secondary audit)</span></h4><dl>{scanner_rows}</dl></div>'
            if scanner_rows else ""
        )

        structured_note = (
            '<p class="structured-note">Additional structured scanner fields are preserved in the JSON report.</p>'
            if item.get("scanner_fields") else ""
        )
        payload_value = item.get("payload") or "; ".join(item.get("payloads") or [])
        return f'''
<article class="finding risk-{_esc(item["risk"])}">
<h3>{index}. {_esc(item["alert"])} <span class="heading-risk">{_esc(item["risk"]).upper()}</span></h3>
<div class="badges">
<span><b>STATUS</b> {_esc(item["verification_status"])}</span>
{confidence_badge}
<span><b>PROFILES</b> {_esc(", ".join(item.get("profiles") or [item["profile"]]))}</span>
<span><b>TOOL</b> {_esc(item["tool"])}</span>
</div>
<dl>
{_field("Affected URL", item.get("url"))}
{_field("HTTP method", item.get("method"))}
{_field("Parameter", item.get("parameter"))}
{_field("Description", item.get("description"))}
{_field("Attack preconditions", item.get("attack_preconditions"))}
{_field("Payload / test input", payload_value, pre=True, max_chars=900, max_lines=12)}
{_field("Evidence", item.get("evidence"), pre=True, max_chars=2200 if item.get("category") in {"vulnerability", "candidate"} else 1200, max_lines=28 if item.get("category") in {"vulnerability", "candidate"} else 16)}
{_field("Security impact", item.get("impact"))}
{_field("Recommended remediation", item.get("solution"))}
{_field("Reproduction / validation steps", item.get("reproduction"), pre=True, max_chars=1200, max_lines=18)}
{_field("OWASP classification", item.get("owasp_category"))}
</dl>
{original_scanner}
{("<h4>Identifiers</h4>" + _render_list(item.get("identifiers") or [])) if item.get("identifiers") else ""}
{("<h4>References</h4>" + _render_list(item.get("references") or [])) if item.get("references") else ""}
{("<div class=\"quality\"><b>Data-quality notes</b>" + _render_list(notes) + "</div>") if notes else ""}
{structured_note}
</article>'''

    finding_sections: list[str] = []
    global_index = 1
    section_ids = {
        "vulnerability": "confirmed-vulnerabilities",
        "candidate": "manual-validation",
        "observation": "security-observations",
        "discovery": "discovered-surface",
    }
    for category in ("vulnerability", "candidate", "observation", "discovery"):
        title, explanation = FINDING_SECTION_META[category]
        items = groups[category]
        cards = "".join(finding_card(item, index) for index, item in enumerate(items, start=global_index))
        global_index += len(items)
        finding_sections.append(
            f'<section id="{section_ids[category]}"><h2>{_esc(title)} <span class="count">{len(items)}</span></h2>'
            f'<p class="section-note">{_esc(explanation)}</p>{cards or "<p>No entries in this category.</p>"}</section>'
        )

    index_items = [
        ("executive", "Executive summary"),
        ("risk-methodology", "Risk rating methodology"),
        ("overall-risk", "Overall risk rating"),
        ("priority-actions", "Priority remediation actions"),
        ("glance", "Security findings at a glance"),
        ("scope", "Scope and assessment context"),
        ("methodology", "Methodology"),
        ("qualifications", "Assessor and platform qualifications"),
        ("visualizations", "Assessment visualizations"),
        ("execution", "Assessment execution"),
    ]
    if audit_rows:
        index_items.append(("agentic-audit", "Agentic planning audit"))
    index_items += [
        ("limitations", "Execution limitations"),
        ("coverage-constraints", "Coverage constraints and untested classes"),
        ("chaining", "Exploitation chaining potential"),
        ("confirmed-vulnerabilities", "Confirmed vulnerabilities"),
        ("manual-validation", "Candidates requiring manual validation"),
        ("security-observations", "Security observations and hardening"),
        ("discovered-surface", "Discovered attack surface"),
        ("cleanup", "Post-assessment cleanup"),
        ("conclusion", "Conclusion and recommendations"),
    ]
    index_html = "".join(f'<li><a href="#{section_id}">{_esc(label)}</a></li>' for section_id, label in index_items)

    stat_cards = "".join(
        f'<div class="stat-card"><div class="stat-value">{int(risks.get(risk, 0) or 0)}</div><div>{risk.title()}</div></div>'
        for risk in ("critical", "high", "medium", "low")
    ) + (
        f'<div class="stat-card"><div class="stat-value">{len(summary["limitations"])}</div><div>Execution<br>limitations</div></div>'
        f'<div class="stat-card"><div class="stat-value">{len(summary.get("coverage_constraints", []))}</div><div>Coverage<br>constraints</div></div>'
    )

    overall_reason = (
        f'At least one confirmed {overall_risk}-severity vulnerability was found within the tested scope.'
        if confirmed else
        (f'The highest validation candidate is rated {overall_risk}; no scanner-confirmed vulnerability is present in this report.' if security_findings else 'No confirmed vulnerabilities or validation candidates were recorded.')
    )

    methodology_steps = [
        ("Planning and scoping", "Target, credentials, testing profiles and safety boundaries are established before execution; destructive actions are excluded by default."),
        ("Reconnaissance and discovery", "Passive and active crawling enumerate reachable URLs, forms, parameters, request contracts, JWTs and client-side sinks."),
        ("Automated vulnerability scanning", "Adaptive, fingerprint-driven and signature-based scanners assess the discovered surface for known vulnerabilities, misconfigurations and exposures."),
        ("Targeted validation", "Findings capable of automated confirmation are re-tested with bounded, evidence-producing checks to separate confirmed vulnerabilities from candidates requiring manual review."),
        ("Coverage and manual-review triggers", "Classes that automated tooling cannot conclusively confirm are reported as coverage constraints for manual follow-up rather than presented as confirmed."),
        ("Reporting", ("Results are normalized and de-duplicated. In agentic runs the final AI analysis may refine severity and narrative using preserved evidence, while original scanner values remain available for audit and scanner verification/evidence remain immutable." if is_agentic else "Results are normalized, de-duplicated across corroborating tools and compiled into this scanner-grounded report, distinguishing confirmed vulnerabilities from candidates, observations and discovery.")),
    ]
    methodology_list = "".join(f'<li><b>{_esc(title)}</b> - {_esc(text)}</li>' for title, text in methodology_steps)

    cleanup_text = (
        'Every active probe used by this platform is tagged with an identifiable "SECOPS_" prefix - uploaded filenames such as '
        'secops_probe_<hex>.html, stored markers such as SECOPS_XSS_..., command-injection canaries such as SECOPS_CMD_..., and '
        'throttling-check usernames such as secops_invalid_... - so they can be found and removed. No destructive actions, persistent '
        'backdoors, or new privileged accounts were created by this assessment.'
    )
    conclusion_text = (
        f'Based on the findings in this report, the highest confirmed or candidate severity is {overall_label}. '
        'This should be treated as the immediate remediation priority before lower-severity hardening work.'
        if security_findings else
        'No confirmed vulnerability or validation candidate was recorded by this run. Coverage constraints and scanner limitations should still be reviewed before treating the target as clean.'
    )

    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SecOps Assessment Report</title>
<style>
@page {{ size:A4; margin:12mm 11mm 12mm; background:#f4f6f8; @bottom-center {{ content:counter(page); font:7.5pt Arial; color:#263645; }} }}
*{{box-sizing:border-box}} body{{font-family:Arial,Helvetica,sans-serif;color:#17212b;margin:0;font-size:8.4pt;line-height:1.23}}
h1,h2,h3,h4{{color:#173b5e;margin-top:0}} h1{{font-size:20pt;line-height:1.05}} h2{{font-size:14pt;margin:0 0 7px}} h3{{font-size:10.4pt;margin:0 0 5px}} h4{{font-size:9pt;margin:8px 0 4px}}
a{{color:inherit;text-decoration:none}} p{{margin:4px 0 7px}} ul,ol{{margin:5px 0 8px;padding-left:18px}} li{{margin:2px 0}}
.page-break{{break-after:page}} .front-page{{min-height:250mm}} .section-page{{break-before:page}} .keep{{break-inside:avoid}} h2,h3{{break-after:avoid}}
.card,.finding,.discovery-card{{background:#fff;border:1px solid #d5dde5;border-radius:7px}} .card{{padding:10px;margin:7px 0}}
.cover-card{{position:relative;background:#fff;border:1px solid #d5dde5;border-radius:7px;padding:32px 28px 24px;margin-top:10px;min-height:125mm}}
.cover-kicker{{font-size:7pt;letter-spacing:2px;color:#4b86b4;font-weight:700;margin:35px 0 8px}} .cover-title{{font-size:24pt;color:#173b5e;font-weight:700;line-height:.95;max-width:105mm}}
.cover-subtitle{{font-size:11pt;font-weight:700;color:#40566a;margin:8px 0 24px}} .cover-badges{{position:absolute;right:0;top:0;width:67mm}}
.cover-badges div{{background:#9d0000;color:#fff;font-weight:700;font-size:7pt;letter-spacing:1px;padding:3px 10px;margin-bottom:2px;border-radius:3px 0 0 3px}}
.cover-meta{{width:100%;border-collapse:collapse;font-size:8pt}} .cover-meta th,.cover-meta td{{border-bottom:1px solid #d9e0e6;padding:5px 0;text-align:left;vertical-align:top}} .cover-meta th{{width:31%;color:#52616f}}
.control-card{{padding:12px;margin:0 0 9px}} .disclaimer{{background:#fff7f7;border-color:#e6c5c5}} .control-table{{width:100%;border-collapse:collapse}} .control-table th,.control-table td{{text-align:left;padding:2px 0;vertical-align:top}} .control-table th{{width:34%}}
.toc{{break-after:page}} .toc ul{{list-style:none;padding:0;margin-top:10px}} .toc li{{margin:2px 0;font-weight:700}} .toc a{{display:block}} .toc a::after{{content:leader('.') target-counter(attr(href), page);font-weight:400}}
.section-note{{background:#eaf1f7;border-left:3px solid #527ca3;padding:7px 8px;margin:6px 0 8px}} .small-note,.muted,.structured-note{{color:#536778;font-size:7.3pt}} .structured-note{{margin-top:7px;font-style:italic}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:6px;margin:8px 0 14px}} .stat-card{{background:#fff;border:1px solid #d5dde5;border-radius:6px;padding:8px;min-height:28mm}} .stat-value{{font-size:21pt;font-weight:700;line-height:1;color:#17212b;margin-bottom:6px}}
table{{width:100%;border-collapse:collapse;table-layout:fixed;font-size:7.1pt;background:#fff}} th,td{{border:1px solid #cbd5df;padding:4px;vertical-align:top;overflow-wrap:anywhere}} thead{{display:table-header-group}} tr{{break-inside:avoid}} thead th{{background:#24476b;color:#fff;text-align:left;font-weight:700}} .kv-table th{{background:transparent;color:#17212b;border:0;padding:2px 5px 2px 0;width:31%}} .kv-table td{{border:0;padding:2px 0}}
.risk-table td:first-child{{width:18%}} .risk-dot{{display:inline-block;width:7px;height:7px;border-radius:1px;margin-right:4px}} .risk-dot-critical,.risk-dot-high{{background:#a40000}} .risk-dot-medium{{background:#d98200}} .risk-dot-low{{background:#c2a000}} .risk-dot-info{{background:#4b86b4}}
.risk-banner{{display:flex;align-items:center;gap:10px;background:#fff;border:1px solid #d5dde5;border-left:5px solid #a40000;border-radius:6px;padding:8px;margin:6px 0 12px}} .risk-pill{{background:#a40000;color:#fff;border-radius:4px;padding:4px 13px;font-weight:700;letter-spacing:1px}}
.priority-list{{padding-left:20px}} .priority-list li{{margin-bottom:4px}} .glance th:nth-child(1){{width:5%}} .glance th:nth-child(2){{width:11%}} .glance th:nth-child(3){{width:29%}} .glance th:nth-child(4){{width:14%}} .glance th:nth-child(5){{width:41%}}
.severity-critical,.severity-high{{font-weight:700}} .scope-grid{{display:grid;grid-template-columns:1fr;gap:6px}} .discovery-card{{padding:7px;display:grid;grid-template-columns:34mm 1fr;gap:3px 7px}} .discovery-label{{font-weight:700}}
.pipeline{{display:flex;align-items:center;flex-wrap:wrap;gap:4px;margin:6px 0 12px}} .pipeline-step{{background:#244f78;color:#fff;border-radius:4px;padding:7px 12px;font-size:7pt}} .pipeline-arrow{{font-weight:700;color:#527ca3}} .bars{{background:#fff;border:1px solid #d5dde5;border-radius:7px;padding:9px;margin-bottom:12px}} .bar-row{{display:grid;grid-template-columns:24mm 1fr 8mm;gap:6px;align-items:center;margin:5px 0}} .bar-track{{height:7px;background:#edf1f4;border-radius:3px;overflow:hidden}} .bar-fill{{height:100%;min-width:0}} .bar-critical{{background:#9d0000}} .bar-high{{background:#b41616}} .bar-medium{{background:#d98200}} .bar-low{{background:#c2a000}} .bar-info{{background:#4b86b4}}
.execution-table th:nth-child(1){{width:4%}} .execution-table th:nth-child(2){{width:11%}} .execution-table th:nth-child(3){{width:25%}} .execution-table th:nth-child(4){{width:9%}} .execution-table th:nth-child(n+5){{width:8.5%}} .compact-list{{font-size:7.4pt}} .compact-table{{font-size:7pt}}
.finding{{border-left:4px solid #4b86b4;padding:10px;margin:8px 0 10px;break-inside:auto}} .risk-critical,.risk-high{{border-left-color:#a40000}} .risk-medium{{border-left-color:#d98200}} .risk-low{{border-left-color:#c2a000}} .heading-risk{{margin-left:5px;color:#17212b}} .badges{{margin:2px 0 7px}} .badges span{{display:inline-block;background:#e8eef4;border-radius:10px;padding:2px 7px;margin:0 4px 4px 0;font-size:6.7pt}} .badges b{{font-size:6pt;letter-spacing:.4px;color:#24476b}}
dl{{display:grid;grid-template-columns:31mm minmax(0,1fr);gap:4px 7px;margin:0}} dt{{font-weight:700}} dd{{margin:0;overflow-wrap:anywhere}} pre{{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;background:#101821;color:#eef4f8;padding:7px;border-radius:5px;font-size:6.5pt;line-height:1.15;margin:2px 0 4px}}
.scanner-original{{background:#f6f8fa;border:1px solid #d7dee5;border-left:3px solid #98a7b5;border-radius:5px;padding:7px;margin-top:8px}} .scanner-original h4{{color:#52616f;margin:0 0 5px}} .scanner-original h4 span{{font-weight:400;font-size:7pt}} .quality{{background:#fff8dc;border:1px solid #e1cb73;padding:7px;border-radius:5px;margin-top:7px}} .count{{font-size:7pt;background:#dce8f3;border-radius:10px;padding:2px 6px;color:#17212b}}
.footer-note{{background:#eaf1f7;border-left:3px solid #527ca3;padding:7px}} .conclusion-card{{background:#fff;border:1px solid #d5dde5;border-radius:7px;padding:10px}}
</style></head><body>
<section class="front-page page-break">
<div class="cover-card">
<div class="cover-badges"><div>{_esc(REPORT_CLASSIFICATION).upper()}</div><div>OVERALL RISK: {_esc(overall_label)}</div></div>
<div class="cover-kicker">SECURITY ASSESSMENT REPORT</div><div class="cover-title">{_esc(REPORT_TITLE)}</div><div class="cover-subtitle">{_esc(subtitle)}</div>
<table class="cover-meta"><tr><th>Client</th><td><b>{_esc(client)}</b></td></tr><tr><th>Target</th><td><b>{_esc(payload["target"])}</b></td></tr><tr><th>Assessor / team</th><td><b>SecOps Automated Assessment Platform</b></td></tr><tr><th>Assessment date(s)</th><td><b>{_esc(report_date)}</b></td></tr><tr><th>Report issue date</th><td><b>{_esc(report_date)}</b></td></tr><tr><th>Report version / ID</th><td><b>{_esc(REPORT_VERSION)} / {_esc(report_id)}</b></td></tr></table>
</div></section>

<section class="front-page page-break">
<div class="card control-card"><h2>Document control</h2><table class="control-table"><tr><th>Document reference</th><td>{_esc(report_id)}</td></tr><tr><th>Engagement report version</th><td>{_esc(REPORT_VERSION)}</td></tr><tr><th>Report template version</th><td>{_esc(REPORT_VERSION)}</td></tr><tr><th>Classification</th><td>{_esc(REPORT_CLASSIFICATION)}</td></tr><tr><th>Prepared by</th><td>SecOps Automated Assessment Platform</td></tr><tr><th>Platform authors</th><td>{_esc(", ".join(AUTHORS))}</td></tr><tr><th>Client / distribution</th><td>{_esc(client)}</td></tr><tr><th>Date issued</th><td>{_esc(report_date)}</td></tr></table></div>
<div class="card control-card disclaimer"><h2>Confidentiality and disclaimer</h2><p>This report is classified <b>{_esc(REPORT_CLASSIFICATION)}</b> and is provided solely for the use of {_esc(client)} in evaluating the security of {_esc(payload["target"])}. It contains details of security vulnerabilities and must not be distributed, copied or disclosed to any party not explicitly authorized by the recipient.</p><p>Testing was performed during {_esc(report_date)} against the scope and identities described in this report. This document reflects the security posture of the target as observed at that time; systems, code and configuration can change afterward, and no assessment - automated or manual - can guarantee the absence of vulnerabilities outside the scope, techniques and time actually exercised.</p><p>Findings are grounded in evidence produced by the tools used during this engagement; where evidence was insufficient to confirm exploitability, the finding is reported as a candidate or observation rather than a confirmed vulnerability. This report does not constitute legal advice, a compliance certification, or a warranty of fitness for any particular purpose.</p></div>
</section>

<nav class="front-page toc"><h1>Index</h1><ul>{index_html}</ul></nav>

<section class="front-page page-break"><h2 id="executive">Executive summary</h2><div class="card">{_esc(payload["executive_summary"])}</div><div class="stats">{stat_cards}</div><h2 id="risk-methodology">Risk rating methodology</h2><p class="section-note">{_esc(methodology_intro)}</p><table class="risk-table"><thead><tr><th>Rating</th><th>Definition and expected remediation priority</th></tr></thead><tbody>{risk_table_rows}</tbody></table></section>

<section class="front-page page-break"><h2 id="overall-risk">Overall risk rating</h2><div class="risk-banner"><span class="risk-pill">{_esc(overall_label)}</span><span>{_esc(overall_reason)}</span></div><h2 id="priority-actions">Priority remediation actions</h2><p class="section-note">Drawn directly from confirmed vulnerabilities and candidates below that carry remediation guidance, in the same priority order as the detailed findings. This shortlist does not replace the full findings detail.</p><ol class="priority-list">{priority_html}</ol></section>

<section class="front-page page-break"><h2 id="glance">Security findings at a glance</h2><p class="section-note">Confirmed vulnerabilities and candidates are named here before execution details.</p><table class="glance"><thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Tool</th><th>Affected endpoint</th></tr></thead><tbody>{glance_rows}</tbody></table>{glance_note}</section>

<section class="front-page page-break"><h2 id="scope">Scope and assessment context</h2><h3>Run configuration</h3><table class="kv-table">{run_config_rows}</table>{configured_html}<h3>Discovery summary</h3><div class="scope-grid">{discovery_html}</div><p class="section-note">The full technical context - discovered URLs, normalized request cases, client-side sink candidates and planner data - is available in the attached JSON report.</p></section>

<section class="front-page page-break"><h2 id="methodology">Methodology</h2><p class="section-note">This assessment followed a staged methodology consistent in intent with common web-application penetration-testing practice. Each stage is described below; the tools used in each stage and their individual results are recorded in Assessment execution.</p><ol>{methodology_list}</ol><h2 id="qualifications">Assessor and platform qualifications</h2><p>This assessment was produced by an automated platform rather than performed manually end-to-end by a certified individual tester. Industry guidance on tester qualifications - certifications, organizational independence from the tested environment, and documented past experience - is written for human testers and does not map directly onto automated tooling; no such credentials are claimed here on behalf of the platform or its authors.</p><p>The platform's authority instead rests on verifiable properties of this report: use of actively maintained security tools restricted to their documented purpose; evidence rules applied before a finding is treated as confirmed; and explicit disclosure of what the automated run could not verify. The platform is developed and maintained by {_esc(", ".join(AUTHORS))}.</p><p>Findings marked as candidates, and every coverage constraint listed in this report, require review by a qualified human penetration tester before being treated as conclusive.</p></section>

<section><h2 id="visualizations">Assessment visualizations</h2><h3>Assessment pipeline (phases actually executed, in order)</h3><div class="pipeline">{pipeline_steps or _esc(pipeline)}</div><h3>Findings by severity</h3><div class="bars">{severity_bars}</div><h2 id="execution">Assessment execution</h2><p class="section-note">This section records tools, targets, duration and execution status. It is deliberately separate from security findings.</p><table class="execution-table"><thead><tr><th>#</th><th>Profile</th><th>Tool and purpose</th><th>Status</th><th>Targets</th><th>Confirmed</th><th>Candidates</th><th>Info/discovery</th><th>Seconds</th></tr></thead><tbody>{coverage_rows}</tbody></table><h3>Execution details</h3><p class="section-note">Raw execution output is not reproduced here. The concise rows below are numbered to match the table above; complete structured output remains in JSON.</p><ol class="compact-list">{execution_details}</ol>{agentic_audit_html}
<h2 id="limitations">Execution limitations</h2><table><thead><tr><th>Run</th><th>Status</th><th>Cause</th><th>Explanation</th></tr></thead><tbody>{limitation_rows}</tbody></table>
<h2 id="coverage-constraints">Coverage constraints and untested classes</h2><p class="section-note">These rows are not scanner failures. They identify security classes that could not be fully validated with the supplied identities, traffic and request contracts.</p><table><thead><tr><th>Area</th><th>Reason</th><th>Recommended next step</th></tr></thead><tbody>{constraint_rows}</tbody></table>
<h2 id="chaining">Exploitation chaining potential</h2><p class="section-note">This automated platform confirms each finding independently and does not claim that separate findings were successfully chained. Hosts below merely identify where multiple distinct issue types coexist and may warrant human review.</p><ul>{chaining_rows}</ul>
{detail_cap_note}{"".join(finding_sections)}
<h2 id="cleanup">Post-assessment cleanup</h2><p class="footer-note">{_esc(cleanup_text)}</p>
<h2 id="conclusion">Conclusion and recommendations</h2><div class="conclusion-card"><p>{_esc(conclusion_text)}</p><h3>Recommended next steps</h3><ol><li>Remediate confirmed vulnerabilities in order of severity, validating each fix against the reproduction steps recorded in this report.</li><li>Address the coverage constraints above and repeat any incomplete or time-limited tests.</li><li>Manually review every validation candidate before treating it as confirmed.</li><li>Where access control is in scope, repeat authorization checks with a second identity or role when available.</li><li>Re-run the assessment after remediation to confirm closure and establish a new baseline.</li></ol></div></section>
</body></html>'''


def _p(value: Any) -> str:
    return html.escape(_redact_text(value)).replace("\n", "<br/>")


@mcp.tool()
def generate_report(
    findings_summary: dict | str,
    target_url: str,
    output_name: str = "",
    assessment_context: dict | str | None = None,
) -> dict:
    """Generate scanner-grounded JSON, HTML and PDF penetration-test reports."""
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
        "report_id": base,
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
    }

    try:
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        html_path.write_text(_render_html(payload), encoding="utf-8")
    except Exception as exc:
        return failure("Report Generator", target_url, f"JSON/HTML report creation failed: {type(exc).__name__}: {exc}", diagnosis="report_serialization_failed")

    # PDF is rendered from the generated HTML via WeasyPrint (html2pdf).
    try:
        html2pdf(html_path, pdf_path)
    except Exception as exc:
        result = failure("Report Generator", target_url, f"PDF report creation failed: {type(exc).__name__}: {exc}", diagnosis="pdf_generation_failed")
        result.update(json_filename=str(json_path.resolve()), html_filename=str(html_path.resolve()), pdf_filename=None, findings_count=len(findings))
        return result

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
