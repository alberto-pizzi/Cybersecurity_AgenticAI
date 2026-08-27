"""Finding normalization: turns raw per-tool scanner output into the
semantically deduplicated, merged finding rows the report renders.
"""

from __future__ import annotations

import re
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .constants import AUTO_INDEX_QUERY_KEYS, RISK_ORDER
from .text_utils import _redact_text, _redact_value

# Walks the nested results tree, yielding each leaf (or run) result with its path
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

# Resolves a finding's category, defaulting by risk when not explicit
def _category(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("category") or "").lower()
    if explicit in {"vulnerability", "candidate", "discovery", "observation"}:
        return explicit
    return "observation" if str(finding.get("risk") or "info").lower() == "info" else "candidate"

# Extracts and deduplicates a finding's reference URLs/citations
def _references(raw: dict[str, Any]) -> list[str]:
    value = raw.get("references") or raw.get("reference") or []
    values = value if isinstance(value, list) else [value]
    return list(dict.fromkeys(_redact_text(item).strip() for item in values if str(item).strip()))

# Builds the "Identifiers" list (CWE, CVE, CVSS, template/plugin IDs) for a finding
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

# Returns the scanner-supplied verification status, or a category-based default
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

# Converts one raw scanner finding into the report's normalized finding schema
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

    # Populated by the agentic analysis stage (orchestratorAgenticCore.py's
    # analysis_node), which enriches severity/description/impact/solution above
    # while preserving the original scanner values here for audit.
    ai_analysis_raw = raw.get("ai_analysis") if isinstance(raw.get("ai_analysis"), dict) else {}
    ai_analysis = _redact_value(ai_analysis_raw) if ai_analysis_raw else {}
    scanner_risk = _redact_text(raw.get("scanner_risk") or "").strip()
    scanner_confidence = _redact_text(raw.get("scanner_confidence") or raw.get("confidence") or "not supplied").strip()
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

# Normalizes a URL (scheme/host case, trailing slash, auto-index query args) for comparison
def _canonical_finding_url(value: str) -> str:
    parsed = urlparse(str(value or ""))
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = "" if pairs and {name.lower() for name, _ in pairs} <= AUTO_INDEX_QUERY_KEYS else urlencode(pairs)
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))

# Normalizes a finding URL by route and parameter names, ignoring test values, for dedup matching
def _finding_route_key(value: str) -> str:
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

# Classifies a finding into a coarse vulnerability family for dedup/chaining grouping
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

# Scores a finding row so the strongest corroborating duplicate wins a merge
def _finding_strength(row: dict[str, Any]) -> tuple[int, int, int, int]:
    category_score = {"vulnerability": 3, "candidate": 2, "observation": 1, "discovery": 0}.get(str(row.get("category") or ""), 0)
    confidence_score = {"high": 3, "medium": 2, "low": 1}.get(str(row.get("confidence") or "").lower(), 0)
    return (category_score, RISK_ORDER.get(str(row.get("risk") or "info"), 0), confidence_score, len(str(row.get("evidence") or "")))

# Merges a corroborating duplicate finding into the existing row in place
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
            "scanner_risk", "scanner_confidence", "scanner_description",
            "scanner_impact", "scanner_solution", "ai_analysis",
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

# Splits a findings list into per-category lists (vulnerability/candidate/observation/discovery)
def _finding_groups(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return {
        "vulnerability": [item for item in findings if item.get("category") == "vulnerability"],
        "candidate": [item for item in findings if item.get("category") == "candidate"],
        "observation": [item for item in findings if item.get("category") == "observation"],
        "discovery": [item for item in findings if item.get("category") == "discovery"],
    }

# Bound HTML-only structured detail while preserving complete JSON data.
def _truncate_human_value(value: Any, *, string_limit: int = 1400, list_limit: int = 25) -> Any:
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
