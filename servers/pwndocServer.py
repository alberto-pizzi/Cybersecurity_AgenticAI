from __future__ import annotations

import html
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import requests
from fastmcp import FastMCP
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from utils import REPORTS_DIR, failure, success

mcp = FastMCP("SecOps Report Server")

RISK_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
TOOL_PURPOSES = {
    "zap": "Authenticated/anonymous traffic import, spidering, passive analysis and active web scanning.",
    "nuclei": "Focused template checks for high-impact vulnerabilities, exposures and misconfigurations.",
    "nikto": "Web-server hardening, exposed resource and outdated component checks.",
    "ffuf": "High-value path and resource discovery with content verification for selected sensitive paths.",
    "arjun": "Hidden HTTP parameter discovery for downstream targeted testing.",
    "sqlmap": "SQL injection confirmation on discovered GET and POST requests.",
    "dalfox": "XSS reflection, AST and verified-vector testing.",
    "commix": "Operating-system command injection confirmation.",
    "idor": "Differential numeric object-reference checks requiring manual two-account validation.",
    "jwt": "JWT structural analysis; it does not prove server acceptance of modified tokens.",
    "interactsh": "Explicit out-of-band callback confirmation for a supplied insertion point.",
}
SECRET_PATTERNS = (
    (re.compile(r"(?i)(PHPSESSID=)[^;\s]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(Cookie:\s*)[^\r\n]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9._~-]+"), r"\1<redacted>"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "<redacted-jwt>"),
)


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
    technical = _redact_text(raw.get("technical_details") or raw.get("other_information") or "").strip()
    reproduction = _redact_text(raw.get("reproduction") or "").strip()

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
            "references", "reference",
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
        "references": _references(raw),
        "identifiers": _identifier_lines(raw),
        "data_quality_notes": data_quality_notes,
        "scanner_fields": preserved,
    }


def flatten_findings(results: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Normalize findings and merge identical evidence observed in multiple profiles.

    Access context remains explicit through the `profiles` field, avoiding pages
    of duplicate anonymous/authenticated entries in the human-readable report.
    """
    merged: dict[tuple[str, ...], dict[str, Any]] = {}
    for path, result in _iter_leaf_results(results):
        profile = path[0] if path else str(result.get("profile") or "unknown")
        tool = path[1].split(":", 1)[0] if len(path) > 1 else str(result.get("tool") or "unknown")
        for raw in result.get("vulnerabilities") or []:
            if not isinstance(raw, dict):
                continue
            row = _normalize_finding(raw, profile, tool)
            fingerprint = tuple(str(row.get(key) or "") for key in (
                "tool", "alert", "risk", "category", "url", "method",
                "parameter", "evidence", "verification_status",
            ))
            existing = merged.get(fingerprint)
            if existing is None:
                row["profiles"] = [profile]
                merged[fingerprint] = row
            else:
                profiles = existing.setdefault("profiles", [])
                if profile not in profiles:
                    profiles.append(profile)
                existing["profile"] = ", ".join(profiles)

    rows = list(merged.values())
    for row in rows:
        row["profiles"] = sorted(set(row.get("profiles") or [row.get("profile", "unknown")]))
        row["profile"] = ", ".join(row["profiles"])
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


FINDING_SECTION_META = {
    "vulnerability": (
        "Confirmed vulnerabilities",
        "Scanner evidence met the tool-specific confirmation rule. Reproduce and validate impact before production remediation.",
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
                    "duration_seconds": 0.0,
                    "purpose": TOOL_PURPOSES.get(str(tool), "Security assessment tool."),
                    "details": "No result object was produced for this tool.",
                })
                continue
            status, status_note = _effective_status(result)
            runs = result.get("runs") if isinstance(result.get("runs"), list) else [result]
            details = _redact_text(result.get("output") or status_note)
            rows.append({
                "profile": profile,
                "tool": tool,
                "status": status,
                "targets": len(runs),
                "findings": len([item for item in (result.get("vulnerabilities") or []) if isinstance(item, dict)]),
                "duration_seconds": round(_duration(result), 2),
                "purpose": TOOL_PURPOSES.get(str(tool), "Security assessment tool."),
                "details": details[:1000],
            })
    return rows


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
    return {
        "risk_counts": dict(risks),
        "category_counts": dict(categories),
        "limitations": limitations,
        "coverage_complete": not any(row["status"] in {"error", "partial", "time_limit", "not_run"} for row in coverage),
        "discovery": discovery,
    }


def _executive_text(summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    confirmed = sum(item["category"] == "vulnerability" for item in findings)
    candidates = sum(item["category"] == "candidate" for item in findings)
    observations = sum(item["category"] in {"observation", "discovery"} for item in findings)
    limits = len(summary["limitations"])
    return (
        f"The automated assessment produced {confirmed} scanner-confirmed findings, {candidates} candidates requiring manual validation, "
        f"and {observations} discovery or hardening observations. {limits} execution limitation(s) were recorded. "
        "The report preserves scanner evidence and metadata; it does not invent missing impact, remediation, CVSS, or exploitability claims."
    )


def _esc(value: Any) -> str:
    return html.escape(_redact_text(value))


def _render_list(values: list[str]) -> str:
    return "" if not values else "<ul>" + "".join(f"<li>{_esc(value)}</li>" for value in values) + "</ul>"


def _field(label: str, value: Any, *, pre: bool = False) -> str:
    if value in (None, "", [], {}):
        return ""
    rendered = f"<pre>{_esc(value)}</pre>" if pre else _esc(value)
    return f"<dt>{_esc(label)}</dt><dd>{rendered}</dd>"


def _render_html(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    risks = summary["risk_counts"]
    groups = _finding_groups(payload["findings"])

    coverage_rows = "".join(
        "<tr>"
        f"<td>{_esc(row['profile'])}</td>"
        f"<td><b>{_esc(row['tool'])}</b><br><small>{_esc(row.get('purpose', ''))}</small></td>"
        f"<td>{_esc(row['status'])}</td>"
        f"<td>{row['targets']}</td><td>{row['findings']}</td>"
        f"<td>{row['duration_seconds']}</td>"
        f"<td>{_esc(row['details'])}</td>"
        "</tr>"
        for row in payload["coverage"]
    ) or '<tr><td colspan="7">No execution data.</td></tr>'

    limitation_rows = "".join(
        f"<tr><td>{_esc(row['path'])}</td><td>{_esc(row['status'])}</td><td>{_esc(row['cause'])}</td><td>{_esc(row['explanation'])}</td></tr>"
        for row in summary["limitations"]
    ) or '<tr><td colspan="4">No recorded execution limitations.</td></tr>'

    def finding_card(item: dict[str, Any], index: int) -> str:
        notes = item.get("data_quality_notes") or []
        scanner_fields = json.dumps(
            item.get("scanner_fields") or {},
            indent=2,
            ensure_ascii=False,
            default=str,
        )
        return f"""
<article class="finding risk-{_esc(item['risk'])}">
<h3>{index}. {_esc(item['alert'])} <span>{_esc(item['risk']).upper()}</span></h3>
<div class="badges">
<b>{_esc(item['verification_status'])}</b>
<b>confidence: {_esc(item['confidence'])}</b>
<b>profiles: {_esc(', '.join(item.get('profiles') or [item['profile']]))}</b>
<b>tool: {_esc(item['tool'])}</b>
</div>
<dl>
{_field('Affected URL', item.get('url'))}
{_field('HTTP method', item.get('method'))}
{_field('Parameter', item.get('parameter'))}
{_field('Description', item.get('description'))}
{_field('Technical details', item.get('technical_details'))}
{_field('Evidence', item.get('evidence'), pre=True)}
{_field('Impact', item.get('impact'))}
{_field('Remediation', item.get('solution'))}
{_field('Reproduction / validation', item.get('reproduction'))}
</dl>
{('<h4>Identifiers</h4>' + _render_list(item.get('identifiers') or [])) if item.get('identifiers') else ''}
{('<h4>References</h4>' + _render_list(item.get('references') or [])) if item.get('references') else ''}
{('<div class="quality"><b>Data-quality notes</b>' + _render_list(notes) + '</div>') if notes else ''}
<details><summary>Additional structured scanner fields</summary><pre>{_esc(scanner_fields)}</pre></details>
</article>"""

    finding_sections: list[str] = []
    global_index = 1
    for category in ("vulnerability", "candidate", "observation", "discovery"):
        title, explanation = FINDING_SECTION_META[category]
        items = groups[category]
        cards = "".join(
            finding_card(item, index)
            for index, item in enumerate(items, start=global_index)
        )
        global_index += len(items)
        empty = "<p>No entries in this category.</p>"
        finding_sections.append(
            f'<section><h2>{_esc(title)} <span class="count">{len(items)}</span></h2>'
            f'<p class="section-note">{_esc(explanation)}</p>{cards or empty}</section>'
        )

    context_json = json.dumps(
        _redact_value(payload.get("assessment_context") or {}),
        indent=2,
        ensure_ascii=False,
        default=str,
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>SecOps Assessment Report</title>
<style>
body{{font-family:Arial,sans-serif;background:#f4f6f8;color:#17212b;margin:0}}
main{{max-width:1220px;margin:auto;padding:28px}}
h1,h2,h3{{color:#173b5e}}h2{{margin-top:32px}}
.meta,.card,.finding{{background:white;border:1px solid #d7dee5;border-radius:10px;padding:16px;margin:12px 0}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}}
.value{{font-size:2rem;font-weight:700}}
table{{width:100%;border-collapse:collapse;background:white;font-size:.92rem}}
th,td{{padding:8px;border:1px solid #cbd5df;vertical-align:top;text-align:left}}
th{{background:#24476b;color:white;position:sticky;top:0}}
small{{color:#4f6273}}.finding{{border-left:7px solid #4b86b4}}
.risk-critical,.risk-high{{border-left-color:#a90000}}.risk-medium{{border-left-color:#d98200}}.risk-low{{border-left-color:#b49b00}}
.badges b{{display:inline-block;background:#e8eef4;padding:4px 8px;margin:0 6px 6px 0;border-radius:12px;font-size:.82rem}}
dl{{display:grid;grid-template-columns:190px 1fr;gap:8px 14px}}dt{{font-weight:700}}dd{{margin:0}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#101821;color:#e5edf5;padding:12px;border-radius:8px;max-height:520px;overflow:auto}}
.quality{{background:#fff8dc;border:1px solid #e1cb73;padding:10px;border-radius:8px}}
details{{margin-top:14px}}.section-note{{background:#eaf1f7;border-left:4px solid #527ca3;padding:10px}}
.count{{font-size:.85rem;background:#dce8f3;border-radius:12px;padding:3px 8px}}
</style></head><body><main>
<h1>SecOps Penetration-Test Report</h1>
<div class="meta"><b>Target:</b> {_esc(payload['target'])}<br><b>Generated:</b> {_esc(payload['generated_at'])}<br><b>Evidence policy:</b> scanner-grounded; missing statements are not fabricated.</div>
<h2>Executive summary</h2><div class="card">{_esc(payload['executive_summary'])}</div>
<div class="grid">{''.join(f'<div class="card"><div class="value">{risks.get(risk,0)}</div><div>{risk.title()}</div></div>' for risk in ('critical','high','medium','low'))}<div class="card"><div class="value">{len(summary['limitations'])}</div><div>Limitations</div></div></div>

<h2>Scope and assessment context</h2>
<details><summary>Profiles, discovery counts and configured limits</summary><pre>{_esc(context_json)}</pre></details>

<h2>Assessment execution</h2>
<p class="section-note">This section records tools, targets, duration and execution status. It is deliberately separate from security findings.</p>
<table><thead><tr><th>Profile</th><th>Tool and purpose</th><th>Status</th><th>Targets</th><th>Findings</th><th>Seconds</th><th>Execution details</th></tr></thead><tbody>{coverage_rows}</tbody></table>

<h2>Execution limitations and incomplete coverage</h2>
<table><thead><tr><th>Run</th><th>Status</th><th>Cause</th><th>Explanation</th></tr></thead><tbody>{limitation_rows}</tbody></table>

{''.join(finding_sections)}
</main></body></html>"""



def _p(value: Any) -> str:
    return html.escape(_redact_text(value)).replace("\n", "<br/>")


def _page_footer(canvas: Any, doc: Any) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#5B6770"))
    canvas.drawString(28, 14, "SecOps Penetration-Test Report")
    canvas.drawRightString(A4[0] - 28, 14, f"Page {doc.page}")
    canvas.restoreState()


def _build_pdf(path: Path, payload: dict[str, Any]) -> None:
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "BodySmall", parent=styles["BodyText"], fontSize=8.2, leading=10.5,
        spaceAfter=5,
    )
    small = ParagraphStyle("Tiny", parent=body, fontSize=7, leading=8.5)
    header = ParagraphStyle(
        "Header", parent=small, fontName="Helvetica-Bold",
        textColor=colors.white,
    )
    section_note = ParagraphStyle(
        "SectionNote", parent=body, backColor=colors.HexColor("#EAF1F7"),
        borderColor=colors.HexColor("#527CA3"), borderWidth=0.5,
        borderPadding=6, spaceAfter=8,
    )
    finding_heading = ParagraphStyle(
        "FindingHeading", parent=styles["Heading3"],
        spaceBefore=8, spaceAfter=5, textColor=colors.HexColor("#173B5E"),
    )
    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=28,
        rightMargin=28,
        topMargin=26,
        bottomMargin=28,
        title="SecOps Penetration-Test Report",
    )

    story: list[Any] = [
        Paragraph("SecOps Penetration-Test Report", styles["Title"]),
        Paragraph(f"<b>Target:</b> {_p(payload['target'])}", body),
        Paragraph(f"<b>Generated:</b> {_p(payload['generated_at'])}", body),
        Paragraph(
            "<b>Evidence policy:</b> scanner-grounded; missing impact, remediation, "
            "exploitability, or confirmation is not fabricated.",
            body,
        ),
        Spacer(1, 8),
        Paragraph("Executive summary", styles["Heading2"]),
        Paragraph(_p(payload["executive_summary"]), body),
        Spacer(1, 8),
    ]

    context = payload.get("assessment_context") if isinstance(payload.get("assessment_context"), dict) else {}
    profiles = context.get("profiles") if isinstance(context.get("profiles"), list) else []
    discovery = context.get("discovery") if isinstance(context.get("discovery"), dict) else {}
    story.append(Paragraph("Scope and discovered attack surface", styles["Heading2"]))
    scope_data = [[
        Paragraph(value, header)
        for value in ("Profile", "Authenticated", "HTML pages", "Request cases", "JWTs", "Crawl warnings")
    ]]
    for profile in profiles:
        name = str(profile.get("name", profile)) if isinstance(profile, dict) else str(profile)
        found = discovery.get(name, {}) if isinstance(discovery.get(name), dict) else {}
        scope_data.append([
            Paragraph(_p(name), small),
            Paragraph("yes" if isinstance(profile, dict) and profile.get("authenticated") else "no", small),
            Paragraph(str(len(found.get("html_urls", []))), small),
            Paragraph(str(len(found.get("request_cases", []))), small),
            Paragraph(str(len(found.get("jwt_tokens", []))), small),
            Paragraph(str(len(found.get("errors", []))), small),
        ])
    if len(scope_data) == 1:
        scope_data.append([
            Paragraph("not supplied", small), Paragraph("-", small), Paragraph("-", small),
            Paragraph("-", small), Paragraph("-", small), Paragraph("-", small),
        ])
    scope_table = Table(scope_data, colWidths=[100, 78, 76, 82, 52, 80], repeatRows=1)
    scope_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#365D7D")),
        ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#B8C2CC")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F7FA")]),
    ]))
    story.extend([
        scope_table,
        Spacer(1, 8),
        Paragraph("Assessment execution", styles["Heading2"]),
        Paragraph(
            "Tool execution is listed separately from findings. A time-limited or "
            "failed tool does not imply that the target is clean.",
            section_note,
        ),
    ])

    # Compact execution table: long tool messages are moved into execution notes.
    coverage_data = [[
        Paragraph(value, header)
        for value in ("Profile", "Tool", "Status", "Targets", "Findings", "Seconds")
    ]]
    for row in payload["coverage"]:
        coverage_data.append([
            Paragraph(_p(row["profile"]), small),
            Paragraph(_p(row["tool"]), small),
            Paragraph(_p(row["status"]), small),
            Paragraph(str(row["targets"]), small),
            Paragraph(str(row["findings"]), small),
            Paragraph(str(row["duration_seconds"]), small),
        ])
    table = Table(
        coverage_data,
        colWidths=[82, 70, 68, 54, 54, 58],
        repeatRows=1,
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#24476B")),
        ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#B8C2CC")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white, colors.HexColor("#F4F7FA")
        ]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)

    story.extend([
        Spacer(1, 8),
        Paragraph("Execution notes", styles["Heading3"]),
    ])
    for row in payload["coverage"]:
        story.append(Paragraph(
            f"<b>{_p(row['profile'])} / {_p(row['tool'])} [{_p(row['status'])}]</b> - "
            f"{_p(row.get('purpose', ''))}<br/>{_p(row.get('details', ''))}",
            small,
        ))

    story.extend([
        PageBreak(),
        Paragraph("Execution limitations and incomplete coverage", styles["Heading2"]),
        Paragraph(
            "These entries describe scanner failures, bounded time limits, and partial "
            "coverage. They are execution facts, not application vulnerabilities.",
            section_note,
        ),
    ])
    limitations = payload["summary"]["limitations"]
    if limitations:
        limitation_data = [[
            Paragraph(value, header)
            for value in ("Run", "Status", "Cause", "Explanation")
        ]]
        for row in limitations:
            limitation_data.append([
                Paragraph(_p(row["path"]), small),
                Paragraph(_p(row["status"]), small),
                Paragraph(_p(row["cause"]), small),
                Paragraph(_p(row["explanation"]), small),
            ])
        limit_table = Table(
            limitation_data,
            colWidths=[105, 55, 95, 280],
            repeatRows=1,
        )
        limit_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6A4C2F")),
            ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#C9B8A8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white, colors.HexColor("#FAF6F1")
            ]),
        ]))
        story.append(limit_table)
    else:
        story.append(Paragraph("No execution limitations were recorded.", body))

    groups = _finding_groups(payload["findings"])
    global_index = 1
    for category in ("vulnerability", "candidate", "observation", "discovery"):
        title, explanation = FINDING_SECTION_META[category]
        story.extend([
            PageBreak(),
            Paragraph(f"{title} ({len(groups[category])})", styles["Heading2"]),
            Paragraph(explanation, section_note),
        ])
        items = groups[category]
        if not items:
            story.append(Paragraph("No entries in this category.", body))
            continue

        for item in items:
            heading = Paragraph(
                f"{global_index}. {_p(item['alert'])} [{_p(item['risk']).upper()}]",
                finding_heading,
            )
            core = [
                heading,
                Paragraph(
                    f"<b>Verification:</b> {_p(item['verification_status'])} &nbsp; "
                    f"<b>Confidence:</b> {_p(item['confidence'])}",
                    body,
                ),
                Paragraph(
                    f"<b>Profiles:</b> {_p(', '.join(item.get('profiles') or [item['profile']]))} "
                    f"&nbsp; <b>Tool:</b> {_p(item['tool'])}",
                    body,
                ),
                Paragraph(f"<b>Affected URL:</b> {_p(item['url']) or '-'}", body),
                Paragraph(
                    f"<b>Method / parameter:</b> {_p(item['method']) or '-'} / "
                    f"{_p(item['parameter']) or '-'}",
                    body,
                ),
            ]
            if item.get("description"):
                core.append(Paragraph(f"<b>Description:</b> {_p(item['description'])}", body))
            story.append(KeepTogether(core))
            for label, key, style in (
                ("Technical details", "technical_details", body),
                ("Evidence", "evidence", small),
                ("Impact", "impact", body),
                ("Remediation", "solution", body),
                ("Reproduction / validation", "reproduction", body),
            ):
                if item.get(key):
                    story.append(Paragraph(
                        f"<b>{label}:</b> {_p(item[key])}",
                        style,
                    ))
            if item.get("identifiers"):
                story.append(Paragraph(
                    f"<b>Identifiers:</b> {_p('; '.join(item['identifiers']))}",
                    body,
                ))
            if item.get("references"):
                story.append(Paragraph(
                    f"<b>References:</b> {_p('; '.join(item['references']))}",
                    small,
                ))
            if item.get("data_quality_notes"):
                story.append(Paragraph(
                    f"<b>Data-quality notes:</b> "
                    f"{_p('; '.join(item['data_quality_notes']))}",
                    small,
                ))
            story.append(Spacer(1, 9))
            global_index += 1

    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)




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
    findings = flatten_findings(results)
    coverage = build_coverage(results, context)
    summary = summarize(results, findings, coverage, context)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
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
        "findings_by_category": _finding_groups(findings),
        "assessment_context": _redact_value(context),
        "results": _redact_value(results),
    }

    try:
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        html_path.write_text(_render_html(payload), encoding="utf-8")
    except Exception as exc:
        return failure("Report Generator", target_url, f"JSON/HTML report creation failed: {type(exc).__name__}: {exc}", diagnosis="report_serialization_failed")

    try:
        _build_pdf(pdf_path, payload)
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
        pwndoc_status=pwndoc_status,
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
