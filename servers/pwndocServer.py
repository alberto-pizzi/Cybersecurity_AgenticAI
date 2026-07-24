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
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from utils import REPORTS_DIR, failure, success

mcp = FastMCP("SecOps Report Server")

RISK_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
TOOL_PURPOSES = {
    "zap": "Broad authenticated/anonymous crawling and active web vulnerability scanning.",
    "nuclei": "Template-based checks for known exposures, CVEs and misconfigurations.",
    "nikto": "Web-server hardening, dangerous files and outdated component checks.",
    "ffuf": "Hidden path and resource discovery used to expand the crawl surface.",
    "arjun": "Hidden HTTP parameter discovery for downstream injection testing.",
    "sqlmap": "SQL injection confirmation on parameterized URLs.",
    "dalfox": "Cross-site scripting confirmation on parameterized URLs.",
    "commix": "Operating-system command injection testing.",
    "idor": "Heuristic object-level authorization differential checks.",
    "jwt": "JWT structural and claim analysis when a token is available.",
    "interactsh": "Explicit out-of-band callback testing when an insertion point is supplied.",
}


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
    explicit = str(finding.get("category", "")).lower()
    if explicit in {"vulnerability", "candidate", "discovery", "observation"}:
        return explicit
    return "observation" if str(finding.get("risk", "info")).lower() == "info" else "vulnerability"


def _default_impact(risk: str) -> str:
    return {
        "critical": "Successful exploitation may result in full compromise of application data or the underlying host.",
        "high": "Successful exploitation may expose sensitive data or enable significant unauthorized actions.",
        "medium": "The issue may enable limited unauthorized access, security-control bypass, or useful attacker reconnaissance.",
        "low": "The issue weakens security posture or exposes information useful for further attacks.",
        "info": "This observation expands the known attack surface but is not proof of a vulnerability by itself.",
    }.get(risk, "Review the finding in its application context.")


def flatten_findings(results: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for path, result in _iter_leaf_results(results):
        profile = path[0] if path else str(result.get("profile", "unknown"))
        tool_key = (path[1].split(":", 1)[0] if len(path) > 1 else str(result.get("tool", "unknown")))
        for raw in result.get("vulnerabilities") or []:
            if not isinstance(raw, dict):
                continue
            risk = str(raw.get("risk", "info")).lower()
            row = {
                "profile": profile,
                "tool": tool_key,
                **raw,
                "risk": risk,
                "category": _category(raw),
                "impact": raw.get("impact") or _default_impact(risk),
                "solution": raw.get("solution") or "Review and remediate the affected component according to vendor and secure-development guidance.",
                "confidence": raw.get("confidence") or ("high" if risk in {"critical", "high"} else "medium"),
            }
            fingerprint = tuple(str(row.get(key, "")) for key in ("profile", "tool", "alert", "risk", "url", "parameter", "evidence"))
            if fingerprint not in seen:
                seen.add(fingerprint)
                rows.append(row)
    return sorted(rows, key=lambda row: (RISK_ORDER.get(row["risk"], 0), row.get("alert", "")), reverse=True)


def _effective_status(result: dict[str, Any]) -> tuple[str, str]:
    status = str(result.get("status", "unknown")).lower()
    diagnosis = str(result.get("diagnosis", "")).lower()
    combined = "\n".join(str(result.get(key, "")) for key in ("output", "stdout", "stderr"))
    if result.get("timed_out") or result.get("time_limit_reached") or "timeout" in diagnosis or "time limit" in combined.lower():
        return "time_limit", "The configured scan budget was reached; findings were preserved and coverage is incomplete."
    if status == "success" and re.search(
        r"(?:not recognized as an internal or external command|non .? riconosciuto come comando interno o esterno|can't open perl script|modulenotfounderror|traceback \(most recent call last\))",
        combined, re.I,
    ):
        return "error", "The scanner result claimed success, but its process output contains a launcher or dependency failure."
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
    matches = [value for key, value in tools.items() if key == tool or key.startswith(f"{tool}:") if isinstance(value, dict)]
    if not matches:
        return None
    statuses = [_effective_status(item)[0] for item in matches]
    successes = sum(status == "success" for status in statuses)
    errors = sum(status == "error" for status in statuses)
    partials = sum(status == "partial" for status in statuses)
    limited = sum(status == "time_limit" for status in statuses)
    if errors == len(matches):
        status = "error"
    elif errors or partials:
        status = "partial"
    elif limited:
        status = "time_limit"
    elif successes:
        status = "success"
    else:
        status = "skipped"
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, ...]] = set()
    for item in matches:
        for finding in item.get("vulnerabilities") or []:
            if not isinstance(finding, dict):
                continue
            fingerprint = tuple(str(finding.get(key, "")) for key in (
                "alert", "risk", "category", "url", "parameter", "evidence"
            ))
            if fingerprint not in seen_findings:
                seen_findings.add(fingerprint)
                findings.append(finding)
    return {
        "tool": tool, "status": status, "target": matches[0].get("target", ""),
        "output": f"Agentic runs: {len(matches)}; successful={successes}; time-limited={limited}; errors={errors}; other partial={partials}.",
        "vulnerabilities": findings, "runs": matches,
    }


def build_coverage(results: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    expected = context.get("expected_tools") if isinstance(context.get("expected_tools"), list) else list(TOOL_PURPOSES)
    profiles = context.get("profiles") if isinstance(context.get("profiles"), list) else list(results)
    profile_names = [item.get("name", item) if isinstance(item, dict) else item for item in profiles]
    for profile in profile_names:
        tools = results.get(profile, {}) if isinstance(results.get(profile), dict) else {}
        for tool in expected:
            result = _tool_result(tools, tool)
            if not isinstance(result, dict):
                rows.append({
                    "profile": profile, "tool": tool, "status": "not_run", "targets": 0,
                    "findings": 0, "duration_seconds": 0.0,
                    "purpose": TOOL_PURPOSES.get(tool, "Security assessment tool."),
                    "details": "The orchestrator did not create a result for this tool.",
                })
                continue
            runs = result.get("runs") if isinstance(result.get("runs"), list) else []
            targets = len(runs) if runs else (1 if result.get("status") != "skipped" else 0)
            effective_status, contradiction = _effective_status(result)
            rows.append({
                "profile": profile,
                "tool": tool,
                "status": effective_status,
                "targets": targets,
                "findings": len(result.get("vulnerabilities") or []),
                "duration_seconds": round(_duration(result), 2),
                "purpose": TOOL_PURPOSES.get(tool, "Security assessment tool."),
                "details": (contradiction + " " + str(result.get("output", ""))).strip(),
            })
    return rows


def summarize(results: dict[str, Any], findings: list[dict[str, Any]], coverage: list[dict[str, Any]], context: dict[str, Any]) -> dict[str, Any]:
    status_counts = Counter(row["status"] for row in coverage)
    risk_counts = Counter(row["risk"] for row in findings if row["category"] in {"vulnerability", "candidate"})
    category_counts = Counter(row["category"] for row in findings)
    limitations = []
    for path, result in _iter_leaf_results(results):
        effective_status, contradiction = _effective_status(result)
        if effective_status in {"error", "partial", "time_limit"}:
            limitations.append({
                "path": "/".join(path), "status": effective_status,
                "diagnosis": result.get("diagnosis", "inconsistent_success" if contradiction else "unknown"),
                "details": (contradiction + " " + str(result.get("output", ""))).strip(),
            })
    for profile, discovery in (context.get("discovery") or {}).items():
        if isinstance(discovery, dict) and discovery.get("authentication_effective") is False:
            limitations.append({
                "path": f"{profile}/authentication", "status": "warning", "diagnosis": "authentication_ineffective",
                "details": discovery.get("authentication_note", "The supplied session appeared to reach a login page."),
            })
    return {
        "status_counts": dict(status_counts),
        "risk_counts": {risk: risk_counts.get(risk, 0) for risk in RISK_ORDER},
        "category_counts": dict(category_counts),
        "limitations": limitations,
        "coverage_complete": not any(row["status"] in {"error", "partial", "time_limit", "not_run"} for row in coverage),
    }


def _executive_text(summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    risks = summary["risk_counts"]
    confirmed = sum(1 for item in findings if item["category"] == "vulnerability")
    candidates = sum(1 for item in findings if item["category"] == "candidate")
    observations = sum(1 for item in findings if item["category"] in {"discovery", "observation"})
    return (
        f"The assessment recorded {confirmed} security findings, {candidates} candidates requiring manual verification, "
        f"and {observations} discovery or hardening observations. Severity distribution: "
        f"{risks.get('critical', 0)} critical, {risks.get('high', 0)} high, {risks.get('medium', 0)} medium, "
        f"{risks.get('low', 0)} low. {len(summary['limitations'])} execution limitations or warnings were recorded; "
        "a failed, skipped, or time-limited scanner is never interpreted as proof that the target is clean."
    )


def _esc(value: Any) -> str:
    return html.escape(str(value or ""))


def _render_html(payload: dict[str, Any]) -> str:
    summary, coverage, findings = payload["summary"], payload["coverage"], payload["findings"]
    security = [item for item in findings if item["category"] in {"vulnerability", "candidate"}]
    observations = [item for item in findings if item["category"] in {"discovery", "observation"}]

    coverage_rows = "".join(
        "<tr>" + "".join(f"<td>{_esc(value)}</td>" for value in (
            row["profile"], row["tool"], row["status"], row["targets"], row["findings"], row["duration_seconds"], row["purpose"], row["details"]
        )) + "</tr>" for row in coverage
    )
    limitation_rows = "".join(
        "<tr>" + "".join(f"<td>{_esc(value)}</td>" for value in (row["path"], row["status"], row["diagnosis"], row["details"])) + "</tr>"
        for row in summary["limitations"]
    ) or '<tr><td colspan="4">No execution limitations were recorded.</td></tr>'
    discovery_rows = []
    for profile, discovered in (payload.get("assessment_context", {}).get("discovery", {}) or {}).items():
        if not isinstance(discovered, dict):
            continue
        cases = discovered.get("request_cases", []) or []
        get_cases = sum(str(case.get("method", "GET")).upper() == "GET" for case in cases if isinstance(case, dict))
        post_cases = sum(str(case.get("method", "GET")).upper() == "POST" for case in cases if isinstance(case, dict))
        discovery_rows.append("<tr>" + "".join(f"<td>{_esc(value)}</td>" for value in (
            profile, len(discovered.get("html_urls", []) or []), get_cases, post_cases,
            discovered.get("authentication_effective"), discovered.get("authentication_note", ""),
            len(discovered.get("errors", []) or []),
        )) + "</tr>")
    discovery_rows_html = "".join(discovery_rows) or '<tr><td colspan="7">No discovery context was supplied.</td></tr>'

    def finding_cards(items: list[dict[str, Any]]) -> str:
        if not items:
            return '<div class="empty">None recorded.</div>'
        cards = []
        for index, item in enumerate(items, start=1):
            refs = item.get("references") or item.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            cards.append(f"""
<article class="finding risk-{_esc(item['risk'])}">
<h3>{index}. {_esc(item.get('alert', 'Finding'))}</h3>
<div class="badges"><span>{_esc(item['risk']).upper()}</span><span>{_esc(item['category'])}</span><span>confidence: {_esc(item.get('confidence'))}</span></div>
<dl>
<dt>Profile / tool</dt><dd>{_esc(item.get('profile'))} / {_esc(item.get('tool'))}</dd>
<dt>Affected URL</dt><dd>{_esc(item.get('url'))}</dd>
<dt>Method</dt><dd>{_esc(item.get('method')) or 'GET / not specified'}</dd>
<dt>Parameter</dt><dd>{_esc(item.get('parameter')) or '-'}</dd>
<dt>Description</dt><dd>{_esc(item.get('description'))}</dd>
<dt>Potential impact</dt><dd>{_esc(item.get('impact'))}</dd>
<dt>Evidence</dt><dd><pre>{_esc(item.get('evidence')) or 'No scanner evidence was supplied.'}</pre></dd>
<dt>Recommendation</dt><dd>{_esc(item.get('solution'))}</dd>
<dt>References</dt><dd>{'<br>'.join(_esc(ref) for ref in refs) or '-'}</dd>
</dl></article>""")
        return "".join(cards)

    raw = _esc(json.dumps(payload.get("results", {}), indent=2, ensure_ascii=False, default=str))
    risks = summary["risk_counts"]
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecOps Assessment</title><style>
:root{{--bg:#f3f6f9;--card:#fff;--text:#17212b;--muted:#607080;--line:#ccd5df;--accent:#24476b;--bad:#8b2f2f}}
@media(prefers-color-scheme:dark){{:root{{--bg:#10161d;--card:#18212b;--text:#edf3f8;--muted:#aeb9c4;--line:#354353;--accent:#5c91c8;--bad:#d87979}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font-family:Segoe UI,Arial,sans-serif}}main{{max-width:1450px;margin:auto;padding:28px}}
h1,h2,h3{{margin-top:0}}.meta,.muted{{color:var(--muted)}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px;margin:18px 0 28px}}
.card,.finding,.empty{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}}.value{{font-size:1.8rem;font-weight:700}}
.table-wrap{{overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:12px;margin-bottom:26px}}table{{width:100%;border-collapse:collapse;min-width:1050px}}th{{background:var(--accent);color:#fff;text-align:left}}th,td{{padding:9px;border-bottom:1px solid var(--line);vertical-align:top;white-space:pre-wrap}}
.badges span{{display:inline-block;padding:3px 8px;margin:0 6px 8px 0;border-radius:999px;background:#68798a22;font-size:.85rem}}dl{{display:grid;grid-template-columns:150px 1fr;gap:8px 14px}}dt{{font-weight:700}}dd{{margin:0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0d141b;color:#dce7f0;padding:12px;border-radius:8px;max-height:420px;overflow:auto}}
.risk-critical,.risk-high{{border-left:6px solid #b22}}.risk-medium{{border-left:6px solid #d98200}}.risk-low{{border-left:6px solid #d0ad00}}.risk-info{{border-left:6px solid #4b86b4}}details{{margin-top:20px}}
</style></head><body><main>
<h1>SecOps Assessment Report</h1><div class="meta"><b>Target:</b> {_esc(payload['target'])}<br><b>Generated:</b> {_esc(payload['generated_at'])}</div>
<h2>Executive summary</h2><div class="card">{_esc(payload['executive_summary'])}</div>
<div class="grid">{''.join(f'<div class="card"><div class="value">{risks.get(risk,0)}</div><div class="muted">{risk.title()}</div></div>' for risk in ('critical','high','medium','low'))}<div class="card"><div class="value">{len(summary['limitations'])}</div><div class="muted">Limitations</div></div></div>
<h2>Discovery and authentication coverage</h2><div class="table-wrap"><table><thead><tr><th>Profile</th><th>HTML pages</th><th>GET cases</th><th>POST cases</th><th>Authentication effective</th><th>Explanation</th><th>Crawl errors</th></tr></thead><tbody>{discovery_rows_html}</tbody></table></div>
<h2>Tool coverage</h2><div class="table-wrap"><table><thead><tr><th>Profile</th><th>Tool</th><th>Status</th><th>Targets</th><th>Findings</th><th>Seconds</th><th>Purpose</th><th>Details</th></tr></thead><tbody>{coverage_rows}</tbody></table></div>
<h2>Execution limitations</h2><div class="table-wrap"><table><thead><tr><th>Path</th><th>Status</th><th>Cause</th><th>Explanation</th></tr></thead><tbody>{limitation_rows}</tbody></table></div>
<h2>Security findings and candidates</h2>{finding_cards(security)}
<h2>Discovery and hardening observations</h2>{finding_cards(observations)}
<details><summary>Raw structured scanner results</summary><pre>{raw}</pre></details>
</main></body></html>"""


def _p(value: Any) -> str:
    return html.escape(str(value or "")).replace("\n", "<br/>")


def _build_pdf(path: Path, payload: dict[str, Any]) -> None:
    styles = getSampleStyleSheet()
    body = ParagraphStyle("BodySmall", parent=styles["BodyText"], fontSize=8, leading=10, spaceAfter=5)
    small = ParagraphStyle("Tiny", parent=body, fontSize=7, leading=8)
    header = ParagraphStyle("Header", parent=small, fontName="Helvetica-Bold", textColor=colors.white)
    heading = ParagraphStyle("FindingHeading", parent=styles["Heading3"], spaceBefore=8, spaceAfter=5)
    doc = SimpleDocTemplate(str(path), pagesize=landscape(A4), leftMargin=28, rightMargin=28, topMargin=26, bottomMargin=26)
    story: list[Any] = [
        Paragraph("SecOps Assessment Report", styles["Title"]),
        Paragraph(f"<b>Target:</b> {_p(payload['target'])}", body),
        Paragraph(f"<b>Generated:</b> {_p(payload['generated_at'])}", body),
        Spacer(1, 8), Paragraph("Executive summary", styles["Heading2"]),
        Paragraph(_p(payload["executive_summary"]), body), Spacer(1, 8),
        Paragraph("Tool coverage", styles["Heading2"]),
    ]
    coverage_data = [[Paragraph(value, header) for value in ("Profile", "Tool", "Status", "Targets", "Findings", "Seconds", "Details")]]
    for row in payload["coverage"]:
        coverage_data.append([
            Paragraph(_p(row["profile"]), small), Paragraph(_p(row["tool"]), small), Paragraph(_p(row["status"]), small),
            Paragraph(str(row["targets"]), small), Paragraph(str(row["findings"]), small), Paragraph(str(row["duration_seconds"]), small), Paragraph(_p(row["details"]), small),
        ])
    table = Table(coverage_data, colWidths=[65, 60, 55, 42, 45, 45, 430], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#24476B")), ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#B8C2CC")), ("VALIGN", (0,0), (-1,-1), "TOP"), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F4F7FA")])]))
    story.extend([table, PageBreak(), Paragraph("Detailed findings", styles["Heading2"])])
    for index, item in enumerate(payload["findings"], start=1):
        story.extend([
            Paragraph(f"{index}. {_p(item.get('alert', 'Finding'))} [{_p(item.get('risk', 'info')).upper()}]", heading),
            Paragraph(f"<b>Category:</b> {_p(item.get('category'))} &nbsp; <b>Confidence:</b> {_p(item.get('confidence'))}", body),
            Paragraph(f"<b>Profile / tool:</b> {_p(item.get('profile'))} / {_p(item.get('tool'))}", body),
            Paragraph(f"<b>URL:</b> {_p(item.get('url'))}", body),
            Paragraph(f"<b>Method:</b> {_p(item.get('method')) or 'GET / not specified'}", body),
            Paragraph(f"<b>Parameter:</b> {_p(item.get('parameter')) or '-'}", body),
            Paragraph(f"<b>Description:</b> {_p(item.get('description'))}", body),
            Paragraph(f"<b>Impact:</b> {_p(item.get('impact'))}", body),
            Paragraph(f"<b>Evidence:</b> {_p(item.get('evidence')) or 'No scanner evidence was supplied.'}", small),
            Paragraph(f"<b>Recommendation:</b> {_p(item.get('solution'))}", body), Spacer(1, 7),
        ])
    if not payload["findings"]:
        story.append(Paragraph("No structured findings were produced. Review coverage and limitations; incomplete scanners are not considered clean results.", body))
    doc.build(story)


@mcp.tool()
def generate_report(
    findings_summary: dict | str,
    target_url: str,
    output_name: str = "",
    assessment_context: dict | str | None = None,
) -> dict:
    """Generate detailed JSON, HTML and PDF reports with coverage and limitations."""
    try:
        results = _as_dict(findings_summary)
        context = _as_dict(assessment_context)
    except (json.JSONDecodeError, ValueError) as exc:
        return failure("Report Generator", target_url, f"Invalid report input: {exc}", diagnosis="invalid_report_input")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    base = _safe_name(output_name) or f"SecOps_Assessment_{datetime.now():%Y%m%d_%H%M%S}"
    json_path, html_path, pdf_path = (Path(REPORTS_DIR) / f"{base}.{suffix}" for suffix in ("json", "html", "pdf"))
    findings = flatten_findings(results)
    coverage = build_coverage(results, context)
    summary = summarize(results, findings, coverage, context)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(), "target": target_url,
        "executive_summary": _executive_text(summary, findings),
        "summary": summary, "coverage": coverage,
        "security_findings_count": sum(item["category"] == "vulnerability" for item in findings),
        "candidate_findings_count": sum(item["category"] == "candidate" for item in findings),
        "observations_count": sum(item["category"] in {"discovery", "observation"} for item in findings),
        "findings_count": len(findings), "findings": findings,
        "assessment_context": context, "results": results,
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
        "Report Generator", target_url,
        f"Detailed PDF, HTML and JSON reports generated. Security findings: {payload['security_findings_count']}; observations: {payload['observations_count']}.",
        pdf_filename=str(pdf_path.resolve()), html_filename=str(html_path.resolve()), json_filename=str(json_path.resolve()),
        local_pdf_generated=True, local_html_generated=True, local_json_generated=True,
        findings_count=len(findings), security_findings_count=payload["security_findings_count"],
        observations_count=payload["observations_count"], pwndoc_status=pwndoc_status,
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")