from __future__ import annotations

import html
import json
import os
import re
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


def _safe_name(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip()).strip("._")
    return sanitized[:120]


def _iter_result_nodes(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], dict[str, Any]]]:
    if isinstance(value, dict):
        runs = value.get("runs")
        if isinstance(runs, list):
            for index, run in enumerate(runs, start=1):
                if isinstance(run, dict):
                    yield (*path, str(index)), run
            return
        if "status" in value or "vulnerabilities" in value:
            yield path, value
            return
        for key, child in value.items():
            yield from _iter_result_nodes(child, (*path, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value, start=1):
            yield from _iter_result_nodes(child, (*path, str(index)))


def _finding_fingerprint(finding: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(finding.get(key, "")) for key in (
        "profile", "tool", "alert", "risk", "url", "parameter", "evidence", "description"
    ))


def flatten_findings(results: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for path, tool_result in _iter_result_nodes(results):
        findings = tool_result.get("vulnerabilities") or []
        if not isinstance(findings, list):
            continue
        profile_name = path[0] if path else str(tool_result.get("profile", ""))
        tool_name = path[1] if len(path) > 1 else str(tool_result.get("tool", "unknown"))
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            row = {
                "profile": profile_name,
                "tool": tool_name,
                **finding,
            }
            fingerprint = _finding_fingerprint(row)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            rows.append(row)
    return sorted(
        rows,
        key=lambda row: RISK_ORDER.get(str(row.get("risk", "info")).lower(), 0),
        reverse=True,
    )


def summarize_results(results: dict[str, Any]) -> dict[str, Any]:
    counts = {"success": 0, "error": 0, "skipped": 0, "partial": 0, "unknown": 0}
    errors: list[dict[str, Any]] = []
    for path, result in _iter_result_nodes(results):
        status = str(result.get("status", "unknown")).lower()
        if status not in counts:
            status = "unknown"
        counts[status] += 1
        if status in {"error", "partial"}:
            errors.append({
                "path": "/".join(path),
                "tool": result.get("tool", path[-1] if path else "unknown"),
                "target": result.get("target", ""),
                "status": status,
                "diagnosis": result.get("diagnosis", "unknown"),
                "output": str(result.get("output", "")),
            })
    return {"counts": counts, "errors": errors}


def _paragraph_text(value: Any) -> str:
    return html.escape(str(value or "")).replace("\n", "<br/>")


def _update_failure(result: dict[str, Any], **extra: Any) -> dict[str, Any]:
    result.update(extra)
    return result


def _render_html_preview(report_payload: dict[str, Any]) -> str:
    """Create a standalone browser preview with no external assets."""
    summary = report_payload.get("summary", {})
    counts = summary.get("counts", {})
    errors = summary.get("errors", [])
    findings = report_payload.get("findings", [])

    def cells(values: list[Any]) -> str:
        return "".join(f"<td>{html.escape(str(value or ''))}</td>" for value in values)

    error_rows = "".join(
        f"<tr>{cells([row.get('path'), row.get('status'), row.get('diagnosis'), row.get('target'), row.get('output')])}</tr>"
        for row in errors
    ) or '<tr><td colspan="5">No scanner errors or partial results.</td></tr>'

    finding_rows = "".join(
        f"<tr>{cells([
            finding.get('profile'),
            finding.get('tool'),
            finding.get('alert', 'Finding'),
            finding.get('risk', 'info'),
            finding.get('url'),
            finding.get('parameter'),
            finding.get('description'),
            finding.get('evidence'),
        ])}</tr>"
        for finding in findings
    ) or '<tr><td colspan="8">No structured findings. Scanner failures are not treated as a clean result.</td></tr>'

    raw_json = html.escape(json.dumps(report_payload.get("results", {}), indent=2, ensure_ascii=False, default=str))
    target = html.escape(str(report_payload.get("target", "")))
    generated = html.escape(str(report_payload.get("generated_at", "")))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecOps Assessment Preview</title>
<style>
:root {{ color-scheme: light dark; --bg:#f4f7fa; --card:#fff; --text:#17212b; --muted:#5f6b76; --line:#cbd5df; --accent:#24476b; --error:#8b2f2f; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#10151b; --card:#18212b; --text:#ecf2f8; --muted:#aeb9c4; --line:#354353; --accent:#5c91c8; --error:#d87979; }} }}
* {{ box-sizing:border-box; }} body {{ margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:var(--bg); color:var(--text); }}
main {{ max-width:1500px; margin:auto; padding:28px; }} h1,h2 {{ margin:0 0 14px; }} .meta {{ color:var(--muted); margin-bottom:20px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:18px 0 26px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; box-shadow:0 3px 12px #0001; }}
.value {{ font-size:1.8rem; font-weight:700; }} .label {{ color:var(--muted); }}
.table-wrap {{ overflow:auto; background:var(--card); border:1px solid var(--line); border-radius:12px; margin-bottom:26px; }}
table {{ width:100%; border-collapse:collapse; min-width:900px; }} th {{ position:sticky; top:0; background:var(--accent); color:white; text-align:left; }}
th,td {{ padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; white-space:pre-wrap; overflow-wrap:anywhere; }}
tr:nth-child(even) td {{ background:#7f8c9810; }} .errors th {{ background:var(--error); }} details {{ margin-top:20px; }}
pre {{ max-height:700px; overflow:auto; background:#0c1117; color:#d7e0ea; padding:16px; border-radius:10px; }}
</style>
</head>
<body><main>
<h1>SecOps Assessment Preview</h1>
<div class="meta"><b>Target:</b> {target}<br><b>Generated:</b> {generated}</div>
<div class="grid">
<div class="card"><div class="value">{counts.get('success', 0)}</div><div class="label">Successful runs</div></div>
<div class="card"><div class="value">{counts.get('error', 0)}</div><div class="label">Errors</div></div>
<div class="card"><div class="value">{counts.get('partial', 0)}</div><div class="label">Partial</div></div>
<div class="card"><div class="value">{counts.get('skipped', 0)}</div><div class="label">Skipped</div></div>
<div class="card"><div class="value">{len(findings)}</div><div class="label">Unique findings</div></div>
</div>
<h2>Scanner errors and partial results</h2>
<div class="table-wrap"><table class="errors"><thead><tr><th>Path</th><th>Status</th><th>Cause</th><th>Target</th><th>Details</th></tr></thead><tbody>{error_rows}</tbody></table></div>
<h2>Security findings</h2>
<div class="table-wrap"><table><thead><tr><th>Profile</th><th>Tool</th><th>Finding</th><th>Risk</th><th>URL</th><th>Parameter</th><th>Description</th><th>Evidence</th></tr></thead><tbody>{finding_rows}</tbody></table></div>
<details><summary>Raw structured scanner results</summary><pre>{raw_json}</pre></details>
</main></body></html>"""


@mcp.tool()
def generate_report(
    findings_summary: dict | str,
    target_url: str,
    output_name: str = "",
) -> dict:
    """Generate local JSON and PDF reports from structured scanner results."""
    try:
        results = json.loads(findings_summary) if isinstance(findings_summary, str) else findings_summary
    except json.JSONDecodeError as exc:
        return failure("Report Generator", target_url, f"Invalid findings JSON: {exc}")

    if not isinstance(results, dict):
        return failure("Report Generator", target_url, "findings_summary must be a dictionary.")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    requested_name = _safe_name(output_name)
    base_name = requested_name or f"SecOps_Assessment_{stamp}"
    pdf_path = Path(REPORTS_DIR) / f"{base_name}.pdf"
    html_path = Path(REPORTS_DIR) / f"{base_name}.html"
    json_path = Path(REPORTS_DIR) / f"{base_name}.json"

    findings = flatten_findings(results)
    result_summary = summarize_results(results)
    report_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target_url,
        "summary": result_summary,
        "findings_count": len(findings),
        "findings": findings,
        "results": results,
    }

    # JSON and HTML preview are intentionally independent from PDF generation.
    try:
        json_path.write_text(
            json.dumps(report_payload, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
    except Exception as exc:
        return failure("Report Generator", target_url, f"JSON report creation failed: {type(exc).__name__}: {exc}")

    try:
        html_path.write_text(_render_html_preview(report_payload), encoding="utf-8")
        if not html_path.is_file() or html_path.stat().st_size == 0:
            raise RuntimeError("HTML preview writer completed without creating a non-empty file.")
    except Exception as exc:
        result = failure(
            "Report Generator",
            target_url,
            f"HTML preview creation failed: {type(exc).__name__}: {exc}",
        )
        return _update_failure(
            result,
            json_filename=str(json_path.resolve()),
            html_filename=None,
            pdf_filename=None,
            local_json_generated=True,
            local_html_generated=False,
            local_pdf_generated=False,
            findings_count=len(findings),
            diagnosis="html_preview_generation_failed",
        )

    try:
        document = SimpleDocTemplate(
            str(pdf_path),
            pagesize=landscape(A4),
            leftMargin=28,
            rightMargin=28,
            topMargin=28,
            bottomMargin=28,
            title="SecOps Assessment Report",
            author="SecOps Agent",
        )
        styles = getSampleStyleSheet()
        cell = ParagraphStyle("SecOpsCell", parent=styles["BodyText"], fontSize=7, leading=9)
        header = ParagraphStyle(
            "SecOpsHeader",
            parent=cell,
            fontName="Helvetica-Bold",
            textColor=colors.white,
        )
        small = ParagraphStyle("SecOpsSmall", parent=styles["BodyText"], fontSize=8, leading=10)

        counts = result_summary["counts"]
        story = [
            Paragraph("SecOps Assessment Report", styles["Title"]),
            Paragraph(f"<b>Target:</b> {_paragraph_text(target_url)}", styles["BodyText"]),
            Paragraph(
                "<b>Scanner executions:</b> "
                f"success {counts['success']} · error {counts['error']} · "
                f"partial {counts['partial']} · skipped {counts['skipped']}",
                styles["BodyText"],
            ),
            Paragraph(f"<b>Unique findings:</b> {len(findings)}", styles["BodyText"]),
            Spacer(1, 12),
        ]

        if result_summary["errors"]:
            story.append(Paragraph("Scanner Errors and Partial Results", styles["Heading2"]))
            error_data = [[
                Paragraph("Path", header),
                Paragraph("Status", header),
                Paragraph("Cause", header),
                Paragraph("Target", header),
                Paragraph("Details", header),
            ]]
            for row in result_summary["errors"]:
                error_data.append([
                    Paragraph(_paragraph_text(row["path"]), cell),
                    Paragraph(_paragraph_text(row["status"]), cell),
                    Paragraph(_paragraph_text(row["diagnosis"]), cell),
                    Paragraph(_paragraph_text(row["target"]), cell),
                    Paragraph(_paragraph_text(row["output"]), cell),
                ])
            error_table = Table(error_data, colWidths=[120, 50, 105, 180, 315], repeatRows=1)
            error_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7A2E2E")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8C2CC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FFF6F6")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.extend([error_table, PageBreak()])

        story.append(Paragraph("Security Findings", styles["Heading2"]))
        table_data = [[
            Paragraph("Profile", header),
            Paragraph("Tool", header),
            Paragraph("Finding", header),
            Paragraph("Risk", header),
            Paragraph("URL", header),
            Paragraph("Description / evidence", header),
        ]]

        if not findings:
            table_data.append([
                Paragraph("-", cell),
                Paragraph("-", cell),
                Paragraph("No structured findings", cell),
                Paragraph("Info", cell),
                Paragraph(_paragraph_text(target_url), cell),
                Paragraph(
                    "Review scanner statuses and errors above. A failed scanner is not treated as evidence that the target is clean.",
                    small,
                ),
            ])
        else:
            for finding in findings:
                description = _paragraph_text(finding.get("description", ""))
                evidence = _paragraph_text(finding.get("evidence", ""))
                detail = description
                if evidence:
                    detail += f"<br/><b>Evidence:</b> {evidence}"
                table_data.append([
                    Paragraph(_paragraph_text(finding.get("profile", "")), cell),
                    Paragraph(_paragraph_text(finding.get("tool", "")), cell),
                    Paragraph(_paragraph_text(finding.get("alert", "Finding")), cell),
                    Paragraph(_paragraph_text(finding.get("risk", "info")), cell),
                    Paragraph(_paragraph_text(finding.get("url", target_url)), cell),
                    Paragraph(detail, cell),
                ])

        table = Table(table_data, colWidths=[65, 80, 125, 45, 180, 275], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#24476B")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8C2CC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F7FA")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)
        document.build(story)

        if not pdf_path.is_file() or pdf_path.stat().st_size == 0:
            raise RuntimeError("ReportLab completed without creating a non-empty PDF.")
    except Exception as exc:
        result = failure(
            "Report Generator",
            target_url,
            f"PDF report creation failed: {type(exc).__name__}: {exc}",
        )
        return _update_failure(
            result,
            json_filename=str(json_path.resolve()),
            html_filename=str(html_path.resolve()),
            pdf_filename=None,
            local_json_generated=True,
            local_html_generated=True,
            local_pdf_generated=False,
            findings_count=len(findings),
            diagnosis="pdf_generation_failed",
        )

    pwndoc_url = os.getenv("PWNDOC_URL", "").rstrip("/")
    pwndoc_status = "not_configured"
    if pwndoc_url:
        verify_tls = os.getenv("PWNDOC_VERIFY_TLS", "true").lower() not in {"0", "false", "no"}
        try:
            response = requests.get(pwndoc_url, timeout=(3, 5), verify=verify_tls)
            if response.status_code < 500:
                pwndoc_status = "reachable"
            else:
                pwndoc_status = f"unhealthy_http_{response.status_code}"
        except requests.RequestException as exc:
            pwndoc_status = f"offline:{type(exc).__name__}"

    return success(
        "Report Generator",
        target_url,
        f"PDF, HTML preview and JSON reports generated. Unique findings: {len(findings)}",
        pdf_filename=str(pdf_path.resolve()),
        html_filename=str(html_path.resolve()),
        json_filename=str(json_path.resolve()),
        local_pdf_generated=True,
        local_html_generated=True,
        local_json_generated=True,
        findings_count=len(findings),
        scanner_summary=result_summary["counts"],
        pwndoc_status=pwndoc_status,
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")