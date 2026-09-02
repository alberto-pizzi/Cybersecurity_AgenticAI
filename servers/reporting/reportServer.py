from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests
from fastmcp import FastMCP

from utils import REPORTS_DIR, failure, run_mcp_http, success

from reporting.coverage import _executive_text, build_coverage, summarize
from reporting.findings import _finding_groups, _human_readable_findings, flatten_findings
from reporting.html_report import _render_html
from reporting.pdf_maker import html2pdf
from reporting.revision_snapshot import build_review_snapshot
from reporting.text_utils import _as_dict, _redact_value, _safe_name


mcp = FastMCP("SecOps Report Server")


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
    """Generate scanner-grounded JSON, HTML, PDF and review-snapshot artifacts.

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
    review_snapshot_path = Path(REPORTS_DIR) / f"{base}.review.json"
    all_findings = flatten_findings(results)
    findings, omitted_detail = _human_readable_findings(all_findings)
    coverage = build_coverage(results, context)
    summary = summarize(results, all_findings, coverage, context)
    summary["omitted_human_readable_detail"] = omitted_detail

    payload = {
        "generated_at": datetime.now(timezone.utc),
        "target": target_url,
        "reporting_policy": "Scanner-grounded: observed facts are not invented; potential consequences and recovery guidance remain explicitly conditional when damage is not evidenced.",
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
        review_snapshot_path.write_text(
            json.dumps(build_review_snapshot(payload), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        html_path.write_text(_render_html(payload), encoding="utf-8")
    except Exception as exc:
        return failure("Report Generator", target_url, f"JSON/HTML/review snapshot creation failed: {type(exc).__name__}: {exc}", diagnosis="report_serialization_failed")

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
        result.update(
            json_filename=str(json_path.resolve()),
            review_snapshot_filename=str(review_snapshot_path.resolve()) if review_snapshot_path.is_file() else None,
            html_filename=str(html_path.resolve()), pdf_filename=None, findings_count=len(findings),
        )
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
            f"Scanner-grounded PDF, HTML, JSON and review snapshot generated. "
            f"Confirmed findings: {payload['security_findings_count']}; "
            f"candidates: {payload['candidate_findings_count']}; observations: {payload['observations_count']}."
        ),
        pdf_filename=str(pdf_path.resolve()),
        html_filename=str(html_path.resolve()),
        json_filename=str(json_path.resolve()),
        review_snapshot_filename=str(review_snapshot_path.resolve()),
        local_pdf_generated=True,
        local_html_generated=True,
        local_json_generated=True,
        local_review_snapshot_generated=True,
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
