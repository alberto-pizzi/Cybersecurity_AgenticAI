"""Assembles the full HTML report from a generated report payload.

This module intentionally contains no section-specific markup of its own:
it derives the handful of cover/disclaimer facts that are shared across
sections, then stitches the document together purely by calling the
rendering functions defined elsewhere in this package, in the order they
should appear. Each call registers its own heading(s) into `toc`, so the
table of contents follows document order automatically (see toc.py).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .coverage import _render_constraints, _render_execution, _render_limitations
from .css import report_css
from .finding_cards import _render_findings, _render_glance
from .findings import _finding_groups
from .sections import (
    _overall_risk_rating,
    _render_agentic_audit,
    _render_chaining_potential,
    _render_cleanup,
    _render_conclusion,
    _render_cover,
    _render_detail_cap_note,
    _render_disclaimer,
    _render_document_control,
    _render_executive_summary,
    _render_methodology,
    _render_overall_risk_banner,
    _render_priority_actions,
    _render_qualifications,
    _render_scope_section,
    _render_severity_legend,
    _render_visualizations,
)
from .text_utils import _esc, _format_date_en, _redact_value
from .toc import _render_toc


def _render_html(payload: dict[str, Any], *, for_pdf: bool = False) -> str:
    summary = payload["summary"]
    risks = summary["risk_counts"]
    groups = _finding_groups(payload["findings"])
    context_value = _redact_value(payload.get("assessment_context") or {})
    overall_rating, overall_color, overall_explanation = _overall_risk_rating(payload["findings"])

    toc: list[tuple[int, str, str]] = []

    # --- Facts shared between the cover page and the disclaimer ---------
    generated_at = payload.get("generated_at")
    generated_display = _format_date_en(generated_at) if isinstance(generated_at, datetime) else _esc(generated_at)

    profiles = context_value.get("profiles") if isinstance(context_value, dict) else None
    authenticated = any(isinstance(p, dict) and p.get("authenticated") for p in (profiles or []))
    assessment_type = payload.get("assessment_type") or (
        "Authenticated Web Application Penetration Test" if authenticated else "Web Application Penetration Test"
    )
    client_display = payload.get("client_name") or payload["target"]

    assessment_start = payload.get("assessment_start") or ""
    assessment_end = payload.get("assessment_end") or ""
    if assessment_start and assessment_end and assessment_start != assessment_end:
        assessment_dates = f"{assessment_start} – {assessment_end}"
    else:
        assessment_dates = assessment_start or assessment_end or generated_display

    cover_html = _render_cover(
        payload,
        assessment_type=assessment_type,
        client_display=client_display,
        assessment_dates=assessment_dates,
        generated_display=generated_display,
        overall_rating=overall_rating,
        overall_color=overall_color,
    )
    doc_control_html = _render_document_control(payload, generated_display)
    disclaimer_html = _render_disclaimer(client_display, assessment_dates)

    # Phase 1: render the body. Every rendering call below fires in the exact
    # order it's written here, appending to `toc` as it goes - this is what
    # makes the index "automatic": you don't edit a separate list, you just
    # write (or move) a section call and the index follows (LaTeX-style, see
    # toc.py).
    body_html = f"""
{_render_executive_summary(payload, summary, toc)}

{_render_severity_legend(toc)}
{_render_overall_risk_banner(overall_rating, overall_color, overall_explanation, toc)}
{_render_priority_actions(payload["findings"], toc)}
{_render_glance(payload["findings"], toc)}

{_render_detail_cap_note(summary.get("omitted_human_readable_detail", {}))}
{_render_scope_section(context_value, toc, for_pdf=for_pdf)}
{_render_methodology(toc)}
{_render_qualifications(toc)}
{_render_visualizations(context_value, risks, toc)}
{_render_agentic_audit(context_value, toc)}

{_render_execution(payload["coverage"], toc)}

{_render_limitations(summary, toc)}

{_render_constraints(summary, toc)}

{_render_chaining_potential(payload["findings"], toc)}

{_render_findings(groups, toc)}

{_render_cleanup(payload["findings"], toc)}

{_render_conclusion(summary, payload["findings"], toc)}
"""
    # toc[] is now fully populated -> Phase 2: render the index from it.
    # (Same reason LaTeX needs two compilation passes: the ToC appears
    # before the content it points to, so it can only be built after that
    # content has already been rendered once.)
    toc_html = _render_toc(toc)

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>SecOps Assessment Report</title>
<style>{report_css()}</style></head><body><main>
{cover_html}
{doc_control_html}
{disclaimer_html}

<div class="toc">
<h2 class="toc-title" id="index">Index</h2>
{toc_html}
</div>
{body_html}
</main></body></html>"""
