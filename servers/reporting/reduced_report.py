"""Renders the *reduced* report: the same assessment, but with per-finding
detail trimmed by severity according to ``report_filters``.

Guarantees:
* Every finding is still present. Severities configured as ``"none"`` detail,
  and findings beyond a severity's ``max_detailed`` cap, are shown as a compact
  one-line row rather than dropped.
* AI-authored content stays clearly marked (the ``(AI-generated)`` field suffix
  and the dedicated "Agentic risk assessment" box), so the reader can always
  tell what the AI said from what the scanner reported.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

from . import report_filters as rf
from .constants import AI_SUFFIX
from .coverage import (
    _render_constraints,
    _render_endpoint_coverage,
    _render_execution,
    _render_limitations,
)
from .fields import _field, _render_list
from .finding_cards import _finding_card, _render_glance
from .findings import _finding_groups
from .sections import (
    _overall_risk_rating,
    _render_agentic_audit,
    _render_chaining_potential,
    _render_cleanup,
    _render_conclusion,
    _render_cover,
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
from .style import report_css
from .text_utils import _esc, _format_date_en, _redact_text, _redact_value
from .toc import _heading, _render_toc


# Length-capped evidence/payload snippet, honouring the per-level snippet cap.
def _capped_snippet(label: str, value: Any, cap: int) -> str:
    if cap <= 0 or value in (None, "", [], {}):
        return ""
    text = _redact_text(value)
    omitted = len(text) - cap
    if omitted > 0:
        text = f"{text[:cap]}\n… [{omitted} further characters omitted]"
    return f'<p class="field-label">{_esc(label)}</p><pre>{html.escape(text)}</pre>'


# Builds the AI-marking helpers for one finding, mirroring finding_cards.
def _ai_helpers(item: dict[str, Any]):
    ai_analysis = item.get("ai_analysis") if isinstance(item.get("ai_analysis"), dict) else {}
    narrative_fallbacks = set(ai_analysis.get("narrative_fallbacks") or []) if ai_analysis else set()

    def ai_suffix(field_key: str) -> str:
        if not ai_analysis or field_key in narrative_fallbacks:
            return ""
        return f" {AI_SUFFIX}"

    return ai_analysis, ai_suffix


# Compact one-line row for findings shown without a detail card (keeps them present).
def _reduced_listed_row(item: dict[str, Any], index: int) -> str:
    risk = str(item.get("risk") or "info").lower()
    bits = [
        f'<b>{index}. {_esc(item.get("alert", "Unnamed finding"))}</b>',
        f'<span>{_esc(risk).upper()}</span>',
    ]
    meta: list[str] = []
    if item.get("tool"):
        meta.append(f'tool: {_esc(item.get("tool"))}')
    if item.get("url"):
        meta.append(f'url: {_esc(item.get("url"))}')
    if item.get("parameter"):
        meta.append(f'parameter: {_esc(item.get("parameter"))}')
    meta_html = f'<br><small>{" · ".join(meta)}</small>' if meta else ""
    return (
        f'<article class="finding risk-{_esc(risk)}" style="padding:8px 14px">'
        f'<div class="reduced-row">{" ".join(bits)}{meta_html}</div>'
        "</article>"
    )


# Renders a single finding at "reduced"/"essential" detail using the field table.
def _reduced_finding_card(
    item: dict[str, Any],
    index: int,
    toc: list[tuple[int, str, str]],
    fields: dict,
    snippet_cap: int,
) -> str:
    ai_analysis, ai_suffix = _ai_helpers(item)

    def on(key: str) -> bool:
        return bool(fields.get(key))

    risk = str(item.get("risk") or "info").lower()
    heading = _heading(
        3, f"{index}. {item['alert']}", toc,
        in_toc=False, anchor=f"reduced-finding-{index}",
        extra=f' <span>{_esc(risk).upper()}{ai_suffix("risk")}</span>',
    )

    badges = ""
    if on("identity_badges"):
        badges = (
            '<div class="badges">'
            f'<b><span class="cat">Status</span><span class="val">{_esc(item.get("verification_status", ""))}</span></b>'
            f'<b><span class="cat">Tool confidence</span><span class="val">{_esc(item.get("confidence", ""))}</span></b>'
            f'<b><span class="cat">Profiles</span><span class="val">{_esc(", ".join(item.get("profiles") or [item.get("profile", "")]))}</span></b>'
            f'<b><span class="cat">Tool</span><span class="val">{_esc(item.get("tool", ""))}</span></b>'
            "</div>"
        )

    identity_rows = ""
    if on("url"):
        identity_rows += _field("Affected URL", item.get("url"))
    if on("source"):
        identity_rows += _field("Source entry point(s)", ", ".join(item.get("source_entry_points") or []))
        identity_rows += _field("Source job(s)", ", ".join(item.get("source_job_ids") or []))
    if on("method"):
        identity_rows += _field("HTTP method", item.get("method"))
    if on("parameter"):
        identity_rows += _field("Parameter", item.get("parameter"))
    if on("description"):
        identity_rows += _field("Description" + ai_suffix("description"), item.get("description"))
    if on("technical_details"):
        identity_rows += _field("Why the evidence confirms or suggests the issue", item.get("technical_details"))
    if on("attack_preconditions"):
        identity_rows += _field("Attack preconditions", item.get("attack_preconditions"))
    identity_block = f"<dl>{identity_rows}</dl>" if identity_rows else ""

    payload_block = _capped_snippet("Payload / test input", item.get("payload") or "; ".join(item.get("payloads") or []), snippet_cap) if on("payload") else ""
    evidence_block = _capped_snippet("Evidence", item.get("evidence"), snippet_cap) if on("evidence") else ""

    impact_rows = ""
    if on("impact"):
        impact_rows += _field("Security impact" + ai_suffix("impact"), item.get("impact"))
    if on("consequences"):
        impact_rows += _field("Potential consequences / damage" + ai_suffix("consequences"), item.get("consequences"))
    if on("recovery"):
        impact_rows += _field("Recovery / restoration actions" + ai_suffix("recovery"), item.get("recovery"))
    if on("solution"):
        impact_rows += _field("Recommended remediation" + ai_suffix("solution"), item.get("solution"))
    impact_block = f"<dl>{impact_rows}</dl>" if impact_rows else ""

    reproduction_block = _capped_snippet("Reproduction / validation steps", item.get("reproduction"), snippet_cap) if on("reproduction") else ""

    tail_rows = ""
    if on("owasp"):
        tail_rows += _field("OWASP classification", item.get("owasp_category"))
    tail_block = f"<dl>{tail_rows}</dl>" if tail_rows else ""

    identifiers_block = ""
    if on("identifiers") and item.get("identifiers"):
        identifiers_block = '<p class="field-label">Identifiers</p>' + _render_list(item.get("identifiers") or [])
    references_block = ""
    if on("references") and item.get("references"):
        references_block = '<p class="field-label">References</p>' + _render_list(item.get("references") or [])

    ai_block = ""
    if on("ai_assessment") and ai_analysis:
        ai_rows = (
            _field("AI assessment confidence", ai_analysis.get("analysis_confidence"))
            + _field("AI severity rationale", ai_analysis.get("rationale"))
            + _field("Assessment model", ai_analysis.get("model"))
        )
        if ai_rows:
            ai_block = f'<div class="quality"><b class="quality-title">Agentic risk assessment</b><dl>{ai_rows}</dl></div>'

    scanner_block = ""
    if on("scanner_original") and ai_analysis:
        original_risk = ai_analysis.get("scanner_risk") or item.get("scanner_risk") or "not supplied"
        scanner_rows = (
            _field("Original scanner severity", str(original_risk).upper())
            + _field("Original scanner confidence", ai_analysis.get("scanner_confidence") or item.get("scanner_confidence"))
        )
        scanner_block = f'<div class="scanner-original"><b class="quality-title">Original scanner assessment <span>(secondary audit)</span></b><dl>{scanner_rows}</dl></div>'

    notes_block = ""
    if on("data_quality_notes") and (item.get("data_quality_notes") or []):
        notes_block = '<div class="quality"><b>Data-quality notes</b>' + _render_list(item.get("data_quality_notes") or []) + "</div>"

    return (
        f'<article class="finding risk-{_esc(risk)}">'
        f"{heading}{badges}{identity_block}{payload_block}{evidence_block}"
        f"{impact_block}{reproduction_block}{tail_block}{identifiers_block}{references_block}"
        f"{ai_block}{scanner_block}{notes_block}"
        "</article>"
    )


# Renders all finding category sections with per-severity filtering applied.
def _render_reduced_findings(groups: dict[str, list[dict[str, Any]]], toc: list[tuple[int, str, str]]) -> str:
    from .constants import FINDING_SECTION_META

    counters: dict[str, int] = {}
    global_index = 1
    sections: list[str] = []
    for category in ("vulnerability", "candidate", "observation", "discovery"):
        items = groups.get(category, [])
        cards: list[str] = []
        listed_only = 0
        for item in items:
            index = global_index
            global_index += 1
            risk = str(item.get("risk") or "info").lower()
            flt = rf.severity_filter(risk)
            detail = str(flt.get("detail") or "essential")
            cap = flt.get("max_detailed")
            shown = counters.get(risk, 0)
            over_cap = cap is not None and shown >= cap
            if detail == "none" or over_cap:
                cards.append(_reduced_listed_row(item, index))
                listed_only += 1
                continue
            counters[risk] = shown + 1
            fields = rf.detail_fields(detail)
            if fields is None:  # "full" -> reuse the complete-report card
                cards.append(_finding_card(item, index, toc))
            else:
                cards.append(_reduced_finding_card(item, index, toc, fields, rf.snippet_cap(detail)))

        title, explanation = FINDING_SECTION_META[category]
        heading = _heading(
            2, title, toc, anchor=f"reduced-findings-{category}",
            extra=f' <span class="count">{len(items)}</span>',
        )
        note = f'<p class="section-note">{_esc(explanation)}</p>'
        if listed_only:
            note += (
                '<p class="section-note">'
                f"{listed_only} finding(s) in this category are listed in condensed one-line form "
                "(per the severity filter policy); none were dropped. See the full report for complete detail."
                "</p>"
            )
        body = "".join(cards) or "<p>No entries in this category.</p>"
        sections.append(f"<section>{heading}{note}{body}</section>")
    return "".join(sections)


# Short banner explaining the filtering policy used for this reduced report.
def _render_filter_policy_note() -> str:
    rows = "".join(
        "<tr>"
        f"<td class='no-wrap'>{_esc(sev.title())}</td>"
        f"<td>{_esc(rf.SEVERITY_FILTERS.get(sev, rf.DEFAULT_SEVERITY_FILTER).get('detail'))}</td>"
        f"<td>{_esc('unlimited' if rf.SEVERITY_FILTERS.get(sev, rf.DEFAULT_SEVERITY_FILTER).get('max_detailed') is None else rf.SEVERITY_FILTERS.get(sev, rf.DEFAULT_SEVERITY_FILTER).get('max_detailed'))}</td>"
        "</tr>"
        for sev in ("critical", "high", "medium", "low", "info")
    )
    return (
        '<section><h2 id="reduced-policy">Reduced-report filtering policy</h2>'
        '<p class="section-note">This is a condensed view of the full report. Every finding is '
        "retained, but the amount of detail shown per finding is trimmed by severity. Findings beyond "
        "a severity's detail limit, and severities with no detail, are still listed in condensed "
        "one-line form. AI-authored content remains marked with "
        f"<b>{_esc(AI_SUFFIX)}</b> and the dedicated \"Agentic risk assessment\" box. The complete, "
        "un-filtered report and the full normalized JSON remain available.</p>"
        "<table><thead><tr><th>Severity</th><th>Detail shown</th><th>Max detailed findings</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></section>"
    )


# Assembles the full reduced HTML document.
def render_reduced_html(payload: dict[str, Any]) -> str:
    sec = rf.REDUCED_REPORT_SECTIONS
    summary = payload["summary"]
    risks = summary["risk_counts"]
    context_value = _redact_value(payload.get("assessment_context") or {})

    if rf.REDUCED_REPORT_USE_ALL_FINDINGS:
        groups = _finding_groups(payload.get("all_findings") or payload["findings"])
    else:
        groups = _finding_groups(payload["findings"])

    overall_rating, overall_color, overall_explanation = _overall_risk_rating(payload["findings"])

    toc: list[tuple[int, str, str]] = []

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

    cover_html = ""
    if sec.get("cover", True):
        cover_html = _render_cover(
            payload, context_value, assessment_type=assessment_type, client_display=client_display,
            assessment_dates=assessment_dates, generated_display=generated_display,
            overall_rating=overall_rating, overall_color=overall_color,
        )
    doc_control_html = _render_document_control(payload, generated_display) if sec.get("document_control", True) else ""
    disclaimer_html = _render_disclaimer(client_display, assessment_dates) if sec.get("disclaimer", True) else ""

    parts: list[str] = [_render_filter_policy_note()]
    if sec.get("executive_summary", True):
        parts.append(_render_executive_summary(payload, summary, toc))
    if sec.get("severity_legend", True):
        parts.append(_render_severity_legend(toc, context_value))
    if sec.get("overall_risk_banner", True):
        parts.append(_render_overall_risk_banner(overall_rating, overall_color, overall_explanation, toc))
    if sec.get("priority_actions", True):
        parts.append(_render_priority_actions(payload["findings"], toc))
    if sec.get("glance", True):
        parts.append(_render_glance(payload["findings"], toc))
    if sec.get("scope", False):
        parts.append(_render_scope_section(context_value, toc, for_pdf=True))
    if sec.get("methodology", False):
        parts.append(_render_methodology(toc))
    if sec.get("qualifications", False):
        parts.append(_render_qualifications(toc))
    if sec.get("visualizations", True):
        parts.append(_render_visualizations(context_value, risks, toc))
    if sec.get("agentic_audit", False):
        parts.append(_render_agentic_audit(context_value, toc))
    if sec.get("execution", True):
        parts.append(_render_execution(payload["coverage"], toc))
    if sec.get("endpoint_coverage", False):
        parts.append(_render_endpoint_coverage(payload.get("endpoint_coverage") or [], toc, for_pdf=True))
    if sec.get("limitations", True):
        parts.append(_render_limitations(summary, toc))
    if sec.get("constraints", True):
        parts.append(_render_constraints(summary, toc))
    if sec.get("chaining_potential", True):
        parts.append(_render_chaining_potential(payload["findings"], toc))
    if sec.get("findings", True):
        parts.append(_render_reduced_findings(groups, toc))
    if sec.get("cleanup", False):
        parts.append(_render_cleanup(payload["findings"], toc))
    if sec.get("conclusion", True):
        parts.append(_render_conclusion(summary, payload["findings"], toc))

    body_html = "\n".join(parts)
    toc_html = _render_toc(toc) if sec.get("toc", True) else ""
    toc_block = (
        f'<div class="toc"><h2 class="toc-title" id="index">Index</h2>{toc_html}</div>'
        if sec.get("toc", True) else ""
    )

    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>SecOps Assessment Report (Reduced)</title>"
        f"<style>{report_css()}</style></head><body><main>"
        f"{cover_html}{doc_control_html}{disclaimer_html}{toc_block}{body_html}"
        "</main></body></html>"
    )
