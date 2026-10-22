"""Renders the *summary* report: a compact document listing every test/attack
that was executed, plus the critical issues that were detected.

It is intentionally short — a quick triage sheet, not a full report. The set of
severities treated as "critical", the categories listed and the item cap are
all configured in ``report_filters``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from . import report_filters as rf
from .constants import AI_SUFFIX
from .coverage import _render_execution
from .findings import _finding_groups
from .sections import _overall_risk_rating
from .style import report_css
from .text_utils import _esc, _format_date_en, _redact_text, _redact_value
from .toc import _heading, _render_toc


# One-line "what it is" blurb for a critical item, AI-marked when AI-authored.
def _blurb(item: dict[str, Any]) -> str:
    ai_analysis = item.get("ai_analysis") if isinstance(item.get("ai_analysis"), dict) else {}
    narrative_fallbacks = set(ai_analysis.get("narrative_fallbacks") or []) if ai_analysis else set()
    text = _redact_text(item.get("description") or item.get("technical_details") or "").strip()
    if not text:
        return ""
    cap = rf.SUMMARY_BLURB_MAX_CHARS
    if cap and len(text) > cap:
        text = text[:cap].rstrip() + "…"
    suffix = f" {AI_SUFFIX}" if ai_analysis and "description" not in narrative_fallbacks else ""
    return f"{_esc(text)}{_esc(suffix)}"


# Compact header block (no full cover page) with identity and risk counts.
def _render_header(payload: dict[str, Any], generated_display: str, overall_rating: str, overall_color: str) -> str:
    summary = payload["summary"]
    risks = summary.get("risk_counts", {})
    client_display = payload.get("client_name") or payload["target"]
    cards = "".join(
        f'<div class="card"><div class="value">{int(risks.get(risk, 0) or 0)}</div><div>{risk.title()}</div></div>'
        for risk in ("critical", "high", "medium", "low", "info")
    )
    return (
        '<section class="cover" style="min-height:auto;padding:28px">'
        '<div class="cover-badges">'
        f'<div class="cover-risk-badge" style="background:{overall_color}">Overall risk: {_esc(overall_rating)}</div>'
        "</div>"
        '<div class="cover-body" style="margin-top:0">'
        '<div class="cover-kicker">Security Assessment — Executive Summary Sheet</div>'
        '<h1 class="cover-title" style="font-size:2rem">Tests performed &amp; critical findings</h1>'
        f'<div class="cover-subtitle">{_esc(client_display)}</div>'
        f'<p><small>Report issue date: {generated_display} · '
        f'Report ID: {_esc(payload.get("report_id") or "n/a")}</small></p>'
        "</div>"
        f'<div class="grid">{cards}</div>'
        "</section>"
    )


# Table of the critical issues detected (critical/high confirmed & candidate findings).
def _render_critical_issues(payload: dict[str, Any], toc: list[tuple[int, str, str]]) -> str:
    groups = _finding_groups(payload.get("all_findings") or payload["findings"])
    wanted_sev = {s.lower() for s in rf.SUMMARY_CRITICAL_SEVERITIES}
    wanted_cat = set(rf.SUMMARY_INCLUDE_CATEGORIES)
    items = [
        item
        for cat in ("vulnerability", "candidate", "observation", "discovery")
        if cat in wanted_cat
        for item in groups.get(cat, [])
        if str(item.get("risk") or "info").lower() in wanted_sev
    ]
    heading = _heading(2, "Critical issues detected", toc, anchor="summary-critical")
    sev_label = ", ".join(s.title() for s in rf.SUMMARY_CRITICAL_SEVERITIES)
    if not items:
        return (
            f"{heading}"
            f'<p class="section-note">No {sev_label} findings were recorded in the included categories.</p>'
        )
    cap = rf.SUMMARY_MAX_CRITICAL_ITEMS
    omitted = 0
    if cap is not None and len(items) > cap:
        omitted = len(items) - cap
        items = items[:cap]
    rows = "".join(
        "<tr>"
        f'<td class="idx">{index}</td>'
        f'<td class="no-wrap">{_esc(str(item.get("risk", "info")).upper())}</td>'
        f'<td><b>{_esc(item.get("alert", "Unnamed finding"))}</b>'
        f'{("<br><small>" + _blurb(item) + "</small>") if _blurb(item) else ""}</td>'
        f'<td>{_esc(item.get("tool", ""))}</td>'
        f'<td>{_esc(item.get("url", ""))}'
        f'{("<br><small>parameter: " + _esc(item.get("parameter")) + "</small>") if item.get("parameter") else ""}</td>'
        "</tr>"
        for index, item in enumerate(items, 1)
    )
    note = (
        f'<p class="section-note">{sev_label} confirmed vulnerabilities and candidates requiring '
        f"manual validation. Items marked <b>{_esc(AI_SUFFIX)}</b> carry an AI-authored description.</p>"
    )
    if omitted:
        note += f'<p class="section-note">{omitted} further item(s) omitted from this summary; see the full or reduced report.</p>'
    return (
        f"{heading}{note}"
        '<table><colgroup><col style="width:3%"><col style="width:10%"><col style="width:45%"><col style="width:14%"><col style="width:28%"></colgroup>'
        "<thead><tr><th>#</th><th>Severity</th><th>Finding &amp; description</th><th>Tool</th><th>Affected endpoint</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


# Assembles the full summary HTML document.
def render_summary_html(payload: dict[str, Any]) -> str:
    _ = _redact_value(payload.get("assessment_context") or {})  # ensure redaction parity
    overall_rating, overall_color, _overall_explanation = _overall_risk_rating(payload["findings"])

    generated_at = payload.get("generated_at")
    generated_display = _format_date_en(generated_at) if isinstance(generated_at, datetime) else _esc(generated_at)

    toc: list[tuple[int, str, str]] = []
    header_html = _render_header(payload, generated_display, overall_rating, overall_color)

    body_parts = [
        _render_execution(payload["coverage"], toc),
        _render_critical_issues(payload, toc),
    ]
    body_html = "\n".join(body_parts)
    toc_html = _render_toc(toc)

    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>SecOps Assessment — Summary</title>"
        f"<style>{report_css()}</style></head><body><main>"
        f"{header_html}"
        f'<div class="toc"><h2 class="toc-title" id="index">Index</h2>{toc_html}</div>'
        f"{body_html}"
        "</main></body></html>"
    )
