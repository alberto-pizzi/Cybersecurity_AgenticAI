"""Per-finding card rendering, the category sections built from them
(vulnerability/candidate/observation/discovery), and the findings-at-a-glance
summary table.
"""

from __future__ import annotations

from typing import Any

from .constants import FINDING_SECTION_META
from .fields import _field, _render_list, _snippet_field
from .text_utils import _esc
from .toc import _heading

# Renders a single finding as its full <article> card (fields, snippets, references)
def _finding_card(item: dict[str, Any], index: int, toc: list[tuple[int, str, str]]) -> str:
    notes = item.get("data_quality_notes") or []
    heading = _heading(
        3, f"{index}. {item['alert']}", toc,
        in_toc=False,  # one h3 per finding: too many to list in the index (LaTeX \subsection* equivalent)
        anchor=f"finding-{index}",
        extra=f' <span>{_esc(item["risk"]).upper()}</span>',
    )
    ai_analysis = item.get("ai_analysis") if isinstance(item.get("ai_analysis"), dict) else {}
    ai_block = ""
    scanner_block = ""
    if ai_analysis:
        # Only the AI's own output belongs under "Agentic risk assessment";
        # the scanner's original values are audit reference data, not an AI
        # finding, so they get their own separate box below.
        ai_rows = (
            _field('AI assessment confidence', ai_analysis.get('analysis_confidence'))
            + _field('AI severity rationale', ai_analysis.get('rationale'))
            + _field('Assessment model', ai_analysis.get('model'))
        )
        ai_block = f'<div class="quality"><b class="quality-title">Agentic risk assessment</b><dl>{ai_rows}</dl></div>'

        original_risk = ai_analysis.get("scanner_risk") or item.get("scanner_risk") or "not supplied"
        scanner_rows = (
            _field('Original scanner severity', str(original_risk).upper())
            + _field('Original scanner confidence', ai_analysis.get('scanner_confidence') or item.get('scanner_confidence'))
        )
        if item.get('scanner_description') and item.get('scanner_description') != item.get('description'):
            scanner_rows += _field('Scanner description', item.get('scanner_description'))
        if item.get('scanner_impact') and item.get('scanner_impact') != item.get('impact'):
            scanner_rows += _field('Scanner security impact', item.get('scanner_impact'))
        if item.get('scanner_solution') and item.get('scanner_solution') != item.get('solution'):
            scanner_rows += _field('Scanner recommended remediation', item.get('scanner_solution'))
        scanner_block = f'<div class="scanner-original"><b class="quality-title">Original scanner assessment <span>(secondary audit)</span></b><dl>{scanner_rows}</dl></div>'
    return f"""
<article class="finding risk-{_esc(item['risk'])}">
{heading}
<div class="badges">
<b><span class="cat">Status</span><span class="val">{_esc(item['verification_status'])}</span></b>
<b><span class="cat">Tool Confidence</span><span class="val">{_esc(item['confidence'])}</span></b>
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
</dl>
{_snippet_field('Payload / test input', item.get('payload') or '; '.join(item.get('payloads') or []))}
{_snippet_field('Evidence', item.get('evidence'))}
<dl>
{_field('Security impact', item.get('impact'))}
{_field('Recommended remediation', item.get('solution'))}
</dl>
{_snippet_field('Reproduction / validation steps', item.get('reproduction'))}
<dl>
{_field('OWASP classification', item.get('owasp_category'))}
</dl>
{('<p class="field-label">Identifiers</p>' + _render_list(item.get('identifiers') or [])) if item.get('identifiers') else ''}
{('<p class="field-label">References</p>' + _render_list(item.get('references') or [])) if item.get('references') else ''}
{ai_block}
{scanner_block}
{('<div class="quality"><b>Data-quality notes</b>' + _render_list(notes) + '</div>') if notes else ''}
</article>"""

# Renders the four finding-category sections in order, with globally numbered cards
def _render_findings(groups: dict[str, list[dict[str, Any]]], toc: list[tuple[int, str, str]]) -> str:
    global_index = 1
    sections: list[str] = []
    for category in ("vulnerability", "candidate", "observation", "discovery"):
        items = groups[category]
        cards = "".join(
            _finding_card(item, index, toc)
            for index, item in enumerate(items, start=global_index)
        )
        global_index += len(items)
        title, explanation = FINDING_SECTION_META[category]
        heading = _heading(
            2, title, toc,
            anchor=f"findings-{category}",
            extra=f' <span class="count">{len(items)}</span>',
        )
        body = cards or "<p>No entries in this category.</p>"
        sections.append(f'<section>{heading}<p class="section-note">{_esc(explanation)}</p>{body}</section>')
    return "".join(sections)

# Renders the "Security findings at a glance" summary table
def _render_glance(findings: list[dict[str, Any]], toc: list[tuple[int, str, str]]) -> str:
    glance_items = [
        item for item in findings
        if item.get("category") in {"vulnerability", "candidate"}
    ]
    heading = _heading(2, "Security findings at a glance", toc, anchor="glance")
    if not glance_items:
        return f"{heading}<p>No confirmed vulnerabilities or validation candidates were recorded.</p>"
    rows = "".join(
        "<tr>"
        f'<td class="idx">{index}</td><td class="no-wrap">{_esc(item.get('risk','info')).upper()}</td>'
        f"<td><b>{_esc(item.get('alert','Unnamed finding'))}</b></td>"
        f"<td>{_esc(item.get('tool',''))}</td>"
        f"<td>{_esc(item.get('url',''))}<br><small>parameter: {_esc(item.get('parameter') or '-')}</small></td>"
        "</tr>"
        for index, item in enumerate(glance_items, 1)
    )
    return (
        f"{heading}"
        "<p class='section-note'>Confirmed vulnerabilities and candidates are named here before execution details.</p>"
        "<table><thead><tr><th class=\"idx\">#</th><th>Severity</th><th>Finding</th><th>Tool</th><th>Affected endpoint</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )
