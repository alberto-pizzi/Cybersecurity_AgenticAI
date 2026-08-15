"""Narrative report-section builders: front matter (document control,
disclaimer, severity legend, methodology, qualifications), the assessment
context summary, and the closing chaining-potential / cleanup / conclusion
sections.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from .charts import _render_pipeline_diagram, _svg_severity_chart
from .constants import AUTHORS, CLIENT_NAME, METHODOLOGY_PHASES, REPORT_CLASSIFICATION, REPORT_TITLE, REPORT_VERSION, SEVERITY_DEFINITIONS, TOOL_PURPOSES
from .fields import _render_list
from .findings import _finding_family
from .text_utils import _esc
from .toc import _heading

# Renders a schematic summary of the assessment context (run config, limits, discovery)
def _context_summary_html(context: dict[str, Any], toc: list[tuple[int, str, str]]) -> str:
    if not isinstance(context, dict) or not context:
        return "<p>No assessment context was supplied.</p>"

    # Renders a list of label/value pairs as a <dl>
    def dl(rows: list[tuple[str, str]]) -> str:
        return "<dl>" + "".join(f"<dt>{_esc(l)}</dt><dd>{v}</dd>" for l, v in rows) + "</dl>"

    parts: list[str] = []

    # Run configuration
    run_rows: list[tuple[str, str]] = []
    if context.get("scan_mode"):
        run_rows.append(("Scan mode", _esc(context["scan_mode"])))
    orchestration = context.get("orchestration") if isinstance(context.get("orchestration"), dict) else {}
    if orchestration.get("engine"):
        run_rows.append(("Orchestration engine", _esc(orchestration["engine"])))
    if orchestration.get("mode"):
        run_rows.append(("Orchestration mode", _esc(orchestration["mode"])))
    if orchestration.get("nodes"):
        run_rows.append(("Pipeline phases", _esc(" -> ".join(str(n) for n in orchestration["nodes"]))))
    if context.get("secondary_identity_supplied") is not None:
        run_rows.append((
            "Secondary identity supplied",
            "Yes" if context["secondary_identity_supplied"]
            else "No - authorization/BOLA differentials could not be tested",
        ))
    if context.get("expected_tools"):
        run_rows.append(("Expected tools", _esc(", ".join(str(t) for t in context["expected_tools"]))))
    if run_rows:
        parts.append(_heading(3, "Run configuration", toc) + dl(run_rows))

    # Configured limits and timeouts
    limit_rows: list[tuple[str, str]] = []
    if context.get("parameter_endpoint_limit") is not None:
        limit_rows.append(("Endpoints tested per parameter-driven tool", _esc(context["parameter_endpoint_limit"])))
    if context.get("arjun_endpoint_limit") is not None:
        limit_rows.append(("Endpoints tested for hidden-parameter discovery (Arjun)", _esc(context["arjun_endpoint_limit"])))
    for key, label in (
        ("broad_scanner_timeouts", "Broad-scanner timeouts"),
        ("parameter_tool_timeouts", "Parameter-driven tool timeouts"),
    ):
        timeouts = context.get(key)
        if isinstance(timeouts, dict) and timeouts:
            limit_rows.append((label, _esc(", ".join(f"{tool}: {seconds}s" for tool, seconds in timeouts.items()))))
    if limit_rows:
        parts.append(_heading(3, "Configured limits", toc) + dl(limit_rows))

    # Per-profile discovery summary
    profiles_meta = {
        str(row.get("name")): row
        for row in (context.get("profiles") or [])
        if isinstance(row, dict) and row.get("name")
    }
    discovery = context.get("discovery") if isinstance(context.get("discovery"), dict) else {}
    profile_cards: list[str] = []
    for profile_name, data in discovery.items():
        if not isinstance(data, dict):
            continue
        meta = profiles_meta.get(profile_name, {})
        auth_label = "authenticated" if meta.get("authenticated") else "anonymous"
        rows: list[tuple[str, str]] = [("Profile", f"{_esc(profile_name)} ({auth_label})")]

        auth_effective = data.get("authentication_effective")
        if auth_effective is not None:
            rows.append((
                "Authentication verified",
                "Yes - distinguished from the anonymous response" if auth_effective
                else "No - could not be confirmed",
            ))
        prep = data.get("target_preparation") if isinstance(data.get("target_preparation"), dict) else {}
        if prep:
            status = "performed and usable" if prep.get("usable") else ("performed" if prep.get("performed") else "not required")
            rows.append(("Target preparation", _esc(status)))

        counts = [
            f"{label}: {len(data[key])}"
            for key, label in (
                ("urls", "URLs discovered"),
                ("html_urls", "HTML pages"),
                ("form_urls", "Forms"),
                ("parameterized_urls", "Parameterized endpoints"),
                ("request_cases", "Normalized request cases"),
                ("client_side_candidates", "Client-side sink candidates"),
                ("jwt_tokens", "JWTs discovered"),
                ("errors", "Discovery errors"),
            )
            if isinstance(data.get(key), list)
        ]
        if counts:
            rows.append(("Discovered surface", _esc(" | ".join(counts))))

        skipped = data.get("destructive_urls_skipped")
        if isinstance(skipped, list) and skipped:
            rows.append((
                f"Destructive URLs deliberately skipped ({len(skipped)})",
                _render_list([str(u) for u in skipped]),
            ))

        profile_cards.append(f'<div class="card">{dl(rows)}</div>')

    if profile_cards:
        parts.append(_heading(3, "Discovery summary", toc) + "".join(profile_cards))

    return "".join(parts) or "<p>No assessment context was supplied.</p>"


def _render_document_control(payload: dict[str, Any], generated_display: str) -> str:
    """Renders the "Document control" front-matter section (report identity/versioning)."""
    rows: list[tuple[str, str]] = [
        ("Document reference", _esc(payload.get("report_id") or "n/a")),
        ("Engagement report version", _esc(payload.get("report_version") or "n/a")),
        ("Report template version", _esc(REPORT_VERSION)),
        ("Classification", _esc(REPORT_CLASSIFICATION)),
        ("Prepared by", _esc(payload.get("assessor") or "SecOps Automated Assessment Platform")),
        ("Platform authors", _esc(", ".join(AUTHORS))),
        ("Client / distribution", _esc(payload.get("client_name") or CLIENT_NAME)),
        ("Date issued", generated_display),
    ]
    return (
        '<section class="doc-control">'
        "<h2>Document control</h2>"
        "<dl>" + "".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in rows) + "</dl>"
        "</section>"
    )


def _render_priority_actions(findings: list[dict[str, Any]], toc: list[tuple[int, str, str]]) -> str:
    """Renders a priority-ordered shortlist of findings that carry remediation guidance."""
    seen: set[tuple[str, str]] = set()
    items: list[str] = []
    for item in findings:
        if item.get("category") not in {"vulnerability", "candidate"} or not item.get("solution"):
            continue
        key = (str(item.get("solution")), str(item.get("canonical_url") or item.get("url") or ""))
        if key in seen:
            continue
        seen.add(key)
        target = f" — {_esc(item['url'])}" if item.get("url") else ""
        items.append(
            f"<li><b>[{_esc(item['risk']).upper()}] {_esc(item['alert'])}</b>{target}"
            f"<br>{_esc(item['solution'])}</li>"
        )
        # TODO this limit is ok?
        if len(items) >= 10:
            break
    if not items:
        return ""
    heading = _heading(2, "Priority remediation actions", toc, anchor="priority-actions")
    return (
        f"{heading}"
        '<p class="section-note">Drawn directly from the confirmed vulnerabilities and candidates below that carry '
        "scanner-supplied remediation guidance, in the same priority order as the detailed findings sections. This "
        "shortlist does not replace the full findings detail.</p>"
        f"<ol>{''.join(items)}</ol>"
    )


def _render_disclaimer(client_display: str, assessment_dates: str) -> str:
    """Renders the confidentiality/legal-disclaimer front-matter section."""
    return (
        '<section class="disclaimer">'
        "<h2>Confidentiality and disclaimer</h2>"
        f"<p>This report is classified <b>{_esc(REPORT_CLASSIFICATION)}</b> and is provided solely for the use of "
        f"{_esc(CLIENT_NAME)} in evaluating the security of {_esc(client_display)}. It contains details of security "
        "vulnerabilities and must not be distributed, copied or disclosed to any party not explicitly authorized by "
        "the recipient.</p>"
        f"<p>Testing was performed during {_esc(assessment_dates)} against the scope and identities described in this "
        "report. This document reflects the security posture of the target as observed at that time; systems, code "
        "and configuration can change afterward, and no assessment - automated or manual - can guarantee the absence "
        "of vulnerabilities outside the scope, techniques and time actually exercised.</p>"
        "<p>Findings are grounded in evidence produced by the tools used during this engagement; where evidence was "
        "insufficient to confirm exploitability, the finding is reported as a candidate or observation rather than a "
        "confirmed vulnerability (see “Methodology” and “Risk rating methodology”). This report "
        "does not constitute legal advice, a compliance certification, or a warranty of fitness for any particular "
        "purpose.</p>"
        "</section>"
    )


# Renders the "Risk rating methodology" severity-definitions table
def _render_severity_legend(toc: list[tuple[int, str, str]]) -> str:
    heading = _heading(2, "Risk rating methodology", toc, anchor="risk-rating")
    rows = "".join(
        f'<tr><td><span class="rating-chip"><span class="legend-swatch" style="background:{color}"></span>'
        f"<b>{_esc(name)}</b></span></td>"
        f"<td>{_esc(desc)}</td></tr>"
        for name, color, desc in SEVERITY_DEFINITIONS
    )
    return (
        f"{heading}"
        '<p class="section-note">Severity is the risk rating supplied by the originating scanner for each finding, '
        "escalated to a confirmed vulnerability only when the tool-specific evidence rule described in "
        "“Methodology” is satisfied. The definitions below describe what each rating means for "
        "prioritization; they are not recalculated per finding.</p>"
        '<table class="rating-table"><colgroup><col class="rating-col"><col></colgroup>'
        f"<thead><tr><th>Rating</th><th>Definition and expected remediation priority</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _render_methodology(toc: list[tuple[int, str, str]]) -> str:
    """Renders the "Methodology" section listing the assessment's staged phases."""
    heading = _heading(2, "Methodology", toc, anchor="methodology")
    phase_items = "".join(
        f"<li><b>{_esc(name)}</b> — {_esc(desc)}</li>" for name, desc in METHODOLOGY_PHASES
    )
    return (
        f"{heading}"
        '<p class="section-note">This assessment followed a staged methodology consistent with industry practice for '
        "web-application penetration testing (comparable in intent to the OWASP Testing Guide and PTES). Each stage "
        "is described below; the tools used in each stage and their individual results are recorded in "
        "“Assessment execution”.</p>"
        f"<ol>{phase_items}</ol>"
    )

# Renders the closing "Conclusion and recommendations" section
def _render_conclusion(summary: dict[str, Any], findings: list[dict[str, Any]], toc: list[tuple[int, str, str]]) -> str:
    risks = summary.get("risk_counts", {})
    confirmed = sum(item["category"] == "vulnerability" for item in findings)
    candidates = sum(item["category"] == "candidate" for item in findings)
    if risks.get("critical") or risks.get("high"):
        posture = (
            "at least one Critical or High severity finding was confirmed. This should be treated as the immediate "
            "remediation priority before the affected functionality is exposed to untrusted users."
        )
    elif confirmed or candidates:
        posture = (
            "no Critical or High severity finding was confirmed, but Medium/Low findings and candidates requiring "
            "manual validation remain and should be tracked to closure."
        )
    else:
        posture = (
            "no confirmed vulnerability was identified within the tested scope and constraints described in this "
            "report; this reflects the scope actually exercised, not a guarantee of overall security."
        )
    next_steps = [
        "Remediate confirmed vulnerabilities in order of severity, validating each fix against the reproduction steps recorded in this report.",
        "Manually review every candidate finding and coverage constraint listed above; automated tooling could not confirm or rule these out on its own.",
        "Re-run this assessment, or the specific affected checks, after remediation to confirm closure before a fix is considered complete.",
    ]
    if summary.get("coverage_constraints"):
        next_steps.insert(
            1,
            "Address the coverage constraints above (for example by supplying a second authenticated identity) so the classes they describe can be tested directly.",
        )
    heading = _heading(2, "Conclusion and recommendations", toc, anchor="conclusion")
    return (
        f"{heading}"
        f'<div class="card">Based on the findings in this report, {_esc(posture)}</div>'
        '<p class="field-label">Recommended next steps</p>'
        f"<ol>{''.join(f'<li>{_esc(step)}</li>' for step in next_steps)}</ol>"
    )

# Derives the single top-line risk verdict from confirmed vulnerabilities and candidates
def _overall_risk_rating(findings: list[dict[str, Any]]) -> tuple[str, str, str]:
    confirmed = Counter(item["risk"] for item in findings if item.get("category") == "vulnerability")
    candidates = Counter(item["risk"] for item in findings if item.get("category") == "candidate")
    if confirmed.get("critical"):
        return ("CRITICAL", "#7a0000", "At least one confirmed critical-severity vulnerability was found within the tested scope.")
    if confirmed.get("high"):
        return ("HIGH", "#a90000", "At least one confirmed high-severity vulnerability was found within the tested scope.")
    if confirmed.get("medium") or candidates.get("critical") or candidates.get("high"):
        return ("MEDIUM", "#d98200", "Confirmed medium-severity findings and/or high-impact candidates requiring manual validation were found.")
    if confirmed.get("low") or candidates:
        return ("LOW", "#b49b00", "Only low-severity confirmed findings and/or lower-impact candidates requiring manual validation were found.")
    return ("INFORMATIONAL", "#4b86b4", "No confirmed vulnerability or candidate requiring manual validation was found within the tested scope and constraints described in this report.")

# Renders the top-line overall-risk-rating banner
def _render_overall_risk_banner(rating: str, color: str, explanation: str, toc: list[tuple[int, str, str]]) -> str:
    heading = _heading(2, "Overall risk rating", toc, anchor="overall-risk")
    return (
        f"{heading}"
        f'<div class="risk-banner" style="border-left-color:{color}">'
        f'<span class="risk-banner-label" style="background:{color}">{_esc(rating)}</span>'
        f'<div class="risk-banner-text">{_esc(explanation)}</div>'
        "</div>"
    )

# Renders the "Assessment visualizations" section (pipeline diagram + severity chart)
def _render_visualizations(context_value: dict[str, Any], risks: dict[str, int], toc: list[tuple[int, str, str]]) -> str:
    orchestration = context_value.get("orchestration") if isinstance(context_value, dict) else {}
    nodes = orchestration.get("nodes") if isinstance(orchestration, dict) else None
    pipeline_html = _render_pipeline_diagram(nodes if isinstance(nodes, list) else [])
    heading = _heading(2, "Assessment visualizations", toc, anchor="visualizations")
    parts = [heading]
    if pipeline_html:
        parts.append(
            '<p class="field-label">Assessment pipeline (phases actually executed, in order)</p>' + pipeline_html
        )
    parts.append('<p class="field-label">Findings by severity</p>')
    parts.append(f'<div class="card">{_svg_severity_chart(risks)}</div>')
    return "".join(parts)

# Flags hosts carrying more than one distinct finding as manual exploitation-chaining candidates
def _render_chaining_potential(findings: list[dict[str, Any]], toc: list[tuple[int, str, str]]) -> str:
    by_host: dict[str, list[dict[str, Any]]] = {}
    for item in findings:
        if item.get("category") not in {"vulnerability", "candidate"}:
            continue
        url = str(item.get("canonical_url") or item.get("url") or "").strip()
        if not url:
            continue
        host = urlparse(url).netloc or url
        by_host.setdefault(host, []).append(item)

    concentrations = {
        host: items for host, items in by_host.items()
        if len({_finding_family(item) for item in items}) > 1
    }
    heading = _heading(2, "Exploitation chaining potential", toc, anchor="chaining")
    intro = (
        '<p class="section-note">This automated platform confirms each finding independently and does not attempt '
        "to chain vulnerabilities together (for example, using an injection flaw to reach an administrative "
        "interface). Hosts below carry more than one distinct confirmed or candidate finding, which is the "
        "real-world precondition for a human attacker to combine them into a multi-step compromise. Listing a host "
        "here is not a claim that any chain was demonstrated or that one exists.</p>"
    )
    if not concentrations:
        return f"{heading}{intro}<p>No host in this report carries more than one distinct confirmed or candidate finding.</p>"
    items_html = "".join(
        f"<li><b>{_esc(host)}</b> — {len(items)} finding(s) across distinct issue types: "
        f"{_esc(', '.join(sorted({_finding_family(item) for item in items})))}.</li>"
        for host, items in sorted(concentrations.items(), key=lambda kv: -len(kv[1]))
    )
    return f"{heading}{intro}<ul>{items_html}</ul>"

# Returns a cleanup instruction for a finding that left a probe artifact, or None
def _artifact_cleanup_hint(row: dict[str, Any]) -> str | None:
    verification = str(row.get("verification_status") or "").lower()
    alert = str(row.get("alert") or "").lower()
    if "upload-accepted" in verification or "file upload" in alert:
        return (
            "Locate and remove the harmless probe file the platform uploaded (filenames are prefixed "
            "“secops_probe_” and contain a SECOPS_UPLOAD_ marker string) and confirm the upload handler "
            "no longer serves it."
        )
    if "stored" in verification or "stored xss" in alert:
        return (
            "Locate and remove the stored payload (a SECOPS_XSS_-prefixed marker) that the platform's stored-XSS "
            "check left in application data."
        )
    if "command execution" in alert or "command injection" in alert:
        return (
            "Review command history/logs for the SECOPS_CMD_-prefixed canary strings used to confirm this finding; "
            "the platform issued no destructive commands."
        )
    return None

# Renders the "Post-assessment cleanup" section listing artifacts to remove
def _render_cleanup(findings: list[dict[str, Any]], toc: list[tuple[int, str, str]]) -> str:
    heading = _heading(2, "Post-assessment cleanup", toc, anchor="cleanup")
    intro = (
        '<p class="section-note">Every active probe used by this platform is tagged with an identifiable '
        '“SECOPS_” prefix - uploaded filenames such as <code>secops_probe_&lt;hex&gt;.html</code>, stored '
        'markers such as <code>SECOPS_XSS_...</code>, command-injection canaries such as <code>SECOPS_CMD_...</code>, '
        'and throttling-check usernames such as <code>secops_invalid_...</code> - so they can be found and removed. '
        "No destructive actions, persistent backdoors, or new privileged accounts were created by this "
        "assessment.</p>"
    )
    artifacts = [
        (item, hint)
        for item in findings
        if item.get("category") in {"vulnerability", "candidate"}
        for hint in [_artifact_cleanup_hint(item)]
        if hint
    ]
    if not artifacts:
        return (
            f"{heading}{intro}"
            "<p>No finding in this report indicates a persisted server-side artifact (such as an accepted upload or "
            'a stored payload). As a precaution, search server logs and storage for the "SECOPS_" prefix before '
            "closing out this engagement.</p>"
        )
    items_html = "".join(
        f"<li><b>{_esc(item['alert'])}</b>{' — ' + _esc(item['url']) if item.get('url') else ''}<br>{_esc(hint)}</li>"
        for item, hint in artifacts
    )
    return f"{heading}{intro}<ol>{items_html}</ol>"

# Renders the "Assessor and platform qualifications" section
def _render_qualifications(toc: list[tuple[int, str, str]]) -> str:
    heading = _heading(2, "Assessor and platform qualifications", toc, anchor="qualifications")
    tool_list = ", ".join(sorted(TOOL_PURPOSES))
    return (
        f"{heading}"
        "<p>This assessment was produced by an automated platform rather than performed manually end-to-end by a "
        "certified individual tester. Industry guidance on tester qualifications - certifications (for example "
        "OSCP, GWAPT, CREST), organizational independence from the tested environment, and documented past "
        "experience - is written for human testers and does not map directly onto automated tooling; no such "
        "credentials are claimed here on behalf of the platform or its authors.</p>"
        "<p>The platform's authority instead rests on three verifiable properties of this report: the use of "
        f"actively maintained, industry-standard scanners ({_esc(tool_list)}), each restricted to the documented "
        "purpose listed in “Assessment execution”; deterministic, tool-specific evidence rules applied "
        "before any finding is escalated to a confirmed vulnerability (see “Risk rating "
        "methodology”); and explicit disclosure, rather than omission, of what the automated run could not "
        "verify (see “Coverage constraints and untested classes”).</p>"
        f"<p>The platform is developed and maintained by {_esc(', '.join(AUTHORS))}.</p>"
        "<p>Findings marked as candidates, and every coverage constraint listed in this report, require review by a "
        "qualified human penetration tester before being treated as conclusive.</p>"
    )

# Renders the report's cover page (title, classification/risk badges, engagement meta)
def _render_cover(
    payload: dict[str, Any],
    *,
    assessment_type: str,
    client_display: str,
    assessment_dates: str,
    generated_display: str,
    overall_rating: str,
    overall_color: str,
) -> str:
    assessor_display = payload.get("assessor") or "SecOps Automated Assessment Platform"
    report_version = payload.get("report_version") or "n/a"
    report_id = payload.get("report_id") or "n/a"
    cover_rows: list[tuple[str, str]] = [
        ("Client", _esc(CLIENT_NAME)),
        ("Target", _esc(client_display)),
        ("Assessor / team", _esc(assessor_display)),
        ("Assessment date(s)", _esc(assessment_dates)),
        ("Report issue date", generated_display),
        ("Report version / ID", _esc(f"{report_version} / {report_id}")),
    ]
    # cover-badges is deliberately position:absolute (WeasyPrint flexbox align-self is unreliable).
    return (
        '<section class="cover">'
        '<div class="cover-badges">'
        f'<div class="cover-classification">{_esc(REPORT_CLASSIFICATION)}</div>'
        f'<div class="cover-risk-badge" style="background:{overall_color}">Overall risk: {_esc(overall_rating)}</div>'
        "</div>"
        '<div class="cover-body">'
        '<div class="cover-kicker">Security Assessment Report</div>'
        f'<h1 class="cover-title">{_esc(REPORT_TITLE)}</h1>'
        f'<div class="cover-subtitle">{_esc(assessment_type)}</div>'
        "</div>"
        '<table class="cover-meta">'
        + "".join(f"<tr><th>{_esc(label)}</th><td>{value}</td></tr>" for label, value in cover_rows)
        + "</table>"
        "</section>"
    )

# Renders the "Executive summary" section: narrative plus the risk-count stat grid
def _render_executive_summary(payload: dict[str, Any], summary: dict[str, Any], toc: list[tuple[int, str, str]]) -> str:
    risks = summary["risk_counts"]
    heading = _heading(2, "Executive summary", toc, anchor="executive")
    grid_cards = "".join(
        f'<div class="card"><div class="value">{risks.get(risk,0)}</div><div>{risk.title()}</div></div>'
        for risk in ("critical", "high", "medium", "low")
    )
    return (
        f'{heading}<div class="card">{_esc(payload["executive_summary"])}</div>'
        f'<div class="grid">{grid_cards}<div class="card">'
        f'<div class="value">{len(summary["limitations"])}</div><div>Execution limitations</div>'
        f'<div class="value">{len(summary.get("coverage_constraints", []))}</div><div>Coverage constraints</div>'
        "</div></div>"
    )

# Renders a note about omitted repetitive detail, or "" if nothing was omitted
def _render_detail_cap_note(omitted: dict[str, int]) -> str:
    if not any(omitted.values()):
        return ""
    return (
        '<p class="section-note">'
        f"Human-readable detail cap: {omitted.get('observation', 0)} repetitive observations "
        f"and {omitted.get('discovery', 0)} discovery entries were omitted from detailed pages. "
        "Aggregate counts remain in the executive summary and the complete normalized set remains in JSON."
        "</p>"
    )

# Renders the "Scope and assessment context" section, with a raw JSON dump outside PDF mode
def _render_scope_section(context_value: dict[str, Any], toc: list[tuple[int, str, str]], *, for_pdf: bool) -> str:
    heading = _heading(2, "Scope and assessment context", toc, anchor="scope")
    context_summary = _context_summary_html(context_value, toc)
    if for_pdf:
        json_block = ""
        pdf_note = (
            '<p class="section-note">The full technical context (discovered URLs, normalized request cases, '
            "client-side sink candidates) is available in the attached JSON report.</p>"
        )
    else:
        context_json = json.dumps(context_value, indent=2, ensure_ascii=False, default=str)
        json_block = f'<details><summary>Raw assessment context (JSON)</summary><pre>{_esc(context_json)}</pre></details>'
        pdf_note = ""
    return f"{heading}{context_summary}{json_block}{pdf_note}"

# Renders the "Agentic planning audit" section from planner-round data, or "" if none
def _render_agentic_audit(context_value: dict[str, Any], toc: list[tuple[int, str, str]]) -> str:
    planner_audit = context_value.get("planner_audit", []) if isinstance(context_value, dict) else []
    audit_rows = ""
    audit_details: list[str] = []
    for item in planner_audit if isinstance(planner_audit, list) else []:
        if not isinstance(item, dict):
            continue
        outcomes = item.get("execution_outcomes", []) if isinstance(item.get("execution_outcomes"), list) else []
        audit_rows += (
            "<tr>"
            f"<td>{_esc(item.get('round',''))}</td>"
            f"<td>{_esc(item.get('planner_source',''))}</td>"
            f"<td>{_esc(item.get('eligible_action_count',0))}</td>"
            f"<td>{_esc(item.get('ai_selected_action_count',0))}</td>"
            f"<td>{_esc(item.get('selected_action_count',0))}</td>"
            f"<td>{_esc(len(item.get('remaining_coverage_gaps',[]) or []))}</td>"
            f"<td>{_esc(len(outcomes))}</td>"
            "</tr>"
        )
        audit_details.append(
            f"<details><summary>Round {_esc(item.get('round',''))}: {_esc(item.get('planner_source',''))}</summary>"
            f"<p><b>Planner summary:</b> {_esc(item.get('reasoning_summary',''))}</p>"
            f"<pre>{_esc(json.dumps(item, indent=2, ensure_ascii=False, default=str))}</pre></details>"
        )
    if not audit_rows:
        return ""
    heading = _heading(2, "Agentic planning audit", toc, anchor="agentic-audit")
    return (
        f"{heading}"
        "<p class='section-note'>This section records model-selected actions, coverage repair, fallback use and execution outcomes. It contains concise planner summaries, not hidden chain-of-thought.</p>"
        "<table><thead><tr><th>Round</th><th>Planner</th><th>Eligible</th><th>AI selected</th><th>Executed plan</th><th>Gaps</th><th>Outcomes</th></tr></thead>"
        f"<tbody>{audit_rows}</tbody></table>{''.join(audit_details)}"
    )
