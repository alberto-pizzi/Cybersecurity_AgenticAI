"""Execution status, per-tool coverage table and the report-level summary
(risk counts, execution limitations, coverage constraints).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .constants import TOOL_PURPOSES
from .findings import _category, _iter_leaf_results
from .text_utils import _esc, _redact_text
from .toc import _heading

# Reclassifies a raw tool result's status, catching disguised failures/timeouts
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

# Computes a tool result's total duration in seconds, summing sub-runs
def _duration(result: dict[str, Any]) -> float:
    if isinstance(result.get("runs"), list):
        return sum(_duration(run) for run in result["runs"] if isinstance(run, dict))
    meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
    value = result.get("duration_seconds", meta.get("duration_seconds", 0))
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0

# Finds and consolidates a tool's result(s) into a single result dict
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

# Builds the per-profile/per-tool coverage table from raw scan results
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
                    "confirmed": 0,
                    "candidates": 0,
                    "observations": 0,
                    "duration_seconds": 0.0,
                    "purpose": TOOL_PURPOSES.get(str(tool), "Security assessment tool."),
                    "details": "No result object was produced for this tool.",
                })
                continue
            status, status_note = _effective_status(result)
            runs = result.get("runs") if isinstance(result.get("runs"), list) else [result]
            details = _redact_text(result.get("output") or status_note)
            raw_findings = [item for item in (result.get("vulnerabilities") or []) if isinstance(item, dict)]
            category_counts = Counter(_category(item) for item in raw_findings)
            rows.append({
                "profile": profile,
                "tool": tool,
                "status": status,
                "targets": len(runs),
                "findings": len(raw_findings),
                "confirmed": category_counts.get("vulnerability", 0),
                "candidates": category_counts.get("candidate", 0),
                "observations": category_counts.get("observation", 0) + category_counts.get("discovery", 0),
                "duration_seconds": round(_duration(result), 2),
                "purpose": TOOL_PURPOSES.get(str(tool), "Security assessment tool."),
                "details": details[:1000],
            })
    return rows

# Flags meaningful untested classes (e.g. BOLA without a second identity), separate from scanner failures
def _coverage_constraints(
    results: dict[str, Any],
    findings: list[dict[str, Any]],
    coverage: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[dict[str, str]]:
    constraints: list[dict[str, str]] = []

    def add(area: str, reason: str, next_step: str) -> None:
        key = (area.strip().lower(), reason.strip().lower())
        if not area or not reason:
            return
        if any((row["area"].lower(), row["reason"].lower()) == key for row in constraints):
            return
        constraints.append({"area": area, "reason": reason, "recommended_next_step": next_step})

    profiles = context.get("profiles") if isinstance(context.get("profiles"), list) else []
    authenticated_profiles = [
        row for row in profiles
        if isinstance(row, dict) and bool(row.get("authenticated"))
    ]
    anonymous_profiles = [
        row for row in profiles
        if isinstance(row, dict) and not bool(row.get("authenticated"))
    ]
    if authenticated_profiles and not anonymous_profiles:
        add(
            "Anonymous attack surface",
            "The assessment was run with authenticated profiles only, so unauthenticated exposure and access-control differences were not compared.",
            "Repeat the assessment without --auth-only or include both anonymous and authenticated profiles.",
        )

    if authenticated_profiles and not bool(context.get("secondary_identity_supplied")):
        add(
            "Authorization / BOLA",
            "Only one authenticated identity was supplied. Horizontal and vertical authorization differences between users or roles could not be confirmed.",
            "Provide --secondary-cookies for an account with different ownership or privileges and repeat the read-only authorization checks.",
        )

    coverage_by_tool = {
        str(row.get("tool") or "").lower(): row
        for row in coverage if isinstance(row, dict)
    }
    arjun = coverage_by_tool.get("arjun")
    if arjun and arjun.get("status") == "skipped":
        add(
            "Hidden HTTP parameters",
            "No Arjun-compatible request contract was exercised, so undocumented parameter names were not actively searched.",
            "Review the relaxed Arjun candidate selected in deep/balanced mode or provide an explicit --tool-url for a safe endpoint.",
        )
    idor = coverage_by_tool.get("idor")
    if idor and idor.get("status") == "skipped":
        add(
            "Object-level authorization",
            "No compatible numeric object reference was discovered. UUID, path-segment, JSON-body and multi-step ownership checks remain outside the bounded IDOR verifier.",
            "Supply representative object endpoints and two identities, then perform manual ownership validation.",
        )
    jwt = coverage_by_tool.get("jwt")
    if jwt and jwt.get("status") == "skipped":
        add(
            "JWT validation",
            "No JWT was discovered in the crawled traffic, so token algorithm, lifetime and claim structure were not analysed.",
            "Provide a representative JWT or capture an authenticated API flow if the application uses bearer tokens.",
        )

    for row in findings:
        verification = str(row.get("verification_status") or "").lower()
        if verification == "upload-accepted-location-not-confirmed":
            add(
                "File-upload retrieval and execution",
                "A harmless file was accepted, but no same-origin retrieval URL was confirmed.",
                "Inspect the upload response and discovered upload directories, then verify storage, MIME type and retrieval with a harmless marker.",
            )
            break

    remaining = int(context.get("remaining_eligible_actions_at_report", 0) or 0)
    if remaining:
        add(
            "Agentic execution plan",
            f"{remaining} applicable discovery-derived action(s) remained when the report was created.",
            "Increase --max-rounds or review the agentic planning audit and rerun the omitted applicable actions.",
        )
    planner_audit = context.get("planner_audit") if isinstance(context.get("planner_audit"), list) else []
    if any(isinstance(item, dict) and item.get("remaining_coverage_gaps") for item in planner_audit):
        add(
            "Agentic coverage contract",
            "At least one planner round ended with unresolved applicable tool groups.",
            "Review the round-level coverage gaps and rerun with a stronger model, more rounds or the deterministic baseline.",
        )

    return constraints

# Aggregates risk counts, execution limitations and coverage constraints into the report summary
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
    constraints = _coverage_constraints(results, findings, coverage, context)
    execution_complete = not any(row["status"] in {"error", "partial", "time_limit", "not_run"} for row in coverage)
    return {
        "risk_counts": dict(risks),
        "category_counts": dict(categories),
        "limitations": limitations,
        "coverage_constraints": constraints,
        "execution_complete": execution_complete,
        "coverage_complete": execution_complete and not constraints,
        "discovery": discovery,
    }

# Writes the executive-summary paragraph from finding/limitation/constraint counts
def _executive_text(summary: dict[str, Any], findings: list[dict[str, Any]], context: dict[str, Any] | None = None) -> str:
    confirmed = sum(item["category"] == "vulnerability" for item in findings)
    candidates = sum(item["category"] == "candidate" for item in findings)
    observations = sum(item["category"] in {"observation", "discovery"} for item in findings)
    limits = len(summary["limitations"])
    constraints = len(summary.get("coverage_constraints") or [])
    ai_assessment = (context or {}).get("ai_risk_assessment", {}) if isinstance(context, dict) else {}
    assessed = int(ai_assessment.get("assessed_findings", 0) or 0) if isinstance(ai_assessment, dict) else 0
    if assessed:
        assessment_note = (
            f" Ollama post-assessed {assessed} confirmed/candidate finding(s), independently enriching severity, description, "
            "impact and remediation while the scanner/verifier evidence and confirmation category remained immutable."
        )
    else:
        assessment_note = ""
    return (
        f"The automated assessment produced {confirmed} scanner-confirmed findings, {candidates} candidates requiring manual validation, "
        f"and {observations} discovery or hardening observations. {limits} execution limitation(s) and {constraints} coverage constraint(s) were recorded. "
        "The report preserves scanner evidence and metadata and does not invent unsupported exploitability claims."
        + assessment_note
        + " Repetitive informational details may be summarized in PDF/HTML while the complete normalized set remains in JSON."
    )

# Renders the "Assessment execution" section: the coverage table plus per-row execution details
def _render_execution(coverage: list[dict[str, Any]], toc: list[tuple[int, str, str]]) -> str:
    heading = _heading(2, "Assessment execution", toc, anchor="execution")
    rows = "".join(
        "<tr>"
        f'<td class="idx">{index}</td>'
        f"<td>{_esc(row['profile'])}</td>"
        f"<td><b>{_esc(row['tool'])}</b><br><small>{_esc(row.get('purpose', ''))}</small></td>"
        f"<td>{_esc(row['status'])}</td>"
        f"<td>{row['targets']}</td><td>{row.get('confirmed',0)}</td>"
        f"<td>{row.get('candidates',0)}</td><td>{row.get('observations',0)}</td>"
        f"<td>{row['duration_seconds']}</td>"
        "</tr>"
        for index, row in enumerate(coverage, start=1)
    ) or '<tr><td colspan="9">No execution data.</td></tr>'

    detail_items = "".join(f"<li>{_esc(row['details'])}</li>" for row in coverage)
    details_html = f"<ol>{detail_items}</ol>" if detail_items else "<p>No execution details recorded.</p>"
    details_heading = _heading(3, "Execution details", toc, anchor="execution-details")

    return (
        f'{heading}'
        '<p class="section-note">This section records tools, targets, duration and execution status. It is deliberately separate from security findings.</p>'
        '<table><colgroup><col style="width:2%"><col style="width:10%"><col style="width:26%"><col style="width:10%"><col style="width:8%"><col style="width:10%"><col style="width:11%"><col style="width:15%"><col style="width:8%"></colgroup>'
        '<thead><tr><th>#</th><th>Profile</th><th>Tool and purpose</th><th>Status</th><th>Targets</th><th>Confirmed</th><th>Candidates</th><th>Info/discovery</th><th>Seconds</th></tr></thead>'
        f"<tbody>{rows}</tbody></table>"
        f'{details_heading}<p class="section-note">Raw execution output per row, numbered to match the table above.</p>{details_html}'
    )

# Renders the "Execution limitations" table section
def _render_limitations(summary: dict[str, Any], toc: list[tuple[int, str, str]]) -> str:
    heading = _heading(2, "Execution limitations", toc, anchor="limitations")
    rows = "".join(
        f"<tr><td>{_esc(row['path'])}</td><td>{_esc(row['status'])}</td><td>{_esc(row['cause'])}</td><td>{_esc(row['explanation'])}</td></tr>"
        for row in summary["limitations"]
    ) or '<tr><td colspan="4">No recorded execution limitations.</td></tr>'
    return (
        f"{heading}"
        "<table><thead><tr><th>Run</th><th>Status</th><th>Cause</th><th>Explanation</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )

# Renders the "Coverage constraints and untested classes" table section
def _render_constraints(summary: dict[str, Any], toc: list[tuple[int, str, str]]) -> str:
    heading = _heading(2, "Coverage constraints and untested classes", toc, anchor="constraints")
    rows = "".join(
        f"<tr><td>{_esc(row['area'])}</td><td>{_esc(row['reason'])}</td><td>{_esc(row['recommended_next_step'])}</td></tr>"
        for row in summary.get("coverage_constraints", [])
    ) or '<tr><td colspan="3">No additional coverage constraints were recorded.</td></tr>'
    return (
        f"{heading}"
        '<p class="section-note">These rows are not scanner failures. They identify security classes that could not be fully validated with the supplied identities, traffic and request contracts.</p>'
        "<table><thead><tr><th>Area</th><th>Reason</th><th>Recommended next step</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )
