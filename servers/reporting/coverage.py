"""Execution status, per-tool coverage table and the report-level summary
(risk counts, execution limitations, coverage constraints).
"""

from __future__ import annotations

import os
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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


# Normalizes endpoint URLs for coverage matching while preserving meaningful query values.
def _endpoint_coverage_url_key(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        if not parsed.scheme or not parsed.netloc:
            return text
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
        return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", query, ""))
    except (TypeError, ValueError):
        return text


# Converts internal discovery metadata to concise report labels.
def _endpoint_discovery_source(case: dict[str, Any]) -> str:
    source = str(case.get("discovery_source") or "").strip().lower()
    if source == "playwright_network":
        return "Chromium network"
    if source == "javascript_literal":
        return "JavaScript"
    if case.get("form_action") or case.get("fields"):
        return "HTML form"
    if case.get("synthetic_from_parameterized_url"):
        return "Parameterized URL"
    if str(case.get("source_url") or "").strip():
        return "Crawler / discovered request"
    return "Discovery"


# Flattens both single-entry and aggregate multi-entry discovery contexts.
def _iter_endpoint_discovery(context: dict[str, Any]):
    discovery = context.get("discovery") if isinstance(context.get("discovery"), dict) else {}
    entry_targets = {
        str(item.get("job_id") or ""): str(item.get("target") or "")
        for item in (context.get("entry_points") or [])
        if isinstance(item, dict)
    }

    def is_profile_discovery(value: Any) -> bool:
        return isinstance(value, dict) and any(
            key in value for key in ("request_cases", "html_urls", "urls", "errors", "browser_navigation_urls")
        )

    if any(is_profile_discovery(value) for value in discovery.values()):
        for profile, data in discovery.items():
            if is_profile_discovery(data):
                yield "", str(profile), data, ""
        return

    for job_id, per_profile in discovery.items():
        if not isinstance(per_profile, dict):
            continue
        for profile, data in per_profile.items():
            if is_profile_discovery(data):
                yield str(job_id), str(profile), data, entry_targets.get(str(job_id), "")


def _iter_endpoint_selection(context: dict[str, Any]):
    selection = context.get("endpoint_selection") if isinstance(context.get("endpoint_selection"), dict) else {}
    if not selection:
        return
    # Single-entry reports store profile -> decision list. Aggregate reports store job -> profile -> list.
    if any(isinstance(value, list) for value in selection.values()):
        for profile, rows in selection.items():
            if isinstance(rows, list):
                yield "", str(profile), rows
        return
    for job_id, per_profile in selection.items():
        if not isinstance(per_profile, dict):
            continue
        for profile, rows in per_profile.items():
            if isinstance(rows, list):
                yield str(job_id), str(profile), rows


# Builds a complete endpoint/request coverage matrix from discovery plus actual scanner executions.
def build_endpoint_coverage(results: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    def ensure_row(job_id: str, profile: str, method: str, url: str, *, entry_point: str = "", source: str = "Discovery") -> dict[str, Any]:
        clean_url = _redact_text(url).strip()
        normalized_method = str(method or "GET").upper()
        key = (str(job_id or ""), str(profile or ""), normalized_method, _endpoint_coverage_url_key(clean_url))
        row = rows.get(key)
        if row is None:
            row = {
                "job_id": str(job_id or ""),
                "entry_point": _redact_text(entry_point).strip(),
                "profile": str(profile or ""),
                "method": normalized_method,
                "url": clean_url,
                "discovery_sources": [],
                "tests": [],
                "status": "Discovered only",
                "reason_code": "NO_TEST_EXECUTION_RECORDED",
                "reason": "No concrete request-level security execution was recorded for this endpoint.",
                "selector_selected_tools": [],
                "selector_eligible_tools": [],
            }
            rows[key] = row
        if source and source not in row["discovery_sources"]:
            row["discovery_sources"].append(source)
        return row

    explicit_entry_points = [str(value) for value in (context.get("explicit_entry_points") or []) if isinstance(value, str) and str(value).strip()]
    profile_names = [
        str(item.get("name") or "") for item in (context.get("profiles") or [])
        if isinstance(item, dict) and str(item.get("name") or "")
    ]
    for profile in profile_names:
        for url in explicit_entry_points:
            row = ensure_row("", profile, "GET", url, source="Configured entry point")
            row["configured_entry_point"] = True

    for job_id, profile, discovery, entry_point in _iter_endpoint_discovery(context):
        browser_urls = {_endpoint_coverage_url_key(str(value)) for value in discovery.get("browser_navigation_urls", []) if str(value)}
        for case in discovery.get("request_cases", []):
            if not isinstance(case, dict):
                continue
            url = str(case.get("url") or "")
            if not url:
                continue
            row = ensure_row(job_id, profile, str(case.get("method") or "GET"), url, entry_point=entry_point, source=_endpoint_discovery_source(case))
            params = [str(value) for value in case.get("parameters", []) if str(value)]
            if params:
                row["parameters"] = list(dict.fromkeys([*(row.get("parameters") or []), *params]))

        for url in discovery.get("html_urls", []):
            if not str(url):
                continue
            source = "HTTP crawler + Chromium" if _endpoint_coverage_url_key(str(url)) in browser_urls else "HTTP crawler"
            ensure_row(job_id, profile, "GET", str(url), entry_point=entry_point, source=source)

        for case in discovery.get("destructive_request_cases", []):
            if not isinstance(case, dict) or not str(case.get("url") or ""):
                continue
            row = ensure_row(job_id, profile, str(case.get("method") or "GET"), str(case.get("url")), entry_point=entry_point, source="Discovery")
            row["status"] = "Skipped"
            row["reason_code"] = "STATE_CHANGE_BLOCKED"
            row["reason"] = "Destructive or state-changing request excluded by the discovery safety policy."

        for url in discovery.get("destructive_urls_skipped", []):
            if not str(url):
                continue
            row = ensure_row(job_id, profile, "GET", str(url), entry_point=entry_point, source="Discovery")
            row["status"] = "Skipped"
            row["reason_code"] = "STATE_CHANGE_BLOCKED"
            row["reason"] = "Destructive route excluded by the discovery safety policy."

        for skipped in discovery.get("coverage_skipped_cases", []):
            if not isinstance(skipped, dict) or not str(skipped.get("url") or ""):
                continue
            row = ensure_row(
                job_id, profile, str(skipped.get("method") or "GET"), str(skipped.get("url")),
                entry_point=entry_point, source="Discovery policy",
            )
            if row["status"] not in {"Tested", "Execution error", "HTTP 404", "HTTP 410"}:
                row["status"] = "Skipped"
                row["reason_code"] = str(skipped.get("reason_code") or "DISCOVERY_POLICY_SKIP").upper()
                row["reason"] = _redact_text(skipped.get("reason") or "Discovery policy excluded this request context.")[:500]

        for error in discovery.get("errors", []):
            if not isinstance(error, dict):
                continue
            kind = str(error.get("type") or "").upper()
            if kind not in {"HTTP404", "HTTP410"}:
                continue
            url = str(error.get("url") or "")
            if not url:
                continue
            row = ensure_row(job_id, profile, "GET", url, entry_point=entry_point, source="HTTP crawler")
            row["status"] = "HTTP 404" if kind == "HTTP404" else "HTTP 410"
            row["reason_code"] = "HTTP_404" if kind == "HTTP404" else "HTTP_410"
            row["reason"] = "The server reported that the discovered resource does not exist." if kind == "HTTP404" else "The server reported that the discovered resource has been removed."

    # Selector decisions explain why reachable request contracts were retained or omitted before execution.
    for job_id, profile, decisions in _iter_endpoint_selection(context) or []:
        entry_point = ""
        if job_id:
            entry_point = next((str(item.get("target") or "") for item in (context.get("entry_points") or []) if isinstance(item, dict) and str(item.get("job_id") or "") == job_id), "")
        for decision in decisions:
            if not isinstance(decision, dict) or not str(decision.get("url") or ""):
                continue
            row = ensure_row(job_id, profile, str(decision.get("method") or "GET"), str(decision.get("url")), entry_point=entry_point, source="Deterministic selector")
            row["selector_selected_tools"] = sorted(set([*(row.get("selector_selected_tools") or []), *[str(v) for v in decision.get("selected_tools", []) if str(v)]]))
            row["selector_eligible_tools"] = sorted(set([*(row.get("selector_eligible_tools") or []), *[str(v) for v in decision.get("eligible_tools", []) if str(v)]]))
            code = str(decision.get("reason_code") or "").upper()
            if code and code != "SELECTED_FOR_SECURITY_TEST" and row["status"] == "Discovered only":
                row["status"] = "Skipped"
                row["reason_code"] = code
                row["reason"] = _redact_text(decision.get("reason") or row.get("reason") or "")[:500]

    # Aggregate reports carry the source job on result objects. Single-entry reports leave it blank.
    for path, result in _iter_leaf_results(results):
        profile = str(path[0] if path else "")
        tool_from_path = str(path[1] if len(path) > 1 else "").split(":", 1)[0]
        tool = str(result.get("tool") or tool_from_path).lower()
        if tool == "jwt":
            continue
        source_job = str(result.get("aggregate_source_job_id") or "")
        source_entry = str(result.get("aggregate_source_entry_point") or "")
        action = result.get("coverage_action") if isinstance(result.get("coverage_action"), dict) else {}
        target = str(action.get("target_url") or result.get("target") or "")
        method = str(action.get("method") or "GET").upper()
        if not target:
            continue
        row = ensure_row(source_job, profile, method, target, entry_point=source_entry, source="Scanner target")
        status, _ = _effective_status(result)
        tool_label = tool or "scanner"
        test_label = f"{tool_label} ({status})"
        if test_label not in row["tests"]:
            row["tests"].append(test_label)
        if status == "skipped":
            if row["status"] not in {"HTTP 404", "HTTP 410", "Tested", "Execution error"}:
                row["status"] = "Skipped"
                diagnosis = str(result.get("diagnosis") or "").lower()
                output_text = _redact_text(result.get("output") or result.get("diagnosis") or "Selected security test was skipped.")[:500]
                if diagnosis == "agentic_deferred_by_planner":
                    row["reason_code"] = "PLANNER_DEFERRED"
                elif diagnosis == "adaptive_budget_reallocated":
                    row["reason_code"] = "BUDGET_LIMIT"
                elif "state" in output_text.lower() and ("disabled" in output_text.lower() or "blocked" in output_text.lower()):
                    row["reason_code"] = "STATE_CHANGE_BLOCKED"
                else:
                    row["reason_code"] = "TOOL_SKIPPED"
                row["reason"] = output_text
        elif status == "error":
            if row["status"] not in {"HTTP 404", "HTTP 410", "Tested"}:
                row["status"] = "Execution error"
                row["reason_code"] = "EXECUTION_ERROR"
                row["reason"] = _redact_text(result.get("output") or result.get("diagnosis") or "Scanner execution failed.")[:500]
        else:
            if row["status"] not in {"HTTP 404", "HTTP 410"}:
                row["status"] = "Tested"
                row["reason_code"] = "TESTED"
                row["reason"] = "One or more concrete security-tool executions were recorded for this endpoint."

        # Broad scanners can test many concrete URLs inside one MCP invocation. Record those exact
        # targets so the endpoint matrix does not attribute all broad coverage only to the root URL.
        # This records execution coverage only; it does not promote broad scans to specialist findings.
        if tool == "nuclei" and status != "skipped":
            nuclei_targets: list[tuple[str, str, str]] = []
            for value in result.get("focused_targets", []) if isinstance(result.get("focused_targets"), list) else []:
                if str(value):
                    nuclei_targets.append(("GET", str(value), "nuclei focused target"))
            for case in result.get("dast_request_cases", []) if isinstance(result.get("dast_request_cases"), list) else []:
                if isinstance(case, dict) and str(case.get("url") or ""):
                    nuclei_targets.append((str(case.get("method") or "GET").upper(), str(case.get("url")), "nuclei DAST request"))
            for nested_method, nested_url, nested_label in nuclei_targets:
                nested = ensure_row(source_job, profile, nested_method, nested_url, entry_point=source_entry, source="Scanner evidence")
                label = f"{nested_label} ({status})"
                if label not in nested["tests"]:
                    nested["tests"].append(label)
                if status == "error":
                    if nested["status"] not in {"HTTP 404", "HTTP 410", "Tested"}:
                        nested["status"] = "Execution error"
                        nested["reason_code"] = "EXECUTION_ERROR"
                        nested["reason"] = "Nuclei received this target/request context, but the scanner invocation failed."
                elif nested["status"] not in {"HTTP 404", "HTTP 410"}:
                    nested["status"] = "Tested"
                    nested["reason_code"] = "TESTED"
                    nested["reason"] = "This endpoint/request context was included in an executed Nuclei target or DAST request set."

        if tool == "zap" and status != "skipped":
            active_scans = result.get("targeted_active_scans") if isinstance(result.get("targeted_active_scans"), list) else []
            for scan in active_scans:
                if not isinstance(scan, dict) or not scan.get("started") or not str(scan.get("url") or ""):
                    continue
                nested_method = str(scan.get("method") or "GET").upper()
                nested_url = str(scan.get("url"))
                nested = ensure_row(source_job, profile, nested_method, nested_url, entry_point=source_entry, source="Scanner evidence")
                label = f"zap targeted active scan ({status})"
                if label not in nested["tests"]:
                    nested["tests"].append(label)
                if status == "error":
                    if nested["status"] not in {"HTTP 404", "HTTP 410", "Tested"}:
                        nested["status"] = "Execution error"
                        nested["reason_code"] = "EXECUTION_ERROR"
                        nested["reason"] = "ZAP started a targeted active scan for this endpoint, but the scanner invocation failed."
                elif nested["status"] not in {"HTTP 404", "HTTP 410"}:
                    nested["status"] = "Tested"
                    nested["reason_code"] = "TESTED"
                    nested["reason"] = "A targeted ZAP active scan was actually started for this endpoint/request context."

    orchestration = context.get("orchestration") if isinstance(context.get("orchestration"), dict) else {}
    orchestration_mode = str(orchestration.get("mode") or "").lower()
    for row in rows.values():
        if row.get("status") != "Discovered only":
            continue
        if row.get("selector_selected_tools"):
            if orchestration_mode == "agentic":
                row["status"] = "Skipped"
                row["reason_code"] = "PLANNER_DEFERRED"
                row["reason"] = "The deterministic selector considered this request contract eligible, but no concrete execution was recorded after Agentic tool-group planning."
            else:
                row["reason_code"] = "EXECUTION_NOT_RECORDED"
                row["reason"] = "The deterministic selector marked this request contract for security testing, but no matching concrete execution was recorded; review the execution audit."
            continue
        if str(row.get("reason_code") or "") == "NO_TEST_EXECUTION_RECORDED" and not row.get("selector_eligible_tools"):
            row["status"] = "Skipped"
            row["reason_code"] = "NO_COMPATIBLE_PARAMETERS"
            row["reason"] = "The reachable page/request context exposed no compatible application parameter or dedicated request-level input for the specialist selectors."

    status_rank = {"Tested": 0, "Execution error": 1, "Skipped": 2, "Discovered only": 3, "HTTP 404": 4, "HTTP 410": 5}
    output = list(rows.values())
    for row in output:
        row["discovery_sources"] = sorted(set(row.get("discovery_sources") or []))
        row["tests"] = sorted(set(row.get("tests") or []))
    output.sort(key=lambda row: (str(row.get("job_id") or ""), str(row.get("profile") or ""), status_rank.get(str(row.get("status") or ""), 9), str(row.get("url") or ""), str(row.get("method") or "")))
    return output


# Summarizes endpoint/request coverage globally and independently for each assessment profile.
def summarize_endpoint_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def summarize_rows(items: list[dict[str, Any]]) -> dict[str, Any]:
        total = len(items)
        dead = sum(str(row.get("status") or "") in {"HTTP 404", "HTTP 410"} for row in items)
        out_scope = sum(str(row.get("reason_code") or "") == "OUT_OF_SCOPE" for row in items)
        reachable = max(0, total - dead - out_scope)
        tested = sum(str(row.get("status") or "") == "Tested" for row in items)
        discovered_only = sum(str(row.get("status") or "") == "Discovered only" for row in items)
        skipped = sum(str(row.get("status") or "") == "Skipped" for row in items)
        errors = sum(str(row.get("status") or "") == "Execution error" for row in items)
        coverage = (100.0 * tested / reachable) if reachable else 0.0
        explicit = [row for row in items if bool(row.get("configured_entry_point"))]
        explicit_tested = sum(str(row.get("status") or "") == "Tested" for row in explicit)
        explicit_coverage = (100.0 * explicit_tested / len(explicit)) if explicit else 0.0
        return {
            "discovered_contexts": total,
            "reachable_in_scope": reachable,
            "tested": tested,
            "configured_entry_points": len(explicit),
            "tested_entry_points": explicit_tested,
            "entry_point_tested_coverage_percent": round(explicit_coverage, 1),
            "discovered_only": discovered_only,
            "intentionally_skipped": skipped,
            "execution_errors": errors,
            "http_404_410": dead,
            "out_of_scope": out_scope,
            "tested_coverage_percent": round(coverage, 1),
        }

    profiles = sorted({str(row.get("profile") or "unknown") for row in rows})
    return {
        "overall": summarize_rows(rows),
        "profiles": {profile: summarize_rows([row for row in rows if str(row.get("profile") or "unknown") == profile]) for profile in profiles},
    }


# Renders the endpoint coverage matrix using the same table language as the rest of the report.
def _render_endpoint_coverage(rows: list[dict[str, Any]], toc: list[tuple[int, str, str]], *, for_pdf: bool=False) -> str:
    heading = _heading(2, "Endpoint coverage matrix", toc, anchor="endpoint-coverage")
    if not rows:
        return f"{heading}<p>No endpoint coverage data were recorded.</p>"

    summary = summarize_endpoint_coverage(rows)
    profiles = sorted(summary.get("profiles", {}))
    summary_columns = [*profiles]
    if len(profiles) > 1:
        summary_columns.append("Total")
    metrics = [
        ("Discovered contexts", "discovered_contexts", False),
        ("Reachable / in scope", "reachable_in_scope", False),
        ("Tested", "tested", False),
        ("Configured entry points", "configured_entry_points", False),
        ("Tested entry points", "tested_entry_points", False),
        ("Entry-point tested coverage", "entry_point_tested_coverage_percent", True),
        ("Discovery only", "discovered_only", False),
        ("Intentionally skipped", "intentionally_skipped", False),
        ("Execution errors", "execution_errors", False),
        ("HTTP 404/410", "http_404_410", False),
        ("Tested coverage", "tested_coverage_percent", True),
    ]
    summary_rows = []
    for label, key, percent in metrics:
        cells = []
        for column in summary_columns:
            values = summary["overall"] if column == "Total" else summary["profiles"].get(column, {})
            value = values.get(key, 0)
            cells.append(f"<td>{float(value):.1f}%</td>" if percent else f"<td>{int(value or 0)}</td>")
        summary_rows.append(f"<tr><td>{_esc(label)}</td>{''.join(cells)}</tr>")
    summary_head = "".join(f"<th>{_esc(column)}</th>" for column in summary_columns)

    aggregate = any(str(row.get("job_id") or "") for row in rows)
    display_rows = list(rows)
    detail_note = ""
    if for_pdf:
        pdf_limit = max(80, int(os.getenv("SECOPS_REPORT_PDF_ENDPOINT_ROWS", "260")))
        if len(display_rows) > pdf_limit:
            status_priority = {
                "Execution error": 0, "Discovered only": 1, "Skipped": 2,
                "Tested": 3, "HTTP 404": 4, "HTTP 410": 4,
            }
            display_rows = sorted(
                display_rows,
                key=lambda row: (status_priority.get(str(row.get("status") or ""), 6), str(row.get("profile") or ""), str(row.get("url") or "")),
            )[:pdf_limit]
            detail_note = (
                f'<p class="section-note"><strong>PDF detail limit:</strong> showing {len(display_rows)} of {len(rows)} endpoint rows, prioritizing gaps and execution errors. '
                'The complete endpoint matrix remains available in the HTML and JSON artifacts.</p>'
            )
    body_rows = []
    for index, row in enumerate(display_rows, start=1):
        profile_text = _esc(row.get("profile", ""))
        if aggregate and row.get("job_id"):
            profile_text += f"<br><small>{_esc(row.get('job_id', ''))}</small>"
        source_text = ", ".join(row.get("discovery_sources") or []) or "-"
        tests_text = ", ".join(row.get("tests") or []) or "-"
        body_rows.append(
            "<tr>"
            f'<td class="idx">{index}</td>'
            f"<td>{profile_text}</td>"
            f'<td class="no-wrap">{_esc(row.get("method", ""))}</td>'
            f"<td>{_esc(row.get('url', ''))}</td>"
            f"<td>{_esc(source_text)}</td>"
            f"<td>{_esc(tests_text)}</td>"
            f"<td>{_esc(row.get('status', ''))}</td>"
            f"<td>{_esc(row.get('reason_code', ''))}</td>"
            f"<td>{_esc(row.get('reason', ''))}</td>"
            "</tr>"
        )
    return (
        f"{heading}"
        '<p class="section-note">Each row represents a discovered endpoint/request context for one assessment profile. '
        '"Tested" means that at least one concrete security-tool execution was recorded for that endpoint; discovery alone does not count as a security test. '
        'The reason code states why an untested context was deferred or excluded. Anonymous and authenticated coverage are calculated independently. '
        'Configured entry-point coverage counts the supplied URLs themselves: a value such as 0/N means none of those N exact request contexts received a concrete security-tool execution, not that the complete assessment executed zero attacks.</p>'
        f'<table><thead><tr><th>Metric</th>{summary_head}</tr></thead><tbody>{"".join(summary_rows)}</tbody></table>'
        '<p class="section-note">Tested coverage is the percentage of reachable, in-scope request contexts for which at least one concrete security-tool execution was recorded. Out-of-scope references and HTTP 404/410 responses are excluded from the denominator.</p>'
        f'{detail_note}'
        '<table><thead><tr><th>#</th><th>Profile / job</th><th>Method</th><th>Endpoint</th><th>Discovered by</th><th>Security tests</th><th>Status</th><th>Reason code</th><th>Reason</th></tr></thead>'
        f"<tbody>{''.join(body_rows)}</tbody></table>"
    )

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
    for entry in context.get("entry_points", []) if isinstance(context.get("entry_points"), list) else []:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or "").lower()
        report_available = bool(entry.get("report_available", True))
        if status not in {"error", "blocked"} and not (status in {"success", "reported", "unknown"} and not report_available):
            continue
        job_id = str(entry.get("job_id") or "entry-point")
        target = str(entry.get("target") or "")
        reason = str(entry.get("reason") or "")
        if status == "error":
            cause = "entry_point_execution_failed"
        elif status == "blocked":
            cause = "entry_point_blocked"
        else:
            cause = "entry_point_report_missing"
        limitations.append({
            "path": f"assessmentRunner/{job_id}",
            "status": status if cause != "entry_point_report_missing" else "partial",
            "cause": cause,
            "explanation": reason or f"The configured entry point {target or job_id} did not produce a complete per-job assessment report.",
        })
    risks = Counter(item["risk"] for item in findings)
    categories = Counter(item["category"] for item in findings)
    discovery = context.get("discovery") if isinstance(context.get("discovery"), dict) else {}
    constraints = _coverage_constraints(results, findings, coverage, context)
    execution_complete = (not limitations) and not any(row["status"] in {"error", "partial", "time_limit", "not_run"} for row in coverage)
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
    ai_assessment = (context or {}).get("ai_analysis", {}) if isinstance(context, dict) else {}
    assessed = int(ai_assessment.get("analyzed_findings", 0) or 0) if isinstance(ai_assessment, dict) else 0
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
