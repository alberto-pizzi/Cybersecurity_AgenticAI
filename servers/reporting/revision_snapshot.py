from __future__ import annotations

from typing import Any


REVIEW_SNAPSHOT_SCHEMA_VERSION = 1


# Builds the redacted evidence bundle retained for later review or report regeneration.
def build_review_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    context = payload.get("assessment_context") if isinstance(payload.get("assessment_context"), dict) else {}
    return {
        "schema_version": REVIEW_SNAPSHOT_SCHEMA_VERSION,
        "snapshot_type": "secops-review-snapshot",
        "generated_at": payload.get("generated_at"),
        "source_report_id": payload.get("report_id"),
        "target": payload.get("target"),
        "reporting_policy": payload.get("reporting_policy"),
        "summary": payload.get("summary") or {},
        "coverage": payload.get("coverage") or {},
        "findings": payload.get("all_findings") or [],
        "results": payload.get("results") or {},
        "assessment_context": context,
        "planner_audit": context.get("planner_audit") or [],
        "ai_analysis": context.get("ai_analysis") or {},
        "revision_policy": (
            "This snapshot contains the redacted scanner results, normalized findings and assessment context needed "
            "to review or regenerate the report without repeating the security scan. Authentication cookies, bearer "
            "tokens, JWT values, passwords and recognized secrets remain redacted."
        ),
    }
