"""Tunable parameters for the two extra condensed PDFs produced alongside the
full report.

Besides the complete report (``<base>.pdf``) the pipeline now also renders:

  1. A **reduced report** (``<base>.reduced.pdf`` / ``.html``) — every finding
     is still present, but the amount of detail per finding is trimmed by
     severity so the document is far smaller than the full report.
  2. A **summary report** (``<base>.summary.pdf`` / ``.html``) — a compact list
     of every test/attack that was executed together with the critical issues
     that were detected.

This module exists so the filtering behaviour can be adjusted in one place,
without touching the rendering code. Everything a non-developer is likely to
want to change lives here.

Design rules honoured by the renderers (see ``reduced_report.py``):

* No finding ever disappears from the reduced report. Severities whose detail
  level is ``"none"``, and findings beyond a severity's ``max_detailed`` cap,
  are still listed as a compact one-line row instead of being dropped.
* Content authored by the AI stays clearly distinguished from scanner output
  (the "Agentic risk assessment" box and the ``(AI-generated)`` field suffix
  are preserved whenever a severity keeps any detail).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Master switches
# ---------------------------------------------------------------------------

# Turn each extra report on/off independently. The full report is unaffected.
GENERATE_REDUCED_REPORT = True
GENERATE_SUMMARY_REPORT = True

# File-name suffixes: <base>.<suffix>.pdf / <base>.<suffix>.html
REDUCED_REPORT_SUFFIX = "reduced"
SUMMARY_REPORT_SUFFIX = "summary"

# Base the reduced report on the COMPLETE normalized finding set
# (payload["all_findings"]) rather than the display-capped list, so no finding
# can disappear. Set to False to reuse the already-capped payload["findings"].
REDUCED_REPORT_USE_ALL_FINDINGS = True


# ---------------------------------------------------------------------------
# Per-severity detail policy for the REDUCED report
# ---------------------------------------------------------------------------
# For each severity:
#   "detail"       -> how much of each finding to show. One of:
#                        "full"      every field, identical to the full report
#                        "reduced"   core identity + what-it-is + impact +
#                                    consequences + remediation + AI assessment
#                        "essential" only what-it-is (description) + impact +
#                                    remediation + a short AI rationale
#                        "none"      finding is listed as a one-line row only
#   "max_detailed" -> how many findings of this severity get a detail card.
#                     Findings beyond this count are NOT dropped: they are
#                     downgraded to a one-line row. None = unlimited.
#
# Defaults implement the requested policy:
#   critical -> full details, all of them
#   high     -> reduced details, first n (n = 1000)
#   medium   -> essential details, first m (m = 100)
#   low      -> no details
#   info     -> no details
SEVERITY_FILTERS: dict[str, dict] = {
    "critical": {"detail": "full",      "max_detailed": None},
    "high":     {"detail": "reduced",   "max_detailed": 1000},
    "medium":   {"detail": "essential", "max_detailed": 100},
    "low":      {"detail": "none",      "max_detailed": 0},
    "info":     {"detail": "none",      "max_detailed": 0},
}

# Applied to any finding whose severity is not listed above.
DEFAULT_SEVERITY_FILTER: dict = {"detail": "essential", "max_detailed": 100}


# ---------------------------------------------------------------------------
# Which finding fields each detail level keeps
# ---------------------------------------------------------------------------
# A value of None means "keep everything" (the full-report card is reused).
# Every other level is a flag table; a missing key is treated as False.
#
# Field keys:
#   identity_badges  - Status / Tool confidence / Profiles / Tool badge row
#   url              - Affected URL
#   method           - HTTP method
#   parameter        - Affected parameter
#   source           - Source entry point(s) / job(s)
#   description      - "what it is" narrative            (AI-marked when AI)
#   technical_details- why the evidence confirms/suggests the issue
#   attack_preconditions
#   payload          - payload / test input snippet
#   evidence         - raw evidence snippet
#   impact           - security impact                   (AI-marked when AI)
#   consequences     - potential consequences / damage   (AI-marked when AI)
#   recovery         - recovery / restoration actions    (AI-marked when AI)
#   solution         - recommended remediation           (AI-marked when AI)
#   reproduction     - reproduction / validation steps snippet
#   owasp            - OWASP classification
#   identifiers      - CWE/CVE/CVSS/template identifiers
#   references       - reference links
#   ai_assessment    - "Agentic risk assessment" box (AI rationale/confidence)
#   ai_coverage      - "AI analysis coverage" box
#   scanner_original - "Original scanner assessment" secondary-audit box
#   corroborating    - corroborating evidence from merged occurrences
#   data_quality_notes
DETAIL_LEVEL_FIELDS: dict[str, dict | None] = {
    "full": None,
    "reduced": {
        "identity_badges": True,
        "url": True, "method": True, "parameter": True, "source": False,
        "description": True, "technical_details": True, "attack_preconditions": True,
        "payload": False, "evidence": False,
        "impact": True, "consequences": True, "recovery": True, "solution": True,
        "reproduction": False, "owasp": True,
        "identifiers": True, "references": False,
        "ai_assessment": True, "ai_coverage": False,
        "scanner_original": False, "corroborating": False, "data_quality_notes": False,
    },
    "essential": {
        "identity_badges": False,
        "url": True, "method": False, "parameter": True, "source": False,
        "description": True, "technical_details": False, "attack_preconditions": False,
        "payload": False, "evidence": False,
        "impact": True, "consequences": False, "recovery": False, "solution": True,
        "reproduction": False, "owasp": False,
        "identifiers": False, "references": False,
        "ai_assessment": True, "ai_coverage": False,
        "scanner_original": False, "corroborating": False, "data_quality_notes": False,
    },
    "none": {},
}

# Max characters for any code/evidence snippet, per detail level
# (the full report uses 3000). 0 disables snippets at that level.
SNIPPET_MAX_CHARS: dict[str, int] = {
    "full": 3000,
    "reduced": 800,
    "essential": 300,
    "none": 0,
}


# ---------------------------------------------------------------------------
# Which top-level sections the REDUCED report keeps
# ---------------------------------------------------------------------------
# The findings section is where severity filtering happens; the other,
# boilerplate-heavy sections are trimmed here to cut volume. Flip any of these
# back to True to restore a section.
REDUCED_REPORT_SECTIONS: dict[str, bool] = {
    "cover": True,
    "document_control": True,
    "disclaimer": True,
    "toc": True,
    "executive_summary": True,
    "severity_legend": True,
    "overall_risk_banner": True,
    "priority_actions": True,
    "glance": True,
    "scope": False,
    "methodology": False,
    "qualifications": False,
    "visualizations": True,
    "agentic_audit": False,
    "execution": True,
    "endpoint_coverage": False,
    "limitations": True,
    "constraints": True,
    "chaining_potential": True,
    "findings": True,
    "cleanup": False,
    "conclusion": True,
}


# ---------------------------------------------------------------------------
# SUMMARY report
# ---------------------------------------------------------------------------
# Severities treated as "critical things detected" and surfaced in the summary.
SUMMARY_CRITICAL_SEVERITIES: tuple[str, ...] = ("critical", "high")

# Finding categories included in the critical-issues list of the summary.
SUMMARY_INCLUDE_CATEGORIES: tuple[str, ...] = ("vulnerability", "candidate")

# Cap on the number of critical items listed in the summary (None = all).
SUMMARY_MAX_CRITICAL_ITEMS: int | None = None

# Length of the one-line "what it is" blurb shown per critical item.
SUMMARY_BLURB_MAX_CHARS: int = 240


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def severity_filter(risk: str) -> dict:
    """Return the configured filter for a severity, or the default."""
    return SEVERITY_FILTERS.get(str(risk or "").lower(), DEFAULT_SEVERITY_FILTER)


def detail_fields(detail_level: str) -> dict | None:
    """Return the field table for a detail level (None means 'everything')."""
    return DETAIL_LEVEL_FIELDS.get(detail_level, DETAIL_LEVEL_FIELDS["essential"])


def snippet_cap(detail_level: str) -> int:
    """Return the snippet character cap for a detail level."""
    return SNIPPET_MAX_CHARS.get(detail_level, 300)
