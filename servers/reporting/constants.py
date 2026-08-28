"""Static, engagement-independent data used across report generation:
report front-matter identity, lookup tables and the secret-redaction
patterns applied to every scanner-supplied string before it is rendered.
"""

from __future__ import annotations

import re

# Report info
REPORT_TITLE = "SecOps Penetration-Test Report"
REPORT_VERSION = "1.0"
AUTHORS = ["Alberto Pizzi", "Tommaso Ciccotti"]
REPORT_CLASSIFICATION = "Confidential"
CLIENT_NAME = "CLIENT NAME"

_MONTHS_EN = {
    1: "January", 2: "February", 3: "March", 4: "April", 5: "May", 6: "June",
    7: "July", 8: "August", 9: "September", 10: "October", 11: "November", 12: "December",
}

RISK_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
TOOL_PURPOSES = {
    "zap": "Traffic import, session handling, spider/site-tree population, passive analysis, and bounded high-value active checks when enabled.",
    "nuclei": "Adaptive fingerprint-driven template checks for CVEs, exposures and misconfigurations, plus bounded DAST only for specialist coverage gaps.",
    "nikto": "Web-server hardening, exposed resource and outdated component checks.",
    "ffuf": "High-value path and resource discovery with content verification for selected sensitive paths.",
    "exposure": "Read-only verification of exposed backups, source files, configuration artifacts and directory indexes.",
    "session": "Cookie-attribute, bounded session-identifier and fixation-indicator analysis.",
    "browser": "Chromium-based verification of DOM, reflected and stored XSS using harmless execution markers.",
    "workflow": "Bounded CSRF, file-upload, authentication-throttling and CAPTCHA workflow checks.",
    "arjun": "Hidden GET/POST parameter discovery using the discovered request contract.",
    "sqlmap": "SQL injection confirmation on discovered GET and POST requests.",
    "dalfox": "XSS reflection, AST and verified-vector testing.",
    "commix": "Operating-system command injection confirmation.",
    "traversal": "Bounded path traversal and local-file-inclusion verification on file-like parameters.",
    "idor": "Single-reference numeric object differential checks requiring manual ownership validation.",
    "authorization": "Read-only anonymous and optional two-account authorization/BOLA differentials on discovered high-value GET requests.",
    "jwt": "JWT structural analysis; it does not prove server acceptance of modified tokens.",
    "interactsh": "Explicit out-of-band callback confirmation for a supplied insertion point.",
}
SECRET_PATTERNS = (
    (re.compile(r"(?i)((?:session(?:_?id)?|sid|jsessionid|connect\.sid|asp\.net_sessionid)=)[^;\s]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(Cookie:\s*)[^\r\n]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(STATIC-COOKIE=)[^\s,\]]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9._~-]+"), r"\1<redacted>"),
    (re.compile(r"(?im)^\s*((?:db_|database_|mysql_|postgres_|redis_|smtp_)?(?:password|passwd|pass|secret|token|api_key|access_key|private_key|client_secret)\s*[=:]\s*)[^\r\n]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(\[\s*['\"]?(?:db_password|db_pass|database_password|db_user|db_username|api_key|secret_key|client_secret|private_key|token)['\"]?\s*\]\s*=\s*['\"])[^'\"]+"), r"\1<redacted>"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "<redacted-jwt>"),
)

# Static front-matter boilerplate (risk-rating legend and methodology narrative).
SEVERITY_DEFINITIONS = [
    ("Critical", "#a90000", "Immediate, severe threat to confidentiality, integrity or availability that is trivial to exploit (e.g. unauthenticated remote code execution, full data-store compromise). Requires emergency remediation, typically within 24-48 hours."),
    ("High", "#a90000", "Significant security impact that is straightforward to exploit or that undermines a core security control (e.g. confirmed SQL injection, authentication bypass). Requires urgent remediation, typically within one to two weeks."),
    ("Medium", "#d98200", "Meaningful weakness with a more constrained impact or exploitability (e.g. reflected XSS, missing authorization checks on non-critical functions). Should be remediated within the next release cycle."),
    ("Low", "#b49b00", "Limited security impact, often requiring specific preconditions or giving only marginal advantage to an attacker (e.g. verbose error messages, minor information disclosure). Should be scheduled for remediation."),
    ("Info", "#4b86b4", "Observations, hardening opportunities or discovered attack surface that do not constitute a confirmed vulnerability but support defense-in-depth and future testing."),
]

METHODOLOGY_PHASES = [
    ("Planning and scoping", "Target, credentials, testing profiles (anonymous and/or authenticated) and safety boundaries were agreed before execution; destructive actions were excluded by default."),
    ("Reconnaissance and discovery", "Passive and active crawling enumerated reachable URLs, forms, parameters, request contracts, JWTs and client-side sinks. See “Scope and assessment context” for the discovered surface."),
    ("Automated vulnerability scanning", "Adaptive, fingerprint-driven and signature-based scanners assessed the discovered surface for known vulnerabilities, misconfigurations and exposures. See “Assessment execution” for the tools used and their purpose."),
    ("Targeted validation", "Findings capable of automated confirmation were re-tested with bounded, evidence-producing checks (for example SQL injection, XSS, command injection, path traversal) to separate confirmed vulnerabilities from candidates requiring manual review."),
    ("Coverage and manual-review triggers", "Classes that automated tooling cannot conclusively confirm (for example business-logic authorization or IDOR without a second identity) are flagged as coverage constraints for manual follow-up rather than reported as confirmed."),
    ("Reporting", "Results were normalized, de-duplicated across corroborating tools and compiled into this evidence-grounded report, distinguishing confirmed vulnerabilities from candidates, observations and discovery."),
]

AUTO_INDEX_QUERY_KEYS = {"c", "n", "m", "s", "d", "o"}

FINDING_SECTION_META = {
    "vulnerability": (
        "Confirmed vulnerabilities",
        "The scanner supplied a bounded payload and response evidence satisfying the tool-specific confirmation rule. Each entry includes preconditions, technical reasoning, impact, remediation and reproduction details when available.",
    ),
    "candidate": (
        "Candidates requiring manual validation",
        "Automated evidence indicates a possible issue, but the report does not present it as confirmed exploitation.",
    ),
    "observation": (
        "Security observations and hardening",
        "Configuration, protocol, or exposure observations that may weaken security but are not confirmed application vulnerabilities.",
    ),
    "discovery": (
        "Discovered attack surface",
        "Reachable paths and parameters retained to explain coverage and guide further testing; these entries are not vulnerabilities.",
    ),
}

AI_SUFFIX = "(AI-generated)"
