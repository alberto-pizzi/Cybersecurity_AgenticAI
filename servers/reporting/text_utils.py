"""Generic text helpers shared by every other reporting module: secret
redaction, HTML escaping, date formatting and safe filename derivation.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from typing import Any

from .constants import _MONTHS_EN, SECRET_PATTERNS


def _format_date_en(dt: datetime) -> str:

    if 10 < dt.day % 100 < 14:  # eccezione: 11, 12, 13
        suffix = "th"

    last_digit = dt.day % 10

    if last_digit == 1:
        suffix = "st"
    elif last_digit == 2:
        suffix = "nd"
    elif last_digit == 3:
        suffix = "rd"
    else:
        suffix = "th"

    return f"{_MONTHS_EN[dt.month]} {dt.day}{suffix} {dt.year}"

def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip()).strip("._")[:120]


def _as_dict(value: dict | str | None) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("Expected a JSON object.")
    return parsed


def _redact_text(value: Any) -> str:
    text = str(value or "")
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_redact_value(child) for child in value]
    if isinstance(value, tuple):
        return [_redact_value(child) for child in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _esc(value: Any) -> str:
    return html.escape(_redact_text(value))
