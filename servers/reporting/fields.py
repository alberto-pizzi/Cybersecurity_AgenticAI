"""Small `<dl>`/list building blocks shared by the finding cards and the
assessment-context summary.
"""

from __future__ import annotations

import html
from typing import Any

from .text_utils import _esc, _redact_text

_MAX_SNIPPET_CHARS = 3000

# Renders a list of strings as an HTML <ul>, or "" if empty
def _render_list(values: list[str]) -> str:
    return "" if not values else "<ul>" + "".join(f"<li>{_esc(value)}</li>" for value in values) + "</ul>"

# Renders a label/value pair as a <dt>/<dd> entry, or "" if the value is empty
def _field(label: str, value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    return f"<dt>{_esc(label)}</dt><dd>{_esc(value)}</dd>"

# Renders a code/evidence snippet as a full-width, length-capped <pre> block outside the `<dl>` grid
def _snippet_field(label: str, value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    text = _redact_text(value)
    omitted = len(text) - _MAX_SNIPPET_CHARS
    if omitted > 0:
        text = f"{text[:_MAX_SNIPPET_CHARS]}\n… [{omitted} further characters omitted for readability]"
    return f'<p class="field-label">{_esc(label)}</p><pre>{html.escape(text)}</pre>'
