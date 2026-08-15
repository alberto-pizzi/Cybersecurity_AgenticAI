"""Small `<dl>`/list building blocks shared by the finding cards and the
assessment-context summary.
"""

from __future__ import annotations

import html
from typing import Any

from .text_utils import _esc, _redact_text

_MAX_SNIPPET_CHARS = 3000


def _render_list(values: list[str]) -> str:
    return "" if not values else "<ul>" + "".join(f"<li>{_esc(value)}</li>" for value in values) + "</ul>"


def _field(label: str, value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    return f"<dt>{_esc(label)}</dt><dd>{_esc(value)}</dd>"


def _snippet_field(label: str, value: Any) -> str:
    """Render a code/evidence snippet as its own full-width block (label stacked
    above the <pre>), deliberately outside the `<dl>` grid. WeasyPrint's CSS Grid
    support gets dramatically slower once spanning items are mixed into a grid,
    so this uses plain block flow instead - the same pattern already used for
    the Identifiers/References lists.

    Also caps the snippet length: raw evidence (full HTTP responses, scanner
    JSON dumps) can run to several KB, which buries the actual proof point in
    boilerplate rather than clarifying it.
    """
    if value in (None, "", [], {}):
        return ""
    text = _redact_text(value)
    omitted = len(text) - _MAX_SNIPPET_CHARS
    if omitted > 0:
        text = f"{text[:_MAX_SNIPPET_CHARS]}\n… [{omitted} further characters omitted for readability]"
    return f'<p class="field-label">{_esc(label)}</p><pre>{html.escape(text)}</pre>'
