"""Heading rendering and the two-pass table-of-contents builder: headings
register themselves into a shared `toc` list as they're written, and the
index is rendered from that list once the body is fully built.
"""

from __future__ import annotations

import re

from .text_utils import _esc

# Turns heading text into a unique, URL-safe anchor slug
def _slugify(text: str, existing: set[str] = frozenset()) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-") or "section"
    if base not in existing:
        return base
    n = 2
    while f"{base}-{n}" in existing:
        n += 1
    return f"{base}-{n}"

# Renders an <hN> heading and registers it into `toc`, unless in_toc=False
def _heading(
    level: int,
    text: str,
    toc: list[tuple[int, str, str]],
    *,
    in_toc: bool = True,
    anchor: str | None = None,
    extra: str = "",
) -> str:
    slug = anchor or _slugify(text, {a for _, _, a in toc})
    if in_toc:
        toc.append((level, text, slug))
    return f'<h{level} id="{slug}">{_esc(text)}{extra}</h{level}>'

# Renders the registered headings as nested <ul> lists matching their heading levels
def _render_toc(toc: list[tuple[int, str, str]]) -> str:
    # Groups a flat (level, text, anchor) list into a nested tree by heading level
    def build(entries: list[tuple[int, str, str]]) -> list[dict]:
        nodes: list[dict] = []
        i = 0
        while i < len(entries):
            level, text, anchor = entries[i]
            j = i + 1
            while j < len(entries) and entries[j][0] > level:
                j += 1
            nodes.append({"text": text, "anchor": anchor, "children": build(entries[i + 1:j])})
            i = j
        return nodes

    # Recursively renders a node tree into nested <ul>/<li> markup
    def render(nodes: list[dict]) -> str:
        if not nodes:
            return ""
        items = "".join(
            f'<li><a href="#{n["anchor"]}">{_esc(n["text"])}</a>{render(n["children"])}</li>'
            for n in nodes
        )
        return f"<ul>{items}</ul>"

    return render(build(toc))
