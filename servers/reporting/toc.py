"""Heading rendering and the two-pass table-of-contents builder: headings
register themselves into a shared `toc` list as they're written, and the
index is rendered from that list once the body is fully built.
"""

from __future__ import annotations

import re

from .text_utils import _esc


def _slugify(text: str, existing: set[str] = frozenset()) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-") or "section"
    if base not in existing:
        return base
    n = 2
    while f"{base}-{n}" in existing:
        n += 1
    return f"{base}-{n}"


def _heading(
    level: int,
    text: str,
    toc: list[tuple[int, str, str]],
    *,
    in_toc: bool = True,
    anchor: str | None = None,
    extra: str = "",
) -> str:
    """Render an <hN> heading and, LaTeX-style, register it into `toc` at the
    moment it is written — writing the heading here is what puts it in the
    table of contents, in this position, in document order. No separate
    list to keep in sync by hand.

    `in_toc=False` is the equivalent of LaTeX's starred `\\section*{}`: the
    heading still gets an anchor (so it can still be linked to), it just
    doesn't get an index entry. Use it for headings that repeat once per
    data row (e.g. one <h3> per finding) — there can be hundreds of those,
    and listing each one would make the index useless for navigation.

    `extra` is raw HTML appended after the escaped title, inside the same
    tag (e.g. a count badge <span>), without leaking into the TOC label.
    """
    slug = anchor or _slugify(text, {a for _, _, a in toc})
    if in_toc:
        toc.append((level, text, slug))
    return f'<h{level} id="{slug}">{_esc(text)}{extra}</h{level}>'


def _render_toc(toc: list[tuple[int, str, str]]) -> str:
    """Render registered (level, text, anchor) entries as nested <ul> lists,
    matching how headings were nested when they were written (h2 under h2,
    h3 nested one level deeper under the preceding h2, etc.) - the same
    structure a LaTeX \\tableofcontents would produce from \\section /
    \\subsection.
    """
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

    def render(nodes: list[dict]) -> str:
        if not nodes:
            return ""
        items = "".join(
            f'<li><a href="#{n["anchor"]}">{_esc(n["text"])}</a>{render(n["children"])}</li>'
            for n in nodes
        )
        return f"<ul>{items}</ul>"

    return render(build(toc))
