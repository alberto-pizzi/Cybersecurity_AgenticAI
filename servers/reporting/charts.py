"""Hand-built inline-SVG/HTML visuals - no external plotting library, no
network fetch - so they render identically in-browser and through
WeasyPrint's PDF pipeline.
"""

from __future__ import annotations

from typing import Any

from .text_utils import _esc

# Renders the executed orchestration phases as an arrow-connected step flow
def _render_pipeline_diagram(nodes: list[Any]) -> str:
    labels = [str(node).strip() for node in (nodes or []) if str(node).strip()]
    if not labels:
        return ""
    items: list[str] = []
    for index, label in enumerate(labels):
        arrow = '<span class="flow-arrow">&#8594;</span>' if index > 0 else ""
        items.append(f'<span class="flow-item">{arrow}<span class="flow-step">{_esc(label)}</span></span>')
    return f'<div class="flow">{"".join(items)}</div>'

# Renders a hand-built inline-SVG horizontal bar chart of findings by severity
def _svg_severity_chart(risks: dict[str, int]) -> str:
    levels = (
        ("Critical", "critical", "#7a0000"),
        ("High", "high", "#a90000"),
        ("Medium", "medium", "#d98200"),
        ("Low", "low", "#b49b00"),
        ("Info", "info", "#4b86b4"),
    )
    values = [(label, color, int(risks.get(key, 0) or 0)) for label, key, color in levels]
    max_value = max((v for _, _, v in values), default=0) or 1
    width, row_h, gap, label_w, pad, track_w = 640, 26, 10, 70, 10, 460
    height = pad * 2 + len(values) * (row_h + gap) - gap
    bars: list[str] = [f'<rect x="0" y="0" width="{width}" height="{height}" fill="white"/>']
    y = pad
    for label, color, value in values:
        bar_w = max(2, round(track_w * value / max_value)) if value else 2
        bars.append(f'<text x="0" y="{y + row_h * 0.68:.1f}" font-size="12" fill="#17212b" font-family="Arial,sans-serif">{_esc(label)}</text>')
        bars.append(f'<rect x="{label_w}" y="{y}" width="{bar_w}" height="{row_h - 6}" rx="4" fill="{color}" opacity="{1 if value else 0.25}"/>')
        bars.append(f'<text x="{label_w + bar_w + 8}" y="{y + row_h * 0.68:.1f}" font-size="12" fill="#17212b" font-family="Arial,sans-serif">{value}</text>')
        y += row_h + gap
    body = "".join(bars)
    return f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Findings by severity">{body}</svg>'
