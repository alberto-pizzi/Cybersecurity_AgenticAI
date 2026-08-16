"""The report's embedded stylesheet, kept in its own module so visual/layout
changes never require touching the HTML assembly in html_report.py.
"""

from __future__ import annotations

# Returns the report's full embedded stylesheet as a CSS string
def report_css() -> str:
    return """
@page {
    size: A4;
    margin: 10mm 0;
    background-color: #f4f6f8;
    @bottom-center {
        content: counter(page);
    }
}
.toc a::after {
    content: leader('.') target-counter(attr(href), page);
}

.toc {
    break-after: page;
}
body{font-family:Arial,sans-serif;background:#f4f6f8;color:#17212b;margin:0}
main{max-width:1220px;margin:auto;padding:28px}
h1,h2,h3{color:#173b5e}h2{margin-top:32px}
.meta,.card,.finding{background:white;border:1px solid #d7dee5;border-radius:10px;padding:16px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.value{font-size:2rem;font-weight:700}
table{table-layout:auto;width:100%;border-collapse:collapse;background:white;font-size:.74rem}
th,td{padding:5px 6px;border:1px solid #cbd5df;overflow-wrap:anywhere;word-break:break-word}
th{background:#24476b;color:white;position:sticky;top:0;white-space:nowrap}
.no-wrap{white-space:nowrap}
.idx{white-space:nowrap;width:1%;text-align:center}
small{color:#4f6273}.finding{border-left:7px solid #4b86b4}
.risk-critical,.risk-high{border-left-color:#a90000}.risk-medium{border-left-color:#d98200}.risk-low{border-left-color:#b49b00}
.badges{display: flex;flex-wrap: wrap;gap: 6px;justify-content: center;align-items: center;}
.badges b{display: inline-flex;align-items: stretch;overflow: hidden;border-radius: 12px;font-size: .82rem;font-weight: normal;box-shadow: 0 0 0 1px #d3dde5;margin: 5px}
.badges .cat{background: #3b5b7a;color: #fff;font-weight: 600;padding: 4px 8px;text-transform: uppercase;letter-spacing: .03em;font-size: .72rem;display: flex;align-items: center;}
.badges .val {background: #e8eef4;color: #1f2d3a;padding: 4px 8px;display: flex;align-items: center;}
dl{display:grid;grid-template-columns:190px minmax(0,1fr);gap:8px 14px;margin:0}
dt{font-weight:700;overflow-wrap:anywhere;min-width:0}
dd{margin:0;overflow-wrap:anywhere;word-break:break-word;min-width:0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;background:#101821;color:#e5edf5;padding:12px;border-radius:8px}
.quality{background:#fff8dc;border:1px solid #e1cb73;padding:10px;border-radius:8px}
details{margin-top:14px}.section-note{background:#eaf1f7;border-left:4px solid #527ca3;padding:10px}
.count{font-size:.85rem;background:#dce8f3;border-radius:12px;padding:3px 8px}
.toc a{color: black;text-decoration: none;}
.toc ul{list-style: none;padding-left: 0;}
.toc ul ul{padding-left: 22px;}
.toc-title{margin-top:0}
.toc>ul>li>a{font-weight:bold}
ol li::marker{font-weight:bold;}
.field-label{font-weight:700;margin:14px 0 6px;color:#173b5e}
.cover{position:relative;break-after:page;min-height:250mm;display:flex;flex-direction:column;justify-content:space-between;background:white;border:1px solid #d7dee5;border-radius:10px;padding:40px;margin:0 0 12px}
.cover-badges{position:absolute;top:0;right:0;display:flex;flex-direction:column;align-items:flex-end;gap:8px;max-width:60%;break-inside:avoid-page;page-break-inside:avoid}
.cover-classification{background:#8a1f1f;color:white;font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:.85rem;padding:6px 14px;border-radius:4px;white-space:nowrap}
.cover-risk-badge{color:white;font-weight:700;letter-spacing:.05em;text-transform:uppercase;font-size:.85rem;padding:6px 14px;border-radius:4px;white-space:nowrap}
.cover-badges div{margin-bottom:2px}
.cover-body{margin-top:70px}
.risk-banner{box-sizing:border-box;break-inside:avoid-page;page-break-inside:avoid;display:table;width:100%;background:white;border:1px solid #d7dee5;border-left:10px solid #4b86b4;border-radius:10px;padding:16px 20px;margin:12px 0}
.risk-banner-label{display:table-cell;vertical-align:middle;white-space:nowrap;color:white;font-weight:800;font-size:1.3rem;padding:8px 18px;border-radius:8px;letter-spacing:.04em}
.risk-banner-text{display:table-cell;vertical-align:middle;width:100%;padding-left:16px}
.flow{margin:14px 0;line-height:2.6}
.flow-item{display:inline-block;vertical-align:middle;white-space:nowrap;margin:0 0 8px}
.flow-step{display:inline-block;vertical-align:middle;background:#24476b;color:#fff;padding:8px 14px;border-radius:8px;font-size:.82rem;white-space:nowrap}
.flow-arrow{display:inline-block;vertical-align:middle;color:#4b86b4;font-weight:700;font-size:1.1rem;margin:0 6px}
.rating-table{table-layout:fixed}
.rating-col{width:150px}
.rating-chip{display:inline-flex;align-items:center;gap:6px;white-space:nowrap;break-inside:avoid-page;page-break-inside:avoid}
.cover-kicker{color:#4b86b4;font-weight:700;letter-spacing:.12em;text-transform:uppercase;font-size:.95rem;margin-bottom:14px}
.cover-title{font-size:2.6rem;line-height:1.15;margin:0 0 14px;max-width:80%}
.cover-subtitle{font-size:1.3rem;color:#4f6273;font-weight:600}
.cover-meta{table-layout:auto;width:auto;font-size:.9rem;margin-top:50px}
.cover-meta th{background:none;color:#4f6273;text-align:left;white-space:nowrap;border:none;border-top:1px solid #d7dee5;padding:10px 24px 10px 0}
.cover-meta td{border:none;border-top:1px solid #d7dee5;padding:10px 0;font-weight:600;overflow-wrap:anywhere;word-break:break-word}
.doc-control{background:white;border:1px solid #d7dee5;border-radius:10px;padding:24px 32px;margin:0 0 12px}
.doc-control h2{margin-top:0}
.doc-control dl{grid-template-columns:220px minmax(0,1fr)}
.disclaimer{background:#fff8f8;border:1px solid #e3b8b8;border-radius:10px;padding:28px 32px;margin:0 0 12px;break-after:page}
.disclaimer h2{margin-top:0}
.disclaimer p{line-height:1.55}
.legend-swatch{display:inline-block;flex:0 0 auto;width:10px;height:10px;border-radius:2px}
"""
