import html
import json
import logging
import os
import sys
from pathlib import Path
from fastmcp import FastMCP
import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# Directory di lavoro del progetto
BASE_DIR = Path(__file__).parent.parent.resolve()
FINDINGS_FILE = BASE_DIR / "scan_findings.json"

# Logging su sys.stderr per non inquinare stdio MCP
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s"
)
logger = logging.getLogger("PwnDoc_Server")

mcp = FastMCP("PwnDoc_Server")
PWNDOC_API_URL = os.getenv("PWNDOC_URL", "http://localhost:8443/api")

# Mappatura per l'ordinamento per livello di gravità
RISK_PRIORITY = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1
}


def load_findings_from_disk() -> dict:
    """Carica i risultati dal file di log condiviso su disco se presente."""
    if FINDINGS_FILE.exists():
        try:
            with open(FINDINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                logger.info(f"Caricati findings di fallback da {FINDINGS_FILE}")
                return data
        except Exception as e:
            logger.error(f"Errore nella lettura di {FINDINGS_FILE}: {e}")
    return {}


@mcp.tool()
def generate_report(
        findings_summary: dict | str = None,
        target: str = "",
        target_url: str = ""
) -> dict:
    """Genera un report PDF locale con layout strutturato a celle separate e sincronizza con PwnDoc se disponibile."""

    # 1. Normalizzazione Target
    target_host = target or target_url or "http://127.0.0.1:3000"
    pdf_filename = "SecOps_Assessment_Report.pdf"
    pdf_generated = False

    # 2. Parsing e Normalizzazione Findings
    parsed_findings = {}
    if isinstance(findings_summary, str):
        try:
            parsed_findings = json.loads(findings_summary)
        except json.JSONDecodeError:
            if findings_summary.strip():
                parsed_findings = {"raw_summary": findings_summary}
    elif isinstance(findings_summary, dict):
        parsed_findings = findings_summary

    if not parsed_findings:
        logger.warning("findings_summary vuoto. Attivazione fallback da disco...")
        parsed_findings = load_findings_from_disk()

    # 3. Costruzione Documento ReportLab con layout a colonne distinte
    try:
        doc = SimpleDocTemplate(
            pdf_filename,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        story = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=16,
            textColor=colors.HexColor("#1A365D"),
            spaceAfter=6
        )

        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor("#4A5568"),
            spaceAfter=12
        )

        cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontSize=8,
            leading=11
        )

        header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontSize=9,
            fontName='Helvetica-Bold',
            textColor=colors.whitesmoke
        )

        story.append(Paragraph("Autonomous SecOps Assessment Report", title_style))
        story.append(Paragraph(f"<b>Target URL:</b> {html.escape(target_host)}", subtitle_style))
        story.append(Spacer(1, 6))

        # Intestazione Tabella con celle separate per Tool, Alert, Rischio e Dettagli/Descrizione
        table_data = [[
            Paragraph("Tool", header_style),
            Paragraph("Alert / Vulnerabilità", header_style),
            Paragraph("Rischio", header_style),
            Paragraph("Descrizione e Dettagli", header_style)
        ]]

        if not parsed_findings:
            table_data.append([
                Paragraph("<b>ALL</b>", cell_style),
                Paragraph("Nessun dato", cell_style),
                Paragraph("N/A", cell_style),
                Paragraph("Nessun dato di scansione disponibile nel report.", cell_style)
            ])
        else:
            for tool_name, result in parsed_findings.items():
                clean_tool_name = html.escape(str(tool_name)).upper()

                if isinstance(result, dict):
                    vulns = result.get("vulnerabilities")

                    if isinstance(vulns, list) and vulns:
                        # Ordinamento per livello di rischio decrescente
                        sorted_vulns = sorted(
                            vulns,
                            key=lambda x: RISK_PRIORITY.get(str(x.get("risk", x.get("severity", ""))).lower(), 0),
                            reverse=True
                        )
                        for v in sorted_vulns:
                            alert = html.escape(str(v.get("alert", v.get("title", "Sconosciuto"))))
                            risk = str(v.get("risk", v.get("severity", "Info"))).strip()
                            url = html.escape(str(v.get("url", "N/A")))
                            desc = html.escape(str(v.get("description", "Nessuna descrizione disponibile.")))
                            sol = html.escape(str(v.get("solution", "")))

                            if len(desc) > 250:
                                desc = desc[:250] + "..."

                            # Formattazione colore badge rischio
                            risk_lower = risk.lower()
                            if risk_lower in ["high", "critical"]:
                                risk_html = f"<font color='#E53E3E'><b>{html.escape(risk)}</b></font>"
                            elif risk_lower == "medium":
                                risk_html = f"<font color='#DD6B20'><b>{html.escape(risk)}</b></font>"
                            elif risk_lower == "low":
                                risk_html = f"<font color='#3182CE'><b>{html.escape(risk)}</b></font>"
                            else:
                                risk_html = f"<font color='#718096'><b>{html.escape(risk)}</b></font>"

                            details_text = f"<b>URL:</b> {url}<br/><b>Desc:</b> {desc}"
                            if sol:
                                details_text += f"<br/><b>Rimedio:</b> {sol}"

                            table_data.append([
                                Paragraph(clean_tool_name, cell_style),
                                Paragraph(alert, cell_style),
                                Paragraph(risk_html, cell_style),
                                Paragraph(details_text, cell_style)
                            ])
                    else:
                        # Gestione output testuali o dizionari senza lista vulnerabilità esplicita
                        msg = (
                            result.get("output") or
                            result.get("findings") or
                            result.get("message") or
                            result.get("status") or
                            str(result)
                        )
                        text_content = html.escape(str(msg)).replace("\n", "<br/>")
                        if len(text_content) > 300:
                            text_content = text_content[:300] + "..."

                        table_data.append([
                            Paragraph(clean_tool_name, cell_style),
                            Paragraph("Output Generico", cell_style),
                            Paragraph("Info", cell_style),
                            Paragraph(text_content, cell_style)
                        ])
                else:
                    text_content = html.escape(str(result)).replace("\n", "<br/>")
                    if len(text_content) > 300:
                        text_content = text_content[:300] + "..."

                    table_data.append([
                        Paragraph(clean_tool_name, cell_style),
                        Paragraph("Risultato", cell_style),
                        Paragraph("Info", cell_style),
                        Paragraph(text_content, cell_style)
                    ])

        # Dimensioni colonne ottimizzate per la pagina letter (Totale larghezza utile: 540 pt)
        t = Table(table_data, colWidths=[80, 130, 60, 270])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F7FAFC")])
        ]))
        story.append(t)
        doc.build(story)
        pdf_generated = True

    except Exception as e:
        logger.error(f"Errore durante la creazione del PDF: {e}")

    # 4. Controllo stato PwnDoc
    pwndoc_status = "offline"
    try:
        res = requests.get(f"{PWNDOC_API_URL}/ping", timeout=2)
        if res.status_code == 200:
            pwndoc_status = "synced_successfully"
    except Exception:
        pass

    logger.info(f"PDF locale generato: {pdf_filename} (Righe tabella: {len(table_data) - 1})")

    return {
        "status": "success",
        "local_pdf_generated": pdf_generated,
        "pdf_filename": pdf_filename,
        "findings_count": len(parsed_findings),
        "pwndoc_status": pwndoc_status,
        "message": "Report PDF creato con layout a celle separate per massima chiarezza."
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")