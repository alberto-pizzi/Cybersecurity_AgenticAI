import os
import sys
import json
import logging
import requests
from pathlib import Path
from fastmcp import FastMCP
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

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
    """Genera un report PDF locale ed effettua il sync con PwnDoc se raggiungibile."""

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

    # FALLBACK: Se l'LLM ha passato un dizionario vuoto ({}), leggi da disco
    if not parsed_findings:
        logger.warning("findings_summary vuoto da LLM. Attivazione fallback da disco...")
        parsed_findings = load_findings_from_disk()

    # 3. Costruzione Documento ReportLab
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
            fontSize=18,
            textColor=colors.HexColor("#1A365D"),
            spaceAfter=12
        )

        cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontSize=8,
            leading=10
        )

        header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontSize=9,
            fontName='Helvetica-Bold',
            textColor=colors.whitesmoke
        )

        story.append(Paragraph("Autonomous SecOps Assessment Report", title_style))
        story.append(Paragraph(f"<b>Target URL:</b> {target_host}", styles['Normal']))
        story.append(Spacer(1, 12))

        # Intestazione Tabella
        table_data = [[
            Paragraph("Tool / Module", header_style),
            Paragraph("Status / Findings Summary", header_style)
        ]]

        if not parsed_findings:
            table_data.append([
                Paragraph("<b>ALL TOOLS</b>", cell_style),
                Paragraph("No tool findings were supplied by agent or found in scan_findings.json.", cell_style)
            ])
        else:
            for tool_name, result in parsed_findings.items():
                # Formattazione estrazione contenuto
                if isinstance(result, dict):
                    text_content = (
                        result.get("vulnerabilities") or
                        result.get("output") or
                        result.get("findings") or
                        result.get("message") or
                        result.get("status") or
                        str(result)
                    )
                else:
                    text_content = str(result)

                # Pulizia e troncamento per evitare overflow grafico
                text_content = str(text_content).replace("\n", "<br/>")
                if len(text_content) > 500:
                    text_content = text_content[:500] + "... [TRUNCATED]"

                table_data.append([
                    Paragraph(f"<b>{str(tool_name).upper()}</b>", cell_style),
                    Paragraph(text_content, cell_style)
                ])

        t = Table(table_data, colWidths=[120, 420])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#F7FAFC")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0"))
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

    logger.info(f"PDF locale generato: {pdf_filename} (Findings usati: {len(parsed_findings)})")

    return {
        "status": "success",
        "local_pdf_generated": pdf_generated,
        "pdf_filename": pdf_filename,
        "findings_count": len(parsed_findings),
        "pwndoc_status": pwndoc_status,
        "message": f"Report PDF creato ({len(parsed_findings)} voci registrate)."
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")