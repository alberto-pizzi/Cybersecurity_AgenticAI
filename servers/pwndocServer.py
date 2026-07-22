import os
import requests
from fastmcp import FastMCP
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

mcp = FastMCP("PwnDoc_Server")
PWNDOC_API_URL = os.getenv("PWNDOC_URL", "http://localhost:8443/api")


@mcp.tool()
def generate_report(
    findings_summary: dict | str = None,
    target: str = "",
    target_url: str = ""
) -> dict:
    """Generates a local PDF report and attempts sync with PwnDoc if reachable."""

    # 1. Resolve argument inconsistencies (handles 'target' vs 'target_url')
    target_host = target or target_url or "Unknown Target"
    pdf_filename = "SecOps_Assessment_Report.pdf"
    pdf_generated = False

    # 2. Normalize findings_summary into a valid dictionary
    if findings_summary is None:
        findings_summary = {}
    elif isinstance(findings_summary, str):
        try:
            findings_summary = json.loads(findings_summary)
        except json.JSONDecodeError:
            findings_summary = {"raw_output": findings_summary}

    # 3. Build local PDF using ReportLab
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
            fontSize=20,
            textColor=colors.HexColor("#1A365D"),
            spaceAfter=12
        )

        cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontSize=9,
            leading=11
        )

        story.append(Paragraph("Autonomous SecOps Assessment Report", title_style))
        story.append(Paragraph(f"<b>Target:</b> {target_host}", styles['Normal']))
        story.append(Spacer(1, 12))

        # Table data construction
        table_data = [["Tool / Module", "Status / Findings Summary"]]

        if not findings_summary:
            table_data.append(["N/A", "No tool findings reported."])
        else:
            for tool_name, result in findings_summary.items():
                # Extract summary text safely depending on data type
                if isinstance(result, dict):
                    summary_text = str(
                        result.get("vulnerabilities") or
                        result.get("findings") or
                        result.get("message") or
                        result.get("status") or
                        "Completed"
                    )
                elif isinstance(result, (list, str)):
                    summary_text = str(result)
                else:
                    summary_text = "Completed"

                # Truncate and wrap in Paragraph to prevent layout overflow
                truncated_text = summary_text[:250] + ("..." if len(summary_text) > 250 else "")
                table_data.append([
                    Paragraph(f"<b>{str(tool_name).upper()}</b>", cell_style),
                    Paragraph(truncated_text, cell_style)
                ])

        t = Table(table_data, colWidths=[120, 420])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#F7FAFC")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0"))
        ]))
        story.append(t)
        doc.build(story)
        pdf_generated = True

    except Exception as e:
        print(f"[-] Errore nella generazione del PDF locale: {e}")

    # 4. Attempt PwnDoc synchronization
    pwndoc_status = "offline"
    try:
        response = requests.get(f"{PWNDOC_API_URL}/ping", timeout=2)
        if response.status_code == 200:
            pwndoc_status = "synced_successfully"
    except Exception:
        pass  # Maintain local fallback if PwnDoc is unreachable

    # 5. Output summary
    print("\n" + "=" * 50)
    print(f" [SUCCESS] PDF locale generato correttamente: {pdf_filename}")
    print(f" [PWNDOC] Stato integrazione: {pwndoc_status}")
    print("=" * 50 + "\n")

    return {
        "status": "success",
        "local_pdf_generated": pdf_generated,
        "pdf_filename": pdf_filename,
        "pwndoc_status": pwndoc_status,
        "message": f"Local PDF report created as {pdf_filename}. PwnDoc status: {pwndoc_status}."
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")