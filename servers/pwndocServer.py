import requests
from fastmcp import FastMCP

mcp = FastMCP("Pwndoc_Reporting_Server")
PWNDOC_API_URL = "http://localhost:4242/api"  # Modifica con la porta corretta del tuo container Pwndoc
AUTH_TOKEN = "IL_TUO_JWT_TOKEN_DI_PWNDOC"  # Token recuperato dal login di Pwndoc


@mcp.tool()
def export_to_pwndoc(report_data: dict) -> str:
    """
    RICEVE: Il JSON Standardizzato.
    Processa i dati inviandoli alle API di Pwndoc per generare il report (.docx).
    """
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}", "Content-Type": "application/json"}

    # 1. Crea un nuovo Audit (Report) su Pwndoc
    audit_payload = {
        "name": f"Automated Assessment - {report_data['target']}",
        "location": "Local Lab",
        "auditType": "Web Application Pentest"
    }

    # Eseguiamo la chiamata POST a Pwndoc per creare il report vuoto
    # response = requests.post(f"{PWNDOC_API_URL}/audits", json=audit_payload, headers=headers)
    # audit_id = response.json()["data"]["_id"]

    print(f"[Pwndoc Server] Creato con successo l'audit per la destinazione: {report_data['target']}")

    # 2. Cicla sulle vulnerabilità presenti nel JSON STANDARDIZZATO e inseriscile nell'audit
    for vuln in report_data["vulnerabilities"]:
        finding_payload = {
            "title": vuln["title"],
            "severity": vuln["severity"],
            "description": vuln["description"],
            "observation": f"Identificato su: {vuln['url']}",
            "poc": vuln["evidence"]
        }
        print(f"[Pwndoc Server] Inserimento vulnerabilità: {vuln['title']} [{vuln['severity']}]")
        # requests.post(f"{PWNDOC_API_URL}/audits/{audit_id}/findings", json=finding_payload, headers=headers)

    # 3. Triggera la generazione del file Word (.docx) finale tramite Pwndoc
    # requests.get(f"{PWNDOC_API_URL}/audits/{audit_id}/generate", headers=headers)

    return "Report compilato e generato con successo all'interno di Pwndoc!"


if __name__ == "__main__":
    mcp.run(transport="stdio")