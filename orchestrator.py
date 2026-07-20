import asyncio
import json
import sys
from pathlib import Path
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

# Risoluzione dinamica del percorso del server ZAP (gestisce sia zap_server.py che zapServer.py)
BASE_DIR = Path(__file__).parent.resolve()
ZAP_SERVER_PATH = BASE_DIR / "servers" / "zap_server.py"
if not ZAP_SERVER_PATH.exists():
    ZAP_SERVER_PATH = BASE_DIR / "servers" / "zapServer.py"


# Definizione dello stato dell'agente
class AgentState(TypedDict):
    target: str
    standardized_json_data: dict
    final_output_status: str


# NODO 1: Interazione con l'MCP Server di ZAP
async def scan_phase(state: AgentState) -> dict:
    print("\n--- [ORCHESTRATORE] Fase 1: Chiamata al server MCP ZAP via stdio ---")

    if not ZAP_SERVER_PATH.exists():
        raise FileNotFoundError(
            f"ERRORE CRITICO: Impossibile trovare il file del server nella cartella '{BASE_DIR / 'servers'}'. "
            "Assicurati che zap_server.py (o zapServer.py) sia presente!"
        )

    # Definizione esplicita del trasporto STDIO per FastMCP
    transport = StdioTransport(
        command=sys.executable,
        args=[str(ZAP_SERVER_PATH)]
    )

    async with Client(transport) as client:
        # Invocazione del tool registrato nel server ZAP
        data_received = await client.call_tool("run_pentest_scan", {"target_url": state["target"]})

        # Estrazione e parsing della risposta
        if hasattr(data_received, "content") and isinstance(data_received.content, list):
            data_received = json.loads(data_received.content[0].text)
        elif isinstance(data_received, str):
            data_received = json.loads(data_received)

        return {"standardized_json_data": data_received}


# NODO 2: Elaborazione e Output
async def print_phase(state: AgentState) -> dict:
    print("\n--- [ORCHESTRATORE] Fase 2: Elaborazione ed output dei risultati ---")

    json_dati = state["standardized_json_data"]

    print("\n================== JSON STANDARDIZZATO GENERATO ==================")
    print(json.dumps(json_dati, indent=4, ensure_ascii=False))
    print("==================================================================\n")

    vulns = json_dati.get("vulnerabilities", [])
    print(f"Riepilogo Finale: Rilevate {len(vulns)} segnalazioni su {json_dati.get('target', 'N/D')}.")

    return {"final_output_status": "Flusso completato con successo!"}


# --- ASSEMBLAGGIO GRAFO LANGGRAPH ---
builder = StateGraph(AgentState)
builder.add_node("attacca_target", scan_phase)
builder.add_node("stampa_risultati", print_phase)

builder.add_edge(START, "attacca_target")
builder.add_edge("attacca_target", "stampa_risultati")
builder.add_edge("stampa_risultati", END)

orchestrator_agent = builder.compile()


async def main():
    # Usa host.docker.internal in modo che il container ZAP possa raggiungere Juice Shop sul tuo host
    inputs = {"target": "http://host.docker.internal:3000"}
    print("=== AVVIO AGENTE AUTOMATIZZATO SU PYCHARM ===")
    risultato = await orchestrator_agent.ainvoke(inputs)
    print(f"\nStato Uscita Grafo: {risultato['final_output_status']}")


if __name__ == "__main__":
    asyncio.run(main())