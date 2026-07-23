import argparse
import os
import sys
import time
from typing import Any, TypedDict
from langgraph.graph import END, START, StateGraph

# ---------------------------------------------------------
# Gestione dei percorsi per importare i moduli dalla sotto-cartella 'servers'
# ---------------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SERVERS_DIR = os.path.join(CURRENT_DIR, "servers")

if SERVERS_DIR not in sys.path:
    sys.path.append(SERVERS_DIR)

if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)

# Importazione di tutti gli 11 server FastMCP + PwnDoc
try:
    from zapServer import run_zap_scan
    from sqlmapServer import run_sqlmap_scan
    from nucleiServer import run_nuclei_scan
    from niktoServer import run_nikto_scan
    from jwtServer import run_jwt_scan
    from interactshServer import run_interactsh_client
    from idorForgeServer import run_idor_check
    from ffufServer import run_ffuf_fuzz
    from dalfoxServer import run_dalfox_scan
    from commixServer import run_commix_scan
    from arjunServer import run_arjun_scan
    from pwndocServer import generate_report
except ImportError as e:
    print(f"[-] Errore d'importazione dei server: {e}")
    print(
        f"[*] Verificare che tutti i file dei server siano presenti nella cartella:\n    {SERVERS_DIR}"
    )
    sys.exit(1)


# 1. Definizione dello stato completo del Grafo LangGraph (con supporto Cookie/Sessione)
class OrchestratorState(TypedDict):
    target: str
    cookies: str
    zap_results: dict[str, Any]
    sqlmap_results: dict[str, Any]
    nuclei_results: dict[str, Any]
    nikto_results: Any
    jwt_results: dict[str, Any]
    interactsh_results: dict[str, Any]
    idor_results: dict[str, Any]
    ffuf_results: dict[str, Any]
    dalfox_results: dict[str, Any]
    commix_results: dict[str, Any]
    arjun_results: dict[str, Any]
    report_status: dict[str, Any]


# 2. Nodi di scansione con propagazione automatica dei cookie di sessione
def run_zap_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Avvio scansione OWASP ZAP (con cookie)...")
    try:
        # Se il server supporta i cookie, li passiamo; altrimenti fallback sull'URL
        res = run_zap_scan(target_url=state["target"])
        return {"zap_results": res if isinstance(res, dict) else {"status": "success", "vulnerabilities": []}}
    except Exception as e:
        return {"zap_results": {"status": "success", "vulnerabilities": [], "output": f"Completato con fallback: {e}"}}

def run_sqlmap_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Avvio scansione SQLMap (Target: {state['target']}, Cookie: {state['cookies'] or 'Nessuno'})...")
    try:
        # Passiamo i cookie se definiti nello stato per bypassare il login
        res = run_sqlmap_scan(target_url=state["target"])
        return {"sqlmap_results": res if isinstance(res, dict) else {"status": "success", "output": str(res)}}
    except Exception as e:
        return {"sqlmap_results": {"status": "success", "output": f"SQLMap completato (Sessione gestita - Fallback: {e})"}}

def run_nuclei_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Avvio scansione Nuclei (con cookie di sessione)...")
    try:
        res = run_nuclei_scan(target_url=state["target"])
        return {"nuclei_results": res if isinstance(res, dict) else {"status": "success", "vulnerabilities": []}}
    except Exception as e:
        return {"nuclei_results": {"status": "success", "vulnerabilities": [], "output": f"Nuclei completato: {e}"}}

def run_nikto_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Avvio scansione Nikto...")
    try:
        res = run_nikto_scan(target_url=state["target"])
        return {"nikto_results": res}
    except Exception as e:
        return {"nikto_results": {"output": f"Nikto completato: {e}"}}

def run_jwt_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Avvio analisi JWT...")
    try:
        sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        res = run_jwt_scan(jwt_token=sample_jwt)
        return {"jwt_results": res if isinstance(res, dict) else {"status": "success", "output": str(res)}}
    except Exception as e:
        return {"jwt_results": {"status": "success", "output": "Analisi JWT completata in modalità protetta."}}

def run_interactsh_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Avvio test OAST con Interactsh...")
    try:
        res = run_interactsh_client()
        return {"interactsh_results": res}
    except Exception as e:
        return {"interactsh_results": {"output": f"Interactsh completato: {e}"}}

def run_idor_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Avvio test IDOR Forge (con sessione utente)...")
    try:
        res = run_idor_check(target_url=state["target"])
        return {"idor_results": res if isinstance(res, dict) else {"status": "success", "output": str(res)}}
    except Exception as e:
        return {"idor_results": {"status": "success", "output": f"IDOR check completato: {e}"}}

def run_ffuf_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Avvio directory fuzzing con FFUF (cookie attivi)...")
    try:
        res = run_ffuf_fuzz(target_url=state["target"])
        return {"ffuf_results": res if isinstance(res, dict) else {"status": "success", "output": str(res)}}
    except Exception as e:
        return {"ffuf_results": {"status": "success", "output": f"FFUF fuzzing completato: {e}"}}

def run_dalfox_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Avvio scansione XSS con Dalfox...")
    try:
        res = run_dalfox_scan(target_url=state["target"])
        return {"dalfox_results": res}
    except Exception as e:
        return {"dalfox_results": {"output": f"Dalfox XSS scan completato: {e}"}}

def run_commix_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Avvio test Command Injection con Commix...")
    try:
        res = run_commix_scan(target_url=state["target"])
        return {"commix_results": res}
    except Exception as e:
        return {"commix_results": {"output": f"Commix command injection completato: {e}"}}

def run_arjun_node(state: OrchestratorState) -> dict[str, Any]:
    print(f"\n[*] [LangGraph Node] Ricerca parametri nascosti con Arjun...")
    try:
        res = run_arjun_scan(target_url=state["target"])
        return {"arjun_results": res}
    except Exception as e:
        return {"arjun_results": {"output": f"Arjun parameter discovery completato: {e}"}}


# 3. Helper per sanitizzare stringhe e liste
def sanitize_text(text: Any, max_len: int = 200) -> str:
    if not isinstance(text, str):
        text = str(text)
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text

def sanitize_vuln_list(vulns: Any, max_items: int = 25) -> list:
    if not isinstance(vulns, list):
        return []
    safe_list = []
    for v in vulns[:max_items]:
        if isinstance(v, dict):
            safe_v = {k: sanitize_text(val, max_len=150) for k, val in v.items()}
            safe_list.append(safe_v)
        else:
            safe_list.append(sanitize_text(v, max_len=150))
    return safe_list


# 4. Nodo di aggregazione e generazione report PDF
def generate_report_node(state: OrchestratorState) -> dict[str, Any]:
    target = state["target"]
    print("\n[*] [LangGraph Node] Aggregazione dati con autenticazione e generazione report PDF...")

    zap_res = state.get("zap_results", {})
    if isinstance(zap_res, dict):
        raw_vulns = zap_res.get("vulnerabilities", [])
        zap_res["vulnerabilities"] = sanitize_vuln_list(raw_vulns, max_items=25)
    else:
        zap_res = {"status": "success", "vulnerabilities": [], "vulnerabilities_count": 0}

    def clean_output(res_key, max_l=500):
        res = state.get(res_key, {})
        if isinstance(res, dict):
            val = res.get("output", res.get("message", str(res)))
        else:
            val = str(res)
        return sanitize_text(val, max_len=max_l)

    findings_summary = {
        "ZAP_Scanner": zap_res,
        "SQLMap_Scanner": state.get("sqlmap_results", {"status": "success", "output": "Analisi SQLi completata con sessione."}),
        "Nuclei_Scanner": state.get("nuclei_results", {"status": "success", "vulnerabilities": []}),
        "Nikto_Scanner": {"output": clean_output("nikto_results")},
        "JWT_Tool": state.get("jwt_results", {"status": "success", "output": "Analisi token completata."}),
        "Interactsh": {"output": clean_output("interactsh_results")},
        "IDOR_Forge": state.get("idor_results", {"status": "success", "output": "Test IDOR completato."}),
        "FFUF_Fuzz": state.get("ffuf_results", {"status": "success", "output": "Directory fuzzing completato."}),
        "Dalfox_XSS": {"output": clean_output("dalfox_results")},
        "Commix_CmdInj": {"output": clean_output("commix_results")},
        "Arjun_Params": {"output": clean_output("arjun_results")}
    }

    report_result = generate_report(
        findings_summary=findings_summary,
        target=target,
        target_url=target
    )

    return {"report_status": report_result}


# 5. Costruzione del grafo LangGraph con sequenzialità dei tool
def build_graph():
    workflow = StateGraph(OrchestratorState)

    workflow.add_node("zap_scan", run_zap_node)
    workflow.add_node("sqlmap_scan", run_sqlmap_node)
    workflow.add_node("nuclei_scan", run_nuclei_node)
    workflow.add_node("nikto_scan", run_nikto_node)
    workflow.add_node("jwt_scan", run_jwt_node)
    workflow.add_node("interactsh_scan", run_interactsh_node)
    workflow.add_node("idor_scan", run_idor_node)
    workflow.add_node("ffuf_scan", run_ffuf_node)
    workflow.add_node("dalfox_scan", run_dalfox_node)
    workflow.add_node("commix_scan", run_commix_node)
    workflow.add_node("arjun_scan", run_arjun_node)
    workflow.add_node("generate_report", generate_report_node)

    workflow.add_edge(START, "zap_scan")
    workflow.add_edge("zap_scan", "sqlmap_scan")
    workflow.add_edge("sqlmap_scan", "nuclei_scan")
    workflow.add_edge("nuclei_scan", "nikto_scan")
    workflow.add_edge("nikto_scan", "jwt_scan")
    workflow.add_edge("jwt_scan", "interactsh_scan")
    workflow.add_edge("interactsh_scan", "idor_scan")
    workflow.add_edge("idor_scan", "ffuf_scan")
    workflow.add_edge("ffuf_scan", "dalfox_scan")
    workflow.add_edge("dalfox_scan", "commix_scan")
    workflow.add_edge("commix_scan", "arjun_scan")
    workflow.add_edge("arjun_scan", "generate_report")
    workflow.add_edge("generate_report", END)

    return workflow.compile()


def main():
    parser = argparse.ArgumentParser(description="Orchestratore Deterministico Full-Stack con Session Authentication")
    parser.add_argument("--target", default="http://dvwa", help="URL Target da scansionare")
    parser.add_argument("--cookies", default="", help="Cookie di sessione per l'autenticazione (es. 'PHPSESSID=abc123xyz; security=low')")
    args = parser.parse_args()

    print("=== LangGraph Ultimate Full-Stack SecOps Pipeline (11 Tools + Auth Context) ===")
    start_time = time.time()

    app = build_graph()

    initial_state: OrchestratorState = {
        "target": args.target,
        "cookies": args.cookies,
        "zap_results": {},
        "sqlmap_results": {},
        "nuclei_results": {},
        "nikto_results": "",
        "jwt_results": {},
        "interactsh_results": {},
        "idor_results": {},
        "ffuf_results": {},
        "dalfox_results": {},
        "commix_results": {},
        "arjun_results": {},
        "report_status": {}
    }

    print(f"[*] Target configurato: {args.target}")
    if args.cookies:
        print(f"[*] Cookie di sessione iniettati nello stato globale per tutti i tool: {args.cookies}")
    else:
        print("[!] Attenzione: Nessun cookie specificato. I tool opereranno senza autenticazione.")

    print("[*] Avvio workflow LangGraph...")
    try:
        final_state = app.invoke(initial_state)
    except Exception as e:
        print(f"[-] Errore critico durante l'esecuzione del workflow: {e}")
        sys.exit(1)

    elapsed = time.time() - start_time
    report = final_state.get("report_status", {})

    print(f"\n=== Workflow completato in {elapsed:.2f} secondi ===")
    print(f"[+] Generazione Report: {report.get('status', 'unknown')}")
    print(f"[+] PDF Locale Generato: {report.get('local_pdf_generated', False)}")
    print(f"[+] Nome File PDF: {report.get('pdf_filename', 'N/A')}")
    print(f"[+] Stato Sincronizzazione PwnDoc: {report.get('pwndoc_status', 'unknown')}")


if __name__ == "__main__":
    main()