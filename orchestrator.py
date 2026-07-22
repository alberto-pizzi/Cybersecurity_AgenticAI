import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Configurazione directory modelli Ollama locale
BASE_DIR = Path(__file__).parent.resolve()
SERVERS_DIR = BASE_DIR / "servers"
OLLAMA_MODELS_DIR = BASE_DIR / "ollama_models"
OLLAMA_MODELS_DIR.mkdir(exist_ok=True)
os.environ["OLLAMA_MODELS"] = str(OLLAMA_MODELS_DIR)

from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import ToolMessage


async def main():
    parser = argparse.ArgumentParser(
        description="Fully Autonomous Local SecOps Agent with Ollama & MCP"
    )
    parser.add_argument(
        "--target",
        type=str,
        default="http://127.0.0.1:3000",
        help="Target URL to assess",
    )
    args = parser.parse_args()

    print(
        f"=== INITIALIZING AUTONOMOUS OLLAMA AGENT ON: {args.target} ===",
        file=sys.stderr,
    )

    # -------------------------------------------------------------------------
    # Inizializzazione file di log condiviso su disco
    # -------------------------------------------------------------------------
    findings_file = BASE_DIR / "scan_findings.json"
    findings_log = {}

    try:
        with open(findings_file, "w", encoding="utf-8") as f:
            json.dump({}, f)
        print(f"[*] Inizializzato log dei findings su {findings_file}", file=sys.stderr)
    except Exception as e:
        print(f"[!] Errore creazione {findings_file}: {e}", file=sys.stderr)

    # Master list of server scripts
    all_servers = {
        "zap": "zapServer.py",
        "nuclei": "nucleiServer.py",
        "sqlmap": "sqlmapServer.py",
        "ffuf": "ffufServer.py",
        "nikto": "niktoServer.py",
        "dalfox": "dalfoxServer.py",
        "arjun": "arjunServer.py",
        "commix": "commixServer.py",
        "idor": "idorForgeServer.py",
        "pwndoc": "pwndocServer.py",
        "jwt": "jwtServer.py",
        "interactsh": "interactshServer.py",
    }

    server_configs = {}
    for name, script_name in all_servers.items():
        script_path = SERVERS_DIR / script_name
        if script_path.exists():
            server_configs[name] = {
                "transport": "stdio",
                "command": sys.executable,
                "args": [str(script_path)],
            }
        else:
            print(
                f"[!] Skipping '{name}': file not found at {script_path}",
                file=sys.stderr,
            )

    print("[*] Connecting to existing MCP tool servers...", file=sys.stderr)

    tools = []
    for name, config in server_configs.items():
        print(f"[*] Loading MCP server '{name}'...", file=sys.stderr)
        try:
            single_client = MultiServerMCPClient({name: config})
            server_tools = await single_client.get_tools()
            tools.extend(server_tools)
            print(
                f"    [+] '{name}' connected ({len(server_tools)} tools active).",
                file=sys.stderr,
            )
        except Exception as e:
            print(f"    [!] Server '{name}' failed to load: {e}", file=sys.stderr)

    if not tools:
        print("[-] Critical Error: No tools loaded. Exiting.", file=sys.stderr)
        return

    print(
        f"\n[+] Total tools registered with LangGraph: {len(tools)}",
        file=sys.stderr,
    )

    model = ChatOllama(
        model="llama3.1",
        temperature=0,
        base_url="http://localhost:11434",
    )

    system_prompt = (
        "You are an automated security testing agent operating under strict phase constraints.\n\n"
        "PHASE 1 — SCANNING (MANDATORY FIRST STEP):\n"
        "- You MUST call available active scanning tools (such as zap, nuclei, ffuf, nikto, sqlmap, etc.) against the target.\n"
        "- Run scans step-by-step. If a tool fails, times out, or finishes, proceed to another available scanning tool.\n"
        "- NEVER call 'generate_report' during Phase 1.\n\n"
        "PHASE 2 — REPORTING (FINAL STEP ONLY):\n"
        "- ONLY call 'generate_report' AFTER you have executed scanning tools in Phase 1.\n"
        "- Pass the collected scan outputs as 'findings_summary'."
    )

    agent = create_react_agent(model, tools, prompt=system_prompt)

    query = (
        f"Execute a full security scan on target: {args.target}.\n"
        "1. Start by running active vulnerability scan tools against the target.\n"
        "2. Once scan tools have executed, call 'generate_report' to create the final PDF report."
    )

    print(f"\n[AGENT PROMPT]: {query}\n", file=sys.stderr)
    print("[*] Agent executing...\n", file=sys.stderr)

    async for chunk in agent.astream(
        {"messages": [("user", query)]}, stream_mode="values"
    ):
        messages = chunk.get("messages", [])

        # -------------------------------------------------------------------------
        # FIX: Scansione completa della cronologia messaggi per salvare ogni ToolMessage
        # -------------------------------------------------------------------------
        for msg in messages:
            if isinstance(msg, ToolMessage) or getattr(msg, "type", "") == "tool":
                tool_name = getattr(msg, "name", "unknown_tool")

                # Ignora generate_report per non salvare il report come finding
                if tool_name != "generate_report":
                    findings_log[tool_name] = msg.content

        # Salva i findings aggiornati su disco
        try:
            with open(findings_file, "w", encoding="utf-8") as f:
                json.dump(findings_log, f, indent=2)
        except Exception as e:
            print(f"[!] Errore aggiornamento {findings_file}: {e}", file=sys.stderr)

        latest_message = messages[-1] if messages else None
        if latest_message and hasattr(latest_message, "tool_calls") and latest_message.tool_calls:
            for tc in latest_message.tool_calls:
                print(
                    f"[NATIVE TOOL CALL]: {tc['name']} -> {tc['args']}",
                    file=sys.stderr,
                )
        elif latest_message:
            latest_message.pretty_print()


if __name__ == "__main__":
    asyncio.run(main())