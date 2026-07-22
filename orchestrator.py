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
    # FIX A: Inizializzazione file di log condiviso su disco
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

    # Dynamically verify file existence to prevent TaskGroup sub-exception crashes
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

    print(
        "[*] Connecting to existing MCP tool servers...",
        file=sys.stderr,
    )

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
        "You are an automated security testing agent.\n"
        "STRICT INSTRUCTIONS:\n"
        "1. Native Tool Execution ONLY: Do NOT output text JSON blocks or explanations. Call tools natively.\n"
        "2. Error Resilience: If a tool fails or times out, ignore the error and invoke the next tool.\n"
        "3. Complete Assessment: Run available discovery and scanning tools before calling 'generate_report'.\n"
        "4. Final Step: Invoke 'generate_report' with 'target' and 'findings_summary'."
    )

    agent = create_react_agent(model, tools, prompt=system_prompt)

    query = (
        f"Perform a full security scan on target: {args.target}.\n"
        "Invoke scanning tools step-by-step. Finish by calling 'generate_report'."
    )

    print(f"\n[AGENT PROMPT]: {query}\n", file=sys.stderr)
    print("[*] Agent executing...\n", file=sys.stderr)

    async for chunk in agent.astream(
        {"messages": [("user", query)]}, stream_mode="values"
    ):
        latest_message = chunk["messages"][-1]

        # -------------------------------------------------------------------------
        #Intercettazione e salvataggio automatico dell'output dei tool
        # -------------------------------------------------------------------------
        if getattr(latest_message, "type", "") == "tool":
            tool_name = getattr(latest_message, "name", "unknown_tool")
            content = getattr(latest_message, "content", "")
            findings_log[tool_name] = content

            try:
                with open(findings_file, "w", encoding="utf-8") as f:
                    json.dump(findings_log, f, indent=2)
            except Exception as e:
                print(f"[!] Errore aggiornamento {findings_file}: {e}", file=sys.stderr)

        if hasattr(latest_message, "tool_calls") and latest_message.tool_calls:
            for tc in latest_message.tool_calls:
                print(
                    f"[NATIVE TOOL CALL]: {tc['name']} -> {tc['args']}",
                    file=sys.stderr,
                )
        else:
            latest_message.pretty_print()


if __name__ == "__main__":
    asyncio.run(main())