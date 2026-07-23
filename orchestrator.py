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
    # Force child MCP processes to inherit user binary and script paths
    bin_dir = str(Path.home() / ".local" / "bin")
    scripts_dir = str(Path(sys.executable).parent / "Scripts")
    os.environ["PATH"] = bin_dir + os.pathsep + scripts_dir + os.pathsep + os.environ.get("PATH", "")
    parser = argparse.ArgumentParser(
        description="Autonomous Ollama SecOps Agent with MCP"
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

    findings_file = BASE_DIR / "scan_findings.json"
    findings_log = {}

    # Reset scan findings file
    try:
        with open(findings_file, "w", encoding="utf-8") as f:
            json.dump({}, f)
        print(f"[*] Initialized findings log at {findings_file}", file=sys.stderr)
    except Exception as e:
        print(f"[!] Error creating {findings_file}: {e}", file=sys.stderr)

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
        "jwt": "jwtServer.py",
        "interactsh": "interactshServer.py",
        "pwndoc": "pwndocServer.py",
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
            print(f"[!] Skipping '{name}': file not found at {script_path}", file=sys.stderr)

    print("[*] Connecting to MCP tool servers...", file=sys.stderr)

    scan_tools = []
    report_tool = None

    # Load servers resiliently (one failure won't crash the rest)
    for name, config in server_configs.items():
        try:
            single_client = MultiServerMCPClient({name: config})
            server_tools = await single_client.get_tools()
            for tool in server_tools:
                if tool.name == "generate_report":
                    report_tool = tool
                else:
                    scan_tools.append(tool)
            print(f"    [+] '{name}' loaded ({len(server_tools)} tools).", file=sys.stderr)
        except Exception as e:
            print(f"    [!] Server '{name}' failed to load: {e}", file=sys.stderr)

    if not scan_tools:
        print("[-] Critical Error: No scan tools loaded. Exiting.", file=sys.stderr)
        return

    print(f"\n[+] Active scan tools passed to Ollama Agent: {len(scan_tools)}", file=sys.stderr)

    model = ChatOllama(
        model="llama3.1",
        temperature=0,
        base_url="http://localhost:11434",
    ).bind_tools(scan_tools)

    system_prompt = (
        "You are an automated security testing agent.\n"
        "CRITICAL INSTRUCTIONS:\n"
        "1. You MUST use the provided tool-calling mechanism to execute commands. "
        "DO NOT write text descriptions, lists, or markdown JSON blocks of tool calls.\n"
        "2. Execute the security scan tools step-by-step against the target URL.\n"
        "3. Run tools systematically to assess vulnerabilities."
    )

    # Note: Only scan_tools are given to Ollama, so it CANNOT call generate_report prematurely
    agent = create_react_agent(model, scan_tools, prompt=system_prompt)

    query = f"Execute active security scan tools against target: {args.target}, run all possible tools without skipping"

    print(f"\n[*] Ollama Agent executing scans...\n", file=sys.stderr)

    # -------------------------------------------------------------------------
    # STEP 1: Ollama Agent Execution Phase
    # -------------------------------------------------------------------------
    async for chunk in agent.astream(
        {"messages": [("user", query)]}, stream_mode="values"
    ):
        messages = chunk.get("messages", [])

        # Process message history to log tool execution results
        for msg in messages:
            if isinstance(msg, ToolMessage) or getattr(msg, "type", "") == "tool":
                tool_name = getattr(msg, "name", "unknown_tool")
                findings_log[tool_name] = msg.content

        # Update JSON on disk
        try:
            with open(findings_file, "w", encoding="utf-8") as f:
                json.dump(findings_log, f, indent=2)
        except Exception as e:
            print(f"[!] Error writing {findings_file}: {e}", file=sys.stderr)

        # Print native tool calls or agent messages
        latest_message = messages[-1] if messages else None
        if latest_message and hasattr(latest_message, "tool_calls") and latest_message.tool_calls:
            for tc in latest_message.tool_calls:
                print(f"[OLLAMA TOOL CALL]: {tc['name']} -> {tc['args']}", file=sys.stderr)
        elif latest_message:
            latest_message.pretty_print()

    # -------------------------------------------------------------------------
    # STEP 2: Display All Findings on CLI Terminal
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("                 CLI SCAN FINDINGS SUMMARY")
    print("=" * 60)

    if not findings_log:
        print("\n[!] No findings were recorded by Ollama.\n")
    else:
        for tool_name, output in findings_log.items():
            print(f"\n--- [TOOL]: {tool_name} ---")
            print(output)
            print("-" * 40)

    # -------------------------------------------------------------------------
    # STEP 3: Automated Report Generation Phase (Programmatic)
    # -------------------------------------------------------------------------
    if report_tool:
        print("\n" + "=" * 60)
        print("             GENERATING REPORT WITH FINDINGS")
        print("=" * 60)
        try:
            report_res = await report_tool.ainvoke({
                "target": args.target,
                "target_url": args.target,
                "findings_summary": findings_log
            })
            print(f"\n[+] Report Generator Response:\n{report_res}")
        except Exception as e:
            print(f"\n[!] Error generating report: {e}")
    else:
        print("\n[!] 'generate_report' tool unavailable. Skipping PDF generation.")


if __name__ == "__main__":
    asyncio.run(main())