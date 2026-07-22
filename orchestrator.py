import os
import sys
from pathlib import Path

# Configurazione directory modelli Ollama locale
BASE_DIR = Path(__file__).parent.resolve()
SERVERS_DIR = BASE_DIR / "servers"
OLLAMA_MODELS_DIR = BASE_DIR / "ollama_models"
OLLAMA_MODELS_DIR.mkdir(exist_ok=True)
os.environ["OLLAMA_MODELS"] = str(OLLAMA_MODELS_DIR)

import asyncio
import argparse
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.client import MultiServerMCPClient


async def main():
    parser = argparse.ArgumentParser(description="Fully Autonomous Local SecOps Agent with Ollama & MCP")
    parser.add_argument("--target", type=str, default="http://127.0.0.1:3000", help="Target URL to assess")
    args = parser.parse_args()

    print(f"=== INITIALIZING AUTONOMOUS OLLAMA AGENT ON: {args.target} ===", file=sys.stderr)

    server_configs = {
        "zap": {"transport": "stdio", "command": sys.executable, "args": [str(SERVERS_DIR / "zapServer.py")]},
        "nuclei": {"transport": "stdio", "command": sys.executable, "args": [str(SERVERS_DIR / "nucleiServer.py")]},
        "sqlmap": {"transport": "stdio", "command": sys.executable, "args": [str(SERVERS_DIR / "sqlmapServer.py")]},
        "ffuf": {"transport": "stdio", "command": sys.executable, "args": [str(SERVERS_DIR / "ffufServer.py")]},
        "nikto": {"transport": "stdio", "command": sys.executable, "args": [str(SERVERS_DIR / "niktoServer.py")]},
        "dalfox": {"transport": "stdio", "command": sys.executable, "args": [str(SERVERS_DIR / "dalfoxServer.py")]},
        "arjun": {"transport": "stdio", "command": sys.executable, "args": [str(SERVERS_DIR / "arjunServer.py")]},
        "commix": {"transport": "stdio", "command": sys.executable, "args": [str(SERVERS_DIR / "commixServer.py")]},
        "idor": {"transport": "stdio", "command": sys.executable, "args": [str(SERVERS_DIR / "idorForgeServer.py")]},
        "pwndoc": {"transport": "stdio", "command": sys.executable, "args": [str(SERVERS_DIR / "pwndocServer.py")]}
    }

    print("[*] Connecting to MCP tool servers and loading capabilities...", file=sys.stderr)
    client = MultiServerMCPClient(server_configs)
    tools = await client.get_tools()

    model = ChatOllama(
        model="llama3.1",
        temperature=0,
        base_url="http://localhost:11434"
    )

    system_prompt = (
        "You are an autonomous AI security agent actively running in a terminal with functional security tools. "
        "CRITICAL RULES: "
        "1. DO NOT write out plans or text tool-call explanations. YOU MUST natively invoke tools. "
        "2. Work step-by-step: trigger ONE tool call, wait for the Observation, then proceed to the next tool. "
        "3. YOU MUST USE MULTIPLE TOOLS to assess the target thoroughly. Do not rely on just one tool. "
        "4. When calling 'generate_report': "
        "   - Use the parameter name 'target' for the URL. "
        "   - 'findings_summary' MUST be a dictionary mapping each tool's name to its findings object "
        "     (e.g., {'zap': zap_results, 'nikto': nikto_results, 'nuclei': nuclei_results}). "
        "5. Never hallucinate outputs. Only report what is contained in tool Observations."
    )

    agent = create_react_agent(model, tools, prompt=system_prompt)

    query = (
        f"Perform a comprehensive, multi-tool security assessment on {args.target}.\n\n"
        "Follow these steps sequentially using your loaded tools:\n"
        "1. Run OWASP ZAP scan or Nikto scan to discover endpoints and general web vulnerabilities.\n"
        "2. Run Nuclei scan to detect known template vulnerabilities.\n"
        "3. Run Dalfox scan if XSS vectors or endpoints are identified.\n"
        "4. Collect and aggregate ALL findings from every tool you executed into a dictionary object.\n"
        "5. Call 'generate_report' passing 'target' (string) and 'findings_summary' (dictionary of all tool outputs).\n\n"
        "ACT NOW. Start by invoking the first tool."
    )

    print(f"\n[AGENT PROMPT]: {query}\n", file=sys.stderr)
    print("[*] Agent is now reasoning and executing tools autonomously...\n", file=sys.stderr)

    execution_errors = []

    async for chunk in agent.astream({"messages": [("user", query)]}, stream_mode="values"):
        latest_message = chunk["messages"][-1]
        latest_message.pretty_print()

        content_str = str(getattr(latest_message, "content", ""))
        # Monitor stream for system tool execution errors
        if any(err in content_str for err in ["WinError", "ValidationError", "Error", "failed"]):
            if getattr(latest_message, "type", "") == "tool":
                execution_errors.append(content_str)

    if execution_errors:
        print("\n[-] Assessment encountered execution errors during tool invocations:", file=sys.stderr)
        for err in execution_errors:
            print(f"  - {err[:200]}...", file=sys.stderr)
        print("[-] Workflow finished with errors. Report may be missing or incomplete.", file=sys.stderr)
    else:
        print("\n[+] Autonomous security assessment workflow completed successfully!", file=sys.stderr)
        print("[+] Check the project folder for the generated PDF report (SecOps_Assessment_Report.pdf).", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())