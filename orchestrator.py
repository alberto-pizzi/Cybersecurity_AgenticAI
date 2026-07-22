import asyncio
import sys
import argparse
from pathlib import Path
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

BASE_DIR = Path(__file__).parent.resolve()
SERVERS_DIR = BASE_DIR / "servers"


async def main():
    parser = argparse.ArgumentParser(description="Fully Autonomous Local SecOps Agent with Ollama & MCP")
    parser.add_argument("--target", type=str, default="http://127.0.0.1:3000", help="Target URL to assess")
    args = parser.parse_args()

    print(f"=== INITIALIZING AUTONOMOUS OLLAMA AGENT ON: {args.target} ===")

    # 1. Configure all local MCP servers via stdio transport
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

    print("[*] Connecting to MCP tool servers and loading capabilities...")
    async with MultiServerMCPClient(server_configs) as client:
        # Automatically converts all MCP server tools into LangChain-compatible tools
        tools = client.get_tools()

        # 2. Initialize local model via Ollama
        model = ChatOllama(
            model="llama3.1",
            temperature=0,
            base_url="http://localhost:11434"
        )

        # 3. Create the autonomous ReAct agent loop
        system_prompt = (
            "You are an expert autonomous offensive security agent. "
            "Your job is to analyze the target web application, decide which security tools to invoke, "
            "evaluate vulnerabilities found, and finally trigger the pwndoc reporting tool to compile the assessment."
        )

        agent = create_react_agent(model, tools, prompt=system_prompt)

        # 4. Run the autonomous assessment loop
        query = (
            f"Perform a comprehensive security assessment on target {args.target}. "
            "Examine endpoints, execute relevant scans, gather vulnerabilities, "
            "and finish by generating the final report using the available reporting tool."
        )

        print(f"\n[AGENT PROMPT]: {query}\n")
        print("[*] Agent is now reasoning and executing tools autonomously...\n")

        async for chunk in agent.astream({"messages": [("user", query)]}, stream_mode="values"):
            latest_message = chunk["messages"][-1]
            latest_message.pretty_print()

    print("\n[+] Autonomous security assessment workflow completed successfully!")


if __name__ == "__main__":
    asyncio.run(main())