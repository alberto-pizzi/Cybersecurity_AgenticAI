import subprocess
import sys
import time


def run_command(cmd: str):
    print(f"[+] Executing: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[-] Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)


def main():
    print("=== Initializing SecOps Autonomous MCP Environment ===")

    # 1. Install required Python packages
    run_command(f"{sys.executable} -m pip install fastmcp langgraph langchain-ollama requests python-owasp-zap-v2.4 reportlab")

    # 2. Start Vulnerable Target (Juice Shop)
    run_command("docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop || docker start juice-shop")

    # 3. Start OWASP ZAP Daemon Container with API enabled
    run_command(
        "docker run -d -p 8080:8080 -p 8090:8090 --name zap_mcp zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true || docker start zap_mcp"
    )

    print("[*] Waiting 10 seconds for ZAP API service to become fully available...")
    time.sleep(10)

    # 4. Verify running containers
    print("\n=== Active Containers (docker ps) ===")
    run_command("docker ps")
    print("\n[+] Environment ready!")


if __name__ == "__main__":
    main()