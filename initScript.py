import os
import platform
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path


def run_command(cmd: str):
    print(f"[+] Executing: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[-] Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)


def ensure_cli_tools():
    """Ensure required CLI binaries (arjun, nuclei) exist in PATH."""
    print("[*] Checking required CLI binaries (arjun, nuclei)...")

    # Install arjun via pip
    run_command(f"{sys.executable} -m pip install arjun")

    # Check if nuclei binary exists in PATH
    nuclei_check = subprocess.run("nuclei -version", shell=True, capture_output=True)
    if nuclei_check.returncode == 0:
        print("[+] Nuclei is already installed and accessible in PATH.")
        return

    print("[*] Nuclei binary not found. Attempting automatic download...")
    system = platform.system().lower()
    arch = platform.machine().lower()

    arch_str = "amd64" if arch in ["x86_64", "amd64"] else "arm64"
    if system == "windows":
        os_str, ext = "windows", "zip"
    elif system == "darwin":
        os_str, ext = "macOS", "zip"
    else:
        os_str, ext = "linux", "tar.gz"

    version = "3.3.0"
    url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_{os_str}_{arch_str}.{ext}"

    bin_dir = Path.home() / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    archive_path = bin_dir / f"nuclei.{ext}"

    try:
        urllib.request.urlretrieve(url, archive_path)
        if ext == "zip":
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(bin_dir)
        else:
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(bin_dir)

        if archive_path.exists():
            archive_path.unlink()

        # Update environment PATH for current runtime
        os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")
        print(f"[+] Nuclei successfully installed to {bin_dir}")
    except Exception as e:
        print(f"[-] Automatic Nuclei installation failed: {e}")
        print("[!] Please manually install Nuclei and add it to your system PATH.")


def start_or_restart_container(name: str, run_cmd: str):
    print(f"[*] Managing container '{name}'...")
    check_exist = subprocess.run(f"docker inspect {name}", shell=True, capture_output=True)
    if check_exist.returncode == 0:
        print(f"[+] Container '{name}' already exists. Ensuring it is running...")
        subprocess.run(f"docker start {name}", shell=True)
    else:
        print(f"[+] Container '{name}' does not exist. Creating and starting...")
        run_command(run_cmd)


def main():
    print("=== Initializing All-in-One SecOps Autonomous MCP Environment ===")

    # 1. Upgrade pip
    run_command(f"{sys.executable} -m pip install --upgrade pip")

    # 2. Install Python dependencies (including arjun)
    run_command(
        f"{sys.executable} -m pip install fastmcp langgraph langchain-ollama langchain-mcp-adapters requests python-owasp-zap-v2.4 reportlab pillow arjun"
    )

    # 3. Ensure CLI dependencies (arjun & nuclei)
    ensure_cli_tools()

    # 4. Create shared Docker network safely
    print("[*] Ensuring Docker network 'secops-net' exists...")
    net_check = subprocess.run("docker network inspect secops-net", shell=True, capture_output=True)
    if net_check.returncode != 0:
        run_command("docker network create secops-net")
    else:
        print("[+] Network 'secops-net' already exists.")

    # 5. Start MongoDB for PwnDoc
    start_or_restart_container(
        "mongodb",
        "docker run -d --name mongodb --network secops-net -e MONGO_DB=pwndoc mongo:4.2.15 --wiredTigerCacheSizeGB 1"
    )

    # 6. Start PwnDoc Backend
    start_or_restart_container(
        "pwndoc-backend",
        "docker run -d --name pwndoc-backend --network secops-net -e DB_SERVER=mongodb -e DB_NAME=pwndoc ghcr.io/pwndoc/pwndoc-backend:latest"
    )

    # 7. Start PwnDoc Frontend (Port 8443)
    start_or_restart_container(
        "pwndoc-frontend",
        "docker run -d --name pwndoc-frontend --network secops-net -p 8443:80 ghcr.io/pwndoc/pwndoc-frontend:latest"
    )

    # 8. Start Ollama in Docker
    start_or_restart_container(
        "ollama",
        "docker run -d --name ollama --network secops-net -p 11434:11434 -v ollama_data:/root/.ollama ollama/ollama:latest"
    )

    # 9. Start Vulnerable Target (Juice Shop)
    start_or_restart_container(
        "juice-shop",
        "docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop"
    )

    # 10. Start OWASP ZAP Container
    start_or_restart_container(
        "zap_mcp",
        "docker run -d -p 8080:8080 -p 8090:8090 --name zap_mcp zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"
    )

    print("[*] Waiting 15 seconds for all services to stabilize...")
    time.sleep(15)

    # 11. Pull Llama 3.1 inside the Ollama container
    print("[*] Pulling local Llama 3.1 model inside the Ollama container...")
    run_command("docker exec ollama ollama pull llama3.1")

    # 12. Verify running containers
    print("\n=== Active Containers (docker ps) ===")
    run_command("docker ps")
    print("\n[+] Environment fully ready! Launching Autonomous Orchestrator...\n")

    # 13. Run orchestrator script
    run_command(f"{sys.executable} orchestrator.py --target http://127.0.0.1:3000")


if __name__ == "__main__":
    main()