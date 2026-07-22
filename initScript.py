import json
import os
import platform
import shutil
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


def get_bin_dir() -> Path:
    """Returns local bin directory and adds it to the current environment PATH."""
    bin_dir = Path.home() / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    bin_str = str(bin_dir)
    if bin_str not in os.environ.get("PATH", ""):
        os.environ["PATH"] = bin_str + os.pathsep + os.environ.get("PATH", "")

    return bin_dir


def install_nikto(bin_dir: Path):
    """Installs Nikto via git clone and generates a platform executable wrapper."""
    print("[*] Checking Nikto installation...")
    if shutil.which("nikto"):
        print("[+] Nikto is already installed and accessible in PATH.")
        return

    if not shutil.which("perl"):
        print("[!] Warning: 'perl' runtime not detected in PATH. Nikto requires Perl to execute.")

    opt_dir = Path.home() / ".local" / "opt"
    opt_dir.mkdir(parents=True, exist_ok=True)
    nikto_dir = opt_dir / "nikto"

    if not nikto_dir.exists():
        print("[*] Cloning Nikto repository...")
        run_command(f'git clone https://github.com/sullo/nikto.git "{nikto_dir}"')

    program_file = nikto_dir / "program" / "nikto.pl"
    system = platform.system().lower()

    if system == "windows":
        bat_file = bin_dir / "nikto.bat"
        with open(bat_file, "w") as f:
            f.write(f'@echo off\nperl "{program_file}" %*\n')
        print(f"[+] Created Windows batch launcher for Nikto at {bat_file}")
    else:
        wrapper_file = bin_dir / "nikto"
        with open(wrapper_file, "w") as f:
            f.write(f'#!/usr/bin/env bash\nexec perl "{program_file}" "$@"\n')
        os.chmod(wrapper_file, 0o755)
        print(f"[+] Created executable wrapper for Nikto at {wrapper_file}")


def install_nuclei(bin_dir: Path):
    """Installs the latest Nuclei release binary for the current OS/Architecture."""
    print("[*] Checking Nuclei installation...")
    if shutil.which("nuclei"):
        print("[+] Nuclei is already installed and accessible in PATH.")
        return

    print("[*] Downloading Nuclei binary...")
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
    archive_path = bin_dir / f"nuclei.{ext}"

    try:
        urllib.request.urlretrieve(url, archive_path)
        if ext == "zip":
            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                zip_ref.extractall(bin_dir)
        else:
            with tarfile.open(archive_path, "r:gz") as tar_ref:
                tar_ref.extractall(bin_dir)

        if archive_path.exists():
            archive_path.unlink()

        nuclei_bin = bin_dir / ("nuclei.exe" if system == "windows" else "nuclei")
        if nuclei_bin.exists() and system != "windows":
            os.chmod(nuclei_bin, 0o755)

        print(f"[+] Nuclei successfully installed to {bin_dir}")
    except Exception as e:
        print(f"[-] Automatic Nuclei installation failed: {e}")


def install_owasp_zap_cli(bin_dir: Path):
    """Ensures OWASP ZAP standalone files or CLI launchers are configured."""
    print("[*] Checking OWASP ZAP CLI accessibility...")
    if shutil.which("zap.sh") or shutil.which("zap"):
        print("[+] OWASP ZAP binary or launcher is already in PATH.")
        return

    system = platform.system().lower()
    zap_ver = "2.15.0"
    opt_dir = Path.home() / ".local" / "opt"
    opt_dir.mkdir(parents=True, exist_ok=True)
    zap_dir = opt_dir / f"ZAP_{zap_ver}"
    wrapper_file = bin_dir / ("zap.bat" if system == "windows" else "zap")

    if not zap_dir.exists() and system == "linux":
        print(f"[*] Downloading OWASP ZAP Standalone package v{zap_ver}...")
        url = f"https://github.com/zaproxy/zaproxy/releases/download/v{zap_ver}/ZAP_{zap_ver}_Linux.tar.gz"
        tar_path = bin_dir / "zap.tar.gz"
        try:
            urllib.request.urlretrieve(url, tar_path)
            with tarfile.open(tar_path, "r:gz") as tar_ref:
                tar_ref.extractall(opt_dir)
            if tar_path.exists():
                tar_path.unlink()

            zap_script = zap_dir / "zap.sh"
            if zap_script.exists():
                os.chmod(zap_script, 0o755)
                with open(wrapper_file, "w") as f:
                    f.write(f'#!/usr/bin/env bash\nexec "{zap_script}" "$@"\n')
                os.chmod(wrapper_file, 0o755)
                print(f"[+] OWASP ZAP standalone installed to {wrapper_file}")
        except Exception as e:
            print(f"[-] Standalone OWASP ZAP download failed/skipped: {e}")

    print("[*] Note: OWASP ZAP container service (`zap_mcp`) will also run on port 8080.")


def ensure_cli_tools():
    """Ensure required CLI binaries (Arjun, Nuclei, Nikto, OWASP ZAP) exist in PATH."""
    print("\n[*] Installing and verifying security CLI tools...")
    bin_dir = get_bin_dir()

    # 1. Install Arjun via pip
    run_command(f"{sys.executable} -m pip install arjun")

    # 2. Install Nuclei
    install_nuclei(bin_dir)

    # 3. Install Nikto
    install_nikto(bin_dir)

    # 4. Install OWASP ZAP CLI / Standalone
    install_owasp_zap_cli(bin_dir)


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

    # 2. Install Python dependencies (including ZAP API and Arjun)
    run_command(
        f"{sys.executable} -m pip install fastmcp langgraph langchain-ollama langchain-mcp-adapters requests python-owasp-zap-v2.4 reportlab pillow arjun"
    )

    # 3. Ensure CLI dependencies (Arjun, Nuclei, Nikto, ZAP)
    ensure_cli_tools()

    # 4. Create shared Docker network safely
    print("\n[*] Ensuring Docker network 'secops-net' exists...")
    net_check = subprocess.run("docker network inspect secops-net", shell=True, capture_output=True)
    if net_check.returncode != 0:
        run_command("docker network create secops-net")
    else:
        print("[+] Network 'secops-net' already exists.")

    # 5. Start MongoDB for PwnDoc
    start_or_restart_container(
        "mongodb",
        "docker run -d --name mongodb --network secops-net -e MONGO_DB=pwndoc mongo:4.2.15 --wiredTigerCacheSizeGB 1",
    )

    # 6. Start PwnDoc Backend
    start_or_restart_container(
        "pwndoc-backend",
        "docker run -d --name pwndoc-backend --network secops-net -e DB_SERVER=mongodb -e DB_NAME=pwndoc ghcr.io/pwndoc/pwndoc-backend:latest",
    )

    # 7. Start PwnDoc Frontend (Port 8443)
    start_or_restart_container(
        "pwndoc-frontend",
        "docker run -d --name pwndoc-frontend --network secops-net -p 8443:80 ghcr.io/pwndoc/pwndoc-frontend:latest",
    )

    # 8. Start Ollama in Docker
    start_or_restart_container(
        "ollama",
        "docker run -d --name ollama --network secops-net -p 11434:11434 -v ollama_data:/root/.ollama ollama/ollama:latest",
    )

    # 9. Start Vulnerable Target (Juice Shop)
    start_or_restart_container("juice-shop", "docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop")

    # 10. Start OWASP ZAP Container
    start_or_restart_container(
        "zap_mcp",
        "docker run -d -p 8080:8080 -p 8090:8090 --name zap_mcp zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true",
    )

    print("[*] Waiting 5 seconds for all services to stabilize...")
    time.sleep(5)

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