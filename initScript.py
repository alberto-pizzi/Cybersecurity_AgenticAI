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
import requests


def run_command(cmd: str):
    print(f"[+] Executing: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[-] Command failed with exit code {result.returncode}")


def get_bin_dir() -> Path:
    """Returns local bin directory and adds it to the current environment PATH."""
    bin_dir = Path.home() / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    bin_str = str(bin_dir)
    if bin_str not in os.environ.get("PATH", ""):
        os.environ["PATH"] = bin_str + os.pathsep + os.environ.get("PATH", "")

    return bin_dir


def install_perl_windows(local_dir: Path):
    """Downloads and extracts Strawberry Perl on Windows if missing."""
    system = platform.system().lower()
    if system != "windows":
        return

    print("[*] Checking Perl installation (required for Nikto on Windows)...")
    if shutil.which("perl"):
        print("[+] Perl is already installed and accessible in PATH.")
        return

    print("[*] Perl runtime missing. Downloading Strawberry Perl Portable...")
    try:
        perl_url = "https://strawberryperl.com/download/5.38.2.1/strawberry-perl-5.38.2.1-64bit-portable.zip"
        perl_zip = local_dir / "perl.zip"
        perl_dir = local_dir / "strawberry_perl"
        perl_dir.mkdir(parents=True, exist_ok=True)

        urllib.request.urlretrieve(perl_url, perl_zip)
        with zipfile.ZipFile(perl_zip, 'r') as zip_ref:
            zip_ref.extractall(perl_dir)
        perl_zip.unlink(missing_ok=True)

        perl_bin = str(perl_dir / "perl" / "bin")
        os.environ["PATH"] = perl_bin + os.pathsep + os.environ.get("PATH", "")
        print(f"[+] Strawberry Perl portable configured at {perl_bin}")
    except Exception as e:
        print(f"[-] Automated Perl setup failed: {e}. Nikto might fail.")


def install_nikto(bin_dir: Path):
    """Installs Nikto via git clone and generates a platform executable wrapper."""
    print("[*] Checking Nikto installation...")
    if shutil.which("nikto"):
        print("[+] Nikto is already installed and accessible in PATH.")
        return

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


def install_nuclei(bin_dir: Path):
    """Installs the Nuclei release binary for the current OS/Architecture."""
    print("[*] Checking Nuclei installation...")
    if shutil.which("nuclei"):
        print("[+] Nuclei is already installed and accessible in PATH.")
        return

    system = platform.system().lower()
    arch = platform.machine().lower()

    arch_str = "amd64" if arch in ["x86_64", "amd64"] else "arm64"
    os_str, ext = ("windows", "zip") if system == "windows" else ("linux", "tar.gz")
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
        print(f"[+] Nuclei successfully installed to {bin_dir}")
    except Exception as e:
        print(f"[-] Automatic Nuclei installation failed: {e}")


def install_ffuf(bin_dir: Path):
    """Installs FFUF release binary."""
    print("[*] Checking FFUF installation...")
    if shutil.which("ffuf"):
        print("[+] FFUF is already installed and accessible in PATH.")
        return

    system = platform.system().lower()
    arch = platform.machine().lower()

    arch_str = "amd64" if arch in ["x86_64", "amd64"] else "arm64"
    os_str, ext = ("windows", "zip") if system == "windows" else ("linux", "tar.gz")
    version = "2.1.0"
    url = f"https://github.com/ffuf/ffuf/releases/download/v{version}/ffuf_{version}_{os_str}_{arch_str}.{ext}"
    archive_path = bin_dir / f"ffuf.{ext}"

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
        print(f"[+] FFUF successfully installed to {bin_dir}")
    except Exception as e:
        print(f"[-] Automatic FFUF installation failed: {e}")


def install_dalfox(bin_dir: Path):
    """Installs DalFox release binary."""
    print("[*] Checking DalFox installation...")
    if shutil.which("dalfox"):
        print("[+] DalFox is already installed and accessible in PATH.")
        return

    system = platform.system().lower()
    arch = platform.machine().lower()

    arch_str = "amd64" if arch in ["x86_64", "amd64"] else "arm64"
    os_str, ext = ("windows", "zip") if system == "windows" else ("linux", "tar.gz")
    version = "2.9.0"
    url = f"https://github.com/hahwul/dalfox/releases/download/v{version}/dalfox_{version}_{os_str}_{arch_str}.{ext}"
    archive_path = bin_dir / f"dalfox.{ext}"

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
        print(f"[+] DalFox successfully installed to {bin_dir}")
    except Exception as e:
        print(f"[-] Automatic DalFox installation failed: {e}")


def install_commix(bin_dir: Path):
    """Clones Commix and builds a launcher script."""
    print("[*] Checking Commix installation...")
    if shutil.which("commix") or shutil.which("commix.bat"):
        print("[+] Commix is already installed and accessible in PATH.")
        return

    opt_dir = Path.home() / ".local" / "opt"
    opt_dir.mkdir(parents=True, exist_ok=True)
    commix_dir = opt_dir / "commix"

    if not commix_dir.exists():
        print("[*] Cloning Commix repository...")
        run_command(f'git clone https://github.com/commixproject/commix.git "{commix_dir}"')

    program_file = commix_dir / "commix.py"
    system = platform.system().lower()

    if system == "windows":
        bat_file = bin_dir / "commix.bat"
        with open(bat_file, "w") as f:
            f.write(f'@echo off\n"{sys.executable}" "{program_file}" %*\n')
        print(f"[+] Created Windows batch launcher for Commix at {bat_file}")
    else:
        wrapper_file = bin_dir / "commix"
        with open(wrapper_file, "w") as f:
            f.write(f'#!/usr/bin/env bash\nexec "{sys.executable}" "{program_file}" "$@"\n')
        os.chmod(wrapper_file, 0o755)


def install_sqlmap(bin_dir: Path):
    """Clones SQLMap and builds a launcher script."""
    print("[*] Checking SQLMap installation...")
    if shutil.which("sqlmap") or shutil.which("sqlmap.bat"):
        print("[+] SQLMap is already installed and accessible in PATH.")
        return

    opt_dir = Path.home() / ".local" / "opt"
    opt_dir.mkdir(parents=True, exist_ok=True)
    sqlmap_dir = opt_dir / "sqlmap"

    if not sqlmap_dir.exists():
        print("[*] Cloning SQLMap repository...")
        run_command(f'git clone https://github.com/sqlmapproject/sqlmap.git "{sqlmap_dir}"')

    program_file = sqlmap_dir / "sqlmap.py"
    system = platform.system().lower()

    if system == "windows":
        bat_file = bin_dir / "sqlmap.bat"
        with open(bat_file, "w") as f:
            f.write(f'@echo off\n"{sys.executable}" "{program_file}" %*\n')
        print(f"[+] Created Windows batch launcher for SQLMap at {bat_file}")
    else:
        wrapper_file = bin_dir / "sqlmap"
        with open(wrapper_file, "w") as f:
            f.write(f'#!/usr/bin/env bash\nexec "{sys.executable}" "{program_file}" "$@"\n')
        os.chmod(wrapper_file, 0o755)


def ensure_cli_tools():
    """Ensure all required CLI tools are downloaded, installed, and wrapped in PATH."""
    print("\n[*] Installing and verifying security CLI tools...")
    bin_dir = get_bin_dir()
    local_dir = Path.home() / ".local"

    # Pip-based tools
    run_command(f"{sys.executable} -m pip install arjun")

    # Install Windows Perl if required before Nikto
    install_perl_windows(local_dir)

    # Binary and script tools
    install_nuclei(bin_dir)
    install_nikto(bin_dir)
    install_ffuf(bin_dir)
    install_dalfox(bin_dir)
    install_commix(bin_dir)
    install_sqlmap(bin_dir)


def start_or_restart_container(name: str, run_cmd: str):
    print(f"[*] Managing container '{name}'...")
    check_exist = subprocess.run(f"docker inspect {name}", shell=True, capture_output=True)
    if check_exist.returncode == 0:
        print(f"[+] Container '{name}' already exists. Ensuring it is running...")
        subprocess.run(f"docker start {name}", shell=True)
    else:
        print(f"[+] Container '{name}' does not exist. Creating and starting...")
        run_command(run_cmd)


def initialize_dvwa_database(target_url: str = "http://127.0.0.1"):
    """Attende l'avvio di DVWA ed esegue l'inizializzazione del Database."""
    print(f"[*] Attesa avvio servizio DVWA su {target_url}...")
    session = requests.Session()

    # Attesa che la porta 80 risponda
    for attempt in range(15):
        try:
            res = session.get(f"{target_url}/login.php", timeout=3)
            if res.status_code == 200:
                print("[+] DVWA e raggiungibile! Inizializzazione Database...")
                break
        except Exception:
            pass
        time.sleep(2)

    # Invio della richiesta HTTP POST per creare/resettare il database
    try:
        setup_resp = session.post(
            f"{target_url}/setup.php",
            data={"create_db": "Create / Reset Database"},
            timeout=10
        )
        if setup_resp.status_code in [200, 302]:
            print("[+] Database DVWA creato e inizializzato con successo!")
        else:
            print(f"[-] Avviso: Risposta inattesa dal setup di DVWA (Status code: {setup_resp.status_code})")
    except Exception as e:
        print(f"[-] Errore durante l'inizializzazione del Database DVWA: {e}")


def main():
    print("=== Initializing All-in-One SecOps Autonomous MCP Environment ===")

    # 1. Upgrade pip
    run_command(f"{sys.executable} -m pip install --upgrade pip")

    # 2. Install Python dependencies
    run_command(
        f"{sys.executable} -m pip install fastmcp langgraph langchain-ollama langchain-mcp-adapters requests python-owasp-zap-v2.4 reportlab pillow arjun"
    )

    # 3. Ensure CLI dependencies
    ensure_cli_tools()

    # 4. Create shared Docker network safely
    print("\n[*] Ensuring Docker network 'secops-net' exists...")
    net_check = subprocess.run("docker network inspect secops-net", shell=True, capture_output=True)
    if net_check.returncode != 0:
        run_command("docker network create secops-net")

    # 5-9. Containers setup
    start_or_restart_container(
        "mongodb",
        "docker run -d --name mongodb --network secops-net -e MONGO_DB=pwndoc mongo:4.2.15 --wiredTigerCacheSizeGB 1",
    )
    start_or_restart_container(
        "pwndoc-backend",
        "docker run -d --name pwndoc-backend --network secops-net -e DB_SERVER=mongodb -e DB_NAME=pwndoc ghcr.io/pwndoc/pwndoc-backend:latest",
    )
    start_or_restart_container(
        "pwndoc-frontend",
        "docker run -d --name pwndoc-frontend --network secops-net -p 8443:80 ghcr.io/pwndoc/pwndoc-frontend:latest",
    )
    start_or_restart_container(
        "ollama",
        "docker run -d --name ollama --network secops-net -p 11434:11434 -v ollama_data:/root/.ollama ollama/ollama:latest",
    )

    # DVWA (Damn Vulnerable Web Application) sulla porta 80
    start_or_restart_container(
        "dvwa",
        "docker run -d --name dvwa --network secops-net -p 80:80 vulnerables/web-dvwa"
    )

    # Inizializzazione automatica del Database di DVWA
    initialize_dvwa_database("http://127.0.0.1")

    # 10. OWASP ZAP Container
    start_or_restart_container(
        "zap_mcp",
        "docker run -d --network secops-net -p 8080:8080 -p 8090:8090 --name zap_mcp zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true",
    )

    print("[*] Waiting for ZAP service on port 8080 to respond...")
    time.sleep(10)

    # 11. Pull Llama 3.1 model inside Ollama container
    print("[*] Pulling local Llama 3.1 model inside the Ollama container...")
    run_command("docker exec ollama ollama pull llama3.1")

    print("\n=== Active Containers (docker ps) ===")
    run_command("docker ps")
    print("\n[+] Environment fully ready! Launching LangGraph Orchestrator against DVWA...\n")

    # 12. Avvio dell'orchestratore LangGraph puntato a DVWA (http://127.0.0.1)
    run_command(f"{sys.executable} orchestratorDeterministic.py --target http://127.0.0.1")
    # run_command(f"{sys.executable} orchestrator.py --target http://127.0.0.1:3000")

if __name__ == "__main__":
    main()