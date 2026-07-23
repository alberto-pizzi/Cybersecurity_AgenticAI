from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Iterable

import requests

from utils import ROOT_DIR, WORDLISTS_DIR, find_executable, setup_path


# -----------------------------------------------------------------------------
# Project configuration
# -----------------------------------------------------------------------------

PYTHON_PACKAGES = [
    # Keep the FastMCP major version expected by the current project.
    "fastmcp==2.12.5",
    "langgraph>=0.6,<2",
    "requests>=2.32,<3",
    "beautifulsoup4>=4.13,<5",
    "python-owasp-zap-v2.4>=0.1.0",
    "reportlab>=4.4,<5",
    "PyJWT>=2.10,<3",
    "arjun>=2.2,<3",
]

DEFAULT_TARGET = "http://127.0.0.1"
DEFAULT_MODEL = "llama3.1:8b"

# All locally managed scanners are stored inside the project/user profile.
LOCAL_ROOT = Path.home() / ".local"
LOCAL_BIN = LOCAL_ROOT / "bin"
LOCAL_OPT = LOCAL_ROOT / "opt"
DOWNLOAD_DIR = LOCAL_ROOT / "downloads"

# Tools that must exist after initialization.
REQUIRED_SCANNERS = (
    "nuclei",
    "nikto",
    "ffuf",
    "dalfox",
    "commix",
    "sqlmap",
    "arjun",
    "interactsh-client",
)


# -----------------------------------------------------------------------------
# Generic process and PATH helpers
# -----------------------------------------------------------------------------

def run(
    command: list[str],
    *,
    required: bool = True,
    capture: bool = False,
    timeout: int = 3600,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command safely without shell interpolation."""
    print("[+] " + subprocess.list2cmdline(command))
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=capture,
            timeout=timeout,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Command not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Command timed out after {timeout} seconds: "
            f"{subprocess.list2cmdline(command)}"
        ) from exc

    if capture:
        if completed.stdout.strip():
            print(completed.stdout.strip())
        if completed.stderr.strip():
            print(completed.stderr.strip(), file=sys.stderr)

    if completed.returncode != 0 and required:
        details = completed.stderr.strip() if capture else ""
        raise RuntimeError(
            f"Command failed with exit code {completed.returncode}: {command}\n{details}"
        )
    return completed


def add_path(path: Path) -> None:
    """Add a directory to the current process PATH exactly once."""
    if not path:
        return
    path = path.expanduser().resolve()
    current_parts = os.environ.get("PATH", "").split(os.pathsep)
    normalized = {os.path.normcase(os.path.abspath(part)) for part in current_parts if part}
    if os.path.normcase(str(path)) not in normalized:
        os.environ["PATH"] = str(path) + os.pathsep + os.environ.get("PATH", "")


def configure_runtime_path() -> None:
    """
    Add every relevant Python/user binary directory to PATH.

    This fixes the exact warning shown in the log where arjun.exe was installed
    successfully but Windows could not find it afterwards.
    """
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    LOCAL_OPT.mkdir(parents=True, exist_ok=True)
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

    candidates: list[Path] = [LOCAL_BIN]

    # Python's user Scripts directory, e.g. ...\Python313\Scripts on Windows.
    user_scripts = sysconfig.get_path("scripts", scheme="nt_user" if os.name == "nt" else "posix_user")
    if user_scripts:
        candidates.append(Path(user_scripts))

    # The active interpreter's Scripts/bin directory.
    candidates.append(Path(sys.executable).resolve().parent)
    if os.name == "nt":
        candidates.append(Path(sys.executable).resolve().parent / "Scripts")
    else:
        candidates.append(Path(sys.executable).resolve().parent / "bin")

    # pip --user sometimes resolves through site.USER_BASE.
    try:
        import site
        candidates.append(Path(site.USER_BASE) / ("Scripts" if os.name == "nt" else "bin"))
    except Exception:
        pass

    for candidate in candidates:
        if candidate.exists():
            add_path(candidate)


def command_path(name: str) -> str | None:
    """Resolve a command using both utils.py and the updated process PATH."""
    try:
        found = find_executable(name)
        if found:
            return found
    except Exception:
        pass
    return shutil.which(name)


# -----------------------------------------------------------------------------
# Python dependencies and launchers
# -----------------------------------------------------------------------------

def install_python_dependencies() -> None:
    run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], timeout=1800)
    run([sys.executable, "-m", "pip", "install", *PYTHON_PACKAGES], timeout=3600)
    configure_runtime_path()


def write_launcher(name: str, command: list[str]) -> Path:
    """Create a portable wrapper in ~/.local/bin."""
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)

    if os.name == "nt":
        launcher = LOCAL_BIN / f"{name}.bat"
        launcher.write_text(
            "@echo off\r\n" + subprocess.list2cmdline(command) + " %*\r\n",
            encoding="utf-8",
        )
    else:
        launcher = LOCAL_BIN / name
        quoted = " ".join(subprocess.list2cmdline([part]) for part in command)
        launcher.write_text(
            f"#!/usr/bin/env sh\nexec {quoted} \"$@\"\n",
            encoding="utf-8",
        )
        launcher.chmod(
            launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )

    print(f"[+] Launcher created: {launcher}")
    configure_runtime_path()
    return launcher


def ensure_arjun_launcher() -> None:
    """
    Arjun is installed by pip. If its generated executable is not visible,
    create a local launcher that invokes its module entry point.
    """
    if command_path("arjun"):
        print(f"[+] arjun already available: {command_path('arjun')}")
        return

    probe = run(
        [sys.executable, "-m", "arjun", "--help"],
        required=False,
        capture=True,
        timeout=60,
    )
    if probe.returncode == 0:
        write_launcher("arjun", [sys.executable, "-m", "arjun"])
        return

    raise RuntimeError(
        "Arjun was installed by pip but neither arjun.exe nor python -m arjun works."
    )


# -----------------------------------------------------------------------------
# Git repositories: SQLMap, Commix and Nikto
# -----------------------------------------------------------------------------

def require_git() -> str:
    git = shutil.which("git")
    if not git:
        raise RuntimeError("Git is required to install SQLMap, Commix and Nikto.")
    return git


def clone_or_update(repository: str, destination: Path) -> None:
    require_git()
    if (destination / ".git").exists():
        update = run(
            ["git", "-C", str(destination), "pull", "--ff-only"],
            required=False,
            capture=True,
            timeout=600,
        )
        if update.returncode != 0:
            print(f"[!] Could not update {destination.name}; keeping the existing copy.")
        return

    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--depth", "1", repository, str(destination)], timeout=1200)


def install_sqlmap() -> None:
    if command_path("sqlmap"):
        print(f"[+] sqlmap already available: {command_path('sqlmap')}")
        return
    destination = LOCAL_OPT / "sqlmap"
    clone_or_update("https://github.com/sqlmapproject/sqlmap.git", destination)
    script = destination / "sqlmap.py"
    if not script.exists():
        raise RuntimeError("sqlmap.py was not found after cloning SQLMap.")
    write_launcher("sqlmap", [sys.executable, str(script)])


def install_commix() -> None:
    if command_path("commix"):
        print(f"[+] commix already available: {command_path('commix')}")
        return
    destination = LOCAL_OPT / "commix"
    clone_or_update("https://github.com/commixproject/commix.git", destination)
    script = destination / "commix.py"
    if not script.exists():
        raise RuntimeError("commix.py was not found after cloning Commix.")
    write_launcher("commix", [sys.executable, str(script)])


def find_perl() -> str | None:
    perl = shutil.which("perl")
    if perl:
        return perl

    if os.name == "nt":
        candidates = [
            Path(r"C:\Strawberry\perl\bin\perl.exe"),
            Path(r"C:\Program Files\Strawberry Perl\perl\bin\perl.exe"),
        ]
        for candidate in candidates:
            if candidate.exists():
                add_path(candidate.parent)
                return str(candidate)
    return None


def install_strawberry_perl_windows() -> str | None:
    """Install Strawberry Perl with winget when Nikto needs it."""
    perl = find_perl()
    if perl or os.name != "nt":
        return perl

    winget = shutil.which("winget")
    if not winget:
        return None

    print("[*] Perl not found. Installing Strawberry Perl with winget...")
    run(
        [
            winget,
            "install",
            "--id",
            "StrawberryPerl.StrawberryPerl",
            "--exact",
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ],
        required=False,
        timeout=1800,
    )
    return find_perl()


def install_nikto() -> None:
    if command_path("nikto"):
        print(f"[+] nikto already available: {command_path('nikto')}")
        return

    destination = LOCAL_OPT / "nikto"
    clone_or_update("https://github.com/sullo/nikto.git", destination)
    script = destination / "program" / "nikto.pl"
    if not script.exists():
        raise RuntimeError("nikto.pl was not found after cloning Nikto.")

    perl = find_perl() or install_strawberry_perl_windows()
    if not perl:
        raise RuntimeError(
            "Nikto was downloaded, but Perl is missing. Install Strawberry Perl and rerun."
        )
    write_launcher("nikto", [perl, str(script)])


# -----------------------------------------------------------------------------
# GitHub release binaries: Nuclei, FFUF, Dalfox and Interactsh
# -----------------------------------------------------------------------------

def github_latest_release(repository: str) -> dict:
    response = requests.get(
        f"https://api.github.com/repos/{repository}/releases/latest",
        headers={"Accept": "application/vnd.github+json"},
        timeout=60,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"Invalid GitHub release response for {repository}.")
    return payload


def architecture_tokens() -> tuple[str, ...]:
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64", "x64"}:
        return ("amd64", "x86_64", "64bit")
    if machine in {"arm64", "aarch64"}:
        return ("arm64", "aarch64")
    raise RuntimeError(f"Unsupported CPU architecture: {machine}")


def operating_system_tokens() -> tuple[str, ...]:
    system = platform.system().lower()
    if system == "windows":
        return ("windows", "win")
    if system == "linux":
        return ("linux",)
    if system == "darwin":
        return ("macos", "darwin", "osx")
    raise RuntimeError(f"Unsupported operating system: {system}")


def select_release_asset(release: dict, tool_hint: str) -> dict:
    assets = release.get("assets") or []
    os_tokens = operating_system_tokens()
    arch_tokens = architecture_tokens()

    candidates: list[dict] = []
    for asset in assets:
        name = str(asset.get("name", "")).lower()
        is_archive = name.endswith((".zip", ".tar.gz", ".tgz"))
        if not is_archive:
            continue
        if not any(token in name for token in os_tokens):
            continue
        if not any(token in name for token in arch_tokens):
            continue
        if tool_hint.lower() not in name:
            continue
        candidates.append(asset)

    if not candidates:
        available = [str(asset.get("name", "")) for asset in assets]
        raise RuntimeError(
            f"No compatible release asset found for {tool_hint}. Available: {available}"
        )

    # Prefer ZIP on Windows and tar.gz elsewhere.
    if os.name == "nt":
        candidates.sort(key=lambda item: not str(item.get("name", "")).lower().endswith(".zip"))
    else:
        candidates.sort(key=lambda item: str(item.get("name", "")).lower().endswith(".zip"))
    return candidates[0]


def download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(url, stream=True, timeout=180) as response:
        response.raise_for_status()
        with destination.open("wb") as handle:
            for chunk in response.iter_content(1024 * 1024):
                if chunk:
                    handle.write(chunk)


def extract_archive(archive: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)

    if archive.name.lower().endswith(".zip"):
        with zipfile.ZipFile(archive) as zipped:
            zipped.extractall(destination)
    elif archive.name.lower().endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(destination)
    else:
        raise RuntimeError(f"Unsupported archive format: {archive.name}")


def install_release_binary(command_name: str, repository: str, asset_hint: str) -> None:
    if command_path(command_name):
        print(f"[+] {command_name} already available: {command_path(command_name)}")
        return

    print(f"[*] Installing {command_name} from {repository}...")
    release = github_latest_release(repository)
    asset = select_release_asset(release, asset_hint)
    archive = DOWNLOAD_DIR / str(asset["name"])
    extract_dir = DOWNLOAD_DIR / f"extract_{command_name}"

    download_file(str(asset["browser_download_url"]), archive)
    extract_archive(archive, extract_dir)

    expected_names = {
        command_name.lower(),
        f"{command_name}.exe".lower(),
    }
    candidates = [
        item
        for item in extract_dir.rglob("*")
        if item.is_file() and item.name.lower() in expected_names
    ]
    if not candidates:
        raise RuntimeError(
            f"Executable {command_name} was not found inside {archive.name}."
        )

    source = candidates[0]
    destination_name = f"{command_name}.exe" if os.name == "nt" else command_name
    destination = LOCAL_BIN / destination_name
    shutil.copy2(source, destination)
    if os.name != "nt":
        destination.chmod(
            destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )

    shutil.rmtree(extract_dir, ignore_errors=True)
    archive.unlink(missing_ok=True)
    configure_runtime_path()

    if not command_path(command_name):
        raise RuntimeError(f"{command_name} installation completed but it is still not resolvable.")
    print(f"[+] Installed {command_name}: {destination}")


def install_binary_scanners() -> None:
    install_release_binary("nuclei", "projectdiscovery/nuclei", "nuclei")
    install_release_binary("ffuf", "ffuf/ffuf", "ffuf")
    install_release_binary("dalfox", "hahwul/dalfox", "dalfox")
    install_release_binary(
        "interactsh-client",
        "projectdiscovery/interactsh",
        "interactsh-client",
    )


def install_all_scanners() -> None:
    print("\n=== Installing/verifying security scanners ===")
    ensure_arjun_launcher()
    install_sqlmap()
    install_commix()
    install_nikto()
    install_binary_scanners()


# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------

def scanner_status() -> dict[str, str | None]:
    configure_runtime_path()
    return {name: command_path(name) for name in REQUIRED_SCANNERS}


def print_cli_status(*, fail_on_missing: bool = False) -> dict[str, str | None]:
    status = scanner_status()
    print("\n=== Scanner executables ===")
    for name, path in status.items():
        print(f"{name:20} {'OK: ' + path if path else 'MISSING'}")

    missing = [name for name, path in status.items() if not path]
    if missing and fail_on_missing:
        raise RuntimeError(
            "Installation incomplete. Missing scanners: " + ", ".join(missing)
        )
    return status


# -----------------------------------------------------------------------------
# Local laboratory and authentication
# -----------------------------------------------------------------------------

def docker_inspect_container(name: str) -> dict | None:
    """Return Docker container inspection data, or None if the container does not exist."""
    completed = subprocess.run(
        ["docker", "inspect", name],
        text=True,
        capture_output=True,
        shell=False,
        timeout=60,
    )
    if completed.returncode != 0:
        return None

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        return None
    return payload[0]


def docker_network_exists(name: str) -> bool:
    completed = subprocess.run(
        ["docker", "network", "inspect", name],
        text=True,
        capture_output=True,
        shell=False,
        timeout=60,
    )
    return completed.returncode == 0


def ensure_network(name: str) -> None:
    """Reuse a valid Docker network, otherwise recreate it."""
    if docker_network_exists(name):
        print(f"[+] Docker network {name} already exists.")
        return

    print(f"[*] Docker network {name} is missing. Creating it...")
    run(["docker", "network", "create", name], timeout=60)


def container_matches(
    inspection: dict,
    *,
    image: str,
    network: str,
    port_bindings: dict[str, str],
) -> tuple[bool, list[str]]:
    """Validate the image, Docker network and published host ports."""
    problems: list[str] = []

    configured_image = str(inspection.get("Config", {}).get("Image", ""))
    if configured_image != image:
        problems.append(
            f"wrong image ({configured_image or 'missing'}, expected {image})"
        )

    networks = inspection.get("NetworkSettings", {}).get("Networks", {}) or {}
    if network not in networks:
        problems.append(f"not connected to network {network}")

    configured_bindings = inspection.get("HostConfig", {}).get("PortBindings", {}) or {}
    for container_port, expected_host_port in port_bindings.items():
        entries = configured_bindings.get(container_port) or []
        actual_ports = {
            str(entry.get("HostPort", ""))
            for entry in entries
            if isinstance(entry, dict)
        }
        if expected_host_port not in actual_ports:
            problems.append(
                f"missing port mapping {expected_host_port}:{container_port.split('/')[0]}"
            )

    return not problems, problems


def remove_container(name: str) -> None:
    print(f"[*] Removing invalid container {name}...")
    run(["docker", "rm", "-f", name], required=False, timeout=180)


def ensure_container(
    name: str,
    create_command: list[str],
    *,
    image: str,
    network: str,
    port_bindings: dict[str, str],
    readiness_url: str,
    readiness_attempts: int = 60,
) -> None:
    """
    Reuse a correctly configured and healthy container.

    If the container is missing, incorrectly configured, cannot start, or does
    not answer its readiness endpoint, remove it and recreate it from scratch.
    """
    inspection = docker_inspect_container(name)

    if inspection is not None:
        valid, problems = container_matches(
            inspection,
            image=image,
            network=network,
            port_bindings=port_bindings,
        )

        if valid:
            running = bool(inspection.get("State", {}).get("Running"))
            if running:
                print(f"[+] Container {name} exists and is correctly configured.")
            else:
                print(f"[*] Container {name} is valid but stopped. Starting it...")
                started = run(
                    ["docker", "start", name],
                    required=False,
                    capture=True,
                    timeout=180,
                )
                if started.returncode != 0:
                    print(f"[!] Container {name} could not be started.")
                    valid = False

            if valid and wait_http(readiness_url, attempts=readiness_attempts):
                print(f"[+] Container {name} is ready.")
                return

            if valid:
                print(
                    f"[!] Container {name} did not pass the readiness check "
                    f"at {readiness_url}."
                )
        else:
            print(f"[!] Container {name} is invalid: {', '.join(problems)}")

        remove_container(name)
    else:
        print(f"[*] Container {name} does not exist.")

    print(f"[*] Creating container {name} from scratch...")
    created = run(create_command, required=False, capture=True, timeout=1200)
    if created.returncode != 0:
        raise RuntimeError(
            f"Could not create container {name}. "
            f"Check whether its host port is already in use."
        )

    if not wait_http(readiness_url, attempts=readiness_attempts):
        run(
            ["docker", "logs", "--tail", "100", name],
            required=False,
            capture=True,
            timeout=60,
        )
        raise RuntimeError(
            f"Container {name} was recreated but is not ready at {readiness_url}. "
            f"Inspect the Docker logs shown above."
        )

    print(f"[+] Container {name} was recreated successfully and is ready.")

def wait_http(url: str, attempts: int = 60) -> bool:
    for _ in range(attempts):
        try:
            if requests.get(url, timeout=3).status_code < 500:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False


def create_wordlist() -> None:
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
    words = [
        "admin", "api", "assets", "backup", "config", "css", "docs", "images",
        "index.php", "js", "login.php", "logout.php", "robots.txt", "server-status",
        "setup.php", "uploads", "vulnerabilities",
    ]
    (WORDLISTS_DIR / "common.txt").write_text(
        "\n".join(words) + "\n",
        encoding="utf-8",
    )


def initialize_and_login_dvwa(target: str) -> str:
    """Reset DVWA and return the authenticated Cookie header value."""
    base = target.rstrip("/")
    if not wait_http(f"{base}/login.php"):
        raise RuntimeError("DVWA did not become reachable.")

    session = requests.Session()
    session.get(f"{base}/setup.php", timeout=15).raise_for_status()
    setup_response = session.post(
        f"{base}/setup.php",
        data={"create_db": "Create / Reset Database"},
        timeout=20,
        allow_redirects=True,
    )
    setup_response.raise_for_status()

    login_page = session.get(f"{base}/login.php", timeout=15)
    login_page.raise_for_status()
    token_match = re.search(
        r'name=["\']user_token["\']\s+value=["\']([^"\']+)',
        login_page.text,
        re.IGNORECASE,
    )
    credentials = {"username": "admin", "password": "password", "Login": "Login"}
    if token_match:
        credentials["user_token"] = token_match.group(1)

    login_response = session.post(
        f"{base}/login.php",
        data=credentials,
        timeout=20,
        allow_redirects=True,
    )
    if (
        "login.php" in login_response.url.lower()
        or "login :: damn vulnerable" in login_response.text.lower()
    ):
        raise RuntimeError("Automatic DVWA login failed.")

    session.cookies.set("security", "low")
    cookie = "; ".join(
        f"{name}={value}" for name, value in session.cookies.get_dict().items()
    )
    if "PHPSESSID=" not in cookie:
        raise RuntimeError("DVWA login succeeded without a PHP session cookie.")
    return cookie


def setup_local_lab(model: str) -> str:
    """Start DVWA, ZAP and Ollama, pull the model, and authenticate to DVWA."""
    if not shutil.which("docker"):
        raise RuntimeError("Docker is required for --with-lab.")

    run(["docker", "info"], timeout=60)
    ensure_network("secops-net")

    ensure_container(
        "dvwa",
        [
            "docker", "run", "-d", "--name", "dvwa",
            "--network", "secops-net", "-p", "80:80",
            "vulnerables/web-dvwa",
        ],
        image="vulnerables/web-dvwa",
        network="secops-net",
        port_bindings={"80/tcp": "80"},
        readiness_url=f"{DEFAULT_TARGET}/login.php",
        readiness_attempts=90,
    )
    ensure_container(
        "zap_mcp",
        [
            "docker", "run", "-d", "--name", "zap_mcp",
            "--network", "secops-net", "-p", "8080:8080",
            "zaproxy/zap-stable", "zap.sh", "-daemon",
            "-host", "0.0.0.0", "-port", "8080",
            "-config", "api.disablekey=true",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
        ],
        image="zaproxy/zap-stable",
        network="secops-net",
        port_bindings={"8080/tcp": "8080"},
        readiness_url="http://127.0.0.1:8080/JSON/core/view/version/",
        readiness_attempts=120,
    )
    ensure_container(
        "ollama_secops",
        [
            "docker", "run", "-d", "--name", "ollama_secops",
            "--network", "secops-net", "-p", "11434:11434",
            "-v", "ollama_secops:/root/.ollama", "ollama/ollama",
        ],
        image="ollama/ollama",
        network="secops-net",
        port_bindings={"11434/tcp": "11434"},
        readiness_url="http://127.0.0.1:11434/api/tags",
        readiness_attempts=120,
    )

    run(
        ["docker", "exec", "ollama_secops", "ollama", "pull", model],
        timeout=7200,
    )
    return initialize_and_login_dvwa(DEFAULT_TARGET)


def print_cli_commands(cookie: str, model: str) -> None:
    deterministic = [
        sys.executable,
        str(ROOT_DIR / "orchestratorDeterministic.py"),
        "--target", DEFAULT_TARGET,
        "--cookies", cookie,
    ]
    agentic = [
        sys.executable,
        str(ROOT_DIR / "orchestratorAgentic.py"),
        "--target", DEFAULT_TARGET,
        "--cookies", cookie,
        "--model", model,
    ]

    print("\n=== Reusable authenticated commands ===")
    print("\nDeterministic orchestrator:")
    print(subprocess.list2cmdline(deterministic))
    print("\nOllama/LangGraph agentic orchestrator:")
    print(subprocess.list2cmdline(agentic))
    print("\nBoth commands execute the anonymous profile by default.")
    print("Add --auth-only to run only the authenticated profile.")


# -----------------------------------------------------------------------------
# Main program
# -----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Initialize the FastMCP SecOps project and local laboratory."
    )
    parser.add_argument(
        "--with-lab",
        action="store_true",
        help="Start DVWA, ZAP and Ollama and create an authenticated DVWA session.",
    )
    parser.add_argument(
        "--run",
        choices=("none", "deterministic", "agentic"),
        default="none",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--skip-scanners",
        action="store_true",
        help="Install only Python dependencies; do not install external scanners.",
    )
    args = parser.parse_args()

    os.chdir(ROOT_DIR)
    setup_path()
    configure_runtime_path()
    print("=== SecOps FastMCP initialization ===")

    try:
        install_python_dependencies()
        create_wordlist()

        if not args.skip_scanners:
            install_all_scanners()
            print_cli_status(fail_on_missing=True)
        else:
            print_cli_status(fail_on_missing=False)

        cookie = ""
        if args.with_lab:
            cookie = setup_local_lab(args.model)
            print("\n[+] DVWA login created successfully.")
            print(f"[+] Cookie header: {cookie}")
            print_cli_commands(cookie, args.model)

        if args.run != "none":
            if not cookie:
                raise RuntimeError(
                    "--run requires --with-lab so the login cookie can be created."
                )

            script = ROOT_DIR / (
                "orchestratorAgentic.py"
                if args.run == "agentic"
                else "orchestratorDeterministic.py"
            )
            command = [
                sys.executable,
                str(script),
                "--target", DEFAULT_TARGET,
                "--cookies", cookie,
            ]
            if args.run == "agentic":
                command.extend(["--model", args.model])
            return run(command, required=False, timeout=7200).returncode

        return 0
    except Exception as exc:
        print(
            f"[-] Initialization failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
