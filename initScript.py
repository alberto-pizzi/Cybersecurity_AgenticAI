from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from setupLab import setup_local_lab, update_runtime_auth
from setupTools import (
    BUILD_ID, COMMAND_REFERENCE_FILE, DEFAULT_MODEL, ROOT, RUNTIME_FILE, TARGET,
    _ensure_report_docker_image, configure_path, configure_perl_environment, create_wordlist, install_playwright_browser,
    install_python_packages, install_scanners, run, verify_scanners, write_runtime_config,
)
from utils import setup_path

UNIFIED_MCP_SERVER = ROOT / "servers" / "secopsServer.py"
LINUX_BASE_PACKAGES = ("perl", "cpanminus", "build-essential")


# Prefixes privileged Linux host commands with sudo when the initializer is not already root.
def _linux_sudo_prefix() -> list[str]:
    if os.name == "nt" or not sys.platform.startswith("linux"):
        return []
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if not sudo:
        raise RuntimeError("Linux host setup requires sudo, but sudo is not installed or not available in PATH.")
    return [sudo]


# Checks whether one Debian package is already installed without changing the host.
def _debian_package_installed(package: str) -> bool:
    dpkg_query = shutil.which("dpkg-query")
    if not dpkg_query:
        return False
    result = subprocess.run(
        [dpkg_query, "-W", "-f=${Status}", package],
        text=True, encoding="utf-8", errors="replace", capture_output=True, check=False,
    )
    return result.returncode == 0 and "install ok installed" in (result.stdout or "").lower()


# Installs the Debian Perl/build prerequisites used by the native Nikto fallback and exports the user Perl library.
def ensure_linux_host_prerequisites() -> None:
    if not sys.platform.startswith("linux"):
        return
    perl_env = configure_perl_environment()
    if perl_env.get("PERL5LIB"):
        print(f"[+] PERL5LIB configured for SecOps: {perl_env['PERL5LIB']}")
    apt_get = shutil.which("apt-get")
    dpkg_query = shutil.which("dpkg-query")
    if not apt_get or not dpkg_query:
        print("[*] Non-Debian Linux detected; automatic apt prerequisite installation skipped.")
        return
    missing = [package for package in LINUX_BASE_PACKAGES if not _debian_package_installed(package)]
    if not missing:
        print("[+] Linux Perl/build prerequisites already installed: " + ", ".join(LINUX_BASE_PACKAGES))
        return
    sudo = _linux_sudo_prefix()
    print("[*] Installing missing Debian host prerequisites: " + ", ".join(missing))
    run([*sudo, apt_get, "update"], timeout=1800)
    run([*sudo, apt_get, "install", "-y", *missing], timeout=3600)
    still_missing = [package for package in LINUX_BASE_PACKAGES if not _debian_package_installed(package)]
    if still_missing:
        raise RuntimeError("Debian prerequisite installation did not complete: " + ", ".join(still_missing))


# Adds known Docker Desktop CLI directories to PATH when the installer has just created them.
def _refresh_docker_path() -> str | None:
    candidates: list[Path] = []
    if os.name == "nt":
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        candidates.extend((
            program_files / "Docker" / "Docker" / "resources" / "bin",
            program_files / "Docker" / "Docker" / "resources",
        ))
    elif sys.platform == "darwin":
        candidates.extend((
            Path("/Applications/Docker.app/Contents/Resources/bin"),
            Path.home() / "Applications" / "Docker.app" / "Contents" / "Resources" / "bin",
            Path("/opt/homebrew/bin"),
            Path("/usr/local/bin"),
        ))
    for directory in candidates:
        if not directory.is_dir():
            continue
        current = os.environ.get("PATH", "")
        entries = [entry for entry in current.split(os.pathsep) if entry]
        if str(directory) not in entries:
            os.environ["PATH"] = str(directory) + (os.pathsep + current if current else "")
        docker = shutil.which("docker")
        if docker:
            return docker
    return shutil.which("docker")


# Installs Docker only when the Docker CLI is missing. It never changes users, groups or socket permissions.
def ensure_docker_installed() -> str:
    docker = _refresh_docker_path()
    if docker:
        print(f"[+] Docker already installed: {docker}")
        return docker

    print("[*] Docker was not found; installing it for this platform.")

    if os.name == "nt":
        winget = shutil.which("winget")
        if winget:
            run([
                winget, "install", "--id", "Docker.DockerDesktop", "--exact",
                "--accept-source-agreements", "--accept-package-agreements",
            ], timeout=3600)
        else:
            choco = shutil.which("choco")
            if not choco:
                raise RuntimeError(
                    "Docker is not installed and neither winget nor Chocolatey is available. "
                    "Install Docker Desktop, then rerun initScript.py."
                )
            run([choco, "install", "docker-desktop", "-y"], timeout=3600)

    elif sys.platform == "darwin":
        brew = shutil.which("brew")
        if not brew:
            raise RuntimeError(
                "Docker is not installed and Homebrew is not available. "
                "Install Homebrew or Docker Desktop, then rerun initScript.py."
            )
        run([brew, "install", "--cask", "docker"], timeout=3600)

    elif sys.platform.startswith("linux"):
        sudo = _linux_sudo_prefix()
        installers: list[tuple[str, list[list[str]]]] = []
        if shutil.which("apt-get"):
            installers.append(("apt", [
                [*sudo, "apt-get", "update"],
                [*sudo, "apt-get", "install", "-y", "docker.io"],
            ]))
        if shutil.which("dnf"):
            installers.extend((
                ("dnf-moby", [[*sudo, "dnf", "install", "-y", "moby-engine"]]),
                ("dnf-docker", [[*sudo, "dnf", "install", "-y", "docker"]]),
            ))
        if shutil.which("yum"):
            installers.extend((
                ("yum-moby", [[*sudo, "yum", "install", "-y", "moby-engine"]]),
                ("yum-docker", [[*sudo, "yum", "install", "-y", "docker"]]),
            ))
        if shutil.which("pacman"):
            installers.append(("pacman", [[*sudo, "pacman", "-Sy", "--noconfirm", "docker"]]))
        if shutil.which("zypper"):
            installers.append(("zypper", [[*sudo, "zypper", "--non-interactive", "install", "docker"]]))
        if shutil.which("apk"):
            installers.append(("apk", [[*sudo, "apk", "add", "docker"]]))
        if not installers:
            raise RuntimeError(
                "Docker is not installed and no supported Linux package manager was found "
                "(apt-get, dnf, yum, pacman, zypper or apk)."
            )

        diagnostics: list[str] = []
        installed = False
        for label, commands in installers:
            failed = False
            for command in commands:
                result = run(command, required=False, capture=True, timeout=3600)
                if result.returncode:
                    failed = True
                    detail = "\n".join(filter(None, ((result.stdout or "").strip(), (result.stderr or "").strip())))
                    diagnostics.append(f"{label}: {detail[-1200:]}")
                    break
            if not failed and shutil.which("docker"):
                installed = True
                break
        if not installed:
            raise RuntimeError(
                "Docker installation was attempted but the docker command is still unavailable.\n" +
                "\n".join(diagnostics[-4:])
            )
    else:
        raise RuntimeError(f"Automatic Docker installation is not supported on platform {sys.platform!r}.")

    docker = _refresh_docker_path()
    if not docker:
        raise RuntimeError(
            "Docker installation completed but the docker command is not visible in the current PATH. "
            "Restart the terminal/session if your platform installer updated PATH, then rerun initScript.py."
        )
    print(f"[+] Docker installed: {docker}")
    return docker


# Fail early when the project source tree is incomplete for the unified MCP architecture.
def verify_unified_mcp_source() -> None:
    if not UNIFIED_MCP_SERVER.is_file():
        raise RuntimeError(
            "Unified MCP server source is missing.\n"
            f"Expected: {UNIFIED_MCP_SERVER}\n"
            "Copy servers/secopsServer.py from the same project version before running initialization or an orchestrator."
        )


# Before normal execution, live preflight catches configuration problems that would break later scans.
def run_preflight() -> None:
    script = ROOT / "orchestratorDeterministic.py"
    environment = {"PATH": os.environ.get("PATH", "")}
    if sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        environment["VIRTUAL_ENV"] = str(Path(sys.executable).parent.parent)
    result = run(
        [sys.executable, str(script), "--target", TARGET, "--preflight-only"], required=False,
        capture=True, timeout=300, cwd=ROOT, env_overrides=environment,
    )
    if result.returncode:
        combined = "\n".join(filter(None, ((result.stdout or ""), (result.stderr or ""))))
        if "ModuleNotFoundError" in combined:
            raise RuntimeError(
                "The live preflight launched an MCP server with an interpreter missing project dependencies.\n"
                f"Initializer interpreter: {sys.executable}\n"
                "The unified orchestrator should prefer this exact interpreter; verify that the project files were all updated together.\n"
                f"Diagnostic: {combined[-2500:]}"
            )
        raise RuntimeError("The live orchestrator preflight failed.\n" + combined[-2500:])

# Reads the operator guide from disk and falls back to a minimal built-in version when needed.
def command_reference_text() -> str:

    try:
        return COMMAND_REFERENCE_FILE.read_text(encoding="utf-8")
    except OSError:
        return (
            "SecOps FastMCP - guida operativa\n\n"
            "python initScript.py --with-lab\n"
            "python orchestratorDeterministic.py --target <TARGET> --authorized --preflight-only\n"
        )

# Ensures the operator command guide exists before it is displayed or reused.
def write_command_reference() -> Path:
    if not COMMAND_REFERENCE_FILE.is_file():
        COMMAND_REFERENCE_FILE.write_text(command_reference_text(), encoding="utf-8")
    return COMMAND_REFERENCE_FILE

# Prints the complete operator guide in a readable terminal format.
def print_command_reference(path: Path) -> None:
    print("\n=== Complete SecOps command reference ===")
    print(command_reference_text().rstrip())
    print(f"\n[+] Command guide written: {path}")

# Builds a copy-and-paste-safe command for the current shell.
def _operator_command(script: str, *arguments: str) -> str:

    values = [sys.executable, str(ROOT / script), *arguments]
    return subprocess.list2cmdline(values) if os.name == "nt" else shlex.join(values)

# Loads the latest local-lab cookie so generated examples use the current session.
def _runtime_cookie_for_commands() -> str:

    try:
        payload = json.loads(RUNTIME_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    if str(payload.get("last_auth_target") or "") != TARGET:
        return ""
    return str(payload.get("last_auth_cookie") or "").strip()

# Prints the main balanced and deep commands that the operator can run next.
def print_important_commands(
    model: str, mode: str = "balanced", cookie_header: str = "",
) -> None:

    cookie = cookie_header or "<COOKIE_HEADER>"
    print("\n=== Commands ready to run ===")
    print("Run them from: " + str(ROOT))
    commands = (
        ("1. Deterministic FAST", _operator_command(
            "orchestratorDeterministic.py", "--target", TARGET, "--cookies", cookie, "--auth-only", "--mode", "fast",
        )),
        ("2. Deterministic BALANCED", _operator_command(
            "orchestratorDeterministic.py", "--target", TARGET, "--cookies", cookie, "--auth-only", "--mode",
            "balanced",
        )),
        ("3. Deterministic DEEP", _operator_command(
            "orchestratorDeterministic.py", "--target", TARGET, "--cookies", cookie, "--auth-only", "--mode", "deep",
        )),
        ("4. Agentic FAST", _operator_command(
            "orchestratorAgentic.py", "--target", TARGET, "--cookies", cookie,
            "--auth-only", "--model", model, "--max-rounds", "2", "--mode", "fast", "--require-ai",
        )),
        ("5. Agentic BALANCED", _operator_command(
            "orchestratorAgentic.py", "--target", TARGET, "--cookies", cookie,
            "--auth-only", "--model", model, "--max-rounds", "2", "--mode", "balanced", "--require-ai",
        )),
        ("6. Agentic DEEP", _operator_command(
            "orchestratorAgentic.py", "--target", TARGET, "--cookies", cookie,
            "--auth-only", "--model", model, "--max-rounds", "3", "--mode", "deep", "--require-ai",
        )),
    )
    for label, command in commands:
        print(f"\n{label}:\n{command}")
    print("\nZAP isolated DEEP full-priority diagnostic:")
    print(_operator_command(
        "orchestratorDeterministic.py", "--target", TARGET, "--cookies", cookie,
        "--tool", "zap", "--mode", "deep", "--tool-timeout", "480",
    ))
    print(f"\n[+] Every command and modifier: {COMMAND_REFERENCE_FILE}")

# Parses command-line options and drives the complete workflow for this entrypoint.
def main() -> int:
    print(f"=== SecOps initializer [{BUILD_ID}] ===")
    parser = argparse.ArgumentParser(
        description="Initialize FastMCP SecOps and generate the complete operator command guide."
    )
    parser.add_argument("--with-lab", action="store_true", help="Start/verify the bundled local training lab, ZAP and Ollama, then create a session.")
    parser.add_argument("--run", choices=("none", "deterministic", "agentic"), default="none", help="Run an orchestrator after initialization; deterministic/agentic requires --with-lab.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model for local-lab/agentic execution (default: {DEFAULT_MODEL}).")
    parser.add_argument("--mode", choices=("fast", "balanced", "deep"), default="balanced", help="Scanner coverage/runtime profile (default: balanced).")
    parser.add_argument("--skip-preflight", action="store_true", help="Skip the live deterministic MCP/dependency preflight.")
    parser.add_argument("--skip-scanners", action="store_true", help="Skip scanner installation and do not require all scanner executables.")
    parser.add_argument("--skip-browser", action="store_true", help="Do not install/verify Playwright Chromium; browser-only checks will be skipped.")
    parser.add_argument("--require-browser", action="store_true", help="Fail initialization if Playwright Chromium cannot be installed/launched.")
    parser.add_argument("--commands-only", action="store_true", help="Print every supported command/modifier, write init.txt, and exit.")
    parser.add_argument("--version", action="version", version=BUILD_ID)
    args = parser.parse_args()

    os.chdir(ROOT)
    setup_path()
    configure_path()
    cookie = ""
    commands_printed = False
    try:
        # Before scans can run, setup installs the required tools and verifies the local environment.
        guide_path = write_command_reference()
        if args.commands_only:
            print_command_reference(guide_path)
            return 0
        print(f"[+] Full command guide written: {guide_path}")
        verify_unified_mcp_source()
        print(f"[+] Unified MCP server source: {UNIFIED_MCP_SERVER}")
        if not args.skip_scanners:
            ensure_linux_host_prerequisites()
        elif sys.platform.startswith("linux"):
            configure_perl_environment()
        ensure_docker_installed()
        print("\n=== SecOps FastMCP initialization ===")
        install_python_packages()
        if not args.skip_browser:
            install_playwright_browser(required=args.require_browser)
        elif args.require_browser:
            raise RuntimeError("--require-browser cannot be combined with --skip-browser.")
        create_wordlist()
        if not args.skip_scanners:
            install_scanners()
        if shutil.which("docker"):
            _ensure_report_docker_image()
        status = verify_scanners(required=not args.skip_scanners)
        write_runtime_config(status)


        # When the operator enables the bundled lab, setup starts it and prepares a fresh authenticated session.
        if args.with_lab:
            cookie = setup_local_lab(args.model)
            update_runtime_auth(cookie)
            print(f"\n[+] Bundled local-lab login created successfully.\n[+] Cookie header: {cookie}")

        if not args.skip_preflight:
            run_preflight()

        if args.run != "none":
            if not cookie:
                raise RuntimeError("--run requires --with-lab because it needs a generated local-lab session.")
            script = "orchestratorAgentic.py" if args.run == "agentic" else "orchestratorDeterministic.py"
            command = [sys.executable, str(ROOT / script), "--target", TARGET, "--cookies", cookie, "--mode", args.mode]
            if args.run == "agentic":
                command += ["--model", args.model, "--max-rounds", "1"]
            return run(command, required=False, timeout=7200, cwd=ROOT).returncode

        print_important_commands(args.model, args.mode, cookie or _runtime_cookie_for_commands())
        commands_printed = True
        return 0
    except Exception as exc:
        print(f"[-] Initialization failed: {type(exc).__name__}: {exc}", file=sys.stderr)


        if not args.commands_only and not commands_printed:
            print_important_commands(
                args.model, args.mode, cookie or _runtime_cookie_for_commands(),
            )
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
