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
    _ensure_report_docker_image, configure_path, create_wordlist, install_playwright_browser,
    install_python_packages, install_scanners, run, verify_scanners, write_runtime_config,
)
from utils import setup_path

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
            "--auth-only", "--model", model, "--max-rounds", "1", "--mode", "fast",
        )),
        ("5. Agentic BALANCED", _operator_command(
            "orchestratorAgentic.py", "--target", TARGET, "--cookies", cookie,
            "--auth-only", "--model", model, "--max-rounds", "2", "--mode", "balanced",
        )),
        ("6. Agentic DEEP", _operator_command(
            "orchestratorAgentic.py", "--target", TARGET, "--cookies", cookie,
            "--auth-only", "--model", model, "--max-rounds", "3", "--mode", "deep",
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
