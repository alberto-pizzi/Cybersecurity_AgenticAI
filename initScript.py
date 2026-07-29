from __future__ import annotations

import argparse
import json
import importlib.metadata
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import sysconfig
import tarfile
import time
import zipfile
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from packaging.requirements import Requirement

from utils import canonical_cookie_header, cookie_names, ROOT_DIR, WORDLISTS_DIR, setup_path

ROOT = Path(ROOT_DIR).resolve()
LOCAL_ROOT = Path.home() / ".local"
LOCAL_BIN = LOCAL_ROOT / "bin"
LOCAL_OPT = LOCAL_ROOT / "opt"
DOWNLOADS = LOCAL_ROOT / "downloads"
RUNTIME_FILE = ROOT / ".secops_runtime.json"
COMMAND_REFERENCE_FILE = ROOT / "init.txt"
TARGET = "http://127.0.0.1"
LOCAL_LAB_CONTAINER = "dvwa"
LOCAL_LAB_IMAGE = "vulnerables/web-dvwa"
LOCAL_LAB_NETWORK = "secops-net"
DEFAULT_MODEL = "llama3.1:8b"
NUCLEI_TEMPLATE_MINIMUM = 1000
NUCLEI_TEMPLATE_UPDATE_TIMEOUT = 600
_NUCLEI_TEMPLATE_STATE: dict[str, Any] = {}
BUILD_ID = "secops-init-resilient-v31.11.4-nikto-docker-dns-nolookup-fix-20260729"

PYTHON_PACKAGES = (
    "fastmcp==2.12.5", "langgraph>=0.6,<2", "requests>=2.32,<3",
    "beautifulsoup4>=4.13,<5", "zaproxy>=0.5,<0.6",
    "reportlab>=4.4,<5", "PyJWT>=2.10,<3", "arjun>=2.2,<3",
    "playwright>=1.54,<2",
)
SCANNERS = ("nuclei", "nikto", "ffuf", "dalfox", "commix", "sqlmap", "arjun", "interactsh-client")
REPOSITORY_TOOLS = {
    "sqlmap": ("https://github.com/sqlmapproject/sqlmap.git", "sqlmap.py"),
    "commix": ("https://github.com/commixproject/commix.git", "commix.py"),
}
RELEASE_TOOLS = {
    "nuclei": ("projectdiscovery/nuclei", "nuclei"),
    "ffuf": ("ffuf/ffuf", "ffuf"),
    "dalfox": ("hahwul/dalfox", "dalfox"),
    "interactsh-client": ("projectdiscovery/interactsh", "interactsh-client"),
}


def run(
    command: list[str],
    *,
    required: bool = True,
    capture: bool = False,
    show_output: bool = True,
    timeout: int = 3600,
    cwd: Path | None = None,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    print("[+] " + subprocess.list2cmdline(command))
    try:
        child_env = os.environ.copy()
        child_env.setdefault("PYTHONUTF8", "1")
        child_env.setdefault("PYTHONIOENCODING", "utf-8")
        if env_overrides:
            child_env.update(env_overrides)
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env=child_env,
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=capture,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Command not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out: {subprocess.list2cmdline(command)}") from exc
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if capture and show_output:
        if stdout.strip():
            print(stdout.strip())
        if stderr.strip():
            print(stderr.strip(), file=sys.stderr)
    if required and result.returncode:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {subprocess.list2cmdline(command)}\n"
            f"{stderr if capture else ''}"
        )
    return result


def _add_path(path: Path) -> None:
    if not path.is_dir():
        return
    resolved = str(path.resolve())
    current = [part for part in os.environ.get("PATH", "").split(os.pathsep) if part]
    if os.path.normcase(resolved) not in {os.path.normcase(os.path.abspath(part)) for part in current}:
        os.environ["PATH"] = resolved + os.pathsep + os.environ.get("PATH", "")


def configure_path() -> list[str]:
    for directory in (LOCAL_BIN, LOCAL_OPT, DOWNLOADS):
        directory.mkdir(parents=True, exist_ok=True)
    candidates = [LOCAL_BIN]
    try:
        scripts = sysconfig.get_path("scripts", scheme="nt_user" if os.name == "nt" else "posix_user")
        if scripts:
            candidates.append(Path(scripts))
    except (KeyError, ValueError):
        pass
    try:
        import site
        candidates.append(Path(site.USER_BASE) / ("Scripts" if os.name == "nt" else "bin"))
    except Exception:
        pass
    candidates.append(Path(sys.executable).parent)
    added = []
    for path in candidates:
        if path.is_dir():
            _add_path(path)
            added.append(str(path.resolve()))
    return list(dict.fromkeys(added))


def command_path(name: str) -> str | None:
    configure_path()
    value = shutil.which(name)
    return str(Path(value).resolve()) if value else None


def write_launcher(name: str, command: list[str]) -> Path:
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        path = LOCAL_BIN / f"{name}.bat"
        path.write_text("@echo off\r\n" + subprocess.list2cmdline(command) + " %*\r\n", encoding="utf-8")
    else:
        path = LOCAL_BIN / name
        quoted = shlex.join([str(part) for part in command])
        path.write_text(f"#!/usr/bin/env sh\nexec {quoted} \"$@\"\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    configure_path()
    print(f"[+] Launcher created: {path}")
    return path


def _verify_fastmcp_import() -> tuple[bool, str]:
    """Verify the exact FastMCP import used by the orchestrators."""
    probe = run(
        [sys.executable, "-c", "from fastmcp import Client; from fastmcp.client.transports import StdioTransport"],
        required=False,
        capture=True,
        show_output=False,
        timeout=60,
    )
    detail = "\n".join(
        part for part in ((probe.stdout or "").strip(), (probe.stderr or "").strip())
        if part
    )
    return probe.returncode == 0, detail


def _missing_python_packages() -> list[str]:
    """Return only missing or version-incompatible requirements.

    This avoids contacting PyPI on every initializer run. It is especially
    important for offline/local-lab runs where all dependencies are already
    installed but DNS is temporarily unavailable.
    """
    missing: list[str] = []
    for raw in PYTHON_PACKAGES:
        requirement = Requirement(raw)
        try:
            installed = importlib.metadata.version(requirement.name)
        except importlib.metadata.PackageNotFoundError:
            missing.append(raw)
            continue
        if requirement.specifier and installed not in requirement.specifier:
            missing.append(raw)
    return missing


def install_python_packages() -> None:
    """Install only missing requirements, then repair a stale FastMCP install."""
    try:
        importlib.metadata.version("python-owasp-zap-v2.4")
    except importlib.metadata.PackageNotFoundError:
        pass
    else:
        run(
            [sys.executable, "-m", "pip", "uninstall", "-y", "python-owasp-zap-v2.4"],
            required=False,
            capture=True,
            show_output=False,
            timeout=600,
        )

    missing = _missing_python_packages()
    if missing:
        print("[*] Installing missing/incompatible Python packages: " + ", ".join(missing))
        run([sys.executable, "-m", "pip", "install", *missing], timeout=3600)
    else:
        print("[+] Python dependencies already satisfy the pinned requirements; PyPI access skipped.")

    healthy, detail = _verify_fastmcp_import()
    if not healthy:
        print("[!] FastMCP import is stale or inconsistent; forcing a clean pinned reinstall.")
        fastmcp_pin = next(
            (package for package in PYTHON_PACKAGES if package.lower().startswith("fastmcp")),
            "fastmcp==2.12.5",
        )
        run(
            [sys.executable, "-m", "pip", "uninstall", "-y", "fastmcp"],
            required=False,
            capture=True,
            show_output=False,
            timeout=300,
        )
        run(
            [sys.executable, "-m", "pip", "install", "--no-cache-dir", fastmcp_pin],
            timeout=1800,
        )
        healthy, detail = _verify_fastmcp_import()
        if not healthy:
            raise RuntimeError(
                "FastMCP still cannot be imported by the active interpreter after a clean reinstall.\n"
                f"Interpreter: {sys.executable}\n"
                f"Diagnostic: {detail[-2500:]}\n"
                "Recreate the project virtual environment and ensure no local fastmcp.py or mcp.py shadows the package."
            )
    configure_path()


def _playwright_chromium_ready() -> tuple[bool, str]:
    """Verify that Chromium can launch from the exact active interpreter."""
    probe_code = (
        "from playwright.sync_api import sync_playwright; "
        "p=sync_playwright().start(); "
        "b=p.chromium.launch(headless=True); "
        "print(b.version); b.close(); p.stop()"
    )
    probe = run(
        [sys.executable, "-c", probe_code],
        required=False, capture=True, show_output=False, timeout=120,
    )
    detail = "\n".join(
        part for part in ((probe.stdout or "").strip(), (probe.stderr or "").strip())
        if part
    )
    return probe.returncode == 0, detail


def install_playwright_browser(*, required: bool = False) -> bool:
    """Install/verify the Chromium runtime used by the optional browser scanner."""
    ready, detail = _playwright_chromium_ready()
    if ready:
        print(f"[+] Playwright Chromium ready: {detail.splitlines()[-1] if detail else 'launch verified'}")
        return True
    print("[*] Installing Playwright Chromium for DOM/stored-XSS workflow verification.")
    result = run(
        [sys.executable, "-m", "playwright", "install", "chromium"],
        required=False, capture=True, timeout=2400,
    )
    ready, detail = _playwright_chromium_ready()
    if ready:
        print(f"[+] Playwright Chromium installed: {detail.splitlines()[-1] if detail else 'launch verified'}")
        return True
    message = (
        "Playwright is installed but Chromium could not be launched. "
        f"Installer return code={result.returncode}. Diagnostic: {detail[-2500:]}"
    )
    if platform.system().lower() == "linux":
        message += "\nOn Linux, install browser system dependencies with: python -m playwright install-deps chromium"
    if required:
        raise RuntimeError(message)
    print(f"[!] {message}\n[!] Browser-only checks will be reported as skipped; all other scanners remain available.", file=sys.stderr)
    return False


def clone_or_update(url: str, destination: Path) -> None:
    if not shutil.which("git"):
        raise RuntimeError("Git is required to install SQLMap, Commix and Nikto.")
    if (destination / ".git").is_dir():
        if run(["git", "-C", str(destination), "pull", "--ff-only"], required=False, capture=True, timeout=600).returncode:
            print(f"[!] Keeping the existing {destination.name} checkout.")
        return
    shutil.rmtree(destination, ignore_errors=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--depth", "1", url, str(destination)], timeout=1200)


def install_repository_tool(name: str, repository: str, script_name: str) -> None:
    if command_path(name):
        print(f"[+] {name} already available: {command_path(name)}")
        return
    destination = LOCAL_OPT / name
    clone_or_update(repository, destination)
    script = destination / script_name
    if not script.is_file():
        raise RuntimeError(f"Missing {script_name} after cloning {name}.")
    write_launcher(name, [sys.executable, str(script)])


def find_perl() -> str | None:
    found = shutil.which("perl")
    if found:
        return found
    candidates: tuple[Path, ...] = ()
    if os.name == "nt":
        candidates = (
            Path(r"C:\Strawberry\perl\bin\perl.exe"),
            Path(r"C:\Program Files\Strawberry Perl\perl\bin\perl.exe"),
        )
    elif platform.system().lower() == "darwin":
        candidates = (
            Path("/opt/homebrew/opt/perl/bin/perl"),
            Path("/opt/homebrew/bin/perl"),
            Path("/usr/local/opt/perl/bin/perl"),
            Path("/usr/local/bin/perl"),
            Path("/usr/bin/perl"),
        )
    for candidate in candidates:
        if candidate.is_file():
            _add_path(candidate.parent)
            return str(candidate)
    return None


def _perl_reinstall_hint() -> str:
    if os.name == "nt":
        return (
            "Install/repair Strawberry Perl with:\n"
            "  winget uninstall --id StrawberryPerl.StrawberryPerl --exact\n"
            "  winget install --id StrawberryPerl.StrawberryPerl --exact"
        )
    if platform.system().lower() == "darwin":
        return (
            "Install the macOS build tools and Perl with:\n"
            "  xcode-select --install\n"
            "  brew install perl cpanminus"
        )
    return (
        "Install Perl and build tools with your package manager, for example:\n"
        "  sudo apt install perl cpanminus build-essential"
    )


def _perl_module_available(perl: Path, module: str) -> tuple[bool, str]:
    probe = run(
        [str(perl), f"-M{module}", "-e", f"print ${module}::VERSION"],
        required=False,
        capture=True,
        show_output=False,
        timeout=60,
    )
    parts = [(probe.stdout or "").strip(), (probe.stderr or "").strip()]
    detail = "\n".join(part for part in parts if part)
    return probe.returncode == 0, detail


def _strawberry_root(perl: Path) -> Path:
    """Return the Strawberry root on Windows; a harmless parent elsewhere."""
    resolved = perl.resolve()
    if os.name == "nt":
        parts = [part.lower() for part in resolved.parts]
        try:
            perl_index = parts.index("perl")
            if perl_index > 0:
                return Path(*resolved.parts[:perl_index])
        except ValueError:
            pass
    return resolved.parent.parent


def _configure_perl_toolchain(perl: Path) -> tuple[Path | None, str]:
    """Resolve the make/compiler toolchain on Windows, macOS and Linux."""
    is_windows = os.name == "nt"
    root = _strawberry_root(perl) if is_windows else None
    tool_dirs = (
        (perl.parent, root / "c" / "bin", root / "perl" / "site" / "bin")
        if root is not None
        else (perl.parent,)
    )
    for directory in tool_dirs:
        if directory.is_dir():
            _add_path(directory)

    probe = run(
        [str(perl), "-MConfig", "-e", "print $Config{make}"],
        required=False,
        capture=True,
        show_output=False,
        timeout=30,
    )
    configured_name = (probe.stdout or "").strip() or "make"
    names = list(dict.fromkeys((configured_name, "gmake", "dmake", "make")))
    candidates: list[Path] = []
    if root is not None:
        candidates.extend(root / "c" / "bin" / name for name in names)
        candidates.extend(
            root / "c" / "bin" / f"{name}.exe"
            for name in names
            if not name.lower().endswith(".exe")
        )
    make = next((path.resolve() for path in candidates if path.is_file()), None)
    if make is None:
        found = next((shutil.which(name) for name in names if shutil.which(name)), None)
        make = Path(found).resolve() if found else None
    if make is not None:
        _add_path(make.parent)
    detail = f"configured make={configured_name}; resolved={make or 'missing'}; root={root or 'n/a'}"
    return make, detail


def _install_perl_module(perl: Path, module: str) -> None:
    """Install a missing Perl module through cpanm or CPAN."""
    make, toolchain_detail = _configure_perl_toolchain(perl)
    if make is None:
        raise RuntimeError(
            "Perl is missing the required build toolchain. "
            f"{toolchain_detail}\n{_perl_reinstall_hint()}"
        )

    environment = {
        "PATH": os.environ.get("PATH", ""),
        "MAKE": str(make),
        "PERL_MM_USE_DEFAULT": "1",
        "PERL_AUTOINSTALL": "--defaultdeps",
        "NONINTERACTIVE_TESTING": "1",
    }
    cpanm_candidates = (
        perl.parent / "cpanm.bat",
        perl.parent / "cpanm.exe",
        perl.parent / "cpanm",
        perl.parent.parent / "site" / "bin" / "cpanm.bat",
        perl.parent.parent / "site" / "bin" / "cpanm.exe",
        Path("/opt/homebrew/bin/cpanm"),
        Path("/usr/local/bin/cpanm"),
    )
    attempts: list[str] = []
    cpanm = next((path for path in cpanm_candidates if path.exists()), None)
    if cpanm:
        result = run(
            [str(cpanm), "--notest", module],
            required=False,
            capture=True,
            timeout=1800,
            env_overrides=environment,
        )
        attempts.append("\n".join(filter(None, ((result.stdout or "").strip(), (result.stderr or "").strip())))[:4000])
        healthy, _ = _perl_module_available(perl, module)
        if healthy:
            return

    cpan_candidates = (
        perl.parent / "cpan.bat", perl.parent / "cpan.exe", perl.parent / "cpan",
        Path("/opt/homebrew/bin/cpan"), Path("/usr/local/bin/cpan"), Path("/usr/bin/cpan"),
    )
    cpan = next((path for path in cpan_candidates if path.exists()), None)
    command = [str(cpan), "-T", module] if cpan else [str(perl), "-MCPAN", "-e", f"CPAN::Shell->install('{module}')"]
    result = run(
        command,
        required=False,
        capture=True,
        timeout=1800,
        env_overrides=environment,
    )
    attempts.append("\n".join(filter(None, ((result.stdout or "").strip(), (result.stderr or "").strip())))[:4000])
    healthy, detail = _perl_module_available(perl, module)
    if not healthy:
        diagnostics = "\n--- installer attempt ---\n".join(value for value in attempts if value)
        raise RuntimeError(
            f"Perl module {module} could not be installed. {toolchain_detail}. {detail}\n{diagnostics}\n"
            "Install the missing modules manually with: cpan JSON XML::Writer\n"
            f"{_perl_reinstall_hint()}"
        )


def _write_nikto_launcher(perl: Path, script: Path) -> Path:
    """Create a quoting-safe native Nikto launcher on every platform."""
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    wrapper = LOCAL_OPT / "nikto_launcher.py"
    wrapper.write_text(
        "import subprocess, sys\n"
        f"raise SystemExit(subprocess.call([{str(perl)!r}, {str(script)!r}, *sys.argv[1:]]))\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        launcher = LOCAL_BIN / "nikto.bat"
        launcher.write_text(
            "@echo off\r\n"
            f'"{sys.executable}" "{wrapper}" %*\r\n'
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )
    else:
        launcher = LOCAL_BIN / "nikto"
        launcher.write_text(
            f"#!/usr/bin/env sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(wrapper))} \"$@\"\n",
            encoding="utf-8",
        )
        launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    configure_path()
    return launcher


def _nikto_health(perl: Path, script: Path, launcher: Path | None = None) -> tuple[bool, str]:
    fatal = re.compile(
        r"(?:can't open perl script|cannot open perl script|invalid argument|required module not found|"
        r"not recognized|non .? riconosciuto|no such file|modulenotfounderror|traceback|^error:)",
        re.IGNORECASE | re.MULTILINE,
    )
    commands = [[str(perl), str(script), "-Version"]]
    if launcher:
        commands.append([str(launcher), "-Version"])
    details: list[str] = []
    for command in commands:
        result = run(command, required=False, capture=True, show_output=False, timeout=60)
        parts = [(result.stdout or "").strip(), (result.stderr or "").strip()]
        combined = "\n".join(part for part in parts if part)
        details.append(combined or f"exit={result.returncode}")
        if result.returncode != 0 or fatal.search(combined):
            return False, details[-1]
    return True, details[-1]


NIKTO_DOCKER_IMAGE = "ghcr.io/sullo/nikto:latest"


def _docker_image_ready(image: str) -> bool:
    if not shutil.which("docker"):
        return False
    result = run(
        ["docker", "image", "inspect", image],
        required=False,
        capture=True,
        show_output=False,
        timeout=60,
    )
    return result.returncode == 0


def _ensure_nikto_docker_image() -> bool:
    if _docker_image_ready(NIKTO_DOCKER_IMAGE):
        print(f"[+] Nikto Docker fallback already available: {NIKTO_DOCKER_IMAGE}")
        return True
    if not shutil.which("docker"):
        return False
    result = run(
        ["docker", "pull", NIKTO_DOCKER_IMAGE],
        required=False,
        capture=True,
        timeout=1800,
    )
    if result.returncode == 0 and _docker_image_ready(NIKTO_DOCKER_IMAGE):
        print(f"[+] Nikto Docker fallback installed: {NIKTO_DOCKER_IMAGE}")
        return True
    print("[!] Nikto Docker image could not be pulled. Native Perl will be checked as a secondary option.")
    return False


def _write_nikto_docker_launcher() -> Path:
    """Create a CLI-compatible marker/launcher while MCP uses its richer Docker path."""
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        launcher = LOCAL_BIN / "nikto.bat"
        launcher.write_text(
            "@echo off\\r\\n"
            f'docker run --rm "{NIKTO_DOCKER_IMAGE}" %*\\r\\n'
            "exit /b %ERRORLEVEL%\\r\\n",
            encoding="utf-8",
        )
    else:
        launcher = LOCAL_BIN / "nikto"
        launcher.write_text(
            "#!/usr/bin/env sh\\n"
            f'exec docker run --rm "{NIKTO_DOCKER_IMAGE}" "$@"\\n',
            encoding="utf-8",
        )
        launcher.chmod(
            launcher.stat().st_mode
            | stat.S_IXUSR
            | stat.S_IXGRP
            | stat.S_IXOTH
        )
    configure_path()
    print(f"[+] Nikto Docker launcher created: {launcher}")
    return launcher


def install_nikto() -> None:
    """Prefer the official Docker image; use native Perl when Docker is absent."""
    if _ensure_nikto_docker_image():
        _write_nikto_docker_launcher()
        return

    destination = LOCAL_OPT / "nikto"
    script = destination / "program" / "nikto.pl"
    if not script.is_file():
        clone_or_update("https://github.com/sullo/nikto.git", destination)

    perl_value = find_perl()
    if not script.is_file() or not perl_value:
        raise RuntimeError(
            "Nikto is unavailable: the official Docker image is not ready and the native Perl fallback is incomplete.\n"
            f"{_perl_reinstall_hint()}"
        )

    perl = Path(perl_value).resolve()
    make, toolchain_detail = _configure_perl_toolchain(perl)
    if make is None:
        raise RuntimeError(
            "The native Perl build toolchain is incomplete and the Docker fallback is unavailable. "
            f"{toolchain_detail}.\n{_perl_reinstall_hint()}"
        )
    print(f"[+] Perl build tool: {make}")
    for module in ("XML::Writer", "JSON"):
        available, _ = _perl_module_available(perl, module)
        if not available:
            print(f"[*] Installing missing Perl module: {module}")
            _install_perl_module(perl, module)

    launcher = _write_nikto_launcher(perl, script.resolve())
    healthy, detail = _nikto_health(perl, script.resolve(), launcher)
    if not healthy:
        raise RuntimeError(
            f"Native Nikto runtime verification failed: {detail}.\n{_perl_reinstall_hint()}"
        )
    print(f"[+] Nikto runtime and launcher verified: {launcher}")


def ensure_arjun() -> None:
    if command_path("arjun"):
        print(f"[+] arjun already available: {command_path('arjun')}")
        return
    if run([sys.executable, "-m", "arjun", "--help"], required=False, capture=True, timeout=60).returncode == 0:
        write_launcher("arjun", [sys.executable, "-m", "arjun"])
        return
    raise RuntimeError("Arjun is installed but no executable/module entry point is available.")


def github_release(repository: str) -> dict[str, Any]:
    response = requests.get(f"https://api.github.com/repos/{repository}/releases/latest", headers={"Accept": "application/vnd.github+json"}, timeout=60)
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError(f"Invalid GitHub response for {repository}.")
    return value


def select_asset(release: dict[str, Any], hint: str) -> dict[str, Any]:
    machine = platform.machine().lower()
    arch = ("amd64", "x86_64", "64bit") if machine in {"amd64", "x86_64", "x64"} else ("arm64", "aarch64")
    system = platform.system().lower()
    os_tokens = ("windows", "win") if system == "windows" else ("linux",) if system == "linux" else ("macos", "darwin", "osx")
    assets = []
    for asset in release.get("assets", []):
        name = str(asset.get("name", "")).lower()
        if name.endswith((".zip", ".tar.gz", ".tgz")) and hint.lower() in name and any(token in name for token in arch) and any(token in name for token in os_tokens):
            assets.append(asset)
    if not assets:
        raise RuntimeError(f"No compatible {hint} release asset found.")
    assets.sort(key=lambda item: not str(item.get("name", "")).lower().endswith(".zip") if os.name == "nt" else str(item.get("name", "")).lower().endswith(".zip"))
    return assets[0]


def install_release_tool(name: str, repository: str, hint: str) -> None:
    if command_path(name):
        print(f"[+] {name} already available: {command_path(name)}")
        return
    asset = select_asset(github_release(repository), hint)
    archive = DOWNLOADS / str(asset["name"])
    extract_dir = DOWNLOADS / f"extract_{name}"
    with requests.get(str(asset["browser_download_url"]), stream=True, timeout=180) as response:
        response.raise_for_status()
        with archive.open("wb") as handle:
            for chunk in response.iter_content(1024 * 1024):
                if chunk:
                    handle.write(chunk)
    shutil.rmtree(extract_dir, ignore_errors=True)
    extract_dir.mkdir(parents=True)
    if archive.name.lower().endswith(".zip"):
        with zipfile.ZipFile(archive) as source:
            source.extractall(extract_dir)
    else:
        with tarfile.open(archive, "r:gz") as source:
            source.extractall(extract_dir)
    expected = {name.lower(), f"{name}.exe".lower()}
    executable = next((path for path in extract_dir.rglob("*") if path.is_file() and path.name.lower() in expected), None)
    if not executable:
        raise RuntimeError(f"Executable {name} was not found in {archive.name}.")
    destination = LOCAL_BIN / (f"{name}.exe" if os.name == "nt" else name)
    shutil.copy2(executable, destination)
    if os.name != "nt":
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    shutil.rmtree(extract_dir, ignore_errors=True)
    archive.unlink(missing_ok=True)
    configure_path()


def _nuclei_template_directories() -> list[Path]:
    home = Path.home()
    appdata = os.environ.get("APPDATA", "").strip()
    localappdata = os.environ.get("LOCALAPPDATA", "").strip()
    programdata = os.environ.get("PROGRAMDATA", "").strip()
    candidates = [
        Path(os.environ["NUCLEI_TEMPLATES_DIR"]).expanduser()
        if os.environ.get("NUCLEI_TEMPLATES_DIR") else None,
        ROOT / "tools" / "nuclei-templates",
        home / "nuclei-templates",
        home / ".local" / "nuclei-templates",
        home / ".config" / "nuclei" / "templates",
        home / "AppData" / "Roaming" / "nuclei" / "templates",
        Path(appdata) / "nuclei-templates" if appdata else None,
        Path(appdata) / "nuclei" / "templates" if appdata else None,
        Path(localappdata) / "nuclei-templates" if localappdata else None,
        Path(localappdata) / "nuclei" / "templates" if localappdata else None,
        Path(programdata) / "nuclei-templates" if programdata else None,
    ]
    return list(dict.fromkeys(path.resolve() for path in candidates if path is not None))


def _filesystem_nuclei_template_inventory() -> list[dict[str, Any]]:
    inventories: list[dict[str, Any]] = []
    for directory in _nuclei_template_directories():
        if not directory.is_dir():
            continue
        count = sum(
            1
            for path in directory.rglob("*")
            if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}
        )
        inventories.append({"directory": str(directory), "count": count})
    inventories.sort(key=lambda item: int(item["count"]), reverse=True)
    return inventories


def _filesystem_nuclei_template_count() -> tuple[int, list[str]]:
    inventory = _filesystem_nuclei_template_inventory()
    return (
        max((int(item["count"]) for item in inventory), default=0),
        [str(item["directory"]) for item in inventory],
    )


def _best_nuclei_template_directory() -> str:
    inventory = _filesystem_nuclei_template_inventory()
    return str(inventory[0]["directory"]) if inventory and int(inventory[0]["count"]) > 0 else ""


def _nuclei_listed_template_count(executable: str) -> tuple[int, str]:
    probe = run(
        [executable, "-tl", "-silent", "-nc", "-disable-update-check"],
        required=False,
        capture=True,
        show_output=False,
        timeout=240,
    )
    lines = {
        line.strip()
        for line in (probe.stdout or "").splitlines()
        if line.strip() and not line.lstrip().startswith("[")
    }
    detail = "\n".join(part for part in ((probe.stdout or "")[-1000:], (probe.stderr or "")[-1000:]) if part)
    return len(lines), detail


def _install_official_nuclei_template_fallback() -> bool:
    """Merge the official template repository when the Nuclei updater is unavailable."""
    archive = DOWNLOADS / "nuclei-templates-main.zip"
    extract_dir = DOWNLOADS / "extract_nuclei_templates"
    destination = Path.home() / "nuclei-templates"
    url = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
    try:
        DOWNLOADS.mkdir(parents=True, exist_ok=True)
        with requests.get(url, stream=True, timeout=180) as response:
            response.raise_for_status()
            with archive.open("wb") as handle:
                for chunk in response.iter_content(1024 * 1024):
                    if chunk:
                        handle.write(chunk)
        shutil.rmtree(extract_dir, ignore_errors=True)
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as source:
            source.extractall(extract_dir)
        extracted = next(
            (item for item in extract_dir.iterdir() if item.is_dir() and item.name.startswith("nuclei-templates")),
            None,
        )
        if extracted is None:
            raise RuntimeError("The official Nuclei template archive had no repository directory.")
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copytree(extracted, destination, dirs_exist_ok=True)
        print(f"[+] Official Nuclei template repository merged into: {destination}")
        return True
    except Exception as exc:
        print(f"[!] Official Nuclei template fallback could not be downloaded: {type(exc).__name__}: {exc}", file=sys.stderr)
        return False
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
        archive.unlink(missing_ok=True)


def ensure_nuclei_engine_current() -> dict[str, Any]:
    """Ask the official Nuclei binary to self-update before refreshing templates."""
    executable = command_path("nuclei")
    if not executable:
        raise RuntimeError("Nuclei executable is unavailable.")
    before = run(
        [executable, "-version"],
        required=False,
        capture=True,
        show_output=False,
        timeout=60,
    )
    update = run(
        [executable, "-update"],
        required=False,
        capture=True,
        timeout=NUCLEI_TEMPLATE_UPDATE_TIMEOUT,
    )
    after = run(
        [executable, "-version"],
        required=False,
        capture=True,
        show_output=False,
        timeout=60,
    )
    state = {
        "update_returncode": update.returncode,
        "version_before": "\n".join(filter(None, ((before.stdout or "").strip(), (before.stderr or "").strip())))[-1000:],
        "version_after": "\n".join(filter(None, ((after.stdout or "").strip(), (after.stderr or "").strip())))[-1000:],
        "update_output_excerpt": "\n".join(filter(None, ((update.stdout or "").strip(), (update.stderr or "").strip())))[-1600:],
    }
    if update.returncode == 0:
        print("[+] Nuclei engine update check completed.")
    else:
        print("[!] Nuclei self-update did not complete; the existing executable will be retained.", file=sys.stderr)
    return state


def ensure_nuclei_templates() -> dict[str, Any]:
    """Install/update the complete official community template pack and report its size."""
    global _NUCLEI_TEMPLATE_STATE
    executable = command_path("nuclei")
    if not executable:
        raise RuntimeError("Nuclei executable is unavailable; templates cannot be installed.")

    listed_before, _ = _nuclei_listed_template_count(executable)
    filesystem_before, directories_before = _filesystem_nuclei_template_count()
    before = max(listed_before, filesystem_before)
    print(f"[*] Nuclei templates before update: {before}")

    update = run(
        [executable, "-update-templates"],
        required=False,
        capture=True,
        timeout=NUCLEI_TEMPLATE_UPDATE_TIMEOUT,
    )
    combined = "\n".join((update.stdout or "", update.stderr or ""))
    if update.returncode != 0 and "unknown flag" in combined.lower():
        update = run(
            [executable, "-ut"],
            required=False,
            capture=True,
            timeout=NUCLEI_TEMPLATE_UPDATE_TIMEOUT,
        )
        combined = "\n".join((update.stdout or "", update.stderr or ""))

    listed_after, listed_detail = _nuclei_listed_template_count(executable)
    filesystem_after, directories_after = _filesystem_nuclei_template_count()
    after = max(listed_after, filesystem_after)
    fallback_used = False

    if after < NUCLEI_TEMPLATE_MINIMUM:
        print(
            f"[!] Only {after} Nuclei templates were detected; attempting the complete official repository fallback.",
            file=sys.stderr,
        )
        fallback_used = _install_official_nuclei_template_fallback()
        listed_after, listed_detail = _nuclei_listed_template_count(executable)
        filesystem_after, directories_after = _filesystem_nuclei_template_count()
        after = max(listed_after, filesystem_after)

    if after <= 0:
        raise RuntimeError(
            "No Nuclei templates are available. Restore network access and rerun initScript.py so "
            "the official projectdiscovery/nuclei-templates repository can be installed."
        )

    sufficient = after >= NUCLEI_TEMPLATE_MINIMUM
    if sufficient:
        print(f"[+] Nuclei template inventory ready: {after} templates (complete official pack threshold satisfied).")
    else:
        print(
            f"[!] Nuclei has {after} templates. Scans can continue, but the expected full-pack threshold "
            f"of {NUCLEI_TEMPLATE_MINIMUM} was not reached.",
            file=sys.stderr,
        )

    _NUCLEI_TEMPLATE_STATE = {
        "count": after,
        "count_before_update": before,
        "minimum_expected": NUCLEI_TEMPLATE_MINIMUM,
        "sufficient": sufficient,
        "update_returncode": update.returncode,
        "update_output_excerpt": combined[-2000:],
        "fallback_used": fallback_used,
        "directory": _best_nuclei_template_directory(),
        "directories": directories_after or directories_before,
        "filesystem_candidates": _filesystem_nuclei_template_inventory(),
        "list_probe_excerpt": listed_detail[-1000:],
    }
    return dict(_NUCLEI_TEMPLATE_STATE)


def install_scanners() -> None:
    print("\n=== Installing/verifying security scanners ===")
    ensure_arjun()
    for name, (repository, script) in REPOSITORY_TOOLS.items():
        install_repository_tool(name, repository, script)
    install_nikto()
    for name, (repository, hint) in RELEASE_TOOLS.items():
        install_release_tool(name, repository, hint)
    nuclei_engine = ensure_nuclei_engine_current()
    nuclei_templates = ensure_nuclei_templates()
    nuclei_templates["engine"] = nuclei_engine
    _NUCLEI_TEMPLATE_STATE.update(nuclei_templates)


def scanner_status() -> dict[str, str | None]:
    return {name: command_path(name) for name in SCANNERS}


def verify_scanners(required: bool = True) -> dict[str, str | None]:
    status = scanner_status()
    if _docker_image_ready(NIKTO_DOCKER_IMAGE):
        if not status.get("nikto"):
            status["nikto"] = str(_write_nikto_docker_launcher())
        print(f"[+] Nikto verified through official Docker fallback: {NIKTO_DOCKER_IMAGE}")
    elif status.get("nikto"):
        perl_value = find_perl()
        script = LOCAL_OPT / "nikto" / "program" / "nikto.pl"
        healthy = False
        detail = "Perl or nikto.pl is missing."
        if perl_value and script.is_file():
            healthy, detail = _nikto_health(
                Path(perl_value).resolve(),
                script.resolve(),
                Path(status["nikto"]),
            )
        if not healthy:
            status["nikto"] = None
            print(
                f"[!] Nikto native runtime is unusable and Docker fallback is absent: {detail}",
                file=sys.stderr,
            )
    print("\n=== Scanner executables ===")
    for name, path in status.items():
        print(f"{name:20} {'OK: ' + path if path else 'MISSING/UNUSABLE'}")
    missing = [name for name, path in status.items() if not path]
    if required and missing:
        raise RuntimeError("Missing or unusable scanners: " + ", ".join(missing))
    return status


def write_runtime_config(status: dict[str, str | None]) -> None:
    directories = configure_path() + [str(Path(path).parent) for path in status.values() if path]
    payload = {
        "schema_version": 3,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(ROOT),
        # Never resolve a macOS/Linux venv symlink to its base interpreter.
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "tool_directories": list(dict.fromkeys(directories)),
        "executables": status,
        "playwright_chromium": {
            "ready": _playwright_chromium_ready()[0],
            "interpreter": sys.executable,
        },
        "nikto_perl": str(Path(find_perl()).resolve()) if find_perl() else "",
        "nikto_script": str((LOCAL_OPT / "nikto" / "program" / "nikto.pl").resolve()),
        "nikto_image": NIKTO_DOCKER_IMAGE,
        "nikto_execution_mode": (
            "docker_official_image" if _docker_image_ready(NIKTO_DOCKER_IMAGE) else "native_perl"
        ),
        "nuclei_templates": (
            dict(_NUCLEI_TEMPLATE_STATE)
            if _NUCLEI_TEMPLATE_STATE
            else {
                "count": max(
                    _nuclei_listed_template_count(status.get("nuclei") or "nuclei")[0],
                    _filesystem_nuclei_template_count()[0],
                ),
                "directory": _best_nuclei_template_directory(),
                "directories": _filesystem_nuclei_template_count()[1],
                "filesystem_candidates": _filesystem_nuclei_template_inventory(),
                "minimum_expected": NUCLEI_TEMPLATE_MINIMUM,
            }
        ),
    }
    RUNTIME_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Runtime scanner configuration written: {RUNTIME_FILE}")


def create_wordlist() -> None:
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
    words = "admin api assets backup config debug docs images index.php js login.php robots.txt server-status uploads vulnerabilities .env .git".split()
    (WORDLISTS_DIR / "common.txt").write_text("\n".join(words) + "\n", encoding="utf-8")


def wait_http(url: str, attempts: int = 60) -> bool:
    for _ in range(attempts):
        try:
            if requests.get(url, timeout=3).status_code < 500:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False


def inspect_container(name: str) -> dict[str, Any] | None:
    result = run(["docker", "inspect", name], required=False, capture=True, show_output=False, timeout=60)
    if result.returncode:
        return None
    try:
        value = json.loads(result.stdout)
        return value[0] if isinstance(value, list) and value else None
    except json.JSONDecodeError:
        return None


def container_valid(info: dict[str, Any], image: str, network: str, ports: dict[str, str]) -> bool:
    if info.get("Config", {}).get("Image") != image or network not in (info.get("NetworkSettings", {}).get("Networks", {}) or {}):
        return False
    bindings = info.get("HostConfig", {}).get("PortBindings", {}) or {}
    return all(host in {str(item.get("HostPort", "")) for item in bindings.get(container, [])} for container, host in ports.items())


def ensure_network(name: str) -> None:
    if run(["docker", "network", "inspect", name], required=False, capture=True, show_output=False, timeout=60).returncode:
        run(["docker", "network", "create", name], timeout=60)


def ensure_container(name: str, image: str, ports: dict[str, str], readiness_url: str, run_options: list[str] | None = None, command: list[str] | None = None, attempts: int = 90) -> None:
    info = inspect_container(name)
    if info and container_valid(info, image, "secops-net", ports):
        if not info.get("State", {}).get("Running"):
            run(["docker", "start", name], required=False, timeout=180)
        if wait_http(readiness_url, attempts):
            print(f"[+] Container {name} is ready.")
            return
    if info:
        run(["docker", "rm", "-f", name], required=False, timeout=180)
    port_args = [item for container, host in ports.items() for item in ("-p", f"{host}:{container.split('/')[0]}")]
    run(["docker", "run", "-d", "--name", name, "--network", "secops-net", *port_args, *(run_options or []), image, *(command or [])], timeout=1200)
    if not wait_http(readiness_url, attempts):
        run(["docker", "logs", "--tail", "100", name], required=False, capture=True, timeout=60)
        raise RuntimeError(f"Container {name} is not ready at {readiness_url}.")


class _HiddenInputParser(HTMLParser):
    """Collect input values without depending on HTML attribute ordering."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: dict[str, str] = {}

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "input":
            return
        attributes = {
            str(name).lower(): "" if value is None else str(value)
            for name, value in attrs
        }
        name = attributes.get("name", "")
        if name:
            self.values[name] = attributes.get("value", "")


def _hidden_input(html_text: str, name: str) -> str:
    parser = _HiddenInputParser()
    try:
        parser.feed(str(html_text or ""))
    except Exception:
        return ""
    return str(parser.values.get(name, "")).strip()


def _local_lab_login_page(response: requests.Response) -> bool:
    text = response.text[:100_000].lower()
    path = urlparse(str(response.url)).path.lower()
    return (
        path.endswith("/login")
        or path.endswith("/login.php")
        or (
            ("name=\"username\"" in text or "name='username'" in text)
            and ("name=\"password\"" in text or "name='password'" in text)
        )
    )


def _local_lab_setup_page(response: requests.Response) -> bool:
    path = urlparse(str(response.url)).path.lower()
    text = response.text[:100_000].lower()
    return (
        path.endswith("/setup.php")
        or "create / reset database" in text
        or "setup check" in text
    )


def _local_lab_response_summary(
    response: requests.Response,
) -> dict[str, Any]:
    text = response.text[:100_000]
    lowered = text.lower()
    title_match = re.search(
        r"<title[^>]*>\s*(.*?)\s*</title>",
        text,
        re.I | re.S,
    )
    error_markers = (
        "database error",
        "could not connect",
        "access denied",
        "connection refused",
        "unknown database",
        "fatal error",
        "warning:",
        "failed",
    )
    return {
        "status": int(response.status_code),
        "final_url": str(response.url),
        "login_page": _local_lab_login_page(response),
        "setup_page": _local_lab_setup_page(response),
        "title": (
            re.sub(r"\s+", " ", title_match.group(1)).strip()
            if title_match
            else ""
        ),
        "body_bytes": len(response.content),
        "error_markers": [
            marker for marker in error_markers if marker in lowered
        ],
    }


def _local_lab_cookie_value(
    session: requests.Session,
    cookie_name: str,
) -> str:
    selected = ""
    for cookie in session.cookies:
        if str(cookie.name).lower() == cookie_name.lower():
            selected = str(cookie.value)
    return selected


def _remove_named_cookies(
    session: requests.Session,
    cookie_name: str,
) -> None:
    removals: list[tuple[str, str, str]] = []
    for cookie in session.cookies:
        if str(cookie.name).lower() == cookie_name.lower():
            removals.append(
                (
                    str(cookie.domain or ""),
                    str(cookie.path or "/"),
                    str(cookie.name),
                )
            )
    for domain, path, name in removals:
        try:
            session.cookies.clear(
                domain=domain,
                path=path,
                name=name,
            )
        except (KeyError, ValueError):
            pass


def _attempt_local_lab_login(
    session: requests.Session,
    username: str,
    password: str,
) -> tuple[bool, dict[str, Any]]:
    page = session.get(
        f"{TARGET}/login.php",
        timeout=15,
        allow_redirects=True,
        headers={"Cache-Control": "no-cache"},
    )
    page.raise_for_status()
    token = _hidden_input(page.text, "user_token")
    credentials = {
        "username": username,
        "password": password,
        "Login": "Login",
    }
    if token:
        credentials["user_token"] = token

    response = session.post(
        f"{TARGET}/login.php",
        data=credentials,
        timeout=20,
        allow_redirects=True,
        headers={
            "Referer": f"{TARGET}/login.php",
            "Cache-Control": "no-cache",
        },
    )
    response.raise_for_status()
    final_path = urlparse(str(response.url)).path.lower()
    successful = (
        not _local_lab_login_page(response)
        and not _local_lab_setup_page(response)
        and final_path not in {"/login.php", "/setup.php"}
    )
    return successful, {
        "login_page": _local_lab_response_summary(page),
        "login_response": _local_lab_response_summary(response),
        "login_token_present": bool(token),
        "cookie_names": sorted(
            {str(cookie.name) for cookie in session.cookies},
            key=str.lower,
        ),
    }


def _reset_local_lab_database(
    session: requests.Session,
) -> dict[str, Any]:
    setup_page = session.get(
        f"{TARGET}/setup.php",
        timeout=20,
        allow_redirects=True,
        headers={"Cache-Control": "no-cache"},
    )
    setup_page.raise_for_status()
    token = _hidden_input(setup_page.text, "user_token")
    payload = {
        "create_db": "Create / Reset Database",
    }
    if token:
        payload["user_token"] = token

    setup_response = session.post(
        f"{TARGET}/setup.php",
        data=payload,
        timeout=45,
        allow_redirects=True,
        headers={
            "Referer": f"{TARGET}/setup.php",
            "Cache-Control": "no-cache",
        },
    )
    setup_response.raise_for_status()
    summary = {
        "setup_page": _local_lab_response_summary(setup_page),
        "setup_response": _local_lab_response_summary(setup_response),
        "setup_token_present": bool(token),
    }

    for _ in range(20):
        try:
            probe = session.get(
                f"{TARGET}/login.php",
                timeout=8,
                allow_redirects=True,
                headers={"Cache-Control": "no-cache"},
            )
            if probe.status_code < 500:
                summary["post_setup_probe"] = _local_lab_response_summary(
                    probe
                )
                break
        except requests.RequestException:
            pass
        time.sleep(0.5)

    return summary



def _configure_local_lab_profile(
    session: requests.Session,
) -> dict[str, Any]:
    """Apply the bundled training lab profile required for repeatable scans."""
    actions: list[dict[str, Any]] = []

    # The bundled lab exposes an optional request filter. Disable it so bounded
    # scanner payloads reach the intentionally vulnerable training handlers.
    for action_url in (
        f"{TARGET}/security.php?phpids=off",
    ):
        response = session.get(
            action_url,
            timeout=15,
            allow_redirects=True,
            headers={
                "Referer": f"{TARGET}/security.php",
                "Cache-Control": "no-cache",
            },
        )
        response.raise_for_status()
        actions.append(_local_lab_response_summary(response))

    verification = session.get(
        f"{TARGET}/security.php",
        timeout=15,
        allow_redirects=True,
        headers={"Cache-Control": "no-cache"},
    )
    verification.raise_for_status()
    lowered = verification.text[:100_000].lower()
    summary = _local_lab_response_summary(verification)
    plain_text = re.sub(r"<[^>]+>", " ", lowered)
    plain_text = re.sub(r"\s+", " ", plain_text)
    phpids_enabled = bool(re.search(
        r"phpids(?:\s+is\s+currently)?\s*:\s*enabled",
        plain_text,
        re.I,
    ))
    phpids_disabled = bool(re.search(
        r"phpids(?:\s+is\s+currently)?\s*:\s*disabled",
        plain_text,
        re.I,
    ))
    security_low = (
        bool(re.search(r"security(?:\s+level)?(?:\s+is\s+currently)?\s*:\s*low", plain_text, re.I))
        or "value=\"low\" selected" in lowered
        or "value='low' selected" in lowered
    )

    if phpids_enabled:
        raise RuntimeError(
            "The bundled lab request filter remained enabled after the initializer requested "
            "security.php?phpids=off. Intentional scanner payloads would be "
            "blocked and vulnerability coverage would be misleading."
        )

    return {
        "security_page": summary,
        "security_level_low": security_low,
        "phpids_disabled": phpids_disabled or not phpids_enabled,
        "actions": actions,
    }


def _finalize_local_lab_cookie(
    session: requests.Session,
) -> tuple[str, dict[str, Any]]:
    php_session = _local_lab_cookie_value(session, "PHPSESSID")
    if not php_session:
        raise RuntimeError("The bundled local lab did not issue its session cookie after login.")

    _remove_named_cookies(session, "security")
    session.cookies.set(
        "security",
        "low",
        domain=urlparse(TARGET).hostname,
        path="/",
    )

    lab_security = _configure_local_lab_profile(session)
    verification = session.get(
        f"{TARGET}/security.php",
        timeout=15,
        allow_redirects=True,
        headers={"Cache-Control": "no-cache"},
    )
    verification.raise_for_status()
    summary = _local_lab_response_summary(verification)
    summary["lab_security"] = lab_security
    if _local_lab_login_page(verification) or _local_lab_setup_page(verification):
        raise RuntimeError(
            "The bundled local-lab cookie verification failed after login: "
            + json.dumps(summary, ensure_ascii=False)
        )

    cookie = canonical_cookie_header(
        f"PHPSESSID={php_session}; security=low"
    )
    return cookie, summary


def create_local_lab_session() -> str:
    """
    Try the existing database first, reset only when needed, then verify the
    exact scanner Cookie header.
    """
    if not wait_http(f"{TARGET}/login.php", 90):
        raise RuntimeError("The bundled local training lab is not reachable.")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "SecOps-Local-Lab-Initializer/5.0",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    diagnostics: dict[str, Any] = {
        "target": TARGET,
        "attempts": [],
    }

    try:
        success_now, first_attempt = _attempt_local_lab_login(
            session,
            "admin",
            "password",
        )
        diagnostics["attempts"].append({
            "phase": "existing_database",
            **first_attempt,
        })
        if success_now:
            cookie, verification = _finalize_local_lab_cookie(session)
            diagnostics["verification"] = verification
            print(
                "[+] Bundled local-lab login succeeded using the existing database."
            )
            return cookie
    except requests.RequestException as exc:
        diagnostics["attempts"].append({
            "phase": "existing_database",
            "request_error": f"{type(exc).__name__}: {exc}",
        })

    session.cookies.clear()

    try:
        diagnostics["database_reset"] = _reset_local_lab_database(
            session
        )
    except requests.RequestException as exc:
        diagnostics["database_reset"] = {
            "request_error": f"{type(exc).__name__}: {exc}",
        }
        raise RuntimeError(
            "Bundled local-lab database setup request failed. Diagnostics: "
            + json.dumps(diagnostics, ensure_ascii=False)
        ) from exc

    for attempt_number in range(1, 6):
        try:
            success_now, attempt = _attempt_local_lab_login(
                session,
                "admin",
                "password",
            )
            diagnostics["attempts"].append({
                "phase": "after_database_reset",
                "attempt": attempt_number,
                **attempt,
            })
            if success_now:
                cookie, verification = _finalize_local_lab_cookie(
                    session
                )
                diagnostics["verification"] = verification
                print(
                    "[+] Bundled local-lab database initialized and automatic login succeeded."
                )
                return cookie
        except requests.RequestException as exc:
            diagnostics["attempts"].append({
                "phase": "after_database_reset",
                "attempt": attempt_number,
                "request_error": f"{type(exc).__name__}: {exc}",
            })
        time.sleep(attempt_number)

    try:
        logs = run(
            ["docker", "logs", "--tail", "80", LOCAL_LAB_CONTAINER],
            required=False,
            capture=True,
            show_output=False,
            timeout=30,
        )
        diagnostics["docker_log_tail"] = "\n".join(
            value
            for value in (
                (logs.stdout or "").strip(),
                (logs.stderr or "").strip(),
            )
            if value
        )[-6000:]
    except Exception as exc:
        diagnostics["docker_log_error"] = (
            f"{type(exc).__name__}: {exc}"
        )

    raise RuntimeError(
        "Automatic local-lab login failed after an existing-database attempt "
        "and five post-reset retries. Redacted diagnostics: "
        + json.dumps(diagnostics, ensure_ascii=False)
    )



def update_runtime_auth(cookie: str) -> None:
    try:
        payload = json.loads(RUNTIME_FILE.read_text(encoding="utf-8")) if RUNTIME_FILE.exists() else {}
    except (OSError, json.JSONDecodeError):
        payload = {}
    parsed = urlparse(TARGET)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    origin = f"{parsed.scheme.lower()}://{parsed.hostname.lower()}:{port}"
    target_profiles = payload.get("target_profiles", {})
    if not isinstance(target_profiles, dict):
        target_profiles = {}
    target_profiles[origin] = {
        "target_url": TARGET,
        "label": "bundled-local-training-lab",
        "container_route": {
            "scanner_container": "zap_mcp",
            "target_container": LOCAL_LAB_CONTAINER,
            "alias": LOCAL_LAB_CONTAINER,
            "network": LOCAL_LAB_NETWORK,
            "internal_port": 80,
        },
        "pre_scan_requests": [
            {
                "method": "GET",
                "path": "/security.php?phpids=off",
                "accepted_statuses": [200, 302],
            }
        ],
        # Exact-target safety metadata consumed generically by the crawler and
        # ZAP server. Other targets receive no special exclusions.
        "excluded_query_keys": ["phpids", "security", "seclev_submit", "test"],
        "probe_paths": ["/security.php", "/", "/index.php"],
        "preferred_probe_paths": ["/security.php"],
    }
    payload.update({
        "last_auth_target": TARGET,
        "last_auth_cookie": cookie,
        "last_auth_generated_at": datetime.now(timezone.utc).isoformat(),
        "target_profiles": target_profiles,
    })
    RUNTIME_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

def _ensure_local_docker_image(image: str, platform_name: str = "") -> None:
    """Use a local image; pull only when absent, optionally for a platform."""
    if _docker_image_ready(image):
        print(f"[+] Docker image already available locally; registry access skipped: {image}")
        return
    command = ["docker", "pull"]
    if platform_name:
        command.extend(["--platform", platform_name])
    command.append(image)
    result = run(command, required=False, capture=True, timeout=1800)
    if result.returncode != 0 or not _docker_image_ready(image):
        raise RuntimeError(
            f"Docker image {image} is not available locally and could not be pulled. "
            "Restore DNS/network access and rerun the initializer."
        )


def _ollama_model_available(model: str) -> bool:
    try:
        response = requests.get(
            "http://127.0.0.1:11434/api/tags",
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()
        models = payload.get("models", []) if isinstance(payload, dict) else []
        wanted = model.lower()
        wanted_base = wanted.split(":", 1)[0]
        for item in models:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("model") or "").lower()
            if name == wanted or (
                ":" not in wanted
                and name.split(":", 1)[0] == wanted_base
            ):
                return True
    except Exception:
        pass
    return False


def setup_local_lab(model: str) -> str:
    if not shutil.which("docker"):
        raise RuntimeError("Docker Desktop/Engine is required for --with-lab.")
    run(["docker", "info"], timeout=60)
    ensure_network(LOCAL_LAB_NETWORK)

    apple_silicon = (
        platform.system().lower() == "darwin"
        and platform.machine().lower() in {"arm64", "aarch64"}
    )
    dvwa_platform = "linux/amd64" if apple_silicon else ""
    _ensure_local_docker_image(LOCAL_LAB_IMAGE, dvwa_platform)
    _ensure_local_docker_image("zaproxy/zap-stable")
    _ensure_local_docker_image(NIKTO_DOCKER_IMAGE)
    _ensure_local_docker_image("ollama/ollama")

    dvwa_options = ["--platform", dvwa_platform] if dvwa_platform else []
    ensure_container(
        LOCAL_LAB_CONTAINER,
        LOCAL_LAB_IMAGE,
        {"80/tcp": "80"},
        f"{TARGET}/login.php",
        run_options=dvwa_options,
    )
    ensure_container(
        "zap_mcp", "zaproxy/zap-stable", {"8080/tcp": "8080"},
        "http://127.0.0.1:8080/JSON/core/view/version/",
        command=[
            "zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8080",
            "-config", "api.disablekey=true",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
        ],
        attempts=120,
    )
    try:
        version = requests.get(
            "http://127.0.0.1:8080/JSON/core/view/version/",
            timeout=15,
        ).json().get("version", "")
        print(f"[+] ZAP daemon version: {version or 'unknown'}")
    except Exception as exc:
        print(f"[!] Could not read ZAP version: {type(exc).__name__}: {exc}")

    ensure_container(
        "ollama_secops",
        "ollama/ollama",
        {"11434/tcp": "11434"},
        "http://127.0.0.1:11434/api/tags",
        run_options=["-v", "ollama_secops:/root/.ollama"],
        attempts=120,
    )
    if apple_silicon:
        print("[!] Ollama is running in Docker on Apple Silicon and may use CPU emulation. A native Ollama service can be faster.")
    if _ollama_model_available(model):
        print(f"[+] Ollama model already available; pull skipped: {model}")
    else:
        run(["docker", "exec", "ollama_secops", "ollama", "pull", model], timeout=7200)
    return create_local_lab_session()


def run_preflight() -> None:
    script = ROOT / "orchestratorDeterministic.py"
    environment = {"PATH": os.environ.get("PATH", "")}
    if sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        environment["VIRTUAL_ENV"] = str(Path(sys.executable).parent.parent)
    result = run(
        [sys.executable, str(script), "--target", TARGET, "--preflight-only"],
        required=False,
        capture=True,
        timeout=300,
        cwd=ROOT,
        env_overrides=environment,
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


def command_reference_text() -> str:
    python = "python" if os.name == "nt" else "python3"
    prefix = ".\\" if os.name == "nt" else "./"
    report_prefix = ".\\reports\\" if os.name == "nt" else "./reports/"
    set_location = (
        f'Set-Location "{ROOT}"'
        if os.name == "nt"
        else f'cd {shlex.quote(str(ROOT))}'
    )
    count_templates = (
        "nuclei -tl -silent -nc -disable-update-check | Measure-Object -Line"
        if os.name == "nt"
        else "nuclei -tl -silent -nc -disable-update-check | wc -l"
    )
    shell_note = (
        "In PowerShell il backtick (`) continua un comando sulla riga successiva."
        if os.name == "nt"
        else "In zsh/bash usa \\ alla fine della riga per continuare un comando."
    )
    p = lambda script: f"{python} {prefix}{script}"
    return f"""SecOps FastMCP - guida operativa multipiattaforma
====================================================

AMBIENTE RILEVATO
-----------------
Sistema: {platform.system()} {platform.machine()}
Python attivo: {sys.executable}
Radice progetto: {ROOT}
Apri il terminale nella radice:
  {set_location}

Usa soltanto target tuoi o esplicitamente autorizzati. Per un target remoto
aggiungi sempre --authorized e mantieni l'intero Cookie header tra virgolette.

1. INIZIALIZZAZIONE E LAB LOCALE
--------------------------------
{p('initScript.py')} --with-lab --model qwen2.5:7b
{p('initScript.py')}
{p('initScript.py')} --commands-only
{p('initScript.py')} --with-lab --run deterministic --mode balanced
{p('initScript.py')} --with-lab --run agentic --model qwen2.5:7b --mode balanced

`initScriptMac.py` rimane disponibile come wrapper compatibile, ma usa lo stesso
initializer multipiattaforma per evitare divergenze tra Windows e macOS.

2. DETERMINISTIC
----------------
{p('orchestratorDeterministic.py')} --target <TARGET> --cookies "<COOKIE_HEADER>" --auth-only --authorized --mode balanced
{p('orchestratorDeterministic.py')} --target <TARGET> --cookies "<COOKIE_HEADER>" --auth-only --authorized --mode deep
{p('orchestratorDeterministic.py')} --target <TARGET> --cookies "<PRIMARY_COOKIE>" --secondary-cookies "<SECOND_ACCOUNT_COOKIE>" --auth-only --authorized --mode deep
{p('orchestratorDeterministic.py')} --target <TARGET> --authorized --mode balanced

3. AGENTIC
----------
{p('orchestratorAgentic.py')} --target <TARGET> --cookies "<COOKIE_HEADER>" --auth-only --authorized --model <MODEL> --max-rounds 2 --mode balanced
{p('orchestratorAgentic.py')} --target <TARGET> --cookies "<COOKIE_HEADER>" --auth-only --authorized --model <MODEL> --max-rounds 3 --mode deep --ai-timeout 720
{p('orchestratorAgentic.py')} --target <TARGET> --cookies "<PRIMARY_COOKIE>" --secondary-cookies "<SECOND_ACCOUNT_COOKIE>" --auth-only --authorized --model <MODEL> --max-rounds 3 --mode deep
{p('orchestratorAgentic.py')} --target <TARGET> --cookies "<COOKIE_HEADER>" --auth-only --authorized --model <MODEL> --require-ai --max-rounds 2 --mode balanced
{p('orchestratorAgentic.py')} --target <TARGET> --authorized --model <MODEL> --no-model-pull --mode balanced

L'agentic usa il catalogo, i selector e l'interprete MCP del deterministic.
Quando il piano omette una classe applicabile, Ollama deve scegliere esplicitamente
un candidato scoperto per riparare la copertura; non vengono inseriti endpoint
hardcoded. I round continuano finché restano azioni valide o viene raggiunto
--max-rounds.

4. PREFLIGHT E DEBUG
--------------------
{p('orchestratorDeterministic.py')} --target <TARGET> --authorized --preflight-only
{p('orchestratorAgentic.py')} --target <TARGET> --authorized --preflight-only
{p('orchestratorDeterministic.py')} --list-tools
{p('orchestratorDeterministic.py')} --target <TARGET> --cookies "<COOKIE_HEADER>" --authorized --tool zap --mode deep --tool-timeout 480
{p('orchestratorDeterministic.py')} --target <TARGET> --cookies "<COOKIE_HEADER>" --authorized --tool sqlmap --tool-url <URL> --method GET --parameters "id,query" --tool-timeout 180
{p('orchestratorDeterministic.py')} --target <TARGET> --authorized --tool jwt --jwt-token "<JWT>"
{p('orchestratorDeterministic.py')} --target <TARGET> --cookies "<COOKIE_HEADER>" --authorized --tool exposure --mode balanced
{p('orchestratorDeterministic.py')} --target <TARGET> --cookies "<COOKIE_HEADER>" --authorized --tool browser --mode balanced
{p('orchestratorDeterministic.py')} --target <TARGET> --cookies "<COOKIE_HEADER>" --authorized --tool workflow --mode balanced
{p('orchestratorDeterministic.py')} --target <TARGET> --cookies "<PRIMARY_COOKIE>" --secondary-cookies "<SECOND_ACCOUNT_COOKIE>" --authorized --tool authorization --mode balanced

5. PROFILI
----------
fast      controllo rapido e budget ridotti
balanced  copertura ampia con priorità ai controlli importanti
deep      più target, richieste e budget per ZAP/Nuclei/strumenti parametrizzati

6. OPZIONI INIT
---------------
--with-lab --run --model --mode --skip-scanners --skip-preflight
--skip-browser --require-browser --commands-only --version

Per un target remoto, i workflow che inviano POST o file di prova restano
disabilitati salvo consenso esplicito con --authorized --allow-state-changes.
Nei laboratori locali vengono abilitati automaticamente.

7. NUCLEI
---------
nuclei -update
nuclei -update-templates
{count_templates}

Le pipeline passano a Nuclei request contract GET/POST same-origin e
non distruttivi. Le fasi statiche per esposizioni, misconfigurazioni e
controlli high-impact vengono eseguite prima del DAST, che usa soltanto i
contratti parametrizzati con priorità maggiore.

7B. COPERTURA WORKFLOW E BROWSER
-------------------------------
Exposure classifica backup, sorgenti, configurazioni, .git, .env e directory
listing realmente recuperabili. Session analizza cookie e indicatori di
unicità/fissazione. Browser usa Chromium per DOM/reflected/stored XSS con
marker innocui. Workflow esegue controlli limitati su CSRF, upload, login
throttling e CAPTCHA usando esclusivamente i form scoperti. Authorization
confronta richieste GET ad alto valore tra identità primaria, anonima e, quando
fornita, una seconda identità autenticata senza eseguire operazioni mutative.

8. REPORT
---------
Deterministic: {report_prefix}SecOps_Assessment_<timestamp>.pdf/.html/.json
Agentic:       {report_prefix}SecOps_Agentic_Assessment_<timestamp>.pdf/.html/.json

NOTA SHELL
----------
{shell_note}
"""


def write_command_reference() -> Path:
    COMMAND_REFERENCE_FILE.write_text(command_reference_text(), encoding="utf-8")
    return COMMAND_REFERENCE_FILE


def print_command_reference(path: Path) -> None:
    print("\n=== Complete SecOps command reference ===")
    print(command_reference_text().rstrip())
    print(f"\n[+] Command guide written: {path}")


def _operator_command(script: str, *arguments: str) -> str:
    """Return a copy/paste-safe command for PowerShell or a POSIX shell."""
    values = [sys.executable, str(ROOT / script), *arguments]
    return subprocess.list2cmdline(values) if os.name == "nt" else shlex.join(values)


def print_important_commands(
    model: str,
    mode: str = "balanced",
    cookie_header: str = "",
) -> None:
    """Print the four normal authenticated test commands after initialization."""
    cookie = cookie_header or "<COOKIE_HEADER>"
    print("\n=== Commands ready to run ===")
    print("Run them from: " + str(ROOT))
    commands = (
        ("1. Deterministic BALANCED", _operator_command(
            "orchestratorDeterministic.py", "--target", TARGET, "--cookies", cookie,
            "--auth-only", "--mode", "balanced",
        )),
        ("2. Deterministic DEEP", _operator_command(
            "orchestratorDeterministic.py", "--target", TARGET, "--cookies", cookie,
            "--auth-only", "--mode", "deep",
        )),
        ("3. Agentic BALANCED", _operator_command(
            "orchestratorAgentic.py", "--target", TARGET, "--cookies", cookie,
            "--auth-only", "--model", model, "--max-rounds", "2",
            "--mode", "balanced",
        )),
        ("4. Agentic DEEP", _operator_command(
            "orchestratorAgentic.py", "--target", TARGET, "--cookies", cookie,
            "--auth-only", "--model", model, "--max-rounds", "3",
            "--mode", "deep",
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
    try:
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
        status = verify_scanners(required=not args.skip_scanners)
        write_runtime_config(status)
        if not args.skip_preflight:
            run_preflight()
        cookie = ""
        if args.with_lab:
            cookie = setup_local_lab(args.model)
            update_runtime_auth(cookie)
            print(f"\n[+] Bundled local-lab login created successfully.\n[+] Cookie header: {cookie}")
        if args.run != "none":
            if not cookie:
                raise RuntimeError("--run requires --with-lab because it needs a generated local-lab session.")
            script = "orchestratorAgentic.py" if args.run == "agentic" else "orchestratorDeterministic.py"
            command = [sys.executable, str(ROOT / script), "--target", TARGET, "--cookies", cookie, "--mode", args.mode]
            if args.run == "agentic":
                command += ["--model", args.model, "--max-rounds", "1"]
            return run(command, required=False, timeout=7200, cwd=ROOT).returncode
        print_important_commands(args.model, args.mode, cookie)
        return 0
    except Exception as exc:
        print(f"[-] Initialization failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())