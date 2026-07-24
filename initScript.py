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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from utils import canonical_cookie_header, cookie_names, ROOT_DIR, WORDLISTS_DIR, setup_path

ROOT = Path(ROOT_DIR).resolve()
LOCAL_ROOT = Path.home() / ".local"
LOCAL_BIN = LOCAL_ROOT / "bin"
LOCAL_OPT = LOCAL_ROOT / "opt"
DOWNLOADS = LOCAL_ROOT / "downloads"
RUNTIME_FILE = ROOT / ".secops_runtime.json"
TARGET = "http://127.0.0.1"
DEFAULT_MODEL = "llama3.1:8b"
BUILD_ID = "secops-init-resilient-v15-20260724"

PYTHON_PACKAGES = (
    "fastmcp==2.12.5", "langgraph>=0.6,<2", "requests>=2.32,<3",
    "beautifulsoup4>=4.13,<5", "zaproxy>=0.5,<0.6",
    "reportlab>=4.4,<5", "PyJWT>=2.10,<3", "arjun>=2.2,<3",
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
    candidates.append(Path(sys.executable).resolve().parent)
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
        quoted = " ".join(subprocess.list2cmdline([part]) for part in command)
        path.write_text(f"#!/usr/bin/env sh\nexec {quoted} \"$@\"\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    configure_path()
    print(f"[+] Launcher created: {path}")
    return path


def install_python_packages() -> None:
    run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], timeout=1800)
    run(
        [sys.executable, "-m", "pip", "uninstall", "-y", "python-owasp-zap-v2.4"],
        required=False,
        capture=True,
        show_output=False,
        timeout=600,
    )
    run([sys.executable, "-m", "pip", "install", "--upgrade", *PYTHON_PACKAGES], timeout=3600)
    configure_path()


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
    if os.name == "nt":
        for candidate in (Path(r"C:\Strawberry\perl\bin\perl.exe"), Path(r"C:\Program Files\Strawberry Perl\perl\bin\perl.exe")):
            if candidate.is_file():
                _add_path(candidate.parent)
                return str(candidate)
    return None


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
    """Return the Strawberry Perl installation root from .../perl/bin/perl.exe."""
    resolved = perl.resolve()
    if resolved.parent.name.lower() == "bin" and resolved.parent.parent.name.lower() == "perl":
        return resolved.parent.parent.parent
    return resolved.parent.parent


def _configure_perl_toolchain(perl: Path) -> tuple[Path | None, str]:
    """Expose Strawberry Perl's compiler/make directory and resolve its configured make tool."""
    root = _strawberry_root(perl)
    tool_dirs = (perl.parent, root / "c" / "bin", root / "perl" / "site" / "bin")
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
    configured_name = (probe.stdout or "").strip() or "gmake"
    names = list(dict.fromkeys((configured_name, "gmake", "dmake", "make")))
    candidates = [root / "c" / "bin" / name for name in names]
    if os.name == "nt":
        candidates += [root / "c" / "bin" / f"{name}.exe" for name in names if not name.lower().endswith(".exe")]

    make = next((path.resolve() for path in candidates if path.is_file()), None)
    if make is None:
        found = next((shutil.which(name) for name in names if shutil.which(name)), None)
        make = Path(found).resolve() if found else None
    if make is not None:
        _add_path(make.parent)
    detail = f"configured make={configured_name}; resolved={make or 'missing'}; root={root}"
    return make, detail


def _install_perl_module(perl: Path, module: str) -> None:
    """Install a Strawberry Perl module with the bundled make tool and a CPAN fallback."""
    make, toolchain_detail = _configure_perl_toolchain(perl)
    if make is None:
        raise RuntimeError(
            "Strawberry Perl is missing its bundled make/compiler toolchain. "
            f"{toolchain_detail}\n"
            "Reinstall it with:\n"
            "  winget uninstall --id StrawberryPerl.StrawberryPerl --exact\n"
            "  winget install --id StrawberryPerl.StrawberryPerl --exact"
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

    cpan_candidates = (perl.parent / "cpan.bat", perl.parent / "cpan.exe", perl.parent / "cpan")
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
            "To reinstall Strawberry Perl:\n"
            "  winget uninstall --id StrawberryPerl.StrawberryPerl --exact\n"
            "  winget install --id StrawberryPerl.StrawberryPerl --exact"
        )


def _write_nikto_launcher(perl: Path, script: Path) -> Path:
    """Use a small Python launcher so cmd.exe never reparses the Perl script path."""
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
            f'"{Path(sys.executable).resolve()}" "{wrapper}" %*\r\n'
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )
    else:
        launcher = LOCAL_BIN / "nikto"
        launcher.write_text(f'#!/usr/bin/env sh\nexec "{Path(sys.executable).resolve()}" "{wrapper}" "$@"\n', encoding="utf-8")
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


def install_nikto() -> None:
    """Install/repair Nikto, Strawberry Perl dependencies, and a quoting-safe launcher."""
    destination = LOCAL_OPT / "nikto"
    script = destination / "program" / "nikto.pl"
    if not script.is_file():
        clone_or_update("https://github.com/sullo/nikto.git", destination)

    perl_value = find_perl()
    if not perl_value and os.name == "nt" and shutil.which("winget"):
        run(
            ["winget", "install", "--id", "StrawberryPerl.StrawberryPerl", "--exact", "--silent",
             "--accept-package-agreements", "--accept-source-agreements"],
            required=False,
            timeout=1800,
        )
        configure_path()
        perl_value = find_perl()

    if not script.is_file() or not perl_value:
        raise RuntimeError(
            "Nikto requires program/nikto.pl and Strawberry Perl. "
            "To remove a corrupted installation run: "
            "winget uninstall --id StrawberryPerl.StrawberryPerl --exact"
        )

    perl = Path(perl_value).resolve()
    make, toolchain_detail = _configure_perl_toolchain(perl)
    if make is None:
        raise RuntimeError(
            "Strawberry Perl was found, but its bundled make/compiler toolchain is missing. "
            f"{toolchain_detail}\n"
            "Reinstall it with:\n"
            "  winget uninstall --id StrawberryPerl.StrawberryPerl --exact\n"
            "  winget install --id StrawberryPerl.StrawberryPerl --exact"
        )
    print(f"[+] Strawberry Perl build tool: {make}")
    for module in ("XML::Writer",):
        available, _ = _perl_module_available(perl, module)
        if not available:
            print(f"[*] Installing missing Perl module: {module}")
            _install_perl_module(perl, module)

    launcher = _write_nikto_launcher(perl, script.resolve())
    healthy, detail = _nikto_health(perl, script.resolve(), launcher)
    if not healthy:
        raise RuntimeError(
            f"Nikto runtime verification failed: {detail}\n"
            "Reinstall Strawberry Perl with:\n"
            "  winget uninstall --id StrawberryPerl.StrawberryPerl --exact\n"
            "  winget install --id StrawberryPerl.StrawberryPerl --exact"
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


def install_scanners() -> None:
    print("\n=== Installing/verifying security scanners ===")
    ensure_arjun()
    for name, (repository, script) in REPOSITORY_TOOLS.items():
        install_repository_tool(name, repository, script)
    install_nikto()
    for name, (repository, hint) in RELEASE_TOOLS.items():
        install_release_tool(name, repository, hint)


def scanner_status() -> dict[str, str | None]:
    return {name: command_path(name) for name in SCANNERS}


def verify_scanners(required: bool = True) -> dict[str, str | None]:
    status = scanner_status()
    if status.get("nikto"):
        perl_value = find_perl()
        script = LOCAL_OPT / "nikto" / "program" / "nikto.pl"
        healthy = False
        detail = "Perl or nikto.pl is missing."
        if perl_value and script.is_file():
            healthy, detail = _nikto_health(Path(perl_value).resolve(), script.resolve(), Path(status["nikto"]))
        if not healthy:
            status["nikto"] = None
            print(f"[!] Nikto is unusable: {detail}", file=sys.stderr)
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
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(ROOT),
        "python_executable": str(Path(sys.executable).resolve()),
        "tool_directories": list(dict.fromkeys(directories)),
        "executables": status,
        "nikto_perl": str(Path(find_perl()).resolve()) if find_perl() else "",
        "nikto_script": str((LOCAL_OPT / "nikto" / "program" / "nikto.pl").resolve()),
    }
    RUNTIME_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Runtime scanner configuration written: {RUNTIME_FILE}")


def create_wordlist() -> None:
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
    words = "admin api assets backup config debug docs images index.php js login.php logout.php robots.txt server-status setup.php uploads vulnerabilities .env .git".split()
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


def login_dvwa() -> str:
    if not wait_http(f"{TARGET}/login.php", 90):
        raise RuntimeError("DVWA is not reachable.")
    session = requests.Session()
    session.get(f"{TARGET}/setup.php", timeout=15).raise_for_status()
    session.post(f"{TARGET}/setup.php", data={"create_db": "Create / Reset Database"}, timeout=20).raise_for_status()
    page = session.get(f"{TARGET}/login.php", timeout=15)
    token = re.search(r'name=["\']user_token["\'][^>]*value=["\']([^"\']+)', page.text, re.I)
    credentials = {"username": "admin", "password": "password", "Login": "Login"}
    if token:
        credentials["user_token"] = token.group(1)
    response = session.post(f"{TARGET}/login.php", data=credentials, timeout=20, allow_redirects=True)
    if "login.php" in response.url.lower() or "login :: damn vulnerable" in response.text.lower():
        raise RuntimeError("Automatic DVWA login failed.")
    session.cookies.set("security", "low", path="/")
    cookie = canonical_cookie_header(
        "; ".join(
            f"{name}={value}"
            for name, value in session.cookies.get_dict().items()
        )
    )
    names = {name.lower() for name in cookie_names(cookie)}
    if "phpsessid" not in names:
        raise RuntimeError("DVWA did not issue PHPSESSID.")
    if "security" not in names:
        raise RuntimeError("DVWA security cookie was not created.")

    verification = requests.get(
        f"{TARGET}/security.php",
        headers={"Cookie": cookie},
        timeout=15,
        allow_redirects=True,
    )
    body = verification.text.lower()
    if (
        "login.php" in verification.url.lower()
        or "type=\"password\"" in body
        or "login :: damn vulnerable" in body
    ):
        raise RuntimeError("DVWA cookie verification failed: the session is not authenticated.")
    return cookie



def update_runtime_auth(cookie: str) -> None:
    try:
        payload = json.loads(RUNTIME_FILE.read_text(encoding="utf-8")) if RUNTIME_FILE.exists() else {}
    except (OSError, json.JSONDecodeError):
        payload = {}
    payload.update({
        "last_auth_target": TARGET,
        "last_auth_cookie": cookie,
        "last_auth_generated_at": datetime.now(timezone.utc).isoformat(),
    })
    RUNTIME_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

def setup_lab(model: str) -> str:
    if not shutil.which("docker"):
        raise RuntimeError("Docker is required for --with-lab.")
    run(["docker", "info"], timeout=60)
    ensure_network("secops-net")
    ensure_container("dvwa", "vulnerables/web-dvwa", {"80/tcp": "80"}, f"{TARGET}/login.php")
    # The ZAP image tag is mutable. Pull and recreate the container so the
    # daemon and the current zaproxy Python API are not silently out of sync.
    run(["docker", "pull", "zaproxy/zap-stable"], timeout=1800)
    run(["docker", "rm", "-f", "zap_mcp"], required=False, timeout=180)
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
    ensure_container("ollama_secops", "ollama/ollama", {"11434/tcp": "11434"}, "http://127.0.0.1:11434/api/tags", run_options=["-v", "ollama_secops:/root/.ollama"], attempts=120)
    run(["docker", "exec", "ollama_secops", "ollama", "pull", model], timeout=7200)
    return login_dvwa()


def run_preflight() -> None:
    script = ROOT / "orchestratorDeterministic.py"
    result = run([sys.executable, str(script), "--target", TARGET, "--preflight-only"], required=False, capture=True, timeout=300, cwd=ROOT)
    if result.returncode:
        raise RuntimeError("The live orchestrator preflight failed.")


def print_commands(cookie: str, model: str) -> None:
    python = str(Path(sys.executable).resolve())
    def show(script: str, *arguments: str) -> None:
        print(subprocess.list2cmdline([python, str(ROOT / script), *arguments]))
    print("\n=== Commands to use from PowerShell ===")
    show("initScript.py", "--with-lab")
    show("orchestratorDeterministic.py", "--target", TARGET, "--preflight-only")
    show("orchestratorDeterministic.py", "--target", TARGET, "--cookies", cookie)
    show("orchestratorDeterministic.py", "--target", TARGET, "--cookies", cookie, "--auth-only")
    show("orchestratorAgentic.py", "--target", TARGET, "--cookies", cookie, "--model", model)
    show("orchestratorAgentic.py", "--target", TARGET, "--cookies", cookie, "--model", model, "--auth-only")


def main() -> int:
    print(f"=== SecOps initializer [{BUILD_ID}] ===")
    parser = argparse.ArgumentParser(description="Initialize the FastMCP SecOps project and local lab.")
    parser.add_argument("--with-lab", action="store_true")
    parser.add_argument("--run", choices=("none", "deterministic", "agentic"), default="none")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--skip-scanners", action="store_true")
    parser.add_argument("--version", action="version", version=BUILD_ID)
    args = parser.parse_args()

    os.chdir(ROOT)
    setup_path()
    configure_path()
    print("=== SecOps FastMCP initialization ===")
    try:
        install_python_packages()
        create_wordlist()
        if not args.skip_scanners:
            install_scanners()
        status = verify_scanners(required=not args.skip_scanners)
        write_runtime_config(status)
        if not args.skip_preflight:
            run_preflight()
        cookie = ""
        if args.with_lab:
            cookie = setup_lab(args.model)
            update_runtime_auth(cookie)
            print(f"\n[+] DVWA login created successfully.\n[+] Cookie header: {cookie}")
            print_commands(cookie, args.model)
        if args.run != "none":
            if not cookie:
                raise RuntimeError("--run requires --with-lab.")
            script = "orchestratorAgentic.py" if args.run == "agentic" else "orchestratorDeterministic.py"
            command = [sys.executable, str(ROOT / script), "--target", TARGET, "--cookies", cookie]
            if args.run == "agentic":
                command += ["--model", args.model]
            return run(command, required=False, timeout=7200, cwd=ROOT).returncode
        return 0
    except Exception as exc:
        print(f"[-] Initialization failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())