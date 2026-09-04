from __future__ import annotations
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
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import requests
from packaging.requirements import Requirement
from utils import ROOT_DIR, WORDLISTS_DIR, MCP_SERVER_PORTS, mcp_http_url
ROOT = Path(ROOT_DIR).resolve()
LOCAL_ROOT = Path.home() / '.local'
LOCAL_BIN = LOCAL_ROOT / 'bin'
LOCAL_OPT = LOCAL_ROOT / 'opt'
DOWNLOADS = LOCAL_ROOT / 'downloads'
PERL_LOCAL_ROOT = Path.home() / 'perl5'
PERL_LOCAL_LIB = PERL_LOCAL_ROOT / 'lib' / 'perl5'
RUNTIME_FILE = ROOT / '.secops_runtime.json'
COMMAND_REFERENCE_FILE = ROOT / 'init.txt'
TARGET = 'http://127.0.0.1'
LOCAL_LAB_CONTAINER = 'dvwa'
LOCAL_LAB_IMAGE = 'vulnerables/web-dvwa'
LOCAL_LAB_NETWORK = 'secops-net'
DEFAULT_MODEL = 'llama3.1:8b'
NUCLEI_TEMPLATE_MINIMUM = 1000
NUCLEI_TEMPLATE_UPDATE_TIMEOUT = 600
_NUCLEI_TEMPLATE_STATE: dict[str, Any] = {}
_NUCLEI_ENGINE_STATE: dict[str, Any] = {}
_IDOR_FORGE_STATE: dict[str, Any] = {}
BUILD_ID = 'secops-v31.30-audit-hardening-20260904'
FASTMCP_VERSION = '3.4.5'
FASTMCP_REQUIREMENT = f'fastmcp=={FASTMCP_VERSION}'
LANGGRAPH_REQUIREMENT = 'langgraph==1.2.10'
COMPATIBILITY_REQUIREMENTS = ('websockets>=15.0.1,<16', 'jsonschema-path>=0.4.5,<0.5.0')
PYTHON_PACKAGES = (FASTMCP_REQUIREMENT, LANGGRAPH_REQUIREMENT, *COMPATIBILITY_REQUIREMENTS, 'requests>=2.32,<3', 'beautifulsoup4>=4.13,<5', 'zaproxy>=0.5,<0.6', 'PyJWT>=2.10,<3', 'arjun>=2.2,<3', 'playwright>=1.54,<2')
SCANNERS = ('nuclei', 'nikto', 'ffuf', 'dalfox', 'commix', 'sqlmap', 'arjun', 'idor-forge', 'interactsh-client')
REPOSITORY_TOOLS = {'sqlmap': ('https://github.com/sqlmapproject/sqlmap.git', 'sqlmap.py'), 'commix': ('https://github.com/commixproject/commix.git', 'commix.py')}
IDOR_FORGE_REPOSITORY = 'https://github.com/errorfiathck/IDOR-Forge.git'
IDOR_FORGE_DIR = LOCAL_OPT / 'idor-forge'
RELEASE_TOOLS = {'nuclei': ('projectdiscovery/nuclei', 'nuclei'), 'ffuf': ('ffuf/ffuf', 'ffuf'), 'dalfox': ('hahwul/dalfox', 'dalfox'), 'interactsh-client': ('projectdiscovery/interactsh', 'interactsh-client')}

# Setup commands use one wrapper so timeouts and process failures produce consistent errors.
def run(command: list[str], *, required: bool=True, capture: bool=False, show_output: bool=True, timeout: int=3600, cwd: Path | None=None, env_overrides: dict[str, str] | None=None) -> subprocess.CompletedProcess[str]:
    print('[+] ' + subprocess.list2cmdline(command))
    try:
        child_env = os.environ.copy()
        child_env.setdefault('PYTHONUTF8', '1')
        child_env.setdefault('PYTHONIOENCODING', 'utf-8')
        if env_overrides:
            child_env.update(env_overrides)
        result = subprocess.run(command, cwd=str(cwd) if cwd else None, env=child_env, shell=False, text=True, encoding='utf-8', errors='replace', capture_output=capture, timeout=timeout)
    except FileNotFoundError as exc:
        raise RuntimeError(f'Command not found: {command[0]}') from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'Command timed out: {subprocess.list2cmdline(command)}') from exc
    stdout = result.stdout or ''
    stderr = result.stderr or ''
    if capture and show_output:
        if stdout.strip():
            print(stdout.strip())
        if stderr.strip():
            destination = sys.stdout if command and Path(command[0]).name.lower().startswith('docker') and (result.returncode == 0) else sys.stderr
            print(stderr.strip(), file=destination)
    if required and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {subprocess.list2cmdline(command)}\n{(stderr if capture else '')}")
    return result

# Joins captured stdout and stderr into one diagnostic string.
def _process_output(result: subprocess.CompletedProcess[str], limit: int=0) -> str:
    text = '\n'.join((part for part in ((result.stdout or '').strip(), (result.stderr or '').strip()) if part))
    return text[-limit:] if limit else text

# Downloads a file to the local tool cache.
def _download_file(url: str, destination: Path, timeout: int=180) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(url, stream=True, timeout=timeout) as response:
        response.raise_for_status()
        with destination.open('wb') as handle:
            for chunk in response.iter_content(1024 * 1024):
                if chunk:
                    handle.write(chunk)

# Extracts a downloaded ZIP or tar.gz archive.
def _extract_archive(archive: Path, destination: Path) -> None:
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)
    if archive.name.lower().endswith('.zip'):
        with zipfile.ZipFile(archive) as source:
            source.extractall(destination)
    else:
        with tarfile.open(archive, 'r:gz') as source:
            source.extractall(destination)

# Adds one existing directory to PATH when needed.
def _add_path(path: Path) -> None:
    if not path.is_dir():
        return
    resolved = str(path.resolve())
    current = [part for part in os.environ.get('PATH', '').split(os.pathsep) if part]
    if os.path.normcase(resolved) not in {os.path.normcase(os.path.abspath(part)) for part in current}:
        os.environ['PATH'] = resolved + os.pathsep + os.environ.get('PATH', '')

# Local tool setup creates the required folders and exposes their executable locations through PATH.
def configure_path() -> list[str]:
    for directory in (LOCAL_BIN, LOCAL_OPT, DOWNLOADS):
        directory.mkdir(parents=True, exist_ok=True)
    candidates = [LOCAL_BIN]
    try:
        scripts = sysconfig.get_path('scripts', scheme='nt_user' if os.name == 'nt' else 'posix_user')
        if scripts:
            candidates.append(Path(scripts))
    except (KeyError, ValueError):
        pass
    try:
        import site
        candidates.append(Path(site.USER_BASE) / ('Scripts' if os.name == 'nt' else 'bin'))
    except Exception:
        pass
    candidates.append(Path(sys.executable).parent)
    added = []
    for path in candidates:
        if path.is_dir():
            _add_path(path)
            added.append(str(path.resolve()))
    return list(dict.fromkeys(added))

# Finds an installed command in the project tool folders or system PATH.
def command_path(name: str) -> str | None:
    configure_path()
    candidate_names = [name]
    if os.name == 'nt' and (not Path(name).suffix):
        candidate_names.extend((f'{name}.exe', f'{name}.bat', f'{name}.cmd'))
    for candidate_name in candidate_names:
        candidate = LOCAL_BIN / candidate_name
        if candidate.is_file():
            return str(candidate.resolve())
    value = shutil.which(name)
    return str(Path(value).resolve()) if value else None

# Writes a small launcher script for a Python-based scanner.
def write_launcher(name: str, command: list[str]) -> Path:
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    if os.name == 'nt':
        path = LOCAL_BIN / f'{name}.bat'
        path.write_text('@echo off\r\n' + subprocess.list2cmdline(command) + ' %*\r\n', encoding='utf-8')
    else:
        path = LOCAL_BIN / name
        quoted = shlex.join([str(part) for part in command])
        path.write_text(f'#!/usr/bin/env sh\nexec {quoted} "$@"\n', encoding='utf-8')
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    configure_path()
    print(f'[+] Launcher created: {path}')
    return path

# FastMCP verification confirms that the required version imports correctly.
def _verify_fastmcp_import() -> tuple[bool, str]:

    probe_code = f"import importlib.metadata as metadata; from fastmcp import Client, FastMCP; assert metadata.version('fastmcp') == '{FASTMCP_VERSION}'; print(metadata.version('fastmcp'))"
    probe = run([sys.executable, '-c', probe_code], required=False, capture=True, show_output=False, timeout=60)
    detail = _process_output(probe)
    return (probe.returncode == 0, detail)

# Removes stale FastMCP package files before a clean reinstall.
def _purge_fastmcp_package_tree() -> None:

    purelib = Path(sysconfig.get_paths()['purelib'])
    targets = [purelib / 'fastmcp', *purelib.glob('fastmcp*.dist-info')]
    for target in targets:
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=False)
        elif target.exists():
            target.unlink()

# Installs the pinned FastMCP version after removing stale files.
def _install_fastmcp_clean() -> None:

    run([sys.executable, '-m', 'pip', 'uninstall', '-y', 'fastmcp', 'fastmcp-slim'], required=False, capture=True, show_output=False, timeout=300)
    _purge_fastmcp_package_tree()
    run([sys.executable, '-m', 'pip', 'install', '--no-cache-dir', '--force-reinstall', FASTMCP_REQUIREMENT, *COMPATIBILITY_REQUIREMENTS], timeout=1800)

# Dependency inspection reports packages that are missing or outside the supported version range.
def _missing_python_packages() -> list[str]:


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

# Installs the Python dependencies needed by the project.
def install_python_packages() -> None:

    try:
        importlib.metadata.version('python-owasp-zap-v2.4')
    except importlib.metadata.PackageNotFoundError:
        pass
    else:
        run([sys.executable, '-m', 'pip', 'uninstall', '-y', 'python-owasp-zap-v2.4'], required=False, capture=True, show_output=False, timeout=600)
    healthy, detail = _verify_fastmcp_import()
    if not healthy:
        print(f'[*] Installing clean FastMCP {FASTMCP_VERSION} runtime.')
        _install_fastmcp_clean()
        healthy, detail = _verify_fastmcp_import()
        if not healthy:
            raise RuntimeError(f'FastMCP still cannot be imported by the active interpreter after a clean reinstall.\nInterpreter: {sys.executable}\nDiagnostic: {detail[-2500:]}\nRecreate the project virtual environment and ensure no local fastmcp.py or mcp.py shadows the package.')
    missing = [package for package in _missing_python_packages() if Requirement(package).name.lower() != 'fastmcp']
    if missing:
        print('[*] Installing missing/incompatible Python packages: ' + ', '.join(missing))
        run([sys.executable, '-m', 'pip', 'install', *missing], timeout=3600)
    else:
        print('[+] Python dependencies already satisfy the pinned requirements; PyPI access skipped.')
    check = run([sys.executable, '-m', 'pip', 'check'], required=False, capture=True, show_output=False, timeout=120)
    if check.returncode:
        detail = '\n'.join((part for part in ((check.stdout or '').strip(), (check.stderr or '').strip()) if part))
        raise RuntimeError(f'Python dependency conflicts remain after initialization.\nInterpreter: {sys.executable}\npip check:\n{detail[-3000:]}')
    print('[+] Python dependency graph is consistent (pip check).')
    configure_path()

# Browser verification confirms that Playwright can launch Chromium successfully.
def _playwright_chromium_ready() -> tuple[bool, str]:

    probe_code = 'from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(headless=True); print(b.version); b.close(); p.stop()'
    probe = run([sys.executable, '-c', probe_code], required=False, capture=True, show_output=False, timeout=120)
    detail = _process_output(probe)
    return (probe.returncode == 0, detail)

# Installs Chromium together with its host dependencies and verifies that it can start.
def install_playwright_browser(*, required: bool=False) -> bool:

    ready, detail = _playwright_chromium_ready()
    if ready:
        print(f"[+] Playwright Chromium ready: {(detail.splitlines()[-1] if detail else 'launch verified')}")
        return True
    print('[*] Installing Playwright Chromium for browser discovery and XSS verification.')
    command = [sys.executable, '-m', 'playwright', 'install']
    if platform.system().lower() == 'linux':
        command.append('--with-deps')
    command.append('chromium')
    result = run(command, required=False, capture=True, timeout=2400)
    ready, detail = _playwright_chromium_ready()
    if ready:
        print(f"[+] Playwright Chromium installed and launch verified: {(detail.splitlines()[-1] if detail else 'launch verified')}")
        return True
    message = f'Playwright Chromium initialization failed. Installer return code={result.returncode}. Diagnostic: {detail[-2500:]}'
    if platform.system().lower() == 'linux':
        message += '\nThe initializer already requested Playwright browser system dependencies with --with-deps; inspect the package-manager output above if installation was denied.'
    if required:
        raise RuntimeError(message)
    print(f'[!] {message}\n[!] Browser-only checks will be reported as skipped; all other scanners remain available.', file=sys.stderr)
    return False

# Clones a Git repository or updates an existing local copy.
def clone_or_update(url: str, destination: Path) -> None:
    if not shutil.which('git'):
        raise RuntimeError('Git is required to install repository-based tools.')
    if (destination / '.git').is_dir():
        fetch = run(['git', '-C', str(destination), 'fetch', '--depth', '1', 'origin', 'HEAD'], required=False, capture=True, timeout=600)
        if fetch.returncode:
            print(f'[!] Keeping the existing {destination.name} checkout.')
            return
        run(['git', '-C', str(destination), 'reset', '--hard', 'FETCH_HEAD'], timeout=120)
        return
    shutil.rmtree(destination, ignore_errors=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(['git', 'clone', '--depth', '1', url, str(destination)], timeout=1200)

# Installs a scanner directly from its upstream Git repository.
def install_repository_tool(name: str, repository: str, script_name: str) -> None:
    if command_path(name):
        print(f'[+] {name} already available: {command_path(name)}')
        return
    destination = LOCAL_OPT / name
    clone_or_update(repository, destination)
    script = destination / script_name
    if not script.is_file():
        raise RuntimeError(f'Missing {script_name} after cloning {name}.')
    write_launcher(name, [sys.executable, str(script)])

# Reads the Python requirements needed by the upstream IDOR-Forge project.
def _idor_forge_runtime_requirements(requirements: Path) -> list[str]:
    packages: list[str] = []
    for raw_line in requirements.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            entries = [line]
            Requirement(line)
        except Exception:
            entries = shlex.split(line, comments=True, posix=True)
            if not entries:
                continue
            for entry in entries:
                Requirement(entry)
        for entry in entries:
            requirement = Requirement(entry)
            name = requirement.name.lower().replace('_', '-')
            if name == 'pyqt5':
                continue
            if name == 'matplotlib' and sys.version_info >= (3, 13):
                entry = 'matplotlib>=3.10,<4'
            if entry not in packages:
                packages.append(entry)
    if not packages:
        raise RuntimeError('IDOR-Forge requirements.txt did not contain usable runtime dependencies.')
    return packages

# Installs the upstream IDOR-Forge project and creates its launcher.
def install_idor_forge() -> dict[str, Any]:
    global _IDOR_FORGE_STATE
    clone_or_update(IDOR_FORGE_REPOSITORY, IDOR_FORGE_DIR)
    entrypoint = IDOR_FORGE_DIR / 'IDOR-Forge.py'
    checker = IDOR_FORGE_DIR / 'core' / 'IDORChecker.py'
    requirements = IDOR_FORGE_DIR / 'requirements.txt'
    if not entrypoint.is_file() or not checker.is_file() or (not requirements.is_file()):
        raise RuntimeError('The IDOR-Forge checkout is incomplete.')
    venv_dir = IDOR_FORGE_DIR / '.venv'
    venv_python = venv_dir / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not venv_python.is_file():
        run([sys.executable, '-m', 'venv', str(venv_dir)], timeout=1200)
    runtime_requirements = _idor_forge_runtime_requirements(requirements)
    print('[*] IDOR-Forge runtime dependencies: ' + ', '.join(runtime_requirements))
    run([str(venv_python), '-m', 'pip', 'install', '--disable-pip-version-check', *runtime_requirements], timeout=3600, cwd=IDOR_FORGE_DIR)
    probe = run([str(venv_python), '-c', "from core.IDORChecker import IDORChecker; print('IDOR-Forge import OK')"], required=False, capture=True, show_output=False, timeout=120, cwd=IDOR_FORGE_DIR, env_overrides={'MPLBACKEND': 'Agg'})
    if probe.returncode:
        detail = '\n'.join(filter(None, ((probe.stdout or '').strip(), (probe.stderr or '').strip())))
        raise RuntimeError('IDOR-Forge dependency preflight failed.\n' + detail[-2500:])
    launcher = write_launcher('idor-forge', [str(venv_python), str(entrypoint)])
    _IDOR_FORGE_STATE = {'repository': IDOR_FORGE_REPOSITORY, 'directory': str(IDOR_FORGE_DIR.resolve()), 'entrypoint': str(entrypoint.resolve()), 'checker': str(checker.resolve()), 'python': str(venv_python.resolve()), 'launcher': str(launcher.resolve()), 'preflight': 'ok'}
    print(f'[+] IDOR-Forge upstream runtime ready: {IDOR_FORGE_DIR}')
    return dict(_IDOR_FORGE_STATE)

# Configures the per-user Perl library used by CPAN on Unix-like hosts.
def configure_perl_environment() -> dict[str, str]:

    if os.name == 'nt':
        return {}
    PERL_LOCAL_ROOT.mkdir(parents=True, exist_ok=True)
    PERL_LOCAL_LIB.mkdir(parents=True, exist_ok=True)
    local_bin = PERL_LOCAL_ROOT / 'bin'
    if local_bin.is_dir():
        _add_path(local_bin)
    current = [part for part in os.environ.get('PERL5LIB', '').split(os.pathsep) if part]
    local_lib = str(PERL_LOCAL_LIB.resolve())
    if os.path.normcase(local_lib) not in {os.path.normcase(os.path.abspath(part)) for part in current}:
        current.insert(0, local_lib)
    perl5lib = os.pathsep.join(current)
    os.environ['PERL5LIB'] = perl5lib
    os.environ.setdefault('PERL_LOCAL_LIB_ROOT', str(PERL_LOCAL_ROOT.resolve()))
    os.environ.setdefault('PERL_MB_OPT', f"--install_base {PERL_LOCAL_ROOT.resolve()}")
    os.environ.setdefault('PERL_MM_OPT', f"INSTALL_BASE={PERL_LOCAL_ROOT.resolve()}")
    return {
        'PERL5LIB': perl5lib,
        'PERL_LOCAL_LIB_ROOT': os.environ['PERL_LOCAL_LIB_ROOT'],
        'PERL_MB_OPT': os.environ['PERL_MB_OPT'],
        'PERL_MM_OPT': os.environ['PERL_MM_OPT'],
    }


# Finds a usable Perl interpreter for Nikto when native execution is possible.
def find_perl() -> str | None:
    found = shutil.which('perl')
    if found:
        return found
    candidates: tuple[Path, ...] = ()
    if os.name == 'nt':
        candidates = (Path('C:\\Strawberry\\perl\\bin\\perl.exe'), Path('C:\\Program Files\\Strawberry Perl\\perl\\bin\\perl.exe'))
    elif platform.system().lower() == 'darwin':
        candidates = (Path('/opt/homebrew/opt/perl/bin/perl'), Path('/opt/homebrew/bin/perl'), Path('/usr/local/opt/perl/bin/perl'), Path('/usr/local/bin/perl'), Path('/usr/bin/perl'))
    for candidate in candidates:
        if candidate.is_file():
            _add_path(candidate.parent)
            return str(candidate)
    return None

# Perl diagnostics provide a short reinstall hint for the detected runtime.
def _perl_reinstall_hint() -> str:
    if os.name == 'nt':
        return 'Install/repair Strawberry Perl with:\n  winget uninstall --id StrawberryPerl.StrawberryPerl --exact\n  winget install --id StrawberryPerl.StrawberryPerl --exact'
    if platform.system().lower() == 'darwin':
        return 'Install the macOS build tools and Perl with:\n  xcode-select --install\n  brew install perl cpanminus'
    return 'Install Perl and build tools with your package manager, for example:\n  sudo apt install perl cpanminus build-essential'

# Perl module probing verifies that an optional module can be loaded.
def _perl_module_available(perl: Path, module: str) -> tuple[bool, str]:
    configure_perl_environment()
    probe = run([str(perl), f'-M{module}', '-e', f'print ${module}::VERSION'], required=False, capture=True, show_output=False, timeout=60)
    parts = [(probe.stdout or '').strip(), (probe.stderr or '').strip()]
    detail = '\n'.join((part for part in parts if part))
    return (probe.returncode == 0, detail)

# Finds the root folder of a Strawberry Perl installation.
def _strawberry_root(perl: Path) -> Path:

    resolved = perl.resolve()
    if os.name == 'nt':
        parts = [part.lower() for part in resolved.parts]
        try:
            perl_index = parts.index('perl')
            if perl_index > 0:
                return Path(*resolved.parts[:perl_index])
        except ValueError:
            pass
    return resolved.parent.parent

# Prepares the Perl build tools needed for optional Nikto modules.
def _configure_perl_toolchain(perl: Path) -> tuple[Path | None, str]:

    is_windows = os.name == 'nt'
    root = _strawberry_root(perl) if is_windows else None
    tool_dirs = (perl.parent, root / 'c' / 'bin', root / 'perl' / 'site' / 'bin') if root is not None else (perl.parent,)
    for directory in tool_dirs:
        if directory.is_dir():
            _add_path(directory)
    probe = run([str(perl), '-MConfig', '-e', 'print $Config{make}'], required=False, capture=True, show_output=False, timeout=30)
    configured_name = (probe.stdout or '').strip() or 'make'
    names = list(dict.fromkeys((configured_name, 'gmake', 'dmake', 'make')))
    candidates: list[Path] = []
    if root is not None:
        candidates.extend((root / 'c' / 'bin' / name for name in names))
        candidates.extend((root / 'c' / 'bin' / f'{name}.exe' for name in names if not name.lower().endswith('.exe')))
    make = next((path.resolve() for path in candidates if path.is_file()), None)
    if make is None:
        found = next((shutil.which(name) for name in names if shutil.which(name)), None)
        make = Path(found).resolve() if found else None
    if make is not None:
        _add_path(make.parent)
    detail = f"configured make={configured_name}; resolved={make or 'missing'}; root={root or 'n/a'}"
    return (make, detail)

# Installs one missing Perl module and verifies it afterward.
def _install_perl_module(perl: Path, module: str) -> None:

    make, toolchain_detail = _configure_perl_toolchain(perl)
    if make is None:
        raise RuntimeError(f'Perl is missing the required build toolchain. {toolchain_detail}\n{_perl_reinstall_hint()}')
    environment = {**configure_perl_environment(), 'PATH': os.environ.get('PATH', ''), 'MAKE': str(make), 'PERL_MM_USE_DEFAULT': '1', 'PERL_AUTOINSTALL': '--defaultdeps', 'NONINTERACTIVE_TESTING': '1'}
    cpanm_candidates = (perl.parent / 'cpanm.bat', perl.parent / 'cpanm.exe', perl.parent / 'cpanm', perl.parent.parent / 'site' / 'bin' / 'cpanm.bat', perl.parent.parent / 'site' / 'bin' / 'cpanm.exe', PERL_LOCAL_ROOT / 'bin' / 'cpanm', Path('/usr/bin/cpanm'), Path('/opt/homebrew/bin/cpanm'), Path('/usr/local/bin/cpanm'))
    attempts: list[str] = []
    cpanm = next((path for path in cpanm_candidates if path.exists()), None)
    if cpanm:
        cpanm_command = [str(cpanm), '--notest', module]
        if os.name != 'nt':
            cpanm_command = [str(cpanm), '--local-lib', str(PERL_LOCAL_ROOT), '--notest', module]
        result = run(cpanm_command, required=False, capture=True, timeout=1800, env_overrides=environment)
        attempts.append('\n'.join(filter(None, ((result.stdout or '').strip(), (result.stderr or '').strip())))[:4000])
        healthy, _ = _perl_module_available(perl, module)
        if healthy:
            return
    cpan_candidates = (perl.parent / 'cpan.bat', perl.parent / 'cpan.exe', perl.parent / 'cpan', Path('/opt/homebrew/bin/cpan'), Path('/usr/local/bin/cpan'), Path('/usr/bin/cpan'))
    cpan = next((path for path in cpan_candidates if path.exists()), None)
    command = [str(cpan), '-T', module] if cpan else [str(perl), '-MCPAN', '-e', f"CPAN::Shell->install('{module}')"]
    result = run(command, required=False, capture=True, timeout=1800, env_overrides=environment)
    attempts.append('\n'.join(filter(None, ((result.stdout or '').strip(), (result.stderr or '').strip())))[:4000])
    healthy, detail = _perl_module_available(perl, module)
    if not healthy:
        diagnostics = '\n--- installer attempt ---\n'.join((value for value in attempts if value))
        raise RuntimeError(f'Perl module {module} could not be installed. {toolchain_detail}. {detail}\n{diagnostics}\nInstall the missing modules manually with: cpan JSON XML::Writer\n{_perl_reinstall_hint()}')

# Writes the native Nikto launcher used when Perl is available.
def _write_nikto_launcher(perl: Path, script: Path) -> Path:

    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    wrapper = LOCAL_OPT / 'nikto_launcher.py'
    if os.name == 'nt':
        wrapper_text = f'import subprocess, sys\nraise SystemExit(subprocess.call([{str(perl)!r}, {str(script)!r}, *sys.argv[1:]]))\n'
    else:
        local_lib = str(PERL_LOCAL_LIB.resolve())
        wrapper_text = (
            'import os, subprocess, sys\n'
            f'_secops_perl5lib = {local_lib!r}\n'
            "_existing = os.environ.get('PERL5LIB', '')\n"
            "os.environ['PERL5LIB'] = _secops_perl5lib + (os.pathsep + _existing if _existing else '')\n"
            f'raise SystemExit(subprocess.call([{str(perl)!r}, {str(script)!r}, *sys.argv[1:]]))\n'
        )
    wrapper.write_text(wrapper_text, encoding='utf-8')
    if os.name == 'nt':
        launcher = LOCAL_BIN / 'nikto.bat'
        launcher.write_text(f'@echo off\r\n"{sys.executable}" "{wrapper}" %*\r\nexit /b %ERRORLEVEL%\r\n', encoding='utf-8')
    else:
        launcher = LOCAL_BIN / 'nikto'
        launcher.write_text(f'#!/usr/bin/env sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(wrapper))} "$@"\n', encoding='utf-8')
        launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    configure_path()
    return launcher

# Nikto probing runs a basic command to confirm that the selected runtime is usable.
def _nikto_health(perl: Path, script: Path, launcher: Path | None=None) -> tuple[bool, str]:
    fatal = re.compile("(?:can't open perl script|cannot open perl script|invalid argument|required module not found|not recognized|non .? riconosciuto|no such file|modulenotfounderror|traceback|^error:)", re.IGNORECASE | re.MULTILINE)
    commands = [[str(perl), str(script), '-Version']]
    if launcher:
        commands.append([str(launcher), '-Version'])
    details: list[str] = []
    for command in commands:
        result = run(command, required=False, capture=True, show_output=False, timeout=60)
        parts = [(result.stdout or '').strip(), (result.stderr or '').strip()]
        combined = '\n'.join((part for part in parts if part))
        details.append(combined or f'exit={result.returncode}')
        if result.returncode != 0 or fatal.search(combined):
            return (False, details[-1])
    return (True, details[-1])
NIKTO_DOCKER_IMAGE = 'ghcr.io/sullo/nikto:latest'
NUCLEI_DOCKER_IMAGE = 'projectdiscovery/nuclei:latest'
NUCLEI_MIN_DAST_VERSION = (3, 11, 1)
REPORT_DOCKER_SOURCE_IMAGE = 'albertopizzi2002/reportingpdf:v1.0'


REPORT_DOCKER_IMAGE = 'secops/report:local'

# Parse the semantic version printed by Nuclei and enforce the DAST-compatible runtime floor.
def _nuclei_version_tuple(text: str) -> tuple[int, int, int]:
    match = re.search(r"(?i)\bv?(\d+)\.(\d+)\.(\d+)\b", str(text or ""))
    return tuple(int(match.group(index)) for index in range(1, 4)) if match else (0, 0, 0)

def _nuclei_version_supported(text: str) -> bool:
    return _nuclei_version_tuple(text) >= NUCLEI_MIN_DAST_VERSION

# Docker image lookup avoids pulling an image that is already available locally.
def _docker_image_ready(image: str) -> bool:
    if not shutil.which('docker'):
        return False
    result = run(['docker', 'image', 'inspect', image], required=False, capture=True, show_output=False, timeout=60)
    return result.returncode == 0

# Pulls a Docker image and verifies that it is available afterward.
def _pull_docker_image(image: str, timeout: int=1800) -> tuple[bool, str]:
    if not shutil.which('docker'):
        return (False, 'Docker is unavailable.')
    if not _docker_image_ready(image):
        result = run(['docker', 'pull', image], required=False, capture=True, timeout=timeout)
        if result.returncode != 0 or not _docker_image_ready(image):
            return (False, _process_output(result, 2000) or 'Docker pull failed.')
    return (True, '')

# Ensures the official Nikto Docker image is available.
def _ensure_nikto_docker_image() -> bool:
    if _docker_image_ready(NIKTO_DOCKER_IMAGE):
        print(f'[+] Nikto Docker fallback already available: {NIKTO_DOCKER_IMAGE}')
        return True
    ready, _ = _pull_docker_image(NIKTO_DOCKER_IMAGE)
    if ready:
        print(f'[+] Nikto Docker fallback installed: {NIKTO_DOCKER_IMAGE}')
        return True
    print('[!] Nikto Docker image could not be pulled. Native Perl will be checked as a secondary option.')
    return False

# Ensures the official Nuclei Docker image is current enough for request-shaped DAST input.
def _ensure_nuclei_docker_image() -> tuple[bool, str]:

    ready, detail = _pull_docker_image(NUCLEI_DOCKER_IMAGE)
    if not ready:
        return (False, detail)
    probe = run(['docker', 'run', '--rm', NUCLEI_DOCKER_IMAGE, '-version'], required=False, capture=True, show_output=False, timeout=120)
    version_detail = _process_output(probe)
    if probe.returncode == 0 and _nuclei_version_supported(version_detail):
        print(f'[+] Nuclei verified through official Docker fallback: {NUCLEI_DOCKER_IMAGE}')
        return (True, version_detail[-1200:])

    # The latest tag may already exist locally but be stale; refresh it once before rejecting Docker.
    refresh = run(['docker', 'pull', NUCLEI_DOCKER_IMAGE], required=False, capture=True, timeout=1800)
    if refresh.returncode == 0:
        probe = run(['docker', 'run', '--rm', NUCLEI_DOCKER_IMAGE, '-version'], required=False, capture=True, show_output=False, timeout=120)
        version_detail = _process_output(probe)
        if probe.returncode == 0 and _nuclei_version_supported(version_detail):
            print(f'[+] Nuclei Docker image refreshed and verified: {NUCLEI_DOCKER_IMAGE}')
            return (True, version_detail[-1200:])

    required = '.'.join(str(value) for value in NUCLEI_MIN_DAST_VERSION)
    detail = '\n'.join(value for value in (version_detail, _process_output(refresh, 1200)) if value)
    return (False, detail[-2000:] or f'Nuclei >= {required} is required for DAST request input.')

# Prepares the external reporting image under the local tag expected by the report server.
def _ensure_report_docker_image() -> bool:


    ready, detail = _pull_docker_image(REPORT_DOCKER_SOURCE_IMAGE)
    if not ready:
        print(f'[!] Report Docker image could not be pulled: {REPORT_DOCKER_SOURCE_IMAGE}\n{detail[-1600:]}')
        return False

    tagged = run(
        ['docker', 'tag', REPORT_DOCKER_SOURCE_IMAGE, REPORT_DOCKER_IMAGE],
        required=False, capture=True, show_output=False, timeout=120,
    )
    if tagged.returncode != 0 or not _docker_image_ready(REPORT_DOCKER_IMAGE):
        print('[!] Report Docker image was pulled but the local compatibility tag could not be created.')
        return False


    probe = run(
        ['docker', 'run', '--rm', REPORT_DOCKER_IMAGE, 'python', '-m', 'weasyprint', '--info'],
        required=False, capture=True, show_output=False, timeout=120,
    )
    if probe.returncode == 0:
        print(f'[+] Report Docker image ready: {REPORT_DOCKER_SOURCE_IMAGE} -> {REPORT_DOCKER_IMAGE}')
        return True

    detail = _process_output(probe, 1800)
    print(
        '[!] The shared report image was pulled, but it is not compatible with the '
        'unchanged reportServer.py Docker invocation. Native WeasyPrint remains the fallback.\n'
        + detail
    )
    return False

# Writes a launcher that runs a scanner through Docker.
def _write_docker_launcher(name: str, image: str, extra_args: tuple[str, ...]=()) -> Path:
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    args = ' '.join(extra_args)
    prefix = f' {args}' if args else ''
    if os.name == 'nt':
        launcher = LOCAL_BIN / f'{name}.bat'
        launcher.write_text(f'@echo off\r\ndocker run --rm{prefix} "{image}" %*\r\nexit /b %ERRORLEVEL%\r\n', encoding='utf-8')
    else:
        launcher = LOCAL_BIN / name
        launcher.write_text(f'#!/usr/bin/env sh\nexec docker run --rm{prefix} "{image}" "$@"\n', encoding='utf-8')
        launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    configure_path()
    return launcher

# Writes the Docker launcher used for Nikto.
def _write_nikto_docker_launcher() -> Path:
    launcher = _write_docker_launcher('nikto', NIKTO_DOCKER_IMAGE)
    print(f'[+] Nikto Docker launcher created: {launcher}')
    return launcher

# Writes the Docker launcher used for Nuclei.
def _write_nuclei_docker_launcher() -> Path:
    launcher = _write_docker_launcher('nuclei-docker', NUCLEI_DOCKER_IMAGE, ('--add-host', 'host.docker.internal:host-gateway'))
    print(f'[+] Nuclei Docker launcher created: {launcher}')
    return launcher

# Selects a working Nikto runtime and creates the matching launcher.
def install_nikto() -> None:

    if _ensure_nikto_docker_image():
        _write_nikto_docker_launcher()
        return
    destination = LOCAL_OPT / 'nikto'
    script = destination / 'program' / 'nikto.pl'
    if not script.is_file():
        clone_or_update('https://github.com/sullo/nikto.git', destination)
    perl_value = find_perl()
    if not script.is_file() or not perl_value:
        raise RuntimeError(f'Nikto is unavailable: the official Docker image is not ready and the native Perl fallback is incomplete.\n{_perl_reinstall_hint()}')
    perl = Path(perl_value).resolve()
    make, toolchain_detail = _configure_perl_toolchain(perl)
    if make is None:
        raise RuntimeError(f'The native Perl build toolchain is incomplete and the Docker fallback is unavailable. {toolchain_detail}.\n{_perl_reinstall_hint()}')
    print(f'[+] Perl build tool: {make}')
    for module in ('XML::Writer', 'JSON'):
        available, _ = _perl_module_available(perl, module)
        if not available:
            print(f'[*] Installing missing Perl module: {module}')
            _install_perl_module(perl, module)
    launcher = _write_nikto_launcher(perl, script.resolve())
    healthy, detail = _nikto_health(perl, script.resolve(), launcher)
    if not healthy:
        raise RuntimeError(f'Native Nikto runtime verification failed: {detail}.\n{_perl_reinstall_hint()}')
    print(f'[+] Nikto runtime and launcher verified: {launcher}')

# Ensures Arjun is installed and available on PATH.
def ensure_arjun() -> None:
    if command_path('arjun'):
        print(f"[+] arjun already available: {command_path('arjun')}")
        return
    if run([sys.executable, '-m', 'arjun', '--help'], required=False, capture=True, timeout=60).returncode == 0:
        write_launcher('arjun', [sys.executable, '-m', 'arjun'])
        return
    raise RuntimeError('Arjun is installed but no executable/module entry point is available.')

# Reads the latest release metadata for an upstream GitHub project.
def github_release(repository: str) -> dict[str, Any]:
    response = requests.get(f'https://api.github.com/repos/{repository}/releases/latest', headers={'Accept': 'application/vnd.github+json'}, timeout=60)
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError(f'Invalid GitHub response for {repository}.')
    return value

# Chooses the release archive that matches the current operating system and CPU.
def select_asset(release: dict[str, Any], hint: str) -> dict[str, Any]:
    machine = platform.machine().lower()
    arch = ('amd64', 'x86_64', '64bit') if machine in {'amd64', 'x86_64', 'x64'} else ('arm64', 'aarch64')
    system = platform.system().lower()
    os_tokens = ('windows', 'win') if system == 'windows' else ('linux',) if system == 'linux' else ('macos', 'darwin', 'osx')
    assets = []
    for asset in release.get('assets', []):
        name = str(asset.get('name', '')).lower()
        if name.endswith(('.zip', '.tar.gz', '.tgz')) and hint.lower() in name and any((token in name for token in arch)) and any((token in name for token in os_tokens)):
            assets.append(asset)
    if not assets:
        raise RuntimeError(f'No compatible {hint} release asset found.')
    assets.sort(key=lambda item: not str(item.get('name', '')).lower().endswith('.zip') if os.name == 'nt' else str(item.get('name', '')).lower().endswith('.zip'))
    return assets[0]

# Downloads and installs a scanner from its official release archive.
def install_release_tool(name: str, repository: str, hint: str) -> None:
    if command_path(name):
        print(f'[+] {name} already available: {command_path(name)}')
        return
    asset = select_asset(github_release(repository), hint)
    archive = DOWNLOADS / str(asset['name'])
    extract_dir = DOWNLOADS / f'extract_{name}'
    _download_file(str(asset['browser_download_url']), archive)
    _extract_archive(archive, extract_dir)
    expected = {name.lower(), f'{name}.exe'.lower()}
    executable = next((path for path in extract_dir.rglob('*') if path.is_file() and path.name.lower() in expected), None)
    if not executable:
        raise RuntimeError(f'Executable {name} was not found in {archive.name}.')
    destination = LOCAL_BIN / (f'{name}.exe' if os.name == 'nt' else name)
    shutil.copy2(executable, destination)
    if os.name != 'nt':
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    shutil.rmtree(extract_dir, ignore_errors=True)
    archive.unlink(missing_ok=True)
    configure_path()

# Lists the local directories that may contain Nuclei templates.
def _nuclei_template_directories() -> list[Path]:
    home = Path.home()
    appdata = os.environ.get('APPDATA', '').strip()
    localappdata = os.environ.get('LOCALAPPDATA', '').strip()
    programdata = os.environ.get('PROGRAMDATA', '').strip()
    candidates = [Path(os.environ['NUCLEI_TEMPLATES_DIR']).expanduser() if os.environ.get('NUCLEI_TEMPLATES_DIR') else None, ROOT / 'tools' / 'nuclei-templates', home / 'nuclei-templates', home / '.local' / 'nuclei-templates', home / '.config' / 'nuclei' / 'templates', home / 'AppData' / 'Roaming' / 'nuclei' / 'templates', Path(appdata) / 'nuclei-templates' if appdata else None, Path(appdata) / 'nuclei' / 'templates' if appdata else None, Path(localappdata) / 'nuclei-templates' if localappdata else None, Path(localappdata) / 'nuclei' / 'templates' if localappdata else None, Path(programdata) / 'nuclei-templates' if programdata else None]
    return list(dict.fromkeys((path.resolve() for path in candidates if path is not None)))

# Counts Nuclei YAML templates in each local template directory.
def _filesystem_nuclei_template_inventory() -> list[dict[str, Any]]:
    inventories: list[dict[str, Any]] = []
    for directory in _nuclei_template_directories():
        if not directory.is_dir():
            continue
        count = sum((1 for path in directory.rglob('*') if path.is_file() and path.suffix.lower() in {'.yaml', '.yml'}))
        inventories.append({'directory': str(directory), 'count': count})
    inventories.sort(key=lambda item: int(item['count']), reverse=True)
    return inventories

# Count official Nuclei DAST templates in one template repository.
def _nuclei_dast_template_count(directory: str | Path) -> int:
    root = Path(directory).expanduser() if directory else Path()
    dast = root / 'dast'
    if not dast.is_dir():
        return 0
    return sum(1 for path in dast.rglob('*') if path.is_file() and path.suffix.lower() in {'.yaml', '.yml'})

# Template inventory counts the Nuclei YAML files available in a directory.
def _filesystem_nuclei_template_count() -> tuple[int, list[str]]:
    inventory = _filesystem_nuclei_template_inventory()
    return (max((int(item['count']) for item in inventory), default=0), [str(item['directory']) for item in inventory])

# Template discovery prefers the local directory with the largest valid Nuclei inventory.
def _best_nuclei_template_directory() -> str:
    inventory = _filesystem_nuclei_template_inventory()
    return str(inventory[0]['directory']) if inventory and int(inventory[0]['count']) > 0 else ''

# Refreshes the official Nuclei template repository when normal updating is unavailable.
def _install_official_nuclei_template_fallback() -> bool:

    archive = DOWNLOADS / 'nuclei-templates-main.zip'
    extract_dir = DOWNLOADS / 'extract_nuclei_templates'
    destination = Path.home() / 'nuclei-templates'
    url = 'https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip'
    try:
        _download_file(url, archive)
        _extract_archive(archive, extract_dir)
        extracted = next((item for item in extract_dir.iterdir() if item.is_dir() and item.name.startswith('nuclei-templates')), None)
        if extracted is None:
            raise RuntimeError('The official Nuclei template archive had no repository directory.')
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copytree(extracted, destination, dirs_exist_ok=True)
        print(f'[+] Official Nuclei template repository merged into: {destination}')
        return True
    except Exception as exc:
        print(f'[!] Official Nuclei template fallback could not be downloaded: {type(exc).__name__}: {exc}', file=sys.stderr)
        return False
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
        archive.unlink(missing_ok=True)

# Prepares a current Nuclei engine and records how it will be executed.
def ensure_nuclei_engine_current() -> dict[str, Any]:

    global _NUCLEI_ENGINE_STATE
    executable = command_path('nuclei')
    native_error = ''
    if executable:
        try:
            before = run([executable, '-version'], required=False, capture=True, show_output=False, timeout=60)
            if before.returncode == 0:
                update = run([executable, '-update'], required=False, capture=True, timeout=NUCLEI_TEMPLATE_UPDATE_TIMEOUT)
                after = run([executable, '-version'], required=False, capture=True, show_output=False, timeout=60)
                if after.returncode == 0 and _nuclei_version_supported(_process_output(after, 1000)):
                    _NUCLEI_ENGINE_STATE = {'execution_mode': 'native', 'executable': executable, 'launcher': executable, 'docker_image': '', 'update_returncode': update.returncode, 'version_before': _process_output(before, 1000), 'version_after': _process_output(after, 1000), 'update_output_excerpt': _process_output(update, 1600)}
                    if update.returncode == 0:
                        print('[+] Nuclei engine update check completed.')
                    else:
                        print('[!] Nuclei self-update did not complete, but the installed version satisfies the DAST runtime floor.', file=sys.stderr)
                    return dict(_NUCLEI_ENGINE_STATE)
                if after.returncode == 0:
                    required = '.'.join(str(value) for value in NUCLEI_MIN_DAST_VERSION)
                    native_error = f'Nuclei {_process_output(after, 300)} is older than required v{required} for reliable request-shaped DAST input.'
                else:
                    native_error = _process_output(after) or f'nuclei -version exited with {after.returncode}'
            else:
                native_error = _process_output(before) or f'nuclei -version exited with {before.returncode}'
        except OSError as exc:
            native_error = f'{type(exc).__name__}: {exc}'
    else:
        native_error = 'Nuclei native executable is unavailable.'
    print(f'[!] Native Nuclei is unusable; switching to the official ProjectDiscovery Docker image. Diagnostic: {native_error[-1200:]}', file=sys.stderr)
    ready, docker_detail = _ensure_nuclei_docker_image()
    if not ready:
        raise RuntimeError(f'Nuclei is unavailable both natively and through Docker.\nNative diagnostic: {native_error[-1600:]}\nDocker diagnostic: {docker_detail[-1600:]}')
    launcher = _write_nuclei_docker_launcher()
    _NUCLEI_ENGINE_STATE = {'execution_mode': 'docker_official_image', 'executable': executable or '', 'launcher': str(launcher.resolve()), 'docker_image': NUCLEI_DOCKER_IMAGE, 'update_returncode': None, 'version_before': '', 'version_after': docker_detail[-1000:], 'update_output_excerpt': 'Native execution unavailable; official Docker image selected.', 'native_diagnostic': native_error[-1600:]}
    return dict(_NUCLEI_ENGINE_STATE)

# Refreshes the Nuclei template set and verifies that enough templates are present.
def ensure_nuclei_templates() -> dict[str, Any]:

    global _NUCLEI_TEMPLATE_STATE
    mode = str(_NUCLEI_ENGINE_STATE.get('execution_mode') or 'native')
    executable = command_path('nuclei')
    filesystem_before, directories_before = _filesystem_nuclei_template_count()
    print(f'[*] Nuclei templates before update: {filesystem_before}')
    update_returncode = 0
    combined = ''
    fallback_used = False
    if mode == 'native':
        if not executable:
            raise RuntimeError('Nuclei native executable is unavailable; templates cannot be updated.')
        try:
            update = run([executable, '-update-templates'], required=False, capture=True, timeout=NUCLEI_TEMPLATE_UPDATE_TIMEOUT)
            combined = '\n'.join((update.stdout or '', update.stderr or ''))
            if update.returncode != 0 and 'unknown flag' in combined.lower():
                update = run([executable, '-ut'], required=False, capture=True, timeout=NUCLEI_TEMPLATE_UPDATE_TIMEOUT)
                combined = '\n'.join((update.stdout or '', update.stderr or ''))
            update_returncode = update.returncode
        except OSError as exc:
            update_returncode = 1
            combined = f'{type(exc).__name__}: {exc}'
    else:
        fallback_used = _install_official_nuclei_template_fallback()
        update_returncode = 0 if fallback_used else 1
        combined = 'Official nuclei-templates repository refreshed directly for Docker execution.' if fallback_used else 'Official nuclei-templates repository refresh failed.'
    filesystem_after, directories_after = _filesystem_nuclei_template_count()
    after = filesystem_after
    best_directory = _best_nuclei_template_directory()
    dast_after = _nuclei_dast_template_count(best_directory)
    if dast_after <= 0:
        print('[!] The installed Nuclei inventory has no DAST subtree; refreshing the complete official repository.', file=sys.stderr)
        fallback_used = _install_official_nuclei_template_fallback() or fallback_used
        filesystem_after, directories_after = _filesystem_nuclei_template_count()
        after = filesystem_after
        best_directory = _best_nuclei_template_directory()
        dast_after = _nuclei_dast_template_count(best_directory)
    if after < NUCLEI_TEMPLATE_MINIMUM:
        print(f'[!] Only {after} Nuclei templates were detected on disk; attempting the complete official repository fallback.', file=sys.stderr)
        fallback_used = _install_official_nuclei_template_fallback() or fallback_used
        filesystem_after, directories_after = _filesystem_nuclei_template_count()
        after = filesystem_after
        best_directory = _best_nuclei_template_directory()
        dast_after = _nuclei_dast_template_count(best_directory)
    if after <= 0:
        raise RuntimeError('No Nuclei templates are available. Restore network access and rerun initScript.py so the official projectdiscovery/nuclei-templates repository can be installed.')
    if dast_after <= 0:
        raise RuntimeError('The official Nuclei DAST template subtree is missing. Restore network access and rerun initScript.py so the complete projectdiscovery/nuclei-templates repository can be installed.')
    sufficient = after >= NUCLEI_TEMPLATE_MINIMUM
    if sufficient:
        print(f'[+] Nuclei template inventory ready: {after} templates (filesystem inventory).')
    else:
        print(f'[!] Nuclei has {after} templates. Scans can continue, but the expected full-pack threshold of {NUCLEI_TEMPLATE_MINIMUM} was not reached.', file=sys.stderr)
    _NUCLEI_TEMPLATE_STATE = {'count': after, 'dast_count': dast_after, 'count_before_update': filesystem_before, 'minimum_expected': NUCLEI_TEMPLATE_MINIMUM, 'sufficient': sufficient, 'update_returncode': update_returncode, 'update_output_excerpt': combined[-2000:], 'fallback_used': fallback_used, 'inventory_source': 'filesystem', 'directory': best_directory or _best_nuclei_template_directory(), 'directories': directories_after or directories_before, 'filesystem_candidates': _filesystem_nuclei_template_inventory()}
    return dict(_NUCLEI_TEMPLATE_STATE)

# Verify that the selected engine can load the official DAST subtree before assessments are allowed to run.
def verify_nuclei_dast_runtime(engine: dict[str, Any], templates: dict[str, Any]) -> dict[str, Any]:
    directory = Path(str(templates.get('directory') or '')).expanduser()
    dast_dir = directory / 'dast'
    if not dast_dir.is_dir():
        raise RuntimeError(f'Nuclei DAST template directory is unavailable: {dast_dir}')
    mode = str(engine.get('execution_mode') or 'native')
    if mode == 'docker_official_image':
        command = [
            'docker', 'run', '--rm', '-v', f'{directory.resolve()}:/official-templates:ro',
            NUCLEI_DOCKER_IMAGE, '-tl', '-dast', '-t', '/official-templates/dast', '-silent', '-duc', '-no-stdin',
        ]
    else:
        executable = str(engine.get('executable') or command_path('nuclei') or 'nuclei')
        command = [executable, '-tl', '-dast', '-t', str(dast_dir), '-silent', '-duc', '-no-stdin']
    result = run(command, required=False, capture=True, show_output=False, timeout=180)
    combined = _process_output(result, 12000)
    listed = [line.strip() for line in combined.splitlines() if line.strip() and not line.lstrip().startswith('[')]
    if result.returncode != 0 or not listed:
        raise RuntimeError('Nuclei DAST runtime validation failed: the selected engine could not list the official DAST templates.\n' + combined[-2400:])
    state = {'validated': True, 'listed_templates': len(listed), 'sample': listed[:8], 'command': command, 'output_excerpt': combined[-1600:]}
    print(f'[+] Nuclei DAST runtime ready: {len(listed)} template entries loadable.')
    return state

# Installs or updates every external scanner required by the project.
def install_scanners() -> None:
    print('\n=== Installing/verifying security scanners ===')
    ensure_arjun()
    for name, (repository, script) in REPOSITORY_TOOLS.items():
        install_repository_tool(name, repository, script)
    install_idor_forge()
    install_nikto()
    for name, (repository, hint) in RELEASE_TOOLS.items():
        docker_launcher = LOCAL_BIN / ('nuclei-docker.bat' if os.name == 'nt' else 'nuclei-docker')
        if name == 'nuclei' and (not command_path('nuclei')) and docker_launcher.is_file() and _docker_image_ready(NUCLEI_DOCKER_IMAGE):
            print(f'[+] Nuclei Docker fallback already configured: {NUCLEI_DOCKER_IMAGE}')
            continue
        install_release_tool(name, repository, hint)
    nuclei_engine = ensure_nuclei_engine_current()
    nuclei_templates = ensure_nuclei_templates()
    nuclei_templates['engine'] = nuclei_engine
    nuclei_templates['dast_runtime'] = verify_nuclei_dast_runtime(nuclei_engine, nuclei_templates)
    _NUCLEI_TEMPLATE_STATE.update(nuclei_templates)

# Scanner resolution locates the executable or launcher that will actually be invoked.
def scanner_status() -> dict[str, str | None]:
    return {name: command_path(name) for name in SCANNERS}

# Final setup verification confirms that every configured scanner and support tool is ready.
def verify_scanners(required: bool=True) -> dict[str, str | None]:
    status = scanner_status()
    if _NUCLEI_ENGINE_STATE.get('execution_mode') == 'docker_official_image' and _docker_image_ready(NUCLEI_DOCKER_IMAGE):
        launcher_value = str(_NUCLEI_ENGINE_STATE.get('launcher') or '')
        launcher = Path(launcher_value) if launcher_value else _write_nuclei_docker_launcher()
        if not launcher.is_file():
            launcher = _write_nuclei_docker_launcher()
        status['nuclei'] = str(launcher.resolve())
        print(f'[+] Nuclei verified through official Docker fallback: {NUCLEI_DOCKER_IMAGE}')
    elif _NUCLEI_ENGINE_STATE.get('execution_mode') == 'native':
        status['nuclei'] = str(_NUCLEI_ENGINE_STATE.get('executable') or status.get('nuclei') or '') or None
    if _docker_image_ready(NIKTO_DOCKER_IMAGE):
        if not status.get('nikto'):
            status['nikto'] = str(_write_nikto_docker_launcher())
        print(f'[+] Nikto verified through official Docker fallback: {NIKTO_DOCKER_IMAGE}')
    elif status.get('nikto'):
        perl_value = find_perl()
        script = LOCAL_OPT / 'nikto' / 'program' / 'nikto.pl'
        healthy = False
        detail = 'Perl or nikto.pl is missing.'
        if perl_value and script.is_file():
            healthy, detail = _nikto_health(Path(perl_value).resolve(), script.resolve(), Path(status['nikto']))
        if not healthy:
            status['nikto'] = None
            print(f'[!] Nikto native runtime is unusable and Docker fallback is absent: {detail}', file=sys.stderr)
    print('\n=== Scanner executables ===')
    for name, path in status.items():
        print(f"{name:20} {('OK: ' + path if path else 'MISSING/UNUSABLE')}")
    missing = [name for name, path in status.items() if not path]
    if required and missing:
        raise RuntimeError('Missing or unusable scanners: ' + ', '.join(missing))
    return status

# Writes local runtime paths, the unified MCP endpoint, tool modes, and template metadata.
def write_runtime_config(status: dict[str, str | None]) -> None:
    status_directories = []
    for value in status.values():
        if not value or str(value).startswith('docker:'):
            continue
        path = Path(str(value))
        if path.exists():
            status_directories.append(str(path.parent))
    directories = configure_path() + status_directories
    payload = {'schema_version': 4, 'generated_at': datetime.now(timezone.utc).isoformat(), 'project_root': str(ROOT), 'python_executable': sys.executable, 'platform': platform.platform(), 'machine': platform.machine(), 'tool_directories': list(dict.fromkeys(directories)), 'executables': status, 'idor_forge': dict(_IDOR_FORGE_STATE) if _IDOR_FORGE_STATE else {'repository': IDOR_FORGE_REPOSITORY, 'directory': str(IDOR_FORGE_DIR), 'python': str(IDOR_FORGE_DIR / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python'))}, 'mcp_transport': 'streamable_http', 'mcp_http': {'host': '127.0.0.1', 'path': '/mcp', 'services': {name: mcp_http_url(name) for name in MCP_SERVER_PORTS}}, 'playwright_chromium': {'ready': _playwright_chromium_ready()[0], 'interpreter': sys.executable}, 'nikto_perl': str(Path(find_perl()).resolve()) if find_perl() else '', 'nikto_script': str((LOCAL_OPT / 'nikto' / 'program' / 'nikto.pl').resolve()), 'nikto_image': NIKTO_DOCKER_IMAGE, 'nikto_execution_mode': 'docker_official_image' if _docker_image_ready(NIKTO_DOCKER_IMAGE) else 'native_perl', 'nuclei_image': NUCLEI_DOCKER_IMAGE if _NUCLEI_ENGINE_STATE.get('execution_mode') == 'docker_official_image' else '', 'nuclei_execution_mode': str(_NUCLEI_ENGINE_STATE.get('execution_mode') or 'native'), 'nuclei_engine': dict(_NUCLEI_ENGINE_STATE), 'report_docker_image': REPORT_DOCKER_IMAGE if _docker_image_ready(REPORT_DOCKER_IMAGE) else '', 'report_docker_source_image': REPORT_DOCKER_SOURCE_IMAGE, 'report_execution_mode': 'docker_registry_alias' if _docker_image_ready(REPORT_DOCKER_IMAGE) else 'native_weasyprint', 'nuclei_templates': dict(_NUCLEI_TEMPLATE_STATE) if _NUCLEI_TEMPLATE_STATE else {'count': _filesystem_nuclei_template_count()[0], 'directory': _best_nuclei_template_directory(), 'directories': _filesystem_nuclei_template_count()[1], 'filesystem_candidates': _filesystem_nuclei_template_inventory(), 'minimum_expected': NUCLEI_TEMPLATE_MINIMUM}}
    RUNTIME_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'[+] Runtime scanner configuration written: {RUNTIME_FILE}')

# FFUF setup writes the bundled fallback wordlist only when no project copy exists.
def create_wordlist() -> None:
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
    words = 'admin api assets backup config debug docs images index.php js login.php robots.txt server-status uploads vulnerabilities .env .git'.split()
    (WORDLISTS_DIR / 'common.txt').write_text('\n'.join(words) + '\n', encoding='utf-8')
