from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

# When invoked as a script, prefer the interpreter bound to this repository's
# virtual environment before importing third-party modules or running pip.
# Importing initScript from another module must never spawn a child interpreter.
def _use_project_venv_for_cli() -> None:
    if __name__ != '__main__':
        return
    project = Path(__file__).absolute().parent
    venv = project / '.venv'
    target = venv / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not target.is_file():
        return  # A new/explicit environment may legitimately lack a project .venv.
    current_prefix = Path(sys.prefix).absolute()
    if os.path.normcase(str(current_prefix)) == os.path.normcase(str(venv.absolute())):
        return
    print(f'[*] Using the existing SecOps project Python: {target}', flush=True)
    try:
        result = subprocess.run([str(target), str(Path(__file__).absolute()), *sys.argv[1:]], check=False)
    except OSError as exc:
        raise RuntimeError(f'Unable to launch project virtual environment {target}: {exc}') from exc
    raise SystemExit(result.returncode)

_use_project_venv_for_cli()

# Minimal setup bootstrap. setupLab/setupTools import requests and packaging BEFORE
# install_python_packages() is called, so resolve only these two dependencies first.
# Do not install packages into the system interpreter or change a working venv.
def _bootstrap_import_dependencies() -> None:
    import importlib
    import importlib.metadata
    import re

    required = (
        ('requests', 'requests>=2.32,<3', (2, 32), (3,)),
        ('packaging', 'packaging>=24,<27', (24,), (27,)),
    )
    missing = []
    for module, requirement, minimum, exclusive_maximum in required:
        try:
            installed = importlib.metadata.version(module)
            match = re.match(r'^(\d+(?:\.\d+)*)', installed)
            if not match:
                missing.append(requirement)
                continue
            version = tuple(int(piece) for piece in match.group(1).split('.'))
            if version < minimum or version >= exclusive_maximum:
                missing.append(requirement)
                continue
            importlib.import_module(module)
        except (importlib.metadata.PackageNotFoundError, ImportError):
            missing.append(requirement)
    if not missing:
        return
    if sys.prefix == getattr(sys, 'base_prefix', sys.prefix):
        raise RuntimeError(
            'Bootstrap dependencies missing/incompatible: ' + ', '.join(missing)
            + '. Run initScript.py with the project .venv Python; refusing system pip.'
        )
    command = [sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check', *missing]
    print('[*] Installing missing bootstrap dependencies only: ' + ', '.join(missing))
    try:
        result = subprocess.run(command, check=False, text=True, capture_output=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f'Bootstrap pip did not complete: {exc}') from exc
    if result.returncode:
        raise RuntimeError('Bootstrap pip failed: ' + (result.stderr or result.stdout or '')[-2500:])
    # Check in a clean interpreter: in-process packages may have been loaded by
    # third-party tooling before a repair, and should not be trusted after upgrade.
    validation = subprocess.run(
        [sys.executable, '-c', 'import requests, packaging; from packaging.requirements import Requirement; print("Bootstrap OK")'],
        capture_output=True, text=True, check=False, timeout=60,
    )
    if validation.returncode:
        raise RuntimeError('Bootstrap verification failed: ' + (validation.stderr or '')[-1800:])

_bootstrap_import_dependencies()

from setupLab import setup_local_lab, update_runtime_auth
from assessmentConfig import default_max_rounds
from setupTools import (
    COMMAND_REFERENCE_FILE, ROOT, RUNTIME_FILE, TARGET,
    _ensure_report_docker_image, configure_path, configure_perl_environment, create_wordlist, install_playwright_browser,
    install_python_packages, install_scanners, run, verify_scanners, write_runtime_config,
)
from utils import atomic_write_text, setup_path

UNIFIED_MCP_SERVER = ROOT / "servers" / "secopsServer.py"
LINUX_BASE_PACKAGES = ("perl", "cpanminus", "build-essential", "python3-venv")
LINUX_REPORT_PACKAGES = ("libpango-1.0-0", "libpangoft2-1.0-0", "libharfbuzz-subset0")
DEFAULT_AGENTIC_MODEL = "snap4city"
LOCAL_AI_MODELS = {"llama": "llama3.1:8b", "qwen": "qwen2.5:7b"}
AI_PREPARATION_CHOICES = ("all", "snap4city", "llama", "qwen")
CONFIGS_DIR = ROOT / "configs"
DVWA_ASSESSMENT_CONFIG = CONFIGS_DIR / "dvwa.generated.json"


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


# Installs Debian host prerequisites for native PDF reporting and, when requested, scanner fallbacks.
def ensure_linux_host_prerequisites(*, include_scanner_packages: bool = True) -> None:
    if not sys.platform.startswith("linux"):
        return
    if include_scanner_packages:
        perl_env = configure_perl_environment()
        if perl_env.get("PERL5LIB"):
            print(f"[+] PERL5LIB configured for SecOps: {perl_env['PERL5LIB']}")
    apt_get = shutil.which("apt-get")
    dpkg_query = shutil.which("dpkg-query")
    if not apt_get or not dpkg_query:
        print("[*] Non-Debian Linux detected; automatic apt prerequisite installation skipped.")
        return
    packages = list(LINUX_REPORT_PACKAGES)
    if include_scanner_packages:
        packages.extend(LINUX_BASE_PACKAGES)
    packages = list(dict.fromkeys(packages))
    missing = [package for package in packages if not _debian_package_installed(package)]
    if not missing:
        print("[+] Linux host prerequisites already installed: " + ", ".join(packages))
        return
    sudo = _linux_sudo_prefix()
    print("[*] Installing missing Debian host prerequisites: " + ", ".join(missing))
    run([*sudo, apt_get, "update"], timeout=1800)
    run([*sudo, apt_get, "install", "-y", *missing], timeout=3600)
    still_missing = [package for package in packages if not _debian_package_installed(package)]
    if still_missing:
        raise RuntimeError("Debian prerequisite installation did not complete: " + ", ".join(still_missing))


# Adds known Docker Desktop CLI directories to PATH when the installer has just created them.
def _refresh_docker_path() -> str | None:
    candidates: list[Path] = []
    if os.name == "nt":
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        candidates.extend((
            program_files / "Docker" / "Docker" / "resources" / "bin",
            Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "Programs" / "DockerDesktop" / "resources" / "bin",
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


# A Docker CLI on PATH does not prove that Docker Desktop's Linux Engine is running.
# This check is invoked only for the bundled lab, before any scanner modifies state.
def ensure_docker_engine_ready() -> None:
    def probe() -> tuple[bool, str]:
        try:
            result = subprocess.run(
                ['docker', 'info', '--format', '{{.ServerVersion}}'],
                capture_output=True, text=True, timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)
        return (result.returncode == 0 and bool(result.stdout.strip()),
                (result.stderr or result.stdout or '').strip()[-1400:])

    ready, diagnostic = probe()
    if ready:
        print('[+] Docker Engine ready.')
        return
    if os.name == 'nt':
        candidates = (
            Path(os.environ.get('LOCALAPPDATA', str(Path.home() / 'AppData' / 'Local'))) / 'Programs' / 'DockerDesktop' / 'Docker Desktop.exe',
            Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Docker' / 'Docker' / 'Docker Desktop.exe',
        )
        desktop = next((candidate for candidate in candidates if candidate.is_file()), None)
        if desktop:
            print('[*] Docker Desktop is installed but its Linux Engine is offline; launching existing Desktop.')
            try:
                subprocess.Popen([str(desktop)], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0))
            except OSError as exc:
                diagnostic = f'Docker Desktop launch failed: {exc}; {diagnostic}'
            else:
                import time
                for _ in range(30):
                    ready, diagnostic = probe()
                    if ready:
                        print('[+] Docker Engine ready after Docker Desktop startup.')
                        return
                    time.sleep(2)
    raise RuntimeError(
        'Docker CLI found, but Docker Engine is unavailable; DVWA/ZAP cannot start. '
        'Start Docker Desktop (Linux containers/WSL2), then retry --with-lab. '
        + diagnostic[-1400:]
    )


# Scanner processes run inside the MCP server, not inside this initializer.  Check the
# Docker access of the actual server user rather than interpreting `docker image inspect`
# as proof that a container can be started by Nikto or Nuclei.
def _docker_socket_identity() -> tuple[int, str] | None:
    if not sys.platform.startswith('linux'):
        return None
    import grp
    import stat
    try:
        info = Path('/var/run/docker.sock').stat()
        if not stat.S_ISSOCK(info.st_mode):
            return None
        return info.st_gid, grp.getgrgid(info.st_gid).gr_name
    except (OSError, KeyError):
        return None


def _docker_grant_service_group(user: str, group_id: int, group_name: str) -> bool:
    import pwd
    account = pwd.getpwnam(user)
    if group_id in os.getgrouplist(user, account.pw_gid):
        return False
    print(f'[DOCKER] Permanent privilege change: adding {user} to {group_name}. '
          'Docker socket access grants root-equivalent privileges.', flush=True)
    run([*_linux_sudo_prefix(), 'usermod', '-aG', group_name, user], timeout=120)
    if group_id not in os.getgrouplist(user, account.pw_gid):
        raise RuntimeError(f'User {user} still lacks Docker group {group_name} after usermod.')
    return True


def _docker_initializer_access() -> None:
    if not shutil.which('docker'):
        raise RuntimeError('Docker is not installed or not on PATH.')
    probe = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'],
                           capture_output=True, text=True, timeout=25, check=False)
    if probe.returncode == 0:
        print('[+] Docker CLI and daemon usable by initializer.', flush=True)
        return
    diagnostic = (probe.stderr or probe.stdout or '').strip()[-1200:]
    socket = _docker_socket_identity()
    if socket and 'permission denied' in diagnostic.lower():
        import pwd
        user = pwd.getpwuid(os.geteuid()).pw_name
        _docker_grant_service_group(user, *socket)
        raise RuntimeError(
            f'Docker group membership for {user} is configured, but this already-running '
            'shell/tmux process cannot acquire new supplementary groups. Reconnect SSH, '
            'create a new tmux session and rerun initScript.py. ' + diagnostic
        )
    raise RuntimeError('Docker is unavailable to initializer: ' + diagnostic)


def _mcp_listener_pids(port: int) -> list[int]:
    if sys.platform.startswith('linux'):
        import re
        ss = shutil.which('ss')
        if not ss:
            raise RuntimeError('Linux iproute2/ss is needed to inspect the MCP listener.')
        command = [ss, '-H', '-ltnp', f'( sport = :{port} )']
        proc = subprocess.run(command, capture_output=True, text=True, timeout=15)
        pids = {int(n) for n in re.findall(r'pid=(\d+)', proc.stdout)}
        if proc.stdout.strip() and not pids:
            sudo = _linux_sudo_prefix()
            proc = subprocess.run([*sudo, *command], capture_output=True, text=True, timeout=30)
            pids = {int(n) for n in re.findall(r'pid=(\d+)', proc.stdout)}
        if proc.returncode or (proc.stdout.strip() and not pids):
            raise RuntimeError('MCP listener owner cannot be identified safely: ' + (proc.stderr or proc.stdout)[-500:])
        return sorted(pids)
    if os.name == 'nt':
        import re
        powershell = shutil.which('powershell.exe') or shutil.which('powershell')
        if not powershell:
            raise RuntimeError('PowerShell is required to identify the Windows MCP listener.')
        command = f'Get-NetTCPConnection -State Listen -LocalPort {int(port)} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique'
        result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', command],
                                capture_output=True, text=True, timeout=25)
        if result.returncode:
            raise RuntimeError('Cannot identify Windows MCP listener: ' + result.stderr[-600:])
        return sorted({int(v) for v in re.findall(r'^\s*(\d+)\s*$', result.stdout, re.M)})
    raise RuntimeError(f'Automatic MCP process identification not supported on {sys.platform}.')


def _mcp_verified_pid(pid: int) -> tuple[str, set[int]]:
    """Only the existing project's exact secopsServer.py process may be restarted."""
    if pid <= 0 or pid == os.getpid():
        raise RuntimeError(f'Refusing unsafe MCP PID {pid}.')
    expected_script = str(UNIFIED_MCP_SERVER.resolve())
    if sys.platform.startswith('linux'):
        import pwd
        proc = Path('/proc') / str(pid)
        cmd = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode('utf-8', errors='replace')
        cwd = str((proc / 'cwd').resolve())
        if expected_script not in cmd and not ('secopsServer.py' in cmd and cwd == str(ROOT)):
            raise RuntimeError(f'PID {pid} on MCP port is not verified as {expected_script}.')
        groups: set[int] = set()
        for line in (proc / 'status').read_text(encoding='utf-8').splitlines():
            if line.startswith('Groups:'):
                groups.update(map(int, line.split(':', 1)[1].split()))
            if line.startswith('Gid:'):
                fields = line.split(':', 1)[1].split()
                if len(fields) > 1:
                    groups.add(int(fields[1]))
        return pwd.getpwuid(proc.stat().st_uid).pw_name, groups
    if os.name == 'nt':
        ps = shutil.which('powershell.exe') or shutil.which('powershell')
        command = f'(Get-CimInstance Win32_Process -Filter "ProcessId={pid}" -ErrorAction Stop).CommandLine'
        result = subprocess.run([ps, '-NoProfile', '-NonInteractive', '-Command', command],
                                capture_output=True, text=True, timeout=25)
        text = (result.stdout or '').lower().replace('/', '\\')
        if result.returncode or expected_script.lower() not in text:
            raise RuntimeError(f'PID {pid} is not the expected original MCP server; not terminating it.')
        return '', set()
    raise RuntimeError('Cannot verify MCP server PID on this platform.')


def _mcp_systemd_unit_for_pid(pid: int) -> str:
    """Find the actual systemd service owning a verified original MCP process."""
    if not sys.platform.startswith('linux') or not shutil.which('systemctl'):
        return ''
    import re
    try:
        cgroups = (Path('/proc') / str(pid) / 'cgroup').read_text(encoding='utf-8')
    except OSError:
        return ''
    units = sorted(set(re.findall(r'(?:^|/)([a-zA-Z0-9_.@\x2d]+\.service)(?:/|$)', cgroups)))
    for unit in units:
        try:
            result = subprocess.run(['systemctl', 'show', unit, '--property=MainPID', '--value'],
                                    capture_output=True, text=True, timeout=10, check=False)
            if result.returncode == 0 and result.stdout.strip() == str(pid):
                return unit
        except (OSError, subprocess.TimeoutExpired):
            continue
    return ''


def _reconcile_existing_mcp_before_preflight() -> None:
    """Refresh a stale or existing original MCP before an assessment can reuse it.

    No unrelated service is stopped, no active assessment lease is bypassed, and
    the source fingerprint check remains authoritative in the final preflight.
    """
    import signal
    import time
    import orchestratorShared as shared
    from utils import MCP_UNIFIED_SERVICE, mcp_http_port

    port = int(mcp_http_port(MCP_UNIFIED_SERVICE))
    if not shared._port_open('127.0.0.1', port):
        print('[+] No existing MCP listener; preflight will start the current version.', flush=True)
        return
    # Keep lock only for the lease/ownership check. A systemd service may take the
    # same lock during shutdown/startup; restarting it while holding the lock deadlocks.
    with shared._mcp_lifecycle_guard():
        live_leases = shared._prune_mcp_leases_locked()
        if live_leases:
            raise RuntimeError(f'MCP port {port} is in use by active assessment lease(s): '
                               f'{live_leases}. Cannot restart while jobs may be executing.')
        pids = _mcp_listener_pids(port)
        if len(pids) != 1:
            raise RuntimeError(f'MCP port {port} is occupied but has {len(pids)} verified owner candidates: {pids}.')
        pid = pids[0]
        username, live_groups = _mcp_verified_pid(pid)
        unit = _mcp_systemd_unit_for_pid(pid)
        # A matching Python command line does not establish service ownership. The manual
        # CP18 service can intentionally start the same source file from this checkout;
        # restarting that systemd unit here would interfere with independent pentests.
        # Only a unit explicitly designated for the ORIGINAL project may be managed.
        if unit:
            permitted_unit = os.environ.get('SECOPS_ORIGINAL_MCP_SYSTEMD_UNIT', '').strip()
            if unit != permitted_unit:
                raise RuntimeError(
                    f'MCP port {port} belongs to systemd unit {unit!r} (PID {pid}), '
                    'not an explicitly designated original MCP service. '
                    'The initializer will not restart or reuse a possibly manual service. '
                    'Isolate the manual MCP on a separate port/service, or set '
                    'SECOPS_ORIGINAL_MCP_SYSTEMD_UNIT to the exact unit name only after '
                    'confirming that it is exclusively owned by the original project.'
                )
        if sys.platform.startswith('linux'):
            socket = _docker_socket_identity()
            if socket and username:
                import pwd
                uid = pwd.getpwnam(username).pw_uid
                if uid != 0 and socket[0] not in live_groups:
                    _docker_grant_service_group(username, *socket)
                    if not unit:
                        current_user = pwd.getpwuid(os.geteuid()).pw_name
                        if username != current_user or socket[0] not in os.getgroups():
                            raise RuntimeError(
                                f'MCP PID {pid} lacks effective Docker access. The persistent '
                                'group is now set, but the installer cannot relaunch this '
                                'different-user process with verified fresh groups. No scanner '
                                'has been declared ready.'
                            )
                        # A same-user MCP process started outside systemd can be
                        # replaced: preflight starts it with our currently valid groups.
    print(f'[MCP] Restarting verified original MCP PID={pid}' + (f' via {unit}' if unit else '') + '.', flush=True)
    if unit:
        run([*_linux_sudo_prefix(), 'systemctl', 'restart', unit], timeout=90)
    elif os.name == 'nt':
        completed = subprocess.run(['taskkill', '/PID', str(pid)], capture_output=True, text=True, timeout=20)
        if completed.returncode:
            raise RuntimeError(f'Cannot stop verified MCP PID {pid}: {completed.stderr[-700:]}')
    else:
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        # With systemd Restart=always the socket may never be free for very long;
        # verify process replacement rather than relying on an observed gap.
        if not shared._port_open('127.0.0.1', port):
            if not unit:
                return  # preflight may start an owned non-systemd singleton
            time.sleep(0.3)  # systemd may still be in its start phase
            continue
        new_pids = _mcp_listener_pids(port)
        if new_pids and pid not in new_pids:
            for new_pid in new_pids:
                _mcp_verified_pid(new_pid)
            print('[+] MCP listener replaced with a new process; live preflight will verify fingerprint.', flush=True)
            return
        time.sleep(0.3)
    raise RuntimeError(f'Original MCP PID {pid} did not restart within its bounded stop window.')

# Confirm Docker from the actual, currently running MCP process, not only from
# the initializer's shell. Systemd sandboxing and namespaces can make these differ.
def _verify_mcp_docker_access() -> None:
    import asyncio
    from fastmcp import Client
    import orchestratorShared as shared
    from utils import MCP_UNIFIED_SERVICE, mcp_http_url, secops_source_fingerprint

    url = mcp_http_url(MCP_UNIFIED_SERVICE)
    expected = secops_source_fingerprint()

    async def inspect() -> dict[str, Any]:
        async with Client(url) as client:
            response = await asyncio.wait_for(
                client.call_tool('secops_runtime_identity', {'check_docker': True}),
                timeout=30,
            )
        data, is_error, message = shared._extract_response(response)
        if is_error or not isinstance(data, dict):
            raise RuntimeError('MCP Docker verification returned an invalid payload: '
                               + str(message or data)[:900])
        return data

    # Uses the ordinary verified launcher; never contacts a third-party listener.
    shared._ensure_http_server()
    response = asyncio.run(inspect())
    if response.get('source_fingerprint') != expected:
        raise RuntimeError('MCP source fingerprint changed during Docker verification; '
                           'refusing to use a stale service.')
    docker = response.get('docker')
    if not isinstance(docker, dict):
        raise RuntimeError('MCP does not support the runtime Docker self-test. '
                           'Update the existing servers/secopsServer.py as well.')
    if docker.get('ok') is not True:
        raise RuntimeError(
            'Docker is NOT usable from inside the MCP process. '
            f"PID={response.get('pid')}; uid={docker.get('uid')}; "
            f"groups={docker.get('groups')}; socket_gid={docker.get('socket_gid')}; "
            f"returncode={docker.get('returncode')}; detail={str(docker.get('detail') or '')[-1200:]}. "
            'Review the actual service sandbox/namespace and Docker environment. '
            'The initializer will not incorrectly declare Nikto ready.'
        )
    print(f"[+] Docker verified inside MCP PID={response.get('pid')}; "
          f"Docker version={docker.get('version')}", flush=True)


# Fail early when the project source tree is incomplete for the unified MCP architecture.
def verify_unified_mcp_source() -> None:
    if not UNIFIED_MCP_SERVER.is_file():
        raise RuntimeError(
            "Unified MCP server source is missing.\n"
            f"Expected: {UNIFIED_MCP_SERVER}\n"
            "Copy servers/secopsServer.py from the same project source tree before running initialization or an orchestrator."
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
        atomic_write_text(COMMAND_REFERENCE_FILE, command_reference_text())
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


# Excludes documentation/template configurations from the ready-to-run command list.
def _is_example_config(path: Path) -> bool:
    lowered = path.stem.lower().replace("-", "_")
    return any(marker in lowered for marker in ("example", "sample", "template"))


# Discovers reusable assessment configurations without duplicating the generated DVWA command set.
def _additional_assessment_configs(assessment_config: Path) -> list[Path]:
    if not CONFIGS_DIR.is_dir():
        return []
    try:
        excluded = assessment_config.resolve()
    except OSError:
        excluded = assessment_config
    discovered: list[Path] = []
    for path in sorted(CONFIGS_DIR.glob("*.json"), key=lambda item: item.name.lower()):
        if _is_example_config(path) or path.name.lower() == "dvwa.generated.json":
            continue
        try:
            if path.resolve() == excluded:
                continue
        except OSError:
            if path == assessment_config:
                continue
        discovered.append(path)
    return discovered


# Reads only the non-secret metadata needed to label commands for one assessment configuration.
def _config_command_metadata(path: Path) -> tuple[str, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return path.stem, DEFAULT_AGENTIC_MODEL
    platform = payload.get("platform") if isinstance(payload, dict) else {}
    execution = payload.get("execution") if isinstance(payload, dict) else {}
    name = str((platform or {}).get("name") or path.stem).strip() or path.stem
    model = str((execution or {}).get("model") or DEFAULT_AGENTIC_MODEL).strip().lower()
    if model not in {"snap4city", "llama", "qwen"}:
        model = DEFAULT_AGENTIC_MODEL
    return name, model

# Loads the latest local-lab cookie so generated examples use the current session.
def _runtime_cookie_for_commands() -> str:

    try:
        payload = json.loads(RUNTIME_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    if str(payload.get("last_auth_target") or "") != TARGET:
        return ""
    return str(payload.get("last_auth_cookie") or "").strip()


# Writes the ready-to-run DVWA platform configuration using the fresh local-lab session.
def _write_dvwa_assessment_config(cookie_header: str, agentic_model: str, mode: str) -> Path:
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "platform": {
            "name": "Bundled DVWA local lab",
            "description": "Generated by initScript.py from the current local training-lab session.",
        },
        "authorization": {
            "confirmed": True,
            "reference": "Bundled local training lab managed by initScript.py",
        },
        "credentials": {
            "dvwa_session": {
                "kind": "cookie",
                "value": cookie_header,
                "purpose": "Fresh authenticated DVWA session generated by the initializer",
            },
        },
        "assets": [
            {
                "id": "dvwa",
                "host": "127.0.0.1",
                "address": "127.0.0.1",
                "services": [
                    {
                        "id": "http-main",
                        "protocol": "http",
                        "port": 80,
                        "base_path": "/",
                        "credential_ref": "dvwa_session",
                        "auth_only": False,
                        "allow_state_changes": True,
                    },
                ],
            },
        ],
        "execution": {
            "orchestrator": "agentic",
            "mode": mode,
            "request_rate": 10,
            "model": agentic_model,
            "max_rounds": default_max_rounds(mode),
            "require_ai": True,
            "allow_state_changes": True,
            "snap4city_credentials": "snap4city_model_credentials.json",
            "ollama_url": "http://127.0.0.1:11434",
        },
    }
    atomic_write_text(DVWA_ASSESSMENT_CONFIG, json.dumps(payload, indent=2, ensure_ascii=False))
    return DVWA_ASSESSMENT_CONFIG


# Resolves which AI backends the bundled lab initializer must prepare.
def _resolve_ai_preparation(prepare_ai: str) -> tuple[list[str], bool, str]:
    selected = str(prepare_ai or "all").lower()
    if selected == "all":
        return [LOCAL_AI_MODELS["llama"], LOCAL_AI_MODELS["qwen"]], True, DEFAULT_AGENTIC_MODEL
    if selected == "snap4city":
        return [], True, "snap4city"
    if selected in LOCAL_AI_MODELS:
        return [LOCAL_AI_MODELS[selected]], False, selected
    raise ValueError(f"Unsupported AI preparation selection: {prepare_ai}")


# Resolves the effective preparation and Agentic model from the two explicit CLI selectors.
def _resolve_ai_cli_selection(prepare_ai: str | None, agentic_model: str) -> tuple[str, str]:
    explicit_prepare = str(prepare_ai or "").strip().lower()
    explicit_agentic = str(agentic_model or "").strip().lower()

    if explicit_prepare and explicit_agentic and explicit_prepare != "all" and explicit_prepare != explicit_agentic:
        raise ValueError(
            f"--agentic-model {explicit_agentic} is not included by --prepare-ai {explicit_prepare}. "
            "Use --prepare-ai all, omit --prepare-ai, or choose the same backend."
        )

    effective_prepare = explicit_prepare or explicit_agentic or "all"
    _, _, default_agentic = _resolve_ai_preparation(effective_prepare)
    effective_agentic = explicit_agentic or default_agentic
    return effective_prepare, effective_agentic


# Checks whether the selected local AI model is available through the configured Ollama runtime.
def _local_ai_model_ready(alias: str) -> bool:
    model = LOCAL_AI_MODELS.get(alias)
    if not model:
        return False
    try:
        from orchestratorAgenticCore import ensure_ollama_model
        selected, _ = ensure_ollama_model(
            "http://127.0.0.1:11434", model, allow_pull=False,
        )
    except Exception:
        return False
    return selected.lower() == model.lower()


# Returns the first supported local AI alias that is already available to the Ollama runtime.
def _first_ready_local_ai_model() -> str:
    for alias in ("llama", "qwen"):
        if _local_ai_model_ready(alias):
            return alias
    return ""


# Verifies the remote Snap4City model during initialization using the same client as the Agentic orchestrator.
def _prepare_snap4city(credentials_path: str) -> None:
    from orchestratorAgenticCore import (
        SNAP4CITY_DEFAULT_API_URL, SNAP4CITY_DEFAULT_MODEL, ensure_snap4city_model,
    )

    selected, diagnostics = ensure_snap4city_model(
        SNAP4CITY_DEFAULT_API_URL, SNAP4CITY_DEFAULT_MODEL, credentials_path, timeout=180,
    )
    print(
        f"[+] Snap4City ready: model={selected}; "
        f"warm-up={diagnostics.get('warmup_seconds')}s"
    )

# Prints the main configuration-driven commands and one direct Agentic command for manual use.
def print_important_commands(
    agentic_model: str | None = DEFAULT_AGENTIC_MODEL, mode: str = "balanced", cookie_header: str = "",
    assessment_config: Path = DVWA_ASSESSMENT_CONFIG,
) -> None:

    cookie = cookie_header or "<COOKIE_HEADER>"
    print("\n=== Commands ready to run ===")
    print("Run them from: " + str(ROOT))
    commands: list[tuple[str, str]] = [
        ("1. DVWA / 127.0.0.1 - Assessment Deterministic TEST", _operator_command(
            "assessmentRunner.py", "--config", str(assessment_config), "--orchestrator", "deterministic",
            "--mode", "test",
        )),
        ("2. DVWA / 127.0.0.1 - Assessment Deterministic FAST", _operator_command(
            "assessmentRunner.py", "--config", str(assessment_config), "--orchestrator", "deterministic",
            "--mode", "fast",
        )),
        ("3. DVWA / 127.0.0.1 - Assessment Deterministic BALANCED", _operator_command(
            "assessmentRunner.py", "--config", str(assessment_config), "--orchestrator", "deterministic",
            "--mode", "balanced",
        )),
        ("4. DVWA / 127.0.0.1 - Assessment Deterministic DEEP", _operator_command(
            "assessmentRunner.py", "--config", str(assessment_config), "--orchestrator", "deterministic",
            "--mode", "deep",
        )),
        ("5. DVWA / 127.0.0.1 - Assessment Agentic TEST", _operator_command(
            "assessmentRunner.py", "--config", str(assessment_config), "--orchestrator", "agentic",
            "--max-rounds", "1", "--mode", "test", "--require-ai",
        )),
        ("6. DVWA / 127.0.0.1 - Assessment Agentic FAST", _operator_command(
            "assessmentRunner.py", "--config", str(assessment_config), "--orchestrator", "agentic",
            "--max-rounds", "2", "--mode", "fast", "--require-ai",
        )),
        ("7. DVWA / 127.0.0.1 - Assessment Agentic BALANCED", _operator_command(
            "assessmentRunner.py", "--config", str(assessment_config), "--orchestrator", "agentic",
            "--max-rounds", "2", "--mode", "balanced", "--require-ai",
        )),
        ("8. DVWA / 127.0.0.1 - Assessment Agentic DEEP", _operator_command(
            "assessmentRunner.py", "--config", str(assessment_config), "--orchestrator", "agentic",
            "--max-rounds", "3", "--mode", "deep", "--require-ai",
        )),
    ]

    for label, command in commands:
        print(f"\n{label}:\n{command}")
    if agentic_model:
        rounds = str(default_max_rounds(mode))
        print("\nDVWA / 127.0.0.1 - Manual Agentic orchestrator command:")
        print(_operator_command(
            "orchestratorAgentic.py", "--target", TARGET, "--cookies", cookie, "--auth-only",
            "--model", agentic_model, "--max-rounds", rounds, "--mode", mode, "--require-ai",
        ))
    additional_configs = _additional_assessment_configs(assessment_config)
    if additional_configs:
        print("\n=== Configured assessments - TEST and BALANCED ===")
        for config_path in additional_configs:
            config_name, _configured_model = _config_command_metadata(config_path)
            print(f"\n{config_name} - Deterministic TEST:")
            print(_operator_command(
                "assessmentRunner.py", "--config", str(config_path),
                "--orchestrator", "deterministic", "--mode", "test", "--authorized",
            ))
            print(f"\n{config_name} - Agentic TEST:")
            print(_operator_command(
                "assessmentRunner.py", "--config", str(config_path),
                "--orchestrator", "agentic", "--max-rounds", "1",
                "--mode", "test", "--require-ai", "--authorized",
            ))
            print(f"\n{config_name} - Deterministic BALANCED:")
            print(_operator_command(
                "assessmentRunner.py", "--config", str(config_path),
                "--orchestrator", "deterministic", "--mode", "balanced", "--authorized",
            ))
            print(f"\n{config_name} - Agentic BALANCED:")
            print(_operator_command(
                "assessmentRunner.py", "--config", str(config_path),
                "--orchestrator", "agentic", "--max-rounds", "2",
                "--mode", "balanced", "--require-ai", "--authorized",
            ))
    print(f"\n[+] Every command and modifier: {COMMAND_REFERENCE_FILE}")

# Parses command-line options and drives the complete workflow for this entrypoint.
def main() -> int:
    print("=== SecOps initializer ===")
    parser = argparse.ArgumentParser(
        description="Initialize FastMCP SecOps and generate the complete operator command guide."
    )
    parser.add_argument("--with-lab", action="store_true", help="Start/verify the bundled local training lab and ZAP, provision the selected AI backends, then create a session.")
    parser.add_argument("--run", choices=("none", "deterministic", "agentic"), default="none", help="Run the generated DVWA assessment after initialization; deterministic/agentic requires --with-lab.")
    parser.add_argument(
        "--prepare-ai", choices=AI_PREPARATION_CHOICES, default=None,
        help=(
            "AI backends prepared by --with-lab. If omitted together with --agentic-model, all backends are prepared. "
            "If --agentic-model is provided and --prepare-ai is omitted, only that selected Agentic model is prepared. "
            "Choose all, snap4city, llama or qwen."
        ),
    )
    parser.add_argument(
        "--agentic-model", choices=("snap4city", "llama", "qwen"), default="",
        help=(
            "AI used by --run agentic and by the Agentic commands printed at the end. "
            "If --prepare-ai is omitted, specifying this option also makes the initializer prepare only this model. "
            "If both options are provided, the selected model must be included by --prepare-ai."
        ),
    )
    parser.add_argument(
        "--snap4city-credentials", default="snap4city_model_credentials.json",
        help="Credentials JSON for the Snap4City AI model/provider (not the assessed dashboard account). Cached access/refresh tokens are reused first; missing/placeholder credentials are requested interactively only when no usable token remains.",
    )
    parser.add_argument("--mode", choices=("test", "fast", "balanced", "deep"), default="balanced", help="Scanner coverage/runtime profile (default: balanced; test = short diagnostic budgets).")
    parser.add_argument("--skip-preflight", action="store_true", help="Skip the live deterministic MCP/dependency preflight.")
    parser.add_argument("--skip-scanners", action="store_true", help="Skip scanner installation and do not require all scanner executables.")
    parser.add_argument("--skip-browser", action="store_true", help="Do not install/verify Playwright Chromium; browser-only checks will be skipped.")
    parser.add_argument("--require-browser", action="store_true", help="Compatibility flag: Chromium is already required by default unless --skip-browser is used.")
    parser.add_argument("--commands-only", action="store_true", help="Print every supported command/modifier, write init.txt, and exit.")
    args = parser.parse_args()

    try:
        prepare_ai, agentic_model = _resolve_ai_cli_selection(args.prepare_ai, args.agentic_model)
    except ValueError as exc:
        parser.error(str(exc))
    local_ai_models, prepare_snap4city, _ = _resolve_ai_preparation(prepare_ai)

    os.chdir(ROOT)
    setup_path()
    configure_path()
    cookie = ""
    commands_printed = False
    snap4city_ready = False
    snap4city_attempted = False
    effective_agentic_model: str | None = agentic_model
    assessment_config = DVWA_ASSESSMENT_CONFIG
    try:
        # Before scans can run, setup installs the required tools and verifies the local environment.
        guide_path = write_command_reference()
        if args.commands_only:
            print_command_reference(guide_path)
            print_important_commands(
                agentic_model, args.mode, _runtime_cookie_for_commands(), DVWA_ASSESSMENT_CONFIG,
            )
            return 0
        print(f"[+] Full command guide written: {guide_path}")
        verify_unified_mcp_source()
        print(f"[+] Unified MCP server source: {UNIFIED_MCP_SERVER}")
        if sys.platform.startswith("linux"):
            ensure_linux_host_prerequisites(include_scanner_packages=not args.skip_scanners)
        ensure_docker_installed()
        # Linux permission repair must precede the generic Engine readiness check:
        # otherwise a permission-denied socket would abort before usermod can fix it.
        if sys.platform.startswith('linux') and (args.with_lab or not args.skip_scanners):
            _docker_initializer_access()
        if args.with_lab:
            ensure_docker_engine_ready()
        # Windows Docker Desktop may have needed startup before a real docker-info check.
        if not sys.platform.startswith('linux') and (args.with_lab or not args.skip_scanners):
            _docker_initializer_access()
        print("\n=== SecOps FastMCP initialization ===")
        install_python_packages()
        if not args.skip_browser:
            install_playwright_browser(required=True)
        elif args.require_browser:
            raise RuntimeError("--require-browser cannot be combined with --skip-browser.")
        create_wordlist()
        if not args.skip_scanners:
            install_scanners()
        if shutil.which("docker"):
            _ensure_report_docker_image()
        status = verify_scanners(required=not args.skip_scanners)
        write_runtime_config(status)


        # When the operator enables the bundled lab, setup starts DVWA/ZAP and provisions the selected AI backends.
        if args.with_lab:
            print(
                "[*] AI preparation: local Ollama models="
                + (", ".join(local_ai_models) if local_ai_models else "none")
                + f"; Snap4City={'yes' if prepare_snap4city else 'no'}"
                + f"; selection={prepare_ai}; Agentic model={agentic_model}"
            )
            cookie = setup_local_lab(local_ai_models)
            update_runtime_auth(cookie)
            print(f"\n[+] Bundled local-lab login created successfully.\n[+] Cookie header: {cookie}")
            if prepare_snap4city:
                try:
                    snap4city_attempted = True
                    _prepare_snap4city(args.snap4city_credentials)
                    snap4city_ready = True
                except Exception as snap_exc:
                    print(
                        f"[!] Snap4City preparation failed: {type(snap_exc).__name__}: {snap_exc}",
                        file=sys.stderr,
                    )
                    fallback_alias = _first_ready_local_ai_model()
                    if not fallback_alias:
                        try:
                            print("[*] Preparing local Ollama fallback: llama3.1:8b")
                            cookie = setup_local_lab([LOCAL_AI_MODELS["llama"]])
                            update_runtime_auth(cookie)
                            fallback_alias = _first_ready_local_ai_model()
                        except Exception as local_exc:
                            print(
                                f"[!] Local Ollama fallback preparation failed: {type(local_exc).__name__}: {local_exc}",
                                file=sys.stderr,
                            )
                    if agentic_model == "snap4city":
                        effective_agentic_model = fallback_alias or None
                        if effective_agentic_model:
                            print(
                                f"[!] Snap4City is unavailable; Agentic execution will use verified local fallback {effective_agentic_model}.",
                                file=sys.stderr,
                            )
                        else:
                            print(
                                "[!] Snap4City is unavailable and no local AI model is ready; initialization continues without Agentic recovery commands.",
                                file=sys.stderr,
                            )
            config_model = effective_agentic_model or agentic_model
            assessment_config = _write_dvwa_assessment_config(cookie, config_model, args.mode)
            print(f"[+] DVWA assessment configuration: {assessment_config}")

        # Always reconcile an already-running ORIGINAL MCP with the current sources
        # and runtime configuration before the first scanner preflight/assessment.
        _reconcile_existing_mcp_before_preflight()
        if not args.skip_scanners:
            _verify_mcp_docker_access()
        if not args.skip_preflight:
            run_preflight()

        if args.run != "none":
            if not cookie:
                raise RuntimeError("--run requires --with-lab because it needs a generated local-lab session.")
            command = [
                sys.executable, str(ROOT / "assessmentRunner.py"),
                "--config", str(assessment_config), "--orchestrator", args.run, "--mode", args.mode,
            ]
            if args.run == "agentic":
                if not effective_agentic_model:
                    print("[-] No verified AI backend is available for --run agentic.", file=sys.stderr)
                    return 4
                rounds = str(default_max_rounds(args.mode))
                command += ["--max-rounds", rounds, "--require-ai"]
            return run(command, required=False, timeout=7200, cwd=ROOT).returncode

        print_important_commands(
            effective_agentic_model, args.mode, cookie or _runtime_cookie_for_commands(), assessment_config,
        )
        commands_printed = True
        return 0
    except Exception as exc:
        print(f"[-] Initialization failed: {type(exc).__name__}: {exc}", file=sys.stderr)


        if not args.commands_only and not commands_printed:
            command_agentic_model: str | None = agentic_model
            if args.with_lab and agentic_model in LOCAL_AI_MODELS:
                if not _local_ai_model_ready(agentic_model):
                    command_agentic_model = None
                    print(
                        f"[!] Local AI model {agentic_model} was not verified; Agentic recovery commands are omitted.",
                        file=sys.stderr,
                    )
            elif args.with_lab and agentic_model == "snap4city" and prepare_snap4city and not snap4city_ready:
                if snap4city_attempted:
                    command_agentic_model = None
                    for local_alias in ("llama", "qwen"):
                        if LOCAL_AI_MODELS[local_alias] in local_ai_models and _local_ai_model_ready(local_alias):
                            command_agentic_model = local_alias
                            print(
                                f"[!] Snap4City verification failed; the direct recovery example uses verified local model {local_alias}. "
                                "Config-driven commands keep each configuration's own execution.model.",
                                file=sys.stderr,
                            )
                            break
                    if command_agentic_model is None:
                        print(
                            "[!] Snap4City verification failed and no prepared local AI model is ready. "
                            "Config-driven commands are still printed without a model override.",
                            file=sys.stderr,
                        )
                else:
                    print(
                        "[!] Snap4City verification was not reached because initialization failed earlier; "
                        "the configured model is preserved and no local provider is substituted.",
                        file=sys.stderr,
                    )
            if assessment_config.is_file():
                print_important_commands(
                    command_agentic_model, args.mode, cookie or _runtime_cookie_for_commands(), assessment_config,
                )
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
