from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from fastmcp import FastMCP

from utils import ROOT_DIR, failure, partial, runtime_container_route, success

mcp = FastMCP("Nikto Scanner")

RUNTIME_FILE = Path(ROOT_DIR) / ".secops_runtime.json"
CONNECTION_FAILURE_MARKERS = (
    "unable to connect",
    "connection refused",
    "cannot connect",
    "could not connect",
    "no route to host",
    "connection timed out",
)

FATAL_MARKERS = (
    "can't open perl script",
    "cannot open perl script",
    "required module not found",
    "can't locate ",
    "begin failed",
    "invalid argument",
    "not recognized as an internal or external command",
    "non è riconosciuto come comando",
    "traceback (most recent call last)",
)


def _load_runtime() -> dict[str, Any]:
    try:
        value = json.loads(RUNTIME_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _launcher_script() -> Path | None:
    """Extract the real nikto.pl path from the generated Windows launcher."""
    runtime = _load_runtime()
    configured = runtime.get("executables", {}).get("nikto")
    candidates = [
        Path(configured) if isinstance(configured, str) else None,
        Path.home() / ".local" / "bin" / "nikto.bat",
    ]
    for launcher in candidates:
        if launcher is None or not launcher.is_file():
            continue
        try:
            text = launcher.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = re.search(
            r'"([^"\r\n]*nikto\.pl)"|([A-Za-z]:\\[^\r\n]*?nikto\.pl)',
            text,
            re.IGNORECASE,
        )
        if match:
            path = Path(match.group(1) or match.group(2)).expanduser()
            if path.is_file():
                return path.resolve()
    return None


def _find_nikto_script() -> Path | None:
    candidates = [
        _launcher_script(),
        Path.home() / ".local" / "opt" / "nikto" / "program" / "nikto.pl",
        Path(ROOT_DIR) / "tools" / "nikto" / "program" / "nikto.pl",
    ]
    for path in candidates:
        if path is not None and path.is_file():
            return path.resolve()
    return None


def _find_perl() -> Path | None:
    runtime = _load_runtime()
    configured = runtime.get("executables", {}).get("perl")
    candidates = [
        Path(configured) if isinstance(configured, str) else None,
        Path(shutil.which("perl")) if shutil.which("perl") else None,
        Path(r"C:\Strawberry\perl\bin\perl.exe"),
        Path(r"C:\Program Files\Strawberry Perl\perl\bin\perl.exe"),
    ]
    for path in candidates:
        if path is not None and path.is_file():
            return path.resolve()
    return None


def _process_environment(perl: Path) -> dict[str, str]:
    env = os.environ.copy()
    additions = [perl.parent]
    strawberry_root = perl.parent.parent.parent
    toolchain = strawberry_root / "c" / "bin"
    if toolchain.is_dir():
        additions.append(toolchain)

    current = [part for part in env.get("PATH", "").split(os.pathsep) if part]
    known = {os.path.normcase(os.path.abspath(part)) for part in current}
    for directory in reversed(additions):
        value = str(directory)
        key = os.path.normcase(os.path.abspath(value))
        if key not in known:
            current.insert(0, value)
            known.add(key)

    env["PATH"] = os.pathsep.join(current)
    env["PERL_UNICODE"] = "SDA"
    return env


def _terminate_tree(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _risk_from_message(message: str) -> str:
    text = message.lower()
    if any(term in text for term in (
        "remote code execution", "command execution", "shell", "backdoor",
        "sql injection", "cross-site scripting", "xss",
    )):
        return "high"
    if any(term in text for term in (
        "default credential", "directory indexing", "directory listing",
        "configuration file", "config file", "source code", "password file",
        "outdated", "admin interface", "sensitive file",
    )):
        return "medium"
    if any(term in text for term in (
        "header is not present", "cookie", "http method", "options method",
        "information disclosure",
    )):
        return "low"
    return "info"


def _message_guidance(message: str) -> tuple[str, str]:
    text = message.lower()
    if "directory indexing" in text or "directory listing" in text:
        return (
            "Directory listing can reveal file names, backups, source artifacts, and other resources that were not intended to be enumerated.",
            "Disable directory indexes for the affected location and explicitly publish only required files.",
        )
    if "default credential" in text or "default password" in text:
        return (
            "Default credentials can permit unauthorized access when the affected interface is reachable.",
            "Remove or rotate default accounts and passwords, restrict the interface, and verify authentication controls.",
        )
    if any(token in text for token in ("backup", "configuration file", "config file", "source code", "password file", "sensitive file")):
        return (
            "The reported resource may expose configuration, source, backup, or credential-bearing content if the response is valid.",
            "Manually verify the response, remove the exposed artifact from the web root, restrict access, and rotate any disclosed secrets.",
        )
    if "outdated" in text or "vulnerable" in text:
        return (
            "The reported component version may be affected by publicly documented vulnerabilities. Nikto's version inference requires manual confirmation.",
            "Confirm the installed version and patch or upgrade it according to the vendor advisory referenced by Nikto.",
        )
    if "header is not present" in text or "missing" in text and "header" in text:
        return (
            "The response is missing the security header named in the Nikto message, reducing the corresponding browser-side protection.",
            "Configure the named response header with an application-appropriate value and verify it on all relevant responses.",
        )
    if "allowed methods" in text or "http method" in text or "options method" in text:
        return (
            "The server advertises HTTP methods that may expand the attack surface if they are not required and correctly authorized.",
            "Disable unnecessary methods and enforce authentication and authorization for every enabled method.",
        )
    return ("", "")


def _parse_csv(output_file: Path, target_url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not output_file.is_file():
        return findings

    with output_file.open(
        "r", encoding="utf-8", errors="replace", newline=""
    ) as handle:
        for row in csv.reader(handle):
            if len(row) < 7 or not row:
                continue
            if row[0].strip().lower().startswith(("nikto", "host")):
                continue

            reference = row[3].strip() if len(row) > 3 else ""
            method = row[4].strip() if len(row) > 4 else ""
            uri = row[5].strip() if len(row) > 5 else ""
            message = row[6].strip()
            if not message:
                continue
            if any(marker in message.lower() for marker in CONNECTION_FAILURE_MARKERS):
                continue

            finding_url = (
                uri if uri.startswith(("http://", "https://"))
                else urljoin(target_url.rstrip("/") + "/", uri.lstrip("/"))
            )
            risk = _risk_from_message(message)
            impact, solution = _message_guidance(message)
            title = message.split(".", 1)[0].strip()[:140] or "Nikto web-server finding"
            findings.append({
                "alert": title,
                "risk": risk,
                "category": "observation" if risk == "info" else "candidate",
                "verification_status": "automated-candidate" if risk != "info" else "hardening-observation",
                "confidence": "medium",
                "description": f"Nikto reported: {message}",
                "impact": impact,
                "solution": solution,
                "url": finding_url or target_url,
                "method": method,
                "reference": reference,
                "references": [reference] if reference else [],
                "technical_details": f"Nikto CSV message; method={method or 'not specified'}; reference={reference or 'not supplied'}.",
                "evidence": message,
            })
    return findings



def _parse_text_findings(log_text: str, target_url: str) -> list[dict[str, Any]]:
    """Parse Nikto's normal console finding lines when report-file output is unavailable."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    ignored = (
        "target ip:", "target hostname:", "target port:", "start time:",
        "end time:", "host(s) tested", "requests:", "server:", "ssl info:",
    )
    for raw in str(log_text or "").splitlines():
        line = raw.strip()
        if not line.startswith("+"):
            continue
        message = line.lstrip("+ ").strip()
        lower = message.lower()
        if not message or any(lower.startswith(prefix) for prefix in ignored):
            continue
        if lower in {"requires a value", "+ requires a value"} or lower.endswith(" requires a value"):
            continue
        if any(marker in lower for marker in (
            "host(s) tested", "item(s) reported", "requests:",
            "error(s)", "items checked", "end time:",
        )):
            continue
        if any(marker in lower for marker in CONNECTION_FAILURE_MARKERS):
            continue
        if message in seen:
            continue
        seen.add(message)
        uri_match = re.match(r"(/[^: ]*)\s*:\s*(.*)", message)
        uri = uri_match.group(1) if uri_match else ""
        description = uri_match.group(2) if uri_match else message
        risk = _risk_from_message(description)
        impact, solution = _message_guidance(description)
        findings.append({
            "alert": description.split(".", 1)[0][:140] or "Nikto finding",
            "risk": risk,
            "category": "observation" if risk == "info" else "candidate",
            "verification_status": "automated-candidate" if risk != "info" else "hardening-observation",
            "confidence": "medium",
            "description": f"Nikto reported: {description}",
            "impact": impact,
            "solution": solution,
            "url": urljoin(target_url.rstrip("/") + "/", uri.lstrip("/")) if uri else target_url,
            "method": "GET",
            "technical_details": "Parsed from Nikto console output.",
            "evidence": message,
        })
    return findings


def _nikto_scan_completed(log_text: str) -> bool:
    lower = str(log_text or "").lower()
    return any(marker in lower for marker in (
        "host(s) tested", "end time:", "requests:", "items checked",
        "item(s) reported", "scan terminated", "scan completed",
    ))

def _connection_runtime_error(log_text: str, csv_path: Path) -> str:
    combined = log_text
    try:
        combined += "\n" + csv_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    for line in combined.splitlines():
        if any(marker in line.lower() for marker in CONNECTION_FAILURE_MARKERS):
            return line.strip()
    return ""


def _fatal_runtime_error(log_text: str) -> str:
    lowered = log_text.lower()
    for marker in FATAL_MARKERS:
        if marker in lowered:
            for line in log_text.splitlines():
                if marker in line.lower():
                    return line.strip()
            return marker
    return ""


def _run_native_nikto_scan(
    target_url: str,
    cookies: str = "",
    timeout: int = 180,
) -> dict:
    """
    Run Nikto through Perl directly.

    The generated nikto.bat launcher is intentionally bypassed because nested
    batch execution on Windows can close or corrupt an MCP STDIO session.
    """
    started = time.monotonic()
    timeout = max(60, min(int(timeout), 600))

    perl = _find_perl()
    script = _find_nikto_script()
    if perl is None:
        return failure("Nikto", target_url, "Perl executable was not found.")
    if script is None:
        return failure(
            "Nikto",
            target_url,
            "nikto.pl was not found. Expected it under ~/.local/opt/nikto/program.",
        )

    with tempfile.TemporaryDirectory(prefix="nikto-") as temporary_directory:
        temp = Path(temporary_directory)
        output_file = temp / "nikto.csv"
        log_file = temp / "nikto.log"

        # Nikto stops itself before the MCP call limit. The outer process limit
        # remains as a final safeguard.
        nikto_limit = max(30, timeout - 20)
        command = [
            str(perl),
            str(script),
            "-h", target_url,
            "-nointeractive",
            "-nolookup",
            "-timeout", "5",
            "-maxtime", f"{nikto_limit}s",
            "-Format", "csv",
            "-output", str(output_file),
        ]
        if cookies:
            command.extend(["-Add-header", f"Cookie: {cookies}"])

        creation_flags = 0
        if os.name == "nt":
            creation_flags = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            )

        timed_out = False
        return_code: int | None = None
        try:
            with log_file.open("w", encoding="utf-8", errors="replace") as log:
                process = subprocess.Popen(
                    command,
                    cwd=str(script.parent),
                    env=_process_environment(perl),
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    creationflags=creation_flags,
                )
                try:
                    return_code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _terminate_tree(process)
                    return_code = process.returncode
        except OSError as exc:
            return failure(
                "Nikto",
                target_url,
                f"Cannot start Nikto directly through Perl: {exc}",
            )
        except Exception as exc:
            return failure(
                "Nikto",
                target_url,
                f"Nikto server error: {type(exc).__name__}: {exc}",
            )

        try:
            log_text = log_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""

        findings = _parse_csv(output_file, target_url)
        if not findings:
            findings = _parse_text_findings(log_text, target_url)
        duration = round(time.monotonic() - started, 3)
        fatal = _fatal_runtime_error(log_text)
        connection_failure = _connection_runtime_error(log_text, output_file)

        common = {
            "vulnerabilities": findings,
            "duration_seconds": duration,
            "return_code": return_code,
            "authenticated": bool(cookies),
            "command": command,
            "execution_mode": "direct_perl",
            "nikto_script": str(script),
            "perl_executable": str(perl),
            "scanner_log": log_text[-6000:],
        }

        if connection_failure and not findings:
            result = failure(
                "Nikto",
                target_url,
                f"Nikto could not complete the target connection: {connection_failure}",
                return_code=return_code,
                stdout=log_text,
                diagnosis="nikto_target_unreachable",
            )
            result.update(common)
            return result

        if fatal:
            result = failure(
                "Nikto",
                target_url,
                f"Nikto runtime failed: {fatal}",
                return_code=return_code,
                stdout=log_text,
            )
            result.update(common)
            result["diagnosis"] = "nikto_runtime_error"
            return result

        if timed_out:
            if findings:
                result = success(
                    "Nikto",
                    target_url,
                    f"Nikto reached the {timeout}-second limit after producing "
                    f"{len(findings)} parseable findings.",
                    **common,
                )
                result["status"] = "partial"
                result["diagnosis"] = "time_limit_reached"
                result["timed_out"] = True
                return result

            result = success(
                "Nikto",
                target_url,
                f"Nikto reached the {timeout}-second scan budget. Findings preserved: 0.",
                **common,
            )
            result["status"] = "partial"
            result["diagnosis"] = "time_limit_reached"
            result["timed_out"] = True
            return result

        if return_code not in (0, 1):
            result = failure(
                "Nikto",
                target_url,
                f"Nikto exited with code {return_code}.",
                return_code=return_code,
                stdout=log_text,
            )
            result.update(common)
            result["diagnosis"] = "unexpected_exit_code"
            return result

        return success(
            "Nikto",
            target_url,
            f"Nikto completed through direct Perl execution. Findings: {len(findings)}.",
            **common,
        )


NIKTO_DOCKER_IMAGE = "ghcr.io/sullo/nikto:latest"


def _target_host_port(target_url: str) -> tuple[str, int]:
    parsed = urlparse(target_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.hostname or "", port


def _python_connectivity_probe(target_url: str) -> dict[str, Any]:
    host, port = _target_host_port(target_url)
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "tcp_connected": False,
        "http_reachable": False,
    }
    try:
        with socket.create_connection((host, port), timeout=5):
            result["tcp_connected"] = True
    except OSError as exc:
        result["tcp_error"] = f"{type(exc).__name__}: {exc}"
        return result
    try:
        response = requests.get(
            target_url,
            timeout=(4, 10),
            allow_redirects=True,
        )
        result.update({
            "http_reachable": response.status_code < 500,
            "http_status": response.status_code,
            "final_url": str(response.url),
        })
    except requests.RequestException as exc:
        result["http_error"] = f"{type(exc).__name__}: {exc}"
    return result


def _perl_connectivity_probe(perl: Path, target_url: str) -> dict[str, Any]:
    host, port = _target_host_port(target_url)
    code = (
        "use IO::Socket::INET;"
        f"my $s=IO::Socket::INET->new(PeerAddr=>q{{{host}}},"
        f"PeerPort=>{port},Proto=>q{{tcp}},Timeout=>5);"
        "if($s){print q{connected};close($s);exit 0;}"
        "print(($@||$!||q{unknown socket error}));exit 2;"
    )
    try:
        completed = subprocess.run(
            [str(perl), "-e", code],
            cwd=str(perl.parent),
            env=_process_environment(perl),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            shell=False,
        )
    except Exception as exc:
        return {
            "connected": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "connected": completed.returncode == 0,
        "return_code": completed.returncode,
        "stdout": (completed.stdout or "").strip(),
        "stderr": (completed.stderr or "").strip(),
    }


def _docker_command_available() -> bool:
    return bool(shutil.which("docker"))


def _configured_target_container(target_url: str) -> tuple[str, str, str]:
    route = runtime_container_route(target_url)
    return (
        str(route.get("target_container") or ""),
        str(route.get("alias") or ""),
        str(route.get("network") or ""),
    )


def _docker_target(target_url: str) -> tuple[str, list[str], str]:
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    docker_args: list[str] = []
    mode = "same_target"

    if hostname in {"127.0.0.1", "localhost", "::1"}:
        container, alias, network = _configured_target_container(target_url)
        if container and alias and network:
            completed = subprocess.run(
                ["docker", "inspect", container],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=20,
            )
            if completed.returncode == 0:
                docker_args.extend(["--network", network])
                internal_port = int(runtime_container_route(target_url).get("internal_port") or (443 if parsed.scheme == "https" else 80))
                netloc = alias if internal_port in {80, 443} else f"{alias}:{internal_port}"
                mode = "configured_docker_route"
                return urlunparse(parsed._replace(netloc=netloc)), docker_args, mode

        netloc = "host.docker.internal"
        if parsed.port:
            netloc += f":{parsed.port}"
        docker_args.extend(["--add-host", "host.docker.internal:host-gateway"])
        mode = "docker_desktop_host_gateway"
        return urlunparse(parsed._replace(netloc=netloc)), docker_args, mode

    return target_url, docker_args, mode



def _run_docker_nikto(
    target_url: str,
    cookies: str,
    timeout: int,
    connectivity: dict[str, Any],
) -> dict[str, Any]:
    """Run the official image through its normal console stream.

    Docker Desktop bind-mounted report files are deliberately not required here:
    on Windows they can remain empty even when Nikto executed. The normal Nikto
    output is authoritative, parseable, and matches the official image's basic
    invocation path.
    """
    if not _docker_command_available():
        return failure(
            "Nikto",
            target_url,
            "Native Nikto could not connect and Docker is unavailable for the fallback.",
            diagnosis="nikto_native_and_docker_unavailable",
            connectivity_diagnostics=connectivity,
        )

    docker_target, network_args, mapping_mode = _docker_target(target_url)
    started = time.monotonic()
    nikto_limit = max(25, timeout - 15)
    command = [
        "docker", "run", "--rm",
        *network_args,
        NIKTO_DOCKER_IMAGE,
        "-h", docker_target,
        "-nointeractive",
        "-ask", "no",
        "-nolookup",
        "-nocookies",
        "-timeout", "4",
        "-maxtime", f"{nikto_limit}s",
    ]
    if cookies:
        command.extend(["-Add-header", f"Cookie: {cookies}"])

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        timed_out = False
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        completed = None
        timed_out = True
        stdout = (
            exc.stdout.decode("utf-8", "replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        stderr = (
            exc.stderr.decode("utf-8", "replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
    except OSError as exc:
        return failure(
            "Nikto", target_url,
            f"Cannot start the official Nikto Docker image: {exc}",
            diagnosis="nikto_docker_start_failed",
            connectivity_diagnostics=connectivity,
            command=command,
        )

    log_text = "\n".join(part for part in (stdout, stderr) if part)
    findings = _parse_text_findings(log_text, target_url)
    duration = round(time.monotonic() - started, 3)
    nonexistent_report = Path(tempfile.gettempdir()) / "secops-nikto-no-report-file"
    connection_failure = _connection_runtime_error(log_text, nonexistent_report)
    fatal = _fatal_runtime_error(log_text)
    completion_marker = _nikto_scan_completed(log_text)
    return_code = completed.returncode if completed is not None else None
    common = {
        "vulnerabilities": findings,
        "duration_seconds": duration,
        "return_code": return_code,
        "authenticated": bool(cookies),
        "execution_mode": "official_docker_console",
        "docker_image": NIKTO_DOCKER_IMAGE,
        "docker_target": docker_target,
        "docker_target_mapping": mapping_mode,
        "connectivity_diagnostics": connectivity,
        "scanner_log": log_text[-12000:],
        "command": command,
        "scan_completion_marker": completion_marker,
        "completion_inferred_from_exit_code": bool(
            not completion_marker and return_code in (0, 1)
        ),
    }

    if timed_out:
        return partial(
            "Nikto",
            target_url,
            f"Containerized Nikto reached its configured budget. Findings preserved: {len(findings)}.",
            diagnosis="time_limit_reached",
            timed_out=True,
            time_limit_reached=True,
            **common,
        )

    if connection_failure and not findings:
        result = failure(
            "Nikto",
            target_url,
            f"Containerized Nikto could not reach its translated target: {connection_failure}",
            return_code=return_code,
            stdout=log_text,
            diagnosis="nikto_docker_target_unreachable",
        )
        result.update(common)
        return result

    if fatal:
        result = failure(
            "Nikto",
            target_url,
            f"Containerized Nikto runtime failed: {fatal}",
            return_code=return_code,
            stdout=log_text,
            diagnosis="nikto_runtime_error",
        )
        result.update(common)
        return result

    if return_code not in (0, 1):
        result = failure(
            "Nikto",
            target_url,
            f"Containerized Nikto exited with code {return_code}.",
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            diagnosis="nikto_docker_exit",
        )
        result.update(common)
        return result

    completion_note = (
        "Nikto emitted its normal completion summary."
        if completion_marker
        else "Nikto exited normally; completion was inferred from the accepted process exit code."
    )
    return success(
        "Nikto",
        target_url,
        f"Containerized Nikto completed. Findings: {len(findings)}. {completion_note}",
        **common,
    )



@mcp.tool()
def run_nikto_scan(
    target_url: str,
    cookies: str = "",
    timeout: int = 180,
) -> dict:
    """
    Prefer the native Perl runtime when its socket layer works. On Windows
    loopback targets, automatically use the official Nikto Docker image when
    Python can reach the server but Strawberry Perl/LibWhisker cannot.
    """
    timeout = max(60, min(int(timeout), 600))
    perl = _find_perl()
    connectivity = {
        "python": _python_connectivity_probe(target_url),
        "perl": {},
    }

    if not connectivity["python"].get("tcp_connected"):
        return failure(
            "Nikto",
            target_url,
            "The target TCP port is not reachable from Python; Nikto was not started.",
            diagnosis="target_tcp_unreachable",
            connectivity_diagnostics=connectivity,
        )

    if perl is not None:
        connectivity["perl"] = _perl_connectivity_probe(perl, target_url)

    host, _ = _target_host_port(target_url)
    loopback = host.lower() in {"127.0.0.1", "localhost", "::1"}

    # This is the exact failure observed on Windows: the target is reachable by
    # Python/curl, but Strawberry Perl cannot create the TCP socket.
    if (
        os.name == "nt"
        and loopback
        and not connectivity["perl"].get("connected")
        and _docker_command_available()
    ):
        return _run_docker_nikto(
            target_url,
            cookies,
            timeout,
            connectivity,
        )

    native = _run_native_nikto_scan(
        target_url,
        cookies,
        timeout,
    )
    native["connectivity_diagnostics"] = connectivity

    if (
        native.get("diagnosis") == "nikto_target_unreachable"
        and connectivity["python"].get("tcp_connected")
        and _docker_command_available()
    ):
        docker = _run_docker_nikto(
            target_url,
            cookies,
            timeout,
            connectivity,
        )
        docker.setdefault("native_failure", {
            "status": native.get("status"),
            "diagnosis": native.get("diagnosis"),
            "output": native.get("output"),
        })
        return docker

    return native



def _once() -> int:
    try:
        arguments = json.loads(os.sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = run_nikto_scan(**arguments)
    except Exception as exc:
        result = failure("Nikto", "", f"One-shot Nikto execution failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio")