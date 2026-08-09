from __future__ import annotations

import ipaddress
import csv
import json
from difflib import SequenceMatcher
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from fastmcp import FastMCP

from utils import ROOT_DIR, failure, load_runtime_config, parse_cookie_header, partial, runtime_container_route, success

from utils import run_mcp_http

mcp = FastMCP("Nikto Scanner")

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
    "unknown option",
    "invalid plugin",
    "plugin not found",
    "no plugins were selected",
    "cannot open output",
    "could not open output",
    "permission denied",
)


NIKTO_SCAN_PROFILES: dict[str, dict[str, Any]] = {
    # Do not pass the literal value "ALL" to -Plugins. Nikto's plugin macros
    # are named @@DEFAULT/@@ALL, and explicitly overriding the plugin string can
    # also remove the report plugin. The official default plugin selection is
    # therefore left implicit for every normal profile; Tuning and CGI scope
    # control scan breadth without breaking CSV output.
    "fast": {
        "plugin_selection": "",
        "plugins_label": "implicit-default",
        "tuning": "123b",
        "cgi_dirs": "none",
        "display": "VP",
        "minimum_clean_requests": 20,
    },
    "balanced": {
        "plugin_selection": "",
        "plugins_label": "implicit-default",
        "tuning": "x6",
        "cgi_dirs": "none",
        "display": "VP",
        "minimum_clean_requests": 80,
    },
    "deep": {
        "plugin_selection": "",
        "plugins_label": "implicit-default",
        "tuning": "x6",
        "cgi_dirs": "all",
        "display": "VP",
        "minimum_clean_requests": 200,
    },
}


def _normalize_scan_profile(value: str) -> str:
    profile = str(value or "balanced").strip().lower()
    return profile if profile in NIKTO_SCAN_PROFILES else "balanced"


def _nikto_profile_arguments(scan_profile: str) -> list[str]:
    profile = NIKTO_SCAN_PROFILES[_normalize_scan_profile(scan_profile)]
    # Do not pass -nocheck. Although newer Nikto documentation lists it,
    # older/cached official Docker images may reject it as an unknown option.
    # Skipping an update check is not required for scan correctness, so the
    # portable command deliberately omits it for native and Docker execution.
    arguments = [
        "-Tuning", str(profile["tuning"]),
        "-Display", str(profile["display"]),
    ]
    plugin_selection = str(profile.get("plugin_selection") or "").strip()
    if plugin_selection:
        arguments.extend(["-Plugins", plugin_selection])
    if str(profile.get("cgi_dirs") or "none").lower() != "none":
        arguments.extend(["-Cgidirs", str(profile["cgi_dirs"])])
    return arguments


def _nikto_static_cookie_value(cookies: str) -> str:
    """Encode a Cookie header for Nikto's long-standing STATIC-COOKIE option.

    ``-Add-header`` was added only in newer Nikto revisions and is rejected by
    older cached Docker images. ``-Option STATIC-COOKIE=...`` is supported by
    old and new releases and populates Nikto's cookie jar for every request.
    """
    pairs = parse_cookie_header(cookies)
    encoded: list[str] = []
    for name, value in pairs:
        # Nikto parses quoted name=value pairs separated by semicolons. Cookie
        # values are opaque; reject quotes rather than silently changing them.
        if '"' in value:
            raise ValueError(f'Nikto STATIC-COOKIE cannot safely encode a quote in cookie {name!r}.')
        encoded.append(f'"{name}={value}"')
    return ";".join(encoded) + (";" if encoded else "")


def _nikto_cookie_arguments(cookies: str) -> list[str]:
    if not str(cookies or "").strip():
        # Keep anonymous scans isolated from cookies set by the target.
        return ["-nocookies"]
    return ["-Option", f"STATIC-COOKIE={_nikto_static_cookie_value(cookies)}"]


def _redact_nikto_command(command: list[str]) -> list[str]:
    """Return a report-safe copy of a Nikto command without session secrets."""
    redacted = list(command)
    for index, value in enumerate(redacted):
        if str(value).startswith("STATIC-COOKIE="):
            redacted[index] = "STATIC-COOKIE=<redacted>"
        elif str(value).lower().startswith("cookie:"):
            redacted[index] = "Cookie: <redacted>"
    return redacted


def _baseline_security_signals(target_url: str, cookies: str) -> dict[str, Any]:
    """Collect a read-only sanity baseline for evaluating a zero-result scan.

    These values are diagnostics only. They are never converted into Nikto
    findings. A zero-result Nikto run is accepted as complete only when Nikto
    also reports a meaningful request count and a structured report.
    """
    headers = {"User-Agent": "SecOps-Nikto-Coverage-Probe/1.0", "Cache-Control": "no-cache"}
    if cookies:
        headers["Cookie"] = cookies
    try:
        response = requests.get(target_url, headers=headers, timeout=(4, 12), allow_redirects=True)
    except requests.RequestException as exc:
        return {"performed": True, "error": f"{type(exc).__name__}: {exc}", "signal_count": 0}

    lowered = {str(key).lower(): str(value) for key, value in response.headers.items()}
    missing_headers = [
        name for name in (
            "x-frame-options",
            "x-content-type-options",
            "content-security-policy",
            "referrer-policy",
        )
        if name not in lowered
    ]
    signals: list[str] = []
    if lowered.get("server"):
        signals.append("server_banner_present")
    if lowered.get("x-powered-by"):
        signals.append("technology_header_present")
    signals.extend(f"missing_header:{name}" for name in missing_headers)
    if "index of /" in response.text[:100_000].lower():
        signals.append("directory_index_marker")
    return {
        "performed": True,
        "status": response.status_code,
        "final_url": str(response.url),
        "server": lowered.get("server", ""),
        "x_powered_by": lowered.get("x-powered-by", ""),
        "missing_security_headers": missing_headers,
        "signals": signals,
        "signal_count": len(signals),
    }


def _nikto_coverage_verified(
    metrics: dict[str, Any],
    structured_report: dict[str, Any],
    scan_profile: str,
) -> bool:
    """Return true only when Nikto demonstrably completed the selected profile.

    A copied structured report is preferred.  A console-only retry is accepted
    when the image cannot write a report file, but only if Nikto prints its
    normal completion summary and reaches the profile's request threshold.
    """
    profile = NIKTO_SCAN_PROFILES[_normalize_scan_profile(scan_profile)]
    minimum = int(profile["minimum_clean_requests"])
    evidence_channel = bool(
        structured_report.get("copied")
        or structured_report.get("console_only")
    )
    return bool(
        metrics.get("completion_marker")
        and int(metrics.get("requests") or 0) >= minimum
        and int(metrics.get("errors") or 0) == 0
        and evidence_channel
    )




def _launcher_script() -> Path | None:
    """Extract the real nikto.pl path from the generated Windows launcher."""
    runtime = load_runtime_config()
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
    runtime = load_runtime_config()
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
                "parser_sources": ["csv"],
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
        # Runtime/configuration failures are execution diagnostics, not target
        # findings.  Treating "+ ERROR: ..." as a hardening observation caused
        # failed Nikto invocations to report a fake finding and to mark coverage
        # as verified.
        if lower.startswith(("error:", "fatal:", "unable to open", "cannot open")):
            continue
        if any(marker in lower for marker in (
            "unknown option", "invalid plugin", "plugin not found",
            "no plugins were selected", "permission denied",
        )):
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
            "parser_sources": ["console"],
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


def _nikto_nolookup_arguments(target_url: str) -> list[str]:
    """Use ``-nolookup`` only when Nikto receives a literal IP address.

    Nikto 2.5.0 exits before scanning when ``-nolookup`` is combined with a
    hostname such as a Docker network alias (for example ``http://dvwa``).
    Container aliases must be resolved by Docker DNS, while literal IPv4/IPv6
    targets can safely keep the optimisation.
    """
    hostname = str(urlparse(str(target_url or "")).hostname or "").strip()
    if not hostname:
        return []
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return []
    return ["-nolookup"]


def _remove_command_flag(command: list[str], flag: str) -> list[str]:
    """Return a copy with a standalone compatibility flag removed."""
    return [value for value in command if value != flag]


def _nikto_nolookup_name_failure(log_text: str) -> bool:
    value = str(log_text or "").lower()
    return "-nolookup set, but given name" in value


def _run_native_nikto_scan(
    target_url: str,
    cookies: str = "",
    timeout: int = 180,
    scan_profile: str = "balanced",
) -> dict:
    """
    Run Nikto through Perl directly.

    The generated nikto.bat launcher is intentionally bypassed because nested
    batch execution on Windows can produce incomplete native output; the wrapper preserves bounded fallback behaviour.
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
            *_nikto_nolookup_arguments(target_url),
            "-timeout", "5",
            "-maxtime", f"{nikto_limit}s",
            "-Format", "csv",
            "-output", str(output_file),
            *_nikto_profile_arguments(scan_profile),
        ]
        command.extend(_nikto_cookie_arguments(cookies))

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

        csv_findings = _parse_csv(output_file, target_url)
        console_findings = _parse_text_findings(log_text, target_url)
        findings = _merge_nikto_findings(csv_findings, console_findings)
        duration = round(time.monotonic() - started, 3)
        fatal = _fatal_runtime_error(log_text)
        connection_failure = _connection_runtime_error(log_text, output_file)
        metrics = _nikto_scan_metrics(log_text)
        structured_report = {
            "attempted": True,
            "copied": output_file.is_file(),
            "bytes": output_file.stat().st_size if output_file.is_file() else 0,
        }
        baseline_probe = _baseline_security_signals(target_url, cookies)
        coverage_verified = _nikto_coverage_verified(
            metrics, structured_report, scan_profile
        )
        zero_result_verified = bool(not findings and coverage_verified)

        common = {
            "vulnerabilities": findings,
            "duration_seconds": duration,
            "return_code": return_code,
            "authenticated": bool(cookies),
            "command": _redact_nikto_command(command),
            "execution_mode": "direct_perl",
            "nikto_script": str(script),
            "perl_executable": str(perl),
            "scanner_log": log_text[-12000:],
            "scan_profile": _normalize_scan_profile(scan_profile),
            "scan_metrics": metrics,
            "structured_report": structured_report,
            "coverage_verified": coverage_verified,
            "zero_result_verified": zero_result_verified,
            "baseline_probe": baseline_probe,
            "minimum_clean_requests": NIKTO_SCAN_PROFILES[_normalize_scan_profile(scan_profile)]["minimum_clean_requests"],
            "csv_findings": len(csv_findings),
            "console_findings": len(console_findings),
            "raw_parsed_findings": len(csv_findings) + len(console_findings),
            "cross_source_duplicates_removed": len(csv_findings) + len(console_findings) - len(findings),
            "nikto_reported_items": int(metrics.get("items_reported") or 0),
            "parser_count_consistent": (
                int(metrics.get("items_reported") or 0) == 0
                or len(findings) == int(metrics.get("items_reported") or 0)
            ),
            "safe_tuning": NIKTO_SCAN_PROFILES[_normalize_scan_profile(scan_profile)]["tuning"],
            "plugins": NIKTO_SCAN_PROFILES[_normalize_scan_profile(scan_profile)]["plugins_label"],
            "cgi_dirs": NIKTO_SCAN_PROFILES[_normalize_scan_profile(scan_profile)]["cgi_dirs"],
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

        if not coverage_verified:
            return partial(
                "Nikto",
                target_url,
                "Nikto returned zero findings without enough request/completion evidence for the selected scan profile. "
                "The result is retained as incomplete rather than reported as a clean scan.",
                diagnosis="nikto_zero_result_unverified",
                timed_out=False,
                time_limit_reached=False,
                **common,
            )

        return success(
            "Nikto",
            target_url,
            f"Nikto completed through direct Perl execution. Findings: {len(findings)}; "
            f"requests={metrics.get('requests', 0)}; profile={_normalize_scan_profile(scan_profile)}.",
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



def _nikto_scan_metrics(log_text: str) -> dict[str, Any]:
    """Extract completion and coverage counters from Nikto's console summary."""
    text = str(log_text or "")
    lower = text.lower()
    metrics: dict[str, Any] = {
        "requests": 0,
        "errors": 0,
        "items_reported": 0,
        "hosts_tested": 0,
        "completion_marker": _nikto_scan_completed(text),
    }
    summary = re.search(
        r"(?im)(\d+)\s+requests?\s*:\s*(\d+)\s+error\(s\)\s+and\s+(\d+)\s+item\(s\)\s+reported",
        text,
    )
    if summary:
        metrics.update({
            "requests": int(summary.group(1)),
            "errors": int(summary.group(2)),
            "items_reported": int(summary.group(3)),
        })
    else:
        request_match = re.search(r"(?im)(\d+)\s+requests?", text)
        item_match = re.search(r"(?im)(\d+)\s+item\(s\)\s+reported", text)
        error_match = re.search(r"(?im)(\d+)\s+error\(s\)", text)
        if request_match:
            metrics["requests"] = int(request_match.group(1))
        if item_match:
            metrics["items_reported"] = int(item_match.group(1))
        if error_match:
            metrics["errors"] = int(error_match.group(1))
    host_match = re.search(r"(?im)(\d+)\s+host\(s\)\s+tested", text)
    if host_match:
        metrics["hosts_tested"] = int(host_match.group(1))
    metrics["normal_summary_present"] = bool(
        metrics["completion_marker"]
        or metrics["requests"]
        or metrics["hosts_tested"]
        or "end time:" in lower
    )
    return metrics


def _canonical_nikto_url(value: Any) -> tuple[str, str, str]:
    """Normalize a finding URL for cross-parser comparison."""
    text = str(value or "").strip()
    try:
        parsed = urlparse(text)
    except ValueError:
        return ("", "", text.rstrip("/").lower())
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return (parsed.scheme.lower(), parsed.netloc.lower(), path.lower())


def _canonical_nikto_message(finding: dict[str, Any]) -> str:
    """Return a stable message fingerprint shared by CSV and console parsers."""
    value = str(
        finding.get("evidence")
        or finding.get("description")
        or finding.get("alert")
        or ""
    ).strip()
    value = re.sub(r"^nikto reported:\s*", "", value, flags=re.I)
    value = re.sub(r"^https?://[^\s:]+(?::\d+)?/[^:]*:\s*", "", value, flags=re.I)
    value = re.sub(r"^/[^:]*:\s*", "", value)
    value = re.sub(r"\s+see:\s+\S+.*$", "", value, flags=re.I)
    value = re.sub(r"https?://\S+", "", value, flags=re.I)
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def _nikto_findings_equivalent(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if _canonical_nikto_url(left.get("url")) != _canonical_nikto_url(right.get("url")):
        return False
    left_message = _canonical_nikto_message(left)
    right_message = _canonical_nikto_message(right)
    if not left_message or not right_message:
        return False
    if left_message == right_message:
        return True
    return SequenceMatcher(None, left_message, right_message).ratio() >= 0.92


def _enrich_nikto_finding(primary: dict[str, Any], secondary: dict[str, Any]) -> None:
    references: list[str] = []
    for source in (primary.get("references"), secondary.get("references")):
        if isinstance(source, list):
            references.extend(str(item) for item in source if str(item))
    for source in (primary.get("reference"), secondary.get("reference")):
        if source:
            references.append(str(source))
    unique_references = list(dict.fromkeys(references))
    if unique_references:
        primary["references"] = unique_references
        primary["reference"] = unique_references[0]
    if not str(primary.get("impact") or "").strip() and secondary.get("impact"):
        primary["impact"] = secondary["impact"]
    if not str(primary.get("solution") or "").strip() and secondary.get("solution"):
        primary["solution"] = secondary["solution"]
    sources = list(primary.get("parser_sources") or [])
    sources.extend(secondary.get("parser_sources") or [])
    primary["parser_sources"] = list(dict.fromkeys(str(item) for item in sources if str(item)))


def _merge_nikto_findings(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge CSV and console representations without double-counting findings.

    Findings inside one parser remain distinct. Equivalence is tested only
    across parser groups, so two different Nikto checks on the same endpoint
    are preserved while the CSV/console duplicate of each check is collapsed.
    """
    merged: list[dict[str, Any]] = []
    group_indexes: list[int] = []
    for group_index, group in enumerate(groups):
        for original in group:
            finding = dict(original)
            finding.setdefault(
                "parser_sources",
                ["csv" if group_index == 0 else "console" if group_index == 1 else f"source-{group_index}"],
            )
            duplicate_index: int | None = None
            for index, existing in enumerate(merged):
                if group_indexes[index] == group_index:
                    continue
                if _nikto_findings_equivalent(existing, finding):
                    duplicate_index = index
                    break
            if duplicate_index is None:
                merged.append(finding)
                group_indexes.append(group_index)
            else:
                _enrich_nikto_finding(merged[duplicate_index], finding)
    return merged


def _docker_nikto_command(
    container_name: str,
    docker_target: str,
    network_args: list[str],
    cookies: str,
    nikto_limit: int,
    scan_profile: str,
    report_path: str = "/tmp/secops-nikto.csv",
    *,
    structured_output: bool = True,
) -> list[str]:
    """Build a portable named-container Nikto command.

    The official image currently runs as an unprivileged user.  Its home
    directory is not guaranteed to be writable in every image revision, while
    ``/tmp`` is the portable writable location.  If even structured output is
    rejected, the caller retries without ``-Format/-o`` and audits the normal
    console summary instead.
    """
    command = [
        "docker", "create", "--name", container_name,
        *network_args,
        NIKTO_DOCKER_IMAGE,
        "-h", docker_target,
        "-nointeractive",
        "-ask", "no",
        *_nikto_nolookup_arguments(docker_target),
        "-followredirects",
        "-timeout", "4",
        "-maxtime", f"{nikto_limit}s",
    ]
    if structured_output:
        command.extend(["-Format", "csv", "-o", report_path])
    command.extend(_nikto_profile_arguments(scan_profile))
    command.extend(_nikto_cookie_arguments(cookies))
    return command


def _docker_container_state(container_name: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["docker", "inspect", "--format", "{{json .State}}", container_name],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    if completed.returncode != 0:
        return {
            "available": False,
            "return_code": completed.returncode,
            "error": (completed.stderr or completed.stdout or "docker inspect failed").strip(),
        }
    try:
        value = json.loads((completed.stdout or "{}").strip() or "{}")
    except json.JSONDecodeError as exc:
        return {"available": False, "error": f"invalid docker state JSON: {exc}"}
    if not isinstance(value, dict):
        return {"available": False, "error": "docker state was not an object"}
    value["available"] = True
    return value


def _copy_nikto_report(container_name: str, report_path: Path, preferred_path: str) -> dict[str, Any]:
    """Copy the report, with a filesystem-diff fallback for image variations."""
    candidates = [preferred_path, "/tmp/secops-nikto.csv"]
    diff_entries: list[str] = []
    try:
        diff = subprocess.run(
            ["docker", "diff", container_name],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
        diff_entries = [line.strip() for line in (diff.stdout or "").splitlines() if line.strip()]
        for line in diff_entries:
            path = line[2:].strip() if len(line) > 2 and line[1:2] == " " else ""
            if path.lower().endswith((".csv", ".json", ".xml", ".txt")):
                candidates.append(path)
    except (OSError, subprocess.SubprocessError):
        pass

    attempts: list[dict[str, Any]] = []
    for candidate in dict.fromkeys(value for value in candidates if value):
        try:
            copied = subprocess.run(
                ["docker", "cp", f"{container_name}:{candidate}", str(report_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )
            attempt = {
                "path": candidate,
                "return_code": copied.returncode,
                "stderr": (copied.stderr or "")[-1200:],
            }
            attempts.append(attempt)
            if copied.returncode == 0 and report_path.is_file():
                return {
                    "attempted": True,
                    "copied": True,
                    "path": candidate,
                    "return_code": copied.returncode,
                    "stderr": attempt["stderr"],
                    "bytes": report_path.stat().st_size,
                    "empty": report_path.stat().st_size == 0,
                    "attempts": attempts,
                    "container_diff": diff_entries[-80:],
                }
        except (OSError, subprocess.SubprocessError) as exc:
            attempts.append({"path": candidate, "return_code": None, "stderr": f"{type(exc).__name__}: {exc}"})
    return {
        "attempted": True,
        "copied": False,
        "path": "",
        "return_code": attempts[-1].get("return_code") if attempts else None,
        "stderr": attempts[-1].get("stderr", "") if attempts else "no report candidate",
        "bytes": 0,
        "empty": False,
        "attempts": attempts,
        "container_diff": diff_entries[-80:],
    }



def _run_named_nikto_container(
    command: list[str],
    container_name: str,
    timeout: int,
    report_path: Path,
    preferred_report_path: str = "",
) -> dict[str, Any]:
    """Execute one named Nikto container and preserve auditable diagnostics."""
    create_result: dict[str, Any] = {}
    start_result: dict[str, Any] = {}
    state: dict[str, Any] = {}
    stdout = ""
    stderr = ""
    timed_out = False
    report_copy: dict[str, Any] = {
        "attempted": False,
        "copied": False,
        "path": "",
        "return_code": None,
        "stderr": "",
        "bytes": 0,
        "empty": False,
        "attempts": [],
        "container_diff": [],
        "console_only": not bool(preferred_report_path),
    }
    try:
        created = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            shell=False,
            check=False,
        )
        create_result = {
            "return_code": created.returncode,
            "stdout": (created.stdout or "")[-1200:],
            "stderr": (created.stderr or "")[-2400:],
        }
        if created.returncode != 0:
            return {
                "create_failed": True,
                "create": create_result,
                "start": start_result,
                "state": state,
                "stdout": stdout,
                "stderr": stderr,
                "timed_out": False,
                "report": report_copy,
            }

        try:
            started_process = subprocess.run(
                ["docker", "start", "-a", container_name],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
                check=False,
            )
            stdout = started_process.stdout or ""
            stderr = started_process.stderr or ""
            start_result = {
                "return_code": started_process.returncode,
                "stdout_bytes": len(stdout.encode("utf-8", "replace")),
                "stderr_bytes": len(stderr.encode("utf-8", "replace")),
            }
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            subprocess.run(
                ["docker", "stop", "-t", "2", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
            )
            start_result = {"return_code": None, "timed_out": True}

        try:
            logs = subprocess.run(
                ["docker", "logs", container_name],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )
            stdout = logs.stdout or stdout
            stderr = logs.stderr or stderr
        except (OSError, subprocess.SubprocessError):
            pass

        state = _docker_container_state(container_name)
        if preferred_report_path:
            report_copy = _copy_nikto_report(
                container_name, report_path, preferred_report_path
            )
            report_copy["console_only"] = False
    finally:
        try:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            pass

    return {
        "create_failed": False,
        "create": create_result,
        "start": start_result,
        "state": state,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "report": report_copy,
    }


def _nikto_report_write_failure(log_text: str) -> bool:
    lower = str(log_text or "").lower()
    return bool(
        re.search(r"unable to open ['\"]?[^\r\n]+['\"]? for write", lower)
        or "cannot open output" in lower
        or "could not open output" in lower
    )

def _run_docker_nikto(
    target_url: str,
    cookies: str,
    timeout: int,
    connectivity: dict[str, Any],
    scan_profile: str = "balanced",
) -> dict[str, Any]:
    """Run the official image with structured-output and console fallbacks."""
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
    normalized_profile = _normalize_scan_profile(scan_profile)
    nikto_limit = max(25, timeout - 20)
    primary_name = f"secops-nikto-{uuid.uuid4().hex[:12]}"
    container_report_path = "/tmp/secops-nikto.csv"
    primary_command = _docker_nikto_command(
        primary_name, docker_target, network_args, cookies, nikto_limit,
        normalized_profile, container_report_path, structured_output=True,
    )

    with tempfile.TemporaryDirectory(prefix="nikto-docker-") as temp_dir:
        report_path = Path(temp_dir) / "nikto.csv"
        try:
            primary = _run_named_nikto_container(
                primary_command, primary_name, timeout, report_path,
                container_report_path,
            )
        except OSError as exc:
            return failure(
                "Nikto", target_url,
                f"Cannot start the official Nikto Docker image: {exc}",
                diagnosis="nikto_docker_start_failed",
                connectivity_diagnostics=connectivity,
                command=_redact_nikto_command(primary_command),
            )

        if primary.get("create_failed"):
            created = primary.get("create") or {}
            return failure(
                "Nikto", target_url,
                "Docker could not create the official Nikto container: "
                + str(created.get("stderr") or created.get("stdout") or "unknown Docker error").strip(),
                diagnosis="nikto_docker_create_failed",
                connectivity_diagnostics=connectivity,
                command=_redact_nikto_command(primary_command),
                docker_create=created,
            )

        primary_log = "\n".join(
            part for part in (primary.get("stdout", ""), primary.get("stderr", "")) if part
        )
        active = primary
        active_command = primary_command
        fallback: dict[str, Any] | None = None
        console_fallback_used = False
        compatibility_retry_used = False

        # Defensive compatibility retry for cached/older project files or
        # unusual target translations. Nikto 2.5.0 rejects -nolookup when -h
        # contains a hostname. The normal command builder already avoids this,
        # but this retry prevents the entire assessment from failing if such a
        # command is ever supplied by a legacy path.
        if (
            _nikto_nolookup_name_failure(primary_log)
            and "-nolookup" in primary_command
            and not primary.get("timed_out")
            and time.monotonic() - started < max(20, timeout - 35)
        ):
            remaining = max(35, int(timeout - (time.monotonic() - started)))
            retry_name = f"secops-nikto-{uuid.uuid4().hex[:12]}"
            retry_command = _remove_command_flag(
                _docker_nikto_command(
                    retry_name, docker_target, network_args, cookies,
                    max(25, remaining - 10), normalized_profile,
                    container_report_path, structured_output=True,
                ),
                "-nolookup",
            )
            retry_report = Path(temp_dir) / "nikto-compatibility-retry.csv"
            retry = _run_named_nikto_container(
                retry_command, retry_name, remaining, retry_report,
                container_report_path,
            )
            if not retry.get("create_failed"):
                primary = retry
                primary_command = retry_command
                report_path = retry_report
                primary_log = "\n".join(
                    part for part in (retry.get("stdout", ""), retry.get("stderr", "")) if part
                )
                active = retry
                active_command = retry_command
                compatibility_retry_used = True

        # Some official/cached image revisions run as a user whose home is not
        # writable.  Retry without a report plugin rather than failing before
        # the first HTTP request.  The console path still provides Nikto's full
        # findings and request/completion summary.
        if (
            _nikto_report_write_failure(primary_log)
            and not primary.get("timed_out")
            and time.monotonic() - started < max(20, timeout - 35)
        ):
            remaining = max(35, int(timeout - (time.monotonic() - started)))
            fallback_name = f"secops-nikto-{uuid.uuid4().hex[:12]}"
            fallback_command = _docker_nikto_command(
                fallback_name, docker_target, network_args, cookies,
                max(25, remaining - 10), normalized_profile,
                structured_output=False,
            )
            fallback_report = Path(temp_dir) / "nikto-console-only.csv"
            fallback = _run_named_nikto_container(
                fallback_command, fallback_name, remaining, fallback_report, ""
            )
            if not fallback.get("create_failed"):
                active = fallback
                active_command = fallback_command
                console_fallback_used = True

        stdout = str(active.get("stdout") or "")
        stderr = str(active.get("stderr") or "")
        log_text = "\n".join(part for part in (stdout, stderr) if part)
        state = active.get("state") if isinstance(active.get("state"), dict) else {}
        report_copy = active.get("report") if isinstance(active.get("report"), dict) else {}
        if console_fallback_used:
            report_copy.update({
                "console_only": True,
                "fallback_reason": "structured_report_not_writable",
                "primary_report": primary.get("report", {}),
            })

        csv_findings = _parse_csv(report_path, target_url) if not console_fallback_used else []
        console_findings = _parse_text_findings(log_text, target_url)
        findings = _merge_nikto_findings(csv_findings, console_findings)
        metrics = _nikto_scan_metrics(log_text)
        duration = round(time.monotonic() - started, 3)
        nonexistent_report = Path(tempfile.gettempdir()) / "secops-nikto-no-report-file"
        connection_failure = _connection_runtime_error(log_text, nonexistent_report)
        fatal = _fatal_runtime_error(log_text)
        state_exit_code = state.get("ExitCode") if state.get("available") else None
        state_error = str(state.get("Error") or "").strip() if state.get("available") else ""
        completion_marker = bool(metrics.get("completion_marker"))
        baseline_probe = _baseline_security_signals(target_url, cookies)
        coverage_verified = _nikto_coverage_verified(
            metrics, report_copy, normalized_profile
        )
        zero_result_verified = bool(
            not findings and coverage_verified
        )

        common = {
            "vulnerabilities": findings,
            "duration_seconds": duration,
            "return_code": state_exit_code,
            "authenticated": bool(cookies),
            "execution_mode": (
                "official_docker_console_fallback"
                if console_fallback_used
                else "official_docker_create_start_copy"
            ),
            "docker_image": NIKTO_DOCKER_IMAGE,
            "docker_target": docker_target,
            "docker_target_mapping": mapping_mode,
            "connectivity_diagnostics": connectivity,
            "scanner_log": log_text[-16000:],
            "command": _redact_nikto_command(active_command),
            "primary_command": _redact_nikto_command(primary_command),
            "docker_create": active.get("create", {}),
            "docker_start": active.get("start", {}),
            "docker_state": state,
            "structured_retry": ({
                "used": console_fallback_used,
                "compatibility_retry_used": compatibility_retry_used,
                "primary_state": primary.get("state", {}),
                "primary_log_excerpt": primary_log[-4000:],
                "fallback_create": fallback.get("create", {}) if fallback else {},
            }),
            "scan_completion_marker": completion_marker,
            "completion_inferred_from_exit_code": False,
            "structured_report": report_copy,
            "scan_metrics": metrics,
            "coverage_verified": coverage_verified,
            "csv_findings": len(csv_findings),
            "console_findings": len(console_findings),
            "raw_parsed_findings": len(csv_findings) + len(console_findings),
            "cross_source_duplicates_removed": len(csv_findings) + len(console_findings) - len(findings),
            "nikto_reported_items": int(metrics.get("items_reported") or 0),
            "parser_count_consistent": (
                int(metrics.get("items_reported") or 0) == 0
                or len(findings) == int(metrics.get("items_reported") or 0)
            ),
            "scan_profile": normalized_profile,
            "minimum_clean_requests": NIKTO_SCAN_PROFILES[normalized_profile]["minimum_clean_requests"],
            "zero_result_verified": zero_result_verified,
            "baseline_probe": baseline_probe,
            "safe_tuning": NIKTO_SCAN_PROFILES[normalized_profile]["tuning"],
            "plugins": NIKTO_SCAN_PROFILES[normalized_profile]["plugins_label"],
            "cgi_dirs": NIKTO_SCAN_PROFILES[normalized_profile]["cgi_dirs"],
        }

        if active.get("timed_out"):
            return partial(
                "Nikto", target_url,
                f"Containerized Nikto reached its configured budget. Findings preserved: {len(findings)}.",
                diagnosis="time_limit_reached",
                timed_out=True,
                time_limit_reached=True,
                **common,
            )

        if connection_failure and not findings:
            result = failure(
                "Nikto", target_url,
                f"Containerized Nikto could not reach its translated target: {connection_failure}",
                return_code=state_exit_code,
                stdout=log_text,
                diagnosis="nikto_docker_target_unreachable",
            )
            result.update(common)
            return result

        if state_error and not fatal:
            fatal = state_error
        if fatal:
            result = failure(
                "Nikto", target_url,
                f"Containerized Nikto runtime failed: {fatal}",
                return_code=state_exit_code,
                stdout=log_text,
                diagnosis="nikto_runtime_error",
            )
            result.update(common)
            return result

        if state_exit_code not in (0, 1, None):
            result = failure(
                "Nikto", target_url,
                f"Containerized Nikto exited with code {state_exit_code}.",
                return_code=state_exit_code,
                stdout=stdout,
                stderr=stderr,
                diagnosis="nikto_docker_exit",
            )
            result.update(common)
            return result

        if (
            state_exit_code == 1
            and not findings
            and not metrics.get("normal_summary_present")
            and not report_copy.get("copied")
            and not report_copy.get("console_only")
        ):
            result = failure(
                "Nikto", target_url,
                "Nikto exited immediately without executing a verifiable scan. "
                "Inspect scanner_log and docker_state for the rejected option or plugin.",
                return_code=state_exit_code,
                stdout=log_text,
                diagnosis="nikto_invocation_rejected",
            )
            result.update(common)
            return result

        if not coverage_verified:
            return partial(
                "Nikto", target_url,
                "Nikto did not provide enough request/completion evidence for the selected scan profile. "
                "Findings and diagnostics were preserved, but coverage remains incomplete.",
                diagnosis="nikto_coverage_unverified",
                timed_out=False,
                time_limit_reached=False,
                **common,
            )

        completion_note = (
            "Nikto emitted its completion summary and met the clean-result request threshold."
            if not findings
            else "Nikto completed the selected profile and produced parseable findings."
        )
        if console_fallback_used:
            completion_note += " Structured output was unavailable, so the verified console-summary fallback was used."
        return success(
            "Nikto", target_url,
            f"Containerized Nikto completed. Findings: {len(findings)}; requests={metrics.get('requests', 0)}; "
            f"profile={normalized_profile}. {completion_note}",
            **common,
        )



@mcp.tool()
def run_nikto_scan(
    target_url: str,
    cookies: str = "",
    timeout: int = 180,
    scan_profile: str = "balanced",
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
            scan_profile,
        )

    native = _run_native_nikto_scan(
        target_url,
        cookies,
        timeout,
        scan_profile,
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
            scan_profile,
        )
        docker.setdefault("native_failure", {
            "status": native.get("status"),
            "diagnosis": native.get("diagnosis"),
            "output": native.get("output"),
        })
        return docker

    return native



if __name__ == "__main__":
    run_mcp_http(mcp, "nikto")
