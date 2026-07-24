from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from fastmcp import FastMCP

from utils import ROOT_DIR, failure, success

mcp = FastMCP("Nikto Scanner")

RUNTIME_FILE = Path(ROOT_DIR) / ".secops_runtime.json"
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

            finding_url = (
                uri if uri.startswith(("http://", "https://"))
                else urljoin(target_url.rstrip("/") + "/", uri.lstrip("/"))
            )
            risk = _risk_from_message(message)
            findings.append({
                "alert": "Nikto web-server finding",
                "risk": risk,
                "category": "observation" if risk == "info" else "candidate",
                "confidence": "medium",
                "description": message,
                "impact": (
                    "The identified server behaviour or exposed resource may increase "
                    "the attack surface. Nikto results should be manually verified."
                ),
                "solution": (
                    "Verify the affected resource, remove unnecessary exposed content, "
                    "update vulnerable components, and harden the reported configuration."
                ),
                "url": finding_url or target_url,
                "method": method,
                "reference": reference,
                "evidence": message,
            })
    return findings


def _fatal_runtime_error(log_text: str) -> str:
    lowered = log_text.lower()
    for marker in FATAL_MARKERS:
        if marker in lowered:
            for line in log_text.splitlines():
                if marker in line.lower():
                    return line.strip()
            return marker
    return ""


@mcp.tool()
def run_nikto_scan(
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
            command.extend(["-header", f"Cookie: {cookies}"])

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
        duration = round(time.monotonic() - started, 3)
        fatal = _fatal_runtime_error(log_text)

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