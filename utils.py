from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

ROOT_DIR = Path(__file__).resolve().parent
SERVERS_DIR = ROOT_DIR / "servers"
REPORTS_DIR = ROOT_DIR / "reports"
WORDLISTS_DIR = ROOT_DIR / "wordlists"
LOCAL_BIN = Path.home() / ".local" / "bin"


def setup_path() -> None:
    """Adds the project-local executable directory to PATH once."""
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    current = os.environ.get("PATH", "")
    parts = current.split(os.pathsep) if current else []
    if str(LOCAL_BIN) not in parts:
        os.environ["PATH"] = str(LOCAL_BIN) + os.pathsep + current


def find_executable(name: str) -> str | None:
    """Returns an executable path on Windows or Unix, or None when missing."""
    setup_path()
    return shutil.which(name) or shutil.which(f"{name}.bat") or shutil.which(f"{name}.exe")


def normalize_url(url: str) -> str:
    """Normalizes a base URL without changing its path."""
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("The target must be an absolute HTTP/HTTPS URL.")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS targets are supported.")
    return url.rstrip("/")


def same_origin(left: str, right: str) -> bool:
    """Prevents the crawler from leaving the selected target."""
    a = urlparse(left)
    b = urlparse(right)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def absolute_url(base: str, candidate: str) -> str:
    """Resolves a relative link and removes its fragment."""
    parsed = urlparse(urljoin(base, candidate))
    return parsed._replace(fragment="").geturl()


def make_result(
    tool: str,
    status: str,
    target: str = "",
    output: str = "",
    vulnerabilities: list[dict[str, Any]] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Creates the common result format used by every MCP tool."""
    result: dict[str, Any] = {
        "tool": tool,
        "status": status,
        "target": target,
        "output": output,
        "vulnerabilities": vulnerabilities or [],
    }
    result.update(extra)
    return result


def success(tool: str, target: str = "", output: str = "", **extra: Any) -> dict[str, Any]:
    return make_result(tool, "success", target, output, **extra)


def skipped(tool: str, target: str, reason: str) -> dict[str, Any]:
    return make_result(tool, "skipped", target, reason)


def failure(
    tool: str,
    target: str,
    message: str,
    *,
    return_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
) -> dict[str, Any]:
    return make_result(
        tool,
        "error",
        target,
        message,
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
    )


def run_process(
    tool: str,
    command: list[str],
    *,
    target: str,
    timeout: int = 180,
    accepted_codes: Iterable[int] = (0,),
    cwd: Path | None = None,
) -> dict[str, Any]:
    """
    Executes a CLI safely.

    It never reports success when the executable is absent, times out, or exits
    with an unexpected return code.
    """
    executable = find_executable(command[0])
    if not executable:
        return failure(tool, target, f"Executable not found: {command[0]}")

    command = [executable, *command[1:]]
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return failure(
            tool, target, f"Timeout after {timeout} seconds",
            stdout=stdout, stderr=stderr,
        )
    except OSError as exc:
        return failure(tool, target, f"Cannot start process: {exc}")

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    combined = "\n".join(value for value in (stdout, stderr) if value).strip()

    if completed.returncode not in set(accepted_codes):
        return failure(
            tool,
            target,
            f"Process exited with code {completed.returncode}",
            return_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    return success(
        tool,
        target,
        combined or "Command completed without textual output.",
        return_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        command=command,
    )


def read_json_lines(text: str) -> list[dict[str, Any]]:
    """Parses JSONL while safely ignoring non-JSON diagnostic lines."""
    rows: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows
