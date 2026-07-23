from __future__ import annotations

import json
import queue
import re
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import requests
from fastmcp import FastMCP

from utils import failure, skipped, success

mcp = FastMCP("Interactsh OAST Client")
_DOMAIN_PATTERN = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)


def _drain_stream(stream: Any, destination: queue.Queue[str]) -> None:
    if stream is None:
        return
    try:
        for line in iter(stream.readline, ""):
            if line:
                destination.put(line.rstrip("\r\n"))
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _read_json_lines(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _first_payload(path: Path, buffered_lines: list[str]) -> str:
    candidates: list[str] = []
    if path.is_file():
        candidates.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
    candidates.extend(buffered_lines)
    for candidate in candidates:
        match = _DOMAIN_PATTERN.search(candidate)
        if match:
            return match.group(0)
    return ""


@mcp.tool()
def run_interactsh_client(
    target_url: str = "",
    injection_url: str = "",
    cookies: str = "",
    timeout: int = 90,
) -> dict:
    """
    Generate an Interactsh payload, inject it into an explicit URL and wait for OAST callbacks.

    ``injection_url`` must contain the literal ``FUZZ`` placeholder. The server only
    claims SSRF/XXE/RCE evidence when Interactsh returns an actual interaction event.
    """
    if not injection_url:
        return skipped(
            "Interactsh",
            target_url,
            "No OAST injection URL was supplied. Use --interactsh-injection-url with FUZZ.",
        )
    if "FUZZ" not in injection_url:
        return skipped(
            "Interactsh",
            target_url,
            "The OAST injection URL must contain the literal FUZZ placeholder.",
        )
    if timeout < 20:
        return failure("Interactsh", target_url, "timeout must be at least 20 seconds.")

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="interactsh-") as temporary_directory:
        temporary = Path(temporary_directory)
        payload_file = temporary / "payloads.txt"
        interaction_file = temporary / "interactions.jsonl"
        command = [
            "interactsh-client",
            "-json",
            "-v",
            "-duc",
            "-ps",
            "-psf", str(payload_file),
            "-o", str(interaction_file),
        ]

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as exc:
            return failure("Interactsh", target_url, f"Cannot start interactsh-client: {type(exc).__name__}: {exc}")

        stdout_queue: queue.Queue[str] = queue.Queue()
        stderr_queue: queue.Queue[str] = queue.Queue()
        stdout_thread = threading.Thread(target=_drain_stream, args=(process.stdout, stdout_queue), daemon=True)
        stderr_thread = threading.Thread(target=_drain_stream, args=(process.stderr, stderr_queue), daemon=True)
        stdout_thread.start()
        stderr_thread.start()

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        payload = ""
        payload_deadline = time.monotonic() + min(25, max(8, timeout // 3))

        try:
            while time.monotonic() < payload_deadline and not payload:
                while not stdout_queue.empty():
                    stdout_lines.append(stdout_queue.get_nowait())
                while not stderr_queue.empty():
                    stderr_lines.append(stderr_queue.get_nowait())
                payload = _first_payload(payload_file, stdout_lines)
                if payload:
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.25)

            if not payload:
                details = "\n".join([*stdout_lines[-20:], *stderr_lines[-20:]])
                return failure(
                    "Interactsh",
                    target_url,
                    "Interactsh did not generate a payload domain. " + (details or "No process output."),
                )

            injected_url = injection_url.replace("FUZZ", payload)
            session = requests.Session()
            if cookies:
                session.headers["Cookie"] = cookies
            try:
                injection_response = session.get(
                    injected_url,
                    timeout=(5, 20),
                    allow_redirects=True,
                )
                injection_status = injection_response.status_code
            except requests.RequestException as exc:
                return failure(
                    "Interactsh",
                    target_url,
                    f"Payload was generated but the injection request failed: {type(exc).__name__}: {exc}",
                )

            interactions: list[dict[str, Any]] = []
            deadline = started + timeout
            while time.monotonic() < deadline:
                interactions = _read_json_lines(interaction_file)
                if interactions:
                    break
                if process.poll() is not None and not interaction_file.exists():
                    break
                time.sleep(1.0)

            findings = []
            for event in interactions:
                protocol = str(event.get("protocol", event.get("type", "unknown")))
                remote = str(event.get("remote-address", event.get("remote_address", "")))
                raw_request = str(event.get("raw-request", event.get("raw_request", "")))
                findings.append({
                    "alert": "Out-of-band interaction observed",
                    "risk": "high",
                    "description": f"Interactsh observed a {protocol} callback after injecting an OAST payload.",
                    "solution": "Validate outbound destinations, disable unsafe URL/entity resolution and restrict egress.",
                    "url": injected_url,
                    "evidence": raw_request[:2000] or json.dumps(event, ensure_ascii=False)[:2000],
                    "protocol": protocol,
                    "remote_address": remote,
                })

            return success(
                "Interactsh",
                target_url,
                f"OAST test completed. Interaction events: {len(interactions)}",
                vulnerabilities=findings,
                generated_domains=[payload],
                injection_url=injected_url,
                injection_status=injection_status,
                interactions=interactions,
                interaction_observed=bool(interactions),
                duration_seconds=round(time.monotonic() - started, 3),
            )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)