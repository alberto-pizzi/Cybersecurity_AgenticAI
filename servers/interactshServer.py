from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

import requests
from fastmcp import FastMCP

from utils import failure, partial, skipped, success

mcp = FastMCP("Interactsh OAST Client")


def _read_lines(path: Path) -> list[str]:
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    except OSError:
        return []


def _stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


@mcp.tool()
def run_interactsh_client(
    target_url: str = "",
    injection_url: str = "",
    cookies: str = "",
    timeout: int = 90,
) -> dict:
    """Run one explicit OAST check using an injection URL containing ``FUZZ``."""
    if not injection_url:
        return skipped("Interactsh", target_url, "No OAST injection URL was supplied.")
    if "FUZZ" not in injection_url:
        return skipped("Interactsh", target_url, "The injection URL must contain the literal FUZZ placeholder.")

    executable = shutil.which("interactsh-client")
    if not executable:
        return failure("Interactsh", target_url, "interactsh-client was not found in PATH.")

    timeout = max(20, min(int(timeout), 300))
    with tempfile.TemporaryDirectory(prefix="interactsh-") as temp_dir:
        temp = Path(temp_dir)
        payload_file = temp / "payload.txt"
        event_file = temp / "events.jsonl"
        command = [
            executable,
            "-n", "1",
            "-pi", "1",
            "-json",
            "-v",
            "-duc",
            "-ps",
            "-psf", str(payload_file),
            "-o", str(event_file),
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        started = time.monotonic()
        try:
            payload = ""
            while time.monotonic() - started < min(25, timeout / 2):
                lines = _read_lines(payload_file)
                if lines:
                    payload = lines[0]
                    break
                if process.poll() is not None:
                    stdout, stderr = process.communicate(timeout=2)
                    return failure(
                        "Interactsh",
                        target_url,
                        f"interactsh-client exited before producing a payload. {stderr or stdout}".strip(),
                    )
                time.sleep(0.25)

            if not payload:
                return partial("Interactsh", target_url, "Interactsh reached its payload-generation time budget.", diagnosis="time_limit_reached", timed_out=True, vulnerabilities=[])

            injected_url = injection_url.replace("FUZZ", quote(payload, safe=""))
            headers = {"User-Agent": "SecOpsAgent-University/1.1"}
            if cookies:
                headers["Cookie"] = cookies
            try:
                response = requests.get(injected_url, headers=headers, timeout=(5, 20), allow_redirects=True)
                injection_status = response.status_code
            except requests.Timeout as exc:
                return partial("Interactsh", target_url, f"Injection request reached its time budget: {exc}", diagnosis="time_limit_reached", timed_out=True, vulnerabilities=[])
            except requests.RequestException as exc:
                return failure("Interactsh", target_url, f"Injection request failed: {exc}")

            events: list[dict] = []
            deadline = started + timeout
            while time.monotonic() < deadline:
                for line in _read_lines(event_file):
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(item, dict) and item not in events:
                        events.append(item)
                if events:
                    break
                if process.poll() is not None:
                    break
                time.sleep(1)

            findings = []
            if events:
                protocols = sorted({str(event.get("protocol") or event.get("type") or "unknown") for event in events if isinstance(event, dict)})
                findings.append({
                    "alert": "Out-of-band interaction confirmed",
                    "risk": "high",
                    "category": "vulnerability",
                    "verification_status": "callback-confirmed",
                    "confidence": "high",
                    "description": (
                        "The supplied injection point caused the target-side processing path to generate "
                        f"an out-of-band callback. Observed interaction protocols: {', '.join(protocols)}."
                    ),
                    "impact": (
                        "The callback proves that attacker-controlled input can cause an external interaction. "
                        "Depending on the tested insertion point and protocol, this may represent SSRF, blind "
                        "command injection, XML external entity processing, or another server-side interaction primitive."
                    ),
                    "solution": (
                        "Trace the exact code path that consumed the payload, restrict outbound network access, "
                        "use allow-lists for remote destinations, disable unsafe parsers or shell execution, and "
                        "add a regression test for the confirmed insertion point."
                    ),
                    "url": injected_url,
                    "method": "GET",
                    "technical_details": f"Interactsh payload={payload}; callbacks={len(events)}; protocols={protocols}.",
                    "evidence": json.dumps(events[:10], indent=2, ensure_ascii=False, default=str),
                })

            return success(
                "Interactsh",
                target_url,
                f"OAST request completed. HTTP {injection_status}; callbacks: {len(events)}.",
                vulnerabilities=findings,
                payload=payload,
                injected_url=injected_url,
                interactions=events[:50],
            )
        finally:
            _stop(process)


if __name__ == "__main__":
    mcp.run(transport="stdio")