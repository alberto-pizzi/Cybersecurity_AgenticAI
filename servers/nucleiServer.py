from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from utils import partial, read_json_lines, run_process

mcp = FastMCP("Nuclei Scanner")


def _finding(item: dict[str, Any], target_url: str) -> dict[str, Any]:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    references = info.get("reference") or info.get("references") or []
    if isinstance(references, str):
        references = [references]
    extracted = item.get("extracted-results") or item.get("extracted_results") or []
    if isinstance(extracted, str):
        extracted = [extracted]
    evidence_parts = [str(value) for value in extracted[:10]]
    matcher = item.get("matcher-name") or item.get("matcher_name")
    if matcher:
        evidence_parts.append(f"Matcher: {matcher}")
    request = str(item.get("request", ""))[:1200]
    response = str(item.get("response", ""))[:1600]
    if request:
        evidence_parts.append(f"Request:\n{request}")
    if response:
        evidence_parts.append(f"Response excerpt:\n{response}")
    severity = str(info.get("severity", "info")).lower()
    return {
        "alert": info.get("name", item.get("template-id", "Nuclei finding")),
        "risk": severity,
        "category": "observation" if severity == "info" else "vulnerability",
        "description": info.get("description", "Nuclei matched a security template against the target."),
        "impact": info.get("impact", "Review the matched template and affected endpoint to determine the practical impact."),
        "solution": info.get("remediation", "Apply the vendor or application-specific remediation for this template match."),
        "url": item.get("matched-at", item.get("host", target_url)),
        "template_id": item.get("template-id", ""),
        "template_url": item.get("template-url", ""),
        "matcher_name": matcher or "",
        "protocol": item.get("type", "http"),
        "tags": info.get("tags", []),
        "references": references,
        "confidence": "high",
        "evidence": "\n\n".join(evidence_parts),
    }


@mcp.tool()
def run_nuclei_scan(target_url: str, cookies: str = "", timeout: int = 420) -> dict:
    """Run HTTP Nuclei templates with bounded request time and preserve partial findings."""
    with tempfile.TemporaryDirectory(prefix="nuclei-") as temporary_directory:
        output_file = Path(temporary_directory) / "nuclei.jsonl"
        command = [
            "nuclei", "-u", target_url,
            "-severity", "info,low,medium,high,critical",
            "-pt", "http",
            "-jsonl", "-silent", "-nc",
            "-o", str(output_file),
            "-disable-update-check",
            "-timeout", "5",
            "-retries", "1",
            "-mhe", "10",
            "-c", "15",
            "-bs", "10",
            "-rl", "80",
            "-fhr",
            "-etags", "dos,fuzz",
        ]
        if cookies:
            command.extend(["-H", f"Cookie: {cookies}"])

        result = run_process("Nuclei", command, target=target_url, timeout=timeout)
        text = output_file.read_text(encoding="utf-8", errors="replace") if output_file.exists() else result.get("stdout", "")
        findings = [_finding(item, target_url) for item in read_json_lines(text)]

        if result.get("status") == "error" and result.get("diagnosis") == "timeout" and findings:
            return partial(
                "Nuclei",
                target_url,
                f"Nuclei reached the {timeout}-second process limit after producing {len(findings)} findings. Results are incomplete.",
                vulnerabilities=findings,
                diagnosis="timeout_with_partial_results",
                timed_out=True,
                command=result.get("command", []),
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                duration_seconds=result.get("duration_seconds"),
                authenticated=bool(cookies),
            )
        if result.get("status") != "success":
            result["vulnerabilities"] = findings
            result["authenticated"] = bool(cookies)
            if result.get("diagnosis") == "timeout":
                result["output"] = (
                    f"Nuclei did not finish within {timeout} seconds and produced no parseable findings. "
                    "The HTTP template set used per-request timeout=5s, retries=1 and excluded dos/fuzz tags."
                )
            return result

        result.update(
            vulnerabilities=findings,
            output=f"Nuclei HTTP scan completed. Findings: {len(findings)}.",
            authenticated=bool(cookies),
            scan_scope="HTTP templates; dos and fuzz tags excluded",
        )
        return result


if __name__ == "__main__":
    mcp.run(transport="stdio")