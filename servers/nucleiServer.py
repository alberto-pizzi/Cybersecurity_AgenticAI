from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from utils import failure, partial, read_json_lines, run_process, success

mcp = FastMCP("Nuclei Scanner")

EXCLUDED_TAGS = "dos,fuzz,tech,osint,creds-stuffing,token-spray"
HIGH_IMPACT_TAGS = "rce,sqli,auth-bypass,lfi,rfi,ssrf,xxe,deserialization,default-login"
EXPOSURE_TAGS = "misconfig,exposure,default-login"


def _finding(item: dict[str, Any], target_url: str) -> dict[str, Any]:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    references = info.get("reference") or info.get("references") or []
    if isinstance(references, str): references = [references]
    extracted = item.get("extracted-results") or item.get("extracted_results") or []
    if isinstance(extracted, str): extracted = [extracted]
    evidence = [str(value) for value in extracted[:10]]
    matcher = item.get("matcher-name") or item.get("matcher_name") or ""
    if matcher: evidence.append(f"Matcher: {matcher}")
    request, response = str(item.get("request", ""))[:1200], str(item.get("response", ""))[:1600]
    if request: evidence.append(f"Request:\n{request}")
    if response: evidence.append(f"Response excerpt:\n{response}")
    severity = str(info.get("severity", "info")).lower()
    return {
        "alert": info.get("name", item.get("template-id", "Nuclei finding")),
        "risk": severity, "category": "observation" if severity == "info" else "vulnerability",
        "confidence": "high", "description": info.get("description", "Nuclei matched a security template."),
        "impact": info.get("impact", "Review the affected endpoint and matched template."),
        "solution": info.get("remediation", "Apply the remediation associated with this template."),
        "url": item.get("matched-at", item.get("host", target_url)),
        "template_id": item.get("template-id", ""), "template_url": item.get("template-url", ""),
        "matcher_name": matcher, "protocol": item.get("type", "http"),
        "tags": info.get("tags", []), "references": references,
        "evidence": "\n\n".join(evidence),
    }


def _read_items(path: Path, stdout: str = "") -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else stdout
    return read_json_lines(text)


def _deduplicate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique, seen = [], set()
    for item in items:
        key = (str(item.get("template-id", "")), str(item.get("matched-at", item.get("host", ""))), str(item.get("matcher-name", item.get("matcher_name", ""))))
        if key not in seen:
            seen.add(key); unique.append(item)
    return unique


def _command(target_url: str, cookies: str, output_file: Path, *, severities: str, tags: str, compatibility: bool=False) -> list[str]:
    command = [
        "nuclei", "-u", target_url, "-severity", severities,
        "-tags", tags, "-jsonl", "-silent", "-nc", "-o", str(output_file),
        "-disable-update-check", "-timeout", "4", "-retries", "0", "-c", "12", "-rl", "60",
    ]
    if not compatibility: command.extend(["-pt", "http", "-etags", EXCLUDED_TAGS])
    if cookies: command.extend(["-H", f"Cookie: {cookies}"])
    return command


def _run_phase(target_url: str, cookies: str, path: Path, *, name: str, severities: str, tags: str, timeout: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result = run_process("Nuclei", _command(target_url, cookies, path, severities=severities, tags=tags), target=target_url, timeout=timeout)
    combined = "\n".join((str(result.get("stdout", "")), str(result.get("stderr", ""))))
    if result.get("status") == "error" and "unknown flag" in combined.lower():
        path.unlink(missing_ok=True)
        result = run_process("Nuclei", _command(target_url, cookies, path, severities=severities, tags=tags, compatibility=True), target=target_url, timeout=timeout)
        result["compatibility_mode"] = True
    items = _read_items(path, str(result.get("stdout", "")))
    if result.get("diagnosis") == "timeout":
        result.update(status="partial", diagnosis="time_limit_reached", timed_out=True,
                      output=f"Phase '{name}' reached its {timeout}-second budget. Findings preserved: {len(items)}.")
    result.update(phase=name, phase_timeout_seconds=timeout, phase_findings=len(items))
    return result, items


def _run_nuclei_core(target_url: str, cookies: str="", timeout: int=180, output_file: str="") -> dict[str, Any]:
    """Run high-impact templates first, then focused exposure and misconfiguration checks."""
    timeout = max(90, min(int(timeout), 300))
    first_budget = max(55, int(timeout * 0.58))
    second_budget = max(35, timeout - first_budget)
    temporary = None
    if output_file:
        combined_path = Path(output_file).expanduser().resolve(); combined_path.parent.mkdir(parents=True, exist_ok=True); combined_path.unlink(missing_ok=True)
        work_dir, prefix = combined_path.parent, combined_path.stem
    else:
        temporary = tempfile.TemporaryDirectory(prefix="nuclei-priority-"); work_dir = Path(temporary.name); prefix = "nuclei"; combined_path = work_dir/"combined.jsonl"
    phase_paths = [work_dir/f"{prefix}-high-impact.jsonl", work_dir/f"{prefix}-exposure.jsonl"]
    for path in phase_paths: path.unlink(missing_ok=True)
    phases, all_items = [], []
    try:
        for path, kwargs in zip(phase_paths, [
            dict(name="high_impact", severities="medium,high,critical", tags=HIGH_IMPACT_TAGS, timeout=first_budget),
            dict(name="exposure_misconfiguration", severities="low,medium,high,critical", tags=EXPOSURE_TAGS, timeout=second_budget),
        ]):
            phase, items = _run_phase(target_url, cookies, path, **kwargs); phases.append(phase); all_items.extend(items)
        all_items = _deduplicate(all_items)
        if all_items:
            combined_path.write_text("\n".join(json.dumps(item, ensure_ascii=False, default=str) for item in all_items)+"\n", encoding="utf-8")
        findings = [_finding(item, target_url) for item in all_items]
        hard_failures = [p for p in phases if p.get("status") == "error"]
        limited = [p for p in phases if p.get("status") == "partial" and p.get("timed_out")]
        summary = [{"name":p.get("phase"),"status":p.get("status"),"diagnosis":p.get("diagnosis", ""),"duration_seconds":p.get("duration_seconds"),"findings":p.get("phase_findings",0),"timeout_seconds":p.get("phase_timeout_seconds")} for p in phases]
        common = {"vulnerabilities": findings, "authenticated": bool(cookies), "phases": summary,
                  "scan_scope": f"High-impact tags first ({HIGH_IMPACT_TAGS}), then {EXPOSURE_TAGS}; excluded {EXCLUDED_TAGS}.",
                  "timed_out": bool(limited), "hard_failure": bool(hard_failures),
                  "output_file": str(combined_path) if output_file else ""}
        if len(hard_failures) == len(phases) and not findings:
            return failure("Nuclei", target_url, "Both focused Nuclei phases failed before producing parseable findings.", stdout="\n".join(str(p.get("stdout", "")) for p in phases), stderr="\n".join(str(p.get("stderr", "")) for p in phases)) | common
        if hard_failures or limited:
            return partial("Nuclei", target_url, f"Focused Nuclei scan ended with incomplete coverage. Findings preserved: {len(findings)}.", diagnosis="time_limit_reached" if limited and not hard_failures else "partial_scan", timed_out=bool(limited), **common)
        return success("Nuclei", target_url, f"Focused Nuclei scan completed. Findings: {len(findings)}.", **common)
    finally:
        for path in phase_paths: path.unlink(missing_ok=True)
        if temporary is not None: temporary.cleanup()


@mcp.tool()
def run_nuclei_scan(target_url: str, cookies: str="", timeout: int=180, output_file: str="") -> dict:
    return _run_nuclei_core(target_url, cookies, timeout, output_file)


def _once() -> int:
    try:
        arguments = json.loads(os.sys.stdin.read() or "{}")
        if not isinstance(arguments, dict): raise ValueError("Expected a JSON object on stdin.")
        result = _run_nuclei_core(**arguments)
    except Exception as exc:
        result = failure("Nuclei", "", f"One-shot Nuclei execution failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str)); return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False); parser.add_argument("--once", action="store_true"); args,_ = parser.parse_known_args()
    if args.once: raise SystemExit(_once())
    mcp.run(transport="stdio")
