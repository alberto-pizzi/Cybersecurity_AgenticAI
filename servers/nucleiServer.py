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


def _as_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    return value if isinstance(value, list) else [value]


def _finding(item: dict[str, Any], target_url: str) -> dict[str, Any]:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    references = [str(value) for value in _as_list(info.get("reference") or info.get("references")) if str(value)]
    extracted = [str(value) for value in _as_list(item.get("extracted-results") or item.get("extracted_results")) if str(value)]
    matcher = str(item.get("matcher-name") or item.get("matcher_name") or "")
    template_id = str(item.get("template-id") or "")
    matched_at = str(item.get("matched-at") or item.get("host") or target_url)
    request = str(item.get("request") or "")[:5000]
    response = str(item.get("response") or "")[:7000]
    severity = str(info.get("severity") or "info").lower()

    evidence_parts = [
        f"Template ID: {template_id}" if template_id else "",
        f"Matcher: {matcher}" if matcher else "",
        *(f"Extracted value: {value}" for value in extracted[:10]),
        f"Request excerpt:\n{request}" if request else "",
        f"Response excerpt:\n{response}" if response else "",
    ]
    evidence = "\n\n".join(part for part in evidence_parts if part)

    description = str(info.get("description") or "").strip()

    cve_ids = [str(value) for value in _as_list(classification.get("cve-id") or classification.get("cve_id")) if str(value)]
    cwe_ids = [str(value) for value in _as_list(classification.get("cwe-id") or classification.get("cwe_id")) if str(value)]
    cvss_score = classification.get("cvss-score") or classification.get("cvss_score") or ""
    cvss_metrics = classification.get("cvss-metrics") or classification.get("cvss_metrics") or ""

    return {
        "alert": str(info.get("name") or template_id or "Nuclei template match"),
        "risk": severity,
        "category": "observation" if severity == "info" else "vulnerability",
        "verification_status": "automated-template-match",
        "confidence": "high",
        "description": description,
        # These fields remain empty when the template does not provide them. The
        # report explicitly records missing scanner metadata instead of inventing it.
        "impact": str(info.get("impact") or "").strip(),
        "solution": str(info.get("remediation") or "").strip(),
        "url": matched_at,
        "method": str(item.get("method") or ""),
        "template_id": template_id,
        "template_url": str(item.get("template-url") or ""),
        "matcher_name": matcher,
        "protocol": str(item.get("type") or "http"),
        "tags": _as_list(info.get("tags")),
        "references": references,
        "cve_ids": cve_ids,
        "cwe_ids": cwe_ids,
        "cvss_score": cvss_score,
        "cvss_metrics": cvss_metrics,
        "classification": classification,
        "extracted_results": extracted,
        "technical_details": (
            f"Nuclei matched template {template_id or 'unknown'} at {matched_at}. "
            f"Protocol={item.get('type') or 'http'}; matcher={matcher or 'unspecified'}; "
            f"severity={severity}."
        ),
        "evidence": evidence,
    }


def _read_items(path: Path, stdout: str = "") -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else stdout
    return read_json_lines(text)


def _deduplicate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        key = (
            str(item.get("template-id") or ""),
            str(item.get("matched-at") or item.get("host") or ""),
            str(item.get("matcher-name") or item.get("matcher_name") or ""),
        )
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _command(
    target_url: str,
    cookies: str,
    output_file: Path,
    *,
    severities: str,
    tags: str,
    compatibility: bool = False,
) -> list[str]:
    command = [
        "nuclei", "-u", target_url,
        "-severity", severities,
        "-tags", tags,
        "-jsonl", "-silent", "-nc",
        "-o", str(output_file),
        "-disable-update-check",
        "-timeout", "4",
        "-retries", "0",
        "-c", "12",
        "-rl", "60",
    ]
    if not compatibility:
        command.extend(["-pt", "http", "-etags", EXCLUDED_TAGS])
    if cookies:
        command.extend(["-H", f"Cookie: {cookies}"])
    return command


def _run_phase(
    target_url: str,
    cookies: str,
    path: Path,
    *,
    name: str,
    severities: str,
    tags: str,
    timeout: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result = run_process(
        "Nuclei",
        _command(target_url, cookies, path, severities=severities, tags=tags),
        target=target_url,
        timeout=timeout,
    )
    combined = "\n".join((str(result.get("stdout", "")), str(result.get("stderr", ""))))
    if result.get("status") == "error" and "unknown flag" in combined.lower():
        path.unlink(missing_ok=True)
        result = run_process(
            "Nuclei",
            _command(
                target_url,
                cookies,
                path,
                severities=severities,
                tags=tags,
                compatibility=True,
            ),
            target=target_url,
            timeout=timeout,
        )
        result["compatibility_mode"] = True

    items = _read_items(path, str(result.get("stdout", "")))
    if result.get("diagnosis") == "timeout":
        result.update(
            status="partial",
            diagnosis="time_limit_reached",
            timed_out=True,
            time_limit_reached=True,
            output=f"Phase '{name}' reached its {timeout}-second budget. Findings preserved: {len(items)}.",
        )
    result.update(
        phase=name,
        phase_timeout_seconds=timeout,
        phase_findings=len(items),
    )
    return result, items


def _run_nuclei_core(
    target_url: str,
    cookies: str = "",
    timeout: int = 180,
    output_file: str = "",
) -> dict[str, Any]:
    """Run high-impact templates first, then exposure and misconfiguration checks."""
    timeout = max(90, min(int(timeout), 300))
    first_budget = max(55, int(timeout * 0.58))
    second_budget = max(35, timeout - first_budget)
    temporary: tempfile.TemporaryDirectory[str] | None = None

    if output_file:
        combined_path = Path(output_file).expanduser().resolve()
        combined_path.parent.mkdir(parents=True, exist_ok=True)
        combined_path.unlink(missing_ok=True)
        work_dir, prefix = combined_path.parent, combined_path.stem
    else:
        temporary = tempfile.TemporaryDirectory(prefix="nuclei-priority-")
        work_dir = Path(temporary.name)
        prefix = "nuclei"
        combined_path = work_dir / "combined.jsonl"

    phase_paths = [
        work_dir / f"{prefix}-high-impact.jsonl",
        work_dir / f"{prefix}-exposure.jsonl",
    ]
    for path in phase_paths:
        path.unlink(missing_ok=True)

    phases: list[dict[str, Any]] = []
    all_items: list[dict[str, Any]] = []
    try:
        definitions = [
            dict(
                name="high_impact",
                severities="medium,high,critical",
                tags=HIGH_IMPACT_TAGS,
                timeout=first_budget,
            ),
            dict(
                name="exposure_misconfiguration",
                severities="low,medium,high,critical",
                tags=EXPOSURE_TAGS,
                timeout=second_budget,
            ),
        ]
        for path, kwargs in zip(phase_paths, definitions):
            phase, items = _run_phase(target_url, cookies, path, **kwargs)
            phases.append(phase)
            all_items.extend(items)

        all_items = _deduplicate(all_items)
        if all_items:
            combined_path.write_text(
                "\n".join(json.dumps(item, ensure_ascii=False, default=str) for item in all_items) + "\n",
                encoding="utf-8",
            )

        findings = [_finding(item, target_url) for item in all_items]
        hard_failures = [phase for phase in phases if phase.get("status") == "error"]
        limited = [
            phase for phase in phases
            if phase.get("status") == "partial" and phase.get("timed_out")
        ]
        summary = [
            {
                "name": phase.get("phase"),
                "status": phase.get("status"),
                "diagnosis": phase.get("diagnosis", ""),
                "duration_seconds": phase.get("duration_seconds"),
                "findings": phase.get("phase_findings", 0),
                "timeout_seconds": phase.get("phase_timeout_seconds"),
                "stderr_excerpt": str(phase.get("stderr", ""))[-1200:],
            }
            for phase in phases
        ]
        common = {
            "vulnerabilities": findings,
            "authenticated": bool(cookies),
            "phases": summary,
            "scan_scope": (
                f"High-impact tags first ({HIGH_IMPACT_TAGS}), then {EXPOSURE_TAGS}; "
                f"excluded {EXCLUDED_TAGS}."
            ),
            "hard_failure": bool(hard_failures),
            "output_file": str(combined_path) if output_file else "",
        }

        if len(hard_failures) == len(phases) and not findings:
            result = failure(
                "Nuclei",
                target_url,
                "Both focused Nuclei phases failed before producing parseable findings.",
                stdout="\n".join(str(phase.get("stdout", "")) for phase in phases),
                stderr="\n".join(str(phase.get("stderr", "")) for phase in phases),
                diagnosis="nuclei_phases_failed",
            )
            result.update(common)
            return result

        if hard_failures or limited:
            # timed_out is supplied exactly once. This fixes the FastMCP ToolError
            # caused by duplicate keyword arguments in the previous version.
            return partial(
                "Nuclei",
                target_url,
                f"Focused Nuclei scan ended with incomplete coverage. Findings preserved: {len(findings)}.",
                diagnosis=(
                    "time_limit_reached"
                    if limited and not hard_failures
                    else "partial_scan"
                ),
                timed_out=bool(limited),
                time_limit_reached=bool(limited),
                **common,
            )

        return success(
            "Nuclei",
            target_url,
            f"Focused Nuclei scan completed. Findings: {len(findings)}.",
            timed_out=False,
            time_limit_reached=False,
            **common,
        )
    finally:
        for path in phase_paths:
            path.unlink(missing_ok=True)
        if temporary is not None:
            temporary.cleanup()


@mcp.tool()
def run_nuclei_scan(
    target_url: str,
    cookies: str = "",
    timeout: int = 180,
    output_file: str = "",
) -> dict:
    return _run_nuclei_core(target_url, cookies, timeout, output_file)


def _once() -> int:
    try:
        arguments = json.loads(os.sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = _run_nuclei_core(**arguments)
    except Exception as exc:
        result = failure(
            "Nuclei",
            "",
            f"One-shot Nuclei execution failed: {type(exc).__name__}: {exc}",
        )
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio")
