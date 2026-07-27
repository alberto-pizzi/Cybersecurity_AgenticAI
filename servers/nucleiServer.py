from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from fastmcp import FastMCP

from utils import failure, partial, read_json_lines, run_process, success

mcp = FastMCP("Nuclei Scanner")

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# The official template repository contains some deliberately aggressive checks.
# They remain excluded from automatic pipeline scans; the full safe HTTP pack is
# still available in deep mode.
EXCLUDED_TAGS = "dos,fuzz,creds-stuffing,token-spray"
DAST_EXCLUDED_TAGS = "dos,creds-stuffing,token-spray"
HIGH_IMPACT_TAGS = (
    "rce,sqli,xss,auth-bypass,lfi,rfi,ssrf,xxe,deserialization,"
    "cmdi,code-injection,ssti,path-traversal,default-login,cve"
)
EXPOSURE_TAGS = (
    "misconfig,exposure,default-login,panel,backup,config,debug,api,"
    "swagger,graphql,token,secret,files,open-redirect,takeover"
)
MIN_EXPECTED_TEMPLATE_COUNT = 1000


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

    cve_ids = [str(value) for value in _as_list(classification.get("cve-id") or classification.get("cve_id")) if str(value)]
    cwe_ids = [str(value) for value in _as_list(classification.get("cwe-id") or classification.get("cwe_id")) if str(value)]

    return {
        "alert": str(info.get("name") or template_id or "Nuclei template match"),
        "risk": severity,
        "category": "observation" if severity == "info" else "vulnerability",
        "verification_status": "automated-template-match",
        "confidence": "high",
        "description": str(info.get("description") or "").strip(),
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
        "cvss_score": classification.get("cvss-score") or classification.get("cvss_score") or "",
        "cvss_metrics": classification.get("cvss-metrics") or classification.get("cvss_metrics") or "",
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
    target_list: Path | None = None,
    *,
    severities: str,
    tags: str = "",
    compatibility: bool = False,
    automatic_scan: bool = False,
    dast: bool = False,
    concurrency: int = 20,
    rate_limit: int = 80,
    request_timeout: int = 5,
    retries: int = 1,
    template_dir: str = "",
) -> list[str]:
    command = [
        "nuclei",
        *(["-l", str(target_list)] if target_list else ["-u", target_url]),
        "-severity", severities,
        "-jsonl", "-silent", "-nc",
        "-o", str(output_file),
        "-disable-update-check",
        "-timeout", str(max(2, request_timeout)),
        "-retries", str(max(0, retries)),
        "-c", str(max(1, concurrency)),
        "-rl", str(max(1, rate_limit)),
    ]
    if template_dir:
        command.extend(["-t", template_dir])
    if tags:
        command.extend(["-tags", tags])
    if automatic_scan:
        command.append("-as")
    if dast:
        command.append("-dast")
    if not compatibility:
        excluded = DAST_EXCLUDED_TAGS if dast else EXCLUDED_TAGS
        command.extend(["-pt", "http", "-etags", excluded, "-fhr"])
    if cookies:
        command.extend(["-H", f"Cookie: {cookies}"])
    return command



def _runtime_template_directories() -> list[Path]:
    configured_runtime = os.environ.get("SECOPS_RUNTIME_CONFIG", "").strip()
    runtime_path = (
        Path(configured_runtime).expanduser()
        if configured_runtime
        else PROJECT_ROOT / ".secops_runtime.json"
    )
    try:
        payload = json.loads(runtime_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    state = payload.get("nuclei_templates", {})
    if not isinstance(state, dict):
        return []
    values: list[str] = []
    for key in ("directory", "template_directory", "path"):
        value = str(state.get(key) or "").strip()
        if value:
            values.append(value)
    for value in state.get("directories", []) if isinstance(state.get("directories"), list) else []:
        if str(value).strip():
            values.append(str(value))
    for item in state.get("filesystem_candidates", []) if isinstance(state.get("filesystem_candidates"), list) else []:
        if isinstance(item, dict) and str(item.get("directory") or "").strip():
            values.append(str(item["directory"]))
    executable = str((payload.get("executables") or {}).get("nuclei") or "").strip()
    if executable:
        parent = Path(executable).expanduser().parent
        values.extend((str(parent / "nuclei-templates"), str(parent.parent / "nuclei-templates")))
    return [Path(value).expanduser().resolve() for value in values]


def _config_template_directories() -> list[Path]:
    home = Path.home()
    appdata = os.environ.get("APPDATA", "").strip()
    localappdata = os.environ.get("LOCALAPPDATA", "").strip()
    config_files = [
        home / ".config" / "nuclei" / "config.yaml",
        home / ".config" / "nuclei" / "config.yml",
        Path(appdata) / "nuclei" / "config.yaml" if appdata else None,
        Path(localappdata) / "nuclei" / "config.yaml" if localappdata else None,
    ]
    values: list[Path] = []
    pattern = re.compile(
        r"^\s*(?:templates-directory|templates_directory|templates-dir)\s*:\s*[\"']?(.+?)[\"']?\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    for config in config_files:
        if config is None or not config.is_file():
            continue
        try:
            content = config.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in pattern.finditer(content):
            raw = os.path.expandvars(match.group(1).strip())
            candidate = Path(raw).expanduser()
            if not candidate.is_absolute():
                candidate = config.parent / candidate
            values.append(candidate.resolve())
    return values


def _template_directories() -> list[Path]:
    home = Path.home()
    configured = os.environ.get("NUCLEI_TEMPLATES_DIR", "").strip()
    appdata = os.environ.get("APPDATA", "").strip()
    localappdata = os.environ.get("LOCALAPPDATA", "").strip()
    programdata = os.environ.get("PROGRAMDATA", "").strip()
    candidates = [
        Path(configured).expanduser() if configured else None,
        *_runtime_template_directories(),
        *_config_template_directories(),
        PROJECT_ROOT / "tools" / "nuclei-templates",
        home / "nuclei-templates",
        home / ".local" / "nuclei-templates",
        home / ".config" / "nuclei" / "templates",
        home / "AppData" / "Roaming" / "nuclei" / "templates",
        Path(appdata) / "nuclei-templates" if appdata else None,
        Path(appdata) / "nuclei" / "templates" if appdata else None,
        Path(localappdata) / "nuclei-templates" if localappdata else None,
        Path(localappdata) / "nuclei" / "templates" if localappdata else None,
        Path(programdata) / "nuclei-templates" if programdata else None,
    ]
    return list(dict.fromkeys(path.resolve() for path in candidates if path is not None))


def _filesystem_template_inventory() -> dict[str, Any]:
    inventories: list[dict[str, Any]] = []
    for directory in _template_directories():
        if not directory.is_dir():
            continue
        count = sum(
            1
            for path in directory.rglob("*")
            if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}
        )
        inventories.append({"directory": str(directory), "count": count})
    best = max(inventories, key=lambda item: item["count"], default={"directory": "", "count": 0})
    return {"count": int(best["count"]), "directory": str(best["directory"]), "candidates": inventories}


def _template_inventory() -> dict[str, Any]:
    # The CLI listing can stall on Windows even when the official repository is
    # present. Filesystem inventory is therefore authoritative fallback and the
    # selected directory is passed explicitly to every scan phase.
    filesystem = _filesystem_template_inventory()
    result = run_process(
        "Nuclei template inventory",
        ["nuclei", "-tl", "-silent", "-nc", "-disable-update-check"],
        target="templates",
        timeout=45,
    )
    lines = {
        line.strip()
        for line in str(result.get("stdout", "")).splitlines()
        if line.strip() and not line.lstrip().startswith("[")
    }
    cli_count = len(lines)
    count = max(cli_count, int(filesystem.get("count", 0)))
    return {
        "count": count,
        "cli_count": cli_count,
        "filesystem_count": int(filesystem.get("count", 0)),
        "directory": str(filesystem.get("directory", "")),
        "filesystem_candidates": filesystem.get("candidates", []),
        "sufficient": count >= MIN_EXPECTED_TEMPLATE_COUNT,
        "minimum_expected": MIN_EXPECTED_TEMPLATE_COUNT,
        "status": result.get("status"),
        "diagnosis": result.get("diagnosis", ""),
        "stderr_excerpt": str(result.get("stderr", ""))[-1200:],
    }


def _attempt_template_refresh() -> dict[str, Any]:
    """Ask the installed Nuclei engine to restore its official template pack."""
    result = run_process(
        "Nuclei template refresh",
        ["nuclei", "-update-templates"],
        target="templates",
        timeout=360,
    )
    combined = "\n".join((str(result.get("stdout", "")), str(result.get("stderr", ""))))
    if result.get("status") == "error" and "unknown flag" in combined.lower():
        result = run_process(
            "Nuclei template refresh",
            ["nuclei", "-ut"],
            target="templates",
            timeout=360,
        )
    return result



def _run_phase(
    target_url: str,
    cookies: str,
    path: Path,
    *,
    name: str,
    severities: str,
    tags: str,
    timeout: int,
    target_list: Path | None = None,
    automatic_scan: bool = False,
    dast: bool = False,
    concurrency: int = 20,
    rate_limit: int = 80,
    request_timeout: int = 5,
    retries: int = 1,
    template_dir: str = "",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    def execute(*, compatibility: bool) -> dict[str, Any]:
        return run_process(
            "Nuclei",
            _command(
                target_url,
                cookies,
                path,
                target_list,
                severities=severities,
                tags=tags,
                compatibility=compatibility,
                automatic_scan=automatic_scan if not compatibility else False,
                dast=dast,
                concurrency=concurrency,
                rate_limit=rate_limit,
                request_timeout=request_timeout,
                retries=retries,
                template_dir=template_dir,
            ),
            target=target_url,
            timeout=timeout,
        )

    result = execute(compatibility=False)
    combined = "\n".join((str(result.get("stdout", "")), str(result.get("stderr", ""))))
    if result.get("status") == "error" and "unknown flag" in combined.lower():
        path.unlink(missing_ok=True)
        result = execute(compatibility=True)
        result["compatibility_mode"] = True
        retry_text = "\n".join((str(result.get("stdout", "")), str(result.get("stderr", ""))))
        if dast and result.get("status") == "error" and "unknown flag" in retry_text.lower():
            result["diagnosis"] = "nuclei_dast_unsupported"
            result["output"] = (
                "The installed Nuclei executable does not accept the DAST flag. "
                "Update Nuclei through initScript.py; non-DAST phases can still continue."
            )

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
        phase_tags=tags,
        automatic_scan=automatic_scan,
        dast=dast,
    )
    return result, items




def _phase_definitions(
    scan_profile: str,
    total_timeout: int,
    has_dast_targets: bool = False,
) -> list[dict[str, Any]]:
    usable = max(24, total_timeout - 12)

    dast_phase = {
        "name": "parameterized_dast",
        "severities": "medium,high,critical",
        "tags": "",
        "dast": True,
    }
    high_phase = {
        "name": "critical_high_value",
        "severities": "medium,high,critical",
        "tags": HIGH_IMPACT_TAGS,
    }
    exposure_phase = {
        "name": "exposures_and_misconfigurations",
        "severities": "info,low,medium,high,critical",
        "tags": EXPOSURE_TAGS,
    }
    automatic_phase = {
        "name": "technology_automatic_scan",
        "severities": "low,medium,high,critical",
        "tags": "",
        "automatic_scan": True,
    }
    broad_phase = {
        "name": "broad_safe_http_templates",
        "severities": "low,medium,high,critical",
        "tags": "",
    }

    if scan_profile == "fast":
        phases = [dast_phase] if has_dast_targets else [high_phase]
        weights = [1.0]
    elif scan_profile == "balanced":
        phases = ([dast_phase] if has_dast_targets else []) + [high_phase, exposure_phase, automatic_phase]
        weights = [0.36, 0.29, 0.21, 0.14] if has_dast_targets else [0.46, 0.34, 0.20]
    else:
        phases = ([dast_phase] if has_dast_targets else []) + [high_phase, exposure_phase, automatic_phase, broad_phase]
        weights = [0.32, 0.24, 0.17, 0.12, 0.15] if has_dast_targets else [0.31, 0.24, 0.18, 0.27]

    # Do not create more processes than the total budget can meaningfully start.
    # This keeps manually requested low timeouts bounded instead of silently
    # allocating more seconds than the caller supplied.
    max_phases = max(1, usable // 12)
    phases = phases[:max_phases]
    weights = weights[:len(phases)]
    weight_total = sum(weights) or 1.0
    normalized = [value / weight_total for value in weights]

    budgets: list[int] = []
    remaining = usable
    for index, weight in enumerate(normalized):
        if index == len(normalized) - 1:
            value = remaining
        else:
            future = len(normalized) - index - 1
            value = max(8, int(round(usable * weight)))
            value = min(value, remaining - 8 * future)
        budgets.append(value)
        remaining -= value

    definitions: list[dict[str, Any]] = []
    for phase, budget in zip(phases, budgets):
        item = dict(phase)
        item["timeout"] = max(8, budget)
        definitions.append(item)
    return definitions




_STATE_CHANGING_KEYS = {
    "action", "delete", "remove", "reset", "logout", "signout", "install",
    "create", "drop", "password", "password_new", "password_conf", "confirm",
}
_STATE_CHANGING_PATH_WORDS = ("logout", "signout", "setup", "install", "reset", "delete", "remove")


def _same_origin_url(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    other = urlparse(candidate)
    return (
        base.scheme.lower(), base.hostname or "", base.port or (443 if base.scheme == "https" else 80)
    ) == (
        other.scheme.lower(), other.hostname or "", other.port or (443 if other.scheme == "https" else 80)
    )


def _dast_target_urls(
    target_url: str,
    request_cases: list[dict[str, Any]] | None,
    limit: int = 20,
) -> list[str]:
    """Select safe, same-origin parameterized GET URLs for Nuclei DAST templates."""
    selected: list[str] = []
    for case in request_cases or []:
        if not isinstance(case, dict) or str(case.get("method") or "GET").upper() != "GET":
            continue
        candidate = str(case.get("url") or case.get("target_url") or "").strip()
        if not candidate.startswith(("http://", "https://")) or not _same_origin_url(target_url, candidate):
            continue
        parsed = urlparse(candidate)
        if not parse_qsl(parsed.query, keep_blank_values=True):
            continue
        path_lower = parsed.path.lower()
        if any(word in path_lower for word in _STATE_CHANGING_PATH_WORDS):
            continue
        names = {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        if names & _STATE_CHANGING_KEYS:
            continue
        if candidate not in selected:
            selected.append(candidate)
        if len(selected) >= max(1, min(int(limit), 50)):
            break
    return selected


def _run_nuclei_core(
    target_url: str,
    cookies: str = "",
    timeout: int = 180,
    output_file: str = "",
    seed_urls: list[str] | None = None,
    max_targets: int = 4,
    scan_profile: str = "balanced",
    request_cases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run official template phases plus bounded DAST on discovered GET contracts."""
    scan_profile = str(scan_profile or "balanced").lower()
    if scan_profile not in {"fast", "balanced", "deep"}:
        return failure("Nuclei", target_url, "scan_profile must be fast, balanced, or deep.")
    timeout = max(35, min(int(timeout), 600))
    inventory = _template_inventory()
    refresh_result: dict[str, Any] = {}
    if inventory.get("count", 0) <= 0:
        refresh_result = _attempt_template_refresh()
        inventory = _template_inventory()
    template_dir = str(inventory.get("directory") or "")
    if inventory.get("count", 0) <= 0:
        result = failure(
            "Nuclei",
            target_url,
            "No Nuclei templates were detected after checking runtime metadata, standard directories, configuration files, and one bounded official update attempt. Run initScript.py with network access to restore the template pack.",
            diagnosis="nuclei_templates_missing",
        )
        result["template_inventory"] = inventory
        result["template_refresh"] = refresh_result
        return result

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

    def target_score(value: str) -> int:
        parsed = urlparse(value)
        path = parsed.path.lower()
        score = 0
        if any(token in path for token in ("setup", "admin", "config", "api", "swagger", "login", "phpinfo")):
            score += 100
        if any(token in path for token in ("upload", "debug", "backup", "download", "search", "query", "callback", "webhook")):
            score += 65
        if parsed.query:
            score += 20
        return score

    max_targets = max(1, min(int(max_targets), 20))
    seed_candidates = [
        value for value in (seed_urls or [])
        if isinstance(value, str)
        and value.startswith(("http://", "https://"))
        and _same_origin_url(target_url, value)
        and value != target_url
    ]
    ranked_seeds = sorted(dict.fromkeys(seed_candidates), key=target_score, reverse=True)
    focused_targets = [target_url, *ranked_seeds[: max(0, max_targets - 1)]]
    target_list = work_dir / f"{prefix}-targets.txt"
    target_list.write_text("\n".join(focused_targets) + "\n", encoding="utf-8")

    dast_targets = _dast_target_urls(target_url, request_cases, limit=20 if scan_profile == "deep" else 10)
    dast_target_list = work_dir / f"{prefix}-dast-targets.txt"
    if dast_targets:
        dast_target_list.write_text("\n".join(dast_targets) + "\n", encoding="utf-8")

    definitions = _phase_definitions(scan_profile, timeout, bool(dast_targets))
    phase_paths = [work_dir / f"{prefix}-{index + 1}.jsonl" for index in range(len(definitions))]
    for phase_path in phase_paths:
        phase_path.unlink(missing_ok=True)

    if scan_profile == "deep":
        concurrency, rate_limit, request_timeout, retries = 30, 120, 6, 1
    elif scan_profile == "balanced":
        concurrency, rate_limit, request_timeout, retries = 24, 100, 5, 1
    else:
        concurrency, rate_limit, request_timeout, retries = 16, 60, 3, 0

    phases: list[dict[str, Any]] = []
    all_items: list[dict[str, Any]] = []
    try:
        for phase_path, definition in zip(phase_paths, definitions):
            phase_target_list = dast_target_list if definition.get("dast") else target_list
            phase, items = _run_phase(
                target_url,
                cookies,
                phase_path,
                target_list=phase_target_list,
                concurrency=concurrency,
                rate_limit=rate_limit,
                request_timeout=request_timeout,
                retries=retries,
                template_dir=template_dir,
                **definition,
            )
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
        limited = [phase for phase in phases if phase.get("status") == "partial" and phase.get("timed_out")]
        summary = [
            {
                "name": phase.get("phase"),
                "status": phase.get("status"),
                "diagnosis": phase.get("diagnosis", ""),
                "duration_seconds": phase.get("duration_seconds"),
                "findings": phase.get("phase_findings", 0),
                "timeout_seconds": phase.get("phase_timeout_seconds"),
                "tags": phase.get("phase_tags", ""),
                "automatic_scan": phase.get("automatic_scan", False),
                "dast": phase.get("dast", False),
                "stderr_excerpt": str(phase.get("stderr", ""))[-1200:],
            }
            for phase in phases
        ]
        common = {
            "vulnerabilities": findings,
            "authenticated": bool(cookies),
            "phases": summary,
            "scan_profile": scan_profile,
            "scan_scope": (
                f"Official template inventory={inventory.get('count')}; profile={scan_profile}; "
                f"static_targets={len(focused_targets)}; dast_targets={len(dast_targets)}; "
                f"phases={','.join(item['name'] for item in definitions)}; "
                f"regular_excluded_tags={EXCLUDED_TAGS}; dast_excluded_tags={DAST_EXCLUDED_TAGS}."
            ),
            "focused_targets": focused_targets,
            "dast_targets": dast_targets,
            "template_inventory": inventory,
            "template_refresh": refresh_result,
            "hard_failure": bool(hard_failures),
            "output_file": str(combined_path) if output_file else "",
        }

        if len(hard_failures) == len(phases) and not findings:
            result = failure(
                "Nuclei",
                target_url,
                "Every prioritized Nuclei phase failed before producing parseable findings.",
                stdout="\n".join(str(phase.get("stdout", "")) for phase in phases),
                stderr="\n".join(str(phase.get("stderr", "")) for phase in phases),
                diagnosis="nuclei_phases_failed",
            )
            result.update(common)
            return result

        if hard_failures or limited:
            return partial(
                "Nuclei",
                target_url,
                f"Prioritized {scan_profile} Nuclei scan ended with incomplete coverage. Findings preserved: {len(findings)}.",
                diagnosis="time_limit_reached" if limited and not hard_failures else "partial_scan",
                timed_out=bool(limited),
                time_limit_reached=bool(limited),
                **common,
            )

        return success(
            "Nuclei",
            target_url,
            f"Prioritized {scan_profile} Nuclei scan completed. Findings: {len(findings)}.",
            timed_out=False,
            time_limit_reached=False,
            **common,
        )
    finally:
        for phase_path in phase_paths:
            phase_path.unlink(missing_ok=True)
        target_list.unlink(missing_ok=True)
        dast_target_list.unlink(missing_ok=True)
        if temporary is not None:
            temporary.cleanup()




@mcp.tool()
def run_nuclei_scan(
    target_url: str,
    cookies: str = "",
    timeout: int = 180,
    output_file: str = "",
    seed_urls: list[str] | None = None,
    max_targets: int = 4,
    scan_profile: str = "balanced",
    request_cases: list[dict[str, Any]] | None = None,
) -> dict:
    return _run_nuclei_core(
        target_url=target_url,
        cookies=cookies,
        timeout=timeout,
        output_file=output_file,
        seed_urls=seed_urls,
        max_targets=max_targets,
        scan_profile=scan_profile,
        request_cases=request_cases,
    )



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
