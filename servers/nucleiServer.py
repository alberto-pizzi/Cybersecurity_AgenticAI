from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

import requests
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
    "rce,auth-bypass,ssrf,xxe,deserialization,ssti,default-login,takeover"
)
EXPOSURE_TAGS = (
    "misconfig,exposure,default-login,panel,backup,config,debug,"
    "swagger,graphql,takeover"
)
SPECIALIST_COVERED_TAGS = "sqli,xss,cmdi,lfi,rfi,path-traversal,fuzz"
DAST_FOCUSED_TAGS = "ssrf,xxe,ssti,deserialization,code-injection,auth-bypass"
TECHNOLOGY_MARKERS: dict[str, tuple[str, ...]] = {
    "php": ("x-powered-by: php", "<?php", ".php"),
    "apache": ("server: apache",),
    "nginx": ("server: nginx",),
    "wordpress": ("wp-content", "wp-includes"),
    "drupal": ("drupal-settings-json", "sites/default"),
    "joomla": ("joomla", "com_content"),
    "laravel": ("laravel_session", "x-powered-by: laravel"),
    "django": ("csrftoken", "django"),
    "flask": ("werkzeug", "flask"),
    "express": ("x-powered-by: express",),
    "nodejs": ("x-powered-by: express", "node.js"),
    "springboot": ("whitelabel error page", "spring boot"),
    "tomcat": ("server: apache-coyote", "apache tomcat"),
    "aspnet": ("x-aspnet-version", "asp.net"),
    "graphql": ("graphql",),
    "swagger": ("swagger-ui", "openapi"),
    "jenkins": ("x-jenkins", "jenkins"),
    "grafana": ("grafana",),
    "kibana": ("kbn-name", "kibana"),
    "phpmyadmin": ("phpmyadmin",),
}
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



def _fingerprint_targets(target_url: str, cookies: str, seed_urls: list[str] | None) -> dict[str, Any]:
    candidates = [target_url]
    for value in seed_urls or []:
        if isinstance(value, str) and value.startswith(("http://", "https://")) and _same_origin_url(target_url, value):
            candidates.append(value)
    selected = list(dict.fromkeys(candidates))[:3]
    headers: dict[str, str] = {}
    body_parts: list[str] = []
    observed: list[dict[str, Any]] = []
    request_headers = {"User-Agent": "SecOps-Nuclei-Fingerprint/1.0", "Accept": "text/html,application/json,*/*;q=0.5"}
    if cookies:
        request_headers["Cookie"] = cookies
    for url in selected:
        try:
            response = requests.get(url, headers=request_headers, timeout=(3, 8), allow_redirects=True)
        except requests.RequestException as exc:
            observed.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
            continue
        for key, value in response.headers.items():
            headers[key.lower()] = str(value)
        body_parts.append(response.text[:60_000].lower())
        observed.append({
            "url": url,
            "status": response.status_code,
            "final_url": str(response.url),
            "server": str(response.headers.get("Server") or ""),
            "powered_by": str(response.headers.get("X-Powered-By") or ""),
        })
    haystack = "\n".join([*(f"{key}: {value}".lower() for key, value in headers.items()), *body_parts])
    tags = [tag for tag, markers in TECHNOLOGY_MARKERS.items() if any(marker in haystack for marker in markers)]
    return {
        "tags": sorted(set(tags)),
        "headers": headers,
        "observed": observed,
        "known": bool(tags),
    }


def _dast_specialist_gap_score(case: dict[str, Any]) -> int:
    url = str(case.get("url") or case.get("target_url") or "")
    parsed = urlparse(url)
    method = str(case.get("method") or "GET").upper()
    names = {str(value).lower() for value in case.get("parameters", []) if str(value)}
    names.update(name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    if method == "POST":
        names.update(name.lower() for name, _ in parse_qsl(str(case.get("data") or ""), keep_blank_values=True))
    path = parsed.path.lower()
    weights = {
        "url": 35, "uri": 35, "host": 35, "hostname": 35, "domain": 30,
        "callback": 45, "webhook": 45, "endpoint": 28, "target": 22,
        "redirect": 18, "next": 14, "return": 14, "fetch": 40, "proxy": 35,
        "xml": 45, "soap": 35, "template": 35, "view": 18, "engine": 30,
        "object": 22, "serialized": 45, "data": 10, "payload": 18,
    }
    score = sum(weight for name, weight in weights.items() if name in names)
    if any(token in path for token in ("ssrf", "xxe", "xml", "soap", "template", "render", "deserialize", "callback", "webhook", "fetch", "proxy")):
        score += 70
    return score


def _focused_dast_request_cases(
    target_url: str,
    request_cases: list[dict[str, Any]] | None,
    limit: int,
) -> list[dict[str, Any]]:
    candidates = _dast_request_cases(target_url, request_cases, limit=30)
    ranked = [dict(item, specialist_gap_score=_dast_specialist_gap_score(item)) for item in candidates]
    ranked = [item for item in ranked if int(item.get("specialist_gap_score", 0)) > 0]
    ranked.sort(key=lambda item: (-int(item.get("specialist_gap_score", 0)), -int(item.get("priority_score", 0)), str(item.get("url") or "")))
    return ranked[: max(0, min(int(limit), 4))]


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
    input_mode: str = "",
    fuzz_aggression: str = "medium",
    fuzz_param_frequency: int = 25,
    concurrency: int = 20,
    rate_limit: int = 80,
    request_timeout: int = 5,
    retries: int = 1,
    template_dir: str = "",
    excluded_tags: str = "",
) -> list[str]:
    input_args = (
        ["-l", str(target_list), *(["-im", input_mode] if input_mode else [])]
        if target_list else ["-u", target_url]
    )
    command = [
        "nuclei",
        *input_args,
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
            command.extend([
                "-fuzz-param-frequency", str(max(10, int(fuzz_param_frequency))),
                "-fa", fuzz_aggression if fuzz_aggression in {"low", "medium", "high"} else "medium",
            ])
    if not compatibility:
        excluded = excluded_tags or (DAST_EXCLUDED_TAGS if dast else EXCLUDED_TAGS)
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
        dast_directory = directory / "dast"
        dast_count = (
            sum(
                1
                for path in dast_directory.rglob("*")
                if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}
            )
            if dast_directory.is_dir() else 0
        )
        inventories.append({
            "directory": str(directory),
            "count": count,
            "dast_directory": str(dast_directory) if dast_directory.is_dir() else "",
            "dast_count": dast_count,
        })
    best = max(inventories, key=lambda item: item["count"], default={
        "directory": "", "count": 0, "dast_directory": "", "dast_count": 0
    })
    return {
        "count": int(best["count"]),
        "directory": str(best["directory"]),
        "dast_directory": str(best.get("dast_directory", "")),
        "dast_count": int(best.get("dast_count", 0)),
        "candidates": inventories,
    }


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
        "dast_directory": str(filesystem.get("dast_directory", "")),
        "dast_count": int(filesystem.get("dast_count", 0)),
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
    input_mode: str = "",
    fuzz_aggression: str = "medium",
    fuzz_param_frequency: int = 25,
    concurrency: int = 20,
    rate_limit: int = 80,
    request_timeout: int = 5,
    retries: int = 1,
    template_dir: str = "",
    excluded_tags: str = "",
    target_scope: str = "focused",
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
                input_mode=input_mode,
                fuzz_aggression=fuzz_aggression,
                fuzz_param_frequency=fuzz_param_frequency,
                concurrency=concurrency,
                rate_limit=rate_limit,
                request_timeout=request_timeout,
                retries=retries,
                template_dir=template_dir,
                excluded_tags=excluded_tags,
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
        input_mode=input_mode,
        fuzz_aggression=fuzz_aggression if dast else "",
        fuzz_param_frequency=fuzz_param_frequency if dast else 0,
        excluded_tags=excluded_tags,
        target_scope=target_scope,
    )
    return result, items




def _phase_definitions(
    scan_profile: str,
    total_timeout: int,
    has_dast_targets: bool = False,
    technology_tags: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Build a small adaptive Nuclei plan that complements specialist scanners.

    The automatic pipeline no longer launches the complete HTTP and DAST packs.
    It fingerprints the target, checks concise exposure/high-impact groups, and
    only uses DAST for SSRF/XXE/SSTI/deserialization-style gaps not already
    covered by SQLMap, Dalfox, Commix, traversal and ZAP.
    """
    technology_tags = sorted(set(str(value).strip().lower() for value in (technology_tags or []) if str(value).strip()))
    if scan_profile == "fast":
        desired = {"exposure": 35, "high": 45, "technology": 35, "dast": 50}
    elif scan_profile == "balanced":
        desired = {"exposure": 50, "high": 65, "technology": 50, "dast": 70}
    else:
        desired = {"exposure": 65, "high": 85, "technology": 70, "dast": 90}

    phases: list[dict[str, Any]] = [
        {
            "name": "focused_exposures_and_misconfigurations",
            "severities": "info,low,medium,high,critical",
            "tags": EXPOSURE_TAGS,
            "timeout": desired["exposure"],
            "target_scope": "focused",
            "excluded_tags": EXCLUDED_TAGS,
        },
        {
            "name": "focused_high_impact_templates",
            "severities": "medium,high,critical",
            "tags": HIGH_IMPACT_TAGS,
            "timeout": desired["high"],
            "target_scope": "base",
            "excluded_tags": EXCLUDED_TAGS + "," + SPECIALIST_COVERED_TAGS,
        },
    ]
    if technology_tags:
        phases.append({
            "name": "fingerprint_relevant_templates",
            "severities": "low,medium,high,critical",
            "tags": ",".join(technology_tags),
            "timeout": desired["technology"],
            "target_scope": "base",
            "excluded_tags": EXCLUDED_TAGS + "," + SPECIALIST_COVERED_TAGS,
        })
    if has_dast_targets:
        phases.append({
            "name": "specialist_gap_dast",
            "severities": "medium,high,critical",
            "tags": DAST_FOCUSED_TAGS,
            "dast": True,
            "timeout": desired["dast"],
            "target_scope": "dast",
            "excluded_tags": DAST_EXCLUDED_TAGS + "," + SPECIALIST_COVERED_TAGS,
        })

    usable = max(30, int(total_timeout) - 12)
    requested = sum(int(item["timeout"]) for item in phases)
    if requested > usable:
        scale = usable / requested
        remaining = usable
        for index, item in enumerate(phases):
            if index == len(phases) - 1:
                value = remaining
            else:
                future = len(phases) - index - 1
                value = max(12, int(round(int(item["timeout"]) * scale)))
                value = min(value, remaining - 12 * future)
            item["timeout"] = value
            remaining -= value
    return phases


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



def _dast_case_score(case: dict[str, Any]) -> int:
    candidate = str(case.get("url") or case.get("target_url") or "")
    parsed = urlparse(candidate)
    path = parsed.path.lower()
    method = str(case.get("method") or "GET").upper()
    names = {
        str(value).lower()
        for value in case.get("parameters", [])
        if str(value)
    }
    names.update(name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    if method == "POST":
        names.update(name.lower() for name, _ in parse_qsl(str(case.get("data") or ""), keep_blank_values=True))
    score = 0
    weights = {
        "id": 16, "uid": 18, "user_id": 20, "query": 16, "search": 14,
        "name": 12, "message": 15, "comment": 15, "file": 18, "path": 18,
        "page": 18, "include": 20, "template": 18, "url": 18, "host": 20,
        "ip": 22, "cmd": 24, "command": 24, "xml": 20,
    }
    score += sum(weight for name, weight in weights.items() if name in names)
    if any(token in path for token in ("sqli", "sql", "xss", "exec", "command", "file", "include", "ssrf", "xxe", "upload", "api")):
        score += 70
    if method == "POST":
        score += 10
    return score


def _dast_request_cases(
    target_url: str,
    request_cases: list[dict[str, Any]] | None,
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Select and rank safe same-origin GET/POST contracts for Nuclei DAST."""
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for case in request_cases or []:
        if not isinstance(case, dict):
            continue
        method = str(case.get("method") or "GET").upper()
        candidate = str(case.get("url") or case.get("target_url") or "").strip()
        data = str(case.get("data") or "")
        if method not in {"GET", "POST"}:
            continue
        if not candidate.startswith(("http://", "https://")) or not _same_origin_url(target_url, candidate):
            continue
        parsed = urlparse(candidate)
        path_lower = parsed.path.lower()
        if any(word in path_lower for word in _STATE_CHANGING_PATH_WORDS):
            continue
        query_names = {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        body_names = {
            name.lower() for name, _ in parse_qsl(data, keep_blank_values=True)
        } if method == "POST" else set()
        names = {
            str(value).lower()
            for value in case.get("parameters", [])
            if str(value)
        } | query_names | body_names
        if not names or names & _STATE_CHANGING_KEYS:
            continue
        key = (method, candidate, data)
        if key in seen:
            continue
        seen.add(key)
        candidates.append({
            "url": candidate,
            "method": method,
            "data": data,
            "parameters": sorted(names),
            "priority_score": _dast_case_score(case),
        })
    candidates.sort(key=lambda item: (-int(item.get("priority_score", 0)), item["url"], item["method"]))
    return candidates[: max(1, min(int(limit), 30))]


def _write_proxify_jsonl(
    path: Path,
    cases: list[dict[str, Any]],
    cookies: str,
) -> int:
    """Write complete request records using Nuclei's supported Proxify JSONL shape."""
    records: list[str] = []
    for case in cases:
        url = str(case.get("url") or "")
        method = str(case.get("method") or "GET").upper()
        data = str(case.get("data") or "")
        parsed = urlparse(url)
        request_target = parsed.path or "/"
        if parsed.query:
            request_target += "?" + parsed.query
        header_lines = [
            f"{method} {request_target} HTTP/1.1",
            f"Host: {parsed.netloc}",
            "User-Agent: SecOps-Nuclei-DAST/3.0",
            "Accept: */*",
        ]
        header_object: dict[str, Any] = {
            "scheme": parsed.scheme,
            "method": method,
            "path": request_target,
            "host": parsed.netloc,
            "user_agent": "SecOps-Nuclei-DAST/3.0",
            "accept": "*/*",
        }
        if cookies:
            header_lines.append(f"Cookie: {cookies}")
            header_object["cookie"] = cookies
        if method == "POST":
            header_lines.extend([
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(data.encode('utf-8'))}",
            ])
            header_object["content_type"] = "application/x-www-form-urlencoded"
            header_object["content_length"] = len(data.encode("utf-8"))
        raw = "\r\n".join(header_lines) + "\r\n\r\n" + (data if method == "POST" else "")
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "url": url,
            "request": {
                "header": header_object,
                "body": data if method == "POST" else "",
                "raw": raw,
            },
            "response": {
                "header": {"status_code": 0},
                "body": "",
                "raw": "",
            },
        }
        records.append(json.dumps(record, ensure_ascii=False, default=str))
    path.write_text("\n".join(records) + ("\n" if records else ""), encoding="utf-8")
    return len(records)


def _dast_target_urls(
    target_url: str,
    request_cases: list[dict[str, Any]] | None,
    limit: int = 20,
) -> list[str]:
    """Select ranked safe same-origin parameterized GET URLs for DAST."""
    candidates: list[tuple[int, str]] = []
    seen: set[str] = set()
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
        if names & _STATE_CHANGING_KEYS or candidate in seen:
            continue
        seen.add(candidate)
        candidates.append((_dast_case_score(case), candidate))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return [value for _, value in candidates[: max(1, min(int(limit), 24))]]


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
    """Run adaptive fingerprint-driven template phases and specialist-gap DAST."""
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
    dast_template_dir = str(inventory.get("dast_directory") or "")
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

    profile_target_cap = 1 if scan_profile == "fast" else 2
    max_targets = max(1, min(int(max_targets), profile_target_cap))
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
    base_target_list = work_dir / f"{prefix}-base-target.txt"
    base_target_list.write_text(target_url + "\n", encoding="utf-8")

    fingerprint = _fingerprint_targets(target_url, cookies, focused_targets)
    dast_cases = _focused_dast_request_cases(
        target_url,
        request_cases,
        limit=3 if scan_profile == "deep" else 2 if scan_profile == "balanced" else 1,
    )
    dast_targets = [
        str(item.get("url") or "")
        for item in dast_cases
        if str(item.get("method") or "GET").upper() == "GET"
    ]
    dast_target_list = work_dir / f"{prefix}-dast-targets.txt"
    if dast_targets:
        dast_target_list.write_text("\n".join(dast_targets) + "\n", encoding="utf-8")
    dast_request_log = work_dir / f"{prefix}-dast-requests.jsonl"
    dast_request_count = _write_proxify_jsonl(dast_request_log, dast_cases, cookies) if dast_cases else 0

    definitions = _phase_definitions(
        scan_profile, timeout, bool(dast_cases or dast_targets),
        technology_tags=list(fingerprint.get("tags") or []),
    )
    phase_paths = [work_dir / f"{prefix}-{index + 1}.jsonl" for index in range(len(definitions))]
    for phase_path in phase_paths:
        phase_path.unlink(missing_ok=True)

    if scan_profile == "deep":
        concurrency, rate_limit, request_timeout, retries = 24, 100, 5, 1
        fuzz_aggression, fuzz_frequency = "medium", 18
    elif scan_profile == "balanced":
        concurrency, rate_limit, request_timeout, retries = 18, 75, 4, 1
        fuzz_aggression, fuzz_frequency = "medium", 16
    else:
        concurrency, rate_limit, request_timeout, retries = 10, 40, 3, 0
        fuzz_aggression, fuzz_frequency = "low", 12

    phases: list[dict[str, Any]] = []
    all_items: list[dict[str, Any]] = []
    try:
        for phase_path, definition in zip(phase_paths, definitions):
            is_dast = bool(definition.get("dast"))
            target_scope = str(definition.get("target_scope") or "focused")
            phase_target_list = (
                dast_request_log
                if is_dast and dast_request_count
                else dast_target_list
                if is_dast
                else base_target_list
                if target_scope == "base"
                else target_list
            )
            input_mode = "jsonl" if is_dast and dast_request_count else ""
            phase_template_dir = (
                dast_template_dir
                if is_dast and dast_template_dir
                else template_dir
            )
            phase, items = _run_phase(
                target_url,
                cookies,
                phase_path,
                target_list=phase_target_list,
                input_mode=input_mode,
                fuzz_aggression=fuzz_aggression,
                fuzz_param_frequency=fuzz_frequency,
                concurrency=concurrency,
                rate_limit=rate_limit,
                request_timeout=request_timeout,
                retries=retries,
                template_dir=phase_template_dir,
                **definition,
            )

            # Older or vendor-modified Nuclei builds may reject Proxify JSONL
            # inputs. Preserve DAST coverage by retrying the safe GET URL list.
            phase_text = "\n".join((
                str(phase.get("stdout", "")),
                str(phase.get("stderr", "")),
                str(phase.get("output", "")),
            )).lower()
            if (
                is_dast
                and input_mode == "jsonl"
                and phase.get("status") == "error"
                and dast_targets
                and any(token in phase_text for token in ("jsonl", "input-mode", "input mode", "could not parse", "invalid input"))
            ):
                phase_path.unlink(missing_ok=True)
                fallback_phase, fallback_items = _run_phase(
                    target_url,
                    cookies,
                    phase_path,
                    target_list=dast_target_list,
                    input_mode="",
                    fuzz_aggression=fuzz_aggression,
                    fuzz_param_frequency=fuzz_frequency,
                    concurrency=concurrency,
                    rate_limit=rate_limit,
                    request_timeout=request_timeout,
                    retries=retries,
                    template_dir=phase_template_dir,
                    **definition,
                )
                fallback_phase["request_log_fallback"] = True
                fallback_phase["request_log_error_excerpt"] = phase_text[-1600:]
                phase, items = fallback_phase, fallback_items

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
                "input_mode": phase.get("input_mode", ""),
                "fuzz_aggression": phase.get("fuzz_aggression", ""),
                "fuzz_param_frequency": phase.get("fuzz_param_frequency", 0),
                "request_log_fallback": phase.get("request_log_fallback", False),
                "target_scope": phase.get("target_scope", ""),
                "excluded_tags": phase.get("excluded_tags", ""),
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
                f"static_targets={len(focused_targets)}; technology_tags={','.join(fingerprint.get('tags') or []) or 'none'}; "
                f"dast_request_cases={len(dast_cases)}; dast_get_targets={len(dast_targets)}; "
                f"dast_templates={inventory.get('dast_count', 0)}; "
                f"phases={','.join(item['name'] for item in definitions)}; "
                f"regular_excluded_tags={EXCLUDED_TAGS}; dast_excluded_tags={DAST_EXCLUDED_TAGS}."
            ),
            "focused_targets": focused_targets,
            "dast_targets": dast_targets,
            "dast_request_cases": [
                {
                    "url": item.get("url", ""),
                    "method": item.get("method", "GET"),
                    "parameters": item.get("parameters", []),
                }
                for item in dast_cases
            ],
            "dast_request_count": dast_request_count,
            "dast_input_mode": "jsonl" if dast_request_count else "list",
            "dast_template_directory": dast_template_dir,
            "technology_fingerprint": fingerprint,
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
                f"Adaptive {scan_profile} Nuclei scan ended with incomplete coverage. Findings preserved: {len(findings)}.",
                diagnosis="time_limit_reached" if limited and not hard_failures else "partial_scan",
                timed_out=bool(limited),
                time_limit_reached=bool(limited),
                **common,
            )

        return success(
            "Nuclei",
            target_url,
            f"Adaptive {scan_profile} Nuclei scan completed. Findings: {len(findings)}.",
            timed_out=False,
            time_limit_reached=False,
            **common,
        )
    finally:
        for phase_path in phase_paths:
            phase_path.unlink(missing_ok=True)
        target_list.unlink(missing_ok=True)
        base_target_list.unlink(missing_ok=True)
        dast_target_list.unlink(missing_ok=True)
        dast_request_log.unlink(missing_ok=True)
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
