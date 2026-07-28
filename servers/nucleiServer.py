from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

import requests
from fastmcp import FastMCP

from utils import failure, partial, read_json_lines, run_process, success

mcp = FastMCP("Nuclei Scanner")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CUSTOM_TEMPLATE_DIR = PROJECT_ROOT / "nuclei-templates-secops"

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
_TEMPLATE_CATALOG_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}


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
    metadata = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}
    metadata_category = str(metadata.get("secops-category") or metadata.get("secops_category") or "").lower()
    category = metadata_category if metadata_category in {"vulnerability", "candidate", "observation", "discovery"} else ("observation" if severity == "info" else "vulnerability")
    verification_status = str(metadata.get("secops-verification-status") or metadata.get("secops_verification_status") or "automated-template-match")
    confidence = str(metadata.get("secops-confidence") or metadata.get("secops_confidence") or "high").lower()

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
        "category": category,
        "verification_status": verification_status,
        "confidence": confidence,
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



def _custom_template_paths() -> list[str]:
    """Return the project-managed, read-only Nuclei templates.

    These small response-classification templates complement the official pack
    and make exact discovered resources (for example a backup file or phpinfo
    page) testable without asking Nuclei to enumerate thousands of paths again.
    """
    if not CUSTOM_TEMPLATE_DIR.is_dir():
        return []
    return [str(path.resolve()) for path in sorted(CUSTOM_TEMPLATE_DIR.glob("*.yaml")) if path.is_file()]


def _evidence_target_score(value: str) -> int:
    parsed = urlparse(str(value or ""))
    path = parsed.path.lower()
    score = 0
    if any(token in path for token in (".env", ".git/", "phpinfo", "server-status", "swagger", "openapi")):
        score += 180
    if any(token in path for token in (".bak", ".dist", ".old", ".orig", "backup", "config", "debug", "dump", "database")):
        score += 150
    if any(token in path for token in ("/admin", "/api", "/docs", "/actuator", "/graphql")):
        score += 90
    if parsed.query and {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)} <= {"c", "n", "m", "s", "d", "o"}:
        score += 80
    if path.endswith("/"):
        score += 15
    return score


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
    template_paths: list[str] | None = None,
    excluded_tags: str = "",
    bulk_size: int = 4,
    payload_concurrency: int = 8,
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
        "-no-stdin",
        *( ["-stream"] if target_list else [] ),
        "-timeout", str(max(2, request_timeout)),
        "-retries", str(max(0, retries)),
        "-c", str(max(1, concurrency)),
        "-bs", str(max(1, bulk_size)),
        "-pc", str(max(1, payload_concurrency)),
        "-rl", str(max(1, rate_limit)),
    ]
    exact_templates = [str(value) for value in (template_paths or []) if str(value)]
    if exact_templates:
        for template_path in exact_templates:
            command.extend(["-t", template_path])
    elif template_dir:
        command.extend(["-t", template_dir])
    if tags and not exact_templates:
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
    """Return a bounded filesystem inventory without enumerating every template through Nuclei.

    ``nuclei -tl`` with an unrestricted official pack can itself take tens of
    seconds on Windows.  The filesystem is authoritative when a complete pack
    is present; the CLI probe is only used as a fallback for unusual layouts.
    """
    filesystem = _filesystem_template_inventory()
    filesystem_count = int(filesystem.get("count", 0))
    result: dict[str, Any] = {
        "status": "skipped",
        "diagnosis": "filesystem_inventory_sufficient",
        "stderr": "",
    }
    cli_count = 0
    if filesystem_count < MIN_EXPECTED_TEMPLATE_COUNT:
        result = run_process(
            "Nuclei template inventory",
            ["nuclei", "-tl", "-silent", "-nc", "-disable-update-check"],
            target="templates",
            timeout=15,
        )
        lines = {
            line.strip()
            for line in str(result.get("stdout", "")).splitlines()
            if line.strip() and not line.lstrip().startswith("[")
        }
        cli_count = len(lines)
    count = max(cli_count, filesystem_count)
    return {
        "count": count,
        "cli_count": cli_count,
        "filesystem_count": filesystem_count,
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


def _template_catalog(template_root: Path) -> list[dict[str, Any]]:
    """Build a lightweight metadata catalogue from the installed official pack."""
    try:
        stamp = template_root.stat().st_mtime
    except OSError:
        return []
    key = str(template_root.resolve())
    cached = _TEMPLATE_CATALOG_CACHE.get(key)
    if cached and cached[0] == stamp:
        return cached[1]

    tag_re = re.compile(r"(?im)^\s*tags\s*:\s*(?:\[([^\]]*)\]|([^\r\n#]+))")
    severity_re = re.compile(r"(?im)^\s*severity\s*:\s*[\"']?([a-z]+)")
    name_re = re.compile(r"(?im)^\s*name\s*:\s*[\"']?([^\r\n\"']+)")
    id_re = re.compile(r"(?im)^\s*id\s*:\s*[\"']?([^\r\n\"']+)")
    rows: list[dict[str, Any]] = []
    for path in template_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        try:
            relative = path.relative_to(template_root).as_posix()
        except ValueError:
            relative = path.name
        relative_lower = relative.lower()
        if any(token in relative_lower for token in ("/.git/", "/helpers/", "/workflows/")):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")[:24_000]
        except OSError:
            continue
        tag_match = tag_re.search(content)
        tag_text = (tag_match.group(1) or tag_match.group(2) or "") if tag_match else ""
        tags = {
            value.strip().strip("\"'").lower()
            for value in re.split(r"[,\s]+", tag_text)
            if value.strip().strip("\"'")
        }
        severity_match = severity_re.search(content)
        name_match = name_re.search(content)
        id_match = id_re.search(content)
        # Exact-file phases should only receive templates that can be executed
        # by the bounded HTTP runner.  The official repository also contains
        # headless/code/javascript/network templates and mixed workflow files;
        # passing one of those to an HTTP-only command can make Nuclei exit with
        # a non-zero status before the remaining valid templates are attempted.
        top_level_http = bool(re.search(r"(?im)^(?:http|requests)\s*:\s*$", content))
        unsupported_protocols = sorted({
            value
            for value in ("headless", "code", "javascript", "dns", "network", "ssl", "websocket", "file")
            if re.search(rf"(?im)^{re.escape(value)}\s*:\s*$", content)
        })
        rows.append({
            "path": str(path.resolve()),
            "relative": relative,
            "relative_lower": relative_lower,
            "tags": tags,
            "severity": (severity_match.group(1).lower() if severity_match else "unknown"),
            "name": (name_match.group(1).strip() if name_match else path.stem),
            "id": (id_match.group(1).strip() if id_match else path.stem),
            "http_compatible": top_level_http and not unsupported_protocols,
            "unsupported_protocols": unsupported_protocols,
        })
    _TEMPLATE_CATALOG_CACHE[key] = (stamp, rows)
    return rows


def _phase_template_limit(scan_profile: str, phase_name: str) -> int:
    limits = {
        "fast": {"direct_evidence_classification": 8, "focused_exposures_and_misconfigurations": 8, "focused_high_impact_templates": 6, "fingerprint_relevant_templates": 4, "specialist_gap_dast": 4},
        "balanced": {"direct_evidence_classification": 8, "focused_exposures_and_misconfigurations": 14, "focused_high_impact_templates": 12, "fingerprint_relevant_templates": 8, "specialist_gap_dast": 6},
        "deep": {"direct_evidence_classification": 8, "focused_exposures_and_misconfigurations": 20, "focused_high_impact_templates": 18, "fingerprint_relevant_templates": 12, "specialist_gap_dast": 8},
    }
    return limits.get(scan_profile, limits["balanced"]).get(phase_name, 40)


def _select_phase_templates(
    catalog: list[dict[str, Any]],
    definition: dict[str, Any],
    technology_tags: list[str],
    scan_profile: str,
) -> list[dict[str, Any]]:
    """Choose exact template files instead of loading broad tag collections."""
    name = str(definition.get("name") or "")
    technologies = {str(value).lower() for value in technology_tags if str(value)}
    excluded = {value for value in (EXCLUDED_TAGS + "," + SPECIALIST_COVERED_TAGS).split(",") if value}
    exposure_tags = {value for value in EXPOSURE_TAGS.split(",") if value}
    high_tags = {value for value in HIGH_IMPACT_TAGS.split(",") if value}
    dast_tags = {value for value in DAST_FOCUSED_TAGS.split(",") if value}
    severity_score = {"critical": 35, "high": 25, "medium": 12, "low": 4, "info": 1, "unknown": 0}
    ranked: list[tuple[int, str, dict[str, Any]]] = []

    for item in catalog:
        relative = str(item.get("relative_lower") or "")
        tags = set(item.get("tags") or set())
        severity = str(item.get("severity") or "unknown")
        if not bool(item.get("http_compatible", True)):
            continue
        if tags & excluded and name != "specialist_gap_dast":
            continue
        is_dast = relative.startswith("dast/") or "/dast/" in relative
        score = severity_score.get(severity, 0)

        if name == "focused_exposures_and_misconfigurations":
            if is_dast:
                continue
            if "http/exposures/" in relative:
                score += 120
            if "http/misconfiguration/" in relative:
                score += 115
            if "http/default-logins/" in relative:
                score += 80
            if "http/takeovers/" in relative:
                score += 65
            score += 35 * len(tags & exposure_tags)
            if any(token in relative for token in ("backup", "config", "debug", "phpinfo", "git-", "swagger", "graphql", "panel", "exposure")):
                score += 45
            if score < 50:
                continue
        elif name == "focused_high_impact_templates":
            if is_dast or tags & {"sqli", "xss", "cmdi", "lfi", "rfi", "path-traversal", "fuzz"}:
                continue
            impact_hits = tags & high_tags
            impact_path = any(token in relative for token in ("auth-bypass", "rce", "ssrf", "xxe", "ssti", "deserial", "takeover"))
            technology_cve = (
                "http/cves/" in relative
                and bool(technologies)
                and bool((tags & technologies) or {tech for tech in technologies if tech in relative})
                and severity in {"medium", "high", "critical"}
            )
            if not impact_hits and not impact_path and not technology_cve:
                continue
            score += 45 * len(impact_hits)
            if technology_cve:
                score += 90
            if "http/cves/" in relative:
                score += 20
            if impact_path:
                score += 55
        elif name == "fingerprint_relevant_templates":
            if is_dast or not technologies:
                continue
            if tags & {"sqli", "xss", "cmdi", "lfi", "rfi", "path-traversal", "fuzz", "exposure", "misconfig", "backup", "config"}:
                continue
            tech_hits = tags & technologies
            path_hits = {tech for tech in technologies if tech in relative}
            if not tech_hits and not path_hits:
                continue
            # Keep this phase for product/technology detection and product CVEs;
            # exposure templates already ran in the first phase.
            if not ("http/technologies/" in relative or "http/cves/" in relative or "detect" in relative):
                continue
            score += 90 * len(tech_hits) + 55 * len(path_hits)
            if "http/technologies/" in relative:
                score += 30
            if "http/cves/" in relative and severity in {"medium", "high", "critical"}:
                score += 45
        elif name == "specialist_gap_dast":
            if not is_dast:
                continue
            hits = tags & dast_tags
            if not hits and not any(token in relative for token in ("ssrf", "xxe", "ssti", "deserial", "auth-bypass")):
                continue
            score += 80 * len(hits)
        else:
            continue
        ranked.append((score, str(item.get("relative") or ""), item))

    limit = _phase_template_limit(scan_profile, name)
    selected = [item for _, _, item in sorted(ranked, key=lambda row: (-row[0], row[1]))[:limit]]
    return selected

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
    template_paths: list[str] | None = None,
    excluded_tags: str = "",
    target_scope: str = "focused",
    bulk_size: int = 4,
    payload_concurrency: int = 8,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    def execute(
        *,
        compatibility: bool,
        selected_paths: list[str] | None = None,
        output_path: Path | None = None,
        budget: int | None = None,
    ) -> dict[str, Any]:
        return run_process(
            "Nuclei",
            _command(
                target_url,
                cookies,
                output_path or path,
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
                template_paths=selected_paths if selected_paths is not None else template_paths,
                excluded_tags=excluded_tags,
                bulk_size=bulk_size,
                payload_concurrency=payload_concurrency,
            ),
            target=target_url,
            timeout=budget if budget is not None else timeout,
        )

    def execute_with_compatibility(
        selected_paths: list[str],
        output_path: Path,
        budget: int,
    ) -> dict[str, Any]:
        current = execute(
            compatibility=False,
            selected_paths=selected_paths,
            output_path=output_path,
            budget=budget,
        )
        current_text = "\n".join((str(current.get("stdout", "")), str(current.get("stderr", ""))))
        if current.get("status") == "error" and "unknown flag" in current_text.lower():
            output_path.unlink(missing_ok=True)
            current = execute(
                compatibility=True,
                selected_paths=selected_paths,
                output_path=output_path,
                budget=budget,
            )
            current["compatibility_mode"] = True
        return current

    def template_error(result: dict[str, Any]) -> bool:
        text = "\n".join((
            str(result.get("stdout", "")),
            str(result.get("stderr", "")),
            str(result.get("output", "")),
        )).lower()
        return any(token in text for token in (
            "could not load template", "could not parse template", "failed to load template",
            "template validation", "invalid template", "yaml:", "unmarshal errors",
            "could not compile", "unsupported protocol", "no templates provided",
        ))

    exact_paths = [str(value) for value in (template_paths or []) if str(value)]

    # Technology/CVE packs occasionally contain a stale or protocol-specific
    # template even when the repository inventory itself is healthy.  Running
    # all exact files in one Nuclei process lets one bad file abort the whole
    # phase.  Execute this phase in bounded batches, isolate a failing batch,
    # and skip only templates that Nuclei itself reports as invalid.
    if name == "fingerprint_relevant_templates" and exact_paths:
        started = time.monotonic()
        batch_size = 4
        batches = [exact_paths[index:index + batch_size] for index in range(0, len(exact_paths), batch_size)]
        recovered_items: list[dict[str, Any]] = []
        completed_templates: list[str] = []
        invalid_templates: list[dict[str, str]] = []
        runtime_failures: list[dict[str, str]] = []
        timed_out_templates: list[str] = []
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        commands: list[list[str]] = []

        def remaining_seconds() -> int:
            return max(0, int(timeout - (time.monotonic() - started)))

        def run_group(paths: list[str], label: str, minimum_budget: int = 4) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            remaining = remaining_seconds()
            if remaining < minimum_budget:
                return ({
                    "status": "partial",
                    "diagnosis": "phase_recovery_budget_exhausted",
                    "output": "No phase budget remained for the isolated template retry.",
                    "timed_out": True,
                }, [])
            groups_left = max(1, len(batches))
            budget = max(minimum_budget, min(14, remaining // groups_left if groups_left else remaining))
            candidate_path = path.with_name(f"{path.stem}-{label}{path.suffix}")
            candidate_path.unlink(missing_ok=True)
            candidate = execute_with_compatibility(paths, candidate_path, budget)
            candidate_items = _read_items(candidate_path, str(candidate.get("stdout", "")))
            candidate_path.unlink(missing_ok=True)
            stdout_parts.append(str(candidate.get("stdout", "")))
            stderr_parts.append(str(candidate.get("stderr", "")))
            if isinstance(candidate.get("command"), list):
                commands.append(candidate["command"])
            return candidate, candidate_items

        for batch_index, batch in enumerate(batches, 1):
            if remaining_seconds() < 4:
                timed_out_templates.extend(batch)
                continue
            batch_result, batch_items = run_group(batch, f"batch-{batch_index}")
            if batch_result.get("status") == "success":
                completed_templates.extend(batch)
                recovered_items.extend(batch_items)
                continue
            if batch_result.get("diagnosis") == "timeout" or batch_result.get("timed_out"):
                timed_out_templates.extend(batch)
                recovered_items.extend(batch_items)
                continue
            if len(batch) > 1 and template_error(batch_result):
                for item_index, template_path in enumerate(batch, 1):
                    if remaining_seconds() < 4:
                        timed_out_templates.append(template_path)
                        continue
                    single_result, single_items = run_group(
                        [template_path],
                        f"batch-{batch_index}-template-{item_index}",
                        minimum_budget=4,
                    )
                    if single_result.get("status") == "success":
                        completed_templates.append(template_path)
                        recovered_items.extend(single_items)
                    elif template_error(single_result):
                        invalid_templates.append({
                            "template": template_path,
                            "error": "\n".join((
                                str(single_result.get("stderr", "")),
                                str(single_result.get("output", "")),
                            ))[-1200:],
                        })
                    elif single_result.get("diagnosis") == "timeout" or single_result.get("timed_out"):
                        timed_out_templates.append(template_path)
                        recovered_items.extend(single_items)
                    else:
                        runtime_failures.append({
                            "template": template_path,
                            "error": "\n".join((
                                str(single_result.get("stderr", "")),
                                str(single_result.get("output", "")),
                            ))[-1200:],
                        })
                continue
            runtime_failures.append({
                "template": ", ".join(batch),
                "error": "\n".join((
                    str(batch_result.get("stderr", "")),
                    str(batch_result.get("output", "")),
                ))[-1200:],
            })
            recovered_items.extend(batch_items)

        recovered_items = _deduplicate(recovered_items)
        if recovered_items:
            path.write_text(
                "\n".join(json.dumps(item, ensure_ascii=False, default=str) for item in recovered_items) + "\n",
                encoding="utf-8",
            )
        else:
            path.unlink(missing_ok=True)

        if runtime_failures:
            phase_status = "partial" if completed_templates or recovered_items else "error"
            diagnosis = "template_batch_runtime_failure"
            output = (
                "Nuclei isolated the technology templates, but one or more runnable templates still failed. "
                f"Completed={len(completed_templates)}; runtime failures={len(runtime_failures)}; "
                f"findings preserved={len(recovered_items)}."
            )
        elif timed_out_templates:
            phase_status = "partial"
            diagnosis = "template_batch_time_limit"
            output = (
                "Nuclei completed the runnable technology-template batches that fit the phase budget. "
                f"Completed={len(completed_templates)}; timed out={len(timed_out_templates)}; "
                f"findings preserved={len(recovered_items)}."
            )
        else:
            phase_status = "success"
            diagnosis = "invalid_templates_isolated" if invalid_templates else ""
            output = (
                "Nuclei completed all runnable technology-template batches. "
                f"Completed={len(completed_templates)}; invalid/unsupported skipped={len(invalid_templates)}; "
                f"findings={len(recovered_items)}."
            )

        result = {
            "tool": "Nuclei",
            "status": phase_status,
            "target": target_url,
            "output": output,
            "vulnerabilities": [],
            "diagnosis": diagnosis,
            "stdout": "\n".join(part for part in stdout_parts if part)[-12000:],
            "stderr": "\n".join(part for part in stderr_parts if part)[-12000:],
            "commands": commands,
            "duration_seconds": round(time.monotonic() - started, 3),
            "timed_out": bool(timed_out_templates),
            "time_limit_reached": bool(timed_out_templates),
            "template_batch_recovery": True,
            "completed_template_count": len(completed_templates),
            "invalid_template_count": len(invalid_templates),
            "invalid_templates": invalid_templates,
            "runtime_template_failures": runtime_failures,
            "timed_out_templates": timed_out_templates,
        }
        result.update(
            phase=name,
            phase_timeout_seconds=timeout,
            phase_findings=len(recovered_items),
            phase_tags=tags,
            automatic_scan=automatic_scan,
            dast=dast,
            input_mode=input_mode,
            fuzz_aggression="",
            fuzz_param_frequency=0,
            excluded_tags=excluded_tags,
            target_scope=target_scope,
            selected_template_count=len(exact_paths),
            selected_template_sample=[Path(value).name for value in exact_paths[:20]],
            bulk_size=bulk_size,
            payload_concurrency=payload_concurrency,
        )
        return result, recovered_items

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
        selected_template_count=len(template_paths or []),
        selected_template_sample=[Path(value).name for value in (template_paths or [])[:20]],
        bulk_size=bulk_size,
        payload_concurrency=payload_concurrency,
    )
    return result, items




def _phase_definitions(
    scan_profile: str,
    total_timeout: int,
    has_dast_targets: bool = False,
    technology_tags: list[str] | None = None,
    has_custom_templates: bool = False,
) -> list[dict[str, Any]]:
    """Build a small adaptive Nuclei plan that complements specialist scanners.

    The automatic pipeline no longer launches the complete HTTP and DAST packs.
    It fingerprints the target, checks concise exposure/high-impact groups, and
    only uses DAST for SSRF/XXE/SSTI/deserialization-style gaps not already
    covered by SQLMap, Dalfox, Commix, traversal and ZAP.
    """
    technology_tags = sorted(set(str(value).strip().lower() for value in (technology_tags or []) if str(value).strip()))
    if scan_profile == "fast":
        desired = {"direct": 14, "exposure": 18, "high": 20, "technology": 14, "dast": 18}
    elif scan_profile == "balanced":
        desired = {"direct": 18, "exposure": 30, "high": 38, "technology": 25, "dast": 35}
    else:
        desired = {"direct": 22, "exposure": 40, "high": 50, "technology": 35, "dast": 45}

    phases: list[dict[str, Any]] = []
    if has_custom_templates:
        phases.append({
            "name": "direct_evidence_classification",
            "severities": "info,low,medium,high,critical",
            "tags": "secops",
            "timeout": desired["direct"],
            "target_scope": "evidence",
            "excluded_tags": EXCLUDED_TAGS,
        })
    phases.extend([
        {
            "name": "focused_exposures_and_misconfigurations",
            "severities": "info,low,medium,high,critical",
            "tags": EXPOSURE_TAGS,
            "timeout": desired["exposure"],
            "target_scope": "evidence",
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
    ])
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

    profile_target_cap = 6 if scan_profile == "fast" else 10 if scan_profile == "balanced" else 16
    max_targets = max(1, min(int(max_targets), profile_target_cap))
    seed_candidates = [
        value for value in (seed_urls or [])
        if isinstance(value, str)
        and value.startswith(("http://", "https://"))
        and _same_origin_url(target_url, value)
        and value != target_url
    ]
    ranked_seeds = sorted(dict.fromkeys(seed_candidates), key=lambda value: (_evidence_target_score(value), target_score(value), value), reverse=True)
    focused_targets = [target_url, *ranked_seeds[: max(0, max_targets - 1)]]
    evidence_ranked = [value for value in ranked_seeds if _evidence_target_score(value) > 0]
    evidence_targets = list(dict.fromkeys([target_url, *evidence_ranked[: max_targets]]))
    target_list = work_dir / f"{prefix}-targets.txt"
    target_list.write_text("\n".join(focused_targets) + "\n", encoding="utf-8")
    evidence_target_list = work_dir / f"{prefix}-evidence-targets.txt"
    evidence_target_list.write_text("\n".join(evidence_targets) + "\n", encoding="utf-8")
    base_target_list = work_dir / f"{prefix}-base-target.txt"
    base_target_list.write_text(target_url + "\n", encoding="utf-8")

    fingerprint = _fingerprint_targets(target_url, cookies, focused_targets)
    catalog = _template_catalog(Path(template_dir)) if template_dir else []
    custom_template_paths = _custom_template_paths()
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
        has_custom_templates=bool(custom_template_paths),
    )
    phase_paths = [work_dir / f"{prefix}-{index + 1}.jsonl" for index in range(len(definitions))]
    for phase_path in phase_paths:
        phase_path.unlink(missing_ok=True)

    if scan_profile == "deep":
        concurrency, bulk_size, payload_concurrency = 20, 8, 8
        rate_limit, request_timeout, retries = 120, 5, 0
        fuzz_aggression, fuzz_frequency = "medium", 18
    elif scan_profile == "balanced":
        concurrency, bulk_size, payload_concurrency = 14, 6, 6
        rate_limit, request_timeout, retries = 80, 4, 0
        fuzz_aggression, fuzz_frequency = "medium", 16
    else:
        concurrency, bulk_size, payload_concurrency = 8, 4, 4
        rate_limit, request_timeout, retries = 40, 3, 0
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
                else evidence_target_list
                if target_scope == "evidence"
                else target_list
            )
            input_mode = "jsonl" if is_dast and dast_request_count else ""
            if str(definition.get("name") or "") == "direct_evidence_classification":
                selected_templates = [
                    {"path": value, "relative": Path(value).name, "relative_lower": Path(value).name.lower()}
                    for value in custom_template_paths[:_phase_template_limit(scan_profile, "direct_evidence_classification")]
                ]
            else:
                selected_templates = _select_phase_templates(
                    catalog,
                    definition,
                    list(fingerprint.get("tags") or []),
                    scan_profile,
                )
            if not selected_templates:
                phases.append({
                    "phase": definition.get("name"),
                    "status": "skipped",
                    "diagnosis": "no_applicable_templates_selected",
                    "output": "No exact installed template matched this adaptive phase.",
                    "phase_timeout_seconds": definition.get("timeout"),
                    "phase_findings": 0,
                    "phase_tags": definition.get("tags", ""),
                    "selected_template_count": 0,
                    "selected_template_sample": [],
                    "target_scope": target_scope,
                    "dast": is_dast,
                })
                continue
            template_paths = [str(item.get("path") or "") for item in selected_templates]
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
                template_dir="",
                template_paths=template_paths,
                bulk_size=bulk_size,
                payload_concurrency=payload_concurrency,
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
                    template_dir="",
                    template_paths=template_paths,
                    bulk_size=bulk_size,
                    payload_concurrency=payload_concurrency,
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
                "selected_template_count": phase.get("selected_template_count", 0),
                "selected_template_sample": phase.get("selected_template_sample", []),
                "bulk_size": phase.get("bulk_size", 0),
                "payload_concurrency": phase.get("payload_concurrency", 0),
                "template_batch_recovery": phase.get("template_batch_recovery", False),
                "completed_template_count": phase.get("completed_template_count", 0),
                "invalid_template_count": phase.get("invalid_template_count", 0),
                "invalid_templates": phase.get("invalid_templates", []),
                "runtime_template_failures": phase.get("runtime_template_failures", []),
                "timed_out_templates": phase.get("timed_out_templates", []),
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
            "evidence_targets": evidence_targets,
            "custom_template_count": len(custom_template_paths),
            "custom_template_directory": str(CUSTOM_TEMPLATE_DIR),
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
            "template_catalog_count": len(catalog),
            "template_selection_strategy": "exact-files-from-local-metadata-catalog",
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
