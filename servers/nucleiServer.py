from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from scannerCommon import cleanup_docker_container, docker_container_name, docker_target, load_config, service, unique_strings
from utils import ROOT_DIR, failure, partial, run_process, same_origin, success

mcp, _serve = service("Nuclei Scanner", "nuclei")
RUNTIME = Path(ROOT_DIR) / ".secops_runtime.json"
CUSTOM_TEMPLATE_DIR = Path(ROOT_DIR) / "nuclei-templates-secops"


def _runtime() -> dict[str, Any]:
    return load_config(RUNTIME)


def _profile(value: str) -> tuple[str, dict[str, int]]:
    name = str(value or "balanced").lower()
    if name not in {"fast", "balanced", "deep"}:
        raise ValueError("scan_profile must be fast, balanced, or deep")
    return name, {
        "fast": {"c": 4, "bs": 2, "pc": 2, "rl": 20, "timeout": 3},
        "balanced": {"c": 6, "bs": 3, "pc": 3, "rl": 35, "timeout": 4},
        "deep": {"c": 14, "bs": 6, "pc": 6, "rl": 90, "timeout": 5},
    }[name]


def _target_score(url: str) -> int:
    path = urlparse(url).path.lower()
    score = 20 if urlparse(url).query else 0
    if any(v in path for v in ("setup", "admin", "config", "api", "swagger", "login", "phpinfo", ".env", ".git")):
        score += 100
    if any(v in path for v in ("upload", "debug", "backup", "download", "search", "query", "callback", "webhook")):
        score += 60
    return score


def _focused_targets(target_url: str, seeds: list[str] | None, limit: int) -> list[str]:
    candidates = [
        value for value in unique_strings(seeds)
        if value.startswith(("http://", "https://")) and same_origin(target_url, value) and value != target_url
    ]
    return [target_url, *sorted(candidates, key=lambda value: (_target_score(value), value), reverse=True)[: max(0, limit - 1)]]


def _dast_cases(target_url: str, cases: list[dict[str, Any]] | None, limit: int) -> list[dict[str, Any]]:
    ranked: list[tuple[int, dict[str, Any]]] = []
    for case in cases or []:
        if not isinstance(case, dict):
            continue
        url, method = str(case.get("url") or ""), str(case.get("method") or "GET").upper()
        if method not in {"GET", "POST"} or not same_origin(target_url, url):
            continue
        path = urlparse(url).path.lower()
        if any(token in path for token in ("logout", "reset", "delete", "setup", "security")):
            continue
        params = [str(v) for v in case.get("parameters", []) if str(v)]
        if not params and not urlparse(url).query and not str(case.get("data") or ""):
            continue
        score = 100 + (30 if method == "POST" else 0) + _target_score(url)
        if any(token in path for token in ("sqli", "xss", "exec", "command", "fi", "include", "ssrf", "xxe")):
            score += 80
        ranked.append((score, case))
    return [case for _, case in sorted(ranked, key=lambda value: -value[0])[:limit]]


def _containerize_url(url: str) -> str:
    return docker_target(url)[0]


def _externalize_url(url: str, target_url: str) -> str:
    parsed, target = urlparse(str(url or "")), urlparse(target_url)
    internal_host = (urlparse(docker_target(target_url)[0]).hostname or "").lower()
    if (parsed.hostname or "").lower() in {"host.docker.internal", internal_host}:
        return urlunparse(parsed._replace(scheme=target.scheme, netloc=target.netloc))
    return url


def _write_proxify_jsonl(path: Path, cases: list[dict[str, Any]], cookies: str, docker: bool) -> int:
    records = []
    for case in cases:
        url, method, data = str(case.get("url") or ""), str(case.get("method") or "GET").upper(), str(case.get("data") or "")
        if docker:
            url = _containerize_url(url)
        parsed = urlparse(url)
        request_path = urlunparse(parsed._replace(scheme="", netloc="")) or "/"
        headers = {"User-Agent": "SecOps-Nuclei/1.0", "host": parsed.netloc, "method": method, "path": request_path, "scheme": parsed.scheme}
        if cookies:
            headers["Cookie"] = cookies
        if method == "POST" and data:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        wire_headers = {"Host": parsed.netloc, **{key: value for key, value in headers.items() if key not in {"host", "method", "path", "scheme"}}}
        raw = f"{method} {request_path} HTTP/1.1\r\n" + "\r\n".join(f"{k}: {v}" for k, v in wire_headers.items()) + "\r\n\r\n" + data
        records.append(json.dumps({
            "timestamp": "", "url": url, "request": {"header": headers, "body": data, "raw": raw},
            "response": {"header": {}, "body": "", "raw": ""},
        }, ensure_ascii=False))
    path.write_text("\n".join(records) + ("\n" if records else ""), encoding="utf-8")
    return len(records)


def _command(runtime: dict[str, Any], work: Path, args: list[str], target_url: str = "", container_name: str = "") -> tuple[list[str], bool]:
    mode = str(runtime.get("nuclei_execution_mode") or runtime.get("nuclei_engine", {}).get("execution_mode") or "native")
    if mode != "docker_official_image":
        return ["nuclei", *args], False
    image = str(runtime.get("nuclei_image") or "projectdiscovery/nuclei:latest")
    _, network_args, _ = docker_target(target_url) if target_url else ("", [], "")
    command = ["docker", "run", "--rm"]
    if container_name:
        command += ["--name", container_name]
    command += [*network_args, "-v", f"{work.resolve()}:/work"]
    inventory = runtime.get("nuclei_templates") if isinstance(runtime.get("nuclei_templates"), dict) else {}
    template_dir = Path(str(inventory.get("directory") or "")).expanduser()
    if template_dir.is_dir():
        resolved = template_dir.resolve()
        command += ["-v", f"{resolved}:/root/nuclei-templates:ro", "-v", f"{resolved}:/official-templates:ro"]
    if CUSTOM_TEMPLATE_DIR.is_dir():
        command += ["-v", f"{CUSTOM_TEMPLATE_DIR.resolve()}:/secops-templates:ro"]
    return [*command, image, *args], True


def _run_phase(
    name: str, target_url: str, runtime: dict[str, Any], work: Path, input_path: Path, output_path: Path, timeout: int,
    settings: dict[str, int], cookies: str, *, automatic: bool = False, dast: bool = False, custom: bool = False,
    broad: bool = False, official_http: bool = False, tags: str = "", exclude_tags: str = "",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    docker = str(runtime.get("nuclei_execution_mode") or runtime.get("nuclei_engine", {}).get("execution_mode") or "native") == "docker_official_image"
    cli_input = f"/work/{input_path.name}" if docker else str(input_path)
    cli_output = f"/work/{output_path.name}" if docker else str(output_path)
    args = [
        "-l", cli_input, "-jsonl", "-silent", "-nc", "-o", cli_output, "-duc", "-no-stdin",
        "-c", str(settings["c"]), "-bs", str(settings["bs"]), "-pc", str(settings["pc"]),
        "-rl", str(settings["rl"]), "-timeout", str(settings["timeout"]), "-retries", "0",
    ]
    if cookies:
        args += ["-H", f"Cookie: {cookies}"]
    if automatic:
        args += ["-as"]
    if dast:
        args += ["-im", "jsonl", "-dast", "-fuzzing-mode", "single"]
    if custom:
        args += ["-t", "/secops-templates" if docker else str(CUSTOM_TEMPLATE_DIR)]
    if official_http:
        inventory = runtime.get("nuclei_templates") if isinstance(runtime.get("nuclei_templates"), dict) else {}
        root = Path(str(inventory.get("directory") or "")).expanduser()
        # Use the official repository layout directly instead of combining a
        # broad http/ tree with protocol/tag filters. This is both cheaper and
        # compatible with Nuclei versions where filter combinations can fail
        # before execution.
        selected = [path for path in (root / "http" / "exposures", root / "http" / "misconfiguration") if path.is_dir()]
        if selected:
            for path in selected:
                template = f"/official-templates/{path.relative_to(root).as_posix()}" if docker else str(path)
                args += ["-t", template]
        else:
            official_dir = root / "http" if (root / "http").is_dir() else root
            args += ["-t", "/official-templates/http" if docker and (root / "http").is_dir() else "/official-templates" if docker else str(official_dir)]
            tags = tags or "exposure,misconfig,config"
    if tags:
        args += ["-tags", tags]
    if exclude_tags:
        args += ["-etags", exclude_tags]
    if broad:
        args += ["-severity", "info,low,medium,high,critical"]
    container_name = docker_container_name(f"nuclei-{name}") if docker else ""
    command, _ = _command(runtime, work, args, target_url, container_name)
    try:
        result = run_process("Nuclei", command, target=target_url, timeout=max(20, timeout), cwd=Path(ROOT_DIR), accepted_codes=(0, 1))
    finally:
        if container_name:
            cleanup_docker_container(container_name)
    process_text = "\n".join(str(result.get(key, "")) for key in ("stdout", "stderr", "output"))
    if int(result.get("return_code") or 0) == 1 and re.search(r"(?:\[FTL\]|fatal:|could not run nuclei)", process_text, re.I):
        result["status"] = "error"
        result["diagnosis"] = "nuclei_runtime_error"
    items: list[dict[str, Any]] = []
    if output_path.is_file():
        for line in output_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    items.append(value)
            except json.JSONDecodeError:
                pass
    phase = {
        "phase": name, "status": result.get("status"), "diagnosis": result.get("diagnosis", ""),
        "duration_seconds": result.get("duration_seconds"), "phase_findings": len(items), "phase_timeout_seconds": timeout,
        "automatic_scan": automatic, "dast": dast, "input_mode": "jsonl" if dast else "list",
        "selected_template_count": 0 if automatic or broad or dast or official_http else len(list(CUSTOM_TEMPLATE_DIR.glob("*.yaml"))),
        "selected_template_sample": [p.name for p in list(CUSTOM_TEMPLATE_DIR.glob("*.yaml"))[:8]] if custom else [],
        "stderr_excerpt": str(result.get("stderr", ""))[-1200:], "stdout": str(result.get("stdout", ""))[-4000:],
        "stderr": str(result.get("stderr", ""))[-4000:], "command": result.get("command", command),
        "timed_out": result.get("diagnosis") == "timeout",
        "engine_mode": "official_docker" if docker else "official_native_cli",
    }
    return phase, items


def _finding(item: dict[str, Any], target_url: str) -> dict[str, Any]:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    severity = str(info.get("severity") or item.get("severity") or "info").lower()
    matched = _externalize_url(str(item.get("matched-at") or item.get("host") or target_url), target_url)
    template_id = str(item.get("template-id") or item.get("templateID") or "nuclei")
    name = str(info.get("name") or template_id)
    extracted = item.get("extracted-results") if isinstance(item.get("extracted-results"), list) else []
    return {
        "alert": name, "risk": severity, "category": "observation" if severity == "info" else "candidate",
        "verification_status": "nuclei-template-match", "confidence": "high", "description": str(info.get("description") or "").strip(),
        "impact": str(info.get("impact") or "").strip(), "solution": str(info.get("remediation") or "").strip(),
        "url": matched, "template_id": template_id, "matcher_name": str(item.get("matcher-name") or ""),
        "type": str(item.get("type") or ""), "extracted_results": extracted, "evidence": json.dumps(item, ensure_ascii=False, default=str)[:12000],
        "references": info.get("reference") if isinstance(info.get("reference"), list) else [],
    }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result, seen = [], set()
    for item in items:
        key = (str(item.get("template-id") or ""), str(item.get("matched-at") or item.get("host") or ""), str(item.get("matcher-name") or ""))
        if key not in seen:
            seen.add(key); result.append(item)
    return result


@mcp.tool()
def run_nuclei_scan(
    target_url: str, cookies: str = "", timeout: int = 180, output_file: str = "",
    seed_urls: list[str] | None = None, max_targets: int = 4,
    scan_profile: str = "balanced", request_cases: list[dict[str, Any]] | None = None,
) -> dict:
    """Drive the official Nuclei engine with automatic scan, JSONL output and request-shaped DAST input."""
    try:
        scan_profile, settings = _profile(scan_profile)
    except ValueError as exc:
        return failure("Nuclei", target_url, str(exc))
    timeout = max(35, min(int(timeout), 600))
    runtime = _runtime()
    inventory = runtime.get("nuclei_templates") if isinstance(runtime.get("nuclei_templates"), dict) else {}
    if int(inventory.get("count") or 0) <= 0:
        result = failure("Nuclei", target_url, "No initialized official Nuclei template inventory was found. Run initScript.py again.", diagnosis="nuclei_templates_missing")
        result["template_inventory"] = inventory
        return result

    cap = 4 if scan_profile == "fast" else 6 if scan_profile == "balanced" else 16
    targets = _focused_targets(target_url, seed_urls, max(1, min(int(max_targets), cap)))
    dast_cases = _dast_cases(target_url, request_cases, 3) if scan_profile == "deep" else []
    temporary = tempfile.TemporaryDirectory(prefix="nuclei-api-first-")
    work = Path(temporary.name)
    target_list = work / "targets.txt"
    docker = str(runtime.get("nuclei_execution_mode") or runtime.get("nuclei_engine", {}).get("execution_mode") or "native") == "docker_official_image"
    target_list.write_text("\n".join(_containerize_url(v) if docker else v for v in targets) + "\n", encoding="utf-8")
    request_log = work / "requests.jsonl"
    dast_count = _write_proxify_jsonl(request_log, dast_cases, cookies, docker) if dast_cases else 0

    # Balanced mode deliberately leaves injection fuzzing to the specialist
    # scanners.  Nuclei covers project evidence plus official exposure/
    # misconfiguration templates; automatic scan and DAST remain available in
    # deep mode.  This keeps broad coverage without monopolising the DVWA worker.
    phases_spec = [("direct_evidence", dict(custom=True))]
    if scan_profile == "balanced":
        phases_spec.append(("official_exposure_misconfig", dict(official_http=True)))
    elif scan_profile == "deep":
        phases_spec.append(("automatic", dict(automatic=True)))
        if dast_count:
            phases_spec.append(("dast", dict(dast=True)))
        phases_spec.append(("broad_templates", dict(broad=True, exclude_tags="dos")))

    phases, all_items = [], []
    per_phase = max(20, int(timeout / max(1, len(phases_spec))))
    try:
        for index, (name, flags) in enumerate(phases_spec):
            input_path = request_log if flags.get("dast") else target_list
            output_path = work / f"{index}-{name}.jsonl"
            phase_budget = min(per_phase, 35) if scan_profile == "balanced" else per_phase
            phase, items = _run_phase(name, target_url, runtime, work, input_path, output_path, phase_budget, settings, cookies, **flags)
            phases.append(phase); all_items.extend(items)
        all_items = _dedupe(all_items)
        findings = [_finding(item, target_url) for item in all_items]
        if output_file:
            destination = Path(output_file).expanduser().resolve(); destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("\n".join(json.dumps(item, ensure_ascii=False, default=str) for item in all_items) + ("\n" if all_items else ""), encoding="utf-8")
        hard = [p for p in phases if p.get("status") == "error"]
        limited = [p for p in phases if p.get("timed_out")]
        summary = [{
            "name": p.get("phase"), "status": p.get("status"), "diagnosis": p.get("diagnosis", ""),
            "duration_seconds": p.get("duration_seconds"), "findings": p.get("phase_findings", 0),
            "timeout_seconds": p.get("phase_timeout_seconds"), "automatic_scan": p.get("automatic_scan", False),
            "dast": p.get("dast", False), "input_mode": p.get("input_mode", ""), "selected_template_count": p.get("selected_template_count", 0),
            "selected_template_sample": p.get("selected_template_sample", []), "stderr_excerpt": p.get("stderr_excerpt", ""), "command": p.get("command", []),
        } for p in phases]
        common = {
            "vulnerabilities": findings, "authenticated": bool(cookies), "phases": summary, "scan_profile": scan_profile,
            "scan_scope": f"Official Nuclei engine + structured JSONL output; profile={scan_profile}; static_targets={len(targets)}; dast_request_cases={dast_count if scan_profile == 'deep' else 0}.",
            "focused_targets": targets, "evidence_targets": targets, "custom_template_count": len(list(CUSTOM_TEMPLATE_DIR.glob("*.yaml"))),
            "custom_template_directory": str(CUSTOM_TEMPLATE_DIR), "dast_targets": [str(c.get("url") or "") for c in dast_cases],
            "dast_request_cases": [{"url": c.get("url", ""), "method": c.get("method", "GET"), "parameters": c.get("parameters", [])} for c in dast_cases],
            "dast_request_count": dast_count, "dast_input_mode": "jsonl" if dast_count else "list",
            "dast_template_directory": str(inventory.get("directory") or ""),
            "technology_fingerprint": {"source": "nuclei-automatic-scan" if scan_profile == "deep" else "nuclei-filtered-official-templates", "tags": []},
            "template_catalog_count": int(inventory.get("count") or 0), "template_selection_strategy": "official-nuclei-engine",
            "template_inventory": inventory, "template_refresh": {}, "hard_failure": bool(hard), "output_file": str(output_file or ""),
            "execution_mode": "official_docker_cli" if docker else "official_native_cli",
        }
        if len(hard) == len(phases) and not findings:
            result = failure("Nuclei", target_url, "Every official Nuclei phase failed before producing parseable findings.", diagnosis="nuclei_phases_failed")
            result.update(common); return result
        if hard or limited:
            return partial("Nuclei", target_url, f"Official Nuclei scan ended with incomplete coverage. Findings preserved: {len(findings)}.", diagnosis="time_limit_reached" if limited and not hard else "partial_scan", timed_out=bool(limited), time_limit_reached=bool(limited), **common)
        return success("Nuclei", target_url, f"Official {scan_profile} Nuclei scan completed. Findings: {len(findings)}.", timed_out=False, time_limit_reached=False, **common)
    finally:
        temporary.cleanup()


if __name__ == "__main__":
    _serve()
