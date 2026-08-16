from __future__ import annotations

import csv
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from scannerCommon import cleanup_docker_container, docker_container_name, docker_target, service
from utils import ROOT_DIR, failure, load_runtime_config, parse_cookie_header, partial, run_process, success, trim_process_output

mcp, _serve = service("Nikto Scanner", "nikto")
NIKTO_IMAGE = "ghcr.io/sullo/nikto:latest"
PROFILES: dict[str, dict[str, Any]] = {
    "fast": {"tuning": "123b", "cgi": "none", "display": "VP", "minimum": 20},
    "balanced": {"tuning": "x6", "cgi": "none", "display": "VP", "minimum": 80},
    "deep": {"tuning": "x6", "cgi": "all", "display": "VP", "minimum": 200},
}


def _profile(value: str) -> tuple[str, dict[str, Any]]:
    name = str(value or "balanced").strip().lower()
    if name not in PROFILES:
        name = "balanced"
    return name, PROFILES[name]


def _cookie_args(cookies: str) -> list[str]:
    if not str(cookies or "").strip():
        return ["-nocookies"]
    encoded = []
    for name, value in parse_cookie_header(cookies):
        if '"' in value:
            raise ValueError(f"Nikto STATIC-COOKIE cannot safely encode a quote in cookie {name!r}.")
        encoded.append(f'"{name}={value}"')
    return ["-Option", f"STATIC-COOKIE={';'.join(encoded)};"]


def _redact(command: list[str]) -> list[str]:
    return ["STATIC-COOKIE=<redacted>" if str(v).startswith("STATIC-COOKIE=") else str(v) for v in command]


def _baseline(target_url: str, cookies: str) -> dict[str, Any]:
    headers = {"Cookie": cookies, "Cache-Control": "no-cache"} if cookies else {"Cache-Control": "no-cache"}
    try:
        response = requests.get(target_url, headers=headers, timeout=(3, 5), allow_redirects=True)
    except requests.RequestException as exc:
        return {"performed": True, "reachable": False, "error": f"{type(exc).__name__}: {exc}", "signal_count": 0}
    lower_headers = {k.lower(): v for k, v in response.headers.items()}
    wanted = ("x-frame-options", "x-content-type-options", "content-security-policy", "referrer-policy")
    missing = [name for name in wanted if name not in lower_headers]
    server = response.headers.get("Server", "")
    return {
        "performed": True, "reachable": True, "status": response.status_code, "final_url": str(response.url),
        "server": server, "missing_security_headers": missing, "signal_count": len(missing) + bool(server),
    }


def _risk(message: str) -> str:
    low = message.lower()
    if any(v in low for v in ("shellshock", "remote code", "command execution", "sql injection", "file upload")):
        return "high"
    if any(v in low for v in ("x-frame-options", "x-content-type-options", "content-security-policy", "referrer-policy", "information disclosure", "directory indexing", "allowed http methods")):
        return "low"
    return "medium" if any(v in low for v in ("outdated", "vulnerable", "exposed", "found", "retrieved")) else "info"


def _guidance(message: str) -> tuple[str, str]:
    low = message.lower()
    if "header" in low or any(v in low for v in ("x-frame-options", "content-security-policy", "referrer-policy")):
        return "Missing or weak response headers can reduce browser-side hardening.", "Configure the indicated security header with an application-appropriate policy."
    if "directory" in low or "file" in low:
        return "Exposed server paths or files may disclose sensitive implementation details or data.", "Remove unnecessary public files and restrict access to sensitive paths."
    if "outdated" in low or "version" in low:
        return "Version disclosure or outdated components can help attackers select known exploits.", "Update supported server components and reduce unnecessary version disclosure."
    return "The reported server behaviour may increase attack surface depending on deployment context.", "Review the affected endpoint and apply the remediation recommended by the upstream Nikto finding."


def _parse_csv(path: Path, target_url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not path.is_file():
        return findings
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) < 7 or not row or row[0].strip().lower().startswith(("nikto", "host")):
                continue
            reference, method, uri, message = row[3].strip(), row[4].strip(), row[5].strip(), row[6].strip()
            if not message:
                continue
            risk = _risk(message); impact, solution = _guidance(message)
            url = uri if uri.startswith(("http://", "https://")) else urljoin(target_url.rstrip("/") + "/", uri.lstrip("/"))
            findings.append({
                "alert": message.split(".", 1)[0].strip()[:140] or "Nikto web-server finding", "risk": risk,
                "category": "observation" if risk == "info" else "candidate",
                "verification_status": "hardening-observation" if risk == "info" else "nikto-structured-candidate",
                "confidence": "medium", "description": f"Nikto reported: {message}", "impact": impact, "solution": solution,
                "url": url or target_url, "method": method, "reference": reference, "references": [reference] if reference else [],
                "technical_details": f"Parsed from Nikto's official CSV report; method={method or 'not specified'}.",
                "evidence": message, "parser_sources": ["csv"],
            })
    return findings


def _parse_console(text: str, target_url: str) -> list[dict[str, Any]]:
    findings = []
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line.startswith("+"):
            continue
        message = line.lstrip("+ ").strip()
        low = message.lower()
        if not message or any(low.startswith(v) for v in ("target ip:", "target hostname:", "target port:", "start time:", "end time:", "server:", "error:")):
            continue
        if any(v in low for v in ("host(s) tested", "item(s) reported", "requests:", "unknown option", "permission denied", "unable to connect", "connection refused")):
            continue
        uri_match = re.match(r"(/[^: ]*)\s*:\s*(.*)", message)
        uri, description = (uri_match.group(1), uri_match.group(2)) if uri_match else ("", message)
        risk = _risk(description); impact, solution = _guidance(description)
        findings.append({
            "alert": description.split(".", 1)[0][:140] or "Nikto finding", "risk": risk,
            "category": "observation" if risk == "info" else "candidate", "verification_status": "nikto-console-candidate",
            "confidence": "medium", "description": f"Nikto reported: {description}", "impact": impact, "solution": solution,
            "url": urljoin(target_url.rstrip("/") + "/", uri.lstrip("/")) if uri else target_url, "method": "GET",
            "technical_details": "Parsed from Nikto console output.", "evidence": message, "parser_sources": ["console"],
        })
    return findings


def _dedupe(groups: list[list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], int]:
    result, seen, raw = [], set(), 0
    for group in groups:
        raw += len(group)
        for item in group:
            key = (str(item.get("url") or ""), str(item.get("alert") or "").lower(), str(item.get("method") or ""))
            if key not in seen:
                seen.add(key); result.append(item)
    return result, raw - len(result)


def _metrics(text: str) -> dict[str, int]:
    def value(pattern: str) -> int:
        match = re.search(pattern, text, re.I)
        return int(match.group(1)) if match else 0
    return {
        "requests": value(r"(\d+)\s+requests"), "items_reported": value(r"(\d+)\s+item\(s\) reported"),
        "hosts_tested": value(r"(\d+)\s+host\(s\) tested"), "errors": value(r"(\d+)\s+error\(s\)"),
    }


def _command(target_url: str, cookies: str, profile: dict[str, Any], timeout: int, work: Path, force_docker: bool = False) -> tuple[list[str], Path, str]:
    runtime = load_runtime_config()
    report = work / "nikto.csv"
    common = [
        "-h", target_url, "-nointeractive", "-ask", "no", "-followredirects", "-timeout", "4", "-maxtime", f"{max(25, timeout - 25)}s",
        "-Format", "csv", "-o", str(report), "-Tuning", str(profile["tuning"]), "-Display", str(profile["display"]),
    ]
    if str(profile["cgi"]).lower() != "none":
        common += ["-Cgidirs", str(profile["cgi"])]
    common += _cookie_args(cookies)
    mode = str(runtime.get("nikto_execution_mode") or "native")
    if force_docker or mode == "docker_official_image":
        docker_report = "/work/nikto.csv"
        common[common.index(str(report))] = docker_report
        translated, network_args, _route_mode = docker_target(target_url)
        common[common.index(target_url)] = translated
        command = [
            "docker", "run", "--rm", "--name", docker_container_name("nikto"), *network_args,
            "-v", f"{work.resolve()}:/work", str(runtime.get("nikto_image") or NIKTO_IMAGE), *common,
        ]
        return command, report, "official_docker_image"
    perl, script = str(runtime.get("nikto_perl") or ""), str(runtime.get("nikto_script") or "")
    if perl and script and Path(perl).is_file() and Path(script).is_file():
        return [perl, script, *common], report, "official_native_perl"
    return ["nikto", *common], report, "official_native_cli"


def _execute(command: list[str], target_url: str, timeout: int) -> dict[str, Any]:
    container_name = ""
    if command and Path(command[0]).name.lower() in {"docker", "docker.exe"} and "--name" in command:
        index = command.index("--name")
        if index + 1 < len(command):
            container_name = command[index + 1]
    try:
        return run_process("Nikto", command, target=target_url, timeout=timeout, cwd=Path(ROOT_DIR))
    finally:
        if container_name:
            cleanup_docker_container(container_name)


@mcp.tool()
def run_nikto_scan(target_url: str, cookies: str = "", timeout: int = 180, scan_profile: str = "balanced") -> dict:
    """Run the official Nikto scanner and consume its structured CSV report."""
    timeout = max(60, min(int(timeout), 600))
    scan_profile, profile = _profile(scan_profile)
    # The Python probe is diagnostic only. A temporarily busy target must not prevent
    # the official scanner (or its Docker fallback) from getting its own chance to run.
    baseline = _baseline(target_url, cookies)
    try:
        parse_cookie_header(cookies)
    except ValueError as exc:
        return failure("Nikto", target_url, f"Invalid Cookie header: {exc}", diagnosis="invalid_cookie_header")

    with tempfile.TemporaryDirectory(prefix="nikto-api-first-") as tmp:
        work = Path(tmp)
        try:
            command, report, mode = _command(target_url, cookies, profile, timeout, work)
        except ValueError as exc:
            return failure("Nikto", target_url, str(exc), diagnosis="invalid_cookie_header")
        result = _execute(command, target_url, timeout)
        fallback_used = False
        if result.get("status") != "success" and result.get("diagnosis") != "timeout" and mode != "official_docker_image" and shutil.which("docker"):
            docker_command, report, mode = _command(target_url, cookies, profile, timeout, work, force_docker=True)
            retry = _execute(docker_command, target_url, timeout)
            if retry.get("status") == "success" or retry.get("diagnosis") == "timeout":
                result, command, fallback_used = retry, docker_command, True
        text = "\n".join(str(result.get(k, "")) for k in ("stdout", "stderr", "output"))
        csv_findings = _parse_csv(report, target_url)
        console_findings = _parse_console(text, target_url)
        findings, duplicates = _dedupe([csv_findings, console_findings])
        metrics = _metrics(text)
        report_bytes = report.stat().st_size if report.is_file() else 0
        coverage_verified = result.get("status") == "success" and (metrics["requests"] > 0 or report_bytes > 0)
        common = {
            "vulnerabilities": findings, "execution_mode": mode, "scan_profile": scan_profile, "plugins": "official-default",
            "safe_tuning": profile["tuning"], "cgi_dirs": profile["cgi"], "baseline_probe": baseline, "scan_metrics": metrics,
            "raw_parsed_findings": len(csv_findings) + len(console_findings), "cross_source_duplicates_removed": duplicates,
            "parser_count_consistent": True, "coverage_verified": coverage_verified, "zero_result_verified": coverage_verified and not findings,
            "structured_report": {"copied": report.is_file(), "bytes": report_bytes, "console_only": not report.is_file(), "path": str(report) if report.is_file() else "", "attempts": []},
            "structured_retry": {"used": fallback_used, "reason": "native_to_official_docker" if fallback_used else ""}, "docker_create": {"return_code": result.get("return_code")},
            "docker_state": {"available": mode == "official_docker_image", "ExitCode": result.get("return_code"), "Error": ""},
            "command": _redact(list(result.get("command") or command)), "duration_seconds": result.get("duration_seconds"),
            "stdout": str(result.get("stdout", ""))[-12000:], "stderr": str(result.get("stderr", ""))[-12000:],
        }
        if result.get("diagnosis") == "timeout":
            return partial("Nikto", target_url, f"Nikto reached its configured time budget. Findings preserved: {len(findings)}.", diagnosis="time_limit_reached", timed_out=True, time_limit_reached=True, **common)
        if result.get("status") != "success":
            out = failure("Nikto", target_url, str(result.get("output") or "Nikto execution failed."), diagnosis=str(result.get("diagnosis") or "nikto_execution_failed"))
            out.update(common); return trim_process_output(out, 12000)
        return success("Nikto", target_url, f"Official Nikto scan completed. Findings: {len(findings)}; requests={metrics['requests']}; profile={scan_profile}.", timed_out=False, time_limit_reached=False, **common)


if __name__ == "__main__":
    _serve()
