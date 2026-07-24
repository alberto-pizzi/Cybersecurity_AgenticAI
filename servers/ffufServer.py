from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from fastmcp import FastMCP

from utils import WORDLISTS_DIR, failure, partial, run_process, success

mcp = FastMCP("FFUF Scanner")

PRIORITY_PATHS = (
    ".env", ".git/HEAD", "config", "config.php", "configuration.php", "settings.php",
    "backup", "backup.zip", "backup.sql", "database.sql", "dump.sql", "db.sql",
    "admin", "administrator", "login", "debug", "phpinfo.php", "server-status",
    "setup.php", "install.php", "api", "swagger", "swagger.json", "openapi.json",
    "actuator", "actuator/env", "actuator/health", "web.config", "composer.json",
    "robots.txt", ".well-known/security.txt", "uploads", "logs", "error.log",
)
SENSITIVE_NAMES = {".env", ".git", "backup", "config", "debug", "server-status", "setup.php", "phpinfo.php", "admin", "administrator"}


def _read_json(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return [item for item in value.get("results", []) if isinstance(item, dict)] if isinstance(value, dict) else []
    except (OSError, json.JSONDecodeError):
        return []


def _run_phase(target_url: str, cookies: str, wordlist: Path, output: Path, budget: int, name: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    command = ["ffuf", "-u", f"{target_url.rstrip('/')}/FUZZ", "-w", str(wordlist), "-of", "json", "-o", str(output), "-ac", "-t", "20", "-timeout", "7", "-maxtime", str(max(10,budget)), "-noninteractive"]
    if cookies: command.extend(["-b", cookies])
    result = run_process("FFUF", command, target=target_url, timeout=max(20,budget+15))
    rows = _read_json(output)
    if result.get("diagnosis") == "timeout":
        result.update(status="partial", diagnosis="time_limit_reached", timed_out=True, output=f"FFUF phase '{name}' reached its time budget. Resources preserved: {len(rows)}.")
    result.update(phase=name, phase_findings=len(rows), phase_timeout_seconds=budget)
    return result, rows


def _verify(url: str, cookies: str) -> tuple[str, str, str, str]:
    path = urlparse(url).path.lower()
    headers = {"Cookie": cookies} if cookies else {}
    try:
        response = requests.get(url, headers=headers, timeout=(3,6), allow_redirects=True)
        sample = response.text[:12000]
    except requests.RequestException:
        return "candidate", "medium", "Potentially sensitive resource exposed", "The resource should be manually verified."
    lower = sample.lower()
    if path.endswith("/.git/head") and sample.lstrip().startswith("ref:"):
        return "vulnerability", "high", "Exposed Git repository metadata", "The Git HEAD reference was retrieved and may permit repository reconstruction."
    if path.endswith("/.env") and any(token in lower for token in ("password=", "secret=", "api_key=", "db_host=", "db_password=")):
        return "vulnerability", "high", "Environment secrets file exposed", "The response resembles an environment file containing secret-bearing keys."
    if "phpinfo" in path and "php version" in lower:
        return "vulnerability", "medium", "PHP diagnostic page exposed", "A PHP information page discloses detailed runtime and server configuration."
    if path.endswith("server-status") and "apache server status" in lower:
        return "vulnerability", "medium", "Apache server-status exposed", "The Apache status page discloses operational details and active requests."
    return "candidate", "medium", "Potentially sensitive resource exposed", "The resource returned a reachable response but requires manual content validation."


def _finding(item: dict[str, Any], cookies: str, verify: bool) -> dict[str, Any]:
    url = str(item.get("url", "")); status = int(item.get("status") or 0)
    name = Path(urlparse(url).path.rstrip("/")).name.lower(); full_path = urlparse(url).path.lower()
    sensitive = name in SENSITIVE_NAMES or any(token in full_path for token in ("/.git/", ".env", "backup", "dump.sql", "database.sql", "phpinfo", "server-status", "actuator/env"))
    if sensitive and status in {200,301,302,307,401,403}:
        category, risk, alert, impact = _verify(url, cookies) if verify and status == 200 else ("candidate","medium","Potentially sensitive resource exposed","The path may expose administrative, diagnostic, configuration, or backup content.")
        solution = "Remove deployment artifacts and secrets, restrict administrative/diagnostic paths, and verify authorization controls."
    else:
        category, risk, alert = "discovery", "info", "Discovered web resource"
        impact = "The resource expands the known attack surface for subsequent crawling and testing."
        solution = "Confirm the resource is intended to be reachable and include it in application security testing."
    return {"alert":alert,"risk":risk,"category":category,"description":f"FFUF received HTTP {status} ({item.get('length',0)} bytes, {item.get('words',0)} words, {item.get('lines',0)} lines).","impact":impact,"solution":solution,"url":url,"status_code":status,"content_length":item.get("length"),"words":item.get("words"),"lines":item.get("lines"),"redirect_location":item.get("redirectlocation", ""),"confidence":"high" if category=="vulnerability" else "medium","evidence":f"HTTP {status}; length={item.get('length')}; words={item.get('words')}; lines={item.get('lines')}"}


@mcp.tool()
def run_ffuf_fuzz(target_url: str, cookies: str="", wordlist: str="", timeout: int=120) -> dict:
    """Check high-value paths first, then use the compact project wordlist with the remaining budget."""
    timeout = max(45, min(int(timeout), 300))
    general = Path(wordlist) if wordlist else WORDLISTS_DIR/"common.txt"
    if not general.exists(): return failure("FFUF", target_url, f"Wordlist not found: {general}", diagnosis="missing_wordlist")
    priority_budget = min(40, max(20, timeout//3)); general_budget = max(20, timeout-priority_budget)
    with tempfile.TemporaryDirectory(prefix="ffuf-priority-") as td:
        temp=Path(td); priority=temp/"priority.txt"; filtered=temp/"general.txt"
        priority.write_text("\n".join(PRIORITY_PATHS)+"\n", encoding="utf-8")
        priority_set={value.lower() for value in PRIORITY_PATHS}
        lines=[line.strip() for line in general.read_text(encoding="utf-8",errors="replace").splitlines() if line.strip() and not line.lstrip().startswith("#") and line.strip().lower() not in priority_set]
        filtered.write_text("\n".join(lines)+"\n", encoding="utf-8")
        phases=[]; rows=[]
        for name,wl,budget in (("high_value_paths",priority,priority_budget),("compact_general_discovery",filtered,general_budget)):
            output=temp/f"{name}.json"; phase,found=_run_phase(target_url,cookies,wl,output,budget,name); phases.append(phase); rows.extend(found)
        unique={}
        for item in rows: unique[(str(item.get("url","")),int(item.get("status") or 0))]=item
        ordered=list(unique.values())
        findings=[_finding(item,cookies,index<12) for index,item in enumerate(ordered)]
        hard=[p for p in phases if p.get("status")=="error"]; limited=[p for p in phases if p.get("status")=="partial"]
        common={"vulnerabilities":findings,"discovered_urls":[f["url"] for f in findings if f.get("url")],"authenticated":bool(cookies),"hard_failure":bool(hard),"phases":[{"name":p.get("phase"),"status":p.get("status"),"findings":p.get("phase_findings",0),"timeout_seconds":p.get("phase_timeout_seconds")} for p in phases]}
        if len(hard)==len(phases) and not findings: return failure("FFUF",target_url,"Both FFUF phases failed before producing parseable results.") | common
        if hard or limited: return partial("FFUF",target_url,f"FFUF completed with incomplete coverage. Resources preserved: {len(findings)}.",diagnosis="time_limit_reached" if limited and not hard else "partial_scan",timed_out=bool(limited),**common)
        return success("FFUF",target_url,f"FFUF completed. Resources: {len(findings)}.",**common)


def _once() -> int:
    try:
        arguments = json.loads(os.sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = run_ffuf_fuzz(**arguments)
    except Exception as exc:
        result = failure("FFUF", "", f"One-shot FFUF execution failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio")