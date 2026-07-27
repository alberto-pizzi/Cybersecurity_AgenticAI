from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import time
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

# These paths can mutate or invalidate an authenticated application session.
# They remain discoverable anonymously but are removed from authenticated FFUF
# wordlists before the scanner starts.
DESTRUCTIVE_AUTH_PATH_TOKENS = {
    "logout", "signout", "logoff", "setup", "install", "reset",
    "create_db", "create-database", "createdb", "drop_db", "drop-database",
}


def _destructive_authenticated_word(value: str) -> bool:
    normalized = str(value or "").strip().lower().strip("/")
    if not normalized:
        return False
    tokens = {
        token
        for token in re.split(r"[^a-z0-9_-]+", normalized)
        if token
    }
    return bool(tokens & DESTRUCTIVE_AUTH_PATH_TOKENS)


def _looks_like_login_response(response: requests.Response) -> bool:
    text = response.text[:50_000].lower()
    path = urlparse(response.url).path.lower()
    return (
        path.endswith("/login")
        or path.endswith("/login.php")
        or ("type=\"password\"" in text and "login" in text)
        or ("type='password'" in text and "login" in text)
    )


def _session_probe(url: str, cookies: str, attempts: int = 3) -> dict[str, Any]:
    if not url or not cookies:
        return {"performed": False, "authenticated": None, "conclusive": True}
    errors: list[str] = []
    for attempt in range(max(1, attempts)):
        try:
            response = requests.get(
                url,
                headers={"Cookie": cookies, "Cache-Control": "no-cache"},
                timeout=(4, 14),
                allow_redirects=True,
            )
            login = _looks_like_login_response(response)
            return {
                "performed": True,
                "authenticated": response.status_code < 400 and not login,
                "conclusive": True,
                "transient_error": False,
                "status": response.status_code,
                "final_url": str(response.url),
                "login_detected": login,
                "attempt_errors": errors,
            }
        except (requests.Timeout, requests.ConnectionError) as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            if attempt + 1 < attempts:
                time.sleep(0.8 * (attempt + 1))
        except requests.RequestException as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            break
    return {
        "performed": True,
        "authenticated": None,
        "conclusive": False,
        "transient_error": True,
        "errors": errors,
        "error": errors[-1] if errors else "request failed",
    }

def _read_json(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return [item for item in value.get("results", []) if isinstance(item, dict)] if isinstance(value, dict) else []
    except (OSError, json.JSONDecodeError):
        return []


def _run_phase(target_url: str, cookies: str, wordlist: Path, output: Path, budget: int, name: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    command = ["ffuf", "-u", f"{target_url.rstrip('/')}/FUZZ", "-w", str(wordlist), "-of", "json", "-o", str(output), "-ac", "-t", "30", "-timeout", "4", "-maxtime", str(max(10,budget)), "-noninteractive"]
    if cookies: command.extend(["-b", cookies])
    result = run_process("FFUF", command, target=target_url, timeout=max(20,budget+15))
    rows = _read_json(output)
    if result.get("diagnosis") == "timeout":
        result.update(status="partial", diagnosis="time_limit_reached", timed_out=True, output=f"FFUF phase '{name}' reached its time budget. Resources preserved: {len(rows)}.")
    result.update(phase=name, phase_findings=len(rows), phase_timeout_seconds=budget)
    return result, rows


def _verify(url: str, cookies: str) -> dict[str, Any]:
    """
    Verify a sensitive-looking FFUF path before classifying it.

    Redirects to login pages, 401/403 responses, and failed verification are not
    reported as exposed medium-severity resources.
    """
    original_path = urlparse(url).path.lower()
    headers = {"Cookie": cookies} if cookies else {}
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=(3, 7),
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return {
            "category": "observation",
            "risk": "info",
            "alert": "Sensitive-looking path could not be verified",
            "verification_status": "verification-request-failed",
            "description": "FFUF discovered a sensitive-looking path, but the follow-up verification request failed.",
            "impact": "",
            "solution": "",
            "confidence": "low",
            "final_url": "",
            "final_status": 0,
            "evidence": f"Verification request failed: {type(exc).__name__}: {exc}",
        }

    final_url = str(response.url)
    final_path = urlparse(final_url).path.lower()
    sample = response.text[:20000]
    lower = sample.lower()
    evidence = (
        f"Original URL: {url}\nFinal URL: {final_url}\n"
        f"Final HTTP status: {response.status_code}\n"
        f"Response bytes sampled: {len(sample.encode('utf-8', errors='replace'))}"
    )

    login_page = (
        final_path.endswith("/login")
        or final_path.endswith("/login.php")
        or ('type="password"' in lower and "login" in lower)
        or ("type='password'" in lower and "login" in lower)
    )
    if login_page and final_url.rstrip("/") != url.rstrip("/"):
        return {
            "category": "observation",
            "risk": "info",
            "alert": "Sensitive-looking path redirected to authentication",
            "verification_status": "access-controlled-or-session-redirect",
            "description": "The discovered path redirected to a login page during verification; exposure was not confirmed.",
            "impact": "",
            "solution": "",
            "confidence": "high",
            "final_url": final_url,
            "final_status": response.status_code,
            "evidence": evidence,
        }

    if response.status_code in {401, 403}:
        return {
            "category": "observation",
            "risk": "info",
            "alert": "Sensitive-looking path is access controlled",
            "verification_status": "access-control-observed",
            "description": f"The verification request returned HTTP {response.status_code}; public exposure was not demonstrated.",
            "impact": "",
            "solution": "",
            "confidence": "high",
            "final_url": final_url,
            "final_status": response.status_code,
            "evidence": evidence,
        }

    if response.status_code >= 400:
        return {
            "category": "discovery",
            "risk": "info",
            "alert": "FFUF path not confirmed by verification",
            "verification_status": "verification-negative",
            "description": f"The follow-up request returned HTTP {response.status_code}; the initial FFUF match was not treated as an exposure.",
            "impact": "",
            "solution": "",
            "confidence": "high",
            "final_url": final_url,
            "final_status": response.status_code,
            "evidence": evidence,
        }

    if original_path.endswith("/.git/head") and sample.lstrip().startswith("ref:"):
        return {
            "category": "vulnerability",
            "risk": "high",
            "alert": "Exposed Git repository metadata",
            "verification_status": "content-verified",
            "description": "The .git/HEAD reference was retrieved from the web server.",
            "impact": "Accessible Git metadata can permit reconstruction of repository contents, including source code and historical secrets.",
            "solution": "Remove the .git directory from the web root, block access to repository metadata, and rotate any exposed credentials.",
            "confidence": "high",
            "final_url": final_url,
            "final_status": response.status_code,
            "evidence": evidence + "\nResponse prefix: " + sample[:300],
        }

    if original_path.endswith("/.env") and any(
        token in lower
        for token in ("password=", "secret=", "api_key=", "db_host=", "db_password=")
    ):
        return {
            "category": "vulnerability",
            "risk": "high",
            "alert": "Environment secrets file exposed",
            "verification_status": "content-verified",
            "description": "The response resembles an environment file and contains secret-bearing configuration keys.",
            "impact": "Exposed application secrets may permit database access, API abuse, session forgery, or compromise of dependent services.",
            "solution": "Remove the file from the web root, block dotfile access, rotate every exposed secret, and review access logs.",
            "confidence": "high",
            "final_url": final_url,
            "final_status": response.status_code,
            "evidence": evidence + "\nSecret-bearing key names were detected; values are not copied into the report.",
        }

    if "phpinfo" in original_path and "php version" in lower:
        return {
            "category": "vulnerability",
            "risk": "medium",
            "alert": "PHP diagnostic page exposed",
            "verification_status": "content-verified",
            "description": "A PHP information page was retrieved and disclosed runtime and server configuration details.",
            "impact": "The page can disclose versions, filesystem paths, loaded modules, environment values, and security-relevant configuration.",
            "solution": "Remove or restrict the diagnostic page and review the disclosed values for secrets or unsafe configuration.",
            "confidence": "high",
            "final_url": final_url,
            "final_status": response.status_code,
            "evidence": evidence + "\nPHP information markers were present in the response.",
        }

    if original_path.endswith("server-status") and "apache server status" in lower:
        return {
            "category": "vulnerability",
            "risk": "medium",
            "alert": "Apache server-status exposed",
            "verification_status": "content-verified",
            "description": "The Apache server-status page was retrieved.",
            "impact": "The page can reveal active requests, client addresses, worker state, hostnames, and operational details useful to an attacker.",
            "solution": "Restrict server-status to trusted administrative networks or disable it when it is not required.",
            "confidence": "high",
            "final_url": final_url,
            "final_status": response.status_code,
            "evidence": evidence + "\nApache server-status markers were present.",
        }

    if "<title>index of" in lower or "<h1>index of" in lower:
        return {
            "category": "candidate",
            "risk": "low",
            "alert": "Directory listing reachable",
            "verification_status": "content-verified-directory-index",
            "description": "The response contains a directory index for a sensitive-looking path.",
            "impact": "Directory indexes can reveal file names, backups, source artifacts, and resources that were not intended to be enumerated.",
            "solution": "Disable directory indexing and publish only the files required by the application.",
            "confidence": "high",
            "final_url": final_url,
            "final_status": response.status_code,
            "evidence": evidence + "\nDirectory-index title or heading was detected.",
        }

    if any(token in original_path for token in ("setup", "install")) and (
        "<form" in lower
        and any(token in lower for token in ("setup", "install", "create database", "reset database"))
    ):
        return {
            "category": "candidate",
            "risk": "medium",
            "alert": "Setup or installation interface reachable",
            "verification_status": "content-verified-requires-manual-validation",
            "description": "A setup or installation interface was reachable and contained an actionable form.",
            "impact": "If the interface permits unauthenticated reconfiguration, database reset, or installation actions, application availability or integrity may be affected.",
            "solution": "Disable the interface after deployment or restrict it to authorized administrators and trusted networks.",
            "confidence": "medium",
            "final_url": final_url,
            "final_status": response.status_code,
            "evidence": evidence + "\nSetup/installation form markers were detected.",
        }

    return {
        "category": "discovery",
        "risk": "info",
        "alert": "Sensitive-looking path reachable without verified sensitive content",
        "verification_status": "reachable-content-not-sensitive",
        "description": "The path was reachable, but the verification response did not match a supported sensitive-content signature.",
        "impact": "",
        "solution": "",
        "confidence": "medium",
        "final_url": final_url,
        "final_status": response.status_code,
        "evidence": evidence,
    }


def _finding(item: dict[str, Any], cookies: str, verify: bool) -> dict[str, Any]:
    url = str(item.get("url", ""))
    status = int(item.get("status") or 0)
    parsed = urlparse(url)
    name = Path(parsed.path.rstrip("/")).name.lower()
    full_path = parsed.path.lower()
    sensitive = (
        name in SENSITIVE_NAMES
        or any(
            token in full_path
            for token in (
                "/.git/", ".env", "backup", "dump.sql", "database.sql",
                "phpinfo", "server-status", "actuator/env", "setup", "install",
            )
        )
    )

    base_evidence = (
        f"FFUF HTTP {status}; length={item.get('length')}; "
        f"words={item.get('words')}; lines={item.get('lines')}; "
        f"redirect={item.get('redirectlocation', '') or 'not supplied'}"
    )

    if sensitive and verify:
        verified = _verify(url, cookies)
        return {
            "alert": verified["alert"],
            "risk": verified["risk"],
            "category": verified["category"],
            "verification_status": verified["verification_status"],
            "description": verified["description"],
            "impact": verified["impact"],
            "solution": verified["solution"],
            "url": url,
            "final_url": verified.get("final_url", ""),
            "status_code": status,
            "verification_status_code": verified.get("final_status", 0),
            "content_length": item.get("length"),
            "words": item.get("words"),
            "lines": item.get("lines"),
            "redirect_location": item.get("redirectlocation", ""),
            "confidence": verified["confidence"],
            "evidence": base_evidence + "\n" + verified["evidence"],
        }

    if sensitive:
        return {
            "alert": "Sensitive-looking resource discovered",
            "risk": "info",
            "category": "discovery",
            "verification_status": "not-content-verified",
            "description": "FFUF discovered a sensitive-looking path, but it was outside the bounded content-verification subset.",
            "impact": "",
            "solution": "",
            "url": url,
            "status_code": status,
            "content_length": item.get("length"),
            "words": item.get("words"),
            "lines": item.get("lines"),
            "redirect_location": item.get("redirectlocation", ""),
            "confidence": "low",
            "evidence": base_evidence,
        }

    return {
        "alert": "Discovered web resource",
        "risk": "info",
        "category": "discovery",
        "verification_status": "discovery-only",
        "description": f"FFUF received HTTP {status} for this resource.",
        "impact": "",
        "solution": "",
        "url": url,
        "status_code": status,
        "content_length": item.get("length"),
        "words": item.get("words"),
        "lines": item.get("lines"),
        "redirect_location": item.get("redirectlocation", ""),
        "confidence": "high",
        "evidence": base_evidence,
    }


@mcp.tool()
def run_ffuf_fuzz(target_url: str, cookies: str="", wordlist: str="", timeout: int=120, session_probe_url: str="") -> dict:
    """Check high-value paths first, then use the compact project wordlist with the remaining budget."""
    timeout = max(30, min(int(timeout), 180))
    general = Path(wordlist) if wordlist else WORDLISTS_DIR/"common.txt"
    if not general.exists(): return failure("FFUF", target_url, f"Wordlist not found: {general}", diagnosis="missing_wordlist")
    priority_budget = min(20, max(10, timeout//3)); general_budget = max(15, timeout-priority_budget)
    with tempfile.TemporaryDirectory(prefix="ffuf-priority-") as td:
        temp=Path(td); priority=temp/"priority.txt"; filtered=temp/"general.txt"
        authenticated = bool(cookies)
        priority_values = [
            value
            for value in PRIORITY_PATHS
            if not (authenticated and _destructive_authenticated_word(value))
        ]
        priority.write_text("\n".join(priority_values)+"\n", encoding="utf-8")
        priority_set={value.lower() for value in priority_values}
        lines=[
            line.strip()
            for line in general.read_text(encoding="utf-8",errors="replace").splitlines()
            if line.strip()
            and not line.lstrip().startswith("#")
            and line.strip().lower() not in priority_set
            and not (authenticated and _destructive_authenticated_word(line))
        ]
        filtered.write_text("\n".join(lines)+"\n", encoding="utf-8")
        session_before = _session_probe(session_probe_url, cookies)
        if authenticated and session_before.get("performed") and session_before.get("conclusive") and session_before.get("authenticated") is False:
            return partial(
                "FFUF", target_url,
                "Authenticated FFUF was not started because the supplied session was already invalid.",
                diagnosis="authentication_precheck_failed",
                timed_out=False,
                vulnerabilities=[],
                authenticated=True,
                session_before=session_before,
                destructive_paths_excluded=sorted(DESTRUCTIVE_AUTH_PATH_TOKENS),
            )
        phases=[]; rows=[]
        for name,wl,budget in (("high_value_paths",priority,priority_budget),("compact_general_discovery",filtered,general_budget)):
            output=temp/f"{name}.json"; phase,found=_run_phase(target_url,cookies,wl,output,budget,name); phases.append(phase); rows.extend(found)
        unique={}
        for item in rows: unique[(str(item.get("url","")),int(item.get("status") or 0))]=item
        ordered=list(unique.values())
        findings=[_finding(item,cookies,index<12) for index,item in enumerate(ordered)]
        hard=[p for p in phases if p.get("status")=="error"]; limited=[p for p in phases if p.get("status")=="partial"]
        session_after = _session_probe(session_probe_url, cookies)
        common={
            "vulnerabilities":findings,
            "discovered_urls":[f["url"] for f in findings if f.get("url")],
            "authenticated":bool(cookies),
            "hard_failure":bool(hard),
            "phases":[
                {
                    "name":p.get("phase"),
                    "status":p.get("status"),
                    "findings":p.get("phase_findings",0),
                    "timeout_seconds":p.get("phase_timeout_seconds"),
                }
                for p in phases
            ],
            "session_before":session_before,
            "session_after":session_after,
            "destructive_paths_excluded":sorted(DESTRUCTIVE_AUTH_PATH_TOKENS) if authenticated else [],
            "session_probe_inconclusive": bool(
                session_before.get("conclusive") is False
                or session_after.get("conclusive") is False
            ),
        }
        if authenticated and session_after.get("performed") and session_after.get("conclusive") and session_after.get("authenticated") is False:
            return partial(
                "FFUF", target_url,
                f"FFUF preserved {len(findings)} findings, but the authenticated session became invalid during the scan.",
                diagnosis="authentication_lost_during_ffuf",
                timed_out=False,
                **common,
            )
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