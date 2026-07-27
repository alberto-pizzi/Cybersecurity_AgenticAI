from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from fastmcp import FastMCP

from utils import ROOT_DIR, failure, partial, run_process, scanner_session_probe, success

mcp = FastMCP("SQLMap Scanner")


def _find_sqlmap_script() -> Path | None:
    candidates = [
        Path.home() / ".local" / "opt" / "sqlmap" / "sqlmap.py",
        Path(ROOT_DIR) / "tools" / "sqlmap" / "sqlmap.py",
    ]
    launcher = Path.home() / ".local" / "bin" / "sqlmap.bat"
    if launcher.is_file():
        text = launcher.read_text(encoding="utf-8", errors="replace")
        match = re.search(r'"([^"\r\n]*sqlmap\.py)"|([A-Za-z]:\\[^\r\n]*?sqlmap\.py)', text, re.I)
        if match:
            candidates.insert(0, Path(match.group(1) or match.group(2)))
    for path in candidates:
        if path.is_file():
            return path.resolve()
    return None


def _extract_findings(text: str, target_url: str, method: str) -> list[dict[str, Any]]:
    if not re.search(
        r"(identified the following injection point|parameter.+is vulnerable|appears to be injectable)",
        text,
        re.IGNORECASE,
    ):
        return []

    dbms_match = re.search(r"back-end DBMS:\s*(.+)", text, re.I)
    dbms = dbms_match.group(1).strip() if dbms_match else ""
    blocks = re.split(r"(?=Parameter:\s*)", text, flags=re.I)
    findings: list[dict[str, Any]] = []
    for block in blocks:
        parameter_match = re.search(r"Parameter:\s*([^\s(]+)(?:\s*\(([^)]+)\))?", block, re.I)
        if not parameter_match:
            continue
        parameter = parameter_match.group(1).strip()
        place = (parameter_match.group(2) or method).strip().upper()
        types = [value.strip() for value in re.findall(r"^\s*Type:\s*(.+)$", block, re.I | re.M)]
        titles = [value.strip() for value in re.findall(r"^\s*Title:\s*(.+)$", block, re.I | re.M)]
        payloads = [value.strip() for value in re.findall(r"^\s*Payload:\s*(.+)$", block, re.I | re.M)]
        if not (types or titles or payloads or re.search(r"vulnerable|injectable", block, re.I)):
            continue
        technique_text = "; ".join(dict.fromkeys([*types, *titles])) or "SQLMap-confirmed injection technique"
        evidence_lines = [
            f"Parameter: {parameter} ({place})",
            *(f"Type: {value}" for value in types),
            *(f"Title: {value}" for value in titles),
            *(f"Payload: {value}" for value in payloads),
            f"Back-end DBMS: {dbms}" if dbms else "",
        ]
        findings.append({
            "alert": f"SQL injection in parameter '{parameter}'",
            "risk": "high",
            "category": "vulnerability",
            "verification_status": "scanner-confirmed-injection",
            "description": (
                f"SQLMap confirmed SQL injection in the {place} parameter '{parameter}' "
                f"on {method} {target_url}. Confirmed technique information: {technique_text}."
            ),
            "impact": (
                "A successful attacker can alter the database query executed by the application. "
                "The achievable impact depends on database privileges and the confirmed technique, and may include "
                "reading or modifying application data, bypassing authentication, or performing database-level actions."
            ),
            "solution": (
                f"Replace dynamic SQL construction for parameter '{parameter}' with parameterized queries, "
                "validate the expected data type server-side, use a least-privileged database account, and add "
                "a regression test using the confirmed request path."
            ),
            "url": target_url,
            "parameter": parameter,
            "parameter_location": place,
            "method": method,
            "confidence": "high",
            "dbms": dbms,
            "injection_types": types,
            "injection_titles": titles,
            "payloads": payloads,
            "technical_details": f"Parameter={parameter}; location={place}; DBMS={dbms or 'not identified'}; techniques={technique_text}.",
            "reproduction": "Replay the affected request using one of the SQLMap-confirmed payloads recorded in the evidence and compare the database-dependent response behaviour.",
            "evidence": "\n".join(line for line in evidence_lines if line),
        })

    if findings:
        return findings
    return [{
        "alert": "SQL injection reported by SQLMap",
        "risk": "high",
        "category": "vulnerability",
        "verification_status": "scanner-confirmed-injection-parser-limited",
        "description": (
            "SQLMap reported an injectable parameter, but the structured parser could not extract the parameter block. "
            "The exact scanner output is retained as evidence and must be reviewed before remediation."
        ),
        "impact": "SQL injection can alter the application's database query; the exact impact must be determined from the retained SQLMap output.",
        "solution": "Identify the affected parameter in the retained SQLMap output, replace dynamic SQL with parameterized queries, and retest the exact request.",
        "url": target_url,
        "method": method,
        "confidence": "high",
        "technical_details": f"SQLMap positive marker detected; DBMS={dbms or 'not identified'}; parameter parser did not find a complete block.",
        "evidence": text[-5000:],
    }]


def _trim(result: dict[str, Any], limit: int = 12000) -> dict[str, Any]:
    for key in ("stdout", "stderr"):
        value = str(result.get(key, ""))
        if len(value) > limit:
            result[key] = value[-limit:]
            result[f"{key}_truncated"] = True
    return result



CONTROL_PARAMETERS = {"submit", "login", "change", "user_token", "csrf", "button"}
SQL_ERROR_MARKERS = (
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "unclosed quotation mark", "quoted string not properly terminated", "sqlstate[",
    "sqlite error", "postgresql query failed", "ora-01756", "mysqli_sql_exception",
)
RESULT_MARKERS = (
    "first name:", "surname:", "last name:", "user id:", "username:",
)
BLIND_TRUE_MARKERS = (
    "user id exists in the database", "exists in the database",
)
BLIND_FALSE_MARKERS = (
    "user id is missing from the database", "missing from the database",
)


def _filtered_parameters(parameters: list[str]) -> list[str]:
    return [
        value for value in dict.fromkeys(parameters)
        if value.lower() not in CONTROL_PARAMETERS
    ]


def _response_excerpt(text: str, needle: str = "", limit: int = 700) -> str:
    value = str(text or "")
    index = value.lower().find(str(needle or "").lower()) if needle else -1
    if index >= 0:
        start = max(0, index - limit // 3)
        return value[start:start + limit]
    return value[:limit]


def _mutated_request(
    target_url: str,
    method: str,
    data: str,
    parameter: str,
    replacement: str,
) -> tuple[str, str]:
    if method == "GET":
        parsed = urlparse(target_url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        changed = [
            (name, replacement if name == parameter else value)
            for name, value in pairs
        ]
        return urlunparse(parsed._replace(query=urlencode(changed))), ""
    pairs = parse_qsl(data, keep_blank_values=True)
    changed = [
        (name, replacement if name == parameter else value)
        for name, value in pairs
    ]
    return target_url, urlencode(changed)


def _send_http(
    url: str,
    cookies: str,
    method: str,
    data: str,
) -> requests.Response:
    import requests as http_requests
    headers = {"Cache-Control": "no-cache", "User-Agent": "SecOps-SQLi-Verifier/2.0"}
    if cookies:
        headers["Cookie"] = cookies
    last: requests.RequestException | None = None
    for attempt in range(3):
        try:
            return http_requests.request(
                method, url, data=data if method != "GET" else None,
                headers=headers, timeout=(4, 16), allow_redirects=True,
            )
        except (http_requests.Timeout, http_requests.ConnectionError) as exc:
            last = exc
            if attempt < 2:
                import time as _time
                _time.sleep(0.7 * (attempt + 1))
        except http_requests.RequestException:
            raise
    assert last is not None
    raise last

def _quick_sqli_probe(
    target_url: str,
    cookies: str,
    method: str,
    data: str,
    parameters: list[str],
) -> dict[str, Any]:
    if not parameters:
        return {"performed": False, "candidate": False, "confirmed": False}
    parameter = parameters[0]
    if method == "GET":
        original_pairs = dict(parse_qsl(urlparse(target_url).query, keep_blank_values=True))
    else:
        original_pairs = dict(parse_qsl(data, keep_blank_values=True))
    original = original_pairs.get(parameter, "1") or "1"
    payload_pairs = [
        (f"{original}' OR '1'='1' #", f"{original}' AND '1'='2' #"),
        (f"{original}' OR '1'='1' -- -", f"{original}' AND '1'='2' -- -"),
    ]
    payload_true, payload_false = payload_pairs[0]
    quote_payload = f"{original}'"
    try:
        baseline = _send_http(target_url, cookies, method, data)
        quote_url, quote_data = _mutated_request(target_url, method, data, parameter, quote_payload)
        quote_response = _send_http(quote_url, cookies, method, quote_data)
        selected_responses = None
        for candidate_true, candidate_false in payload_pairs:
            true_url, true_data = _mutated_request(target_url, method, data, parameter, candidate_true)
            false_url, false_data = _mutated_request(target_url, method, data, parameter, candidate_false)
            candidate_true_response = _send_http(true_url, cookies, method, true_data)
            candidate_false_response = _send_http(false_url, cookies, method, false_data)
            low_true = candidate_true_response.text.lower()
            low_false = candidate_false_response.text.lower()
            if (
                low_true != low_false
                or "user id exists in the database" in low_true
                or "first name:" in low_true
            ):
                payload_true, payload_false = candidate_true, candidate_false
                selected_responses = (candidate_true_response, candidate_false_response)
                break
        if selected_responses is None:
            selected_responses = (candidate_true_response, candidate_false_response)
        true_response, false_response = selected_responses
    except requests.RequestException as exc:
        return {
            "performed": True, "candidate": False, "confirmed": False,
            "error": f"{type(exc).__name__}: {exc}", "parameter": parameter,
        }

    baseline_lower = baseline.text.lower()
    true_lower = true_response.text.lower()
    false_lower = false_response.text.lower()
    quote_lower = quote_response.text.lower()
    error_markers = [
        marker for marker in SQL_ERROR_MARKERS
        if marker in quote_lower and marker not in baseline_lower
    ]
    marker_counts = {
        "baseline": sum(baseline_lower.count(marker) for marker in RESULT_MARKERS),
        "true": sum(true_lower.count(marker) for marker in RESULT_MARKERS),
        "false": sum(false_lower.count(marker) for marker in RESULT_MARKERS),
    }
    true_false_delta = abs(len(true_response.content) - len(false_response.content))
    blind_true = any(marker in true_lower for marker in BLIND_TRUE_MARKERS)
    blind_false = any(marker in false_lower for marker in BLIND_FALSE_MARKERS)
    blind_confirmed = (
        true_response.status_code == false_response.status_code == 200
        and blind_true and blind_false
    )
    boolean_confirmed = (
        true_response.status_code < 400
        and false_response.status_code < 400
        and marker_counts["true"] >= max(2, marker_counts["baseline"] + 1)
        and marker_counts["true"] > marker_counts["false"]
    )
    strong_differential = (
        true_response.status_code == false_response.status_code == 200
        and true_false_delta >= 120
        and true_response.text != false_response.text
        and marker_counts["true"] > marker_counts["false"]
    )
    confirmed = boolean_confirmed or strong_differential or blind_confirmed
    candidate = confirmed or bool(error_markers)
    return {
        "performed": True,
        "candidate": candidate,
        "confirmed": confirmed,
        "parameter": parameter,
        "payload_true": payload_true,
        "payload_false": payload_false,
        "payload_quote": quote_payload,
        "error_markers": error_markers,
        "result_marker_counts": marker_counts,
        "baseline": {
            "status": baseline.status_code, "bytes": len(baseline.content),
            "final_url": str(baseline.url),
        },
        "true_probe": {
            "status": true_response.status_code, "bytes": len(true_response.content),
            "final_url": str(true_response.url),
            "excerpt": _response_excerpt(true_response.text, "First name"),
        },
        "false_probe": {
            "status": false_response.status_code, "bytes": len(false_response.content),
            "final_url": str(false_response.url),
            "excerpt": _response_excerpt(false_response.text),
        },
        "quote_probe": {
            "status": quote_response.status_code, "bytes": len(quote_response.content),
            "final_url": str(quote_response.url),
            "excerpt": _response_excerpt(quote_response.text, error_markers[0] if error_markers else ""),
        },
        "true_false_byte_delta": true_false_delta,
        "blind_true_marker": blind_true,
        "blind_false_marker": blind_false,
        "blind_confirmed": blind_confirmed,
    }


def _quick_probe_finding(
    target_url: str,
    method: str,
    probe: dict[str, Any],
) -> list[dict[str, Any]]:
    if not probe.get("candidate"):
        return []
    parameter = str(probe.get("parameter") or "")
    confirmed = bool(probe.get("confirmed"))
    evidence = (
        f"Parameter: {parameter}\n"
        f"Boolean-true payload: {probe.get('payload_true')}\n"
        f"Boolean-false payload: {probe.get('payload_false')}\n"
        f"Result marker counts: {probe.get('result_marker_counts')}\n"
        f"Baseline: {probe.get('baseline')}\n"
        f"True probe: {probe.get('true_probe')}\n"
        f"False probe: {probe.get('false_probe')}\n"
        f"SQL error markers from quote probe: {probe.get('error_markers')}"
    )
    return [{
        "alert": (
            f"Blind SQL injection in parameter '{parameter}'"
            if confirmed and probe.get("blind_confirmed")
            else f"SQL injection in parameter '{parameter}'"
            if confirmed else f"SQL error behaviour in parameter '{parameter}'"
        ),
        "risk": "high" if confirmed else "medium",
        "category": "vulnerability" if confirmed else "candidate",
        "verification_status": (
            "blind-boolean-response-marker-confirmed"
            if confirmed and probe.get("blind_confirmed")
            else "boolean-response-differential-confirmed"
            if confirmed else "sql-error-probe-needs-sqlmap-confirmation"
        ),
        "confidence": "high" if confirmed else "medium",
        "description": (
            "A bounded boolean differential produced multiple database result markers for the true condition and fewer or no results for the false condition. "
            "This response behaviour confirms that the selected input changes the SQL query logic."
            if confirmed else
            "Adding a quote introduced a database error marker that was absent from the baseline response."
        ),
        "attack_preconditions": "An attacker must be able to submit the affected HTTP parameter to the vulnerable endpoint. The tested request used the supplied authenticated session.",
        "impact": "An attacker may alter database queries, enumerate or extract application data, bypass data-selection controls, and potentially modify data depending on database permissions and reachable statements.",
        "solution": "Replace string-built SQL with parameterized statements, validate the expected parameter type, use a least-privileged database account, and add regression tests for boolean, UNION, error and time-based payloads.",
        "url": target_url,
        "method": method,
        "parameter": parameter,
        "payloads": [probe.get("payload_true"), probe.get("payload_false"), probe.get("payload_quote")],
        "cwe_id": "89",
        "owasp_category": "A03:2021 Injection",
        "technical_details": "The verifier compared baseline, boolean-true, boolean-false and quote-mutated responses using status, response size, database-result labels and blind true/false markers.",
        "reproduction": (
            f"1. Send the original {method} request to {target_url}.\n"
            f"2. Replace '{parameter}' with: {probe.get('payload_true')}\n"
            f"3. Repeat with: {probe.get('payload_false')}\n"
            "4. Compare returned database rows and response sizes; the true condition returns additional records while the false condition does not."
        ),
        "evidence": evidence,
    }]

@mcp.tool()
def run_sqlmap_scan(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    timeout: int = 180,
) -> dict:
    """Run SQLMap directly through Python instead of the Windows batch launcher."""
    method = method.upper()
    timeout = max(45, min(int(timeout), 600))
    parameters = _filtered_parameters([str(value) for value in (parameters or []) if str(value)])
    session_probe = scanner_session_probe(target_url, cookies, method, data)
    if cookies and session_probe.get("performed") and session_probe.get("conclusive") and session_probe.get("authenticated") is False:
        return partial(
            "SQLMap", target_url,
            "SQLMap was not started because the authenticated request redirected to a login page.",
            diagnosis="authentication_precheck_failed", timed_out=False,
            vulnerabilities=[], session_probe=session_probe,
        )
    quick_probe = _quick_sqli_probe(target_url, cookies, method, data, parameters)
    quick_findings = _quick_probe_finding(target_url, method, quick_probe)
    if quick_probe.get("confirmed"):
        return success(
            "SQLMap", target_url,
            "The bounded SQL boolean-differential verifier confirmed injection; the slower SQLMap phase was not required.",
            vulnerabilities=quick_findings,
            sql_injection_found=True,
            request_method=method,
            tested_parameters=parameters,
            authenticated=bool(cookies),
            session_probe=session_probe,
            quick_sqli_probe=quick_probe,
            execution_mode="direct_boolean_differential",
        )

    script = _find_sqlmap_script()
    if script is None:
        if quick_findings:
            return partial(
                "SQLMap", target_url,
                "A SQL-error candidate was preserved, but sqlmap.py was not found for confirmation.",
                diagnosis="missing_sqlmap_script", timed_out=False,
                vulnerabilities=quick_findings,
                session_probe=session_probe,
                quick_sqli_probe=quick_probe,
            )
        return failure(
            "SQLMap", target_url,
            "sqlmap.py was not found under ~/.local/opt/sqlmap. Run initScript.py again.",
            diagnosis="missing_sqlmap_script",
        )

    command = [
        sys.executable, str(script), "-u", target_url,
        "--batch", "--level=2", "--risk=1", "--technique=BEUSTQ", "--time-sec=1",
        "--timeout=4", "--retries=0", "--threads=3",
        "--flush-session", "--skip-waf", "--answers=follow=N", "--drop-set-cookie",
    ]
    if method != "GET":
        command.append(f"--method={method}")
    if data:
        command.extend(["--data", data])
    if parameters:
        command.extend(["-p", ",".join(dict.fromkeys(parameters))])
    if cookies:
        command.extend(["--cookie", cookies])

    result = run_process(
        "SQLMap",
        command,
        target=target_url,
        timeout=timeout,
        cwd=script.parent,
    )
    text = "\n".join(str(result.get(key, "")) for key in ("stdout", "stderr", "output"))
    findings = _extract_findings(text, target_url, method)
    if not findings:
        findings = quick_findings
    common = {
        "vulnerabilities": findings,
        "request_method": method,
        "request_data_present": bool(data),
        "tested_parameters": parameters,
        "authenticated": bool(cookies),
        "execution_mode": "direct_python",
        "sqlmap_script": str(script),
        "session_probe": session_probe,
        "quick_sqli_probe": quick_probe,
    }

    if result.get("diagnosis") == "timeout":
        return partial(
            "SQLMap", target_url,
            f"SQLMap reached its configured time budget. Confirmed findings preserved: {len(findings)}.",
            diagnosis="time_limit_reached",
            timed_out=True,
            time_limit_reached=True,
            duration_seconds=result.get("duration_seconds"),
            stdout=str(result.get("stdout", ""))[-12000:],
            stderr=str(result.get("stderr", ""))[-12000:],
            command=result.get("command", []),
            **common,
        )
    if result.get("status") != "success":
        result.update(common)
        return _trim(result)

    return success(
        "SQLMap", target_url,
        f"SQLMap completed for {method}. Confirmed SQL injection findings: {len(findings)}.",
        sql_injection_found=bool(findings),
        duration_seconds=result.get("duration_seconds"),
        command=result.get("command", []),
        stdout=str(result.get("stdout", ""))[-12000:],
        stderr=str(result.get("stderr", ""))[-12000:],
        **common,
    )


def _once() -> int:
    try:
        arguments = json.loads(os.sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = run_sqlmap_scan(**arguments)
    except Exception as exc:
        result = failure("SQLMap", "", f"One-shot SQLMap execution failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio")