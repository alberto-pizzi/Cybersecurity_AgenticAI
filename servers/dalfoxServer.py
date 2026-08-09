from __future__ import annotations

import re
import tempfile
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
from typing import Any

from fastmcp import FastMCP

from utils import partial, read_json_lines, response_excerpt, run_process, scanner_session_probe, success

from utils import run_mcp_http

mcp = FastMCP("Dalfox Scanner")


def _text_findings(text: str, target_url: str, method: str) -> list[dict[str, Any]]:
    verified = [line.strip() for line in text.splitlines() if re.search(r"\[V\]|verified", line, re.I)]
    candidates = [line.strip() for line in text.splitlines() if re.search(r"\[POC\]|\[R\]|reflected", line, re.I)]
    findings: list[dict[str, Any]] = []
    if verified:
        findings.append({
            "alert": "Verified cross-site scripting",
            "risk": "high",
            "category": "vulnerability",
            "verification_status": "dalfox-verified-vector",
            "description": f"Dalfox reported a verified executable XSS vector in an HTTP {method} input.",
            "impact": "The verified vector can execute attacker-controlled JavaScript in a victim browser within the affected origin.",
            "solution": "Apply context-aware output encoding at the affected sink, validate the input server-side, use safe DOM APIs, and add an effective Content Security Policy as defence in depth.",
            "url": target_url,
            "method": method,
            "confidence": "high",
            "technical_details": "Dalfox text output contained a verified-vector marker.",
            "evidence": "\n".join(verified[:30]),
        })
    if candidates and not verified:
        findings.append({
            "alert": "Potential cross-site scripting reflection",
            "risk": "medium",
            "category": "candidate",
            "verification_status": "reflection-or-poc-needs-validation",
            "description": f"Dalfox reported a reflection or proof-of-concept candidate in an HTTP {method} input, but did not mark it as a verified executable vector.",
            "impact": "No browser execution was confirmed. Manual validation is required to determine whether the reflection reaches an executable HTML, attribute, JavaScript, or URL context.",
            "solution": "Review the reflected context, apply context-aware encoding, validate the input, and retest with a browser-based proof of execution.",
            "url": target_url,
            "method": method,
            "confidence": "medium",
            "technical_details": "Dalfox text output contained a POC/reflection marker without a verified-vector marker.",
            "evidence": "\n".join(candidates[:30]),
        })
    return findings


def _json_findings(path: Path, target_url: str, method: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    findings: list[dict[str, Any]] = []
    for item in read_json_lines(path.read_text(encoding="utf-8", errors="replace")):
        finding_type = str(item.get("type", "")).upper()
        if finding_type not in {"V", "A", "R"}:
            continue
        severity = str(item.get("severity", "high" if finding_type == "V" else "medium")).lower()
        category = "vulnerability" if finding_type == "V" else "candidate"
        findings.append({
            "alert": str(item.get("type_description") or "Cross-site scripting"),
            "risk": severity,
            "category": category,
            "verification_status": "dalfox-verified-vector" if finding_type == "V" else "reflection-or-ast-candidate",
            "description": (
                "Dalfox verified an executable XSS vector."
                if finding_type == "V"
                else "Dalfox identified an XSS reflection or AST candidate requiring confirmation."
            ),
            "impact": "Successful XSS can execute attacker-controlled JavaScript in a victim browser session.",
            "solution": "Apply context-aware output encoding at the affected sink, validate the input server-side, use safe DOM APIs, and deploy Content Security Policy as defence in depth.",
            "url": str(item.get("data") or target_url),
            "method": str(item.get("method") or method),
            "parameter": str(item.get("param") or ""),
            "confidence": "high" if finding_type == "V" else "medium",
            "inject_type": str(item.get("inject_type") or ""),
            "payload": str(item.get("payload") or "")[:1500],
            "evidence": str(item.get("evidence") or item)[:2500],
            "cwe": str(item.get("cwe") or ""),
        })
    return findings



def _http_retry(method: str, url: str, **kwargs: Any) -> requests.Response:
    import requests as http_requests
    last: requests.RequestException | None = None
    for attempt in range(3):
        try:
            return http_requests.request(method, url, **kwargs)
        except (http_requests.Timeout, http_requests.ConnectionError) as exc:
            last = exc
            if attempt < 2:
                import time as _time
                _time.sleep(0.7 * (attempt + 1))
        except http_requests.RequestException:
            raise
    assert last is not None
    raise last


def _reflection_probe(
    target_url: str,
    cookies: str,
    method: str,
    data: str,
    parameters: list[str],
    allow_state_changes: bool = False,
) -> dict[str, Any]:
    if not parameters:
        return {"performed": False, "reflected": False, "confirmed": False}
    import requests as http_requests
    marker = "SECOPS_XSS_7F31"
    payload = f'<svg id="{marker}" onload="void(0)"></svg>'
    priority = ("mtxmessage", "message", "comment", "body", "text", "description", "txtname", "name", "title", "search", "query", "q")
    def parameter_score(value: str) -> tuple[int, int]:
        lowered = value.lower()
        for index, hint in enumerate(priority):
            if lowered == hint:
                return (300 - index, -len(lowered))
            if hint in lowered:
                return (200 - index, -len(lowered))
        return (0, -len(lowered))
    parameter = max(parameters, key=parameter_score)
    headers = {
        "Cache-Control": "no-cache",
        "User-Agent": "SecOps-XSS-Verifier/2.0",
        "Referer": target_url,
    }
    if cookies:
        headers["Cookie"] = cookies
    if method == "POST" and not allow_state_changes:
        return {
            "performed": False, "reflected": False, "confirmed": False,
            "parameter": parameter, "state_change_skipped": True,
        }
    try:
        if method == "GET":
            parsed = urlparse(target_url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            changed, replaced = [], False
            for name, value in pairs:
                if not replaced and name.lower() == parameter.lower():
                    changed.append((name, payload)); replaced = True
                else:
                    changed.append((name, value))
            if not replaced:
                changed.append((parameter, payload))
            probe_url = urlunparse(parsed._replace(query=urlencode(changed)))
            request_data = ""
            response = _http_retry("GET", probe_url, headers=headers, timeout=(4, 16), allow_redirects=True)
            follow_up = None
        else:
            pairs = parse_qsl(data, keep_blank_values=True)
            changed, replaced = [], False
            for name, value in pairs:
                lowered = name.lower()
                if not replaced and lowered == parameter.lower():
                    changed.append((name, payload)); replaced = True
                elif lowered in {"name", "txtname", "author"}:
                    changed.append((name, "SecOps"))
                else:
                    changed.append((name, value))
            if not replaced:
                changed.append((parameter, payload))
            probe_url = target_url
            request_data = urlencode(changed)
            response = _http_retry(
                method, target_url, data=request_data, headers=headers,
                timeout=(4, 16), allow_redirects=True,
            )
            follow_up = _http_retry(
                "GET", target_url, headers=headers, timeout=(4, 16), allow_redirects=True
            )
    except requests.RequestException as exc:
        return {
            "performed": True, "reflected": False, "confirmed": False,
            "error": f"{type(exc).__name__}: {exc}", "parameter": parameter,
        }
    body = response.text
    follow_body = follow_up.text if follow_up is not None else ""
    content_type = str(response.headers.get("Content-Type", ""))
    exact = payload in body
    persisted = bool(follow_up is not None and payload in follow_body)
    encoded = (
        "&lt;svg" in body.lower() or "&quot;" in body.lower()
        or payload.replace("<", "&lt;") in body
    )
    confirmed = (exact or persisted) and not encoded and "html" in content_type.lower()
    reflected = marker in body or marker in follow_body
    excerpt_source = follow_body if persisted else body
    return {
        "performed": True, "reflected": reflected, "confirmed": confirmed,
        "stored_confirmed": persisted and confirmed,
        "parameter": parameter, "marker": marker, "payload": payload,
        "status": response.status_code, "final_url": str(response.url),
        "content_type": content_type, "response_bytes": len(response.content),
        "exact_unescaped_payload": exact and not encoded,
        "persisted_unescaped_payload": persisted and not encoded,
        "request_data": request_data,
        "response_excerpt": response_excerpt(excerpt_source, marker),
    }


def _reflection_finding(
    target_url: str,
    method: str,
    probe: dict[str, Any],
) -> list[dict[str, Any]]:
    if not probe.get("reflected"):
        return []
    confirmed = bool(probe.get("confirmed"))
    parameter = str(probe.get("parameter") or "")
    return [{
        "alert": (
            f"Stored cross-site scripting in parameter '{parameter}'"
            if confirmed and probe.get("stored_confirmed")
            else f"Reflected cross-site scripting in parameter '{parameter}'"
            if confirmed else f"Reflected input candidate in parameter '{parameter}'"
        ),
        "risk": "high" if confirmed else "medium",
        "category": "vulnerability" if confirmed else "candidate",
        "verification_status": (
            "stored-persistence-unescaped-executable-html-confirmed"
            if confirmed and probe.get("stored_confirmed")
            else "unescaped-executable-html-payload-confirmed"
            if confirmed else "marker-reflection-needs-browser-validation"
        ),
        "confidence": "high" if confirmed else "medium",
        "description": (
            ("The application stored the attacker-controlled SVG/event-handler markup and returned it unchanged on a follow-up request. "
             "Because the payload persisted without encoding, later visitors can interpret it as executable markup.")
            if probe.get("stored_confirmed") else
            ("The application returned an attacker-controlled SVG element with an event handler unchanged inside an HTML response. "
             "Because the payload was not encoded, the browser can interpret it as executable markup.")
            if confirmed else
            "A unique marker was reflected, but executable HTML interpretation was not conclusively established."
        ),
        "attack_preconditions": "A victim must follow or submit a request containing the crafted parameter while viewing the response in a browser.",
        "impact": "An attacker can execute JavaScript in the application's origin, access DOM data available to the page, perform authenticated actions as the victim, and alter displayed content.",
        "solution": "Apply context-aware output encoding at every sink, validate input according to business requirements, use safe DOM APIs, and deploy a restrictive Content Security Policy as defence in depth.",
        "url": target_url,
        "method": method,
        "parameter": parameter,
        "payload": probe.get("payload"),
        "cwe_id": "79",
        "owasp_category": "A03:2021 Injection",
        "technical_details": (
            f"HTTP {probe.get('status')}; content type={probe.get('content_type')}; "
            f"exact unescaped payload={probe.get('exact_unescaped_payload')}; "
            f"persisted unescaped payload={probe.get('persisted_unescaped_payload')}; "
            f"response bytes={probe.get('response_bytes')}."
        ),
        "reproduction": (
            f"1. Send the {method} request to {target_url}.\n"
            f"2. Set '{parameter}' to: {probe.get('payload')}\n"
            "3. Open the response in a browser and observe that the injected SVG/event-handler markup is interpreted in the application origin."
        ),
        "evidence": (
            f"Payload: {probe.get('payload')}\n"
            f"Final URL: {probe.get('final_url')}\n"
            f"Response excerpt:\n{probe.get('response_excerpt')}"
        ),
    }]


def _looks_like_v3_cli_error(result: dict[str, Any]) -> bool:
    text = "\n".join(str(result.get(key, "")) for key in ("stdout", "stderr", "output")).lower()
    return int(result.get("return_code") or 0) == 2 and any(token in text for token in (
        "unexpected argument", "unrecognized", "unknown command", "found argument 'url'",
        "invalid value", "usage:",
    ))


def _trim(result: dict[str, Any]) -> dict[str, Any]:
    for key, limit in (("stdout", 8000), ("stderr", 8000)):
        value = str(result.get(key, ""))
        if len(value) > limit:
            result[key] = value[-limit:]
            result[f"{key}_truncated"] = True
    return result


def _run_v3(
    target_url: str,
    cookies: str,
    method: str,
    data: str,
    parameters: list[str],
    timeout: int,
    output_file: Path,
) -> dict[str, Any]:
    scan_timeout = max(15, min(30, timeout - 10))
    command = [
        "dalfox", "scan", target_url,
        "--format", "jsonl",
        "--output", str(output_file),
        "--no-color", "--silence",
        "--skip-mining",
        "--workers", "15",
        "--max-payloads-per-param", "12",
        "--timeout", "3",
        "--scan-timeout", str(scan_timeout),
    ]
    location = "query" if method == "GET" else "body"
    for parameter in dict.fromkeys(parameters):
        command.extend(["-p", f"{parameter}:{location}"])
    if method != "GET":
        command.extend(["-X", method])
    if data:
        command.extend(["-d", data])
    if cookies:
        command.extend(["--cookies", cookies])
    result = run_process("Dalfox", command, target=target_url, timeout=timeout, accepted_codes=(0, 1))
    result["dalfox_cli_generation"] = "v3"
    return _trim(result)


def _run_v2(
    target_url: str,
    cookies: str,
    method: str,
    data: str,
    parameters: list[str],
    timeout: int,
) -> dict[str, Any]:
    command = [
        "dalfox", "url", target_url,
        "--silence", "--skip-bav",
        "--worker", "10",
        "--timeout", "5",
    ]
    if method != "GET":
        command.extend(["--method", method])
    if data:
        command.extend(["--data", data])
    for parameter in dict.fromkeys(parameters):
        command.extend(["-p", parameter])
    if cookies:
        command.extend(["--cookie", cookies])
    result = run_process("Dalfox", command, target=target_url, timeout=timeout, accepted_codes=(0, 1))
    result["dalfox_cli_generation"] = "v2"
    return _trim(result)


@mcp.tool()
def run_dalfox_scan(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    timeout: int = 120,
    allow_state_changes: bool = False,
) -> dict:
    """Run a bounded Dalfox scan with automatic v3/v2 CLI compatibility."""
    method = method.upper()
    timeout = max(30, min(int(timeout), 300))
    parameters = [str(value) for value in (parameters or []) if str(value)]
    session_probe = scanner_session_probe(target_url, cookies, method, data)
    if cookies and session_probe.get("performed") and session_probe.get("conclusive") and session_probe.get("authenticated") is False:
        return partial("Dalfox", target_url, "Dalfox was not started because the authenticated request redirected to a login page.", diagnosis="authentication_precheck_failed", timed_out=False, vulnerabilities=[], session_probe=session_probe)
    reflection_probe = _reflection_probe(target_url, cookies, method, data, parameters, allow_state_changes)
    reflection_findings = _reflection_finding(target_url, method, reflection_probe)
    if reflection_probe.get("confirmed"):
        return success(
            "Dalfox", target_url,
            ("The bounded verifier confirmed stored XSS persistence; the slower Dalfox phase was not required."
             if reflection_probe.get("stored_confirmed") else
             "The bounded response verifier confirmed unescaped executable reflected XSS; the slower Dalfox phase was not required."),
            vulnerabilities=reflection_findings,
            xss_found=True,
            request_method=method,
            tested_parameters=parameters,
            authenticated=bool(cookies),
            session_probe=session_probe,
            reflection_probe=reflection_probe,
            execution_mode="direct_unescaped_html_probe",
        )
    common = {
        "request_method": method,
        "request_data_present": bool(data),
        "tested_parameters": parameters,
        "authenticated": bool(cookies),
        "session_probe": session_probe,
        "reflection_probe": reflection_probe,
    }

    with tempfile.TemporaryDirectory(prefix="dalfox-") as temporary_directory:
        output_file = Path(temporary_directory) / "dalfox.jsonl"
        result = _run_v3(target_url, cookies, method, data, parameters, timeout, output_file)
        if _looks_like_v3_cli_error(result):
            output_file.unlink(missing_ok=True)
            previous = {
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "return_code": result.get("return_code"),
            }
            result = _run_v2(target_url, cookies, method, data, parameters, timeout)
            result["compatibility_retry"] = previous

        text = "\n".join(str(result.get(key, "")) for key in ("stdout", "stderr", "output"))
        findings = (
            _json_findings(output_file, target_url, method)
            if result.get("dalfox_cli_generation") == "v3"
            else _text_findings(text, target_url, method)
        )
        if not findings:
            findings = _reflection_finding(target_url, method, reflection_probe)
        common["vulnerabilities"] = findings
        common["dalfox_cli_generation"] = result.get("dalfox_cli_generation", "unknown")

        if result.get("diagnosis") == "timeout":
            return partial(
                "Dalfox", target_url,
                f"Dalfox reached its configured time budget. Findings preserved: {len(findings)}.",
                diagnosis="time_limit_reached",
                timed_out=True,
                time_limit_reached=True,
                duration_seconds=result.get("duration_seconds"),
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                command=result.get("command", []),
                **common,
            )
        if result.get("status") != "success":
            result.update(common)
            if int(result.get("return_code") or 0) == 2:
                result["diagnosis"] = "dalfox_cli_or_runtime_error"
                result["output"] = (
                    "Dalfox rejected the command or encountered a runtime/configuration error. "
                    f"CLI generation attempted: {common['dalfox_cli_generation']}. "
                    f"Details: {text[-2000:]}"
                )
            return result

        return success(
            "Dalfox", target_url,
            f"Dalfox completed for {method}. Findings: {len(findings)}.",
            xss_found=any(item.get("category") == "vulnerability" for item in findings),
            duration_seconds=result.get("duration_seconds"),
            command=result.get("command", []),
            **common,
        )


if __name__ == "__main__":
    run_mcp_http(mcp, "dalfox")
