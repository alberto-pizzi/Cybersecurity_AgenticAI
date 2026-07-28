from __future__ import annotations

import argparse
import asyncio
import json
import re
import shutil
import sys
import time
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from fastmcp import FastMCP

from utils import failure, parse_cookie_header, skipped, success

mcp = FastMCP("Browser XSS and Workflow Verifier")

DESTRUCTIVE_RE = re.compile(r"(?:logout|signout|logoff|setup|install|delete|remove|drop|truncate|purge|wipe|reset)", re.I)
TOKEN_RE = re.compile(r"(?:csrf|xsrf|token|nonce|authenticity|request[_-]?verification)", re.I)
XSS_NAME_RE = re.compile(r"(?:name|message|comment|search|query|q|text|title|input|html|body|content|url|redirect|default)", re.I)


def _same_origin(left: str, right: str) -> bool:
    a, b = urlparse(left), urlparse(right)
    return (a.scheme.lower(), a.hostname, a.port or (443 if a.scheme == "https" else 80)) == (
        b.scheme.lower(), b.hostname, b.port or (443 if b.scheme == "https" else 80)
    )


def _mutate_query(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    changed: list[tuple[str, str]] = []
    replaced = False
    for name, current in pairs:
        if not replaced and name.lower() == parameter.lower():
            changed.append((name, value))
            replaced = True
        else:
            changed.append((name, current))
    if not replaced:
        changed.append((parameter, value))
    return urlunparse(parsed._replace(query=urlencode(changed)))


def _browser_cookies(target_url: str, cookies: str) -> list[dict[str, Any]]:
    parsed = urlparse(target_url)
    rows: list[dict[str, Any]] = []
    for name, value in parse_cookie_header(cookies):
        rows.append({
            "name": name,
            "value": value,
            "domain": parsed.hostname or "localhost",
            "path": "/",
            "httpOnly": False,
            "secure": parsed.scheme == "https",
            "sameSite": "Lax",
        })
    return rows


def _marker_payload(marker: str) -> str:
    return (
        '<img src=x onerror="document.documentElement.setAttribute('
        f"'data-secops-browser-xss','{marker}')\" data-secops-marker=\"{marker}\">"
    )


async def _executed(page: Any, marker: str) -> bool:
    try:
        value = await page.evaluate("document.documentElement.getAttribute('data-secops-browser-xss')")
        return str(value or "") == marker
    except Exception:
        return False


async def _reflection_present(page: Any, marker: str) -> bool:
    try:
        return marker in str(await page.content())
    except Exception:
        return False


async def _safe_goto(page: Any, url: str, timeout_ms: int) -> tuple[bool, str]:
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        await page.wait_for_timeout(700)
        return True, f"status={response.status if response else 'unknown'}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


async def _dom_checks(
    page: Any,
    target_url: str,
    parameters: list[str],
    timeout_ms: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    candidates = [value for value in parameters if value and XSS_NAME_RE.search(value)] or list(parameters)
    candidates = list(dict.fromkeys(candidates))[:4]
    for parameter in candidates:
        marker = "SECOPS_DOM_" + re.sub(r"[^A-Za-z0-9]", "", parameter)[:12] + str(int(time.time() * 1000))[-6:]
        payload = _marker_payload(marker)
        mutated = _mutate_query(target_url, parameter, payload)
        ok, detail = await _safe_goto(page, mutated, timeout_ms)
        executed = ok and await _executed(page, marker)
        reflected = ok and await _reflection_present(page, marker)
        attempts.append({
            "mode": "query",
            "parameter": parameter,
            "url": mutated,
            "navigation": detail,
            "executed": executed,
            "reflected": reflected,
        })
        if executed:
            findings.append({
                "alert": f"Browser-confirmed DOM or reflected XSS in parameter '{parameter}'",
                "risk": "high",
                "category": "vulnerability",
                "verification_status": "playwright-browser-marker-executed",
                "confidence": "high",
                "description": "A harmless event-handler payload executed in a real Chromium page context and set the expected DOM marker.",
                "impact": "Attacker-controlled JavaScript can execute in the application origin and access data or actions available to the victim session.",
                "solution": "Apply context-aware output encoding, avoid unsafe DOM sinks, sanitize untrusted HTML and use Content Security Policy as defence in depth.",
                "url": mutated,
                "method": "GET",
                "parameter": parameter,
                "payload": payload,
                "evidence": f"Chromium marker executed=True; marker={marker}; navigation={detail}",
                "owasp_category": "A03:2021 Injection",
                "cwe_id": "79",
            })
            continue
        if reflected:
            findings.append({
                "alert": f"Browser-observed unexecuted HTML reflection in parameter '{parameter}'",
                "risk": "medium",
                "category": "candidate",
                "verification_status": "browser-reflection-without-marker-execution",
                "confidence": "medium",
                "description": "The marker payload was present in the browser DOM, but its event handler did not execute during the bounded check.",
                "impact": "The reflection may become exploitable in a different HTML, attribute or script context and needs manual validation.",
                "solution": "Apply context-aware encoding and review the exact reflection context.",
                "url": mutated,
                "method": "GET",
                "parameter": parameter,
                "payload": payload,
                "evidence": f"marker_reflected=True; marker_executed=False; navigation={detail}",
                "owasp_category": "A03:2021 Injection",
            })

    marker = "SECOPS_HASH_" + str(int(time.time() * 1000))[-8:]
    payload = _marker_payload(marker)
    base_url = target_url.split("#", 1)[0]
    fragment_url = base_url + "#" + quote(payload, safe="<>/'\"=() -_:;")
    ok, detail = await _safe_goto(page, base_url, timeout_ms)
    executed = False
    reload_detail = "not-attempted"
    if ok:
        try:
            await page.evaluate("payload => { window.location.hash = payload; }", payload)
            await page.wait_for_timeout(700)
            executed = await _executed(page, marker)
            if not executed:
                await page.reload(wait_until="domcontentloaded", timeout=timeout_ms)
                await page.wait_for_timeout(700)
                executed = await _executed(page, marker)
                reload_detail = "completed"
        except Exception as exc:
            reload_detail = f"{type(exc).__name__}: {exc}"
    attempts.append({
        "mode": "fragment",
        "url": fragment_url,
        "navigation": detail,
        "reload": reload_detail,
        "executed": executed,
    })
    if executed:
        findings.append({
            "alert": "Browser-confirmed DOM XSS through URL fragment",
            "risk": "high",
            "category": "vulnerability",
            "verification_status": "playwright-browser-marker-executed",
            "confidence": "high",
            "description": "A harmless payload placed in location.hash executed in Chromium without being sent to the server.",
            "impact": "An attacker can craft a URL that executes JavaScript in the application origin when opened by a victim.",
            "solution": "Do not insert location-derived data into HTML or script sinks; use textContent and strict validation.",
            "url": fragment_url,
            "method": "GET",
            "parameter": "location.hash",
            "payload": payload,
            "evidence": f"Chromium marker executed=True; marker={marker}; navigation={detail}",
            "owasp_category": "A03:2021 Injection",
            "cwe_id": "79",
        })
    return findings, attempts


async def _stored_check(
    page: Any,
    target_url: str,
    source_url: str,
    parameters: list[str],
    timeout_ms: int,
    allow_state_changes: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    diagnostic: dict[str, Any] = {"attempted": False}
    findings: list[dict[str, Any]] = []
    if not allow_state_changes or DESTRUCTIVE_RE.search(urlparse(target_url).path):
        diagnostic["reason"] = "state changes not authorized or route excluded"
        return findings, diagnostic
    start_url = source_url if source_url and _same_origin(target_url, source_url) else target_url
    ok, detail = await _safe_goto(page, start_url, timeout_ms)
    if not ok:
        diagnostic["navigation"] = detail
        return findings, diagnostic

    candidate_parameters = [value for value in parameters if XSS_NAME_RE.search(value)] or list(parameters)
    candidate_parameters = list(dict.fromkeys(candidate_parameters))[:2]
    for parameter in candidate_parameters:
        escaped = parameter.replace('"', '\\"')
        selector = f'[name="{escaped}"]'
        locator = page.locator(selector)
        try:
            if await locator.count() == 0:
                continue
        except Exception:
            continue
        marker = "SECOPS_STORED_" + str(int(time.time() * 1000))[-8:]
        payload = _marker_payload(marker)
        diagnostic["attempted"] = True
        diagnostic["parameter"] = parameter
        try:
            element = locator.first
            tag = await element.evaluate("el => el.tagName.toLowerCase()")
            field_type = await element.get_attribute("type") or ""
            if tag == "select":
                values = await element.locator("option").evaluate_all("els => els.map(e => e.value)")
                if values:
                    await element.select_option(str(values[0]))
            elif field_type.lower() not in {"hidden", "submit", "button", "file", "checkbox", "radio"}:
                await element.fill(payload)
            else:
                continue

            controls = await page.locator("form input, form textarea, form select").all()
            for other in controls[:80]:
                try:
                    name = await other.get_attribute("name") or ""
                    other_type = (await other.get_attribute("type") or "text").lower()
                    if not name or name == parameter or TOKEN_RE.search(name):
                        continue
                    if other_type in {"hidden", "submit", "button", "file", "reset", "checkbox", "radio"}:
                        continue
                    other_tag = await other.evaluate("el => el.tagName.toLowerCase()")
                    if other_tag == "select":
                        values = await other.locator("option").evaluate_all("els => els.map(e => e.value)")
                        if values:
                            await other.select_option(str(values[0]))
                    elif not await other.input_value():
                        await other.fill("secops")
                except Exception:
                    continue

            form = element.locator("xpath=ancestor::form[1]")
            if await form.count() == 0:
                continue
            await form.evaluate("form => form.requestSubmit ? form.requestSubmit() : form.submit()")
            await page.wait_for_timeout(1200)
            revisit_urls = list(dict.fromkeys([start_url, target_url, str(page.url)]))
            executed_url = ""
            for revisit in revisit_urls:
                if not _same_origin(target_url, revisit):
                    continue
                await _safe_goto(page, revisit, timeout_ms)
                if await _executed(page, marker):
                    executed_url = revisit
                    break
            diagnostic.update({"submitted": True, "marker": marker, "executed_url": executed_url})
            if executed_url:
                findings.append({
                    "alert": f"Browser-confirmed stored XSS in parameter '{parameter}'",
                    "risk": "high",
                    "category": "vulnerability",
                    "verification_status": "playwright-stored-marker-executed-after-revisit",
                    "confidence": "high",
                    "description": "A harmless payload submitted through the discovered form executed after the page was revisited in Chromium.",
                    "impact": "Stored attacker-controlled JavaScript can execute for every user who views the affected content, including privileged users.",
                    "solution": "Encode stored content at every output context, sanitize permitted markup, validate input and apply CSP as defence in depth.",
                    "url": executed_url,
                    "method": "POST",
                    "parameter": parameter,
                    "payload": payload,
                    "evidence": f"form_source={start_url}; action={target_url}; marker={marker}; executed_after_revisit=True",
                    "owasp_category": "A03:2021 Injection",
                    "cwe_id": "79",
                })
            break
        except Exception as exc:
            diagnostic["error"] = f"{type(exc).__name__}: {exc}"
    return findings, diagnostic


async def _run_browser_scan_core(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    source_url: str = "",
    timeout: int = 60,
    allow_state_changes: bool = False,
) -> dict[str, Any]:
    try:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright
    except Exception as exc:
        return skipped(
            "Browser XSS and Workflow Verifier",
            target_url,
            f"Playwright is not installed or importable: {type(exc).__name__}: {exc}. Run initScript.py to install Chromium support.",
            diagnosis="missing_playwright",
        )

    if not target_url.startswith(("http://", "https://")):
        return failure("Browser XSS and Workflow Verifier", target_url, "target_url must be absolute HTTP/HTTPS.")
    if source_url and not _same_origin(target_url, source_url):
        source_url = ""
    parameters = [str(value) for value in (parameters or []) if str(value)]
    timeout = max(15, min(int(timeout), 180))
    timeout_ms = timeout * 1000
    findings: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {
        "method": str(method or "GET").upper(),
        "parameters": parameters,
        "source_url": source_url,
        "allow_state_changes": bool(allow_state_changes),
        "playwright_api": "async",
    }

    try:
        async with async_playwright() as playwright:
            try:
                browser = await playwright.chromium.launch(headless=True)
                diagnostics["browser_executable"] = "playwright-managed"
            except PlaywrightError as exc:
                system_browser = next((
                    value for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "msedge")
                    if (value := shutil.which(name))
                ), None)
                if not system_browser:
                    return skipped(
                        "Browser XSS and Workflow Verifier",
                        target_url,
                        f"Playwright Chromium is not installed: {exc}. Run: python -m playwright install chromium",
                        diagnosis="missing_playwright_browser",
                    )
                browser = await playwright.chromium.launch(headless=True, executable_path=system_browser)
                diagnostics["browser_executable"] = system_browser
                diagnostics["managed_browser_error"] = str(exc)
            context = await browser.new_context(ignore_https_errors=True)
            try:
                if cookies:
                    await context.add_cookies(_browser_cookies(target_url, cookies))
                page = await context.new_page()
                page.set_default_timeout(timeout_ms)
                await page.add_init_script(
                    "document.addEventListener('DOMContentLoaded', () => { "
                    "document.documentElement.removeAttribute('data-secops-browser-xss'); });"
                )

                dom_findings, dom_attempts = await _dom_checks(page, target_url, parameters, timeout_ms)
                findings.extend(dom_findings)
                diagnostics["dom_attempts"] = dom_attempts

                if str(method or "GET").upper() == "POST":
                    stored_findings, stored_diag = await _stored_check(
                        page, target_url, source_url, parameters, timeout_ms, allow_state_changes
                    )
                    findings.extend(stored_findings)
                    diagnostics["stored"] = stored_diag
                else:
                    diagnostics["stored"] = {"attempted": False, "reason": "request method is not POST"}
            finally:
                await context.close()
                await browser.close()
    except Exception as exc:
        return failure(
            "Browser XSS and Workflow Verifier",
            target_url,
            f"Browser verification failed: {type(exc).__name__}: {exc}",
            diagnosis="browser_runtime_error",
        )

    return success(
        "Browser XSS and Workflow Verifier",
        target_url,
        f"Browser verification completed. Findings: {len(findings)}.",
        vulnerabilities=findings,
        diagnostics=diagnostics,
    )


@mcp.tool()
async def run_browser_scan(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    parameters: list[str] | None = None,
    source_url: str = "",
    timeout: int = 60,
    allow_state_changes: bool = False,
) -> dict:
    """Use async Chromium to verify DOM, reflected and stored XSS with harmless markers."""
    return await _run_browser_scan_core(
        target_url=target_url,
        cookies=cookies,
        method=method,
        data=data,
        parameters=parameters,
        source_url=source_url,
        timeout=timeout,
        allow_state_changes=allow_state_changes,
    )


def _once() -> int:
    try:
        arguments = json.loads(sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = asyncio.run(_run_browser_scan_core(**arguments))
    except Exception as exc:
        result = failure("Browser XSS and Workflow Verifier", "", f"One-shot browser scan failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio", show_banner=False)
