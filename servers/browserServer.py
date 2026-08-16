from __future__ import annotations

import re
import secrets
import shutil
from typing import Any
from urllib.parse import quote, urlparse

from utils import failure, parse_cookie_header, skipped, success

from utils import same_origin

from scannerCommon import mutate_parameter, service

mcp, _serve = service("Browser XSS and Workflow Verifier", "browser")

DESTRUCTIVE_RE = re.compile(
    r"(?:logout|signout|logoff|setup|install|delete|remove|drop|truncate|purge|wipe|reset|clear)", re.I,
)
TOKEN_RE = re.compile(r"(?:csrf|xsrf|token|nonce|authenticity|request[_-]?verification)", re.I)
XSS_NAME_RE = re.compile(
    r"(?:name|message|comment|search|query|q|text|title|input|html|body|content|url|redirect|default|description|bio|note)", re.I,
)
POSITIVE_SUBMIT_RE = re.compile(r"(?:submit|send|save|post|publish|sign|add|create|update|upload|change)", re.I)
NEGATIVE_SUBMIT_RE = re.compile(r"(?:clear|delete|remove|reset|cancel|logout|drop|purge)", re.I)

# Process browser cookies for authenticated scanner requests and session analysis.
def _browser_cookies(target_url: str, cookies: str) -> list[dict[str, Any]]:
    parsed = urlparse(target_url)
    rows: list[dict[str, Any]] = []
    for name, value in parse_cookie_header(cookies):
        rows.append({
            "name": name, "value": value, "domain": parsed.hostname or "localhost", "path": "/",
            "httpOnly": False, "secure": parsed.scheme == "https", "sameSite": "Lax",
        })
    return rows

# Create a short unique marker used to prove harmless browser-side execution.
def _short_marker(prefix: str = "S") -> str:
    return prefix[:1].upper() + secrets.token_hex(4).upper()

# Return harmless execution markers, shortest first when a field is bounded.
def _payload_candidates(marker: str, maxlength: int = 0) -> list[str]:

    candidates = [
        f"<svg/onload=document.body.id='{marker}'>", f"<img src=x onerror=document.body.id='{marker}'>",
        (
            '<img src=x onerror="document.documentElement.setAttribute('
            f"'data-secops-browser-xss','{marker}')\" data-secops-marker=\"{marker}\">"
        ),
        f"<script>document.documentElement.id='{marker}'</script>",
    ]
    unique = list(dict.fromkeys(candidates))
    if maxlength > 0:
        unique = [value for value in unique if len(value) <= maxlength]
    return unique

# Include context-breaking variants needed by select/attribute/script sinks.
def _query_payload_candidates(marker: str) -> list[str]:

    base = f"<svg/onload=document.body.id='{marker}'>"
    return list(dict.fromkeys([
        base, f"</option></select>{base}",
        f"'><svg/onload=document.body.id='{marker}'>", f'"><svg/onload=document.body.id="{marker}">',
        f"</script>{base}", f"';document.body.id='{marker}';//", f'";document.body.id="{marker}";//',
    ]))

# Check whether the browser executed the injected marker in the current page context.
async def _executed(page: Any, marker: str) -> bool:
    try:
        value = await page.evaluate(
            """marker => ({
                htmlMarker: document.documentElement.getAttribute('data-secops-browser-xss'),
                htmlId: document.documentElement.id,
                bodyId: document.body ? document.body.id : ''
            })""",
            marker,
        )
        return marker in {
            str((value or {}).get("htmlMarker") or ""), str((value or {}).get("htmlId") or ""),
            str((value or {}).get("bodyId") or ""),
        }
    except Exception:
        return False

# Check whether a payload is reflected in page content without claiming execution.
async def _reflection_present(page: Any, marker: str) -> bool:
    try:
        return marker in str(await page.content())
    except Exception:
        return False

# Perform goto with bounded behavior that preserves target and session safety.
async def _safe_goto(page: Any, url: str, timeout_ms: int) -> tuple[bool, str]:
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        await page.wait_for_timeout(700)
        return True, f"status={response.status if response else 'unknown'}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"

# Test query parameters with harmless browser payloads and record execution or reflection.
async def _query_checks(
    page: Any, target_url: str, parameters: list[str], timeout_ms: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    candidates = [value for value in parameters if value and XSS_NAME_RE.search(value)] or list(parameters)
    candidates = list(dict.fromkeys(candidates))[:5]
    for parameter in candidates:
        marker = _short_marker("Q")
        variants = _query_payload_candidates(marker)
        for payload_index, payload in enumerate(variants, start=1):
            mutated = mutate_parameter(target_url, "GET", "", parameter, payload, case_insensitive=True, clear_fragment=True)[0]
            ok, detail = await _safe_goto(page, mutated, timeout_ms)
            executed = ok and await _executed(page, marker)
            reflected = ok and await _reflection_present(page, marker)
            attempts.append({
                "mode": "query", "parameter": parameter, "payload_variant": payload_index, "url": mutated,
                "navigation": detail, "executed": executed, "reflected": reflected,
            })
            if executed:
                findings.append({
                    "alert": f"Browser-confirmed DOM or reflected XSS in parameter '{parameter}'", "risk": "high",
                    "category": "vulnerability", "verification_status": "playwright-browser-marker-executed", "confidence": "high",
                    "description": "A harmless event-handler payload executed in a real Chromium page context and set the expected DOM marker.",
                    "impact": "Attacker-controlled JavaScript can execute in the application origin and access data or actions available to the victim session.",
                    "solution": "Apply context-aware output encoding, avoid unsafe DOM sinks, sanitize untrusted HTML and use Content Security Policy as defence in depth.",
                    "url": mutated, "method": "GET", "parameter": parameter, "payload": payload,
                    "evidence": f"Chromium marker executed=True; marker={marker}; navigation={detail}; payload_variant={payload_index}",
                    "owasp_category": "A03:2021 Injection", "cwe_id": "79",
                })
                break
            if reflected:
                findings.append({
                    "alert": f"Browser-observed unexecuted HTML reflection in parameter '{parameter}'",
                    "risk": "medium", "category": "candidate",
                    "verification_status": "browser-reflection-without-marker-execution", "confidence": "medium",
                    "description": "The marker payload was present in the browser DOM, but its event handler did not execute during the bounded check.",
                    "impact": "The reflection may become exploitable in a different HTML, attribute or script context and needs manual validation.",
                    "solution": "Apply context-aware encoding and review the exact reflection context.",
                    "url": mutated, "method": "GET", "parameter": parameter, "payload": payload,
                    "evidence": f"marker_reflected=True; marker_executed=False; navigation={detail}; payload_variant={payload_index}",
                    "owasp_category": "A03:2021 Injection",
                })
                break
    return findings, attempts

# Inspect client-side source and URL sinks for DOM-XSS execution opportunities.
async def _client_source_checks(
    page: Any, target_url: str, timeout_ms: int, client_sources: list[str], client_sinks: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    sources = {str(value).lower() for value in client_sources if str(value)}
    sinks = [str(value) for value in client_sinks if str(value)]
    base_url = target_url.split("#", 1)[0]

    if any("window.name" in source for source in sources):
        marker = _short_marker("N")
        javascript = f"document.documentElement.id='{marker}'"
        try:
            await page.goto("about:blank", wait_until="domcontentloaded", timeout=timeout_ms)
            await page.evaluate("value => { window.name = value; }", javascript)
            ok, detail = await _safe_goto(page, base_url, timeout_ms)
            executed = ok and await _executed(page, marker)
        except Exception as exc:
            ok, detail, executed = False, f"{type(exc).__name__}: {exc}", False
        attempts.append({
            "mode": "window.name", "url": base_url, "navigation": detail, "executed": executed, "sinks": sinks,
        })
        if executed:
            findings.append({
                "alert": "Browser-confirmed DOM XSS through window.name", "risk": "high",
                "category": "vulnerability", "verification_status": "playwright-window-name-marker-executed", "confidence": "high",
                "description": "JavaScript supplied through window.name executed in Chromium and set a harmless DOM marker.",
                "impact": "An attacker-controlled browsing context can execute JavaScript in the affected application origin.",
                "solution": "Never pass window.name or other navigation-controlled values to eval, Function, document.write or HTML sinks. Use strict parsing and safe DOM APIs.",
                "url": base_url, "method": "GET", "parameter": "window.name", "payload": javascript,
                "evidence": f"marker={marker}; navigation={detail}; discovered_sinks={sinks}",
                "owasp_category": "A03:2021 Injection", "cwe_id": "79",
            })

    marker = _short_marker("H")
    fragment_payloads = _payload_candidates(marker)
    for payload_index, payload in enumerate(fragment_payloads, start=1):
        fragment_url = base_url + "#" + quote(payload, safe="<>/'\"=() -_:;")
        ok, detail = await _safe_goto(page, fragment_url, timeout_ms)
        executed = ok and await _executed(page, marker)
        if not executed and ok:
            try:
                await page.reload(wait_until="domcontentloaded", timeout=timeout_ms)
                await page.wait_for_timeout(700)
                executed = await _executed(page, marker)
            except Exception:
                pass
        attempts.append({
            "mode": "fragment", "payload_variant": payload_index, "url": fragment_url, "navigation": detail,
            "executed": executed, "sources": sorted(sources), "sinks": sinks,
        })
        if executed:
            findings.append({
                "alert": "Browser-confirmed DOM XSS through URL fragment", "risk": "high",
                "category": "vulnerability", "verification_status": "playwright-fragment-marker-executed", "confidence": "high",
                "description": "A harmless payload placed in location.hash executed in Chromium without being sent to the server.",
                "impact": "An attacker can craft a URL that executes JavaScript in the application origin when opened by a victim.",
                "solution": "Do not insert location-derived data into HTML or script sinks; use textContent and strict validation.",
                "url": fragment_url, "method": "GET", "parameter": "location.hash", "payload": payload,
                "evidence": f"Chromium marker executed=True; marker={marker}; navigation={detail}; payload_variant={payload_index}",
                "owasp_category": "A03:2021 Injection", "cwe_id": "79",
            })
            break
    return findings, attempts

# Normalize field metadata from the discovered request contract for workflow testing.
def _field_metadata(fields: list[dict[str, Any]], parameter: str) -> dict[str, Any]:
    for item in fields:
        if isinstance(item, dict) and str(item.get("name") or "").lower() == parameter.lower():
            return item
    return {}

# Fill and submit one discovered form with bounded marker payloads.
async def _submit_form(form: Any) -> tuple[bool, str]:
    submitters = form.locator("input[type=submit], button[type=submit], button:not([type])")
    rows: list[tuple[int, Any, str]] = []
    try:
        count = min(await submitters.count(), 20)
    except Exception:
        count = 0
    for index in range(count):
        item = submitters.nth(index)
        try:
            label = " ".join(filter(None, [
                await item.get_attribute("name") or "", await item.get_attribute("value") or "", await item.inner_text() or "",
            ])).strip()
        except Exception:
            continue
        if NEGATIVE_SUBMIT_RE.search(label):
            continue
        score = 20 if POSITIVE_SUBMIT_RE.search(label) else 0
        rows.append((score, item, label))
    if rows:
        _, submitter, label = sorted(rows, key=lambda row: -row[0])[0]
        try:
            await submitter.click()
            return True, f"clicked submitter: {label or 'unnamed'}"
        except Exception as exc:
            click_error = f"{type(exc).__name__}: {exc}"
        else:
            click_error = ""
    else:
        click_error = "no safe submitter found"
    try:
        await form.evaluate("form => form.requestSubmit ? form.requestSubmit() : form.submit()")
        return True, f"requestSubmit fallback; prior={click_error}"
    except Exception as exc:
        return False, f"submit failed: {type(exc).__name__}: {exc}; prior={click_error}"

# Submit a harmless stored-XSS marker and revisit the page to verify later execution.
async def _stored_check(
    context: Any, page: Any, target_url: str, source_url: str,
    parameters: list[str], fields: list[dict[str, Any]], timeout_ms: int, allow_state_changes: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    diagnostic: dict[str, Any] = {"attempted": False, "attempts": []}
    findings: list[dict[str, Any]] = []
    if not allow_state_changes or DESTRUCTIVE_RE.search(urlparse(target_url).path):
        diagnostic["reason"] = "state changes not authorized or route excluded"
        return findings, diagnostic
    start_url = source_url if source_url and same_origin(target_url, source_url) else target_url

    # Rank writable fields so likely persistent-text sinks are tested first.
    ranked: list[tuple[int, str]] = []
    for index, parameter in enumerate(dict.fromkeys(parameters)):
        meta = _field_metadata(fields, parameter)
        tag = str(meta.get("tag") or "").lower()
        field_type = str(meta.get("type") or "text").lower()
        if field_type in {"hidden", "submit", "button", "file", "checkbox", "radio", "reset"}:
            continue
        score = 0
        if tag == "textarea" or field_type == "textarea":
            score += 120
        if re.search(r"(?:message|comment|content|body|description|text|bio)", parameter, re.I):
            score += 80
        if XSS_NAME_RE.search(parameter):
            score += 30
        score -= index
        ranked.append((score, parameter))
    if not ranked:
        ranked = [(0, value) for value in dict.fromkeys(parameters)]

    for _, parameter in sorted(ranked, key=lambda row: -row[0])[:4]:
        ok, detail = await _safe_goto(page, start_url, timeout_ms)
        if not ok:
            diagnostic["attempts"].append({"parameter": parameter, "navigation": detail})
            continue
        escaped = parameter.replace('"', '\\"')
        locator = page.locator(f'[name="{escaped}"]')
        try:
            if await locator.count() == 0:
                diagnostic["attempts"].append({"parameter": parameter, "reason": "field not present"})
                continue
            element = locator.first
            tag = str(await element.evaluate("el => el.tagName.toLowerCase()") or "")
            field_type = str(await element.get_attribute("type") or "text").lower()
            if field_type in {"hidden", "submit", "button", "file", "checkbox", "radio", "reset"}:
                continue
            raw_max = await element.get_attribute("maxlength")
            try:
                maxlength = int(raw_max or 0)
            except ValueError:
                maxlength = 0
            marker = _short_marker("S")
            payloads = _payload_candidates(marker, maxlength)
            if not payloads:
                diagnostic["attempts"].append({
                    "parameter": parameter, "tag": tag,
                    "maxlength": maxlength, "reason": "field length is too short for a harmless executable marker",
                })
                continue

            # Submit harmless variants, then revisit in a fresh page to distinguish stored execution.
            for payload_index, payload in enumerate(payloads, start=1):
                await element.fill(payload)
                form = element.locator("xpath=ancestor::form[1]")
                if await form.count() == 0:
                    diagnostic["attempts"].append({"parameter": parameter, "reason": "ancestor form not found"})
                    break

                controls = form.locator("input, textarea, select")
                try:
                    control_count = min(await controls.count(), 80)
                except Exception:
                    control_count = 0
                for control_index in range(control_count):
                    other = controls.nth(control_index)
                    try:
                        name = await other.get_attribute("name") or ""
                        other_type = (await other.get_attribute("type") or "text").lower()
                        other_tag = await other.evaluate("el => el.tagName.toLowerCase()")
                        if not name or name == parameter or TOKEN_RE.search(name):
                            continue
                        if other_type in {"hidden", "submit", "button", "file", "reset", "checkbox", "radio"}:
                            continue
                        if other_tag == "select":
                            values = await other.locator("option").evaluate_all("els => els.map(e => e.value)")
                            if values:
                                await other.select_option(str(values[0]))
                        elif not await other.input_value():
                            await other.fill("secops")
                    except Exception:
                        continue

                submitted, submit_detail = await _submit_form(form)
                await page.wait_for_timeout(1200)
                executed_url = ""
                revisit_urls = list(dict.fromkeys([start_url, target_url, str(page.url)]))
                verification_page = await context.new_page()
                try:
                    for revisit in revisit_urls:
                        if not same_origin(target_url, revisit):
                            continue
                        await _safe_goto(verification_page, revisit, timeout_ms)
                        if await _executed(verification_page, marker):
                            executed_url = revisit
                            break
                finally:
                    await verification_page.close()

                attempt = {
                    "parameter": parameter, "tag": tag, "maxlength": maxlength, "payload_variant": payload_index,
                    "payload_length": len(payload), "submitted": submitted,
                    "submit_detail": submit_detail, "marker": marker, "executed_url": executed_url,
                }
                diagnostic["attempted"] = True
                diagnostic["attempts"].append(attempt)
                if executed_url:
                    findings.append({
                        "alert": f"Browser-confirmed stored XSS in parameter '{parameter}'", "risk": "high",
                        "category": "vulnerability",
                        "verification_status": "playwright-stored-marker-executed-after-fresh-page-revisit", "confidence": "high",
                        "description": "A harmless payload submitted through the discovered form executed after the page was revisited in a fresh Chromium page.",
                        "impact": "Stored attacker-controlled JavaScript can execute for every user who views the affected content, including privileged users.",
                        "solution": "Encode stored content at every output context, sanitize permitted markup, validate input and apply CSP as defence in depth.",
                        "url": executed_url, "method": "POST", "parameter": parameter, "payload": payload,
                        "evidence": (
                            f"form_source={start_url}; action={target_url}; marker={marker}; "
                            f"executed_after_fresh_page_revisit=True; {submit_detail}"
                        ),
                        "owasp_category": "A03:2021 Injection", "cwe_id": "79",
                    })
                    diagnostic["confirmed_parameter"] = parameter
                    return findings, diagnostic

                await _safe_goto(page, start_url, timeout_ms)
        except Exception as exc:
            diagnostic["attempts"].append({"parameter": parameter, "error": f"{type(exc).__name__}: {exc}"})
    if not diagnostic["attempted"]:
        diagnostic["reason"] = "no compatible field could carry a harmless executable marker"
    return findings, diagnostic

# Coordinate Chromium checks for DOM, reflected and stored XSS on one request case.
async def _run_browser_scan_core(
    target_url: str, cookies: str = "", method: str = "GET", data: str = "",
    parameters: list[str] | None = None, fields: list[dict[str, Any]] | None = None,
    source_url: str = "", client_sources: list[str] | None = None,
    client_sinks: list[str] | None = None, timeout: int = 60, allow_state_changes: bool = False,
) -> dict[str, Any]:
    try:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright
    except Exception as exc:
        return skipped(
            "Browser XSS and Workflow Verifier", target_url,
            f"Playwright is not installed or importable: {type(exc).__name__}: {exc}. Run initScript.py to install Chromium support.",
            diagnosis="missing_playwright",
        )

    if not target_url.startswith(("http://", "https://")):
        return failure("Browser XSS and Workflow Verifier", target_url, "target_url must be absolute HTTP/HTTPS.")
    if source_url and not same_origin(target_url, source_url):
        source_url = ""
    parameters = [str(value) for value in (parameters or []) if str(value)]
    fields = [dict(value) for value in (fields or []) if isinstance(value, dict)]
    client_sources = [str(value) for value in (client_sources or []) if str(value)]
    client_sinks = [str(value) for value in (client_sinks or []) if str(value)]
    timeout = max(15, min(int(timeout), 180))
    timeout_ms = timeout * 1000
    findings: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {
        "method": str(method or "GET").upper(), "parameters": parameters, "fields": fields, "source_url": source_url,
        "client_sources": client_sources, "client_sinks": client_sinks,
        "allow_state_changes": bool(allow_state_changes), "playwright_api": "async",
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
                        "Browser XSS and Workflow Verifier", target_url,
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

                query_findings, query_attempts = await _query_checks(page, target_url, parameters, timeout_ms)
                findings.extend(query_findings)
                source_findings, source_attempts = await _client_source_checks(
                    page, target_url, timeout_ms, client_sources, client_sinks
                )
                findings.extend(source_findings)
                diagnostics["dom_attempts"] = [*query_attempts, *source_attempts]

                if str(method or "GET").upper() == "POST":
                    stored_findings, stored_diag = await _stored_check(
                        context, page, target_url, source_url, parameters, fields, timeout_ms, allow_state_changes,
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
            "Browser XSS and Workflow Verifier", target_url,
            f"Browser verification failed: {type(exc).__name__}: {exc}", diagnosis="browser_runtime_error",
        )

    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in findings:
        key = (
            str(item.get("verification_status") or ""), str(item.get("parameter") or ""),
            urlparse(str(item.get("url") or target_url)).path,
        )
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return success(
        "Browser XSS and Workflow Verifier", target_url,
        f"Browser verification completed. Findings: {len(unique)}.", vulnerabilities=unique, diagnostics=diagnostics,
    )

# Use async Chromium to verify DOM, reflected and stored XSS with harmless markers.
@mcp.tool()
async def run_browser_scan(
    target_url: str, cookies: str = "", method: str = "GET", data: str = "",
    parameters: list[str] | None = None, fields: list[dict[str, Any]] | None = None,
    source_url: str = "", client_sources: list[str] | None = None,
    client_sinks: list[str] | None = None, timeout: int = 60, allow_state_changes: bool = False,
) -> dict:

    return await _run_browser_scan_core(
        target_url=target_url, cookies=cookies, method=method, data=data,
        parameters=parameters, fields=fields, source_url=source_url, client_sources=client_sources,
        client_sinks=client_sinks, timeout=timeout, allow_state_changes=allow_state_changes,
    )

if __name__ == "__main__":
    _serve()
