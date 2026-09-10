from __future__ import annotations

import argparse
import copy
import getpass
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from assessmentConfig import (
    SUPPORTED_MODELS,
    SUPPORTED_MODES,
    SUPPORTED_ORCHESTRATORS,
    iter_service_jobs,
    load_assessment_config,
    redacted_configuration,
    resolve_cookie_credential,
    target_is_local,
    validate_authorization_scope,
)
from orchestratorAgenticCore import _model_matches, ensure_ollama_model, resolve_ai_model
from utils import canonical_cookie_header, cookie_names, same_origin


ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"


# Builds one ephemeral single-target assessment without requiring a JSON configuration file.
def _direct_assessment(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        parsed = urlparse(str(args.target or "").strip())
        protocol = str(parsed.scheme or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise ValueError("--target must be a valid absolute HTTP/HTTPS URL with a valid port.") from exc
    if protocol not in {"http", "https"} or not parsed.hostname:
        raise ValueError("--target must be an absolute HTTP/HTTPS URL.")
    if args.auth_only and not args.cookies:
        raise ValueError("--auth-only requires --cookies.")
    if args.secondary_cookies and not args.cookies:
        raise ValueError("--secondary-cookies requires --cookies.")

    credentials: dict[str, Any] = {}
    primary_ref = ""
    secondary_ref = ""
    if args.cookies:
        primary_ref = "direct_primary"
        credentials[primary_ref] = {
            "kind": "cookie",
            "value": args.cookies,
            "purpose": "Primary cookie supplied directly to assessmentRunner.py",
        }
    if args.secondary_cookies:
        secondary_ref = "direct_secondary"
        credentials[secondary_ref] = {
            "kind": "cookie",
            "value": args.secondary_cookies,
            "purpose": "Secondary cookie supplied directly to assessmentRunner.py",
        }

    execution = {
        "orchestrator": args.orchestrator or "deterministic",
        "mode": args.mode or "balanced",
        "model": args.model or "snap4city",
        "max_rounds": args.max_rounds or 2,
        "require_ai": True if args.require_ai is None else bool(args.require_ai),
        "allow_state_changes": args.allow_state_changes,
    }
    config: dict[str, Any] = {
        "schema_version": 1,
        "platform": {
            "name": "Direct target assessment",
            "description": "Ephemeral assessment created from assessmentRunner.py command-line arguments.",
        },
        "authorization": {
            "confirmed": bool(args.authorized),
            "reference": "Command-line --authorized confirmation" if args.authorized else "",
            "allowed_origins": list(args.authorized_origin or []),
            "allowed_host_suffixes": list(args.authorized_host_suffix or []),
        },
        "credentials": credentials,
        "assets": [],
        "execution": execution,
    }
    job = {
        "id": "direct/target",
        "asset_id": "direct",
        "service_id": "target",
        "host": str(parsed.hostname or ""),
        "address": "",
        "protocol": protocol,
        "port": port,
        "target": str(args.target).strip(),
        "enabled": True,
        "supported": True,
        "unsupported_reason": "",
        "credential_ref": primary_ref,
        "credential_kind": "cookie" if primary_ref else "",
        "secondary_credential_ref": secondary_ref,
        "secondary_credential_kind": "cookie" if secondary_ref else "",
        "auth_only": bool(args.auth_only),
        "allow_state_changes": args.allow_state_changes,
        "interactsh_injection_url": "",
        "notes": "Direct command-line target",
    }
    return config, [job]


# Replaces credential values in a persisted command representation while keeping the executed argv unchanged.
def _redacted_command(command: list[str]) -> list[str]:
    redacted = list(command)
    for flag in ("--cookies", "--secondary-cookies"):
        try:
            index = redacted.index(flag)
        except ValueError:
            continue
        if index + 1 < len(redacted):
            redacted[index + 1] = "<redacted>"
    return redacted


# Applies command-line execution overrides without changing the source configuration file.
def _apply_execution_overrides(config: dict[str, Any], args: argparse.Namespace) -> None:
    execution = config.setdefault("execution", {})
    if args.orchestrator:
        execution["orchestrator"] = args.orchestrator
    if args.mode:
        execution["mode"] = args.mode
    if args.model:
        execution["model"] = args.model
    if args.max_rounds:
        execution["max_rounds"] = args.max_rounds
    if args.require_ai is not None:
        execution["require_ai"] = args.require_ai
    if args.allow_state_changes is not None:
        execution["allow_state_changes"] = args.allow_state_changes
    if args.authorized:
        config.setdefault("authorization", {})["confirmed"] = True
    authorization = config.setdefault("authorization", {})
    if args.authorized_origin:
        authorization["allowed_origins"] = list(dict.fromkeys([*(authorization.get("allowed_origins") or []), *args.authorized_origin]))
    if args.authorized_host_suffix:
        authorization["allowed_host_suffixes"] = list(dict.fromkeys([*(authorization.get("allowed_host_suffixes") or []), *args.authorized_host_suffix]))


# Verifies that an explicitly selected local Agentic model is already installed before any service job starts.
def _verify_selected_agentic_model(config: dict[str, Any]) -> None:
    execution = config.get("execution") or {}
    if str(execution.get("orchestrator") or "deterministic").lower() != "agentic":
        return
    alias = str(execution.get("model") or "snap4city").lower()
    provider, requested_model, _ = resolve_ai_model(alias)
    if provider != "ollama":
        return
    ollama_url = str(execution.get("ollama_url") or "http://127.0.0.1:11434").rstrip("/")
    selected_model, _ = ensure_ollama_model(ollama_url, requested_model, allow_pull=False)
    if not _model_matches(requested_model, selected_model):
        raise ValueError(
            f"Requested model {alias!r} ({requested_model}) is not installed in Ollama. "
            "Run initScript.py with the matching --prepare-ai/--agentic-model option first."
        )


# Returns the first visible locator among a small set of login-form selectors.
def _first_visible_locator(page: Any, selectors: tuple[str, ...]) -> Any | None:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() and locator.is_visible():
                return locator
        except Exception:
            continue
    return None


# Returns a short visible Keycloak diagnostic without exposing entered credentials.
def _keycloak_login_diagnostic(page: Any) -> str:
    error_selectors = (
        "#input-error", "#kc-error-message", ".kc-feedback-text", ".alert-error",
        "[role='alert']", ".pf-c-alert__title", ".pf-v5-c-alert__title",
    )
    for selector in error_selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() and locator.is_visible():
                text = " ".join(str(locator.inner_text() or "").split())
                if text:
                    return "credentials_rejected: " + text[:240]
        except Exception:
            continue
    additional_step_selectors = (
        "input[name='otp']", "input[name='totp']", "input[autocomplete='one-time-code']",
        "#otp", "#kc-otp-login-form",
    )
    if _first_visible_locator(page, additional_step_selectors) is not None:
        return "additional_authentication_step_required"
    return ""


# Reports whether a browser URL still belongs to the Keycloak/OIDC login flow rather than the assessed application.
def _looks_like_oidc_login_url(url: str) -> bool:
    path = str(urlparse(str(url or "")).path or "").lower().rstrip("/")
    return "/auth/realms/" in path or path.endswith(("/login", "/signin", "/sign-in"))


# Performs the real Snap4City browser login and returns only the target cookies consumed by the existing orchestrators.
def _snap4city_browser_login_cookie(
    target_url: str,
    username: str,
    password: str,
    credential: dict[str, Any],
) -> str:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(f"Playwright is unavailable for automatic Snap4City login: {type(exc).__name__}: {exc}") from exc

    login_path = str(credential.get("login_path") or "/").strip() or "/"
    validation_path = str(credential.get("validation_path") or login_path).strip() or login_path
    login_url = urljoin(target_url, login_path)
    validation_url = urljoin(target_url, validation_path)
    timeout_seconds = int(credential.get("timeout_seconds") or 60)
    timeout_ms = timeout_seconds * 1000
    headless = bool(credential.get("headless", True))

    username_selectors = (
        "#username",
        "input[name='username']",
        "input[autocomplete='username']",
        "input[type='email']",
    )
    password_selectors = (
        "#password",
        "input[name='password']",
        "input[autocomplete='current-password']",
        "input[type='password']",
    )
    submit_selectors = (
        "#kc-login",
        "input[type='submit']",
        "button[type='submit']",
        "button[name='login']",
    )
    login_trigger_selectors = (
        'button:has-text("login")',
        'a:has-text("login")',
        '[role="button"]:has-text("login")',
        "input[type='button'][value='login']",
        "input[type='button'][value='Login']",
        "input[type='submit'][value='login']",
        "input[type='submit'][value='Login']",
    )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context = browser.new_context(ignore_https_errors=True, user_agent="SecOps-Snap4City-Login/1.0")
        page = context.new_page()
        try:
            page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            username_field = _first_visible_locator(page, username_selectors)
            password_field = _first_visible_locator(page, password_selectors)
            if username_field is None and password_field is None:
                login_trigger = _first_visible_locator(page, login_trigger_selectors)
                if login_trigger is None:
                    raise RuntimeError(
                        f"Snap4City login form or login control was not found after opening {login_url}; current URL is {page.url}."
                    )
                login_trigger.click()
                form_deadline = time.monotonic() + timeout_seconds
                while time.monotonic() < form_deadline:
                    username_field = _first_visible_locator(page, username_selectors)
                    password_field = _first_visible_locator(page, password_selectors)
                    if username_field is not None or password_field is not None:
                        break
                    page.wait_for_timeout(250)
                if username_field is None and password_field is None:
                    raise RuntimeError(
                        f"Snap4City login control was activated but the OIDC/Keycloak form did not appear within {timeout_seconds}s; "
                        f"current URL is {page.url}."
                    )
            if username_field is not None:
                username_field.fill(username)

            if password_field is None:
                submit = _first_visible_locator(page, submit_selectors)
                if submit is None:
                    raise RuntimeError("Snap4City login page exposes a username field but no submit control.")
                submit.click()
                page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
                password_field = _first_visible_locator(page, password_selectors)
            if password_field is None:
                raise RuntimeError("Snap4City login flow did not expose a password field.")

            password_field.fill(password)
            submit = _first_visible_locator(page, submit_selectors)
            if submit is not None:
                submit.click()
            else:
                password_field.press("Enter")

            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                current_url = str(page.url or "")
                password_still_visible = _first_visible_locator(page, password_selectors) is not None
                if same_origin(target_url, current_url) and not _looks_like_oidc_login_url(current_url) and not password_still_visible:
                    break
                diagnostic = _keycloak_login_diagnostic(page)
                if diagnostic.startswith("credentials_rejected:"):
                    message = diagnostic.split(":", 1)[1].strip()
                    raise RuntimeError(f"Snap4City/Keycloak rejected the supplied target credentials: {message}")
                if diagnostic == "additional_authentication_step_required":
                    raise RuntimeError("Snap4City/Keycloak requires an additional authentication step such as OTP; automatic username/password login cannot complete it.")
                page.wait_for_timeout(250)
            else:
                diagnostic = _keycloak_login_diagnostic(page)
                password_still_visible = _first_visible_locator(page, password_selectors) is not None
                if diagnostic.startswith("credentials_rejected:"):
                    message = diagnostic.split(":", 1)[1].strip()
                    raise RuntimeError(f"Snap4City/Keycloak rejected the supplied target credentials: {message}")
                if password_still_visible and _looks_like_oidc_login_url(str(page.url or "")):
                    raise RuntimeError(
                        "Snap4City login remained on the Keycloak password form; the credentials may be invalid or the account may require an additional login step. "
                        f"Current URL is {page.url}."
                    )
                raise RuntimeError(f"Snap4City login did not return to the assessed application within {timeout_seconds}s; current URL is {page.url}.")

            page.goto(validation_url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(300)
            final_url = str(page.url or "")
            if not same_origin(target_url, final_url) or _looks_like_oidc_login_url(final_url):
                raise RuntimeError(f"Snap4City authenticated validation returned to the login flow: {final_url}")
            if _first_visible_locator(page, password_selectors) is not None:
                raise RuntimeError("Snap4City authenticated validation still exposes the login password form.")
            if _first_visible_locator(page, login_trigger_selectors) is not None:
                raise RuntimeError("Snap4City authenticated validation still exposes the anonymous login control.")

            cookie_rows = list(context.cookies([validation_url]))
            if not cookie_rows:
                raise RuntimeError("Snap4City login completed in Chromium but no target cookie was available for the HTTP orchestrators.")
            cookie_rows.sort(key=lambda row: len(str(row.get("path") or "/")), reverse=True)
            selected: dict[str, tuple[str, str]] = {}
            for row in cookie_rows:
                name = str(row.get("name") or "").strip()
                value = str(row.get("value") or "")
                if name and name.lower() not in selected:
                    selected[name.lower()] = (name, value)
            header = canonical_cookie_header("; ".join(f"{name}={value}" for name, value in selected.values()))
            required = {str(name).strip().lower() for name in credential.get("required_cookie_names") or [] if str(name).strip()}
            present = {name.lower() for name in cookie_names(header)}
            missing = sorted(required - present)
            if missing:
                raise RuntimeError("Snap4City login completed but required target cookie(s) are missing: " + ", ".join(missing))
            return header
        finally:
            browser.close()


# Resolves an authenticated target session from a manual cookie or from the configured Snap4City OIDC browser login.
def _resolve_job_cookie(
    config: dict[str, Any],
    reference: str,
    target_url: str,
    cache: dict[str, str],
) -> str:
    if reference in cache:
        return cache[reference]
    credentials = config.get("credentials") or {}
    credential = credentials.get(reference)
    if not isinstance(credential, dict):
        raise ValueError(f"Unknown credential reference: {reference}")
    kind = str(credential.get("kind") or "").strip().lower()
    if kind == "cookie":
        value = resolve_cookie_credential(config, reference)
        if not value:
            print(f"[AUTH] Optional credential {reference!r} is unavailable; the job will run the anonymous profile only.")
        cache[reference] = value
        return value
    if kind != "snap4city_oidc":
        raise ValueError(f"Credential {reference!r} has unsupported web credential kind={kind!r}.")

    cookie_env = str(credential.get("cookie_env") or "").strip()
    if cookie_env:
        manual_cookie = os.environ.get(cookie_env, "").strip()
        if manual_cookie:
            value = canonical_cookie_header(manual_cookie)
            print(f"[AUTH] Using existing target session from {cookie_env}; cookie names: {', '.join(cookie_names(value)) or 'none'}")
            cache[reference] = value
            return value

    username_env = str(credential.get("username_env") or "DASHBOARD_TEST_USERNAME").strip()
    password_env = str(credential.get("password_env") or "DASHBOARD_TEST_PASSWORD").strip()
    username = os.environ.get(username_env, "").strip() if username_env else ""
    password = os.environ.get(password_env, "") if password_env else ""
    interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())

    if not username and interactive:
        username = input(f"[AUTH] Snap4City username ({username_env} not set): ").strip()
    if not password and interactive:
        password = getpass.getpass(f"[AUTH] Snap4City password ({password_env} not set): ")

    if not username or not password:
        if bool(credential.get("optional", False)):
            print(
                f"[AUTH] Optional credential {reference!r} has no usable Snap4City username/password; "
                "the job will run the anonymous profile only."
            )
            cache[reference] = ""
            return ""
        missing = []
        if not username:
            missing.append(username_env or "username")
        if not password:
            missing.append(password_env or "password")
        raise ValueError("Missing Snap4City login credential(s): " + ", ".join(missing))

    print(f"[AUTH] Performing automatic Snap4City login for {target_url} with Chromium.")
    try:
        value = _snap4city_browser_login_cookie(target_url, username, password, credential)
    except RuntimeError as exc:
        if bool(credential.get("optional", False)):
            print(f"[AUTH] Automatic Snap4City login failed: {exc}; the job will run the anonymous profile only.")
            cache[reference] = ""
            return ""
        raise ValueError(str(exc)) from exc
    print(f"[AUTH] Automatic Snap4City login succeeded; target cookie names: {', '.join(cookie_names(value)) or 'none'}")
    cache[reference] = value
    return value


# Builds one existing orchestrator command from a normalized service job.
def _build_command(
    config: dict[str, Any], job: dict[str, Any], *, resolve_secrets: bool = True, force_auth_only: bool = False,
    credential_cache: dict[str, str] | None = None,
) -> list[str]:
    execution = config.get("execution") or {}
    orchestrator = str(execution.get("orchestrator") or "deterministic").lower()
    script = "orchestratorAgentic.py" if orchestrator == "agentic" else "orchestratorDeterministic.py"
    command = [
        sys.executable,
        str(ROOT / script),
        "--target", job["target"],
        "--mode", str(execution.get("mode") or "balanced"),
    ]

    cache = credential_cache if credential_cache is not None else {}
    primary_ref = str(job.get("credential_ref") or "")
    primary_value = ""
    if primary_ref:
        primary_value = _resolve_job_cookie(config, primary_ref, job["target"], cache) if resolve_secrets else f"<credential:{primary_ref}>"
        if primary_value:
            command.extend(["--cookies", primary_value])
    secondary_ref = str(job.get("secondary_credential_ref") or "")
    if secondary_ref:
        secondary_value = _resolve_job_cookie(config, secondary_ref, job["target"], cache) if resolve_secrets else f"<credential:{secondary_ref}>"
        if secondary_value:
            command.extend(["--secondary-cookies", secondary_value])
    if force_auth_only or job.get("auth_only"):
        if not primary_ref:
            raise ValueError(f"Job {job['id']} requests auth_only but has no credential_ref.")
        if resolve_secrets and not primary_value:
            raise ValueError(f"Job {job['id']} requests auth_only but optional credential {primary_ref!r} is unavailable.")
        command.append("--auth-only")

    authorization = config.get("authorization") or {}
    if bool(authorization.get("confirmed")):
        command.append("--authorized")
        for value in authorization.get("allowed_origins") or []:
            command.extend(["--authorized-origin", str(value)])
        for value in authorization.get("allowed_host_suffixes") or []:
            command.extend(["--authorized-host-suffix", str(value)])
    elif not target_is_local(job["target"]):
        raise ValueError(
            f"Job {job['id']} targets a non-local service, but authorization.confirmed is not true."
        )

    state_change_setting = job.get("allow_state_changes")
    if state_change_setting is True:
        command.append("--allow-state-changes")
    elif state_change_setting is False:
        command.append("--no-allow-state-changes")
    if job.get("interactsh_injection_url"):
        command.extend(["--interactsh-injection-url", str(job["interactsh_injection_url"])])

    if orchestrator == "agentic":
        model = str(execution.get("model") or "snap4city")
        command.extend([
            "--model", model,
            "--max-rounds", str(int(execution.get("max_rounds") or 2)),
        ])
        if bool(execution.get("require_ai", True)):
            command.append("--require-ai")
        if model in {"llama", "qwen"}:
            command.append("--no-model-pull")
        ollama_url = str(execution.get("ollama_url") or "").strip()
        if ollama_url:
            command.extend(["--ollama-url", ollama_url])
        snap4city_api_url = str(execution.get("snap4city_api_url") or "").strip()
        if snap4city_api_url:
            command.extend(["--snap4city-api-url", snap4city_api_url])
        snap4city_credentials = str(execution.get("snap4city_credentials") or "").strip()
        if snap4city_credentials:
            command.extend(["--snap4city-credentials", snap4city_credentials])
    return command


# Writes redacted assessment result data that can be reviewed without exposing target credentials.
def _write_results_data(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


# Loads one JSON artifact when present; malformed or missing artifacts stay explicit instead of aborting the runner.
def _load_json_artifact(path_value: str | None) -> tuple[dict[str, Any] | None, str | None]:
    if not path_value:
        return None, "artifact path unavailable"
    path = Path(path_value)
    if not path.is_file():
        return None, f"artifact not found: {path}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"artifact could not be loaded: {type(exc).__name__}: {exc}"
    if not isinstance(payload, dict):
        return None, "artifact root is not a JSON object"
    return payload, None


# Builds the self-contained, redacted dataset used for later analysis without repeating the security scan.
def _embedded_report_data(artifact: dict[str, Any]) -> dict[str, Any]:
    technical, technical_error = _load_json_artifact(artifact.get("json_path"))
    review, review_error = _load_json_artifact(artifact.get("review_snapshot_path"))
    source = technical or review or {}
    context = source.get("assessment_context") if isinstance(source.get("assessment_context"), dict) else {}
    if not context and isinstance(review, dict) and isinstance(review.get("assessment_context"), dict):
        context = review.get("assessment_context") or {}

    results = source.get("results") if isinstance(source.get("results"), dict) else {}
    if not results and isinstance(review, dict) and isinstance(review.get("results"), dict):
        results = review.get("results") or {}

    summary = source.get("summary") if isinstance(source.get("summary"), dict) else {}
    coverage = source.get("coverage") if isinstance(source.get("coverage"), list) else []
    endpoint_coverage = source.get("endpoint_coverage") if isinstance(source.get("endpoint_coverage"), list) else []
    endpoint_coverage_summary = source.get("endpoint_coverage_summary") if isinstance(source.get("endpoint_coverage_summary"), dict) else {}
    if not endpoint_coverage and isinstance(review, dict) and isinstance(review.get("endpoint_coverage"), list):
        endpoint_coverage = review.get("endpoint_coverage") or []
    if not endpoint_coverage_summary and isinstance(review, dict) and isinstance(review.get("endpoint_coverage_summary"), dict):
        endpoint_coverage_summary = review.get("endpoint_coverage_summary") or {}
    findings = source.get("findings") if isinstance(source.get("findings"), list) else []
    all_findings = source.get("all_findings") if isinstance(source.get("all_findings"), list) else []
    if not all_findings and isinstance(review, dict) and isinstance(review.get("findings"), list):
        all_findings = review.get("findings") or []

    planner_audit = context.get("planner_audit") if isinstance(context.get("planner_audit"), list) else []
    if not planner_audit and isinstance(review, dict) and isinstance(review.get("planner_audit"), list):
        planner_audit = review.get("planner_audit") or []
    ai_analysis_summary = context.get("ai_analysis") if isinstance(context.get("ai_analysis"), dict) else {}
    if not ai_analysis_summary and isinstance(review, dict) and isinstance(review.get("ai_analysis"), dict):
        ai_analysis_summary = review.get("ai_analysis") or {}
    finding_ai_analysis = []
    for finding in all_findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("ai_analysis"), dict):
            continue
        finding_ai_analysis.append({
            "title": finding.get("title") or finding.get("alert") or finding.get("name"),
            "tool": finding.get("tool"),
            "url": finding.get("url"),
            "parameter": finding.get("parameter"),
            "analysis": finding.get("ai_analysis"),
        })

    return {
        "report_id": artifact.get("report_id"),
        "target": source.get("target") or (review or {}).get("target"),
        "generated_at": source.get("generated_at") or (review or {}).get("generated_at"),
        "reporting_policy": source.get("reporting_policy") or (review or {}).get("reporting_policy"),
        "report_metadata": {
            "client_name": source.get("client_name"),
            "assessor": source.get("assessor"),
            "assessment_type": source.get("assessment_type"),
            "assessment_start": source.get("assessment_start"),
            "assessment_end": source.get("assessment_end"),
            "report_version": source.get("report_version"),
            "security_findings_count": source.get("security_findings_count"),
            "candidate_findings_count": source.get("candidate_findings_count"),
            "observations_count": source.get("observations_count"),
            "findings_count": source.get("findings_count"),
        },
        "assessment_results": {
            "executive_summary": source.get("executive_summary"),
            "summary": summary,
            "coverage": coverage,
            "endpoint_coverage": endpoint_coverage,
            "endpoint_coverage_summary": endpoint_coverage_summary,
            "findings": findings,
            "all_findings": all_findings,
            "findings_by_category": source.get("findings_by_category") if isinstance(source.get("findings_by_category"), dict) else {},
            "scanner_results": results,
        },
        "assessment_context": context,
        "discovery": context.get("discovery") if isinstance(context.get("discovery"), dict) else {},
        "diagnostics": context.get("diagnostics") if isinstance(context.get("diagnostics"), (dict, list)) else {},
        "agentic_decisions": {
            "planner_source": context.get("planner_source"),
            "planner_rounds": context.get("planner_rounds"),
            "planner_notes": context.get("planner_notes") if isinstance(context.get("planner_notes"), list) else [],
            "planner_audit": planner_audit,
            "reasoning_summaries": [
                str(item.get("reasoning_summary") or "")
                for item in planner_audit
                if isinstance(item, dict) and str(item.get("reasoning_summary") or "").strip()
            ],
            "breadth_review_reasoning": [
                str(item.get("review_reasoning") or "")
                for item in planner_audit
                if isinstance(item, dict) and str(item.get("review_reasoning") or "").strip()
            ],
        },
        "ai_analysis": {
            "summary": ai_analysis_summary,
            "findings": finding_ai_analysis,
        },
        "artifacts": dict(artifact),
        "source_artifact_status": {
            "technical_json_loaded": technical is not None,
            "technical_json_error": technical_error,
            "review_snapshot_loaded": review is not None,
            "review_snapshot_error": review_error,
        },
    }


# Executes the configured HTTP/HTTPS services sequentially through the existing orchestrators.

def _aggregate_report_requested(config: dict[str, Any]) -> tuple[bool, bool]:
    reporting = config.get("reporting") if isinstance(config.get("reporting"), dict) else {}
    return bool(reporting.get("aggregate_report", False)), bool(reporting.get("keep_job_reports", True))


def _annotate_aggregate_provenance(result: dict[str, Any], *, job_id: str, target: str, report_id: str) -> dict[str, Any]:
    """Copy one job result and attach entry-point provenance to every raw finding."""
    annotated = copy.deepcopy(result)

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        node.setdefault("aggregate_source_job_id", job_id)
        node.setdefault("aggregate_source_entry_point", target)
        if report_id:
            node.setdefault("aggregate_source_report_id", report_id)
        vulnerabilities = node.get("vulnerabilities")
        if isinstance(vulnerabilities, list):
            for finding in vulnerabilities:
                if not isinstance(finding, dict):
                    continue
                finding.setdefault("aggregate_source_job_id", job_id)
                finding.setdefault("aggregate_source_entry_point", target)
                if report_id:
                    finding.setdefault("aggregate_source_report_id", report_id)
        runs = node.get("runs")
        if isinstance(runs, list):
            for run in runs:
                visit(run)

    visit(annotated)
    return annotated


def _aggregate_report_inputs(results_data: dict[str, Any], config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
    aggregate_results: dict[str, dict[str, Any]] = {}
    profiles: dict[str, bool] = {}
    expected_tools: set[str] = set()
    entry_points: list[dict[str, Any]] = []
    entry_points_by_job: dict[str, dict[str, Any]] = {}
    discovery_by_entry: dict[str, Any] = {}
    diagnostics_by_entry: dict[str, Any] = {}
    endpoint_selection_by_entry: dict[str, Any] = {}
    secondary_identity_supplied = False

    # Start from runner job records so an entry point remains visible even when its orchestrator
    # exits before producing a per-job report. Non-web inventory rows have no target and are not
    # counted as web entry points in the aggregate report.
    for job_index, job in enumerate(results_data.get("jobs", []), start=1):
        if not isinstance(job, dict):
            continue
        target = str(job.get("target") or "").strip()
        if not target:
            continue
        job_id = str(job.get("id") or f"entry-{job_index}")
        entry = {
            "job_id": job_id,
            "target": target,
            "report_id": None,
            "report_available": False,
            "status": str(job.get("status") or "unknown"),
            "reason": str(job.get("reason") or ""),
        }
        entry_points.append(entry)
        entry_points_by_job[job_id] = entry
        if entry["status"] in {"error", "blocked"}:
            diagnostics_by_entry[job_id] = [{
                "phase": "assessment_runner",
                "type": "job_execution",
                "status": entry["status"],
                "message": entry["reason"] or f"Entry point finished with status {entry['status']} before a complete per-job report was available.",
            }]

    reported_jobs: set[str] = set()
    for row_index, row in enumerate(results_data.get("reports_data", []), start=1):
        if not isinstance(row, dict):
            continue
        artifact = row.get("artifacts") if isinstance(row.get("artifacts"), dict) else {}
        job_id = str(artifact.get("job_id") or f"entry-{row_index}")
        target = str(row.get("target") or "")
        report_id = str(row.get("report_id") or "")
        source_status = row.get("source_artifact_status") if isinstance(row.get("source_artifact_status"), dict) else None
        report_usable = True if source_status is None else bool(
            source_status.get("technical_json_loaded") or source_status.get("review_snapshot_loaded")
        )
        if report_usable:
            reported_jobs.add(job_id)
        if job_id in entry_points_by_job:
            entry = entry_points_by_job[job_id]
            if target and not entry.get("target"):
                entry["target"] = target
            entry["report_id"] = report_id or entry.get("report_id")
            entry["report_available"] = report_usable
        else:
            entry = {"job_id": job_id, "target": target, "report_id": report_id or None, "report_available": report_usable, "status": "reported", "reason": ""}
            entry_points.append(entry)
            entry_points_by_job[job_id] = entry
        if not report_usable:
            diagnostics_by_entry[job_id] = [{
                "phase": "assessment_runner",
                "type": "report_artifact",
                "status": "partial",
                "message": "The per-entry report artifact could not be loaded into the aggregate Results Data dataset.",
            }]

        context = row.get("assessment_context") if isinstance(row.get("assessment_context"), dict) else {}
        for profile in context.get("profiles", []) if isinstance(context.get("profiles"), list) else []:
            if isinstance(profile, dict):
                name = str(profile.get("name") or "").strip()
                if name:
                    profiles[name] = profiles.get(name, False) or bool(profile.get("authenticated"))
            elif str(profile).strip():
                profiles[str(profile)] = profiles.get(str(profile), False)
        for tool in context.get("expected_tools", []) if isinstance(context.get("expected_tools"), list) else []:
            if str(tool).strip():
                expected_tools.add(str(tool))
        secondary_identity_supplied = secondary_identity_supplied or bool(context.get("secondary_identity_supplied"))
        discovery_by_entry[job_id] = row.get("discovery") if isinstance(row.get("discovery"), dict) else {}
        row_diagnostics = row.get("diagnostics") if isinstance(row.get("diagnostics"), (dict, list)) else {}
        if row_diagnostics:
            diagnostics_by_entry[job_id] = row_diagnostics
        endpoint_selection_by_entry[job_id] = context.get("endpoint_selection") if isinstance(context.get("endpoint_selection"), dict) else {}

        scanner_results = ((row.get("assessment_results") or {}).get("scanner_results")
                           if isinstance(row.get("assessment_results"), dict) else {})
        if not isinstance(scanner_results, dict):
            continue
        for profile_name, tool_results in scanner_results.items():
            if not isinstance(tool_results, dict):
                continue
            profile_name = str(profile_name)
            aggregate_results.setdefault(profile_name, {})
            profiles.setdefault(profile_name, profile_name != "anonymous")
            for tool_key, result in tool_results.items():
                if not isinstance(result, dict):
                    continue
                aggregate_key = f"{tool_key}:{job_id}"
                suffix = 2
                while aggregate_key in aggregate_results[profile_name]:
                    aggregate_key = f"{tool_key}:{job_id}:{suffix}"
                    suffix += 1
                aggregate_results[profile_name][aggregate_key] = _annotate_aggregate_provenance(
                    result,
                    job_id=job_id,
                    target=target,
                    report_id=report_id,
                )

    targets = [row["target"] for row in entry_points if row.get("target")]
    origins = []
    for target in targets:
        try:
            parsed = urlparse(target)
            origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        except ValueError:
            origin = ""
        if origin:
            origins.append(origin)
    target_label = origins[0] if origins and len(set(origins)) == 1 else str((config.get("platform") or {}).get("name") or "Multi-entry assessment")

    status_counts: dict[str, int] = {}
    for entry in entry_points:
        status = str(entry.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    context = {
        "profiles": [{"name": name, "authenticated": authenticated} for name, authenticated in sorted(profiles.items())],
        "expected_tools": sorted(expected_tools),
        "discovery": discovery_by_entry,
        "endpoint_selection": endpoint_selection_by_entry,
        "diagnostics": diagnostics_by_entry,
        "entry_points": entry_points,
        "entry_point_count": len(entry_points),
        "entry_point_reports_available": len(reported_jobs),
        "entry_point_status_counts": status_counts,
        "logical_target_name": str((config.get("platform") or {}).get("name") or target_label),
        "multi_entry_target": True,
        "reporting_scope": "aggregate logical target",
        "secondary_identity_supplied": secondary_identity_supplied,
        "scan_mode": str((config.get("execution") or {}).get("mode") or "balanced"),
        "allow_state_changes": (config.get("execution") or {}).get("allow_state_changes"),
        "orchestration": {
            "engine": "assessmentRunner aggregate",
            "mode": str((config.get("execution") or {}).get("orchestrator") or ""),
            "entry_points": len(entry_points),
        },
    }
    return aggregate_results, context, target_label


def _generate_aggregate_report(results_data: dict[str, Any], config: dict[str, Any], assessment_id: str) -> dict[str, Any]:
    servers_dir = str((ROOT / "servers").resolve())
    if servers_dir not in sys.path:
        sys.path.insert(0, servers_dir)
    from reporting.coverage import _executive_text, build_coverage, build_endpoint_coverage, summarize, summarize_endpoint_coverage
    from reporting.findings import _finding_groups, _human_readable_findings, flatten_findings
    from reporting.html_report import _render_html
    from reporting.pdf_maker import html2pdf
    from reporting.revision_snapshot import build_review_snapshot
    from reporting.text_utils import _redact_value, _safe_name

    results, context, target_label = _aggregate_report_inputs(results_data, config)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    base = _safe_name(f"{assessment_id}_aggregate")
    json_path = REPORTS_DIR / f"{base}.json"
    html_path = REPORTS_DIR / f"{base}.html"
    pdf_path = REPORTS_DIR / f"{base}.pdf"
    review_path = REPORTS_DIR / f"{base}.review.json"
    pdf_source_path = REPORTS_DIR / f"{base}.pdf-source.html"

    all_findings = flatten_findings(results)
    findings, omitted_detail = _human_readable_findings(all_findings)
    coverage = build_coverage(results, context)
    endpoint_coverage = build_endpoint_coverage(results, context)
    endpoint_coverage_summary = summarize_endpoint_coverage(endpoint_coverage)
    summary = summarize(results, all_findings, coverage, context)
    summary["omitted_human_readable_detail"] = omitted_detail
    payload = {
        "generated_at": datetime.now(timezone.utc),
        "target": target_label,
        "reporting_policy": "Scanner-grounded aggregate report for multiple authorized entry points of one logical target; observed facts are not invented and per-entry evidence remains traceable in the Results Data dataset.",
        "executive_summary": _executive_text(summary, findings, context),
        "summary": summary,
        "coverage": coverage,
        "endpoint_coverage": endpoint_coverage,
        "endpoint_coverage_summary": endpoint_coverage_summary,
        "security_findings_count": sum(item["category"] == "vulnerability" for item in findings),
        "candidate_findings_count": sum(item["category"] == "candidate" for item in findings),
        "observations_count": sum(item["category"] in {"discovery", "observation"} for item in findings),
        "findings_count": len(findings),
        "findings": findings,
        "all_findings": all_findings,
        "findings_by_category": _finding_groups(findings),
        "assessment_context": _redact_value(context),
        "results": _redact_value(results),
        "client_name": "",
        "assessor": "",
        "assessment_type": "Multi-entry web application assessment",
        "assessment_start": "",
        "assessment_end": "",
        "report_version": "1.0",
        "report_id": base,
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    review_path.write_text(json.dumps(build_review_snapshot(payload), indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    html_path.write_text(_render_html(payload), encoding="utf-8")
    try:
        pdf_source_path.write_text(_render_html(payload, for_pdf=True), encoding="utf-8")
        html2pdf(pdf_source_path, pdf_path)
    finally:
        pdf_source_path.unlink(missing_ok=True)
    return {
        "job_id": "aggregate",
        "report_id": base,
        "pdf_path": str(pdf_path.resolve()) if pdf_path.is_file() else None,
        "json_path": str(json_path.resolve()),
        "html_path": str(html_path.resolve()),
        "review_snapshot_path": str(review_path.resolve()),
        "aggregate": True,
    }


def _archive_job_report_artifacts(results_data: dict[str, Any], assessment_id: str) -> list[dict[str, Any]]:
    supporting_dir = REPORTS_DIR / "supporting" / assessment_id
    supporting_dir.mkdir(parents=True, exist_ok=True)
    moved: list[dict[str, Any]] = []
    for artifact in results_data.get("report_artifacts", []):
        if not isinstance(artifact, dict):
            continue
        updated = dict(artifact)
        for key in ("pdf_path", "html_path", "json_path", "review_snapshot_path"):
            raw = artifact.get(key)
            if not raw:
                continue
            source = Path(str(raw))
            if not source.is_file():
                continue
            destination = supporting_dir / source.name
            if destination.exists():
                destination = supporting_dir / f"{source.stem}_{artifact.get('job_id','job')}{source.suffix}"
            shutil.move(str(source), str(destination))
            updated[key] = str(destination.resolve())
        updated["supporting"] = True
        moved.append(updated)
    return moved

# Selects the one human-facing report artifact for a job. A normal Assessment report
# always wins over an Emergency report when both were created during the same run.
def _report_artifact_is_emergency(artifact: dict[str, Any]) -> bool:
    report_id = str(artifact.get('report_id') or '').lower()
    return 'emergency' in report_id


def _report_artifact_mtime_ns(artifact: dict[str, Any]) -> int:
    values = []
    for key in ('pdf_path', 'html_path', 'json_path', 'review_snapshot_path'):
        raw = artifact.get(key)
        if not raw:
            continue
        path = Path(str(raw))
        if path.is_file():
            try:
                values.append(path.stat().st_mtime_ns)
            except OSError:
                pass
    return max(values, default=0)


def _select_primary_job_report_artifact(artifacts: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    rows = [dict(item) for item in artifacts if isinstance(item, dict)]
    if not rows:
        return None, []
    normal = [item for item in rows if not _report_artifact_is_emergency(item)]
    pool = normal or rows
    primary = max(
        pool,
        key=lambda item: (
            bool(item.get('pdf_path')),
            bool(item.get('html_path')),
            bool(item.get('json_path')),
            bool(item.get('review_snapshot_path')),
            _report_artifact_mtime_ns(item),
        ),
    )
    suppressed = [item for item in rows if item.get('report_id') != primary.get('report_id')]
    return primary, suppressed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one direct target or expand a multi-asset assessment JSON file through the existing deterministic or agentic orchestrators."
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--config", help="Platform assessment JSON file.")
    source_group.add_argument("--target", help="Direct HTTP/HTTPS target; alternative to --config.")
    parser.add_argument("--cookies", default="", help="Primary cookie header for direct --target mode. Without --auth-only, both anonymous and authenticated profiles are run.")
    parser.add_argument("--secondary-cookies", default="", help="Optional second authenticated identity for direct --target authorization/BOLA comparison.")
    parser.add_argument("--orchestrator", choices=tuple(sorted(SUPPORTED_ORCHESTRATORS)), default="", help="Override execution.orchestrator from the configuration.")
    parser.add_argument("--mode", choices=tuple(sorted(SUPPORTED_MODES)), default="", help="Override execution.mode from the configuration.")
    parser.add_argument("--model", choices=tuple(sorted(SUPPORTED_MODELS)), default="", help="Override the Agentic AI model selected in the configuration.")
    parser.add_argument("--max-rounds", type=int, choices=(1, 2, 3), default=0, help="Override Agentic maximum planning rounds.")
    parser.add_argument("--auth-only", action="store_true", help="Run only the authenticated profile. With a cookie and without this flag, both anonymous and authenticated profiles are run.")
    parser.add_argument("--authorized", action="store_true", help="Confirm that the configured non-local targets are explicitly authorized for assessment.")
    parser.add_argument("--authorized-origin", action="append", default=[], help="Additional exact HTTP/HTTPS origin included in the authorized scope; repeat as needed.")
    parser.add_argument("--authorized-host-suffix", action="append", default=[], help="Additional authorized DNS suffix included in the scope; repeat as needed.")
    state_change_group = parser.add_mutually_exclusive_group()
    state_change_group.add_argument("--allow-state-changes", dest="allow_state_changes", action="store_true", default=None, help="Explicitly allow bounded state-changing probes for this run.")
    state_change_group.add_argument("--no-allow-state-changes", dest="allow_state_changes", action="store_false", help="Explicitly disable bounded state-changing probes, including on local targets.")
    ai_group = parser.add_mutually_exclusive_group()
    ai_group.add_argument("--require-ai", dest="require_ai", action="store_true", default=None, help="Require successful Agentic planning and final AI analysis.")
    ai_group.add_argument("--no-require-ai", dest="require_ai", action="store_false", help="Allow the existing Agentic deterministic fallback when AI planning fails.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and persist the job plan without executing scanners.")
    parser.add_argument("--only", default="", help="Optional exact service job id, for example web01/https-main.")
    parser.add_argument("--stop-on-error", action="store_true", help="Stop after the first failed executable job.")
    args = parser.parse_args()

    try:
        if args.config:
            if args.cookies or args.secondary_cookies:
                raise ValueError("--cookies and --secondary-cookies are direct --target options; use credential references inside a configuration file.")
            config = load_assessment_config(args.config)
            _apply_execution_overrides(config, args)
            authorization = config.get("authorization") or {}
            validate_authorization_scope(authorization)
            jobs = list(iter_service_jobs(config))
        else:
            config, jobs = _direct_assessment(args)
            validate_authorization_scope(config.get("authorization") or {})
        _verify_selected_agentic_model(config)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))

    if args.only:
        jobs = [job for job in jobs if job["id"] == args.only]
        if not jobs:
            parser.error(f"No service job matches --only {args.only!r}.")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    platform_name = str((config.get("platform") or {}).get("name") or "platform")
    safe_name = "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in platform_name).strip("._") or "platform"
    assessment_id = f"{safe_name}_{stamp}"
    results_data_path = REPORTS_DIR / f"Assessment_Results_Data_{assessment_id}.json"
    results_data: dict[str, Any] = {
        "schema_version": 4,
        "dataset_type": "secops-assessment-results-data",
        "dataset_purpose": "Self-contained redacted evidence and decision dataset for later analysis without repeating the security scan.",
        "test_id": assessment_id,
        "assessment_id": assessment_id,
        "reference_id": assessment_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_config": str(Path(args.config).expanduser().resolve()) if args.config else None,
        "configuration": redacted_configuration(config),
        "jobs": [],
        "report_artifacts": [],
        "reports_data": [],
    }

    exit_code = 0
    credential_cache: dict[str, str] = {}
    for job in jobs:
        record: dict[str, Any] = {
            "id": job["id"],
            "asset_id": job["asset_id"],
            "service_id": job["service_id"],
            "host": job["host"],
            "address": job.get("address") or None,
            "protocol": job["protocol"],
            "port": job["port"],
            "target": job["target"] or None,
            "credential_ref": job.get("credential_ref") or None,
            "secondary_credential_ref": job.get("secondary_credential_ref") or None,
            "notes": job.get("notes") or "",
        }
        if not job.get("enabled"):
            record.update(status="skipped", reason="service disabled in configuration")
            results_data["jobs"].append(record)
            print(f"[SKIP] {job['id']}: disabled")
            continue
        if not job.get("supported"):
            record.update(status="skipped", reason=job.get("unsupported_reason"))
            results_data["jobs"].append(record)
            print(f"[SKIP] {job['id']}: {job.get('unsupported_reason')}")
            continue
        try:
            command = _build_command(
                config, job, resolve_secrets=not args.dry_run, force_auth_only=args.auth_only, credential_cache=credential_cache
            )
        except ValueError as exc:
            record.update(status="blocked", reason=str(exc))
            results_data["jobs"].append(record)
            print(f"[BLOCKED] {job['id']}: {exc}", file=sys.stderr)
            exit_code = 2
            if args.stop_on_error:
                break
            continue

        record["command"] = _redacted_command(command)
        if args.dry_run:
            record["status"] = "planned"
            print("[PLAN] " + " ".join(record["command"]))
        else:
            print(f"\n[RUN] {job['id']} -> {job['target']}")
            job_started_ns = time.time_ns()
            completed = subprocess.run(command, cwd=ROOT, check=False)
            record["returncode"] = completed.returncode
            record["status"] = "success" if completed.returncode == 0 else "error"
            if completed.returncode != 0:
                record["reason"] = f"orchestrator exited with return code {completed.returncode}"
            generated_pdfs = sorted(
                (path.resolve() for path in REPORTS_DIR.glob("*.pdf") if path.stat().st_mtime_ns >= job_started_ns),
                key=lambda path: path.stat().st_mtime_ns,
            )
            generated_html = sorted(
                (
                    path.resolve()
                    for path in REPORTS_DIR.glob("*.html")
                    if path.stat().st_mtime_ns >= job_started_ns and not path.name.endswith(".pdf-source.html")
                ),
                key=lambda path: path.stat().st_mtime_ns,
            )
            report_bases: dict[str, dict[str, Path | None]] = {}
            for pdf_path in generated_pdfs:
                report_bases[pdf_path.stem] = {"pdf": pdf_path, "html": pdf_path.with_suffix(".html")}
            for html_path in generated_html:
                report_bases.setdefault(html_path.stem, {"pdf": None, "html": html_path})
            artifact_candidates: list[dict[str, Any]] = []
            for report_id, paths in sorted(
                report_bases.items(),
                key=lambda item: max(
                    path.stat().st_mtime_ns for path in item[1].values() if isinstance(path, Path) and path.is_file()
                ),
            ):
                pdf_path = paths.get("pdf")
                html_path = paths.get("html")
                base_path = pdf_path if isinstance(pdf_path, Path) else html_path
                if not isinstance(base_path, Path):
                    continue
                json_path = base_path.with_suffix(".json")
                review_path = base_path.with_name(f"{report_id}.review.json")
                artifact_candidates.append({
                    "job_id": job["id"],
                    "report_id": report_id,
                    "pdf_path": str(pdf_path) if isinstance(pdf_path, Path) and pdf_path.is_file() else None,
                    "json_path": str(json_path.resolve()) if json_path.is_file() else None,
                    "html_path": str(html_path.resolve()) if isinstance(html_path, Path) and html_path.is_file() else None,
                    "review_snapshot_path": str(review_path.resolve()) if review_path.is_file() else None,
                })
            primary_artifact, suppressed_artifacts = _select_primary_job_report_artifact(artifact_candidates)
            record["reports"] = [primary_artifact] if primary_artifact else []
            record["pdf_reports"] = [str(primary_artifact.get("pdf_path"))] if primary_artifact and primary_artifact.get("pdf_path") else []
            if suppressed_artifacts:
                record["suppressed_report_artifacts"] = [
                    {"report_id": item.get("report_id"), "reason": "superseded by the normal primary report artifact"}
                    for item in suppressed_artifacts
                ]
                print(
                    f"[REPORT] Selected {primary_artifact.get('report_id')} as the primary job report; suppressed {len(suppressed_artifacts)} superseded recovery artifact(s).",
                    flush=True,
                )
            if primary_artifact:
                results_data["report_artifacts"].append(primary_artifact)
                results_data["reports_data"].append(_embedded_report_data(primary_artifact))
            if completed.returncode:
                exit_code = 1
                if args.stop_on_error:
                    results_data["jobs"].append(record)
                    break
        results_data["jobs"].append(record)
        _write_results_data(results_data_path, results_data)

    aggregate_requested, keep_job_reports = _aggregate_report_requested(config)
    source_report_artifacts = list(results_data.get("report_artifacts", []))
    aggregate_entry_points = [row for row in results_data.get("jobs", []) if isinstance(row, dict) and str(row.get("target") or "").strip()]
    if aggregate_requested and len(aggregate_entry_points) > 1 and not args.dry_run:
        try:
            aggregate_artifact = _generate_aggregate_report(results_data, config, assessment_id)
            aggregate_data = _embedded_report_data(aggregate_artifact)
            if keep_job_reports:
                results_data["supporting_report_artifacts"] = source_report_artifacts
            else:
                supporting = _archive_job_report_artifacts(results_data, assessment_id)
                results_data["supporting_report_artifacts"] = supporting
                supporting_by_id = {str(item.get("report_id") or ""): item for item in supporting}
                for job_record in results_data.get("jobs", []):
                    if not isinstance(job_record, dict):
                        continue
                    updated_reports = []
                    for item in job_record.get("reports", []) if isinstance(job_record.get("reports"), list) else []:
                        if not isinstance(item, dict):
                            continue
                        updated_reports.append(supporting_by_id.get(str(item.get("report_id") or ""), item))
                    if updated_reports:
                        job_record["reports"] = updated_reports
                        job_record["pdf_reports"] = [str(item.get("pdf_path")) for item in updated_reports if item.get("pdf_path")]
            results_data["report_artifacts"] = [aggregate_artifact]
            results_data["reports_data"] = [aggregate_data]
            results_data["aggregate_report"] = {
                "enabled": True,
                "entry_point_reports_merged": len(source_report_artifacts),
                "supporting_job_reports_kept": keep_job_reports,
            }
            print(f"[+] Aggregate logical-target report generated from {len(source_report_artifacts)} per-entry report artifact(s).")
        except Exception as exc:
            results_data["aggregate_report"] = {"enabled": True, "status": "error", "error": f"{type(exc).__name__}: {exc}"}
            print(f"[!] Aggregate report generation failed: {type(exc).__name__}: {exc}", file=sys.stderr)

    report_artifacts = list(results_data.get("report_artifacts", []))
    if len(report_artifacts) == 1 and report_artifacts[0].get("report_id"):
        reference_id = str(report_artifacts[0]["report_id"])
        final_results_data_path = REPORTS_DIR / f"Assessment_Results_Data_{reference_id}.json"
        results_data["report_id"] = reference_id
    else:
        reference_id = assessment_id
        final_results_data_path = REPORTS_DIR / f"Assessment_Results_Data_{reference_id}.json"
    results_data["reference_id"] = reference_id
    reports_data = [item for item in results_data.get("reports_data", []) if isinstance(item, dict)]
    if len(reports_data) == 1:
        single = reports_data[0]
        results_data["assessment_results"] = single.get("assessment_results") or {}
        results_data["assessment_context"] = single.get("assessment_context") or {}
        results_data["discovery"] = single.get("discovery") or {}
        results_data["diagnostics"] = single.get("diagnostics") or {}
        results_data["agentic_decisions"] = single.get("agentic_decisions") or {}
        results_data["ai_analysis"] = single.get("ai_analysis") or {}
    results_data["results_data_file"] = str(final_results_data_path.resolve())
    results_data["completed_at"] = datetime.now(timezone.utc).isoformat()
    _write_results_data(final_results_data_path, results_data)
    if final_results_data_path != results_data_path:
        results_data_path.unlink(missing_ok=True)

    print("\n=== Assessment final artifacts ===")
    if report_artifacts:
        for artifact in report_artifacts:
            pdf_path = artifact.get('pdf_path')
            html_path = artifact.get('html_path')
            emergency = _report_artifact_is_emergency(artifact)
            print(f"[+] PDF report: {pdf_path or 'not generated'}")
            if html_path:
                label = "Emergency HTML report" if emergency else ("HTML report (PDF fallback)" if not pdf_path else "HTML report")
                print(f"[+] {label}: {html_path}")
    else:
        print("[+] PDF report: not generated")
    print(f"[+] Results data JSON: {final_results_data_path.resolve()}")
    print(f"[+] Results data reference ID: {reference_id}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
