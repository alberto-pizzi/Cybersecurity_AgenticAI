from __future__ import annotations

import argparse
import getpass
import json
import os
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
)
from orchestratorAgenticCore import _model_matches, ensure_ollama_model, resolve_ai_model
from utils import canonical_cookie_header, cookie_names, same_origin


ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"


# Builds one ephemeral single-target assessment without requiring a JSON configuration file.
def _direct_assessment(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    parsed = urlparse(str(args.target or "").strip())
    protocol = str(parsed.scheme or "").lower()
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
        "port": parsed.port,
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

    login_path = str(credential.get("login_path") or "/dashboardSmartCity/").strip() or "/dashboardSmartCity/"
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

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context = browser.new_context(ignore_https_errors=True, user_agent="SecOps-Snap4City-Login/1.0")
        page = context.new_page()
        try:
            page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            username_field = _first_visible_locator(page, username_selectors)
            password_field = _first_visible_locator(page, password_selectors)
            if username_field is None and password_field is None:
                raise RuntimeError(
                    f"Snap4City login form was not found after opening {login_url}; current URL is {page.url}."
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
                page.wait_for_timeout(250)
            else:
                raise RuntimeError(f"Snap4City login did not return to the assessed application within {timeout_seconds}s; current URL is {page.url}.")

            page.goto(validation_url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(300)
            final_url = str(page.url or "")
            if not same_origin(target_url, final_url) or _looks_like_oidc_login_url(final_url):
                raise RuntimeError(f"Snap4City authenticated validation returned to the login flow: {final_url}")
            if _first_visible_locator(page, password_selectors) is not None:
                raise RuntimeError("Snap4City authenticated validation still exposes the login password form.")

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
    coverage = source.get("coverage") if isinstance(source.get("coverage"), dict) else {}
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
            "findings": findings,
            "all_findings": all_findings,
            "findings_by_category": source.get("findings_by_category") if isinstance(source.get("findings_by_category"), dict) else {},
            "scanner_results": results,
        },
        "assessment_context": context,
        "discovery": context.get("discovery") if isinstance(context.get("discovery"), dict) else {},
        "diagnostics": context.get("diagnostics") if isinstance(context.get("diagnostics"), dict) else {},
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
            jobs = list(iter_service_jobs(config))
        else:
            config, jobs = _direct_assessment(args)
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
            generated_pdfs = sorted(
                (path.resolve() for path in REPORTS_DIR.glob("*.pdf") if path.stat().st_mtime_ns >= job_started_ns),
                key=lambda path: path.stat().st_mtime_ns,
            )
            record["pdf_reports"] = [str(path) for path in generated_pdfs]
            record["reports"] = []
            for pdf_path in generated_pdfs:
                report_id = pdf_path.stem
                json_path = pdf_path.with_suffix(".json")
                html_path = pdf_path.with_suffix(".html")
                review_path = pdf_path.with_name(f"{report_id}.review.json")
                artifact = {
                    "job_id": job["id"],
                    "report_id": report_id,
                    "pdf_path": str(pdf_path),
                    "json_path": str(json_path.resolve()) if json_path.is_file() else None,
                    "html_path": str(html_path.resolve()) if html_path.is_file() else None,
                    "review_snapshot_path": str(review_path.resolve()) if review_path.is_file() else None,
                }
                record["reports"].append(artifact)
                results_data["report_artifacts"].append(artifact)
                results_data["reports_data"].append(_embedded_report_data(artifact))
            if completed.returncode:
                exit_code = 1
                if args.stop_on_error:
                    results_data["jobs"].append(record)
                    break
        results_data["jobs"].append(record)
        _write_results_data(results_data_path, results_data)

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
            print(f"[+] PDF report: {artifact.get('pdf_path') or 'not generated'}")
    else:
        print("[+] PDF report: not generated")
    print(f"[+] Results data JSON: {final_results_data_path.resolve()}")
    print(f"[+] Results data reference ID: {reference_id}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
