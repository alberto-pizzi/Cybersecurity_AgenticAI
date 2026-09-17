from __future__ import annotations

import argparse
import copy
import getpass
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from assessmentConfig import (
    SUPPORTED_MODELS,
    SUPPORTED_MODES,
    SUPPORTED_ORCHESTRATORS,
    default_max_rounds,
    iter_service_jobs,
    load_assessment_config,
    redacted_configuration,
    resolve_cookie_credential,
    service_credential_refs,
    target_is_local,
    validate_authorization_scope,
)
from utils import atomic_write_text, canonical_cookie_header, cookie_header_fingerprint, cookie_names, normalized_origin, normalized_hostname, same_origin, scanner_request_rate_policy, safe_bool_value, safe_int_value
from targetAuth import browser_oidc_login_session


ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"


# Resolves execution.request_rate without widening the accepted traffic envelope silently.
def _resolve_request_rate(config: dict[str, Any]) -> dict[str, Any]:
    execution = config.setdefault("execution", {})
    configured = "request_rate" in execution
    raw_value = execution.get("request_rate", 10)
    # The JSON contract accepts an actual integer, not a numeric string/float. Internal wrappers and
    # environment propagation may still use normalized float/string representations after this boundary.
    if configured and (isinstance(raw_value, bool) or not isinstance(raw_value, int)):
        policy = scanner_request_rate_policy(None)
        policy["requested"] = raw_value
        policy["fallback_applied"] = True
        policy["fallback_reason"] = "execution.request_rate must be a JSON integer between 1 and 50"
    else:
        policy = scanner_request_rate_policy(raw_value)
    policy["configured"] = configured
    policy["source"] = "execution.request_rate" if configured else "default"
    execution["request_rate"] = policy["effective"]
    return policy


# Propagates the normalized traffic policy to every child orchestrator/scanner process.
def _request_rate_environment(base_env: dict[str, str], policy: dict[str, Any]) -> dict[str, str]:
    env = dict(base_env)
    env["SECOPS_MAX_REQUEST_RATE"] = str(policy.get("effective", 10))
    env["SECOPS_REQUEST_RATE_REQUESTED"] = str(policy.get("requested", ""))
    env["SECOPS_REQUEST_RATE_CONFIGURED"] = "1" if policy.get("configured") else "0"
    env["SECOPS_REQUEST_RATE_FALLBACK"] = "1" if policy.get("fallback_applied") else "0"
    env["SECOPS_REQUEST_RATE_FALLBACK_REASON"] = str(policy.get("fallback_reason") or "")
    return env


# Builds one ephemeral single-target assessment without requiring a JSON configuration file.
def _direct_assessment(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if args.authorized_host_suffix:
        raise ValueError("--authorized-host-suffix is disabled; authorize each additional origin explicitly with --authorized-origin.")
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
        "max_rounds": args.max_rounds or default_max_rounds(args.mode or "balanced"),
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
            "allow_same_host_ports": bool(args.allow_same_host_ports),
            "discover_same_host_services": bool(args.discover_same_host_services),
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
    index = 0
    while index < len(redacted):
        flag = redacted[index]
        if flag in {"--cookies", "--secondary-cookies"} and index + 1 < len(redacted):
            redacted[index + 1] = "<redacted>"
            index += 2
            continue
        if flag == "--identity-cookie" and index + 1 < len(redacted):
            raw = str(redacted[index + 1])
            label = raw.split("=", 1)[0].strip() if "=" in raw else "identity"
            redacted[index + 1] = f"{label}=<redacted>"
            index += 2
            continue
        index += 1
    return redacted


# Applies command-line execution overrides without changing the source configuration file.
def _apply_execution_overrides(config: dict[str, Any], args: argparse.Namespace) -> None:
    execution = config.setdefault("execution", {})
    if args.orchestrator:
        execution["orchestrator"] = args.orchestrator
    if args.mode:
        previous_mode = str(execution.get("mode") or "balanced").strip().lower()
        execution["mode"] = args.mode
        if not args.max_rounds and str(args.mode).strip().lower() != previous_mode:
            execution["max_rounds"] = default_max_rounds(args.mode)
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
    if args.allow_same_host_ports is not None:
        authorization["allow_same_host_ports"] = bool(args.allow_same_host_ports)
    if args.discover_same_host_services is not None:
        authorization["discover_same_host_services"] = bool(args.discover_same_host_services)
    if args.authorized_host_suffix:
        raise ValueError("--authorized-host-suffix is disabled; authorize each additional origin explicitly with --authorized-origin.")


# Verifies that an explicitly selected local Agentic model is already installed before any service job starts.
def _verify_selected_agentic_model(config: dict[str, Any]) -> None:
    # Agentic model helpers pull in the MCP runtime. Keep that dependency lazy so
    # configuration-only operations (notably --dry-run) remain usable before the
    # full scanner stack is installed.
    from orchestratorAgenticCore import _model_matches, ensure_ollama_model, resolve_ai_model

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


# Credential cache entries are origin + application-path specific for browser/OIDC identities.
# The underlying browser storage remains identity-scoped and reusable, while each flattened Cookie
# header is re-resolved for the concrete path. Raw cookies may still be retried on another port of
# the exact same hostname/scheme only when allow_same_host_ports explicitly permits it.
def _credential_cache_key(reference: str, target_url: str) -> tuple[str, str]:
    """Cache one resolved identity for the concrete application path, not only its origin.

    Browser/OIDC storage can legitimately contain path-scoped cookies for multiple applications on
    the same origin. Reusing the flattened Cookie header obtained for /app-a on /app-b would either
    send an inapplicable cookie or omit the cookie that /app-b needs. The browser storage itself is
    still reused per identity; only the flattened child Cookie header is resolved per target path.
    """
    try:
        parsed = urlparse(str(target_url or ''))
        path = str(parsed.path or '/') or '/'
    except ValueError:
        path = '/'
    if not path.startswith('/'):
        path = '/' + path
    # Query/fragment do not define cookie path scope. Preserve the path itself, including a trailing
    # slash: HTTP cookie Path matching can distinguish /app from /app/, so collapsing them may reuse
    # a flattened Cookie header that is not applicable to the concrete request URL.
    return str(reference or ''), f"{normalized_origin(target_url)}{path}"


def _same_host_port_authorized(config: dict[str, Any], left_url: str, right_url: str) -> bool:
    authorization = config.get("authorization") or {}
    if not bool(authorization.get("allow_same_host_ports", False)):
        return False
    try:
        left = urlparse(str(left_url or ""))
        right = urlparse(str(right_url or ""))
        return (
            str(left.scheme or "").lower() in {"http", "https"}
            and str(left.scheme or "").lower() == str(right.scheme or "").lower()
            and normalized_hostname(left.hostname or "") == normalized_hostname(right.hostname or "")
            and bool(left.hostname)
            and bool(right.hostname)
        )
    except ValueError:
        return False


# Resolves one target session in this order: an existing cookie when it is applicable, saved browser
# SSO/storage state, then the username/password already resolved for this credential reference. The
# prompt path is attempted at most once for the whole assessment; later origins/ports never prompt again.
def _resolve_job_cookie(
    config: dict[str, Any],
    reference: str,
    target_url: str,
    cache: dict[tuple[str, str], str],
    runtime_auth_cache: dict[str, dict[str, Any]] | None = None,
) -> str:
    cache_key = _credential_cache_key(reference, target_url)
    if cache_key in cache:
        cached_value = cache[cache_key]
        # The flattened Cookie header is path-specific for browser/OIDC identities. A later job on
        # another application path may have updated runtime["resolved_cookie"], so a cache hit must
        # restore the cookie that belongs to *this* target before _runtime_auth_payload() fingerprints
        # it for the child. Otherwise CLI cookie and browser storage identity can become temporarily
        # mismatched when the same credential revisits an earlier application path.
        runtime_cache = runtime_auth_cache if runtime_auth_cache is not None else {}
        runtime = runtime_cache.get(reference)
        if isinstance(runtime, dict) and str(runtime.get("kind") or "") in {"browser_oidc", "snap4city_oidc"}:
            runtime["resolved_cookie"] = cached_value
        return cached_value

    credentials = config.get("credentials") or {}
    credential = credentials.get(reference)
    if not isinstance(credential, dict):
        raise ValueError(f"Unknown credential reference: {reference}")
    kind = str(credential.get("kind") or "").strip().lower()
    if kind == "cookie":
        value = resolve_cookie_credential(config, reference)
        if not value:
            print(f"[AUTH] Optional credential {reference!r} is unavailable; this identity will be omitted; the job may continue with any other available configured profile.")
        else:
            value = canonical_cookie_header(value)
            # A raw Cookie header has lost Domain/Path/Secure metadata. Remember the first hostname/origin
            # on which this credential is used and never copy it to a different hostname merely because
            # another job reuses the same credential reference. Same-host/same-scheme port reuse is the
            # only implicit expansion and is allowed only when the config explicitly enables it.
            runtime_cache = runtime_auth_cache if runtime_auth_cache is not None else {}
            runtime = runtime_cache.setdefault(reference, {
                "reference": reference,
                "kind": "cookie",
                "manual_cookie_origin": "",
            })
            target_origin = normalized_origin(target_url)
            manual_origin = str(runtime.get("manual_cookie_origin") or "")
            if not manual_origin:
                runtime["manual_cookie_origin"] = target_origin
            elif manual_origin != target_origin and not _same_host_port_authorized(config, manual_origin, target_origin):
                print(
                    f"[AUTH WARNING] Raw cookie credential {reference!r} is scoped to {manual_origin}; "
                    f"it will not be copied to different hostname/origin {target_origin}. "
                    "Use a separate credential reference or browser/OIDC storage for that destination."
                )
                value = ""
        cache[cache_key] = value
        return value
    if kind not in {"browser_oidc", "snap4city_oidc"}:
        raise ValueError(f"Credential {reference!r} has unsupported web credential kind={kind!r}.")

    runtime_cache = runtime_auth_cache if runtime_auth_cache is not None else {}
    runtime = runtime_cache.setdefault(reference, {
        "reference": reference,
        "kind": "browser_oidc",
        "credential": copy.deepcopy(credential),
        "username": "",
        "password": "",
        "storage_state": None,
        "oidc_issuer": "",
        "browser_login_completed": False,
        "manual_cookie_origin": "",
        "prompt_attempted": False,
    })

    username_env = str(credential.get("username_env") or "").strip()
    password_env = str(credential.get("password_env") or "").strip()
    if not runtime.get("username") and username_env:
        runtime["username"] = os.environ.get(username_env, "").strip()
    if not runtime.get("password") and password_env:
        runtime["password"] = os.environ.get(password_env, "")

    cookie_env = str(credential.get("cookie_env") or "").strip()
    manual_cookie = os.environ.get(cookie_env, "").strip() if cookie_env else ""
    if manual_cookie:
        try:
            manual_cookie = canonical_cookie_header(manual_cookie)
        except ValueError as exc:
            if bool(credential.get("optional", False)):
                print(f"[AUTH] Optional credential {reference!r} supplied an invalid cookie in {cookie_env}: {exc}; browser/username-password fallback will be tried.")
                manual_cookie = ""
            else:
                raise ValueError(f"Cookie environment variable {cookie_env!r} for credential {reference!r} is invalid: {exc}") from exc
        if manual_cookie:
            required_cookie_names = {
                str(name).strip().casefold()
                for name in credential.get("required_cookie_names") or []
                if str(name).strip()
            }
            present_cookie_names = {name.casefold() for name in cookie_names(manual_cookie)}
            missing_required = sorted(required_cookie_names - present_cookie_names)
            if missing_required:
                print(
                    f"[AUTH] Existing cookie for credential {reference!r} is missing required cookie(s) "
                    f"{', '.join(missing_required)}; saved browser/SSO state or username/password fallback will be tried instead."
                )
                manual_cookie = ""
    target_origin = normalized_origin(target_url)
    manual_origin = str(runtime.get("manual_cookie_origin") or "")
    manual_cookie_allowed = bool(
        manual_cookie
        and (
            not manual_origin
            or manual_origin == target_origin
            or _same_host_port_authorized(config, manual_origin, target_origin)
        )
    )
    storage_state = runtime.get("storage_state") if isinstance(runtime.get("storage_state"), dict) else None
    username = str(runtime.get("username") or "")
    password = str(runtime.get("password") or "")
    interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())

    if manual_cookie_allowed:
        # The cookie is still the first authentication mechanism actually sent to the target.
        # Prepare missing fallback credentials once in the runner, however, so that if the child
        # later proves the cookie invalid it can continue with saved browser state and finally the
        # original username/password without opening a second console prompt. Empty answers remain
        # valid for optional credentials and simply make the final fallback unavailable.
        if not storage_state and (not username or not password) and not bool(runtime.get("prompt_attempted")):
            runtime["prompt_attempted"] = True
            if not username and interactive:
                username = input(f"[AUTH:{reference}] Target username ({username_env or 'environment variable'} not set; optional fallback after cookie/SSO): ").strip()
            if not password and interactive:
                password = getpass.getpass(f"[AUTH:{reference}] Target password ({password_env or 'environment variable'} not set; optional fallback after cookie/SSO): ")
            runtime["username"] = username
            runtime["password"] = password

        value = manual_cookie
        if not manual_origin:
            runtime["manual_cookie_origin"] = target_origin
            reuse_note = ""
        elif manual_origin != target_origin:
            reuse_note = " on another explicitly authorized port of the same hostname"
        else:
            reuse_note = ""
        print(
            f"[AUTH] Trying existing target session from {cookie_env}{reuse_note}; "
            f"cookie names: {', '.join(cookie_names(value)) or 'none'}. "
            "The child orchestrator will validate it, then try saved browser/SSO state, then the original username/password if needed."
        )
        runtime["resolved_cookie"] = value
        cache[cache_key] = value
        return value

    # With no saved browser session, resolve the initial username/password once before the first login.
    # With a saved session, browser_oidc_login_session tries that state first and asks for credentials
    # only if the IdP actually presents a login form.
    if not storage_state and (not username or not password) and not bool(runtime.get("prompt_attempted")):
        runtime["prompt_attempted"] = True
        if not username and interactive:
            username = input(f"[AUTH:{reference}] Target username ({username_env or 'environment variable'} not set): ").strip()
        if not password and interactive:
            password = getpass.getpass(f"[AUTH:{reference}] Target password ({password_env or 'environment variable'} not set): ")
        runtime["username"] = username
        runtime["password"] = password

    if not storage_state and (not username or not password):
        if bool(credential.get("optional", False)):
            detail = "existing cookie is not applicable to this authorized origin/port and no reusable browser session or complete username/password is available"
            print(f"[AUTH] Optional credential {reference!r}: {detail}; this identity will be omitted; the job may continue with any other available configured profile.")
            cache[cache_key] = ""
            return ""
        missing = []
        if not username:
            missing.append(username_env or "username")
        if not password:
            missing.append(password_env or "password")
        raise ValueError("Missing target login credential(s): " + ", ".join(missing))

    print(f"[AUTH] Trying browser SSO/session for {target_url}; stored username/password are used only if the login flow requests them.")
    try:
        login_result = browser_oidc_login_session(
            target_url,
            username,
            password,
            credential,
            storage_state=storage_state,
            initial_login=not bool(runtime.get("browser_login_completed")),
            expected_oidc_issuer=str(runtime.get("oidc_issuer") or ""),
        )
    except RuntimeError as first_exc:
        # A saved SSO state may expire after the initial job. If no credentials were available yet,
        # allow one prompt now, then retry once; never prompt again later in the assessment.
        if storage_state and (not username or not password) and not bool(runtime.get("prompt_attempted")) and interactive:
            runtime["prompt_attempted"] = True
            if not username:
                username = input(f"[AUTH:{reference}] Target username ({username_env or 'environment variable'} not set): ").strip()
            if not password:
                password = getpass.getpass(f"[AUTH:{reference}] Target password ({password_env or 'environment variable'} not set): ")
            runtime["username"] = username
            runtime["password"] = password
            if username and password:
                try:
                    login_result = browser_oidc_login_session(
                        target_url,
                        username,
                        password,
                        credential,
                        storage_state=storage_state,
                        initial_login=not bool(runtime.get("browser_login_completed")),
                        expected_oidc_issuer=str(runtime.get("oidc_issuer") or ""),
                    )
                except RuntimeError as exc:
                    first_exc = exc
                else:
                    first_exc = None
        if first_exc is not None:
            if bool(credential.get("optional", False)):
                print(f"[AUTH] Automatic browser login failed: {first_exc}; this identity will be omitted; the job may continue with any other available configured profile.")
                cache[cache_key] = ""
                return ""
            raise ValueError(str(first_exc)) from first_exc

    value = str(login_result.get("cookie_header") or "")
    if not value:
        if bool(credential.get("optional", False)):
            print(f"[AUTH] Browser authentication for {reference!r} returned no application cookie; this identity will be omitted; the job may continue with any other available configured profile.")
            cache[cache_key] = ""
            return ""
        raise ValueError("Automatic browser login returned no application cookie.")
    runtime["storage_state"] = login_result.get("storage_state") if isinstance(login_result.get("storage_state"), dict) else runtime.get("storage_state")
    runtime["oidc_issuer"] = str(login_result.get("oidc_issuer") or runtime.get("oidc_issuer") or "")
    runtime["browser_login_completed"] = True
    runtime["username"] = username
    runtime["password"] = password
    reuse_note = "existing browser/SSO state" if login_result.get("sso_reused") else "the original username/password"
    print(f"[AUTH] Browser authentication succeeded using {reuse_note}; target cookie names: {', '.join(cookie_names(value)) or 'none'}.")
    runtime["resolved_cookie"] = value
    cache[cache_key] = value
    return value


def _runtime_auth_payload(config: dict[str, Any], job: dict[str, Any], runtime_auth_cache: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Serialize identity-bound browser/OIDC runtime state for every resolved identity.

    The child receives every resolved browser/OIDC identity so same-origin browser storage remains
    identity-correct. Cross-origin/same-host reuse is still governed by each credential's
    reuse_on_authorized_siblings flag. Cookie values are never written to this payload: a SHA-256
    fingerprint links each already-resolved child Cookie header to its own browser storage state.
    """
    effective_refs = [str(value).strip() for value in (job.get("_effective_credential_refs") or []) if str(value).strip()]
    if not effective_refs:
        fallback = str(job.get("credential_ref") or "").strip()
        if fallback:
            effective_refs = [fallback]
    identities: list[dict[str, Any]] = []
    for reference in effective_refs:
        runtime = runtime_auth_cache.get(reference)
        if not isinstance(runtime, dict) or str(runtime.get("kind") or "") not in {"browser_oidc", "snap4city_oidc"}:
            continue
        credential_options = runtime.get("credential") if isinstance(runtime.get("credential"), dict) else {}
        username = str(runtime.get("username") or "")
        password = str(runtime.get("password") or "")
        storage_state = runtime.get("storage_state") if isinstance(runtime.get("storage_state"), dict) else None
        if (not username or not password) and not storage_state:
            continue
        resolved_cookie = str(runtime.get("resolved_cookie") or "")
        if not resolved_cookie:
            continue
        try:
            canonical = canonical_cookie_header(resolved_cookie)
        except ValueError:
            canonical = resolved_cookie
        fingerprint = cookie_header_fingerprint(canonical)
        identities.append({
            "reference": reference,
            "cookie_fingerprint": fingerprint,
            "username": username,
            "password": password,
            "credential": copy.deepcopy(credential_options),
            "storage_state": storage_state,
            "oidc_issuer": str(runtime.get("oidc_issuer") or ""),
        })
    if not identities:
        return {}
    authorization = config.get("authorization") or {}
    return {
        "schema_version": 2,
        "kind": "browser_oidc_multi",
        # Preserve the actual CLI-primary identity even when it is a raw-cookie credential and
        # therefore has no browser/OIDC state row in ``identities``. The child must never infer
        # another browser identity as primary merely because it is the first serializable state.
        "primary_reference": effective_refs[0],
        "primary_origin": normalized_origin(str(job.get("target") or "")),
        "identities": identities,
        "allowed_origins": list(authorization.get("allowed_origins") or []),
    }


def _runtime_auth_environment(base_env: dict[str, str], payload: dict[str, Any]) -> tuple[dict[str, str], str]:
    env = dict(base_env)
    if not payload:
        env.pop("SECOPS_RUNTIME_AUTH_STATE", None)
        return env, ""
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="secops-target-auth-", suffix=".json", delete=False)
    try:
        json.dump(payload, handle, ensure_ascii=False)
        handle.flush()
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(handle.fileno(), 0o600)
            except OSError:
                pass
        path = handle.name
    finally:
        handle.close()
    env["SECOPS_RUNTIME_AUTH_STATE"] = path
    return env, path


# Coalesces equivalent same-route services into one scan while preserving every configured URL as a forced seed.
def _coalesce_same_route_jobs(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    order: list[tuple[Any, ...]] = []
    passthrough_positions: list[tuple[int, dict[str, Any]]] = []
    for position, job in enumerate(jobs):
        target = str(job.get('target') or '').strip()
        if not job.get('enabled') or not job.get('supported') or not target:
            passthrough_positions.append((position, dict(job)))
            continue
        try:
            parsed = urlparse(target)
            # Preserve the concrete URL path, including a trailing slash. /app and /app/ may be
            # distinct application routes and, critically, HTTP Cookie Path matching distinguishes
            # them. Query/fragment remain outside the coalescing key so same-route configured entry
            # URLs (for example dashboard IDs) still share one bounded full-pipeline scan while all
            # concrete URLs are retained as forced discovery seeds below.
            route = str(parsed.path or '/') or '/'
            origin = (parsed.scheme.lower(), normalized_hostname(parsed.hostname or ''), parsed.port or (443 if parsed.scheme.lower() == 'https' else 80))
        except ValueError:
            passthrough_positions.append((position, dict(job)))
            continue
        key = (
            str(job.get('asset_id') or ''), origin, route,
            tuple(str(value) for value in (job.get('credential_refs') or []) if str(value)),
            bool(job.get('auth_only')), job.get('allow_state_changes'), str(job.get('interactsh_injection_url') or ''),
        )
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(dict(job))

    merged_rows: list[tuple[int, dict[str, Any]]] = list(passthrough_positions)
    source_positions = {str(job.get('id') or ''): index for index, job in enumerate(jobs)}
    for key in order:
        bucket = grouped[key]
        first = dict(bucket[0])
        if len(bucket) == 1:
            merged_rows.append((source_positions.get(str(first.get('id') or ''), len(jobs)), first))
            continue
        entry_points: list[str] = []
        service_ids: list[str] = []
        for item in bucket:
            service_ids.append(str(item.get('service_id') or ''))
            for value in [str(item.get('target') or ''), *[str(seed) for seed in item.get('entry_points') or []]]:
                if value and value not in entry_points:
                    entry_points.append(value)
        first['entry_points'] = entry_points
        first['merged_service_ids'] = service_ids
        first['coalesced_service_count'] = len(bucket)
        first['notes'] = (str(first.get('notes') or '') + f' Runtime coalescing: {len(bucket)} same-route service entries are assessed once with every configured URL retained as a forced discovery seed.').strip()
        merged_rows.append((source_positions.get(str(bucket[0].get('id') or ''), len(jobs)), first))
    merged_rows.sort(key=lambda item: item[0])
    return [row for _, row in merged_rows]


# Uses existing credential validation/login paths as ordinary discovery seeds without changing target configuration.
def _credential_discovery_seeds(config: dict[str, Any], job: dict[str, Any]) -> list[str]:
    references = [str(value).strip() for value in (job.get('credential_refs') or []) if str(value).strip()]
    if not references:
        references = [value for value in (str(job.get('credential_ref') or '').strip(), str(job.get('secondary_credential_ref') or '').strip()) if value]
    target = str(job.get('target') or '').strip()
    if not target:
        return []
    selected: list[str] = []
    credentials = config.get('credentials') or {}
    for reference in references:
        credential = credentials.get(reference)
        if not isinstance(credential, dict):
            continue
        for key in ('validation_path', 'login_path'):
            raw = str(credential.get(key) or '').strip()
            if not raw:
                continue
            try:
                candidate = urljoin(target, raw)
            except Exception:
                continue
            if candidate and same_origin(target, candidate) and candidate not in selected:
                selected.append(candidate)
    return selected


# Builds one existing orchestrator command from a normalized service job.
def _build_command(
    config: dict[str, Any], job: dict[str, Any], *, resolve_secrets: bool = True, force_auth_only: bool = False,
    credential_cache: dict[tuple[str, str], str] | None = None,
    runtime_auth_cache: dict[str, dict[str, Any]] | None = None,
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
    for entry_point in job.get("entry_points") or []:
        command.extend(["--entry-point", str(entry_point)])
    for discovery_seed in _credential_discovery_seeds(config, job):
        command.extend(["--discovery-seed", discovery_seed])

    cache = credential_cache if credential_cache is not None else {}
    configured_refs = [str(value).strip() for value in (job.get("credential_refs") or []) if str(value).strip()]
    if not configured_refs:
        configured_refs = [value for value in (str(job.get("credential_ref") or "").strip(), str(job.get("secondary_credential_ref") or "").strip()) if value]
    configured_refs = list(dict.fromkeys(configured_refs))
    available_identities: list[tuple[str, str]] = []
    seen_sessions: dict[str, str] = {}
    for reference in configured_refs:
        value = _resolve_job_cookie(config, reference, job["target"], cache, runtime_auth_cache) if resolve_secrets else f"<credential:{reference}>"
        if not value:
            continue
        if resolve_secrets:
            try:
                canonical = canonical_cookie_header(value)
            except ValueError:
                canonical = value
            fingerprint = cookie_header_fingerprint(canonical)
            previous = seen_sessions.get(fingerprint)
            if previous:
                print(
                    f"[AUTH WARNING] Credential {reference!r} resolved to the same concrete application session as {previous!r}; "
                    "it is not added as a second authenticated identity because that would make cross-account/BOLA evidence misleading."
                )
                continue
            seen_sessions[fingerprint] = reference
        available_identities.append((reference, value))
    job["_effective_credential_refs"] = [reference for reference, _ in available_identities]
    if available_identities:
        primary_ref, primary_value = available_identities[0]
        command.extend(["--primary-identity-name", primary_ref, "--cookies", primary_value])
        for reference, value in available_identities[1:]:
            command.extend(["--identity-cookie", f"{reference}={value}"])
    else:
        primary_ref, primary_value = "", ""
    if force_auth_only or job.get("auth_only"):
        if not configured_refs:
            raise ValueError(f"Job {job['id']} requests auth_only but has no credential_refs/credential_ref.")
        if resolve_secrets and not available_identities:
            raise ValueError(f"Job {job['id']} requests auth_only but none of its configured identities is available.")
        command.append("--auth-only")

    authorization = config.get("authorization") or {}
    if bool(authorization.get("confirmed")):
        command.append("--authorized")
        for value in authorization.get("allowed_origins") or []:
            command.extend(["--authorized-origin", str(value)])
        if bool(authorization.get("allow_same_host_ports", False)):
            command.append("--allow-same-host-ports")
        if bool(authorization.get("discover_same_host_services", False)):
            command.append("--discover-same-host-services")
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
            "--max-rounds", str(int(execution.get("max_rounds") or default_max_rounds(str(execution.get("mode") or "balanced")))),
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
def _unique_run_stamp() -> str:
    # Microseconds + PID + random suffix make IDs collision-resistant even when separate assessment
    # processes start in the same second on the same host. No process-global coordination is needed.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    return f"{timestamp}_{os.getpid()}_{uuid.uuid4().hex[:8]}"

def _write_results_data(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, ensure_ascii=False, default=str))


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
    authenticated_identity_count = 0

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
        report_usable = True if source_status is None else (
            safe_bool_value(source_status.get("technical_json_loaded"), False)
            or safe_bool_value(source_status.get("review_snapshot_loaded"), False)
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
                    profiles[name] = profiles.get(name, False) or safe_bool_value(profile.get("authenticated"), False)
            elif str(profile).strip():
                profiles[str(profile)] = profiles.get(str(profile), False)
        for tool in context.get("expected_tools", []) if isinstance(context.get("expected_tools"), list) else []:
            if str(tool).strip():
                expected_tools.add(str(tool))
        secondary_identity_supplied = secondary_identity_supplied or safe_bool_value(context.get("secondary_identity_supplied"), False)
        authenticated_identity_count = max(
            authenticated_identity_count,
            max(0, safe_int_value(context.get("authenticated_identity_count"), 0)),
        )
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
        "authenticated_identity_count": max(
            authenticated_identity_count,
            sum(1 for authenticated in profiles.values() if authenticated),
        ),
        "secondary_identity_supplied": secondary_identity_supplied or max(
            authenticated_identity_count,
            sum(1 for authenticated in profiles.values() if authenticated),
        ) >= 2,
        "scan_mode": str((config.get("execution") or {}).get("mode") or "balanced"),
        "request_rate_policy": dict(results_data.get("traffic_policy") or {}),
        "allow_same_host_ports": bool((config.get("authorization") or {}).get("allow_same_host_ports", False)),
        "discover_same_host_services": bool((config.get("authorization") or {}).get("discover_same_host_services", False)),
        "authentication_scope_policy": (
            "authenticated destinations try an applicable existing cookie first; when same-host multi-port is enabled, "
            "the raw cookie may be tried on another authorized port of the exact same hostname and scheme and must validate; "
            "if rejected, saved browser/OIDC state is tried, followed by the username/password resolved once by the runner if the login flow requests them; "
            "a conclusively rejected speculative raw cookie is remembered per cookie+origin so later scanners do not retry it; "
            "raw cookies are never copied to a different hostname and no second child-console prompt is opened"
        ),
        "redirect_scope_policy": (
            "active scanners use explicit-origin authorization; same-host multi-port expansion is "
            + ("enabled (exact hostname, HTTP/HTTPS services on authorized ports)" if bool((config.get("authorization") or {}).get("allow_same_host_ports", False)) else "disabled")
            + "; project discovery follows bounded redirects only while each hop remains authorized; external scanner processes do not autonomously follow redirects, so scanner-internal redirect-dependent behavior is conservatively suppressed unless the destination was independently discovered; unauthorized destinations are observed but not queued"
        ),
        "allow_state_changes": (
            next(iter({safe_bool_value(row.get("allow_state_changes"), False) for row in results_data.get("jobs", []) if isinstance(row, dict)}))
            if len({safe_bool_value(row.get("allow_state_changes"), False) for row in results_data.get("jobs", []) if isinstance(row, dict)}) == 1
            else None
        ),
        "allow_state_changes_mixed": len({safe_bool_value(row.get("allow_state_changes"), False) for row in results_data.get("jobs", []) if isinstance(row, dict)}) > 1,
        "allow_state_changes_by_entry": {
            str(row.get("id") or index): safe_bool_value(row.get("allow_state_changes"), False)
            for index, row in enumerate(results_data.get("jobs", []), start=1) if isinstance(row, dict)
        },
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
    atomic_write_text(json_path, json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    atomic_write_text(review_path, json.dumps(build_review_snapshot(payload), indent=2, ensure_ascii=False, default=str))
    atomic_write_text(html_path, _render_html(payload))
    # PDF rendering is wrapped in its own try/except (mirroring servers/reporting/reportServer.py's
    # _generate_report) so that a PDF failure - e.g. WeasyPrint/its native Pango/Harfbuzz libraries
    # missing, or the Docker fallback being unavailable - degrades to "no PDF" instead of raising and
    # discarding the JSON/HTML/review-snapshot artifacts that were already written above. Previously
    # an exception here propagated out of this function entirely: the caller's except-block then
    # logged "Aggregate report generation failed" and kept the old per-job report list, silently
    # orphaning the aggregate HTML/JSON already on disk with no reference to them anywhere.
    pdf_error: str | None = None
    try:
        atomic_write_text(pdf_source_path, _render_html(payload, for_pdf=True))
        html2pdf(pdf_source_path, pdf_path)
    except Exception as exc:
        pdf_error = f"{type(exc).__name__}: {exc}"
        print(f"[!] Aggregate report PDF rendering failed; keeping JSON/HTML artifacts. {pdf_error}", file=sys.stderr)
    finally:
        pdf_source_path.unlink(missing_ok=True)
    result = {
        "job_id": "aggregate",
        "report_id": base,
        "pdf_path": str(pdf_path.resolve()) if pdf_path.is_file() else None,
        "json_path": str(json_path.resolve()),
        "html_path": str(html_path.resolve()),
        "review_snapshot_path": str(review_path.resolve()),
        "aggregate": True,
    }
    if pdf_error:
        result["pdf_error"] = pdf_error
    return result


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
    port_scope_group = parser.add_mutually_exclusive_group()
    port_scope_group.add_argument("--allow-same-host-ports", dest="allow_same_host_ports", action="store_true", default=None, help="Allow HTTP/HTTPS services on other ports of the same already-authorized exact hostname.")
    port_scope_group.add_argument("--no-allow-same-host-ports", dest="allow_same_host_ports", action="store_false", help="Keep authorization exact-origin/explicit-origin only; this is the default when the config field is absent.")
    service_discovery_group = parser.add_mutually_exclusive_group()
    service_discovery_group.add_argument("--discover-same-host-services", dest="discover_same_host_services", action="store_true", default=None, help="Proactively discover responsive HTTP/HTTPS services on the exact authorized hostname. Requires same-host multi-port authorization.")
    service_discovery_group.add_argument("--no-discover-same-host-services", dest="discover_same_host_services", action="store_false", help="Disable proactive same-host service discovery.")
    parser.add_argument("--authorized-host-suffix", action="append", default=[], help=argparse.SUPPRESS)
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
        request_rate_policy = _resolve_request_rate(config)
        if not args.dry_run:
            _verify_selected_agentic_model(config)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))

    effective_rate = float(request_rate_policy["effective"])
    if request_rate_policy.get("fallback_applied"):
        print(
            f"[RATE WARNING] execution.request_rate={request_rate_policy.get('requested')!r} is not accepted: "
            f"{request_rate_policy.get('fallback_reason')}. Using the default {effective_rate:g} requests/second.",
            file=sys.stderr,
        )
    elif request_rate_policy.get("configured"):
        print(f"[RATE] Active-scanner request rate: {effective_rate:g} requests/second (configured; maximum 50).")
    else:
        print(f"[RATE] Active-scanner request rate: {effective_rate:g} requests/second (default; execution.request_rate not specified).")

    if args.only:
        jobs = [job for job in jobs if job["id"] == args.only]
        if not jobs:
            parser.error(f"No service job matches --only {args.only!r}.")
    else:
        original_job_count = len(jobs)
        jobs = _coalesce_same_route_jobs(jobs)
        removed_jobs = original_job_count - len(jobs)
        merged_groups = [job for job in jobs if int(job.get('coalesced_service_count') or 1) > 1]
        if removed_jobs > 0:
            merged_service_count = sum(int(job.get('coalesced_service_count') or 1) for job in merged_groups)
            print(
                f"[PLAN] Coalesced {merged_service_count} same-route service entries into {len(merged_groups)} logical job(s); "
                f"{removed_jobs} duplicate full-pipeline run(s) were removed. Every configured URL remains a forced discovery seed and each logical job is reported once."
            )

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _unique_run_stamp()
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
        "traffic_policy": dict(request_rate_policy),
        "jobs": [],
        "report_artifacts": [],
        "reports_data": [],
    }

    exit_code = 0
    credential_cache: dict[tuple[str, str], str] = {}
    runtime_auth_cache: dict[str, dict[str, Any]] = {}
    orchestrator_kind = str((config.get("execution") or {}).get("orchestrator") or "deterministic").lower()
    for job_index, job in enumerate(jobs, start=1):
        report_prefix = "SecOps_Agentic_Assessment" if orchestrator_kind == "agentic" else "SecOps_Assessment"
        expected_report_id = f"{report_prefix}_{stamp}_j{job_index:03d}"
        record: dict[str, Any] = {
            "id": job["id"],
            "asset_id": job["asset_id"],
            "service_id": job["service_id"],
            "host": job["host"],
            "address": job.get("address") or None,
            "protocol": job["protocol"],
            "port": job["port"],
            "target": job["target"] or None,
            "expected_report_id": expected_report_id,
            "entry_points": list(job.get("entry_points") or []),
            "merged_service_ids": list(job.get("merged_service_ids") or []),
            "coalesced_service_count": int(job.get("coalesced_service_count") or 1),
            "credential_refs": list(job.get("credential_refs") or []),
            "credential_ref": job.get("credential_ref") or None,
            "secondary_credential_ref": job.get("secondary_credential_ref") or None,
            # Persist the effective job policy rather than only the execution-level default.
            # A service override may differ from another service in the same aggregate assessment.
            "allow_state_changes": bool(job.get("allow_state_changes")),
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
                config, job, resolve_secrets=not args.dry_run, force_auth_only=args.auth_only, credential_cache=credential_cache, runtime_auth_cache=runtime_auth_cache
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
            runtime_payload = _runtime_auth_payload(config, job, runtime_auth_cache)
            rate_env = _request_rate_environment(os.environ, request_rate_policy)
            rate_env["SECOPS_REPORT_RUN_ID"] = expected_report_id
            child_env, runtime_state_path = _runtime_auth_environment(rate_env, runtime_payload)
            try:
                completed = subprocess.run(command, cwd=ROOT, check=False, env=child_env)
            finally:
                if runtime_state_path:
                    try:
                        Path(runtime_state_path).unlink(missing_ok=True)
                    except OSError:
                        pass
            record["returncode"] = completed.returncode
            record["status"] = "success" if completed.returncode == 0 else "error"
            if completed.returncode != 0:
                record["reason"] = f"orchestrator exited with return code {completed.returncode}"
            # Correlate artifacts by the unique per-job report id supplied to the child. Do not scan
            # every file modified since job start: another assessment process may be writing to the
            # same reports directory at the same time. Emergency fallbacks are tied to the same prefix.
            report_bases: dict[str, dict[str, Path | None]] = {}
            for path in REPORTS_DIR.glob(f"{expected_report_id}*"):
                if not path.is_file() or path.name.endswith(".pdf-source.html"):
                    continue
                suffix = path.suffix.lower()
                report_id = path.name[:-len(".review.json")] if path.name.endswith(".review.json") else path.stem
                if not (report_id == expected_report_id or report_id.startswith(expected_report_id + "_Emergency_")):
                    continue
                if suffix == ".pdf":
                    report_bases.setdefault(report_id, {"pdf": None, "html": None})["pdf"] = path.resolve()
                elif suffix == ".html":
                    report_bases.setdefault(report_id, {"pdf": None, "html": None})["html"] = path.resolve()
                elif suffix in {".json"}:
                    report_bases.setdefault(report_id, {"pdf": None, "html": None})
            artifact_candidates: list[dict[str, Any]] = []
            for report_id, paths in sorted(report_bases.items()):
                pdf_path = paths.get("pdf")
                html_path = paths.get("html")
                json_path = REPORTS_DIR / f"{report_id}.json"
                review_path = REPORTS_DIR / f"{report_id}.review.json"
                artifact_candidates.append({
                    "job_id": job["id"],
                    "report_id": report_id,
                    "pdf_path": str(pdf_path) if isinstance(pdf_path, Path) and pdf_path.is_file() else None,
                    "json_path": str(json_path.resolve()) if json_path.is_file() else None,
                    "html_path": str(html_path) if isinstance(html_path, Path) and html_path.is_file() else None,
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
                "pdf_generated": bool(aggregate_artifact.get("pdf_path")),
            }
            if aggregate_artifact.get("pdf_error"):
                results_data["aggregate_report"]["pdf_error"] = aggregate_artifact["pdf_error"]
            print(f"[+] Aggregate logical-target report generated from {len(source_report_artifacts)} per-entry report artifact(s).")
            if not aggregate_artifact.get("pdf_path"):
                print(f"[!] Aggregate report PDF was not generated; HTML/JSON artifacts remain available. {aggregate_artifact.get('pdf_error') or ''}", file=sys.stderr)
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
