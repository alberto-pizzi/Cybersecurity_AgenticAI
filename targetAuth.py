from __future__ import annotations

import re
import shutil
import time
from typing import Any, Iterable
from urllib.parse import parse_qsl, urljoin, urlparse

from utils import canonical_cookie_header, cookie_names, normalized_origin, same_origin


class BrowserLoginError(RuntimeError):
    # Browser authentication failure carrying only entry points actually visited.
    def __init__(self, message: str, attempted_candidates: Iterable[str] | None = None):
        super().__init__(message)
        self.attempted_candidates = [str(value) for value in (attempted_candidates or []) if str(value)]



USERNAME_SELECTORS = (
    "#username",
    "input[name='username']",
    "input[autocomplete='username']",
    "input[type='email']",
)
PASSWORD_SELECTORS = (
    "#password",
    "input[name='password']",
    "input[autocomplete='current-password']",
    "input[type='password']",
)
SUBMIT_SELECTORS = (
    "input[type='submit']",
    "button[type='submit']",
    "button[name='login']",
)
LOGIN_TRIGGER_SELECTORS = (
    'button:has-text("login")',
    'a:has-text("login")',
    '[role="button"]:has-text("login")',
    "input[type='button'][value='login']",
    "input[type='button'][value='Login']",
    "input[type='submit'][value='login']",
    "input[type='submit'][value='Login']",
    'button:has-text("sign in")',
    'a:has-text("sign in")',
)
ERROR_SELECTORS = (
    "#input-error",
    ".alert-error",
    "[role='alert']",
    ".pf-c-alert__title",
    ".pf-v5-c-alert__title",
)
ADDITIONAL_STEP_SELECTORS = (
    "input[name='otp']",
    "input[name='totp']",
    "input[autocomplete='one-time-code']",
    "#otp",
)


def _first_visible_locator(page: Any, selectors: Iterable[str]) -> Any | None:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() and locator.is_visible():
                return locator
        except Exception:
            continue
    return None


def _login_diagnostic(page: Any) -> str:
    for selector in ERROR_SELECTORS:
        try:
            locator = page.locator(selector).first
            if locator.count() and locator.is_visible():
                text = " ".join(str(locator.inner_text() or "").split())
                if text:
                    return "credentials_rejected: " + text[:240]
        except Exception:
            continue
    if _first_visible_locator(page, ADDITIONAL_STEP_SELECTORS) is not None:
        return "additional_authentication_step_required"
    return ""


def looks_like_oidc_login_url(url: str) -> bool:
    """Detect an OAuth/OIDC authorization step using generic protocol signals."""
    try:
        parsed = urlparse(str(url or ""))
    except ValueError:
        return False
    path = str(parsed.path or "").lower().rstrip("/")
    names = {str(name).lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    # client_id is the strongest generic query signal. redirect_uri/response_type are accepted
    # together, but either one alone is too common in ordinary application routing to establish
    # an OIDC realm safely.
    protocol_signal = 'client_id' in names or {'redirect_uri', 'response_type'} <= names
    return protocol_signal or path.endswith(('/authorize', '/oauth2/authorize', '/oidc/authorize'))


def oidc_issuer_key(url: str) -> str:
    """Return a stable OAuth/OIDC authorization-endpoint key, never an arbitrary application URL."""
    raw = str(url or "")
    if not looks_like_oidc_login_url(raw):
        return ""
    try:
        parsed = urlparse(raw)
    except ValueError:
        return ""
    origin = normalized_origin(raw)
    if not origin:
        return ""
    path = str(parsed.path or '/').rstrip('/') or '/'
    # Keep the authorization endpoint path while discarding one-shot query values such as state/code.
    return origin + path


def observed_oidc_issuer(current_url: str, observed_auth_requests: list[str] | tuple[str, ...]) -> str:
    """Resolve a real observed OIDC authorization endpoint without inventing an issuer from an app page."""
    direct = oidc_issuer_key(str(current_url or ""))
    if direct:
        return direct
    for request_url in reversed(list(observed_auth_requests or ())):
        issuer = oidc_issuer_key(str(request_url or ""))
        if issuer:
            return issuer
    return ""


def oidc_credential_reuse_allowed(
    current_url: str, expected_oidc_issuer: str, observed_auth_requests: list[str] | tuple[str, ...]
) -> tuple[bool, str]:
    """Allow local-form reuse when no OIDC issuer exists; require the actual OIDC form to match otherwise."""
    observed = observed_oidc_issuer(current_url, observed_auth_requests)
    expected = str(expected_oidc_issuer or "").strip().rstrip("/")
    if not expected:
        # A primary local-form login has no OIDC issuer. With explicit sibling-credential reuse, the
        # same resolved credentials may be retried only on another already-authorized LOCAL form. If
        # the destination exposes an OIDC authorization flow, do not send local-form credentials to a
        # newly observed provider/realm merely because the network origin is authorized for testing.
        return (not bool(observed)), observed
    direct = oidc_issuer_key(str(current_url or ""))
    if direct and direct.rstrip("/") == expected:
        return True, observed
    # OAuth/OIDC providers commonly redirect from the authorization endpoint to a provider-local
    # login/authenticate route. Reuse remains safe only when this same attempt actually observed the
    # expected authorization endpoint and the credential form is still on that provider origin.
    same_provider_login = (
        bool(observed)
        and observed.rstrip("/") == expected
        and normalized_origin(str(current_url or "")) == normalized_origin(expected)
        and _looks_like_application_login_entry(str(current_url or ""))
    )
    return bool(same_provider_login), observed

def _looks_like_application_login_entry(url: str) -> bool:
    """Heuristic used only to prioritize browser authentication attempts, never to decide attack scope."""
    try:
        path = str(urlparse(str(url or "")).path or "").lower()
    except ValueError:
        return False
    return any(token in path for token in ('login', 'signin', 'sign-in', 'session', 'authenticate'))

def _preauth_safe_candidate(target_url: str, candidate: str) -> bool:
    """Keep generic pre-auth browsing same-origin, HTTP(S), GET-like and non-destructive."""
    try:
        parsed = urlparse(str(candidate or ""))
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"} or not same_origin(target_url, candidate):
        return False
    path_words = {part for part in re.split(r"[^a-z0-9]+", str(parsed.path or "").lower()) if part}
    blocked_actions = {"logout", "signout", "delete", "remove", "destroy", "install", "uninstall", "purge", "wipe", "drop", "truncate"}
    if path_words & blocked_actions:
        return False
    action_keys = {"action", "operation", "op", "task", "command"}
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if str(name).lower() in action_keys and str(value).lower() in blocked_actions:
            return False
    return True


def _preauth_link_score(url: str, label: str = "") -> int:
    """Rank same-origin pre-auth links without making any path application-specific."""
    try:
        parsed = urlparse(str(url or ""))
    except ValueError:
        return -10_000
    path = str(parsed.path or "/").lower()
    text = (path + " " + str(label or "").lower()).replace("_", "-")
    words = {part for part in re.split(r"[^a-z0-9]+", text) if part}
    score = 0
    if _looks_like_application_login_entry(url):
        score += 180
    if "login" in words:
        score += 160
    if "signin" in words or ("sign" in words and "in" in words):
        score += 150
    if words & {"auth", "authenticate", "authentication"}:
        score += 110
    if "account" in words:
        score += 70
    if "portal" in words:
        score += 55
    if words & {"app", "application"}:
        score += 35
    depth = len([part for part in path.split("/") if part])
    score += max(0, 30 - depth * 6)
    score -= min(30, len(path) // 12)
    if parsed.query:
        score -= 5
    return score


def _discover_pre_auth_candidates(page: Any, target_url: str, deadline: float, *, max_pages: int = 8, max_candidates: int = 12) -> list[str]:
    """Bounded same-origin browser discovery used only when login_path is not configured.

    It does not submit forms or click controls. It follows a small number of ordinary same-origin
    GET navigation links and stops early when a login form/control or an OIDC redirect is observed.
    """
    origin = normalized_origin(target_url)
    if not origin:
        return []
    seeds = _same_origin_candidates(target_url, [target_url, origin + "/"])
    queue: list[tuple[int, str]] = [(10_000 - index, value) for index, value in enumerate(seeds)]
    queued = {value for _, value in queue}
    visited: set[str] = set()
    selected: list[str] = []

    while queue and len(visited) < max(1, int(max_pages)) and time.monotonic() < deadline:
        queue.sort(key=lambda row: (-row[0], len(row[1]), row[1]))
        _, candidate = queue.pop(0)
        if candidate in visited or not _preauth_safe_candidate(target_url, candidate):
            continue
        visited.add(candidate)
        try:
            page.goto(candidate, wait_until="domcontentloaded", timeout=_remaining_ms(deadline, cap_ms=8000))
            page.wait_for_timeout(120)
        except Exception:
            continue

        current_url = str(page.url or "")
        if looks_like_oidc_login_url(current_url):
            selected.append(candidate)
            break
        if not same_origin(target_url, current_url):
            # A same-origin entry point that redirects to another non-OIDC origin is not a login
            # discovery candidate and is never followed further here.
            continue

        username_field = _first_visible_locator(page, USERNAME_SELECTORS)
        password_field = _first_visible_locator(page, PASSWORD_SELECTORS)
        login_trigger = _first_visible_locator(page, LOGIN_TRIGGER_SELECTORS)
        if username_field is not None or password_field is not None or login_trigger is not None:
            selected.append(current_url)
            break

        try:
            # Use the browser DOM directly instead of Playwright's selector engine. Some legacy/XHTML
            # applications expose custom selector behaviour that can make evaluate_all() fail with
            # `result is not iterable`; native querySelectorAll keeps this pre-auth discovery robust.
            rows = page.evaluate(
                """() => Array.from(document.querySelectorAll('a[href], [data-href], [data-url]')).slice(0, 240).map(element => ({
                    url: element.href || element.getAttribute('data-href') || element.getAttribute('data-url') || '',
                    label: (element.innerText || element.textContent || '').trim().slice(0, 160)
                }))"""
            )
        except Exception:
            rows = []

        ranked: list[tuple[int, str]] = []
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            raw = str(row.get("url") or "").strip()
            if not raw:
                continue
            try:
                resolved = raw if urlparse(raw).scheme else urljoin(current_url, raw)
            except Exception:
                continue
            resolved_values = _same_origin_candidates(target_url, [resolved])
            if not resolved_values:
                continue
            resolved = resolved_values[0]
            if resolved in visited or resolved in queued or not _preauth_safe_candidate(target_url, resolved):
                continue
            score = _preauth_link_score(resolved, str(row.get("label") or ""))
            ranked.append((score, resolved))

        for score, resolved in sorted(ranked, key=lambda row: (-row[0], len(row[1]), row[1]))[:max_candidates]:
            if resolved in queued:
                continue
            queued.add(resolved)
            queue.append((score, resolved))

    return list(dict.fromkeys(selected))


def _same_origin_candidates(target_url: str, values: Iterable[str]) -> list[str]:
    selected: list[str] = []
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        try:
            candidate = value if urlparse(value).scheme else urljoin(target_url.rstrip("/") + "/", value)
        except Exception:
            continue
        if not same_origin(target_url, candidate):
            continue
        if candidate not in selected:
            selected.append(candidate)
    return selected


def _target_cookie_header(context: Any, url: str, credential: dict[str, Any], *, enforce_required: bool) -> str:
    cookie_rows = list(context.cookies([url]))
    if not cookie_rows:
        return ""
    cookie_rows.sort(key=lambda row: len(str(row.get("path") or "/")), reverse=True)
    selected: dict[str, tuple[str, str]] = {}
    for row in cookie_rows:
        name = str(row.get("name") or "").strip()
        value = str(row.get("value") or "")
        if name and name.lower() not in selected:
            selected[name.lower()] = (name, value)
    if not selected:
        return ""
    header = canonical_cookie_header("; ".join(f"{name}={value}" for name, value in selected.values()))
    if enforce_required:
        required = {
            str(name).strip().lower()
            for name in credential.get("required_cookie_names") or []
            if str(name).strip()
        }
        present = {name.lower() for name in cookie_names(header)}
        missing = sorted(required - present)
        if missing:
            raise RuntimeError(
                "Browser login completed but required target cookie(s) are missing: " + ", ".join(missing)
            )
    return header


def _remaining_ms(deadline: float, *, cap_ms: int = 20_000, floor_ms: int = 1_000) -> int:
    remaining = max(0.0, deadline - time.monotonic())
    return max(floor_ms, min(cap_ms, int(remaining * 1000)))


def browser_oidc_login_session(
    target_url: str,
    username: str,
    password: str,
    credential: dict[str, Any],
    *,
    storage_state: dict[str, Any] | None = None,
    candidate_urls: Iterable[str] | None = None,
    initial_login: bool = False,
    include_configured_fallbacks: bool = True,
    expected_oidc_issuer: str = "",
) -> dict[str, Any]:
    """Obtain one origin-scoped application session without ever prompting for credentials.

    A previous Playwright storage state is imported first so an existing browser/OIDC SSO session can
    silently create an application cookie for a newly discovered sibling origin. If the identity provider
    asks for credentials again, the username/password already resolved by assessmentRunner are reused.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(
            f"Playwright is unavailable for automatic browser login: {type(exc).__name__}: {exc}"
        ) from exc

    origin = normalized_origin(target_url)
    if not origin:
        raise RuntimeError(f"Invalid target origin for automatic login: {target_url!r}")

    timeout_seconds = max(15, int(credential.get("timeout_seconds") or 60))
    headless = bool(credential.get("headless", True))
    configured_login_path = str(credential.get("login_path") or "").strip()
    configured_validation_path = str(credential.get("validation_path") or "").strip()
    explicit_candidates = _same_origin_candidates(target_url, candidate_urls or [])
    configured_values = [*[str(value) for value in credential.get("sibling_login_paths") or []]]
    if configured_login_path:
        configured_values.append(configured_login_path)
    if configured_validation_path:
        configured_values.append(configured_validation_path)
    configured_values.extend([target_url, origin + "/"])
    configured_candidates = _same_origin_candidates(target_url, configured_values) if include_configured_fallbacks else []
    candidates = []
    for value in [*explicit_candidates, *configured_candidates]:
        if value not in candidates:
            candidates.append(value)
    if not candidates:
        candidates = [origin + "/"]

    # The total deadline is shared across all candidate entry points so a dead sibling cannot multiply
    # the configured login timeout by the number of observed URLs.
    deadline = time.monotonic() + timeout_seconds
    failures: list[str] = []
    attempted_candidates: list[str] = []

    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=headless)
        except Exception as exc:
            # initScript normally installs the Playwright-managed browser. A system Chromium is a
            # safe compatibility fallback when the Python package is present but that cache was removed.
            system_chromium = next((path for name in ('chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable', 'msedge') if (path := shutil.which(name))), '')
            if not system_chromium:
                raise RuntimeError(f'Chromium could not be launched for automatic target authentication: {type(exc).__name__}: {exc}') from exc
            browser = playwright.chromium.launch(headless=headless, executable_path=system_chromium)
        context_kwargs: dict[str, Any] = {
            "ignore_https_errors": True,
            "user_agent": "SecOps-Browser-Login/3.0",
        }
        if isinstance(storage_state, dict) and (storage_state.get("cookies") or storage_state.get("origins")):
            context_kwargs["storage_state"] = storage_state
        context = browser.new_context(**context_kwargs)
        page = context.new_page()
        observed_auth_requests: list[str] = []

        def record_auth_request(request: Any) -> None:
            request_url = str(request.url or "")
            if looks_like_oidc_login_url(request_url):
                observed_auth_requests.append(request_url)

        def current_issuer(offset: int=0) -> str:
            return observed_oidc_issuer(str(page.url or ""), observed_auth_requests[offset:])

        def issuer_allowed(offset: int=0) -> tuple[bool, str]:
            # If the primary login used OIDC, credentials may be filled only on the same actual
            # authorization endpoint. A background request to that issuer is not enough to authorize
            # an unrelated local form. If the primary login was local-form, no fake issuer is created.
            return oidc_credential_reuse_allowed(
                str(page.url or ""), expected_oidc_issuer, observed_auth_requests[offset:]
            )

        page.on("request", record_auth_request)
        try:
            # login_path is an optional optimization, not a requirement. For the initial target only,
            # when it is omitted, spend a small fraction of the existing login deadline on generic
            # same-origin pre-auth discovery. Explicit/configured entry points still take priority.
            if initial_login and not configured_login_path and time.monotonic() < deadline:
                remaining = max(0.0, deadline - time.monotonic())
                preauth_seconds = min(8.0, max(2.0, remaining * 0.20))
                preauth_deadline = min(deadline, time.monotonic() + preauth_seconds)
                discovered_candidates = _discover_pre_auth_candidates(page, target_url, preauth_deadline)
                if discovered_candidates:
                    print(
                        f"[AUTH] login_path not configured; bounded same-origin pre-auth discovery found "
                        f"{len(discovered_candidates)} candidate login entry point(s)."
                    )
                    merged_candidates: list[str] = []
                else:
                    print("[AUTH] login_path not configured; bounded same-origin pre-auth discovery found no stronger entry point, using normal root/target fallbacks.")
                if discovered_candidates:
                    for value in [*explicit_candidates, *discovered_candidates, *candidates]:
                        if value not in merged_candidates:
                            merged_candidates.append(value)
                    candidates = merged_candidates

            for candidate in candidates:
                if time.monotonic() >= deadline:
                    break
                attempted_candidates.append(candidate)
                used_credentials = False
                auth_request_offset = len(observed_auth_requests)
                flow_observed = False
                try:
                    page.goto(candidate, wait_until="domcontentloaded", timeout=_remaining_ms(deadline))
                    page.wait_for_timeout(250)
                except Exception as exc:
                    failures.append(f"{candidate}: navigation {type(exc).__name__}: {exc}")
                    continue

                # Reused SSO state may have already created an application session during navigation.
                current_url = str(page.url or "")
                flow_observed = (
                    flow_observed
                    or looks_like_oidc_login_url(current_url)
                    or len(observed_auth_requests) > auth_request_offset
                )
                password_field = _first_visible_locator(page, PASSWORD_SELECTORS)
                username_field = _first_visible_locator(page, USERNAME_SELECTORS)
                login_trigger = _first_visible_locator(page, LOGIN_TRIGGER_SELECTORS)
                existing_header = ""
                if same_origin(target_url, current_url) and not looks_like_oidc_login_url(current_url):
                    existing_header = _target_cookie_header(
                        context,
                        current_url,
                        credential,
                        enforce_required=bool(initial_login),
                    )
                    if existing_header and storage_state and flow_observed and password_field is None and username_field is None:
                        issuer = current_issuer(auth_request_offset)
                        return {
                            "cookie_header": existing_header,
                            "storage_state": context.storage_state(),
                            "final_url": current_url,
                            "entry_url": candidate,
                            "used_credentials": False,
                            "sso_reused": True,
                            "authentication_flow_observed": flow_observed,
                            "oidc_issuer": issuer,
                        }

                if username_field is None and password_field is None and login_trigger is not None:
                    flow_observed = True
                    try:
                        login_trigger.click()
                    except Exception as exc:
                        failures.append(f"{candidate}: login trigger {type(exc).__name__}: {exc}")
                        continue
                    form_deadline = min(deadline, time.monotonic() + 12)
                    while time.monotonic() < form_deadline:
                        username_field = _first_visible_locator(page, USERNAME_SELECTORS)
                        password_field = _first_visible_locator(page, PASSWORD_SELECTORS)
                        current_url = str(page.url or "")
                        if username_field is not None or password_field is not None:
                            break
                        if same_origin(target_url, current_url) and not looks_like_oidc_login_url(current_url):
                            header = _target_cookie_header(
                                context,
                                current_url,
                                credential,
                                enforce_required=bool(initial_login),
                            )
                            if header:
                                issuer = current_issuer(auth_request_offset)
                                return {
                                    "cookie_header": header,
                                    "storage_state": context.storage_state(),
                                    "final_url": current_url,
                                    "entry_url": candidate,
                                    "used_credentials": False,
                                    "sso_reused": True,
                                    "authentication_flow_observed": flow_observed,
                                    "oidc_issuer": issuer,
                                }
                        page.wait_for_timeout(250)

                # Some explicit SSO endpoints immediately redirect to an external identity provider and therefore expose the form
                # without a local login control.
                username_field = username_field or _first_visible_locator(page, USERNAME_SELECTORS)
                password_field = password_field or _first_visible_locator(page, PASSWORD_SELECTORS)
                current_url = str(page.url or "")
                flow_observed = flow_observed or looks_like_oidc_login_url(current_url)
                if username_field is None and password_field is None:
                    if same_origin(target_url, current_url) and not looks_like_oidc_login_url(current_url):
                        header = _target_cookie_header(
                            context,
                            current_url,
                            credential,
                            enforce_required=bool(initial_login),
                        )
                        # On the initial target, do not mistake a public page with incidental cookies for a
                        # successful login when no login interaction happened. On additional explicitly authorized origins a non-empty
                        # imported SSO state is allowed to establish the application session silently.
                        if header and storage_state and flow_observed:
                            issuer = current_issuer(auth_request_offset)
                            return {
                                "cookie_header": header,
                                "storage_state": context.storage_state(),
                                "final_url": current_url,
                                "entry_url": candidate,
                                "used_credentials": False,
                                "sso_reused": True,
                                "authentication_flow_observed": flow_observed,
                                "oidc_issuer": issuer,
                            }
                    failures.append(f"{candidate}: login form/control not found")
                    continue

                if username_field is not None or password_field is not None:
                    flow_observed = True

                allowed_issuer, observed_issuer = issuer_allowed(auth_request_offset)
                if not allowed_issuer:
                    failures.append(
                        f"{candidate}: credential reuse blocked because OIDC issuer {observed_issuer!r} "
                        f"differs from the primary issuer {str(expected_oidc_issuer)!r}"
                    )
                    continue

                if not username or not password:
                    raise BrowserLoginError(
                        "The authentication provider requested username/password again, but the initial target credentials are not available for automatic reuse.",
                        attempted_candidates,
                    )

                if username_field is not None:
                    username_field.fill(username)
                    used_credentials = True

                if password_field is None:
                    submit = _first_visible_locator(page, SUBMIT_SELECTORS)
                    if submit is None:
                        failures.append(f"{candidate}: username step has no submit control")
                        continue
                    submit.click()
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=_remaining_ms(deadline))
                    except Exception:
                        pass
                    password_field = _first_visible_locator(page, PASSWORD_SELECTORS)
                if password_field is None:
                    diagnostic = _login_diagnostic(page)
                    if diagnostic == "additional_authentication_step_required":
                        raise BrowserLoginError(
                            "The authentication provider requires an additional step such as OTP; automatic username/password login cannot complete it.",
                            attempted_candidates,
                        )
                    failures.append(f"{candidate}: password field not exposed")
                    continue

                password_field.fill(password)
                used_credentials = True
                submit = _first_visible_locator(page, SUBMIT_SELECTORS)
                if submit is not None:
                    submit.click()
                else:
                    password_field.press("Enter")

                while time.monotonic() < deadline:
                    current_url = str(page.url or "")
                    password_still_visible = _first_visible_locator(page, PASSWORD_SELECTORS) is not None
                    if same_origin(target_url, current_url) and not looks_like_oidc_login_url(current_url) and not password_still_visible:
                        header = _target_cookie_header(
                            context,
                            current_url,
                            credential,
                            enforce_required=bool(initial_login),
                        )
                        if header:
                            issuer = current_issuer(auth_request_offset)
                            return {
                                "cookie_header": header,
                                "storage_state": context.storage_state(),
                                "final_url": current_url,
                                "entry_url": candidate,
                                "used_credentials": used_credentials,
                                "sso_reused": False,
                                "authentication_flow_observed": flow_observed,
                                "oidc_issuer": issuer,
                            }
                    diagnostic = _login_diagnostic(page)
                    if diagnostic.startswith("credentials_rejected:"):
                        message = diagnostic.split(":", 1)[1].strip()
                        raise BrowserLoginError(
                            f"The authentication provider rejected the supplied target credentials: {message}",
                            attempted_candidates,
                        )
                    if diagnostic == "additional_authentication_step_required":
                        raise BrowserLoginError(
                            "The authentication provider requires an additional step such as OTP; automatic username/password login cannot complete it.",
                            attempted_candidates,
                        )
                    page.wait_for_timeout(250)

                failures.append(f"{candidate}: login did not return to the target origin before the shared timeout")

            detail = "; ".join(failures[-4:]) if failures else "no usable login entry point was found"
            raise BrowserLoginError(
                f"Automatic browser login could not establish an application session for {origin} within {timeout_seconds}s: {detail}",
                attempted_candidates,
            )
        finally:
            browser.close()


# Backward-compatible alias for older configs/imports; new code uses the provider-neutral name.
snap4city_browser_login_session = browser_oidc_login_session
