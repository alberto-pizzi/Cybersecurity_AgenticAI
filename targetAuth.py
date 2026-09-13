from __future__ import annotations

import shutil
import time
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

from utils import canonical_cookie_header, cookie_names, normalized_origin, same_origin


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
    "#kc-login",
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
    "#kc-error-message",
    ".kc-feedback-text",
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
    "#kc-otp-login-form",
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


def _keycloak_login_diagnostic(page: Any) -> str:
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
    try:
        path = str(urlparse(str(url or "")).path or "").lower().rstrip("/")
    except ValueError:
        return False
    return "/auth/realms/" in path or path.endswith(("/login", "/signin", "/sign-in"))


def _looks_like_application_login_entry(url: str) -> bool:
    try:
        path = str(urlparse(str(url or "")).path or "").lower()
    except ValueError:
        return False
    return "ssologin" in path or path.endswith(("/login", "/signin", "/sign-in")) or "/login/" in path


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
                "Snap4City login completed but required target cookie(s) are missing: " + ", ".join(missing)
            )
    return header


def _remaining_ms(deadline: float, *, cap_ms: int = 20_000, floor_ms: int = 1_000) -> int:
    remaining = max(0.0, deadline - time.monotonic())
    return max(floor_ms, min(cap_ms, int(remaining * 1000)))


def snap4city_browser_login_session(
    target_url: str,
    username: str,
    password: str,
    credential: dict[str, Any],
    *,
    storage_state: dict[str, Any] | None = None,
    candidate_urls: Iterable[str] | None = None,
    initial_login: bool = False,
) -> dict[str, Any]:
    """Obtain one origin-scoped application session without ever prompting for credentials.

    A previous Playwright storage state is imported first so an existing Keycloak/OIDC SSO session can
    silently create an application cookie for a newly discovered sibling origin. If the identity provider
    asks for credentials again, the username/password already resolved by assessmentRunner are reused.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(
            f"Playwright is unavailable for automatic Snap4City login: {type(exc).__name__}: {exc}"
        ) from exc

    origin = normalized_origin(target_url)
    if not origin:
        raise RuntimeError(f"Invalid target origin for automatic login: {target_url!r}")

    timeout_seconds = max(15, int(credential.get("timeout_seconds") or 60))
    headless = bool(credential.get("headless", True))
    login_path = str(credential.get("login_path") or "/").strip() or "/"
    validation_path = str(credential.get("validation_path") or login_path).strip() or login_path

    explicit_candidates = _same_origin_candidates(target_url, candidate_urls or [])
    configured_candidates = _same_origin_candidates(
        target_url,
        [
            *[str(value) for value in credential.get("sibling_login_paths") or []],
            login_path,
            validation_path,
            origin + "/",
        ],
    )
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
            "user_agent": "SecOps-Snap4City-Login/2.0",
        }
        if isinstance(storage_state, dict) and (storage_state.get("cookies") or storage_state.get("origins")):
            context_kwargs["storage_state"] = storage_state
        context = browser.new_context(**context_kwargs)
        page = context.new_page()
        try:
            for candidate in candidates:
                if time.monotonic() >= deadline:
                    break
                used_credentials = False
                flow_observed = _looks_like_application_login_entry(candidate)
                try:
                    page.goto(candidate, wait_until="domcontentloaded", timeout=_remaining_ms(deadline))
                    page.wait_for_timeout(250)
                except Exception as exc:
                    failures.append(f"{candidate}: navigation {type(exc).__name__}: {exc}")
                    continue

                # Reused SSO state may have already created an application session during navigation.
                current_url = str(page.url or "")
                flow_observed = flow_observed or looks_like_oidc_login_url(current_url)
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
                        return {
                            "cookie_header": existing_header,
                            "storage_state": context.storage_state(),
                            "final_url": current_url,
                            "entry_url": candidate,
                            "used_credentials": False,
                            "sso_reused": True,
                            "authentication_flow_observed": flow_observed,
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
                                return {
                                    "cookie_header": header,
                                    "storage_state": context.storage_state(),
                                    "final_url": current_url,
                                    "entry_url": candidate,
                                    "used_credentials": False,
                                    "sso_reused": True,
                                    "authentication_flow_observed": flow_observed,
                                }
                        page.wait_for_timeout(250)

                # Some explicit SSO endpoints immediately redirect to Keycloak and therefore expose the form
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
                        # successful login when no login interaction happened. On sibling origins a non-empty
                        # imported SSO state is allowed to establish the application session silently.
                        if header and storage_state and flow_observed:
                            return {
                                "cookie_header": header,
                                "storage_state": context.storage_state(),
                                "final_url": current_url,
                                "entry_url": candidate,
                                "used_credentials": False,
                                "sso_reused": True,
                                "authentication_flow_observed": flow_observed,
                            }
                    failures.append(f"{candidate}: login form/control not found")
                    continue

                if username_field is not None or password_field is not None:
                    flow_observed = True

                if not username or not password:
                    raise RuntimeError(
                        "Snap4City/Keycloak requested username/password again, but the initial target credentials are not available for automatic reuse."
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
                    diagnostic = _keycloak_login_diagnostic(page)
                    if diagnostic == "additional_authentication_step_required":
                        raise RuntimeError(
                            "Snap4City/Keycloak requires an additional authentication step such as OTP; automatic username/password login cannot complete it."
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
                            return {
                                "cookie_header": header,
                                "storage_state": context.storage_state(),
                                "final_url": current_url,
                                "entry_url": candidate,
                                "used_credentials": used_credentials,
                                "sso_reused": False,
                                "authentication_flow_observed": flow_observed,
                            }
                    diagnostic = _keycloak_login_diagnostic(page)
                    if diagnostic.startswith("credentials_rejected:"):
                        message = diagnostic.split(":", 1)[1].strip()
                        raise RuntimeError(f"Snap4City/Keycloak rejected the supplied target credentials: {message}")
                    if diagnostic == "additional_authentication_step_required":
                        raise RuntimeError(
                            "Snap4City/Keycloak requires an additional authentication step such as OTP; automatic username/password login cannot complete it."
                        )
                    page.wait_for_timeout(250)

                failures.append(f"{candidate}: login did not return to the target origin before the shared timeout")

            detail = "; ".join(failures[-4:]) if failures else "no usable login entry point was found"
            raise RuntimeError(
                f"Snap4City automatic login could not establish an application session for {origin} within {timeout_seconds}s: {detail}"
            )
        finally:
            browser.close()
