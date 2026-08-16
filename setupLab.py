from __future__ import annotations

import json
import platform
import re
import shutil
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

import requests

from utils import canonical_cookie_header
from setupTools import (
    LOCAL_LAB_CONTAINER, LOCAL_LAB_IMAGE, LOCAL_LAB_NETWORK, NIKTO_DOCKER_IMAGE, RUNTIME_FILE, TARGET, _docker_image_ready, run,
)

def wait_http(url: str, attempts: int = 60) -> bool:
    for _ in range(attempts):
        try:
            if requests.get(url, timeout=3).status_code < 500:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False

def inspect_container(name: str) -> dict[str, Any] | None:
    result = run(["docker", "inspect", name], required=False, capture=True, show_output=False, timeout=60)
    if result.returncode:
        return None
    try:
        value = json.loads(result.stdout)
        return value[0] if isinstance(value, list) and value else None
    except json.JSONDecodeError:
        return None

def container_valid(info: dict[str, Any], image: str, network: str, ports: dict[str, str]) -> bool:
    if info.get("Config", {}).get("Image") != image or network not in (info.get("NetworkSettings", {}).get("Networks", {}) or {}):
        return False
    bindings = info.get("HostConfig", {}).get("PortBindings", {}) or {}
    return all(host in {str(item.get("HostPort", "")) for item in bindings.get(container, [])} for container, host in ports.items())

def ensure_network(name: str) -> None:
    if run(["docker", "network", "inspect", name], required=False, capture=True, show_output=False, timeout=60).returncode:
        run(["docker", "network", "create", name], timeout=60)

def ensure_container(name: str, image: str, ports: dict[str, str], readiness_url: str, run_options: list[str] | None = None, command: list[str] | None = None, attempts: int = 90) -> None:
    info = inspect_container(name)
    if info and container_valid(info, image, "secops-net", ports):
        if not info.get("State", {}).get("Running"):
            run(["docker", "start", name], required=False, timeout=180)
        if wait_http(readiness_url, attempts):
            print(f"[+] Container {name} is ready.")
            return
    if info:
        run(["docker", "rm", "-f", name], required=False, timeout=180)
    port_args = [item for container, host in ports.items() for item in ("-p", f"{host}:{container.split('/')[0]}")]
    run(["docker", "run", "-d", "--name", name, "--network", "secops-net", *port_args, *(run_options or []), image, *(command or [])], timeout=1200)
    if not wait_http(readiness_url, attempts):
        run(["docker", "logs", "--tail", "100", name], required=False, capture=True, timeout=60)
        raise RuntimeError(f"Container {name} is not ready at {readiness_url}.")

class _HiddenInputParser(HTMLParser):
    """Collect input values without depending on HTML attribute ordering."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: dict[str, str] = {}

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "input":
            return
        attributes = {
            str(name).lower(): "" if value is None else str(value)
            for name, value in attrs
        }
        name = attributes.get("name", "")
        if name:
            self.values[name] = attributes.get("value", "")

def _hidden_input(html_text: str, name: str) -> str:
    parser = _HiddenInputParser()
    try:
        parser.feed(str(html_text or ""))
    except Exception:
        return ""
    return str(parser.values.get(name, "")).strip()

def _local_lab_login_page(response: requests.Response) -> bool:
    text = response.text[:100_000].lower()
    path = urlparse(str(response.url)).path.lower()
    return (
        path.endswith("/login")
        or path.endswith("/login.php")
        or (
            ("name=\"username\"" in text or "name='username'" in text)
            and ("name=\"password\"" in text or "name='password'" in text)
        )
    )

def _local_lab_setup_page(response: requests.Response) -> bool:
    path = urlparse(str(response.url)).path.lower()
    text = response.text[:100_000].lower()
    return (
        path.endswith("/setup.php")
        or "create / reset database" in text
        or "setup check" in text
    )

def _local_lab_response_summary(
    response: requests.Response,
) -> dict[str, Any]:
    text = response.text[:100_000]
    lowered = text.lower()
    title_match = re.search(
        r"<title[^>]*>\s*(.*?)\s*</title>", text, re.I | re.S,
    )
    error_markers = (
        "database error", "could not connect", "access denied", "connection refused",
        "unknown database", "fatal error", "warning:", "failed",
    )
    return {
        "status": int(response.status_code), "final_url": str(response.url),
        "login_page": _local_lab_login_page(response), "setup_page": _local_lab_setup_page(response),
        "title": (
            re.sub(r"\s+", " ", title_match.group(1)).strip()
            if title_match
            else ""
        ),
        "body_bytes": len(response.content),
        "error_markers": [
            marker for marker in error_markers if marker in lowered
        ],
    }

def _local_lab_cookie_value(
    session: requests.Session, cookie_name: str,
) -> str:
    selected = ""
    for cookie in session.cookies:
        if str(cookie.name).lower() == cookie_name.lower():
            selected = str(cookie.value)
    return selected

def _remove_named_cookies(
    session: requests.Session, cookie_name: str,
) -> None:
    removals: list[tuple[str, str, str]] = []
    for cookie in session.cookies:
        if str(cookie.name).lower() == cookie_name.lower():
            removals.append(
                (
                    str(cookie.domain or ""), str(cookie.path or "/"), str(cookie.name),
                )
            )
    for domain, path, name in removals:
        try:
            session.cookies.clear(
                domain=domain, path=path, name=name,
            )
        except (KeyError, ValueError):
            pass

def _attempt_local_lab_login(
    session: requests.Session, username: str, password: str,
) -> tuple[bool, dict[str, Any]]:
    page = session.get(
        f"{TARGET}/login.php", timeout=15, allow_redirects=True, headers={"Cache-Control": "no-cache"},
    )
    page.raise_for_status()
    token = _hidden_input(page.text, "user_token")
    credentials = {
        "username": username, "password": password, "Login": "Login",
    }
    if token:
        credentials["user_token"] = token

    response = session.post(
        f"{TARGET}/login.php", data=credentials, timeout=20, allow_redirects=True,
        headers={
            "Referer": f"{TARGET}/login.php", "Cache-Control": "no-cache",
        },
    )
    response.raise_for_status()
    final_path = urlparse(str(response.url)).path.lower()
    successful = (
        not _local_lab_login_page(response)
        and not _local_lab_setup_page(response)
        and final_path not in {"/login.php", "/setup.php"}
    )
    return successful, {
        "login_page": _local_lab_response_summary(page), "login_response": _local_lab_response_summary(response),
        "login_token_present": bool(token),
        "cookie_names": sorted(
            {str(cookie.name) for cookie in session.cookies}, key=str.lower,
        ),
    }

def _reset_local_lab_database(
    session: requests.Session,
) -> dict[str, Any]:
    setup_page = session.get(
        f"{TARGET}/setup.php", timeout=20, allow_redirects=True, headers={"Cache-Control": "no-cache"},
    )
    setup_page.raise_for_status()
    token = _hidden_input(setup_page.text, "user_token")
    payload = {
        "create_db": "Create / Reset Database",
    }
    if token:
        payload["user_token"] = token

    setup_response = session.post(
        f"{TARGET}/setup.php", data=payload, timeout=45, allow_redirects=True,
        headers={
            "Referer": f"{TARGET}/setup.php", "Cache-Control": "no-cache",
        },
    )
    setup_response.raise_for_status()
    summary = {
        "setup_page": _local_lab_response_summary(setup_page),
        "setup_response": _local_lab_response_summary(setup_response), "setup_token_present": bool(token),
    }

    for _ in range(20):
        try:
            probe = session.get(
                f"{TARGET}/login.php", timeout=8, allow_redirects=True, headers={"Cache-Control": "no-cache"},
            )
            if probe.status_code < 500:
                summary["post_setup_probe"] = _local_lab_response_summary(
                    probe
                )
                break
        except requests.RequestException:
            pass
        time.sleep(0.5)

    return summary

def _configure_local_lab_profile(
    session: requests.Session,
) -> dict[str, Any]:
    """Apply the bundled training lab profile required for repeatable scans."""
    actions: list[dict[str, Any]] = []

    # The bundled lab exposes an optional request filter. Disable it so bounded
    # scanner payloads reach the intentionally vulnerable training handlers.
    for action_url in (
        f"{TARGET}/security.php?phpids=off",
    ):
        response = session.get(
            action_url, timeout=15, allow_redirects=True,
            headers={
                "Referer": f"{TARGET}/security.php", "Cache-Control": "no-cache",
            },
        )
        response.raise_for_status()
        actions.append(_local_lab_response_summary(response))

    verification = session.get(
        f"{TARGET}/security.php", timeout=15, allow_redirects=True, headers={"Cache-Control": "no-cache"},
    )
    verification.raise_for_status()
    lowered = verification.text[:100_000].lower()
    summary = _local_lab_response_summary(verification)
    plain_text = re.sub(r"<[^>]+>", " ", lowered)
    plain_text = re.sub(r"\s+", " ", plain_text)
    phpids_enabled = bool(re.search(
        r"phpids(?:\s+is\s+currently)?\s*:\s*enabled", plain_text, re.I,
    ))
    phpids_disabled = bool(re.search(
        r"phpids(?:\s+is\s+currently)?\s*:\s*disabled", plain_text, re.I,
    ))
    security_low = (
        bool(re.search(r"security(?:\s+level)?(?:\s+is\s+currently)?\s*:\s*low", plain_text, re.I))
        or "value=\"low\" selected" in lowered
        or "value='low' selected" in lowered
    )

    if phpids_enabled:
        raise RuntimeError(
            "The bundled lab request filter remained enabled after the initializer requested "
            "security.php?phpids=off. Intentional scanner payloads would be "
            "blocked and vulnerability coverage would be misleading."
        )

    return {
        "security_page": summary, "security_level_low": security_low,
        "phpids_disabled": phpids_disabled or not phpids_enabled, "actions": actions,
    }

def _finalize_local_lab_cookie(
    session: requests.Session,
) -> tuple[str, dict[str, Any]]:
    php_session = _local_lab_cookie_value(session, "PHPSESSID")
    if not php_session:
        raise RuntimeError("The bundled local lab did not issue its session cookie after login.")

    _remove_named_cookies(session, "security")
    session.cookies.set(
        "security", "low", domain=urlparse(TARGET).hostname, path="/",
    )

    lab_security = _configure_local_lab_profile(session)
    verification = session.get(
        f"{TARGET}/security.php", timeout=15, allow_redirects=True, headers={"Cache-Control": "no-cache"},
    )
    verification.raise_for_status()
    summary = _local_lab_response_summary(verification)
    summary["lab_security"] = lab_security
    if _local_lab_login_page(verification) or _local_lab_setup_page(verification):
        raise RuntimeError(
            "The bundled local-lab cookie verification failed after login: "
            + json.dumps(summary, ensure_ascii=False)
        )

    cookie = canonical_cookie_header(
        f"PHPSESSID={php_session}; security=low"
    )
    return cookie, summary

def create_local_lab_session() -> str:
    """
    Try the existing database first, reset only when needed, then verify the
    exact scanner Cookie header.
    """
    if not wait_http(f"{TARGET}/login.php", 90):
        raise RuntimeError("The bundled local training lab is not reachable.")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "SecOps-Local-Lab-Initializer/5.0", "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    diagnostics: dict[str, Any] = {
        "target": TARGET, "attempts": [],
    }

    try:
        success_now, first_attempt = _attempt_local_lab_login(
            session, "admin", "password",
        )
        diagnostics["attempts"].append({
            "phase": "existing_database", **first_attempt,
        })
        if success_now:
            cookie, verification = _finalize_local_lab_cookie(session)
            diagnostics["verification"] = verification
            print(
                "[+] Bundled local-lab login succeeded using the existing database."
            )
            return cookie
    except requests.RequestException as exc:
        diagnostics["attempts"].append({
            "phase": "existing_database", "request_error": f"{type(exc).__name__}: {exc}",
        })

    session.cookies.clear()

    try:
        diagnostics["database_reset"] = _reset_local_lab_database(
            session
        )
    except requests.RequestException as exc:
        diagnostics["database_reset"] = {
            "request_error": f"{type(exc).__name__}: {exc}",
        }
        raise RuntimeError(
            "Bundled local-lab database setup request failed. Diagnostics: "
            + json.dumps(diagnostics, ensure_ascii=False)
        ) from exc

    for attempt_number in range(1, 6):
        try:
            success_now, attempt = _attempt_local_lab_login(
                session, "admin", "password",
            )
            diagnostics["attempts"].append({
                "phase": "after_database_reset", "attempt": attempt_number, **attempt,
            })
            if success_now:
                cookie, verification = _finalize_local_lab_cookie(
                    session
                )
                diagnostics["verification"] = verification
                print(
                    "[+] Bundled local-lab database initialized and automatic login succeeded."
                )
                return cookie
        except requests.RequestException as exc:
            diagnostics["attempts"].append({
                "phase": "after_database_reset", "attempt": attempt_number, "request_error": f"{type(exc).__name__}: {exc}",
            })
        time.sleep(attempt_number)

    try:
        logs = run(
            ["docker", "logs", "--tail", "80", LOCAL_LAB_CONTAINER], required=False, capture=True, show_output=False, timeout=30,
        )
        diagnostics["docker_log_tail"] = "\n".join(
            value
            for value in (
                (logs.stdout or "").strip(), (logs.stderr or "").strip(),
            )
            if value
        )[-6000:]
    except Exception as exc:
        diagnostics["docker_log_error"] = (
            f"{type(exc).__name__}: {exc}"
        )

    raise RuntimeError(
        "Automatic local-lab login failed after an existing-database attempt "
        "and five post-reset retries. Redacted diagnostics: "
        + json.dumps(diagnostics, ensure_ascii=False)
    )

def update_runtime_auth(cookie: str) -> None:
    try:
        payload = json.loads(RUNTIME_FILE.read_text(encoding="utf-8")) if RUNTIME_FILE.exists() else {}
    except (OSError, json.JSONDecodeError):
        payload = {}
    parsed = urlparse(TARGET)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    origin = f"{parsed.scheme.lower()}://{parsed.hostname.lower()}:{port}"
    target_profiles = payload.get("target_profiles", {})
    if not isinstance(target_profiles, dict):
        target_profiles = {}
    target_profiles[origin] = {
        "target_url": TARGET, "label": "bundled-local-training-lab",
        "container_route": {
            "scanner_container": "zap_mcp", "target_container": LOCAL_LAB_CONTAINER,
            "alias": LOCAL_LAB_CONTAINER, "network": LOCAL_LAB_NETWORK, "internal_port": 80,
        },
        "pre_scan_requests": [
            {
                "method": "GET", "path": "/security.php?phpids=off", "accepted_statuses": [200, 302],
            }
        ],
        # Exact-target safety metadata consumed generically by the crawler and
        # ZAP server. Other targets receive no special exclusions.
        "excluded_query_keys": ["phpids", "security", "seclev_submit", "test"],
        "probe_paths": ["/security.php", "/", "/index.php"], "preferred_probe_paths": ["/security.php"],
    }
    payload.update({
        "last_auth_target": TARGET, "last_auth_cookie": cookie,
        "last_auth_generated_at": datetime.now(timezone.utc).isoformat(), "target_profiles": target_profiles,
    })
    RUNTIME_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

def _ensure_local_docker_image(image: str, platform_name: str = "") -> None:
    """Use a local image; pull only when absent, optionally for a platform."""
    if _docker_image_ready(image):
        print(f"[+] Docker image already available locally; registry access skipped: {image}")
        return
    command = ["docker", "pull"]
    if platform_name:
        command.extend(["--platform", platform_name])
    command.append(image)
    result = run(command, required=False, capture=True, timeout=1800)
    if result.returncode != 0 or not _docker_image_ready(image):
        raise RuntimeError(
            f"Docker image {image} is not available locally and could not be pulled. "
            "Restore DNS/network access and rerun the initializer."
        )

def _ollama_model_available(model: str) -> bool:
    try:
        response = requests.get(
            "http://127.0.0.1:11434/api/tags", timeout=15,
        )
        response.raise_for_status()
        payload = response.json()
        models = payload.get("models", []) if isinstance(payload, dict) else []
        wanted = model.lower()
        wanted_base = wanted.split(":", 1)[0]
        for item in models:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("model") or "").lower()
            if name == wanted or (
                ":" not in wanted
                and name.split(":", 1)[0] == wanted_base
            ):
                return True
    except Exception:
        pass
    return False

def setup_local_lab(model: str) -> str:
    if not shutil.which("docker"):
        raise RuntimeError("Docker Desktop/Engine is required for --with-lab.")
    run(["docker", "info"], timeout=60)
    ensure_network(LOCAL_LAB_NETWORK)

    apple_silicon = (
        platform.system().lower() == "darwin"
        and platform.machine().lower() in {"arm64", "aarch64"}
    )
    dvwa_platform = "linux/amd64" if apple_silicon else ""
    _ensure_local_docker_image(LOCAL_LAB_IMAGE, dvwa_platform)
    _ensure_local_docker_image("zaproxy/zap-stable")
    _ensure_local_docker_image(NIKTO_DOCKER_IMAGE)
    _ensure_local_docker_image("ollama/ollama")

    dvwa_options = ["--platform", dvwa_platform] if dvwa_platform else []
    ensure_container(
        LOCAL_LAB_CONTAINER, LOCAL_LAB_IMAGE, {"80/tcp": "80"}, f"{TARGET}/login.php", run_options=dvwa_options,
    )
    ensure_container(
        "zap_mcp", "zaproxy/zap-stable", {"8080/tcp": "8080"}, "http://127.0.0.1:8080/JSON/core/view/version/",
        command=[
            "zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8080", "-config", "api.disablekey=true",
            "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true",
        ],
        attempts=120,
    )
    try:
        version = requests.get(
            "http://127.0.0.1:8080/JSON/core/view/version/", timeout=15,
        ).json().get("version", "")
        print(f"[+] ZAP daemon version: {version or 'unknown'}")
    except Exception as exc:
        print(f"[!] Could not read ZAP version: {type(exc).__name__}: {exc}")

    ensure_container(
        "ollama_secops", "ollama/ollama", {"11434/tcp": "11434"}, "http://127.0.0.1:11434/api/tags",
        run_options=["-v", "ollama_secops:/root/.ollama"], attempts=120,
    )
    if apple_silicon:
        print("[!] Ollama is running in Docker on Apple Silicon and may use CPU emulation. A native Ollama service can be faster.")
    if _ollama_model_available(model):
        print(f"[+] Ollama model already available; pull skipped: {model}")
    else:
        run(["docker", "exec", "ollama_secops", "ollama", "pull", model], timeout=7200)
    return create_local_lab_session()

