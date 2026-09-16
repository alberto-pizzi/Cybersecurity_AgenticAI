from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urljoin, urlparse

from utils import MAX_AUTHENTICATED_IDENTITIES, valid_identity_label


SCHEMA_VERSION = 1
SUPPORTED_WEB_PROTOCOLS = {"http", "https"}
SUPPORTED_ORCHESTRATORS = {"deterministic", "agentic"}
SUPPORTED_MODES = {"fast", "balanced", "deep"}
SUPPORTED_MODELS = {"snap4city", "llama", "qwen"}
SUPPORTED_CREDENTIAL_KINDS = {"cookie", "browser_oidc", "snap4city_oidc"}
MAX_SERVICE_CREDENTIAL_IDENTITIES = MAX_AUTHENTICATED_IDENTITIES


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Assessment configuration contains duplicate JSON key {key!r}.")
        result[key] = value
    return result


# Loads and validates the platform-level assessment configuration.
def load_assessment_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"), object_pairs_hook=_strict_json_object)
    except OSError as exc:
        raise ValueError(f"Cannot read assessment configuration {config_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Assessment configuration is not valid JSON: {config_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Assessment configuration must be a JSON object.")
    if int(payload.get("schema_version") or 0) != SCHEMA_VERSION:
        raise ValueError(f"Unsupported assessment schema_version; expected {SCHEMA_VERSION}.")
    platform = payload.get("platform")
    if not isinstance(platform, dict) or not str(platform.get("name") or "").strip():
        raise ValueError("platform.name is required.")
    assets = payload.get("assets")
    if not isinstance(assets, list) or not assets:
        raise ValueError("assets must contain at least one asset.")
    execution = payload.get("execution")
    if not isinstance(execution, dict):
        raise ValueError("execution must be a JSON object.")
    orchestrator = str(execution.get("orchestrator") or "deterministic").strip().lower()
    if orchestrator not in SUPPORTED_ORCHESTRATORS:
        raise ValueError(f"execution.orchestrator must be one of {sorted(SUPPORTED_ORCHESTRATORS)}.")
    mode = str(execution.get("mode") or "balanced").strip().lower()
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"execution.mode must be one of {sorted(SUPPORTED_MODES)}.")
    model = str(execution.get("model") or "snap4city").strip().lower()
    if model not in SUPPORTED_MODELS:
        raise ValueError(f"execution.model must be one of {sorted(SUPPORTED_MODELS)}.")
    execution["orchestrator"] = orchestrator
    execution["mode"] = mode
    execution["model"] = model
    if "allow_state_changes" in execution and not isinstance(execution.get("allow_state_changes"), bool):
        raise ValueError("execution.allow_state_changes must be true or false when supplied.")
    if "require_ai" in execution and not isinstance(execution.get("require_ai"), bool):
        raise ValueError("execution.require_ai must be true or false when supplied.")
    if "max_rounds" in execution:
        value = execution.get("max_rounds")
        if isinstance(value, bool) or not isinstance(value, int) or value not in {1, 2, 3}:
            raise ValueError("execution.max_rounds must be one of 1, 2 or 3 when supplied.")
    authorization_value = payload.get("authorization")
    _validate_authorization({} if authorization_value is None else authorization_value)
    _validate_assets(assets)
    credentials_value = payload.get("credentials")
    credentials = {} if credentials_value is None else credentials_value
    _validate_credentials(credentials)
    _validate_credential_references(assets, credentials)
    _validate_reporting(payload.get("reporting"))
    return payload


# Validates the optional aggregate-reporting controls used by multi-job assessments.
def _validate_reporting(reporting: Any) -> None:
    if reporting is None:
        return
    if not isinstance(reporting, dict):
        raise ValueError("reporting must be a JSON object when supplied.")
    for field in ("aggregate_report", "keep_job_reports"):
        if field in reporting and not isinstance(reporting.get(field), bool):
            raise ValueError(f"reporting.{field} must be true or false when supplied.")


# Validates optional scope extensions without implicitly authorizing unrelated external hosts.
def _validate_authorization(authorization: Any) -> None:
    if not isinstance(authorization, dict):
        raise ValueError("authorization must be a JSON object when supplied.")
    if "confirmed" in authorization and not isinstance(authorization.get("confirmed"), bool):
        raise ValueError("authorization.confirmed must be true or false when supplied.")
    if "allow_same_host_ports" in authorization and not isinstance(authorization.get("allow_same_host_ports"), bool):
        raise ValueError("authorization.allow_same_host_ports must be true or false when supplied.")
    if "discover_same_host_services" in authorization and not isinstance(authorization.get("discover_same_host_services"), bool):
        raise ValueError("authorization.discover_same_host_services must be true or false when supplied.")
    if bool(authorization.get("discover_same_host_services", False)) and not bool(authorization.get("allow_same_host_ports", False)):
        raise ValueError(
            "authorization.discover_same_host_services=true requires authorization.allow_same_host_ports=true "
            "because proactive service discovery may add HTTP/HTTPS services on other ports of the exact hostname."
        )
    origins = authorization.get("allowed_origins", [])
    if origins is not None:
        if not isinstance(origins, list) or not all(isinstance(value, str) and value.strip() for value in origins):
            raise ValueError("authorization.allowed_origins must be a list of non-empty absolute HTTP/HTTPS origins.")
        for value in origins:
            parsed = urlparse(value.strip())
            if str(parsed.scheme or "").lower() not in SUPPORTED_WEB_PROTOCOLS or not parsed.hostname:
                raise ValueError(f"Invalid authorization.allowed_origins entry: {value!r}")
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password:
                raise ValueError(f"authorization.allowed_origins entries must contain only scheme, host and optional port: {value!r}")
            try:
                _ = parsed.port
            except ValueError as exc:
                raise ValueError(f"Invalid port in authorization.allowed_origins entry: {value!r}") from exc
    suffixes = authorization.get("allowed_host_suffixes", [])
    if suffixes:
        raise ValueError(
            "authorization.allowed_host_suffixes is not accepted for active testing. "
            "Authorize additional HTTP origins explicitly with authorization.allowed_origins, or enable authorization.allow_same_host_ports only when site-level authorization covers discovered ports of the same exact hostname over HTTP/HTTPS."
        )
    if origins and authorization.get("confirmed") is not True:
        raise ValueError("authorization.allowed_origins requires authorization.confirmed=true.")


# Public validation entry point used by the runner after applying CLI scope overrides.
def validate_authorization_scope(authorization: Any) -> None:
    _validate_authorization(authorization)


# Validates asset/service identifiers and either an absolute service URL or the fields needed to derive one.
def _validate_assets(assets: list[Any]) -> None:
    seen_assets: set[str] = set()
    seen_services: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("Every asset must be a JSON object.")
        asset_id = str(asset.get("id") or "").strip()
        host = str(asset.get("host") or "").strip()
        if not asset_id:
            raise ValueError("Every asset requires id.")
        if asset_id in seen_assets:
            raise ValueError(f"Duplicate asset id: {asset_id}")
        seen_assets.add(asset_id)
        services = asset.get("services")
        if not isinstance(services, list) or not services:
            raise ValueError(f"Asset {asset_id} must contain at least one service.")
        for service in services:
            if not isinstance(service, dict):
                raise ValueError(f"Every service in asset {asset_id} must be a JSON object.")
            service_id = str(service.get("id") or "").strip()
            if not service_id:
                raise ValueError(f"Every service in asset {asset_id} requires id.")
            global_id = f"{asset_id}/{service_id}"
            if global_id in seen_services:
                raise ValueError(f"Duplicate service id: {global_id}")
            seen_services.add(global_id)
            for field in ("enabled", "auth_only", "allow_state_changes"):
                if field in service and not isinstance(service.get(field), bool):
                    raise ValueError(f"{field} for {global_id} must be true or false when supplied.")

            absolute_url = str(service.get("url") or "").strip()
            if absolute_url:
                parsed = urlparse(absolute_url)
                if str(parsed.scheme or "").lower() not in SUPPORTED_WEB_PROTOCOLS or not parsed.hostname:
                    raise ValueError(f"Service url for {global_id} must be an absolute HTTP/HTTPS URL.")
                try:
                    _ = parsed.port
                except ValueError as exc:
                    raise ValueError(f"Invalid port in service url for {global_id}: {absolute_url!r}") from exc
            else:
                if not host:
                    raise ValueError(f"Service {global_id} requires either service.url or asset.host.")
                protocol = str(service.get("protocol") or "").strip().lower()
                port = service.get("port")
                if not protocol and port in (None, ""):
                    raise ValueError(f"Service {global_id} requires protocol or port when service.url is not supplied.")

            entry_points = service.get("entry_points", [])
            if entry_points is not None:
                if not isinstance(entry_points, list) or not all(isinstance(value, str) and value.strip() for value in entry_points):
                    raise ValueError(f"entry_points for {global_id} must be a list of non-empty absolute HTTP/HTTPS URLs or root-relative paths.")
                if len(entry_points) > 256:
                    raise ValueError(f"entry_points for {global_id} exceeds the 256-entry safety limit.")
                for value in entry_points:
                    raw = value.strip()
                    if raw.startswith("/"):
                        continue
                    parsed_entry = urlparse(raw)
                    if str(parsed_entry.scheme or "").lower() not in SUPPORTED_WEB_PROTOCOLS or not parsed_entry.hostname:
                        raise ValueError(f"Invalid entry_points value for {global_id}: {value!r}")
                    try:
                        _ = parsed_entry.port
                    except ValueError as exc:
                        raise ValueError(f"Invalid port in entry_points value for {global_id}: {value!r}") from exc

            port = service.get("port")
            if port not in (None, ""):
                try:
                    numeric_port = int(port)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"Invalid port for {global_id}: {port!r}") from exc
                if not 1 <= numeric_port <= 65535:
                    raise ValueError(f"Port out of range for {global_id}: {numeric_port}")


def service_credential_refs(service: dict[str, Any]) -> list[str]:
    """Return ordered credential identities for one service, preserving legacy fields."""
    refs: list[str] = []
    configured = service.get("credential_refs")
    if configured is not None:
        if not isinstance(configured, list) or not all(isinstance(item, str) and item.strip() for item in configured):
            raise ValueError("service credential_refs must be a list of non-empty credential names.")
        refs.extend(str(item).strip() for item in configured)
        if len(refs) > MAX_SERVICE_CREDENTIAL_IDENTITIES:
            raise ValueError(
                f"service credential_refs exceeds the bounded {MAX_SERVICE_CREDENTIAL_IDENTITIES}-identity safety limit."
            )
    for field in ("credential_ref", "secondary_credential_ref"):
        value = str(service.get(field) or "").strip()
        if value and value not in refs:
            refs.append(value)
    refs = list(dict.fromkeys(refs))
    folded: dict[str, str] = {}
    for reference in refs:
        if not valid_identity_label(reference):
            raise ValueError(
                f"service credential reference {reference!r} is not a stable identity label; use only letters, digits, dot, underscore or hyphen."
            )
        key = reference.casefold()
        previous = folded.get(key)
        if previous is not None and previous != reference:
            raise ValueError(
                f"service credential references {previous!r} and {reference!r} differ only by case; identity labels must be unique."
            )
        folded[key] = reference
    if len(refs) > MAX_SERVICE_CREDENTIAL_IDENTITIES:
        raise ValueError(
            f"service credential references exceed the bounded {MAX_SERVICE_CREDENTIAL_IDENTITIES}-identity safety limit."
        )
    return refs


# Validates that every service credential reference resolves before a dry-run can be accepted.
def _validate_credential_references(assets: list[Any], credentials: dict[str, Any]) -> None:
    for asset in assets:
        asset_id = str(asset.get("id") or "").strip()
        for service in asset.get("services") or []:
            service_id = str(service.get("id") or "").strip()
            global_id = f"{asset_id}/{service_id}"
            refs = service_credential_refs(service)
            for reference in refs:
                if reference not in credentials:
                    raise ValueError(f"Unknown credential reference {reference!r} for service {global_id}.")
            if service.get("auth_only") is True and not refs:
                raise ValueError(f"Service {global_id} sets auth_only=true but has no credential_refs/credential_ref.")


# Validates secret references without resolving or persisting the secret values.
def _validate_credentials(credentials: Any) -> None:
    if not isinstance(credentials, dict):
        raise ValueError("credentials must be a JSON object when supplied.")
    folded_names: dict[str, str] = {}
    for name, credential in credentials.items():
        if not isinstance(name, str) or not valid_identity_label(name):
            raise ValueError(
                f"Credential name {name!r} is not a stable identity label; use only letters, digits, dot, underscore or hyphen."
            )
        folded = name.casefold()
        previous = folded_names.get(folded)
        if previous is not None and previous != name:
            raise ValueError(
                f"Credential names {previous!r} and {name!r} differ only by case; credential identity labels must be globally unique."
            )
        folded_names[folded] = name
        if not isinstance(credential, dict):
            raise ValueError(f"Credential {name!r} must be a JSON object.")
        kind = str(credential.get("kind") or "").strip().lower()
        if not kind:
            raise ValueError(f"Credential {name!r} requires kind.")
        if kind not in SUPPORTED_CREDENTIAL_KINDS:
            raise ValueError(f"Credential {name!r} kind must be one of {sorted(SUPPORTED_CREDENTIAL_KINDS)}.")
        if "optional" in credential and not isinstance(credential.get("optional"), bool):
            raise ValueError(f"Credential {name!r} optional must be true or false when supplied.")
        if kind == "cookie" and not (credential.get("env") or credential.get("value")):
            raise ValueError(f"Cookie credential {name!r} requires env or value.")
        if kind in {"browser_oidc", "snap4city_oidc"}:
            for field in ("username_env", "password_env", "cookie_env", "login_path", "validation_path"):
                if field in credential and not isinstance(credential.get(field), str):
                    raise ValueError(f"Credential {name!r} field {field} must be a string when supplied.")
            if "headless" in credential and not isinstance(credential.get("headless"), bool):
                raise ValueError(f"Credential {name!r} headless must be true or false when supplied.")
            if "reuse_on_authorized_siblings" in credential and not isinstance(credential.get("reuse_on_authorized_siblings"), bool):
                raise ValueError(f"Credential {name!r} reuse_on_authorized_siblings must be true or false when supplied.")
            sibling_paths = credential.get("sibling_login_paths")
            if sibling_paths is not None and (
                not isinstance(sibling_paths, list)
                or not all(isinstance(item, str) and item.strip() for item in sibling_paths)
            ):
                raise ValueError(f"Credential {name!r} sibling_login_paths must be a list of non-empty strings.")
            if "timeout_seconds" in credential:
                try:
                    timeout_seconds = int(credential.get("timeout_seconds"))
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"Credential {name!r} timeout_seconds must be an integer.") from exc
                if not 10 <= timeout_seconds <= 180:
                    raise ValueError(f"Credential {name!r} timeout_seconds must be between 10 and 180.")
            required_names = credential.get("required_cookie_names")
            if required_names is not None and (
                not isinstance(required_names, list)
                or not all(isinstance(item, str) and item.strip() for item in required_names)
            ):
                raise ValueError(f"Credential {name!r} required_cookie_names must be a list of non-empty strings.")
            if required_names is not None:
                folded_required: set[str] = set()
                for cookie_name in required_names:
                    folded_cookie = str(cookie_name).strip().casefold()
                    if folded_cookie in folded_required:
                        raise ValueError(
                            f"Credential {name!r} required_cookie_names contains duplicate cookie name {cookie_name!r} (case-insensitive)."
                        )
                    folded_required.add(folded_cookie)


# Resolves one target credential at execution time; environment references are preferred.
def resolve_cookie_credential(config: dict[str, Any], reference: str) -> str:
    credentials = config.get("credentials") or {}
    credential = credentials.get(reference)
    if not isinstance(credential, dict):
        raise ValueError(f"Unknown credential reference: {reference}")
    kind = str(credential.get("kind") or "").strip().lower()
    if kind != "cookie":
        raise ValueError(
            f"Credential {reference!r} has kind={kind!r}; the current HTTP orchestrators consume cookie sessions directly."
        )
    env_name = str(credential.get("env") or "").strip()
    if env_name:
        value = os.environ.get(env_name, "").strip()
        if not value:
            if bool(credential.get("optional", False)):
                return ""
            raise ValueError(f"Environment variable {env_name!r} required by credential {reference!r} is empty or missing.")
        return value
    value = str(credential.get("value") or "").strip()
    if not value:
        raise ValueError(f"Credential {reference!r} does not contain a usable cookie value.")
    return value


# Infers the common web protocol when a configuration supplies only host/IP and port.
def _service_protocol(protocol: str, port: int | None) -> str:
    explicit = str(protocol or "").strip().lower()
    if explicit:
        return explicit
    return "https" if port == 443 else "http"


# Formats a host/port/protocol service as the URL consumed by the web orchestrators.
def service_target_url(host: str, protocol: str, port: int | None, base_path: str = "/") -> str:
    protocol = _service_protocol(protocol, port)
    host = str(host).strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    normalized_path = "/" + str(base_path or "/").lstrip("/")
    default_port = 80 if protocol == "http" else 443 if protocol == "https" else None
    port_fragment = "" if port in (None, default_port) else f":{int(port)}"
    return f"{protocol}://{host}{port_fragment}{normalized_path}"


# Resolves one service from either its absolute url field or the legacy host/protocol/port fields.
def _service_target(asset_host: str, service: dict[str, Any]) -> tuple[str, str, str, int | None]:
    absolute_url = str(service.get("url") or "").strip()
    if absolute_url:
        parsed = urlparse(absolute_url)
        protocol = str(parsed.scheme or "").lower()
        host = str(parsed.hostname or "")
        port = parsed.port
        if port is None:
            port = 80 if protocol == "http" else 443 if protocol == "https" else None
        return absolute_url, host, protocol, port

    port_value = service.get("port")
    port = int(port_value) if port_value not in (None, "") else None
    protocol = _service_protocol(str(service.get("protocol") or ""), port)
    target = service_target_url(asset_host, protocol, port, str(service.get("base_path") or "/"))
    return target, str(asset_host or ""), protocol, port


# Reports whether the current orchestrators may accept a target without --authorized.
def target_is_local(url: str) -> bool:
    host = str(urlparse(url).hostname or "").strip().lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# Expands a platform definition into independently executable service jobs.
def iter_service_jobs(config: dict[str, Any]) -> Iterator[dict[str, Any]]:
    execution = config.get("execution") or {}
    credentials = config.get("credentials") or {}
    for asset in config.get("assets") or []:
        asset_id = str(asset.get("id") or "")
        host = str(asset.get("host") or "")
        address = str(asset.get("address") or "").strip()
        for service in asset.get("services") or []:
            service_id = str(service.get("id") or "")
            enabled = bool(service.get("enabled", True))
            configured_protocol = str(service.get("protocol") or "").lower()
            configured_url = str(service.get("url") or "").strip()
            if configured_url or configured_protocol in SUPPORTED_WEB_PROTOCOLS or (not configured_protocol and service.get("port") not in (None, "")):
                target, resolved_host, protocol, port = _service_target(host, service)
            else:
                protocol = configured_protocol
                resolved_host = host
                port_value = service.get("port")
                port = int(port_value) if port_value not in (None, "") else None
                target = ""
            entry_points: list[str] = []
            for raw_entry in service.get("entry_points") or []:
                value = str(raw_entry or "").strip()
                if not value:
                    continue
                entry_points.append(urljoin(target, value) if value.startswith("/") and target else value)
            entry_points = list(dict.fromkeys(entry_points))
            credential_refs = service_credential_refs(service)
            primary_ref = credential_refs[0] if credential_refs else ""
            secondary_ref = credential_refs[1] if len(credential_refs) > 1 else ""
            yield {
                "id": f"{asset_id}/{service_id}",
                "asset_id": asset_id,
                "service_id": service_id,
                "host": resolved_host,
                "address": address,
                "protocol": protocol,
                "port": port,
                "target": target,
                "entry_points": entry_points,
                "enabled": enabled,
                "supported": protocol in SUPPORTED_WEB_PROTOCOLS,
                "unsupported_reason": "" if protocol in SUPPORTED_WEB_PROTOCOLS else "current orchestrators assess HTTP/HTTPS application services only",
                "credential_refs": credential_refs,
                "credential_ref": primary_ref,
                "credential_kind": str((credentials.get(primary_ref) or {}).get("kind") or "") if primary_ref else "",
                "secondary_credential_ref": secondary_ref,
                "secondary_credential_kind": str((credentials.get(secondary_ref) or {}).get("kind") or "") if secondary_ref else "",
                "auth_only": bool(service.get("auth_only", False)),
                # Omission is the binding safe default, not a third runtime state. Normalizing here
                # keeps command generation, same-route coalescing and reporting consistent.
                "allow_state_changes": bool(service.get("allow_state_changes") if "allow_state_changes" in service else execution.get("allow_state_changes", False)),
                "interactsh_injection_url": str(service.get("interactsh_injection_url") or "").strip(),
                "notes": str(service.get("notes") or "").strip(),
            }


# Produces a persistable configuration view that keeps secret sources but removes inline secret values.
def redacted_configuration(config: dict[str, Any]) -> dict[str, Any]:
    def redact(value: Any, parent_key: str = "") -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, child in value.items():
                lowered = str(key).lower()
                if lowered in {"value", "password", "secret", "access_token", "refresh_token", "api_key", "cookie"}:
                    result[str(key)] = "<redacted>" if child not in (None, "") else child
                else:
                    result[str(key)] = redact(child, lowered)
            return result
        if isinstance(value, list):
            return [redact(child, parent_key) for child in value]
        return value

    return redact(config)
