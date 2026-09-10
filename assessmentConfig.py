from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse


SCHEMA_VERSION = 1
SUPPORTED_WEB_PROTOCOLS = {"http", "https"}
SUPPORTED_ORCHESTRATORS = {"deterministic", "agentic"}
SUPPORTED_MODES = {"fast", "balanced", "deep"}
SUPPORTED_MODELS = {"snap4city", "llama", "qwen"}


# Loads and validates the platform-level assessment configuration.
def load_assessment_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
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
    _validate_authorization(payload.get("authorization") or {})
    _validate_assets(assets)
    _validate_credentials(payload.get("credentials") or {})
    return payload


# Validates optional scope extensions without implicitly authorizing unrelated external hosts.
def _validate_authorization(authorization: Any) -> None:
    if not isinstance(authorization, dict):
        raise ValueError("authorization must be a JSON object when supplied.")
    if "confirmed" in authorization and not isinstance(authorization.get("confirmed"), bool):
        raise ValueError("authorization.confirmed must be true or false when supplied.")
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
    if suffixes is not None:
        if not isinstance(suffixes, list) or not all(isinstance(value, str) and value.strip() for value in suffixes):
            raise ValueError("authorization.allowed_host_suffixes must be a list of non-empty DNS suffixes.")
        for value in suffixes:
            suffix = value.strip().lower().lstrip(".").rstrip(".")
            if not suffix or "://" in suffix or "/" in suffix or ":" in suffix or " " in suffix:
                raise ValueError(f"Invalid authorization.allowed_host_suffixes entry: {value!r}")
    if (origins or suffixes) and authorization.get("confirmed") is not True:
        raise ValueError("authorization.allowed_origins/allowed_host_suffixes require authorization.confirmed=true.")


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
            if "allow_state_changes" in service and not isinstance(service.get("allow_state_changes"), bool):
                raise ValueError(f"allow_state_changes for {global_id} must be true or false when supplied.")

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

            port = service.get("port")
            if port not in (None, ""):
                try:
                    numeric_port = int(port)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"Invalid port for {global_id}: {port!r}") from exc
                if not 1 <= numeric_port <= 65535:
                    raise ValueError(f"Port out of range for {global_id}: {numeric_port}")


# Validates secret references without resolving or persisting the secret values.
def _validate_credentials(credentials: Any) -> None:
    if not isinstance(credentials, dict):
        raise ValueError("credentials must be a JSON object when supplied.")
    for name, credential in credentials.items():
        if not isinstance(credential, dict):
            raise ValueError(f"Credential {name!r} must be a JSON object.")
        kind = str(credential.get("kind") or "").strip().lower()
        if not kind:
            raise ValueError(f"Credential {name!r} requires kind.")
        if "optional" in credential and not isinstance(credential.get("optional"), bool):
            raise ValueError(f"Credential {name!r} optional must be true or false when supplied.")
        if kind == "cookie" and not (credential.get("env") or credential.get("value")):
            raise ValueError(f"Cookie credential {name!r} requires env or value.")
        if kind == "snap4city_oidc":
            for field in ("username_env", "password_env", "cookie_env", "login_path", "validation_path"):
                if field in credential and not isinstance(credential.get(field), str):
                    raise ValueError(f"Credential {name!r} field {field} must be a string when supplied.")
            if "headless" in credential and not isinstance(credential.get("headless"), bool):
                raise ValueError(f"Credential {name!r} headless must be true or false when supplied.")
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
            primary_ref = str(service.get("credential_ref") or "").strip()
            secondary_ref = str(service.get("secondary_credential_ref") or "").strip()
            yield {
                "id": f"{asset_id}/{service_id}",
                "asset_id": asset_id,
                "service_id": service_id,
                "host": resolved_host,
                "address": address,
                "protocol": protocol,
                "port": port,
                "target": target,
                "enabled": enabled,
                "supported": protocol in SUPPORTED_WEB_PROTOCOLS,
                "unsupported_reason": "" if protocol in SUPPORTED_WEB_PROTOCOLS else "current orchestrators assess HTTP/HTTPS application services only",
                "credential_ref": primary_ref,
                "credential_kind": str((credentials.get(primary_ref) or {}).get("kind") or "") if primary_ref else "",
                "secondary_credential_ref": secondary_ref,
                "secondary_credential_kind": str((credentials.get(secondary_ref) or {}).get("kind") or "") if secondary_ref else "",
                "auth_only": bool(service.get("auth_only", False)),
                "allow_state_changes": service.get("allow_state_changes") if "allow_state_changes" in service else execution.get("allow_state_changes"),
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
