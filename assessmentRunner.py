from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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


# Builds one existing orchestrator command from a normalized service job.
def _build_command(
    config: dict[str, Any], job: dict[str, Any], *, resolve_secrets: bool = True, force_auth_only: bool = False,
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

    primary_ref = str(job.get("credential_ref") or "")
    if primary_ref:
        if str(job.get("credential_kind") or "").lower() != "cookie":
            raise ValueError(f"Job {job['id']} references a non-cookie primary credential that the web orchestrators cannot consume directly.")
        primary_value = resolve_cookie_credential(config, primary_ref) if resolve_secrets else f"<credential:{primary_ref}>"
        if primary_value:
            command.extend(["--cookies", primary_value])
        elif resolve_secrets:
            print(f"[AUTH] Optional credential {primary_ref!r} is unavailable; {job['id']} will run the anonymous profile only.")
    secondary_ref = str(job.get("secondary_credential_ref") or "")
    if secondary_ref:
        if str(job.get("secondary_credential_kind") or "").lower() != "cookie":
            raise ValueError(f"Job {job['id']} references a non-cookie secondary credential that the web orchestrators cannot consume directly.")
        secondary_value = resolve_cookie_credential(config, secondary_ref) if resolve_secrets else f"<credential:{secondary_ref}>"
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


# Writes a redacted execution manifest that can be reviewed without exposing target credentials.
def _write_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


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
    manifest_path = REPORTS_DIR / f"Assessment_Batch_{safe_name}_{stamp}.manifest.json"
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_config": str(Path(args.config).expanduser().resolve()) if args.config else None,
        "configuration": redacted_configuration(config),
        "jobs": [],
    }

    exit_code = 0
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
            manifest["jobs"].append(record)
            print(f"[SKIP] {job['id']}: disabled")
            continue
        if not job.get("supported"):
            record.update(status="skipped", reason=job.get("unsupported_reason"))
            manifest["jobs"].append(record)
            print(f"[SKIP] {job['id']}: {job.get('unsupported_reason')}")
            continue
        try:
            command = _build_command(config, job, resolve_secrets=not args.dry_run, force_auth_only=args.auth_only)
        except ValueError as exc:
            record.update(status="blocked", reason=str(exc))
            manifest["jobs"].append(record)
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
            completed = subprocess.run(command, cwd=ROOT, check=False)
            record["returncode"] = completed.returncode
            record["status"] = "success" if completed.returncode == 0 else "error"
            if completed.returncode:
                exit_code = 1
                if args.stop_on_error:
                    manifest["jobs"].append(record)
                    break
        manifest["jobs"].append(record)
        _write_manifest(manifest_path, manifest)

    _write_manifest(manifest_path, manifest)
    print(f"\n[+] Assessment manifest: {manifest_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
