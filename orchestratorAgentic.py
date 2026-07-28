from __future__ import annotations

import argparse
import asyncio
import json
import platform
import sys
import time
import traceback
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, TypedDict
from urllib.parse import parse_qsl, urlparse

warnings.filterwarnings("ignore", message=r"authlib\.jose module is deprecated.*")

import requests
from langgraph.graph import END, START, StateGraph

import orchestratorDeterministic as deterministic_core

from orchestratorDeterministic import (
    BROAD_SCANNER_TIMEOUTS,
    CURRENT_SCAN_MODE,
    ARJUN_TIMEOUT,
    configure_scan_mode,
    PARAMETER_TOOL_TIMEOUTS,
    _tool_case_skip_reason,
    call_mcp,
    call_mcp_with_progress,
    diagnose_error,
    discover_target,
    enrich_discovery_with_arjun,
    enrich_discovery_with_ffuf,
    merge_discovery,
    make_skipped_result,
    select_arjun_request_cases,
    iter_leaf_results,
    log_result,
    log_zap_session_diagnostics,
    print_preflight_report,
    print_security_finding_summary,
    run_preflight_checks,
    select_request_cases,
    select_tool_request_cases,
    select_browser_request_cases,
    select_workflow_request_cases,
    select_authorization_request_cases,
    select_oast_request_cases,
    write_emergency_json_report,
)
from utils import canonical_cookie_header, cookie_names, normalize_url, same_origin


class AgentState(TypedDict):
    target: str
    profiles: list[dict[str, str]]
    discovery: dict[str, dict[str, Any]]
    plan: list[dict[str, Any]]
    completed: list[str]
    results: dict[str, dict[str, Any]]
    round: int
    max_rounds: int
    ollama_url: str
    model: str
    injection_url: str
    notes: list[str]
    finished: bool
    diagnostics: list[dict[str, Any]]
    report_status: dict[str, Any]
    require_ai: bool
    planner_source: str
    ai_timeout: int
    allow_state_changes: bool
    secondary_cookies: str
    planner_audit: list[dict[str, Any]]


REGISTRY = deterministic_core.agentic_registry()

AI_PLANNER_TIMEOUTS = {"fast": 300, "balanced": 480, "deep": 720}
AI_PLANNER_MAX_PREDICT = {"fast": 700, "balanced": 1000, "deep": 1400}
LAST_OLLAMA_PLAN_DIAGNOSTICS: dict[str, Any] = {}

BROAD_COVERAGE_TOOLS = ("ffuf", "exposure", "zap", "nuclei", "session", "nikto")
DISCOVERY_COVERAGE_TOOLS = ("arjun",)
PARAMETER_COVERAGE_TOOLS = ("sqlmap", "dalfox", "commix", "traversal", "idor")
AUTHORIZATION_COVERAGE_TOOLS = ("authorization",)
WORKFLOW_COVERAGE_TOOLS = ("browser", "workflow")
OPTIONAL_COVERAGE_TOOLS = ("jwt", "interactsh")
ROUND_ACTION_BUDGETS = {"fast": 14, "balanced": 24, "deep": 36}

COVERAGE_REPAIR_SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning_summary": {"type": "string"},
        "selected_candidate_ids": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["reasoning_summary", "selected_candidate_ids"],
}

PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning_summary": {"type": "string"},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "profile": {"type": "string"},
                    "tool": {"type": "string"},
                    "target_url": {"type": "string"},
                    "jwt_token": {"type": "string"},
                    "injection_url": {"type": "string"},
                    "method": {"type": "string"},
                    "data": {"type": "string"},
                    "parameters": {"type": "array", "items": {"type": "string"}},
                    "reason": {"type": "string"},
                },
                "required": ["profile", "tool", "target_url", "jwt_token", "injection_url", "reason"],
            },
        },
        "finish": {"type": "boolean"},
    },
    "required": ["reasoning_summary", "actions", "finish"],
}



def _ollama_error(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return (response.text or response.reason or "unknown Ollama error").strip()
    if isinstance(payload, dict):
        return str(payload.get("error") or payload.get("message") or payload).strip()
    return str(payload)


def _ollama_installed_models(ollama_url: str) -> list[str]:
    response = requests.get(
        f"{ollama_url.rstrip('/')}/api/tags", timeout=(5, 30)
    )
    response.raise_for_status()
    payload = response.json()
    values: list[str] = []
    for item in payload.get("models", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("name") or item.get("model") or "").strip()
        if value:
            values.append(value)
    return list(dict.fromkeys(values))


def _model_matches(requested: str, installed: str) -> bool:
    left, right = requested.lower(), installed.lower()
    if left == right:
        return True
    if ":" not in left and right.split(":", 1)[0] == left:
        return True
    return False


def ensure_ollama_model(
    ollama_url: str,
    requested_model: str,
    *,
    allow_pull: bool = True,
) -> tuple[str, dict[str, Any]]:
    """Verify Ollama and ensure a usable model exists before planning."""
    base = ollama_url.rstrip("/")
    diagnostics: dict[str, Any] = {
        "ollama_url": base,
        "requested_model": requested_model,
        "model_pull_attempted": False,
        "fallback_model_used": False,
    }
    version = requests.get(f"{base}/api/version", timeout=(5, 20))
    version.raise_for_status()
    try:
        diagnostics["ollama_version"] = version.json().get("version", "unknown")
    except ValueError:
        diagnostics["ollama_version"] = "unknown"

    installed = _ollama_installed_models(base)
    diagnostics["installed_models_before"] = installed
    matched = next(
        (name for name in installed if _model_matches(requested_model, name)),
        "",
    )
    if matched:
        diagnostics.update(model_ready=True, selected_model=matched)
        return matched, diagnostics

    pull_error = ""
    if allow_pull:
        diagnostics["model_pull_attempted"] = True
        try:
            response = requests.post(
                f"{base}/api/pull",
                json={"model": requested_model, "stream": False},
                timeout=(10, 7200),
            )
            if response.status_code >= 400:
                raise RuntimeError(
                    f"HTTP {response.status_code}: {_ollama_error(response)}"
                )
            installed = _ollama_installed_models(base)
            diagnostics["installed_models_after_pull"] = installed
            matched = next(
                (name for name in installed if _model_matches(requested_model, name)),
                "",
            )
            if matched:
                diagnostics.update(model_ready=True, selected_model=matched)
                return matched, diagnostics
            pull_error = (
                "Ollama pull completed but the requested model was not listed "
                "by /api/tags."
            )
        except Exception as exc:
            pull_error = f"{type(exc).__name__}: {exc}"
    diagnostics["model_pull_error"] = pull_error

    if installed:
        selected = installed[0]
        diagnostics.update(
            model_ready=True,
            selected_model=selected,
            fallback_model_used=True,
            fallback_reason=(
                pull_error
                or "Requested model is absent and automatic pulling was disabled."
            ),
        )
        return selected, diagnostics

    diagnostics.update(model_ready=False, selected_model="")
    raise RuntimeError(
        "Ollama is reachable but no usable local model exists. "
        + (pull_error or f"Requested model '{requested_model}' is not installed.")
    )


def _parse_ollama_plan_content(content: str) -> dict[str, Any]:
    value = json.loads(str(content or ""))
    if not isinstance(value, dict) or not isinstance(value.get("actions", []), list):
        raise ValueError("Ollama returned an invalid plan object.")
    return value


def compact_discovery_for_planner(discovery: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Keep the LLM context bounded without removing actionable requests.

    The previous implementation serialized complete discovery objects. On a
    local 7B/8B model this could contain large response excerpts and exhaust the
    240-second HTTP read timeout before a single plan was returned.
    """
    compact: dict[str, Any] = {}
    for profile, found in discovery.items():
        ranked_cases = select_request_cases(found, limit=36)
        request_cases = []
        for case in ranked_cases:
            request_cases.append({
                "url": str(case.get("url", "")),
                "method": str(case.get("method", "GET")).upper(),
                "data": str(case.get("data", ""))[:900],
                "parameters": [str(value) for value in case.get("parameters", [])][:20],
                "file_parameters": [str(value) for value in case.get("file_parameters", [])][:8],
                "token_parameters": [str(value) for value in case.get("token_parameters", [])][:8],
                "enctype": str(case.get("enctype", ""))[:120],
                "source_url": str(case.get("source_url", "")),
                "priority_score": int(case.get("priority_score", 0) or 0),
            })
        compact[profile] = {
            "authenticated": found.get("authentication_effective"),
            "html_url_count": len(found.get("html_urls", [])),
            "request_case_count": len(found.get("request_cases", [])),
            "high_value_html_urls": [str(value) for value in found.get("html_urls", [])[:45]],
            "request_cases": request_cases,
            "client_side_candidates": [
                {
                    "url": str(item.get("url", "")),
                    "script_url": str(item.get("script_url", "")),
                    "sources": list(item.get("sources", []))[:8],
                    "sinks": list(item.get("sinks", []))[:8],
                }
                for item in found.get("client_side_candidates", [])[:12]
                if isinstance(item, dict)
            ],
            "jwt_tokens": [str(value)[:1800] for value in found.get("jwt_tokens", [])[:4]],
            "crawl_errors": [
                {
                    "url": str(item.get("url", "")),
                    "error": str(item.get("error", item.get("message", "")))[:300],
                }
                for item in found.get("errors", [])[:8]
                if isinstance(item, dict)
            ],
        }
    return compact


def _ollama_stream_content(
    url: str,
    payload: dict[str, Any],
    *,
    response_kind: str,
    total_timeout: int,
) -> str:
    """Read a streamed Ollama response so token progress prevents false timeout.

    The non-stream JSON branch is retained for older Ollama-compatible servers
    and for the project's controlled regression fixtures.
    """
    started = time.monotonic()
    chunks: list[str] = []
    read_timeout = max(90, int(total_timeout) + 30)
    response = requests.post(
        url,
        json={**payload, "stream": True},
        stream=True,
        timeout=(10, read_timeout),
    )
    try:
        if response.status_code >= 400:
            raise RuntimeError(f"HTTP {response.status_code}: {_ollama_error(response)}")
        if not hasattr(response, "iter_lines"):
            value = response.json()
            if response_kind == "chat":
                content = str((value.get("message") or {}).get("content") or "")
            else:
                content = str(value.get("response") or "")
            if not content:
                raise ValueError("Ollama completed without returning plan content.")
            return content
        for raw in response.iter_lines(decode_unicode=True):
            if time.monotonic() - started > total_timeout:
                raise TimeoutError(
                    f"Ollama planning exceeded the {total_timeout}-second budget."
                )
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Ollama returned a non-JSON stream event: {raw[:200]}") from exc
            if event.get("error"):
                raise RuntimeError(str(event.get("error")))
            if response_kind == "chat":
                piece = str((event.get("message") or {}).get("content") or "")
            else:
                piece = str(event.get("response") or "")
            if piece:
                chunks.append(piece)
            if event.get("done") is True:
                break
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()
    content = "".join(chunks).strip()
    if not content:
        raise ValueError("Ollama completed without returning plan content.")
    return content


def warm_ollama_model(
    ollama_url: str,
    model: str,
    *,
    timeout: int,
) -> dict[str, Any]:
    """Load model weights before discovery so planning starts from a warm model."""
    started = time.monotonic()
    content = _ollama_stream_content(
        f"{ollama_url.rstrip('/')}/api/generate",
        {
            "model": model,
            "prompt": "Reply with READY and nothing else.",
            "options": {"temperature": 0, "num_predict": 4, "num_ctx": 2048},
            "keep_alive": "30m",
        },
        response_kind="generate",
        total_timeout=max(90, min(int(timeout), 600)),
    )
    return {
        "ready": True,
        "response": content[:80],
        "seconds": round(time.monotonic() - started, 2),
    }


def action_id(action: dict[str, Any]) -> str:
    return "|".join(str(action.get(key, "")) for key in ("profile", "tool", "target_url", "method", "data", "jwt_token", "injection_url"))


def ollama_plan(state: AgentState) -> dict[str, Any]:
    registry = {
        name: {"scope": values[2], "description": values[3]}
        for name, values in REGISTRY.items()
    }
    eligible = validate_plan(state, discovery_candidate_actions(state))
    remaining_by_profile: dict[str, list[dict[str, Any]]] = {}
    for action in eligible:
        remaining_by_profile.setdefault(action["profile"], []).append({
            "tool": action["tool"],
            "target_url": action["target_url"],
            "method": action.get("method", "GET"),
            "parameters": action.get("parameters", []),
            "file_parameters": action.get("file_parameters", []),
            "token_parameters": action.get("token_parameters", []),
            "source_url": action.get("source_url", ""),
        })
    coverage_contract = _coverage_contract(state, eligible)
    prompt = {
        "target": state["target"],
        "round": state["round"] + 1,
        "maximum_rounds": state["max_rounds"],
        "round_action_budget": ROUND_ACTION_BUDGETS.get(deterministic_core.CURRENT_SCAN_MODE, 12),
        "profiles": [profile["name"] for profile in state["profiles"]],
        "registry": registry,
        "discovery": compact_discovery_for_planner(state["discovery"]),
        "previous_results": compact_results(state["results"]),
        "already_completed": state["completed"],
        "remaining_eligible_actions": remaining_by_profile,
        "minimum_coverage_contract": coverage_contract,
        "configured_oast_url": state["injection_url"],
    }
    system_message = (
        "Plan an explicitly authorized web-security assessment. Use only the supplied registry and "
        "discovered request contracts. Broad scanners are complementary: FFUF must discover resources "
        "before ZAP imports the enriched traffic and performs passive/active analysis; Nuclei checks templates and DAST, "
        "and Nikto checks server exposure; do not replace one with another. In the first round include "
        "all missing eligible broad scanners and Arjun discovery actions before expensive parameter "
        "checks. In later rounds cover remaining eligible SQLMap, Dalfox, Commix, traversal, IDOR, "
        "read-only authorization/BOLA differentials, browser XSS, multi-step workflow, JWT and Interactsh actions. Exposure and session analysis "
        "remain separate broad capabilities. The minimum_coverage_contract requires at least one AI-selected "
        "action for every still-applicable profile/tool class; do not omit a group merely because "
        "another scanner overlaps it. Use parameter tools only on an exactly matching discovered "
        "request, IDOR only on numeric object references, authorization only on discovered read-only identity/object/resource signals, and Interactsh only on compatible inputs. "
        "Avoid duplicates and do not repeat completed actions. Do not set finish=true while "
        "remaining_eligible_actions is non-empty. Return up to round_action_budget actions and only "
        "schema-valid JSON with a concise reasoning_summary."
    )
    base = state["ollama_url"].rstrip("/")
    total_timeout = max(120, int(state.get("ai_timeout") or 480))
    max_predict = AI_PLANNER_MAX_PREDICT.get(
        deterministic_core.CURRENT_SCAN_MODE, 1000
    )
    if state["round"] >= 1:
        # Later rounds normally select only a handful of newly discovered
        # requests. A 720-second/1400-token retry added twelve minutes to the
        # observed run before a useful continuation plan was produced. Cap only
        # continuation planning; the generic coverage contract and repair pass
        # remain active, while scanner execution budgets are unchanged.
        total_timeout = min(total_timeout, 300)
        max_predict = min(max_predict, 600)
    common_options = {
        "temperature": 0,
        "num_predict": max_predict,
        "num_ctx": 8192,
        "top_p": 0.9,
    }
    context = json.dumps(prompt, ensure_ascii=False, separators=(",", ":"))
    attempts = [
        (
            "chat",
            f"{base}/api/chat",
            {
                "model": state["model"],
                "format": PLAN_SCHEMA,
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": context},
                ],
                "options": common_options,
                "keep_alive": "30m",
            },
            max(90, int(total_timeout * 0.62)),
        ),
        (
            "generate",
            f"{base}/api/generate",
            {
                "model": state["model"],
                "format": PLAN_SCHEMA,
                "prompt": system_message + "\n\nAssessment context:\n" + context,
                "options": common_options,
                "keep_alive": "30m",
            },
            max(90, int(total_timeout * 0.38)),
        ),
    ]
    errors: list[str] = []
    for kind, url, payload, budget in attempts:
        try:
            content = _ollama_stream_content(
                url,
                payload,
                response_kind=kind,
                total_timeout=budget,
            )
            plan = _parse_ollama_plan_content(content)
            LAST_OLLAMA_PLAN_DIAGNOSTICS.clear()
            LAST_OLLAMA_PLAN_DIAGNOSTICS.update({
                "endpoint": kind,
                "context_bytes": len(context.encode("utf-8")),
                "attempt_errors": list(errors),
            })
            return plan
        except Exception as exc:
            errors.append(f"{kind}: {type(exc).__name__}: {exc}")
    raise RuntimeError("; ".join(errors))


def compact_results(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        profile: {
            key: {
                "status": value.get("status"),
                "target": value.get("target"),
                "findings": len(value.get("vulnerabilities") or []),
                "diagnosis": value.get("diagnosis"),
                "output": str(value.get("output", ""))[:250],
            }
            for key, value in values.items() if isinstance(value, dict)
        }
        for profile, values in results.items()
    }


def discovery_node(state: AgentState) -> dict[str, Any]:
    print("\n[*] Discovery of anonymous and authenticated surfaces")
    discovery, diagnostics = {}, list(state["diagnostics"])
    for profile in state["profiles"]:
        found = discover_target(state["target"], profile["cookies"], max_pages=30)
        discovery[profile["name"]] = found
        diagnostics.extend({"phase": "discovery", "profile": profile["name"], **item} for item in found["errors"])
        print(f"    {profile['name']}: {len(found.get('html_urls', []))} HTML pages, {len(found.get('request_cases', []))} GET/POST cases, {len(found['jwt_tokens'])} JWTs")
        if found.get("authentication_effective") is False:
            print(f"    [WARNING] {profile['name']}: {found.get('authentication_note')}", file=sys.stderr)
    return {"discovery": discovery, "diagnostics": diagnostics}


def discovery_candidate_actions(state: AgentState) -> list[dict[str, Any]]:
    """Build a target-independent action catalogue from live discovery.

    The same catalogue is shown to Ollama and can serve as an explicitly
    labelled fallback only when AI planning is unavailable.
    """
    actions: list[dict[str, Any]] = []
    has_auth = any(bool(profile.get("cookies")) for profile in state["profiles"])
    for profile in state["profiles"]:
        name = profile["name"]
        authenticated = bool(profile.get("cookies"))
        broad = list(deterministic_core.broad_tool_order(authenticated))
        for tool in broad:
            actions.append({"profile": name, "tool": tool, "target_url": state["target"], "jwt_token": "", "injection_url": "", "reason": "Session-aware baseline coverage."})
        for case in select_arjun_request_cases(
            state["discovery"].get(name, {}), state["target"],
            limit=deterministic_core.ARJUN_ENDPOINT_LIMIT,
        ):
            actions.append({
                "profile": name,
                "tool": "arjun",
                "target_url": case["url"],
                "method": case.get("method", "GET"),
                "data": case.get("data", ""),
                "parameters": case.get("parameters", []),
                "jwt_token": "",
                "injection_url": "",
                "reason": "Hidden-parameter discovery using the real request method and body.",
            })
        if authenticated or not has_auth:
            for tool in ("sqlmap", "dalfox", "commix", "traversal", "idor"):
                for case in select_tool_request_cases(
                    state["discovery"].get(name, {}), tool,
                    limit=deterministic_core.PARAMETER_TOOL_CASE_LIMITS.get(tool, 1),
                ):
                    actions.append({"profile": name, "tool": tool, "target_url": case["url"], "method": case.get("method", "GET"), "data": case.get("data", ""), "parameters": case.get("parameters", []), "jwt_token": "", "injection_url": "", "reason": f"Highest-value discovered request for {tool}."})
            for case in select_authorization_request_cases(
                state["discovery"].get(name, {}),
                limit=deterministic_core.tool_action_limit("authorization"),
            ):
                actions.append({
                    "profile": name, "tool": "authorization", "target_url": case["url"],
                    "method": "GET", "data": "",
                    "parameters": case.get("parameters", []), "jwt_token": "", "injection_url": "",
                    "reason": "Read-only authorization differential candidate derived from an identity, object or privileged-resource signal.",
                })
            for case in select_browser_request_cases(
                state["discovery"].get(name, {}),
                limit=deterministic_core.tool_action_limit("browser"),
            ):
                actions.append({
                    "profile": name, "tool": "browser", "target_url": case["url"],
                    "method": case.get("method", "GET"), "data": case.get("data", ""),
                    "parameters": case.get("parameters", []), "jwt_token": "", "injection_url": "",
                    "fields": case.get("fields", []),
                    "source_url": case.get("source_url", ""),
                    "client_sources": case.get("client_sources", []),
                    "client_sinks": case.get("client_sinks", []),
                    "reason": "Browser verification candidate derived from XSS-like parameters or client-side source/sink evidence.",
                })
            for case in select_workflow_request_cases(
                state["discovery"].get(name, {}),
                limit=deterministic_core.tool_action_limit("workflow"),
            ):
                actions.append({
                    "profile": name, "tool": "workflow", "target_url": case["url"],
                    "method": case.get("method", "POST"), "data": case.get("data", ""),
                    "parameters": case.get("parameters", []), "jwt_token": "", "injection_url": "",
                    "source_url": case.get("source_url", ""),
                    "fields": case.get("fields", []),
                    "file_parameters": case.get("file_parameters", []),
                    "token_parameters": case.get("token_parameters", []),
                    "enctype": case.get("enctype", ""),
                    "reason": "Multi-step workflow candidate derived from discovered form metadata.",
                })
        tokens = state["discovery"].get(name, {}).get("jwt_tokens", [])
        if tokens:
            actions.append({"profile": name, "tool": "jwt", "target_url": state["target"], "jwt_token": tokens[0], "injection_url": "", "reason": "Discovered JWT."})
        if state["injection_url"]:
            actions.append({"profile": name, "tool": "interactsh", "target_url": state["target"], "method": "GET", "data": "", "parameters": ["explicit"], "jwt_token": "", "injection_url": state["injection_url"], "reason": "Configured OAST URL."})
        else:
            for case in select_oast_request_cases(
                state["discovery"].get(name, {}), state["target"],
                limit=deterministic_core.tool_action_limit("interactsh"),
            ):
                actions.append({
                    "profile": name, "tool": "interactsh", "target_url": state["target"],
                    "method": case.get("method", "GET"), "data": case.get("data", ""),
                    "parameters": case.get("parameters", []), "jwt_token": "",
                    "injection_url": case.get("injection_url", ""),
                    "reason": f"Automatically selected OAST-capable parameter: {case.get('parameter', 'unknown')}.",
                })
    return actions


def validate_plan(state: AgentState, proposed: Any) -> list[dict[str, Any]]:
    if not isinstance(proposed, list):
        return []
    profiles = {profile["name"] for profile in state["profiles"]}
    completed, valid = set(state["completed"]), []
    per_tool: dict[tuple[str, str], int] = {}
    proposal_limit = max(60, ROUND_ACTION_BUDGETS.get(deterministic_core.CURRENT_SCAN_MODE, 20) * 2)
    for raw in proposed[:proposal_limit]:
        if not isinstance(raw, dict):
            continue
        profile, tool = str(raw.get("profile", "")), str(raw.get("tool", "")).lower()
        if profile not in profiles or tool not in REGISTRY:
            continue
        has_authenticated_profile = any(
            bool(item.get("cookies")) for item in state["profiles"]
        )
        profile_has_cookie = next(
            (
                bool(item.get("cookies"))
                for item in state["profiles"]
                if item.get("name") == profile
            ),
            False,
        )
        if deterministic_core.CURRENT_SCAN_MODE != "deep":
            # Match the deterministic orchestrator: do not duplicate slow host
            # scanners and active parameter exploitation anonymously when an
            # authenticated profile is available.
            if (
                profile == "anonymous"
                and has_authenticated_profile
                and tool in {"session", "nikto", "sqlmap", "dalfox", "commix", "traversal", "idor", "authorization", "browser", "workflow"}
            ):
                continue
        found = state["discovery"].get(profile, {})
        target_url = str(raw.get("target_url", "")).strip()
        token = str(raw.get("jwt_token", "")).strip()
        injection = str(raw.get("injection_url", "")).strip()
        method = str(raw.get("method", "")).upper().strip()
        data = ""
        parameters: list[str] = []
        source_url = ""
        fields: list[dict[str, Any]] = []
        client_sources: list[str] = []
        client_sinks: list[str] = []
        file_parameters: list[str] = []
        token_parameters: list[str] = []
        enctype = ""
        scope = REGISTRY[tool][2]
        if scope == "base":
            target_url = state["target"]
        elif scope == "url":
            cases = select_arjun_request_cases(found, state["target"], limit=10)
            matching = [case for case in cases if str(case.get("url", "")) == target_url]
            if method:
                matching = [
                    case for case in matching
                    if str(case.get("method", "GET")).upper() == method
                ]
            if not matching:
                continue
            selected = matching[0]
            method = str(selected.get("method", "GET")).upper()
            data = str(selected.get("data", ""))
            parameters = [str(value) for value in selected.get("parameters", [])]
        elif scope in {"parameterized", "numeric"}:
            cases = select_tool_request_cases(found, tool, limit=20)
            matching = [case for case in cases if str(case.get("url", "")) == target_url]
            if method:
                matching = [case for case in matching if str(case.get("method", "GET")).upper() == method]
            if not matching:
                continue
            selected = matching[0]
            if _tool_case_skip_reason(tool, selected):
                continue
            if tool == "sqlmap" and profile_has_cookie and deterministic_core._is_login_case(selected):
                # An authenticated profile is expected to stay inside the
                # application. Testing the public login form with that session
                # repeatedly produced login redirects and wasted a deep-mode
                # action without adding authenticated coverage.
                continue
            method = str(selected.get("method", "GET")).upper()
            data = str(selected.get("data", ""))
            parameters = [str(value) for value in selected.get("parameters", [])]
            if scope == "numeric" and (
                method != "GET" or
                not any(value.isdigit() for _, value in parse_qsl(urlparse(target_url).query, keep_blank_values=True))
            ):
                continue
        elif scope == "authorization":
            if not profile_has_cookie:
                continue
            cases = select_authorization_request_cases(found, limit=30)
            matching = [case for case in cases if str(case.get("url", "")) == target_url]
            if not matching:
                continue
            selected = matching[0]
            method = "GET"
            data = ""
            parameters = [str(value) for value in selected.get("parameters", [])]
        elif scope == "browser":
            cases = select_browser_request_cases(found, limit=20)
            matching = [case for case in cases if str(case.get("url", "")) == target_url]
            if method:
                matching = [case for case in matching if str(case.get("method", "GET")).upper() == method]
            if not matching:
                continue
            selected = matching[0]
            method = str(selected.get("method", "GET")).upper()
            data = str(selected.get("data", ""))
            parameters = [str(value) for value in selected.get("parameters", [])]
            source_url = str(selected.get("source_url", ""))
            fields = [dict(value) for value in selected.get("fields", []) if isinstance(value, dict)]
            client_sources = [str(value) for value in selected.get("client_sources", []) if str(value)]
            client_sinks = [str(value) for value in selected.get("client_sinks", []) if str(value)]
        elif scope == "workflow":
            cases = select_workflow_request_cases(found, limit=30)
            matching = [case for case in cases if str(case.get("url", "")) == target_url]
            if method:
                matching = [case for case in matching if str(case.get("method", "POST")).upper() == method]
            if not matching:
                continue
            selected = matching[0]
            method = str(selected.get("method", "POST")).upper()
            data = str(selected.get("data", ""))
            parameters = [str(value) for value in selected.get("parameters", [])]
            source_url = str(selected.get("source_url", ""))
            fields = [dict(value) for value in selected.get("fields", []) if isinstance(value, dict)]
            file_parameters = [str(value) for value in selected.get("file_parameters", [])]
            token_parameters = [str(value) for value in selected.get("token_parameters", [])]
            enctype = str(selected.get("enctype", ""))
        elif scope == "jwt":
            if token not in set(found.get("jwt_tokens") or []):
                continue
            target_url = state["target"]
        elif scope == "oast":
            target_url = state["target"]
            if state["injection_url"]:
                injection = state["injection_url"]
                method = "GET"
                data = ""
                parameters = ["explicit"]
            else:
                candidates = select_oast_request_cases(found, state["target"], limit=5)
                matching = [item for item in candidates if not injection or item.get("injection_url") == injection]
                if not matching:
                    continue
                selected = matching[0]
                injection = str(selected.get("injection_url", ""))
                method = str(selected.get("method", "GET")).upper()
                data = str(selected.get("data", ""))
                parameters = [str(value) for value in selected.get("parameters", [])]
        action = {
            "profile": profile, "tool": tool, "target_url": target_url,
            "method": method or "GET", "data": data, "parameters": parameters,
            "source_url": source_url, "fields": fields,
            "client_sources": client_sources, "client_sinks": client_sinks,
            "file_parameters": file_parameters, "token_parameters": token_parameters,
            "enctype": enctype, "jwt_token": token, "injection_url": injection,
            "reason": str(raw.get("reason", ""))[:500] or "No planner reason supplied.",
        }
        identifier = action_id(action)
        key = (profile, tool)
        limit = deterministic_core.tool_action_limit(tool)
        if per_tool.get(key, 0) >= limit:
            continue
        if identifier not in completed and all(action_id(item) != identifier for item in valid):
            valid.append(action)
            per_tool[key] = per_tool.get(key, 0) + 1
    return valid


def _coverage_phase(tool: str) -> int:
    if tool in BROAD_COVERAGE_TOOLS:
        return 0
    if tool in DISCOVERY_COVERAGE_TOOLS:
        return 1
    if tool in PARAMETER_COVERAGE_TOOLS:
        return 2
    if tool in AUTHORIZATION_COVERAGE_TOOLS:
        return 3
    if tool in WORKFLOW_COVERAGE_TOOLS:
        return 4
    if tool in OPTIONAL_COVERAGE_TOOLS:
        return 5
    return 9


def _coverage_group_key(action: dict[str, Any]) -> tuple[str, str]:
    return str(action.get("profile", "")), str(action.get("tool", "")).lower()


def _eligible_action_catalog(state: AgentState) -> list[dict[str, Any]]:
    """Return target-independent actions allowed by discovery and tool schemas.

    This catalogue is not an execution plan.  It contains only actions derived
    from the shared deterministic selectors and the request contracts actually
    discovered for each profile.  The LLM must still choose the actions that
    become part of an agentic round.
    """
    return validate_plan(state, discovery_candidate_actions(state))


def _coverage_contract(
    state: AgentState,
    eligible: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build a generic minimum-coverage contract for the current AI round.

    One action is requested for every still-applicable profile/tool class. This
    does not contain DVWA routes, product names, or a fixed pentest plan: the
    applicability and candidate endpoints are computed from live discovery.
    """
    catalog = eligible if eligible is not None else _eligible_action_catalog(state)
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for action in catalog:
        grouped.setdefault(_coverage_group_key(action), []).append(action)

    groups: list[dict[str, Any]] = []
    for (profile, tool), candidates in grouped.items():
        groups.append({
            "profile": profile,
            "tool": tool,
            "phase": _coverage_phase(tool),
            "required": 1,
            "candidate_count": len(candidates),
        })
    groups.sort(key=lambda item: (
        int(item["phase"]),
        deterministic_core.tool_execution_rank(
            str(item["tool"]),
            any(
                profile.get("name") == item["profile"] and bool(profile.get("cookies"))
                for profile in state["profiles"]
            ),
        ),
        str(item["profile"]),
        str(item["tool"]),
    ))
    return groups


def _coverage_gaps(
    state: AgentState,
    plan: list[dict[str, Any]],
    eligible: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    catalog = eligible if eligible is not None else _eligible_action_catalog(state)
    by_group: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for action in catalog:
        by_group.setdefault(_coverage_group_key(action), []).append(action)
    planned_groups = {_coverage_group_key(action) for action in plan}
    gaps: list[dict[str, Any]] = []
    for requirement in _coverage_contract(state, catalog):
        key = (str(requirement["profile"]), str(requirement["tool"]))
        if key in planned_groups:
            continue
        gaps.append({
            **requirement,
            "candidates": by_group.get(key, []),
        })
    return gaps


def _merge_ai_actions(
    current: list[dict[str, Any]],
    additions: list[dict[str, Any]],
    *,
    budget: int,
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for action in [*current, *additions]:
        identifier = action_id(action)
        if identifier in seen:
            continue
        seen.add(identifier)
        merged.append(action)
        if len(merged) >= budget:
            break
    return merged


def ollama_coverage_repair(
    state: AgentState,
    current_plan: list[dict[str, Any]],
    gaps: list[dict[str, Any]],
    *,
    attempt: int,
) -> tuple[list[dict[str, Any]], str]:
    """Ask Ollama to choose exact candidate IDs for missing tool classes.

    The orchestrator never silently inserts an endpoint.  Candidate actions are
    generated from discovery, but Ollama explicitly selects the IDs to add.
    """
    candidate_map: dict[str, dict[str, Any]] = {}
    missing_groups: list[dict[str, Any]] = []
    serial = 1
    for gap in gaps:
        candidate_rows: list[dict[str, Any]] = []
        for action in list(gap.get("candidates") or [])[:6]:
            candidate_id = f"C{serial:03d}"
            serial += 1
            candidate_map[candidate_id] = action
            candidate_rows.append({
                "candidate_id": candidate_id,
                "profile": action["profile"],
                "tool": action["tool"],
                "target_url": action["target_url"],
                "method": action.get("method", "GET"),
                "parameters": action.get("parameters", []),
                "reason": action.get("reason", ""),
            })
        missing_groups.append({
            "profile": gap["profile"],
            "tool": gap["tool"],
            "required": 1,
            "candidates": candidate_rows,
        })

    remaining_slots = max(
        0,
        ROUND_ACTION_BUDGETS.get(deterministic_core.CURRENT_SCAN_MODE, 20)
        - len(current_plan),
    )
    if not candidate_map or remaining_slots <= 0:
        return [], "No repair slots or candidates were available."

    prompt = {
        "target": state["target"],
        "round": state["round"] + 1,
        "repair_attempt": attempt,
        "remaining_action_slots": remaining_slots,
        "current_plan": [
            {
                "profile": action["profile"],
                "tool": action["tool"],
                "target_url": action["target_url"],
                "method": action.get("method", "GET"),
            }
            for action in current_plan
        ],
        "missing_coverage_groups": missing_groups,
    }
    system_message = (
        "Repair an authorized web-security plan. Select candidate IDs only from the supplied "
        "missing_coverage_groups. Choose at least one valid candidate for every group while "
        "respecting remaining_action_slots. These groups are generic scanner classes derived "
        "from the live discovered surface; none may be silently skipped. Prefer the highest-value "
        "candidate when several exist. Return only schema-valid JSON."
    )
    base = state["ollama_url"].rstrip("/")
    context = json.dumps(prompt, ensure_ascii=False, separators=(",", ":"))
    options = {
        "temperature": 0,
        "num_predict": min(500, AI_PLANNER_MAX_PREDICT.get(
            deterministic_core.CURRENT_SCAN_MODE, 1000
        )),
        "num_ctx": 8192,
        "top_p": 0.9,
    }
    total_timeout = min(max(120, int(state.get("ai_timeout") or 480) // 3), 240)
    attempts = [
        (
            "chat",
            f"{base}/api/chat",
            {
                "model": state["model"],
                "format": COVERAGE_REPAIR_SCHEMA,
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": context},
                ],
                "options": options,
                "keep_alive": "30m",
            },
            max(75, int(total_timeout * 0.65)),
        ),
        (
            "generate",
            f"{base}/api/generate",
            {
                "model": state["model"],
                "format": COVERAGE_REPAIR_SCHEMA,
                "prompt": system_message + "\n\nRepair context:\n" + context,
                "options": options,
                "keep_alive": "30m",
            },
            max(60, int(total_timeout * 0.35)),
        ),
    ]
    errors: list[str] = []
    for kind, url, payload, timeout in attempts:
        try:
            content = _ollama_stream_content(
                url,
                payload,
                response_kind=kind,
                total_timeout=timeout,
            )
            value = json.loads(content)
            if not isinstance(value, dict):
                raise ValueError("Coverage repair was not a JSON object.")
            selected_ids = value.get("selected_candidate_ids", [])
            if not isinstance(selected_ids, list):
                raise ValueError("selected_candidate_ids was not a list.")
            selected: list[dict[str, Any]] = []
            seen: set[str] = set()
            for raw_id in selected_ids:
                candidate_id = str(raw_id)
                action = candidate_map.get(candidate_id)
                if action is None or candidate_id in seen:
                    continue
                seen.add(candidate_id)
                chosen = dict(action)
                chosen["reason"] = (
                    f"AI coverage repair selected {candidate_id}: "
                    f"{chosen.get('reason', 'applicable discovered request')}"
                )[:500]
                selected.append(chosen)
                if len(selected) >= remaining_slots:
                    break
            summary = str(value.get("reasoning_summary", ""))[:700]
            return selected, summary
        except Exception as exc:
            errors.append(f"{kind}: {type(exc).__name__}: {exc}")
    raise RuntimeError("; ".join(errors))


def _remaining_coverage_actions(state: AgentState) -> list[dict[str, Any]]:
    return validate_plan(state, discovery_candidate_actions(state))


def _has_tool_result(profile_results: dict[str, Any], tool: str) -> bool:
    return any(
        key == tool or key.startswith(f"{tool}:")
        for key, value in profile_results.items()
        if isinstance(value, dict)
    )


def _missing_tool_reason(state: AgentState, profile_name: str, tool: str) -> str:
    found = state["discovery"].get(profile_name, {})
    has_authenticated_profile = any(bool(item.get("cookies")) for item in state["profiles"] )
    profile_has_cookie = any(
        item.get("name") == profile_name and bool(item.get("cookies"))
        for item in state["profiles"]
    )
    if (
        profile_name == "anonymous" and has_authenticated_profile
        and deterministic_core.CURRENT_SCAN_MODE != "deep"
        and tool in {"session", "nikto", *PARAMETER_COVERAGE_TOOLS, *AUTHORIZATION_COVERAGE_TOOLS, *WORKFLOW_COVERAGE_TOOLS}
    ):
        return "The richer authenticated profile provides this coverage in the selected scan mode."
    if tool in BROAD_COVERAGE_TOOLS:
        return ""
    if tool == "arjun":
        return "" if select_arjun_request_cases(found, state["target"], limit=1) else "No suitable discovered GET/POST request was available for hidden-parameter discovery."
    if tool in PARAMETER_COVERAGE_TOOLS:
        return "" if select_tool_request_cases(found, tool, limit=1) else f"No discovered request matched {tool}'s vulnerability class."
    if tool == "authorization":
        if not profile_has_cookie:
            return "Authorization comparison requires a primary authenticated profile."
        return "" if select_authorization_request_cases(found, limit=1) else "No discovered read-only request contained a plausible identity, object or privileged-resource signal."
    if tool == "browser":
        return "" if select_browser_request_cases(found, limit=1) else "No discovered request or client-side page matched browser XSS verification."
    if tool == "workflow":
        return "" if select_workflow_request_cases(found, limit=1) else "No discovered POST form matched CSRF, upload, authentication or CAPTCHA workflow classes."
    if tool == "jwt":
        return "" if found.get("jwt_tokens") else "No JWT was discovered in crawled responses."
    if tool == "interactsh":
        if state.get("injection_url") or select_oast_request_cases(found, state["target"], limit=1):
            return ""
        return "No discovered OAST-capable input was available."
    return ""


def _materialize_missing_coverage(state: AgentState) -> dict[str, dict[str, Any]]:
    results = {profile: dict(values) for profile, values in state["results"].items()}
    for profile in state["profiles"]:
        name = profile["name"]
        profile_results = results.setdefault(name, {})
        for tool in REGISTRY:
            if _has_tool_result(profile_results, tool):
                continue
            reason = _missing_tool_reason(state, name, tool)
            if reason:
                profile_results[tool] = make_skipped_result(tool, state["target"], reason)
            else:
                profile_results[tool] = {
                    "tool": tool,
                    "status": "partial",
                    "target": state["target"],
                    "output": (
                        "The action was applicable but the configured agentic round/action budget "
                        "ended before it could be executed."
                    ),
                    "diagnosis": "agentic_round_budget_exhausted",
                    "timed_out": False,
                    "vulnerabilities": [],
                }
    return results


def _audit_action_summary(action: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded, secret-free action summary for the report audit."""
    return {
        "profile": str(action.get("profile") or ""),
        "tool": str(action.get("tool") or ""),
        "target_url": str(action.get("target_url") or ""),
        "method": str(action.get("method") or "GET"),
        "parameters": [str(value) for value in action.get("parameters", [])][:12],
        "reason": str(action.get("reason") or "")[:500],
    }


def _coverage_group_counts(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], int] = {}
    for action in actions:
        key = _coverage_group_key(action)
        grouped[key] = grouped.get(key, 0) + 1
    return [
        {"profile": profile, "tool": tool, "candidate_count": count}
        for (profile, tool), count in sorted(grouped.items())
    ]


def planner_node(state: AgentState) -> dict[str, Any]:
    round_number = state["round"] + 1
    notes = list(state["notes"])
    audit = list(state.get("planner_audit", []))
    eligible = _eligible_action_catalog(state)
    budget = ROUND_ACTION_BUDGETS.get(deterministic_core.CURRENT_SCAN_MODE, 20)
    planner_source = "ai"
    repair_summaries: list[str] = []
    summary = ""
    endpoint = "unavailable"
    context_bytes = 0
    ai_selected_count = 0
    fallback_reason = ""
    gaps: list[dict[str, Any]] = []

    try:
        decision = ollama_plan(state)
        proposed = decision.get("actions", [])
        ai_plan = validate_plan(state, proposed)
        ai_selected_count = len(ai_plan)
        plan = _merge_ai_actions([], ai_plan, budget=budget)
        summary = str(decision.get("reasoning_summary", ""))[:1000]

        # A weak local model may return a syntactically valid but under-covered
        # plan. Repair remains agentic: Ollama explicitly chooses discovery-
        # derived candidate IDs; the orchestrator never inserts a route merely
        # because it is eligible.
        for repair_attempt in range(1, 3):
            gaps = _coverage_gaps(state, plan, eligible)
            if not gaps or len(plan) >= budget:
                break
            try:
                additions, repair_summary = ollama_coverage_repair(
                    state, plan, gaps, attempt=repair_attempt,
                )
            except Exception as repair_exc:
                repair_summaries.append(
                    f"attempt {repair_attempt} failed: "
                    f"{type(repair_exc).__name__}: {repair_exc}"
                )
                break
            validated_additions = validate_plan(state, additions)
            before = len(plan)
            plan = _merge_ai_actions(plan, validated_additions, budget=budget)
            repair_summaries.append(
                f"attempt {repair_attempt}: added {len(plan) - before}; {repair_summary}"
            )
            if len(plan) == before:
                break

        gaps = _coverage_gaps(state, plan, eligible)
        if repair_summaries:
            planner_source = "ai-repaired"
            summary += " Coverage repair: " + " | ".join(repair_summaries)
        if gaps:
            missing = ", ".join(
                f"{gap['profile']}/{gap['tool']}" for gap in gaps[:20]
            )
            warning = (
                f"AI plan remains below the generic coverage contract for "
                f"{len(gaps)} group(s): {missing}. Remaining candidates will be "
                "presented again in the next round."
            )
            notes.append(warning)
            print(f"\n[!] {warning}", file=sys.stderr, flush=True)
            if state.get("require_ai") and not plan:
                raise RuntimeError(warning)

        if not plan and eligible:
            raise RuntimeError(
                "Ollama returned no executable action despite applicable discovered candidates."
            )
        finished = bool(decision.get("finish", False)) and not plan and not eligible
        endpoint = str(LAST_OLLAMA_PLAN_DIAGNOSTICS.get("endpoint", "unknown"))
        context_bytes = int(LAST_OLLAMA_PLAN_DIAGNOSTICS.get("context_bytes", 0) or 0)
        notes.append(
            f"Round {round_number} [{planner_source}/{endpoint}; "
            f"context={context_bytes}B]: {summary}"
        )
        print(
            f"\n[*] Ollama plan round {round_number} via {endpoint} "
            f"(context={context_bytes} bytes): {summary}",
            flush=True,
        )
    except Exception as exc:
        if state.get("require_ai"):
            raise RuntimeError(
                f"Strict agentic mode requires a successful Ollama plan and "
                f"coverage repair: {type(exc).__name__}: {exc}"
            ) from exc

        ordered_fallback = sorted(
            eligible,
            key=lambda action: (
                _coverage_phase(action["tool"]),
                deterministic_core.tool_execution_rank(
                    action["tool"],
                    any(
                        profile.get("name") == action["profile"]
                        and bool(profile.get("cookies"))
                        for profile in state["profiles"]
                    ),
                ),
            ),
        )
        plan = ordered_fallback[:budget]
        finished = not plan
        fallback_reason = f"{type(exc).__name__}: {exc}"
        message = (
            "AI planning/repair failed after streamed retries; the explicitly "
            "labelled discovery-driven fallback was used: " + fallback_reason
        )
        notes.append(message)
        planner_source = "fallback"
        summary = message[:1000]
        gaps = _coverage_gaps(state, plan, eligible)
        print(f"\n[!] {message}", file=sys.stderr, flush=True)

    if not plan and not eligible:
        finished = True
    elif not plan:
        finished = False

    audit.append({
        "round": round_number,
        "planner_source": planner_source,
        "planner_endpoint": endpoint,
        "context_bytes": context_bytes,
        "eligible_action_count": len(eligible),
        "eligible_groups": _coverage_group_counts(eligible),
        "round_action_budget": budget,
        "ai_selected_action_count": ai_selected_count,
        "repair_attempts": repair_summaries,
        "fallback_reason": fallback_reason,
        "selected_action_count": len(plan),
        "selected_actions": [_audit_action_summary(action) for action in plan],
        "remaining_coverage_gaps": [
            {
                "profile": str(gap.get("profile") or ""),
                "tool": str(gap.get("tool") or ""),
                "candidate_count": int(gap.get("candidate_count", 0) or 0),
            }
            for gap in gaps
        ],
        "reasoning_summary": summary[:1500],
    })

    print(f"[*] Validated actions: {len(plan)}", flush=True)
    for action in plan:
        print(
            f"    {action['profile']:13} {action['tool']:10} "
            f"{action['target_url']} — {action['reason']}",
            flush=True,
        )
    return {
        "plan": plan,
        "round": round_number,
        "notes": notes,
        "finished": finished,
        "planner_source": planner_source,
        "planner_audit": audit,
    }


async def execute_action(
    action: dict[str, Any],
    cookies: dict[str, str],
    discovery: dict[str, dict[str, Any]],
    allow_state_changes: bool = False,
    secondary_cookies: str = "",
) -> tuple[dict[str, Any], dict[str, Any]]:
    server, function = REGISTRY[action["tool"]][:2]
    if action["tool"] == "jwt":
        arguments = {"jwt_token": action["jwt_token"], "target_url": action["target_url"]}
    elif action["tool"] == "interactsh":
        arguments = {
            "target_url": action["target_url"],
            "injection_url": action["injection_url"],
            "cookies": cookies.get(action["profile"], ""),
            "method": action.get("method", "GET"),
            "data": action.get("data", ""),
            "parameter": (action.get("parameters") or [""])[0],
            "timeout": (
                120 if deterministic_core.CURRENT_SCAN_MODE == "deep"
                else 75 if deterministic_core.CURRENT_SCAN_MODE == "balanced"
                else 60
            ),
        }
    else:
        arguments = {"target_url": action["target_url"], "cookies": cookies.get(action["profile"], "")}
        profile_discovery = discovery.get(action["profile"], {})
        local_authorized_state_changes = deterministic_core.state_changing_tests_allowed(
            action["target_url"], allow_state_changes
        )
        if action["tool"] in BROAD_SCANNER_TIMEOUTS:
            arguments["timeout"] = BROAD_SCANNER_TIMEOUTS[action["tool"]]
            if action["tool"] == "exposure":
                arguments.update({
                    "discovered_urls": profile_discovery.get("urls", []),
                    "max_urls": (
                        80 if deterministic_core.CURRENT_SCAN_MODE == "deep"
                        else 45 if deterministic_core.CURRENT_SCAN_MODE == "balanced"
                        else 20
                    ),
                })
            elif action["tool"] == "zap":
                authenticated = bool(cookies.get(action["profile"], ""))
                arguments.update({
                    "seed_urls": profile_discovery.get("html_urls", []),
                    "request_cases": profile_discovery.get("request_cases", []),
                    # Active checks are bounded to authenticated, high-value
                    # discovered GET/POST contracts. Anonymous runs remain passive.
                    "scan_mode": (
                        "full" if authenticated and deterministic_core.CURRENT_SCAN_MODE == "deep"
                        else "prioritized" if authenticated and deterministic_core.CURRENT_SCAN_MODE == "balanced"
                        else "passive"
                    ),
                    "max_observations": (
                        100 if deterministic_core.CURRENT_SCAN_MODE == "deep"
                        else 50 if deterministic_core.CURRENT_SCAN_MODE == "balanced"
                        else 25
                    ),
                })
            elif action["tool"] == "nuclei":
                arguments["seed_urls"] = profile_discovery.get("urls", [])
                arguments["request_cases"] = profile_discovery.get("request_cases", [])
                arguments["scan_profile"] = deterministic_core.CURRENT_SCAN_MODE
                arguments["max_targets"] = (
                    16 if deterministic_core.CURRENT_SCAN_MODE == "deep"
                    else 10 if deterministic_core.CURRENT_SCAN_MODE == "balanced"
                    else 6
                )
            elif action["tool"] == "session":
                probe_root = deterministic_core.select_session_probe_url(
                    profile_discovery, action["target_url"]
                )
                arguments.update({
                    "probe_url": probe_root,
                    "sample_count": (
                        7 if deterministic_core.CURRENT_SCAN_MODE == "deep"
                        else 5 if deterministic_core.CURRENT_SCAN_MODE == "balanced"
                        else 3
                    ),
                })
        elif action["tool"] == "arjun":
            arguments.update({
                "timeout": deterministic_core.ARJUN_TIMEOUT,
                "method": action.get("method", "GET"),
                "data": action.get("data", ""),
                "known_parameters": action.get("parameters", []),
            })
        elif action["tool"] in PARAMETER_TOOL_TIMEOUTS:
            arguments["timeout"] = PARAMETER_TOOL_TIMEOUTS[action["tool"]]
        if action["tool"] in {"sqlmap", "dalfox", "commix", "traversal"}:
            arguments.update({
                "method": action.get("method", "GET"),
                "data": action.get("data", ""),
                "parameters": action.get("parameters", []),
            })
            if action["tool"] == "dalfox":
                arguments["allow_state_changes"] = local_authorized_state_changes
        elif action["tool"] == "authorization":
            arguments.update({
                "secondary_cookies": secondary_cookies,
                "method": "GET",
                "data": "",
                "parameters": action.get("parameters", []),
            })
        elif action["tool"] == "browser":
            arguments.update({
                "method": action.get("method", "GET"),
                "data": action.get("data", ""),
                "parameters": action.get("parameters", []),
                "fields": action.get("fields", []),
                "source_url": action.get("source_url", ""),
                "client_sources": action.get("client_sources", []),
                "client_sinks": action.get("client_sinks", []),
                "allow_state_changes": local_authorized_state_changes,
            })
        elif action["tool"] == "workflow":
            arguments.update({
                "method": action.get("method", "POST"),
                "data": action.get("data", ""),
                "parameters": action.get("parameters", []),
                "fields": action.get("fields", []),
                "file_parameters": action.get("file_parameters", []),
                "token_parameters": action.get("token_parameters", []),
                "source_url": action.get("source_url", ""),
                "enctype": action.get("enctype", ""),
                "allow_state_changes": local_authorized_state_changes,
            })

    state_refresh: dict[str, Any] | None = None
    if (
        cookies.get(action["profile"], "")
        and action["tool"] in {"sqlmap", "dalfox", "commix", "traversal", "idor", "authorization", "interactsh", "arjun", "browser", "workflow"}
    ):
        parsed_target = urlparse(action["target_url"])
        refresh_target = f"{parsed_target.scheme}://{parsed_target.netloc}"
        profile_discovery = discovery.get(action["profile"], {})
        probe_url = deterministic_core.select_session_probe_url(
            profile_discovery, refresh_target
        )
        print(
            f"    [PRECHECK] {action['tool']}: validating authenticated session "
            f"with {probe_url}",
            flush=True,
        )
        state_refresh = deterministic_core.refresh_authenticated_session_state(
            refresh_target, cookies[action["profile"]], probe_url
        )
        if state_refresh.get("usable") is False:
            print(
                f"    [PARTIAL ] {action['tool']}: authenticated session precheck failed",
                flush=True,
            )
            return action, {
                "tool": action["tool"],
                "status": "partial",
                "target": action["target_url"],
                "output": "The authenticated session could not be re-established before the scanner.",
                "vulnerabilities": [],
                "diagnosis": "authentication_precheck_failed",
                "state_refresh": state_refresh,
            }
        print(
            f"    [SESSION ] {action['tool']}: authenticated session usable",
            flush=True,
        )
    try:
        scanner_limit = float(arguments.get("timeout", 180))
        spec = next(
            (item for item in deterministic_core.ALL_TOOLS if item.name == action["tool"]),
            None,
        )
        if spec is not None:
            result = await call_mcp_with_progress(
                spec,
                arguments,
                timeout_seconds=scanner_limit + 35,
            )
        else:
            # Defensive fallback for a future registry entry that is not yet
            # represented by a deterministic ToolSpec.
            print(
                f"    [RUNNING ] {action['tool']}: {action['target_url']} "
                f"(scanner limit {scanner_limit:g}s)",
                flush=True,
            )
            result = await call_mcp(
                server,
                function,
                arguments,
                timeout_seconds=scanner_limit + 35,
            )
        if state_refresh is not None:
            result["state_refresh"] = state_refresh
        return action, result
    except Exception as exc:
        message = f"Agent executor failed: {type(exc).__name__}: {exc}"
        result = {"tool": action["tool"], "status": "error", "target": action["target_url"], "output": message, "vulnerabilities": [], "diagnosis": diagnose_error(message), "traceback": traceback.format_exc()}
        if state_refresh is not None:
            result["state_refresh"] = state_refresh
        return action, result


async def execute_plan(
    plan: list[dict[str, Any]],
    cookies: dict[str, str],
    discovery: dict[str, dict[str, Any]],
    allow_state_changes: bool = False,
    secondary_cookies: str = "",
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Execute the AI-selected actions with live per-action CLI progress."""
    profile_order = {name: index for index, name in enumerate(cookies)}
    ordered = sorted(
        plan,
        key=lambda action: (
            profile_order.get(action["profile"], 999),
            deterministic_core.tool_execution_rank(
                action["tool"], bool(cookies.get(action["profile"], ""))
            ),
        ),
    )
    total = len(ordered)
    print(
        f"\n[*] Executing {total} validated action(s) sequentially. "
        f"Progress heartbeat: every {deterministic_core.SCANNER_PROGRESS_INTERVAL}s.",
        flush=True,
    )
    executed: list[tuple[dict[str, Any], dict[str, Any]]] = []
    arjun_empty_limits: dict[str, int] = {}
    arjun_threshold = 2 if deterministic_core.CURRENT_SCAN_MODE == "deep" else 1
    for index, action in enumerate(ordered, start=1):
        started = time.monotonic()
        print(
            f"\n[*] Action {index}/{total}: {action['profile']} / "
            f"{action['tool']} / {action['target_url']}",
            flush=True,
        )
        try:
            if (
                action["tool"] == "arjun"
                and arjun_empty_limits.get(action["profile"], 0) >= arjun_threshold
            ):
                item = (
                    action,
                    {
                        "tool": "arjun",
                        "status": "skipped",
                        "target": action["target_url"],
                        "output": (
                            "Adaptive budget reallocation: earlier high-priority Arjun actions "
                            "reached their full budget without discovering a parameter; this "
                            "lower-priority repeat was skipped."
                        ),
                        "diagnosis": "adaptive_budget_reallocated",
                        "vulnerabilities": [],
                    },
                )
            else:
                item = await execute_action(
                    action, cookies, discovery,
                    allow_state_changes=allow_state_changes,
                    secondary_cookies=secondary_cookies,
                )
        except Exception as exc:
            message = f"Agent executor isolated failure: {type(exc).__name__}: {exc}"
            item = (
                action,
                {
                    "tool": action["tool"],
                    "status": "error",
                    "target": action["target_url"],
                    "output": message,
                    "vulnerabilities": [],
                    "diagnosis": diagnose_error(message),
                    "traceback": traceback.format_exc(),
                },
            )
        executed.append(item)
        _, result = item
        if action["tool"] == "arjun":
            found_parameters = int(result.get("phase_parameters", 0) or 0)
            if (
                str(result.get("diagnosis", "")) in deterministic_core.TIME_LIMIT_DIAGNOSES
                and not result.get("vulnerabilities")
                and found_parameters == 0
            ):
                arjun_empty_limits[action["profile"]] = arjun_empty_limits.get(action["profile"], 0) + 1
            elif result.get("diagnosis") != "adaptive_budget_reallocated":
                arjun_empty_limits[action["profile"]] = 0
        elapsed = time.monotonic() - started
        vulnerabilities = result.get("vulnerabilities", [])
        finding_count = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
        status = str(result.get("status", "unknown")).upper()
        diagnosis = str(result.get("diagnosis", "") or "")
        diagnosis_text = f"; diagnosis={diagnosis}" if diagnosis else ""
        print(
            f"    [FINISHED] {action['tool']}: status={status}; "
            f"findings={finding_count}; elapsed={elapsed:.1f}s{diagnosis_text}",
            flush=True,
        )
    print(f"\n[*] Round action execution finished: {total}/{total} action(s).", flush=True)
    return executed


def _record_execution_batch(
    executed: list[tuple[dict[str, Any], dict[str, Any]]],
    *,
    state: AgentState,
    results: dict[str, dict[str, Any]],
    discovery: dict[str, dict[str, Any]],
    completed: list[str],
    profile_cookies: dict[str, str],
) -> int:
    """Persist one execution stage and immediately merge new attack surface."""
    new_attack_surface = 0
    for action, result in executed:
        profile, tool = action["profile"], action["tool"]
        profile_results = results.setdefault(profile, {})
        number = 1 + sum(key.startswith(f"{tool}:") for key in profile_results)
        profile_results[f"{tool}:{number}"] = {
            **result,
            "planner_reason": action["reason"],
            "planner_round": state["round"],
        }
        completed.append(action_id(action))
        log_result(profile, tool, result, action["target_url"])
        if tool == "zap":
            log_zap_session_diagnostics(result)
        if tool == "ffuf" and result.get("status") in {"success", "partial"}:
            before = len(discovery.get(profile, {}).get("request_cases", []))
            enriched, urls = enrich_discovery_with_ffuf(
                discovery.get(profile, {}), result, state["target"]
            )
            if urls:
                recrawl = discover_target(
                    state["target"], profile_cookies.get(profile, ""), seeds=urls
                )
                enriched = merge_discovery(enriched, recrawl)
                print(
                    f"    [DISCOVERY] {profile}: FFUF re-crawl expanded the surface to "
                    f"{len(enriched.get('html_urls', []))} HTML pages and "
                    f"{len(enriched.get('request_cases', []))} request cases.",
                    flush=True,
                )
            discovery[profile] = enriched
            new_attack_surface += max(
                0, len(enriched.get("request_cases", [])) - before
            )
        if tool == "arjun" and result.get("status") in {"success", "partial"}:
            discovery[profile], generated = enrich_discovery_with_arjun(
                discovery.get(profile, {}), result, action["target_url"]
            )
            new_attack_surface += len(generated)
    return new_attack_surface


def executor_node(state: AgentState) -> dict[str, Any]:
    if not state["plan"]:
        return {}
    cookies = {profile["name"]: profile["cookies"] for profile in state["profiles"]}
    results = {profile: dict(values) for profile, values in state["results"].items()}
    discovery = {profile: dict(values) for profile, values in state["discovery"].items()}
    completed = list(state["completed"])
    profile_cookies = {profile["name"]: profile["cookies"] for profile in state["profiles"]}
    new_attack_surface = 0

    # Discovery must be consumed before active scanners. The previous agentic
    # executor ran FFUF and ZAP in the same batch, then merged FFUF only after
    # ZAP had already finished. This stage boundary makes ZAP and Nuclei receive
    # the newly discovered URLs/forms in the same round.
    discovery_stage = [action for action in state["plan"] if action["tool"] == "ffuf"]
    remaining_stage = [action for action in state["plan"] if action["tool"] != "ffuf"]

    if discovery_stage:
        print("\n[*] Discovery enrichment stage: FFUF runs before ZAP/Nuclei.", flush=True)
        ffuf_executed = asyncio.run(execute_plan(
            discovery_stage, cookies, discovery,
            allow_state_changes=state.get("allow_state_changes", False),
            secondary_cookies=state.get("secondary_cookies", ""),
        ))
        new_attack_surface += _record_execution_batch(
            ffuf_executed,
            state=state,
            results=results,
            discovery=discovery,
            completed=completed,
            profile_cookies=profile_cookies,
        )

        # ZAP and Nuclei already present in the AI plan consume the enriched
        # discovery object below. Newly applicable parameter actions are not
        # inserted automatically: they are returned to Ollama as candidates in
        # the next planning round, preserving genuinely agent-selected scope.
        print(
            "[*] FFUF enrichment is available to planned ZAP/Nuclei actions; "
            "new parameter candidates will be offered to Ollama next round.",
            flush=True,
        )

    if remaining_stage:
        executed = asyncio.run(execute_plan(
            remaining_stage, cookies, discovery,
            allow_state_changes=state.get("allow_state_changes", False),
            secondary_cookies=state.get("secondary_cookies", ""),
        ))
        new_attack_surface += _record_execution_batch(
            executed,
            state=state,
            results=results,
            discovery=discovery,
            completed=completed,
            profile_cookies=profile_cookies,
        )

    next_state = dict(state)
    next_state.update(results=results, discovery=discovery, completed=completed)
    remaining = _remaining_coverage_actions(next_state)
    can_continue = state["round"] < state["max_rounds"] and bool(
        new_attack_surface > 0 or remaining
    )
    notes = list(state["notes"])
    notes.append(
        f"Round {state['round']} execution: new request contracts={new_attack_surface}; "
        f"remaining eligible actions={len(remaining)}."
    )
    audit = [dict(item) for item in state.get("planner_audit", [])]
    if audit and int(audit[-1].get("round", 0) or 0) == state["round"]:
        outcome_rows: list[dict[str, Any]] = []
        for profile, profile_results in results.items():
            for key, result in profile_results.items():
                if not isinstance(result, dict) or int(result.get("planner_round", 0) or 0) != state["round"]:
                    continue
                outcome_rows.append({
                    "profile": profile,
                    "result_key": key,
                    "tool": str(result.get("tool") or key.split(":", 1)[0]),
                    "status": str(result.get("status") or "unknown"),
                    "diagnosis": str(result.get("diagnosis") or ""),
                    "findings": len(result.get("vulnerabilities") or []),
                    "duration_seconds": result.get("duration_seconds") or (result.get("_meta") or {}).get("duration_seconds"),
                })
        audit[-1]["execution_outcomes"] = outcome_rows
        audit[-1]["new_request_contracts"] = new_attack_surface
        audit[-1]["remaining_eligible_actions_after_execution"] = len(remaining)
    return {
        "results": results,
        "discovery": discovery,
        "completed": completed,
        "notes": notes,
        "planner_audit": audit,
        "finished": not can_continue,
    }

def route_after_execution(state: AgentState) -> Literal["planner", "report"]:
    return "report" if state["finished"] or state["round"] >= state["max_rounds"] or not state["plan"] else "planner"


def report_node(state: AgentState) -> dict[str, Any]:
    print("\n[*] Creating final PDF, HTML preview and JSON report...")
    output_name = f"SecOps_Agentic_Assessment_{datetime.now():%Y%m%d_%H%M%S}"
    report_results = _materialize_missing_coverage(state)
    remaining = _remaining_coverage_actions({**state, "results": report_results})
    context = {
        "profiles": [{"name": profile["name"], "authenticated": bool(profile["cookies"])} for profile in state["profiles"]],
        "expected_tools": list(REGISTRY),
        "discovery": state["discovery"],
        "diagnostics": state["diagnostics"],
        "planner_notes": state["notes"],
        "planner_rounds": state["round"],
        "ollama_model": state["model"],
        "ollama_url": state["ollama_url"],
        "strict_ai_required": state.get("require_ai", False),
        "planner_source": state.get("planner_source", "unknown"),
        "planner_audit": state.get("planner_audit", []),
        "scan_mode": deterministic_core.CURRENT_SCAN_MODE,
        "runtime_platform": platform.platform(),
        "python_executable": sys.executable,
        "mcp_server_python": deterministic_core._server_python(),
        "remaining_eligible_actions_at_report": len(remaining),
        "execution_policy": "AI-selected actions are validated against the shared deterministic tool catalogue and discovered same-profile request contracts. A target-independent minimum-coverage contract is repaired by asking Ollama to choose explicit discovery-derived candidate IDs; successful AI plans are never silently supplemented with hard-coded endpoints. FFUF is credential-isolated, runs before exposure/ZAP/Nuclei, and newly discovered parameter, authorization, browser and workflow candidates are returned to the AI in later rounds. Bounded state-changing workflow probes run automatically on local labs and require explicit --allow-state-changes for remote authorized targets.",
        "allow_state_changes": state.get("allow_state_changes", False),
        "secondary_identity_supplied": bool(state.get("secondary_cookies", "")),
    }
    report = asyncio.run(call_mcp("pwndocServer.py", "generate_report", {
        "findings_summary": report_results, "target_url": state["target"],
        "output_name": output_name, "assessment_context": context,
    }))
    if report.get("status") != "success" and not report.get("json_filename"):
        fallback = write_emergency_json_report(state["target"], state["results"], state["diagnostics"], str(report.get("output", "Report MCP failed.")), "SecOps_Agentic_Emergency")
        if fallback:
            report.update(json_filename=fallback, html_filename=str(Path(fallback).with_suffix(".html")), local_json_fallback=True)
    return {"report_status": report, "results": report_results}


def build_graph() -> Any:
    graph = StateGraph(AgentState)
    for name, node in (("discovery", discovery_node), ("planner", planner_node), ("executor", executor_node), ("report", report_node)):
        graph.add_node(name, node)
    graph.add_edge(START, "discovery")
    graph.add_edge("discovery", "planner")
    graph.add_edge("planner", "executor")
    graph.add_conditional_edges("executor", route_after_execution, {"planner": "planner", "report": "report"})
    graph.add_edge("report", END)
    return graph.compile()


def summarize(results: dict[str, Any]) -> tuple[int, int, int]:
    errors = skips = partial = 0
    for path, result in iter_leaf_results(results):
        status = str(result.get("status", "error"))
        errors += status == "error"
        skips += status == "skipped"
        partial += status == "partial"
        if status == "error":
            print(f"[-] {'/'.join(path)}: {result.get('diagnosis', 'unknown')} — {str(result.get('output', ''))[:500]}", file=sys.stderr)
    return errors, skips, partial


def main() -> int:
    parser = argparse.ArgumentParser(description="Ollama + LangGraph FastMCP security orchestrator.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--cookies", default="")
    parser.add_argument(
        "--secondary-cookies", default="",
        help="Optional second authenticated identity for read-only authorization/BOLA comparison.",
    )
    parser.add_argument("--auth-only", action="store_true")
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument(
        "--allow-state-changes", action="store_true",
        help="Enable bounded POST/upload/stored-XSS workflow probes on an explicitly authorized remote target; local labs enable them automatically.",
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--ignore-preflight-errors", action="store_true")
    parser.add_argument("--interactsh-injection-url", default="")
    parser.add_argument("--model", default="llama3.1:8b")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument(
        "--no-model-pull", action="store_true",
        help="Do not automatically pull a missing requested Ollama model."
    )
    parser.add_argument(
        "--require-ai", action="store_true",
        help="Fail instead of using deterministic fallback when Ollama planning fails."
    )
    parser.add_argument("--max-rounds", type=int, default=1, choices=(1, 2, 3))
    parser.add_argument(
        "--ai-timeout", type=int, default=0,
        help="Total planning budget per AI round; 0 selects a mode-specific default."
    )
    parser.add_argument("--mode", choices=("fast", "balanced", "deep"), default="balanced")
    args = parser.parse_args()
    configure_scan_mode(args.mode)
    print(f"[*] Runtime platform: {platform.platform()}")
    print(f"[*] MCP server Python: {deterministic_core._server_python()}")
    globals()["CURRENT_SCAN_MODE"] = deterministic_core.CURRENT_SCAN_MODE
    globals()["ARJUN_TIMEOUT"] = deterministic_core.ARJUN_TIMEOUT

    checks = run_preflight_checks(include_live=True)
    errors = print_preflight_report(checks, show_ok=args.preflight_only)
    if args.preflight_only:
        return 0 if not errors else 3
    if errors and not args.ignore_preflight_errors:
        return 3

    target = normalize_url(args.target)
    if urlparse(target).hostname not in {"127.0.0.1", "localhost", "::1"} and not args.authorized:
        parser.error("Remote targets require --authorized.")
    if args.allow_state_changes and urlparse(target).hostname not in {"127.0.0.1", "localhost", "::1"} and not args.authorized:
        parser.error("--allow-state-changes on a remote target requires --authorized.")
    injection = args.interactsh_injection_url.strip()
    if injection and not same_origin(target, injection):
        parser.error("--interactsh-injection-url must have the same origin as --target.")
    profiles = [] if args.auth_only else [{"name": "anonymous", "cookies": ""}]
    if args.cookies:
        try:
            normalized_cookie = canonical_cookie_header(args.cookies)
        except ValueError as exc:
            parser.error(f"Invalid --cookies value: {exc}")
        print(
            "[*] Authenticated cookie names: "
            + ", ".join(cookie_names(normalized_cookie))
        )
        profiles.append({"name": "authenticated", "cookies": normalized_cookie})
    elif args.auth_only:
        parser.error("--auth-only requires --cookies.")

    secondary_cookie = ""
    if args.secondary_cookies:
        if not args.cookies:
            parser.error("--secondary-cookies requires a primary --cookies value.")
        try:
            secondary_cookie = canonical_cookie_header(args.secondary_cookies)
        except ValueError as exc:
            parser.error(f"Invalid --secondary-cookies value: {exc}")
        if secondary_cookie == normalized_cookie:
            parser.error("--secondary-cookies must represent a different authenticated identity.")
        print(
            "[*] Secondary identity cookie names: "
            + ", ".join(cookie_names(secondary_cookie))
        )

    try:
        selected_model, ollama_diagnostics = ensure_ollama_model(
            args.ollama_url,
            args.model,
            allow_pull=not args.no_model_pull,
        )
        print(
            f"[*] Ollama ready: version={ollama_diagnostics.get('ollama_version', 'unknown')}; "
            f"model={selected_model}; requested={args.model}"
        )
        if ollama_diagnostics.get("fallback_model_used"):
            print(
                "[!] Requested model was unavailable; using installed fallback "
                f"{selected_model}: {ollama_diagnostics.get('fallback_reason', '')}",
                file=sys.stderr,
            )
        planner_timeout = args.ai_timeout or AI_PLANNER_TIMEOUTS[args.mode]
        try:
            warmup = warm_ollama_model(
                args.ollama_url,
                selected_model,
                timeout=planner_timeout,
            )
            ollama_diagnostics["warmup"] = warmup
            print(
                f"[*] Ollama model warm: {warmup.get('seconds')}s; "
                f"planner budget={planner_timeout}s per round"
            )
        except Exception as warm_exc:
            ollama_diagnostics["warmup_error"] = (
                f"{type(warm_exc).__name__}: {warm_exc}"
            )
            print(
                "[!] Ollama warm-up was inconclusive; the streamed planner will "
                f"still retry both endpoints: {ollama_diagnostics['warmup_error']}",
                file=sys.stderr,
            )
    except Exception as exc:
        if args.require_ai:
            print(
                f"[-] Strict agentic mode could not prepare Ollama: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return 4
        selected_model = args.model
        ollama_diagnostics = {
            "model_ready": False,
            "requested_model": args.model,
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(
            "[!] Ollama readiness check failed; deterministic fallback remains "
            f"available: {ollama_diagnostics['error']}",
            file=sys.stderr,
        )
        planner_timeout = args.ai_timeout or AI_PLANNER_TIMEOUTS[args.mode]

    initial: AgentState = {
        "target": target, "profiles": profiles, "discovery": {}, "plan": [], "completed": [],
        "results": {profile["name"]: {} for profile in profiles}, "round": 0,
        "max_rounds": args.max_rounds, "ollama_url": args.ollama_url, "model": selected_model,
        "injection_url": injection,
        "notes": [
            "Ollama readiness: "
            + json.dumps(ollama_diagnostics, ensure_ascii=False, default=str)
        ],
        "finished": False, "diagnostics": [], "report_status": {},
        "require_ai": args.require_ai,
        "planner_source": "pending",
        "ai_timeout": planner_timeout,
        "allow_state_changes": args.allow_state_changes,
        "secondary_cookies": secondary_cookie,
        "planner_audit": [],
    }
    started = time.time()
    try:
        final = build_graph().invoke(initial)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"[-] Agentic workflow failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    report = final.get("report_status", {})
    errors, skips, partial = summarize(final.get("results", {}))
    print(f"\n=== Agentic pipeline completed in {time.time() - started:.2f} seconds ===")
    print(f"[+] PDF: {report.get('pdf_filename') or 'not generated'}")
    print(f"[+] HTML preview: {report.get('html_filename') or 'not generated'}")
    print(f"[+] JSON: {report.get('json_filename') or 'not generated'}")
    print_security_finding_summary(final.get("results", {}))
    print(f"[+] Scanner run errors: {errors}\n[+] Time-limited/partial scanner runs: {partial}\n[+] Scanner run skips: {skips}")
    return 1 if report.get("status") != "success" else 0


if __name__ == "__main__":
    raise SystemExit(main())