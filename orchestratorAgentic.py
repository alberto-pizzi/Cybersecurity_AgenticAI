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


REGISTRY = deterministic_core.agentic_registry()

AI_PLANNER_TIMEOUTS = {"fast": 300, "balanced": 480, "deep": 720}
AI_PLANNER_MAX_PREDICT = {"fast": 700, "balanced": 1000, "deep": 1400}
LAST_OLLAMA_PLAN_DIAGNOSTICS: dict[str, Any] = {}

BROAD_COVERAGE_TOOLS = ("ffuf", "zap", "nuclei", "nikto")
DISCOVERY_COVERAGE_TOOLS = ("arjun",)
PARAMETER_COVERAGE_TOOLS = ("sqlmap", "dalfox", "commix", "traversal", "idor")
OPTIONAL_COVERAGE_TOOLS = ("jwt", "interactsh")
ROUND_ACTION_BUDGETS = {"fast": 8, "balanced": 12, "deep": 16}

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
                "priority_score": int(case.get("priority_score", 0) or 0),
            })
        compact[profile] = {
            "authenticated": found.get("authentication_effective"),
            "html_url_count": len(found.get("html_urls", [])),
            "request_case_count": len(found.get("request_cases", [])),
            "high_value_html_urls": [str(value) for value in found.get("html_urls", [])[:45]],
            "request_cases": request_cases,
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
    eligible = validate_plan(state, adaptive_fallback_plan(state))
    remaining_by_profile: dict[str, list[dict[str, Any]]] = {}
    for action in eligible:
        remaining_by_profile.setdefault(action["profile"], []).append({
            "tool": action["tool"],
            "target_url": action["target_url"],
            "method": action.get("method", "GET"),
            "parameters": action.get("parameters", []),
        })
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
        "configured_oast_url": state["injection_url"],
    }
    system_message = (
        "Plan an explicitly authorized web-security assessment. Use only the supplied registry and "
        "discovered request contracts. Broad scanners are complementary: FFUF discovers resources, "
        "ZAP imports traffic and performs passive/active analysis, Nuclei checks templates and DAST, "
        "and Nikto checks server exposure; do not replace one with another. In the first round include "
        "all missing eligible broad scanners and Arjun discovery actions before expensive parameter "
        "checks. In later rounds cover remaining eligible SQLMap, Dalfox, Commix, traversal, IDOR, JWT, "
        "and Interactsh actions. Use parameter tools only on an exactly matching discovered request, "
        "IDOR only on numeric object references, and Interactsh only on compatible inputs. Avoid "
        "duplicates and do not repeat completed actions. Do not set finish=true while "
        "remaining_eligible_actions is non-empty. Return up to round_action_budget actions and only "
        "schema-valid JSON with a concise reasoning_summary."
    )
    base = state["ollama_url"].rstrip("/")
    total_timeout = max(120, int(state.get("ai_timeout") or 480))
    max_predict = AI_PLANNER_MAX_PREDICT.get(
        deterministic_core.CURRENT_SCAN_MODE, 1000
    )
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


def adaptive_fallback_plan(state: AgentState) -> list[dict[str, Any]]:
    """Build a discovery-driven fallback only when AI planning is unavailable."""
    actions: list[dict[str, Any]] = []
    has_auth = any(bool(profile.get("cookies")) for profile in state["profiles"])
    for profile in state["profiles"]:
        name = profile["name"]
        authenticated = bool(profile.get("cookies"))
        broad = ["ffuf", "zap", "nuclei", "nikto"] if not authenticated else ["zap", "ffuf", "nuclei", "nikto"]
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
    for raw in proposed[:30]:
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
                and tool in {"nikto", "sqlmap", "dalfox", "commix", "traversal", "idor"}
            ):
                continue
        found = state["discovery"].get(profile, {})
        target_url = str(raw.get("target_url", "")).strip()
        token = str(raw.get("jwt_token", "")).strip()
        injection = str(raw.get("injection_url", "")).strip()
        method = str(raw.get("method", "")).upper().strip()
        data = ""
        parameters: list[str] = []
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
            method = str(selected.get("method", "GET")).upper()
            data = str(selected.get("data", ""))
            parameters = [str(value) for value in selected.get("parameters", [])]
            if scope == "numeric" and (
                method != "GET" or
                not any(value.isdigit() for _, value in parse_qsl(urlparse(target_url).query, keep_blank_values=True))
            ):
                continue
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
            "jwt_token": token, "injection_url": injection,
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
    if tool in OPTIONAL_COVERAGE_TOOLS:
        return 3
    return 9


def _augment_plan_for_coverage(
    state: AgentState,
    ai_plan: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Keep AI choice, while guaranteeing generic scanner-class coverage.

    This is target-independent: applicability comes exclusively from the shared
    deterministic selectors and the actually discovered request contracts.
    """
    eligible = validate_plan(state, adaptive_fallback_plan(state))
    round_number = state["round"] + 1
    budget = ROUND_ACTION_BUDGETS.get(deterministic_core.CURRENT_SCAN_MODE, 12)

    if round_number == 1:
        coverage_first = [
            action for action in eligible
            if action["tool"] in BROAD_COVERAGE_TOOLS + DISCOVERY_COVERAGE_TOOLS
        ]
        ordered = [*coverage_first, *ai_plan, *eligible]
    else:
        ordered = [*ai_plan, *eligible]

    ordered.sort(key=lambda action: (
        0 if round_number > 1 and action_id(action) in {action_id(item) for item in ai_plan} else 1,
        _coverage_phase(action["tool"]),
        deterministic_core.tool_execution_rank(
            action["tool"],
            any(
                profile.get("name") == action["profile"] and bool(profile.get("cookies"))
                for profile in state["profiles"]
            ),
        ),
    ))

    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for action in ordered:
        identifier = action_id(action)
        if identifier in seen:
            continue
        seen.add(identifier)
        merged.append(action)
        if len(merged) >= budget:
            break
    augmented = [action for action in merged if action_id(action) not in {action_id(item) for item in ai_plan}]
    return merged, augmented


def _remaining_coverage_actions(state: AgentState) -> list[dict[str, Any]]:
    return validate_plan(state, adaptive_fallback_plan(state))


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
        and tool in {"nikto", *PARAMETER_COVERAGE_TOOLS}
    ):
        return "The richer authenticated profile provides this coverage in the selected scan mode."
    if tool in BROAD_COVERAGE_TOOLS:
        return ""
    if tool == "arjun":
        return "" if select_arjun_request_cases(found, state["target"], limit=1) else "No suitable discovered GET/POST request was available for hidden-parameter discovery."
    if tool in PARAMETER_COVERAGE_TOOLS:
        return "" if select_tool_request_cases(found, tool, limit=1) else f"No discovered request matched {tool}'s vulnerability class."
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


def planner_node(state: AgentState) -> dict[str, Any]:
    round_number = state["round"] + 1
    notes = list(state["notes"])
    try:
        decision = ollama_plan(state)
        proposed = decision.get("actions", [])
        ai_plan = validate_plan(state, proposed)
        plan, augmented = _augment_plan_for_coverage(state, ai_plan)
        summary = str(decision.get("reasoning_summary", ""))[:1000]
        if augmented:
            summary += (
                f" Coverage guardrail added {len(augmented)} applicable action(s) "
                "that the model omitted."
            )
        finished = bool(decision.get("finish", False)) and not plan
        endpoint = str(LAST_OLLAMA_PLAN_DIAGNOSTICS.get("endpoint", "unknown"))
        context_bytes = int(LAST_OLLAMA_PLAN_DIAGNOSTICS.get("context_bytes", 0) or 0)
        notes.append(
            f"Round {round_number} [ai/{endpoint}; context={context_bytes}B]: {summary}"
        )
        planner_source = "ai"
        print(
            f"\n[*] Ollama plan round {round_number} via {endpoint} "
            f"(context={context_bytes} bytes): {summary}"
        )
    except Exception as exc:
        if state.get("require_ai"):
            raise RuntimeError(
                f"Strict agentic mode requires a successful Ollama plan: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        fallback_plan = validate_plan(state, adaptive_fallback_plan(state))
        plan, _ = _augment_plan_for_coverage(state, fallback_plan)
        finished = False
        message = f"AI planning failed after streamed chat/generate retries; discovery-driven fallback used: {type(exc).__name__}: {exc}"
        notes.append(message)
        planner_source = "fallback"
        print(f"\n[!] {message}", file=sys.stderr)
    if not plan and round_number == 1:
        fallback_plan = validate_plan(state, adaptive_fallback_plan(state))
        plan, _ = _augment_plan_for_coverage(state, fallback_plan)
        planner_source = "fallback"
    if not plan:
        finished = True
    print(f"[*] Validated actions: {len(plan)}", flush=True)
    for action in plan:
        print(
            f"    {action['profile']:13} {action['tool']:10} "
            f"{action['target_url']} — {action['reason']}",
            flush=True,
        )
    return {"plan": plan, "round": round_number, "notes": notes, "finished": finished, "planner_source": planner_source}


async def execute_action(action: dict[str, Any], cookies: dict[str, str], discovery: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
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
            "timeout": 120 if deterministic_core.CURRENT_SCAN_MODE == "deep" else 75,
        }
    else:
        arguments = {"target_url": action["target_url"], "cookies": cookies.get(action["profile"], "")}
        if action["tool"] in BROAD_SCANNER_TIMEOUTS:
            arguments["timeout"] = BROAD_SCANNER_TIMEOUTS[action["tool"]]
            profile_discovery = discovery.get(action["profile"], {})
            if action["tool"] == "zap":
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
                    "max_observations": 100 if deterministic_core.CURRENT_SCAN_MODE == "deep" else 50,
                })
            elif action["tool"] == "nuclei":
                arguments["seed_urls"] = profile_discovery.get("html_urls", [])
                arguments["request_cases"] = profile_discovery.get("request_cases", [])
                arguments["scan_profile"] = deterministic_core.CURRENT_SCAN_MODE
                arguments["max_targets"] = (
                    8 if deterministic_core.CURRENT_SCAN_MODE == "deep"
                    else 4 if deterministic_core.CURRENT_SCAN_MODE == "balanced"
                    else 1
                )
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
                arguments["allow_state_changes"] = urlparse(action["target_url"]).hostname in {"127.0.0.1", "localhost", "::1"}

    state_refresh: dict[str, Any] | None = None
    if (
        cookies.get(action["profile"], "")
        and action["tool"] in {"sqlmap", "dalfox", "commix", "traversal", "idor", "interactsh", "arjun"}
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


async def execute_plan(plan: list[dict[str, Any]], cookies: dict[str, str], discovery: dict[str, dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
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
    for index, action in enumerate(ordered, start=1):
        started = time.monotonic()
        print(
            f"\n[*] Action {index}/{total}: {action['profile']} / "
            f"{action['tool']} / {action['target_url']}",
            flush=True,
        )
        try:
            item = await execute_action(action, cookies, discovery)
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


def executor_node(state: AgentState) -> dict[str, Any]:
    if not state["plan"]:
        return {}
    cookies = {profile["name"]: profile["cookies"] for profile in state["profiles"]}
    executed = asyncio.run(execute_plan(state["plan"], cookies, state["discovery"]))
    results = {profile: dict(values) for profile, values in state["results"].items()}
    discovery = {profile: dict(values) for profile, values in state["discovery"].items()}
    completed, new_attack_surface = list(state["completed"]), 0
    profile_cookies = {profile["name"]: profile["cookies"] for profile in state["profiles"]}
    for action, result in executed:
        profile, tool = action["profile"], action["tool"]
        profile_results = results.setdefault(profile, {})
        number = 1 + sum(key.startswith(f"{tool}:") for key in profile_results)
        profile_results[f"{tool}:{number}"] = {**result, "planner_reason": action["reason"], "planner_round": state["round"]}
        completed.append(action_id(action))
        log_result(profile, tool, result, action["target_url"])
        if tool == "zap":
            log_zap_session_diagnostics(result)
        if tool == "ffuf" and result.get("status") in {"success", "partial"}:
            before = len(discovery.get(profile, {}).get("request_cases", []))
            enriched, urls = enrich_discovery_with_ffuf(discovery.get(profile, {}), result, state["target"])
            if urls:
                recrawl = discover_target(state["target"], profile_cookies.get(profile, ""), seeds=urls)
                enriched = merge_discovery(enriched, recrawl)
            discovery[profile] = enriched
            new_attack_surface += max(0, len(enriched.get("request_cases", [])) - before)
        if tool == "arjun" and result.get("status") in {"success", "partial"}:
            discovery[profile], generated = enrich_discovery_with_arjun(discovery.get(profile, {}), result, action["target_url"])
            new_attack_surface += len(generated)
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
    update: dict[str, Any] = {
        "results": results,
        "discovery": discovery,
        "completed": completed,
        "notes": notes,
        "finished": not can_continue,
    }
    return update


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
        "scan_mode": deterministic_core.CURRENT_SCAN_MODE,
        "runtime_platform": platform.platform(),
        "python_executable": sys.executable,
        "mcp_server_python": deterministic_core._server_python(),
        "remaining_eligible_actions_at_report": len(remaining),
        "execution_policy": "AI-selected actions are validated against the shared deterministic tool catalogue and discovered same-profile request contracts. A target-independent coverage guardrail adds omitted applicable scanner classes, preserves phase ordering, and continues planning while eligible actions remain and round budget is available.",
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
    parser.add_argument("--auth-only", action="store_true")
    parser.add_argument("--authorized", action="store_true")
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
