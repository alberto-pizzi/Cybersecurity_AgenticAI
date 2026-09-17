from __future__ import annotations

import asyncio
import copy
import getpass
import json
import math
import os
import re
import platform
import socket
import sys
import uuid
import time
import traceback
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, TypedDict
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

warnings.filterwarnings("ignore", message=r".*authlib\.jose.*deprecated.*")
import requests
import orchestratorShared as shared
from orchestratorShared import (
    BROAD_SCANNER_TIMEOUTS, PARAMETER_TOOL_TIMEOUTS,
    build_tool_arguments, call_mcp, call_mcp_with_progress, diagnose_error,
    discover_target, discover_target_sync_safe, enrich_discovery_with_arjun, enrich_discovery_with_ffuf,
    iter_leaf_results, log_result, log_zap_session_diagnostics, make_skipped_result,
    merge_discovery, print_security_finding_summary, select_arjun_request_cases,
    select_authorization_request_cases, select_browser_request_cases, select_logout_request_cases, select_oast_request_cases,
    select_request_cases, select_session_probe_url, select_tool_request_cases, select_workflow_request_cases,
    write_emergency_json_report,
)

REGISTRY: dict[str, tuple[str, str, str, str]] = {}
OLLAMA_DEFAULT_MODEL = 'llama3.1:8b'
OLLAMA_QWEN_MODEL = 'qwen2.5:7b'
SNAP4CITY_DEFAULT_API_URL = 'https://www.snap4city.org/apis/llama4-agentic-inference'
SNAP4CITY_DEFAULT_MODEL = 'llama4-agentic-inference'
_SNAP4CITY_TOKEN_MANAGERS: dict[str, Any] = {}


# Stores the state exchanged between the agentic workflow steps.
class AgentState(TypedDict):
    target: str
    entry_points: list[str]
    discovery_seeds: list[str]
    profiles: list[dict[str, str]]
    discovery: dict[str, dict[str, Any]]
    plan: list[dict[str, Any]]
    completed: list[str]
    results: dict[str, dict[str, Any]]
    round: int
    max_rounds: int
    ai_provider: str
    ollama_url: str
    snap4city_api_url: str
    snap4city_credentials: str
    model: str
    injection_url: str
    notes: list[str]
    finished: bool
    diagnostics: list[dict[str, Any]]
    report_status: dict[str, Any]
    require_ai: bool
    planner_source: str
    ai_timeout: int
    allow_state_changes: bool | None
    secondary_cookies: str
    planner_audit: list[dict[str, Any]]
    analysis: dict[str, Any]
    verification_done: bool
    only_tool: str
# CPU-only Ollama hosts can take far longer than 720s to prefill+decode a JSON-schema-constrained
# plan (no tokens at all until prefill finishes), so these budgets stay generous by default.
AI_PLANNER_TIMEOUTS = {
    'test': 90,
    'fast': 900,
    'balanced': 1800,
    'deep': 3000,
}

AI_PLANNER_MAX_PREDICT = {
    'test': 500,
    'fast': 800,
    'balanced': 1300,
    'deep': 1800,
}

AI_PLANNER_CONTEXT_WINDOWS = {
    'test': 4096,
    'fast': 6144,
    'balanced': 8192,
    'deep': 12288,
}
# Concrete-action planning is batched so large multi-identity catalogs remain tractable without
# turning prompt size into a security-policy decision. Context limits may change batch size/context
# representation, but every eligible concrete action must still be presented to the AI.
AI_PLANNER_CONTEXT_WINDOWS_MAX = {
    'test': 6144,
    'fast': 12288,
    'balanced': 16384,
    'deep': 24576,
}
PLANNER_CONTEXT_BYTES_PER_TOKEN_ESTIMATE = 3
PLANNER_CONTEXT_SAFETY_TOKENS = 512

# Same CPU-only-Ollama rationale as AI_PLANNER_TIMEOUTS above: this is a hard ceiling on
# batch_budget (analysis_node caps it with min(ai_timeout, this value)), so raising --ai-timeout
# alone does not help this stage unless this dict is also raised.
AI_ANALYSIS_BATCH_TIMEOUTS = {
    'test': 60,
    'fast': 480,
    'balanced': 900,
    'deep': 1500,
}
AI_ANALYSIS_BATCH_SIZES = {'test': 1, 'fast': 2, 'balanced': 4, 'deep': 6}
TEST_PLANNER_CANDIDATE_LIMIT = 32
TEST_ANALYSIS_FINDING_LIMIT = 1
AI_ANALYSIS_MAX_PREDICT = {'test': 400, 'fast': 520, 'balanced': 850, 'deep': 1200}
AI_ANALYSIS_RESCUE_MAX_PREDICT = {'test': 260, 'fast': 340, 'balanced': 460, 'deep': 600}
AI_ANALYSIS_CONTEXT_WINDOWS = {'test': 4096, 'fast': 6144, 'balanced': 8192, 'deep': 12288}
LAST_AI_PLAN_DIAGNOSTICS: dict[str, Any] = {}
BROAD_COVERAGE_TOOLS = ('ffuf', 'zap', 'nuclei', 'session', 'nikto')
PARAMETER_COVERAGE_TOOLS = ('sqlmap', 'dalfox', 'commix', 'traversal', 'idor')
AUTHORIZATION_COVERAGE_TOOLS = ('authorization',)
WORKFLOW_COVERAGE_TOOLS = ('browser', 'workflow')
# In normal Agentic mode no scanner, tool, capability family or request is mandatory. Python
# derives concrete discovery-backed action candidates and enforces only scope/safety/resource limits;
# the AI decides which concrete actions are useful. Deterministic mode remains the fixed pipeline.
#
# These are GLOBAL per-round execution ceilings, not coverage baselines and not minimums. They never
# cause an action to run by themselves. The planner may select fewer actions, including zero.
ROUND_EXECUTION_ACTION_REFERENCE_CAPS = {
    'test': 24,
    'fast': 300,
    'balanced': 800,
    'deep': 1144,
}
# Compatibility alias used by older report/validation code. It now means the normal global round
# ceiling; it is not a per-profile target and must not be interpreted as deterministic coverage.
PROFILE_EXECUTION_ACTION_BUDGETS = dict(ROUND_EXECUTION_ACTION_REFERENCE_CAPS)
PROFILE_EXECUTION_ACTION_OVERFLOW_INITIAL = {mode: 0 for mode in ROUND_EXECUTION_ACTION_REFERENCE_CAPS}
PROFILE_EXECUTION_ACTION_OVERFLOW_STEP = {mode: 0 for mode in ROUND_EXECUTION_ACTION_REFERENCE_CAPS}
PROFILE_EXECUTION_ACTION_OVERFLOW_MAX = {mode: 0 for mode in ROUND_EXECUTION_ACTION_REFERENCE_CAPS}
PROFILE_EXECUTION_ACTION_MAX = dict(ROUND_EXECUTION_ACTION_REFERENCE_CAPS)
# The AI may explicitly ask for up to +12.5% capacity when useful selected actions would otherwise
# exceed the normal ceiling. Python validates the request and still enforces scope and safety.
ROUND_EXECUTION_ADAPTIVE_CEILING_NUMERATOR = 9
ROUND_EXECUTION_ADAPTIVE_CEILING_DENOMINATOR = 8
ROUND_EXECUTION_ACTION_ADAPTIVE_CEILINGS = {
    mode: max(
        int(reference),
        (int(reference) * ROUND_EXECUTION_ADAPTIVE_CEILING_NUMERATOR + ROUND_EXECUTION_ADAPTIVE_CEILING_DENOMINATOR - 1)
        // ROUND_EXECUTION_ADAPTIVE_CEILING_DENOMINATOR,
    )
    for mode, reference in ROUND_EXECUTION_ACTION_REFERENCE_CAPS.items()
}

def _execution_overflow_cap(mode: str, round_number: int) -> int:
    # Legacy helper retained for report compatibility. Normal Agentic planning has no Python-chosen
    # overflow lane; capacity above the normal ceiling exists only after an explicit AI request.
    reference = int(ROUND_EXECUTION_ACTION_REFERENCE_CAPS.get(str(mode or 'balanced'), 800))
    adaptive = int(ROUND_EXECUTION_ACTION_ADAPTIVE_CEILINGS.get(str(mode or 'balanced'), reference))
    return max(0, adaptive - reference)


def _execution_round_max(mode: str, round_number: int) -> int:
    return int(ROUND_EXECUTION_ACTION_REFERENCE_CAPS.get(str(mode or 'balanced'), 800))


def _round_execution_budget(state: AgentState, eligible: list[dict[str, Any]], round_number: int, *, ai_extension_requested: bool=False) -> dict[str, int]:
    """Return resource ceilings only; never select or guarantee security actions.

    The normal reference ceiling is a maximum number of concrete actions that may execute in this
    round. It is not a baseline/minimum and does not add any scanner/tool/request to the plan. The AI
    may explicitly request the bounded adaptive ceiling; Python accepts it only when enough concrete
    eligible actions exist.
    """
    mode = str(shared.CURRENT_SCAN_MODE or 'balanced')
    reference_cap = max(1, int(ROUND_EXECUTION_ACTION_REFERENCE_CAPS.get(mode, 800)))
    adaptive_ceiling = max(reference_cap, int(ROUND_EXECUTION_ACTION_ADAPTIVE_CEILINGS.get(mode, reference_cap)))
    eligible_count = len([action for action in eligible if isinstance(action, dict)])
    remaining_rounds = max(1, int(state.get('max_rounds', 1) or 1) - int(state.get('round', 0) or 0))
    ordinary_remaining = sum(1 for action in eligible if isinstance(action, dict) and not bool(action.get('adaptive_budget')))
    required_per_round = (ordinary_remaining + remaining_rounds - 1) // remaining_rounds if ordinary_remaining else 0
    ai_request_effective = bool(ai_extension_requested) and eligible_count > reference_cap
    active_ceiling = adaptive_ceiling if ai_request_effective else reference_cap
    resolved_max = min(active_ceiling, eligible_count)
    resolved_base = min(reference_cap, eligible_count)
    return {
        'normal_base': reference_cap,  # compatibility name: ceiling, never a minimum
        'normal_round_max': reference_cap,
        'configured_normal_max': reference_cap,
        'overflow_cap': max(0, active_ceiling - reference_cap),
        'reference_cap': reference_cap,
        'adaptive_ceiling': adaptive_ceiling,
        'active_ceiling': active_ceiling,
        'adaptive_extension_unlocked': int(ai_request_effective),
        'adaptive_extension_ai_requested': int(bool(ai_extension_requested)),
        'adaptive_extension_ai_effective': int(ai_request_effective),
        'adaptive_extension_deterministic_pressure': 0,
        'hard_cap': active_ceiling,
        'remaining_rounds': remaining_rounds,
        'ordinary_remaining': ordinary_remaining,
        'required_per_round': required_per_round,
        'resolved_base': resolved_base,
        'resolved_max': resolved_max,
    }


def _fair_global_action_cap(actions: list[dict[str, Any]], cap: int) -> list[dict[str, Any]]:
    """Fairly cap concrete actions across profiles, then capabilities inside each profile.

    Active profiles share the global round cap evenly while both have work. When one profile
    exhausts its eligible work, unused capacity flows to the remaining profile(s). Within each
    profile, tools are round-robined so one large specialist family cannot monopolize that
    profile's share.
    """
    maximum = max(0, int(cap))
    if maximum <= 0:
        return []
    if len(actions) <= maximum:
        return list(actions)

    profile_tool_buckets: dict[str, dict[str, list[dict[str, Any]]]] = {}
    profile_order: list[str] = []
    tool_order: dict[str, list[str]] = {}
    for action in actions:
        profile = str(action.get('profile') or '')
        tool = str(action.get('tool') or '').lower()
        if profile not in profile_tool_buckets:
            profile_tool_buckets[profile] = {}
            profile_order.append(profile)
            tool_order[profile] = []
        if tool not in profile_tool_buckets[profile]:
            profile_tool_buckets[profile][tool] = []
            tool_order[profile].append(tool)
        profile_tool_buckets[profile][tool].append(action)

    tool_offsets = {
        profile: {tool: 0 for tool in tool_order[profile]}
        for profile in profile_order
    }
    tool_cursors = {profile: 0 for profile in profile_order}

    def next_for_profile(profile: str) -> dict[str, Any] | None:
        tools = tool_order.get(profile, [])
        if not tools:
            return None
        cursor = tool_cursors[profile]
        for step in range(len(tools)):
            index = (cursor + step) % len(tools)
            tool = tools[index]
            offset = tool_offsets[profile][tool]
            bucket = profile_tool_buckets[profile][tool]
            if offset >= len(bucket):
                continue
            tool_offsets[profile][tool] = offset + 1
            tool_cursors[profile] = (index + 1) % len(tools)
            return bucket[offset]
        return None

    selected: list[dict[str, Any]] = []
    active_profiles = list(profile_order)
    while len(selected) < maximum and active_profiles:
        next_active: list[str] = []
        added = False
        for profile in active_profiles:
            action = next_for_profile(profile)
            if action is None:
                continue
            selected.append(action)
            added = True
            # Keep the profile active only if at least one bucket still has work. This allows
            # unused capacity to flow to other profiles on the next pass.
            if any(
                tool_offsets[profile][tool] < len(profile_tool_buckets[profile][tool])
                for tool in tool_order[profile]
            ):
                next_active.append(profile)
            if len(selected) >= maximum:
                break
        if not added:
            break
        # Profiles that were not visited because the cap was reached do not matter; otherwise
        # next_active is the exact set still holding work.
        active_profiles = next_active
    return selected

# 32/64/96/128 are NOT tool/group quotas and do not limit what the AI may choose. They are only the
# maximum number of CONCRETE action candidates put in one planner request. If more candidates exist,
# Python creates additional fair batches until every eligible action has been presented to the AI.
PLANNER_ACTION_BATCH_SIZES = {'test': 32, 'fast': 64, 'balanced': 96, 'deep': 128}
PLAN_SCHEMA = {
    'type': 'object',
    'properties': {
        'reasoning_summary': {'type': 'string'},
        'selected_action_ids': {'type': 'array', 'items': {'type': 'string'}},
        'selected_action_priorities': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string'},
                    'priority': {'type': 'integer', 'minimum': 0, 'maximum': 100},
                },
                'required': ['id', 'priority'],
            },
        },
        'request_adaptive_extension': {'type': 'boolean'},
        'finish': {'type': 'boolean'},
    },
    'required': ['reasoning_summary', 'selected_action_ids', 'selected_action_priorities', 'finish'],
}

ANALYSIS_SCHEMA = {
    'type': 'object',
    'properties': {
        'analyses': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string'},
                    'risk': {'type': 'string', 'enum': ['critical', 'high', 'medium', 'low', 'info']},
                    'description': {'type': 'string'},
                    'impact': {'type': 'string'},
                    'consequences': {'type': 'string'},
                    'recovery': {'type': 'string'},
                    'solution': {'type': 'string'},
                    'rationale': {'type': 'string'},
                    'confidence': {'type': 'string', 'enum': ['high', 'medium', 'low']},
                },
                'required': ['id', 'risk', 'description', 'impact', 'consequences', 'recovery', 'solution', 'rationale', 'confidence'],
            },
        },
    },
    'required': ['analyses'],
}


# Resolves user-friendly model aliases into the concrete provider/model pair.
# Provider=auto never sends data to Snap4City unless the selected model explicitly names Snap4City.
def resolve_ai_model(requested_model: str) -> tuple[str, str, dict[str, Any]]:
    choice = str(requested_model or 'snap4city').strip().lower()
    supported = {
        'snap4city': ('snap4city', SNAP4CITY_DEFAULT_MODEL),
        'llama': ('ollama', OLLAMA_DEFAULT_MODEL),
        'qwen': ('ollama', OLLAMA_QWEN_MODEL),
    }
    if choice not in supported:
        raise ValueError(
            f"Unsupported AI model '{requested_model}'. Choose one of: snap4city, llama, qwen."
        )
    provider, model = supported[choice]
    return provider, model, {
        'requested_model': choice,
        'selected_provider': provider,
        'selected_model': model,
        'selection_source': 'model_choice',
    }


# Turns an Ollama error response into a readable message.
def _ollama_error(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return (response.text or response.reason or 'unknown Ollama error').strip()
    if isinstance(payload, dict):
        return str(payload.get('error') or payload.get('message') or payload).strip()
    return str(payload)

# Asks Ollama which models are already installed.
def _ollama_installed_models(ollama_url: str) -> list[str]:
    response = requests.get(f"{ollama_url.rstrip('/')}/api/tags", timeout=(5, 30))
    response.raise_for_status()
    payload = response.json()
    values: list[str] = []
    for item in payload.get('models', []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        value = str(item.get('name') or item.get('model') or '').strip()
        if value:
            values.append(value)
    return list(dict.fromkeys(values))

# Model matching accepts the requested Ollama name when a compatible installed tag is available.
def _model_matches(requested: str, installed: str) -> bool:
    left, right = (requested.lower(), installed.lower())
    if left == right:
        return True
    if ':' not in left and right.split(':', 1)[0] == left:
        return True
    return False

# Ensures a usable Ollama model is available before planning.
def ensure_ollama_model(ollama_url: str, requested_model: str, *, allow_pull: bool=True) -> tuple[str, dict[str, Any]]:

    base = ollama_url.rstrip('/')
    diagnostics: dict[str, Any] = {'ollama_url': base, 'requested_model': requested_model, 'model_pull_attempted': False, 'fallback_model_used': False}
    version = requests.get(f'{base}/api/version', timeout=(5, 20))
    version.raise_for_status()
    try:
        diagnostics['ollama_version'] = version.json().get('version', 'unknown')
    except ValueError:
        diagnostics['ollama_version'] = 'unknown'
    installed = _ollama_installed_models(base)
    diagnostics['installed_models_before'] = installed
    matched = next((name for name in installed if _model_matches(requested_model, name)), '')
    if matched:
        diagnostics.update(model_ready=True, selected_model=matched)
        return (matched, diagnostics)
    pull_error = ''
    if allow_pull:
        diagnostics['model_pull_attempted'] = True
        try:
            response = requests.post(f'{base}/api/pull', json={'model': requested_model, 'stream': False}, timeout=(10, 7200))
            if response.status_code >= 400:
                raise RuntimeError(f'HTTP {response.status_code}: {_ollama_error(response)}')
            installed = _ollama_installed_models(base)
            diagnostics['installed_models_after_pull'] = installed
            matched = next((name for name in installed if _model_matches(requested_model, name)), '')
            if matched:
                diagnostics.update(model_ready=True, selected_model=matched)
                return (matched, diagnostics)
            pull_error = 'Ollama pull completed but the requested model was not listed by /api/tags.'
        except Exception as exc:
            pull_error = f'{type(exc).__name__}: {exc}'
    diagnostics['model_pull_error'] = pull_error
    supported_fallbacks = [OLLAMA_DEFAULT_MODEL, OLLAMA_QWEN_MODEL]
    for preferred in supported_fallbacks:
        if _model_matches(requested_model, preferred):
            continue
        selected = next((name for name in installed if _model_matches(preferred, name)), '')
        if selected:
            diagnostics.update(
                model_ready=True, selected_model=selected, fallback_model_used=True,
                fallback_reason=pull_error or f"Requested model '{requested_model}' is unavailable; selected supported local fallback '{selected}'.",
            )
            return (selected, diagnostics)
    diagnostics.update(model_ready=False, selected_model='')
    raise RuntimeError('Ollama is reachable but no usable local model exists. ' + (pull_error or f"Requested model '{requested_model}' is not installed."))

def _normalize_ai_boolean_field(value: dict[str, Any], field: str, *, default: bool=False) -> bool:
    """Normalize harmless schema-type drift without relying on Python truthiness."""
    if field not in value:
        value[field] = bool(default)
        return bool(default)
    raw = value.get(field)
    normalized: bool
    if isinstance(raw, bool):
        normalized = raw
    elif isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(float(raw)) and float(raw) in {0.0, 1.0}:
        normalized = bool(int(raw))
    elif isinstance(raw, str) and raw.strip().lower() in {'true', 'false', '1', '0', 'yes', 'no'}:
        normalized = raw.strip().lower() in {'true', '1', 'yes'}
    else:
        raise ValueError(f'AI provider returned an invalid boolean for {field}.')
    if raw is not normalized or type(raw) is not bool:
        value.setdefault('_contract_normalizations', []).append({
            'field': field,
            'received': raw,
            'normalized': normalized,
        })
    value[field] = normalized
    return normalized


# Parses the compact concrete-action ID selection contract shared by every supported AI provider.
def _parse_ai_plan_content(content: str) -> dict[str, Any]:
    raw = str(content or '').strip()
    if raw.startswith('```'):
        raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.IGNORECASE)
        raw = re.sub(r'\s*```$', '', raw)
    first, last = raw.find('{'), raw.rfind('}')
    if first >= 0 and last > first:
        raw = raw[first:last + 1]
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get('selected_action_ids', []), list):
        raise ValueError('AI provider returned an invalid compact plan object.')
    priorities = value.get('selected_action_priorities')
    if not isinstance(priorities, list):
        raise ValueError('AI provider omitted selected_action_priorities.')
    selected: list[str] = []
    seen_selected: set[str] = set()
    duplicate_selected: list[str] = []
    for item in value.get('selected_action_ids', []):
        candidate_id = str(item).strip()
        if not candidate_id:
            continue
        if candidate_id in seen_selected:
            if candidate_id not in duplicate_selected:
                duplicate_selected.append(candidate_id)
            continue
        seen_selected.add(candidate_id)
        selected.append(candidate_id)
    if duplicate_selected:
        value.setdefault('_contract_normalizations', []).append({
            'field': 'selected_action_ids',
            'deduplicated_ids': duplicate_selected,
        })
    value['selected_action_ids'] = selected
    _normalize_ai_boolean_field(value, 'request_adaptive_extension', default=False)
    _normalize_ai_boolean_field(value, 'finish', default=False)
    priority_ids: set[str] = set()
    priority_values: dict[str, int] = {}
    normalized_priorities: list[dict[str, Any]] = []
    for raw_row in priorities:
        if not isinstance(raw_row, dict) or not str(raw_row.get('id') or '').strip():
            raise ValueError('AI provider returned an invalid selected_action_priorities entry.')
        row = dict(raw_row)
        row['id'] = str(row.get('id')).strip()
        raw_priority = row.get('priority')
        if isinstance(raw_priority, bool):
            raise ValueError('AI provider returned a boolean action priority; an integer 0..100 is required.')
        try:
            numeric_priority = float(raw_priority)
        except (TypeError, ValueError) as exc:
            raise ValueError('AI provider returned a non-numeric action priority.') from exc
        if not math.isfinite(numeric_priority):
            raise ValueError('AI provider returned a non-finite action priority.')
        # Structured-output providers occasionally violate the JSON-schema numeric bounds even
        # when the rest of the plan is valid (for example 120 on a documented 0..100 scale).
        # Treat this as a recoverable representation defect rather than discarding a complete AI
        # decision. Clamping preserves the model's monotonic intent while Python still does not
        # invent an action or a priority for an omitted action.
        priority = max(0, min(100, int(round(numeric_priority))))
        if numeric_priority != priority:
            value.setdefault('_contract_normalizations', []).append({
                'field': 'selected_action_priorities.priority',
                'id': row['id'],
                'received': raw_priority,
                'normalized': priority,
            })
        row['priority'] = priority
        candidate_id = row['id']
        if candidate_id in priority_values:
            if priority_values[candidate_id] != priority:
                raise ValueError(
                    f'AI provider returned conflicting priorities for {candidate_id}: '
                    f'{priority_values[candidate_id]} and {priority}.'
                )
            value.setdefault('_contract_normalizations', []).append({
                'field': 'selected_action_priorities',
                'deduplicated_id': candidate_id,
                'priority': priority,
            })
            continue
        priority_values[candidate_id] = priority
        priority_ids.add(candidate_id)
        normalized_priorities.append(row)
    value['selected_action_priorities'] = normalized_priorities
    missing = [candidate_id for candidate_id in selected if candidate_id not in priority_ids]
    if missing:
        raise ValueError('AI provider omitted priorities for selected action IDs: ' + ', '.join(missing[:8]))
    return value


# Compact view of ONE concrete action. Python already validated the request contract; the AI decides
# whether this exact action is useful. Values that could contain credentials remain local/redacted.
def _planner_candidate_view(action: dict[str, Any], candidate_id: str) -> dict[str, Any]:
    return {
        'id': candidate_id,
        'profile': str(action.get('profile') or ''),
        'tool': str(action.get('tool') or ''),
        'method': str(action.get('method') or 'GET'),
        'url': str(action.get('target_url') or ''),
        'parameters': [str(value) for value in action.get('parameters', [])][:8],
        'file_parameters': [str(value) for value in action.get('file_parameters', [])][:4],
        'token_parameters': [str(value) for value in action.get('token_parameters', [])][:4],
        'oast_class': str(action.get('oast_class') or ''),
        'adaptive_candidate': bool(action.get('adaptive_budget')),
        'coverage_reserve_hint': bool(action.get('coverage_reserve')),
        'priority_score_hint': action.get('priority_score'),
        'evidence': str(action.get('reason') or '')[:150],
    }


def _fair_planner_action_order(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Interleave profile/tool buckets without deciding which actions are useful.

    This is prompt scheduling only. Every input action is returned exactly once. The purpose is to
    prevent an early large tool/profile bucket from occupying all of the first planner batch.
    """
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str, str]] = []
    for action in actions:
        key = (str(action.get('profile') or ''), str(action.get('tool') or '').lower())
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(action)
    offsets = {key: 0 for key in order}
    output: list[dict[str, Any]] = []
    while len(output) < len(actions):
        added = False
        for key in order:
            index = offsets[key]
            bucket = buckets[key]
            if index >= len(bucket):
                continue
            output.append(bucket[index])
            offsets[key] = index + 1
            added = True
        if not added:
            break
    return output


def _planner_action_batches(actions: list[dict[str, Any]], batch_size: int) -> list[list[dict[str, Any]]]:
    ordered = _fair_planner_action_order(actions)
    size = max(1, int(batch_size))
    return [ordered[index:index + size] for index in range(0, len(ordered), size)]


def _fit_planner_prompt_context(
    prompt: dict[str, Any],
    system_message: str,
    *,
    base_context_window: int,
    max_context_window: int,
    max_predict: int,
) -> tuple[dict[str, Any], str, int, int]:
    """Fit one concrete-action batch without silently hiding candidates.

    Unlike the older group planner, candidate_actions is never trimmed. If a configured batch does
    not fit even at the bounded maximum context, the caller must split it into smaller batches.
    """
    adjusted = dict(prompt)
    candidates = list(adjusted.get('candidate_actions') or [])
    minimum_window = max(2048, int(base_context_window))
    maximum_window = max(minimum_window, int(max_context_window))
    system_bytes = len(str(system_message or '').encode('utf-8'))
    context = json.dumps(adjusted, ensure_ascii=False, separators=(',', ':'))
    context_bytes = len(context.encode('utf-8'))
    prompt_bytes = system_bytes + context_bytes
    estimated_prompt_tokens = (prompt_bytes + PLANNER_CONTEXT_BYTES_PER_TOKEN_ESTIMATE - 1) // PLANNER_CONTEXT_BYTES_PER_TOKEN_ESTIMATE
    needed = estimated_prompt_tokens + max(0, int(max_predict)) + PLANNER_CONTEXT_SAFETY_TOKENS
    context_window = minimum_window if needed <= minimum_window else min(maximum_window, ((needed + 2047) // 2048) * 2048)
    if needed > context_window:
        raise RuntimeError(
            f'Planner action batch requires about {needed} context tokens, exceeding bounded context window {context_window}. '
            'Split the concrete-action batch; never drop candidates silently.'
        )
    return adjusted, context, context_window, len(candidates)


def _planner_discovery_summary(discovery: dict[str, dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for profile, found in discovery.items():
        summary[profile] = {
            'authenticated': found.get('authentication_effective'),
            'html_pages': len(found.get('html_urls', [])),
            'request_cases': len(found.get('request_cases', [])),
            'browser_network_requests': len(found.get('browser_network_requests', [])),
            'browser_navigations': len(found.get('browser_navigation_urls', [])),
            'script_endpoint_hints': len(found.get('script_endpoint_hints', [])),
            'client_side_candidates': len(found.get('client_side_candidates', [])),
            'jwt_tokens': len(found.get('jwt_tokens', [])),
            'crawl_errors': len(found.get('errors', [])),
        }
    return summary


_OLLAMA_RUNNER_CRASH_MARKER = 'model runner has unexpectedly stopped'

# Reads the streamed Ollama response and joins its text safely.
def _ollama_stream_content(url: str, payload: dict[str, Any], *, response_kind: str, total_timeout: int, early_json: bool=False) -> str:

    def _attempt(budget: int) -> str:
        started = time.monotonic()
        chunks: list[str] = []
        read_timeout = max(60, int(budget) + 60)
        response = requests.post(url, json={**payload, 'stream': True}, stream=True, timeout=(10, read_timeout))
        try:
            if response.status_code >= 400:
                raise RuntimeError(f'HTTP {response.status_code}: {_ollama_error(response)}')
            if not hasattr(response, 'iter_lines'):
                value = response.json()
                if response_kind == 'chat':
                    content = str((value.get('message') or {}).get('content') or '')
                else:
                    content = str(value.get('response') or '')
                if not content:
                    raise ValueError('Ollama completed without returning response content.')
                return content
            for raw in response.iter_lines(decode_unicode=True):
                if time.monotonic() - started > budget:
                    raise TimeoutError(f'Ollama request exceeded the {budget}-second budget.')
                if not raw:
                    continue
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ValueError(f'Ollama returned a non-JSON stream event: {raw[:200]}') from exc
                if event.get('error'):
                    raise RuntimeError(str(event.get('error')))
                if response_kind == 'chat':
                    piece = str((event.get('message') or {}).get('content') or '')
                else:
                    piece = str(event.get('response') or '')
                if piece:
                    chunks.append(piece)
                    if early_json:
                        candidate = ''.join(chunks).strip()
                        if candidate.endswith('}'):
                            try:
                                parsed = json.loads(candidate)
                            except json.JSONDecodeError:
                                parsed = None
                            if isinstance(parsed, dict):
                                plan_complete = isinstance(parsed.get('selected_action_ids'), list) and isinstance(parsed.get('finish'), bool)
                                analysis_complete = isinstance(parsed.get('analyses'), list)
                                if plan_complete or analysis_complete:
                                    return candidate
                if event.get('done') is True:
                    break
        finally:
            close = getattr(response, 'close', None)
            if callable(close):
                close()
        content = ''.join(chunks).strip()
        if not content:
            raise ValueError('Ollama completed without returning response content.')
        return content

    # Ollama's model runner can crash under memory pressure mid-batch (HTTP 500
    # "model runner has unexpectedly stopped"); it typically reloads the model on
    # the next request, so one short-delayed retry recovers without failing the
    # whole batch outright.
    outer_started = time.monotonic()
    retries_left = 1
    while True:
        remaining = total_timeout - (time.monotonic() - outer_started)
        try:
            return _attempt(max(1, int(remaining)))
        except RuntimeError as exc:
            remaining = total_timeout - (time.monotonic() - outer_started)
            if retries_left > 0 and _OLLAMA_RUNNER_CRASH_MARKER in str(exc) and remaining > 30:
                retries_left -= 1
                time.sleep(3)
                continue
            raise

# Sends a small request so the model is ready before planning starts.
def warm_ollama_model(ollama_url: str, model: str, *, timeout: int) -> dict[str, Any]:

    started = time.monotonic()
    content = _ollama_stream_content(f"{ollama_url.rstrip('/')}/api/generate", {'model': model, 'prompt': 'Reply with READY and nothing else.', 'options': {'temperature': 0, 'num_predict': 4, 'num_ctx': 2048}, 'keep_alive': '30m'}, response_kind='generate', total_timeout=max(90, min(int(timeout), 600)))
    return {'ready': True, 'response': content[:80], 'seconds': round(time.monotonic() - started, 2)}


# Reuses the Snap4City TokenManager and preserves its authentication order.
# When the credentials file still contains placeholders, cached access/refresh tokens are tried
# first; interactive username/password entry is only the final fallback for this process.
def _snap4city_token_manager(credentials_path: str) -> Any:
    path = str(Path(credentials_path).expanduser().resolve())
    cached = _SNAP4CITY_TOKEN_MANAGERS.get(path)
    if cached is not None:
        return cached
    try:
        from token_manager import TokenManager
    except ImportError as exc:
        raise RuntimeError('Snap4City requires token_manager.py in the project root.') from exc
    try:
        payload = json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        payload = {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f'Snap4City credentials file is not valid JSON: {path}') from exc

    username = str(payload.get('username') or '').strip()
    password = str(payload.get('password') or '').strip()
    placeholders = (
        not username or not password
        or username.startswith('<') or password.startswith('<')
        or username.upper() == 'SNAP4CITY_USERNAME'
        or password.upper() in {'PASSWORD', 'SNAP4CITY_PASSWORD'}
    )

    # Construct TokenManager before prompting so its original load_token_data() can reuse
    # token_stored.json through its existing load_token_data() path. Real file credentials are passed
    # through unchanged; placeholders are withheld so they can never be sent to the token endpoint.
    manager = TokenManager('' if placeholders else username, '' if placeholders else password)

    if not placeholders:
        # From here manager.get_token() keeps the original order unchanged:
        # valid access token -> refresh token -> username/password.
        _SNAP4CITY_TOKEN_MANAGERS[path] = manager
        return manager

    # With placeholder credentials, first honor a still-valid cached access token.
    if manager.token and time.time() < manager.token_expiry:
        print('[*] Snap4City: using the valid cached access token from token_stored.json.', flush=True)
        _SNAP4CITY_TOKEN_MANAGERS[path] = manager
        return manager

    # If the cached access token expired, try the TokenManager refresh-token request
    # before asking the operator for credentials. A failed refresh is consumed here so get_token()
    # will not repeat the same failed refresh after interactive credentials are supplied.
    refresh_error = ''
    if manager.refresh_token:
        try:
            print('[*] Snap4City: cached access token is unavailable/expired; trying refresh token.', flush=True)
            token_data = manager.get_token_via_refresh_token(manager.refresh_token)
            if token_data and 'access_token' in token_data:
                manager.save_token_data(token_data)
                print('[+] Snap4City: access token refreshed successfully; interactive credentials are not required.', flush=True)
                _SNAP4CITY_TOKEN_MANAGERS[path] = manager
                return manager
            refresh_error = 'refresh-token response did not contain access_token'
        except Exception as exc:
            refresh_error = f'{type(exc).__name__}: {exc}'
        manager.refresh_token = None

    if not sys.stdin or not sys.stdin.isatty():
        detail = f' Refresh attempt: {refresh_error}.' if refresh_error else ''
        raise RuntimeError(
            f'Snap4City has no usable cached token and credentials are missing/placeholders in {path}; '
            f'no interactive console is available.{detail}'
        )

    print(
        f"[*] Snap4City has no usable cached token and credentials are missing/placeholders in {path}; "
        'enter them for this run.',
        flush=True,
    )
    try:
        username = input('Snap4City username: ').strip()
        password = getpass.getpass('Snap4City password: ').strip()
    except (EOFError, KeyboardInterrupt) as exc:
        raise RuntimeError('Snap4City credential entry was cancelled.') from exc
    if not username or not password:
        raise RuntimeError('Snap4City username and password are required.')

    # Keep interactive credentials only in this TokenManager instance. They are not written back
    # to snap4city_model_credentials.json; get_token() will now use its normal username/password final step.
    manager.username = username
    manager.password = password
    _SNAP4CITY_TOKEN_MANAGERS[path] = manager
    return manager


# Local address the OS would route through to reach the internet, without sending any packet
# (UDP connect() only resolves a route). Snap4City's own access-control gateway reads
# X-Forwarded-For/X-Real-IP rather than the raw TCP source, so this needs to be forwarded
# explicitly; per Snap4City's own guidance this is the VM's LAN IP, not its public egress IP.
def _local_outbound_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(('8.8.8.8', 80))
            return sock.getsockname()[0]
    except OSError:
        return ''


# Calls the Snap4City/ClearML endpoint in its documented OpenAI-compatible chat mode.
def _snap4city_chat_content(
    state: AgentState,
    system_message: str,
    user_content: str,
    *,
    total_timeout: int,
    temperature: float=0.0,
) -> str:
    manager = _snap4city_token_manager(state['snap4city_credentials'])
    access_token = manager.get_token()
    body = {
        'access_token': access_token,
        'endpoint': state['model'],
        'params': {
            'messages': [
                {'role': 'system', 'content': system_message},
                {'role': 'user', 'content': user_content},
            ],
            # An empty tools array plus tool_choice=none enables the documented
            # OpenAI-compatible response envelope without asking the model to call tools.
            'tools': [],
            'tool_choice': 'none',
            'temperature': temperature,
        },
    }
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}',
    }
    local_ip = _local_outbound_ip()
    if local_ip:
        headers['X-Forwarded-For'] = local_ip
        headers['X-Real-IP'] = local_ip
    response = requests.post(
        state['snap4city_api_url'],
        json=body,
        headers=headers,
        timeout=(10, max(20, int(total_timeout))),
    )
    if response.status_code >= 400:
        detail = (response.text or response.reason or 'unknown Snap4City error').strip()
        try:
            parsed_error = response.json()
            if isinstance(parsed_error, dict):
                detail = str(parsed_error.get('message') or parsed_error.get('detail') or parsed_error)
        except ValueError:
            pass
        raise RuntimeError(f'HTTP {response.status_code}: {detail[:1000]}')
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError('Snap4City returned a non-JSON response.') from exc
    if isinstance(payload, dict) and payload.get('choices'):
        choice = payload['choices'][0] if isinstance(payload['choices'], list) else {}
        message = choice.get('message', {}) if isinstance(choice, dict) else {}
        content = message.get('content') if isinstance(message, dict) else None
        if isinstance(content, str) and content.strip():
            return content.strip()
    # Keep compatibility with the endpoint's documented legacy envelope, even
    # though tools=[]/tool_choice=none should normally force the OpenAI envelope.
    if isinstance(payload, dict) and isinstance(payload.get('answer'), str) and payload['answer'].strip():
        return payload['answer'].strip()
    if isinstance(payload, dict) and (payload.get('message') or payload.get('detail')):
        raise RuntimeError(str(payload.get('message') or payload.get('detail')))
    raise ValueError('Snap4City completed without returning assistant content.')


# Authenticates and performs a minimal inference so --require-ai can fail before scanners start.
def ensure_snap4city_model(
    api_url: str,
    requested_model: str,
    credentials_path: str,
    *,
    timeout: int,
) -> tuple[str, dict[str, Any]]:
    selected = str(requested_model or SNAP4CITY_DEFAULT_MODEL).strip()
    state: AgentState = {  # type: ignore[typeddict-item]
        'ai_provider': 'snap4city',
        'snap4city_api_url': str(api_url or SNAP4CITY_DEFAULT_API_URL).rstrip('/'),
        'snap4city_credentials': credentials_path,
        'model': selected,
    }
    started = time.monotonic()
    content = _snap4city_chat_content(
        state,
        'This is a connectivity check. Follow the user instruction exactly.',
        'Reply with READY and nothing else.',
        total_timeout=max(45, min(int(timeout), 180)),
    )
    return selected, {
        'provider': 'snap4city',
        'model_ready': True,
        'selected_model': selected,
        'api_url': state['snap4city_api_url'],
        'credentials_file': str(Path(credentials_path).expanduser()),
        'warmup_response': content[:80],
        'warmup_seconds': round(time.monotonic() - started, 2),
    }

# Builds a stable identifier for one planned action. Parameter/field names are part of the
# identity so two contracts on the same route are not collapsed when they expose different inputs.
def action_id(action: dict[str, Any]) -> str:
    parameter_names = sorted({str(value) for value in action.get('parameters', []) if str(value)})
    file_names = sorted({str(value) for value in action.get('file_parameters', []) if str(value)})
    token_names = sorted({str(value) for value in action.get('token_parameters', []) if str(value)})
    field_names = sorted({
        str(field.get('name'))
        for field in action.get('fields', [])
        if isinstance(field, dict) and str(field.get('name') or '')
    })
    target_identity = shared.semantic_request_identity_url(str(action.get('target_url', '')))
    return '|'.join((
        str(action.get('profile', '')), str(action.get('tool', '')), target_identity,
        str(action.get('method', '')), str(action.get('data', '')), ','.join(parameter_names),
        ','.join(file_names), ','.join(token_names), ','.join(field_names),
        str(action.get('jwt_token', '')), str(action.get('injection_url', '')),
    ))

# Execution equivalence intentionally ignores the profile label. It is used only when neither
# profile can apply a credential to the concrete target, so an "authenticated" sibling action and
# the anonymous action are literally the same HTTP security test.
def action_execution_id(action: dict[str, Any]) -> str:
    return action_id({**action, 'profile': ''})

def _profile_cookie(state: AgentState, profile_name: str) -> str:
    profile = next((item for item in state.get('profiles', []) if str(item.get('name') or '') == profile_name), None)
    return str(profile.get('cookies') or '') if isinstance(profile, dict) else ''

# Most tools issue their concrete HTTP request to target_url. Interactsh records the assessment
# target separately but sends the injection request to injection_url, so credential scoping must use
# that destination instead of the reporting target.
def _action_request_url(action: dict[str, Any], fallback_target: str='') -> str:
    if str(action.get('tool') or '') == 'interactsh' and str(action.get('injection_url') or ''):
        return str(action.get('injection_url') or '').replace('FUZZ', 'secops-oast-placeholder')
    return str(action.get('target_url') or fallback_target or '')

def _dedupe_no_cookie_profile_actions(state: AgentState, actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    anonymous_equivalent: dict[str, int] = {}
    for action in actions:
        profile = str(action.get('profile') or '')
        request_url = _action_request_url(action, str(state.get('target') or ''))
        raw_cookie = _profile_cookie(state, profile)
        effective_cookie = shared.scope_cookie_header(request_url, raw_cookie)
        if effective_cookie:
            output.append(action)
            continue
        # A browser/OIDC identity may legitimately have no cookie for a newly authorized origin yet
        # while still being able to establish an identity-bound session there. Keep that candidate so
        # the executor can perform the bounded refresh. A raw-cookie identity with neither an
        # applicable cookie nor an identity-aware runtime path must not consume authenticated budget.
        if raw_cookie and shared.runtime_target_auth_available(raw_cookie, request_url):
            output.append(action)
            continue
        if raw_cookie:
            continue
        identifier = action_execution_id(action)
        previous_index = anonymous_equivalent.get(identifier)
        if previous_index is None:
            anonymous_equivalent[identifier] = len(output)
            output.append(action)
            continue
        # Prefer the explicit anonymous label for reporting when the concrete execution is no-cookie.
        previous = output[previous_index]
        if profile == 'anonymous' and str(previous.get('profile') or '') != 'anonymous':
            output[previous_index] = action
    return output


# Treat a profile as authenticated only while discovery has not disproved its supplied session.
def _profile_has_effective_auth(state: AgentState, profile_name: str) -> bool:
    profile = next((item for item in state.get('profiles', []) if str(item.get('name') or '') == profile_name), None)
    if not isinstance(profile, dict) or not bool(profile.get('cookies')):
        return False
    found = state.get('discovery', {}).get(profile_name, {})
    return not isinstance(found, dict) or found.get('authentication_effective') is not False


# Invalid authenticated profiles remain visible in reporting but are not eligible for scanner planning.
def _profile_is_plannable(state: AgentState, profile_name: str) -> bool:
    profile = next((item for item in state.get('profiles', []) if str(item.get('name') or '') == profile_name), None)
    if not isinstance(profile, dict):
        return False
    return not bool(profile.get('cookies')) or _profile_has_effective_auth(state, profile_name)

# Converts internal planner field names into readable console/report wording.
def _humanize_planner_reasoning(value: Any) -> str:
    text = str(value or '').strip()
    replacements = (
        ('already_selected_action_ids', 'actions already selected'),
        ('selected_action_ids', 'selected concrete actions'),
        ('remaining_candidates', 'remaining concrete actions'),
        ('reasoning_summary', 'reasoning'),
        ('execution_action_normal_target_total', 'normal concrete-action ceiling for the whole round'),
        ('execution_action_resolved_base_total', 'normal concrete-action capacity available this round'),
        ('execution_action_adaptive_max_total', 'active concrete-action ceiling for the whole round'),
        ('execution_action_hard_cap_total', 'absolute concrete-action cap for the whole round'),
        ('remaining_slots_by_profile', 'remaining execution capacity by profile'),
    )
    for internal, readable in replacements:
        text = text.replace(internal, readable)
    text = re.sub(r'\bredundant with actions already selected\b', 'overlap with actions already selected', text, flags=re.IGNORECASE)
    return re.sub(r'\s+', ' ', text).strip()


def _planner_system_message() -> str:
    return (
        '[ROLE]\n'
        'You are the autonomous planner for an explicitly authorized web-security assessment. You decide which CONCRETE discovery-derived actions should execute. '
        'Each candidate ID is one exact profile + tool + target/request contract; selecting an ID selects that action, not an entire tool family.\n\n'
        '[OBJECTIVE]\n'
        'Choose the useful concrete actions that maximize complementary security evidence. Python does not choose attacks for you: it only discovers/normalizes candidates, removes invalid or unsafe work, batches the catalog for context size, and enforces the final traffic/time ceiling.\n\n'
        '[INPUT CONTRACT]\n'
        'The user message contains one batch of concrete candidate_actions, discovery summary, previous results and round resource ceilings. '
        'If the full catalog is larger than this batch, other batches are evaluated separately; therefore judge every candidate in this batch on its own evidence and complementarity.\n\n'
        '[DECISION RULES]\n'
        '- Evaluate EVERY candidate action in candidate_actions. Do not choose a tool first and then assume all of its requests should run.\n'
        '- SELECT an action ID when that exact request/scanner action is useful, complementary or independently evidentiary.\n'
        '- DEFER an action only for a concrete reason such as semantic duplication, equivalent completed work, weak applicability, incompatibility, safety constraints already described, or very low expected value.\n'
        '- Different actions from the same tool can have very different value; judge them independently. Likewise, an important action from a tool whose other actions are weak must still be selectable.\n'
        '- Broad scanners and targeted specialists are complementary; neither category replaces the other automatically.\n'
        '- Previous findings raise follow-up priority when relevant but do not justify repeating equivalent completed work.\n'
        '- adaptive_candidate and coverage_reserve_hint are Python ranking hints only, not mandatory selections and not exclusions.\n'
        '- FAST/BALANCED/DEEP normal global execution ceilings are 300/800/1144 concrete actions per round. Python may execute fewer because you selected fewer. '
        'Set request_adaptive_extension=true only if useful selected work may need the bounded +12.5% ceiling; never request it merely to fill capacity.\n'
        '- For every selected_action_id, include one matching selected_action_priorities entry with an integer priority from 0 to 100. Use the same scale across batches: 100 = highest-value action for this assessment, 0 = selected only as a very low-priority fallback.\n'
        '- Order selected_action_ids from highest to lowest priority within this batch. After all batches, Python merges selections by YOUR numeric priorities before applying per-tool/global ceilings; ties preserve your returned order.\n'
        '- finish is a batch-local signal: set it true only when none of the candidates in this batch is useful.\n\n'
        '[OUTPUT CONTRACT]\n'
        'Return exactly one JSON object with these fields and no others: '
        '{"reasoning_summary":"brief decision summary, not chain-of-thought","selected_action_ids":["concrete candidate IDs"],"selected_action_priorities":[{"id":"A0001","priority":90}],"request_adaptive_extension":false,"finish":false}.\n'
        'Use only IDs present in candidate_actions. Do not include chain-of-thought.\n\n'
        '[FINAL INSTRUCTION]\nReturn only valid JSON.'
    )


# Kept as a compatibility wrapper for older callers/tests. Normal planning no longer performs a
# tool-group breadth review because every concrete action is already evaluated by the AI.
def _planner_review_system_message() -> str:
    return _planner_system_message()


def _analysis_system_message() -> str:
    return (
        '[ROLE]\n'
        'You are the final evidence analyst for an explicitly authorized web-security assessment.\n\n'
        '[IMMUTABLE FACTS]\n'
        'Finding category, verification status, URL, parameter, payload and scanner/verifier evidence are facts supplied by the system. '
        'Never upgrade a candidate into a confirmed vulnerability and never invent exploitation, stolen data, privileges, actual damage or unsupported preconditions.\n\n'
        '[RISK RULES]\n'
        '- Choose risk independently as critical, high, medium, low or info; scanner_risk is input, not authority.\n'
        '- Calibrate severity to demonstrated impact, not vulnerability class alone.\n'
        '- CRITICAL is exceptional. A confirmed SQL injection alone is normally HIGH; reserve CRITICAL for evidence of system-wide compromise such as full data-store compromise, unauthenticated administrative takeover or remote code execution.\n'
        '- Candidates must retain uncertainty and conservative severity.\n\n'
        '[WRITING RULES]\n'
        '- Analyze every supplied finding ID exactly once.\n'
        '- Rewrite scanner narrative into stronger professional wording; do not merely repeat the alert title or verification label.\n'
        '- Python preserves scanner wording as a safety net for empty or materially underdeveloped AI fields, so make each AI narrative field independently complete.\n'
        '- Description: 2 concise sentences, first the weakness/affected input, then the concrete evidence.\n'
        '- Impact: state the security impact demonstrated by the supplied evidence; do not present unobserved damage as if it occurred.\n'
        '- Consequences: explain the realistic damage that exploitation beyond the bounded verification could cause. Clearly distinguish demonstrated effects from potential downstream consequences.\n'
        '- Recovery: give concrete containment/restoration actions that would apply if the described damage occurred, including integrity/log checks, restoration or credential rotation only when relevant; do not claim recovery was required when no damage is evidenced.\n'
        '- Solution: give weakness-specific remediation and an appropriate regression/verification step; avoid generic filler such as "validate input" by itself.\n'
        '- Preserve useful technical facts such as method, parameter, response differential, matcher, payload class, DBMS, browser execution or verifier result when supplied.\n'
        '- Related findings may affect confidence or severity only when they clearly refer to the same weakness or attack chain.\n'
        '- Use high for major demonstrated exploitable impact, medium for meaningful but constrained impact, low for limited impact and info for non-exploitable security context.\n'
        '- Target roughly 30-55 words description, 18-35 impact, 18-40 consequences, 18-45 recovery, 25-50 solution and 8-20 rationale.\n\n'
        '[OUTPUT CONTRACT]\n'
        'Return exactly one JSON object with an analyses array. Each item must contain id, risk, description, impact, consequences, recovery, solution, rationale and confidence. '
        'risk must be critical/high/medium/low/info and confidence high/medium/low.\n\n'
        '[FINAL INSTRUCTION]\n'
        'Return only valid JSON. Do not include chain-of-thought; rationale is a short evidence-based justification.'
    )


# Asks the selected AI provider which exact concrete actions should run next. No tool/capability is
# preselected in normal Agentic mode. Python constructs a valid deduplicated catalog, batches it for
# context size, and applies safety/resource ceilings only after the model has prioritized actions.
def ai_plan(state: AgentState) -> dict[str, Any]:
    """Ask the AI to decide concrete actions, not tools/groups.

    Large catalogs are split into fair concrete-action batches. Every eligible action is presented to
    the AI exactly once in the planning pass. Python never expands a selected tool into hidden
    requests.
    """
    full_concrete_pool = _eligible_action_catalog(state)
    if not full_concrete_pool:
        return {'reasoning_summary': 'No eligible concrete actions.', 'actions': [], 'request_adaptive_extension': False, 'finish': True}

    mode = str(shared.CURRENT_SCAN_MODE or 'balanced')
    eligible_candidate_count = len(full_concrete_pool)
    if mode == 'test' and eligible_candidate_count > TEST_PLANNER_CANDIDATE_LIMIT:
        # TEST is a plumbing/smoke profile, not a coverage profile. Keep one fair interleaved
        # sample across profile/tool buckets so large applications cannot multiply the AI timeout
        # into dozens of planner batches. FAST/BALANCED/DEEP still present every eligible action.
        concrete_pool = _fair_planner_action_order(full_concrete_pool)[:TEST_PLANNER_CANDIDATE_LIMIT]
    else:
        concrete_pool = full_concrete_pool
    batch_size = int(PLANNER_ACTION_BATCH_SIZES.get(mode, 96))
    batches = _planner_action_batches(concrete_pool, batch_size)
    # Stable IDs follow the fair prompt order so diagnostics and batch boundaries are reproducible.
    ordered_pool = [action for batch in batches for action in batch]
    candidate_map = {f'A{index:04d}': action for index, action in enumerate(ordered_pool, 1)}
    id_by_identity = {id(action): candidate_id for candidate_id, action in candidate_map.items()}

    candidate_tools = sorted({str(action.get('tool') or '') for action in concrete_pool})
    registry = {
        name: {'scope': REGISTRY[name][2], 'description': str(REGISTRY[name][3])[:180]}
        for name in candidate_tools if name in REGISTRY
    }
    current_round = int(state.get('round', 0) or 0) + 1
    initial_budget = _round_execution_budget(state, concrete_pool, current_round)
    system_message = _planner_system_message()
    provider = str(state.get('ai_provider') or 'ollama').lower()
    base = state['ollama_url'].rstrip('/')
    planner_timeout_floor = 20 if mode == 'test' else 120
    total_timeout = max(planner_timeout_floor, int(state.get('ai_timeout') or 480))
    max_predict = AI_PLANNER_MAX_PREDICT.get(mode, 800)
    base_context_window = AI_PLANNER_CONTEXT_WINDOWS.get(mode, 6144)
    max_context_window = AI_PLANNER_CONTEXT_WINDOWS_MAX.get(mode, base_context_window)

    selected_ids: list[str] = []
    selected_id_set: set[str] = set()
    selected_priority_by_id: dict[str, int] = {}
    selected_first_seen: dict[str, int] = {}
    selected_actions: list[dict[str, Any]] = []
    reasoning_parts: list[str] = []
    adaptive_requested = False
    endpoint_kinds: list[str] = []
    errors: list[str] = []
    batch_diagnostics: list[dict[str, Any]] = []
    total_context_bytes = 0
    max_context_used = 0
    planning_started = time.monotonic()

    def build_batch_prompt(batch_number: int, batch_count: int, batch: list[dict[str, Any]], selected_count: int) -> dict[str, Any]:
        return {
            'target': state['target'],
            'round': current_round,
            'maximum_rounds': state['max_rounds'],
            'scan_mode': mode,
            'batch_number': batch_number,
            'batch_count': batch_count,
            'batch_size_limit': batch_size,
            'total_concrete_action_candidates': len(concrete_pool),
            'total_eligible_action_candidates': eligible_candidate_count,
            'normal_global_execution_ceiling': int(initial_budget['reference_cap']),
            'adaptive_global_execution_ceiling': int(initial_budget['adaptive_ceiling']),
            'selected_so_far_count': selected_count,
            'discovery_summary': _planner_discovery_summary(state['discovery']),
            'previous_results': compact_results(state['results']),
            'available_tools': registry,
            'candidate_actions': [
                _planner_candidate_view(action, id_by_identity[id(action)])
                for action in batch
            ],
        }

    # 64/96/128 are maxima, not requirements. If unusually rich candidate descriptions make one
    # configured batch exceed the bounded context window, split it until every action still fits.
    # No candidate is dropped and no Python-side attack choice is introduced by this operation.
    while True:
        provisional_count = len(batches)
        rebuilt: list[list[dict[str, Any]]] = []
        split_happened = False
        for provisional_number, batch in enumerate(batches, 1):
            preflight_prompt = build_batch_prompt(provisional_number, provisional_count, batch, 0)
            try:
                _fit_planner_prompt_context(
                    preflight_prompt, system_message,
                    base_context_window=base_context_window,
                    max_context_window=max_context_window,
                    max_predict=max_predict,
                )
            except RuntimeError:
                if len(batch) <= 1:
                    raise
                midpoint = (len(batch) + 1) // 2
                rebuilt.extend((batch[:midpoint], batch[midpoint:]))
                split_happened = True
            else:
                rebuilt.append(batch)
        batches = rebuilt
        if not split_happened:
            break

    effective_batch_size = max((len(batch) for batch in batches), default=0)

    def run_one_batch(batch_number: int, batch: list[dict[str, Any]]) -> tuple[dict[str, Any], str, int, int, str]:
        prompt = build_batch_prompt(batch_number, len(batches), batch, len(selected_ids))
        prompt, context, context_window, candidate_count = _fit_planner_prompt_context(
            prompt, system_message,
            base_context_window=base_context_window,
            max_context_window=max_context_window,
            max_predict=max_predict,
        )
        common_options = {'temperature': 0, 'num_predict': max_predict, 'num_ctx': context_window, 'top_p': 0.9}
        if provider == 'snap4city':
            content = _snap4city_chat_content(
                state, system_message, context, total_timeout=total_timeout, temperature=0.0,
            )
            kind = 'snap4city'
        else:
            chat_payload = {
                'model': state['model'],
                'format': PLAN_SCHEMA,
                'messages': [
                    {'role': 'system', 'content': system_message},
                    {'role': 'user', 'content': context},
                ],
                'options': common_options,
                'keep_alive': '30m',
            }
            try:
                content = _ollama_stream_content(
                    f'{base}/api/chat', chat_payload, response_kind='chat', total_timeout=total_timeout, early_json=True,
                )
                kind = 'chat'
            except Exception as chat_exc:
                errors.append(f'batch {batch_number} chat: {type(chat_exc).__name__}: {chat_exc}')
                generate_payload = {
                    'model': state['model'],
                    'format': PLAN_SCHEMA,
                    'prompt': system_message + '\n\nAssessment context:\n' + context,
                    'options': common_options,
                    'keep_alive': '30m',
                }
                content = _ollama_stream_content(
                    f'{base}/api/generate', generate_payload, response_kind='generate', total_timeout=total_timeout, early_json=True,
                )
                kind = 'generate'
        plan = _parse_ai_plan_content(content)
        return plan, context, context_window, candidate_count, kind

    for batch_number, batch in enumerate(batches, 1):
        batch_started = time.monotonic()
        try:
            compact_plan, context, context_window, candidate_count, kind = run_one_batch(batch_number, batch)
            endpoint_kinds.append(kind)
            total_context_bytes += len(context.encode('utf-8'))
            max_context_used = max(max_context_used, context_window)
            adaptive_requested = adaptive_requested or bool(compact_plan.get('request_adaptive_extension', False))
            valid_batch_ids = {id_by_identity[id(action)] for action in batch}
            raw_priority_rows = compact_plan.get('selected_action_priorities', [])
            priority_map: dict[str, int] = {}
            for row in raw_priority_rows if isinstance(raw_priority_rows, list) else []:
                if not isinstance(row, dict):
                    continue
                candidate_id = str(row.get('id') or '')
                if candidate_id not in valid_batch_ids:
                    continue
                priority_map[candidate_id] = max(0, min(100, int(row.get('priority'))))
            accepted_this_batch: list[str] = []
            for candidate_id in [str(value) for value in compact_plan.get('selected_action_ids', [])]:
                if candidate_id not in valid_batch_ids or candidate_id in selected_id_set:
                    continue
                if candidate_id not in priority_map:
                    raise ValueError(f'AI batch {batch_number} selected {candidate_id} without a priority.')
                selected_id_set.add(candidate_id)
                selected_first_seen[candidate_id] = len(selected_ids)
                selected_priority_by_id[candidate_id] = int(priority_map[candidate_id])
                selected_ids.append(candidate_id)
                selected_actions.append(dict(candidate_map[candidate_id]))
                accepted_this_batch.append(candidate_id)
            reasoning = _humanize_planner_reasoning(compact_plan.get('reasoning_summary'))[:400]
            if reasoning:
                reasoning_parts.append(f'Batch {batch_number}/{len(batches)}: {reasoning}')
            batch_diagnostics.append({
                'batch': batch_number,
                'candidate_count': candidate_count,
                'selected_count': len(accepted_this_batch),
                'selected_action_ids': accepted_this_batch,
                'endpoint': kind,
                'context_bytes': len(context.encode('utf-8')),
                'context_window': context_window,
                'seconds': round(time.monotonic() - batch_started, 2),
                'contract_normalizations': list(compact_plan.get('_contract_normalizations') or []),
            })
        except Exception as exc:
            errors.append(f'batch {batch_number}: {type(exc).__name__}: {exc}')
            # A failed batch means some concrete actions were never judged by the AI. In strict
            # Agentic planning this is a planner failure, not permission for Python to choose them.
            raise RuntimeError('; '.join(errors)) from exc

    # Every batch uses the same AI priority scale. Merge the batch-local selections globally using
    # only priorities returned by the model; technical batch order is a tie-breaker only when the AI
    # assigned equal priority. This prevents an early prompt batch from winning a later execution cap
    # merely because it was evaluated first.
    selected_ids.sort(key=lambda candidate_id: (-selected_priority_by_id[candidate_id], selected_first_seen[candidate_id]))
    selected_actions = [dict(candidate_map[candidate_id]) for candidate_id in selected_ids]

    round_budget = _round_execution_budget(
        state, concrete_pool, current_round, ai_extension_requested=adaptive_requested,
    )
    execution_max = int(round_budget['resolved_max'])
    selected_before_cap = len(selected_actions)
    # Python now applies only the global ceiling to the AI-prioritized sequence. Unadmitted selected
    # actions remain eligible in later rounds because they are not marked completed.
    selected_actions = selected_actions[:execution_max]
    selected_ids_admitted = selected_ids[:execution_max]

    selected_per_profile: dict[str, int] = {}
    available_per_profile: dict[str, int] = {}
    for action in concrete_pool:
        profile = str(action.get('profile') or '')
        available_per_profile[profile] = available_per_profile.get(profile, 0) + 1
    for action in selected_actions:
        profile = str(action.get('profile') or '')
        selected_per_profile[profile] = selected_per_profile.get(profile, 0) + 1
    # Attach stable planner IDs after copying.
    for candidate_id, action in zip(selected_ids_admitted, selected_actions):
        action['planner_action_id'] = candidate_id
        action['reason'] = f"AI selected concrete action {candidate_id}: {str(action.get('reason') or 'discovery-derived candidate')[:420]}"

    LAST_AI_PLAN_DIAGNOSTICS.clear()
    LAST_AI_PLAN_DIAGNOSTICS.update({
        'endpoint': '+'.join(dict.fromkeys(endpoint_kinds)) or 'unknown',
        'context_bytes': total_context_bytes,
        'context_window': max_context_used,
        'candidate_count': len(concrete_pool),
        'eligible_candidate_count': eligible_candidate_count,
        'test_candidate_limit': TEST_PLANNER_CANDIDATE_LIMIT if mode == 'test' else 0,
        'test_candidates_deferred': max(0, eligible_candidate_count - len(concrete_pool)) if mode == 'test' else 0,
        'detailed_candidate_count': len(concrete_pool),
        'candidate_pool_count': len(concrete_pool),
        'concrete_action_pool_count': len(concrete_pool),
        'planner_batch_size': effective_batch_size,
        'planner_configured_batch_size': batch_size,
        'planner_batch_count': len(batches),
        'planner_batches': batch_diagnostics,
        'selected_action_ids': selected_ids_admitted,
        'ai_selected_action_ids_before_cap': selected_ids,
        'ai_selected_action_priorities': {candidate_id: selected_priority_by_id[candidate_id] for candidate_id in selected_ids},
        'admitted_actions_per_profile': selected_per_profile,
        'admitted_action_count': len(selected_actions),
        'available_actions_per_profile': available_per_profile,
        'round_execution_normal_base': int(round_budget['reference_cap']),
        'round_execution_resolved_base': int(round_budget['resolved_base']),
        'round_execution_resolved_max': execution_max,
        'round_execution_overflow_cap': int(round_budget['overflow_cap']),
        'round_execution_configured_normal_max': int(round_budget['reference_cap']),
        'round_execution_reference_ceiling': int(round_budget['reference_cap']),
        'round_execution_adaptive_ceiling': int(round_budget['adaptive_ceiling']),
        'round_execution_active_ceiling': int(round_budget['active_ceiling']),
        'round_execution_adaptive_extension_ai_requested': bool(round_budget.get('adaptive_extension_ai_requested')),
        'round_execution_adaptive_extension_ai_effective': bool(round_budget.get('adaptive_extension_ai_effective')),
        'round_execution_ordinary_remaining': int(round_budget['ordinary_remaining']),
        'round_execution_required_per_round': int(round_budget['required_per_round']),
        'round_execution_remaining_rounds': int(round_budget['remaining_rounds']),
        'expanded_before_global_cap': selected_before_cap,
        'execution_budget_diagnostics_per_profile': {},
        'review_seconds': 0.0,
        'review_error': '',
        'review_reasoning': '',
        'seconds': round(time.monotonic() - planning_started, 2),
        'attempt_errors': list(errors),
    })
    return {
        'reasoning_summary': ' '.join(reasoning_parts)[:1400],
        'actions': selected_actions,
        'request_adaptive_extension': adaptive_requested,
        'initial_request_adaptive_extension': adaptive_requested,
        'review_request_adaptive_extension': False,
        'finish': len(selected_actions) == 0,
    }

# Removes reusable credentials from evidence before it is sent to the selected AI provider.
def _redact_ai_evidence(value: Any) -> str:
    text = str(value or '')
    text = re.sub(r'(?i)(Cookie:\s*)[^\r\n]+', r'\1<redacted>', text)
    text = re.sub(r'(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9._~-]+', r'\1<redacted>', text)
    text = re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', '<redacted-jwt>', text)
    return text

# Builds immutable evidence views while retaining references to the raw findings that AI may enrich.
def _analysis_catalog(results: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    finding_map: dict[str, dict[str, Any]] = {}
    for path, result in iter_leaf_results(results):
        profile = path[0] if path else str(result.get('profile') or 'unknown')
        tool = path[1].split(':', 1)[0] if len(path) > 1 else str(result.get('tool') or 'unknown')
        for finding in result.get('vulnerabilities') or []:
            if not isinstance(finding, dict):
                continue
            category = str(finding.get('category') or '').lower()
            scanner_risk = str(finding.get('risk') or 'info').lower()
            if category not in {'vulnerability', 'candidate'}:
                if category or scanner_risk in {'', 'info'}:
                    continue
                category = 'candidate'
            finding_id = f'F{len(candidates) + 1:03d}'
            finding_map[finding_id] = finding
            candidates.append({
                'id': finding_id,
                'profile': profile,
                'tool': tool,
                'alert': str(finding.get('alert') or '')[:240],
                'scanner_risk': scanner_risk,
                'category': category,
                'verification_status': str(finding.get('verification_status') or '')[:180],
                'verification_confidence': str(finding.get('confidence') or '')[:80],
                'url': str(finding.get('url') or result.get('target') or '')[:500],
                'method': str(finding.get('method') or finding.get('request_method') or '')[:20],
                'parameter': str(finding.get('parameter') or '')[:160],
                'description': _redact_ai_evidence(finding.get('description'))[:650],
                'technical_details': _redact_ai_evidence(finding.get('technical_details') or finding.get('other_information'))[:550],
                'evidence': _redact_ai_evidence(finding.get('evidence'))[:1000],
                'scanner_impact': _redact_ai_evidence(finding.get('impact'))[:550],
                'scanner_consequences': _redact_ai_evidence(
                    finding.get('consequences') or finding.get('damage') or finding.get('potential_damage')
                )[:550],
                'scanner_recovery': _redact_ai_evidence(
                    finding.get('recovery') or finding.get('recovery_actions')
                )[:550],
                'scanner_solution': _redact_ai_evidence(finding.get('solution'))[:550],
                'attack_preconditions': _redact_ai_evidence(finding.get('attack_preconditions') or finding.get('preconditions'))[:320],
                'owasp_category': str(finding.get('owasp_category') or '')[:180],
                'cwe_id': str(finding.get('cwe_id') or '')[:80],
                'cve_ids': [str(value) for value in (finding.get('cve_ids') or [])][:8] if isinstance(finding.get('cve_ids') or [], list) else [],
            })
    return candidates, finding_map

# Parses one structured batch returned by the AI analysis stage.
def _parse_analysis_content(content: str) -> list[dict[str, Any]]:
    raw = str(content or '').strip()
    if raw.startswith('```'):
        raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.IGNORECASE)
        raw = re.sub(r'\s*```$', '', raw)
    first, last = raw.find('{'), raw.rfind('}')
    if first >= 0 and last > first:
        raw = raw[first:last + 1]

    # Structured AI output is normally valid JSON. These two bounded repairs
    # recover common model mistakes without asking the provider to regenerate
    # an otherwise complete answer.
    candidates = [raw, re.sub(r',\s*([}\]])', r'\1', raw)]
    repaired = candidates[-1]
    for _ in range(4):
        try:
            value = json.loads(repaired)
            break
        except json.JSONDecodeError as exc:
            if "Expecting ',' delimiter" not in str(exc) or exc.pos <= 0 or exc.pos >= len(repaired):
                value = None
                break
            before = repaired[:exc.pos]
            after = repaired[exc.pos:]
            next_nonspace = after.lstrip()[:1]
            previous_nonspace = before.rstrip()[-1:] if before.rstrip() else ''
            if next_nonspace not in {'"', '{'} or previous_nonspace not in {'"', '}', ']', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'e', 'l'}:
                value = None
                break
            repaired = before + ',' + after
    else:
        value = None

    if value is None:
        # Re-raise the original parser error so diagnostics still point to the
        # model output rather than to the repair helper.
        value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('AI provider returned an invalid analysis object.')
    rows = value.get('analyses')
    if not isinstance(rows, list):
        raise ValueError('AI provider returned an invalid analysis object.')
    return [dict(row) for row in rows if isinstance(row, dict)]


def _analysis_related_findings(batch: list[dict[str, Any]], all_candidates: list[dict[str, Any]], limit: int=4) -> list[dict[str, Any]]:
    batch_ids = {str(item.get('id') or '') for item in batch}
    batch_urls = {str(item.get('url') or '') for item in batch if item.get('url')}
    batch_parameters = {str(item.get('parameter') or '').lower() for item in batch if item.get('parameter')}
    batch_alerts = {re.sub(r'\s+', ' ', str(item.get('alert') or '').strip().lower()) for item in batch if item.get('alert')}
    ranked: list[tuple[int, dict[str, Any]]] = []
    for item in all_candidates:
        if str(item.get('id') or '') in batch_ids:
            continue
        score = 0
        if str(item.get('url') or '') in batch_urls:
            score += 5
        if str(item.get('parameter') or '').lower() in batch_parameters and item.get('parameter'):
            score += 4
        if re.sub(r'\s+', ' ', str(item.get('alert') or '').strip().lower()) in batch_alerts and item.get('alert'):
            score += 4
        if score:
            ranked.append((score, item))
    ranked.sort(key=lambda pair: (-pair[0], str(pair[1].get('id') or '')))
    return [
        {
            'id': item.get('id'),
            'tool': item.get('tool'),
            'alert': str(item.get('alert') or '')[:120],
            'scanner_risk': item.get('scanner_risk'),
            'category': item.get('category'),
            'verification_status': str(item.get('verification_status') or '')[:90],
            'url': str(item.get('url') or '')[:220],
            'parameter': str(item.get('parameter') or '')[:80],
        }
        for _, item in ranked[:limit]
    ]


AI_ANALYSIS_MIN_WORDS = {'description': 20, 'impact': 12, 'consequences': 12, 'recovery': 12, 'solution': 15, 'rationale': 8}


def _normalize_analysis_enum(raw: Any, field: str) -> tuple[str, bool]:
    """Normalize obvious formatting/synonym drift in bounded AI enum fields."""
    text = re.sub(r'[\s_-]+', ' ', str(raw or '').strip().lower())
    original = text
    if field == 'risk':
        for suffix in (' risk', ' severity'):
            if text.endswith(suffix):
                text = text[:-len(suffix)].strip()
        aliases = {'informational': 'info', 'information': 'info', 'moderate': 'medium', 'med': 'medium'}
        text = aliases.get(text, text)
        valid = {'critical', 'high', 'medium', 'low', 'info'}
    elif field == 'confidence':
        if text.endswith(' confidence'):
            text = text[:-len(' confidence')].strip()
        aliases = {'moderate': 'medium', 'med': 'medium', 'very high': 'high', 'very low': 'low'}
        text = aliases.get(text, text)
        valid = {'high', 'medium', 'low'}
    else:
        raise ValueError(f'Unsupported AI analysis enum field: {field}')
    if text not in valid:
        raise ValueError(f'Analysis returned invalid {field}: {raw!r}.')
    return text, text != original or str(raw or '').strip() != text


def _analysis_quality_check(rows: list[dict[str, Any]], expected: set[str]) -> list[dict[str, Any]]:
    # Validate the AI contract without failing strict mode for weak prose alone.
    # Strict agentic mode still requires a real, parseable AI assessment for every finding.
    # Narrative quality is handled field-by-field later: if the AI returns a materially
    # underdeveloped narrative field and the scanner has a stronger
    # original value, that one field falls back to the scanner text instead of aborting
    # the entire assessment.
    normalized_expected = {str(value).strip() for value in expected if str(value).strip()}
    for row in rows:
        row['id'] = str(row.get('id') or '').strip()
    # Extra/hallucinated rows can be discarded safely when every requested finding is present;
    # Python is not inventing an analysis, only refusing an unsolicited ID. Missing or duplicate
    # requested IDs remain fatal in strict mode because choosing/reconstructing one would invent data.
    extra_ids = sorted({str(row.get('id') or '') for row in rows if str(row.get('id') or '') not in normalized_expected})
    filtered = [row for row in rows if str(row.get('id') or '') in normalized_expected]
    returned_ids = [str(item.get('id') or '') for item in filtered]
    returned = set(returned_ids)
    missing = sorted(normalized_expected - returned)
    duplicates = sorted({value for value in returned_ids if returned_ids.count(value) > 1 and value})
    if missing or duplicates:
        raise ValueError(f'Analysis IDs mismatch; missing={missing}, extra={extra_ids}, duplicates={duplicates}')
    if extra_ids and filtered:
        filtered[0].setdefault('_contract_normalizations', []).append({
            'field': 'analyses.id', 'dropped_extra_ids': extra_ids,
        })
    rows = filtered
    for row in rows:
        risk, risk_changed = _normalize_analysis_enum(row.get('risk'), 'risk')
        confidence, confidence_changed = _normalize_analysis_enum(row.get('confidence'), 'confidence')
        if risk_changed:
            row.setdefault('_contract_normalizations', []).append({'field': 'risk', 'received': row.get('risk'), 'normalized': risk})
        if confidence_changed:
            row.setdefault('_contract_normalizations', []).append({'field': 'confidence', 'received': row.get('confidence'), 'normalized': confidence})
        row['risk'] = risk
        row['confidence'] = confidence
        short_fields: list[str] = []
        for key, minimum in AI_ANALYSIS_MIN_WORDS.items():
            value = str(row.get(key) or '').strip()
            if len(value.split()) < minimum:
                short_fields.append(key)
        if short_fields:
            row['_short_fields'] = short_fields
    return rows


# Runs one evidence-grounded analysis batch with the selected AI provider. Multi-finding failures are split
# immediately; a single finding gets one smaller rescue attempt instead of
# spending the entire batch budget on a second long generation.
def _ai_analysis_batch(state: AgentState, batch: list[dict[str, Any]], all_candidates: list[dict[str, Any]], timeout: int) -> list[dict[str, Any]]:
    system_message = _analysis_system_message()
    mode = shared.CURRENT_SCAN_MODE
    related_findings = [] if mode in {'test', 'fast'} else _analysis_related_findings(batch, all_candidates)
    context = json.dumps({
        'target': state['target'],
        'scan_mode': mode,
        'authenticated_profiles': [profile['name'] for profile in state['profiles'] if _profile_has_effective_auth(state, str(profile.get('name') or ''))],
        'related_findings': related_findings,
        'findings_to_analyze': batch,
    }, ensure_ascii=False, separators=(',', ':'))
    options = {
        'temperature': 0,
        'num_predict': AI_ANALYSIS_MAX_PREDICT.get(mode, 700),
        'num_ctx': AI_ANALYSIS_CONTEXT_WINDOWS.get(mode, 6144),
        'top_p': 0.9,
    }
    provider = str(state.get('ai_provider') or 'ollama').lower()
    base = state['ollama_url'].rstrip('/')
    expected = {str(item['id']) for item in batch}
    started = time.monotonic()
    errors: list[str] = []

    # For a one-finding request, reserve time for a compact rescue. TEST uses much smaller
    # control-plane minima so a diagnostic run cannot inherit the normal 45--60 second retry floors.
    if mode == 'test':
        rescue_reserve = 10
        if len(batch) == 1:
            chat_budget = max(15, min(int(timeout * 0.70), max(15, timeout - rescue_reserve)))
        else:
            chat_budget = max(15, min(int(timeout * 0.70), 30))
    elif len(batch) == 1:
        chat_budget = max(60, min(int(timeout * 0.62), timeout - 45))
    else:
        chat_budget = max(55, min(int(timeout * 0.70), 105))

    try:
        if provider == 'snap4city':
            content = _snap4city_chat_content(
                state, system_message, context,
                total_timeout=chat_budget, temperature=0.0,
            )
        else:
            chat_payload = {
                'model': state['model'], 'format': ANALYSIS_SCHEMA,
                'messages': [{'role': 'system', 'content': system_message}, {'role': 'user', 'content': context}],
                'options': options, 'keep_alive': '30m',
            }
            content = _ollama_stream_content(
                f'{base}/api/chat', chat_payload, response_kind='chat',
                total_timeout=chat_budget, early_json=True,
            )
        return _analysis_quality_check(_parse_analysis_content(content), expected)
    except Exception as exc:
        errors.append(f'chat: {type(exc).__name__}: {exc}')
        if len(batch) > 1:
            raise RuntimeError('; '.join(errors)) from exc

    remaining = max(0, int(timeout - (time.monotonic() - started)))
    rescue_minimum = 8 if mode == 'test' else 40
    if remaining < rescue_minimum:
        raise RuntimeError('; '.join(errors + ['single-finding rescue skipped: analysis budget exhausted']))

    rescue_system = (
        system_message
        + ' This is a single-finding rescue pass. Be concise but complete: 25-40 words for description, '
          '15-28 for impact, 15-30 for consequences, 15-35 for recovery, 22-40 for remediation, and 8-15 for rationale. '
          'Return the normal JSON root object with an analyses array containing exactly one analysis item.'
    )
    rescue_options = {
        **options,
        'num_predict': AI_ANALYSIS_RESCUE_MAX_PREDICT.get(mode, 320),
    }
    try:
        if provider == 'snap4city':
            content = _snap4city_chat_content(
                state, rescue_system, context,
                total_timeout=remaining, temperature=0.0,
            )
        else:
            generate_payload = {
                'model': state['model'], 'format': ANALYSIS_SCHEMA,
                'prompt': rescue_system + '\n\nAnalyze this finding:\n' + context,
                'options': rescue_options, 'keep_alive': '30m',
            }
            content = _ollama_stream_content(
                f'{base}/api/generate', generate_payload, response_kind='generate',
                total_timeout=remaining, early_json=True,
            )
        return _analysis_quality_check(_parse_analysis_content(content), expected)
    except Exception as exc:
        errors.append(f'generate rescue: {type(exc).__name__}: {exc}')
        raise RuntimeError('; '.join(errors)) from exc


# Retries failed multi-finding AI analysis batches by splitting them into smaller
# AI-only batches before a long malformed or timed-out response can fail strict mode.
def _ai_analysis_batch_adaptive(
    state: AgentState,
    batch: list[dict[str, Any]],
    all_candidates: list[dict[str, Any]],
    timeout: int,
    *,
    label: str,
    deadline: float | None = None,
) -> list[dict[str, Any]]:
    # Every retry/split belongs to one original batch budget. Older code restarted the full
    # timeout for each child batch, so a malformed four-finding response could multiply a
    # 900-second Balanced budget across several retries. A shared deadline keeps the whole
    # adaptive tree bounded while still allowing smaller rescue batches.
    if deadline is None:
        deadline = time.monotonic() + max(1, int(timeout))
    remaining = max(0, int(deadline - time.monotonic()))
    attempt_floor = 12 if shared.CURRENT_SCAN_MODE == 'test' else 45
    if remaining < attempt_floor:
        raise TimeoutError(f'{label} exhausted its shared analysis batch budget before another AI attempt could start.')
    try:
        return _ai_analysis_batch(state, batch, all_candidates, remaining)
    except Exception:
        if len(batch) <= 1:
            raise
        midpoint = max(1, len(batch) // 2)
        left = batch[:midpoint]
        right = batch[midpoint:]
        remaining = max(0, int(deadline - time.monotonic()))
        split_floor = 24 if shared.CURRENT_SCAN_MODE == 'test' else 90
        if remaining < split_floor:
            raise
        print(
            f'    AI analysis: {label} did not complete cleanly; retrying as smaller AI batches '
            f'({len(left)} + {len(right)} findings) within the same {timeout}s batch deadline.',
            flush=True,
        )
        rows: list[dict[str, Any]] = []
        # Allocate the first child only its proportional share of the remaining wall-clock time;
        # the second child receives whatever remains under the same parent deadline.
        left_floor = 12 if shared.CURRENT_SCAN_MODE == 'test' else 45
        left_share = max(left_floor, int(remaining * (len(left) / max(1, len(batch)))))
        left_deadline = min(deadline, time.monotonic() + left_share)
        rows.extend(_ai_analysis_batch_adaptive(
            state, left, all_candidates, timeout, label=f'{label}.1', deadline=left_deadline,
        ))
        rows.extend(_ai_analysis_batch_adaptive(
            state, right, all_candidates, timeout, label=f'{label}.2', deadline=deadline,
        ))
        return rows


# Applies the AI narrative as the final report wording while preserving every
# scanner-originating narrative field separately for auditability.
def _apply_analysis(rows: list[dict[str, Any]], finding_map: dict[str, dict[str, Any]], model: str, provider: str) -> tuple[int, int]:
    analyzed = changed = 0
    for row in rows:
        finding_id = str(row.get('id') or '')
        finding = finding_map.get(finding_id)
        risk = str(row.get('risk') or '').lower()
        confidence = str(row.get('confidence') or '').lower()
        if finding is None or risk not in {'critical', 'high', 'medium', 'low', 'info'} or confidence not in {'high', 'medium', 'low'}:
            continue
        original_risk = str(finding.get('risk') or 'info').lower()
        scanner_confidence = str(finding.get('confidence') or '').lower()
        finding.setdefault('scanner_risk', original_risk)
        finding.setdefault('scanner_confidence', scanner_confidence)
        finding.setdefault('scanner_description', str(finding.get('description') or ''))
        finding.setdefault('scanner_impact', str(finding.get('impact') or ''))
        finding.setdefault(
            'scanner_consequences',
            str(finding.get('consequences') or finding.get('damage') or finding.get('potential_damage') or ''),
        )
        finding.setdefault(
            'scanner_recovery',
            str(finding.get('recovery') or finding.get('recovery_actions') or ''),
        )
        finding.setdefault('scanner_solution', str(finding.get('solution') or ''))

        # Deterministic browser evidence constrains confidence, not potential impact.
        # A bounded non-reproduction therefore lowers confidence without rewriting severity.
        confidence_order = {'low': 1, 'medium': 2, 'high': 3}
        browser_outcome = str(finding.get('browser_final_verification') or '').lower()
        verification_status = str(finding.get('verification_status') or '').lower()
        explicit_ceiling = str(finding.get('browser_confidence_ceiling') or '').lower()
        confidence_ceiling = explicit_ceiling if explicit_ceiling in {'low', 'medium'} else None
        if confidence_ceiling is None and (browser_outcome == 'not_reproduced' or verification_status == 'browser-not-reproduced-bounded'):
            confidence_ceiling = 'low'
        elif confidence_ceiling is None and (browser_outcome == 'reflected_not_executed' or verification_status == 'browser-reflection-without-marker-execution'):
            confidence_ceiling = 'medium'
        applied_risk = risk
        # An unresolved scanner candidate may retain its potential severity, but the AI must not
        # raise it above the scanner's severity when the exact-parameter Chromium check did not execute it.
        risk_order = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        candidate_category = str(finding.get('category') or '').lower() == 'candidate'
        browser_unconfirmed = browser_outcome in {'not_reproduced', 'reflected_not_executed'} or verification_status in {
            'browser-not-reproduced-bounded', 'browser-reflection-without-marker-execution'
        }
        if candidate_category and browser_unconfirmed and original_risk in risk_order and risk_order.get(applied_risk, 0) > risk_order[original_risk]:
            applied_risk = original_risk
        applied_confidence = confidence
        if browser_outcome == 'confirmed' or verification_status == 'playwright-browser-marker-executed':
            applied_confidence = 'high'
        elif confidence_ceiling and confidence_order.get(applied_confidence, 0) > confidence_order[confidence_ceiling]:
            applied_confidence = confidence_ceiling
        finding['risk'] = applied_risk
        finding['confidence'] = applied_confidence

        # AI wording remains the primary assessment. A weak individual field does
        # not invalidate a successful AI analysis: when the scanner already has a
        # substantive original value, retain that value only for the weak field.
        short_fields = {str(value) for value in row.get('_short_fields', [])}
        scanner_values = {
            'description': str(finding.get('scanner_description') or '').strip(),
            'impact': str(finding.get('scanner_impact') or '').strip(),
            'consequences': str(finding.get('scanner_consequences') or '').strip(),
            'recovery': str(finding.get('scanner_recovery') or '').strip(),
            'solution': str(finding.get('scanner_solution') or '').strip(),
        }
        narrative_fallbacks: list[str] = []
        for key in ('description', 'impact', 'consequences', 'recovery', 'solution'):
            ai_value = str(row.get(key) or '').strip()
            scanner_value = scanner_values[key]
            if key in short_fields and scanner_value:
                finding[key] = scanner_value[:1800]
                narrative_fallbacks.append(key)
            else:
                finding[key] = (ai_value or scanner_value)[:1800]
                if not ai_value and scanner_value:
                    narrative_fallbacks.append(key)

        finding['ai_analysis'] = {
            'source': f'{provider}-analysis',
            'provider': provider,
            'model': model,
            'risk': applied_risk,
            'ai_requested_risk': risk,
            'scanner_risk': original_risk,
            'severity_changed': applied_risk != original_risk,
            'analysis_confidence': applied_confidence,
            'ai_requested_confidence': confidence,
            'confidence_ceiling': confidence_ceiling or '',
            'scanner_confidence': scanner_confidence,
            'rationale': str(row.get('rationale') or '').strip()[:1000],
            'short_ai_fields': sorted(short_fields),
            'narrative_fallbacks': narrative_fallbacks,
        }
        analyzed += 1
        changed += applied_risk != original_risk
    return analyzed, changed

# After tool execution, the agent performs a separate evidence-grounded analysis of collected findings.
def analysis_node(state: AgentState) -> dict[str, Any]:
    print('\nAI analysis: analyzing collected findings...', flush=True)
    results = copy.deepcopy(state['results'])
    candidates, finding_map = _analysis_catalog(results)
    if not candidates:
        analysis = {'status': 'skipped', 'provider': str(state.get('ai_provider') or 'ollama'), 'model': state['model'], 'analyzed_findings': 0, 'severity_changes': 0, 'errors': [], 'seconds': 0.0}
        print('AI analysis: no confirmed/candidate findings to analyze.', flush=True)
        return {'results': results, 'analysis': analysis}

    started = time.monotonic()
    mode = shared.CURRENT_SCAN_MODE
    total_candidate_findings = len(candidates)
    if mode == 'test' and total_candidate_findings > TEST_ANALYSIS_FINDING_LIMIT:
        # One bounded batch is enough to prove the analysis path and structured-output contract.
        # TEST deliberately leaves the remaining scanner findings untouched for the real profiles.
        candidates = candidates[:TEST_ANALYSIS_FINDING_LIMIT]
    default_batch_budget = AI_ANALYSIS_BATCH_TIMEOUTS.get(mode, 240)
    configured_budget = int(state.get('ai_timeout') or default_batch_budget)
    batch_budget = min(configured_budget, default_batch_budget)
    batch_size = AI_ANALYSIS_BATCH_SIZES.get(mode, 8)
    analyzed = changed = 0
    errors: list[str] = []
    batch_count = (len(candidates) + batch_size - 1) // batch_size
    if batch_budget < 45:
        message = f'analysis batch time budget is too small: {batch_budget}s; minimum is 45s'
        if state.get('require_ai'):
            raise RuntimeError(f'Strict agentic mode requires AI analysis: {message}')
        errors.append(message)
    else:
        for batch_index in range(batch_count):
            batch = candidates[batch_index * batch_size:(batch_index + 1) * batch_size]
            try:
                batch_deadline = time.monotonic() + batch_budget
                rows = _ai_analysis_batch_adaptive(
                    state, batch, candidates, batch_budget,
                    label=f'batch {batch_index + 1}/{batch_count}', deadline=batch_deadline,
                )
                batch_analyzed, batch_changed = _apply_analysis(rows, finding_map, state['model'], str(state.get('ai_provider') or 'ollama'))
                analyzed += batch_analyzed
                changed += batch_changed
                print(f'    AI analysis: batch {batch_index + 1}/{batch_count}: analyzed={batch_analyzed}; severity changes={batch_changed}', flush=True)
            except Exception as exc:
                message = f'batch {batch_index + 1}: {type(exc).__name__}: {exc}'
                errors.append(message)
                if state.get('require_ai'):
                    raise RuntimeError(f'Strict agentic mode requires AI analysis: {message}') from exc
                print(f'    AI analysis: {message}; scanner data retained for this batch.', file=sys.stderr, flush=True)

    analysis = {
        'status': 'success' if not errors else 'partial',
        'provider': str(state.get('ai_provider') or 'ollama'),
        'model': state['model'],
        'candidate_findings': len(candidates),
        'candidate_findings_total': total_candidate_findings,
        'test_finding_limit': TEST_ANALYSIS_FINDING_LIMIT if mode == 'test' else 0,
        'test_findings_deferred': max(0, total_candidate_findings - len(candidates)) if mode == 'test' else 0,
        'analyzed_findings': analyzed,
        'severity_changes': changed,
        'errors': errors,
        'seconds': round(time.monotonic() - started, 2),
        'batch_timeout_seconds': batch_budget,
        'policy': 'AI supplies the final severity and professional description/impact/consequence/recovery/remediation wording; browser verification constrains confidence independently from severity, while original scanner narrative, category, verification status and evidence remain preserved and scanner/verifier-controlled where applicable.',
    }
    print(f"AI analysis: finished; analyzed={analyzed}/{len(candidates)}; severity changes={changed}; {analysis['seconds']:.1f}s", flush=True)
    return {'results': results, 'analysis': analysis}

# Keeps a small result summary that is safe to send back to the planner.
def compact_results(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {profile: {key: {'status': value.get('status'), 'target': value.get('target'), 'findings': len(value.get('vulnerabilities') or []), 'diagnosis': value.get('diagnosis'), 'output': str(value.get('output', ''))[:250]} for key, value in values.items() if isinstance(value, dict)} for profile, values in results.items()}

# Before planning, discovery gathers the real pages, forms, and request cases available on the target.
def discovery_node(state: AgentState) -> dict[str, Any]:
    active_profiles = ', '.join(str(profile.get('name') or '') for profile in state['profiles']) or 'none'
    print(f'\n[*] Discovery of active profiles: {active_profiles}')
    discovery, diagnostics = ({}, list(state['diagnostics']))
    for profile in state['profiles']:
        state_changes_allowed = shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes'))
        found = discover_target_sync_safe(
            state['target'], profile['cookies'],
            seeds=list(state.get('discovery_seeds') or []),
            forced_seeds=list(state.get('entry_points') or []),
            allow_state_changes=state_changes_allowed,
        )
        if profile.get('cookies') and found.get('authentication_effective') is not False:
            found = shared.authenticate_discovered_sibling_origins(found, state['target'], profile['cookies'], allow_state_changes=state_changes_allowed)
        discovery[profile['name']] = found
        diagnostics.extend(({'phase': 'discovery', 'profile': profile['name'], **item} for item in found['errors']))
        print(f"    {profile['name']}: {len(found.get('html_urls', []))} HTML pages, {len(found.get('request_cases', []))} request contracts, {len(found.get('browser_network_requests', []))} browser network requests, {len(found.get('browser_navigation_urls', []))} Chromium navigations, {len(found['jwt_tokens'])} JWTs")
        budget = found.get('budget_diagnostics', {})
        dead_count = int(budget.get('dead_http_404_410', 0) or 0)
        if dead_count:
            print(f"      [DISCOVERY] {dead_count} HTTP 404/410 responses kept as diagnostics and excluded from the useful-page budget; HTTP attempts={budget.get('http_requests_attempted', 0)}/{budget.get('http_attempt_budget', 0)}")
        http_pages = int(budget.get('http_pages_processed', 0) or 0)
        http_page_budget = int(budget.get('http_page_budget', 0) or 0)
        http_page_max_budget = int(budget.get('http_page_max_budget', http_page_budget) or http_page_budget)
        http_overflow = int(budget.get('http_adaptive_overflow_used', 0) or 0)
        http_remaining = int(budget.get('http_remaining_candidates', 0) or 0)
        if http_overflow:
            print(f"      [DISCOVERY] HTTP adaptive useful-page budget: base={http_page_budget}, overflow={http_overflow}, processed={http_pages}/{http_page_max_budget}.")
        if http_remaining and budget.get('http_page_max_budget_saturated'):
            print(f"      [DISCOVERY] HTTP useful-page max budget saturated: {http_pages}/{http_page_max_budget}; {http_remaining} queued candidate(s) remain.")
        elif http_remaining and budget.get('http_page_budget_saturated') and not http_overflow:
            print(f"      [DISCOVERY] HTTP useful-page base budget reached: {http_pages}/{http_page_budget}; adaptive ranking stopped before the max {http_page_max_budget}; {http_remaining} queued candidate(s) remain.")
        elif http_remaining and budget.get('http_attempt_budget_saturated'):
            print(f"      [DISCOVERY] HTTP attempt budget saturated: {budget.get('http_requests_attempted', 0)}/{budget.get('http_attempt_budget', 0)}; {http_remaining} queued candidate(s) remain.")
        browser_budget = int(budget.get('browser_page_budget', 0) or 0)
        browser_max_budget = int(budget.get('browser_page_max_budget', browser_budget) or browser_budget)
        browser_attempted = int(budget.get('browser_pages_attempted', len(found.get('browser_navigation_urls', []))) or 0)
        browser_overflow = int(budget.get('browser_adaptive_overflow_used', 0) or 0)
        browser_remaining = int(budget.get('browser_remaining_candidates', 0) or 0)
        if browser_overflow:
            print(f"      [DISCOVERY] Chromium adaptive navigation budget: base={browser_budget}, overflow={browser_overflow}, attempted={browser_attempted}/{browser_max_budget}.")
        if browser_remaining and browser_attempted >= browser_max_budget:
            print(f"      [DISCOVERY] Chromium navigation max budget saturated: {browser_attempted}/{browser_max_budget}; {browser_remaining} queued candidate(s) remain.")
        script_done = int(budget.get('scripts_processed', 0) or 0)
        script_budget = int(budget.get('script_budget', 0) or 0)
        script_attempts = int(budget.get('script_requests_attempted', 0) or 0)
        script_attempt_budget = int(budget.get('script_attempt_budget', 0) or 0)
        script_deferred = int(budget.get('script_candidates_deferred', 0) or 0)
        if script_deferred:
            print(
                f"      [DISCOVERY] JavaScript budget: inspected={script_done}/{script_budget}; "
                f"attempts={script_attempts}/{script_attempt_budget}; deferred={script_deferred}."
            )
        route_skipped = int(budget.get('route_variants_skipped', 0) or 0)
        if route_skipped:
            print(f"      [DISCOVERY] Anti-saturation route variants omitted: {route_skipped}; per-shape limit={budget.get('route_variant_limit', 0)}.")
        browser_warning = shared.chromium_discovery_warning(found)
        if browser_warning:
            print(f"      [BROWSER WARNING] {browser_warning}")
        for error in shared.prioritized_discovery_errors(found.get('errors', []))[:5]:
            print(f"      [DISCOVERY WARNING] {error.get('type', 'error')}: {shared.compact_log_url(error.get('url', ''))} — {error.get('message', '')}")
        if found.get('authentication_effective') is False:
            print(f"    [WARNING] {profile['name']}: {found.get('authentication_note')}", file=sys.stderr)
    broad_profile = next((str(profile.get('name') or '') for profile in state['profiles'] if str(profile.get('name') or '') == 'anonymous'), '')
    if not broad_profile:
        broad_profile = next((str(profile.get('name') or '') for profile in state['profiles'] if str(profile.get('name') or '')), '')
    if broad_profile and broad_profile in discovery:
        sibling_selection = shared.select_sibling_broad_origins(discovery[broad_profile], state['target'])
        sibling_ranking = sibling_selection['ranking']
        if sibling_ranking:
            print(
                f"    [DISCOVERY] Agentic sibling-origin catalog ({shared.CURRENT_SCAN_MODE}): "
                f"authorized_observed_origins={len(sibling_ranking)}; each origin is exposed as a concrete "
                "ZAP/Nuclei/Nikto action when its profile/session is valid. Execution ceilings are applied after AI prioritization."
            )
    return {'discovery': discovery, 'diagnostics': diagnostics}


# Returns how many concrete actions of one profile/tool have already completed. Kept for coverage
# accounting only; candidate visibility must not depend on the AI having selected earlier actions.
def _completed_tool_action_count(state: AgentState, profile_name: str, tool: str) -> int:
    prefix = f"{profile_name}|{str(tool or '').lower()}|"
    return sum(1 for identifier in state.get('completed', []) if str(identifier).startswith(prefix))


# Agentic catalog selectors enumerate the complete structurally eligible surface. Prompt
# size is controlled by planner batching and execution ceilings apply after AI prioritization.

def _completed_sibling_origins(state: AgentState, profile_name: str, tool: str) -> set[str]:
    result: set[str] = set()
    prefix = f"{profile_name}|{str(tool or '').lower()}|"
    primary = str(state.get('target') or '')
    for identifier in state.get('completed', []):
        text = str(identifier)
        if not text.startswith(prefix):
            continue
        parts = text.split('|', 4)
        if len(parts) < 3:
            continue
        target_url = parts[2]
        if target_url and not shared.same_origin(primary, target_url):
            origin = shared.normalized_origin(target_url)
            if origin:
                result.add(origin)
    return result


# Selects a fresh broad-sibling page for one tool. Authenticated pages are ranked only among origins
# where the stored browser cookie is valid for a concrete application URL, so no unauthenticated
# sibling can consume an authenticated broad slot.
def _agentic_sibling_selection(state: AgentState, profile_name: str, tool: str) -> tuple[dict[str, Any], dict[str, str]]:
    found = state.get('discovery', {}).get(profile_name, {})
    raw_cookie = _profile_cookie(state, profile_name)
    authenticated = _profile_has_effective_auth(state, profile_name)
    authenticated_targets: dict[str, str] = {}
    allowed_origins: set[str] | None = None
    if authenticated:
        for origin, _ in shared.discovered_scope_origin_ranking(found, state['target']):
            target_url = shared.authenticated_broad_target(found, origin, raw_cookie)
            if target_url:
                authenticated_targets[origin] = target_url
        allowed_origins = set(authenticated_targets)
    selection = shared.select_sibling_broad_origins(
        found,
        state['target'],
        allowed_origins=allowed_origins,
        exclude_origins=_completed_sibling_origins(state, profile_name, tool),
    )
    return selection, authenticated_targets

# Discovery evidence is converted into tool actions that the planner can safely choose.
def discovery_candidate_actions(state: AgentState) -> list[dict[str, Any]]:

    actions: list[dict[str, Any]] = []
    state_changes_allowed = shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes'))
    for profile in state['profiles']:
        name = profile['name']
        if not _profile_is_plannable(state, name):
            continue
        authenticated = _profile_has_effective_auth(state, name)
        broad = list(shared.broad_tool_order(authenticated))
        for tool in broad:
            actions.append({'profile': name, 'tool': tool, 'target_url': state['target'], 'jwt_token': '', 'injection_url': '', 'reason': 'Session-aware broad coverage candidate for AI selection.'})
        anonymous_available = any(
            str(item.get('name') or '') == 'anonymous' and _profile_is_plannable(state, 'anonymous')
            for item in state['profiles']
        )
        # The primary raw Cookie header is never copied to siblings. A sibling broad scan is repeated
        # under the authenticated profile only when runtime OIDC/SSO established an independent cookie
        # for that exact origin; otherwise the existing anonymous scan remains the single no-cookie run.
        raw_profile_cookie = _profile_cookie(state, name)
        for tool in ('zap', 'nuclei', 'nikto'):
            sibling_selection, authenticated_targets = _agentic_sibling_selection(state, name, tool)
            for sibling_origin, sibling_score in sibling_selection.get('ranking', sibling_selection.get('selected', [])):
                broad_target = authenticated_targets.get(sibling_origin, sibling_origin)
                sibling_cookie = shared.scope_cookie_header(broad_target, raw_profile_cookie)
                if authenticated and not sibling_cookie:
                    continue
                reason = (
                    'Ranked broad authenticated coverage using a runtime OIDC/SSO session that is valid for the concrete application URL.'
                    if sibling_cookie else
                    'Ranked broad no-cookie coverage for a high-value explicitly authorized sibling origin observed during discovery.'
                )
                actions.append({
                    'profile': name,
                    'tool': tool,
                    'target_url': broad_target,
                    'jwt_token': '',
                    'injection_url': '',
                    'sibling_broad': True,
                    'sibling_origin_score': sibling_score,
                    'reason': reason,
                })
        for case in select_arjun_request_cases(state['discovery'].get(name, {}), state['target'], allow_state_changes=state_changes_allowed, agentic_catalog=True):
            adaptive = bool(case.get('adaptive_budget'))
            actions.append({'profile': name, 'tool': 'arjun', 'target_url': case['url'], 'method': case.get('method', 'GET'), 'data': case.get('data', ''), 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': '', 'adaptive_budget': adaptive, 'priority_score': case.get('priority_score'), 'reason': ('Discovery ranking marked this as an adaptive high-value candidate; AI still decides execution. ' if adaptive else '') + 'Hidden-parameter discovery using the real request method and body.'})
        for tool in ('sqlmap', 'dalfox', 'commix', 'traversal', 'idor'):
            for case in select_tool_request_cases(state['discovery'].get(name, {}), tool, authenticated_profile=authenticated, allow_state_changes=state_changes_allowed, credential_cookies=_profile_cookie(state, name), agentic_catalog=True):
                adaptive = bool(case.get('adaptive_budget'))
                coverage_reserve = bool(case.get('coverage_reserve'))
                prefix = f'Discovery ranking marked this as an adaptive high-value candidate for {tool}; AI still decides execution. ' if adaptive else 'Discovery marked this as a routing-value traversal/LFI candidate; AI still decides execution. ' if coverage_reserve else ''
                actions.append({'profile': name, 'tool': tool, 'target_url': case['url'], 'method': case.get('method', 'GET'), 'data': case.get('data', ''), 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': '', 'adaptive_budget': adaptive, 'coverage_reserve': coverage_reserve, 'priority_score': case.get('priority_score'), 'reason': prefix + f'Concrete discovered request candidate for {tool}.'})
        if authenticated:
            raw_cookie = _profile_cookie(state, name)
            for case in select_authorization_request_cases(state['discovery'].get(name, {}), agentic_catalog=True):
                if (not state_changes_allowed) and shared.request_case_state_change_reason(case):
                    continue
                case_url = str(case.get('url') or '')
                if not (shared.scope_cookie_header(case_url, raw_cookie) or shared.runtime_target_auth_available(raw_cookie, case_url)):
                    continue
                adaptive = bool(case.get('adaptive_budget'))
                actions.append({'profile': name, 'tool': 'authorization', 'target_url': case['url'], 'method': 'GET', 'data': '', 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': '', 'adaptive_budget': adaptive, 'priority_score': case.get('priority_score'), 'reason': ('Discovery ranking marked this as an adaptive high-value authorization candidate; AI still decides execution. ' if adaptive else '') + 'Read-only authorization differential candidate derived from an identity, object or privileged-resource signal.'})
        for case in select_browser_request_cases(state['discovery'].get(name, {}), agentic_catalog=True):
            if (not state_changes_allowed) and shared.request_case_state_change_reason(case):
                continue
            actions.append({'profile': name,
                'tool': 'browser',
                'target_url': case['url'],
                'method': case.get('method', 'GET'),
                'data': case.get('data', ''),
                'parameters': case.get('parameters', []),
                'jwt_token': '',
                'injection_url': '',
                'fields': case.get('fields', []),
                'source_url': case.get('source_url', ''),
                'client_sources': case.get('client_sources', []),
                'client_sinks': case.get('client_sinks', []),
                'adaptive_budget': bool(case.get('adaptive_budget')),
                'priority_score': case.get('priority_score'),
                'reason': ('Discovery ranking marked this as an adaptive high-value candidate; AI still decides execution. ' if case.get('adaptive_budget') else '') + 'Browser verification candidate derived from XSS-like parameters or client-side source/sink evidence.'})
        for case in select_workflow_request_cases(state['discovery'].get(name, {}), agentic_catalog=True):
            if (not state_changes_allowed) and shared.request_case_state_change_reason(case):
                continue
            actions.append({'profile': name,
                'tool': 'workflow',
                'target_url': case['url'],
                'method': case.get('method', 'POST'),
                'data': case.get('data', ''),
                'parameters': case.get('parameters', []),
                'jwt_token': '',
                'injection_url': '',
                'source_url': case.get('source_url', ''),
                'fields': case.get('fields', []),
                'file_parameters': case.get('file_parameters', []),
                'token_parameters': case.get('token_parameters', []),
                'enctype': case.get('enctype', ''),
                'adaptive_budget': bool(case.get('adaptive_budget')),
                'priority_score': case.get('priority_score'),
                'reason': ('Discovery ranking marked this as an adaptive high-value candidate; AI still decides execution. ' if case.get('adaptive_budget') else '') + 'Multi-step workflow candidate derived from discovered form metadata.'})
        tokens = list(dict.fromkeys(str(value) for value in state['discovery'].get(name, {}).get('jwt_tokens', []) if str(value)))
        for token in tokens:
            actions.append({'profile': name, 'tool': 'jwt', 'target_url': state['target'], 'jwt_token': token, 'injection_url': '', 'reason': 'Discovered JWT candidate exposed as a concrete AI action.'})
        if state['injection_url']:
            actions.append({'profile': name, 'tool': 'interactsh', 'target_url': state['target'], 'method': 'GET', 'data': '', 'parameters': ['explicit'], 'jwt_token': '', 'injection_url': state['injection_url'], 'oast_class': 'explicit', 'reason': 'Configured OAST URL.'})
        else:
            for case in select_oast_request_cases(state['discovery'].get(name, {}), state['target'], allow_state_changes=state_changes_allowed, agentic_catalog=True):
                actions.append({'profile': name, 'tool': 'interactsh', 'target_url': state['target'], 'method': case.get('method', 'GET'), 'data': case.get('data', ''), 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': case.get('injection_url', ''), 'oast_class': case.get('oast_class', 'remote-fetch'), 'reason': f"Discovered OAST-capable candidate parameter: {case.get('parameter', 'unknown')}."})
    return _dedupe_no_cookie_profile_actions(state, actions)

# Planner validation compares proposed actions with target scope, discovery evidence, and safety rules.
def validate_plan(state: AgentState, proposed: Any, *, enforce_execution_limits: bool = True) -> list[dict[str, Any]]:
    if not isinstance(proposed, list):
        return []
    profiles = {profile['name'] for profile in state['profiles']}
    completed, valid = (set(state['completed']), [])
    per_tool: dict[tuple[str, str], int] = {}
    proposal_limit = max(512, PROFILE_EXECUTION_ACTION_BUDGETS.get(shared.CURRENT_SCAN_MODE, 20) * max(1, len(state.get('profiles', []))) * 8)
    # Candidate-catalog validation must not silently hide otherwise valid actions before the AI sees them.
    # Execution limits are applied only to the AI-selected list, in the priority order returned by the model.
    proposal_rows = proposed[:proposal_limit] if enforce_execution_limits else proposed
    for raw in proposal_rows:
        if not isinstance(raw, dict):
            continue
        profile, tool = (str(raw.get('profile', '')), str(raw.get('tool', '')).lower())
        if profile not in profiles or tool not in REGISTRY or not _profile_is_plannable(state, profile):
            continue
        profile_has_cookie = _profile_has_effective_auth(state, profile)
        found = state['discovery'].get(profile, {})
        target_url = str(raw.get('target_url', '')).strip()
        token = str(raw.get('jwt_token', '')).strip()
        injection = str(raw.get('injection_url', '')).strip()
        method = str(raw.get('method', '')).upper().strip()
        data = ''
        parameters: list[str] = []
        source_url = ''
        fields: list[dict[str, Any]] = []
        client_sources: list[str] = []
        client_sinks: list[str] = []
        file_parameters: list[str] = []
        token_parameters: list[str] = []
        enctype = ''
        selected: dict[str, Any] = {}
        oast_class = str(raw.get('oast_class') or '')
        scope = REGISTRY[tool][2]
        if scope == 'base':
            if tool in {'ffuf', 'session'}:
                target_url = state['target']
            else:
                if (not target_url) or shared.same_origin(state['target'], target_url):
                    target_url = state['target']
                else:
                    normalized_target = shared.normalized_origin(target_url)
                    sibling_selection, authenticated_targets = _agentic_sibling_selection(state, profile, tool)
                    sibling_origins = {origin for origin, _ in sibling_selection.get('ranking', sibling_selection.get('selected', []))}
                    if normalized_target not in sibling_origins:
                        continue
                    # Preserve the concrete path where a path-scoped browser cookie is applicable.
                    # Normalizing an authenticated sibling back to the bare origin can turn a valid
                    # session into a false authentication_precheck_failed result.
                    target_url = authenticated_targets.get(normalized_target, normalized_target)
        elif scope == 'url':
            cases = select_arjun_request_cases(found, state['target'], allow_state_changes=shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')), agentic_catalog=True)
            matching = [case for case in cases if str(case.get('url', '')) == target_url]
            if method:
                matching = [case for case in matching if str(case.get('method', 'GET')).upper() == method]
            if not matching:
                continue
            selected = matching[0]
            method = str(selected.get('method', 'GET')).upper()
            data = str(selected.get('data', ''))
            parameters = [str(value) for value in selected.get('parameters', [])]
        elif scope in {'parameterized', 'numeric'}:
            cases = select_tool_request_cases(found, tool, authenticated_profile=profile_has_cookie, allow_state_changes=shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')), credential_cookies=_profile_cookie(state, profile), agentic_catalog=True)
            matching = [case for case in cases if str(case.get('url', '')) == target_url]
            if method:
                matching = [case for case in matching if str(case.get('method', 'GET')).upper() == method]
            if not matching:
                continue
            selected = matching[0]
            raw_profile_cookie = _profile_cookie(state, profile)
            selected_url = str(selected.get('url') or '')
            selected_cookie = shared.scope_cookie_header(selected_url, raw_profile_cookie)
            can_refresh_identity = bool(raw_profile_cookie and shared.runtime_target_auth_available(raw_profile_cookie, selected_url))
            if shared.tool_case_hard_skip_reason(tool, selected):
                continue
            if (not shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes'))) and shared.request_case_state_change_reason(selected):
                continue
            method = str(selected.get('method', 'GET')).upper()
            data = str(selected.get('data', ''))
            parameters = [str(value) for value in selected.get('parameters', [])]
            if scope == 'numeric' and (method != 'GET' or not any((value.isdigit() for _, value in parse_qsl(urlparse(target_url).query, keep_blank_values=True)))):
                continue
        elif scope == 'authorization':
            raw_profile_cookie = _profile_cookie(state, profile)
            if not profile_has_cookie or not (shared.scope_cookie_header(target_url, raw_profile_cookie) or shared.runtime_target_auth_available(raw_profile_cookie, target_url)):
                continue
            cases = select_authorization_request_cases(found, agentic_catalog=True)
            matching = [case for case in cases if str(case.get('url', '')) == target_url]
            if not matching:
                continue
            selected = matching[0]
            if (not shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes'))) and shared.request_case_state_change_reason(selected):
                continue
            method = 'GET'
            data = ''
            parameters = [str(value) for value in selected.get('parameters', [])]
        elif scope == 'browser':
            cases = select_browser_request_cases(found, agentic_catalog=True)
            matching = [case for case in cases if str(case.get('url', '')) == target_url]
            if method:
                matching = [case for case in matching if str(case.get('method', 'GET')).upper() == method]
            if not matching:
                continue
            selected = matching[0]
            if (not shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes'))) and shared.request_case_state_change_reason(selected):
                continue
            method = str(selected.get('method', 'GET')).upper()
            data = str(selected.get('data', ''))
            parameters = [str(value) for value in selected.get('parameters', [])]
            source_url = str(selected.get('source_url', ''))
            fields = [dict(value) for value in selected.get('fields', []) if isinstance(value, dict)]
            client_sources = [str(value) for value in selected.get('client_sources', []) if str(value)]
            client_sinks = [str(value) for value in selected.get('client_sinks', []) if str(value)]
        elif scope == 'workflow':
            cases = select_workflow_request_cases(found, agentic_catalog=True)
            matching = [case for case in cases if str(case.get('url', '')) == target_url]
            if method:
                matching = [case for case in matching if str(case.get('method', 'POST')).upper() == method]
            if not matching:
                continue
            selected = matching[0]
            method = str(selected.get('method', 'POST')).upper()
            data = str(selected.get('data', ''))
            parameters = [str(value) for value in selected.get('parameters', [])]
            source_url = str(selected.get('source_url', ''))
            fields = [dict(value) for value in selected.get('fields', []) if isinstance(value, dict)]
            file_parameters = [str(value) for value in selected.get('file_parameters', [])]
            token_parameters = [str(value) for value in selected.get('token_parameters', [])]
            enctype = str(selected.get('enctype', ''))
        elif scope == 'jwt':
            if token not in set(found.get('jwt_tokens') or []):
                continue
            target_url = state['target']
        elif scope == 'oast':
            target_url = state['target']
            if state['injection_url']:
                injection = state['injection_url']
                method = 'GET'
                data = ''
                parameters = ['explicit']
                oast_class = 'explicit'
            else:
                candidates = select_oast_request_cases(found, state['target'], allow_state_changes=shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')), agentic_catalog=True)
                matching = [item for item in candidates if not injection or item.get('injection_url') == injection]
                if not matching:
                    continue
                selected = matching[0]
                injection = str(selected.get('injection_url', ''))
                method = str(selected.get('method', 'GET')).upper()
                data = str(selected.get('data', ''))
                parameters = [str(value) for value in selected.get('parameters', [])]
                oast_class = str(selected.get('oast_class') or 'remote-fetch')
        action = {'profile': profile, 'tool': tool, 'target_url': target_url, 'method': method or 'GET', 'data': data, 'parameters': parameters, 'source_url': source_url, 'fields': fields, 'client_sources': client_sources, 'client_sinks': client_sinks, 'file_parameters': file_parameters, 'token_parameters': token_parameters, 'enctype': enctype, 'jwt_token': token, 'injection_url': injection, 'oast_class': oast_class, 'adaptive_budget': bool(selected.get('adaptive_budget')), 'coverage_reserve': bool(selected.get('coverage_reserve') or raw.get('coverage_reserve')), 'priority_score': selected.get('priority_score'), 'sibling_broad': bool(raw.get('sibling_broad')), 'sibling_origin_score': raw.get('sibling_origin_score'), 'reason': str(raw.get('reason', ''))[:500] or 'No planner reason supplied.'}
        identifier = action_id(action)
        key = (profile, tool)
        if enforce_execution_limits:
            limit = shared.tool_action_limit(tool, include_adaptive=True)
            if per_tool.get(key, 0) >= limit:
                continue
        if identifier not in completed and all((action_id(item) != identifier for item in valid)):
            valid.append(action)
            if enforce_execution_limits:
                per_tool[key] = per_tool.get(key, 0) + 1
    return valid

# Lists the actions that are currently valid for the planner.
# --only-tool is a debug filter only: when unset, the autonomous candidate set is unchanged.
def _eligible_action_catalog(state: AgentState) -> list[dict[str, Any]]:
    actions = validate_plan(state, discovery_candidate_actions(state), enforce_execution_limits=False)
    only_tool = str(state.get('only_tool') or '').strip().lower()
    if only_tool:
        actions = [action for action in actions if str(action.get('tool') or '').lower() == only_tool]
    return actions

# Emergency fallback is used only when AI planning fails and --require-ai is not active. It is not
# part of normal Agentic decision-making: no tool is mandatory here either. The fallback simply uses
# the same discovery-derived eligible pool, tool execution ranking and fair global concrete-action
# ceiling so a non-strict run can still finish without fabricating scope or bypassing safety rules.
def _fallback_plan(state: AgentState, eligible: list[dict[str, Any]], budget_total: int) -> list[dict[str, Any]]:
    maximum = max(0, int(budget_total))
    if maximum <= 0:
        return []
    authenticated = {str(profile.get('name') or ''): _profile_has_effective_auth(state, str(profile.get('name') or '')) for profile in state['profiles']}
    ordered = sorted(
        eligible,
        key=lambda action: (
            shared.tool_execution_rank(str(action.get('tool') or ''), authenticated.get(str(action.get('profile') or ''), False)),
            str(action.get('profile') or ''),
            str(action.get('tool') or ''),
            str(action.get('target_url') or ''),
        ),
    )
    return _fair_global_action_cap(ordered, maximum)


# Pending-action filtering keeps only valid actions that have not run yet.
def _remaining_eligible_actions(state: AgentState) -> list[dict[str, Any]]:
    actions = validate_plan(state, discovery_candidate_actions(state), enforce_execution_limits=False)
    only_tool = str(state.get('only_tool') or '').strip().lower()
    if only_tool:
        actions = [action for action in actions if str(action.get('tool') or '').lower() == only_tool]
    return actions

# Result lookup avoids scheduling a tool that already produced output for the same profile.
def _has_tool_result(profile_results: dict[str, Any], tool: str) -> bool:
    return any((key == tool or key.startswith(f'{tool}:') for key, value in profile_results.items() if isinstance(value, dict)))

# Explains why an expected tool action cannot be created.
def _missing_tool_reason(state: AgentState, profile_name: str, tool: str) -> str:
    found = state['discovery'].get(profile_name, {})
    if not _profile_is_plannable(state, profile_name):
        return 'Authenticated session was conclusively invalid during discovery; this action was not eligible for authenticated coverage.'
    profile_has_cookie = _profile_has_effective_auth(state, profile_name)
    if tool in BROAD_COVERAGE_TOOLS:
        return ''
    if tool == 'arjun':
        return '' if select_arjun_request_cases(found, state['target'], limit=1, allow_state_changes=shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')), agentic_catalog=True) else 'No suitable discovered GET/POST request was available for hidden-parameter discovery.'
    if tool in PARAMETER_COVERAGE_TOOLS:
        return '' if select_tool_request_cases(found, tool, limit=1, authenticated_profile=profile_has_cookie, allow_state_changes=shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')), credential_cookies=_profile_cookie(state, profile_name), agentic_catalog=True) else f"No discovered policy-eligible request matched {tool}'s vulnerability class."
    if tool == 'authorization':
        if not profile_has_cookie:
            return 'Authorization comparison requires a primary authenticated profile.'
        raw_cookie = _profile_cookie(state, profile_name)
        credentialed_cases = [
            case for case in select_authorization_request_cases(found, agentic_catalog=True)
            if shared.scope_cookie_header(str(case.get('url') or ''), raw_cookie)
            or (raw_cookie and shared.runtime_target_auth_available(raw_cookie, str(case.get('url') or '')))
        ]
        return '' if credentialed_cases else 'No identity-applicable exact-origin read-only request contained a plausible identity, object or privileged-resource signal.'
    if tool == 'browser':
        return '' if select_browser_request_cases(found, limit=1, agentic_catalog=True) else 'No discovered request or client-side page matched browser XSS verification.'
    if tool == 'workflow':
        return '' if select_workflow_request_cases(found, limit=1, agentic_catalog=True) else 'No discovered POST form matched CSRF, upload, authentication or CAPTCHA workflow classes.'
    if tool == 'jwt':
        return '' if found.get('jwt_tokens') else 'No JWT was discovered in crawled responses.'
    if tool == 'interactsh':
        if state.get('injection_url') or select_oast_request_cases(found, state['target'], limit=1, allow_state_changes=shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')), agentic_catalog=True):
            return ''
        return 'No discovered OAST-capable input was available.'
    return ''

# Records valid actions that the planner chose not to run.
def _materialize_unselected_actions(state: AgentState) -> dict[str, dict[str, Any]]:
    results = {profile: dict(values) for profile, values in state['results'].items()}
    for profile in state['profiles']:
        name = profile['name']
        profile_results = results.setdefault(name, {})
        for tool in REGISTRY:
            if _has_tool_result(profile_results, tool):
                continue
            reason = _missing_tool_reason(state, name, tool)
            if reason:
                profile_results[tool] = make_skipped_result(tool, state['target'], reason)
            else:
                profile_results[tool] = {'tool': tool, 'status': 'skipped', 'target': state['target'], 'output': 'The action was applicable but was not selected by the agentic planner; other discovery-derived actions were prioritized within the configured budget.', 'diagnosis': 'agentic_deferred_by_planner', 'timed_out': False, 'vulnerabilities': []}
    return results

# Planner auditing records a concise summary of each proposed action.
def _audit_action_summary(action: dict[str, Any]) -> dict[str, Any]:

    return {'planner_action_id': str(action.get('planner_action_id') or ''), 'profile': str(action.get('profile') or ''), 'tool': str(action.get('tool') or ''), 'target_url': str(action.get('target_url') or ''), 'method': str(action.get('method') or 'GET'), 'parameters': [str(value) for value in action.get('parameters', [])][:12], 'reason': str(action.get('reason') or '')[:500]}

# At each planning round, the model proposes useful actions and validation filters unsafe or unsupported choices.
def planner_node(state: AgentState) -> dict[str, Any]:
    round_number = state['round'] + 1
    notes = list(state['notes'])
    audit = list(state.get('planner_audit', []))
    eligible = _eligible_action_catalog(state)
    if not eligible:
        notes.append(f'Round {round_number}: no eligible discovery-derived actions remain; no AI concrete-action selection call was required.')
        audit.append({
            'round': round_number,
            'planner_source': 'no_eligible_actions',
            'planner_endpoint': 'not_required',
            'context_bytes': 0,
            'context_window': 0,
            'eligible_action_count': 0,
            'planner_candidate_pool_count': 0,
            'planner_candidate_count': 0,
            'planner_detailed_candidate_count': 0,
            'concrete_action_pool_count': 0,
                        'eligible_tools': [],
            'selected_action_count': 0,
            'validated_concrete_action_count': 0,
            'selected_actions': [],
            'reasoning_summary': 'No eligible discovery-derived actions remain.',
        })
        return {
            'plan': [], 'round': round_number, 'notes': notes, 'finished': True,
            'planner_source': 'no_eligible_actions', 'planner_audit': audit,
        }
    round_budget = _round_execution_budget(state, eligible, round_number)
    normal_round_base = int(round_budget['normal_base'])
    resolved_round_base = int(round_budget['resolved_base'])
    round_overflow_cap = int(round_budget['overflow_cap'])
    resolved_round_max = int(round_budget['resolved_max'])
    configured_normal_round_max = int(round_budget['configured_normal_max'])
    reference_round_cap = int(round_budget['reference_cap'])
    adaptive_round_ceiling = int(round_budget['adaptive_ceiling'])
    active_round_ceiling = int(round_budget['active_ceiling'])
    planner_source = 'ai'
    summary = ''
    endpoint = 'unavailable'
    context_bytes = 0
    validated_concrete_action_count = 0
    review_selected_ids: list[str] = []
    review_reasoning = ''
    fallback_reason = ''
    try:
        decision = ai_plan(state)
        round_budget = _round_execution_budget(
            state, eligible, round_number,
            ai_extension_requested=bool(decision.get('request_adaptive_extension', False)),
        )
        normal_round_base = int(round_budget['normal_base'])
        resolved_round_base = int(round_budget['resolved_base'])
        round_overflow_cap = int(round_budget['overflow_cap'])
        resolved_round_max = int(round_budget['resolved_max'])
        configured_normal_round_max = int(round_budget['configured_normal_max'])
        reference_round_cap = int(round_budget['reference_cap'])
        adaptive_round_ceiling = int(round_budget['adaptive_ceiling'])
        active_round_ceiling = int(round_budget['active_ceiling'])
        validated_plan = validate_plan(state, decision.get('actions', []))
        validated_concrete_action_count = len(validated_plan)
        # ai_plan already returns actions in explicit AI priority order. Validation may remove invalid
        # rows, but Python must not reshuffle the surviving actions by tool/profile.
        plan = validated_plan[:resolved_round_max]
        summary = str(decision.get('reasoning_summary', ''))[:1000]
        finished = bool(decision.get('finish', False)) and (not plan)
        endpoint = str(LAST_AI_PLAN_DIAGNOSTICS.get('endpoint', 'unknown'))
        context_bytes = int(LAST_AI_PLAN_DIAGNOSTICS.get('context_bytes', 0) or 0)
        planner_seconds = float(LAST_AI_PLAN_DIAGNOSTICS.get('seconds', 0) or 0)
        candidate_count = int(LAST_AI_PLAN_DIAGNOSTICS.get('candidate_count', 0) or 0)
        detailed_candidate_count = int(LAST_AI_PLAN_DIAGNOSTICS.get('detailed_candidate_count', candidate_count) or 0)
        candidate_pool_count = int(LAST_AI_PLAN_DIAGNOSTICS.get('candidate_pool_count', candidate_count) or candidate_count)
        selected_ids = [str(value) for value in LAST_AI_PLAN_DIAGNOSTICS.get('selected_action_ids', [])]
        ai_selected_ids = [str(value) for value in LAST_AI_PLAN_DIAGNOSTICS.get('ai_selected_action_ids_before_cap', selected_ids)]
        review_selected_ids = []
        review_seconds = 0.0
        review_error = ''
        review_reasoning = ''
        if not plan and (not finished) and eligible:
            finished = True
            summary = (summary + ' No action was selected; the planner ended the round without forcing a checklist.').strip()
        notes.append(f'Round {round_number} [{planner_source}/{endpoint}; context={context_bytes}B]: {summary}')
        provider_name = str(state.get('ai_provider') or 'ollama')
        concrete_pool_count = int(LAST_AI_PLAN_DIAGNOSTICS.get('concrete_action_pool_count', len(eligible)) or len(eligible))
        selected_count = int(LAST_AI_PLAN_DIAGNOSTICS.get('admitted_action_count', len(plan)) or len(plan))
        planner_batch_count = int(LAST_AI_PLAN_DIAGNOSTICS.get('planner_batch_count', 1) or 1)
        planner_batch_size = int(LAST_AI_PLAN_DIAGNOSTICS.get('planner_batch_size', candidate_count) or candidate_count)
        print(
            f'\n[*] AI plan round {round_number} [{provider_name}] via {endpoint} '
            f'(context_total={context_bytes} bytes; concrete_candidates={concrete_pool_count}; '
            f'batches={planner_batch_count}x<= {planner_batch_size}; AI_selected={len(ai_selected_ids)}; '
            f'admitted={selected_count}; {planner_seconds:.1f}s): {summary}',
            flush=True,
        )
        selected_actions_by_profile = LAST_AI_PLAN_DIAGNOSTICS.get('admitted_actions_per_profile', {})
        available_actions_by_profile = LAST_AI_PLAN_DIAGNOSTICS.get('available_actions_per_profile', {})
        if isinstance(available_actions_by_profile, dict):
            for profile_name in sorted(available_actions_by_profile):
                selected_for_profile = int(selected_actions_by_profile.get(profile_name, 0) or 0) if isinstance(selected_actions_by_profile, dict) else 0
                available_for_profile = int(available_actions_by_profile.get(profile_name, 0) or 0)
                print(
                    f"    [PLANNER] {profile_name}: concrete candidates={available_for_profile}; AI-selected/admitted={selected_for_profile}; "
                    f"deferred={max(0, available_for_profile - selected_for_profile)}",
                    flush=True,
                )
        before_global_cap = int(LAST_AI_PLAN_DIAGNOSTICS.get('expanded_before_global_cap', len(plan)) or len(plan))
        print(
            f"    [ROUND BUDGET] actions={len(plan)}; normal ceiling={reference_round_cap}; "
            f"adaptive ceiling={adaptive_round_ceiling}; active ceiling={active_round_ceiling}; "
            f"AI extension request={'yes' if round_budget.get('adaptive_extension_ai_requested') else 'no'}; "
            f"before cap={before_global_cap}",
            flush=True,
        )
    except Exception as exc:
        endpoint = str(LAST_AI_PLAN_DIAGNOSTICS.get('endpoint', 'unavailable'))
        context_bytes = int(LAST_AI_PLAN_DIAGNOSTICS.get('context_bytes', 0) or 0)
        if state.get('require_ai'):
            raise RuntimeError(f'Strict agentic mode requires a successful AI plan: {type(exc).__name__}: {exc}') from exc
        plan = _fallback_plan(state, eligible, resolved_round_max)
        finished = not plan
        fallback_reason = f'{type(exc).__name__}: {exc}'
        message = 'AI concrete-action planning failed; because --require-ai is disabled, the emergency deterministic fallback was used under the same global round cap: ' + fallback_reason
        notes.append(message)
        planner_source = 'fallback'
        summary = message[:1000]
        print(f'\n[!] {message}', file=sys.stderr, flush=True)
    plan_before_final_cap = len(plan)
    final_cap = min(resolved_round_max, active_round_ceiling)
    if planner_source == 'ai':
        plan = plan[:final_cap]
    else:
        plan = _fair_global_action_cap(plan, final_cap)
    if plan_before_final_cap != len(plan):
        notes.append(f'Round {round_number}: final shared action cap reduced {plan_before_final_cap} validated actions to {len(plan)}.')
    audit.append({'round': round_number,
        'planner_source': planner_source,
        'planner_endpoint': endpoint,
        'context_bytes': context_bytes,
        'context_window': int(LAST_AI_PLAN_DIAGNOSTICS.get('context_window', 0) or 0) if planner_source == 'ai' else 0,
        'eligible_action_count': len(eligible),
        'planner_candidate_pool_count': int(LAST_AI_PLAN_DIAGNOSTICS.get('candidate_pool_count', len(eligible)) or len(eligible)) if planner_source == 'ai' else len(eligible),
        'planner_candidate_count': int(LAST_AI_PLAN_DIAGNOSTICS.get('candidate_count', len(eligible)) or len(eligible)) if planner_source == 'ai' else len(eligible),
        'planner_detailed_candidate_count': int(LAST_AI_PLAN_DIAGNOSTICS.get('detailed_candidate_count', 0) or 0) if planner_source == 'ai' else 0,
        'concrete_action_pool_count': int(LAST_AI_PLAN_DIAGNOSTICS.get('concrete_action_pool_count', len(eligible)) or len(eligible)) if planner_source == 'ai' else len(eligible),
        'planner_batch_size': int(LAST_AI_PLAN_DIAGNOSTICS.get('planner_batch_size', 0) or 0) if planner_source == 'ai' else 0,
        'planner_batch_count': int(LAST_AI_PLAN_DIAGNOSTICS.get('planner_batch_count', 0) or 0) if planner_source == 'ai' else 0,
        'available_actions_per_profile': dict(LAST_AI_PLAN_DIAGNOSTICS.get('available_actions_per_profile', {})) if planner_source == 'ai' and isinstance(LAST_AI_PLAN_DIAGNOSTICS.get('available_actions_per_profile', {}), dict) else {},
        'admitted_actions_per_profile': dict(LAST_AI_PLAN_DIAGNOSTICS.get('admitted_actions_per_profile', {})) if planner_source == 'ai' and isinstance(LAST_AI_PLAN_DIAGNOSTICS.get('admitted_actions_per_profile', {}), dict) else {},
        'eligible_tools': sorted({str(action.get('tool') or '') for action in eligible}),
        'round_action_normal_target_total': normal_round_base,
        'round_action_normal_base_total': normal_round_base,  # legacy compatibility
        'round_action_resolved_base_total': resolved_round_base,
        'round_action_resolved_max_total': resolved_round_max,
        'round_action_overflow_total': round_overflow_cap,
        'round_action_configured_normal_max_total': configured_normal_round_max,
        'round_action_reference_cap_total': reference_round_cap,
        'round_action_adaptive_ceiling_total': adaptive_round_ceiling,
        'round_action_active_ceiling_total': active_round_ceiling,
        'round_action_adaptive_extension_unlocked': bool(round_budget.get('adaptive_extension_unlocked')),
        'round_action_adaptive_extension_ai_requested': bool(round_budget.get('adaptive_extension_ai_requested')),
        'round_action_adaptive_extension_ai_effective': bool(round_budget.get('adaptive_extension_ai_effective')),
        'round_action_adaptive_extension_deterministic_pressure': bool(round_budget.get('adaptive_extension_deterministic_pressure')),
        # Compatibility field for older report consumers.
        'round_action_hard_cap_total': active_round_ceiling,
        'round_action_ordinary_remaining': int(round_budget['ordinary_remaining']),
        'round_action_required_per_round': int(round_budget['required_per_round']),
        'round_action_remaining_rounds': int(round_budget['remaining_rounds']),
        'round_action_count_before_final_cap': plan_before_final_cap,
        'execution_budget_diagnostics_per_profile': dict(LAST_AI_PLAN_DIAGNOSTICS.get('execution_budget_diagnostics_per_profile', {})) if planner_source == 'ai' and isinstance(LAST_AI_PLAN_DIAGNOSTICS.get('execution_budget_diagnostics_per_profile', {}), dict) else {},
        'ai_selected_action_count_before_cap': len(ai_selected_ids) if planner_source == 'ai' else 0,
        'validated_concrete_action_count': validated_concrete_action_count,
        'review_reasoning': review_reasoning if planner_source == 'ai' else '',
        'fallback_reason': fallback_reason,
        'selected_action_count': len(plan),
        'selected_actions': [_audit_action_summary(action) for action in plan],
        'reasoning_summary': summary[:1500]})
    print(f'[*] Validated actions: {len(plan)}', flush=True)
    for action in plan:
        print(f"    {action['profile']:13} {action['tool']:10} {shared.compact_log_url(action['target_url'])} — {action['reason']}", flush=True)
    return {'plan': plan, 'round': round_number, 'notes': notes, 'finished': finished, 'planner_source': planner_source, 'planner_audit': audit}

# Action execution invokes one validated tool and stores the normalized result in planner state.
async def execute_action(action: dict[str, Any], cookies: dict[str, str], discovery: dict[str, dict[str, Any]], allow_state_changes: bool | None=None, secondary_cookies: str='', identity_labels: dict[str, str] | None=None) -> tuple[dict[str, Any], dict[str, Any]]:
    tool = action['tool']
    profile = action['profile']
    server, function = REGISTRY[tool][:2]
    if tool == 'jwt':
        arguments = {'jwt_token': action['jwt_token'], 'target_url': action['target_url']}
    elif tool == 'interactsh':
        oast_class = str(action.get('oast_class') or 'remote-fetch')
        oast_timeout = shared.oast_timeout_seconds(oast_class)
        request_url = _action_request_url(action, action['target_url'])
        arguments = {'target_url': action['target_url'], 'injection_url': action['injection_url'], 'cookies': shared.scope_cookie_header(request_url, cookies.get(profile, '')), 'method': action.get('method', 'GET'), 'data': action.get('data', ''), 'parameter': (action.get('parameters') or [''])[0], 'timeout': oast_timeout, 'request_rate': shared.MAX_REQUEST_RATE, 'allow_state_changes': shared.state_changing_tests_allowed(action['target_url'], allow_state_changes)}
    else:
        profile_discovery = discovery.get(profile, {})
        labels = identity_labels or {}
        comparison_identities = [
            {'label': str(labels.get(str(name)) or name), 'cookies': str(value)}
            for name, value in cookies.items()
            if str(name) != str(profile) and str(value)
        ]
        arguments = shared.build_tool_arguments(
            tool, action['target_url'], cookies.get(profile, ''), profile_discovery, case=action,
            secondary_cookies=secondary_cookies, comparison_identities=comparison_identities,
            allow_state_changes=allow_state_changes,
        )
        if action.get('sibling_broad') and tool in {'zap', 'nuclei', 'nikto'}:
            arguments['timeout'] = shared.sibling_broad_timeout(tool, arguments.get('timeout'))
        if tool == 'ffuf':
            arguments.pop('session_probe_url', None)
    state_refresh: dict[str, Any] | None = None
    authenticated_specialists = {'sqlmap', 'dalfox', 'commix', 'traversal', 'idor', 'authorization', 'interactsh', 'arjun', 'browser', 'workflow'}
    raw_profile_cookie = cookies.get(profile, '')
    request_url = _action_request_url(action, action['target_url'])
    effective_action_cookie = shared.scope_cookie_header(request_url, raw_profile_cookie)
    if raw_profile_cookie and (tool in authenticated_specialists or bool(action.get('sibling_broad'))):
        profile_discovery = discovery.get(profile, {})
        source_url = str(action.get('source_url') or '')
        method = str(action.get('method') or 'GET').upper()
        probe_url = request_url if method in {'GET', 'HEAD'} else shared.select_application_session_probe_url(profile_discovery, request_url, source_url)
        print(f'    [PRECHECK] {tool}: validating authenticated session with {shared.compact_log_url(probe_url)}', flush=True)
        # refresh_authenticated_session_state may use the synchronous Playwright authentication
        # helper when an application/path session must be repaired. execute_action runs inside the
        # Agentic asyncio loop, so execute the synchronous precheck in a worker thread instead of
        # invoking Playwright Sync API on the event-loop thread. Actions are still globally
        # sequential, therefore shared runtime-auth state is not concurrently mutated by scanners.
        state_refresh = await asyncio.to_thread(
            shared.refresh_authenticated_session_state,
            request_url, raw_profile_cookie, probe_url,
            allow_state_changes=shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')),
        )
        if state_refresh.get('usable') is False or not state_refresh.get('credential_applied'):
            print(f'    [PARTIAL ] {tool}: authenticated session precheck failed', flush=True)
            return (action, {'tool': tool, 'status': 'partial', 'target': action['target_url'], 'output': 'The authenticated application session could not be re-established before the scanner.', 'vulnerabilities': [], 'diagnosis': 'authentication_precheck_failed', 'state_refresh': state_refresh})
        effective_action_cookie = shared.scope_cookie_header(request_url, raw_profile_cookie)
        # build_tool_arguments ran before the just-in-time refresh; update the concrete scanner
        # arguments so a newly established application/path session is actually used by the tool.
        if isinstance(arguments, dict) and 'cookies' in arguments:
            arguments['cookies'] = effective_action_cookie
        print(f'    [SESSION ] {tool}: authenticated application session usable', flush=True)
    try:
        scanner_limit = float(arguments.get('timeout', 180))
        spec = next((item for item in shared.ALL_TOOLS if item.name == tool), None)
        if spec is not None:
            result = await call_mcp_with_progress(spec, arguments, timeout_seconds=scanner_limit)
        else:
            print(f"    [RUNNING ] {tool}: {shared.compact_log_url(action['target_url'])} (scanner limit {scanner_limit:g}s)", flush=True)
            result = await call_mcp(server, function, arguments, timeout_seconds=scanner_limit)
        if state_refresh is not None:
            result['state_refresh'] = state_refresh
        return (action, result)
    except Exception as exc:
        message = f'Agent executor failed: {type(exc).__name__}: {exc}'
        result = {'tool': tool, 'status': 'error', 'target': action['target_url'], 'output': message, 'vulnerabilities': [], 'diagnosis': diagnose_error(message), 'traceback': traceback.format_exc()}
        if state_refresh is not None:
            result['state_refresh'] = state_refresh
        return (action, result)

# Orders one sequential round fairly across profile/tool buckets. This does not introduce scanner
# concurrency or reduce coverage; it prevents a slow capability such as SQLMap from occupying the
# first several hours of a large round before any faster complementary capability gets a chance.
def _fair_sequential_action_order(plan: list[dict[str, Any]], cookies: dict[str, str]) -> list[dict[str, Any]]:
    profile_order = {name: index for index, name in enumerate(cookies)}
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for action in plan:
        key = (str(action.get('profile') or ''), str(action.get('tool') or ''))
        buckets.setdefault(key, []).append(action)
    keys = sorted(
        buckets,
        key=lambda key: (
            profile_order.get(key[0], 999),
            shared.tool_execution_rank(key[1], bool(cookies.get(key[0], ''))),
            key[1],
        ),
    )
    offsets = {key: 0 for key in keys}
    ordered: list[dict[str, Any]] = []
    while True:
        added = False
        for key in keys:
            index = offsets[key]
            bucket = buckets[key]
            if index >= len(bucket):
                continue
            ordered.append(bucket[index])
            offsets[key] = index + 1
            added = True
        if not added:
            break
    return ordered


# Within each planner round, validated actions run before the model is asked to plan again.
async def execute_plan(plan: list[dict[str, Any]], cookies: dict[str, str], discovery: dict[str, dict[str, Any]], allow_state_changes: bool | None=None, secondary_cookies: str='', identity_labels: dict[str, str] | None=None) -> list[tuple[dict[str, Any], dict[str, Any]]]:

    ordered = _fair_sequential_action_order(plan, cookies)
    total = len(ordered)
    print(f'\n[*] Executing {total} validated action(s) sequentially. Progress heartbeat: every {shared.SCANNER_PROGRESS_INTERVAL}s.', flush=True)
    executed: list[tuple[dict[str, Any], dict[str, Any]]] = []
    arjun_empty_limits: dict[str, int] = {}
    confirmed_oast_classes: set[tuple[str, str]] = set()
    jwt_result_cache: dict[str, dict[str, Any]] = {}
    arjun_threshold = 2 if shared.CURRENT_SCAN_MODE == 'deep' else 1
    for index, action in enumerate(ordered, start=1):
        started = time.monotonic()
        print(f"\n[*] Action {index}/{total}: {action['profile']} / {action['tool']} / {shared.compact_log_url(action['target_url'])}", flush=True)
        try:
            oast_key = (action['profile'], str(action.get('oast_class') or 'remote-fetch'))
            if action['tool'] == 'jwt' and str(action.get('jwt_token') or '') in jwt_result_cache:
                reused = copy.deepcopy(jwt_result_cache[str(action.get('jwt_token') or '')])
                reused['analysis_reused'] = True
                reused['output'] = (str(reused.get('output') or '') + '\nJWT analysis result reused for an identical token already analyzed in this assessment.').strip()
                item = (action, reused)
            elif action['tool'] == 'interactsh' and oast_key in confirmed_oast_classes:
                item = (action, {'tool': 'interactsh', 'status': 'skipped', 'target': action['target_url'], 'output': 'A callback was already confirmed for the same OAST class in this profile; the duplicate polling wait was omitted.', 'diagnosis': 'duplicate_oast_class_already_confirmed', 'vulnerabilities': []})
            elif action['tool'] == 'arjun' and arjun_empty_limits.get(action['profile'], 0) >= arjun_threshold:
                item = (action, {'tool': 'arjun', 'status': 'skipped', 'target': action['target_url'], 'output': 'Adaptive budget reallocation: earlier high-priority Arjun actions reached their full budget without discovering a parameter; this lower-priority repeat was skipped.', 'diagnosis': 'adaptive_budget_reallocated', 'vulnerabilities': []})
            else:
                item = await execute_action(action, cookies, discovery, allow_state_changes=allow_state_changes, secondary_cookies=secondary_cookies, identity_labels=identity_labels)
        except Exception as exc:
            message = f'Agent executor isolated failure: {type(exc).__name__}: {exc}'
            item = (action, {'tool': action['tool'], 'status': 'error', 'target': action['target_url'], 'output': message, 'vulnerabilities': [], 'diagnosis': diagnose_error(message), 'traceback': traceback.format_exc()})
        executed.append(item)
        _, result = item
        if action['tool'] == 'jwt' and str(action.get('jwt_token') or '') and not result.get('analysis_reused'):
            jwt_result_cache[str(action.get('jwt_token') or '')] = copy.deepcopy(result)
        if action['tool'] == 'interactsh' and result.get('callback_confirmed'):
            confirmed_oast_classes.add((action['profile'], str(action.get('oast_class') or 'remote-fetch')))
        if action['tool'] == 'arjun':
            found_parameters = shared.safe_int_metadata(result.get('phase_parameters', 0), 0)
            if str(result.get('diagnosis', '')) in shared.TIME_LIMIT_DIAGNOSES and (not result.get('vulnerabilities')) and (found_parameters == 0):
                arjun_empty_limits[action['profile']] = arjun_empty_limits.get(action['profile'], 0) + 1
            elif result.get('diagnosis') != 'adaptive_budget_reallocated':
                arjun_empty_limits[action['profile']] = 0
        elapsed = time.monotonic() - started
        vulnerabilities = result.get('vulnerabilities', [])
        finding_count = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
        status = str(result.get('status', 'unknown')).upper()
        diagnosis = str(result.get('diagnosis', '') or '')
        diagnosis_text = f'; diagnosis={diagnosis}' if diagnosis else ''
        print(f"    [FINISHED] {action['tool']}: status={status}; findings={finding_count}; elapsed={elapsed:.1f}s{diagnosis_text}", flush=True)
    print(f'\n[*] Round action execution finished: {total}/{total} action(s).', flush=True)
    return executed

# Records which actions ran and which ones remain available.
def _record_execution_batch(executed: list[tuple[dict[str, Any], dict[str, Any]]], *, state: AgentState, results: dict[str, dict[str, Any]], discovery: dict[str, dict[str, Any]], completed: list[str], profile_cookies: dict[str, str]) -> int:

    new_attack_surface = 0
    batch_summary: dict[tuple[str, str], dict[str, int]] = {}
    for action, result in executed:
        profile, tool = (action['profile'], action['tool'])
        profile_results = results.setdefault(profile, {})
        number = 1 + sum((key.startswith(f'{tool}:') for key in profile_results))
        metadata = {key: action[key] for key in ('verification_source_result', 'verification_source_parameter', 'verification_source_path', 'verification_source_url') if key in action}
        coverage_action_target = str(action.get('source_url') or action.get('target_url') or '') if tool == 'interactsh' else str(action.get('target_url') or '')
        coverage_action = {
            'tool': tool,
            'target_url': coverage_action_target,
            'method': str(action.get('method') or 'GET').upper(),
            'parameters': [str(value) for value in action.get('parameters', []) if str(value)],
            'body_fingerprint': shared.request_body_fingerprint(
                str(action.get('method') or 'GET'), str(action.get('data') or ''),
                [str(value) for value in action.get('parameters', []) if str(value)],
            ),
            'source_url': str(action.get('source_url') or ''),
        }
        profile_results[f'{tool}:{number}'] = {**result, **metadata, 'coverage_action': coverage_action, 'planner_reason': action['reason'], 'planner_round': state['round']}
        completed.append(action_id(action))
        status = str(result.get('status') or 'unknown').lower()
        vulnerabilities = result.get('vulnerabilities') if isinstance(result.get('vulnerabilities'), list) else []
        actionable_findings = sum(
            1 for finding in vulnerabilities
            if isinstance(finding, dict)
            and (
                str(finding.get('category') or '').lower() in {'candidate', 'vulnerability'}
                or str(finding.get('risk') or 'info').lower() not in {'', 'info'}
            )
        )
        summary_key = (profile, tool)
        counters = batch_summary.setdefault(summary_key, {
            'actions': 0, 'success': 0, 'partial': 0, 'error': 0, 'skipped': 0,
            'findings': 0, 'actionable_findings': 0,
        })
        counters['actions'] += 1
        if status in counters:
            counters[status] += 1
        counters['findings'] += len(vulnerabilities)
        counters['actionable_findings'] += actionable_findings

        # execute_plan() already emitted one [FINISHED] line for every action. Reprinting every
        # zero-finding success here made the post-round "results" section hundreds of lines long
        # and noticeably slow over SSH/tmux. Keep detailed diagnostics for incomplete/error runs,
        # broad scanners and real security candidates; aggregate routine successes below.
        detailed_result = (
            status != 'success'
            or actionable_findings > 0
            or tool in {'ffuf', 'zap', 'nuclei', 'session', 'nikto', 'interactsh'}
        )
        if detailed_result:
            log_result(profile, tool, result, action['target_url'])
        if tool == 'zap':
            log_zap_session_diagnostics(result)
        if tool == 'ffuf' and result.get('status') in {'success', 'partial'}:
            before = len(discovery.get(profile, {}).get('request_cases', []))
            enriched, urls = enrich_discovery_with_ffuf(discovery.get(profile, {}), result, state['target'])
            if urls:
                recrawl = discover_target_sync_safe(state['target'], profile_cookies.get(profile, ''), seeds=urls, allow_state_changes=shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')))
                enriched = merge_discovery(enriched, recrawl)
                print(f"    [DISCOVERY] {profile}: FFUF re-crawl expanded the surface to {len(enriched.get('html_urls', []))} HTML pages and {len(enriched.get('request_cases', []))} request cases.", flush=True)
            if profile_cookies.get(profile, '') and enriched.get('authentication_effective') is not False:
                enriched = shared.authenticate_discovered_sibling_origins(enriched, state['target'], profile_cookies[profile], allow_state_changes=shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')))
            discovery[profile] = enriched
            new_attack_surface += max(0, len(enriched.get('request_cases', [])) - before)
        if tool == 'arjun' and result.get('status') in {'success', 'partial'}:
            discovery[profile], generated = enrich_discovery_with_arjun(discovery.get(profile, {}), result, action['target_url'])
            new_attack_surface += len(generated)

    if batch_summary:
        print('    [ROUND RESULT SUMMARY] routine zero-finding successes are aggregated; detailed findings/partials/errors are printed above.', flush=True)
        for (profile, tool), counters in sorted(batch_summary.items()):
            print(
                f"      {profile}/{tool}: actions={counters['actions']}; success={counters['success']}; "
                f"partial={counters['partial']}; error={counters['error']}; skipped={counters['skipped']}; "
                f"findings={counters['findings']}; actionable={counters['actionable_findings']}",
                flush=True,
            )
    return new_attack_surface

# After validation, the selected actions run and their results are written back to shared state.
def executor_node(state: AgentState) -> dict[str, Any]:
    if not state['plan']:
        return {}
    audit = state.get('planner_audit', [])
    last_audit = audit[-1] if isinstance(audit, list) and audit and isinstance(audit[-1], dict) else {}
    mode = str(shared.CURRENT_SCAN_MODE or 'balanced')
    reference_cap = int(ROUND_EXECUTION_ACTION_REFERENCE_CAPS.get(mode, len(state['plan'])) or len(state['plan']))
    adaptive_ceiling = int(ROUND_EXECUTION_ACTION_ADAPTIVE_CEILINGS.get(mode, reference_cap) or reference_cap)
    # The executor never unlocks the emergency extension by itself: it only honors the active
    # ceiling already resolved/audited by the planner. Without audit metadata it falls back to the
    # safer normal reference ceiling.
    active_ceiling = int(last_audit.get('round_action_active_ceiling_total', reference_cap) or reference_cap)
    active_ceiling = max(1, min(active_ceiling, max(reference_cap, adaptive_ceiling)))
    resolved_max = int(last_audit.get('round_action_resolved_max_total', active_ceiling) or active_ceiling)
    execution_cap = max(1, min(active_ceiling, resolved_max))
    guarded_plan = _fair_global_action_cap(list(state['plan']), execution_cap)
    if len(guarded_plan) != len(state['plan']):
        print(f"[!] Final round guard reduced plan from {len(state['plan'])} to {len(guarded_plan)} total action(s) (cap={execution_cap}).", flush=True)
    cookies = {profile['name']: profile['cookies'] for profile in state['profiles']}
    identity_labels = {str(profile.get('name') or ''): str(profile.get('identity_ref') or profile.get('name') or '') for profile in state['profiles']}
    results = {profile: dict(values) for profile, values in state['results'].items()}
    discovery = {profile: dict(values) for profile, values in state['discovery'].items()}
    completed = list(state['completed'])
    profile_cookies = {profile['name']: profile['cookies'] for profile in state['profiles']}
    new_attack_surface = 0
    discovery_stage = [action for action in guarded_plan if action['tool'] == 'ffuf']
    remaining_stage = [action for action in guarded_plan if action['tool'] != 'ffuf']
    if discovery_stage:
        print('\n[*] Discovery enrichment stage: FFUF runs before ZAP/Nuclei.', flush=True)
        ffuf_executed = asyncio.run(execute_plan(discovery_stage, cookies, discovery, allow_state_changes=state.get('allow_state_changes'), secondary_cookies=state.get('secondary_cookies', ''), identity_labels=identity_labels))
        new_attack_surface += _record_execution_batch(ffuf_executed, state=state, results=results, discovery=discovery, completed=completed, profile_cookies=profile_cookies)
        print('[*] FFUF enrichment is available to planned ZAP/Nuclei actions; any new parameter candidates will be available to a later planner round.', flush=True)
    if remaining_stage:
        executed = asyncio.run(execute_plan(remaining_stage, cookies, discovery, allow_state_changes=state.get('allow_state_changes'), secondary_cookies=state.get('secondary_cookies', ''), identity_labels=identity_labels))
        new_attack_surface += _record_execution_batch(executed, state=state, results=results, discovery=discovery, completed=completed, profile_cookies=profile_cookies)
    next_state = dict(state)
    next_state.update(results=results, discovery=discovery, completed=completed)
    remaining = _remaining_eligible_actions(next_state)
    # When at least two rounds are allowed, always give the planner one feedback pass after
    # round 1 so it can inspect scanner outcomes even when the first plan exhausted the
    # initial candidate catalogue. Later rounds remain demand-driven by newly discovered or
    # still-unexecuted actions, preserving --max-rounds as an upper bound rather than forcing
    # every configured round.
    feedback_round_due = state['round'] == 1 and state['max_rounds'] >= 2
    can_continue = state['round'] < state['max_rounds'] and bool(feedback_round_due or new_attack_surface > 0 or remaining)
    notes = list(state['notes'])
    notes.append(f"Round {state['round']} execution: new request contracts={new_attack_surface}; remaining eligible actions={len(remaining)}; feedback round due={feedback_round_due}.")
    audit = [dict(item) for item in state.get('planner_audit', [])]
    if audit and int(audit[-1].get('round', 0) or 0) == state['round']:
        outcome_rows: list[dict[str, Any]] = []
        for profile, profile_results in results.items():
            for key, result in profile_results.items():
                if not isinstance(result, dict) or int(result.get('planner_round', 0) or 0) != state['round']:
                    continue
                outcome_rows.append({'profile': profile, 'result_key': key, 'tool': str(result.get('tool') or key.split(':', 1)[0]), 'status': str(result.get('status') or 'unknown'), 'diagnosis': str(result.get('diagnosis') or ''), 'findings': len(result.get('vulnerabilities') or []), 'duration_seconds': result.get('duration_seconds') or (result.get('_meta') or {}).get('duration_seconds')})
        audit[-1]['execution_outcomes'] = outcome_rows
        audit[-1]['new_request_contracts'] = new_attack_surface
        audit[-1]['remaining_eligible_actions_after_execution'] = len(remaining)
    return {'results': results, 'discovery': discovery, 'completed': completed, 'notes': notes, 'planner_audit': audit, 'finished': not can_continue}

# Builds bounded Chromium actions for XSS candidates that still require runtime validation.
def _final_browser_verification_actions(state: AgentState) -> list[dict[str, Any]]:

    per_profile_max = shared.final_browser_verification_max_limit()
    actions: list[dict[str, Any]] = []
    for profile, profile_results in state.get('results', {}).items():
        discovered = state.get('discovery', {}).get(profile, {})
        browser_cases = select_browser_request_cases(discovered, limit=max(24, per_profile_max * 4))
        ranked: list[tuple[int, dict[str, Any]]] = []
        seen: set[tuple[str, str]] = set()
        for result_key, result in profile_results.items():
            if not isinstance(result, dict) or str(result_key).startswith('browser:'):
                continue
            for finding in result.get('vulnerabilities', []) if isinstance(result.get('vulnerabilities'), list) else []:
                if not isinstance(finding, dict):
                    continue
                category = str(finding.get('category') or finding.get('verification_status') or '').lower()
                text = ' '.join(str(finding.get(key) or '') for key in ('alert', 'title', 'name', 'description', 'type')).lower()
                if category != 'candidate' or 'xss' not in text:
                    continue
                finding_url = str(finding.get('url') or result.get('target') or state['target'])
                parameter = str(finding.get('parameter') or '').strip()
                finding_path = urlparse(finding_url).path
                selected: dict[str, Any] | None = None
                context_score = 0
                compatible_cases: list[tuple[int, dict[str, Any]]] = []
                for case in browser_cases:
                    case_parameters = {str(value) for value in case.get('parameters', [])}
                    case_url = str(case.get('url') or '')
                    if urlparse(case_url).path != finding_path:
                        continue
                    if parameter and parameter not in case_parameters:
                        continue
                    compatible_cases.append((shared.xss_verification_context_score(finding_url, case_url, parameter), case))
                if compatible_cases:
                    context_score, best_case = max(compatible_cases, key=lambda item: item[0])
                    selected = dict(best_case)
                if selected is None and shared.url_in_authorized_scope(state['target'], finding_url) and not shared._destructive_crawl_url(finding_url):
                    parsed = urlparse(finding_url)
                    pairs = [(name, '1' if any(token in value.lower() for token in ('<script', '<img', 'javascript:', 'onerror=', 'onload=')) else value) for name, value in parse_qsl(parsed.query, keep_blank_values=True)]
                    safe_url = urlunparse(parsed._replace(query=urlencode(pairs)))
                    parameters = [name for name, _ in pairs]
                    if parameters:
                        selected = {'url': safe_url, 'method': 'GET', 'data': '', 'parameters': parameters, 'fields': [], 'source_url': safe_url}
                        context_score = shared.xss_verification_context_score(finding_url, safe_url, parameter)
                if selected is None:
                    continue
                if parameter:
                    selected['parameters'] = [parameter]
                    selected['fields'] = [field for field in selected.get('fields', []) if isinstance(field, dict) and str(field.get('name') or '') == parameter]
                key = (str(selected.get('url') or ''), parameter)
                if key in seen:
                    continue
                seen.add(key)
                action = {'profile': profile, 'tool': 'browser', 'target_url': selected['url'], 'method': selected.get('method', 'GET'), 'data': selected.get('data', ''), 'parameters': selected.get('parameters', []), 'jwt_token': '', 'injection_url': '', 'fields': selected.get('fields', []), 'source_url': selected.get('source_url', ''), 'client_sources': selected.get('client_sources', []), 'client_sinks': selected.get('client_sinks', []), 'verification_source_result': str(result_key), 'verification_source_parameter': parameter, 'verification_source_path': finding_path, 'verification_source_url': finding_url, 'reason': f"Final Chromium verification of XSS candidate from {result_key} parameter={parameter or 'n/a'}."}
                ranked.append((shared.final_xss_verification_priority(finding, selected, context_score), action))
        for chosen in shared.select_adaptive_final_xss_candidates(ranked):
            action = dict(chosen)
            if chosen.get('adaptive_final_xss_budget'):
                action['reason'] = 'Discovery ranking marked this as an adaptive final-XSS candidate; AI still decides execution. ' + str(action.get('reason') or '')
            actions.append(action)
    return actions

# Reconcile one scanner XSS candidate with the exact-parameter Chromium result.
def _reconcile_final_browser_result(results: dict[str, dict[str, Any]], action: dict[str, Any], browser_result: dict[str, Any]) -> None:
    profile = str(action.get('profile') or '')
    source_key = str(action.get('verification_source_result') or '')
    parameter = str(action.get('verification_source_parameter') or '')
    source_path = str(action.get('verification_source_path') or '')
    source_url = str(action.get('verification_source_url') or '')
    source = results.get(profile, {}).get(source_key)
    if not isinstance(source, dict):
        return
    browser_findings = [item for item in browser_result.get('vulnerabilities', []) if isinstance(item, dict) and (not parameter or str(item.get('parameter') or '') == parameter)]
    confirmed = next((item for item in browser_findings if str(item.get('category') or '').lower() == 'vulnerability'), None)
    reflected = next((item for item in browser_findings if str(item.get('verification_status') or '') == 'browser-reflection-without-marker-execution'), None)
    attempts = ((browser_result.get('diagnostics') or {}).get('dom_attempts') or []) if isinstance(browser_result.get('diagnostics'), dict) else []
    verified_parameters = {str(value) for value in browser_result.get('verified_parameters', []) if str(value)}
    action_parameters = {str(value) for value in action.get('parameters', []) if str(value)}
    attempted = (
        any(isinstance(item, dict) and (not parameter or str(item.get('parameter') or '') == parameter) for item in attempts)
        or (bool(parameter) and parameter in verified_parameters)
        or (str(browser_result.get('status') or '').lower() == 'success' and bool(parameter) and parameter in action_parameters)
    )
    for finding in source.get('vulnerabilities', []) if isinstance(source.get('vulnerabilities'), list) else []:
        if not isinstance(finding, dict) or str(finding.get('category') or '').lower() != 'candidate':
            continue
        text = ' '.join(str(finding.get(key) or '') for key in ('alert', 'title', 'name', 'description', 'type')).lower()
        if 'xss' not in text or (parameter and str(finding.get('parameter') or '') != parameter):
            continue
        finding_url = str(finding.get('url') or '')
        if source_path and urlparse(finding_url).path != source_path:
            continue
        if source_url and shared.xss_verification_context_score(source_url, finding_url, parameter) < 20:
            continue
        if confirmed is not None:
            finding.update(category='vulnerability', verification_status='playwright-browser-marker-executed', confidence='high', browser_final_verification='confirmed', browser_confidence_ceiling='', browser_verification_evidence=str(confirmed.get('evidence') or ''))
        elif reflected is not None:
            finding.update(verification_status='browser-reflection-without-marker-execution', confidence='medium', browser_final_verification='reflected_not_executed', browser_confidence_ceiling='medium', browser_verification_evidence=str(reflected.get('evidence') or ''))
        elif str(browser_result.get('status') or '').lower() == 'success' and attempted:
            finding.update(verification_status='browser-not-reproduced-bounded', confidence='low', browser_final_verification='not_reproduced', browser_confidence_ceiling='low', browser_verification_evidence=f"Chromium completed an exact-parameter bounded check for {parameter or 'the source parameter'} without marker execution or reflection.")

# Runs the final authenticated logout lifecycle check after every other authenticated test.
async def _final_logout_checks(state: AgentState, results: dict[str, dict[str, Any]]) -> int:
    executed = 0
    if not shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')):
        for profile in state.get('profiles', []):
            name = str(profile.get('name') or '')
            if str(profile.get('cookies') or ''):
                results.setdefault(name, {})['session_logout_final'] = make_skipped_result(
                    'session-logout', state['target'],
                    'Logout lifecycle verification is state-changing and allow_state_changes is false.',
                )
        return executed
    for profile in state.get('profiles', []):
        name = str(profile.get('name') or '')
        cookies = str(profile.get('cookies') or '')
        if not cookies or not _profile_has_effective_auth(state, name):
            continue
        discovery = state.get('discovery', {}).get(name, {})
        logout_cases = [
            case for case in select_logout_request_cases(discovery, limit=3)
            if shared.scope_cookie_header(str(case.get('url') or ''), cookies)
        ]
        if not logout_cases:
            skipped = make_skipped_result(
                'session-logout', state['target'],
                'No credentialed exact-origin logout/signout/logoff endpoint was discovered safely for the authenticated profile.',
            )
            results.setdefault(name, {})['session_logout_final'] = skipped
            log_result(name, 'session-logout', skipped, state['target'])
            continue
        probe_url = select_session_probe_url(discovery, state['target'])
        for index, logout_case in enumerate(logout_cases, start=1):
            logout_url = str(logout_case.get('url') or '')
            logout_cookies = shared.scope_cookie_header(logout_url, cookies)
            logout_probe = probe_url if shared.same_origin(logout_url, probe_url) else logout_url
            print(f'    [RUNNING ] session-logout: {shared.compact_log_url(logout_url)}', flush=True)
            result = await call_mcp(
                'custom_checks/sessionServer.py', 'run_logout_check',
                {
                    'target_url': state['target'], 'logout_url': logout_url, 'cookies': logout_cookies,
                    'probe_url': logout_probe, 'method': str(logout_case.get('method') or 'GET'),
                    'data': str(logout_case.get('data') or ''), 'timeout': 25, 'request_rate': shared.MAX_REQUEST_RATE,
                    'allow_state_changes': True,
                },
                timeout_seconds=30,
            )
            result['coverage_action'] = {
                'tool': 'session-logout',
                'target_url': logout_url,
                'method': str(logout_case.get('method') or 'GET').upper(),
                'parameters': [str(value) for value in logout_case.get('parameters', []) if str(value)],
                'body_fingerprint': shared.request_body_fingerprint(
                    str(logout_case.get('method') or 'GET'), str(logout_case.get('data') or ''),
                    [str(value) for value in logout_case.get('parameters', []) if str(value)],
                ),
                'source_url': str(logout_case.get('source_url') or ''),
            }
            key = 'session_logout_final' if index == 1 else f'session_logout_final_{index}'
            results.setdefault(name, {})[key] = result
            log_result(name, 'session-logout', result, logout_url)
            executed += 1
            # A successful lifecycle decision either proved invalidation or confirmed that the
            # old session remains valid. In both cases no second logout endpoint should mutate
            # the already-evaluated session state.
            if str(result.get('status') or '').lower() == 'success':
                break
            # A method-incompatible logout contract has not changed the authenticated session, so a
            # second safely-discovered logout candidate may still be tried. Other partial states
            # are inconclusive and stop here to avoid uncontrolled session transitions.
            if str(result.get('diagnosis') or '') != 'logout_endpoint_not_executable':
                break
    return executed

# Runs a deterministic final browser verification stage before AI narrative analysis, then
# validates authenticated logout as the last session-mutating action in the assessment.
def verification_node(state: AgentState) -> dict[str, Any]:

    actions = _final_browser_verification_actions(state)
    notes = list(state.get('notes', []))
    cookies = {profile['name']: profile['cookies'] for profile in state['profiles']}
    profile_cookies = dict(cookies)
    results = {profile: dict(values) for profile, values in state['results'].items()}
    discovery = {profile: dict(values) for profile, values in state['discovery'].items()}
    completed = list(state['completed'])

    print('\n[*] Completion-driven safe surface sweep: replaying still-untested reachable non-destructive contexts.', flush=True)
    for profile in state['profiles']:
        profile_name = str(profile.get('name') or '')
        sweep = shared.run_safe_surface_sweep(
            state['target'], discovery.get(profile_name, {}), results.get(profile_name, {}),
            str(profile.get('cookies') or ''),
        )
        results.setdefault(profile_name, {})['safe_surface_completion'] = sweep
        notes.append(
            f"Safe-surface completion {profile_name}: tested={sweep.get('tested_contexts', 0)}/"
            f"{sweep.get('selected_contexts', 0)}, eligible={sweep.get('eligible_contexts', 0)}, status={sweep.get('status', 'unknown')}."
        )

    if not actions:
        notes.append('Final verification: no unresolved XSS candidate had a compatible Chromium request contract.')
        print('\n[*] Final verification: no Chromium candidate requires validation.', flush=True)
    else:
        verification_counts: dict[str, int] = {}
        for action in actions:
            profile_name = str(action.get('profile') or '')
            verification_counts[profile_name] = verification_counts.get(profile_name, 0) + 1
        counts_text = ', '.join(
            f"{profile['name']}={verification_counts.get(profile['name'], 0)}/{shared.final_browser_verification_limit()} base, max={shared.final_browser_verification_max_limit()}"
            for profile in state['profiles']
        )
        print(f'\n[*] Final verification: validating {len(actions)} XSS candidate(s) with Chromium; per-profile={counts_text}.', flush=True)
        before_keys = {profile: set(values) for profile, values in results.items()}
        executed = asyncio.run(execute_plan(actions, cookies, discovery, allow_state_changes=state.get('allow_state_changes'), secondary_cookies=state.get('secondary_cookies', ''), identity_labels={str(profile.get('name') or ''): str(profile.get('identity_ref') or profile.get('name') or '') for profile in state['profiles']}))
        for action, browser_result in executed:
            _reconcile_final_browser_result(results, action, browser_result)
        _record_execution_batch(executed, state=state, results=results, discovery=discovery, completed=completed, profile_cookies=profile_cookies)
        for profile, values in results.items():
            for key, value in values.items():
                if key not in before_keys.get(profile, set()) and isinstance(value, dict) and key.startswith('browser:'):
                    value['final_verification_stage'] = True
        notes.append(f'Final verification: Chromium executed {len(executed)} candidate validation action(s).')

    print('\n[*] Final session lifecycle: validating discovered authenticated logout endpoint(s).', flush=True)
    logout_executed = asyncio.run(_final_logout_checks({**state, 'discovery': discovery}, results))
    notes.append(f'Final session lifecycle: executed {logout_executed} authenticated logout validation action(s); anonymous profiles were excluded.')
    return {'results': results, 'discovery': discovery, 'completed': completed, 'verification_done': True, 'notes': notes}

# Decides whether the agent should plan again or enter final deterministic verification.
def route_after_execution(state: AgentState) -> Literal['planner', 'verification']:
    return 'verification' if state['finished'] or state['round'] >= state['max_rounds'] or (not state['plan']) else 'planner'

# Once execution is complete, reporting receives the collected state and produces the final assessment.
def report_node(state: AgentState) -> dict[str, Any]:
    print('\n[*] Creating final PDF, HTML preview and JSON report...')
    output_name = str(os.environ.get('SECOPS_REPORT_RUN_ID') or f'SecOps_Agentic_Assessment_{datetime.now():%Y%m%d_%H%M%S_%f}_{os.getpid()}_{uuid.uuid4().hex[:8]}')
    report_results = _materialize_unselected_actions(state)
    remaining = _remaining_eligible_actions({**state, 'results': report_results})
    context = {'profiles': [{'name': profile['name'], 'identity_ref': str(profile.get('identity_ref') or ''), 'authenticated': _profile_has_effective_auth(state, str(profile.get('name') or ''))} for profile in state['profiles']],
        'explicit_entry_points': list(state.get('entry_points') or []),
        'priority_discovery_seeds': list(state.get('discovery_seeds') or []),
        'expected_tools': list(REGISTRY),
        'discovery': state['discovery'],
        'endpoint_selection': {
            profile['name']: shared.endpoint_selection_decisions(
                state['discovery'].get(profile['name'], {}), state['target'],
                authenticated_profile=_profile_has_effective_auth(state, str(profile.get('name') or '')),
                allow_state_changes=shared.state_changing_tests_allowed(state['target'], state.get('allow_state_changes')),
                credential_cookies=str(profile.get('cookies') or ''),
                agentic_catalog=True,
            )
            for profile in state['profiles']
        },
        'diagnostics': state['diagnostics'],
        'planner_notes': state['notes'],
        'planner_rounds': state['round'],
        'ai_provider': str(state.get('ai_provider') or 'ollama'),
        'ai_model': state['model'],
        'ai_endpoint': state['snap4city_api_url'] if str(state.get('ai_provider') or 'ollama') == 'snap4city' else state['ollama_url'],
        'ollama_model': state['model'] if str(state.get('ai_provider') or 'ollama') == 'ollama' else '',
        'ollama_url': state['ollama_url'] if str(state.get('ai_provider') or 'ollama') == 'ollama' else '',
        'strict_ai_required': state.get('require_ai', False),
        'planner_source': state.get('planner_source', 'unknown'),
        'planner_audit': state.get('planner_audit', []),
        'ai_analysis': state.get('analysis', {}),
        'scan_mode': shared.CURRENT_SCAN_MODE,
        'request_rate_policy': shared.runtime_request_rate_policy(),
        'allow_same_host_ports': shared.ALLOW_SAME_HOST_PORTS,
        'discover_same_host_services': shared.DISCOVER_SAME_HOST_SERVICES,
        'authentication_scope_policy': ('authenticated destinations try an applicable existing cookie first; when same-host multi-port is enabled, the raw cookie may be tried on another authorized port of the exact same hostname and scheme and must validate; if rejected, saved browser/OIDC state is tried, followed by the username/password resolved once by the runner if the login flow requests them; a conclusively rejected speculative raw cookie is remembered per cookie+origin so later scanners do not retry it; raw cookies are never copied to a different hostname and no second child-console prompt is opened'),
        'redirect_scope_policy': ('active scanners use explicit-origin authorization; same-host multi-port expansion is ' + ('enabled (exact hostname, HTTP/HTTPS services across authorized ports)' if shared.ALLOW_SAME_HOST_PORTS else 'disabled') + '; sensitive HTTP helpers stay same-origin, while project discovery follows bounded redirects only across destinations authorized before the run; external scanner processes do not autonomously follow redirects, so tool-internal redirect-dependent behavior is intentionally conservative; ZAP adds an exact-origin context plus in-scope-only active scans and Protected mode; browser authentication may traverse an external IdP without authorizing it for active testing'),
        'runtime_platform': platform.platform(),
        'python_executable': sys.executable,
        'mcp_server_python': shared._server_python(),
        'remaining_eligible_actions_at_report': len(remaining),
        'execution_policy': 'AI selects discovery-derived scan actions under deterministic safety validation. After the planning rounds, the deterministic verification stage rechecks unresolved XSS candidates with Chromium and then validates any safely discovered authenticated logout endpoint as the final session-mutating action; anonymous profiles never execute logout. A separate AI analysis node then independently enriches severity, description, impact, potential consequences, recovery guidance and remediation using scanner evidence. Category, verification status, request evidence and confirmation rules remain deterministic and immutable. Bounded state-changing workflow probes use a tri-state policy: an explicit allow/deny is authoritative; when unspecified, only loopback local labs enable them automatically and remote authorized targets keep them disabled.',
        'allow_state_changes': state.get('allow_state_changes'),
        'authenticated_identity_count': sum(
            1 for profile in state['profiles']
            if bool(profile.get('cookies')) and _profile_has_effective_auth(state, str(profile.get('name') or ''))
        ),
        # Compatibility alias for old report readers. Multi-identity reports should use authenticated_identity_count.
        'secondary_identity_supplied': bool(state.get('secondary_cookies', '')) or sum(
            1 for profile in state['profiles']
            if bool(profile.get('cookies')) and _profile_has_effective_auth(state, str(profile.get('name') or ''))
        ) >= 2,
        'orchestration': {'engine': 'langgraph', 'mode': 'agentic', 'nodes': ['discovery', 'planner', 'executor', 'verification', 'analysis', 'report']}}
    report = asyncio.run(call_mcp('reporting/reportServer.py', 'generate_report', {'findings_summary': report_results, 'target_url': state['target'], 'output_name': output_name, 'assessment_context': context}))
    if report.get('status') != 'success':
        if not any((report.get('json_filename'), report.get('html_filename'), report.get('pdf_filename'), report.get('review_snapshot_filename'))):
            report = shared.recover_normal_report_artifacts(output_name, report)
            if report.get('normal_report_artifacts_recovered'):
                print(f"[REPORT RECOVERY] Reusing normal report artifacts already written for {output_name}; emergency report not required.", flush=True)
        if report.get('status') != 'success':
            print(f"[REPORT ERROR] {report.get('diagnosis') or 'report_failed'} — {report.get('output') or 'No report error detail returned.'}", file=sys.stderr, flush=True)
    if report.get('status') != 'success' and not any((report.get('json_filename'), report.get('html_filename'), report.get('pdf_filename'), report.get('review_snapshot_filename'))):
        fallback = write_emergency_json_report(state['target'], state['results'], state['diagnostics'], str(report.get('output', 'Report MCP failed.')), f'{output_name}_Emergency')
        if fallback:
            report.update(json_filename=fallback, html_filename=str(Path(fallback).with_suffix('.html')), local_json_fallback=True, emergency_report=True)
    return {'report_status': report, 'results': report_results}
