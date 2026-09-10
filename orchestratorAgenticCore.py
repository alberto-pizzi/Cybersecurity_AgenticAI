from __future__ import annotations

import asyncio
import copy
import getpass
import json
import re
import platform
import socket
import sys
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
    BROAD_SCANNER_TIMEOUTS, PARAMETER_TOOL_TIMEOUTS, _tool_case_skip_reason,
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
    'fast': 900,
    'balanced': 1800,
    'deep': 3000,
}

AI_PLANNER_MAX_PREDICT = {
    'fast': 800,
    'balanced': 1300,
    'deep': 1800,
}

AI_PLANNER_CONTEXT_WINDOWS = {
    'fast': 6144,
    'balanced': 8192,
    'deep': 12288,
}

# Same CPU-only-Ollama rationale as AI_PLANNER_TIMEOUTS above: this is a hard ceiling on
# batch_budget (analysis_node caps it with min(ai_timeout, this value)), so raising --ai-timeout
# alone does not help this stage unless this dict is also raised.
AI_ANALYSIS_BATCH_TIMEOUTS = {
    'fast': 480,
    'balanced': 900,
    'deep': 1500,
}
AI_ANALYSIS_BATCH_SIZES = {'fast': 2, 'balanced': 4, 'deep': 6}
AI_ANALYSIS_MAX_PREDICT = {'fast': 520, 'balanced': 850, 'deep': 1200}
AI_ANALYSIS_RESCUE_MAX_PREDICT = {'fast': 340, 'balanced': 460, 'deep': 600}
AI_ANALYSIS_CONTEXT_WINDOWS = {'fast': 6144, 'balanced': 8192, 'deep': 12288}
LAST_AI_PLAN_DIAGNOSTICS: dict[str, Any] = {}
BROAD_COVERAGE_TOOLS = ('ffuf', 'zap', 'nuclei', 'session', 'nikto')
PARAMETER_COVERAGE_TOOLS = ('sqlmap', 'dalfox', 'commix', 'traversal', 'idor')
AUTHORIZATION_COVERAGE_TOOLS = ('authorization',)
WORKFLOW_COVERAGE_TOOLS = ('browser', 'workflow')
# Broad baseline coverage and cheap local JWT analysis are mandatory when discovery makes them eligible.
# The AI still chooses complementary specialist/workflow groups; it cannot accidentally omit the baseline.
AGENTIC_BASELINE_TOOLS = ('ffuf', 'zap', 'nuclei', 'session', 'nikto', 'jwt')
# Planner choices are tool/capability groups, while concrete scanner executions are expanded
# deterministically afterwards. Both budgets are independent for every active profile so
# anonymous work cannot consume authenticated capacity, or vice versa.
PROFILE_EXECUTION_ACTION_BUDGETS = {'fast': 48, 'balanced': 144, 'deep': 288}
# Concrete execution can grow above the base only when selected capability groups still contain
# validated request actions. The ceiling is per profile and per round and is intentionally above
# the sum of all current per-tool maxima, so it normally acts only as an emergency guardrail.
PROFILE_EXECUTION_ACTION_MAX = {'fast': 80, 'balanced': 240, 'deep': 480}
PROFILE_TOOL_GROUP_BUDGETS = {'fast': 12, 'balanced': 16, 'deep': 18}
PROFILE_BREADTH_REVIEW_GROUP_CAPS = {'fast': 3, 'balanced': 6, 'deep': 8}
# A grouped catalog is much smaller than the concrete request-action pool. The limit is only a
# prompt guard and is filled fairly across profiles; normally every available profile/tool group fits.
PLANNER_GROUP_CANDIDATE_LIMITS = {'fast': 32, 'balanced': 40, 'deep': 48}
PLAN_SCHEMA = {
    'type': 'object',
    'properties': {
        'reasoning_summary': {'type': 'string'},
        'selected_action_ids': {'type': 'array', 'items': {'type': 'string'}},
        'finish': {'type': 'boolean'},
    },
    'required': ['reasoning_summary', 'selected_action_ids', 'finish'],
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
    # If the requested local model cannot be used, fall back only to the other
    # explicitly supported local planner model rather than to an arbitrary installed tag.
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

# Parses the compact ID-selection contract shared by every supported AI provider.
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
    return value


# The model sees compact identifiers; Python retains the exact validated request contracts.
def _planner_candidate_view(action: dict[str, Any], candidate_id: str) -> dict[str, Any]:
    return {
        'id': candidate_id,
        'profile': str(action.get('profile') or ''),
        'tool': str(action.get('tool') or ''),
        'method': str(action.get('method') or 'GET'),
        'url': str(action.get('target_url') or ''),
        'parameters': [str(value) for value in action.get('parameters', [])][:10],
        'file_parameters': [str(value) for value in action.get('file_parameters', [])][:6],
        'token_parameters': [str(value) for value in action.get('token_parameters', [])][:6],
        'oast_class': str(action.get('oast_class') or ''),
        'evidence': str(action.get('reason') or '')[:220],
    }


# Groups concrete request-level actions by profile and tool before they are shown to the AI.
# The model therefore decides which capabilities are useful; Python still decides which exact
# ranked request contracts each selected capability receives.
def _planner_action_groups(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for action in actions:
        key = (str(action.get('profile') or ''), str(action.get('tool') or '').lower())
        if key not in groups:
            groups[key] = {'profile': key[0], 'tool': key[1], 'actions': []}
            order.append(key)
        groups[key]['actions'].append(action)
    return [groups[key] for key in order]


# Compact AI view for one profile/tool capability group. Exact request bodies remain local.
def _planner_group_candidate_view(group: dict[str, Any], candidate_id: str) -> dict[str, Any]:
    actions = [item for item in group.get('actions', []) if isinstance(item, dict)]
    examples = []
    for action in actions[:4]:
        examples.append({
            'method': str(action.get('method') or 'GET'),
            'url': str(action.get('target_url') or ''),
            'parameters': [str(value) for value in action.get('parameters', [])][:6],
            'adaptive': bool(action.get('adaptive_budget')),
            'evidence': str(action.get('reason') or '')[:150],
        })
    return {
        'id': candidate_id,
        'profile': str(group.get('profile') or ''),
        'tool': str(group.get('tool') or ''),
        'concrete_action_count': len(actions),
        'adaptive_action_count': sum(bool(action.get('adaptive_budget')) for action in actions),
        'examples': examples,
    }


# Prompt groups are bounded fairly by profile. Since there is at most one group per profile/tool,
# this guard normally keeps every capability and only matters for future registry growth.
def _fair_planner_group_catalog(groups: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    cap = max(1, int(limit))
    if len(groups) <= cap:
        return list(groups)
    by_profile: dict[str, list[dict[str, Any]]] = {}
    profile_order: list[str] = []
    for group in groups:
        profile = str(group.get('profile') or '')
        if profile not in by_profile:
            by_profile[profile] = []
            profile_order.append(profile)
        by_profile[profile].append(group)
    offsets = {profile: 0 for profile in profile_order}
    selected: list[dict[str, Any]] = []
    while len(selected) < cap:
        added = False
        for profile in profile_order:
            index = offsets[profile]
            bucket = by_profile[profile]
            if index >= len(bucket):
                continue
            selected.append(bucket[index])
            offsets[profile] = index + 1
            added = True
            if len(selected) >= cap:
                break
        if not added:
            break
    return selected


# Expands AI-selected capability groups back into concrete request actions. The per-profile base
# grows automatically up to a hard ceiling when selected groups still contain validated cases.
# Expansion remains round-robin and consumes non-adaptive specialist cases before adaptive overflow,
# so a large SQLMap/Dalfox family cannot starve the other selected capabilities.
def _expand_planner_groups(
    selected_groups: list[tuple[str, dict[str, Any], str]],
    *,
    per_profile_budget: int,
    per_profile_max: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, int]]]:
    by_profile: dict[str, list[tuple[str, dict[str, Any], str]]] = {}
    profile_order: list[str] = []
    for candidate_id, group, selection_source in selected_groups:
        profile = str(group.get('profile') or '')
        if profile not in by_profile:
            by_profile[profile] = []
            profile_order.append(profile)
        by_profile[profile].append((candidate_id, group, selection_source))

    expanded: list[dict[str, Any]] = []
    diagnostics: dict[str, dict[str, int]] = {}
    for profile in profile_order:
        groups = by_profile[profile]
        prepared: list[tuple[str, dict[str, Any], str, list[dict[str, Any]]]] = []
        available = 0
        adaptive_available = 0
        for candidate_id, group, selection_source in groups:
            actions = [item for item in group.get('actions', []) if isinstance(item, dict)]
            # The specialist selector appends adaptive cases after the base. Make that ordering
            # explicit here as well so a future producer cannot place overflow ahead of base cases.
            actions = sorted(actions, key=lambda item: bool(item.get('adaptive_budget')))
            prepared.append((candidate_id, group, selection_source, actions))
            available += len(actions)
            adaptive_available += sum(bool(item.get('adaptive_budget')) for item in actions)

        base = max(1, int(per_profile_budget))
        maximum = max(base, int(per_profile_max))
        effective = min(maximum, available)
        offsets = [0] * len(prepared)
        used = 0
        while used < effective:
            added = False
            for index, (candidate_id, group, selection_source, actions) in enumerate(prepared):
                offset = offsets[index]
                if offset >= len(actions):
                    continue
                action = dict(actions[offset])
                offsets[index] += 1
                action['planner_group_id'] = candidate_id
                action['planner_group_action_index'] = offset + 1
                action['planner_group_action_count'] = len(actions)
                if selection_source == 'baseline':
                    prefix = 'Deterministic baseline selected'
                elif selection_source == 'review':
                    prefix = 'AI review selected'
                else:
                    prefix = 'AI selected'
                action['reason'] = f"{prefix} {candidate_id} ({group.get('tool')} capability): {str(action.get('reason') or 'discovery-derived candidate')[:380]}"
                expanded.append(action)
                used += 1
                added = True
                if used >= effective:
                    break
            if not added:
                break
        diagnostics[profile] = {
            'base': base,
            'adaptive_max': maximum,
            'available': available,
            'selected': used,
            'execution_overflow_used': max(0, used - min(base, used)),
            'adaptive_cases_available': adaptive_available,
            'deferred': max(0, available - used),
        }
    return expanded, diagnostics


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
    return '|'.join((
        str(action.get('profile', '')), str(action.get('tool', '')), str(action.get('target_url', '')),
        str(action.get('method', '')), str(action.get('data', '')), ','.join(parameter_names),
        ','.join(file_names), ','.join(token_names), ','.join(field_names),
        str(action.get('jwt_token', '')), str(action.get('injection_url', '')),
    ))


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
        ('already_selected_action_ids', 'tool groups already selected'),
        ('selected_action_ids', 'selected tool groups'),
        ('remaining_candidates', 'remaining tool groups'),
        ('reasoning_summary', 'reasoning'),
        ('tool_group_budget_per_profile', 'tool-group budget per profile'),
        ('execution_action_budget_per_profile', 'base concrete execution budget per profile'),
        ('execution_action_adaptive_max_per_profile', 'adaptive concrete execution ceiling per profile'),
        ('remaining_slots_by_profile', 'remaining slots by profile'),
    )
    for internal, readable in replacements:
        text = text.replace(internal, readable)
    text = re.sub(r'\bredundant with actions already selected\b', 'overlap with actions already selected', text, flags=re.IGNORECASE)
    return re.sub(r'\s+', ' ', text).strip()

def _planner_system_message() -> str:
    # The provider-specific prompt uses explicit role, constraints, definitions and output sections.
    # Reuse that structure while keeping this planner task-specific and compact for local models.
    return (
        '[ROLE]\n'
        'You are the autonomous planner for an explicitly authorized web-security assessment. '
        'Choose the next useful scanner capability groups from discovery-derived candidate IDs. Each candidate represents one tool for one profile and may contain several concrete request-level actions that Python will rank and bound.\n\n'
        '[OBJECTIVE]\n'
        'Maximize useful and complementary security evidence within each profile-specific tool-group budget. '
        'Do not execute tools yourself and do not invent endpoints, parameters, identities or candidate IDs.\n\n'
        '[INPUT CONTRACT]\n'
        'The user message is JSON containing target, round, scan mode, discovery summary, previous results, available tools and candidates. '
        'Every candidate has already been derived from live discovery and will be validated again by Python.\n\n'
        '[DECISION RULES]\n'
        '- Baseline groups listed in baseline_group_ids are already selected deterministically; do not rely on the model to preserve broad coverage or JWT analysis.\n'
        '- Evaluate every remaining profile/tool group before returning the plan.\n'
        '- SELECT a profile/tool group when that capability can add useful, complementary or independent evidence for that profile; Python chooses the exact ranked request contracts inside the group.\n'
        '- DEFER only for a concrete reason: real duplication, already completed equivalent work, unsupported discovery, incompatible input, unsafe action, or clearly very low expected value.\n'
        '- Broad scanners and targeted tools are complementary; neither category replaces the other by default.\n'
        '- A confirmed finding does not stop exploration of unrelated attack surfaces.\n'
        '- Use IDOR only for suitable numeric references, authorization only for read-only identity/object/resource signals, and Interactsh only for compatible OAST inputs.\n'
        '- tool_group_budget_per_profile is an independent maximum for each active profile, not a shared quota. Never add groups merely to reach a count.\n'
        '- Concrete request execution is bounded separately by a base and an adaptive maximum for each profile. Python, not the model, decides whether selected groups contain enough validated work to use capacity above the base.\n'
        '- Do not omit authenticated coverage merely because anonymous groups were selected: the two profiles have separate planning and concrete execution capacity.\n'
        '- Set finish=true only when no remaining candidate is likely to add useful evidence.\n\n'
        '[OUTPUT CONTRACT]\n'
        'Return exactly one JSON object with these fields and no others: '
        '{"reasoning_summary":"brief decision summary, not chain-of-thought","selected_action_ids":["candidate IDs"],"finish":false}. '
        'reasoning_summary must be concise and must not reveal hidden chain-of-thought.\n\n'
        '[FINAL INSTRUCTION]\n'
        'Return only valid JSON. Re-check that every selected_action_id exists in candidates and that finish matches the remaining useful work.'
    )


def _planner_review_system_message() -> str:
    return (
        '[ROLE]\nYou are the breadth-review pass for an explicitly authorized web-security assessment.\n\n'
        '[OBJECTIVE]\nReview only the profile/tool groups deferred by the first AI plan and add useful complementary capabilities that were missed, especially for sparse profiles.\n\n'
        '[RULES]\n'
        '- Evaluate every remaining profile/tool group.\n'
        '- ADD discovery-supported profile/tool groups that can provide useful, complementary or independent evidence.\n'
        '- KEEP DEFERRED only for concrete duplication, completed equivalent work, unsupported discovery, incompatibility, unsafe action or clearly very low value.\n'
        '- Broad scanners and targeted tools remain complementary; do not reject one category solely because the other was already selected.\n'
        '- Do not repeat already_selected_action_ids and do not add actions merely to fill remaining slots.\n'
        "- Respect review_addition_cap_per_profile and remaining_slots_by_profile strictly; one profile must never consume another profile's capacity.\n\n"
        '[OUTPUT CONTRACT]\n'
        'Return exactly one JSON object: {"reasoning_summary":"brief review summary","selected_action_ids":["remaining candidate IDs"],"finish":false}.\n\n'
        '[FINAL INSTRUCTION]\nReturn only valid JSON.'
    )


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


# Asks the selected AI provider which profile/tool capabilities should run next. Python expands
# each selected capability into exact ranked request actions under an independent budget per profile.
def ai_plan(state: AgentState) -> dict[str, Any]:
    concrete_pool = _eligible_action_catalog(state)
    group_pool = _planner_action_groups(concrete_pool)
    eligible_groups = _fair_planner_group_catalog(
        group_pool, PLANNER_GROUP_CANDIDATE_LIMITS.get(shared.CURRENT_SCAN_MODE, 32)
    )
    candidate_map = {f'G{index:03d}': group for index, group in enumerate(eligible_groups, 1)}
    candidates = [_planner_group_candidate_view(group, candidate_id) for candidate_id, group in candidate_map.items()]
    baseline_group_ids = [
        candidate_id for candidate_id, group in candidate_map.items()
        if str(group.get('tool') or '').lower() in AGENTIC_BASELINE_TOOLS
    ]
    candidate_tools = sorted({str(group.get('tool') or '') for group in eligible_groups})
    registry = {
        name: {'scope': REGISTRY[name][2], 'description': str(REGISTRY[name][3])[:180]}
        for name in candidate_tools if name in REGISTRY
    }
    profile_names = list(dict.fromkeys(str(group.get('profile') or '') for group in eligible_groups if str(group.get('profile') or '')))
    group_budget = PROFILE_TOOL_GROUP_BUDGETS.get(shared.CURRENT_SCAN_MODE, 12)
    execution_budget = PROFILE_EXECUTION_ACTION_BUDGETS.get(shared.CURRENT_SCAN_MODE, 48)
    execution_max = PROFILE_EXECUTION_ACTION_MAX.get(shared.CURRENT_SCAN_MODE, execution_budget)
    prompt = {
        'target': state['target'],
        'round': state['round'] + 1,
        'maximum_rounds': state['max_rounds'],
        'tool_group_budget_per_profile': group_budget,
        'execution_action_budget_per_profile': execution_budget,
        'execution_action_adaptive_max_per_profile': execution_max,
        'active_profiles': profile_names,
        'scan_mode': shared.CURRENT_SCAN_MODE,
        'discovery_summary': _planner_discovery_summary(state['discovery']),
        'previous_results': compact_results(state['results']),
        'available_tools': registry,
        'baseline_group_ids': baseline_group_ids,
        'candidates': candidates,
    }
    system_message = _planner_system_message()
    provider = str(state.get('ai_provider') or 'ollama').lower()
    base = state['ollama_url'].rstrip('/')
    total_timeout = max(120, int(state.get('ai_timeout') or 480))
    max_predict = AI_PLANNER_MAX_PREDICT.get(shared.CURRENT_SCAN_MODE, 320)
    context = json.dumps(prompt, ensure_ascii=False, separators=(',', ':'))
    context_window = AI_PLANNER_CONTEXT_WINDOWS.get(shared.CURRENT_SCAN_MODE, 6144)
    common_options = {'temperature': 0, 'num_predict': max_predict, 'num_ctx': context_window, 'top_p': 0.9}
    LAST_AI_PLAN_DIAGNOSTICS.clear()
    LAST_AI_PLAN_DIAGNOSTICS.update({
        'endpoint': 'pending',
        'context_bytes': len(context.encode('utf-8')),
        'candidate_count': len(candidates),
        'candidate_pool_count': len(group_pool),
        'concrete_action_pool_count': len(concrete_pool),
        'selected_action_ids': [],
        'seconds': 0.0,
        'attempt_errors': [],
    })
    if provider == 'snap4city':
        attempts = [('snap4city', '', {}, total_timeout)]
    else:
        attempts = [
            ('chat', f'{base}/api/chat', {
                'model': state['model'],
                'format': PLAN_SCHEMA,
                'messages': [
                    {'role': 'system', 'content': system_message},
                    {'role': 'user', 'content': context},
                ],
                'options': common_options,
                'keep_alive': '30m',
            }, total_timeout),
            ('generate', f'{base}/api/generate', {
                'model': state['model'],
                'format': PLAN_SCHEMA,
                'prompt': system_message + '\n\nAssessment context:\n' + context,
                'options': common_options,
                'keep_alive': '30m',
            }, total_timeout),
        ]
    errors: list[str] = []
    planning_started = time.monotonic()
    for kind, url, payload, budget in attempts:
        started = time.monotonic()
        try:
            if provider == 'snap4city':
                content = _snap4city_chat_content(
                    state, system_message, context,
                    total_timeout=budget, temperature=0.0,
                )
            else:
                content = _ollama_stream_content(url, payload, response_kind=kind, total_timeout=budget, early_json=True)
            compact_plan = _parse_ai_plan_content(content)
            requested_ids = [str(value) for value in compact_plan.get('selected_action_ids', [])]
            selected_ids: list[str] = []
            selected_groups: list[tuple[str, dict[str, Any], str]] = []
            selected_per_profile: dict[str, int] = {}
            baseline_selected_ids: list[str] = []
            ai_selected_ids: list[str] = []
            baseline_per_profile: dict[str, int] = {}
            for candidate_id in baseline_group_ids:
                group = candidate_map.get(candidate_id)
                if group is None:
                    continue
                profile = str(group.get('profile') or '')
                if selected_per_profile.get(profile, 0) >= group_budget:
                    continue
                selected_ids.append(candidate_id)
                baseline_selected_ids.append(candidate_id)
                selected_groups.append((candidate_id, group, 'baseline'))
                selected_per_profile[profile] = selected_per_profile.get(profile, 0) + 1
                baseline_per_profile[profile] = baseline_per_profile.get(profile, 0) + 1
            for candidate_id in requested_ids:
                group = candidate_map.get(candidate_id)
                if group is None or candidate_id in selected_ids:
                    continue
                profile = str(group.get('profile') or '')
                if selected_per_profile.get(profile, 0) >= group_budget:
                    continue
                selected_ids.append(candidate_id)
                ai_selected_ids.append(candidate_id)
                selected_groups.append((candidate_id, group, 'initial'))
                selected_per_profile[profile] = selected_per_profile.get(profile, 0) + 1

            # Breadth recovery is evaluated per profile. A sparse/omitted authenticated plan can
            # therefore be reviewed without consuming the anonymous profile's independent capacity.
            review_selected_ids: list[str] = []
            review_seconds = 0.0
            review_error = ''
            review_reasoning = ''
            eligible_per_profile: dict[str, int] = {}
            for group in eligible_groups:
                profile = str(group.get('profile') or '')
                eligible_per_profile[profile] = eligible_per_profile.get(profile, 0) + 1
            review_cap_per_profile = PROFILE_BREADTH_REVIEW_GROUP_CAPS.get(shared.CURRENT_SCAN_MODE, 4)
            remaining_slots_by_profile = {
                profile: max(0, group_budget - selected_per_profile.get(profile, 0))
                for profile in eligible_per_profile
            }
            # Mandatory baseline groups must not make a profile look well-covered by the AI.
            # Breadth recovery judges only the discretionary (non-baseline) capability choices.
            sparse_profiles = []
            for profile, eligible_count in eligible_per_profile.items():
                baseline_count = baseline_per_profile.get(profile, 0)
                discretionary_eligible = max(0, eligible_count - baseline_count)
                discretionary_selected = max(0, selected_per_profile.get(profile, 0) - baseline_count)
                if (
                    remaining_slots_by_profile.get(profile, 0) > 0
                    and discretionary_eligible > discretionary_selected
                    and discretionary_selected <= max(1, discretionary_eligible // 3)
                ):
                    sparse_profiles.append(profile)
            review_addition_cap = sum(
                min(review_cap_per_profile, remaining_slots_by_profile.get(profile, 0))
                for profile in sparse_profiles
            )
            remaining_candidate_count = len(candidates) - len(selected_ids)
            review_time_budget = min(total_timeout, max(120, int(total_timeout * 0.40)))
            if sparse_profiles and remaining_candidate_count >= 1 and review_addition_cap > 0 and review_time_budget >= 30:
                remaining_candidates = [
                    candidate for candidate in candidates
                    if str(candidate.get('id') or '') not in selected_ids
                ]
                review_prompt = {
                    'target': state['target'],
                    'scan_mode': shared.CURRENT_SCAN_MODE,
                    'round': state['round'] + 1,
                    'tool_group_budget_per_profile': group_budget,
                    'execution_action_budget_per_profile': execution_budget,
                    'execution_action_adaptive_max_per_profile': execution_max,
                    'discovery_summary': prompt['discovery_summary'],
                    'previous_results': prompt['previous_results'],
                    'available_tools': registry,
                    'already_selected_action_ids': selected_ids,
                    'sparse_profiles': sparse_profiles,
                    'remaining_slots_by_profile': remaining_slots_by_profile,
                    'review_addition_cap_per_profile': review_cap_per_profile,
                    'remaining_candidates': remaining_candidates,
                    'previous_reasoning_summary': str(compact_plan.get('reasoning_summary') or '')[:240],
                }
                review_system_message = _planner_review_system_message()
                review_context = json.dumps(review_prompt, ensure_ascii=False, separators=(',', ':'))
                review_started = time.monotonic()
                try:
                    if provider == 'snap4city':
                        review_content = _snap4city_chat_content(
                            state, review_system_message, review_context,
                            total_timeout=review_time_budget, temperature=0.0,
                        )
                    else:
                        review_content = _ollama_stream_content(
                            f'{base}/api/chat',
                            {
                                'model': state['model'],
                                'format': PLAN_SCHEMA,
                                'messages': [
                                    {'role': 'system', 'content': review_system_message},
                                    {'role': 'user', 'content': review_context},
                                ],
                                'options': common_options,
                                'keep_alive': '30m',
                            },
                            response_kind='chat',
                            total_timeout=review_time_budget,
                            early_json=True,
                        )
                    review_plan = _parse_ai_plan_content(review_content)
                    review_reasoning = _humanize_planner_reasoning(review_plan.get('reasoning_summary'))[:500]
                    review_per_profile: dict[str, int] = {}
                    for candidate_id in [str(value) for value in review_plan.get('selected_action_ids', [])]:
                        group = candidate_map.get(candidate_id)
                        if group is None or candidate_id in selected_ids:
                            continue
                        profile = str(group.get('profile') or '')
                        if profile not in sparse_profiles:
                            continue
                        if selected_per_profile.get(profile, 0) >= group_budget:
                            continue
                        if review_per_profile.get(profile, 0) >= review_cap_per_profile:
                            continue
                        selected_ids.append(candidate_id)
                        review_selected_ids.append(candidate_id)
                        selected_groups.append((candidate_id, group, 'review'))
                        selected_per_profile[profile] = selected_per_profile.get(profile, 0) + 1
                        review_per_profile[profile] = review_per_profile.get(profile, 0) + 1
                except Exception as review_exc:
                    review_error = f'{type(review_exc).__name__}: {review_exc}'
                finally:
                    review_seconds = round(time.monotonic() - review_started, 2)

            selected_actions, execution_diagnostics = _expand_planner_groups(
                selected_groups,
                per_profile_budget=execution_budget,
                per_profile_max=execution_max,
            )
            concrete_selected_per_profile = {
                profile: int(values.get('selected', 0))
                for profile, values in execution_diagnostics.items()
            }

            selected_group_summaries = [
                {
                    'id': candidate_id,
                    'profile': str(group.get('profile') or ''),
                    'tool': str(group.get('tool') or ''),
                    'concrete_action_count': len(group.get('actions') or []),
                    'adaptive_action_count': sum(1 for item in (group.get('actions') or []) if isinstance(item, dict) and item.get('adaptive_budget')),
                    'source': source,
                }
                for candidate_id, group, source in selected_groups
            ]
            LAST_AI_PLAN_DIAGNOSTICS.clear()
            LAST_AI_PLAN_DIAGNOSTICS.update({
                'endpoint': kind,
                'context_bytes': len(context.encode('utf-8')),
                'candidate_count': len(candidates),
                'candidate_pool_count': len(group_pool),
                'concrete_action_pool_count': len(concrete_pool),
                'selected_action_ids': selected_ids,
                'selected_group_ids': selected_ids,
                'baseline_selected_group_ids': baseline_selected_ids,
                'baseline_groups_per_profile': dict(baseline_per_profile),
                'ai_selected_group_ids': ai_selected_ids,
                'review_selected_action_ids': review_selected_ids,
                'review_selected_group_ids': review_selected_ids,
                'selected_group_summaries': selected_group_summaries,
                'selected_groups_per_profile': dict(selected_per_profile),
                'expanded_actions_per_profile': concrete_selected_per_profile,
                'expanded_action_count': len(selected_actions),
                'tool_group_budget_per_profile': group_budget,
                'execution_action_budget_per_profile': execution_budget,
                'execution_action_adaptive_max_per_profile': execution_max,
                'execution_budget_diagnostics_per_profile': execution_diagnostics,
                'review_seconds': review_seconds,
                'review_error': review_error,
                'review_reasoning': review_reasoning,
                'seconds': round(time.monotonic() - planning_started, 2),
                'attempt_errors': list(errors),
            })
            return {
                'reasoning_summary': _humanize_planner_reasoning(compact_plan.get('reasoning_summary'))[:1000],
                'actions': selected_actions,
                'finish': bool(compact_plan.get('finish', False)),
            }
        except Exception as exc:
            errors.append(f'{kind}: {type(exc).__name__}: {exc}')
            LAST_AI_PLAN_DIAGNOSTICS.update({
                'endpoint': kind,
                'seconds': round(time.monotonic() - planning_started, 2),
                'attempt_errors': list(errors),
            })
    raise RuntimeError('; '.join(errors))

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


def _analysis_quality_check(rows: list[dict[str, Any]], expected: set[str]) -> list[dict[str, Any]]:
    # Validate the AI contract without failing strict mode for weak prose alone.
    # Strict agentic mode still requires a real, parseable AI assessment for every finding.
    # Narrative quality is handled field-by-field later: if the AI returns a materially
    # underdeveloped narrative field and the scanner has a stronger
    # original value, that one field falls back to the scanner text instead of aborting
    # the entire assessment.
    returned_ids = [str(item.get('id') or '') for item in rows]
    returned = set(returned_ids)
    if returned != expected or len(returned_ids) != len(expected):
        missing = sorted(expected - returned)
        extra = sorted(returned - expected)
        duplicates = sorted({value for value in returned_ids if returned_ids.count(value) > 1 and value})
        raise ValueError(f'Analysis IDs mismatch; missing={missing}, extra={extra}, duplicates={duplicates}')
    for row in rows:
        risk = str(row.get('risk') or '').lower()
        confidence = str(row.get('confidence') or '').lower()
        if risk not in {'critical', 'high', 'medium', 'low', 'info'} or confidence not in {'high', 'medium', 'low'}:
            raise ValueError(f"Analysis returned invalid risk/confidence for {row.get('id')!r}.")
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
    related_findings = [] if mode == 'fast' else _analysis_related_findings(batch, all_candidates)
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

    # For a one-finding request, reserve time for a compact rescue. For a larger
    # batch, use a shorter first attempt so adaptive splitting happens early.
    if len(batch) == 1:
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
    if remaining < 40:
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
) -> list[dict[str, Any]]:
    try:
        return _ai_analysis_batch(state, batch, all_candidates, timeout)
    except Exception as exc:
        if len(batch) <= 1:
            raise
        midpoint = max(1, len(batch) // 2)
        left = batch[:midpoint]
        right = batch[midpoint:]
        print(
            f'    AI analysis: {label} did not complete cleanly; retrying as smaller AI batches ({len(left)} + {len(right)} findings).',
            flush=True,
        )
        rows: list[dict[str, Any]] = []
        rows.extend(_ai_analysis_batch_adaptive(state, left, all_candidates, timeout, label=f'{label}.1'))
        rows.extend(_ai_analysis_batch_adaptive(state, right, all_candidates, timeout, label=f'{label}.2'))
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
                rows = _ai_analysis_batch_adaptive(state, batch, candidates, batch_budget, label=f'batch {batch_index + 1}/{batch_count}')
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
        found = discover_target_sync_safe(state['target'], profile['cookies'])
        discovery[profile['name']] = found
        diagnostics.extend(({'phase': 'discovery', 'profile': profile['name'], **item} for item in found['errors']))
        print(f"    {profile['name']}: {len(found.get('html_urls', []))} HTML pages, {len(found.get('request_cases', []))} request contracts, {len(found.get('browser_network_requests', []))} browser network requests, {len(found.get('browser_navigation_urls', []))} Chromium navigations, {len(found['jwt_tokens'])} JWTs")
        budget = found.get('budget_diagnostics', {})
        dead_count = int(budget.get('dead_http_404_410', 0) or 0)
        if dead_count:
            print(f"      [DISCOVERY] {dead_count} HTTP 404/410 responses kept as diagnostics and excluded from the useful-page budget; HTTP attempts={budget.get('http_requests_attempted', 0)}/{budget.get('http_attempt_budget', 0)}")
        browser_budget = int(budget.get('browser_page_budget', 0) or 0)
        browser_used = len(found.get('browser_navigation_urls', []))
        if browser_budget and browser_used >= browser_budget:
            print(f"      [DISCOVERY] Chromium navigation budget saturated: {browser_used}/{browser_budget}; additional dynamic pages may remain unnavigated.")
        browser_warning = shared.chromium_discovery_warning(found)
        if browser_warning:
            print(f"      [BROWSER WARNING] {browser_warning}")
        for error in shared.prioritized_discovery_errors(found.get('errors', []))[:5]:
            print(f"      [DISCOVERY WARNING] {error.get('type', 'error')}: {shared.compact_log_url(error.get('url', ''))} — {error.get('message', '')}")
        if found.get('authentication_effective') is False:
            print(f"    [WARNING] {profile['name']}: {found.get('authentication_note')}", file=sys.stderr)
    return {'discovery': discovery, 'diagnostics': diagnostics}

# Discovery evidence is converted into tool actions that the planner can safely choose.
def discovery_candidate_actions(state: AgentState) -> list[dict[str, Any]]:

    actions: list[dict[str, Any]] = []
    for profile in state['profiles']:
        name = profile['name']
        if not _profile_is_plannable(state, name):
            continue
        authenticated = _profile_has_effective_auth(state, name)
        broad = list(shared.broad_tool_order(authenticated))
        for tool in broad:
            actions.append({'profile': name, 'tool': tool, 'target_url': state['target'], 'jwt_token': '', 'injection_url': '', 'reason': 'Session-aware baseline coverage.'})
        anonymous_available = any(
            str(item.get('name') or '') == 'anonymous' and _profile_is_plannable(state, 'anonymous')
            for item in state['profiles']
        )
        # Sibling origins never receive the primary target cookie. When an anonymous profile exists,
        # scan each sibling broad surface only once there instead of duplicating an identical no-cookie
        # ZAP/Nuclei/Nikto run under the authenticated profile label.
        if name == 'anonymous' or not anonymous_available:
            for sibling_origin in shared.discovered_scope_origins(state['discovery'].get(name, {}), state['target']):
                for tool in ('zap', 'nuclei', 'nikto'):
                    actions.append({'profile': name, 'tool': tool, 'target_url': sibling_origin, 'jwt_token': '', 'injection_url': '', 'reason': 'Broad no-cookie coverage for an explicitly authorized sibling origin observed during discovery.'})
        for case in select_arjun_request_cases(state['discovery'].get(name, {}), state['target'], limit=shared.ARJUN_ENDPOINT_LIMIT):
            adaptive = bool(case.get('adaptive_budget'))
            actions.append({'profile': name, 'tool': 'arjun', 'target_url': case['url'], 'method': case.get('method', 'GET'), 'data': case.get('data', ''), 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': '', 'adaptive_budget': adaptive, 'priority_score': case.get('priority_score'), 'reason': ('Adaptive high-value overflow selected by deterministic ranking: ' if adaptive else '') + 'Hidden-parameter discovery using the real request method and body.'})
        for tool in ('sqlmap', 'dalfox', 'commix', 'traversal', 'idor'):
            for case in select_tool_request_cases(state['discovery'].get(name, {}), tool, limit=shared.PARAMETER_TOOL_CASE_LIMITS.get(tool, 1), authenticated_profile=authenticated):
                adaptive = bool(case.get('adaptive_budget'))
                actions.append({'profile': name, 'tool': tool, 'target_url': case['url'], 'method': case.get('method', 'GET'), 'data': case.get('data', ''), 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': '', 'adaptive_budget': adaptive, 'priority_score': case.get('priority_score'), 'reason': (f'Adaptive high-value overflow selected by deterministic ranking for {tool}. ' if adaptive else '') + f'Highest-value discovered request for {tool}.'})
        if authenticated:
            for case in select_authorization_request_cases(state['discovery'].get(name, {}), limit=shared.tool_action_limit('authorization')):
                adaptive = bool(case.get('adaptive_budget'))
                actions.append({'profile': name, 'tool': 'authorization', 'target_url': case['url'], 'method': 'GET', 'data': '', 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': '', 'adaptive_budget': adaptive, 'priority_score': case.get('priority_score'), 'reason': ('Adaptive high-value overflow selected by deterministic ranking for authorization. ' if adaptive else '') + 'Read-only authorization differential candidate derived from an identity, object or privileged-resource signal.'})
        for case in select_browser_request_cases(state['discovery'].get(name, {}), limit=shared.tool_action_limit('browser')):
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
                'reason': ('Adaptive high-value overflow selected by deterministic ranking. ' if case.get('adaptive_budget') else '') + 'Browser verification candidate derived from XSS-like parameters or client-side source/sink evidence.'})
        for case in select_workflow_request_cases(state['discovery'].get(name, {}), limit=shared.tool_action_limit('workflow')):
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
                'reason': ('Adaptive high-value overflow selected by deterministic ranking. ' if case.get('adaptive_budget') else '') + 'Multi-step workflow candidate derived from discovered form metadata.'})
        tokens = [str(value) for value in state['discovery'].get(name, {}).get('jwt_tokens', []) if str(value)][:shared.jwt_token_limit()]
        for token in tokens:
            actions.append({'profile': name, 'tool': 'jwt', 'target_url': state['target'], 'jwt_token': token, 'injection_url': '', 'reason': 'Discovered JWT selected within the bounded per-profile token budget.'})
        if state['injection_url']:
            actions.append({'profile': name, 'tool': 'interactsh', 'target_url': state['target'], 'method': 'GET', 'data': '', 'parameters': ['explicit'], 'jwt_token': '', 'injection_url': state['injection_url'], 'oast_class': 'explicit', 'reason': 'Configured OAST URL.'})
        else:
            for case in select_oast_request_cases(state['discovery'].get(name, {}), state['target'], limit=shared.tool_action_limit('interactsh')):
                actions.append({'profile': name, 'tool': 'interactsh', 'target_url': state['target'], 'method': case.get('method', 'GET'), 'data': case.get('data', ''), 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': case.get('injection_url', ''), 'oast_class': case.get('oast_class', 'remote-fetch'), 'reason': f"Automatically selected OAST-capable parameter: {case.get('parameter', 'unknown')}."})
    return actions

# Planner validation compares proposed actions with target scope, discovery evidence, and safety rules.
def validate_plan(state: AgentState, proposed: Any) -> list[dict[str, Any]]:
    if not isinstance(proposed, list):
        return []
    profiles = {profile['name'] for profile in state['profiles']}
    completed, valid = (set(state['completed']), [])
    per_tool: dict[tuple[str, str], int] = {}
    proposal_limit = max(512, PROFILE_EXECUTION_ACTION_BUDGETS.get(shared.CURRENT_SCAN_MODE, 20) * max(1, len(state.get('profiles', []))) * 8)
    for raw in proposed[:proposal_limit]:
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
                sibling_origins = set(shared.discovered_scope_origins(found, state['target']))
                if (not target_url) or shared.same_origin(state['target'], target_url):
                    target_url = state['target']
                else:
                    normalized_target = shared.normalized_origin(target_url)
                    if normalized_target not in sibling_origins:
                        continue
                    target_url = normalized_target
        elif scope == 'url':
            cases = select_arjun_request_cases(found, state['target'], limit=shared.ARJUN_ENDPOINT_LIMIT)
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
            cases = select_tool_request_cases(found, tool, limit=shared.PARAMETER_TOOL_CASE_LIMITS.get(tool, 1), authenticated_profile=profile_has_cookie)
            matching = [case for case in cases if str(case.get('url', '')) == target_url]
            if method:
                matching = [case for case in matching if str(case.get('method', 'GET')).upper() == method]
            if not matching:
                continue
            selected = matching[0]
            if _tool_case_skip_reason(tool, selected, authenticated_profile=profile_has_cookie):
                continue
            method = str(selected.get('method', 'GET')).upper()
            data = str(selected.get('data', ''))
            parameters = [str(value) for value in selected.get('parameters', [])]
            if scope == 'numeric' and (method != 'GET' or not any((value.isdigit() for _, value in parse_qsl(urlparse(target_url).query, keep_blank_values=True)))):
                continue
        elif scope == 'authorization':
            if not profile_has_cookie:
                continue
            cases = select_authorization_request_cases(found, limit=shared.tool_action_limit('authorization'))
            matching = [case for case in cases if str(case.get('url', '')) == target_url]
            if not matching:
                continue
            selected = matching[0]
            method = 'GET'
            data = ''
            parameters = [str(value) for value in selected.get('parameters', [])]
        elif scope == 'browser':
            cases = select_browser_request_cases(found, limit=shared.tool_action_limit('browser'))
            matching = [case for case in cases if str(case.get('url', '')) == target_url]
            if method:
                matching = [case for case in matching if str(case.get('method', 'GET')).upper() == method]
            if not matching:
                continue
            selected = matching[0]
            method = str(selected.get('method', 'GET')).upper()
            data = str(selected.get('data', ''))
            parameters = [str(value) for value in selected.get('parameters', [])]
            source_url = str(selected.get('source_url', ''))
            fields = [dict(value) for value in selected.get('fields', []) if isinstance(value, dict)]
            client_sources = [str(value) for value in selected.get('client_sources', []) if str(value)]
            client_sinks = [str(value) for value in selected.get('client_sinks', []) if str(value)]
        elif scope == 'workflow':
            cases = select_workflow_request_cases(found, limit=shared.tool_action_limit('workflow'))
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
                candidates = select_oast_request_cases(found, state['target'], limit=5)
                matching = [item for item in candidates if not injection or item.get('injection_url') == injection]
                if not matching:
                    continue
                selected = matching[0]
                injection = str(selected.get('injection_url', ''))
                method = str(selected.get('method', 'GET')).upper()
                data = str(selected.get('data', ''))
                parameters = [str(value) for value in selected.get('parameters', [])]
                oast_class = str(selected.get('oast_class') or 'remote-fetch')
        action = {'profile': profile, 'tool': tool, 'target_url': target_url, 'method': method or 'GET', 'data': data, 'parameters': parameters, 'source_url': source_url, 'fields': fields, 'client_sources': client_sources, 'client_sinks': client_sinks, 'file_parameters': file_parameters, 'token_parameters': token_parameters, 'enctype': enctype, 'jwt_token': token, 'injection_url': injection, 'oast_class': oast_class, 'adaptive_budget': bool(selected.get('adaptive_budget')), 'priority_score': selected.get('priority_score'), 'reason': str(raw.get('reason', ''))[:500] or 'No planner reason supplied.'}
        identifier = action_id(action)
        key = (profile, tool)
        limit = shared.tool_action_limit(tool, include_adaptive=True)
        if per_tool.get(key, 0) >= limit:
            continue
        if identifier not in completed and all((action_id(item) != identifier for item in valid)):
            valid.append(action)
            per_tool[key] = per_tool.get(key, 0) + 1
    return valid

# Lists the actions that are currently valid for the planner.
# --only-tool is a debug filter only: when unset, the autonomous candidate set is unchanged.
def _eligible_action_catalog(state: AgentState) -> list[dict[str, Any]]:
    actions = validate_plan(state, discovery_candidate_actions(state))
    only_tool = str(state.get('only_tool') or '').strip().lower()
    if only_tool:
        actions = [action for action in actions if str(action.get('tool') or '').lower() == only_tool]
    return actions

# Builds the bounded prompt catalog fairly across profile/tool buckets. Within each bucket the
# existing deterministic ranking is preserved, while round-robin admission prevents the anonymous
# profile or an early broad-scanner family from starving authenticated/specialist candidates.
def _fair_planner_candidate_catalog(actions: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    cap = max(1, int(limit))
    if len(actions) <= cap:
        return list(actions)
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    bucket_order: list[tuple[str, str]] = []
    for action in actions:
        key = (str(action.get('profile') or ''), str(action.get('tool') or '').lower())
        if key not in buckets:
            buckets[key] = []
            bucket_order.append(key)
        buckets[key].append(action)
    selected: list[dict[str, Any]] = []
    offsets = {key: 0 for key in bucket_order}
    while len(selected) < cap:
        added = False
        for key in bucket_order:
            index = offsets[key]
            bucket = buckets[key]
            if index >= len(bucket):
                continue
            selected.append(bucket[index])
            offsets[key] = index + 1
            added = True
            if len(selected) >= cap:
                break
        if not added:
            break
    return selected

# Combines new AI actions with valid actions already selected.
def _merge_ai_actions(base: list[dict[str, Any]], additions: list[dict[str, Any]], *, budget: int) -> list[dict[str, Any]]:
    merged = list(base)
    known = {action_id(action) for action in merged}
    for action in additions:
        identifier = action_id(action)
        if identifier in known or len(merged) >= budget:
            continue
        merged.append(action)
        known.add(identifier)
    return merged

# Concrete execution capacity is enforced independently for each active profile.
def _merge_ai_actions_per_profile(base: list[dict[str, Any]], additions: list[dict[str, Any]], *, budget_per_profile: int) -> list[dict[str, Any]]:
    merged = list(base)
    known = {action_id(action) for action in merged}
    counts: dict[str, int] = {}
    for action in merged:
        profile = str(action.get('profile') or '')
        counts[profile] = counts.get(profile, 0) + 1
    for action in additions:
        identifier = action_id(action)
        profile = str(action.get('profile') or '')
        if identifier in known or counts.get(profile, 0) >= budget_per_profile:
            continue
        merged.append(action)
        known.add(identifier)
        counts[profile] = counts.get(profile, 0) + 1
    return merged

# Fallback planning selects a safe deterministic set of actions when AI planning is unavailable.
def _fallback_plan(state: AgentState, eligible: list[dict[str, Any]], budget_per_profile: int) -> list[dict[str, Any]]:

    authenticated = {str(profile.get('name') or ''): _profile_has_effective_auth(state, str(profile.get('name') or '')) for profile in state['profiles']}
    ordered = sorted(eligible, key=lambda action: (str(action.get('profile') or ''), shared.tool_execution_rank(str(action.get('tool') or ''), authenticated.get(str(action.get('profile') or ''), False)), str(action.get('target_url') or ''), str(action.get('tool') or '')))
    selected: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    per_profile_cap = min(max(1, int(budget_per_profile)), 3)
    for action in ordered:
        profile = str(action.get('profile') or '')
        if counts.get(profile, 0) >= per_profile_cap:
            continue
        selected.append(action)
        counts[profile] = counts.get(profile, 0) + 1
    return selected

# Pending-action filtering keeps only valid actions that have not run yet.
def _remaining_eligible_actions(state: AgentState) -> list[dict[str, Any]]:
    actions = validate_plan(state, discovery_candidate_actions(state))
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
        return '' if select_arjun_request_cases(found, state['target'], limit=1) else 'No suitable discovered GET/POST request was available for hidden-parameter discovery.'
    if tool in PARAMETER_COVERAGE_TOOLS:
        return '' if select_tool_request_cases(found, tool, limit=1, authenticated_profile=profile_has_cookie) else f"No discovered request matched {tool}'s vulnerability class."
    if tool == 'authorization':
        if not profile_has_cookie:
            return 'Authorization comparison requires a primary authenticated profile.'
        return '' if select_authorization_request_cases(found, limit=1) else 'No discovered read-only request contained a plausible identity, object or privileged-resource signal.'
    if tool == 'browser':
        return '' if select_browser_request_cases(found, limit=1) else 'No discovered request or client-side page matched browser XSS verification.'
    if tool == 'workflow':
        return '' if select_workflow_request_cases(found, limit=1) else 'No discovered POST form matched CSRF, upload, authentication or CAPTCHA workflow classes.'
    if tool == 'jwt':
        return '' if found.get('jwt_tokens') else 'No JWT was discovered in crawled responses.'
    if tool == 'interactsh':
        if state.get('injection_url') or select_oast_request_cases(found, state['target'], limit=1):
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

    return {'profile': str(action.get('profile') or ''), 'tool': str(action.get('tool') or ''), 'target_url': str(action.get('target_url') or ''), 'method': str(action.get('method') or 'GET'), 'parameters': [str(value) for value in action.get('parameters', [])][:12], 'reason': str(action.get('reason') or '')[:500]}

# At each planning round, the model proposes useful actions and validation filters unsafe or unsupported choices.
def planner_node(state: AgentState) -> dict[str, Any]:
    round_number = state['round'] + 1
    notes = list(state['notes'])
    audit = list(state.get('planner_audit', []))
    eligible = _eligible_action_catalog(state)
    budget_per_profile = PROFILE_EXECUTION_ACTION_BUDGETS.get(shared.CURRENT_SCAN_MODE, 48)
    max_budget_per_profile = PROFILE_EXECUTION_ACTION_MAX.get(shared.CURRENT_SCAN_MODE, budget_per_profile)
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
        validated_plan = validate_plan(state, decision.get('actions', []))
        validated_concrete_action_count = len(validated_plan)
        plan = _merge_ai_actions_per_profile([], validated_plan, budget_per_profile=max_budget_per_profile)
        summary = str(decision.get('reasoning_summary', ''))[:1000]
        finished = bool(decision.get('finish', False)) and (not plan)
        endpoint = str(LAST_AI_PLAN_DIAGNOSTICS.get('endpoint', 'unknown'))
        context_bytes = int(LAST_AI_PLAN_DIAGNOSTICS.get('context_bytes', 0) or 0)
        planner_seconds = float(LAST_AI_PLAN_DIAGNOSTICS.get('seconds', 0) or 0)
        candidate_count = int(LAST_AI_PLAN_DIAGNOSTICS.get('candidate_count', 0) or 0)
        candidate_pool_count = int(LAST_AI_PLAN_DIAGNOSTICS.get('candidate_pool_count', candidate_count) or candidate_count)
        selected_ids = [str(value) for value in LAST_AI_PLAN_DIAGNOSTICS.get('selected_action_ids', [])]
        baseline_selected_ids = [str(value) for value in LAST_AI_PLAN_DIAGNOSTICS.get('baseline_selected_group_ids', [])]
        discretionary_ai_ids = [str(value) for value in LAST_AI_PLAN_DIAGNOSTICS.get('ai_selected_group_ids', [])]
        review_selected_ids = [str(value) for value in LAST_AI_PLAN_DIAGNOSTICS.get('review_selected_action_ids', [])]
        review_seconds = float(LAST_AI_PLAN_DIAGNOSTICS.get('review_seconds', 0) or 0)
        review_error = str(LAST_AI_PLAN_DIAGNOSTICS.get('review_error', '') or '')
        review_reasoning = str(LAST_AI_PLAN_DIAGNOSTICS.get('review_reasoning', '') or '')[:500]
        if not plan and (not finished) and eligible:
            finished = True
            summary = (summary + ' No action was selected; the planner ended the round without forcing a checklist.').strip()
        if review_selected_ids:
            summary = (summary + f' Breadth review added {len(review_selected_ids)} complementary tool group(s).').strip()
            if review_reasoning:
                summary = (summary + f' Review: {review_reasoning}').strip()
        elif review_seconds and review_reasoning:
            summary = (summary + f' Breadth review added no actions. Review: {review_reasoning}').strip()
        elif review_error:
            summary = (summary + ' Optional breadth review failed; the initial AI plan was kept.').strip()
        notes.append(f'Round {round_number} [{planner_source}/{endpoint}; context={context_bytes}B]: {summary}')
        review_note = f'; review_groups=+{len(review_selected_ids)} in {review_seconds:.1f}s' if review_seconds else ''
        provider_name = str(state.get('ai_provider') or 'ollama')
        concrete_pool_count = int(LAST_AI_PLAN_DIAGNOSTICS.get('concrete_action_pool_count', len(eligible)) or len(eligible))
        expanded_count = int(LAST_AI_PLAN_DIAGNOSTICS.get('expanded_action_count', len(plan)) or len(plan))
        group_note = f'group_pool={candidate_pool_count}; ' if candidate_pool_count != candidate_count else ''
        print(f'\n[*] AI plan round {round_number} [{provider_name}] via {endpoint} (context={context_bytes} bytes; concrete_pool={concrete_pool_count}; {group_note}tool_groups={candidate_count}; baseline_groups={len(baseline_selected_ids)}; ai_groups={len(discretionary_ai_ids)}{review_note}; concrete_actions={expanded_count}; {planner_seconds:.1f}s): {summary}', flush=True)
        selected_groups_by_profile = LAST_AI_PLAN_DIAGNOSTICS.get('selected_groups_per_profile', {})
        execution_budget_diagnostics = LAST_AI_PLAN_DIAGNOSTICS.get('execution_budget_diagnostics_per_profile', {})
        if isinstance(selected_groups_by_profile, dict):
            for profile_name in sorted(selected_groups_by_profile):
                details = execution_budget_diagnostics.get(profile_name, {}) if isinstance(execution_budget_diagnostics, dict) else {}
                selected_actions = int(details.get('selected', 0) or 0) if isinstance(details, dict) else 0
                available_actions = int(details.get('available', selected_actions) or selected_actions) if isinstance(details, dict) else selected_actions
                deferred_actions = int(details.get('deferred', 0) or 0) if isinstance(details, dict) else 0
                print(
                    f"    [PLANNER BUDGET] {profile_name}: tool groups={selected_groups_by_profile.get(profile_name, 0)}/{PROFILE_TOOL_GROUP_BUDGETS.get(shared.CURRENT_SCAN_MODE, 12)}; "
                    f"concrete actions={selected_actions}/{budget_per_profile} base, adaptive max={max_budget_per_profile}; "
                    f"selected-group pool={available_actions}; deferred={deferred_actions}",
                    flush=True,
                )
    except Exception as exc:
        endpoint = str(LAST_AI_PLAN_DIAGNOSTICS.get('endpoint', 'unavailable'))
        context_bytes = int(LAST_AI_PLAN_DIAGNOSTICS.get('context_bytes', 0) or 0)
        if state.get('require_ai'):
            raise RuntimeError(f'Strict agentic mode requires a successful AI plan: {type(exc).__name__}: {exc}') from exc
        plan = _fallback_plan(state, eligible, budget_per_profile)
        finished = not plan
        fallback_reason = f'{type(exc).__name__}: {exc}'
        message = 'AI planning failed after streamed retries; a small discovery-derived fallback was used without enforcing tool or capability coverage: ' + fallback_reason
        notes.append(message)
        planner_source = 'fallback'
        summary = message[:1000]
        print(f'\n[!] {message}', file=sys.stderr, flush=True)
    audit.append({'round': round_number,
        'planner_source': planner_source,
        'planner_endpoint': endpoint,
        'context_bytes': context_bytes,
        'eligible_action_count': len(eligible),
        'planner_candidate_pool_count': int(LAST_AI_PLAN_DIAGNOSTICS.get('candidate_pool_count', len(eligible)) or len(eligible)) if planner_source == 'ai' else len(eligible),
        'planner_candidate_count': int(LAST_AI_PLAN_DIAGNOSTICS.get('candidate_count', len(eligible)) or len(eligible)) if planner_source == 'ai' else len(eligible),
        'concrete_action_pool_count': int(LAST_AI_PLAN_DIAGNOSTICS.get('concrete_action_pool_count', len(eligible)) or len(eligible)) if planner_source == 'ai' else len(eligible),
        'selected_groups_per_profile': dict(LAST_AI_PLAN_DIAGNOSTICS.get('selected_groups_per_profile', {})) if planner_source == 'ai' and isinstance(LAST_AI_PLAN_DIAGNOSTICS.get('selected_groups_per_profile', {}), dict) else {},
        'expanded_actions_per_profile': dict(LAST_AI_PLAN_DIAGNOSTICS.get('expanded_actions_per_profile', {})) if planner_source == 'ai' and isinstance(LAST_AI_PLAN_DIAGNOSTICS.get('expanded_actions_per_profile', {}), dict) else {},
        'eligible_tools': sorted({str(action.get('tool') or '') for action in eligible}),
        'execution_action_budget_per_profile': budget_per_profile,
        'execution_action_adaptive_max_per_profile': max_budget_per_profile,
        'execution_budget_diagnostics_per_profile': dict(LAST_AI_PLAN_DIAGNOSTICS.get('execution_budget_diagnostics_per_profile', {})) if planner_source == 'ai' and isinstance(LAST_AI_PLAN_DIAGNOSTICS.get('execution_budget_diagnostics_per_profile', {}), dict) else {},
        'tool_group_budget_per_profile': PROFILE_TOOL_GROUP_BUDGETS.get(shared.CURRENT_SCAN_MODE, 12),
        'baseline_selected_group_count': len(baseline_selected_ids) if planner_source == 'ai' else 0,
        'ai_selected_group_count': len(discretionary_ai_ids) if planner_source == 'ai' else 0,
        'review_selected_group_count': len(review_selected_ids) if planner_source == 'ai' else 0,
        'selected_group_count': len(selected_ids) if planner_source == 'ai' else 0,
        'selected_tool_groups': list(LAST_AI_PLAN_DIAGNOSTICS.get('selected_group_summaries', [])) if planner_source == 'ai' and isinstance(LAST_AI_PLAN_DIAGNOSTICS.get('selected_group_summaries', []), list) else [],
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
async def execute_action(action: dict[str, Any], cookies: dict[str, str], discovery: dict[str, dict[str, Any]], allow_state_changes: bool | None=None, secondary_cookies: str='') -> tuple[dict[str, Any], dict[str, Any]]:
    tool = action['tool']
    profile = action['profile']
    server, function = REGISTRY[tool][:2]
    if tool == 'jwt':
        arguments = {'jwt_token': action['jwt_token'], 'target_url': action['target_url']}
    elif tool == 'interactsh':
        oast_class = str(action.get('oast_class') or 'remote-fetch')
        timeout_by_class = {'explicit': (120, 75), 'command': (75, 55), 'remote-fetch': (60, 45)}
        deep_timeout, normal_timeout = timeout_by_class.get(oast_class, timeout_by_class['remote-fetch'])
        oast_timeout = deep_timeout if shared.CURRENT_SCAN_MODE == 'deep' else normal_timeout
        arguments = {'target_url': action['target_url'], 'injection_url': action['injection_url'], 'cookies': shared.scope_cookie_header(action['target_url'], cookies.get(profile, '')), 'method': action.get('method', 'GET'), 'data': action.get('data', ''), 'parameter': (action.get('parameters') or [''])[0], 'timeout': oast_timeout}
    else:
        profile_discovery = discovery.get(profile, {})
        arguments = shared.build_tool_arguments(tool, action['target_url'], cookies.get(profile, ''), profile_discovery, case=action, secondary_cookies=secondary_cookies, allow_state_changes=allow_state_changes)
        if tool == 'ffuf':
            arguments.pop('session_probe_url', None)
    state_refresh: dict[str, Any] | None = None
    authenticated_specialists = {'sqlmap', 'dalfox', 'commix', 'traversal', 'idor', 'authorization', 'interactsh', 'arjun', 'browser', 'workflow'}
    if cookies.get(profile, '') and tool in authenticated_specialists:
        parsed_target = urlparse(action['target_url'])
        refresh_target = f'{parsed_target.scheme}://{parsed_target.netloc}'
        profile_discovery = discovery.get(profile, {})
        probe_url = shared.select_session_probe_url(profile_discovery, refresh_target)
        print(f'    [PRECHECK] {tool}: validating authenticated session with {shared.compact_log_url(probe_url)}', flush=True)
        state_refresh = shared.refresh_authenticated_session_state(refresh_target, cookies[profile], probe_url)
        if state_refresh.get('usable') is False:
            print(f'    [PARTIAL ] {tool}: authenticated session precheck failed', flush=True)
            return (action, {'tool': tool, 'status': 'partial', 'target': action['target_url'], 'output': 'The authenticated session could not be re-established before the scanner.', 'vulnerabilities': [], 'diagnosis': 'authentication_precheck_failed', 'state_refresh': state_refresh})
        print(f'    [SESSION ] {tool}: authenticated session usable', flush=True)
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

# Within each planner round, validated actions run before the model is asked to plan again.
async def execute_plan(plan: list[dict[str, Any]], cookies: dict[str, str], discovery: dict[str, dict[str, Any]], allow_state_changes: bool | None=None, secondary_cookies: str='') -> list[tuple[dict[str, Any], dict[str, Any]]]:

    profile_order = {name: index for index, name in enumerate(cookies)}
    ordered = sorted(plan, key=lambda action: (profile_order.get(action['profile'], 999), shared.tool_execution_rank(action['tool'], bool(cookies.get(action['profile'], '')))))
    total = len(ordered)
    print(f'\n[*] Executing {total} validated action(s) sequentially. Progress heartbeat: every {shared.SCANNER_PROGRESS_INTERVAL}s.', flush=True)
    executed: list[tuple[dict[str, Any], dict[str, Any]]] = []
    arjun_empty_limits: dict[str, int] = {}
    confirmed_oast_classes: set[tuple[str, str]] = set()
    arjun_threshold = 2 if shared.CURRENT_SCAN_MODE == 'deep' else 1
    for index, action in enumerate(ordered, start=1):
        started = time.monotonic()
        print(f"\n[*] Action {index}/{total}: {action['profile']} / {action['tool']} / {shared.compact_log_url(action['target_url'])}", flush=True)
        try:
            oast_key = (action['profile'], str(action.get('oast_class') or 'remote-fetch'))
            if action['tool'] == 'interactsh' and oast_key in confirmed_oast_classes:
                item = (action, {'tool': 'interactsh', 'status': 'skipped', 'target': action['target_url'], 'output': 'A callback was already confirmed for the same OAST class in this profile; the duplicate polling wait was omitted.', 'diagnosis': 'duplicate_oast_class_already_confirmed', 'vulnerabilities': []})
            elif action['tool'] == 'arjun' and arjun_empty_limits.get(action['profile'], 0) >= arjun_threshold:
                item = (action, {'tool': 'arjun', 'status': 'skipped', 'target': action['target_url'], 'output': 'Adaptive budget reallocation: earlier high-priority Arjun actions reached their full budget without discovering a parameter; this lower-priority repeat was skipped.', 'diagnosis': 'adaptive_budget_reallocated', 'vulnerabilities': []})
            else:
                item = await execute_action(action, cookies, discovery, allow_state_changes=allow_state_changes, secondary_cookies=secondary_cookies)
        except Exception as exc:
            message = f'Agent executor isolated failure: {type(exc).__name__}: {exc}'
            item = (action, {'tool': action['tool'], 'status': 'error', 'target': action['target_url'], 'output': message, 'vulnerabilities': [], 'diagnosis': diagnose_error(message), 'traceback': traceback.format_exc()})
        executed.append(item)
        _, result = item
        if action['tool'] == 'interactsh' and result.get('callback_confirmed'):
            confirmed_oast_classes.add((action['profile'], str(action.get('oast_class') or 'remote-fetch')))
        if action['tool'] == 'arjun':
            found_parameters = int(result.get('phase_parameters', 0) or 0)
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
    for action, result in executed:
        profile, tool = (action['profile'], action['tool'])
        profile_results = results.setdefault(profile, {})
        number = 1 + sum((key.startswith(f'{tool}:') for key in profile_results))
        metadata = {key: action[key] for key in ('verification_source_result', 'verification_source_parameter', 'verification_source_path', 'verification_source_url') if key in action}
        coverage_target = str(action.get('source_url') or action.get('target_url') or '') if tool == 'interactsh' else str(action.get('target_url') or '')
        coverage_action = {
            'tool': tool,
            'target_url': coverage_target,
            'method': str(action.get('method') or 'GET').upper(),
            'parameters': [str(value) for value in action.get('parameters', []) if str(value)],
            'source_url': str(action.get('source_url') or ''),
        }
        profile_results[f'{tool}:{number}'] = {**result, **metadata, 'coverage_action': coverage_action, 'planner_reason': action['reason'], 'planner_round': state['round']}
        completed.append(action_id(action))
        log_result(profile, tool, result, action['target_url'])
        if tool == 'zap':
            log_zap_session_diagnostics(result)
        if tool == 'ffuf' and result.get('status') in {'success', 'partial'}:
            before = len(discovery.get(profile, {}).get('request_cases', []))
            enriched, urls = enrich_discovery_with_ffuf(discovery.get(profile, {}), result, state['target'])
            if urls:
                recrawl = discover_target_sync_safe(state['target'], profile_cookies.get(profile, ''), seeds=urls)
                enriched = merge_discovery(enriched, recrawl)
                print(f"    [DISCOVERY] {profile}: FFUF re-crawl expanded the surface to {len(enriched.get('html_urls', []))} HTML pages and {len(enriched.get('request_cases', []))} request cases.", flush=True)
            discovery[profile] = enriched
            new_attack_surface += max(0, len(enriched.get('request_cases', [])) - before)
        if tool == 'arjun' and result.get('status') in {'success', 'partial'}:
            discovery[profile], generated = enrich_discovery_with_arjun(discovery.get(profile, {}), result, action['target_url'])
            new_attack_surface += len(generated)
    return new_attack_surface

# After validation, the selected actions run and their results are written back to shared state.
def executor_node(state: AgentState) -> dict[str, Any]:
    if not state['plan']:
        return {}
    cookies = {profile['name']: profile['cookies'] for profile in state['profiles']}
    results = {profile: dict(values) for profile, values in state['results'].items()}
    discovery = {profile: dict(values) for profile, values in state['discovery'].items()}
    completed = list(state['completed'])
    profile_cookies = {profile['name']: profile['cookies'] for profile in state['profiles']}
    new_attack_surface = 0
    discovery_stage = [action for action in state['plan'] if action['tool'] == 'ffuf']
    remaining_stage = [action for action in state['plan'] if action['tool'] != 'ffuf']
    if discovery_stage:
        print('\n[*] Discovery enrichment stage: FFUF runs before ZAP/Nuclei.', flush=True)
        ffuf_executed = asyncio.run(execute_plan(discovery_stage, cookies, discovery, allow_state_changes=state.get('allow_state_changes'), secondary_cookies=state.get('secondary_cookies', '')))
        new_attack_surface += _record_execution_batch(ffuf_executed, state=state, results=results, discovery=discovery, completed=completed, profile_cookies=profile_cookies)
        print('[*] FFUF enrichment is available to planned ZAP/Nuclei actions; new parameter candidates will be offered to the AI planner next round.', flush=True)
    if remaining_stage:
        executed = asyncio.run(execute_plan(remaining_stage, cookies, discovery, allow_state_changes=state.get('allow_state_changes'), secondary_cookies=state.get('secondary_cookies', '')))
        new_attack_surface += _record_execution_batch(executed, state=state, results=results, discovery=discovery, completed=completed, profile_cookies=profile_cookies)
    next_state = dict(state)
    next_state.update(results=results, discovery=discovery, completed=completed)
    remaining = _remaining_eligible_actions(next_state)
    can_continue = state['round'] < state['max_rounds'] and bool(new_attack_surface > 0 or remaining)
    notes = list(state['notes'])
    notes.append(f"Round {state['round']} execution: new request contracts={new_attack_surface}; remaining eligible actions={len(remaining)}.")
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
                action['reason'] = 'Adaptive final-XSS overflow selected by deterministic ranking. ' + str(action.get('reason') or '')
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
    for profile in state.get('profiles', []):
        name = str(profile.get('name') or '')
        cookies = str(profile.get('cookies') or '')
        if not cookies or not _profile_has_effective_auth(state, name):
            continue
        discovery = state.get('discovery', {}).get(name, {})
        logout_cases = select_logout_request_cases(discovery, limit=3)
        if not logout_cases:
            skipped = make_skipped_result(
                'session-logout', state['target'],
                'No logout/signout/logoff endpoint was discovered safely for the authenticated profile.',
            )
            results.setdefault(name, {})['session_logout_final'] = skipped
            log_result(name, 'session-logout', skipped, state['target'])
            continue
        probe_url = select_session_probe_url(discovery, state['target'])
        for index, logout_case in enumerate(logout_cases, start=1):
            logout_url = str(logout_case.get('url') or '')
            print(f'    [RUNNING ] session-logout: {shared.compact_log_url(logout_url)}', flush=True)
            result = await call_mcp(
                'custom_checks/sessionServer.py', 'run_logout_check',
                {
                    'target_url': state['target'], 'logout_url': logout_url, 'cookies': cookies,
                    'probe_url': probe_url, 'method': str(logout_case.get('method') or 'GET'),
                    'data': str(logout_case.get('data') or ''), 'timeout': 25,
                },
                timeout_seconds=30,
            )
            result['coverage_action'] = {
                'tool': 'session-logout',
                'target_url': logout_url,
                'method': str(logout_case.get('method') or 'GET').upper(),
                'parameters': [str(value) for value in logout_case.get('parameters', []) if str(value)],
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
        executed = asyncio.run(execute_plan(actions, cookies, discovery, allow_state_changes=state.get('allow_state_changes'), secondary_cookies=state.get('secondary_cookies', '')))
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
    output_name = f'SecOps_Agentic_Assessment_{datetime.now():%Y%m%d_%H%M%S}'
    report_results = _materialize_unselected_actions(state)
    remaining = _remaining_eligible_actions({**state, 'results': report_results})
    context = {'profiles': [{'name': profile['name'], 'authenticated': _profile_has_effective_auth(state, str(profile.get('name') or ''))} for profile in state['profiles']],
        'expected_tools': list(REGISTRY),
        'discovery': state['discovery'],
        'endpoint_selection': {
            profile['name']: shared.endpoint_selection_decisions(
                state['discovery'].get(profile['name'], {}), state['target'],
                authenticated_profile=_profile_has_effective_auth(state, str(profile.get('name') or '')),
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
        'runtime_platform': platform.platform(),
        'python_executable': sys.executable,
        'mcp_server_python': shared._server_python(),
        'remaining_eligible_actions_at_report': len(remaining),
        'execution_policy': 'AI selects discovery-derived scan actions under deterministic safety validation. After the planning rounds, the deterministic verification stage rechecks unresolved XSS candidates with Chromium and then validates any safely discovered authenticated logout endpoint as the final session-mutating action; anonymous profiles never execute logout. A separate AI analysis node then independently enriches severity, description, impact, potential consequences, recovery guidance and remediation using scanner evidence. Category, verification status, request evidence and confirmation rules remain deterministic and immutable. Bounded state-changing workflow probes use a tri-state policy: an explicit allow/deny is authoritative; when unspecified, only loopback local labs enable them automatically and remote authorized targets keep them disabled.',
        'allow_state_changes': state.get('allow_state_changes'),
        'secondary_identity_supplied': bool(state.get('secondary_cookies', '')),
        'orchestration': {'engine': 'langgraph', 'mode': 'agentic', 'nodes': ['discovery', 'planner', 'executor', 'verification', 'analysis', 'report']}}
    report = asyncio.run(call_mcp('reporting/reportServer.py', 'generate_report', {'findings_summary': report_results, 'target_url': state['target'], 'output_name': output_name, 'assessment_context': context}))
    if report.get('status') != 'success':
        print(f"[REPORT ERROR] {report.get('diagnosis') or 'report_failed'} — {report.get('output') or 'No report error detail returned.'}", file=sys.stderr, flush=True)
    if report.get('status') != 'success' and (not report.get('json_filename')):
        fallback = write_emergency_json_report(state['target'], state['results'], state['diagnostics'], str(report.get('output', 'Report MCP failed.')), 'SecOps_Agentic_Emergency')
        if fallback:
            report.update(json_filename=fallback, html_filename=str(Path(fallback).with_suffix('.html')), local_json_fallback=True)
    return {'report_status': report, 'results': report_results}
