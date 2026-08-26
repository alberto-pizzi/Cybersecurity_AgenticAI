from __future__ import annotations

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

warnings.filterwarnings("ignore", message=r".*authlib\.jose.*deprecated.*")
import requests
import orchestratorShared as shared
from orchestratorShared import (
    BROAD_SCANNER_TIMEOUTS, PARAMETER_TOOL_TIMEOUTS, _tool_case_skip_reason,
    build_tool_arguments, call_mcp, call_mcp_with_progress, diagnose_error,
    discover_target, enrich_discovery_with_arjun, enrich_discovery_with_ffuf,
    iter_leaf_results, log_result, log_zap_session_diagnostics, make_skipped_result,
    merge_discovery, print_security_finding_summary, select_arjun_request_cases,
    select_authorization_request_cases, select_browser_request_cases, select_oast_request_cases,
    select_request_cases, select_tool_request_cases, select_workflow_request_cases,
    write_emergency_json_report,
)

REGISTRY: dict[str, tuple[str, str, str, str]] = {}


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
AI_PLANNER_TIMEOUTS = {'fast': 300, 'balanced': 480, 'deep': 720}
AI_PLANNER_MAX_PREDICT = {'fast': 700, 'balanced': 1000, 'deep': 1400}
AI_PLANNER_CONTEXT_WINDOWS = {'fast': 4096, 'balanced': 6144, 'deep': 8192}
LAST_OLLAMA_PLAN_DIAGNOSTICS: dict[str, Any] = {}
BROAD_COVERAGE_TOOLS = ('ffuf', 'zap', 'nuclei', 'session', 'nikto')
PARAMETER_COVERAGE_TOOLS = ('sqlmap', 'dalfox', 'commix', 'traversal', 'idor')
AUTHORIZATION_COVERAGE_TOOLS = ('authorization',)
WORKFLOW_COVERAGE_TOOLS = ('browser', 'workflow')
ROUND_ACTION_BUDGETS = {'fast': 14, 'balanced': 24, 'deep': 36}
PLAN_SCHEMA = {
    'type': 'object',
    'properties': {
        'reasoning_summary': {'type': 'string'},
        'selected_action_ids': {'type': 'array', 'items': {'type': 'string'}},
        'finish': {'type': 'boolean'},
    },
    'required': ['reasoning_summary', 'selected_action_ids', 'finish'],
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
    if installed:
        selected = installed[0]
        diagnostics.update(model_ready=True, selected_model=selected, fallback_model_used=True, fallback_reason=pull_error or 'Requested model is absent and automatic pulling was disabled.')
        return (selected, diagnostics)
    diagnostics.update(model_ready=False, selected_model='')
    raise RuntimeError('Ollama is reachable but no usable local model exists. ' + (pull_error or f"Requested model '{requested_model}' is not installed."))

# Plan parsing accepts only the compact ID-selection contract used by the local model.
def _parse_ollama_plan_content(content: str) -> dict[str, Any]:
    value = json.loads(str(content or ''))
    if not isinstance(value, dict) or not isinstance(value.get('selected_action_ids', []), list):
        raise ValueError('Ollama returned an invalid compact plan object.')
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


def _planner_discovery_summary(discovery: dict[str, dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for profile, found in discovery.items():
        summary[profile] = {
            'authenticated': found.get('authentication_effective'),
            'html_pages': len(found.get('html_urls', [])),
            'request_cases': len(found.get('request_cases', [])),
            'client_side_candidates': len(found.get('client_side_candidates', [])),
            'jwt_tokens': len(found.get('jwt_tokens', [])),
            'crawl_errors': len(found.get('errors', [])),
        }
    return summary


# Reads the streamed Ollama response and joins its text safely.
def _ollama_stream_content(url: str, payload: dict[str, Any], *, response_kind: str, total_timeout: int, early_json: bool=False) -> str:

    started = time.monotonic()
    chunks: list[str] = []
    read_timeout = max(90, int(total_timeout) + 30)
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
                raise ValueError('Ollama completed without returning plan content.')
            return content
        for raw in response.iter_lines(decode_unicode=True):
            if time.monotonic() - started > total_timeout:
                raise TimeoutError(f'Ollama planning exceeded the {total_timeout}-second budget.')
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
                        if isinstance(parsed, dict) and isinstance(parsed.get('selected_action_ids'), list) and isinstance(parsed.get('finish'), bool):
                            return candidate
            if event.get('done') is True:
                break
    finally:
        close = getattr(response, 'close', None)
        if callable(close):
            close()
    content = ''.join(chunks).strip()
    if not content:
        raise ValueError('Ollama completed without returning plan content.')
    return content

# Sends a small request so the model is ready before planning starts.
def warm_ollama_model(ollama_url: str, model: str, *, timeout: int) -> dict[str, Any]:

    started = time.monotonic()
    content = _ollama_stream_content(f"{ollama_url.rstrip('/')}/api/generate", {'model': model, 'prompt': 'Reply with READY and nothing else.', 'options': {'temperature': 0, 'num_predict': 4, 'num_ctx': 2048}, 'keep_alive': '30m'}, response_kind='generate', total_timeout=max(90, min(int(timeout), 600)))
    return {'ready': True, 'response': content[:80], 'seconds': round(time.monotonic() - started, 2)}

# Builds a stable identifier for one planned action.
def action_id(action: dict[str, Any]) -> str:
    return '|'.join((str(action.get(key, '')) for key in ('profile', 'tool', 'target_url', 'method', 'data', 'jwt_token', 'injection_url')))

# Asks Ollama for the next scan actions and returns a structured plan.
def ollama_plan(state: AgentState) -> dict[str, Any]:
    eligible = _eligible_action_catalog(state)
    candidate_map = {f'A{index:03d}': action for index, action in enumerate(eligible, 1)}
    candidates = [_planner_candidate_view(action, candidate_id) for candidate_id, action in candidate_map.items()]
    candidate_tools = sorted({str(action.get('tool') or '') for action in eligible})
    registry = {
        name: {'scope': REGISTRY[name][2], 'description': str(REGISTRY[name][3])[:180]}
        for name in candidate_tools if name in REGISTRY
    }
    prompt = {
        'target': state['target'],
        'round': state['round'] + 1,
        'maximum_rounds': state['max_rounds'],
        'round_action_budget': ROUND_ACTION_BUDGETS.get(shared.CURRENT_SCAN_MODE, 12),
        'scan_mode': shared.CURRENT_SCAN_MODE,
        'discovery_summary': _planner_discovery_summary(state['discovery']),
        'previous_results': compact_results(state['results']),
        'available_tools': registry,
        'candidates': candidates,
    }
    system_message = (
    'Plan an explicitly authorized web-security assessment using only candidate IDs supplied in the user context. '
    'Each candidate is discovery-derived and will be validated again by Python. '

    'Evaluate EVERY candidate before returning the plan. For each candidate decide SELECT or DEFER. '

    'SELECT any safe, discovery-supported candidate that can provide useful or complementary security evidence. '
    'A candidate does not need to be the single highest-value action. When uncertain about a safe and useful candidate, '
    'prefer SELECT. '

    'DEFER only for a concrete reason: genuine duplication of already selected/completed work, unsupported discovery, '
    'unsafe or incompatible input, or clearly very low expected value. Do not keep the plan artificially small. '

    'Broad scanners and targeted tools are complementary, not substitutes by default. FFUF, ZAP, Nuclei, session and '
    'Nikto may provide evidence that SQLMap, Dalfox, Commix, traversal, browser, workflow or authorization do not, and '
    'vice versa. Do not systematically prefer either category. '

    'Use previous_results and the current candidate set to avoid real repetition. A confirmed finding must not stop exploration '
    'of unrelated attack surfaces. '

    'Use IDOR only for appropriate numeric references, authorization only for read-only identity/object/resource signals, '
    'and Interactsh only for compatible OAST inputs. '

    'round_action_budget is a maximum, not a quota. Do not select actions to satisfy a count or checklist, but do not '
    'exclude useful candidates without a concrete reason. '

    'Before returning, reconsider all deferred candidates once. Set finish=true only when no remaining candidate is likely '
    'to add useful evidence. Keep reasoning_summary concise. Return only schema-valid JSON.'
)
    base = state['ollama_url'].rstrip('/')
    total_timeout = max(120, int(state.get('ai_timeout') or 480))
    max_predict = AI_PLANNER_MAX_PREDICT.get(shared.CURRENT_SCAN_MODE, 320)
    # Keep the planner timeout profile-specific on every round. The configured fast/balanced/deep
    # budgets already bound wall-clock time, so later rounds should not collapse to the fast limit.
    context = json.dumps(prompt, ensure_ascii=False, separators=(',', ':'))
    # Larger scan profiles can expose more candidates, so scale the model context with the profile.
    context_window = AI_PLANNER_CONTEXT_WINDOWS.get(shared.CURRENT_SCAN_MODE, 6144)
    common_options = {'temperature': 0, 'num_predict': max_predict, 'num_ctx': context_window, 'top_p': 0.9}
    LAST_OLLAMA_PLAN_DIAGNOSTICS.clear()
    LAST_OLLAMA_PLAN_DIAGNOSTICS.update({
        'endpoint': 'pending',
        'context_bytes': len(context.encode('utf-8')),
        'candidate_count': len(candidates),
        'selected_action_ids': [],
        'seconds': 0.0,
        'attempt_errors': [],
    })
    attempts = [
        ('chat', f'{base}/api/chat', {
            'model': state['model'], 'format': PLAN_SCHEMA,
            'messages': [{'role': 'system', 'content': system_message}, {'role': 'user', 'content': context}],
            'options': common_options, 'keep_alive': '30m'}, max(90, int(total_timeout * 0.7))),
        ('generate', f'{base}/api/generate', {
            'model': state['model'], 'format': PLAN_SCHEMA,
            'prompt': system_message + '\n\nAssessment context:\n' + context,
            'options': common_options, 'keep_alive': '30m'}, max(90, int(total_timeout * 0.3))),
    ]
    errors: list[str] = []
    planning_started = time.monotonic()
    for kind, url, payload, budget in attempts:
        started = time.monotonic()
        try:
            content = _ollama_stream_content(url, payload, response_kind=kind, total_timeout=budget, early_json=True)
            compact_plan = _parse_ollama_plan_content(content)
            requested_ids = [str(value) for value in compact_plan.get('selected_action_ids', [])]
            selected_ids = []
            selected_actions = []
            action_budget = ROUND_ACTION_BUDGETS.get(shared.CURRENT_SCAN_MODE, 12)
            for candidate_id in requested_ids:
                action = candidate_map.get(candidate_id)
                if action is None or candidate_id in selected_ids or len(selected_actions) >= action_budget:
                    continue
                selected_ids.append(candidate_id)
                selected = dict(action)
                selected['reason'] = f"AI selected {candidate_id}: {str(action.get('reason') or 'discovery-derived candidate')[:420]}"
                selected_actions.append(selected)

            # Compact local models can still produce an overly narrow first pass. Trigger one
            # AI-only breadth review when the selection is sparse relative to the actions that
            # could actually run in this profile/round; the review never forces a minimum count.
            review_selected_ids: list[str] = []
            review_seconds = 0.0
            review_error = ''
            review_reasoning = ''
            review_capacity = min(action_budget, len(candidates))
            remaining_candidate_count = len(candidates) - len(selected_actions)
            sparse_plan = (
                review_capacity >= 4
                and remaining_candidate_count >= 3
                and len(selected_actions) * 2 < review_capacity
                and len(selected_actions) < action_budget
            )
            # Reserve up to 40% of the profile's planning budget for the optional second AI pass.
            # The actual allowance is also bounded by the wall-clock time still remaining.
            review_time_budget = min(
                max(120, int(total_timeout * 0.40)),
                max(0, int(total_timeout - (time.monotonic() - planning_started))),
            )
            if sparse_plan and review_time_budget >= 30:
                remaining_candidates = [
                    candidate for candidate in candidates
                    if str(candidate.get('id') or '') not in selected_ids
                ]
                review_prompt = {
                    'target': state['target'],
                    'scan_mode': shared.CURRENT_SCAN_MODE,
                    'round': state['round'] + 1,
                    'round_action_budget': action_budget,
                    'discovery_summary': prompt['discovery_summary'],
                    'previous_results': prompt['previous_results'],
                    'available_tools': registry,
                    'already_selected_action_ids': selected_ids,
                    'remaining_slots': action_budget - len(selected_actions),
                    'remaining_candidates': remaining_candidates,
                    'previous_reasoning_summary': str(compact_plan.get('reasoning_summary') or '')[:240],
                }
                review_system_message = (
                    'Review the candidates deferred by the first AI plan for an explicitly authorized web-security assessment. '

                    'Evaluate EVERY remaining candidate. ADD any safe, discovery-supported candidate that can provide useful, '
                    'complementary or independent security evidence. When uncertain about a safe and useful candidate, prefer ADD. '

                    'KEEP DEFERRED only for a concrete reason: genuine duplication, already completed coverage, unsupported discovery, '
                    'unsafe or incompatible input, or clearly very low expected value. '

                    'Broad scanners and targeted tools are complementary, not substitutes by default. Do not reject a broad scanner '
                    'simply because targeted tools were already selected, and do not add actions merely to satisfy coverage or a count. '

                    'Do not repeat already_selected_action_ids. Select only IDs from remaining_candidates. '
                    'It is valid to add zero actions only if every remaining candidate has a concrete defer reason. '

                    'Keep reasoning_summary concise. Return only schema-valid JSON.'
                )
                review_context = json.dumps(review_prompt, ensure_ascii=False, separators=(',', ':'))
                review_started = time.monotonic()
                try:
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
                    review_plan = _parse_ollama_plan_content(review_content)
                    review_reasoning = str(review_plan.get('reasoning_summary') or '')[:500]
                    for candidate_id in [str(value) for value in review_plan.get('selected_action_ids', [])]:
                        action = candidate_map.get(candidate_id)
                        if (
                            action is None
                            or candidate_id in selected_ids
                            or len(selected_actions) >= action_budget
                        ):
                            continue
                        selected_ids.append(candidate_id)
                        review_selected_ids.append(candidate_id)
                        selected = dict(action)
                        selected['reason'] = (
                            f"AI review selected {candidate_id}: "
                            f"{str(action.get('reason') or 'discovery-derived candidate')[:420]}"
                        )
                        selected_actions.append(selected)
                except Exception as review_exc:
                    # The initial AI plan is already valid, so an optional breadth review
                    # must not turn a successful strict-agentic round into a failure.
                    review_error = f'{type(review_exc).__name__}: {review_exc}'
                finally:
                    review_seconds = round(time.monotonic() - review_started, 2)

            LAST_OLLAMA_PLAN_DIAGNOSTICS.clear()
            LAST_OLLAMA_PLAN_DIAGNOSTICS.update({
                'endpoint': kind,
                'context_bytes': len(context.encode('utf-8')),
                'candidate_count': len(candidates),
                'selected_action_ids': selected_ids,
                'review_selected_action_ids': review_selected_ids,
                'review_seconds': review_seconds,
                'review_error': review_error,
                'review_reasoning': review_reasoning,
                'seconds': round(time.monotonic() - planning_started, 2),
                'attempt_errors': list(errors),
            })
            return {
                'reasoning_summary': str(compact_plan.get('reasoning_summary') or '')[:1000],
                'actions': selected_actions,
                'finish': bool(compact_plan.get('finish', False)),
            }
        except Exception as exc:
            errors.append(f'{kind}: {type(exc).__name__}: {exc}')
            LAST_OLLAMA_PLAN_DIAGNOSTICS.update({
                'endpoint': kind,
                'seconds': round(time.monotonic() - planning_started, 2),
                'attempt_errors': list(errors),
            })
    raise RuntimeError('; '.join(errors))

# Keeps a small result summary that is safe to send back to the planner.
def compact_results(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {profile: {key: {'status': value.get('status'), 'target': value.get('target'), 'findings': len(value.get('vulnerabilities') or []), 'diagnosis': value.get('diagnosis'), 'output': str(value.get('output', ''))[:250]} for key, value in values.items() if isinstance(value, dict)} for profile, values in results.items()}

# Before planning, discovery gathers the real pages, forms, and request cases available on the target.
def discovery_node(state: AgentState) -> dict[str, Any]:
    print('\n[*] Discovery of anonymous and authenticated surfaces')
    discovery, diagnostics = ({}, list(state['diagnostics']))
    for profile in state['profiles']:
        found = discover_target(state['target'], profile['cookies'], max_pages=30)
        discovery[profile['name']] = found
        diagnostics.extend(({'phase': 'discovery', 'profile': profile['name'], **item} for item in found['errors']))
        print(f"    {profile['name']}: {len(found.get('html_urls', []))} HTML pages, {len(found.get('request_cases', []))} GET/POST cases, {len(found['jwt_tokens'])} JWTs")
        if found.get('authentication_effective') is False:
            print(f"    [WARNING] {profile['name']}: {found.get('authentication_note')}", file=sys.stderr)
    return {'discovery': discovery, 'diagnostics': diagnostics}

# Discovery evidence is converted into tool actions that the planner can safely choose.
def discovery_candidate_actions(state: AgentState) -> list[dict[str, Any]]:

    actions: list[dict[str, Any]] = []
    has_auth = any((bool(profile.get('cookies')) for profile in state['profiles']))
    for profile in state['profiles']:
        name = profile['name']
        authenticated = bool(profile.get('cookies'))
        broad = list(shared.broad_tool_order(authenticated))
        for tool in broad:
            actions.append({'profile': name, 'tool': tool, 'target_url': state['target'], 'jwt_token': '', 'injection_url': '', 'reason': 'Session-aware baseline coverage.'})
        for case in select_arjun_request_cases(state['discovery'].get(name, {}), state['target'], limit=shared.ARJUN_ENDPOINT_LIMIT):
            actions.append({'profile': name, 'tool': 'arjun', 'target_url': case['url'], 'method': case.get('method', 'GET'), 'data': case.get('data', ''), 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': '', 'reason': 'Hidden-parameter discovery using the real request method and body.'})
        if authenticated or not has_auth:
            for tool in ('sqlmap', 'dalfox', 'commix', 'traversal', 'idor'):
                for case in select_tool_request_cases(state['discovery'].get(name, {}), tool, limit=shared.PARAMETER_TOOL_CASE_LIMITS.get(tool, 1)):
                    actions.append({'profile': name, 'tool': tool, 'target_url': case['url'], 'method': case.get('method', 'GET'), 'data': case.get('data', ''), 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': '', 'reason': f'Highest-value discovered request for {tool}.'})
            for case in select_authorization_request_cases(state['discovery'].get(name, {}), limit=shared.tool_action_limit('authorization')):
                actions.append({'profile': name, 'tool': 'authorization', 'target_url': case['url'], 'method': 'GET', 'data': '', 'parameters': case.get('parameters', []), 'jwt_token': '', 'injection_url': '', 'reason': 'Read-only authorization differential candidate derived from an identity, object or privileged-resource signal.'})
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
                    'reason': 'Browser verification candidate derived from XSS-like parameters or client-side source/sink evidence.'})
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
                    'reason': 'Multi-step workflow candidate derived from discovered form metadata.'})
        tokens = state['discovery'].get(name, {}).get('jwt_tokens', [])
        if tokens:
            actions.append({'profile': name, 'tool': 'jwt', 'target_url': state['target'], 'jwt_token': tokens[0], 'injection_url': '', 'reason': 'Discovered JWT.'})
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
    proposal_limit = max(60, ROUND_ACTION_BUDGETS.get(shared.CURRENT_SCAN_MODE, 20) * 2)
    for raw in proposed[:proposal_limit]:
        if not isinstance(raw, dict):
            continue
        profile, tool = (str(raw.get('profile', '')), str(raw.get('tool', '')).lower())
        if profile not in profiles or tool not in REGISTRY:
            continue
        has_authenticated_profile = any((bool(item.get('cookies')) for item in state['profiles']))
        profile_has_cookie = next((bool(item.get('cookies')) for item in state['profiles'] if item.get('name') == profile), False)
        if shared.CURRENT_SCAN_MODE != 'deep':
            if profile == 'anonymous' and has_authenticated_profile and (tool in {'session', 'nikto', 'sqlmap', 'dalfox', 'commix', 'traversal', 'idor', 'authorization', 'browser', 'workflow'}):
                continue
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
        oast_class = str(raw.get('oast_class') or '')
        scope = REGISTRY[tool][2]
        if scope == 'base':
            target_url = state['target']
        elif scope == 'url':
            cases = select_arjun_request_cases(found, state['target'], limit=10)
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
            cases = select_tool_request_cases(found, tool, limit=20)
            matching = [case for case in cases if str(case.get('url', '')) == target_url]
            if method:
                matching = [case for case in matching if str(case.get('method', 'GET')).upper() == method]
            if not matching:
                continue
            selected = matching[0]
            if _tool_case_skip_reason(tool, selected):
                continue
            if tool == 'sqlmap' and profile_has_cookie and shared._is_login_case(selected):
                continue
            method = str(selected.get('method', 'GET')).upper()
            data = str(selected.get('data', ''))
            parameters = [str(value) for value in selected.get('parameters', [])]
            if scope == 'numeric' and (method != 'GET' or not any((value.isdigit() for _, value in parse_qsl(urlparse(target_url).query, keep_blank_values=True)))):
                continue
        elif scope == 'authorization':
            if not profile_has_cookie:
                continue
            cases = select_authorization_request_cases(found, limit=30)
            matching = [case for case in cases if str(case.get('url', '')) == target_url]
            if not matching:
                continue
            selected = matching[0]
            method = 'GET'
            data = ''
            parameters = [str(value) for value in selected.get('parameters', [])]
        elif scope == 'browser':
            cases = select_browser_request_cases(found, limit=20)
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
            cases = select_workflow_request_cases(found, limit=30)
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
        action = {'profile': profile, 'tool': tool, 'target_url': target_url, 'method': method or 'GET', 'data': data, 'parameters': parameters, 'source_url': source_url, 'fields': fields, 'client_sources': client_sources, 'client_sinks': client_sinks, 'file_parameters': file_parameters, 'token_parameters': token_parameters, 'enctype': enctype, 'jwt_token': token, 'injection_url': injection, 'oast_class': oast_class, 'reason': str(raw.get('reason', ''))[:500] or 'No planner reason supplied.'}
        identifier = action_id(action)
        key = (profile, tool)
        limit = shared.tool_action_limit(tool)
        if per_tool.get(key, 0) >= limit:
            continue
        if identifier not in completed and all((action_id(item) != identifier for item in valid)):
            valid.append(action)
            per_tool[key] = per_tool.get(key, 0) + 1
    return valid

# Lists the actions that are currently valid for the planner.
def _eligible_action_catalog(state: AgentState) -> list[dict[str, Any]]:

    return validate_plan(state, discovery_candidate_actions(state))

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

# Fallback planning selects a safe deterministic set of actions when AI planning is unavailable.
def _fallback_plan(state: AgentState, eligible: list[dict[str, Any]], budget: int) -> list[dict[str, Any]]:

    authenticated = {str(profile.get('name') or ''): bool(profile.get('cookies')) for profile in state['profiles']}
    ordered = sorted(eligible, key=lambda action: (shared.tool_execution_rank(str(action.get('tool') or ''), authenticated.get(str(action.get('profile') or ''), False)), str(action.get('profile') or ''), str(action.get('target_url') or ''), str(action.get('tool') or '')))
    return ordered[:min(budget, 3)]

# Pending-action filtering keeps only valid actions that have not run yet.
def _remaining_eligible_actions(state: AgentState) -> list[dict[str, Any]]:
    return validate_plan(state, discovery_candidate_actions(state))

# Result lookup avoids scheduling a tool that already produced output for the same profile.
def _has_tool_result(profile_results: dict[str, Any], tool: str) -> bool:
    return any((key == tool or key.startswith(f'{tool}:') for key, value in profile_results.items() if isinstance(value, dict)))

# Explains why an expected tool action cannot be created.
def _missing_tool_reason(state: AgentState, profile_name: str, tool: str) -> str:
    found = state['discovery'].get(profile_name, {})
    has_authenticated_profile = any((bool(item.get('cookies')) for item in state['profiles']))
    profile_has_cookie = any((item.get('name') == profile_name and bool(item.get('cookies')) for item in state['profiles']))
    if profile_name == 'anonymous' and has_authenticated_profile and (shared.CURRENT_SCAN_MODE != 'deep') and (tool in {'session', 'nikto', *PARAMETER_COVERAGE_TOOLS, *AUTHORIZATION_COVERAGE_TOOLS, *WORKFLOW_COVERAGE_TOOLS}):
        return 'The richer authenticated profile provides this coverage in the selected scan mode.'
    if tool in BROAD_COVERAGE_TOOLS:
        return ''
    if tool == 'arjun':
        return '' if select_arjun_request_cases(found, state['target'], limit=1) else 'No suitable discovered GET/POST request was available for hidden-parameter discovery.'
    if tool in PARAMETER_COVERAGE_TOOLS:
        return '' if select_tool_request_cases(found, tool, limit=1) else f"No discovered request matched {tool}'s vulnerability class."
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
    budget = ROUND_ACTION_BUDGETS.get(shared.CURRENT_SCAN_MODE, 20)
    planner_source = 'ai'
    summary = ''
    endpoint = 'unavailable'
    context_bytes = 0
    ai_selected_count = 0
    review_selected_ids: list[str] = []
    review_reasoning = ''
    fallback_reason = ''
    try:
        decision = ollama_plan(state)
        ai_plan = validate_plan(state, decision.get('actions', []))
        ai_selected_count = len(ai_plan)
        plan = _merge_ai_actions([], ai_plan, budget=budget)
        summary = str(decision.get('reasoning_summary', ''))[:1000]
        finished = bool(decision.get('finish', False)) and (not plan)
        endpoint = str(LAST_OLLAMA_PLAN_DIAGNOSTICS.get('endpoint', 'unknown'))
        context_bytes = int(LAST_OLLAMA_PLAN_DIAGNOSTICS.get('context_bytes', 0) or 0)
        planner_seconds = float(LAST_OLLAMA_PLAN_DIAGNOSTICS.get('seconds', 0) or 0)
        candidate_count = int(LAST_OLLAMA_PLAN_DIAGNOSTICS.get('candidate_count', 0) or 0)
        selected_ids = [str(value) for value in LAST_OLLAMA_PLAN_DIAGNOSTICS.get('selected_action_ids', [])]
        review_selected_ids = [str(value) for value in LAST_OLLAMA_PLAN_DIAGNOSTICS.get('review_selected_action_ids', [])]
        review_seconds = float(LAST_OLLAMA_PLAN_DIAGNOSTICS.get('review_seconds', 0) or 0)
        review_error = str(LAST_OLLAMA_PLAN_DIAGNOSTICS.get('review_error', '') or '')
        review_reasoning = str(LAST_OLLAMA_PLAN_DIAGNOSTICS.get('review_reasoning', '') or '')[:500]
        if not plan and (not finished) and eligible:
            finished = True
            summary = (summary + ' No action was selected; the planner ended the round without forcing a checklist.').strip()
        if review_selected_ids:
            summary = (summary + f' Breadth review added {len(review_selected_ids)} complementary action(s).').strip()
            if review_reasoning:
                summary = (summary + f' Review: {review_reasoning}').strip()
        elif review_seconds and review_reasoning:
            summary = (summary + f' Breadth review added no actions. Review: {review_reasoning}').strip()
        elif review_error:
            summary = (summary + ' Optional breadth review failed; the initial AI plan was kept.').strip()
        notes.append(f'Round {round_number} [{planner_source}/{endpoint}; context={context_bytes}B]: {summary}')
        review_note = f'; review=+{len(review_selected_ids)} in {review_seconds:.1f}s' if review_seconds else ''
        print(f'\n[*] Ollama plan round {round_number} via {endpoint} (context={context_bytes} bytes; candidates={candidate_count}; selected={len(selected_ids)}{review_note}; {planner_seconds:.1f}s): {summary}', flush=True)
    except Exception as exc:
        endpoint = str(LAST_OLLAMA_PLAN_DIAGNOSTICS.get('endpoint', 'unavailable'))
        context_bytes = int(LAST_OLLAMA_PLAN_DIAGNOSTICS.get('context_bytes', 0) or 0)
        if state.get('require_ai'):
            raise RuntimeError(f'Strict agentic mode requires a successful Ollama plan: {type(exc).__name__}: {exc}') from exc
        plan = _fallback_plan(state, eligible, budget)
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
        'eligible_tools': sorted({str(action.get('tool') or '') for action in eligible}),
        'round_action_budget': budget,
        'ai_selected_action_count': ai_selected_count,
        'review_selected_action_count': len(review_selected_ids) if planner_source == 'ai' else 0,
        'review_reasoning': review_reasoning if planner_source == 'ai' else '',
        'fallback_reason': fallback_reason,
        'selected_action_count': len(plan),
        'selected_actions': [_audit_action_summary(action) for action in plan],
        'reasoning_summary': summary[:1500]})
    print(f'[*] Validated actions: {len(plan)}', flush=True)
    for action in plan:
        print(f"    {action['profile']:13} {action['tool']:10} {action['target_url']} — {action['reason']}", flush=True)
    return {'plan': plan, 'round': round_number, 'notes': notes, 'finished': finished, 'planner_source': planner_source, 'planner_audit': audit}

# Action execution invokes one validated tool and stores the normalized result in planner state.
async def execute_action(action: dict[str, Any], cookies: dict[str, str], discovery: dict[str, dict[str, Any]], allow_state_changes: bool=False, secondary_cookies: str='') -> tuple[dict[str, Any], dict[str, Any]]:
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
        arguments = {'target_url': action['target_url'], 'injection_url': action['injection_url'], 'cookies': cookies.get(profile, ''), 'method': action.get('method', 'GET'), 'data': action.get('data', ''), 'parameter': (action.get('parameters') or [''])[0], 'timeout': oast_timeout}
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
        print(f'    [PRECHECK] {tool}: validating authenticated session with {probe_url}', flush=True)
        state_refresh = shared.refresh_authenticated_session_state(refresh_target, cookies[profile], probe_url)
        if state_refresh.get('usable') is False:
            print(f'    [PARTIAL ] {tool}: authenticated session precheck failed', flush=True)
            return (action, {'tool': tool, 'status': 'partial', 'target': action['target_url'], 'output': 'The authenticated session could not be re-established before the scanner.', 'vulnerabilities': [], 'diagnosis': 'authentication_precheck_failed', 'state_refresh': state_refresh})
        print(f'    [SESSION ] {tool}: authenticated session usable', flush=True)
    try:
        scanner_limit = float(arguments.get('timeout', 180))
        spec = next((item for item in shared.ALL_TOOLS if item.name == tool), None)
        if spec is not None:
            result = await call_mcp_with_progress(spec, arguments, timeout_seconds=scanner_limit + 35)
        else:
            print(f"    [RUNNING ] {tool}: {action['target_url']} (scanner limit {scanner_limit:g}s)", flush=True)
            result = await call_mcp(server, function, arguments, timeout_seconds=scanner_limit + 35)
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
async def execute_plan(plan: list[dict[str, Any]], cookies: dict[str, str], discovery: dict[str, dict[str, Any]], allow_state_changes: bool=False, secondary_cookies: str='') -> list[tuple[dict[str, Any], dict[str, Any]]]:

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
        print(f"\n[*] Action {index}/{total}: {action['profile']} / {action['tool']} / {action['target_url']}", flush=True)
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
        profile_results[f'{tool}:{number}'] = {**result, 'planner_reason': action['reason'], 'planner_round': state['round']}
        completed.append(action_id(action))
        log_result(profile, tool, result, action['target_url'])
        if tool == 'zap':
            log_zap_session_diagnostics(result)
        if tool == 'ffuf' and result.get('status') in {'success', 'partial'}:
            before = len(discovery.get(profile, {}).get('request_cases', []))
            enriched, urls = enrich_discovery_with_ffuf(discovery.get(profile, {}), result, state['target'])
            if urls:
                recrawl = discover_target(state['target'], profile_cookies.get(profile, ''), seeds=urls)
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
        ffuf_executed = asyncio.run(execute_plan(discovery_stage, cookies, discovery, allow_state_changes=state.get('allow_state_changes', False), secondary_cookies=state.get('secondary_cookies', '')))
        new_attack_surface += _record_execution_batch(ffuf_executed, state=state, results=results, discovery=discovery, completed=completed, profile_cookies=profile_cookies)
        print('[*] FFUF enrichment is available to planned ZAP/Nuclei actions; new parameter candidates will be offered to Ollama next round.', flush=True)
    if remaining_stage:
        executed = asyncio.run(execute_plan(remaining_stage, cookies, discovery, allow_state_changes=state.get('allow_state_changes', False), secondary_cookies=state.get('secondary_cookies', '')))
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

# Decides whether the agent should plan again or create the report.
def route_after_execution(state: AgentState) -> Literal['planner', 'report']:
    return 'report' if state['finished'] or state['round'] >= state['max_rounds'] or (not state['plan']) else 'planner'

# Once execution is complete, reporting receives the collected state and produces the final assessment.
def report_node(state: AgentState) -> dict[str, Any]:
    print('\n[*] Creating final PDF, HTML preview and JSON report...')
    output_name = f'SecOps_Agentic_Assessment_{datetime.now():%Y%m%d_%H%M%S}'
    report_results = _materialize_unselected_actions(state)
    remaining = _remaining_eligible_actions({**state, 'results': report_results})
    context = {'profiles': [{'name': profile['name'], 'authenticated': bool(profile['cookies'])} for profile in state['profiles']],
        'expected_tools': list(REGISTRY),
        'discovery': state['discovery'],
        'diagnostics': state['diagnostics'],
        'planner_notes': state['notes'],
        'planner_rounds': state['round'],
        'ollama_model': state['model'],
        'ollama_url': state['ollama_url'],
        'strict_ai_required': state.get('require_ai', False),
        'planner_source': state.get('planner_source', 'unknown'),
        'planner_audit': state.get('planner_audit', []),
        'scan_mode': shared.CURRENT_SCAN_MODE,
        'runtime_platform': platform.platform(),
        'python_executable': sys.executable,
        'mcp_server_python': shared._server_python(),
        'remaining_eligible_actions_at_report': len(remaining),
        'execution_policy': 'AI-selected actions use the same deterministic tool catalogue, discovery selectors, request contracts, scan profiles and safety validators. The planner chooses only discovery-derived candidates according to expected information gain and may defer redundant actions without a checklist or minimum tool set. Bounded state-changing workflow probes run automatically on local labs and require explicit --allow-state-changes for remote authorized targets.',
        'allow_state_changes': state.get('allow_state_changes', False),
        'secondary_identity_supplied': bool(state.get('secondary_cookies', ''))}
    report = asyncio.run(call_mcp('reporting/reportServer.py', 'generate_report', {'findings_summary': report_results, 'target_url': state['target'], 'output_name': output_name, 'assessment_context': context}))
    if report.get('status') != 'success' and (not report.get('json_filename')):
        fallback = write_emergency_json_report(state['target'], state['results'], state['diagnostics'], str(report.get('output', 'Report MCP failed.')), 'SecOps_Agentic_Emergency')
        if fallback:
            report.update(json_filename=fallback, html_filename=str(Path(fallback).with_suffix('.html')), local_json_fallback=True)
    return {'report_status': report, 'results': report_results}
