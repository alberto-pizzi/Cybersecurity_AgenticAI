from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import traceback
from pathlib import Path
from typing import Any, TypedDict
from urllib.parse import parse_qsl, urlparse

from langgraph.graph import END, START, StateGraph

import orchestratorShared as shared
from orchestratorShared import (
    ALL_TOOLS, ARJUN_TOOL, AUTHORIZATION_TOOL, BASE_TOOLS, BROAD_SCANNER_TIMEOUTS,
    OPTIONAL_TOOLS, PARAMETER_TOOLS, PARAMETER_TOOL_TIMEOUTS, PARAMETER_TOOL_CASE_LIMITS,
    SCANNER_PROGRESS_INTERVAL, SINGLE_TOOL_CHOICES, TIME_LIMIT_DIAGNOSES, ToolSpec, WORKFLOW_TOOLS,
    add_common_cli_arguments, agentic_registry, aggregate_runs, broad_tool_order,
    build_tool_arguments, call_mcp, call_mcp_with_progress, configure_scan_mode,
    diagnose_error, discover_target, enrich_discovery_with_arjun, enrich_discovery_with_ffuf,
    iter_leaf_results, log_result, log_zap_session_diagnostics, make_skipped_result,
    merge_discovery, prepare_cli_context, print_preflight_report, print_security_finding_summary,
    refresh_authenticated_session_state, run_preflight_checks, select_arjun_request_cases,
    select_authorization_request_cases, select_browser_request_cases, select_oast_request_cases,
    select_request_cases, select_session_probe_url, select_tool_request_cases,
    select_workflow_request_cases, state_changing_tests_allowed, summarize_results,
    tool_action_limit, tool_execution_rank, write_emergency_json_report,
    _is_login_case, _server_python, _tool_case_skip_reason,
)
from utils import normalize_url, same_origin, scanner_session_probe

# The compatibility self-test looks for Client(url), mcp_http_handshake_ok, ToolSpec("idor", "idorForgeServer.py", "run_idor_check", "idor-forge"), and ToolSpec("report", "reportServer.py", "generate_report", module="weasyprint").


# Delegates MCP server startup to the shared helper so both orchestrators use the same lifecycle.
def _ensure_http_server(*args: Any, **kwargs: Any):
    return shared._ensure_http_server(*args, **kwargs)

# Falls back to the shared implementation when a public name is not defined locally.
def __getattr__(name: str) -> Any:
    try:
        return getattr(shared, name)
    except AttributeError as exc:
        raise AttributeError(name) from exc


# Stores the state exchanged between the deterministic workflow steps.
class DeterministicState(TypedDict, total=False):
    target: str
    profiles: list[dict[str, str]]
    injection_url: str
    allow_state_changes: bool
    secondary_cookies: str
    discovery: dict[str, dict[str, Any]]
    diagnostics: list[dict[str, Any]]
    results: dict[str, dict[str, Any]]
    workflow_state_changes: bool
    has_authenticated_profile: bool
    profile_session_state: dict[str, bool]
    parameter_selection_summary: dict[str, dict[str, list[dict[str, Any]]]]
    authorization_selection_summary: dict[str, list[dict[str, Any]]]
    workflow_selection_summary: dict[str, dict[str, list[dict[str, Any]]]]
    oast_selection_summary: dict[str, list[dict[str, Any]]]
    assessment_context: dict[str, Any]
    report_status: dict[str, Any]

# Discovers pages, forms, and request cases separately for every active profile.
async def deterministic_discovery_node(state: DeterministicState) -> dict[str, Any]:
    target = state['target']
    profiles = state['profiles']
    allow_state_changes = bool(state.get('allow_state_changes', False))
    print('\n[*] Discovery anonima e autenticata...')
    discovery: dict[str, dict[str, Any]] = {}
    diagnostics: list[dict[str, Any]] = []
    results = {profile['name']: {} for profile in profiles}
    workflow_state_changes = state_changing_tests_allowed(target, allow_state_changes)
    for profile in profiles:
        name = profile['name']
        found = discover_target(target, profile['cookies'])
        discovery[name] = found
        diagnostics.extend(({'phase': 'discovery', 'profile': name, **item} for item in found['errors']))
        print(f"    {name}: {len(found['html_urls'])} pagine HTML, {len(found['request_cases'])} casi GET/POST, {len(found['errors'])} errori")
        for error in found['errors'][:5]:
            print(f"      [CRAWL WARNING] {error.get('type', 'error')}: {error.get('url', '')} — {error.get('message', '')}")
        if len(found['errors']) > 5:
            print(f"      [CRAWL WARNING] altri {len(found['errors']) - 5} errori sono inclusi nel report.")
        if found.get('authentication_effective') is False:
            print(f"    [WARNING] {name}: {found.get('authentication_note')}", file=sys.stderr)
    return {'discovery': discovery, 'diagnostics': diagnostics, 'results': results, 'workflow_state_changes': workflow_state_changes}

# Because FFUF and ZAP can expand discovery, broad scanning is completed before specialist selection.
async def deterministic_broad_scan_node(state: DeterministicState) -> dict[str, Any]:
    target = state['target']
    profiles = state['profiles']
    discovery = state['discovery']
    diagnostics = state['diagnostics']
    results = state['results']
    has_authenticated_profile = any((bool(profile.get('cookies')) for profile in profiles))
    profile_session_state = {profile['name']: discovery[profile['name']].get('authentication_effective') is not False for profile in profiles}
    broad_specs = {spec.name: spec for spec in BASE_TOOLS}
    for profile in profiles:
        name, cookies = (profile['name'], profile['cookies'])
        print(f'\n[*] Scanner generali - profilo: {name}')
        if cookies and 'anonymous' in results:
            anonymous_ffuf = results.get('anonymous', {}).get('ffuf', {})
            if isinstance(anonymous_ffuf, dict):
                _, anonymous_urls = enrich_discovery_with_ffuf(discovery[name], anonymous_ffuf, target)
                if anonymous_urls:
                    recrawl = discover_target(target, cookies, seeds=anonymous_urls)
                    discovery[name] = merge_discovery(discovery[name], recrawl)
                    diagnostics.extend(({'phase': 'anonymous_ffuf_authenticated_recrawl', 'profile': name, **item} for item in recrawl['errors']))
        session_valid = discovery[name].get('authentication_effective') is not False
        probe_url = select_session_probe_url(discovery[name], target)
        for scanner_name in broad_tool_order(bool(cookies)):
            spec = broad_specs[scanner_name]
            scanner_timeout = BROAD_SCANNER_TIMEOUTS.get(spec.name, 180)
            if cookies and spec.name == 'ffuf' and (shared.CURRENT_SCAN_MODE == 'balanced'):
                scanner_timeout = min(scanner_timeout, 35)
            if name == 'anonymous' and has_authenticated_profile and (shared.CURRENT_SCAN_MODE != 'deep') and (spec.name in {'nikto', 'session'}):
                result = make_skipped_result(spec.name, target, 'Balanced mode runs this host/session-level scanner once on the authenticated profile to avoid duplicate time and traffic.')
            elif cookies and (not session_valid):
                result = make_skipped_result(spec.name, target, 'Authenticated session is no longer valid; this run was skipped to avoid reporting anonymous coverage as authenticated.')
            else:
                arguments = build_tool_arguments(spec.name, target, cookies, discovery[name], timeout_override=scanner_timeout)
                result = await call_mcp_with_progress(spec, arguments)
            results[name][spec.name] = result
            log_result(name, spec.name, result, target)
            if result.get('status') == 'skipped':
                continue
            if spec.name == 'zap':
                log_zap_session_diagnostics(result)
                if cookies:
                    recovery = scanner_session_probe(probe_url, cookies, timeout=10, attempts=4)
                    refresh = refresh_authenticated_session_state(target, cookies, probe_url)
                    result['downstream_session_recovery'] = recovery
                    result['downstream_session_state_refresh'] = refresh
                    if refresh.get('usable') is False:
                        session_valid = False
                        print('    [AUTH SESSION ROOT CAUSE] The authenticated session could not be restored after ZAP.', file=sys.stderr)
                    if recovery.get('conclusive') and recovery.get('authenticated') is False:
                        session_valid = False
                        print('    [AUTH SESSION ROOT CAUSE] Direct recovery probe conclusively reached the login page after ZAP.', file=sys.stderr)
                    elif recovery.get('conclusive') is False:
                        print('    [WARNING] Target recovery remained temporarily inconclusive; downstream scanners will still run because no logout was proven.', file=sys.stderr)
            if spec.name == 'ffuf' and result.get('status') in {'success', 'partial'}:
                discovery[name], discovered_urls = enrich_discovery_with_ffuf(discovery[name], result, target)
                if discovered_urls:
                    recrawl = discover_target(target, cookies, seeds=discovered_urls)
                    discovery[name] = merge_discovery(discovery[name], recrawl)
                    diagnostics.extend(({'phase': 'ffuf_recrawl', 'profile': name, **item} for item in recrawl['errors']))
                    print(f"    [INFO   ] FFUF re-crawl: {len(discovery[name]['html_urls'])} HTML pages, {len(discovery[name]['request_cases'])} GET/POST cases")
                    if cookies and recrawl.get('authentication_effective') is False:
                        session_valid = False
                        print('    [AUTH SESSION ROOT CAUSE] The authenticated session became invalid after FFUF. Remaining authenticated scanners will be skipped.', file=sys.stderr)
                if cookies and result.get('diagnosis') == 'authentication_lost_during_ffuf':
                    session_valid = False
        arjun_runs: list[dict[str, Any]] = []
        arjun_cases = select_arjun_request_cases(discovery[name], target, limit=shared.ARJUN_ENDPOINT_LIMIT)
        if arjun_cases:
            print(f'    [INFO   ] Arjun request cases selected: {len(arjun_cases)}')
            empty_limits = 0
            limit_threshold = 2 if shared.CURRENT_SCAN_MODE == 'deep' else 1
            for case in arjun_cases:
                endpoint = str(case.get('url') or target)
                if empty_limits >= limit_threshold:
                    result = make_skipped_result('arjun', endpoint, 'Adaptive budget reallocation: earlier high-priority Arjun runs reached their full budget without discovering a parameter, so lower-priority repeats were skipped.') | {'diagnosis': 'adaptive_budget_reallocated'}
                else:
                    refresh = refresh_authenticated_session_state(target, cookies, probe_url) if cookies else {'performed': False, 'usable': True}
                    arguments = build_tool_arguments('arjun', endpoint, cookies, discovery[name], case=case)
                    result = await call_mcp_with_progress(ARJUN_TOOL, arguments)
                    result['session_state_refresh'] = refresh
                    found = int(result.get('phase_parameters', 0) or 0)
                    timed_out_empty = result.get('diagnosis') in TIME_LIMIT_DIAGNOSES and (not result.get('vulnerabilities')) and (found == 0)
                    empty_limits = empty_limits + 1 if timed_out_empty else 0
                    if result.get('status') in {'success', 'partial'}:
                        discovery[name], _ = enrich_discovery_with_arjun(discovery[name], result, endpoint)
                arjun_runs.append(result)
                log_result(name, 'arjun', result, endpoint)
        profile_session_state[name] = session_valid
        results[name]['arjun'] = aggregate_runs('arjun', target, arjun_runs) if arjun_runs else make_skipped_result('arjun', target, 'No suitable HTML/form endpoint was available for hidden-parameter discovery.')
    return {'discovery': discovery, 'diagnostics': diagnostics, 'results': results, 'has_authenticated_profile': has_authenticated_profile, 'profile_session_state': profile_session_state}

# For parameter testing, each specialist receives only the request cases relevant to its vulnerability class.
async def deterministic_parameter_scan_node(state: DeterministicState) -> dict[str, Any]:
    target = state['target']
    profiles = state['profiles']
    discovery = state['discovery']
    results = state['results']
    allow_state_changes = bool(state.get('workflow_state_changes', False))
    has_authenticated_profile = bool(state.get('has_authenticated_profile', False))
    session_state = state.get('profile_session_state', {})
    selection_summary: dict[str, dict[str, list[dict[str, Any]]]] = {}
    semaphore = asyncio.Semaphore(2 if shared.CURRENT_SCAN_MODE == 'deep' else 1)

    # A selected request case is executed and converted into the common tool-result format.
    async def run_case(spec: ToolSpec, case: dict[str, Any], cookies: str, probe_url: str) -> dict[str, Any]:
        url = str(case.get('url', ''))
        skip_reason = _tool_case_skip_reason(spec.name, case)
        if skip_reason:
            return make_skipped_result(spec.name, url, skip_reason)
        timeout = PARAMETER_TOOL_TIMEOUTS.get(spec.name, 120)
        arguments = build_tool_arguments(spec.name, url, cookies, {}, case=case, allow_state_changes=allow_state_changes, timeout_override=timeout)
        async with semaphore:
            refresh = refresh_authenticated_session_state(target, cookies, probe_url) if cookies else {'performed': False, 'usable': True}
            if refresh.get('usable') is False:
                return make_skipped_result(spec.name, url, 'The authenticated session could not be restored before this scanner.') | {'session_state_refresh': refresh}
            result = await call_mcp_with_progress(spec, arguments, timeout_seconds=timeout + 35)
            result['session_state_refresh'] = refresh
            return result
    for profile in profiles:
        name, cookies = (profile['name'], profile['cookies'])
        print(f'\n[*] Scanner su parametri - profilo: {name}')
        selection_summary[name] = {}
        skip_reason = ''
        if name == 'anonymous' and has_authenticated_profile:
            skip_reason = 'Active parameter testing uses the richer authenticated request surface; repeating it against the anonymous authentication form is non-applicable and wastes the scan budget.'
        elif cookies and (not session_state.get(name, True)):
            skip_reason = 'Authenticated session became invalid before parameter testing.'
        if skip_reason:
            for spec in PARAMETER_TOOLS:
                results[name][spec.name] = make_skipped_result(spec.name, target, skip_reason)
                log_result(name, spec.name, results[name][spec.name], target)
            continue
        grouped = {spec.name: [] for spec in PARAMETER_TOOLS}
        tasks: list[tuple[ToolSpec, dict[str, Any], asyncio.Task[dict[str, Any]]]] = []
        probe_url = select_session_probe_url(discovery[name], target)
        for spec in PARAMETER_TOOLS:
            cases = select_tool_request_cases(discovery[name], spec.name)
            if cookies and spec.name == 'sqlmap':
                cases = [case for case in cases if not _is_login_case(case)]
            get_count = sum((str(case.get('method', 'GET')).upper() == 'GET' for case in cases))
            selection_summary[name][spec.name] = [{'method': str(case.get('method', 'GET')).upper(), 'url': str(case.get('url', '')), 'parameters': list(case.get('parameters', []))} for case in cases]
            print(f'    [INFO   ] {spec.name}: casi selezionati={len(cases)} (GET={get_count}, POST={len(cases) - get_count})')
            tasks.extend(((spec, case, asyncio.create_task(run_case(spec, case, cookies, probe_url))) for case in cases))
        for spec, case, task in tasks:
            result = await task
            grouped[spec.name].append(result)
            log_result(name, spec.name, result, f"{case.get('method', 'GET')} {case.get('url', '')}")
        for spec in PARAMETER_TOOLS:
            runs = grouped[spec.name]
            results[name][spec.name] = aggregate_runs(spec.name, target, runs) if runs else make_skipped_result(spec.name, target, f"No discovered request matched {spec.name}'s vulnerability class.")
    return {'results': results, 'parameter_selection_summary': selection_summary}

# Authorization checks remain read-only and use only requests that support a meaningful comparison.
async def deterministic_authorization_node(state: DeterministicState) -> dict[str, Any]:
    target = state['target']
    profiles = state['profiles']
    discovery = state['discovery']
    results = state['results']
    secondary_cookies = str(state.get('secondary_cookies', ''))
    profile_session_state = state.get('profile_session_state', {})
    authorization_selection_summary: dict[str, list[dict[str, Any]]] = {}
    for profile in profiles:
        name, cookies = (profile['name'], profile['cookies'])
        authorization_selection_summary[name] = []
        if not cookies:
            result = make_skipped_result('authorization', target, 'Authorization comparison requires a primary authenticated profile.')
            results[name]['authorization'] = result
            log_result(name, 'authorization', result, target)
            continue
        if not profile_session_state.get(name, True):
            result = make_skipped_result('authorization', target, 'Authenticated session became invalid before authorization comparison.')
            results[name]['authorization'] = result
            log_result(name, 'authorization', result, target)
            continue
        cases = select_authorization_request_cases(discovery[name])
        authorization_selection_summary[name] = [{'method': 'GET', 'url': str(case.get('url', '')), 'parameters': list(case.get('parameters', []))} for case in cases]
        print(f"\n[*] Authorization differential - profilo: {name}\n    [INFO   ] authorization: casi selezionati={len(cases)}; seconda identità={('sì' if secondary_cookies else 'no')}")
        runs: list[dict[str, Any]] = []
        probe_url = select_session_probe_url(discovery[name], target)
        for case in cases:
            state_refresh = refresh_authenticated_session_state(target, cookies, probe_url)
            if state_refresh.get('usable') is False:
                result = make_skipped_result('authorization', str(case.get('url', target)), 'The primary authenticated session could not be restored before authorization comparison.') | {'session_state_refresh': state_refresh}
            else:
                result = await call_mcp_with_progress(AUTHORIZATION_TOOL, {'target_url': str(case.get('url', target)), 'cookies': cookies, 'secondary_cookies': secondary_cookies, 'method': 'GET', 'data': '', 'parameters': list(case.get('parameters', [])), 'timeout': PARAMETER_TOOL_TIMEOUTS.get('authorization', 40)}, timeout_seconds=PARAMETER_TOOL_TIMEOUTS.get('authorization', 40) + 30)
                result['session_state_refresh'] = state_refresh
            runs.append(result)
            log_result(name, 'authorization', result, str(case.get('url', target)))
        results[name]['authorization'] = aggregate_runs('authorization', target, runs) if runs else make_skipped_result('authorization', target, 'No discovered read-only request contained a plausible identity, object or privileged-resource signal.')
        if not runs:
            log_result(name, 'authorization', results[name]['authorization'], target)
    return {'results': results, 'authorization_selection_summary': authorization_selection_summary}

# Once parameter scanners finish, browser and workflow checks reuse the latest discovery state.
async def deterministic_browser_workflow_node(state: DeterministicState) -> dict[str, Any]:
    target = state['target']
    profiles = state['profiles']
    discovery = state['discovery']
    results = state['results']
    allow_state_changes = bool(state.get('workflow_state_changes', False))
    has_authenticated_profile = bool(state.get('has_authenticated_profile', False))
    session_state = state.get('profile_session_state', {})
    selection_summary: dict[str, dict[str, list[dict[str, Any]]]] = {}
    specs = {spec.name: spec for spec in WORKFLOW_TOOLS}

    # A selected request case is executed and converted into the common tool-result format.
    async def run_case(tool: str, case: dict[str, Any], cookies: str, profile_discovery: dict[str, Any], probe_url: str) -> dict[str, Any]:
        url = str(case.get('url', target))
        refresh = refresh_authenticated_session_state(target, cookies, probe_url) if cookies else {'performed': False, 'usable': True}
        if refresh.get('usable') is False:
            return make_skipped_result(tool, url, f'The authenticated session could not be restored before {tool} verification.')
        arguments = build_tool_arguments(tool, url, cookies, profile_discovery, case=case, allow_state_changes=allow_state_changes)
        result = await call_mcp_with_progress(specs[tool], arguments, timeout_seconds=PARAMETER_TOOL_TIMEOUTS[tool] + 35)
        result['session_state_refresh'] = refresh
        return result
    for profile in profiles:
        name, cookies = (profile['name'], profile['cookies'])
        selection_summary[name] = {'browser': [], 'workflow': []}
        skip_reason = ''
        if name == 'anonymous' and has_authenticated_profile and (shared.CURRENT_SCAN_MODE != 'deep'):
            skip_reason = 'Balanced mode runs browser/workflow verification on the richer authenticated surface.'
        elif cookies and (not session_state.get(name, True)):
            skip_reason = 'Authenticated session became invalid before browser/workflow verification.'
        if skip_reason:
            for spec in WORKFLOW_TOOLS:
                results[name][spec.name] = make_skipped_result(spec.name, target, skip_reason)
                log_result(name, spec.name, results[name][spec.name], target)
            continue
        profile_discovery = discovery[name]
        probe_url = select_session_probe_url(profile_discovery, target)
        browser_cases = select_browser_request_cases(profile_discovery)
        workflow_cases = select_workflow_request_cases(profile_discovery)
        selection_summary[name]['browser'] = [{'method': str(case.get('method', 'GET')).upper(), 'url': str(case.get('url', '')), 'parameters': list(case.get('parameters', [])), 'fields': list(case.get('fields', [])), 'source_url': str(case.get('source_url', '')), 'client_sources': list(case.get('client_sources', [])), 'client_sinks': list(case.get('client_sinks', []))} for case in browser_cases]
        selection_summary[name]['workflow'] = [{'method': str(case.get('method', 'POST')).upper(), 'url': str(case.get('url', '')), 'parameters': list(case.get('parameters', [])), 'file_parameters': list(case.get('file_parameters', [])), 'token_parameters': list(case.get('token_parameters', [])), 'source_url': str(case.get('source_url', ''))} for case in workflow_cases]
        print(f'\n[*] Browser/workflow - profilo: {name}')
        print(f'    [INFO   ] browser: casi selezionati={len(browser_cases)}')
        print(f'    [INFO   ] workflow: casi selezionati={len(workflow_cases)}')
        browser_runs: list[dict[str, Any]] = []
        browser_unavailable = False
        for case in browser_cases:
            url = str(case.get('url', target))
            if browser_unavailable:
                result = make_skipped_result('browser', url, 'Playwright was unavailable in the first browser run; remaining browser cases were not repeated.')
            else:
                result = await run_case('browser', case, cookies, profile_discovery, probe_url)
                if result.get('diagnosis') in {'missing_playwright', 'missing_playwright_browser'}:
                    browser_unavailable = True
            browser_runs.append(result)
            log_result(name, 'browser', result, url)
        results[name]['browser'] = aggregate_runs('browser', target, browser_runs) if browser_runs else make_skipped_result('browser', target, 'No discovered request or client-side source/sink page matched browser XSS verification.')
        if not browser_runs:
            log_result(name, 'browser', results[name]['browser'], target)
        workflow_runs: list[dict[str, Any]] = []
        for case in workflow_cases:
            url = str(case.get('url', target))
            result = await run_case('workflow', case, cookies, profile_discovery, probe_url)
            workflow_runs.append(result)
            log_result(name, 'workflow', result, url)
        results[name]['workflow'] = aggregate_runs('workflow', target, workflow_runs) if workflow_runs else make_skipped_result('workflow', target, 'No discovered POST form matched CSRF, upload, authentication or CAPTCHA workflow classes.')
        if not workflow_runs:
            log_result(name, 'workflow', results[name]['workflow'], target)
    return {'results': results, 'workflow_selection_summary': selection_summary}

# OAST and JWT analysis are added only when discovery provides suitable inputs.
async def deterministic_special_checks_node(state: DeterministicState) -> dict[str, Any]:
    target = state['target']
    profiles = state['profiles']
    discovery = state['discovery']
    results = state['results']
    injection_url = str(state.get('injection_url', ''))
    oast_selection_summary: dict[str, list[dict[str, Any]]] = {}
    for profile in profiles:
        name = profile['name']
        token = (discovery[name].get('jwt_tokens') or [''])[0]
        jwt_result = await call_mcp('jwtServer.py', 'run_jwt_scan', {'jwt_token': token, 'target_url': target}) if token else make_skipped_result('jwt', target, 'No JWT was discovered in crawled responses.')
        if injection_url:
            oast_cases = [{'target_url': target, 'source_url': injection_url, 'injection_url': injection_url, 'method': 'GET', 'data': '', 'parameter': 'explicit', 'parameters': ['explicit'], 'priority_score': 1000}]
        else:
            oast_cases = select_oast_request_cases(discovery[name], target, limit=2 if shared.CURRENT_SCAN_MODE == 'deep' else 1)
        oast_selection_summary[name] = oast_cases
        interactsh_runs: list[dict[str, Any]] = []
        confirmed_oast_classes: set[str] = set()
        for oast_case in oast_cases:
            oast_class = str(oast_case.get('oast_class') or 'explicit')
            if oast_class in confirmed_oast_classes:
                skipped_duplicate = make_skipped_result('interactsh', oast_case.get('source_url', target), f'A callback was already confirmed for the same OAST class ({oast_class}); the duplicate wait was omitted.')
                interactsh_runs.append(skipped_duplicate)
                log_result(name, 'interactsh', skipped_duplicate, oast_case.get('source_url', target))
                continue
            interactsh_spec = next((item for item in OPTIONAL_TOOLS if item.name == 'interactsh'))
            if injection_url:
                oast_timeout = 120 if shared.CURRENT_SCAN_MODE == 'deep' else 75
            elif oast_class == 'command':
                oast_timeout = 75 if shared.CURRENT_SCAN_MODE == 'deep' else 55
            else:
                oast_timeout = 60 if shared.CURRENT_SCAN_MODE == 'deep' else 45
            result = await call_mcp_with_progress(interactsh_spec, {'target_url': target, 'injection_url': oast_case['injection_url'], 'cookies': profile['cookies'], 'method': oast_case.get('method', 'GET'), 'data': oast_case.get('data', ''), 'parameter': oast_case.get('parameter', ''), 'timeout': oast_timeout}, timeout_seconds=oast_timeout + 35)
            result['oast_class'] = oast_class
            interactsh_runs.append(result)
            log_result(name, 'interactsh', result, oast_case.get('source_url', target))
            if result.get('callback_confirmed'):
                confirmed_oast_classes.add(oast_class)
        interactsh_result = aggregate_runs('interactsh', target, interactsh_runs) if interactsh_runs else make_skipped_result('interactsh', target, 'No discovered OAST-capable input was available. Interactsh is functional, but no URL/host/callback/webhook/proxy/remote-resource or command-execution insertion point was found.')
        results[name].update(jwt=jwt_result, interactsh=interactsh_result)
        log_result(name, 'jwt', jwt_result, target)
        if not interactsh_runs:
            log_result(name, 'interactsh', interactsh_result, target)
    return {'results': results, 'oast_selection_summary': oast_selection_summary}

# At the end of the pipeline, the complete assessment state is sent to the report service.
async def deterministic_report_node(state: DeterministicState) -> dict[str, Any]:
    target = state['target']
    profiles = state['profiles']
    discovery = state['discovery']
    diagnostics = state['diagnostics']
    results = state['results']
    secondary_cookies = str(state.get('secondary_cookies', ''))
    parameter_selection_summary = state.get('parameter_selection_summary', {})
    oast_selection_summary = state.get('oast_selection_summary', {})
    workflow_selection_summary = state.get('workflow_selection_summary', {})
    authorization_selection_summary = state.get('authorization_selection_summary', {})
    context = {'profiles': [{'name': profile['name'], 'authenticated': bool(profile['cookies'])} for profile in profiles],
        'expected_tools': [spec.name for spec in (*BASE_TOOLS, ARJUN_TOOL, *PARAMETER_TOOLS, AUTHORIZATION_TOOL, *WORKFLOW_TOOLS, OPTIONAL_TOOLS[0], OPTIONAL_TOOLS[1])],
        'discovery': discovery,
        'diagnostics': diagnostics,
        'parameter_endpoint_limit': shared.MAX_PARAMETER_ENDPOINTS,
        'request_case_counts': {name: {'GET': sum((str(case.get('method', 'GET')).upper() == 'GET' for case in found.get('request_cases', []))), 'POST': sum((str(case.get('method', 'GET')).upper() == 'POST' for case in found.get('request_cases', [])))} for name, found in discovery.items()},
        'arjun_endpoint_limit': shared.ARJUN_ENDPOINT_LIMIT,
        'parameter_selection': parameter_selection_summary,
        'oast_selection': oast_selection_summary,
        'workflow_selection': workflow_selection_summary,
        'authorization_selection': authorization_selection_summary,
        'secondary_identity_supplied': bool(secondary_cookies),
        'parameter_tool_timeouts': PARAMETER_TOOL_TIMEOUTS,
        'broad_scanner_timeouts': BROAD_SCANNER_TIMEOUTS,
        'scan_mode': shared.CURRENT_SCAN_MODE}
    context['orchestration'] = {'engine': 'langgraph', 'mode': 'deterministic', 'nodes': ['discovery', 'broad_scan', 'parameter_scan', 'authorization', 'browser_workflow', 'special_checks', 'report']}
    print('\n[*] Generazione report...')
    report = await call_mcp('reportServer.py', 'generate_report', {'findings_summary': results, 'target_url': target, 'assessment_context': context})
    if report.get('status') != 'success' and (not report.get('json_filename')):
        fallback = write_emergency_json_report(target, results, diagnostics, str(report.get('output', 'Report MCP failed.')))
        if fallback:
            report.update(json_filename=fallback, html_filename=str(Path(fallback).with_suffix('.html')), local_json_fallback=True)
    return {'assessment_context': context, 'report_status': report}

# The deterministic pipeline executes the full graph and returns the state produced by its final node.
async def run_pipeline(target: str, profiles: list[dict[str, str]], injection_url: str, allow_state_changes: bool=False, secondary_cookies: str='') -> dict[str, Any]:
    # The deterministic graph starts from a fresh state containing discovery, results, and scan settings.
    initial: DeterministicState = {'target': target, 'profiles': profiles, 'injection_url': injection_url, 'allow_state_changes': allow_state_changes, 'secondary_cookies': secondary_cookies}
    final = await build_deterministic_graph().ainvoke(initial)
    return {'results': final['results'], 'discovery': final['discovery'], 'diagnostics': final['diagnostics'], 'report_status': final['report_status']}

# Reads a parameter list passed on the command line.
def _parse_parameter_argument(value: str) -> list[str]:
    return [item.strip() for item in str(value or '').split(',') if item.strip()]

# Selects one request case for an isolated tool run.
def _single_tool_case(discovery: dict[str, Any], tool: str, target: str, explicit_url: str, method: str, data: str, parameters: list[str]) -> dict[str, Any] | None:
    if explicit_url:
        url = normalize_url(explicit_url)
        if not same_origin(target, url):
            raise ValueError('--tool-url must have the same origin as --target.')
        effective_parameters = list(parameters)
        if not effective_parameters:
            source = urlparse(url).query if method == 'GET' else data
            effective_parameters = [name for name, _ in parse_qsl(source, keep_blank_values=True)]
        return {'url': url, 'method': method, 'data': data, 'parameters': effective_parameters, 'source_url': url}
    if tool == 'arjun':
        cases = select_arjun_request_cases(discovery, target, limit=1)
        return cases[0] if cases else None
    if tool == 'authorization':
        cases = select_authorization_request_cases(discovery, limit=1)
        return cases[0] if cases else None
    if tool == 'browser':
        cases = select_browser_request_cases(discovery, limit=1)
        return cases[0] if cases else None
    if tool == 'workflow':
        cases = select_workflow_request_cases(discovery, limit=1)
        return cases[0] if cases else None
    cases = select_tool_request_cases(discovery, tool, limit=1)
    return cases[0] if cases else None

# Tool-specific preflight filtering keeps only errors relevant to the requested isolated run.
def _single_tool_preflight_errors(checks: list[dict[str, str]], tool: str) -> list[dict[str, str]]:

    allowed = {'project', 'mcp', tool}
    return [item for item in checks if item.get('level') == 'error' and item.get('component') in allowed]

# Isolated tool mode keeps the same preparation and validation used by full assessments.
async def run_single_tool_debug(*, tool: str, target: str, cookies: str, mode: str, secondary_cookies: str='', explicit_url: str='', method: str='GET', data: str='', parameters: list[str] | None=None, jwt_token: str='', injection_url: str='', timeout_override: int=0, diagnostic_only: bool=False, allow_state_changes: bool=False) -> dict[str, Any]:

    configure_scan_mode(mode)
    method = str(method or 'GET').upper()
    parameters = [str(value) for value in parameters or [] if str(value)]
    if method not in {'GET', 'POST'}:
        raise ValueError('--method must be GET or POST.')
    if timeout_override < 0:
        raise ValueError('--tool-timeout cannot be negative.')
    discovery = discover_target(target, cookies)
    state_changes = state_changing_tests_allowed(target, allow_state_changes)
    spec = next((item for item in ALL_TOOLS if item.name == tool))
    selected_target = target
    if tool in {'ffuf', 'zap', 'nuclei', 'session', 'nikto'}:
        arguments = build_tool_arguments(tool, target, cookies, discovery, timeout_override=timeout_override or BROAD_SCANNER_TIMEOUTS[tool], diagnostic_only=diagnostic_only, single_tool=True)
    elif tool in {'arjun', 'sqlmap', 'dalfox', 'commix', 'traversal', 'idor', 'authorization', 'browser', 'workflow'}:
        if tool == 'authorization' and (not cookies):
            return make_skipped_result(tool, target, 'A primary authenticated Cookie header is required for authorization comparison.')
        case = _single_tool_case(discovery, tool, target, explicit_url, method, data, parameters)
        if not case:
            messages = {'arjun': 'No suitable endpoint was discovered for Arjun.', 'authorization': 'No discovered read-only request contained a plausible identity, object or privileged-resource signal.', 'browser': "No discovered request matched browser's workflow class.", 'workflow': "No discovered request matched workflow's workflow class."}
            return make_skipped_result(tool, target, messages.get(tool, f"No request matched {tool}'s vulnerability class."))
        selected_target = str(case.get('url') or target)
        effective_case = {**case, 'method': str(case.get('method') or method).upper(), 'data': str(case.get('data') or data), 'parameters': list(case.get('parameters') or parameters)}
        if tool == 'authorization':
            arguments = build_tool_arguments(tool, selected_target, cookies, discovery, case=effective_case, secondary_cookies=secondary_cookies, timeout_override=timeout_override)
        else:
            if tool not in {'arjun', 'authorization'} and cookies:
                refresh = refresh_authenticated_session_state(target, cookies, select_session_probe_url(discovery, target))
                if refresh.get('usable') is False:
                    if tool in {'browser', 'workflow'}:
                        return make_skipped_result(tool, selected_target, 'The authenticated session could not be restored before the isolated workflow run.')
                    return {'tool': tool, 'status': 'partial', 'target': selected_target, 'output': 'The authenticated session could not be restored before the isolated scanner run.', 'vulnerabilities': [], 'diagnosis': 'authentication_precheck_failed', 'state_refresh': refresh}
            arguments = build_tool_arguments(tool, selected_target, cookies, discovery, case=effective_case, allow_state_changes=state_changes, timeout_override=timeout_override, single_tool=True)
    elif tool == 'jwt':
        token = jwt_token or next(iter(discovery.get('jwt_tokens', [])), '')
        if not token:
            return make_skipped_result('jwt', target, 'No JWT was supplied or discovered.')
        arguments = {'jwt_token': token, 'target_url': target}
    elif tool == 'interactsh':
        if injection_url:
            selected = {'injection_url': injection_url, 'method': method, 'data': data, 'parameter': parameters[0] if parameters else 'explicit'}
        else:
            cases = select_oast_request_cases(discovery, target, limit=1)
            if not cases:
                return make_skipped_result('interactsh', target, 'No OAST-capable input was discovered.')
            selected = cases[0]
        arguments = {'target_url': target, 'injection_url': selected['injection_url'], 'cookies': cookies, 'method': selected.get('method', 'GET'), 'data': selected.get('data', ''), 'parameter': selected.get('parameter', ''), 'timeout': timeout_override or (120 if mode == 'deep' else 75)}
    else:
        raise ValueError(f'Unsupported single tool: {tool}')
    scanner_limit = float(arguments.get('timeout', 180))
    result = await call_mcp_with_progress(spec, arguments, timeout_seconds=scanner_limit + 45)
    result.setdefault('single_tool_debug', True)
    result.setdefault('selected_target', selected_target)
    result.setdefault('arguments_summary', {'method': arguments.get('method', ''), 'parameters': arguments.get('parameters', arguments.get('known_parameters', [])), 'timeout': arguments.get('timeout', 0), 'scan_mode': arguments.get('scan_mode', arguments.get('scan_profile', ''))})
    result.setdefault('discovery_summary', {'html_urls': len(discovery.get('html_urls', [])), 'request_cases': len(discovery.get('request_cases', [])), 'authentication_effective': discovery.get('authentication_effective')})
    return result

# Builds the ordered LangGraph used by the deterministic pipeline.
def build_deterministic_graph() -> Any:
    graph = StateGraph(DeterministicState)
    graph.add_node("discovery", deterministic_discovery_node)
    graph.add_node("broad_scan", deterministic_broad_scan_node)
    graph.add_node("parameter_scan", deterministic_parameter_scan_node)
    graph.add_node("authorization", deterministic_authorization_node)
    graph.add_node("browser_workflow", deterministic_browser_workflow_node)
    graph.add_node("special_checks", deterministic_special_checks_node)
    graph.add_node("report", deterministic_report_node)
    graph.add_edge(START, "discovery")
    graph.add_edge("discovery", "broad_scan")
    graph.add_edge("broad_scan", "parameter_scan")
    graph.add_edge("parameter_scan", "authorization")
    graph.add_edge("authorization", "browser_workflow")
    graph.add_edge("browser_workflow", "special_checks")
    graph.add_edge("special_checks", "report")
    graph.add_edge("report", END)
    return graph.compile()


# Parses command-line options and drives the complete workflow for this entrypoint.
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic LangGraph + FastMCP web-security orchestrator."
    )
    add_common_cli_arguments(parser, require_target=False)
    parser.add_argument("--list-tools", action="store_true")
    parser.add_argument(
        "--tool",
        choices=SINGLE_TOOL_CHOICES,
        help="Run exactly one scanner for isolated debugging.",
    )
    parser.add_argument(
        "--tool-url", default="",
        help="Explicit same-origin URL for the selected single tool."
    )
    parser.add_argument(
        "--tool-timeout", type=int, default=0,
        help="Override the selected scanner timeout in seconds."
    )
    parser.add_argument("--method", choices=("GET", "POST"), default="GET")
    parser.add_argument(
        "--data", default="",
        help="POST form body for a single parameter tool."
    )
    parser.add_argument(
        "--parameters",
        default="",
        help="Comma-separated parameters for a single parameter tool.",
    )
    parser.add_argument("--jwt-token", default="", help="JWT value for --tool jwt.")
    parser.add_argument(
        "--diagnostic-only",
        action="store_true",
        help="For --tool zap, validate session/proxy without scanning.",
    )
    args = parser.parse_args()

    if args.list_tools:
        print("Canonical SecOps MCP tools:")
        for spec in ALL_TOOLS:
            if spec.name != "report":
                print(f"  {spec.name:11} {spec.server}:{spec.tool}")
        return 0
    if not args.target:
        parser.error("--target is required unless --list-tools is used.")
    if args.diagnostic_only and args.tool != "zap":
        parser.error("--diagnostic-only is valid only with --tool zap.")

    configure_scan_mode(args.mode)
    # If required local services fail preflight, the deterministic run stops before scanning begins.
    checks = run_preflight_checks(include_live=True)
    # Single-tool execution bypasses the full graph but keeps normal setup, scope, and preflight checks.
    if args.tool:
        print_preflight_report(checks, show_ok=args.preflight_only)
        selected_errors = _single_tool_preflight_errors(checks, args.tool)
        preflight_errors = len(selected_errors)
        if selected_errors:
            print("\n=== Selected-tool preflight blockers ===", file=sys.stderr)
            for item in selected_errors:
                print(
                    f"[-] {item['component']}: {item['cause']} — {item['detail']}",
                    file=sys.stderr,
                )
    else:
        preflight_errors = print_preflight_report(checks, show_ok=args.preflight_only)

    if args.preflight_only:
        return 0 if not preflight_errors else 3
    if preflight_errors and not args.ignore_preflight_errors:
        return 3

    target, profiles, cookie, secondary_cookie, injection_url = prepare_cli_context(
        parser, args
    )
    if args.tool:
        try:
            result = asyncio.run(
                run_single_tool_debug(
                    tool=args.tool,
                    target=target,
                    cookies=cookie,
                    secondary_cookies=secondary_cookie,
                    mode=args.mode,
                    explicit_url=args.tool_url,
                    method=args.method,
                    data=args.data,
                    parameters=_parse_parameter_argument(args.parameters),
                    jwt_token=args.jwt_token,
                    injection_url=injection_url,
                    timeout_override=args.tool_timeout,
                    diagnostic_only=args.diagnostic_only,
                    allow_state_changes=args.allow_state_changes,
                )
            )
        except (ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        profile_name = "authenticated" if cookie else "anonymous"
        log_result(
            profile_name,
            args.tool,
            result,
            str(result.get("selected_target") or target),
        )
        if args.tool == "zap":
            log_zap_session_diagnostics(result)
        print_security_finding_summary({profile_name: {args.tool: result}})
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return 2 if result.get("status") == "error" else 0

    print("=== FastMCP Deterministic Security Pipeline ===")
    print(f"[*] Target: {target}")
    print(f"[*] Mode: {shared.CURRENT_SCAN_MODE}")
    if shared.CURRENT_SCAN_MODE == 'deep':
        print("[*] Deep profile: coverage-max-20m-v1 (broader request classes, bounded ZAP/Nuclei breadth, 2-way specialist concurrency)")
    print(f"[*] Profiles: {', '.join(profile['name'] for profile in profiles)}")
    started = time.time()
    try:
        final = asyncio.run(
            run_pipeline(
                target,
                profiles,
                injection_url,
                allow_state_changes=args.allow_state_changes,
                secondary_cookies=secondary_cookie,
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Workflow interrupted by the operator.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[-] Workflow failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    report = final["report_status"]
    errors, skips, partial = summarize_results(final["results"])
    print(f"\n=== Completed in {time.time() - started:.2f} seconds ===")
    print_security_finding_summary(final["results"])
    print(f"[+] PDF: {report.get('pdf_filename') or 'not generated'}")
    print(f"[+] HTML preview: {report.get('html_filename') or 'not generated'}")
    print(f"[+] JSON: {report.get('json_filename') or 'not generated'}")
    print(f"[+] Coverage constraints recorded: {report.get('coverage_constraints_count', 0)}")
    print(f"[+] Scanner run errors: {errors}")
    print(f"[+] Time-limited/partial scanner runs: {partial}")
    print(f"[+] Scanner run skips: {skips}")
    return 1 if report.get("status") != "success" else 0

if __name__ == "__main__":
    raise SystemExit(main())
