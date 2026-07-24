from __future__ import annotations

import argparse
import asyncio
import json
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

from orchestratorDeterministic import (
    BROAD_SCANNER_TIMEOUTS,
    PARAMETER_TOOL_TIMEOUTS,
    _tool_case_skip_reason,
    call_mcp,
    diagnose_error,
    discover_target,
    enrich_discovery_with_arjun,
    enrich_discovery_with_ffuf,
    merge_discovery,
    select_arjun_candidates,
    iter_leaf_results,
    log_result,
    print_preflight_report,
    run_preflight_checks,
    select_request_cases,
    select_tool_request_cases,
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


REGISTRY = {
    "zap": ("zapServer.py", "run_zap_scan", "base", "Broad spider and active scan."),
    "nuclei": ("nucleiServer.py", "run_nuclei_scan", "base", "Known exposures and misconfigurations."),
    "nikto": ("niktoServer.py", "run_nikto_scan", "base", "Web-server checks."),
    "ffuf": ("ffufServer.py", "run_ffuf_fuzz", "base", "Hidden resource discovery."),
    "arjun": ("arjunServer.py", "run_arjun_scan", "url", "Hidden GET parameter discovery."),
    "sqlmap": ("sqlmapServer.py", "run_sqlmap_scan", "parameterized", "SQL injection testing."),
    "dalfox": ("dalfoxServer.py", "run_dalfox_scan", "parameterized", "XSS testing."),
    "commix": ("commixServer.py", "run_commix_scan", "parameterized", "Command injection testing."),
    "idor": ("idorForgeServer.py", "run_idor_check", "numeric", "Numeric IDOR differential check."),
    "jwt": ("jwtServer.py", "run_jwt_scan", "jwt", "JWT analysis."),
    "interactsh": ("interactshServer.py", "run_interactsh_client", "oast", "Explicit OAST test."),
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
                    "reason": {"type": "string"},
                },
                "required": ["profile", "tool", "target_url", "jwt_token", "injection_url", "reason"],
            },
        },
        "finish": {"type": "boolean"},
    },
    "required": ["reasoning_summary", "actions", "finish"],
}


def action_id(action: dict[str, Any]) -> str:
    return "|".join(str(action.get(key, "")) for key in ("profile", "tool", "target_url", "method", "data", "jwt_token", "injection_url"))


def ollama_plan(state: AgentState) -> dict[str, Any]:
    registry = {name: {"scope": values[2], "description": values[3]} for name, values in REGISTRY.items()}
    prompt = {
        "target": state["target"],
        "round": state["round"] + 1,
        "maximum_rounds": state["max_rounds"],
        "profiles": [profile["name"] for profile in state["profiles"]],
        "registry": registry,
        "discovery": state["discovery"],
        "previous_results": compact_results(state["results"]),
        "already_completed": state["completed"],
        "configured_oast_url": state["injection_url"],
    }
    response = requests.post(
        f"{state['ollama_url'].rstrip('/')}/api/chat",
        json={
            "model": state["model"], "stream": False, "format": PLAN_SCHEMA,
            "messages": [
                {"role": "system", "content": (
                    "Plan an explicitly authorized web-security assessment. Use only the supplied registry, "
                    "same-profile discovered URLs, GET/POST request cases and JWTs. Use parameter tools only on discovered request cases, "
                    "IDOR only on numeric values, and Interactsh only when configured. Avoid duplicates. "
                    "A scanner error never means the target is clean. A configured time limit is a partial result, not an error. Prioritize high-impact checks and risk-ranked request cases. Return only schema-valid JSON."
                )},
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
            ],
            "options": {"temperature": 0},
        },
        timeout=(5, 180),
    )
    response.raise_for_status()
    content = response.json().get("message", {}).get("content", "")
    value = json.loads(content)
    if not isinstance(value, dict) or not isinstance(value.get("actions", []), list):
        raise ValueError("Ollama returned an invalid plan.")
    return value


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


def fallback_plan(state: AgentState) -> list[dict[str, Any]]:
    """Guarantee baseline coverage while keeping parameter tools discovery-driven."""
    actions: list[dict[str, Any]] = []
    for profile in state["profiles"]:
        name = profile["name"]
        for tool in ("ffuf", "zap", "nuclei", "nikto"):
            actions.append({"profile": name, "tool": tool, "target_url": state["target"], "jwt_token": "", "injection_url": "", "reason": "Mandatory baseline coverage."})
        for endpoint in select_arjun_candidates(state["discovery"].get(name, {}), state["target"]):
            actions.append({"profile": name, "tool": "arjun", "target_url": endpoint, "jwt_token": "", "injection_url": "", "reason": "Hidden-parameter discovery on a crawled HTML/form endpoint."})
        for tool in ("sqlmap", "dalfox", "commix", "idor"):
            for case in select_tool_request_cases(state["discovery"].get(name, {}), tool):
                actions.append({
                    "profile": name, "tool": tool, "target_url": case["url"],
                    "method": case.get("method", "GET"), "data": case.get("data", ""),
                    "parameters": case.get("parameters", []),
                    "jwt_token": "", "injection_url": "",
                    "reason": f"Risk-ranked request case suited to {tool}.",
                })
        tokens = state["discovery"].get(name, {}).get("jwt_tokens", [])
        if tokens:
            actions.append({"profile": name, "tool": "jwt", "target_url": state["target"], "jwt_token": tokens[0], "injection_url": "", "reason": "Discovered JWT."})
        if state["injection_url"]:
            actions.append({"profile": name, "tool": "interactsh", "target_url": state["target"], "jwt_token": "", "injection_url": state["injection_url"], "reason": "Configured OAST URL."})
    return actions


def validate_plan(state: AgentState, proposed: Any) -> list[dict[str, Any]]:
    if not isinstance(proposed, list):
        return []
    profiles = {profile["name"] for profile in state["profiles"]}
    completed, valid = set(state["completed"]), []
    for raw in proposed[:30]:
        if not isinstance(raw, dict):
            continue
        profile, tool = str(raw.get("profile", "")), str(raw.get("tool", "")).lower()
        if profile not in profiles or tool not in REGISTRY:
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
            allowed = set(select_arjun_candidates(found, state["target"], limit=10))
            if target_url not in allowed:
                continue
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
            if not state["injection_url"]:
                continue
            target_url, injection = state["target"], state["injection_url"]
        action = {
            "profile": profile, "tool": tool, "target_url": target_url,
            "method": method or "GET", "data": data, "parameters": parameters,
            "jwt_token": token, "injection_url": injection,
            "reason": str(raw.get("reason", ""))[:500] or "No planner reason supplied.",
        }
        identifier = action_id(action)
        if identifier not in completed and all(action_id(item) != identifier for item in valid):
            valid.append(action)
    return valid


def planner_node(state: AgentState) -> dict[str, Any]:
    round_number = state["round"] + 1
    notes = list(state["notes"])
    try:
        decision = ollama_plan(state)
        proposed = decision.get("actions", [])
        if round_number == 1:
            proposed = [*fallback_plan(state), *proposed]
        plan = validate_plan(state, proposed)
        summary = str(decision.get("reasoning_summary", ""))[:1000]
        finished = bool(decision.get("finish", False))
        notes.append(f"Round {round_number}: {summary}")
        print(f"\n[*] Ollama plan round {round_number}: {summary}")
    except Exception as exc:
        plan = validate_plan(state, fallback_plan(state))
        finished = False
        message = f"Ollama unavailable; deterministic fallback used: {type(exc).__name__}: {exc}"
        notes.append(message)
        print(f"\n[!] {message}", file=sys.stderr)
    if not plan and round_number == 1:
        plan = validate_plan(state, fallback_plan(state))
    if not plan:
        finished = True
    print(f"[*] Validated actions: {len(plan)}")
    for action in plan:
        print(f"    {action['profile']:13} {action['tool']:10} {action['target_url']} — {action['reason']}")
    return {"plan": plan, "round": round_number, "notes": notes, "finished": finished}


async def execute_action(action: dict[str, Any], cookies: dict[str, str], discovery: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    server, function = REGISTRY[action["tool"]][:2]
    if action["tool"] == "jwt":
        arguments = {"jwt_token": action["jwt_token"], "target_url": action["target_url"]}
    elif action["tool"] == "interactsh":
        arguments = {"target_url": action["target_url"], "injection_url": action["injection_url"], "cookies": cookies.get(action["profile"], "")}
    else:
        arguments = {"target_url": action["target_url"], "cookies": cookies.get(action["profile"], "")}
        if action["tool"] in BROAD_SCANNER_TIMEOUTS:
            arguments["timeout"] = BROAD_SCANNER_TIMEOUTS[action["tool"]]
            if action["tool"] == "zap":
                profile_discovery = discovery.get(action["profile"], {})
                arguments.update({
                    "seed_urls": profile_discovery.get("html_urls", []),
                    "request_cases": profile_discovery.get("request_cases", []),
                })
        elif action["tool"] == "arjun":
            arguments["timeout"] = 120
        elif action["tool"] in PARAMETER_TOOL_TIMEOUTS:
            arguments["timeout"] = PARAMETER_TOOL_TIMEOUTS[action["tool"]]
        if action["tool"] in {"sqlmap", "dalfox", "commix"}:
            arguments.update({
                "method": action.get("method", "GET"),
                "data": action.get("data", ""),
                "parameters": action.get("parameters", []),
            })
    try:
        scanner_limit = float(arguments.get("timeout", 180))
        return action, await call_mcp(
            server,
            function,
            arguments,
            timeout_seconds=scanner_limit + 35,
        )
    except Exception as exc:
        message = f"Agent executor failed: {type(exc).__name__}: {exc}"
        return action, {"tool": action["tool"], "status": "error", "target": action["target_url"], "output": message, "vulnerabilities": [], "diagnosis": diagnose_error(message), "traceback": traceback.format_exc()}


async def execute_plan(plan: list[dict[str, Any]], cookies: dict[str, str], discovery: dict[str, dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    semaphore, zap_lock = asyncio.Semaphore(3), asyncio.Lock()
    async def limited(action: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        async with semaphore:
            if action["tool"] == "zap":
                async with zap_lock:
                    return await execute_action(action, cookies, discovery)
            return await execute_action(action, cookies, discovery)
    return await asyncio.gather(*(limited(action) for action in plan))


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
    update: dict[str, Any] = {"results": results, "discovery": discovery, "completed": completed}
    if new_attack_surface and state["round"] < state["max_rounds"]:
        update["finished"] = False
    return update


def route_after_execution(state: AgentState) -> Literal["planner", "report"]:
    return "report" if state["finished"] or state["round"] >= state["max_rounds"] or not state["plan"] else "planner"


def report_node(state: AgentState) -> dict[str, Any]:
    print("\n[*] Creating final PDF, HTML preview and JSON report...")
    output_name = f"SecOps_Agentic_Assessment_{datetime.now():%Y%m%d_%H%M%S}"
    context = {
        "profiles": [{"name": profile["name"], "authenticated": bool(profile["cookies"])} for profile in state["profiles"]],
        "expected_tools": list(REGISTRY),
        "discovery": state["discovery"],
        "diagnostics": state["diagnostics"],
        "planner_notes": state["notes"],
        "planner_rounds": state["round"],
    }
    report = asyncio.run(call_mcp("pwndocServer.py", "generate_report", {
        "findings_summary": state["results"], "target_url": state["target"],
        "output_name": output_name, "assessment_context": context,
    }))
    if report.get("status") != "success" and not report.get("json_filename"):
        fallback = write_emergency_json_report(state["target"], state["results"], state["diagnostics"], str(report.get("output", "Report MCP failed.")), "SecOps_Agentic_Emergency")
        if fallback:
            report.update(json_filename=fallback, html_filename=str(Path(fallback).with_suffix(".html")), local_json_fallback=True)
    return {"report_status": report}


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
    parser.add_argument("--max-rounds", type=int, default=2, choices=(1, 2, 3))
    args = parser.parse_args()

    checks = run_preflight_checks(include_live=True)
    errors = print_preflight_report(checks, show_ok=args.preflight_only)
    if args.preflight_only:
        return 0 if not errors else 3
    if errors and not args.ignore_preflight_errors:
        return 3

    target = normalize_url(args.target)
    if urlparse(target).hostname not in {"127.0.0.1", "localhost", "dvwa"} and not args.authorized:
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

    initial: AgentState = {
        "target": target, "profiles": profiles, "discovery": {}, "plan": [], "completed": [],
        "results": {profile["name"]: {} for profile in profiles}, "round": 0,
        "max_rounds": args.max_rounds, "ollama_url": args.ollama_url, "model": args.model,
        "injection_url": injection, "notes": [], "finished": False, "diagnostics": [], "report_status": {},
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
    print(f"[+] Scanner run errors: {errors}\n[+] Time-limited/partial scanner runs: {partial}\n[+] Scanner run skips: {skips}")
    return 1 if report.get("status") != "success" else 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())