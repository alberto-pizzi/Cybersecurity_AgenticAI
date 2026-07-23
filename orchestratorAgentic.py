from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, TypedDict
from urllib.parse import parse_qsl, urlparse

import requests
from langgraph.graph import END, START, StateGraph

from orchestratorDeterministic import (
    call_mcp,
    diagnose_error,
    discover_target,
    enrich_discovery_with_arjun,
    enrich_discovery_with_ffuf,
    iter_leaf_results,
    log_result,
    print_preflight_report,
    run_preflight_checks,
    select_parameterized_urls,
    write_emergency_json_report,
)
from utils import normalize_url, same_origin


class AgentState(TypedDict):
    target: str
    profiles: list[dict[str, str]]
    discovery: dict[str, dict[str, Any]]
    plan: list[dict[str, Any]]
    completed_actions: list[str]
    results: dict[str, dict[str, Any]]
    round_number: int
    max_rounds: int
    ollama_url: str
    model: str
    interactsh_injection_url: str
    planner_notes: list[str]
    planner_finished: bool
    diagnostics: list[dict[str, Any]]
    report_status: dict[str, Any]


TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "zap": {
        "server": "zapServer.py",
        "tool": "run_zap_scan",
        "scope": "base",
        "description": "Broad spider and active web scan.",
    },
    "nuclei": {
        "server": "nucleiServer.py",
        "tool": "run_nuclei_scan",
        "scope": "base",
        "description": "Known exposures and misconfiguration templates.",
    },
    "nikto": {
        "server": "niktoServer.py",
        "tool": "run_nikto_scan",
        "scope": "base",
        "description": "Web-server configuration and dangerous-file checks.",
    },
    "ffuf": {
        "server": "ffufServer.py",
        "tool": "run_ffuf_fuzz",
        "scope": "base",
        "description": "Hidden path and file discovery.",
    },
    "arjun": {
        "server": "arjunServer.py",
        "tool": "run_arjun_scan",
        "scope": "url",
        "description": "Hidden GET parameter discovery.",
    },
    "sqlmap": {
        "server": "sqlmapServer.py",
        "tool": "run_sqlmap_scan",
        "scope": "parameterized",
        "description": "SQL injection testing on parameterized URLs.",
    },
    "dalfox": {
        "server": "dalfoxServer.py",
        "tool": "run_dalfox_scan",
        "scope": "parameterized",
        "description": "Reflected XSS testing on parameterized URLs.",
    },
    "commix": {
        "server": "commixServer.py",
        "tool": "run_commix_scan",
        "scope": "parameterized",
        "description": "Command-injection testing on parameterized URLs.",
    },
    "idor": {
        "server": "idorForgeServer.py",
        "tool": "run_idor_check",
        "scope": "numeric",
        "description": "Heuristic differential check on numeric identifiers.",
    },
    "jwt": {
        "server": "jwtServer.py",
        "tool": "run_jwt_scan",
        "scope": "jwt",
        "description": "JWT analysis for tokens discovered in the target.",
    },
    "interactsh": {
        "server": "interactshServer.py",
        "tool": "run_interactsh_client",
        "scope": "oast",
        "description": "OAST execution only when an explicit same-origin injection URL is supplied.",
    },
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
                    "reason": {"type": "string"},
                },
                "required": ["profile", "tool", "target_url", "jwt_token", "reason"],
            },
        },
        "finish": {"type": "boolean"},
    },
    "required": ["reasoning_summary", "actions", "finish"],
}


def action_id(action: dict[str, Any]) -> str:
    return "|".join([
        str(action.get("profile", "")),
        str(action.get("tool", "")),
        str(action.get("target_url", "")),
        str(action.get("jwt_token", ""))[:30],
        str(action.get("injection_url", "")),
    ])


def ollama_json(
    ollama_url: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    timeout: int = 180,
) -> dict[str, Any]:
    """Call Ollama and validate that the response contains a JSON planning object."""
    response = requests.post(
        f"{ollama_url.rstrip('/')}/api/chat",
        json={
            "model": model,
            "stream": False,
            "format": PLAN_SCHEMA,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "options": {"temperature": 0},
        },
        timeout=(5, timeout),
    )
    response.raise_for_status()
    payload = response.json()
    content = payload.get("message", {}).get("content", "")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Ollama returned an empty planning response.")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Ollama returned invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("Ollama returned a non-object plan.")
    if not isinstance(parsed.get("actions", []), list):
        raise ValueError("Ollama plan field 'actions' must be a list.")
    return parsed


def discovery_node(state: AgentState) -> dict[str, Any]:
    print("\n[*] Discovery of anonymous and authenticated surfaces")
    discovery: dict[str, dict[str, Any]] = {}
    diagnostics = list(state.get("diagnostics", []))
    for profile in state["profiles"]:
        name = profile["name"]
        found = discover_target(state["target"], profile["cookies"], max_pages=30)
        discovery[name] = found
        for error in found.get("errors", []):
            diagnostics.append({"phase": "discovery", "profile": name, **error})
        print(
            f"    {name}: {len(found['urls'])} pages, "
            f"{len(found['parameterized_urls'])} parameterized URLs, "
            f"{len(found['jwt_tokens'])} JWTs, {len(found.get('errors', []))} crawl errors"
        )
    return {"discovery": discovery, "diagnostics": diagnostics}


def compact_results(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for profile, profile_results in results.items():
        compact[profile] = {}
        for key, result in profile_results.items():
            if isinstance(result, dict):
                compact[profile][key] = {
                    "status": result.get("status"),
                    "target": result.get("target"),
                    "findings": len(result.get("vulnerabilities") or []),
                    "diagnosis": result.get("diagnosis"),
                    "output": str(result.get("output", ""))[:350],
                }
    return compact


def fallback_plan(state: AgentState) -> list[dict[str, Any]]:
    """Fair deterministic fallback: broad coverage for every profile, then parameters."""
    actions: list[dict[str, Any]] = []
    profiles = state["profiles"]

    for tool in ("nuclei", "nikto", "ffuf", "arjun", "zap"):
        for profile in profiles:
            actions.append({
                "profile": profile["name"],
                "tool": tool,
                "target_url": state["target"],
                "jwt_token": "",
                "reason": "Deterministic broad fallback coverage.",
            })

    selected_by_profile = {
        profile["name"]: select_parameterized_urls(
            state["discovery"].get(profile["name"], {}).get("parameterized_urls", []),
            limit=3,
        )
        for profile in profiles
    }
    for index in range(3):
        for profile in profiles:
            profile_name = profile["name"]
            urls = selected_by_profile[profile_name]
            if index >= len(urls):
                continue
            url = urls[index]
            for tool in ("sqlmap", "dalfox", "commix", "idor"):
                actions.append({
                    "profile": profile_name,
                    "tool": tool,
                    "target_url": url,
                    "jwt_token": "",
                    "reason": "Deterministic parameter-testing fallback.",
                })

    for profile in profiles:
        profile_name = profile["name"]
        tokens = state["discovery"].get(profile_name, {}).get("jwt_tokens", [])
        if tokens:
            actions.append({
                "profile": profile_name,
                "tool": "jwt",
                "target_url": state["target"],
                "jwt_token": tokens[0],
                "injection_url": "",
                "reason": "JWT discovered during crawling.",
            })
        if state.get("interactsh_injection_url", ""):
            actions.append({
                "profile": profile_name,
                "tool": "interactsh",
                "target_url": state["target"],
                "jwt_token": "",
                "injection_url": state["interactsh_injection_url"],
                "reason": "Explicit OAST injection URL supplied by the operator.",
            })
    return actions


def validate_plan(state: AgentState, proposed: Any) -> list[dict[str, Any]]:
    """Restrict model actions to registered tools and URLs discovered in that profile."""
    if not isinstance(proposed, list):
        return []
    profiles = {profile["name"] for profile in state["profiles"]}
    completed = set(state["completed_actions"])
    valid: list[dict[str, Any]] = []

    for raw in proposed[:20]:
        if not isinstance(raw, dict):
            continue
        profile = str(raw.get("profile", ""))
        tool = str(raw.get("tool", "")).lower()
        target_url = str(raw.get("target_url", "")).strip()
        jwt_token = str(raw.get("jwt_token", "")).strip()
        injection_url = str(raw.get("injection_url", "")).strip()
        reason = str(raw.get("reason", ""))[:500]
        if profile not in profiles or tool not in TOOL_REGISTRY:
            continue

        found = state["discovery"].get(profile, {})
        allowed_urls = {state["target"], *(found.get("urls") or [])}
        parameterized = set(found.get("parameterized_urls") or [])
        allowed_tokens = set(found.get("jwt_tokens") or [])
        scope = TOOL_REGISTRY[tool]["scope"]

        if scope == "base":
            target_url = state["target"]
        elif scope == "url":
            if target_url not in allowed_urls:
                target_url = state["target"]
        elif scope in {"parameterized", "numeric"}:
            if target_url not in parameterized:
                continue
            if scope == "numeric" and not any(
                value.isdigit()
                for _, value in parse_qsl(urlparse(target_url).query, keep_blank_values=True)
            ):
                continue
        elif scope == "jwt":
            if jwt_token not in allowed_tokens:
                continue
            target_url = state["target"]
        elif scope == "oast":
            configured_url = state.get("interactsh_injection_url", "").strip()
            if not configured_url:
                continue
            injection_url = configured_url
            target_url = state["target"]

        action = {
            "profile": profile,
            "tool": tool,
            "target_url": target_url,
            "jwt_token": jwt_token,
            "injection_url": injection_url,
            "reason": reason or "No planner reason supplied.",
        }
        identifier = action_id(action)
        if identifier in completed or any(action_id(existing) == identifier for existing in valid):
            continue
        valid.append(action)
    return valid


def planner_node(state: AgentState) -> dict[str, Any]:
    round_number = state["round_number"] + 1
    registry_summary = {
        name: {"scope": data["scope"], "description": data["description"]}
        for name, data in TOOL_REGISTRY.items()
    }
    system_prompt = """
You are a conservative scanner planner for an explicitly authorized web target.
Choose only tools in the supplied registry and only URLs or JWTs found by the same
access profile during discovery. Prefer broad coverage in round one. Use parameter
scanners only on parameterized URLs, numeric IDOR checks only on numeric values, and
Interactsh only when a configured OAST injection URL is present. Avoid duplicates, and
never interpret a failed scanner as a clean target. Return only JSON
matching the supplied schema.
""".strip()
    user_prompt = json.dumps({
        "target": state["target"],
        "round": round_number,
        "maximum_rounds": state["max_rounds"],
        "profiles": [profile["name"] for profile in state["profiles"]],
        "tool_registry": registry_summary,
        "discovery": state["discovery"],
        "previous_results": compact_results(state["results"]),
        "already_completed": state["completed_actions"],
        "configured_oast_injection_url": state.get("interactsh_injection_url", ""),
        "maximum_new_actions": 20,
    }, ensure_ascii=False)

    notes = list(state["planner_notes"])
    planner_finished = False
    try:
        decision = ollama_json(state["ollama_url"], state["model"], system_prompt, user_prompt)
        plan = validate_plan(state, decision.get("actions", []))
        summary = str(decision.get("reasoning_summary", ""))[:1000]
        planner_finished = bool(decision.get("finish", False))
        notes.append(f"Round {round_number}: {summary}")
        print(f"\n[*] Ollama plan round {round_number}: {summary}")
    except Exception as exc:
        plan = validate_plan(state, fallback_plan(state))
        message = f"Ollama planner unavailable; deterministic fallback used: {type(exc).__name__}: {exc}"
        notes.append(message)
        print(f"\n[!] {message}", file=sys.stderr)

    if not plan and round_number == 1:
        plan = validate_plan(state, fallback_plan(state))
    if not plan:
        planner_finished = True

    print(f"[*] Validated actions: {len(plan)}")
    for action in plan:
        print(
            f"    {action['profile']:13} {action['tool']:8} "
            f"{action['target_url']} — {action['reason']}"
        )
    return {
        "plan": plan,
        "round_number": round_number,
        "planner_notes": notes,
        "planner_finished": planner_finished,
    }


async def execute_action(
    action: dict[str, Any],
    profile_cookies: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        specification = TOOL_REGISTRY[action["tool"]]
        if action["tool"] == "jwt":
            arguments = {
                "jwt_token": action["jwt_token"],
                "target_url": action["target_url"],
            }
        elif action["tool"] == "interactsh":
            arguments = {
                "target_url": action["target_url"],
                "injection_url": action.get("injection_url", ""),
                "cookies": profile_cookies.get(action["profile"], ""),
            }
        else:
            arguments = {
                "target_url": action["target_url"],
                "cookies": profile_cookies.get(action["profile"], ""),
            }
        result = await call_mcp(specification["server"], specification["tool"], arguments)
        return action, result
    except Exception as exc:
        message = f"Agent executor failed before/during MCP call: {type(exc).__name__}: {exc}"
        return action, {
            "tool": action.get("tool", "unknown"),
            "status": "error",
            "target": action.get("target_url", ""),
            "output": message,
            "vulnerabilities": [],
            "diagnosis": diagnose_error(message),
            "traceback": traceback.format_exc(),
        }


async def execute_plan(
    plan: list[dict[str, Any]],
    profile_cookies: dict[str, str],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    semaphore = asyncio.Semaphore(3)
    zap_lock = asyncio.Lock()

    async def limited(action: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        async with semaphore:
            # One shared ZAP daemon cannot safely reset sessions for two profiles at once.
            if action.get("tool") == "zap":
                async with zap_lock:
                    return await execute_action(action, profile_cookies)
            return await execute_action(action, profile_cookies)

    return await asyncio.gather(*(limited(action) for action in plan))


def executor_node(state: AgentState) -> dict[str, Any]:
    if not state["plan"]:
        return {}
    profile_cookies = {profile["name"]: profile["cookies"] for profile in state["profiles"]}
    executed = asyncio.run(execute_plan(state["plan"], profile_cookies))
    results = {profile: dict(values) for profile, values in state["results"].items()}
    discovery = {profile: dict(values) for profile, values in state["discovery"].items()}
    completed = list(state["completed_actions"])
    arjun_added_urls = 0

    for action, result in executed:
        profile = action["profile"]
        tool = action["tool"]
        profile_results = results.setdefault(profile, {})
        index = sum(1 for key in profile_results if key.startswith(f"{tool}:"))
        profile_results[f"{tool}:{index + 1}"] = {
            **result,
            "planner_reason": action["reason"],
            "planner_round": state["round_number"],
        }
        completed.append(action_id(action))
        log_result(profile, tool, result, action["target_url"])

        if tool == "ffuf":
            current = discovery.get(profile, {})
            enriched, generated_resources = enrich_discovery_with_ffuf(
                current, result, state["target"]
            )
            discovery[profile] = enriched
            if generated_resources:
                print(f"    [INFO   ] ffuf added {len(generated_resources)} resources for {profile}")

        if tool == "arjun":
            current = discovery.get(profile, {})
            enriched, generated = enrich_discovery_with_arjun(current, result, action["target_url"])
            discovery[profile] = enriched
            arjun_added_urls += len(generated)
            if generated:
                print(f"    [INFO   ] arjun added {len(generated)} parameterized URLs for {profile}")

    update: dict[str, Any] = {
        "results": results,
        "discovery": discovery,
        "completed_actions": completed,
    }
    if arjun_added_urls and state["round_number"] < state["max_rounds"]:
        # Give the planner another round so SQLMap/Dalfox/Commix can consume Arjun output.
        update["planner_finished"] = False
    return update


def route_after_execution(state: AgentState) -> Literal["planner", "report"]:
    if state.get("planner_finished", False):
        return "report"
    if state["round_number"] >= state["max_rounds"] or not state["plan"]:
        return "report"
    return "planner"


def report_node(state: AgentState) -> dict[str, Any]:
    print("\n[*] Creating final PDF, HTML preview and JSON report through MCP...")
    output_name = f"SecOps_Agentic_Assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    report = asyncio.run(call_mcp(
        "pwndocServer.py",
        "generate_report",
        {
            "findings_summary": state["results"],
            "target_url": state["target"],
            "output_name": output_name,
        },
    ))
    if report.get("status") != "success" and not report.get("json_filename"):
        fallback_path = write_emergency_json_report(
            state["target"],
            state["results"],
            state.get("diagnostics", []),
            str(report.get("output", "PwnDoc MCP report failed.")),
            output_name="SecOps_Agentic_Emergency",
        )
        if fallback_path:
            report["json_filename"] = fallback_path
            preview_path = str(Path(fallback_path).with_suffix(".html"))
            if Path(preview_path).is_file():
                report["html_filename"] = preview_path
            report["local_json_fallback"] = True
    return {"report_status": report}


def build_graph() -> Any:
    graph = StateGraph(AgentState)
    graph.add_node("discovery", discovery_node)
    graph.add_node("planner", planner_node)
    graph.add_node("executor", executor_node)
    graph.add_node("report", report_node)
    graph.add_edge(START, "discovery")
    graph.add_edge("discovery", "planner")
    graph.add_edge("planner", "executor")
    graph.add_conditional_edges(
        "executor",
        route_after_execution,
        {"planner": "planner", "report": "report"},
    )
    graph.add_edge("report", END)
    return graph.compile()


def summarize_statuses(results: dict[str, Any]) -> tuple[int, int, int]:
    errors = skips = partial = 0
    error_rows: list[tuple[str, str, str]] = []
    for path, result in iter_leaf_results(results):
        status = str(result.get("status", "error")).lower()
        if status == "error":
            errors += 1
            error_rows.append((
                "/".join(path),
                str(result.get("diagnosis", "unknown")),
                str(result.get("output", "")),
            ))
        elif status == "skipped":
            skips += 1
        elif status == "partial":
            partial += 1
    if error_rows:
        print("\n=== Scanner error details ===", file=sys.stderr)
        for path, cause, output in error_rows:
            print(f"[-] {path}: {cause} — {output[:500]}", file=sys.stderr)
    return errors, skips, partial


def main() -> int:
    parser = argparse.ArgumentParser(description="Ollama + LangGraph FastMCP security orchestrator.")
    parser.add_argument("--target", required=True, help="Authorized HTTP/HTTPS target.")
    parser.add_argument("--cookies", default="", help="Authenticated session cookie string.")
    parser.add_argument("--auth-only", action="store_true")
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument(
        "--interactsh-injection-url",
        default="",
        help="Optional same-origin URL accepted by interactshServer.py; use a FUZZ placeholder when supported.",
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--model", default="llama3.1:8b")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--max-rounds", type=int, default=2, choices=(1, 2, 3))
    args = parser.parse_args()

    preflight_checks = run_preflight_checks()
    preflight_errors = print_preflight_report(preflight_checks, show_ok=args.preflight_only)
    if args.preflight_only:
        return 0 if preflight_errors == 0 else 3

    target = normalize_url(args.target)
    if urlparse(target).hostname not in {"127.0.0.1", "localhost", "dvwa"} and not args.authorized:
        parser.error("Remote targets require --authorized.")

    injection_url = args.interactsh_injection_url.strip()
    if injection_url and not same_origin(target, injection_url):
        parser.error("--interactsh-injection-url must have the same origin as --target.")

    profiles: list[dict[str, str]] = []
    if not args.auth_only:
        profiles.append({"name": "anonymous", "cookies": ""})
    if args.cookies:
        profiles.append({"name": "authenticated", "cookies": args.cookies})
    elif args.auth_only:
        parser.error("--auth-only requires --cookies.")

    initial: AgentState = {
        "target": target,
        "profiles": profiles,
        "discovery": {},
        "plan": [],
        "completed_actions": [],
        "results": {profile["name"]: {} for profile in profiles},
        "round_number": 0,
        "max_rounds": args.max_rounds,
        "ollama_url": args.ollama_url,
        "model": args.model,
        "interactsh_injection_url": injection_url,
        "planner_notes": [],
        "planner_finished": False,
        "diagnostics": [],
        "report_status": {},
    }

    print("=== Ollama + LangGraph FastMCP Security Agent ===")
    print(f"[*] Target: {target}")
    print(f"[*] Model: {args.model}")
    print(f"[*] Profiles: {', '.join(profile['name'] for profile in profiles)}")
    started = time.time()

    try:
        final = build_graph().invoke(initial)
    except Exception as exc:
        detail = f"Workflow failed: {type(exc).__name__}: {exc}"
        print(f"[-] {detail}", file=sys.stderr)
        traceback.print_exc()
        emergency = write_emergency_json_report(
            target,
            initial["results"],
            initial["diagnostics"],
            detail,
            output_name="SecOps_Agentic_Crash",
        )
        print(f"[+] JSON: {emergency or 'not generated'}")
        return 1

    report = final.get("report_status", {})
    errors, skips, partial = summarize_statuses(final.get("results", {}))
    print(f"\n=== Completed in {time.time() - started:.2f} seconds ===")
    print(f"[+] Planner rounds: {final.get('round_number', 0)}")
    print(f"[+] PDF: {report.get('pdf_filename') or 'not generated'}")
    print(f"[+] HTML preview: {report.get('html_filename') or 'not generated'}")
    print(f"[+] JSON: {report.get('json_filename') or 'not generated'}")
    print(f"[+] Scanner errors: {errors}")
    print(f"[+] Scanner partial results: {partial}")
    print(f"[+] Scanner skips: {skips}")
    print(f"[+] Discovery diagnostics: {len(final.get('diagnostics', []))}")

    if report.get("status") != "success":
        return 1
    if errors:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())