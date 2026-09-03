from __future__ import annotations

import argparse
import json
import platform
import sys
import time
import traceback
from typing import Any

from langgraph.graph import END, START, StateGraph

import orchestratorDeterministic as deterministic_core
import orchestratorAgenticCore as agentic_core
from orchestratorAgenticCore import (
    AgentState, AI_PLANNER_TIMEOUTS, SNAP4CITY_DEFAULT_API_URL, resolve_ai_model,
    ensure_ollama_model, warm_ollama_model, ensure_snap4city_model,
    discovery_node, planner_node, executor_node, verification_node, analysis_node, report_node, route_after_execution,
    execute_action, execute_plan, validate_plan,
)
from orchestratorShared import (
    BROAD_SCANNER_TIMEOUTS, PARAMETER_TOOL_TIMEOUTS, configure_scan_mode,
    iter_leaf_results, print_preflight_report, print_security_finding_summary,
    run_preflight_checks, select_tool_request_cases, select_browser_request_cases,
    select_workflow_request_cases, select_authorization_request_cases,
    select_oast_request_cases, tool_action_limit, broad_tool_order,
    add_common_cli_arguments, prepare_cli_context,
)

REGISTRY = deterministic_core.agentic_registry()
agentic_core.REGISTRY = REGISTRY


def __getattr__(name: str) -> Any:
    try:
        return getattr(agentic_core, name)
    except AttributeError as exc:
        raise AttributeError(name) from exc

# Autonomous planner: plan without a checklist and avoid redundant tool execution.
# Eligible but unselected actions remain visible as diagnosis="agentic_deferred_by_planner".

def build_graph() -> Any:
    graph = StateGraph(AgentState)
    graph.add_node("discovery", discovery_node)
    graph.add_node("planner", planner_node)
    graph.add_node("executor", executor_node)
    graph.add_node("verification", verification_node)
    graph.add_node("analysis", analysis_node)
    graph.add_node("report", report_node)
    graph.add_edge(START, "discovery")
    graph.add_edge("discovery", "planner")
    graph.add_edge("planner", "executor")
    graph.add_conditional_edges("executor", route_after_execution, {"planner": "planner", "verification": "verification"})
    graph.add_edge("verification", "analysis")
    graph.add_edge("analysis", "report")
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
    parser = argparse.ArgumentParser(
        description="LangGraph FastMCP security orchestrator with selectable AI model."
    )
    add_common_cli_arguments(parser, require_target=True)
    parser.add_argument(
        "--model", choices=("snap4city", "llama", "qwen"), default="snap4city",
        help=(
            "AI used for planning and final finding analysis: snap4city -> remote "
            "llama4-agentic-inference; llama -> local llama3.1:8b via Ollama; "
            "qwen -> local qwen2.5:7b via Ollama. Default: snap4city."
        ),
    )
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--snap4city-api-url", default=SNAP4CITY_DEFAULT_API_URL, help="Snap4City ClearML on-demand API URL.")
    parser.add_argument("--snap4city-credentials", default="user_credentials.json", help="Snap4City credentials JSON. Cached access/refresh tokens are reused first; missing/placeholder credentials are requested interactively only when no usable token remains.")
    parser.add_argument(
        "--no-model-pull",
        action="store_true",
        help="Do not automatically pull a missing requested Ollama model.",
    )
    parser.add_argument(
        "--require-ai",
        action="store_true",
        help="Fail if a required AI planning or analysis stage cannot complete.",
    )
    parser.add_argument("--max-rounds", type=int, default=1, choices=(1, 2, 3))
    parser.add_argument(
        "--only-tool",
        default="",
        choices=("", *sorted(REGISTRY)),
        help="Debug filter: expose only this scanner/tool to the AI planner. Empty keeps the normal autonomous candidate set.",
    )
    parser.add_argument(
        "--ai-timeout",
        type=int,
        default=0,
        help="AI planning budget per round; the analysis stage also derives its bounded per-batch budget from this value. 0 selects mode-specific defaults.",
    )
    args = parser.parse_args()

    configure_scan_mode(args.mode)
    if args.mode == "deep":
        print("[*] Deep profile: coverage-max-20m-v1 (broader request classes and bounded high-coverage scanner phases)")
    print(f"[*] Runtime platform: {platform.platform()}")
    print(f"[*] MCP server Python: {deterministic_core._server_python()}")
    if args.only_tool:
        print(f"[*] Single-tool debug filter: {args.only_tool}")
    globals()["CURRENT_SCAN_MODE"] = deterministic_core.CURRENT_SCAN_MODE
    globals()["ARJUN_TIMEOUT"] = deterministic_core.ARJUN_TIMEOUT

    checks = run_preflight_checks(include_live=True)
    errors = print_preflight_report(checks, show_ok=args.preflight_only)
    if args.preflight_only:
        return 0 if not errors else 3
    if errors and not args.ignore_preflight_errors:
        return 3

    target, profiles, _, secondary_cookie, injection = (
        prepare_cli_context(parser, args)
    )
    planner_timeout = args.ai_timeout or AI_PLANNER_TIMEOUTS[args.mode]
    selected_provider, requested_model, selection_diagnostics = resolve_ai_model(args.model)
    print(
        f"[*] AI selection: provider={selected_provider}; model={requested_model}; "
        f"source={selection_diagnostics.get('selection_source')}"
    )
    try:
        if selected_provider == "snap4city":
            selected_model, ai_diagnostics = ensure_snap4city_model(
                args.snap4city_api_url,
                requested_model,
                args.snap4city_credentials,
                timeout=planner_timeout,
            )
            print(
                f"[*] Snap4City ready: model={selected_model}; "
                f"warm-up={ai_diagnostics.get('warmup_seconds')}s; planner budget={planner_timeout}s per round"
            )
        else:
            selected_model, ai_diagnostics = ensure_ollama_model(
                args.ollama_url,
                requested_model,
                allow_pull=not args.no_model_pull,
            )
            print(
                f"[*] Ollama ready: version={ai_diagnostics.get('ollama_version', 'unknown')}; "
                f"model={selected_model}; requested={requested_model}"
            )
            if ai_diagnostics.get("fallback_model_used"):
                print(
                    "[!] Requested model was unavailable; using installed fallback "
                    f"{selected_model}: {ai_diagnostics.get('fallback_reason', '')}",
                    file=sys.stderr,
                )
            try:
                warmup = warm_ollama_model(
                    args.ollama_url, selected_model, timeout=planner_timeout
                )
                ai_diagnostics["warmup"] = warmup
                print(
                    f"[*] Ollama model warm: {warmup.get('seconds')}s; "
                    f"planner budget={planner_timeout}s per round"
                )
            except Exception as warm_exc:
                ai_diagnostics["warmup_error"] = (
                    f"{type(warm_exc).__name__}: {warm_exc}"
                )
                print(
                    "[!] Ollama warm-up was inconclusive; the streamed planner will still "
                    f"retry both endpoints: {ai_diagnostics['warmup_error']}",
                    file=sys.stderr,
                )
    except Exception as exc:
        if args.require_ai:
            print(
                f"[-] Strict agentic mode could not prepare {selected_provider}: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return 4
        selected_model = requested_model
        ai_diagnostics = {
            "provider": selected_provider,
            "model_ready": False,
            "requested_model": requested_model,
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(
            f"[!] {selected_provider} readiness check failed; deterministic fallback remains available: "
            f"{ai_diagnostics['error']}",
            file=sys.stderr,
        )

    ai_diagnostics['selection'] = selection_diagnostics
    initial: AgentState = {
        "target": target,
        "profiles": profiles,
        "discovery": {},
        "plan": [],
        "completed": [],
        "results": {profile["name"]: {} for profile in profiles},
        "round": 0,
        "max_rounds": args.max_rounds,
        "ai_provider": selected_provider,
        "ollama_url": args.ollama_url,
        "snap4city_api_url": args.snap4city_api_url,
        "snap4city_credentials": args.snap4city_credentials,
        "model": selected_model,
        "injection_url": injection,
        "notes": [
            "AI readiness: "
            + json.dumps(ai_diagnostics, ensure_ascii=False, default=str)
        ],
        "finished": False,
        "diagnostics": [],
        "report_status": {},
        "require_ai": args.require_ai,
        "planner_source": "pending",
        "ai_timeout": planner_timeout,
        "allow_state_changes": args.allow_state_changes,
        "secondary_cookies": secondary_cookie,
        "planner_audit": [],
        "analysis": {},
        "verification_done": False,
        "only_tool": args.only_tool,
    }
    started = time.time()
    try:
        final = build_graph().invoke(initial)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(
            f"[-] Agentic workflow failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        traceback.print_exc()
        return 1

    report = final.get("report_status", {})
    errors, skips, partial = deterministic_core.summarize_results(
        final.get("results", {})
    )
    print(f"\n=== Agentic pipeline completed in {time.time() - started:.2f} seconds ===")
    print(f"[+] PDF: {report.get('pdf_filename') or 'not generated'}")
    print(f"[+] HTML preview: {report.get('html_filename') or 'not generated'}")
    print(f"[+] JSON: {report.get('json_filename') or 'not generated'}")
    print(f"[+] Review snapshot: {report.get('review_snapshot_filename') or 'not generated'}")
    print(f"[+] Coverage constraints recorded: {report.get('coverage_constraints_count', 0)}")
    print_security_finding_summary(final.get("results", {}))
    print(f"[+] Scanner run errors: {errors}")
    print(f"[+] Time-limited/partial scanner runs: {partial}")
    print(f"[+] Scanner run skips: {skips}")
    return 1 if report.get("status") != "success" else 0

if __name__ == "__main__":
    raise SystemExit(main())
