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
    AgentState, AI_PLANNER_TIMEOUTS, ensure_ollama_model, warm_ollama_model,
    discovery_node, planner_node, executor_node, report_node, route_after_execution,
    execute_action, execute_plan, validate_plan, ollama_plan,
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


# Falls back to the shared implementation when a public name is not defined locally.
def __getattr__(name: str) -> Any:
    try:
        return getattr(agentic_core, name)
    except AttributeError as exc:
        raise AttributeError(name) from exc


# Builds the LangGraph flow that connects discovery, planning, execution, and reporting.
def build_graph() -> Any:
    graph = StateGraph(AgentState)
    graph.add_node("discovery", discovery_node)
    graph.add_node("planner", planner_node)
    graph.add_node("executor", executor_node)
    graph.add_node("report", report_node)
    graph.add_edge(START, "discovery")
    graph.add_edge("discovery", "planner")
    graph.add_edge("planner", "executor")
    graph.add_conditional_edges("executor", route_after_execution, {"planner": "planner", "report": "report"})
    graph.add_edge("report", END)
    return graph.compile()


# Counts errors, skips, and partial runs before the final agentic summary is printed.
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

# Parses command-line options and drives the complete workflow for this entrypoint.
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ollama + LangGraph FastMCP security orchestrator."
    )
    add_common_cli_arguments(parser, require_target=True)
    parser.add_argument("--model", default="llama3.1:8b")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument(
        "--no-model-pull",
        action="store_true",
        help="Do not automatically pull a missing requested Ollama model.",
    )
    parser.add_argument(
        "--require-ai",
        action="store_true",
        help="Fail instead of using deterministic fallback when Ollama planning fails.",
    )
    parser.add_argument("--max-rounds", type=int, default=1, choices=(1, 2, 3))
    parser.add_argument(
        "--ai-timeout",
        type=int,
        default=0,
        help="Total planning budget per AI round; 0 selects a mode-specific default.",
    )
    args = parser.parse_args()

    configure_scan_mode(args.mode)
    if args.mode == "deep":
        print("[*] Deep profile: coverage-max-20m-v1 (broader request classes and bounded high-coverage scanner phases)")
    print(f"[*] Runtime platform: {platform.platform()}")
    print(f"[*] MCP server Python: {deterministic_core._server_python()}")
    globals()["CURRENT_SCAN_MODE"] = deterministic_core.CURRENT_SCAN_MODE
    globals()["ARJUN_TIMEOUT"] = deterministic_core.ARJUN_TIMEOUT

    # If preflight finds missing local tools, execution stops before the agentic graph starts.
    checks = run_preflight_checks(include_live=True)
    errors = print_preflight_report(checks, show_ok=args.preflight_only)
    if args.preflight_only:
        return 0 if not errors else 3
    if errors and not args.ignore_preflight_errors:
        return 3

    target, profiles, _, secondary_cookie, injection = (
        prepare_cli_context(parser, args)
    )
    # Before planning begins, Ollama is checked and the requested model is prepared for use.
    planner_timeout = args.ai_timeout or AI_PLANNER_TIMEOUTS[args.mode]
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
        try:
            warmup = warm_ollama_model(
                args.ollama_url, selected_model, timeout=planner_timeout
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
                "[!] Ollama warm-up was inconclusive; the streamed planner will still "
                f"retry both endpoints: {ollama_diagnostics['warmup_error']}",
                file=sys.stderr,
            )
    except Exception as exc:
        if args.require_ai:
            print(
                f"[-] Strict agentic mode could not prepare Ollama: {type(exc).__name__}: {exc}",
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
            "[!] Ollama readiness check failed; deterministic fallback remains available: "
            f"{ollama_diagnostics['error']}",
            file=sys.stderr,
        )

    # The agentic run starts from a fresh state containing profiles, planner settings, and empty results.
    initial: AgentState = {
        "target": target,
        "profiles": profiles,
        "discovery": {},
        "plan": [],
        "completed": [],
        "results": {profile["name"]: {} for profile in profiles},
        "round": 0,
        "max_rounds": args.max_rounds,
        "ollama_url": args.ollama_url,
        "model": selected_model,
        "injection_url": injection,
        "notes": [
            "Ollama readiness: "
            + json.dumps(ollama_diagnostics, ensure_ascii=False, default=str)
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
    print(f"[+] Coverage constraints recorded: {report.get('coverage_constraints_count', 0)}")
    print_security_finding_summary(final.get("results", {}))
    print(f"[+] Scanner run errors: {errors}")
    print(f"[+] Time-limited/partial scanner runs: {partial}")
    print(f"[+] Scanner run skips: {skips}")
    return 1 if report.get("status") != "success" else 0

if __name__ == "__main__":
    raise SystemExit(main())
