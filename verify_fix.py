from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path


def parameters(path: Path, function_name: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
            return {argument.arg for argument in node.args.args}
    return set()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    args = parser.parse_args()

    root = Path(args.project_root).resolve()
    servers = root / "servers"
    deterministic = (root / "orchestratorDeterministic.py").read_text(encoding="utf-8", errors="replace")
    agentic = (root / "orchestratorAgentic.py").read_text(encoding="utf-8", errors="replace")
    init = (root / "initScript.py").read_text(encoding="utf-8", errors="replace")
    utils = (root / "utils.py").read_text(encoding="utf-8", errors="replace")
    zap = (servers / "zapServer.py").read_text(encoding="utf-8", errors="replace")
    nuclei = (servers / "nucleiServer.py").read_text(encoding="utf-8", errors="replace")
    sqlmap = (servers / "sqlmapServer.py").read_text(encoding="utf-8", errors="replace")
    commix = (servers / "commixServer.py").read_text(encoding="utf-8", errors="replace")

    common = re.search(r"common\s*=\s*\{.*?\n\s*\}", nuclei, re.S)
    common_text = common.group(0) if common else ""
    numbered = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*.py")
        if re.search(r"\(\d+\)\.py$", path.name, re.I)
    )

    checks = {
        "canonical_files_only": not numbered,
        "official_zaproxy_package": (
            '"zaproxy>=0.5,<0.6"' in init
            and "python-owasp-zap-v2.4>=0.1.0" not in init
        ),
        "legacy_zap_package_uninstalled": "pip\", \"uninstall\", \"-y\", \"python-owasp-zap-v2.4\"" in init,
        "zap_container_recreated": 'docker", "rm", "-f", "zap_mcp"' in init,
        "cookie_canonicalization_present": all(
            marker in utils
            for marker in (
                "def parse_cookie_header",
                "def canonical_cookie_header",
                "Duplicate cookie name",
            )
        ),
        "zap_session_precheck": "session_precheck" in zap and "authentication_precheck_failed" in zap,
        "zap_direct_proxy_comparison": "proxy_matches_direct" in zap and "direct_proxy_similarity" in zap,
        "zap_history_cookie_verification": "_history_cookie_diagnostics" in zap and "exact_values_match" in zap,
        "zap_http_sessions_configured": "_configure_http_sessions" in zap,
        "zap_logout_reset_exclusions": all(
            marker in zap
            for marker in (
                "set_option_logout_avoidance",
                "exclude_from_context",
                "exclude_from_scan",
                "set_option_accept_cookies(False)",
            )
        ),
        "zap_targeted_get_post_scans": "_run_targeted_active_scans" in zap and "postdata=" in zap,
        "zap_post_scan_session_check": "authentication_lost_during_scan" in zap,
        "zap_diagnostic_only_mode": "diagnostic_only" in parameters(servers / "zapServer.py", "run_zap_scan"),
        "session_diagnostic_script_present": (root / "diagnose_sessions.py").is_file(),
        "nuclei_duplicate_timed_out_fixed": '"timed_out"' not in common_text,
        "idor_contract_fixed": {
            "target_url", "cookies", "timeout", "method", "data", "parameters"
        } <= parameters(servers / "idorForgeServer.py", "run_idor_check"),
        "deterministic_idor_arguments_fixed": 'if spec.name == "idor":' in deterministic,
        "tool_specific_cases": "select_tool_request_cases" in deterministic and "select_tool_request_cases" in agentic,
        "sqlmap_cookie_rotation_disabled": "--drop-set-cookie" in sqlmap,
        "commix_cookie_rotation_disabled": "--drop-set-cookie" in commix,
        "verbose_zap_root_cause": "ZAP AUTH ROOT CAUSE" in deterministic,
    }
    result = {
        "project_root": str(root),
        "numbered_duplicates": numbered,
        "checks": checks,
        "all_passed": all(checks.values()),
    }
    print(json.dumps(result, indent=2))
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
