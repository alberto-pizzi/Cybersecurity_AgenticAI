from __future__ import annotations

import argparse
import asyncio
import json
from urllib.parse import urlparse

from orchestratorDeterministic import (
    ToolSpec,
    call_mcp_with_progress,
    discover_target,
    log_zap_session_diagnostics,
)
from utils import canonical_cookie_header, cookie_names, normalize_url


async def main_async(
    target: str,
    cookies: str,
    active: bool,
    timeout: int,
) -> int:
    discovery = discover_target(target, cookies)
    print(
        f"[*] Discovery: HTML={len(discovery.get('html_urls', []))}; "
        f"requests={len(discovery.get('request_cases', []))}; "
        f"authentication_effective={discovery.get('authentication_effective')}"
    )
    if discovery.get("target_preparation"):
        print(
            "[*] Target preparation: "
            + json.dumps(
                discovery["target_preparation"],
                ensure_ascii=False,
                default=str,
            )
        )

    spec = ToolSpec(
        "zap",
        "zapServer.py",
        "run_zap_scan",
        module="zapv2",
    )
    scan_mode = "targeted" if active else "passive"
    result = await call_mcp_with_progress(
        spec,
        {
            "target_url": target,
            "cookies": cookies,
            "timeout": timeout,
            "seed_urls": discovery.get("html_urls", []),
            "request_cases": discovery.get("request_cases", []),
            "scan_mode": scan_mode,
            "max_observations": 40,
        },
        timeout_seconds=timeout + 45,
    )
    log_zap_session_diagnostics(result)

    stats = result.get("zap_alert_stats") if isinstance(result.get("zap_alert_stats"), dict) else {}
    policy = result.get("active_scanner_policy") if isinstance(result.get("active_scanner_policy"), dict) else {}
    print("\n=== ZAP diagnostic summary ===")
    print(f"status: {result.get('status')}")
    print(f"scan_mode: {result.get('scan_mode')}")
    print(f"native active rules enabled: {', '.join(policy.get('enabled_ids', [])) or 'none'}")
    print(
        "targeted active scans: "
        f"{result.get('targeted_active_scans_completed', 0)}/"
        f"{result.get('targeted_active_scans_started', 0)} completed"
    )
    print(f"proxy-assisted confirmed findings: {result.get('proxy_assisted_confirmed', 0)}")
    print(f"native/security findings returned: {stats.get('security_total_returned', 0)}")
    print(f"informational observations returned: {stats.get('observations', 0)}")

    concise = {
        "tool": result.get("tool"),
        "status": result.get("status"),
        "target": result.get("target"),
        "output": result.get("output"),
        "scan_mode": result.get("scan_mode"),
        "authentication_effective": result.get("authentication_effective"),
        "active_scanner_policy": policy,
        "targeted_active_scans": result.get("targeted_active_scans", []),
        "proxy_assisted_confirmed": result.get("proxy_assisted_confirmed", 0),
        "proxy_assisted_verification": result.get("proxy_assisted_verification", []),
        "zap_alert_stats": stats,
        "findings": [
            {
                "alert": item.get("alert"),
                "risk": item.get("risk"),
                "category": item.get("category"),
                "url": item.get("url"),
                "parameter": item.get("parameter"),
                "verification_status": item.get("verification_status"),
                "plugin_id": item.get("plugin_id"),
            }
            for item in result.get("vulnerabilities", [])
            if isinstance(item, dict)
        ],
    }
    print(json.dumps(concise, indent=2, ensure_ascii=False, default=str))

    status = str(result.get("status", "error"))
    if status == "error":
        return 2
    if active and not result.get("targeted_active_scans_started"):
        return 3
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run an isolated ZAP passive or bounded active diagnostic using the "
            "same discovery/session pipeline as the orchestrator."
        )
    )
    parser.add_argument("--target", default="http://127.0.0.1")
    parser.add_argument("--cookies", default="")
    parser.add_argument(
        "--active",
        action="store_true",
        help="Run bounded high-value active rules and proxy-assisted verification.",
    )
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()

    target = normalize_url(args.target)
    if urlparse(target).scheme not in {"http", "https"}:
        parser.error("HTTP or HTTPS target required.")
    try:
        cookies = canonical_cookie_header(args.cookies)
    except ValueError as exc:
        parser.error(str(exc))
    if cookies:
        print("[*] Cookie names: " + ", ".join(cookie_names(cookies)))
    return asyncio.run(
        main_async(
            target,
            cookies,
            bool(args.active),
            max(60, min(int(args.timeout), 600)),
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
