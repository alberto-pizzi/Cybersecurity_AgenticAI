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


async def main_async(target: str, cookies: str) -> int:
    discovery = discover_target(target, cookies)
    print(
        f"[*] Discovery: HTML={len(discovery.get('html_urls', []))}; "
        f"requests={len(discovery.get('request_cases', []))}; "
        f"authentication_effective={discovery.get('authentication_effective')}"
    )
    print(
        f"[*] Safe discovery skipped destructive URLs: "
        f"{len(discovery.get('destructive_urls_skipped', []))}"
    )
    if discovery.get("authentication_probe"):
        print(
            "[*] Discovery final auth probe: "
            + json.dumps(
                discovery["authentication_probe"],
                ensure_ascii=False,
            )
        )
    spec = ToolSpec(
        "zap",
        "zapServer.py",
        "run_zap_scan",
        module="zapv2",
    )
    result = await call_mcp_with_progress(
        spec,
        {
            "target_url": target,
            "cookies": cookies,
            "timeout": 120,
            "seed_urls": discovery.get("html_urls", []),
            "request_cases": discovery.get("request_cases", []),
            "diagnostic_only": True,
        },
    )
    log_zap_session_diagnostics(result)
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0 if result.get("status") == "success" else 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Diagnose direct and ZAP-proxied authenticated session handling."
    )
    parser.add_argument("--target", default="http://127.0.0.1")
    parser.add_argument("--cookies", required=True)
    args = parser.parse_args()

    target = normalize_url(args.target)
    if urlparse(target).scheme not in {"http", "https"}:
        parser.error("HTTP or HTTPS target required.")
    try:
        cookies = canonical_cookie_header(args.cookies)
    except ValueError as exc:
        parser.error(str(exc))
    print("[*] Cookie names: " + ", ".join(cookie_names(cookies)))
    return asyncio.run(main_async(target, cookies))


if __name__ == "__main__":
    raise SystemExit(main())
