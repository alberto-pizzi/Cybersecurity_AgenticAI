from __future__ import annotations

import os
import time
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP
from zapv2 import ZAPv2

from utils import failure, success

mcp = FastMCP("OWASP ZAP Scanner")
COOKIE_RULE_NAME = "secops-session-cookie"


def risk_name(value: Any) -> str:
    return {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(
        str(value), str(value or "info").lower()
    )


def _valid_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _scan_id_or_error(value: Any, phase: str) -> str:
    scan_id = str(value or "").strip()
    if not scan_id or not scan_id.isdigit():
        raise RuntimeError(f"ZAP did not return a valid {phase} scan id: {value!r}")
    return scan_id


def _wait_for_scan(status_function: Any, scan_id: str, timeout: int, phase: str, interval: float) -> int:
    deadline = time.monotonic() + timeout
    last_progress = -1
    while True:
        raw_status = status_function(scan_id)
        try:
            progress = int(str(raw_status))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Invalid ZAP {phase} status for scan {scan_id}: {raw_status!r}") from exc
        if progress >= 100:
            return progress
        if progress < 0:
            raise RuntimeError(f"ZAP {phase} returned negative progress: {progress}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"ZAP {phase} timeout after {timeout} seconds; last progress={progress}%")
        if progress != last_progress:
            last_progress = progress
        time.sleep(interval)


def _remove_cookie_rule(zap: ZAPv2) -> None:
    try:
        zap.replacer.remove_rule(COOKIE_RULE_NAME)
    except Exception:
        # Removing a missing rule is harmless and differs across ZAP add-on versions.
        pass


@mcp.tool()
def run_zap_scan(
    target_url: str,
    cookies: str = "",
    zap_url: str = "http://127.0.0.1:8080",
    timeout: int = 300,
    api_key: str = "",
) -> dict:
    """Run a ZAP spider and active scan against an explicitly authorized URL."""
    if not _valid_http_url(target_url):
        return failure("OWASP ZAP", target_url, "target_url must be a valid HTTP or HTTPS URL.")
    if not _valid_http_url(zap_url):
        return failure("OWASP ZAP", target_url, "zap_url must be a valid HTTP or HTTPS URL.")
    if timeout < 10:
        return failure("OWASP ZAP", target_url, "timeout must be at least 10 seconds.")

    effective_api_key = api_key or os.getenv("ZAP_API_KEY", "")
    started = time.monotonic()
    zap: ZAPv2 | None = None
    try:
        zap = ZAPv2(
            apikey=effective_api_key,
            proxies={"http": zap_url, "https": zap_url},
        )
        version = str(zap.core.version)
        if not version:
            raise RuntimeError("ZAP API returned an empty version.")

        # ZAP session and replacer configuration are global to the daemon. The
        # orchestrator serializes ZAP actions, and this server always clears the
        # cookie rule before and after a scan to prevent profile leakage.
        _remove_cookie_rule(zap)
        zap.core.new_session(name=f"scan-{int(time.time())}", overwrite=True)

        if cookies:
            zap.replacer.add_rule(
                description=COOKIE_RULE_NAME,
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Cookie",
                replacement=cookies,
                initiators="",
            )

        zap.urlopen(target_url)

        spider_id = _scan_id_or_error(zap.spider.scan(target_url), "spider")
        _wait_for_scan(zap.spider.status, spider_id, timeout, "spider", 2.0)

        active_id = _scan_id_or_error(
            zap.ascan.scan(target_url, recurse=True, inscopeonly=False),
            "active",
        )
        _wait_for_scan(zap.ascan.status, active_id, timeout, "active scan", 3.0)

        findings: list[dict[str, Any]] = []
        alerts = zap.core.alerts(baseurl=target_url)
        if not isinstance(alerts, list):
            raise RuntimeError(f"ZAP alerts API returned {type(alerts).__name__}, expected list.")
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            findings.append({
                "alert": alert.get("alert", "ZAP finding"),
                "risk": risk_name(alert.get("riskcode")),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "url": alert.get("url", target_url),
                "parameter": alert.get("param", ""),
                "evidence": alert.get("evidence", ""),
                "cwe_id": alert.get("cweid", ""),
                "confidence": alert.get("confidence", ""),
                "plugin_id": alert.get("pluginId", alert.get("pluginid", "")),
            })

        return success(
            "OWASP ZAP",
            target_url,
            f"Spider and active scan completed. Findings: {len(findings)}",
            vulnerabilities=findings,
            zap_version=version,
            spider_scan_id=spider_id,
            active_scan_id=active_id,
            duration_seconds=round(time.monotonic() - started, 3),
            authenticated=bool(cookies),
        )
    except TimeoutError as exc:
        result = failure("OWASP ZAP", target_url, str(exc))
        result.update({
            "diagnosis": "timeout",
            "duration_seconds": round(time.monotonic() - started, 3),
        })
        return result
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"
        lowered = message.lower()
        if "connection refused" in lowered or "failed to establish" in lowered:
            diagnosis = "zap_service_unreachable"
        elif "api key" in lowered or "unauthorized" in lowered or "forbidden" in lowered:
            diagnosis = "zap_api_key_or_permissions"
        elif "replacer" in lowered:
            diagnosis = "zap_replacer_addon_or_rule_error"
        elif "scan id" in lowered:
            diagnosis = "zap_scan_not_started"
        else:
            diagnosis = "zap_api_error"
        result = failure("OWASP ZAP", target_url, message)
        result.update({
            "diagnosis": diagnosis,
            "duration_seconds": round(time.monotonic() - started, 3),
        })
        return result
    finally:
        if zap is not None:
            _remove_cookie_rule(zap)


if __name__ == "__main__":
    mcp.run(transport="stdio")