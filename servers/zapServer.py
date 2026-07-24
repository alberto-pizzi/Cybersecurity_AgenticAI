from __future__ import annotations

import os
import time
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP
from zapv2 import ZAPv2

from utils import failure, partial, success

mcp = FastMCP("OWASP ZAP Scanner")
COOKIE_RULE_NAME = "secops-session-cookie"


def risk_name(value: Any) -> str:
    return {"0":"info","1":"low","2":"medium","3":"high"}.get(str(value),str(value or "info").lower())


def _valid_http_url(value: str) -> bool:
    parsed=urlparse(value); return parsed.scheme in {"http","https"} and bool(parsed.netloc)


def _scan_id(value: Any, phase: str) -> str:
    scan_id=str(value or "").strip()
    if not scan_id.isdigit(): raise RuntimeError(f"ZAP did not return a valid {phase} scan id: {value!r}")
    return scan_id


def _wait(status_function: Any, scan_id: str, deadline: float, phase: str, interval: float) -> int:
    while True:
        raw=status_function(scan_id)
        try: progress=int(str(raw))
        except (TypeError,ValueError) as exc: raise RuntimeError(f"Invalid ZAP {phase} status: {raw!r}") from exc
        if progress>=100: return progress
        if progress<0: raise RuntimeError(f"ZAP {phase} returned negative progress: {progress}")
        if time.monotonic()>=deadline: raise TimeoutError(f"ZAP {phase} reached the assessment time budget; last progress={progress}%")
        time.sleep(interval)


def _remove_cookie_rule(zap: ZAPv2) -> None:
    try: zap.replacer.remove_rule(COOKIE_RULE_NAME)
    except Exception: pass


def _findings(zap: ZAPv2, target_url: str) -> list[dict[str,Any]]:
    alerts=zap.core.alerts(baseurl=target_url)
    if not isinstance(alerts,list): return []
    findings=[]
    for alert in alerts:
        if not isinstance(alert,dict): continue
        risk=risk_name(alert.get("riskcode"))
        findings.append({"alert":alert.get("alert","ZAP finding"),"risk":risk,"category":"observation" if risk=="info" else "candidate","description":alert.get("description",""),"impact":alert.get("other","") or "The issue may weaken application security and requires validation.","solution":alert.get("solution",""),"url":alert.get("url",target_url),"parameter":alert.get("param",""),"evidence":alert.get("evidence",""),"cwe_id":alert.get("cweid",""),"confidence":alert.get("confidence",""),"plugin_id":alert.get("pluginId",alert.get("pluginid",""))})
    return findings


@mcp.tool()
def run_zap_scan(target_url: str,cookies: str="",zap_url: str="http://127.0.0.1:8080",timeout: int=300,api_key: str="") -> dict:
    """Run spider then active scan inside one total time budget, preserving current alerts."""
    if not _valid_http_url(target_url): return failure("OWASP ZAP",target_url,"target_url must be a valid HTTP or HTTPS URL.")
    if not _valid_http_url(zap_url): return failure("OWASP ZAP",target_url,"zap_url must be a valid HTTP or HTTPS URL.")
    if timeout<30: return failure("OWASP ZAP",target_url,"timeout must be at least 30 seconds.")
    started=time.monotonic(); deadline=started+timeout; zap=None; spider_id=""; active_id=""; phase="startup"
    try:
        zap=ZAPv2(apikey=api_key or os.getenv("ZAP_API_KEY",""),proxies={"http":zap_url,"https":zap_url})
        version=str(zap.core.version)
        if not version: raise RuntimeError("ZAP API returned an empty version.")
        _remove_cookie_rule(zap); zap.core.new_session(name=f"scan-{int(time.time())}",overwrite=True)
        if cookies: zap.replacer.add_rule(description=COOKIE_RULE_NAME,enabled=True,matchtype="REQ_HEADER",matchregex=False,matchstring="Cookie",replacement=cookies,initiators="")
        zap.urlopen(target_url)
        phase="spider"; spider_id=_scan_id(zap.spider.scan(target_url),"spider"); spider_deadline=min(deadline,started+max(30,int(timeout*0.3))); _wait(zap.spider.status,spider_id,spider_deadline,"spider",2.0)
        phase="active_scan"; active_id=_scan_id(zap.ascan.scan(target_url,recurse=True,inscopeonly=False),"active"); _wait(zap.ascan.status,active_id,deadline,"active scan",3.0)
        findings=_findings(zap,target_url)
        return success("OWASP ZAP",target_url,f"Spider and active scan completed. Findings: {len(findings)}.",vulnerabilities=findings,zap_version=version,spider_scan_id=spider_id,active_scan_id=active_id,duration_seconds=round(time.monotonic()-started,3),authenticated=bool(cookies))
    except TimeoutError as exc:
        findings=_findings(zap,target_url) if zap is not None else []
        return partial("OWASP ZAP",target_url,f"ZAP reached the configured {timeout}-second budget during {phase}. Findings preserved: {len(findings)}.",vulnerabilities=findings,diagnosis="time_limit_reached",timed_out=True,time_limit_phase=phase,spider_scan_id=spider_id,active_scan_id=active_id,duration_seconds=round(time.monotonic()-started,3),authenticated=bool(cookies))
    except Exception as exc:
        message=f"{type(exc).__name__}: {exc}"; lower=message.lower()
        diagnosis="zap_service_unreachable" if "connection refused" in lower or "failed to establish" in lower else "zap_api_key_or_permissions" if "api key" in lower or "unauthorized" in lower or "forbidden" in lower else "zap_scan_not_started" if "scan id" in lower else "zap_api_error"
        result=failure("OWASP ZAP",target_url,message); result.update(diagnosis=diagnosis,duration_seconds=round(time.monotonic()-started,3)); return result
    finally:
        if zap is not None: _remove_cookie_rule(zap)


if __name__=="__main__": mcp.run(transport="stdio")