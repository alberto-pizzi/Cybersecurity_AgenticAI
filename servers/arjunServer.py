from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from utils import failure, partial, run_process, success

from utils import run_mcp_http

mcp = FastMCP("Arjun Scanner")

PRIORITY_PARAMETERS = (
    "id", "uid", "user_id", "account", "role", "admin", "action",
    "cmd", "command", "exec", "shell", "ip", "host", "file", "path",
    "page", "include", "template", "url", "redirect", "callback",
    "webhook", "xml", "debug", "download", "upload", "message",
)
HIGH_RISK_NAMES = {"cmd","command","exec","shell","file","filename","path","include","template","url","uri","redirect","callback","webhook","role","admin","user_id","id","xml"}


def collect_parameters(value: Any) -> list[str]:
    found=[]
    if isinstance(value,list): found.extend(str(item) for item in value if isinstance(item,(str,int,float)))
    elif isinstance(value,dict):
        for nested in value.values(): found.extend(collect_parameters(nested))
    return found


def _load(path: Path) -> list[str]:
    try: parsed=json.loads(path.read_text(encoding="utf-8",errors="replace"))
    except (OSError,json.JSONDecodeError): return []
    return sorted({item.strip() for item in collect_parameters(parsed) if item.strip()})


def _run(target_url: str, cookies: str, output: Path, wordlist: str, budget: int, name: str, method: str = "GET", data: str = "") -> tuple[dict[str,Any],list[str]]:
    method = method.upper()
    command=[
        "arjun", "-u", target_url, "-m", method,
        "-oJ", str(output), "-q", "-t", "2", "-T", "4",
        "-w", wordlist, "-c", "15", "--rate-limit", "20",
    ]
    if data and method in {"POST", "JSON", "XML"}:
        command.extend(["--include", data])
    if cookies: command.extend(["--headers",f"Cookie: {cookies}"])
    result=run_process("Arjun",command,target=target_url,timeout=budget)
    parameters=_load(output)
    if result.get("diagnosis")=="timeout": result.update(status="partial",diagnosis="time_limit_reached",timed_out=True,output=f"Arjun phase '{name}' reached its {budget}-second budget. Parameters preserved: {len(parameters)}.")
    result.update(phase=name,phase_parameters=len(parameters),phase_timeout_seconds=budget)
    return result,parameters


def _finding(target_url: str, parameter: str, method: str = "GET") -> dict[str,Any]:
    high=parameter.lower() in HIGH_RISK_NAMES
    return {
        "alert": "High-priority hidden HTTP parameter discovered" if high else "Hidden HTTP parameter discovered",
        "risk": "info",
        "category": "discovery",
        "verification_status": "parameter-name-discovery-only",
        "description": f"Arjun observed that the endpoint accepts or reacts to the undocumented {method} parameter '{parameter}'.",
        "impact": "No vulnerability is inferred from the parameter name alone. The result expands the attack surface and identifies an input that should be tested by the appropriate injection or authorization scanner.",
        "solution": "Confirm whether the parameter is intended, document it, apply server-side validation and authorization where relevant, and remove unused inputs.",
        "url": target_url,
        "method": method,
        "parameter": parameter,
        "confidence": "medium",
        "priority": "high" if high else "normal",
        "technical_details": f"Arjun parameter discovery result; parameter={parameter}; priority={'high' if high else 'normal'}.",
        "evidence": f"Parameter name returned by Arjun: {parameter}",
    }


@mcp.tool()
def run_arjun_scan(
    target_url: str,
    cookies: str = "",
    method: str = "GET",
    data: str = "",
    known_parameters: list[str] | None = None,
    timeout: int = 60,
) -> dict:
    """Discover hidden GET or POST parameters using the actual request method."""
    method = str(method or "GET").upper()
    if method not in {"GET", "POST", "JSON", "XML"}:
        return failure("Arjun", target_url, "method must be GET, POST, JSON, or XML.")
    timeout=max(20,min(int(timeout),180))
    known = sorted({str(value) for value in (known_parameters or []) if str(value)})
    with tempfile.TemporaryDirectory(prefix="arjun-priority-") as td:
        temp=Path(td)
        priority=temp/"priority.txt"
        priority.write_text("\n".join(PRIORITY_PARAMETERS)+"\n",encoding="utf-8")
        phase, found = _run(
            target_url, cookies, temp/"high_risk_parameter_names.json",
            str(priority), timeout, "high_risk_parameter_names", method, data,
        )
        parameters=sorted(
            set(found) - set(known),
            key=lambda value:(value.lower() not in HIGH_RISK_NAMES,value.lower()),
        )
        findings=[_finding(target_url,p,method) for p in parameters]
        common={
            "vulnerabilities":findings,
            "parameters":parameters,
            "known_parameters":known,
            "authenticated":bool(cookies),
            "hard_failure":phase.get("status")=="error",
            "phases":[{
                "name":phase.get("phase"),
                "status":phase.get("status"),
                "diagnosis":phase.get("diagnosis",""),
                "return_code":phase.get("return_code"),
                "parameters":phase.get("phase_parameters",0),
                "timeout_seconds":phase.get("phase_timeout_seconds"),
                "command":phase.get("command",[]),
                "stdout_excerpt":str(phase.get("stdout",""))[-3000:],
                "stderr_excerpt":str(phase.get("stderr",""))[-3000:],
                "output_excerpt":str(phase.get("output",""))[-1500:],
            }],
            "scan_profile":f"bounded high-risk hidden-parameter names; method={method}",
            "request_method":method,
            "persistent_data_present":bool(data),
        }
        if phase.get("status")=="error" and not parameters:
            detail = (
                str(phase.get("stderr") or "").strip()
                or str(phase.get("stdout") or "").strip()
                or str(phase.get("output") or "").strip()
                or "No scanner diagnostic text was returned."
            )
            result=failure(
                "Arjun",
                target_url,
                f"Arjun failed before returning parameters. {detail[-1200:]}",
                return_code=phase.get("return_code"),
                stdout=str(phase.get("stdout") or ""),
                stderr=str(phase.get("stderr") or ""),
                diagnosis=str(phase.get("diagnosis") or "scanner_error"),
                command=phase.get("command",[]),
            )
            result.update(common)
            return result
        if phase.get("status")=="partial":
            return partial(
                "Arjun",target_url,
                f"Arjun ended with incomplete coverage. Hidden parameters preserved: {len(parameters)}.",
                diagnosis="time_limit_reached",timed_out=True,**common,
            )
        return success(
            "Arjun",target_url,
            f"Arjun completed for {method}. New hidden parameters: {len(parameters)}.",
            **common,
        )


if __name__ == "__main__":
    run_mcp_http(mcp, "arjun")
