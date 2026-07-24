from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from utils import failure, partial, run_process, success

mcp = FastMCP("Arjun Scanner")

PRIORITY_PARAMETERS = (
    "id","uid","user","user_id","account","role","admin","action","query","search","q",
    "cmd","command","exec","shell","ip","host","file","filename","path","page","include",
    "template","url","uri","redirect","next","return","callback","webhook","xml","data",
    "token","key","debug","format","download","upload","name","email","message","sort","order",
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


def _run(target_url: str, cookies: str, output: Path, wordlist: str, budget: int, name: str) -> tuple[dict[str,Any],list[str]]:
    command=["arjun","-u",target_url,"-m","GET","-oJ",str(output),"-t","5","-T","6","-w",wordlist,"-c","100"]
    if cookies: command.extend(["--headers",f"Cookie: {cookies}"])
    result=run_process("Arjun",command,target=target_url,timeout=budget)
    parameters=_load(output)
    if result.get("diagnosis")=="timeout": result.update(status="partial",diagnosis="time_limit_reached",timed_out=True,output=f"Arjun phase '{name}' reached its {budget}-second budget. Parameters preserved: {len(parameters)}.")
    result.update(phase=name,phase_parameters=len(parameters),phase_timeout_seconds=budget)
    return result,parameters


def _finding(target_url: str, parameter: str) -> dict[str,Any]:
    high=parameter.lower() in HIGH_RISK_NAMES
    return {
        "alert": "High-priority hidden HTTP parameter discovered" if high else "Hidden HTTP parameter discovered",
        "risk": "info",
        "category": "discovery",
        "verification_status": "parameter-name-discovery-only",
        "description": f"Arjun observed that the endpoint accepts or reacts to the undocumented GET parameter '{parameter}'.",
        "impact": "No vulnerability is inferred from the parameter name alone. The result expands the attack surface and identifies an input that should be tested by the appropriate injection or authorization scanner.",
        "solution": "Confirm whether the parameter is intended, document it, apply server-side validation and authorization where relevant, and remove unused inputs.",
        "url": target_url,
        "method": "GET",
        "parameter": parameter,
        "confidence": "medium",
        "priority": "high" if high else "normal",
        "technical_details": f"Arjun parameter discovery result; parameter={parameter}; priority={'high' if high else 'normal'}.",
        "evidence": f"Parameter name returned by Arjun: {parameter}",
    }


@mcp.tool()
def run_arjun_scan(target_url: str,cookies: str="",timeout: int=120) -> dict:
    """Probe high-risk parameter names first, then use Arjun's compact general list."""
    timeout=max(45,min(int(timeout),240)); priority_budget=min(40,max(20,timeout//3)); general_budget=max(20,timeout-priority_budget)
    with tempfile.TemporaryDirectory(prefix="arjun-priority-") as td:
        temp=Path(td); priority=temp/"priority.txt"; priority.write_text("\n".join(PRIORITY_PARAMETERS)+"\n",encoding="utf-8")
        phases=[]; parameters=[]
        for name,wordlist,budget in (("high_risk_parameter_names",str(priority),priority_budget),("compact_general_parameters","small",general_budget)):
            phase,found=_run(target_url,cookies,temp/f"{name}.json",wordlist,budget,name); phases.append(phase); parameters.extend(found)
        parameters=sorted(set(parameters),key=lambda value:(value.lower() not in HIGH_RISK_NAMES,value.lower()))
        findings=[_finding(target_url,p) for p in parameters]
        hard=[p for p in phases if p.get("status")=="error"]; limited=[p for p in phases if p.get("status")=="partial"]
        common={"vulnerabilities":findings,"parameters":parameters,"authenticated":bool(cookies),"hard_failure":bool(hard),"phases":[{"name":p.get("phase"),"status":p.get("status"),"parameters":p.get("phase_parameters",0),"timeout_seconds":p.get("phase_timeout_seconds")} for p in phases],"scan_profile":"high-risk names first, then compact general discovery"}
        if len(hard)==len(phases) and not parameters: return failure("Arjun",target_url,"Both Arjun phases failed before returning parameters.") | common
        if hard or limited: return partial("Arjun",target_url,f"Arjun completed with incomplete coverage. Hidden parameters preserved: {len(parameters)}.",diagnosis="time_limit_reached" if limited and not hard else "partial_scan",timed_out=bool(limited),**common)
        return success("Arjun",target_url,f"Arjun completed. Hidden parameters: {len(parameters)}.",**common)


def _once() -> int:
    try:
        arguments = json.loads(os.sys.stdin.read() or "{}")
        if not isinstance(arguments, dict):
            raise ValueError("Expected a JSON object on stdin.")
        result = run_arjun_scan(**arguments)
    except Exception as exc:
        from utils import failure
        result = failure("Arjun", "", f"One-shot Arjun execution failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args, _ = parser.parse_known_args()
    if args.once:
        raise SystemExit(_once())
    mcp.run(transport="stdio")