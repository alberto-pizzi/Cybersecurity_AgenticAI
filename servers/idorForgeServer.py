from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from utils import failure, load_runtime_config, partial,  skipped, success

from scannerCommon import service

mcp, _serve = service("IDOR-Forge Wrapper", "idor")

UPSTREAM_REPOSITORY = "https://github.com/errorfiathck/IDOR-Forge.git"
RESULT_MARKER = "SECOPS_IDOR_FORGE_RESULT="

def _upstream_runtime() -> tuple[Path, str]:
    runtime = load_runtime_config().get("idor_forge", {})
    configured = runtime if isinstance(runtime, dict) else {}
    root = Path(
        os.getenv(
            "SECOPS_IDOR_FORGE_HOME", str(configured.get("directory") or (Path.home() / ".local" / "opt" / "idor-forge")),
        )
    ).expanduser()
    python = str(configured.get("python") or "").strip()
    if not python:
        python = str(root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    return root, python

def _numeric_parameter(target_url: str, parameters: list[str] | None) -> tuple[str, str] | None:
    requested = {str(value) for value in (parameters or []) if str(value)}
    for name, value in parse_qsl(urlparse(target_url).query, keep_blank_values=True):
        if value.isdigit() and (not requested or name in requested):
            return name, str(int(value) + 1)
    return None

def _run_upstream(root: Path, python: str, config: dict, timeout: int) -> list[dict]:
    runner = r'''
import json
import sys
from core.IDORChecker import IDORChecker

cfg = json.loads(sys.argv[1])
checker = IDORChecker(
    cfg["url"],
    delay=0,
    headers=cfg["headers"],
    timeout=cfg["request_timeout"],
    verbose=False,
    max_workers=1,
    max_retries=1,
    logger=lambda message: None,
)
checker.payload = {}
checker._generate_payloads = lambda param, values: [
    {**checker.params, param: str(value)} for value in values
]
results = checker.check_idor(
    cfg["parameter"],
    cfg["test_values"],
    method="GET",
    max_workers=1,
)
print("SECOPS_IDOR_FORGE_RESULT=" + json.dumps(results, default=str, separators=(",", ":")))
'''
    environment = os.environ.copy()
    environment["MPLBACKEND"] = "Agg"
    completed = subprocess.run(
        [python, "-c", runner, json.dumps(config, separators=(",", ":"))], cwd=root, env=environment, text=True,
        capture_output=True, timeout=max(5, int(timeout)), check=False,
    )
    if completed.returncode:
        detail = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
        raise RuntimeError(detail[-3000:] or f"IDOR-Forge exited with code {completed.returncode}")
    for line in reversed((completed.stdout or "").splitlines()):
        if line.startswith(RESULT_MARKER):
            value = json.loads(line[len(RESULT_MARKER):])
            return value if isinstance(value, list) else []
    raise RuntimeError("IDOR-Forge completed without returning the expected structured result.")

@mcp.tool()
def run_idor_check(
    target_url: str, cookies: str = "", timeout: int = 20, method: str = "GET", data: str = "", parameters: list[str] | None = None,
) -> dict:
    """Run the upstream IDOR-Forge engine on one discovered numeric GET reference."""
    if str(method).upper() != "GET" or str(data or "").strip():
        return skipped("IDOR-Forge", target_url, "The bounded project contract uses numeric GET object references only.")

    selected = _numeric_parameter(target_url, parameters)
    if not selected:
        return skipped("IDOR-Forge", target_url, "No compatible numeric query parameter was available for the IDOR check.")
    parameter, test_value = selected

    root, python = _upstream_runtime()
    if not (root / "core" / "IDORChecker.py").is_file() or not Path(python).is_file():
        return failure(
            "IDOR-Forge", target_url, "The upstream IDOR-Forge runtime is missing. Run initScript.py to clone and prepare it.",
            diagnosis="idor_forge_not_installed", upstream_repository=UPSTREAM_REPOSITORY,
        )

    config = {
        "url": target_url, "parameter": parameter, "test_values": [test_value], "headers": {"Cookie": cookies} if cookies else {},
        "request_timeout": max(3, min(15, int(timeout))),
    }
    try:
        rows = _run_upstream(root, python, config, timeout)
    except subprocess.TimeoutExpired:
        return partial(
            "IDOR-Forge", target_url, "IDOR-Forge reached the configured execution time budget.", diagnosis="time_limit_reached",
            timed_out=True, vulnerabilities=[], upstream_repository=UPSTREAM_REPOSITORY,
        )
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        return failure("IDOR-Forge", target_url, str(exc), diagnosis="upstream_execution_failed")

    candidates = [row for row in rows if isinstance(row, dict) and bool(row.get("idor_detected"))]
    findings = []
    for row in candidates:
        comparison = row.get("comparison") if isinstance(row.get("comparison"), dict) else {}
        findings.append({
            "alert": "Potential IDOR candidate reported by IDOR-Forge", "risk": "medium", "category": "candidate",
            "verification_status": "upstream-candidate-needs-two-account-ownership-validation",
            "description": (
                f"IDOR-Forge flagged the numeric parameter '{parameter}' after comparing the baseline "
                "with a bounded mutated object reference. The result is a candidate, not proof that the "
                "returned object belongs to another user."
            ),
            "impact": "If object-level authorization is missing, another user's data or action may become accessible.",
            "solution": "Enforce object-level authorization on every request and validate ownership with two distinct accounts.",
            "url": str(row.get("url") or target_url), "method": "GET", "parameter": parameter, "confidence": "low",
            "evidence": (
                f"status={row.get('status_code')}; test_value={test_value}; "
                f"structure_similarity={comparison.get('structure_similarity')}; "
                f"content_similarity={comparison.get('content_similarity')}; "
                f"text_similarity={comparison.get('text_similarity')}"
            ),
        })

    return success(
        "IDOR-Forge", target_url, f"Upstream IDOR-Forge completed a bounded numeric check. Candidates: {len(findings)}.",
        vulnerabilities=findings, candidate=bool(findings), parameter=parameter, test_value=test_value,
        upstream_results=rows, upstream_repository=UPSTREAM_REPOSITORY, upstream_directory=str(root), authenticated=bool(cookies),
    )

if __name__ == "__main__":
    _serve()
