from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SERVERS = ROOT / "servers"
if str(SERVERS) not in sys.path:
    sys.path.insert(0, str(SERVERS))

from reporting.reportServer import generate_report  # noqa: E402
from reporting.revision_snapshot import REVIEW_SNAPSHOT_SCHEMA_VERSION  # noqa: E402


# Loads one persisted review snapshot and validates the fields required to regenerate a report.
def _load_snapshot(path: str) -> dict:
    snapshot_path = Path(path).expanduser().resolve()
    try:
        payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Cannot read review snapshot {snapshot_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Review snapshot is not valid JSON: {snapshot_path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("snapshot_type") != "secops-review-snapshot":
        raise ValueError("Input is not a SecOps review snapshot.")
    if int(payload.get("schema_version") or 0) != REVIEW_SNAPSHOT_SCHEMA_VERSION:
        raise ValueError(f"Unsupported review snapshot schema; expected {REVIEW_SNAPSHOT_SCHEMA_VERSION}.")
    if not isinstance(payload.get("results"), dict) or not str(payload.get("target") or ""):
        raise ValueError("Review snapshot does not contain target/results required for report regeneration.")
    return payload


# Re-renders HTML/PDF/JSON from preserved redacted evidence without executing scanners again.
def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate a SecOps report from a saved .review.json evidence snapshot.")
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--output-name", default="")
    parser.add_argument("--client-name", default="")
    parser.add_argument("--assessor", default="")
    parser.add_argument("--assessment-type", default="")
    parser.add_argument("--report-version", default="1.1")
    args = parser.parse_args()

    try:
        snapshot = _load_snapshot(args.snapshot)
    except ValueError as exc:
        parser.error(str(exc))

    output_name = args.output_name or f"{snapshot.get('source_report_id') or 'SecOps_Assessment'}_revision"
    result = generate_report(
        findings_summary=snapshot["results"],
        target_url=str(snapshot["target"]),
        output_name=output_name,
        assessment_context=snapshot.get("assessment_context") or {},
        client_name=args.client_name,
        assessor=args.assessor,
        assessment_type=args.assessment_type,
        report_version=args.report_version,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0 if result.get("status") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
