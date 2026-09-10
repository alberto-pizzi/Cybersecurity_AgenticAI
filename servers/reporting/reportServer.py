from __future__ import annotations

import json
import os
import base64
import hashlib
import threading
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path

import requests
from fastmcp import FastMCP

from utils import REPORTS_DIR, failure, run_mcp_http, success

from reporting.coverage import _executive_text, build_coverage, build_endpoint_coverage, summarize, summarize_endpoint_coverage
from reporting.findings import _finding_groups, _human_readable_findings, flatten_findings
from reporting.html_report import _render_html
from reporting.pdf_maker import html2pdf
from reporting.revision_snapshot import build_review_snapshot
from reporting.text_utils import _as_dict, _redact_value, _safe_name


mcp = FastMCP("SecOps Report Server")


REPORT_UPLOAD_TTL_SECONDS = max(60, int(os.getenv("SECOPS_REPORT_UPLOAD_TTL_SECONDS", "900")))
REPORT_UPLOAD_MAX_BYTES = max(1024 * 1024, int(os.getenv("SECOPS_REPORT_UPLOAD_MAX_BYTES", str(64 * 1024 * 1024))))
REPORT_UPLOAD_MAX_COMPRESSED_BYTES = REPORT_UPLOAD_MAX_BYTES + 1024 * 1024
REPORT_UPLOAD_MAX_CHUNKS = max(8, int(os.getenv("SECOPS_REPORT_UPLOAD_MAX_CHUNKS", "2048")))
_REPORT_UPLOADS: dict[str, dict] = {}
_REPORT_UPLOAD_LOCK = threading.Lock()


def _cleanup_report_uploads_locked(now: float) -> None:
    expired = [upload_id for upload_id, row in _REPORT_UPLOADS.items() if now - float(row.get("updated", now)) > REPORT_UPLOAD_TTL_SECONDS]
    for upload_id in expired:
        _REPORT_UPLOADS.pop(upload_id, None)


def _valid_upload_id(value: str) -> bool:
    text = str(value or "")
    return len(text) == 32 and all(character in "0123456789abcdef" for character in text.lower())


@mcp.tool()
def upload_report_chunk(
    upload_id: str,
    chunk_index: int,
    total_chunks: int,
    compressed_sha256: str,
    uncompressed_bytes: int,
    chunk_b64: str,
) -> dict:
    """Receive one bounded fragment of an oversized report payload over MCP/HTTP."""
    if not _valid_upload_id(upload_id):
        return {"status": "error", "error": "invalid upload_id"}
    if total_chunks < 1 or total_chunks > REPORT_UPLOAD_MAX_CHUNKS or chunk_index < 0 or chunk_index >= total_chunks:
        return {"status": "error", "error": "invalid report chunk index/count"}
    if uncompressed_bytes < 0 or uncompressed_bytes > REPORT_UPLOAD_MAX_BYTES:
        return {"status": "error", "error": "report payload exceeds the configured in-memory safety ceiling"}
    digest = str(compressed_sha256 or "").lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        return {"status": "error", "error": "invalid compressed payload digest"}
    try:
        chunk = base64.b64decode(str(chunk_b64 or ""), validate=True)
    except Exception:
        return {"status": "error", "error": "invalid base64 report chunk"}
    if len(chunk) > 512 * 1024:
        return {"status": "error", "error": "individual report chunk exceeds the server safety ceiling"}

    now = time.monotonic()
    with _REPORT_UPLOAD_LOCK:
        _cleanup_report_uploads_locked(now)
        row = _REPORT_UPLOADS.setdefault(upload_id, {
            "total_chunks": total_chunks,
            "compressed_sha256": digest,
            "uncompressed_bytes": uncompressed_bytes,
            "chunks": {},
            "updated": now,
        })
        if (
            int(row.get("total_chunks", -1)) != total_chunks
            or str(row.get("compressed_sha256", "")) != digest
            or int(row.get("uncompressed_bytes", -1)) != uncompressed_bytes
        ):
            _REPORT_UPLOADS.pop(upload_id, None)
            return {"status": "error", "error": "inconsistent metadata for report upload"}
        chunks = row["chunks"]
        previous = chunks.get(chunk_index)
        if previous is not None and previous != chunk:
            _REPORT_UPLOADS.pop(upload_id, None)
            return {"status": "error", "error": "conflicting duplicate report chunk"}
        chunks[chunk_index] = chunk
        row["updated"] = now
        compressed_bytes = sum(len(value) for value in chunks.values())
        if compressed_bytes > REPORT_UPLOAD_MAX_COMPRESSED_BYTES:
            _REPORT_UPLOADS.pop(upload_id, None)
            return {"status": "error", "error": "compressed report upload exceeds the configured safety ceiling"}
        return {
            "status": "success",
            "upload_id": upload_id,
            "received_chunks": len(chunks),
            "total_chunks": total_chunks,
            "received_compressed_bytes": compressed_bytes,
        }


def _consume_report_upload(upload_id: str) -> dict:
    if not _valid_upload_id(upload_id):
        raise ValueError("invalid upload_id")
    with _REPORT_UPLOAD_LOCK:
        _cleanup_report_uploads_locked(time.monotonic())
        row = _REPORT_UPLOADS.pop(upload_id, None)
    if not isinstance(row, dict):
        raise ValueError("report upload is missing or expired")
    total_chunks = int(row.get("total_chunks", 0))
    chunks = row.get("chunks") if isinstance(row.get("chunks"), dict) else {}
    if len(chunks) != total_chunks or any(index not in chunks for index in range(total_chunks)):
        raise ValueError(f"report upload is incomplete: received {len(chunks)}/{total_chunks} chunks")
    compressed = b"".join(chunks[index] for index in range(total_chunks))
    if hashlib.sha256(compressed).hexdigest() != str(row.get("compressed_sha256", "")):
        raise ValueError("report upload digest mismatch")
    expected_bytes = int(row.get("uncompressed_bytes", 0))
    if expected_bytes > REPORT_UPLOAD_MAX_BYTES:
        raise ValueError("report payload exceeds the configured in-memory safety ceiling")
    decompressor = zlib.decompressobj()
    decoded = decompressor.decompress(compressed, REPORT_UPLOAD_MAX_BYTES + 1)
    if len(decoded) > REPORT_UPLOAD_MAX_BYTES or decompressor.unconsumed_tail:
        raise ValueError("report payload exceeds the configured in-memory safety ceiling after decompression")
    remaining = REPORT_UPLOAD_MAX_BYTES + 1 - len(decoded)
    decoded += decompressor.flush(remaining)
    if (
        len(decoded) > REPORT_UPLOAD_MAX_BYTES
        or len(decoded) != expected_bytes
        or not decompressor.eof
        or decompressor.unused_data
    ):
        raise ValueError("report payload size or stream integrity mismatch after decompression")
    loaded = json.loads(decoded.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("reconstructed report payload must be one JSON object")
    return loaded


@mcp.tool()
def discard_report_upload(upload_id: str) -> dict:
    """Discard an incomplete in-memory report upload."""
    with _REPORT_UPLOAD_LOCK:
        existed = _REPORT_UPLOADS.pop(str(upload_id or ""), None) is not None
    return {"status": "success", "upload_id": str(upload_id or ""), "discarded": existed}


def _generate_report(
    findings_summary: dict | str,
    target_url: str,
    output_name: str = "",
    assessment_context: dict | str | None = None,
    client_name: str = "",
    assessor: str = "",
    assessment_type: str = "",
    assessment_start: str = "",
    assessment_end: str = "",
    report_version: str = "1.0",
) -> dict:
    """Generate scanner-grounded JSON, HTML, PDF and review-snapshot artifacts.

    client_name, assessor, assessment_type, assessment_start/end and
    report_version are optional cover-page fields. Any left blank fall back
    to a neutral, non-fabricated default (e.g. target for client_name) -
    see _render_html's cover section.
    """
    try:
        results = _as_dict(findings_summary)
        context = _as_dict(assessment_context)
    except (json.JSONDecodeError, ValueError) as exc:
        return failure("Report Generator", target_url, f"Invalid report input: {exc}", diagnosis="invalid_report_input")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    base = _safe_name(output_name) or f"SecOps_Assessment_{datetime.now():%Y%m%d_%H%M%S}"
    json_path = Path(REPORTS_DIR) / f"{base}.json"
    html_path = Path(REPORTS_DIR) / f"{base}.html"
    pdf_path = Path(REPORTS_DIR) / f"{base}.pdf"
    review_snapshot_path = Path(REPORTS_DIR) / f"{base}.review.json"
    all_findings = flatten_findings(results)
    findings, omitted_detail = _human_readable_findings(all_findings)
    coverage = build_coverage(results, context)
    endpoint_coverage = build_endpoint_coverage(results, context)
    endpoint_coverage_summary = summarize_endpoint_coverage(endpoint_coverage)
    summary = summarize(results, all_findings, coverage, context)
    summary["omitted_human_readable_detail"] = omitted_detail

    payload = {
        "generated_at": datetime.now(timezone.utc),
        "target": target_url,
        "reporting_policy": "Scanner-grounded: observed facts are not invented; potential consequences and recovery guidance remain explicitly conditional when damage is not evidenced.",
        "executive_summary": _executive_text(summary, findings),
        "summary": summary,
        "coverage": coverage,
        "endpoint_coverage": endpoint_coverage,
        "endpoint_coverage_summary": endpoint_coverage_summary,
        "security_findings_count": sum(item["category"] == "vulnerability" for item in findings),
        "candidate_findings_count": sum(item["category"] == "candidate" for item in findings),
        "observations_count": sum(item["category"] in {"discovery", "observation"} for item in findings),
        "findings_count": len(findings),
        "findings": findings,
        "all_findings": all_findings,
        "findings_by_category": _finding_groups(findings),
        "assessment_context": _redact_value(context),
        "results": _redact_value(results),
        "client_name": client_name,
        "assessor": assessor,
        "assessment_type": assessment_type,
        "assessment_start": assessment_start,
        "assessment_end": assessment_end,
        "report_version": report_version,
        "report_id": base,
    }

    try:
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        review_snapshot_path.write_text(
            json.dumps(build_review_snapshot(payload), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        html_path.write_text(_render_html(payload), encoding="utf-8")
    except Exception as exc:
        return failure("Report Generator", target_url, f"JSON/HTML/review snapshot creation failed: {type(exc).__name__}: {exc}", diagnosis="report_serialization_failed")

    # The PDF is rendered from a separate, PDF-only HTML render (for_pdf=True):
    # same content, minus sections that only make sense in an interactive
    # browser (e.g. the raw JSON context dump, which WeasyPrint can't
    # collapse into a <details> the way a browser does). The full HTML
    # served to the user (html_path, written above) is unaffected.
    pdf_source_path = html_path.with_name(f"{html_path.stem}.pdf-source.html")
    try:
        pdf_source_path.write_text(_render_html(payload, for_pdf=True), encoding="utf-8")
        html2pdf(pdf_source_path, pdf_path)
    except Exception as exc:
        result = failure("Report Generator", target_url, f"PDF report creation failed: {type(exc).__name__}: {exc}", diagnosis="pdf_generation_failed")
        result.update(
            json_filename=str(json_path.resolve()),
            review_snapshot_filename=str(review_snapshot_path.resolve()) if review_snapshot_path.is_file() else None,
            html_filename=str(html_path.resolve()), pdf_filename=None, findings_count=len(findings),
        )
        return result
    finally:
        pdf_source_path.unlink(missing_ok=True)

    pwndoc_url = os.getenv("PWNDOC_URL", "").rstrip("/")
    pwndoc_status = "not_configured"
    if pwndoc_url:
        try:
            response = requests.get(pwndoc_url, timeout=4, verify=os.getenv("PWNDOC_VERIFY_TLS", "true").lower() not in {"0", "false", "no"})
            pwndoc_status = "reachable" if response.status_code < 500 else "unhealthy"
        except requests.RequestException:
            pwndoc_status = "offline"

    return success(
        "Report Generator",
        target_url,
        (
            f"Scanner-grounded PDF, HTML, JSON and review snapshot generated. "
            f"Confirmed findings: {payload['security_findings_count']}; "
            f"candidates: {payload['candidate_findings_count']}; observations: {payload['observations_count']}."
        ),
        pdf_filename=str(pdf_path.resolve()),
        html_filename=str(html_path.resolve()),
        json_filename=str(json_path.resolve()),
        review_snapshot_filename=str(review_snapshot_path.resolve()),
        local_pdf_generated=True,
        local_html_generated=True,
        local_json_generated=True,
        local_review_snapshot_generated=True,
        findings_count=len(findings),
        security_findings_count=payload["security_findings_count"],
        candidate_findings_count=payload["candidate_findings_count"],
        observations_count=payload["observations_count"],
        execution_limitations_count=len(summary.get("limitations") or []),
        coverage_constraints_count=len(summary.get("coverage_constraints") or []),
        execution_complete=bool(summary.get("execution_complete")),
        coverage_complete=bool(summary.get("coverage_complete")),
        pwndoc_status=pwndoc_status,
    )


@mcp.tool()
def generate_report(
    findings_summary: dict | str,
    target_url: str,
    output_name: str = "",
    assessment_context: dict | str | None = None,
    client_name: str = "",
    assessor: str = "",
    assessment_type: str = "",
    assessment_start: str = "",
    assessment_end: str = "",
    report_version: str = "1.0",
) -> dict:
    """Generate a report from an ordinary inline MCP/HTTP payload."""
    return _generate_report(
        findings_summary=findings_summary,
        target_url=target_url,
        output_name=output_name,
        assessment_context=assessment_context,
        client_name=client_name,
        assessor=assessor,
        assessment_type=assessment_type,
        assessment_start=assessment_start,
        assessment_end=assessment_end,
        report_version=report_version,
    )


@mcp.tool()
def generate_report_from_chunks(upload_id: str) -> dict:
    """Reconstruct an oversized report payload received through bounded MCP/HTTP chunks and render it."""
    try:
        arguments = _consume_report_upload(upload_id)
        allowed = {
            "findings_summary", "target_url", "output_name", "assessment_context", "client_name",
            "assessor", "assessment_type", "assessment_start", "assessment_end", "report_version",
        }
        unknown = sorted(set(arguments) - allowed)
        if unknown:
            raise ValueError("unsupported report argument(s): " + ", ".join(unknown))
        if "findings_summary" not in arguments or "target_url" not in arguments:
            raise ValueError("reconstructed report payload is missing required arguments")
        return _generate_report(**arguments)
    except Exception as exc:
        return failure("Report Generator", "", f"Chunked HTTP report input failed: {type(exc).__name__}: {exc}", diagnosis="invalid_chunked_report_input")


if __name__ == "__main__":
    run_mcp_http(mcp, "report")
