"""HTML -> PDF conversion for the generated report, via WeasyPrint (native or,
when unavailable in this environment, through the sandboxed report Docker
image).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from utils import ROOT_DIR

REPORT_PDF_TIMEOUT_SECONDS = max(300, int(os.getenv("SECOPS_REPORT_PDF_TIMEOUT", "3600")))


# Converts an HTML report to PDF via native WeasyPrint, falling back to the report Docker image
def html2pdf(html_path, pdf_path):
    html_path = Path(html_path).resolve()
    pdf_path = Path(pdf_path).resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_pdf = pdf_path.with_name(f".{pdf_path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp.pdf")

    # Keep conversion diagnostics on stderr so the MCP response channel stays clean.
    print("HTML path received:", html_path, file=sys.stderr)
    print("PDF path received:", pdf_path, file=sys.stderr)
    print("Starting HTML2PDF...", file=sys.stderr)

    if not html_path.exists():
        raise FileNotFoundError(f"HTML file not found: {html_path}")

    native_error = None
    try:
        # Import lazily: the MCP HTTP service must still start when WeasyPrint is
        # intentionally provided only by the local report Docker image.
        import weasyprint  # noqa: F401
    except (ImportError, OSError) as exc:
        native_error = exc

    if native_error is None:
        try:
            converted = subprocess.run(
                [sys.executable, "-m", "weasyprint", str(html_path), str(temporary_pdf)],
                cwd=str(ROOT_DIR),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=REPORT_PDF_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            temporary_pdf.unlink(missing_ok=True)
            raise TimeoutError(
                f"Native WeasyPrint exceeded the configured {REPORT_PDF_TIMEOUT_SECONDS}-second PDF rendering budget."
            ) from exc
        if converted.returncode != 0 or not temporary_pdf.is_file():
            temporary_pdf.unlink(missing_ok=True)
            detail = "\n".join(
                part for part in ((converted.stdout or "").strip(), (converted.stderr or "").strip())
                if part
            )
            raise RuntimeError(
                f"Native WeasyPrint conversion failed with exit code {converted.returncode}. {detail[-2000:]}"
            )
        os.replace(temporary_pdf, pdf_path)
        print("Weasyprint: PDF converted into", pdf_path, file=sys.stderr)
        return

    docker = shutil.which("docker")
    image = os.getenv("SECOPS_REPORT_DOCKER_IMAGE", "secops/report:local").strip() or "secops/report:local"
    if not docker:
        raise RuntimeError(
            "WeasyPrint is unavailable natively and Docker is not available for the report fallback."
        ) from native_error

    inspect = subprocess.run(
        [docker, "image", "inspect", image],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    if inspect.returncode != 0:
        detail = (inspect.stderr or inspect.stdout or "").strip()
        raise RuntimeError(
            f"WeasyPrint is unavailable natively and report Docker image {image!r} is not ready. "
            f"{detail[-1200:]}"
        ) from native_error

    input_dir = html_path.parent
    output_dir = pdf_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    command = [docker, "run", "--rm"]
    if input_dir == output_dir:
        command += [
            "-v", f"{input_dir}:/reports",
            image,
            "python", "-m", "weasyprint",
            f"/reports/{html_path.name}",
            f"/reports/{temporary_pdf.name}",
        ]
    else:
        command += [
            "-v", f"{input_dir}:/input:ro",
            "-v", f"{output_dir}:/output",
            image,
            "python", "-m", "weasyprint",
            f"/input/{html_path.name}",
            f"/output/{temporary_pdf.name}",
        ]

    try:
        converted = subprocess.run(
            command,
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=REPORT_PDF_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        temporary_pdf.unlink(missing_ok=True)
        raise TimeoutError(
            f"Report Docker conversion exceeded the configured {REPORT_PDF_TIMEOUT_SECONDS}-second PDF rendering budget."
        ) from exc
    if converted.returncode != 0 or not temporary_pdf.is_file():
        temporary_pdf.unlink(missing_ok=True)
        detail = "\n".join(
            part for part in ((converted.stdout or "").strip(), (converted.stderr or "").strip())
            if part
        )
        raise RuntimeError(
            f"Report Docker conversion failed with exit code {converted.returncode}. {detail[-2000:]}"
        ) from native_error

    os.replace(temporary_pdf, pdf_path)
    print("Weasyprint Docker fallback: PDF converted into", pdf_path, file=sys.stderr)
