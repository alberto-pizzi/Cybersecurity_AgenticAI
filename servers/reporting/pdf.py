"""HTML -> PDF conversion for the generated report, via WeasyPrint (native or,
when unavailable in this environment, through the sandboxed report Docker
image).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from utils import ROOT_DIR


def html2pdf(html_path, pdf_path):
    html_path = Path(html_path).resolve()
    pdf_path = Path(pdf_path).resolve()

    # Keep conversion diagnostics on stderr so the MCP response channel stays clean.
    print("HTML path received:", html_path, file=sys.stderr)
    print("PDF path received:", pdf_path, file=sys.stderr)

    print("Starting HTML2PDF...", file=sys.stderr)

    if not html_path.exists():
        raise FileNotFoundError(f"HTML file not found: {html_path}")

    try:
        # Import lazily: the MCP HTTP service must still start when WeasyPrint is
        # intentionally provided only by the local report Docker image.
        from weasyprint import HTML

        HTML(
            filename=str(html_path),
            base_url=str(html_path.parent)
        ).write_pdf(
            str(pdf_path)
        )
        print("Weasyprint: PDF converted into", pdf_path, file=sys.stderr)
        return
    except (ImportError, OSError) as native_error:
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
                f"/reports/{pdf_path.name}",
            ]
        else:
            command += [
                "-v", f"{input_dir}:/input:ro",
                "-v", f"{output_dir}:/output",
                image,
                "python", "-m", "weasyprint",
                f"/input/{html_path.name}",
                f"/output/{pdf_path.name}",
            ]

        converted = subprocess.run(
            command,
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
        if converted.returncode != 0 or not pdf_path.is_file():
            detail = "\n".join(
                part for part in ((converted.stdout or "").strip(), (converted.stderr or "").strip())
                if part
            )
            raise RuntimeError(
                f"Report Docker conversion failed with exit code {converted.returncode}. "
                f"{detail[-2000:]}"
            ) from native_error

        print("Weasyprint Docker fallback: PDF converted into", pdf_path, file=sys.stderr)
