"""HTML -> PDF conversion via native WeasyPrint, report Docker, then Chromium fallback.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from utils import ROOT_DIR, safe_int_value, safe_float_value

REPORT_PDF_TIMEOUT_SECONDS = max(300, safe_int_value(os.getenv("SECOPS_REPORT_PDF_TIMEOUT", "3600"), 3600))


# Converts an HTML report to PDF via native WeasyPrint, falling back to the report Docker image
def html2pdf(html_path, pdf_path, *, timeout_seconds: int | float | None = None):
    html_path = Path(html_path).resolve()
    pdf_path = Path(pdf_path).resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_pdf = pdf_path.with_name(f".{pdf_path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp.pdf")
    effective_timeout = REPORT_PDF_TIMEOUT_SECONDS if timeout_seconds is None else max(30, safe_int_value(safe_float_value(timeout_seconds, REPORT_PDF_TIMEOUT_SECONDS), REPORT_PDF_TIMEOUT_SECONDS))
    conversion_started = time.monotonic()
    conversion_deadline = conversion_started + float(effective_timeout)

    def remaining_budget(*, minimum: float = 0.05) -> float:
        remaining = conversion_deadline - time.monotonic()
        if remaining <= minimum:
            raise TimeoutError(
                f"PDF conversion exceeded the shared {effective_timeout}-second rendering budget."
            )
        return remaining

    # A shared deadline avoids timeout multiplication, but a single hung renderer must not consume
    # the whole allowance and starve every fallback. Reserve a bounded tail for later renderers.
    fallback_reserve = min(300.0, max(120.0, float(effective_timeout) * 0.20))
    chromium_reserve = min(180.0, max(60.0, float(effective_timeout) * 0.10))

    def stage_timeout(*, reserve_after: float = 0.0, ceiling: float | None = None) -> float:
        remaining = remaining_budget()
        reserve = min(max(0.0, float(reserve_after)), max(0.0, remaining - 1.0))
        budget = max(1.0, remaining - reserve)
        if ceiling is not None:
            budget = min(budget, max(1.0, float(ceiling)))
        return budget

    def chromium_fallback(previous_error: Exception | str) -> None:
        temporary_pdf.unlink(missing_ok=True)
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as playwright:
                launch_timeout_ms = max(1, int(min(remaining_budget(), 120.0) * 1000))
                browser = playwright.chromium.launch(headless=True, timeout=launch_timeout_ms)
                try:
                    page = browser.new_page()
                    navigation_timeout_ms = max(1, int(min(remaining_budget(), 120.0) * 1000))
                    page.goto(html_path.as_uri(), wait_until="load", timeout=navigation_timeout_ms)
                    remaining_budget()
                    page.pdf(path=str(temporary_pdf), format="A4", print_background=True)
                    # Playwright's page.pdf() has no independent timeout option. Do not accept a
                    # result that completed after the shared conversion deadline. The outer MCP
                    # watchdog remains the final guard if Chromium itself stops responding.
                    remaining_budget(minimum=0.0)
                finally:
                    browser.close()
            if not temporary_pdf.is_file() or temporary_pdf.stat().st_size <= 0:
                raise RuntimeError("Chromium completed without producing a PDF file")
            os.replace(temporary_pdf, pdf_path)
            print("Chromium: PDF converted into", pdf_path, file=sys.stderr)
            return
        except TimeoutError:
            temporary_pdf.unlink(missing_ok=True)
            raise
        except Exception as chromium_exc:
            temporary_pdf.unlink(missing_ok=True)
            raise RuntimeError(
                f"PDF conversion failed through native WeasyPrint, Docker fallback and Chromium fallback. "
                f"Previous error: {previous_error}. Chromium: {type(chromium_exc).__name__}: {chromium_exc}"
            ) from chromium_exc

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
                timeout=stage_timeout(reserve_after=fallback_reserve),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            temporary_pdf.unlink(missing_ok=True)
            native_error = TimeoutError(f"Native WeasyPrint exhausted the remaining shared PDF rendering budget (total={effective_timeout}s).")
        else:
            if converted.returncode == 0 and temporary_pdf.is_file():
                os.replace(temporary_pdf, pdf_path)
                print("Weasyprint: PDF converted into", pdf_path, file=sys.stderr)
                return
            temporary_pdf.unlink(missing_ok=True)
            detail = "\n".join(part for part in ((converted.stdout or "").strip(), (converted.stderr or "").strip()) if part)
            native_error = RuntimeError(f"Native WeasyPrint conversion failed with exit code {converted.returncode}. {detail[-2000:]}")

    docker = shutil.which("docker")
    image = os.getenv("SECOPS_REPORT_DOCKER_IMAGE", "secops/report:local").strip() or "secops/report:local"
    if not docker:
        return chromium_fallback(native_error or "Docker is not available for the report fallback")

    # Keep Docker readiness probing proportional to the active render budget. In TEST the
    # conversion itself is bounded, so a fixed 60s image inspection would consume a disproportionate
    # fraction of the smoke-test report allowance before rendering even starts.
    inspect_timeout = max(1.0, min(60.0, stage_timeout(reserve_after=chromium_reserve) * 0.20))
    try:
        inspect = subprocess.run(
            [docker, "image", "inspect", image],
            cwd=str(ROOT_DIR), capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=inspect_timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return chromium_fallback(f"Report Docker image inspection exceeded {inspect_timeout}s; native={native_error}")
    if inspect.returncode != 0:
        detail = (inspect.stderr or inspect.stdout or "").strip()
        return chromium_fallback(f"Report Docker image {image!r} is not ready. {detail[-1200:]}; native={native_error}")

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
            timeout=stage_timeout(reserve_after=chromium_reserve),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        temporary_pdf.unlink(missing_ok=True)
        return chromium_fallback(f"Report Docker conversion exhausted the remaining shared PDF budget (total={effective_timeout}s); native={native_error}")
    if converted.returncode != 0 or not temporary_pdf.is_file():
        temporary_pdf.unlink(missing_ok=True)
        detail = "\n".join(
            part for part in ((converted.stdout or "").strip(), (converted.stderr or "").strip())
            if part
        )
        return chromium_fallback(f"Report Docker conversion failed with exit code {converted.returncode}. {detail[-2000:]}; native={native_error}")

    os.replace(temporary_pdf, pdf_path)
    print("Weasyprint Docker fallback: PDF converted into", pdf_path, file=sys.stderr)
