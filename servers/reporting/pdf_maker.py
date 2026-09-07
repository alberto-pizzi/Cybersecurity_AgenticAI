"""HTML -> PDF conversion for the generated report.

The normal renderer remains WeasyPrint so the established report appearance is
unchanged. A Chromium print fallback is used only when both native WeasyPrint
and the configured WeasyPrint Docker image cannot produce the PDF.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from utils import ROOT_DIR


def _chromium_pdf(html_path: Path, pdf_path: Path) -> None:
    """Render the same PDF-only HTML/CSS through project Playwright Chromium."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(f"Playwright Chromium PDF fallback is unavailable: {type(exc).__name__}: {exc}") from exc

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.goto(html_path.as_uri(), wait_until="load", timeout=30_000)
            page.emulate_media(media="print")
            page.pdf(
                path=str(pdf_path),
                print_background=True,
                prefer_css_page_size=True,
            )
        finally:
            browser.close()
    if not pdf_path.is_file() or pdf_path.stat().st_size <= 0:
        raise RuntimeError("Chromium returned without creating a non-empty PDF.")


def _remove_docker_container(docker: str, name: str) -> None:
    try:
        subprocess.run(
            [docker, "rm", "-f", name], cwd=str(ROOT_DIR), capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=20, check=False,
        )
    except Exception:
        pass


# Converts an HTML report to PDF via native WeasyPrint, the configured Docker
# image, then Chromium as a final renderer fallback. The HTML/CSS source itself
# is never changed by this function.
def html2pdf(html_path, pdf_path) -> str:
    html_path = Path(html_path).resolve()
    pdf_path = Path(pdf_path).resolve()

    print("HTML path received:", html_path, file=sys.stderr)
    print("PDF path received:", pdf_path, file=sys.stderr)
    print("Starting HTML2PDF...", file=sys.stderr)

    if not html_path.exists():
        raise FileNotFoundError(f"HTML file not found: {html_path}")

    native_error: Exception | None = None
    try:
        from weasyprint import HTML

        HTML(filename=str(html_path), base_url=str(html_path.parent)).write_pdf(str(pdf_path))
        if not pdf_path.is_file() or pdf_path.stat().st_size <= 0:
            raise RuntimeError("Native WeasyPrint returned without creating a non-empty PDF.")
        print("WeasyPrint: PDF converted into", pdf_path, file=sys.stderr)
        return "weasyprint-native"
    except Exception as exc:
        native_error = exc
        pdf_path.unlink(missing_ok=True)
        print(f"Native WeasyPrint failed; trying Docker fallback: {type(exc).__name__}: {exc}", file=sys.stderr)

    docker = shutil.which("docker")
    image = os.getenv("SECOPS_REPORT_DOCKER_IMAGE", "secops/report:local").strip() or "secops/report:local"
    docker_error: Exception | None = None
    if docker:
        try:
            inspect = subprocess.run(
                [docker, "image", "inspect", image], cwd=str(ROOT_DIR), capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=60, check=False,
            )
            if inspect.returncode != 0:
                detail = (inspect.stderr or inspect.stdout or "").strip()
                raise RuntimeError(f"Report Docker image {image!r} is not ready. {detail[-1200:]}")

            input_dir = html_path.parent
            output_dir = pdf_path.parent
            output_dir.mkdir(parents=True, exist_ok=True)
            container_name = f"secops-report-{os.getpid()}-{uuid.uuid4().hex[:8]}"
            command = [docker, "run", "--rm", "--name", container_name]
            if input_dir == output_dir:
                command += [
                    "-v", f"{input_dir}:/reports", image, "python", "-m", "weasyprint",
                    f"/reports/{html_path.name}", f"/reports/{pdf_path.name}",
                ]
            else:
                command += [
                    "-v", f"{input_dir}:/input:ro", "-v", f"{output_dir}:/output", image,
                    "python", "-m", "weasyprint", f"/input/{html_path.name}", f"/output/{pdf_path.name}",
                ]
            docker_timeout = max(60, min(int(os.getenv("SECOPS_REPORT_DOCKER_TIMEOUT", "150")), 600))
            try:
                converted = subprocess.run(
                    command, cwd=str(ROOT_DIR), capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=docker_timeout, check=False,
                )
            except subprocess.TimeoutExpired as exc:
                _remove_docker_container(docker, container_name)
                raise RuntimeError(f"Report Docker conversion exceeded {docker_timeout}s and was stopped.") from exc

            if converted.returncode != 0 or not pdf_path.is_file() or pdf_path.stat().st_size <= 0:
                detail = "\n".join(
                    part for part in ((converted.stdout or "").strip(), (converted.stderr or "").strip()) if part
                )
                raise RuntimeError(f"Report Docker conversion failed with exit code {converted.returncode}. {detail[-2000:]}")
            print("WeasyPrint Docker fallback: PDF converted into", pdf_path, file=sys.stderr)
            return "weasyprint-docker"
        except Exception as exc:
            docker_error = exc
            pdf_path.unlink(missing_ok=True)
            print(f"Docker report fallback failed; trying Chromium: {type(exc).__name__}: {exc}", file=sys.stderr)
    else:
        docker_error = RuntimeError("Docker is unavailable for the report fallback.")

    try:
        _chromium_pdf(html_path, pdf_path)
        print("Chromium fallback: PDF converted into", pdf_path, file=sys.stderr)
        return "playwright-chromium"
    except Exception as chromium_error:
        raise RuntimeError(
            "All PDF renderers failed. "
            f"Native WeasyPrint: {type(native_error).__name__}: {native_error}; "
            f"Docker WeasyPrint: {type(docker_error).__name__}: {docker_error}; "
            f"Chromium: {type(chromium_error).__name__}: {chromium_error}"
        ) from chromium_error
