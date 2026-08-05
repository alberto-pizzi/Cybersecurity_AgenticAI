FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libpangoft2-1.0-0 \
    libgdk-pixbuf-2.0-0 libcairo2 libglib2.0-0 \
    fonts-dejavu-core \
    && ldconfig \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    "fastmcp==2.12.5" "requests>=2.32,<3" \
    "reportlab>=4.4,<5" "weasyprint>=63,<64"

# Fail the build (not a silent runtime warning) if WeasyPrint can't locate
# its native libraries (pango/cairo/gobject/gdk-pixbuf) inside this image.
RUN python -m weasyprint --info

WORKDIR /workspace