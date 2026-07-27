from __future__ import annotations

"""Compatibility entrypoint for macOS.

The complete cross-platform implementation lives in initScript.py so Windows
and macOS cannot silently diverge again.
"""

from initScript import main


if __name__ == "__main__":
    raise SystemExit(main())
