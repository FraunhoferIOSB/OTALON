"""``python -m otalon_scan.cve_lookup`` entry point.

Thin wrapper that delegates to :func:`entrypoint.main_sync`. Kept
separate from the package's ``__init__`` so importing
``otalon_scan.cve_lookup`` does not run the loop as a side effect.
"""

from __future__ import annotations

import sys

from .entrypoint import main_sync

if __name__ == "__main__":
    sys.exit(main_sync())
