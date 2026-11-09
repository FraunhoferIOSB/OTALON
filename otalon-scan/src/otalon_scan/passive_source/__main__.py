"""``python -m otalon_scan.passive_source`` entry point.

Thin wrapper that delegates to :func:`entrypoint.main_sync`. Kept
separate from the package's ``__init__`` so importing
``otalon_scan.passive_source`` does not run the seeder as a side effect.
"""

from __future__ import annotations

import sys

from .entrypoint import main_sync

if __name__ == "__main__":
    sys.exit(main_sync())
