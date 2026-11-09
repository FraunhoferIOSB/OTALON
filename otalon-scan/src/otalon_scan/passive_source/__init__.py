"""Passive asset seeder package for otalon-scan.

This package implements the ``add-passive-asset-seeder`` OpenSpec
change. It periodically queries InfluxDB for MAC and UCI tags written
by ``otalon-capture`` and projects them into the ``otalon-scan``
PostgreSQL inventory via the existing F-03 ``upsert_network_interface``
helper with ``source='passive'``.

The package is intentionally consumed as a standalone process (its own
docker-compose service ``otalon-scan-passive-seeder``) rather than a
thread inside the FastAPI process — see design.md decision
``D-WORKER-PLACEMENT`` for the rationale. The container entry point is
``python -m otalon_scan.passive_source`` (matching the workspace-wide
convention that otalon-scan imports live under ``src.*``; the
spec/design text uses the ``cyberscan_ics.passive_source`` namespace,
which is treated as the logical name — the on-disk module path
follows the established layout).

Public symbols:

- :class:`PassiveSeederSettings` — Pydantic v2 settings model.
- :class:`InfluxPoller`        — single-cycle Influx reader.
- :class:`PollResult`          — dataclass returned by ``poll_once``.
- :func:`run`                  — async entrypoint of the poll loop.
"""

from __future__ import annotations

from .influx_poller import InfluxPoller, InfluxUnreachableError, PollResult
from .settings import PassiveSeederSettings

__all__ = [
    "InfluxPoller",
    "InfluxUnreachableError",
    "PassiveSeederSettings",
    "PollResult",
    "run",
]


def run() -> int:
    """Synchronous entry-point wrapper around the async ``_main``.

    Exposed at package level so external callers (tests, ad-hoc
    scripts) can invoke the seeder without importing the private
    ``__main__`` module. The compose service launches the seeder via
    ``python -m otalon_scan.passive_source``, which routes through
    ``__main__.py`` and ultimately calls the same ``_main`` coroutine.
    """
    from .entrypoint import main_sync

    return main_sync()
