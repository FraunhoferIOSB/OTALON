"""Regression tests for the CVE lookup entrypoint supervisor loop.

Covers the Docker healthcheck liveness marker (F-01: the marker must be
touched in BOTH the enabled cycle path and the disabled idle path, since
``CVE_LOOKUP_ENABLED=false`` is the shipped default and idling is a
healthy, not a failed, state).
"""

from __future__ import annotations

import asyncio

import pytest

from otalon_scan.cve_lookup import entrypoint
from otalon_scan.cve_lookup.settings import CveLookupSettings


@pytest.mark.asyncio
async def test_main_touches_liveness_marker_when_disabled(tmp_path, monkeypatch):
    """``_main`` must touch the liveness marker while idling disabled.

    Without this, the Docker compose healthcheck (``find
    /tmp/cve-lookup-last-cycle -mmin -15``) never finds the marker file
    when ``CVE_LOOKUP_ENABLED=false`` (the shipped default), and the
    container is permanently reported ``unhealthy`` despite idling
    exactly as designed.
    """
    marker_path = tmp_path / "cve-lookup-last-cycle"
    monkeypatch.setattr(entrypoint, "LIVENESS_MARKER_PATH", marker_path)

    settings = CveLookupSettings(enabled=False, interval_s=86400)
    stop_event = asyncio.Event()

    async def _lookup_assets() -> list[object]:
        return []

    async def _persist(cycle_id: str, result: object) -> int:
        return 0

    async def _run_and_stop() -> None:
        await asyncio.sleep(0.05)
        stop_event.set()

    runner = asyncio.create_task(_run_and_stop())
    await entrypoint._main(
        settings=settings,
        lookup_assets_callable=_lookup_assets,
        persist_callable=_persist,
        stop_event=stop_event,
    )
    await runner

    assert marker_path.exists(), (
        "liveness marker was not touched while the worker idled disabled; "
        "the compose healthcheck would report this container unhealthy"
    )
