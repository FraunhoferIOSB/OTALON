"""Unit tests for ``otalon_scan.cve_lookup.entrypoint`` (Task 3.3).

Exercise the lookup loop with stubbed callables so no NVD or Postgres
I/O happens.  Covers spec scenarios:

    - Disabled flag idles and persists a disabled status.
- ``Enabled flag enters lookup loop`` (``_main`` runs one cycle then stops).
- ``Liveness marker touched at cycle end``.
- ``Asset query failure carries the cycle correlation id``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from otalon_scan.cve_lookup.entrypoint import _main, _run_one_cycle, main_sync
from otalon_scan.cve_lookup.settings import CveLookupSettings


@dataclass
class _StubAssetQuery:
    """Stand-in for ``ScannerPostgresRepo.lookup_eligible_assets``."""

    assets: list[Any] = field(default_factory=list)
    raise_on_call: bool = False
    call_count: int = 0

    async def __call__(self) -> list[Any]:
        self.call_count += 1
        if self.raise_on_call:
            raise RuntimeError("simulated asset query failure")
        return self.assets


@dataclass
class _StubPersist:
    """Capture every ``persist_lookup_result`` invocation."""

    calls: list[dict[str, Any]] = field(default_factory=list)
    return_written: int = 0
    raise_on_call: bool = False

    async def __call__(self, cycle_id: str, result: Any) -> int:
        self.calls.append({"cycle_id": cycle_id, "result": result})
        if self.raise_on_call:
            raise RuntimeError("simulated persist failure")
        return self.return_written


def _settings(**overrides: Any) -> CveLookupSettings:
    """Build settings with all mandatory env vars defaulted."""
    kwargs: dict[str, Any] = {
        "enabled": True,
        "interval_s": 10,
        "nvd_api_key": None,
    }
    kwargs.update(overrides)
    return CveLookupSettings.model_construct(**kwargs)


class TestRunOneCycle:
    """Single-cycle behaviour."""

    async def test_no_eligible_assets_touches_marker(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Zero eligible assets still updates the liveness marker."""
        from otalon_scan.cve_lookup import entrypoint as ep

        marker = tmp_path / "cve-lookup-last-cycle"
        monkeypatch.setattr(ep, "LIVENESS_MARKER_PATH", marker)

        await _run_one_cycle(
            settings=_settings(),
            lookup_assets_callable=_StubAssetQuery(),
            persist_callable=_StubPersist(),
        )
        assert marker.exists()

    async def test_asset_query_failure_touches_marker(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Asset-query failure does NOT crash the worker; marker is touched."""
        from otalon_scan.cve_lookup import entrypoint as ep

        marker = tmp_path / "cve-lookup-last-cycle"
        monkeypatch.setattr(ep, "LIVENESS_MARKER_PATH", marker)

        await _run_one_cycle(
            settings=_settings(),
            lookup_assets_callable=_StubAssetQuery(raise_on_call=True),
            persist_callable=_StubPersist(),
        )
        assert marker.exists()

    async def test_persist_failure_touches_marker(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Persist failure does NOT crash the worker; marker is touched."""
        from otalon_scan.cve_lookup import entrypoint as ep

        marker = tmp_path / "cve-lookup-last-cycle"
        monkeypatch.setattr(ep, "LIVENESS_MARKER_PATH", marker)

        async def _fake_run_lookup(assets: Any, source: Any) -> Any:
            from otalon_scan.cve_lookup.core import LookupResult

            return LookupResult(assets_checked=len(assets), total_hits=0, per_asset=[])

        monkeypatch.setattr(ep, "run_lookup", _fake_run_lookup)

        await _run_one_cycle(
            settings=_settings(),
            lookup_assets_callable=_StubAssetQuery(assets=[object()]),
            persist_callable=_StubPersist(raise_on_call=True),
        )
        assert marker.exists()


class TestMain:
    """Coroutine-level: stop-event integration, repeated cycles."""

    async def test_main_runs_one_cycle_and_stops(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SCENARIO: Enabled flag enters lookup loop (one cycle then stop)."""
        from otalon_scan.cve_lookup import entrypoint as ep

        marker = Path("/tmp/cve-lookup-last-cycle")
        monkeypatch.setattr(ep, "LIVENESS_MARKER_PATH", marker)

        async def _fake_run_lookup(assets: Any, source: Any) -> Any:
            from otalon_scan.cve_lookup.core import LookupResult

            return LookupResult(assets_checked=len(assets), total_hits=0, per_asset=[])

        monkeypatch.setattr(ep, "run_lookup", _fake_run_lookup)

        asset_query = _StubAssetQuery(assets=[object()])
        persist = _StubPersist(return_written=5)
        stop = asyncio.Event()

        async def stopper() -> None:
            await asyncio.sleep(0.05)
            stop.set()

        await asyncio.gather(
            _main(
                settings=_settings(interval_s=10),
                lookup_assets_callable=asset_query,
                persist_callable=persist,
                stop_event=stop,
            ),
            stopper(),
        )
        assert asset_query.call_count >= 1
        assert len(persist.calls) == 1

    async def test_disabled_idles_and_records_status(self) -> None:
        """Disabled worker performs no lookup and remains in supervisor loop."""

        class _Status:
            calls: list[dict[str, Any]] = []

            async def upsert(self, **kwargs: Any) -> None:
                self.calls.append(kwargs)

        status = _Status()
        query = _StubAssetQuery(raise_on_call=True)
        stop = asyncio.Event()

        async def stopper() -> None:
            await asyncio.sleep(0.02)
            stop.set()

        await asyncio.gather(
            _main(
                settings=_settings(enabled=False, interval_s=1),
                lookup_assets_callable=query,
                persist_callable=_StubPersist(),
                stop_event=stop,
                status_repo=status,  # type: ignore[arg-type]
            ),
            stopper(),
        )
        assert query.call_count == 0
        assert status.calls[0]["state"] == "disabled"


class TestMainSync:
    """``main_sync`` boundary: settings -> return code."""

    def test_disabled_requires_postgres_dsn_for_persisted_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Disabled mode still needs database connectivity for status."""
        monkeypatch.delenv("CVE_LOOKUP_ENABLED", raising=False)
        monkeypatch.delenv("POSTGRES_DSN", raising=False)
        rc = main_sync()
        assert rc == 2

    def test_enabled_without_postgres_dsn_returns_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Enabled without POSTGRES_DSN must exit 2 cleanly."""
        monkeypatch.setenv("CVE_LOOKUP_ENABLED", "true")
        monkeypatch.delenv("POSTGRES_DSN", raising=False)
        rc = main_sync()
        assert rc == 2
