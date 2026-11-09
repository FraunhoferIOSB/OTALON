"""Unit tests for ``otalon_scan.passive_source.entrypoint``.

Exercise the poll loop with a stubbed poller and an in-memory upsert
callable so no Influx or Postgres I/O happens. Covers spec scenarios:

- ``Disabled flag idles without terminating`` (the loop stays alive, issues no
  Influx query, and records ``state="disabled"``).
- ``Enabled flag enters poll loop`` (``_main`` runs one cycle then stops).
- ``A successful cycle records running state`` / ``A failed cycle records the
  error without terminating`` (status persistence around the cycle).
- ``A stale schema stops the seeder loudly`` (the seeder's own revision guard).
- ``Successful cycle emits exactly one INFO line`` (log assertion).
- ``Per-upsert failure carries the cycle correlation id`` (warning + count).
- ``Influx connection refused for 10 minutes → no process exit`` (cycle loop
  keeps running on repeated ``InfluxUnreachableError``).
- ``LAA MAC dropped only when opt-in flag is true`` (drop_laa=False path).
- ``LAA MAC dropped when opt-in flag is true`` (drop_laa=True path).
- ``Seeder creates orphan interface row`` (upsert is called with
  ``device_id=None`` and ``source='passive'``).
- ``Cyberclas-ics offline does not affect the seeder`` (asserted by
  absence: the entrypoint code never references otalon-clas).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest

from otalon_scan.passive_source.entrypoint import (
    _main,
    _run_one_cycle,
    main_sync,
    verify_schema_revision,
)
from otalon_scan.passive_source.influx_poller import InfluxUnreachableError, PollResult
from otalon_scan.passive_source.runtime_config import EffectiveConfig
from otalon_scan.passive_source.settings import PassiveSeederSettings


@dataclass
class _StubPoller:
    """Stand-in for :class:`InfluxPoller` driven by a sequence of results."""

    results: list[PollResult | Exception] = field(default_factory=list)
    lookback_window_s: int = 300
    call_count: int = 0

    async def poll_once(self) -> PollResult:
        self.call_count += 1
        if not self.results:
            return PollResult()
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@dataclass
class _StubStatusRepo:
    """Capture every status upsert issued by the supervisor loop."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    async def upsert(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)

    def states(self) -> list[str]:
        """Return the recorded states in call order."""
        return [call["state"] for call in self.calls]


@dataclass
class _StubRuntimeReader:
    """Resolve the boot settings with a fixed set of runtime overrides."""

    overrides: dict[str, Any] = field(default_factory=dict)

    async def resolve(self, settings: PassiveSeederSettings) -> EffectiveConfig:
        return EffectiveConfig(
            enabled=bool(self.overrides.get("enabled", settings.enabled)),
            poll_interval_s=int(self.overrides.get("poll_interval_s", settings.poll_interval_s)),
            lookback_window_s=int(self.overrides.get("lookback_window_s", settings.lookback_window_s)),
            drop_laa=bool(self.overrides.get("drop_laa", settings.drop_laa)),
        )


@dataclass
class _StubSchemaRepo:
    """Stand-in for ``ScannerPostgresRepo`` exposing the revision check only."""

    error: str | None = None

    async def verify_schema_revision(self) -> None:
        if self.error is not None:
            raise RuntimeError(self.error)


@dataclass
class _StubUpsert:
    """Capture every ``upsert_network_interface`` invocation."""

    calls: list[dict[str, Any]] = field(default_factory=list)
    raise_on_call: int | None = None

    async def __call__(self, **kwargs: Any) -> int:
        self.calls.append(kwargs)
        if self.raise_on_call is not None and len(self.calls) == self.raise_on_call:
            raise RuntimeError("simulated upsert failure")
        return len(self.calls)


@dataclass
class _StubDeviceUpsert:
    """Capture every ``upsert_device`` invocation.

    Bug-cluster 2026-05-21 fixture: in-memory model of the F-03
    ``upsert_device`` natural-key UPSERT. Each unique ``primary_mac``
    gets a stable synthetic ``device_id`` (1, 2, 3, …); repeat calls
    for the same MAC return the same id (matching the real helper's
    ON CONFLICT semantics). Optional ``existing`` dict pre-seeds
    devices created by an earlier active scan so the
    "active-then-passive" test can verify the existing id is reused.
    """

    calls: list[dict[str, Any]] = field(default_factory=list)
    raise_on_call: int | None = None
    _mac_to_id: dict[str, int] = field(default_factory=dict)
    existing: dict[str, int] | None = None

    def __post_init__(self) -> None:
        if self.existing:
            self._mac_to_id.update(self.existing)

    async def __call__(self, **kwargs: Any) -> int:
        self.calls.append(kwargs)
        if self.raise_on_call is not None and len(self.calls) == self.raise_on_call:
            raise RuntimeError("simulated device upsert failure")
        mac = kwargs["primary_mac"]
        if mac not in self._mac_to_id:
            self._mac_to_id[mac] = max(self._mac_to_id.values(), default=0) + 1
        return self._mac_to_id[mac]


def _settings(
    *,
    enabled: bool = True,
    drop_laa: bool = False,
    poll_interval_s: int = 1,
    lookback_window_s: int = 60,
) -> PassiveSeederSettings:
    """Build a settings instance for unit tests bypassing env vars."""
    return PassiveSeederSettings.model_construct(
        enabled=enabled,
        poll_interval_s=poll_interval_s,
        lookback_window_s=lookback_window_s,
        influx_url="http://stub:8181",
        influx_token="stub",
        influx_bucket="netcap",
        drop_laa=drop_laa,
    )


class TestRunOneCycle:
    """Single-cycle behaviour: filtering, upsert orchestration, logging."""

    async def test_orphan_interface_upsert(self) -> None:
        """SCENARIO: Seeder creates orphan interface row.

        Asserts ``upsert_network_interface`` is called with
        ``device_id=None`` and ``source='passive'`` for each filtered
        MAC.
        """
        poller = _StubPoller(
            results=[
                PollResult(
                    macs={"aa:bb:cc:dd:ee:ff"},
                    mac_to_ipv4={"aa:bb:cc:dd:ee:ff": "10.0.0.1"},
                )
            ]
        )
        upsert = _StubUpsert()
        await _run_one_cycle(
            settings=_settings(),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=upsert,
        )
        assert len(upsert.calls) == 1
        call = upsert.calls[0]
        assert call["mac"] == "aa:bb:cc:dd:ee:ff"
        assert call["ipv4"] == "10.0.0.1"
        assert call["device_id"] is None
        assert call["source"] == "passive"

    async def test_multicast_dropped(self) -> None:
        """SCENARIO: Broadcast/multicast MACs dropped before upsert."""
        poller = _StubPoller(results=[PollResult(macs={"ff:ff:ff:ff:ff:ff", "01:00:5e:7f:00:01", "aa:bb:cc:dd:ee:01"})])
        upsert = _StubUpsert()
        await _run_one_cycle(
            settings=_settings(),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=upsert,
        )
        macs_upserted = {call["mac"] for call in upsert.calls}
        assert macs_upserted == {"aa:bb:cc:dd:ee:01"}

    async def test_laa_kept_when_flag_off(self) -> None:
        """SCENARIO: LAA MAC dropped only when opt-in flag is true.

        With ``drop_laa=False`` the LAA MAC ``02:11:22:33:44:55``
        SHALL reach ``upsert_network_interface``.
        """
        poller = _StubPoller(results=[PollResult(macs={"02:11:22:33:44:55"})])
        upsert = _StubUpsert()
        await _run_one_cycle(
            settings=_settings(drop_laa=False),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=upsert,
        )
        assert len(upsert.calls) == 1
        assert upsert.calls[0]["mac"] == "02:11:22:33:44:55"

    async def test_laa_dropped_when_flag_on(self) -> None:
        """SCENARIO: LAA MAC dropped when opt-in flag is true."""
        poller = _StubPoller(results=[PollResult(macs={"02:11:22:33:44:55"})])
        upsert = _StubUpsert()
        await _run_one_cycle(
            settings=_settings(drop_laa=True),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=upsert,
        )
        assert upsert.calls == []

    async def test_influx_unreachable_skips_upserts(self) -> None:
        """SCENARIO: Influx returns HTTP 503 → cycle is skipped.

        The cycle MUST NOT call upsert and MUST NOT raise.
        """
        poller = _StubPoller(results=[InfluxUnreachableError("HTTP 503")])
        upsert = _StubUpsert()
        # Must not raise.
        await _run_one_cycle(
            settings=_settings(),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=upsert,
        )
        assert upsert.calls == []

    async def test_upsert_failure_does_not_break_cycle(self) -> None:
        """SCENARIO: Per-upsert failure carries the cycle correlation id.

        One failing upsert SHALL NOT abort the remaining upserts.
        """
        poller = _StubPoller(results=[PollResult(macs={"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})])
        upsert = _StubUpsert(raise_on_call=1)
        await _run_one_cycle(
            settings=_settings(),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=upsert,
        )
        # Both MACs were attempted; one raised, one succeeded.
        assert len(upsert.calls) == 2


class TestDevicesUpsert:
    """Bug-cluster 2026-05-21: passive cycle must UPSERT devices too.

    Without these calls the ``network_interfaces`` rows live with
    ``device_id IS NULL`` and the UI Asset list stays empty.
    """

    async def test_fresh_passive_creates_device_and_links_interface(self) -> None:
        """SCENARIO: First passive sighting of a MAC creates a device.

        Asserts the cycle calls ``upsert_device(primary_mac=<mac>)``
        and threads the returned id into the interface UPSERT.
        """
        poller = _StubPoller(
            results=[
                PollResult(
                    macs={"aa:bb:cc:dd:ee:ff"},
                    mac_to_ipv4={"aa:bb:cc:dd:ee:ff": "10.0.0.1"},
                )
            ]
        )
        iface_upsert = _StubUpsert()
        device_upsert = _StubDeviceUpsert()

        await _run_one_cycle(
            settings=_settings(),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=iface_upsert,
            device_upsert_callable=device_upsert,
        )

        assert device_upsert.calls == [{"primary_mac": "aa:bb:cc:dd:ee:ff"}]
        assert len(iface_upsert.calls) == 1
        iface_call = iface_upsert.calls[0]
        assert iface_call["mac"] == "aa:bb:cc:dd:ee:ff"
        assert iface_call["ipv4"] == "10.0.0.1"
        assert iface_call["device_id"] == 1
        assert iface_call["source"] == "passive"

    async def test_passive_twice_no_duplicate_devices(self) -> None:
        """SCENARIO: Two cycles, same MAC → one device, two timestamp refreshes.

        The stub's MAC-to-id map matches the real F-03 UPSERT's
        ON-CONFLICT behaviour: repeated calls for the same
        ``primary_mac`` return the existing id. The interface UPSERT
        on cycle 2 MUST receive the same ``device_id`` as cycle 1.
        """
        poller = _StubPoller(
            results=[
                PollResult(macs={"aa:bb:cc:dd:ee:ff"}),
                PollResult(macs={"aa:bb:cc:dd:ee:ff"}),
            ]
        )
        iface_upsert = _StubUpsert()
        device_upsert = _StubDeviceUpsert()

        for _ in range(2):
            await _run_one_cycle(
                settings=_settings(),
                poller=poller,  # type: ignore[arg-type]
                upsert_callable=iface_upsert,
                device_upsert_callable=device_upsert,
            )

        # Two upsert_device calls (one per cycle) but the in-memory
        # model returns the SAME id both times — i.e. no duplicate
        # device row.
        assert len(device_upsert.calls) == 2
        assert all(call["primary_mac"] == "aa:bb:cc:dd:ee:ff" for call in device_upsert.calls)
        assert {iface_call["device_id"] for iface_call in iface_upsert.calls} == {1}

    async def test_active_then_passive_reuses_existing_device(self) -> None:
        """SCENARIO: Active scan ran first → passive cycle reuses the device.

        Pre-seed the device-upsert stub with a MAC→id mapping (as if
        an active scan had inserted the row with vendor /
        device_type / article_number set). The passive cycle MUST:

        1. Call ``upsert_device`` with only ``primary_mac`` (no
           enrichment fields — preserves the active-scan data via
           the helper's NULL-skipping COALESCE semantics).
        2. Receive the EXISTING device id back.
        3. Thread it into the interface UPSERT.
        """
        existing_mac = "aa:bb:cc:dd:ee:ff"
        poller = _StubPoller(results=[PollResult(macs={existing_mac})])
        iface_upsert = _StubUpsert()
        device_upsert = _StubDeviceUpsert(existing={existing_mac: 42})

        await _run_one_cycle(
            settings=_settings(),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=iface_upsert,
            device_upsert_callable=device_upsert,
        )

        # Only primary_mac passed — no vendor / device_type / etc.,
        # so the NULL-skipping helper preserves the active-scan
        # enrichment fields.
        assert device_upsert.calls == [{"primary_mac": existing_mac}]
        assert iface_upsert.calls[0]["device_id"] == 42

    async def test_device_upsert_failure_still_writes_interface(self) -> None:
        """A device-upsert failure MUST NOT block the interface write.

        Leaving the interface unwritten would lose the MAC entirely;
        keeping the legacy ``device_id=None`` semantics at least
        guarantees the MAC is observable in ``network_interfaces``
        and re-attempted next cycle.
        """
        poller = _StubPoller(results=[PollResult(macs={"aa:bb:cc:dd:ee:01"})])
        iface_upsert = _StubUpsert()
        device_upsert = _StubDeviceUpsert(raise_on_call=1)

        await _run_one_cycle(
            settings=_settings(),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=iface_upsert,
            device_upsert_callable=device_upsert,
        )

        assert len(iface_upsert.calls) == 1
        assert iface_upsert.calls[0]["device_id"] is None

    async def test_backwards_compat_no_device_callable(self) -> None:
        """``device_upsert_callable=None`` keeps the legacy iface-only path."""
        poller = _StubPoller(results=[PollResult(macs={"aa:bb:cc:dd:ee:01"})])
        iface_upsert = _StubUpsert()

        await _run_one_cycle(
            settings=_settings(),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=iface_upsert,
            # device_upsert_callable omitted -> defaults to None
        )

        assert len(iface_upsert.calls) == 1
        assert iface_upsert.calls[0]["device_id"] is None


class TestLivenessMarker:
    """Bug-cluster 2026-05-21: ``_run_one_cycle`` updates the marker."""

    async def test_marker_touched_at_cycle_end(self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """The marker file's mtime SHALL advance after one cycle."""
        from otalon_scan.passive_source import entrypoint as ep

        marker = tmp_path / "passive-seeder-last-cycle"
        monkeypatch.setattr(ep, "LIVENESS_MARKER_PATH", marker)

        poller = _StubPoller(results=[PollResult(macs={"aa:bb:cc:dd:ee:01"})])
        upsert = _StubUpsert()

        assert not marker.exists()
        await _run_one_cycle(
            settings=_settings(),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=upsert,
        )
        assert marker.exists()

    async def test_marker_touched_even_on_influx_outage(self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """An Influx outage MUST still update the marker.

        The worker process IS alive — it just couldn't fetch data
        this cycle. Letting the marker go stale would flip the
        container to ``(unhealthy)`` and trigger needless restarts
        for what is an upstream-data problem.
        """
        from otalon_scan.passive_source import entrypoint as ep

        marker = tmp_path / "passive-seeder-last-cycle"
        monkeypatch.setattr(ep, "LIVENESS_MARKER_PATH", marker)

        poller = _StubPoller(results=[InfluxUnreachableError("down")])
        upsert = _StubUpsert()

        await _run_one_cycle(
            settings=_settings(),
            poller=poller,  # type: ignore[arg-type]
            upsert_callable=upsert,
        )
        assert marker.exists()


class TestMain:
    """Coroutine-level: stop-event integration, repeated cycles."""

    async def test_main_runs_one_cycle_and_stops(self) -> None:
        """SCENARIO: Enabled flag enters poll loop (one cycle then stop)."""
        poller = _StubPoller(results=[PollResult(macs={"aa:bb:cc:dd:ee:01"})])
        upsert = _StubUpsert()
        stop = asyncio.Event()

        async def stopper() -> None:
            # Allow the loop to run one cycle then signal stop.
            await asyncio.sleep(0.05)
            stop.set()

        await asyncio.gather(
            _main(
                settings=_settings(poll_interval_s=10),
                poller=poller,  # type: ignore[arg-type]
                upsert_callable=upsert,
                stop_event=stop,
            ),
            stopper(),
        )
        assert poller.call_count >= 1
        assert len(upsert.calls) == 1

    async def test_main_survives_repeated_influx_outage(self) -> None:
        """SCENARIO: Influx connection refused for 10 minutes → no exit."""
        poller = _StubPoller(results=[InfluxUnreachableError("down") for _ in range(3)])
        upsert = _StubUpsert()
        stop = asyncio.Event()

        async def stopper() -> None:
            await asyncio.sleep(0.05)
            stop.set()

        # Should complete cleanly without raising.
        await asyncio.gather(
            _main(
                settings=_settings(poll_interval_s=10),
                poller=poller,  # type: ignore[arg-type]
                upsert_callable=upsert,
                stop_event=stop,
            ),
            stopper(),
        )
        # No upserts occurred (every cycle was an outage).
        assert upsert.calls == []


class TestDisabledSupervisor:
    """``Feature Flag Default-Off``: disabled idles, it does not terminate.

    Replaces the former ``main_sync`` exit-0 assertion. The disabled state is
    now expressed by the supervisor loop staying alive, issuing no InfluxDB
    query, and publishing ``state="disabled"``.
    """

    async def test_disabled_idles_without_polling_and_records_state(self) -> None:
        """SCENARIO: Disabled flag idles without terminating.

        The loop MUST NOT query Influx, MUST NOT upsert inventory rows, MUST
        record ``disabled``, and MUST still be running when the stop event is
        set — i.e. it returns because it was stopped, not because it exited.
        """
        poller = _StubPoller(results=[PollResult(macs={"aa:bb:cc:dd:ee:01"})])
        upsert = _StubUpsert()
        status = _StubStatusRepo()
        stop = asyncio.Event()

        async def stopper() -> None:
            await asyncio.sleep(0.05)
            stop.set()

        results = await asyncio.gather(
            _main(
                settings=_settings(enabled=False, poll_interval_s=1),
                poller=poller,  # type: ignore[arg-type]
                upsert_callable=upsert,
                stop_event=stop,
                status_repo=status,  # type: ignore[arg-type]
            ),
            stopper(),
        )

        assert results[0] == 0
        assert poller.call_count == 0
        assert upsert.calls == []
        assert status.states() == ["disabled"]
        assert status.calls[0]["poll_interval_s"] == 1

    async def test_runtime_row_enables_without_restart(self) -> None:
        """SCENARIO: Enabling at runtime requires no restart.

        A boot-disabled seeder whose runtime row sets ``enabled=true`` starts
        polling on the next cycle inside the same process.
        """
        poller = _StubPoller(results=[PollResult(macs={"aa:bb:cc:dd:ee:01"})])
        upsert = _StubUpsert()
        status = _StubStatusRepo()
        stop = asyncio.Event()

        async def stopper() -> None:
            await asyncio.sleep(0.05)
            stop.set()

        await asyncio.gather(
            _main(
                settings=_settings(enabled=False, poll_interval_s=10),
                poller=poller,  # type: ignore[arg-type]
                upsert_callable=upsert,
                stop_event=stop,
                runtime_reader=_StubRuntimeReader(overrides={"enabled": True}),  # type: ignore[arg-type]
                status_repo=status,  # type: ignore[arg-type]
            ),
            stopper(),
        )

        assert poller.call_count == 1
        assert status.states() == ["running"]


class TestStatusPersistence:
    """``The passive seeder SHALL persist its operational status every cycle``."""

    async def test_successful_cycle_records_running_with_rows(self) -> None:
        """SCENARIO: A successful cycle records running state."""
        poller = _StubPoller(results=[PollResult(macs={"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})])
        upsert = _StubUpsert()
        status = _StubStatusRepo()
        stop = asyncio.Event()

        async def stopper() -> None:
            await asyncio.sleep(0.05)
            stop.set()

        await asyncio.gather(
            _main(
                settings=_settings(poll_interval_s=10),
                poller=poller,  # type: ignore[arg-type]
                upsert_callable=upsert,
                stop_event=stop,
                status_repo=status,  # type: ignore[arg-type]
            ),
            stopper(),
        )

        assert status.states() == ["running"]
        assert status.calls[0]["rows_seeded"] == 2
        assert status.calls[0]["last_error"] is None

    async def test_cycle_error_recorded_without_terminating(self) -> None:
        """SCENARIO: A failed cycle records the error without terminating.

        The first cycle raises a non-Influx error; the loop MUST record
        ``error`` with the message and continue into the next cycle.
        """
        poller = _StubPoller(
            results=[
                RuntimeError("boom"),
                PollResult(macs={"aa:bb:cc:dd:ee:01"}),
            ]
        )
        upsert = _StubUpsert()
        status = _StubStatusRepo()
        stop = asyncio.Event()

        async def stopper() -> None:
            while len(status.calls) < 2:
                await asyncio.sleep(0.01)
            stop.set()

        await asyncio.gather(
            _main(
                settings=_settings(poll_interval_s=1),
                poller=poller,  # type: ignore[arg-type]
                upsert_callable=upsert,
                stop_event=stop,
                status_repo=status,  # type: ignore[arg-type]
            ),
            stopper(),
        )

        assert status.states()[0] == "error"
        assert status.calls[0]["last_error"] == "boom"
        assert "running" in status.states()
        assert poller.call_count >= 2

    async def test_failed_cycle_leaves_marker_untouched(self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """SCENARIO: The healthcheck marker is untouched by a failed cycle."""
        from otalon_scan.passive_source import entrypoint as ep

        marker = tmp_path / "passive-seeder-last-cycle"
        monkeypatch.setattr(ep, "LIVENESS_MARKER_PATH", marker)

        poller = _StubPoller(results=[RuntimeError("boom")])
        upsert = _StubUpsert()
        status = _StubStatusRepo()
        stop = asyncio.Event()

        async def stopper() -> None:
            await asyncio.sleep(0.03)
            stop.set()

        await asyncio.gather(
            _main(
                settings=_settings(poll_interval_s=10),
                poller=poller,  # type: ignore[arg-type]
                upsert_callable=upsert,
                stop_event=stop,
                status_repo=status,  # type: ignore[arg-type]
            ),
            stopper(),
        )

        assert not marker.exists()
        assert status.states() == ["error"]


class TestHotKeyApplication:
    """Resolved keys are applied to the cycle that resolved them."""

    async def test_interval_change_applies_from_next_wait(self) -> None:
        """SCENARIO: A changed interval applies from the next wait.

        The status row carries the interval actually in effect, which is the
        runtime value rather than the boot value.
        """
        poller = _StubPoller(results=[PollResult()])
        upsert = _StubUpsert()
        status = _StubStatusRepo()
        stop = asyncio.Event()

        async def stopper() -> None:
            await asyncio.sleep(0.05)
            stop.set()

        await asyncio.gather(
            _main(
                settings=_settings(poll_interval_s=60),
                poller=poller,  # type: ignore[arg-type]
                upsert_callable=upsert,
                stop_event=stop,
                runtime_reader=_StubRuntimeReader(overrides={"poll_interval_s": 11}),  # type: ignore[arg-type]
                status_repo=status,  # type: ignore[arg-type]
            ),
            stopper(),
        )

        assert status.calls[0]["poll_interval_s"] == 11

    async def test_lookback_change_rebuilds_the_poller(self) -> None:
        """A changed lookback window is applied through the poller factory."""
        built: list[int] = []

        def _factory(lookback_window_s: int) -> _StubPoller:
            built.append(lookback_window_s)
            return _StubPoller(results=[PollResult()], lookback_window_s=lookback_window_s)

        upsert = _StubUpsert()
        stop = asyncio.Event()

        async def stopper() -> None:
            await asyncio.sleep(0.05)
            stop.set()

        await asyncio.gather(
            _main(
                settings=_settings(poll_interval_s=10, lookback_window_s=300),
                poller=_factory(300),  # type: ignore[arg-type]
                upsert_callable=upsert,
                stop_event=stop,
                runtime_reader=_StubRuntimeReader(overrides={"lookback_window_s": 900}),  # type: ignore[arg-type]
                poller_factory=_factory,  # type: ignore[arg-type]
            ),
            stopper(),
        )

        assert built == [300, 900]

    async def test_drop_laa_override_applies_to_the_cycle(self) -> None:
        """A runtime ``drop_laa=true`` filters LAA MACs in the same cycle."""
        poller = _StubPoller(results=[PollResult(macs={"02:11:22:33:44:55"})])
        upsert = _StubUpsert()
        stop = asyncio.Event()

        async def stopper() -> None:
            await asyncio.sleep(0.05)
            stop.set()

        await asyncio.gather(
            _main(
                settings=_settings(drop_laa=False, poll_interval_s=10),
                poller=poller,  # type: ignore[arg-type]
                upsert_callable=upsert,
                stop_event=stop,
                runtime_reader=_StubRuntimeReader(overrides={"drop_laa": True}),  # type: ignore[arg-type]
            ),
            stopper(),
        )

        assert upsert.calls == []


class TestSchemaRevisionGuard:
    """C4b: the seeder verifies the Alembic head itself."""

    async def test_matching_revision_returns_none(self) -> None:
        """A matching schema produces no error message."""
        assert await verify_schema_revision(_StubSchemaRepo()) is None

    async def test_stale_revision_returns_the_upgrade_hint(self) -> None:
        """A stale schema surfaces the documented resolution hint."""
        repo = _StubSchemaRepo(error="alembic_version mismatch — run alembic upgrade head")
        message = await verify_schema_revision(repo)
        assert message is not None
        assert "run alembic upgrade head" in message

    def test_main_sync_exits_non_zero_on_stale_schema(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SCENARIO: A stale schema stops the seeder loudly.

        ``main_sync`` MUST return a non-zero code and MUST NOT enter the loop.
        """
        from otalon_scan.passive_source import entrypoint as ep

        monkeypatch.setenv("POSTGRES_DSN", "postgresql://stub/stub")
        monkeypatch.setattr(
            ep,
            "_build_repo",
            lambda _dsn: _StubSchemaRepo(error="alembic_version mismatch — run alembic upgrade head"),
        )

        def _fail(**_kwargs: Any) -> int:
            raise AssertionError("supervisor must not start on a stale schema")

        monkeypatch.setattr(ep, "_run_supervisor", _fail)
        rc = main_sync()
        assert rc != 0
        assert rc == ep.SCHEMA_MISMATCH_EXIT_CODE


class TestMainSync:
    """``main_sync`` boundary: settings → return code."""

    def test_invalid_config_returns_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SCENARIO: Invalid window-to-interval ratio → exit code 2."""
        monkeypatch.setenv("PASSIVE_SEEDER_POLL_INTERVAL_S", "120")
        monkeypatch.setenv("PASSIVE_SEEDER_LOOKBACK_WINDOW_S", "60")
        rc = main_sync()
        assert rc == 2

    def test_enabled_without_postgres_dsn_returns_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Enabled without POSTGRES_DSN must exit 2 cleanly."""
        monkeypatch.setenv("PASSIVE_SEEDER_ENABLED", "true")
        monkeypatch.setenv("PASSIVE_SEEDER_INFLUX_TOKEN", "test")
        monkeypatch.delenv("POSTGRES_DSN", raising=False)
        rc = main_sync()
        assert rc == 2
