"""Unit tests for absence-episode hysteresis.

Regression cover for a live defect: during a sustained ettercap MitM the
victim connection produced ~8 short ``AbsenceAnomaly`` rows instead of
one continuous episode. ettercap *relays* packets rather than cutting
the link, so the series dipped past its absence deadline, received a
stray relayed packet, and dipped again. Each dip recomputed the deadline
from the new ``last_seen``, which is the key of the persisted row, so
every dip minted a new row.

The fix freezes the deadline anchor for the duration of an episode and
requires ``absence_recovery_cycles`` consecutive observed cycles before
the episode is considered closed. These tests pin both halves: one
silence with a stray packet stays ONE episode, and two genuinely
separate silences stay TWO.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import polars as pl
import pytest

from otalon_clas.common.postgres_connector import AnomalyRecord, PostgresConnector
from otalon_clas.detection.anomaly_persister import AnomalyPersister
from otalon_clas.detection.frequency_monitor import (
    ABSENCE_ANOMALY,
    DEFAULT_ABSENCE_RECOVERY_CYCLES,
    FrequencyMonitor,
    FrequencyResult,
    _SeriesFrequencyProfile,
)

BASE = datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)
MEAN_INTERVAL = 4.2
"""Cadence of the live victim series the defect was observed on."""

ABSENCE_FACTOR = 3.0
TIMEOUT_S = MEAN_INTERVAL * ABSENCE_FACTOR
TICK_S = 5.0
"""Live detection poll interval."""

SERIES = "80:39:e5:00:ab:d2/a8:74:1d:18:c6:96//IPv4/192.168.0.77/192.168.0.10/80/*/Ethernet:IPv4:TCP"


def _monitor(recovery_cycles: int | None = None) -> FrequencyMonitor:
    """Build a monitor with the live absence factor and one profile."""
    monitor = FrequencyMonitor(
        frequency_tolerance_factor=2.0,
        absence_timeout_factor=ABSENCE_FACTOR,
        absence_recovery_cycles=recovery_cycles,
    )
    monitor._profiles[SERIES] = _SeriesFrequencyProfile(
        mean_interval=MEAN_INTERVAL,
        std_interval=0.4,
        last_seen=BASE,
    )
    return monitor


def _observation(at: datetime) -> pl.DataFrame:
    """Build a one-row observation frame for the victim series."""
    return pl.DataFrame({"uci": [SERIES], "time": [at]})


def _silent_tick(monitor: FrequencyMonitor, at: datetime) -> list[FrequencyResult]:
    """Run one detection cycle in which the series is not observed."""
    return monitor.check(pl.DataFrame(), "uci", at.isoformat())


def _observed_tick(monitor: FrequencyMonitor, at: datetime) -> list[FrequencyResult]:
    """Run one detection cycle in which the series IS observed."""
    return monitor.check(_observation(at), "uci", at.isoformat())


def _absence_anchors(results: list[FrequencyResult]) -> list[datetime]:
    """Extract the absence deadlines of the absence results."""
    return [r.absence_since for r in results if r.anomaly_type == ABSENCE_ANOMALY and r.absence_since is not None]


class TestOneSilenceIsOneEpisode:
    """A stray packet mid-silence must not split the episode."""

    @pytest.mark.unit
    def test_stray_packet_does_not_reanchor_the_episode(self) -> None:
        """Silence → one relayed packet → silence yields ONE anchor.

        This is the exact live shape: the disruption never fully stops
        traffic, it only thins it below the cadence.
        """
        monitor = _monitor()
        anchors: list[datetime] = []
        at = BASE

        for _ in range(12):
            at += timedelta(seconds=TICK_S)
            anchors.extend(_absence_anchors(_silent_tick(monitor, at)))

        at += timedelta(seconds=TICK_S)
        _observed_tick(monitor, at)

        for _ in range(12):
            at += timedelta(seconds=TICK_S)
            anchors.extend(_absence_anchors(_silent_tick(monitor, at)))

        assert len(set(anchors)) == 1
        assert anchors[0] == BASE + timedelta(seconds=TIMEOUT_S)

    @pytest.mark.unit
    def test_repeated_blips_still_yield_one_episode(self) -> None:
        """Several stray packets across one disruption stay one episode."""
        monitor = _monitor()
        anchors: list[datetime] = []
        at = BASE

        for blip in range(4):
            for _ in range(8):
                at += timedelta(seconds=TICK_S)
                anchors.extend(_absence_anchors(_silent_tick(monitor, at)))
            at += timedelta(seconds=TICK_S)
            _observed_tick(monitor, at)

        assert len(set(anchors)) == 1

    @pytest.mark.unit
    def test_a_short_burst_below_the_recovery_floor_does_not_close_it(self) -> None:
        """Fewer than ``absence_recovery_cycles`` observations keep it open."""
        monitor = _monitor()
        at = BASE

        for _ in range(10):
            at += timedelta(seconds=TICK_S)
            first = _absence_anchors(_silent_tick(monitor, at))

        for _ in range(DEFAULT_ABSENCE_RECOVERY_CYCLES - 1):
            at += timedelta(seconds=TICK_S)
            _observed_tick(monitor, at)

        for _ in range(10):
            at += timedelta(seconds=TICK_S)
            second = _absence_anchors(_silent_tick(monitor, at))

        assert first == second


class TestGenuinelySeparateEpisodesSurvive:
    """Hysteresis must not merge distinct outages."""

    @pytest.mark.unit
    def test_restored_rhythm_closes_the_episode(self) -> None:
        """A full recovery streak lets the next silence open a new row."""
        monitor = _monitor()
        at = BASE

        for _ in range(10):
            at += timedelta(seconds=TICK_S)
            first = _absence_anchors(_silent_tick(monitor, at))

        for _ in range(DEFAULT_ABSENCE_RECOVERY_CYCLES):
            at += timedelta(seconds=TICK_S)
            _observed_tick(monitor, at)
        recovered_at = at

        for _ in range(10):
            at += timedelta(seconds=TICK_S)
            second = _absence_anchors(_silent_tick(monitor, at))

        assert first[0] != second[0]
        assert second[0] == recovered_at + timedelta(seconds=TIMEOUT_S)

    @pytest.mark.unit
    def test_hysteresis_can_be_disabled(self) -> None:
        """``absence_recovery_cycles=1`` restores the legacy behaviour."""
        monitor = _monitor(recovery_cycles=1)
        at = BASE

        for _ in range(10):
            at += timedelta(seconds=TICK_S)
            first = _absence_anchors(_silent_tick(monitor, at))

        at += timedelta(seconds=TICK_S)
        _observed_tick(monitor, at)
        resumed_at = at

        for _ in range(10):
            at += timedelta(seconds=TICK_S)
            second = _absence_anchors(_silent_tick(monitor, at))

        assert first[0] != second[0]
        assert second[0] == resumed_at + timedelta(seconds=TIMEOUT_S)


class TestEpisodeStateHygiene:
    """The episode map must not leak or outlive its profiles."""

    @pytest.mark.unit
    def test_episode_is_dropped_when_the_profile_disappears(self) -> None:
        """A retrained-away series does not keep an episode forever."""
        monitor = _monitor()
        at = BASE + timedelta(seconds=TICK_S * 10)
        _silent_tick(monitor, at)
        assert SERIES in monitor._absence_episodes

        monitor._profiles = {}
        _silent_tick(monitor, at + timedelta(seconds=TICK_S))

        assert monitor._absence_episodes == {}

    @pytest.mark.unit
    def test_a_healthy_series_never_creates_an_episode(self) -> None:
        """No silence, no episode state."""
        monitor = _monitor()
        at = BASE

        for _ in range(10):
            at += timedelta(seconds=TICK_S)
            _observed_tick(monitor, at)

        assert monitor._absence_episodes == {}


class TestPersistedRowCount:
    """The end-to-end effect: one disruption, one ``anomalies`` row."""

    def _persist_all(self, tmp_path: Path, results_per_tick: list[tuple[datetime, list[FrequencyResult]]]) -> int:
        """Persist every tick's results and return the resulting row count."""
        db_path = tmp_path / "anomalies.sqlite"
        pg = PostgresConnector(dsn=f"sqlite:///{db_path}", pool_size=1, max_overflow=0)
        AnomalyRecord.__table__.create(pg.engine, checkfirst=True)
        persister = AnomalyPersister(connector=pg)
        for observed_at, results in results_per_tick:
            persister.persist_absence(results, "conn", observed_at)
        with pg.session() as session:
            return session.query(AnomalyRecord).count()

    @pytest.mark.unit
    def test_flickering_disruption_persists_as_one_row(self, tmp_path: Path) -> None:
        """The live ~8-row symptom collapses to a single row."""
        monitor = _monitor()
        ticks: list[tuple[datetime, list[FrequencyResult]]] = []
        at = BASE

        for _ in range(6):
            for _ in range(8):
                at += timedelta(seconds=TICK_S)
                ticks.append((at, _silent_tick(monitor, at)))
            at += timedelta(seconds=TICK_S)
            ticks.append((at, _observed_tick(monitor, at)))

        assert self._persist_all(tmp_path, ticks) == 1

    @pytest.mark.unit
    def test_without_hysteresis_the_same_run_produces_many_rows(self, tmp_path: Path) -> None:
        """Pins the defect: the legacy behaviour really did flicker."""
        monitor = _monitor(recovery_cycles=1)
        ticks: list[tuple[datetime, list[FrequencyResult]]] = []
        at = BASE

        for _ in range(6):
            for _ in range(8):
                at += timedelta(seconds=TICK_S)
                ticks.append((at, _silent_tick(monitor, at)))
            at += timedelta(seconds=TICK_S)
            ticks.append((at, _observed_tick(monitor, at)))

        assert self._persist_all(tmp_path, ticks) > 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
