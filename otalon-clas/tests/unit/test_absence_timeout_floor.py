"""Unit tests for absence-timeout floor behavior."""

from datetime import datetime, timedelta, timezone

import polars as pl
import pytest

from otalon_clas.detection.frequency_monitor import (
    ABSENCE_ANOMALY,
    FrequencyMonitor,
    _SeriesFrequencyProfile,
)

BASE = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)


def _monitor(mean: float, floor: float) -> FrequencyMonitor:
    """Build monitor with one profiled, previously observed series."""
    monitor = FrequencyMonitor(absence_timeout_factor=3.0, absence_timeout_floor_seconds=floor)
    monitor._profiles["s1"] = _SeriesFrequencyProfile(mean, 0.0, last_seen=BASE)
    return monitor


def _check(monitor: FrequencyMonitor, elapsed: float) -> bool:
    """Return whether silent check reports absence."""
    results = monitor.check(pl.DataFrame(), "series", (BASE + timedelta(seconds=elapsed)).isoformat())
    return any(result.anomaly_type == ABSENCE_ANOMALY for result in results)


@pytest.mark.unit
def test_floor_blocks_short_timeout_until_floor() -> None:
    """A 45-second floor blocks at 10 seconds and fires at 50 seconds."""
    monitor = _monitor(1.0, 45.0)
    assert not _check(monitor, 10.0)
    assert _check(monitor, 50.0)


@pytest.mark.unit
def test_floor_does_not_shorten_long_timeout() -> None:
    """Naturally longer profile timeout remains unchanged."""
    monitor = _monitor(3600.0, 45.0)
    assert not _check(monitor, 10799.0)
    assert _check(monitor, 10801.0)


@pytest.mark.unit
def test_zero_floor_preserves_legacy_timeout() -> None:
    """Zero floor preserves raw mean-times-factor timeout."""
    monitor = _monitor(1.0, 0.0)
    assert not _check(monitor, 3.0)
    assert _check(monitor, 4.0)


@pytest.mark.unit
def test_floor_anchors_absence_since_at_floored_deadline() -> None:
    """Episode deadline uses floor and remains stable across checks."""
    monitor = _monitor(1.0, 45.0)
    first = monitor.check(pl.DataFrame(), "series", (BASE + timedelta(seconds=50)).isoformat())
    second = monitor.check(pl.DataFrame(), "series", (BASE + timedelta(seconds=100)).isoformat())
    assert first[0].absence_since == BASE + timedelta(seconds=45)
    assert second[0].absence_since == first[0].absence_since
