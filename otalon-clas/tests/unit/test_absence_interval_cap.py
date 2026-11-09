"""Unit tests for absence interval cap (CLAS-012).

Verifies that profiles whose ``mean_interval`` exceeds
``absence_interval_cap_seconds`` are excluded from absence monitoring.
"""

from datetime import datetime, timedelta, timezone

import polars as pl
import pytest

from otalon_clas.detection.frequency_monitor import (
    ABSENCE_ANOMALY,
    FrequencyMonitor,
    _SeriesFrequencyProfile,
)

BASE = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
CAP = 86400.0
FACTOR = 3.0


def _monitor(mean: float, cap: float = CAP) -> FrequencyMonitor:
    """Build monitor with one profiled, previously observed series."""
    monitor = FrequencyMonitor(absence_timeout_factor=FACTOR, absence_interval_cap_seconds=cap)
    monitor._profiles["s1"] = _SeriesFrequencyProfile(mean, 0.0, last_seen=BASE)
    return monitor


def _check(monitor: FrequencyMonitor, elapsed: float) -> bool:
    """Return whether silent check reports absence."""
    results = monitor.check(pl.DataFrame(), "series", (BASE + timedelta(seconds=elapsed)).isoformat())
    return any(result.anomaly_type == ABSENCE_ANOMALY for result in results)


@pytest.mark.unit
def test_below_cap_fires_normally() -> None:
    """Profile just below cap still fires absence when deadline is exceeded."""
    mean = CAP - 1.0
    timeout = mean * FACTOR
    monitor = _monitor(mean)
    assert not _check(monitor, timeout - 1.0)
    assert _check(monitor, timeout + 1.0)


@pytest.mark.unit
def test_at_cap_fires_normally() -> None:
    """Profile exactly at cap is still monitored."""
    timeout = CAP * FACTOR
    monitor = _monitor(CAP)
    assert not _check(monitor, timeout - 1.0)
    assert _check(monitor, timeout + 1.0)


@pytest.mark.unit
def test_above_cap_never_fires() -> None:
    """Profile just above cap never fires absence regardless of elapsed time."""
    monitor = _monitor(CAP + 1.0)
    assert not _check(monitor, CAP * FACTOR * 10)


@pytest.mark.unit
def test_zero_cap_disables_filtering() -> None:
    """A cap of 0 means no cap is applied."""
    mean = CAP * 2
    timeout = mean * FACTOR
    monitor = _monitor(mean, cap=0.0)
    assert not _check(monitor, timeout - 1.0)
    assert _check(monitor, timeout + 1.0)


@pytest.mark.unit
def test_capped_series_check_does_not_crash() -> None:
    """Cap filtering does not cause errors in the check path."""
    mean = CAP * 10
    monitor = _monitor(mean, cap=CAP)
    results = monitor.check(pl.DataFrame(), "series", (BASE + timedelta(seconds=1000)).isoformat())
    assert all(r.anomaly_type != ABSENCE_ANOMALY for r in results)