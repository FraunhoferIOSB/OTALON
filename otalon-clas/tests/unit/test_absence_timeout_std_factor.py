"""Regression tests for standard-deviation-aware absence timeouts."""

from datetime import datetime, timedelta, timezone

import polars as pl
import pytest

from otalon_clas.detection.frequency_monitor import (
    ABSENCE_ANOMALY,
    FrequencyMonitor,
    _SeriesFrequencyProfile,
)

BASE = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)


def _monitor(mean: float, std: float) -> FrequencyMonitor:
    """Build monitor with one previously observed series profile."""
    monitor = FrequencyMonitor(absence_timeout_factor=3.0, absence_timeout_std_factor=3.0)
    monitor._profiles["s1"] = _SeriesFrequencyProfile(mean, std, last_seen=BASE)
    return monitor


def _has_absence(monitor: FrequencyMonitor, elapsed: float) -> bool:
    """Return whether silent check reports an absence anomaly."""
    results = monitor.check(pl.DataFrame(), "series", (BASE + timedelta(seconds=elapsed)).isoformat())
    return any(result.anomaly_type == ABSENCE_ANOMALY for result in results)


@pytest.mark.unit
def test_high_std_profile_allows_training_observed_tail() -> None:
    """High-jitter profile does not fire before mean plus three standard deviations."""
    monitor = _monitor(mean=44.4, std=41.8)

    assert not _has_absence(monitor, 160.0)


@pytest.mark.unit
def test_high_std_profile_still_detects_genuine_absence() -> None:
    """Silence beyond the standard-deviation-aware deadline still fires."""
    monitor = _monitor(mean=44.4, std=41.8)

    assert _has_absence(monitor, 200.0)


@pytest.mark.unit
def test_low_std_profile_keeps_mean_factor_deadline() -> None:
    """Periodic profile retains the longer mean-times-factor deadline."""
    monitor = _monitor(mean=44.4, std=1.0)

    assert not _has_absence(monitor, 133.0)
    assert _has_absence(monitor, 134.0)
