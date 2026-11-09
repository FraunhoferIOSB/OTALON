"""Tests for frequency-monitor series exclusions."""

from datetime import datetime

import polars as pl

from otalon_clas.detection.frequency_monitor import FrequencyMonitor, _SeriesFrequencyProfile


def test_multicast_blacklist_excludes_absence_but_not_unicast() -> None:
    """IPv6 multicast MACs are excluded while unicast MACs remain checked."""
    monitor = FrequencyMonitor(absence_timeout_factor=1.0, blacklist=["33:33:*"])
    last_seen = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    monitor._profiles = {
        "33:33:00:00:00:02": _SeriesFrequencyProfile(10.0, 1.0, last_seen=last_seen),
        "aa:bb:cc:dd:ee:ff": _SeriesFrequencyProfile(10.0, 1.0, last_seen=last_seen),
    }

    results = monitor.check(
        pl.DataFrame({"time": [], "mac_address": []}),
        tag_key="mac_address",
        current_time="2026-01-01T00:00:20",
    )

    assert [result.series_id for result in results] == ["aa:bb:cc:dd:ee:ff"]
    assert results[0].anomaly_type == "AbsenceAnomaly"
