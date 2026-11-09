"""Regression tests for robust proto FrequencyAnomaly tuning (CLAS-009).

These tests reproduce the permanent false-positive flood the
``proto_traffic`` module fired on strictly periodic real-time traffic
(PROFINET_RT_IO / PROFINET_RT_PTCP). The detector runs on aggregated
buckets, so a single late or missing bucket is normal jitter, not an
anomaly. The robust-tune fix (minimum sample count + mean-relative
deviation floor) must:

* NOT flag a clean periodic series that contains one single bucket gap,
* STILL flag a sustained genuine shift of the mean inter-arrival,
* return no verdict when there is insufficient evidence (too few
  intervals to form a meaningful observed mean).

The series statistics mirror the real PROFINET_RT_IO profile
(``mean_interval`` ~5.53 s, ``std_interval`` ~1.63 s) so the regression
guards the exact production scenario.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import polars as pl
from otalon_clas.detection.frequency_monitor import (
    FREQUENCY_ANOMALY,
    FrequencyMonitor,
    FrequencyResult,
)

_BASE = datetime.fromisoformat("2026-06-20T00:00:00")
_SERIES = "PROFINET_RT_IO"
_TAG = "protocol"

# Real-world-ish PROFINET_RT_IO cadence: mean ~5.53 s, std ~1.63 s.
_TRAIN_INTERVALS: list[float] = [5.5, 5.6, 5.4, 5.5, 8.0, 3.5, 5.6, 5.5, 5.5, 5.4]


def _series_from_intervals(intervals: list[float]) -> pl.Series:
    """Build a timestamp Series from a list of inter-arrival seconds."""
    times = [_BASE]
    for gap in intervals:
        times.append(times[-1] + timedelta(seconds=gap))
    return pl.Series(times)


def _trained_monitor() -> FrequencyMonitor:
    """Return a monitor trained on the periodic PROFINET_RT_IO cadence."""
    df_train = pl.DataFrame(
        {
            "time": _series_from_intervals(_TRAIN_INTERVALS),
            _TAG: [_SERIES] * (len(_TRAIN_INTERVALS) + 1),
        }
    )
    monitor = FrequencyMonitor(module_name="proto_traffic")
    monitor.train(df_train, tag_key=_TAG)
    return monitor


def _check(monitor: FrequencyMonitor, intervals: list[float]) -> list[FrequencyResult]:
    """Run a detection check for a window built from ``intervals``."""
    df_check = pl.DataFrame(
        {
            "time": _series_from_intervals(intervals),
            _TAG: [_SERIES] * (len(intervals) + 1),
        }
    )
    last = _BASE + timedelta(seconds=sum(intervals))
    results: list[FrequencyResult] = monitor.check(
        df_check, tag_key=_TAG, current_time=last.isoformat()
    )
    return results


def test_single_bucket_gap_on_periodic_traffic_no_anomaly() -> None:
    """A clean periodic window with one doubled bucket must NOT fire.

    This is the exact false-positive case: one missing aggregated bucket
    doubles a single interval (~11 s vs 5.53 s). With at least five
    intervals averaged and the mean-relative floor, the observed mean
    barely moves and no FrequencyAnomaly is produced.
    """
    monitor = _trained_monitor()
    # Six clean intervals plus one single doubled bucket (the gap).
    observed = [5.5, 5.5, 11.0, 5.5, 5.5, 5.5, 5.5]
    results = _check(monitor, observed)
    freq = [r for r in results if r.anomaly_type == FREQUENCY_ANOMALY]
    assert freq == []


def test_sustained_interval_shift_still_detected() -> None:
    """A sustained genuine cadence shift MUST still fire an anomaly.

    Every interval roughly doubles (the series slowed to ~11 s), so the
    observed mean shifts far beyond the robust threshold and the detector
    must remain sensitive.
    """
    monitor = _trained_monitor()
    observed = [11.0, 11.2, 10.8, 11.1, 11.0, 10.9, 11.2]
    results = _check(monitor, observed)
    freq = [r for r in results if r.anomaly_type == FREQUENCY_ANOMALY]
    assert len(freq) >= 1
    assert freq[0].series_id == _SERIES


def test_insufficient_intervals_returns_no_anomaly() -> None:
    """A window with fewer than ``min_intervals`` intervals is skipped.

    Two rows (one interval) carry a mean dominated by single-bucket
    jitter; even a wildly off interval must not be reported, because
    there is insufficient evidence.
    """
    monitor = _trained_monitor()
    observed = [25.0]  # one interval only → 2 rows
    results = _check(monitor, observed)
    freq = [r for r in results if r.anomaly_type == FREQUENCY_ANOMALY]
    assert freq == []
