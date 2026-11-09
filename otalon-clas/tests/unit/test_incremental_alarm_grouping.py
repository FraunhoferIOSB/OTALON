"""Unit tests for incremental alarm module labels and duration limits."""

from datetime import datetime, timedelta, timezone

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord
from otalon_clas.detection.grouping import (
    MULTI_MODULE_SENTINEL,
    _create_alarm_from_anomaly,
    _find_mergable_alarm,
    _merge_anomaly_into_alarm,
)

BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _anomaly(module: str, offset: int, series: str) -> AnomalyRecord:
    """Create minimal anomaly fixture."""
    return AnomalyRecord(
        id=f"{module}-{offset}-{series}",
        module=module,
        series_id=series,
        anomaly_type="bound",
        start_ts=BASE_TIME + timedelta(seconds=offset),
        end_ts=BASE_TIME + timedelta(seconds=offset + 1),
        confidence=0.9,
        violated_features=[],
        rate_summary={},
    )


def _alarm(module: str = "conn", duration: int = 1) -> Alarm:
    """Create minimal alarm fixture."""
    return Alarm(
        id="alarm",
        module=module,
        start_timestamp=BASE_TIME,
        end_timestamp=BASE_TIME + timedelta(seconds=duration),
        primary_type="bound",
        series_ids=["first"],
        anomaly_type_stats={},
    )


def test_cross_module_merge_marks_alarm_multi() -> None:
    """A module change marks an alarm as multi-module."""
    alarm = _create_alarm_from_anomaly(_anomaly("conn", 0, "conn-series"))
    _merge_anomaly_into_alarm(alarm, _anomaly("mac_traffic", 2, "mac-series"))
    assert alarm.module == MULTI_MODULE_SENTINEL


def test_same_module_merge_keeps_module() -> None:
    """Same-module merges retain original module label."""
    alarm = _create_alarm_from_anomaly(_anomaly("conn", 0, "first"))
    _merge_anomaly_into_alarm(alarm, _anomaly("conn", 2, "second"))
    assert alarm.module == "conn"


def test_multi_module_merge_never_falls_back() -> None:
    """Multi-module label remains stable after later same-module merges."""
    alarm = _alarm(MULTI_MODULE_SENTINEL)
    _merge_anomaly_into_alarm(alarm, _anomaly("conn", 2, "second"))
    assert alarm.module == MULTI_MODULE_SENTINEL


def test_multi_module_merge_accumulates_series_ids() -> None:
    """Cross-module merge retains all series identifiers."""
    alarm = _create_alarm_from_anomaly(_anomaly("conn", 0, "conn-series"))
    _merge_anomaly_into_alarm(alarm, _anomaly("mac_traffic", 2, "mac-series"))
    assert alarm.series_ids == ["conn-series", "mac-series"]


def test_duration_cap_rejects_alarm_that_would_be_too_long() -> None:
    """Candidate is rejected when resulting span exceeds cap."""
    alarm = _alarm(duration=100)
    anomaly = _anomaly("conn", 110, "late")
    assert _find_mergable_alarm(anomaly, [alarm], timedelta(seconds=20), 100) is None


def test_duration_cap_accepts_alarm_within_limit() -> None:
    """Candidate is accepted when resulting span stays within cap."""
    alarm = _alarm(duration=100)
    anomaly = _anomaly("conn", 105, "near")
    assert _find_mergable_alarm(anomaly, [alarm], timedelta(seconds=20), 110) is alarm


def test_zero_duration_cap_disables_limit() -> None:
    """Non-positive cap allows long alarm chains."""
    alarm = _alarm(duration=100)
    anomaly = _anomaly("conn", 110, "long")
    assert _find_mergable_alarm(anomaly, [alarm], timedelta(seconds=20), 0) is alarm
