"""Recovery-1 regressions for Guided Bound Review truthfulness.

These reproduce the defects the first worker draft left in place:

* BoundViolation affected features must come from the real ``violated_features``
  JSON column, not a non-existent ``feature`` column (which silently made every
  bounded series look OK and dropped the canary violation).
* The event window must be a strict ``[from, to)`` interval, excluding an event
  exactly at ``to`` and excluding events before ``from``.
* Each row must carry a structured, truthful timeline (timestamp + anomaly type
  + real affected features), never a feature guessed by list index.
* Exactly one row per Series/UCI, with status priority NoBounds > Violation > OK,
  so a series that both lacks a bound and has events is a single NoBounds row.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from otalon_api.services.detection_readiness_service import DetectionReadinessService

_CANARY_SERIES = "30:b8:51:31:06:84/00:01:05:2b:ae:a2/0//////Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO"


def _dt(day: int, hour: int = 0) -> datetime:
    return datetime(2026, 7, day, hour, tzinfo=timezone.utc)


class _RealSchemaPostgres:
    """Fake mirroring the real anomalies schema (no ``feature`` column).

    Bounded series ``s-bound`` carries two BoundViolation events whose affected
    features live in ``violated_features`` JSON. A second series ``s-nb`` has no
    bounds row and three NoBounds events, one of which sits exactly at the ``to``
    boundary and one before ``from`` so a correct strict window drops both.
    """

    def __init__(self) -> None:
        self.violation_queries: list[dict[str, Any]] = []

    def query_bounds(self, module: str, series_id: str | None = None) -> list[dict[str, Any]]:
        row = {
            "module": module,
            "series_id": "s-bound",
            "lower_bounds": {"min_interarrival_time": 0.8, "packet_count": 1.0},
            "upper_bounds": {"min_interarrival_time": 2.4, "packet_count": 10.0},
            "trained_at": _dt(1),
        }
        if series_id is None or series_id == "s-bound":
            return [row]
        return []

    def query_bound_violations(
        self,
        module: str,
        series_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        # Real repo returns anomaly_type + violated_features JSON, never a
        # scalar ``feature`` column. Recording the call proves the strict
        # window bounds are forwarded to the repository, not applied post-hoc.
        self.violation_queries.append({"since": since, "until": until, "series_id": series_id})
        if series_id != "s-bound":
            return []
        events = [
            {
                "event_ts": _dt(5, 10),
                "start_ts": _dt(5, 10),
                "anomaly_type": "BoundViolation",
                "violated_features": ["min_interarrival_time"],
                "violated_feature_details": {"min_interarrival_time": 1},
            },
            {
                "event_ts": _dt(6, 12),
                "start_ts": _dt(6, 12),
                "anomaly_type": "BoundViolation",
                "violated_features": ["packet_count", "min_interarrival_time"],
                "violated_feature_details": {"packet_count": 2, "min_interarrival_time": 1},
            },
        ]
        return [
            event
            for event in events
            if (since is None or event["event_ts"] >= since) and (until is None or event["event_ts"] < until)
        ]

    def _execute_query(self, sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        if "series_id, start_ts AS event_ts" not in sql:
            return [{"count": 0}]
        since = params.get("since")
        until = params.get("until")
        all_events = [
            {"series_id": "s-nb", "event_ts": _dt(3, 0)},  # before a 07-04 from
            {"series_id": "s-nb", "event_ts": _dt(5, 8)},
            {"series_id": "s-nb", "event_ts": _dt(9, 0)},  # exactly at a 07-09 to
        ]
        rows = [
            row
            for row in all_events
            if (since is None or row["event_ts"] >= since) and (until is None or row["event_ts"] < until)
        ]
        rows.sort(key=lambda row: row["event_ts"], reverse=True)
        return rows


def _service() -> tuple[DetectionReadinessService, _RealSchemaPostgres]:
    pg = _RealSchemaPostgres()
    return DetectionReadinessService(pg, "/missing", "/missing"), pg


def test_violation_affected_features_come_from_violated_features_column() -> None:
    """Affected features are the union of real ``violated_features`` values."""
    service, _ = _service()
    rows = service.bounds("conn", None, _dt(1), None, until=_dt(10))
    bound_row = next(row for row in rows if row["series_id"] == "s-bound")
    assert bound_row["state"] == "BoundViolation"
    assert bound_row["affected_features"] == ["min_interarrival_time", "packet_count"]
    assert bound_row["violation_count"] == 2


def test_structured_timeline_carries_type_and_real_features() -> None:
    """Timeline events expose timestamp + anomaly type + real features, not index guesses."""
    service, _ = _service()
    rows = service.bounds("conn", None, _dt(1), None, until=_dt(10))
    bound_row = next(row for row in rows if row["series_id"] == "s-bound")
    events = bound_row["timeline_events"]
    assert [event["ts"] for event in events] == [_dt(5, 10), _dt(6, 12)]
    assert events[0]["type"] == "BoundViolation"
    assert events[0]["features"] == ["min_interarrival_time"]
    assert events[1]["features"] == ["min_interarrival_time", "packet_count"]


def test_strict_upper_bound_excludes_event_at_to() -> None:
    """A NoBounds event exactly at ``to`` is excluded; one before ``from`` too."""
    service, _ = _service()
    rows = service.bounds("conn", "NoBounds", _dt(4), None, until=_dt(9))
    nb_row = next(row for row in rows if row["series_id"] == "s-nb")
    timestamps = [event["ts"] for event in nb_row["timeline_events"]]
    assert timestamps == [_dt(5, 8)]
    assert _dt(9, 0) not in timestamps
    assert _dt(3, 0) not in timestamps
    assert nb_row["violation_count"] == 1


def test_window_bounds_forwarded_to_violation_query() -> None:
    """The strict window is pushed into the repository query, not filtered later."""
    service, pg = _service()
    service.bounds("conn", None, _dt(4), None, until=_dt(9))
    forwarded = [call for call in pg.violation_queries if call["series_id"] == "s-bound"]
    assert forwarded
    assert forwarded[0]["since"] == _dt(4)
    assert forwarded[0]["until"] == _dt(9)


class _DualStatePostgres:
    """A single series that both lacks bounds and has NoBounds events."""

    def query_bounds(self, module: str, series_id: str | None = None) -> list[dict[str, Any]]:
        return []

    def query_bound_violations(
        self,
        module: str,
        series_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        return []

    def _execute_query(self, sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        if "series_id, start_ts AS event_ts" not in sql:
            return [{"count": 0}]
        return [{"series_id": "s-x", "event_ts": _dt(5)}]


def test_one_row_per_series_priority_nobounds_over_violation() -> None:
    """A series without a bound row is a single NoBounds row, never duplicated."""
    service = DetectionReadinessService(_DualStatePostgres(), "/missing", "/missing")
    rows = service.bounds("conn", None, _dt(1), None, until=_dt(10))
    matching = [row for row in rows if row["series_id"] == "s-x"]
    assert len(matching) == 1
    assert matching[0]["state"] == "NoBounds"
    assert matching[0]["has_bounds"] is False
