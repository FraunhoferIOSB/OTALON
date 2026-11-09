"""Unit tests for derived detection readiness."""

from datetime import datetime, timezone
from typing import cast

from otalon_api.domain.netcap.models import proto_series_hash
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.services.detection_readiness_service import (
    FEATURES,
    DetectionReadinessService,
    derive_readiness,
)


def test_untrained_module_is_not_ready() -> None:
    """Missing bounds/frequency/training derives untrained."""
    assert (
        derive_readiness(
            enabled=True,
            bounds_count=0,
            frequency_count=0,
            no_bounds_count=2,
            last_training=None,
            schema_compatible=True,
            training=False,
        )
        == "untrained"
    )


def test_running_training_takes_precedence() -> None:
    """A running operations job derives training even before readiness."""
    assert (
        derive_readiness(
            enabled=True,
            bounds_count=0,
            frequency_count=0,
            no_bounds_count=0,
            last_training=None,
            schema_compatible=True,
            training=True,
        )
        == "training"
    )


def test_complete_compatible_module_is_ready() -> None:
    """Complete compatible persisted signals derive ready."""
    assert (
        derive_readiness(
            enabled=True,
            bounds_count=2,
            frequency_count=2,
            no_bounds_count=0,
            last_training=datetime.now(timezone.utc),
            schema_compatible=True,
            training=False,
        )
        == "ready"
    )


def test_incompatible_module_is_degraded() -> None:
    """Schema incompatibility cannot claim production readiness."""
    assert (
        derive_readiness(
            enabled=True,
            bounds_count=2,
            frequency_count=2,
            no_bounds_count=0,
            last_training=datetime.now(timezone.utc),
            schema_compatible=False,
            training=False,
        )
        == "degraded"
    )


class _ReadinessPostgres:
    def query_bounds(self, module: str) -> list[dict[str, object]]:
        return [
            {
                "module": module,
                "series_id": "uci-1",
                "lower_bounds": {"packet_count": 1},
                "upper_bounds": {"packet_count": 10},
                "trained_at": datetime(2026, 7, 1, tzinfo=timezone.utc),
            }
        ]

    def query_bound_violations(
        self,
        module: str,
        series: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, object]]:
        return [
            {
                "event_ts": datetime(2026, 7, 2, tzinfo=timezone.utc),
                "anomaly_type": "BoundViolation",
                "violated_features": ["packet_count"],
            },
            {
                "event_ts": datetime(2026, 7, 3, tzinfo=timezone.utc),
                "anomaly_type": "BoundViolation",
                "violated_features": ["packet_count"],
            },
        ]

    def _execute_query(self, sql: str, params: dict[str, object]) -> list[dict[str, int]]:
        return [{"count": 1}]


def test_bound_review_aggregates_one_row_per_series_and_uses_event_time() -> None:
    service = DetectionReadinessService(cast(PostgresRepository, _ReadinessPostgres()), "/missing", "/missing")
    rows = service.bounds("conn", None, datetime(2026, 6, 1, tzinfo=timezone.utc), None)
    assert len(rows) == 1
    assert rows[0]["series_id"] == "uci-1"
    assert rows[0]["violation_count"] == 2
    assert rows[0]["affected_features"] == ["packet_count"]
    assert rows[0]["ok"] is False
    assert rows[0]["last_event"] == datetime(2026, 7, 3, tzinfo=timezone.utc)


class _NoBoundsPostgres:
    """Serves NoBounds anomaly events with strict ``since`` SQL filtering.

    Models the real anomalies table: bounded series have none; a single
    NoBounds series (``uci-nb``) carries three persisted events, one of which
    predates the ``since`` cutoff so a correct query must exclude it.
    """

    _EVENTS = [
        ("uci-nb", datetime(2026, 7, 1, tzinfo=timezone.utc)),
        ("uci-nb", datetime(2026, 7, 5, tzinfo=timezone.utc)),
        ("uci-nb", datetime(2026, 7, 9, tzinfo=timezone.utc)),
    ]

    def query_bounds(self, module: str) -> list[dict[str, object]]:
        return []

    def query_bound_violations(
        self,
        module: str,
        series: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, object]]:
        return []

    def _execute_query(self, sql: str, params: dict[str, object]) -> list[dict[str, object]]:
        if "series_id, start_ts AS event_ts" not in sql:
            return [{"count": 0}]
        since = params.get("since")
        rows: list[dict[str, object]] = []
        for series, event in self._EVENTS:
            if since is not None and event < since:  # type: ignore[operator]
                continue
            rows.append({"series_id": series, "event_ts": event})
        rows.sort(key=lambda row: row["event_ts"], reverse=True)  # type: ignore[arg-type,return-value]
        return rows


def test_no_bounds_row_reports_filtered_count_latest_and_ordered_timeline() -> None:
    """NoBounds aggregate reports truthful count/latest/timeline for the window."""
    service = DetectionReadinessService(cast(PostgresRepository, _NoBoundsPostgres()), "/missing", "/missing")
    # since=2026-07-03 excludes the 2026-07-01 event; keeps 07-05 and 07-09.
    rows = service.bounds("conn", "NoBounds", datetime(2026, 7, 3, tzinfo=timezone.utc), None)
    nb_rows = [row for row in rows if row["state"] == "NoBounds"]
    assert len(nb_rows) == 1
    row = nb_rows[0]
    assert row["series_id"] == "uci-nb"
    assert row["violation_count"] == 2
    assert row["last_event"] == datetime(2026, 7, 9, tzinfo=timezone.utc)
    assert row["timeline"] == [
        datetime(2026, 7, 5, tzinfo=timezone.utc),
        datetime(2026, 7, 9, tzinfo=timezone.utc),
    ]
    # Older event before the since cutoff must not leak into the timeline.
    assert datetime(2026, 7, 1, tzinfo=timezone.utc) not in row["timeline"]


def test_no_bounds_row_includes_all_events_when_since_is_absent() -> None:
    """Without a since filter all persisted NoBounds events are counted."""
    service = DetectionReadinessService(cast(PostgresRepository, _NoBoundsPostgres()), "/missing", "/missing")
    rows = service.bounds("conn", "NoBounds", None, None)
    nb_rows = [row for row in rows if row["state"] == "NoBounds"]
    assert len(nb_rows) == 1
    assert nb_rows[0]["violation_count"] == 3
    assert nb_rows[0]["last_event"] == datetime(2026, 7, 9, tzinfo=timezone.utc)
    assert len(nb_rows[0]["timeline"]) == 3


def test_no_bounds_row_exposes_available_feature_names() -> None:
    """NoBounds hints use tracked features, not persisted violation fields."""

    class _FeaturePostgres(_NoBoundsPostgres):
        def _execute_query(self, sql: str, params: dict[str, object]) -> list[dict[str, object]]:
            rows = super()._execute_query(sql, params)
            if "violated_features" in sql:
                for row in rows:
                    row["violated_features"] = "not_a_real_violation,"
                    row["violated_feature_details"] = {}
            return rows

    service = DetectionReadinessService(cast(PostgresRepository, _FeaturePostgres()), "/missing", "/missing")
    rows = service.bounds("conn", "NoBounds", None, None)
    row = next(item for item in rows if item["state"] == "NoBounds")
    expected = list(FEATURES["conn"])
    assert row["affected_features"] == sorted(expected)
    assert all(event["features"] == expected for event in row["timeline_events"])


class _MixedAnomalyPostgres:
    """Expose an unbounded ML-labelled series and a bounded series."""

    def query_bounds(self, module: str) -> list[dict[str, object]]:
        return [
            {
                "module": module,
                "series_id": "bounded",
                "lower_bounds": {"packet_count": 1},
                "upper_bounds": {"packet_count": 10},
                "trained_at": datetime(2026, 7, 1, tzinfo=timezone.utc),
            }
        ]

    def query_bound_violations(
        self,
        module: str,
        series: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, object]]:
        return []

    def _execute_query(self, sql: str, params: dict[str, object]) -> list[dict[str, object]]:
        if "series_id, start_ts AS event_ts" in sql:
            return [
                {
                    "series_id": "unbounded",
                    "event_ts": datetime(2026, 7, 2, tzinfo=timezone.utc),
                    "anomaly_type": "arp_spoofing",
                    "violated_features": ["packet_count"],
                }
            ]
        # Readiness batches the unbounded counts into one grouped query
        # (SUITE-045): one row per module carrying both the distinct-series
        # and the raw-event count, instead of two COUNT queries per module.
        if "per_series" in sql:
            return [{"module": "conn", "series_count": 1, "event_count": 1}]
        if "COUNT(DISTINCT" in sql:
            return [{"count": 1}]
        if "COUNT(*)" in sql:
            return [{"count": 1}]
        return []


def test_ml_labelled_series_without_bounds_is_no_bounds() -> None:
    """Bounds-table absence, not anomaly label, selects NoBounds rows."""
    service = DetectionReadinessService(cast(PostgresRepository, _MixedAnomalyPostgres()), "/missing", "/missing")

    rows = service.bounds("conn", "NoBounds", None, None)

    assert [row["series_id"] for row in rows] == ["unbounded"]
    assert rows[0]["latest_event_type"] == "NoBounds"


def test_bounded_series_with_ml_label_is_not_no_bounds() -> None:
    """A bounds row keeps a series on normal OK/violation derivation."""
    service = DetectionReadinessService(cast(PostgresRepository, _MixedAnomalyPostgres()), "/missing", "/missing")

    rows = service.bounds("conn", "NoBounds", None, None)

    assert all(row["series_id"] != "bounded" for row in rows)


def test_readiness_counts_unbounded_ml_labelled_series() -> None:
    """Readiness counters use unbounded series regardless of anomaly label."""
    service = DetectionReadinessService(cast(PostgresRepository, _MixedAnomalyPostgres()), "/missing", "/missing")

    conn = next(row for row in service.readiness(set()) if row["module"] == "conn")

    assert conn["no_bounds_series_count"] == 1
    assert conn["no_bounds_count"] == 1
    assert conn["no_bounds_event_count"] == 1


class _ProtoResolver:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def resolve_many(self, values: list[str]) -> list[str]:
        self.calls.append(values)
        return ["Ethernet:IPv4:UDP:DNS" for _ in values]


class _ProtoPostgres(_ReadinessPostgres):
    def query_bounds(self, module: str) -> list[dict[str, object]]:
        return [
            {
                "series_id": proto_series_hash("Ethernet:IPv4:UDP:DNS"),
                "lower_bounds": {},
                "upper_bounds": {},
            }
        ]


def test_bound_review_resolves_proto_display_once_and_exposes_features() -> None:
    resolver = _ProtoResolver()
    service = DetectionReadinessService(
        _ProtoPostgres(), "/missing", "/missing", proto_resolver=resolver  # type: ignore[arg-type]
    )
    rows = service.bounds("proto_traffic", None, None, "DNS")
    assert rows[0]["series_display"] == "Ethernet:IPv4:UDP:DNS"
    assert rows[0]["available_features"]
    assert resolver.calls == [[rows[0]["series_id"]]]


def _ready_kwargs() -> dict[str, object]:
    """Facts that derive ``ready`` when nothing failed (API-073 baseline)."""
    return {
        "enabled": True,
        "bounds_count": 3,
        "frequency_count": 3,
        "no_bounds_count": 0,
        "last_training": datetime(2026, 7, 1, tzinfo=timezone.utc),
        "schema_compatible": True,
        "training": False,
    }


def test_baseline_complete_module_is_ready() -> None:
    """Gegenprobe: without a query failure the same facts still derive ready."""
    assert derive_readiness(**_ready_kwargs()) == "ready"  # type: ignore[arg-type]


def test_query_failure_never_derives_ready() -> None:
    """API-073: a fact query that raised must not report ready (fail closed)."""
    assert derive_readiness(**_ready_kwargs(), query_failed=True) == "degraded"  # type: ignore[arg-type]


class _RaisingPostgres:
    """Injected DB failure: every fact query raises (API-073)."""

    def _execute_query(self, sql: str, params: dict[str, object]) -> list[dict[str, object]]:
        raise RuntimeError("injected DB failure")


def test_injected_db_error_sets_failure_flag_not_silent_zero() -> None:
    """API-073: a raising query must set the failure flag, not return a silent zero.

    The old code returned 0/{} here and the readiness path read that as
    'untrained or healthy'. The flag is what the derivation consumes.
    """
    svc = DetectionReadinessService(
        cast(PostgresRepository, _RaisingPostgres()),
        config_path="/nonexistent/config.json",
        model_dir="/nonexistent/models",
    )
    assert svc._query_count("bounds", "mac_traffic") == 0
    assert svc._query_failed is True
    assert derive_readiness(**_ready_kwargs(), query_failed=svc._query_failed) == "degraded"  # type: ignore[arg-type]
