"""CLAS-028 regression tests: per-series minimum training coverage guard.

A manual ``retrain-boundaries`` over a too-short window (2026-08-25
16:00-17:45, 1h45) produced quantile envelopes so tight that normal
fluctuation violated them immediately, driving proto_traffic
``BoundViolation`` from 4 to 22 hits within the following 1h45.

The guard is per-series wall-clock coverage: a series whose observed
samples span less than ``min_series_coverage_hours`` inside the training
window does not get new bounds published. It keeps its previous bounds
when it has any, and stays unbounded (``NoBounds``) when it was never
trained.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import polars as pl

from otalon_clas.common.postgres_connector import Bound, PostgresConnector
from otalon_clas.common.settings import BoundaryTrainingConfig
from otalon_clas.detection.bounds_manager import (
    BoundsManager,
    BoundsRepository,
    BoundsTrainer,
)
from otalon_clas.runtime.training_helpers import (
    compute_bounds_candidate,
    publish_bounds_candidate,
)

_TAG = "protocol"
_FEATURES = ["proto_conn_count"]
_BASE = datetime(2026, 8, 25, 16, 0, 0, tzinfo=timezone.utc)


def _series_rows(
    series_id: str,
    *,
    span_hours: float,
    count: int,
    value: float = 3.0,
) -> list[dict[str, object]]:
    """Build rows for one series spread evenly over ``span_hours``."""
    step = timedelta(hours=span_hours) / max(count - 1, 1)
    return [{_TAG: series_id, "time": _BASE + step * i, "proto_conn_count": value} for i in range(count)]


def _frame(*row_groups: list[dict[str, object]]) -> pl.DataFrame:
    rows: list[dict[str, object]] = []
    for group in row_groups:
        rows.extend(group)
    return pl.DataFrame(rows)


def test_sparse_series_in_short_window_is_skipped() -> None:
    """A series spanning less than the threshold gets no new bounds (CLAS-028)."""
    df = _frame(_series_rows("Ethernet:IPv4:UDP:PROFINET_DCE_RPC", span_hours=1.75, count=40))

    result = BoundsTrainer().train(
        df=df,
        tag_key=_TAG,
        features=_FEATURES,
        config=BoundaryTrainingConfig(),
    )

    assert "Ethernet:IPv4:UDP:PROFINET_DCE_RPC" not in result


def test_series_above_threshold_trains_normally() -> None:
    """A series spanning at least the threshold still gets fresh bounds."""
    df = _frame(_series_rows("Ethernet:LLDP", span_hours=8.0, count=40))

    result = BoundsTrainer().train(
        df=df,
        tag_key=_TAG,
        features=_FEATURES,
        config=BoundaryTrainingConfig(),
    )

    assert "Ethernet:LLDP" in result
    assert set(result["Ethernet:LLDP"]) == {"proto_conn_count"}


def test_threshold_is_read_from_config() -> None:
    """Lowering ``min_series_coverage_hours`` re-admits a short-span series."""
    df = _frame(_series_rows("Ethernet:ARP", span_hours=1.75, count=40))

    strict = BoundsTrainer().train(
        df=df,
        tag_key=_TAG,
        features=_FEATURES,
        config=BoundaryTrainingConfig(min_series_coverage_hours=5.0),
    )
    relaxed = BoundsTrainer().train(
        df=df,
        tag_key=_TAG,
        features=_FEATURES,
        config=BoundaryTrainingConfig(min_series_coverage_hours=1.0),
    )

    assert "Ethernet:ARP" not in strict
    assert "Ethernet:ARP" in relaxed


def test_threshold_default_comes_from_config_json() -> None:
    """The shipped ``config/config.json`` carries the coverage threshold."""
    raw = json.loads((Path(__file__).resolve().parents[2] / "config" / "config.json").read_text())
    boundary = BoundaryTrainingConfig(**raw["training"]["boundary"])

    assert raw["training"]["boundary"]["min_series_coverage_hours"] == 5.0
    assert boundary.min_series_coverage_hours == 5.0
    assert boundary.time_column == "time"


def test_skipped_series_keeps_previous_bounds() -> None:
    """A skipped series carries its previously trained envelope forward."""
    df = _frame(
        _series_rows("Ethernet:IPv4:UDP", span_hours=1.0, count=10),
        _series_rows("Ethernet:LLDP", span_hours=9.0, count=40),
    )
    previous = {"Ethernet:IPv4:UDP": {"proto_conn_count": (1.0, 99.0)}}

    result = BoundsTrainer().train(
        df=df,
        tag_key=_TAG,
        features=_FEATURES,
        config=BoundaryTrainingConfig(),
        previous_bounds=previous,
    )

    assert result["Ethernet:IPv4:UDP"] == {"proto_conn_count": (1.0, 99.0)}
    assert "Ethernet:LLDP" in result


def test_never_trained_sparse_series_stays_unbounded() -> None:
    """Without previous bounds a skipped series is simply absent from the result."""
    df = _frame(
        _series_rows("Ethernet:IPv6:UDP", span_hours=0.22, count=5),
        _series_rows("Ethernet:LLDP", span_hours=9.0, count=40),
    )

    result = BoundsTrainer().train(
        df=df,
        tag_key=_TAG,
        features=_FEATURES,
        config=BoundaryTrainingConfig(),
        previous_bounds={},
    )

    assert "Ethernet:IPv6:UDP" not in result
    assert "Ethernet:LLDP" in result


def test_guard_inactive_without_time_column() -> None:
    """Frames without a time column keep the pre-CLAS-028 behaviour."""
    df = pl.DataFrame(
        {
            _TAG: ["Ethernet:ARP"] * 10,
            "proto_conn_count": [float(i) for i in range(10)],
        }
    )

    result = BoundsTrainer().train(df=df, tag_key=_TAG, features=_FEATURES, config=BoundaryTrainingConfig())

    assert "Ethernet:ARP" in result


class _Mod:
    name = "proto_traffic"
    tag_key = _TAG
    features = _FEATURES


class _TrainingCfg:
    def __init__(self, boundary: BoundaryTrainingConfig) -> None:
        self.boundary = boundary


class _Config:
    def __init__(self, boundary: BoundaryTrainingConfig) -> None:
        self.training = _TrainingCfg(boundary)


class _FakeBundle:
    """Minimal bundle exposing what the bounds runtime helpers touch."""

    def __init__(self, pg: PostgresConnector) -> None:
        self.config = _Mod()
        self.bounds_trainer = BoundsTrainer()
        self.bounds_repository = BoundsRepository(connector=pg)
        self.bounds_manager = BoundsManager(
            module_name=_Mod.name,
            repository=self.bounds_repository,
            cache_ttl_seconds=3600,
        )


def _make_connector(tmp_path: Path) -> PostgresConnector:
    db = tmp_path / "bounds_coverage.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db}", pool_size=1, max_overflow=0)
    Bound.__table__.create(pg.engine, checkfirst=True)
    return pg


def test_runtime_short_window_retrain_preserves_sparse_bounds(tmp_path: Path) -> None:
    """The runtime path keeps healthy bounds when a short window is retrained."""
    pg = _make_connector(tmp_path)
    bundle = _FakeBundle(pg)
    healthy = _Config(BoundaryTrainingConfig(min_series_coverage_hours=0.0))

    long_df = _frame(
        _series_rows("Ethernet:IPv4:UDP:PROFINET_DCE_RPC", span_hours=12.0, count=60, value=8.0),
        _series_rows("Ethernet:LLDP", span_hours=12.0, count=60, value=8.0),
    )
    seeded = compute_bounds_candidate(healthy, bundle, long_df)
    publish_bounds_candidate(bundle, seeded, invalidate_cache=True)
    baseline = seeded.bounds["Ethernet:IPv4:UDP:PROFINET_DCE_RPC"]

    short_df = _frame(
        _series_rows("Ethernet:IPv4:UDP:PROFINET_DCE_RPC", span_hours=1.75, count=20, value=1.0),
        _series_rows("Ethernet:LLDP", span_hours=9.0, count=60, value=8.0),
    )
    guarded = compute_bounds_candidate(_Config(BoundaryTrainingConfig()), bundle, short_df)
    publish_bounds_candidate(bundle, guarded, invalidate_cache=True)

    assert guarded.bounds["Ethernet:IPv4:UDP:PROFINET_DCE_RPC"] == baseline
    with pg.session() as session:
        stored = {str(r.series_id) for r in session.query(Bound)}
    assert "Ethernet:IPv4:UDP:PROFINET_DCE_RPC" in stored
