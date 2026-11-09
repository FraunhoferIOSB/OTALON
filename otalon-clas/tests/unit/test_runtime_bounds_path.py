"""Runtime-path CLAS-008 / CLAS-011 regression tests (audit F5 / task 8.3).

Exercises the RUNTIME bounds path (``compute_bounds_candidate`` +
``publish_bounds_candidate``) end-to-end with real
``BoundsTrainer``/``BoundsManager``/``BoundsRepository`` objects, proving:

* an attack-only series absent from a later clean window is pruned by the
  module-scoped atomic replace (CLAS-008), and
* an empty training window raises before any DB mutation, leaving the
  existing rows intact (CLAS-011).

These are the assertions task 8.3 claimed but no runtime-path test
covered — the prior tests only exercised ``BoundsRepository`` directly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import polars as pl
import pytest

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

_FEATURES = ["bytes"]
_TAG = "uci"


class _FakeBundle:
    """Minimal bundle exposing what the bounds helpers touch."""

    def __init__(self, pg: PostgresConnector) -> None:
        class _Mod:
            name = "conn"
            tag_key = _TAG
            features = _FEATURES

        self.config = _Mod()
        self.bounds_trainer = BoundsTrainer()
        self.bounds_repository = BoundsRepository(connector=pg)
        self.bounds_manager = BoundsManager(
            module_name="conn",
            repository=self.bounds_repository,
            cache_ttl_seconds=3600,
        )


def _make_connector(tmp_path: Path) -> PostgresConnector:
    db = tmp_path / "runtime_bounds.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db}", pool_size=1, max_overflow=0)
    Bound.__table__.create(pg.engine, checkfirst=True)
    return pg


def _window_df(series_ids: list[str]) -> pl.DataFrame:
    """Build a training frame with enough rows and span per series.

    Rows are spaced one hour apart so every series clears the CLAS-028
    per-series coverage guard; these tests target the atomic-replace and
    empty-window behaviour, not the coverage threshold.
    """
    rows = []
    base = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
    for sid in series_ids:
        for i in range(20):
            rows.append(
                {
                    _TAG: sid,
                    "time": base + timedelta(hours=i),
                    "bytes": float(100 + i),
                }
            )
    return pl.DataFrame(rows)


def _persisted_series(pg: PostgresConnector) -> set[str]:
    with pg.session() as session:
        return {str(r.series_id) for r in session.query(Bound).filter(Bound.module == "conn")}


class _TrainingCfg:
    """Carries only ``boundary`` — all ``compute_bounds_candidate`` reads."""

    def __init__(self) -> None:
        self.boundary = BoundaryTrainingConfig()


class _Config:
    """Lightweight AppConfig stand-in for the bounds runtime path."""

    def __init__(self) -> None:
        self.training = _TrainingCfg()


def _config() -> _Config:
    return _Config()


def test_runtime_retrain_prunes_attack_only_series(tmp_path: Path) -> None:
    """A clean-window runtime retrain drops the attack-only series (CLAS-008)."""
    pg = _make_connector(tmp_path)
    bundle = _FakeBundle(pg)
    config = _config()

    # Prior training saw an attack window with A, B and an attack-only C.
    attack_df = _window_df(["series-A", "series-B", "Ethernet:IPv4:ICMP"])
    first = compute_bounds_candidate(config, bundle, attack_df)
    publish_bounds_candidate(bundle, first, invalidate_cache=True)
    assert _persisted_series(pg) == {"series-A", "series-B", "Ethernet:IPv4:ICMP"}

    # Runtime retrain over a clean window with only A, B.
    clean_df = _window_df(["series-A", "series-B"])
    second = compute_bounds_candidate(config, bundle, clean_df)
    publish_bounds_candidate(bundle, second, invalidate_cache=True)

    # The attack-only series is pruned by the atomic module-scoped replace.
    assert _persisted_series(pg) == {"series-A", "series-B"}
    assert "Ethernet:IPv4:ICMP" not in _persisted_series(pg)


def test_runtime_empty_window_raises_and_keeps_rows(tmp_path: Path) -> None:
    """An empty runtime window raises and leaves existing bounds intact (CLAS-011)."""
    pg = _make_connector(tmp_path)
    bundle = _FakeBundle(pg)
    config = _config()

    seeded = compute_bounds_candidate(config, bundle, _window_df(["series-A", "series-B"]))
    publish_bounds_candidate(bundle, seeded, invalidate_cache=True)
    assert _persisted_series(pg) == {"series-A", "series-B"}

    # Empty window -> trainer yields no series -> compute raises before publish.
    with pytest.raises(ValueError, match="empty"):
        compute_bounds_candidate(config, bundle, pl.DataFrame({_TAG: [], "time": [], "bytes": []}))

    # DB rows untouched: no silent wipe.
    assert _persisted_series(pg) == {"series-A", "series-B"}
