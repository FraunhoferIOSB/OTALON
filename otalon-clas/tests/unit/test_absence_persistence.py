"""Unit tests for the AbsenceAnomaly persistence path.

Regression cover for the structural defect that made
``AbsenceAnomaly`` unpersistable: ``fusion._attach_frequency_flags``
left-joins frequency results onto ``bounds_df``, but an absent series
by definition has no row in ``bounds_df`` (it was not observed), so the
join matched nothing and the result was dropped. Zero ``AbsenceAnomaly``
rows had ever reached the ``anomalies`` table.

The tests run against an in-memory SQLite database. Only the
``anomalies`` table is created; the sibling ORM models with PG-specific
column types are not needed here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import polars as pl
import pytest

from otalon_clas.common.postgres_connector import AnomalyRecord, PostgresConnector
from otalon_clas.detection.anomaly_persister import AnomalyPersister
from otalon_clas.detection.frequency_monitor import (
    ABSENCE_ANOMALY,
    FREQUENCY_ANOMALY,
    FrequencyMonitor,
    FrequencyResult,
    _SeriesFrequencyProfile,
)
from otalon_clas.detection.fusion import fuse_results

BASE = datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)


def _make_sqlite_connector(tmp_path: Path) -> PostgresConnector:
    """Build a PostgresConnector backed by a fresh SQLite file."""
    db_path = tmp_path / "anomalies.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db_path}", pool_size=1, max_overflow=0)
    AnomalyRecord.__table__.create(pg.engine, checkfirst=True)
    return pg


def _absence_result(
    series_id: str = "s1",
    deadline: datetime | None = None,
    last_seen: datetime | None = None,
    confidence: float = 1.0,
) -> FrequencyResult:
    """Build an AbsenceAnomaly result with an explicit deadline."""
    return FrequencyResult(
        is_anomaly=True,
        anomaly_type=ABSENCE_ANOMALY,
        confidence=confidence,
        series_id=series_id,
        absence_since=deadline if deadline is not None else BASE,
        last_seen=last_seen if last_seen is not None else BASE - timedelta(seconds=30),
    )


def _rows(pg: PostgresConnector) -> list[AnomalyRecord]:
    """Return every persisted anomaly row, oldest first."""
    with pg.session() as session:
        return list(session.query(AnomalyRecord).order_by(AnomalyRecord.start_ts).all())


class TestAbsenceReachesPersistence:
    """An absent series must materialise as its own ``anomalies`` row."""

    def test_absence_result_is_written(self, tmp_path: Path) -> None:
        """persist_absence writes one AbsenceAnomaly row."""
        pg = _make_sqlite_connector(tmp_path)
        persister = AnomalyPersister(connector=pg)

        count = persister.persist_absence([_absence_result()], "conn", BASE + timedelta(seconds=5))

        assert count == 1
        rows = _rows(pg)
        assert len(rows) == 1
        assert rows[0].anomaly_type == ABSENCE_ANOMALY
        assert rows[0].module == "conn"
        assert rows[0].series_id == "s1"
        assert rows[0].is_anomaly is True

    def test_fusion_alone_never_produces_an_absence_row(self, tmp_path: Path) -> None:
        """The old path is provably incapable of persisting absence.

        This pins the root cause: the absent series has no row in
        ``bounds_df``, so fusing and persisting the fused frame yields
        nothing at all.
        """
        pg = _make_sqlite_connector(tmp_path)
        persister = AnomalyPersister(connector=pg)
        bounds_df = pl.DataFrame(
            {
                "uci": ["observed_series"],
                "time": [BASE],
                "is_anomaly": [False],
                "anomaly_type": [""],
                "confidence": [0.0],
                "violated_features": [""],
                "severity": [0.0],
            }
        )

        fused = fuse_results(
            bounds_df=bounds_df,
            freq_results=[_absence_result(series_id="silent_series")],
            ml_predictions=None,
            tag_key="uci",
        )
        persisted = persister.persist(fused, "conn", "uci")

        assert persisted == 0
        assert _rows(pg) == []

    def test_absence_does_not_pollute_an_observed_row(self, tmp_path: Path) -> None:
        """An absence verdict must never be attached to a different series."""
        bounds_df = pl.DataFrame(
            {
                "uci": ["observed_series"],
                "time": [BASE],
                "is_anomaly": [False],
                "anomaly_type": [""],
                "confidence": [0.0],
                "violated_features": [""],
                "severity": [0.0],
            }
        )

        fused = fuse_results(
            bounds_df=bounds_df,
            freq_results=[_absence_result(series_id="observed_series")],
            ml_predictions=None,
            tag_key="uci",
        )

        assert fused["freq_type"].to_list() == [None]
        assert fused["is_anomaly"].to_list() == [False]


class TestAbsenceRowSemantics:
    """Absence rows must not fabricate feature or bounds evidence."""

    def test_no_fabricated_feature_or_severity_evidence(self, tmp_path: Path) -> None:
        """violated_features stays empty; severities stay NULL."""
        pg = _make_sqlite_connector(tmp_path)
        persister = AnomalyPersister(connector=pg)

        persister.persist_absence([_absence_result()], "conn", BASE + timedelta(seconds=5))

        row = _rows(pg)[0]
        assert row.violated_features == []
        assert row.violated_feature_count == 0
        assert row.violated_feature_details == {}
        assert row.feature_summary == {}
        assert row.ml_details == {}
        assert row.bound_severity_max is None
        assert row.bound_severity_mean is None

    def test_row_records_the_silence_itself(self, tmp_path: Path) -> None:
        """rate_summary carries silence duration and the last_seen anchor."""
        pg = _make_sqlite_connector(tmp_path)
        persister = AnomalyPersister(connector=pg)
        last_seen = BASE - timedelta(seconds=30)

        persister.persist_absence(
            [_absence_result(last_seen=last_seen)],
            "conn",
            BASE + timedelta(seconds=45),
        )

        summary = _rows(pg)[0].rate_summary
        assert summary["silence_seconds"] == pytest.approx(45.0)
        assert summary["absence_since"] == BASE.isoformat()
        assert summary["last_seen"] == last_seen.isoformat()

    def test_interval_starts_at_the_deadline_not_the_tick(self, tmp_path: Path) -> None:
        """start_ts is the absence deadline, not the moment of detection."""
        pg = _make_sqlite_connector(tmp_path)
        persister = AnomalyPersister(connector=pg)
        deadline = BASE
        tick = BASE + timedelta(seconds=120)

        persister.persist_absence([_absence_result(deadline=deadline)], "conn", tick)

        row = _rows(pg)[0]
        assert row.start_ts.replace(tzinfo=timezone.utc) == deadline
        assert row.end_ts.replace(tzinfo=timezone.utc) == tick


class TestAbsenceDoesNotSpam:
    """A continuously absent series must occupy one row, not one per tick."""

    def test_repeated_ticks_update_one_row(self, tmp_path: Path) -> None:
        """Twenty polls of the same silence produce a single row."""
        pg = _make_sqlite_connector(tmp_path)
        persister = AnomalyPersister(connector=pg)
        result = _absence_result()

        for tick in range(20):
            persister.persist_absence(
                [result],
                "conn",
                BASE + timedelta(seconds=5 * (tick + 1)),
            )

        rows = _rows(pg)
        assert len(rows) == 1
        assert rows[0].end_ts.replace(tzinfo=timezone.utc) == BASE + timedelta(seconds=100)

    def test_a_new_silence_episode_gets_its_own_row(self, tmp_path: Path) -> None:
        """A later deadline (after the series spoke again) opens a new row."""
        pg = _make_sqlite_connector(tmp_path)
        persister = AnomalyPersister(connector=pg)

        persister.persist_absence([_absence_result(deadline=BASE)], "conn", BASE + timedelta(seconds=10))
        second_deadline = BASE + timedelta(hours=1)
        persister.persist_absence(
            [_absence_result(deadline=second_deadline)],
            "conn",
            second_deadline + timedelta(seconds=10),
        )

        rows = _rows(pg)
        assert len(rows) == 2
        assert [r.start_ts.replace(tzinfo=timezone.utc) for r in rows] == [BASE, second_deadline]


class TestAbsenceGates:
    """Suppression is honoured; malformed results are refused."""

    def test_suppressed_series_is_not_written(self, tmp_path: Path) -> None:
        """An active suppression drops the absence row."""

        class _Entry:
            suppression_id = "sup-1"
            reason = "planned maintenance"

        class _Service:
            def is_suppressed(self, series_id: str, anomaly_type: str) -> object | None:
                if series_id == "s1" and anomaly_type == ABSENCE_ANOMALY:
                    return _Entry()
                return None

        pg = _make_sqlite_connector(tmp_path)
        persister = AnomalyPersister(connector=pg, suppression_service=_Service())

        count = persister.persist_absence([_absence_result()], "conn", BASE + timedelta(seconds=5))

        assert count == 0
        assert _rows(pg) == []

    def test_result_without_deadline_is_skipped(self, tmp_path: Path) -> None:
        """A malformed absence result never becomes a row."""
        pg = _make_sqlite_connector(tmp_path)
        persister = AnomalyPersister(connector=pg)
        broken = FrequencyResult(
            is_anomaly=True,
            anomaly_type=ABSENCE_ANOMALY,
            confidence=1.0,
            series_id="s1",
        )

        assert persister.persist_absence([broken], "conn", BASE) == 0
        assert _rows(pg) == []

    def test_frequency_anomaly_is_not_taken_by_the_absence_writer(self, tmp_path: Path) -> None:
        """persist_absence ignores FrequencyAnomaly results."""
        pg = _make_sqlite_connector(tmp_path)
        persister = AnomalyPersister(connector=pg)
        freq = FrequencyResult(
            is_anomaly=True,
            anomaly_type=FREQUENCY_ANOMALY,
            confidence=0.9,
            series_id="s1",
        )

        assert persister.persist_absence([freq], "conn", BASE) == 0
        assert _rows(pg) == []


class TestMonitorEmitsDeadline:
    """The monitor must supply the frozen deadline the writer relies on."""

    def test_absence_result_carries_a_stable_deadline(self) -> None:
        """absence_since is derived from last_seen, not from ``now``."""
        monitor = FrequencyMonitor(2.0, 3.0)
        last_seen = BASE
        monitor._profiles["s1"] = _SeriesFrequencyProfile(
            mean_interval=10.0,
            std_interval=1.0,
            last_seen=last_seen,
        )
        empty = pl.DataFrame()

        first = monitor.check(empty, "uci", (BASE + timedelta(seconds=60)).isoformat())
        second = monitor.check(empty, "uci", (BASE + timedelta(seconds=600)).isoformat())

        expected = last_seen + timedelta(seconds=30.0)
        assert first[0].absence_since == expected
        assert second[0].absence_since == expected
        assert first[0].last_seen == last_seen


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
