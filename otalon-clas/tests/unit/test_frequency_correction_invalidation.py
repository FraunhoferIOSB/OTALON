"""Detector-side tests for the UI-101 rhythm-correction contract.

Covers ``cyberclas--frequency-profile-corrections``:

* A committed notification for a profile an active detector uses makes
  the next frequency evaluation apply the updated effective factors,
  without a process restart.
* A notification naming a different series leaves an active detector's
  cached state untouched.
* Re-training updates learned cadence statistics while both persisted
  operator overrides survive.

Runs against an in-memory SQLite database, the same substitute the
sibling persistence suite uses: the two frequency ORM models carry no
PostgreSQL-specific columns, so the cache/override semantics under test
are fully exercised. Only the ``select.select()`` LISTEN loop is
PostgreSQL-only; the in-process equivalent (dispatching a payload into
:meth:`FrequencyMonitor.apply_invalidation`) is what the invalidator
thread ultimately calls, so that is what is asserted here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import polars as pl
import pytest

from otalon_clas.common.postgres_connector import (
    FrequencyProfile,
    FrequencyProfileHistory,
    PostgresConnector,
)
from otalon_clas.detection.frequency_monitor import ABSENCE_ANOMALY, FrequencyMonitor
from otalon_clas.detection.frequency_profile_repository import FrequencyProfileRepository

NOW = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


def _connector(tmp_path: Path) -> PostgresConnector:
    """Build a PostgresConnector backed by a fresh SQLite file."""
    pg = PostgresConnector(dsn=f"sqlite:///{tmp_path / 'freq.sqlite'}", pool_size=1, max_overflow=0)
    FrequencyProfile.__table__.create(pg.engine, checkfirst=True)
    FrequencyProfileHistory.__table__.create(pg.engine, checkfirst=True)
    return pg


def _seed(
    pg: PostgresConnector,
    series_id: str,
    mean_interval: float = 10.0,
    std_interval: float = 1.0,
    last_seen: datetime | None = None,
    tolerance_override: float | None = None,
    absence_override: float | None = None,
) -> None:
    """Insert one persisted profile row."""
    with pg.session() as session:
        session.add(
            FrequencyProfile(
                module="conn",
                series_id=series_id,
                mean_interval=mean_interval,
                std_interval=std_interval,
                last_seen=last_seen,
                trained_at=NOW - timedelta(days=1),
                tolerance_factor_override=tolerance_override,
                absence_factor_override=absence_override,
            )
        )


def _apply_override(
    pg: PostgresConnector,
    series_id: str,
    tolerance: float | None = None,
    absence: float | None = None,
) -> None:
    """Mutate the persisted override columns exactly as the API commit does."""
    with pg.session() as session:
        row = (
            session.query(FrequencyProfile)
            .filter(
                FrequencyProfile.module == "conn",
                FrequencyProfile.series_id == series_id,
            )
            .one()
        )
        row.tolerance_factor_override = tolerance  # type: ignore[assignment]  # SQLAlchemy 1.x Column descriptor
        row.absence_factor_override = absence  # type: ignore[assignment]  # SQLAlchemy 1.x Column descriptor


def _training_frame(series_intervals: dict[str, list[float]]) -> pl.DataFrame:
    """Build a ``time``/``uci`` frame from per-series inter-arrival times."""
    rows: list[dict[str, object]] = []
    for series_id, intervals in series_intervals.items():
        stamp = NOW - timedelta(hours=1)
        rows.append({"uci": series_id, "time": stamp})
        for delta in intervals:
            stamp = stamp + timedelta(seconds=delta)
            rows.append({"uci": series_id, "time": stamp})
    return pl.DataFrame(rows)


class TestNotifiedProfileReload:
    """A committed notification changes the next evaluation, no restart."""

    def test_notified_absence_override_stops_next_absence_verdict(self, tmp_path: Path) -> None:
        """Widening absence_factor.override silences the next absence check."""
        pg = _connector(tmp_path)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            absence_timeout_std_factor=0.0,
            absence_timeout_floor_seconds=0.0,
            repository=FrequencyProfileRepository(connector=pg),
            module_name="conn",
        )
        _seed(pg, "s1", mean_interval=10.0, std_interval=1.0)
        monitor.bootstrap_from_repository()
        # Set last_seen through the runtime path: the SQLite test backend
        # returns DateTime(timezone=True) columns naive, which the detector's
        # timezone-aware arithmetic (correctly) refuses.
        monitor._update_last_seen("s1", NOW - timedelta(seconds=100))

        before = monitor.check(pl.DataFrame({"uci": [], "time": []}), "uci", NOW.isoformat())
        assert [result.anomaly_type for result in before] == [ABSENCE_ANOMALY]

        _apply_override(pg, "s1", absence=20.0)
        monitor.apply_invalidation("s1")

        assert monitor.effective_absence_factor("s1") == pytest.approx(20.0)
        after = monitor.check(pl.DataFrame({"uci": [], "time": []}), "uci", NOW.isoformat())
        assert after == []

    def test_notified_tolerance_override_changes_effective_factor(self, tmp_path: Path) -> None:
        """The reloaded tolerance override supersedes the global default."""
        pg = _connector(tmp_path)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=FrequencyProfileRepository(connector=pg),
            module_name="conn",
        )
        _seed(pg, "s1")
        monitor.bootstrap_from_repository()
        assert monitor.effective_tolerance("s1") == pytest.approx(2.0)

        _apply_override(pg, "s1", tolerance=6.5)
        monitor.apply_invalidation("s1")

        assert monitor.effective_tolerance("s1") == pytest.approx(6.5)

    def test_cleared_override_restores_global_default(self, tmp_path: Path) -> None:
        """An audited restore-to-default is reloaded as the global default."""
        pg = _connector(tmp_path)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=FrequencyProfileRepository(connector=pg),
            module_name="conn",
        )
        _seed(pg, "s1", tolerance_override=7.0, absence_override=9.0)
        monitor.bootstrap_from_repository()
        assert monitor.effective_tolerance("s1") == pytest.approx(7.0)

        _apply_override(pg, "s1", tolerance=None, absence=None)
        monitor.apply_invalidation("s1")

        assert monitor.effective_tolerance("s1") == pytest.approx(2.0)
        assert monitor.effective_absence_factor("s1") == pytest.approx(3.0)

    def test_reload_reanchors_a_still_open_absence_episode(self, tmp_path: Path) -> None:
        """A corrected profile must not re-emit the pre-correction deadline.

        An open episode freezes its deadline anchor and re-emits it for
        as long as the silence lasts. Without dropping that episode on a
        correction, a later absence verdict for the same silence would
        still be stamped with the anchor derived from the OLD absence
        factor — reporting a deadline the corrected detector would never
        have produced.
        """
        pg = _connector(tmp_path)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            absence_timeout_std_factor=0.0,
            absence_timeout_floor_seconds=0.0,
            repository=FrequencyProfileRepository(connector=pg),
            module_name="conn",
        )
        _seed(pg, "s1", mean_interval=10.0, std_interval=1.0)
        monitor.bootstrap_from_repository()
        last_seen = NOW - timedelta(seconds=100)
        monitor._update_last_seen("s1", last_seen)

        empty = pl.DataFrame({"uci": [], "time": []})
        opened = monitor.check(empty, "uci", NOW.isoformat())
        stale_anchor = opened[0].absence_since
        assert stale_anchor == last_seen + timedelta(seconds=30.0)

        # Widen the factor: 10 s x 6 = 60 s timeout, still under the 100 s
        # silence, so the series stays absent — but under a new deadline.
        _apply_override(pg, "s1", absence=6.0)
        monitor.apply_invalidation("s1")

        reopened = monitor.check(empty, "uci", NOW.isoformat())
        assert [result.anomaly_type for result in reopened] == [ABSENCE_ANOMALY]
        assert reopened[0].absence_since == last_seen + timedelta(seconds=60.0)
        assert reopened[0].absence_since != stale_anchor

    def test_reload_preserves_runtime_last_seen(self, tmp_path: Path) -> None:
        """The correction must not look like 'never seen' to absence detection."""
        pg = _connector(tmp_path)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=FrequencyProfileRepository(connector=pg),
            module_name="conn",
        )
        _seed(pg, "s1", last_seen=None)
        monitor.bootstrap_from_repository()
        runtime_last_seen = NOW - timedelta(seconds=5)
        monitor._update_last_seen("s1", runtime_last_seen)

        _apply_override(pg, "s1", absence=12.0)
        monitor.apply_invalidation("s1")

        assert monitor.profiles["s1"].last_seen == runtime_last_seen


class TestUnrelatedProfileUntouched:
    """A notification for another series leaves this detector's state alone."""

    def test_unrelated_series_retains_cached_overrides(self, tmp_path: Path) -> None:
        """Invalidating s2 does not touch s1's cached override or last_seen."""
        pg = _connector(tmp_path)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=FrequencyProfileRepository(connector=pg),
            module_name="conn",
        )
        _seed(pg, "s1", tolerance_override=4.0)
        _seed(pg, "s2", tolerance_override=None)
        monitor.bootstrap_from_repository()
        s1_last_seen = NOW - timedelta(seconds=7)
        monitor._update_last_seen("s1", s1_last_seen)

        _apply_override(pg, "s2", tolerance=8.0)
        monitor.apply_invalidation("s2")

        assert monitor.effective_tolerance("s2") == pytest.approx(8.0)
        assert monitor.effective_tolerance("s1") == pytest.approx(4.0)
        assert monitor.profiles["s1"].last_seen == s1_last_seen

    def test_unknown_series_notification_is_a_noop(self, tmp_path: Path) -> None:
        """A notification for a series with no row adds nothing to the cache."""
        pg = _connector(tmp_path)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=FrequencyProfileRepository(connector=pg),
            module_name="conn",
        )
        _seed(pg, "s1")
        monitor.bootstrap_from_repository()

        monitor.apply_invalidation("does-not-exist")

        assert set(monitor.profiles) == {"s1"}


class TestRetrainingPreservesOverrides:
    """Learned cadence updates; both persisted overrides survive."""

    def test_retraining_updates_cadence_and_keeps_both_overrides(self, tmp_path: Path) -> None:
        """A retrain rewrites mean/std but never the two override columns."""
        pg = _connector(tmp_path)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=FrequencyProfileRepository(connector=pg),
            module_name="conn",
        )
        _seed(pg, "s1", mean_interval=10.0, std_interval=1.0)
        monitor.bootstrap_from_repository()

        _apply_override(pg, "s1", tolerance=5.5, absence=11.25)
        monitor.apply_invalidation("s1")

        monitor.train(_training_frame({"s1": [2.0, 2.0, 2.0, 2.0]}), tag_key="uci")

        with pg.session() as session:
            row = (
                session.query(FrequencyProfile)
                .filter(FrequencyProfile.module == "conn", FrequencyProfile.series_id == "s1")
                .one()
            )
            assert float(row.mean_interval) == pytest.approx(2.0)
            assert float(row.tolerance_factor_override) == pytest.approx(5.5)
            assert float(row.absence_factor_override) == pytest.approx(11.25)

        assert monitor.effective_tolerance("s1") == pytest.approx(5.5)
        assert monitor.effective_absence_factor("s1") == pytest.approx(11.25)

    def test_correction_after_retraining_still_reloads(self, tmp_path: Path) -> None:
        """Correction and retraining compose in either order."""
        pg = _connector(tmp_path)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=FrequencyProfileRepository(connector=pg),
            module_name="conn",
        )
        _seed(pg, "s1", mean_interval=10.0, std_interval=1.0)
        monitor.bootstrap_from_repository()
        monitor.train(_training_frame({"s1": [4.0, 4.0, 4.0, 4.0]}), tag_key="uci")

        _apply_override(pg, "s1", absence=15.0)
        monitor.apply_invalidation("s1")

        assert monitor.effective_absence_factor("s1") == pytest.approx(15.0)
        assert monitor.profiles["s1"].mean_interval == pytest.approx(4.0)

    def test_replace_retrain_keeps_temporarily_absent_overrides(self, tmp_path: Path) -> None:
        """A stale overridden row remains available across a replacement run."""
        pg = _connector(tmp_path)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=FrequencyProfileRepository(connector=pg),
            module_name="conn",
        )
        _seed(pg, "s1", tolerance_override=5.5, absence_override=11.25)
        monitor.bootstrap_from_repository()

        monitor.train(_training_frame({"s2": [4.0, 4.0, 4.0, 4.0]}), tag_key="uci", replace=True)

        with pg.session() as session:
            row = (
                session.query(FrequencyProfile)
                .filter(FrequencyProfile.module == "conn", FrequencyProfile.series_id == "s1")
                .one()
            )
            assert row.tolerance_factor_override == pytest.approx(5.5)
            assert row.absence_factor_override == pytest.approx(11.25)
        assert monitor.effective_tolerance("s1") == pytest.approx(5.5)
        assert monitor.effective_absence_factor("s1") == pytest.approx(11.25)
