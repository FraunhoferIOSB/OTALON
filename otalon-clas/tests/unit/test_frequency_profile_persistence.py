"""Unit tests for the frequency-profile persistence layer.

Covers tasks 5.1 through 5.5 of OpenSpec change
``add-frequency-profile-persistence``:

* 5.1 — stats-only UPSERT preserves an existing override after re-training.
* 5.2 — effective-threshold resolution returns the global default when
  override is NULL, the override when set.
* 5.3 — feature flag off = no PG read/write, legacy RAM-only behaviour.
* 5.4 — bootstrap-load populates the cache; empty table logs once.
* 5.5 — invalidation callback updates the cached effective value
  without restart (the in-process equivalent of LISTEN/NOTIFY: the
  invalidator dispatches a payload → ``apply_invalidation`` re-fetches
  the row).

The tests run against an in-memory SQLite database. The
:class:`FrequencyProfileRepository` only depends on the
:class:`PostgresConnector` for sessions, and the ``frequency_profiles``
ORM model has no PG-specific columns; SQLite via SQLAlchemy is
sufficient to verify the stats-only UPSERT semantics and the
effective-threshold resolution. The PG-only LISTEN/NOTIFY wiring is
exercised in its in-process form (the callback path); the actual
``select.select()`` loop runs only against PostgreSQL and is left for
the Phase 7 validation gate.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import polars as pl
import pytest

from otalon_clas.common.postgres_connector import (
    FrequencyProfile,
    FrequencyProfileHistory,
    PostgresConnector,
)
from otalon_clas.detection.frequency_monitor import (
    ABSENCE_ANOMALY,
    FrequencyMonitor,
    _SeriesFrequencyProfile,
)
from otalon_clas.detection.frequency_profile_repository import (
    FrequencyProfileRepository,
)
from otalon_clas.runtime.training_helpers import FrequencyCandidate, publish_frequency_candidate


def _make_sqlite_connector(tmp_path: Path) -> PostgresConnector:
    """Build a PostgresConnector backed by a fresh SQLite file.

    Only the two frequency tables are created. The full
    ``Base.metadata.create_all`` is not used because some sibling ORM
    models (notably :class:`AnomalySuppression` with its PG ``ARRAY``
    column) don't compile under the SQLite dialect, and the rest of the
    schema is not needed for these tests.
    """
    db_path = tmp_path / "freq.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db_path}", pool_size=1, max_overflow=0)
    FrequencyProfile.__table__.create(pg.engine, checkfirst=True)
    FrequencyProfileHistory.__table__.create(pg.engine, checkfirst=True)
    return pg


def _make_training_frame(series_intervals: dict[str, list[float]]) -> pl.DataFrame:
    """Build a polars frame with `time` + `uci` columns from per-series intervals.

    Each entry maps a series_id to a list of consecutive inter-arrival
    times (seconds). The first row's `time` is fixed; subsequent rows
    accumulate the intervals.
    """
    base = datetime(2026, 6, 9, 12, 0, 0, tzinfo=timezone.utc)
    rows: list[dict[str, object]] = []
    for series_id, intervals in series_intervals.items():
        t = base
        rows.append({"uci": series_id, "time": t})
        for dt in intervals:
            t = t + timedelta(seconds=dt)
            rows.append({"uci": series_id, "time": t})
    return pl.DataFrame(rows)


# --------------------------------------------------------------------------- #
# 5.3 — feature flag off = no PG read/write
# --------------------------------------------------------------------------- #


class TestFeatureFlagOff:
    """When no repository is wired up, the monitor never hits PostgreSQL."""

    def test_train_without_repository_only_populates_ram(self) -> None:
        """A monitor with ``repository=None`` runs the legacy RAM-only path."""
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.5,
            absence_timeout_factor=4.0,
            repository=None,
            module_name="conn",
        )
        df = _make_training_frame({"s1": [1.0, 1.0, 1.0]})
        monitor.train(df, tag_key="uci")
        assert "s1" in monitor.profiles
        assert monitor.repository is None
        # No persistence wiring means bootstrap and invalidation are no-ops.
        assert monitor.bootstrap_from_repository() == 0
        monitor.apply_invalidation("s1")  # should not raise

    def test_effective_threshold_uses_global_default_when_no_override(self) -> None:
        """With no per-profile override, the global default applies."""
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.5,
            absence_timeout_factor=4.0,
        )
        df = _make_training_frame({"s1": [1.0, 1.0, 1.0]})
        monitor.train(df, tag_key="uci")
        assert monitor.effective_tolerance("s1") == pytest.approx(2.5)
        assert monitor.effective_absence_factor("s1") == pytest.approx(4.0)


# --------------------------------------------------------------------------- #
# 5.2 — effective-threshold resolution honours the override
# --------------------------------------------------------------------------- #


class TestEffectiveThresholdResolution:
    """``override ?? global_default`` semantics."""

    def test_override_wins_over_global_default(self) -> None:
        """An explicit override supersedes the global default."""
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
        )
        monitor._profiles["s1"] = _SeriesFrequencyProfile(
            mean_interval=1.0,
            std_interval=0.1,
            tolerance_factor_override=4.5,
            absence_factor_override=8.0,
        )
        assert monitor.effective_tolerance("s1") == pytest.approx(4.5)
        assert monitor.effective_absence_factor("s1") == pytest.approx(8.0)

    def test_null_override_falls_back(self) -> None:
        """A NULL override (None) falls back to the global default."""
        monitor = FrequencyMonitor(2.0, 3.0)
        monitor._profiles["s1"] = _SeriesFrequencyProfile(
            mean_interval=1.0,
            std_interval=0.1,
            tolerance_factor_override=None,
            absence_factor_override=None,
        )
        assert monitor.effective_tolerance("s1") == pytest.approx(2.0)
        assert monitor.effective_absence_factor("s1") == pytest.approx(3.0)

    def test_unknown_series_falls_back_to_global_default(self) -> None:
        """An effective lookup for a series with no cached profile returns the default."""
        monitor = FrequencyMonitor(2.0, 3.0)
        assert monitor.effective_tolerance("ghost") == pytest.approx(2.0)
        assert monitor.effective_absence_factor("ghost") == pytest.approx(3.0)


# --------------------------------------------------------------------------- #
# 5.1 — stats-only UPSERT preserves overrides across re-training
# --------------------------------------------------------------------------- #


class TestStatsOnlyUpsert:
    """``train()`` must never clobber operator-supplied override columns."""

    def test_existing_override_survives_retraining(self, tmp_path: Path) -> None:
        """Set an override → call train() again → override stays put."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=repo,
            module_name="conn",
        )
        # First training run — no override yet.
        df1 = _make_training_frame({"s1": [1.0, 1.0, 1.0, 1.0]})
        monitor.train(df1, tag_key="uci")

        # Operator sets an override directly in the DB (the MCP write
        # tools do this through PostgresRepo.update_frequency_profile;
        # here we go straight to the row to keep the test isolated to
        # the train() semantics).
        with pg.session() as session:
            row = (
                session.query(FrequencyProfile)
                .filter(
                    FrequencyProfile.module == "conn",
                    FrequencyProfile.series_id == "s1",
                )
                .one()
            )
            row.tolerance_factor_override = 4.5
            row.absence_factor_override = 6.0

        # Second training run with different stats.
        df2 = _make_training_frame({"s1": [2.0, 2.0, 2.0, 2.0]})
        monitor.train(df2, tag_key="uci")

        # The DB row must keep its overrides intact …
        with pg.session() as session:
            row = (
                session.query(FrequencyProfile)
                .filter(
                    FrequencyProfile.module == "conn",
                    FrequencyProfile.series_id == "s1",
                )
                .one()
            )
            assert row.tolerance_factor_override == pytest.approx(4.5)
            assert row.absence_factor_override == pytest.approx(6.0)
            # … while the stats columns reflect the second training run.
            assert row.mean_interval > 0.0

        # The in-memory cache must mirror the surviving overrides so
        # the next detection tick uses the operator-tuned thresholds.
        cached = monitor.profiles["s1"]
        assert cached.tolerance_factor_override == pytest.approx(4.5)
        assert cached.absence_factor_override == pytest.approx(6.0)
        assert monitor.effective_tolerance("s1") == pytest.approx(4.5)
        assert monitor.effective_absence_factor("s1") == pytest.approx(6.0)

    def test_first_train_inserts_with_null_overrides(self, tmp_path: Path) -> None:
        """A fresh ``train()`` writes the row with NULL overrides."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        df = _make_training_frame({"s1": [1.0, 1.0, 1.0]})
        monitor.train(df, tag_key="uci")
        with pg.session() as session:
            row = session.query(FrequencyProfile).filter(FrequencyProfile.module == "conn").one()
            assert row.tolerance_factor_override is None
            assert row.absence_factor_override is None


# --------------------------------------------------------------------------- #
# 5.4 — bootstrap-load populates the cache; empty table logs once
# --------------------------------------------------------------------------- #


class TestBootstrapLoad:
    """``bootstrap_from_repository`` is the LIVE-boot entry point."""

    def test_bootstrap_populates_cache_with_persisted_overrides(self, tmp_path: Path) -> None:
        """A persisted row with overrides becomes a cache entry on bootstrap."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        # Seed the table directly so the bootstrap actually loads something.
        with pg.session() as session:
            session.add(
                FrequencyProfile(
                    module="conn",
                    series_id="s1",
                    mean_interval=1.0,
                    std_interval=0.1,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                    tolerance_factor_override=3.5,
                    absence_factor_override=None,
                )
            )

        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=repo,
            module_name="conn",
        )
        loaded = monitor.bootstrap_from_repository()
        assert loaded == 1
        assert "s1" in monitor.profiles
        assert monitor.effective_tolerance("s1") == pytest.approx(3.5)
        # Absence override is NULL → global default takes over.
        assert monitor.effective_absence_factor("s1") == pytest.approx(3.0)

    def test_bootstrap_with_empty_table_returns_zero(self, tmp_path: Path) -> None:
        """An empty table yields a zero-loaded bootstrap (single INFO line)."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            absence_timeout_factor=3.0,
            repository=repo,
            module_name="conn",
        )
        loaded = monitor.bootstrap_from_repository()
        assert loaded == 0
        assert monitor.profiles == {}

    def test_bootstrap_only_loads_matching_module(self, tmp_path: Path) -> None:
        """Bootstrap is scoped to the monitor's module name."""
        pg = _make_sqlite_connector(tmp_path)
        with pg.session() as session:
            session.add(
                FrequencyProfile(
                    module="conn",
                    series_id="s_conn",
                    mean_interval=1.0,
                    std_interval=0.1,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                )
            )
            session.add(
                FrequencyProfile(
                    module="mac_traffic",
                    series_id="s_mac",
                    mean_interval=2.0,
                    std_interval=0.2,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                )
            )
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        loaded = monitor.bootstrap_from_repository()
        assert loaded == 1
        assert "s_conn" in monitor.profiles
        assert "s_mac" not in monitor.profiles


# --------------------------------------------------------------------------- #
# 5.5 — NOTIFY invalidation refreshes the cached effective value
# --------------------------------------------------------------------------- #


class TestInvalidationCallback:
    """Simulate a NOTIFY: external override → ``apply_invalidation`` → fresh cache."""

    def test_apply_invalidation_refreshes_overrides(self, tmp_path: Path) -> None:
        """After the DB row mutates, ``apply_invalidation`` reflects the change."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        # Seed initial profile with no override and bootstrap into cache.
        with pg.session() as session:
            session.add(
                FrequencyProfile(
                    module="conn",
                    series_id="s1",
                    mean_interval=1.0,
                    std_interval=0.1,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                    tolerance_factor_override=None,
                    absence_factor_override=None,
                )
            )
        monitor.bootstrap_from_repository()
        assert monitor.effective_tolerance("s1") == pytest.approx(2.0)

        # An MCP tool mutates the row (simulated by a direct update).
        with pg.session() as session:
            row = session.query(FrequencyProfile).filter(FrequencyProfile.module == "conn").one()
            row.tolerance_factor_override = 5.0

        # Before the NOTIFY fires, the cache is stale.
        assert monitor.effective_tolerance("s1") == pytest.approx(2.0)
        # The invalidator dispatches the NOTIFY → apply_invalidation runs.
        monitor.apply_invalidation("s1")
        assert monitor.effective_tolerance("s1") == pytest.approx(5.0)

    def test_apply_invalidation_for_deleted_row_drops_cache_entry(self, tmp_path: Path) -> None:
        """If the row is gone, the cache entry is removed."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        with pg.session() as session:
            session.add(
                FrequencyProfile(
                    module="conn",
                    series_id="s1",
                    mean_interval=1.0,
                    std_interval=0.1,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                )
            )
        monitor.bootstrap_from_repository()
        assert "s1" in monitor.profiles

        with pg.session() as session:
            row = session.query(FrequencyProfile).filter(FrequencyProfile.module == "conn").one()
            session.delete(row)
        monitor.apply_invalidation("s1")
        assert "s1" not in monitor.profiles


# --------------------------------------------------------------------------- #
# Audit M1 / M3 — periodic refresh / invalidation MERGE override columns into
# the existing cache; runtime ``last_seen`` is preserved across both paths.
# Regression for findings A1 / C-05 / A7 / B1.
# --------------------------------------------------------------------------- #


class TestRuntimeLastSeenPreservation:
    """The 60 s safety-net and the NOTIFY-driven invalidation MUST NOT wipe
    runtime ``last_seen`` — otherwise the absence check fires a spurious
    AbsenceAnomaly storm the moment the override is touched."""

    def test_periodic_refresh_preserves_last_seen_and_picks_up_override(self, tmp_path: Path) -> None:
        """Seed profile → simulate runtime last_seen update → operator changes
        override out-of-band → periodic refresh (``is_initial=False``) MUST
        keep runtime ``last_seen`` AND pull the new override into the cache.
        """
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")

        # Seed one profile with no override.
        with pg.session() as session:
            session.add(
                FrequencyProfile(
                    module="conn",
                    series_id="s1",
                    mean_interval=1.0,
                    std_interval=0.1,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                    tolerance_factor_override=None,
                    absence_factor_override=None,
                )
            )

        # Initial bootstrap loads everything (full load semantics).
        assert monitor.bootstrap_from_repository(is_initial=True) == 1
        assert monitor.profiles["s1"].last_seen is None

        # Simulate a runtime last_seen update (happens on the hot path).
        runtime_last_seen = datetime(2026, 6, 9, 14, 0, 0, tzinfo=timezone.utc)
        monitor._update_last_seen("s1", runtime_last_seen)
        assert monitor.profiles["s1"].last_seen == runtime_last_seen

        # Out-of-band, the operator (or NOTIFY-missing safety-net) sets a
        # tolerance override directly in the DB.
        with pg.session() as session:
            row = session.query(FrequencyProfile).filter(FrequencyProfile.module == "conn").one()
            row.tolerance_factor_override = 4.5

        # The 60 s periodic refresh fires.
        loaded = monitor.bootstrap_from_repository(is_initial=False)
        assert loaded == 1

        # Override was picked up …
        assert monitor.effective_tolerance("s1") == pytest.approx(4.5)
        # … AND runtime last_seen was preserved (this was the A1 bug:
        # the old code did self._profiles.clear() and reset last_seen
        # to whatever the DB carried, i.e. None).
        assert monitor.profiles["s1"].last_seen == runtime_last_seen

    def test_apply_invalidation_preserves_last_seen(self, tmp_path: Path) -> None:
        """NOTIFY path MUST not wipe the in-memory ``last_seen``."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")

        with pg.session() as session:
            session.add(
                FrequencyProfile(
                    module="conn",
                    series_id="s1",
                    mean_interval=1.0,
                    std_interval=0.1,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                    tolerance_factor_override=None,
                    absence_factor_override=None,
                )
            )
        monitor.bootstrap_from_repository(is_initial=True)
        runtime_last_seen = datetime(2026, 6, 9, 14, 0, 0, tzinfo=timezone.utc)
        monitor._update_last_seen("s1", runtime_last_seen)

        # Operator tunes override; NOTIFY fires → apply_invalidation runs.
        with pg.session() as session:
            row = session.query(FrequencyProfile).filter(FrequencyProfile.module == "conn").one()
            row.tolerance_factor_override = 5.0

        monitor.apply_invalidation("s1")

        # New override visible …
        assert monitor.effective_tolerance("s1") == pytest.approx(5.0)
        # … and runtime last_seen was NOT clobbered.
        assert monitor.profiles["s1"].last_seen == runtime_last_seen

    def test_periodic_refresh_picks_up_new_series_and_drops_removed(self, tmp_path: Path) -> None:
        """Series newly inserted in DB appear; series removed from DB drop."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")

        with pg.session() as session:
            session.add(
                FrequencyProfile(
                    module="conn",
                    series_id="s_keep",
                    mean_interval=1.0,
                    std_interval=0.1,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                )
            )
            session.add(
                FrequencyProfile(
                    module="conn",
                    series_id="s_drop",
                    mean_interval=2.0,
                    std_interval=0.2,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                )
            )
        monitor.bootstrap_from_repository(is_initial=True)
        assert "s_keep" in monitor.profiles
        assert "s_drop" in monitor.profiles

        # Mutate the DB: remove s_drop, add s_new.
        with pg.session() as session:
            (session.query(FrequencyProfile).filter(FrequencyProfile.series_id == "s_drop").delete())
            session.add(
                FrequencyProfile(
                    module="conn",
                    series_id="s_new",
                    mean_interval=3.0,
                    std_interval=0.3,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                )
            )

        monitor.bootstrap_from_repository(is_initial=False)
        assert "s_keep" in monitor.profiles
        assert "s_new" in monitor.profiles
        assert "s_drop" not in monitor.profiles

    def test_startup_profile_without_last_seen_does_not_raise_absence(self, tmp_path: Path) -> None:
        """A persisted profile is not absent until this process observes it."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        with pg.session() as session:
            session.add(
                FrequencyProfile(
                    module="conn",
                    series_id="s1",
                    mean_interval=10.0,
                    std_interval=1.0,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                )
            )
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        monitor.bootstrap_from_repository()

        results = monitor.check(
            pl.DataFrame({"uci": [], "time": []}),
            tag_key="uci",
            current_time=datetime(2026, 6, 9, 14, 1, tzinfo=timezone.utc).isoformat(),
        )

        assert [result for result in results if result.anomaly_type == ABSENCE_ANOMALY] == []

    def test_partial_publish_keeps_observed_profile_for_later_absence(self, tmp_path: Path) -> None:
        """Partial retraining must not discard an observed persisted series."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        monitor.train(_make_training_frame({"s1": [10.0], "s2": [10.0]}), "uci")
        observed_at = datetime(2026, 6, 9, 14, 0, tzinfo=timezone.utc)
        monitor.check(
            pl.DataFrame({"uci": ["s2"], "time": [observed_at]}),
            tag_key="uci",
            current_time=observed_at.isoformat(),
        )

        monitor.train(_make_training_frame({"s1": [20.0]}), "uci")
        results = monitor.check(
            pl.DataFrame({"uci": [], "time": []}),
            tag_key="uci",
            current_time=datetime(2026, 6, 9, 14, 0, 31, tzinfo=timezone.utc).isoformat(),
        )

        absence = [result for result in results if result.anomaly_type == ABSENCE_ANOMALY]
        assert [result.series_id for result in absence] == ["s2"]
        assert "s2" in monitor.profiles
        assert "s2" in repo.load_all("conn")


# --------------------------------------------------------------------------- #
# Retraining full-replace per module — a training run REPLACES the module's
# profile set instead of stacking on top of every earlier run (CLAS stale
# profile pile-up: 166 conn profiles, 129 with last_seen IS NULL).
# --------------------------------------------------------------------------- #


def _series_ids(repo: FrequencyProfileRepository, module: str) -> set[str]:
    """Return the persisted series ids for one module."""
    return set(repo.load_all(module))


def _set_override(pg: PostgresConnector, series_id: str, tolerance: float, absence: float) -> None:
    """Apply operator overrides directly on a persisted row."""
    with pg.session() as session:
        row = (
            session.query(FrequencyProfile)
            .filter(
                FrequencyProfile.module == "conn",
                FrequencyProfile.series_id == series_id,
            )
            .one()
        )
        row.tolerance_factor_override = tolerance
        row.absence_factor_override = absence


class TestFullReplaceRetraining:
    """``replace=True`` swaps the module's whole profile set atomically."""

    def test_retrain_drops_series_the_new_run_no_longer_covers(self, tmp_path: Path) -> None:
        """Train {A,B,C} → retrain {A,B} → only {A,B} persist; A keeps its override."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")

        monitor.train(
            _make_training_frame({"A": [1.0] * 6, "B": [2.0] * 6, "C": [3.0] * 6}),
            tag_key="uci",
            replace=True,
        )
        assert _series_ids(repo, "conn") == {"A", "B", "C"}
        _set_override(pg, "A", tolerance=4.5, absence=6.0)

        monitor.train(
            _make_training_frame({"A": [1.5] * 6, "B": [2.5] * 6}),
            tag_key="uci",
            replace=True,
        )

        assert _series_ids(repo, "conn") == {"A", "B"}
        surviving = repo.load_one("conn", "A")
        assert surviving is not None
        assert surviving.tolerance_factor_override == pytest.approx(4.5)
        assert surviving.absence_factor_override == pytest.approx(6.0)
        assert monitor.effective_tolerance("A") == pytest.approx(4.5)

        monitor.train(_make_training_frame({"A": [1.0] * 6}), tag_key="uci", replace=True)
        assert _series_ids(repo, "conn") == {"A"}
        final = repo.load_one("conn", "A")
        assert final is not None
        assert final.tolerance_factor_override == pytest.approx(4.5)

    def test_in_memory_cache_matches_persisted_set_after_replace(self, tmp_path: Path) -> None:
        """The RAM cache and the table agree on the surviving series."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")

        monitor.train(_make_training_frame({"A": [1.0] * 6, "C": [3.0] * 6}), "uci", replace=True)
        monitor.train(_make_training_frame({"A": [1.0] * 6}), "uci", replace=True)

        assert set(monitor.profiles) == {"A"}
        assert _series_ids(repo, "conn") == {"A"}
        assert set(monitor.profiles) == _series_ids(repo, "conn")

    def test_replace_is_scoped_to_the_module(self, tmp_path: Path) -> None:
        """A conn retrain never touches another module's profiles."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        with pg.session() as session:
            session.add(
                FrequencyProfile(
                    module="mac_traffic",
                    series_id="mac_series",
                    mean_interval=2.0,
                    std_interval=0.2,
                    last_seen=None,
                    trained_at=datetime.now(timezone.utc),
                )
            )
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")

        monitor.train(_make_training_frame({"A": [1.0] * 6}), "uci", replace=True)

        assert _series_ids(repo, "conn") == {"A"}
        assert _series_ids(repo, "mac_traffic") == {"mac_series"}

    def test_replace_false_keeps_the_legacy_additive_merge(self, tmp_path: Path) -> None:
        """The default publication still preserves series outside the run."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")

        monitor.train(_make_training_frame({"A": [1.0] * 6, "C": [3.0] * 6}), "uci")
        monitor.train(_make_training_frame({"A": [1.0] * 6}), "uci")

        assert _series_ids(repo, "conn") == {"A", "C"}
        assert set(monitor.profiles) == {"A", "C"}

    def test_empty_profile_set_never_wipes_the_module(self, tmp_path: Path) -> None:
        """An empty replace is refused before the transaction opens."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        monitor.train(_make_training_frame({"A": [1.0] * 6}), "uci", replace=True)

        with pytest.raises(ValueError, match="refusing replace=True"):
            repo.upsert_stats("conn", {}, replace=True)

        assert _series_ids(repo, "conn") == {"A"}

    def test_training_without_usable_intervals_keeps_the_profile_set(self, tmp_path: Path) -> None:
        """Insufficient evidence is not an empty topology — nothing is deleted."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        monitor.train(_make_training_frame({"A": [1.0] * 6, "C": [3.0] * 6}), "uci", replace=True)

        # One row per series yields zero inter-arrival intervals.
        monitor.train(_make_training_frame({"A": []}), "uci", replace=True)

        assert _series_ids(repo, "conn") == {"A", "C"}
        assert set(monitor.profiles) == {"A", "C"}

    def test_replace_reports_the_deleted_series(self, tmp_path: Path) -> None:
        """``StatsWriteResult.deleted`` names exactly the removed series."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        monitor.train(_make_training_frame({"A": [1.0] * 6, "B": [2.0] * 6, "C": [3.0] * 6}), "uci", replace=True)

        result = repo.upsert_stats("conn", monitor.compute_candidate_profiles(_make_training_frame({"A": [1.0] * 6}), "uci"), replace=True)

        assert result.deleted == ("B", "C")
        assert set(result.survivors) == {"A"}

    def test_replace_is_atomic_on_failure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A crash mid-swap leaves the previous profile set fully intact."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        monitor.train(_make_training_frame({"A": [1.0] * 6, "B": [2.0] * 6, "C": [3.0] * 6}), "uci", replace=True)
        _set_override(pg, "A", tolerance=4.5, absence=6.0)
        prior_rows = repo.snapshot_profiles("conn")

        def explode(*_args: object, **_kwargs: object) -> tuple[str, ...]:
            raise OSError("injected failure after the inserts, before the commit")

        monkeypatch.setattr(FrequencyProfileRepository, "_delete_stale", staticmethod(explode))
        candidates = monitor.compute_candidate_profiles(
            _make_training_frame({"A": [9.0] * 6, "D": [9.0] * 6}),
            "uci",
        )
        with pytest.raises(OSError, match="injected failure"):
            repo.upsert_stats("conn", candidates, replace=True)

        # Neither the deletes nor the freshly inserted series survived —
        # the whole swap rolled back to the pre-run generation.
        assert repo.snapshot_profiles("conn") == prior_rows
        assert _series_ids(repo, "conn") == {"A", "B", "C"}
        restored = repo.load_one("conn", "A")
        assert restored is not None
        assert restored.tolerance_factor_override == pytest.approx(4.5)

    def test_replace_notifies_peers_about_deleted_series(self, tmp_path: Path) -> None:
        """Deleted series get a cache-invalidation NOTIFY like published ones."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)
        monitor = FrequencyMonitor(2.0, 3.0, repository=repo, module_name="conn")
        monitor.train(_make_training_frame({"A": [1.0] * 6, "C": [3.0] * 6}), "uci", replace=True)

        notified: list[str] = []
        monitor._emit_notifies = lambda channel, series_ids: notified.extend(sorted(series_ids))  # type: ignore[method-assign]
        monitor.train(_make_training_frame({"A": [1.0] * 6}), "uci", replace=True, notify_channel="freq_chan")

        assert notified == ["A", "C"]


def test_publish_frequency_upsert_failure_keeps_real_cache_and_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Persist-first frequency publication exposes no candidate on upsert failure."""
    pg = _make_sqlite_connector(tmp_path)
    repo = FrequencyProfileRepository(connector=pg)
    monitor = FrequencyMonitor(repository=repo, module_name="conn")
    prior_df = _make_training_frame({"s1": [1.0, 1.0, 1.0]})
    monitor.train(prior_df, "uci")
    monitor._update_last_seen("s1", datetime(2026, 6, 9, 14, 0, tzinfo=timezone.utc))
    prior_rows = repo.snapshot_profiles("conn")
    prior_cache = monitor.profiles
    candidate = FrequencyCandidate(
        "conn", monitor.compute_candidate_profiles(_make_training_frame({"s1": [2.0, 2.0, 2.0]}), "uci")
    )

    def fail_upsert(*args: object, **kwargs: object) -> dict[str, tuple[float | None, float | None]]:
        raise OSError("injected frequency persistence failure")

    monkeypatch.setattr(repo, "upsert_stats", fail_upsert)
    with pytest.raises(OSError, match="injected frequency"):
        publish_frequency_candidate(SimpleNamespace(freq_monitor=monitor), candidate)

    assert repo.snapshot_profiles("conn") == prior_rows
    assert monitor.profiles == prior_cache


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
