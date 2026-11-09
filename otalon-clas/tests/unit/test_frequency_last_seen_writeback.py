"""Unit tests for the runtime ``last_seen`` write-back path.

Before this path existed, ``_update_last_seen`` mutated only the
in-memory cache and the sole PostgreSQL writer (``upsert_stats``) ran
from the TRAINING path. The persisted ``frequency_profiles.last_seen``
therefore froze at the last training run, and after a container restart
absence detection resumed from a stale timestamp.

These tests pin the three binding constraints of the write-back:

* it must never touch the operator override columns;
* it must never bump ``trained_at``;
* it must not fight the periodic-refresh merge that deliberately
  preserves runtime ``last_seen`` over DB values (audit M1 / A1 / C-05).
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
from otalon_clas.detection.frequency_monitor import FrequencyMonitor
from otalon_clas.detection.frequency_profile_repository import (
    FrequencyProfileRepository,
)
from otalon_clas.main import _detect

BASE = datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)
TRAINED_AT = datetime(2026, 7, 20, 3, 0, 0, tzinfo=timezone.utc)


def _make_sqlite_connector(tmp_path: Path) -> PostgresConnector:
    """Build a PostgresConnector backed by a fresh SQLite file."""
    db_path = tmp_path / "freq.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db_path}", pool_size=1, max_overflow=0)
    FrequencyProfile.__table__.create(pg.engine, checkfirst=True)
    FrequencyProfileHistory.__table__.create(pg.engine, checkfirst=True)
    return pg


def _seed(
    pg: PostgresConnector,
    series_id: str = "s1",
    last_seen: datetime | None = None,
    tolerance: float | None = None,
    absence: float | None = None,
) -> None:
    """Insert one persisted profile row."""
    with pg.session() as session:
        session.add(
            FrequencyProfile(
                module="conn",
                series_id=series_id,
                mean_interval=10.0,
                std_interval=1.0,
                last_seen=last_seen,
                trained_at=TRAINED_AT,
                tolerance_factor_override=tolerance,
                absence_factor_override=absence,
            )
        )


def _row(pg: PostgresConnector, series_id: str = "s1") -> FrequencyProfile:
    """Fetch one persisted profile row."""
    with pg.session() as session:
        return (
            session.query(FrequencyProfile)
            .filter(
                FrequencyProfile.module == "conn",
                FrequencyProfile.series_id == series_id,
            )
            .one()
        )


def _monitor(
    pg: PostgresConnector,
    flush_interval: int = 60,
) -> tuple[FrequencyMonitor, FrequencyProfileRepository]:
    """Build a bootstrapped monitor wired to the repository."""
    repo = FrequencyProfileRepository(connector=pg)
    monitor = FrequencyMonitor(
        2.0,
        3.0,
        repository=repo,
        module_name="conn",
        last_seen_flush_interval_seconds=flush_interval,
    )
    monitor.bootstrap_from_repository()
    return monitor, repo


def _observe(monitor: FrequencyMonitor, series_id: str, at: datetime) -> None:
    """Run one detection tick in which ``series_id`` is observed."""
    monitor.check(
        pl.DataFrame({"uci": [series_id], "time": [at]}),
        tag_key="uci",
        current_time=at.isoformat(),
    )


class TestRepositoryUpdateLastSeen:
    """The narrow single-column writer."""

    def test_writes_last_seen(self, tmp_path: Path) -> None:
        """A persisted row receives the runtime timestamp."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        repo = FrequencyProfileRepository(connector=pg)

        assert repo.update_last_seen("conn", {"s1": BASE}) == 1
        assert _row(pg).last_seen.replace(tzinfo=timezone.utc) == BASE

    def test_never_touches_override_columns(self, tmp_path: Path) -> None:
        """Operator tuning survives the write-back."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg, tolerance=4.5, absence=8.0)
        repo = FrequencyProfileRepository(connector=pg)

        repo.update_last_seen("conn", {"s1": BASE})

        row = _row(pg)
        assert row.tolerance_factor_override == pytest.approx(4.5)
        assert row.absence_factor_override == pytest.approx(8.0)

    def test_never_bumps_trained_at(self, tmp_path: Path) -> None:
        """Observing traffic is not training."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        repo = FrequencyProfileRepository(connector=pg)

        repo.update_last_seen("conn", {"s1": BASE})

        assert _row(pg).trained_at.replace(tzinfo=timezone.utc) == TRAINED_AT

    def test_never_touches_trained_statistics(self, tmp_path: Path) -> None:
        """mean/std stay exactly as trained."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        repo = FrequencyProfileRepository(connector=pg)

        repo.update_last_seen("conn", {"s1": BASE})

        row = _row(pg)
        assert row.mean_interval == pytest.approx(10.0)
        assert row.std_interval == pytest.approx(1.0)

    def test_does_not_insert_unknown_series(self, tmp_path: Path) -> None:
        """A last_seen without trained stats would be a cadence-less profile."""
        pg = _make_sqlite_connector(tmp_path)
        repo = FrequencyProfileRepository(connector=pg)

        assert repo.update_last_seen("conn", {"ghost": BASE}) == 0
        with pg.session() as session:
            assert session.query(FrequencyProfile).count() == 0

    def test_older_timestamp_does_not_overwrite_newer(self, tmp_path: Path) -> None:
        """The write-back is monotonic."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg, last_seen=BASE)
        repo = FrequencyProfileRepository(connector=pg)

        assert repo.update_last_seen("conn", {"s1": BASE - timedelta(minutes=5)}) == 0
        assert _row(pg).last_seen.replace(tzinfo=timezone.utc) == BASE

    def test_is_scoped_to_the_module(self, tmp_path: Path) -> None:
        """A same-named series in another module is untouched."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        with pg.session() as session:
            session.add(
                FrequencyProfile(
                    module="mac_traffic",
                    series_id="s1",
                    mean_interval=10.0,
                    std_interval=1.0,
                    last_seen=None,
                    trained_at=TRAINED_AT,
                )
            )
        repo = FrequencyProfileRepository(connector=pg)

        repo.update_last_seen("conn", {"s1": BASE})

        with pg.session() as session:
            other = session.query(FrequencyProfile).filter(FrequencyProfile.module == "mac_traffic").one()
            assert other.last_seen is None


class TestMonitorFlushBatching:
    """The flush must be batched, not one write per series per tick."""

    def test_observation_alone_does_not_write(self, tmp_path: Path) -> None:
        """The interval gate holds the write back."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        monitor, _ = _monitor(pg, flush_interval=3600)

        _observe(monitor, "s1", BASE)
        monitor.flush_last_seen()

        assert _row(pg).last_seen is None
        assert monitor.profiles["s1"].last_seen == BASE

    def test_forced_flush_writes(self, tmp_path: Path) -> None:
        """A forced flush drains the dirty set regardless of the interval."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        monitor, _ = _monitor(pg, flush_interval=3600)

        _observe(monitor, "s1", BASE)
        assert monitor.flush_last_seen(force=True) == 1
        assert _row(pg).last_seen.replace(tzinfo=timezone.utc) == BASE

    def test_many_ticks_collapse_into_one_write(self, tmp_path: Path) -> None:
        """Fifty polls of one series produce one UPDATE carrying the newest value."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        monitor, repo = _monitor(pg, flush_interval=3600)
        calls: list[dict[str, datetime]] = []
        original = repo.update_last_seen

        def _recording(module: str, last_seen: dict[str, datetime]) -> int:
            calls.append(dict(last_seen))
            return original(module, last_seen)

        repo.update_last_seen = _recording  # type: ignore[method-assign]

        for tick in range(50):
            _observe(monitor, "s1", BASE + timedelta(seconds=5 * tick))
            monitor.flush_last_seen()
        monitor.flush_last_seen(force=True)

        assert len(calls) == 1
        assert calls[0] == {"s1": BASE + timedelta(seconds=245)}

    def test_flush_with_nothing_dirty_is_a_noop(self, tmp_path: Path) -> None:
        """No observations means no write."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        monitor, _ = _monitor(pg, flush_interval=3600)

        assert monitor.flush_last_seen(force=True) == 0

    def test_failed_flush_retries_on_the_next_attempt(self, tmp_path: Path) -> None:
        """A transient DB failure must not silently drop the pending values."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        monitor, repo = _monitor(pg, flush_interval=3600)
        original = repo.update_last_seen
        attempts: list[int] = []

        def _failing(module: str, last_seen: dict[str, datetime]) -> int:
            attempts.append(1)
            raise OSError("injected write failure")

        repo.update_last_seen = _failing  # type: ignore[method-assign]
        _observe(monitor, "s1", BASE)
        assert monitor.flush_last_seen(force=True) == 0
        assert len(attempts) == 1

        repo.update_last_seen = original  # type: ignore[method-assign]
        assert monitor.flush_last_seen(force=True) == 1
        assert _row(pg).last_seen.replace(tzinfo=timezone.utc) == BASE

    def test_no_repository_means_no_flush(self, tmp_path: Path) -> None:
        """RAM-only mode is unaffected."""
        monitor = FrequencyMonitor(2.0, 3.0)
        monitor.train(pl.DataFrame({"uci": ["s1", "s1"], "time": [BASE, BASE + timedelta(seconds=10)]}), "uci")

        _observe(monitor, "s1", BASE + timedelta(seconds=20))

        assert monitor.flush_last_seen(force=True) == 0


def test_live_detect_updates_exact_profile_when_prediction_uci_is_collapsed(tmp_path: Path) -> None:
    """Live frequency monitoring keeps raw trained UCIs distinct from collapsed ML UCIs."""
    pg = _make_sqlite_connector(tmp_path)
    uci = "00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/192.168.0.2/192.168.0.41/50000/56247/Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
    _seed(pg, series_id=uci)
    monitor, _ = _monitor(pg, flush_interval=3600)

    class _Config:
        name = "conn"
        tag_key = "uci"
        features = ["packet_count"]

    class _Bounds:
        def check(self, df: pl.DataFrame, tag_key: str, features: list[str]) -> pl.DataFrame:
            return df.with_columns(
                pl.lit(False).alias("is_anomaly"),
                pl.lit("").alias("anomaly_type"),
                pl.lit(0.0).alias("confidence"),
                pl.lit("").alias("violated_features"),
                pl.lit(0.0).alias("severity"),
            )

    class _Bundle:
        config = _Config()
        freq_monitor = monitor
        bounds_manager = _Bounds()
        label_map = {}
        ml_pipeline = None

    raw = pl.DataFrame({"uci": [uci], "time": [BASE], "packet_count": [1.0]})
    collapsed = raw.with_columns(pl.col("uci").str.replace("50000/56247", "*/*"))

    _detect(_Bundle(), collapsed, raw, BASE.isoformat())

    assert monitor.profiles[uci].last_seen == BASE


class TestFlushDoesNotFightTheRefreshMerge:
    """Regression guard for audit M1 / A1 / C-05."""

    def test_periodic_refresh_after_flush_keeps_runtime_value(self, tmp_path: Path) -> None:
        """Write-back then merge must not regress the in-memory timestamp."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        monitor, _ = _monitor(pg, flush_interval=3600)

        _observe(monitor, "s1", BASE)
        monitor.flush_last_seen(force=True)
        newer = BASE + timedelta(seconds=30)
        _observe(monitor, "s1", newer)

        monitor.bootstrap_from_repository(is_initial=False)

        assert monitor.profiles["s1"].last_seen == newer
        assert _row(pg).last_seen.replace(tzinfo=timezone.utc) == BASE

    def test_flush_does_not_resurrect_a_stale_value_after_invalidation(self, tmp_path: Path) -> None:
        """An override NOTIFY between observation and flush changes nothing."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        monitor, _ = _monitor(pg, flush_interval=3600)

        _observe(monitor, "s1", BASE)
        with pg.session() as session:
            session.query(FrequencyProfile).filter(
                FrequencyProfile.series_id == "s1"
            ).one().tolerance_factor_override = 4.5
        monitor.apply_invalidation("s1")
        monitor.flush_last_seen(force=True)

        row = _row(pg)
        assert row.last_seen.replace(tzinfo=timezone.utc) == BASE
        assert row.tolerance_factor_override == pytest.approx(4.5)
        assert monitor.profiles["s1"].last_seen == BASE


class TestRestartResumesFromReality:
    """The reason the write-back exists."""

    def test_restart_picks_up_the_runtime_timestamp(self, tmp_path: Path) -> None:
        """After a flush, a fresh monitor bootstraps to the observed value."""
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg)
        monitor, _ = _monitor(pg, flush_interval=3600)
        _observe(monitor, "s1", BASE)
        monitor.flush_last_seen(force=True)

        restarted, _ = _monitor(pg)

        assert restarted.profiles["s1"].last_seen.replace(tzinfo=timezone.utc) == BASE

    def test_observed_series_becomes_durable_without_any_training(self, tmp_path: Path) -> None:
        """Part-3 root cause: a NULL last_seen resolves through observation alone.

        Previously ``last_seen`` could only ever become non-NULL as a
        side effect of a training run carrying the RAM value along, so
        a profile for a series that was never observed *between two
        trainings* stayed NULL forever and was permanently exempt from
        absence detection.
        """
        pg = _make_sqlite_connector(tmp_path)
        _seed(pg, last_seen=None)
        monitor, _ = _monitor(pg, flush_interval=3600)
        assert _row(pg).last_seen is None

        _observe(monitor, "s1", BASE)
        monitor.flush_last_seen(force=True)

        assert _row(pg).last_seen.replace(tzinfo=timezone.utc) == BASE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
