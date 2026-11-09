"""Training-data repository for the alarm-group classifier.

Loads alarms from PostgreSQL and per-alarm raw network metrics from
InfluxDB, returning the matched rows ready for feature extraction. Used
during the offline training run; live inference uses the same matching
helpers but reads from the live InfluxDB and PostgreSQL.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

import polars as pl
from otalon_clas.common.influx_connector import InfluxModule
from otalon_clas.common.postgres_connector import (Alarm,
                                                          PostgresConnector)
from otalon_clas.ml.group_classifier.features import \
    series_ids_to_regex
from loguru import logger


@dataclass(frozen=True, slots=True)
class AlarmTrainingRecord:
    """Snapshot of an alarm row used as input for training/inference."""

    id: str
    start_ts: datetime
    end_ts: datetime
    series_ids: list[str]


class GroupClassifierTrainingRepository:
    """Provides training data: alarms in window + their underlying rows.

    Args:
        pg: PostgreSQL connector for alarm queries.
        influx: InfluxDB connector for network-metric queries (typically
            the ``conn`` module's :class:`InfluxModule`).
    """

    def __init__(self, pg: PostgresConnector, influx: InfluxModule) -> None:
        """Initialize the repository."""
        self._pg = pg
        self._influx = influx
        self._bulk_cache: pl.DataFrame | None = None
        self._bulk_cache_window: tuple[datetime, datetime] | None = None

    def fetch_alarms_in_window(
        self,
        start: datetime,
        stop: datetime,
    ) -> list[AlarmTrainingRecord]:
        """Fetch all alarms whose start_timestamp falls into ``[start, stop]``.

        Args:
            start: Inclusive window start (UTC-aware).
            stop: Inclusive window stop (UTC-aware).

        Returns:
            List of alarm snapshots ordered by start_timestamp ascending.
        """
        records: list[AlarmTrainingRecord] = []
        with self._pg.session() as session:
            query = (
                session.query(Alarm)
                .filter(Alarm.start_timestamp >= start)
                .filter(Alarm.start_timestamp <= stop)
                .order_by(Alarm.start_timestamp.asc())
            )
            for row in query.all():
                series_ids = row.series_ids or []
                if not isinstance(series_ids, list):
                    continue
                records.append(
                    AlarmTrainingRecord(
                        id=str(row.id),
                        start_ts=_ensure_utc(row.start_timestamp),
                        end_ts=_ensure_utc(row.end_timestamp),
                        series_ids=[str(s) for s in series_ids],
                    )
                )
        logger.info(
            "GroupClassifierTrainingRepository: fetched {} alarms in [{}, {}]",
            len(records),
            start.isoformat(),
            stop.isoformat(),
        )
        return records

    def fetch_influx_rows_for_alarm(self, alarm: AlarmTrainingRecord) -> pl.DataFrame:
        """Return the network-metric rows that match an alarm's series_ids.

        When a bulk window has been pre-fetched via
        :meth:`prefetch_window`, the rows are sliced from the cache and
        no InfluxDB query is issued. Otherwise the method falls back to
        a per-alarm query.

        Args:
            alarm: Alarm snapshot.

        Returns:
            Polars DataFrame containing the matching rows. Empty when
            the alarm has no series_ids or no rows match.
        """
        if not alarm.series_ids:
            return pl.DataFrame()

        # Zero- or near-zero-duration alarm windows confuse InfluxDB v3
        # (the planner refuses ``time < X`` predicates with no spread).
        # We also widen by a few seconds at both ends because alarm
        # timestamps are bucket-aligned and the originating raw rows can
        # fall slightly outside the bucket boundary.
        from datetime import timedelta

        # Live alarms inherit their timestamps from the underlying
        # ``_bucket_epoch`` aggregation grid (typically 5–60 seconds)
        # while the originating raw rows can fall slightly outside the
        # bucket boundary. Widen the window symmetrically so that
        # short-duration alarms still cover the actual traffic.
        margin = timedelta(seconds=60)
        widened_start = _ensure_utc(alarm.start_ts) - margin
        widened_stop = _ensure_utc(alarm.end_ts) + margin
        if (widened_stop - widened_start).total_seconds() < 1.0:
            widened_stop = widened_start + timedelta(seconds=1)

        cached = self._slice_from_cache(widened_start, widened_stop)
        if cached is not None:
            return filter_rows_by_series_ids(cached, alarm.series_ids)

        # InfluxDB v3 only accepts UTC ISO timestamps with a ``Z`` suffix
        # in its SQL query planner; ``+02:00`` style offsets cause an
        # empty result without a planner error. Always convert to UTC
        # before serialising.
        start_iso = widened_start.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        stop_iso = widened_stop.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        try:
            df = self._influx.fetch(start=start_iso, stop=stop_iso)
        except Exception as exc:
            logger.warning(
                "GroupClassifierTrainingRepository: influx fetch failed for "
                "alarm window [{}, {}]: {}",
                start_iso,
                stop_iso,
                exc,
            )
            return pl.DataFrame()
        logger.info(
            "GroupClassifierTrainingRepository: alarm window [{}, {}] "
            "fetched {} rows (alarm.series_ids={})",
            start_iso,
            stop_iso,
            len(df),
            len(alarm.series_ids),
        )
        if df.is_empty() or "uci" not in df.columns:
            return pl.DataFrame()

        return filter_rows_by_series_ids(df, alarm.series_ids)

    def prefetch_window(self, start: datetime, stop: datetime) -> int:
        """Bulk-fetch the InfluxDB window once and cache it for later slicing.

        Useful during training: a single query for the whole training
        window followed by per-alarm filtering avoids the many small
        round-trips that dominate runtime when iterating over hundreds of
        alarms.

        Args:
            start: Inclusive window start.
            stop: Inclusive window stop.

        Returns:
            Number of rows in the bulk cache. ``0`` when the window is empty.
        """
        df = self._influx.fetch(start=start.isoformat(), stop=stop.isoformat())
        if df.is_empty() or "uci" not in df.columns:
            self._bulk_cache = pl.DataFrame()
            self._bulk_cache_window = (start, stop)
            return 0
        if df.schema.get("time") != pl.Datetime:
            df = df.with_columns(pl.col("time").cast(pl.Datetime, strict=False))
        self._bulk_cache = df
        self._bulk_cache_window = (start, stop)
        logger.info(
            "GroupClassifierTrainingRepository: prefetched {} rows for [{}, {}]",
            len(df),
            start.isoformat(),
            stop.isoformat(),
        )
        return len(df)

    def _slice_from_cache(
        self,
        start: datetime,
        stop: datetime,
    ) -> pl.DataFrame | None:
        """Return cached rows within an alarm window, or ``None`` on cache miss."""
        if self._bulk_cache is None or self._bulk_cache_window is None:
            return None
        cache_start, cache_stop = self._bulk_cache_window
        if start < cache_start or stop > cache_stop:
            return None
        if self._bulk_cache.is_empty():
            return self._bulk_cache
        start_naive = start.replace(tzinfo=None) if start.tzinfo else start
        stop_naive = stop.replace(tzinfo=None) if stop.tzinfo else stop
        return self._bulk_cache.filter(
            (pl.col("time") >= start_naive) & (pl.col("time") <= stop_naive)
        )


def filter_rows_by_series_ids(
    df: pl.DataFrame,
    series_ids: Sequence[str],
) -> pl.DataFrame:
    """Filter a network-metric DataFrame to rows whose UCI matches a series_id.

    Wildcards (``*``) inside series_ids are treated as ``[^/]*`` regex
    segments to handle ephemeral ports.

    Args:
        df: Source DataFrame containing a ``uci`` column.
        series_ids: List of series_ids to match (possibly with wildcards).

    Returns:
        Filtered Polars DataFrame.
    """
    if df.is_empty() or "uci" not in df.columns or not series_ids:
        return df

    pattern = series_ids_to_regex(series_ids)
    pattern_str = pattern.pattern
    return df.filter(pl.col("uci").cast(pl.Utf8).str.contains(pattern_str))


def _ensure_utc(dt: datetime | None) -> datetime:
    """Ensure a datetime carries UTC timezone information.

    Args:
        dt: Optional datetime.

    Returns:
        UTC-aware datetime; defaults to current UTC when input is None.
    """
    if dt is None:
        return datetime.now(tz=timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
