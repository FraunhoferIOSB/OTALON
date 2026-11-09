"""InfluxDB v3 repository.

Wraps the ``influxdb3-python`` client for time-series queries used by
the timeseries, anomaly, and aggregation services.  All queries use
InfluxDB v3 SQL (not Flux).

Key design decision: **time is kept as a column**, never set as the
DataFrame index.  This differs from the legacy UI repository and
simplifies downstream JSON serialization.
"""

from __future__ import annotations

import math
import re
from time import perf_counter
from typing import Any, Dict, List, Optional, Sequence, Union

import pandas as pd
from influxdb_client_3 import InfluxDBClient3
from loguru import logger

from otalon_api.domain.time import time_policy

NICE_BUCKETS: List[int] = [
    1,
    2,
    5,
    10,
    15,
    30,
    60,
    120,
    300,
    600,
    900,
    1800,
    3600,
    7200,
    21600,
    43200,
    86400,
]


DATA_EXTENT_BAND_DAYS: List[int] = [1, 7, 30, 180, 365, 1095, 1825]

DATA_EXTENT_FLOOR: "pd.Timestamp" = pd.Timestamp("1970-01-01T00:00:00Z")

DATA_EXTENT_CACHE_TTL_SECONDS: float = 300.0


def is_broadcast_or_multicast_mac(mac: str) -> bool:
    """Return whether *mac* is an IEEE broadcast or multicast address.

    Args:
        mac: MAC address, with or without separators.

    Returns:
        ``True`` for the all-FF broadcast address or an address whose first
        octet has the multicast bit set.
    """
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if cleaned == "ffffffffffff":
        return True
    if len(cleaned) < 2:
        return False
    try:
        return bool(int(cleaned[:2], 16) & 1)
    except ValueError:
        return False


def _extent_bands(edges: Sequence[int]) -> List[tuple[int, int]]:
    """Build disjoint ``(lower_days, upper_days)`` bands from band edges.

    Bands are disjoint on purpose: a single widening window would keep
    re-scanning the dense recent tail, which is what makes a wide extent
    query expensive.

    Args:
        edges: Ascending band edges in days, starting at the anchor.

    Returns:
        Bands ordered nearest-to-oldest, each ``lower`` further back in time
        than its ``upper``.
    """
    bounds = [0, *edges]
    return [(bounds[i + 1], bounds[i]) for i in range(len(bounds) - 1)]


def _extent_literal(value: "pd.Timestamp") -> str:
    """Render a timestamp as a millisecond-precision SQL literal.

    Args:
        value: Timezone-aware or naive timestamp.

    Returns:
        An ISO-8601 string with a trailing ``Z``.
    """
    return value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _to_sql_interval_literal(seconds: int) -> str:
    """Convert a number of seconds to an InfluxDB SQL ``INTERVAL`` literal.

    Args:
        seconds: Duration in seconds (at least 1).

    Returns:
        An SQL ``INTERVAL`` string, e.g. ``INTERVAL '5 minutes'``.
    """
    s = max(1, int(seconds))
    if s % 86400 == 0:
        v = s // 86400
        return f"INTERVAL '{v} {'day' if v == 1 else 'days'}'"
    if s % 3600 == 0:
        v = s // 3600
        return f"INTERVAL '{v} {'hour' if v == 1 else 'hours'}'"
    if s % 60 == 0:
        v = s // 60
        return f"INTERVAL '{v} {'minute' if v == 1 else 'minutes'}'"
    return f"INTERVAL '{s} {'second' if s == 1 else 'seconds'}'"


def _nice_bucket_seconds(seconds: int) -> int:
    """Snap *seconds* up to the nearest human-friendly bucket size.

    Args:
        seconds: Raw bucket duration.

    Returns:
        The smallest entry from :data:`NICE_BUCKETS` that is ``>=`` *seconds*.
    """
    for b in NICE_BUCKETS:
        if seconds <= b:
            return b
    return NICE_BUCKETS[-1]


def _sql_quote(value: Any) -> str:
    """Quote a Python value for safe embedding in an InfluxDB SQL string.

    Args:
        value: A scalar Python value.

    Returns:
        An SQL-safe string representation.
    """
    if isinstance(value, str):
        v = value.replace("'", "''")
        return f"'{v}'"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    return str(value)


def _distinct_values(df: pd.DataFrame, col: str) -> List[str]:
    """Extract sorted unique non-empty string values from a DataFrame column.

    Args:
        df: Source DataFrame.
        col: Column name to extract from.

    Returns:
        Sorted list of unique non-empty string values.
    """
    if df is None or df.empty or col not in df.columns:
        return []
    vals = df[col].dropna().map(lambda x: str(x).strip()).tolist()
    return sorted({v for v in vals if v})


_IDENTIFIER_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_]+$")


def _validate_identifier(name: str) -> str:
    """Verify that *name* contains only safe identifier characters.

    Allowed characters are ASCII letters, digits, and underscores.

    Args:
        name: The identifier string to validate.

    Returns:
        The validated name (unchanged).

    Raises:
        ValueError: If *name* contains disallowed characters.
    """
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(f"Invalid SQL identifier: {name!r}")
    return name


def _align_bucket_boundaries(start: str, stop: str, bucket_seconds: int) -> tuple[str, str]:
    """Align start/stop timestamps to DATE_BIN bucket boundaries.

    DATE_BIN with an epoch anchor (1970-01-01) creates buckets at fixed
    intervals from epoch.  If the query window does not fall exactly on
    bucket boundaries, the first and last buckets will be partial and
    show misleadingly low values.

    This function ceils *start* and floors *stop* to the nearest bucket
    boundary so the SQL query only returns complete buckets.

    Args:
        start: ISO-8601 start timestamp.
        stop: ISO-8601 stop timestamp.
        bucket_seconds: Bucket duration in seconds.

    Returns:
        Tuple of (aligned_start, aligned_stop) as ISO-8601 strings.
    """
    try:
        t0 = pd.to_datetime(start)
        t1 = pd.to_datetime(stop)
        epoch_s0 = t0.timestamp()
        epoch_s1 = t1.timestamp()
        aligned_start = math.ceil(epoch_s0 / bucket_seconds) * bucket_seconds
        aligned_stop = math.floor(epoch_s1 / bucket_seconds) * bucket_seconds
        if aligned_start >= aligned_stop:
            return start, stop
        return (
            pd.Timestamp(aligned_start, unit="s", tz="UTC").isoformat(),
            pd.Timestamp(aligned_stop, unit="s", tz="UTC").isoformat(),
        )
    except Exception:
        return start, stop


class InfluxRepository:
    """Thin wrapper around the InfluxDB v3 Python client.

    All query methods return DataFrames with ``time`` as a **regular
    column** (never the index).
    """

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        org: str,
        database: str,
    ) -> None:
        """Initialize the InfluxDB repository.

        Args:
            host: InfluxDB server hostname.
            port: InfluxDB server port.
            token: Authentication token.
            org: InfluxDB organization.
            database: Target database / bucket name.
        """
        self.host = host
        self.port = port
        self.token = token
        self.org = org
        self.database = database
        self._data_extent_cache: Dict[str, tuple[float, tuple["pd.Timestamp", "pd.Timestamp"]]] = {}
        url = f"http://{host}:{port}" if not host.startswith("http") else f"{host}:{port}"
        self._client = InfluxDBClient3(host=url, token=token, database=database)  # type: ignore[no-untyped-call]
        logger.debug("InfluxRepository initialized for {}:{}/{}", host, port, database)

    async def health_check(self) -> bool:
        """Check whether the InfluxDB connection is alive.

        Returns:
            ``True`` if the database is reachable, ``False`` otherwise.
        """
        try:
            self._client.query("SELECT 1", database=self.database)
            return True
        except Exception as exc:
            logger.error("InfluxDB health check failed: {}", exc)
            return False

    def query_timeseries(
        self,
        measurement: str,
        id_tag: str,
        fields: List[str],
        start: str,
        stop: str,
        tags: Optional[Dict[str, Union[str, int, float, bool]]] = None,
        limit: Optional[int] = None,
        aggregate: Optional[Union[str, Dict[str, str]]] = None,
        sample_max_points: Optional[int] = None,
        preserve_extrema: bool = True,
        bucket_seconds: Optional[int] = None,
    ) -> pd.DataFrame:
        """Query time-series data from InfluxDB.

        Builds an SQL query with optional ``DATE_BIN`` aggregation.  When
        *aggregate* is set the bucket size is derived from the time window
        and *sample_max_points*.

        When *preserve_extrema* is ``True`` and aggregation is active,
        additional ``MIN`` / ``MAX`` columns are selected for each field
        so that downstream logic can preserve extreme values.

        The computed bucket duration (seconds) is stored in the returned
        DataFrame's ``attrs["bucket_seconds"]`` metadata field.

        **Important:** ``time`` is returned as a regular column, not as
        the DataFrame index.

        Args:
            measurement: InfluxDB measurement name.
            id_tag: Tag column used as identifier (e.g. ``"uci"``).
            fields: List of field names to select.
            start: ISO-8601 start timestamp for the ``WHERE`` clause.
            stop: ISO-8601 stop timestamp for the ``WHERE`` clause.
            tags: Optional tag filters (``key=value``).
            limit: Optional row limit.
            aggregate: Aggregation function name (e.g. ``"mean"``) or a
                per-field dict ``{field: func}``.  ``None`` disables
                aggregation.
            sample_max_points: Maximum number of data points.  Controls
                the ``DATE_BIN`` bucket size when *aggregate* is set.
            preserve_extrema: When ``True`` and aggregation is active,
                select additional ``MIN``/``MAX`` columns per field.

        Returns:
            A DataFrame with ``time`` as a column, metric fields, and
            optionally the *id_tag* column.
        """
        for field_name in fields:
            _validate_identifier(field_name)
        if isinstance(aggregate, str):
            _validate_identifier(aggregate)
        elif isinstance(aggregate, dict):
            for func_name in aggregate.values():
                _validate_identifier(str(func_name))

        where_clauses: List[str] = [f"time >= '{start}'", f"time <= '{stop}'"]
        if tags:
            for k, v in tags.items():
                where_clauses.append(f'"{k}" = {_sql_quote(v)}')
        where_str = " AND ".join(where_clauses)

        select_parts: List[str] = []
        group_by_clause = ""
        order_clause = ""
        limit_clause = ""

        if aggregate:
            bucket_seconds = bucket_seconds or self._compute_bucket_seconds(start, stop, sample_max_points)
            bucket_literal = _to_sql_interval_literal(bucket_seconds)
            time_expr = f"date_bin({bucket_literal}, time, TIMESTAMP '1970-01-01 00:00:00Z') AS agg_time"
            select_parts = [time_expr]

            agg_map: Dict[str, str] = {}
            if isinstance(aggregate, dict):
                agg_map = {str(k): str(v) for k, v in aggregate.items()}
            for f in fields:
                func = agg_map.get(f, str(aggregate))
                select_parts.append(f'{func}("{f}") AS "{f}"')
                if preserve_extrema and func not in ("min", "max"):
                    select_parts.append(f'min("{f}") AS "{f}_min"')
                    select_parts.append(f'max("{f}") AS "{f}_max"')

            group_cols: List[str] = ["agg_time"]
            if not tags or id_tag not in tags:
                select_parts.append(f'"{id_tag}"')
                group_cols.append(f'"{id_tag}"')

            group_by_clause = " GROUP BY " + ", ".join(group_cols)
            order_clause = " ORDER BY agg_time ASC"
        else:
            base_cols: List[str] = ['"time"']
            if not tags or id_tag not in (tags or {}):
                base_cols.append(f'"{id_tag}"')
            field_cols: List[str] = [f'"{f}"' for f in fields]
            select_parts = base_cols + field_cols
            order_clause = " ORDER BY time ASC"

        if isinstance(limit, int) and limit > 0:
            limit_clause = f" LIMIT {int(limit)}"

        select_clause = ", ".join(select_parts)
        query = (
            f'SELECT {select_clause} FROM "{measurement}"'
            f" WHERE {where_str}{group_by_clause}{order_clause}{limit_clause}"
        )

        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if "agg_time" in df.columns:
                df = df.rename(columns={"agg_time": "time"})
            if "time" in df.columns:
                df["time"] = pd.to_datetime(df["time"])
            df.attrs["bucket_seconds"] = bucket_seconds
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_timeseries OK: {} rows, bucket={}s, {:.1f}ms",
                len(df),
                bucket_seconds,
                duration_ms,
            )
            return df
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_timeseries FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            empty = pd.DataFrame(columns=["time"] + fields)
            empty.attrs["bucket_seconds"] = bucket_seconds
            return empty

    def list_ids_between(
        self,
        measurement: str,
        id_tag: str,
        start: str,
        stop: str,
        nonzero: bool = False,
        fields: Optional[List[str]] = None,
        threshold: Optional[float] = 0.0,
    ) -> List[str]:
        """List distinct identifier values between two timestamps.

        Args:
            measurement: InfluxDB measurement name.
            id_tag: Tag column used as identifier.
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            nonzero: When ``True``, only return IDs where the summed
                *fields* exceed *threshold*.
            fields: Field names for the nonzero check.
            threshold: Minimum total sum to keep an ID (default ``0.0``).

        Returns:
            A sorted list of distinct identifier strings.
        """
        if fields:
            for field_name in fields:
                _validate_identifier(field_name)

        where = f"time >= '{start}' AND time <= '{stop}'"
        is_nonzero = bool(nonzero and fields)
        threshold_val = float(threshold or 0.0)

        if not is_nonzero:
            query = f'SELECT DISTINCT "{id_tag}" FROM "{measurement}" WHERE {where}'
        else:
            sum_exprs = [f'sum("{f}") AS "{f}_sum"' for f in fields or []]
            select_clause = f'"{id_tag}", ' + ", ".join(sum_exprs)
            group_by = f'GROUP BY "{id_tag}"'
            query = f'SELECT {select_clause} FROM "{measurement}" WHERE {where} {group_by}'

        perf_start = perf_counter()
        ids: List[str] = []
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None:
                df = pd.DataFrame()

            if not is_nonzero:
                ids = _distinct_values(df, str(id_tag))
            else:
                ids = self._filter_nonzero_ids(df, id_tag, threshold_val)

            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "list_ids_between OK: {} ids, nonzero={}, {:.1f}ms",
                len(ids),
                is_nonzero,
                duration_ms,
            )
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "list_ids_between FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
        return ids

    def query_collapsed_port_counts(
        self,
        measurement: str,
        id_tag: str,
        ids: List[str],
        start: str,
        stop: str,
    ) -> dict[str, int]:
        """Query the maximum collapsed-port count per UCI.

        Args:
            measurement: InfluxDB measurement name.
            id_tag: Tag column used as identifier (e.g. ``"uci"``).
            ids: List of UCI strings to query.
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.

        Returns:
            A dict mapping each UCI to its max ``collapsed_port_count``
            value. UCIs with no data or without the field are omitted.
        """
        _validate_identifier(measurement)
        _validate_identifier(id_tag)
        if not ids:
            return {}

        id_list = ", ".join(_sql_quote(u) for u in ids)
        query = (
            f'SELECT "{id_tag}", MAX("collapsed_port_count") AS collapsed_port_count'
            f' FROM "{measurement}"'
            f" WHERE time >= '{start}' AND time <= '{stop}'"
            f' AND "{id_tag}" IN ({id_list})'
            f' GROUP BY "{id_tag}"'
        )

        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
                logger.debug("query_collapsed_port_counts OK: 0 rows, {:.1f}ms", duration_ms)
                return {}

            counts: dict[str, int] = {}
            for _, row in df.iterrows():
                uci_val = str(row.get(id_tag, ""))
                val = row.get("collapsed_port_count")
                if uci_val and val is not None and not pd.isna(val):
                    try:
                        counts[uci_val] = int(val)
                    except (ValueError, TypeError):
                        pass

            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_collapsed_port_counts OK: {} rows, {:.1f}ms",
                len(counts),
                duration_ms,
            )
            return counts
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_collapsed_port_counts FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            return {}

    def query_distinct_tags(
        self,
        measurement: str,
        tag: str,
    ) -> List[str]:
        """Query all distinct values of a tag from a measurement.

        Args:
            measurement: InfluxDB measurement name.
            tag: Tag column name.

        Returns:
            A sorted list of distinct tag values.
        """
        _validate_identifier(measurement)
        _validate_identifier(tag)

        query = f'SELECT DISTINCT "{tag}" FROM "{measurement}"'
        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            tags = _distinct_values(df, tag)
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_distinct_tags OK: {} tags, {:.1f}ms",
                len(tags),
                duration_ms,
            )
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_distinct_tags FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            return []
        return tags

    def query_timeseries_multi_ids_chunked(
        self,
        measurement: str,
        id_tag: str,
        fields: List[str],
        start: str,
        stop: str,
        ids: Sequence[str],
        limit: Optional[int] = None,
        initial_chunk_size: int = 5000,
    ) -> pd.DataFrame:
        """Bulk-query time-series data for multiple IDs using chunked SQL.

        Splits *ids* into chunks and issues one ``SELECT … WHERE id_tag
        IN (…)`` per chunk.  Automatically halves the chunk size when the
        server rejects an oversized request.

        Args:
            measurement: InfluxDB measurement name.
            id_tag: Tag column used as identifier.
            fields: List of field names to select.
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            ids: Iterable of identifier values to query.
            limit: Optional total row limit applied after merging.
            initial_chunk_size: Starting number of IDs per chunk.

        Returns:
            A merged DataFrame with ``time`` as a column, sorted by time.
        """
        perf_start = perf_counter()
        if not ids:
            return pd.DataFrame()

        select_cols: List[str] = ['"time"', f'"{id_tag}"'] + [f'"{f}"' for f in fields]
        select_clause: str = ", ".join(select_cols)
        ids_list: List[str] = list(ids)
        out_frames: List[pd.DataFrame] = []
        chunk_size: int = max(1, int(initial_chunk_size))
        idx: int = 0

        while idx < len(ids_list):
            chunk = ids_list[idx : idx + chunk_size]
            try:
                df_chunk = self._run_multi_id_chunk(measurement, id_tag, select_clause, start, stop, chunk)
                out_frames.append(df_chunk)
                idx += chunk_size
            except Exception as exc:
                msg = str(exc).lower()
                if self._is_oversized_error(msg):
                    chunk_size = max(1, chunk_size // 2)
                    if chunk_size == 1:
                        self._run_single_id_fallback(
                            measurement,
                            id_tag,
                            select_clause,
                            start,
                            stop,
                            ids_list[idx],
                            out_frames,
                        )
                        idx += 1
                    continue
                logger.error(
                    "Multi-id chunked query failed (chunk_size={}): {}",
                    chunk_size,
                    exc,
                )
                idx += chunk_size

        df_all = pd.concat(out_frames, ignore_index=True) if out_frames else pd.DataFrame()
        if "time" in df_all.columns:
            df_all["time"] = pd.to_datetime(df_all["time"])
            df_all = df_all.sort_values("time")
        if isinstance(limit, int) and limit > 0:
            df_all = df_all.head(limit)

        duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
        logger.debug(
            "query_timeseries_multi_ids_chunked OK: {} rows, {} ids, {:.1f}ms",
            len(df_all),
            len(ids),
            duration_ms,
        )
        return df_all

    def query_network_throughput(
        self,
        measurement: str,
        start: str,
        stop: str,
        buckets: int = 60,
    ) -> tuple[list[dict[str, Any]], int]:
        """Query aggregated network throughput over a time window.

        Computes ``SUM(total_volume)`` and ``SUM(packet_count)`` per
        ``DATE_BIN`` bucket across all UCIs.  The bucket duration is
        derived from the time range divided by *buckets*, snapped to
        a human-friendly value.

        Args:
            measurement: InfluxDB measurement name.
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            buckets: Desired number of output buckets.

        Returns:
            A tuple of (rows, bucket_seconds) where rows is a list of
            dicts with ``timestamp``, ``total_bytes``, ``total_packets``.
            Returns ``([], bucket_seconds)`` on error or empty result.
        """
        _validate_identifier(measurement)

        bucket_seconds = self._compute_bucket_seconds(start, stop, buckets)
        bucket_literal = _to_sql_interval_literal(bucket_seconds)
        aligned_start, aligned_stop = _align_bucket_boundaries(start, stop, bucket_seconds)

        query = (
            f"SELECT date_bin({bucket_literal}, time, TIMESTAMP '1970-01-01 00:00:00Z') AS bucket,"
            f' SUM("total_volume") AS total_bytes,'
            f' SUM("packet_count") AS total_packets'
            f' FROM "{measurement}"'
            f" WHERE time >= '{aligned_start}' AND time < '{aligned_stop}'"
            f" GROUP BY bucket"
            f" ORDER BY bucket"
        )

        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
                logger.debug("query_network_throughput OK: 0 rows, {:.1f}ms", duration_ms)
                return [], bucket_seconds

            rows: list[dict[str, Any]] = []
            for _, row in df.iterrows():
                ts = row.get("bucket")
                if ts is None:
                    ts_str = ""
                else:
                    ts_pd = pd.Timestamp(ts)
                    if ts_pd.tz is None:
                        ts_pd = ts_pd.tz_localize("UTC")
                    ts_str = time_policy.to_local_offset_string(ts_pd)
                rows.append(
                    {
                        "timestamp": ts_str,
                        "total_bytes": int(row.get("total_bytes", 0) or 0),
                        "total_packets": int(row.get("total_packets", 0) or 0),
                    }
                )

            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_network_throughput OK: {} rows, bucket={}s, {:.1f}ms",
                len(rows),
                bucket_seconds,
                duration_ms,
            )
            return rows, bucket_seconds
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_network_throughput FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            return [], bucket_seconds

    def query_top_connections(
        self,
        measurement: str,
        id_tag: str,
        start: str,
        stop: str,
        limit: int = 5,
        metric: str = "packet_count",
    ) -> list[dict[str, Any]]:
        """Query the top connections ranked by aggregated traffic volume.

        Sums ``packet_count`` and ``total_volume`` per UCI over the given
        time window and returns the top *limit* rows ordered by the
        chosen *metric*.  The ``total_volume`` field is aliased as
        ``total_bytes`` in the output for consistency with the API schema.

        Args:
            measurement: InfluxDB measurement name.
            id_tag: Tag column used as identifier (e.g. ``"uci"``).
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            limit: Maximum number of rows to return.
            metric: Field to rank by (``"packet_count"`` or ``"byte_count"``).

        Returns:
            A list of dicts with keys ``uci``, ``total_packets``, ``total_bytes``.
            Returns an empty list on error.
        """
        _validate_identifier(measurement)
        _validate_identifier(id_tag)

        order_col = "total_bytes" if metric == "byte_count" else "total_packets"
        safe_limit = max(1, int(limit))

        query = (
            f'SELECT "{id_tag}",'
            f' SUM("packet_count") AS total_packets,'
            f' SUM("total_volume") AS total_bytes'
            f' FROM "{measurement}"'
            f" WHERE time >= '{start}' AND time < '{stop}'"
            f' GROUP BY "{id_tag}"'
            f" ORDER BY {order_col} DESC"
            f" LIMIT {safe_limit}"
        )

        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
                logger.debug("query_top_connections OK: 0 rows, {:.1f}ms", duration_ms)
                return []

            rows: list[dict[str, Any]] = []
            for _, row in df.iterrows():
                rows.append(
                    {
                        "uci": str(row.get(id_tag, "")),
                        "total_packets": int(row.get("total_packets", 0) or 0),
                        "total_bytes": int(row.get("total_bytes", 0) or 0),
                    }
                )

            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_top_connections OK: {} rows, {:.1f}ms",
                len(rows),
                duration_ms,
            )
            return rows
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_top_connections FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            return []

    def query_connection_sparklines(
        self,
        ucis: list[str],
        start: str,
        stop: str,
        buckets: int = 12,
    ) -> dict[str, list[int]]:
        """Query per-UCI total_volume sparkline data over a time window.

        Issues a single aggregated query for all requested UCIs using
        ``DATE_BIN`` and ``SUM(total_volume)``, then pivots the result
        into a dict mapping each UCI to a fixed-length list of integers.
        Buckets with no data are filled with ``0``.

        Args:
            ucis: List of UCI strings to query sparklines for.
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            buckets: Desired number of time buckets (default 12).

        Returns:
            A dict mapping each UCI to a list of ``total_volume`` integers
            per bucket.  UCIs with no data are omitted from the result.
        """
        if not ucis:
            return {}

        bucket_seconds = self._compute_bucket_seconds(start, stop, buckets)
        bucket_literal = _to_sql_interval_literal(bucket_seconds)
        aligned_start, aligned_stop = _align_bucket_boundaries(start, stop, bucket_seconds)
        uci_list = ", ".join(_sql_quote(u) for u in ucis)

        query = (
            f"SELECT date_bin({bucket_literal}, time, TIMESTAMP '1970-01-01 00:00:00Z') AS bucket,"
            f' "uci",'
            f' SUM("total_volume") AS total_bytes'
            f' FROM "network_metrics"'
            f" WHERE time >= '{aligned_start}' AND time < '{aligned_stop}'"
            f' AND "uci" IN ({uci_list})'
            f' GROUP BY bucket, "uci"'
            f" ORDER BY bucket"
        )

        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
                logger.debug("query_connection_sparklines OK: 0 rows, {:.1f}ms", duration_ms)
                return {}

            sparklines = self._pivot_sparkline_dataframe(df, ucis)

            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_connection_sparklines OK: {} rows, {} ucis, bucket={}s, {:.1f}ms",
                len(df),
                len(sparklines),
                bucket_seconds,
                duration_ms,
            )
            return sparklines
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_connection_sparklines FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            return {}

    def query_top_mac_addresses(
        self,
        start: str,
        stop: str,
        limit: int = 5,
        metric: str = "packet_count",
    ) -> list[dict[str, Any]]:
        """Query the top MAC addresses ranked by aggregated traffic volume.

        Sums ``out_total_packets + in_total_packets`` and
        ``out_total_volume + in_total_volume`` per MAC over the given
        time window and returns the top *limit* rows ordered by the
        chosen *metric*.

        Args:
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            limit: Maximum number of rows to return.
            metric: Field to rank by (``"packet_count"`` or ``"byte_count"``).

        Returns:
            A list of dicts with keys ``id``, ``total_packets``, ``total_bytes``.
            Returns an empty list on error.
        """
        order_col = "total_bytes" if metric == "byte_count" else "total_packets"
        safe_limit = max(1, int(limit))

        query = (
            f'SELECT "mac_address",'
            f' SUM("out_total_packets") + SUM("in_total_packets") AS total_packets,'
            f' SUM("out_total_volume") + SUM("in_total_volume") AS total_bytes'
            f' FROM "mac_traffic"'
            f" WHERE time >= '{start}' AND time < '{stop}'"
            f' GROUP BY "mac_address"'
            f" ORDER BY {order_col} DESC"
            f" LIMIT {safe_limit}"
        )

        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
                logger.debug("query_top_mac_addresses OK: 0 rows, {:.1f}ms", duration_ms)
                return []

            rows: list[dict[str, Any]] = []
            for _, row in df.iterrows():
                rows.append(
                    {
                        "id": str(row.get("mac_address", "")),
                        "total_packets": int(row.get("total_packets", 0) or 0),
                        "total_bytes": int(row.get("total_bytes", 0) or 0),
                    }
                )

            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_top_mac_addresses OK: {} rows, {:.1f}ms",
                len(rows),
                duration_ms,
            )
            return rows
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_top_mac_addresses FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            return []

    def query_top_protocols(
        self,
        start: str,
        stop: str,
        limit: int = 5,
        metric: str = "packet_count",
    ) -> list[dict[str, Any]]:
        """Query the top protocol stacks ranked by aggregated traffic volume.

        Sums ``proto_total_packets`` and ``proto_total_volume`` per
        protocol over the given time window and returns the top *limit*
        rows ordered by the chosen *metric*.

        Args:
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            limit: Maximum number of rows to return.
            metric: Field to rank by (``"packet_count"`` or ``"byte_count"``).

        Returns:
            A list of dicts with keys ``id``, ``total_packets``, ``total_bytes``.
            Returns an empty list on error.
        """
        order_col = "total_bytes" if metric == "byte_count" else "total_packets"
        safe_limit = max(1, int(limit))

        query = (
            f'SELECT "protocol",'
            f' SUM("proto_total_packets") AS total_packets,'
            f' SUM("proto_total_volume") AS total_bytes'
            f' FROM "proto_traffic"'
            f" WHERE time >= '{start}' AND time < '{stop}'"
            f' GROUP BY "protocol"'
            f" ORDER BY {order_col} DESC"
            f" LIMIT {safe_limit}"
        )

        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
                logger.debug("query_top_protocols OK: 0 rows, {:.1f}ms", duration_ms)
                return []

            rows: list[dict[str, Any]] = []
            for _, row in df.iterrows():
                rows.append(
                    {
                        "id": str(row.get("protocol", "")),
                        "total_packets": int(row.get("total_packets", 0) or 0),
                        "total_bytes": int(row.get("total_bytes", 0) or 0),
                    }
                )

            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_top_protocols OK: {} rows, {:.1f}ms",
                len(rows),
                duration_ms,
            )
            return rows
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_top_protocols FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            return []

    def query_protocol_count(self, start: str, stop: str) -> int:
        """Count distinct protocol stacks seen in the time window.

        Args:
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.

        Returns:
            Number of distinct protocol values, or ``0`` on error.
        """
        query = f'SELECT DISTINCT "protocol" FROM "proto_traffic"' f" WHERE time >= '{start}' AND time < '{stop}'"
        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
                logger.debug("query_protocol_count OK: 0 rows, {:.1f}ms", duration_ms)
                return 0
            count = len(df["protocol"].unique()) if "protocol" in df.columns else 0
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_protocol_count OK: {} protocols, {:.1f}ms",
                count,
                duration_ms,
            )
            return int(count)
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_protocol_count FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            return 0

    def query_mac_sparklines(
        self,
        macs: list[str],
        start: str,
        stop: str,
        buckets: int = 12,
    ) -> dict[str, list[int]]:
        """Query per-MAC sparkline data over a time window.

        Issues a single aggregated query for all requested MACs using
        ``DATE_BIN`` and ``SUM(out_total_volume) + SUM(in_total_volume)``,
        then pivots the result into a dict mapping each MAC to a
        fixed-length list of integers.

        Args:
            macs: List of MAC address strings.
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            buckets: Desired number of time buckets (default 12).

        Returns:
            Dict mapping MAC to list of total bytes per bucket.
        """
        if not macs:
            return {}

        bucket_seconds = self._compute_bucket_seconds(start, stop, buckets)
        bucket_literal = _to_sql_interval_literal(bucket_seconds)
        aligned_start, aligned_stop = _align_bucket_boundaries(start, stop, bucket_seconds)
        mac_list = ", ".join(_sql_quote(m) for m in macs)

        query = (
            f"SELECT date_bin({bucket_literal}, time, TIMESTAMP '1970-01-01 00:00:00Z') AS bucket,"
            f' "mac_address",'
            f' SUM("out_total_volume") + SUM("in_total_volume") AS total_bytes'
            f' FROM "mac_traffic"'
            f" WHERE time >= '{aligned_start}' AND time < '{aligned_stop}'"
            f' AND "mac_address" IN ({mac_list})'
            f' GROUP BY bucket, "mac_address"'
            f" ORDER BY bucket"
        )

        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
                logger.debug("query_mac_sparklines OK: 0 rows, {:.1f}ms", duration_ms)
                return {}

            df = df.rename(columns={"mac_address": "uci"})
            sparklines = self._pivot_sparkline_dataframe(df, macs)

            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_mac_sparklines OK: {} rows, {} macs, bucket={}s, {:.1f}ms",
                len(df),
                len(sparklines),
                bucket_seconds,
                duration_ms,
            )
            return sparklines
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_mac_sparklines FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            return {}

    def query_proto_sparklines(
        self,
        protocols: list[str],
        start: str,
        stop: str,
        buckets: int = 12,
    ) -> dict[str, list[int]]:
        """Query per-protocol sparkline data over a time window.

        Issues a single aggregated query for all requested protocols using
        ``DATE_BIN`` and ``SUM(proto_total_volume)``, then pivots the
        result into a dict mapping each protocol to a fixed-length list
        of integers.

        Args:
            protocols: List of protocol stack strings.
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            buckets: Desired number of time buckets (default 12).

        Returns:
            Dict mapping protocol to list of total bytes per bucket.
        """
        if not protocols:
            return {}

        bucket_seconds = self._compute_bucket_seconds(start, stop, buckets)
        bucket_literal = _to_sql_interval_literal(bucket_seconds)
        aligned_start, aligned_stop = _align_bucket_boundaries(start, stop, bucket_seconds)
        proto_list = ", ".join(_sql_quote(p) for p in protocols)

        query = (
            f"SELECT date_bin({bucket_literal}, time, TIMESTAMP '1970-01-01 00:00:00Z') AS bucket,"
            f' "protocol",'
            f' SUM("proto_total_volume") AS total_bytes'
            f' FROM "proto_traffic"'
            f" WHERE time >= '{aligned_start}' AND time < '{aligned_stop}'"
            f' AND "protocol" IN ({proto_list})'
            f' GROUP BY bucket, "protocol"'
            f" ORDER BY bucket"
        )

        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
                logger.debug("query_proto_sparklines OK: 0 rows, {:.1f}ms", duration_ms)
                return {}

            df = df.rename(columns={"protocol": "uci"})
            sparklines = self._pivot_sparkline_dataframe(df, protocols)

            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "query_proto_sparklines OK: {} rows, {} protos, bucket={}s, {:.1f}ms",
                len(df),
                len(sparklines),
                bucket_seconds,
                duration_ms,
            )
            return sparklines
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "query_proto_sparklines FAILED ({:.1f}ms): {} | Query: {}",
                duration_ms,
                exc,
                query,
            )
            return {}

    def query_last_record_time(
        self,
        measurement: str,
        lookback_hours: int = 24,
        now: "pd.Timestamp | None" = None,
    ) -> "pd.Timestamp" | None:
        """Return the most recent ``time`` value for a measurement, or None.

        The query is bounded to a recent time window so it never triggers a
        full-measurement scan on high-cardinality data. Records older than the
        window are treated as absent, which matches the caller's ``no-data``
        semantics (anything past the lookback is already ``no-data``).

        Args:
            measurement: InfluxDB measurement name.
            lookback_hours: Size of the bounded lookback window in hours.
            now: Optional shared "now" boundary. When provided, the lookback
                lower bound is computed from it so the query and the caller's
                freshness classification use the exact same clock (avoids a
                boundary race that could flip a marginal record to ``no-data``).
                Defaults to ``pd.Timestamp.utcnow()`` when omitted.

        Returns:
            The latest timestamp as a timezone-aware pandas Timestamp, or
            ``None`` when the measurement has no rows in the window or the
            query fails.
        """
        _validate_identifier(measurement)
        window_hours = max(1, int(lookback_hours))
        anchor = now if now is not None else pd.Timestamp.utcnow()
        since = anchor - pd.Timedelta(hours=window_hours)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        query = f'SELECT "time" FROM "{measurement}"' f" WHERE time >= '{since_str}'" " ORDER BY time DESC LIMIT 1"
        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                return None
            if "time" not in df.columns:
                return None
            ts = pd.to_datetime(df["time"].iloc[0])
            if ts.tz is None:
                ts = ts.tz_localize("UTC")
            return ts  # type: ignore[no-any-return]
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.warning(
                "query_last_record_time FAILED for {} ({:.1f}ms): {} | Query: {}",
                measurement,
                duration_ms,
                exc,
                query,
            )
            return None

    def query_data_extent(
        self,
        measurement: str,
        now: "pd.Timestamp | None" = None,
    ) -> "tuple[pd.Timestamp, pd.Timestamp] | None":
        """Return the first and last record timestamps of a measurement.

        The extent is resolved with bounded edge probes rather than an
        aggregate. Two properties of the live instance drive the design
        (measured 2026-07-29, ``network_metrics``):

        * Query cost tracks the **row density** of the scanned window, not
          its width. A window reaching into the continuously written recent
          tail costs 15-24 s; a window that excludes that tail costs ~0.2 s
          however far back it reaches.
        * Historic data is **not contiguous**. An imported capture can sit
          behind a multi-year gap, so a search that stops at the first empty
          window under-reports the extent just as badly as one that stops at
          the first non-empty window (the defect this replaces: it always
          returned the 1-day window and reported it as the full extent).

        ``last_ts`` therefore comes from the cheap recent tail, while
        ``first_ts`` walks *disjoint* bands outward from the anchor and keeps
        widening past the first hit, ending with one wide probe whose upper
        bound stays clear of the dense tail. Results are cached; see
        :meth:`invalidate_data_extent_cache` for the write path.

        Args:
            measurement: InfluxDB measurement name.
            now: Optional shared UTC boundary for deterministic searches.

        Returns:
            A timezone-aware ``(first, last)`` tuple, or ``None`` when no rows
            are found or a query fails.
        """
        _validate_identifier(measurement)
        anchor = now if now is not None else pd.Timestamp.utcnow()
        if anchor.tz is None:
            anchor = anchor.tz_localize("UTC")
        cached = self._cached_data_extent(measurement)
        if cached is not None:
            return cached
        perf_start = perf_counter()
        try:
            last_ts = self._probe_last_ts(measurement, anchor)
            if last_ts is None:
                return None
            first_ts = self._probe_first_ts(measurement, anchor)
            extent = (min(first_ts, last_ts) if first_ts is not None else last_ts, last_ts)
            self._data_extent_cache[measurement] = (perf_counter(), extent)
            logger.debug(
                "query_data_extent OK for {}: {} .. {} ({:.1f}ms)",
                measurement,
                extent[0],
                extent[1],
                round((perf_counter() - perf_start) * 1000.0, 3),
            )
            return extent
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.warning(
                "query_data_extent FAILED for {} ({:.1f}ms): {}",
                measurement,
                duration_ms,
                exc,
            )
            return None

    def invalidate_data_extent_cache(self, measurement: str | None = None) -> None:
        """Drop cached extents so the next read re-probes the database.

        The earliest timestamp only moves when data is written outside the
        known extent — a PCAP import can extend it backwards by years — so
        the cache is invalidated on that event rather than merely expiring.

        **Non-blocking invariant.** This method performs NO IO: it only
        mutates the in-memory ``_data_extent_cache`` dict. That is why
        ``PcapImportService._apply_terminal`` may call it directly from
        ``async`` code without an ``asyncio.to_thread`` hop (audit
        QUA-09). Should this ever need to reach InfluxDB, Postgres or the
        filesystem, the async caller must be moved to a worker thread in
        the same change. ``tests/unit/test_suite035_event_loop.py`` pins
        the invariant.

        Args:
            measurement: Measurement to forget, or ``None`` to clear all.
        """
        if measurement is None:
            self._data_extent_cache.clear()
        else:
            self._data_extent_cache.pop(measurement, None)

    def _cached_data_extent(self, measurement: str) -> "tuple[pd.Timestamp, pd.Timestamp] | None":
        """Return a cached extent when it is still within its TTL.

        Args:
            measurement: InfluxDB measurement name.

        Returns:
            The cached ``(first, last)`` tuple, or ``None`` when absent or stale.
        """
        entry = self._data_extent_cache.get(measurement)
        if entry is None:
            return None
        cached_at, extent = entry
        if perf_counter() - cached_at > DATA_EXTENT_CACHE_TTL_SECONDS:
            self._data_extent_cache.pop(measurement, None)
            return None
        return extent

    def _probe_last_ts(self, measurement: str, anchor: "pd.Timestamp") -> "pd.Timestamp | None":
        """Return the newest timestamp, searching outward in disjoint bands.

        The newest record is normally inside the first band, so this costs a
        single cheap query in the live case.

        Args:
            measurement: InfluxDB measurement name.
            anchor: UTC upper bound of the search.

        Returns:
            The newest timestamp found, or ``None`` when every band is empty.
        """
        for lower_days, upper_days in _extent_bands(DATA_EXTENT_BAND_DAYS):
            found = self._probe_edge(
                measurement,
                anchor - pd.Timedelta(days=lower_days),
                anchor - pd.Timedelta(days=upper_days),
                descending=True,
            )
            if found is not None:
                return found
        return self._probe_edge(
            measurement,
            DATA_EXTENT_FLOOR,
            anchor - pd.Timedelta(days=DATA_EXTENT_BAND_DAYS[-1]),
            descending=True,
        )

    def _probe_first_ts(self, measurement: str, anchor: "pd.Timestamp") -> "pd.Timestamp | None":
        """Return the earliest timestamp, widening past the first hit.

        Bands are walked from the oldest outward-most probe inward, so a hit
        behind a gap still wins over a nearer one. The widest probe stops
        short of the dense recent tail to stay cheap; the remaining bands
        cover that tail individually.

        Args:
            measurement: InfluxDB measurement name.
            anchor: UTC upper bound of the search.

        Returns:
            The earliest timestamp found, or ``None`` when every band is empty.
        """
        oldest = self._probe_edge(
            measurement,
            DATA_EXTENT_FLOOR,
            anchor - pd.Timedelta(days=DATA_EXTENT_BAND_DAYS[-1]),
            descending=False,
        )
        if oldest is not None:
            return oldest
        for lower_days, upper_days in reversed(_extent_bands(DATA_EXTENT_BAND_DAYS)):
            found = self._probe_edge(
                measurement,
                anchor - pd.Timedelta(days=lower_days),
                anchor - pd.Timedelta(days=upper_days),
                descending=False,
            )
            if found is not None:
                return found
        return None

    def _probe_edge(
        self,
        measurement: str,
        start: "pd.Timestamp",
        stop: "pd.Timestamp",
        descending: bool,
    ) -> "pd.Timestamp | None":
        """Return the first or last timestamp inside a bounded window.

        Uses the same shape as :meth:`has_rows_between` — bounded on both
        sides and stopping at the first row — so the probe never degenerates
        into a full-measurement aggregate.

        Args:
            measurement: InfluxDB measurement name.
            start: Inclusive lower bound.
            stop: Inclusive upper bound.
            descending: Return the newest row instead of the oldest.

        Returns:
            The edge timestamp, or ``None`` when the window holds no rows.
        """
        if start >= stop:
            return None
        order = "DESC" if descending else "ASC"
        query = (
            f'SELECT "time" FROM "{measurement}"'
            f" WHERE time >= '{_extent_literal(start)}' AND time <= '{_extent_literal(stop)}'"
            f" ORDER BY time {order} LIMIT 1"
        )
        result = self._client.query(query, database=self.database)
        df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
        if df is None or df.empty or "time" not in df.columns:
            return None
        ts = pd.to_datetime(df["time"].iloc[0])
        if pd.isna(ts):
            return None
        return ts.tz_localize("UTC") if ts.tz is None else ts  # type: ignore[no-any-return]

    def has_rows_between(self, measurement: str, start: str, stop: str) -> bool:
        """Return whether any row exists in the inclusive ``[start, stop]`` window.

        Deliberately an **existence probe**, not an aggregate: the query is
        bounded on both sides and stops at the first hit (``LIMIT 1``). An
        unbounded aggregate over ``network_metrics`` measured 25-28 s on the
        live instance, the bounded probe 0.026 s (2026-07-29). Callers use
        this to refuse an import that would silently overwrite existing
        measurements, so a query failure returns ``False`` (no proven
        conflict) and the decision is left to the explicit force flag.

        Args:
            measurement: InfluxDB measurement name.
            start: ISO-8601 lower bound (inclusive).
            stop: ISO-8601 upper bound (inclusive).

        Returns:
            ``True`` when at least one row falls inside the window.
        """
        _validate_identifier(measurement)
        query = (
            f'SELECT "time" FROM "{measurement}"'
            f" WHERE time >= '{start}' AND time <= '{stop}'"
            " ORDER BY time ASC LIMIT 1"
        )
        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            found = df is not None and not df.empty
            logger.debug(
                "has_rows_between OK: found={}, {:.1f}ms",
                found,
                round((perf_counter() - perf_start) * 1000.0, 3),
            )
            return bool(found)
        except Exception as exc:
            logger.warning(
                "has_rows_between FAILED for {} ({:.1f}ms): {} | Query: {}",
                measurement,
                round((perf_counter() - perf_start) * 1000.0, 3),
                exc,
                query,
            )
            return False

    def query_record_count_since(self, measurement: str, since: "pd.Timestamp") -> int:
        """Count rows written to a measurement since a given timestamp.

        Args:
            measurement: InfluxDB measurement name.
            since: Inclusive start timestamp.

        Returns:
            Row count, or ``0`` on error or when no rows exist.
        """
        _validate_identifier(measurement)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        query = f"SELECT COUNT(*) AS cnt FROM \"{measurement}\" WHERE time >= '{since_str}'"
        perf_start = perf_counter()
        try:
            result = self._client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None or df.empty:
                return 0
            count_col = next(
                (c for c in df.columns if str(c).lower() == "cnt" or str(c).lower().startswith("count")),
                None,
            )
            if count_col is None:
                return 0
            return max(0, int(df[count_col].iloc[0] or 0))
        except Exception as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.warning(
                "query_record_count_since FAILED for {} ({:.1f}ms): {} | Query: {}",
                measurement,
                duration_ms,
                exc,
                query,
            )
            return 0

    def close(self) -> None:
        """Close the underlying InfluxDB client connection."""
        try:
            self._client.close()  # type: ignore[no-untyped-call]
        except Exception:
            pass

    @staticmethod
    def _pivot_sparkline_dataframe(
        df: pd.DataFrame,
        ucis: list[str],
    ) -> dict[str, list[int]]:
        """Pivot a bucketed DataFrame into per-UCI sparkline lists.

        Fills missing buckets with ``0`` so every UCI receives the same
        number of data points.

        Args:
            df: DataFrame with columns ``bucket``, ``uci``, ``total_bytes``.
            ucis: List of UCI strings requested (used for ordering).

        Returns:
            Dict mapping each UCI to a list of integer values per bucket.
        """
        if df.empty:
            return {}

        all_buckets = sorted(df["bucket"].unique())
        sparklines: dict[str, list[int]] = {}

        for uci in ucis:
            uci_df = df[df["uci"] == uci]
            if uci_df.empty:
                continue
            bucket_map: dict[Any, int] = {}
            for _, row in uci_df.iterrows():
                bucket_map[row["bucket"]] = int(row.get("total_bytes", 0) or 0)
            sparklines[uci] = [bucket_map.get(b, 0) for b in all_buckets]

        return sparklines

    @staticmethod
    def _compute_bucket_seconds(
        start: str,
        stop: str,
        sample_max_points: Optional[int],
    ) -> int:
        """Derive the DATE_BIN bucket size from the query window.

        Args:
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            sample_max_points: Desired maximum number of points.

        Returns:
            Bucket duration in seconds, snapped to a nice value.
        """
        try:
            t0 = pd.to_datetime(start)
            t1 = pd.to_datetime(stop)
            window_s = max(1, int((t1 - t0).total_seconds()))
        except Exception:
            window_s = 600
        if sample_max_points and sample_max_points > 0:
            seconds_per_point = max(1, math.ceil(window_s / int(sample_max_points)))
        else:
            seconds_per_point = max(60, window_s // 120)
        return _nice_bucket_seconds(seconds_per_point)

    @staticmethod
    def _filter_nonzero_ids(
        df: pd.DataFrame,
        id_tag: str,
        threshold_val: float,
    ) -> List[str]:
        """Filter IDs whose summed fields exceed a threshold.

        Args:
            df: Query result with ``<field>_sum`` columns.
            id_tag: Identifier column name.
            threshold_val: Minimum total sum.

        Returns:
            Sorted list of qualifying ID strings.
        """
        if df.empty or str(id_tag) not in df.columns:
            return []
        sum_cols = [c for c in df.columns if c.endswith("_sum")]
        if not sum_cols:
            return _distinct_values(df, str(id_tag))
        df = df.copy()
        df["_total_sum_"] = df[sum_cols].sum(axis=1, numeric_only=True)
        filt = df[df["_total_sum_"] > threshold_val]
        return _distinct_values(filt, str(id_tag))

    def _run_multi_id_chunk(
        self,
        measurement: str,
        id_tag: str,
        select_clause: str,
        start: str,
        stop: str,
        chunk_ids: List[str],
    ) -> pd.DataFrame:
        """Execute a single chunked query for a subset of IDs.

        Args:
            measurement: InfluxDB measurement name.
            id_tag: Identifier tag column.
            select_clause: Pre-built ``SELECT`` column list.
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            chunk_ids: List of ID values for the ``IN`` clause.

        Returns:
            DataFrame with ``time`` as a column.
        """
        in_list = ", ".join(_sql_quote(v) for v in chunk_ids)
        where_clause = f"time >= '{start}' AND time <= '{stop}' AND \"{id_tag}\" IN ({in_list})"
        query = f'SELECT {select_clause} FROM "{measurement}" WHERE {where_clause} ORDER BY time ASC'
        result = self._client.query(query, database=self.database)
        df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
        if "time" in df.columns:
            df["time"] = pd.to_datetime(df["time"])
        return df

    def _run_single_id_fallback(
        self,
        measurement: str,
        id_tag: str,
        select_clause: str,
        start: str,
        stop: str,
        single_id: str,
        out_frames: List[pd.DataFrame],
    ) -> None:
        """Attempt to query a single ID as a last-resort fallback.

        Args:
            measurement: InfluxDB measurement name.
            id_tag: Identifier tag column.
            select_clause: Pre-built ``SELECT`` column list.
            start: ISO-8601 start timestamp.
            stop: ISO-8601 stop timestamp.
            single_id: The single ID value to query.
            out_frames: Accumulator list to append the result to.
        """
        try:
            df_one = self._run_multi_id_chunk(measurement, id_tag, select_clause, start, stop, [single_id])
            out_frames.append(df_one)
        except Exception as exc_one:
            logger.error(
                "Multi-id chunk failed for single id={}: {}",
                single_id,
                exc_one,
            )

    @staticmethod
    def _is_oversized_error(msg: str) -> bool:
        """Check whether an error message indicates a too-large request.

        Args:
            msg: Lowercased error message string.

        Returns:
            ``True`` if the error is due to message/request size limits.
        """
        return "message length too large" in msg or "out-of-range" in msg or "request entity too large" in msg
