# src/repositories/influx_repo.py
from __future__ import annotations

import math
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Union

import pandas as pd
from influxdb_client_3 import InfluxDBClient3
from loguru import logger

VERBOSE = False

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

ALLOWED_AGGREGATES: frozenset[str] = frozenset({"avg", "min", "max", "sum", "count", "mean", "median", "stddev"})
"""SQL aggregate functions callers may request.

``aggregate`` reaches this module straight from an LLM-supplied tool
argument and was previously inlined verbatim as the function name, so any
string became executable SQL (audit MCP-03).
"""
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


def _to_sql_interval_literal(seconds: int) -> str:
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
    for b in NICE_BUCKETS:
        if seconds <= b:
            return b
    return NICE_BUCKETS[-1]


def _sql_quote(value: Any) -> str:
    if isinstance(value, str):
        v = value.replace("'", "''")
        return f"'{v}'"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    return str(value)


def _quote_identifier(value: str, kind: str = "identifier") -> str:
    """Return ``value`` as a double-quoted SQL identifier after validation.

    InfluxDB v3 accepts SQL, and measurement/tag/field names arrive from
    LLM-supplied tool arguments. Rejecting anything outside
    ``[A-Za-z_][A-Za-z0-9_]*`` means a name can never carry a closing
    quote and escape into the statement (audit MCP-03).

    Args:
        value: Candidate identifier.
        kind: Label used in the error message.

    Returns:
        The identifier wrapped in double quotes.

    Raises:
        ValueError: When ``value`` is not a bare identifier.
    """
    candidate = str(value or "").strip()
    if not _IDENTIFIER_RE.match(candidate):
        raise ValueError(f"invalid {kind}: {value!r}")
    return f'"{candidate}"'


def _aggregate_function(value: Any, kind: str = "aggregate") -> str:
    """Return an allow-listed SQL aggregate function name.

    Args:
        value: Candidate aggregate name (case-insensitive).
        kind: Label used in the error message.

    Returns:
        The lower-cased function name.

    Raises:
        ValueError: When the function is not in :data:`ALLOWED_AGGREGATES`.
    """
    candidate = str(value or "").strip().lower()
    if candidate not in ALLOWED_AGGREGATES:
        raise ValueError(f"invalid {kind}: {value!r}; allowed: {sorted(ALLOWED_AGGREGATES)}")
    return candidate


def _time_literal(value: Any, kind: str) -> str:
    """Validate an ISO-8601 timestamp and return it as a SQL literal.

    Accepts ``datetime`` objects and ISO-8601 strings (including a
    trailing ``Z``). The value is re-emitted through :func:`_sql_quote`
    only after a successful parse, so a crafted ``start``/``stop`` can
    neither close the literal nor append a clause (audit MCP-02).

    Args:
        value: Candidate timestamp.
        kind: Label used in the error message (``"start"`` / ``"stop"``).

    Returns:
        A quoted SQL timestamp literal.

    Raises:
        ValueError: When the value is not a parseable ISO-8601 timestamp.
    """
    if isinstance(value, datetime):
        return _sql_quote(value.isoformat())
    candidate = str(value or "").strip()
    if not candidate:
        raise ValueError(f"invalid {kind} timestamp: {value!r}")
    normalized = candidate[:-1] + "+00:00" if candidate.endswith("Z") else candidate
    try:
        datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid {kind} timestamp: {value!r}") from exc
    return _sql_quote(candidate)


def _distinct_values(df: pd.DataFrame, col: str) -> List[str]:
    if df is None or df.empty or col not in df.columns:
        return []
    vals = df[col].dropna().map(lambda x: str(x).strip()).tolist()
    uniq = sorted({v for v in vals if v})
    return uniq


def _build_perf_extra(**kwargs: Any) -> Dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v is not None}


class InfluxRepo:
    def __init__(self, host: str, token: str, database: str) -> None:
        self.host = host
        self.token = token
        self.database = database
        self.client = InfluxDBClient3(host=self.host, token=self.token, database=self.database)
        logger.debug(f"InfluxRepo initialized for host={self.host}, database={self.database}")

    def list_ids(self, measurement: str, id_tag: str, minutes: int = 10) -> List[str]:
        """Return distinct tag values seen in the last ``minutes``.

        Raises:
            ValueError: On an invalid measurement or tag identifier.
            Exception: Query failures propagate so the tool layer reports
                an error instead of an empty result (audit MCP-06).
        """
        minutes_window = max(1, int(minutes))
        since = (datetime.now() - timedelta(minutes=minutes_window)).replace(microsecond=0)
        since_str = since.isoformat() + "Z"
        tag_ident = _quote_identifier(id_tag, "id_tag")
        measurement_ident = _quote_identifier(measurement, "measurement")
        query = (
            f"SELECT DISTINCT {tag_ident} FROM {measurement_ident} "
            f"WHERE time >= {_time_literal(since_str, 'since')}"
        )

        row_count = 0
        error_message: Optional[str] = None
        ids: List[str] = []
        try:
            if VERBOSE:
                logger.debug(f"Influx list_ids executing: {query}")
            result = self.client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            row_count = len(df) if df is not None else 0
            ids = _distinct_values(df, str(id_tag))
        except Exception as exc:
            error_message = str(exc)
            logger.error(f"Influx list_ids failed: {exc} | Query: {query}")
            raise
        finally:
            _build_perf_extra(
                measurement=measurement,
                id_tag=id_tag,
                minutes=minutes_window,
                rows_returned=row_count if error_message is None else None,
                ids=len(ids) if error_message is None else None,
                error=error_message,
            )
        return ids

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
        tag_ident = _quote_identifier(id_tag, "id_tag")
        measurement_ident = _quote_identifier(measurement, "measurement")
        where = f"time >= {_time_literal(start, 'start')} " f"AND time <= {_time_literal(stop, 'stop')}"
        is_nonzero = bool(nonzero and fields)
        threshold_val = float(threshold or 0.0)
        query_variant = "nonzero" if is_nonzero else "distinct"

        if not is_nonzero:
            query = f"SELECT DISTINCT {tag_ident} FROM {measurement_ident} WHERE {where}"
        else:
            sum_exprs = []
            for f in fields or []:
                field_ident = _quote_identifier(f, "field")
                alias = _quote_identifier(f"{f}_sum", "field alias")
                sum_exprs.append(f"sum({field_ident}) AS {alias}")
            select_clause = f"{tag_ident}, " + ", ".join(sum_exprs)
            group_by = f"GROUP BY {tag_ident}"
            order_by = ""
            query = f"SELECT {select_clause} FROM {measurement_ident} " f"WHERE {where} {group_by} {order_by}"

        row_count = 0
        error_message: Optional[str] = None
        ids: List[str] = []
        try:
            if VERBOSE:
                logger.debug(f"Influx list_ids_between executing: {query}")
            result = self.client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if df is None:
                df = pd.DataFrame()
            row_count = len(df)

            if not is_nonzero:
                ids = _distinct_values(df, str(id_tag))
            else:
                if df.empty or str(id_tag) not in df.columns:
                    ids = []
                else:
                    sum_cols = [c for c in df.columns if c.endswith("_sum")]
                    if not sum_cols:
                        ids = _distinct_values(df, str(id_tag))
                    else:
                        df["_total_sum_"] = df[sum_cols].sum(axis=1, numeric_only=True)
                        filt = df[df["_total_sum_"] > threshold_val]
                        ids = _distinct_values(filt, str(id_tag))
        except Exception as exc:
            error_message = str(exc)
            if is_nonzero:
                logger.error(f"Influx list_ids_between (nonzero) failed: {exc} | Query: {query}")
            else:
                logger.error(f"Influx list_ids_between failed: {exc} | Query: {query}")
            raise
        finally:
            _build_perf_extra(
                measurement=measurement,
                id_tag=id_tag,
                start=start,
                stop=stop,
                nonzero=is_nonzero,
                fields=len(fields or []),
                threshold=threshold_val if is_nonzero else None,
                rows_returned=row_count if error_message is None else None,
                ids=len(ids) if error_message is None else None,
                query_variant=query_variant,
                error=error_message,
            )
        return ids

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
    ) -> pd.DataFrame:
        tag_ident = _quote_identifier(id_tag, "id_tag")
        measurement_ident = _quote_identifier(measurement, "measurement")
        where_clauses: List[str] = [
            f"time >= {_time_literal(start, 'start')}",
            f"time <= {_time_literal(stop, 'stop')}",
        ]
        if tags:
            for k, v in tags.items():
                where_clauses.append(f"{_quote_identifier(k, 'tag')} = {_sql_quote(v)}")
        where_str = " AND ".join(where_clauses)

        bucket_seconds: Optional[int] = None
        bucket_literal: Optional[str] = None
        time_expr: Optional[str] = None
        select_parts: List[str] = []
        group_cols: List[str] = []
        order_clause = ""
        limit_clause = ""
        aggregate_descriptor: Optional[str] = None

        if aggregate:
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
            bucket_seconds = _nice_bucket_seconds(seconds_per_point)
            bucket_literal = _to_sql_interval_literal(bucket_seconds)
            time_expr = f"date_bin({bucket_literal}, time, TIMESTAMP '1970-01-01 00:00:00Z') AS agg_time"

            select_parts = [time_expr]
            agg_map: Dict[str, str] = {}
            if isinstance(aggregate, dict):
                aggregate_descriptor = "dict"
                agg_map = {str(k): str(v) for k, v in aggregate.items()}
            else:
                aggregate_descriptor = str(aggregate)
            for f in fields:
                func = _aggregate_function(agg_map.get(f, aggregate))
                field_ident = _quote_identifier(f, "field")
                select_parts.append(f"{func}({field_ident}) AS {field_ident}")
                if preserve_extrema and func not in ("min", "max"):
                    min_alias = _quote_identifier(f"{f}_min", "field alias")
                    max_alias = _quote_identifier(f"{f}_max", "field alias")
                    select_parts.append(f"min({field_ident}) AS {min_alias}")
                    select_parts.append(f"max({field_ident}) AS {max_alias}")

            group_cols = ["agg_time"]
            if not tags or id_tag not in tags:
                select_parts.append(tag_ident)
                group_cols.append(tag_ident)

            group_by_clause = " GROUP BY " + ", ".join(group_cols)
            order_clause = " ORDER BY agg_time ASC"
        else:
            base_cols: List[str] = ['"time"']
            if not tags or id_tag not in (tags or {}):
                base_cols.append(tag_ident)
            field_cols: List[str] = [_quote_identifier(f, "field") for f in fields]
            select_parts = base_cols + field_cols
            group_by_clause = ""
            order_clause = " ORDER BY time ASC"
            aggregate_descriptor = None
        if isinstance(limit, int) and limit > 0:
            limit_clause = f" LIMIT {int(limit)}"

        select_clause = ", ".join(select_parts)
        query = (
            f"SELECT {select_clause} FROM {measurement_ident} "
            f"WHERE {where_str}{group_by_clause}{order_clause}{limit_clause}"
        )

        row_count = 0
        error_message: Optional[str] = None
        try:
            if VERBOSE:
                logger.debug(f"Influx query_timeseries executing: {query}")
            result = self.client.query(query, database=self.database)
            df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
            if "agg_time" in df.columns:
                df = df.rename(columns={"agg_time": "time"})
            if "time" in df.columns:
                df["time"] = pd.to_datetime(df["time"])
                df.set_index("time", inplace=True)
            row_count = len(df)
            return df
        except Exception as exc:
            error_message = str(exc)
            logger.error(f"Influx query_timeseries failed: {exc} | Query: {query}")
            raise
        finally:
            _build_perf_extra(
                measurement=measurement,
                id_tag=id_tag,
                fields=len(fields),
                tags=len(tags or {}),
                aggregate=aggregate_descriptor,
                bucket_seconds=bucket_seconds,
                sample_max_points=sample_max_points,
                limit=limit,
                preserve_extrema=preserve_extrema,
                rows_returned=row_count if error_message is None else None,
                error=error_message,
            )

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
        chunk_count = 0
        total_rows = 0
        error_message: Optional[str] = None
        try:
            if not ids:
                return pd.DataFrame()
            tag_ident = _quote_identifier(id_tag, "id_tag")
            measurement_ident = _quote_identifier(measurement, "measurement")
            start_literal = _time_literal(start, "start")
            stop_literal = _time_literal(stop, "stop")
            select_cols: List[str] = ['"time"', tag_ident] + [_quote_identifier(f, "field") for f in fields]
            select_clause: str = ", ".join(select_cols)
            ids_list: List[str] = list(ids)
            out_frames: List[pd.DataFrame] = []
            chunk_size: int = max(1, int(initial_chunk_size))
            idx: int = 0

            def run_chunk(chunk_ids: List[str]) -> pd.DataFrame:
                ids_csv = ", ".join(_sql_quote(v) for v in chunk_ids)
                where_clause = f"time >= {start_literal} AND time <= {stop_literal} " f"AND {tag_ident} IN ({ids_csv})"
                query = f"SELECT {select_clause} FROM {measurement_ident} " f"WHERE {where_clause} ORDER BY time ASC"
                if VERBOSE:
                    logger.debug(f"Influx query_timeseries executing: {query}")
                result = self.client.query(query, database=self.database)
                df = result.to_pandas() if hasattr(result, "to_pandas") else pd.DataFrame()
                if "time" in df.columns:
                    df["time"] = pd.to_datetime(df["time"])
                return df

            while idx < len(ids_list):
                chunk = ids_list[idx : idx + chunk_size]
                try:
                    df_chunk = run_chunk(chunk)
                    chunk_count += 1
                    total_rows += len(df_chunk)
                    out_frames.append(df_chunk)
                    idx += chunk_size
                except Exception as exc:
                    msg = str(exc).lower()
                    if "message length too large" in msg or "out-of-range" in msg or "request entity too large" in msg:
                        chunk_size = max(1, chunk_size // 2)
                        if chunk_size == 1:
                            one_id = ids_list[idx]
                            # A single id that still exceeds the transport
                            # limit cannot be split further; surface it
                            # instead of silently dropping the series
                            # (audit MCP-06).
                            df_one = run_chunk([one_id])
                            chunk_count += 1
                            total_rows += len(df_one)
                            out_frames.append(df_one)
                            idx += 1
                        continue
                    logger.error(f"Influx multi-id chunked query failed (chunk_size={chunk_size}): {exc}")
                    raise

            df_all = pd.concat(out_frames, ignore_index=True) if out_frames else pd.DataFrame()
            if "time" in df_all.columns:
                df_all = df_all.sort_values("time")
            if isinstance(limit, int) and limit > 0:
                df_all = df_all.head(limit)
            total_rows = len(df_all)
            return df_all
        except Exception as exc:
            error_message = str(exc)
            logger.error(f"Influx query_timeseries_multi_ids_chunked failed: {exc}")
            raise
        finally:
            _build_perf_extra(
                measurement=measurement,
                id_tag=id_tag,
                fields=len(fields),
                ids=len(ids or []),
                chunks=chunk_count,
                rows_returned=total_rows if error_message is None else None,
                limit=limit,
                initial_chunk_size=initial_chunk_size,
                error=error_message,
            )

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass
