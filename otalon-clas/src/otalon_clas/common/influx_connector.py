"""InfluxDB multi-module connector for fetching time-series data.

Provides ``InfluxModule`` for querying InfluxDB v3 with selective columns,
automatic chunked-fallback, and Polars/Pandas return types.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Any, cast

import pandas as pd  # type: ignore[import-untyped]  # pandas stubs not installed in this environment
import polars as pl
from otalon_common.influx import create_influx_client, sql_quote
from loguru import logger


class InfluxUnavailableError(RuntimeError):
    """Raised when InfluxDB cannot serve a query after one reconnect retry.

    The message is deliberately target-free (no host/port/DNS). The raw
    underlying exception — which may carry the connection target — is logged at
    WARNING for operators only, never interpolated into this persisted error
    (OT least-disclosure lens, audit B-7).
    """


# gRPC/Arrow signals that a single response was too large to materialize. These
# are NOT availability failures: ``fetch`` must be allowed to catch them and
# retry the SAME window in smaller time-based chunks. They therefore must not be
# collapsed into :class:`InfluxUnavailableError` before ``fetch`` can inspect
# them (audit B-4).
OVERSIZED_RESPONSE_SIGNALS: frozenset[str] = frozenset({"FlightInternalError", "ArrowInvalid"})

_UNAVAILABLE_MESSAGE = "InfluxDB unavailable for {module} after reconnect retry"


def _redacted_unavailable(module_name: str) -> str:
    """Build a stable, target-free persisted error message (no host/port)."""
    return _UNAVAILABLE_MESSAGE.format(module=module_name)


class InfluxModule:
    """InfluxDB query wrapper for a single data source module.

    Each module (conn, mac_traffic, proto_traffic) gets its own instance
    with a dedicated InfluxDB client and column selection.

    Args:
        url: InfluxDB server URL.
        token: InfluxDB authentication token.
        database: InfluxDB database name.
        measurement: InfluxDB measurement name.
        tag_key: Tag column to select (e.g., ``uci``, ``mac_address``).
        features: Feature column names to select.
        module_name: Descriptive name for logging.
    """

    def __init__(
        self,
        url: str,
        token: str,
        database: str,
        measurement: str,
        tag_key: str,
        features: list[str],
        module_name: str = "",
    ) -> None:
        """Initialize the InfluxModule with connection parameters."""
        self._url = url
        self._token = token
        self._client = create_influx_client(url=url, token=token, database=database)
        self._database = database
        self._measurement = measurement
        self._tag_key = tag_key
        self._features = features
        self._module_name = module_name or measurement
        self._columns = [tag_key, *features]

    def fetch(self, start: str, stop: str, use_polars: bool = True) -> pl.DataFrame | pd.DataFrame:
        """Fetch data for the configured time range.

        Executes a SQL query with selective columns and returns a DataFrame
        with column ordering ``[time, tag_key, ...features]``. On
        ``FlightInternalError`` or ``ArrowInvalid``, automatically falls
        back to ``fetch_in_chunks()``.

        Args:
            start: Start timestamp (ISO-8601 string).
            stop: Stop timestamp (ISO-8601 string).
            use_polars: If True, return Polars DataFrame; otherwise Pandas.

        Returns:
            DataFrame with time-series data for the module.
        """
        sql = self._build_query(start, stop)
        logger.debug("InfluxModule[{}] query: {}", self._module_name, sql)
        try:
            return self._execute_query(sql, use_polars)
        except InfluxUnavailableError:
            # Already typed and redacted by _execute_query (transport failure
            # after one reconnect). Propagate unchanged — this is a real
            # availability failure, not a size condition.
            raise
        except Exception as exc:
            exc_name = type(exc).__name__
            if exc_name in OVERSIZED_RESPONSE_SIGNALS:
                # Oversized single response: retry the SAME window in smaller
                # time-based chunks (audit B-4). _execute_query re-raises these
                # untouched precisely so this fallback stays reachable.
                logger.warning(
                    "InfluxModule[{}] direct fetch failed ({}), falling back to chunked fetch",
                    self._module_name,
                    exc_name,
                )
                return self.fetch_in_chunks(start, stop, use_polars=use_polars)
            logger.warning("InfluxModule[{}] direct fetch failed: {}", self._module_name, exc)
            raise InfluxUnavailableError(_redacted_unavailable(self._module_name)) from exc

    def fetch_in_chunks(
        self,
        start: str,
        stop: str,
        chunk_size: str = "8h",
        use_polars: bool = True,
    ) -> pl.DataFrame | pd.DataFrame:
        """Fetch data in time-based chunks and concatenate results.

        Splits the time range into segments of ``chunk_size`` duration,
        fetches each independently, and concatenates the results.

        Args:
            start: Start timestamp (ISO-8601 string).
            stop: Stop timestamp (ISO-8601 string).
            chunk_size: Duration string for each chunk (e.g., ``"8h"``).
            use_polars: If True, return Polars DataFrame; otherwise Pandas.

        Returns:
            Concatenated DataFrame from all chunks.
        """
        chunk_seconds = _parse_duration_to_seconds(chunk_size)
        start_dt = pd.Timestamp(start)
        stop_dt = pd.Timestamp(stop)
        total_seconds = (stop_dt - start_dt).total_seconds()
        num_chunks = max(1, math.ceil(total_seconds / chunk_seconds))

        frames: list[pl.DataFrame] = []
        for i in range(num_chunks):
            chunk_start = start_dt + timedelta(seconds=i * chunk_seconds)
            chunk_stop = min(start_dt + timedelta(seconds=(i + 1) * chunk_seconds), stop_dt)
            sql = self._build_query(str(chunk_start), str(chunk_stop))
            try:
                df = cast(pl.DataFrame, self._execute_query(sql, use_polars=True))
                if len(df) > 0:
                    frames.append(df)
            except Exception as exc:
                logger.warning(
                    "InfluxModule[{}] chunk {}/{} failed: {}",
                    self._module_name,
                    i + 1,
                    num_chunks,
                    exc,
                )
                raise InfluxUnavailableError(_redacted_unavailable(self._module_name)) from exc

        if not frames:
            return _empty_frame(self._tag_key, self._features, use_polars)

        result = pl.concat(frames)
        if not use_polars:
            return result.to_pandas()
        return result

    def fetch_distinct_tag_values(self, start: str, stop: str) -> list[str]:
        """Fetch the distinct tag-key values present in a time window.

        Used by the cross-source aggregation to recover the protocol
        vocabulary for the proto module (the proto ``protocol`` tag is
        hash-encoded before persistence, so the reverse map must be
        rebuilt from the raw measurement).

        Args:
            start: Start timestamp (ISO-8601 string).
            stop: Stop timestamp (ISO-8601 string).

        Returns:
            Sorted list of distinct, non-null tag values as strings.
        """
        validated_start = _validate_iso_timestamp(start)
        validated_stop = _validate_iso_timestamp(stop)
        sql = (
            f'SELECT DISTINCT "{self._tag_key}" AS tag_value '
            f'FROM "{self._measurement}" '
            f"WHERE time >= {sql_quote(validated_start)} AND time < {sql_quote(validated_stop)}"
        )
        try:
            df = self._execute_query(sql, use_polars=True)
        except InfluxUnavailableError:
            raise
        except Exception as exc:
            logger.warning("InfluxModule[{}] distinct-tag query failed: {}", self._module_name, exc)
            raise InfluxUnavailableError(_redacted_unavailable(self._module_name)) from exc
        if "tag_value" not in df.columns:
            return []
        values = df["tag_value"].drop_nulls().to_list()
        return sorted({str(v) for v in values})

    def close(self) -> None:
        """Release the underlying InfluxDB client connection."""
        try:
            client: Any = self._client
            client.close()
            logger.debug("InfluxModule[{}] connection closed", self._module_name)
        except Exception:
            logger.warning("InfluxModule[{}] error closing connection", self._module_name)

    def _build_query(self, start: str, stop: str) -> str:
        """Build the SQL query with selective columns."""
        validated_start = _validate_iso_timestamp(start)
        validated_stop = _validate_iso_timestamp(stop)
        cols = ", ".join(f'"{c}"' for c in self._columns)
        return (
            f'SELECT "time", {cols} '
            f'FROM "{self._measurement}" '
            f"WHERE time >= {sql_quote(validated_start)} AND time < {sql_quote(validated_stop)} "
            f"ORDER BY time"
        )

    def _execute_query(self, sql: str, use_polars: bool = True) -> pl.DataFrame | pd.DataFrame:
        """Execute a SQL query, reconnecting once on a transport failure.

        A size-signal exception (``FlightInternalError``/``ArrowInvalid``,
        "response too large") is re-raised UNTOUCHED so :meth:`fetch` can fall
        back to :meth:`fetch_in_chunks`; it is never converted to
        :class:`InfluxUnavailableError` (audit B-4). Only a genuine transport/
        connection failure triggers the single reconnect retry; a second
        failure raises the typed, target-free unavailable error.
        """
        try:
            reader = self._client.query(sql, mode="polars" if use_polars else "pandas")
        except Exception as exc:
            if type(exc).__name__ in OVERSIZED_RESPONSE_SIGNALS:
                # Size signal: let fetch() decide to chunk. Do NOT reconnect or
                # re-type — a fresh client would hit the same oversized window.
                raise
            logger.warning(
                "InfluxModule[{}] query transport failure ({}); recreating client and retrying once",
                self._module_name,
                type(exc).__name__,
            )
            self._replace_client()
            try:
                reader = self._client.query(sql, mode="polars" if use_polars else "pandas")
            except Exception as retry_exc:
                if type(retry_exc).__name__ in OVERSIZED_RESPONSE_SIGNALS:
                    # The reconnected client surfaced a size signal — still a
                    # chunkable condition, not an availability failure.
                    raise
                # Raw exception (may carry host:port) goes to operator logs
                # only; the persisted/raised message is target-free (B-7).
                logger.warning(
                    "InfluxModule[{}] unavailable after reconnect retry: {}",
                    self._module_name,
                    retry_exc,
                )
                raise InfluxUnavailableError(_redacted_unavailable(self._module_name)) from retry_exc
        if reader is None:
            return _empty_frame(self._tag_key, self._features, use_polars)
        return reader

    def _replace_client(self) -> None:
        """Replace stale transport once without requiring process restart."""
        old_client: Any = self._client
        try:
            old_client.close()
        except Exception:
            logger.debug("InfluxModule[{}] stale client close failed", self._module_name)
        self._client = create_influx_client(url=self._url, token=self._token, database=self._database)


def _validate_iso_timestamp(value: str) -> str:
    """Validate that ``value`` is a parseable ISO-8601 timestamp.

    This is a defense-in-depth check run before interpolating a timestamp
    into an InfluxDB SQL WHERE clause.

    Args:
        value: Timestamp string to validate.

    Returns:
        The original timestamp string.

    Raises:
        ValueError: If ``value`` cannot be parsed as an ISO-8601 timestamp.
    """
    try:
        datetime.fromisoformat(value)
    except Exception as exc:
        msg = f"Invalid ISO-8601 timestamp: {value!r}"
        raise ValueError(msg) from exc
    return value


def _parse_duration_to_seconds(duration: str) -> int:
    """Parse a simple duration string to seconds.

    Supports 'h' (hours), 'm' (minutes), and 's' (seconds) suffixes.

    Args:
        duration: Duration string like ``"8h"``, ``"30m"``, ``"300s"``.

    Returns:
        Duration in seconds.

    Raises:
        ValueError: If the format is unrecognized.
    """
    duration = duration.strip()
    if duration.endswith("h"):
        return int(duration[:-1]) * 3600
    if duration.endswith("m"):
        return int(duration[:-1]) * 60
    if duration.endswith("s"):
        return int(duration[:-1])
    msg = f"Unrecognized duration format: '{duration}'. Use 'h', 'm', or 's' suffix."
    raise ValueError(msg)


def _empty_frame(tag_key: str, features: list[str], use_polars: bool) -> pl.DataFrame | pd.DataFrame:
    """Create an empty DataFrame with the expected schema.

    Args:
        tag_key: Tag column name.
        features: Feature column names.
        use_polars: If True, return Polars DataFrame; otherwise Pandas.

    Returns:
        Empty DataFrame with columns ``[time, tag_key, ...features]``.
    """
    schema = {"time": pl.Datetime, tag_key: pl.Utf8}
    for f in features:
        schema[f] = pl.Float64
    df = pl.DataFrame(schema=schema)
    if not use_polars:
        return df.to_pandas()
    return df
