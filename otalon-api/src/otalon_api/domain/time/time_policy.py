"""Time conversion policy for InfluxDB / UI interaction.

Handles timezone-aware conversions between UTC (as stored in InfluxDB)
and local wall-clock time (as displayed in the UI).  Uses ``ZoneInfo``
for automatic DST handling.

Public helpers
--------------
- :func:`ui_to_influx_query_range` – format a UI time-range for InfluxDB SQL
- :func:`ui_to_pg_query_range` – format a UI time-range for PostgreSQL
- :func:`normalize_time_for_ui` – convert InfluxDB result timestamps back
  to naive local wall-clock values suitable for the frontend
- :func:`make_aware_local` – interpret any timestamp as local time
- :func:`to_utc_z_string` – ISO-8601 string with ``Z`` suffix
- :func:`to_local_offset_string` – ISO-8601 string with local UTC offset
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, List, Optional, Tuple, Union
from zoneinfo import ZoneInfo

import pandas as pd
from loguru import logger

TsLike = Union[pd.Timestamp, datetime, str, int, float]

_LOCAL_TZ_NAME: str = "Europe/Berlin"
_LOCAL_TZ: ZoneInfo = ZoneInfo(_LOCAL_TZ_NAME)


def configure_timezone(tz_name: str) -> None:
    """Set the local timezone used by all conversion functions.

    Call this once at application startup (e.g. from settings).

    Args:
        tz_name: IANA timezone name (e.g. ``"Europe/Berlin"``).
    """
    global _LOCAL_TZ_NAME, _LOCAL_TZ
    _LOCAL_TZ_NAME = tz_name
    _LOCAL_TZ = ZoneInfo(tz_name)


def configure_utc_offset(hours: int) -> None:
    """Deprecated wrapper kept for backward compatibility.

    Logs a warning and delegates to :func:`configure_timezone` using
    the default timezone.  New code should call :func:`configure_timezone`
    directly.

    Args:
        hours: Ignored. The timezone is determined by :func:`configure_timezone`.
    """
    logger.warning(
        "configure_utc_offset() is deprecated; use configure_timezone() instead. "
        "Ignoring hours={}, keeping timezone '{}'.",
        hours,
        _LOCAL_TZ_NAME,
    )


def _to_timestamp(dt: TsLike) -> pd.Timestamp:
    """Coerce any timestamp-like value to a :class:`pandas.Timestamp`.

    Args:
        dt: A datetime-like value (Timestamp, datetime, ISO string,
            epoch int/float).

    Returns:
        A ``pd.Timestamp`` instance.
    """
    return dt if isinstance(dt, pd.Timestamp) else pd.Timestamp(dt)


def _ensure_utc(ts: pd.Timestamp) -> pd.Timestamp:
    """Ensure a Timestamp is UTC-aware.

    Naive timestamps are assumed to represent local wall-clock time and
    are first localized to the configured timezone before converting to
    UTC.  Already-aware timestamps are simply converted to UTC.

    Args:
        ts: A pandas Timestamp (naive or aware).

    Returns:
        A UTC-aware Timestamp.
    """
    if ts.tz is None:
        ts = ts.tz_localize(_LOCAL_TZ_NAME)
    return ts.tz_convert("UTC")


def make_aware_local(dt: TsLike) -> datetime:
    """Interpret *dt* as local wall-clock time and return a naive datetime.

    Naive timestamps are localized to the configured timezone and then
    converted back to a naive local datetime.  Aware timestamps are
    converted to local time first.

    Args:
        dt: Any datetime-like value.

    Returns:
        A naive ``datetime`` representing local wall-clock time.
    """
    ts = _to_timestamp(dt)
    if ts.tz is None:
        ts = ts.tz_localize(_LOCAL_TZ_NAME)
    else:
        ts = ts.tz_convert(_LOCAL_TZ_NAME)
    return ts.tz_localize(None).to_pydatetime()


def to_utc_z_string(dt: TsLike) -> str:
    """Format *dt* as an ISO-8601 string with ``Z`` suffix (true UTC).

    Naive timestamps are assumed to be local time.

    Args:
        dt: Any datetime-like value.

    Returns:
        A string like ``2024-01-15T13:30:00Z``.
    """
    ts = _to_timestamp(dt)
    utc_ts = _ensure_utc(ts).replace(microsecond=0)
    return utc_ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def to_local_offset_string(dt: TsLike) -> str:
    """Format *dt* as a local ISO-8601 string carrying the UTC offset.

    Naive timestamps are assumed to be local wall-clock time and are
    localized to the configured timezone.  The resulting string always
    carries an explicit offset (e.g. ``+01:00``) so that UTC clients
    interpret API timestamps correctly (API-072).

    Args:
        dt: Any datetime-like value.

    Returns:
        A string like ``2024-01-15T14:30:00+01:00``.
    """
    ts = _to_timestamp(dt)
    if ts.tz is None:
        ts = ts.tz_localize(_LOCAL_TZ_NAME)
    else:
        ts = ts.tz_convert(_LOCAL_TZ_NAME)
    return ts.replace(microsecond=0).isoformat()


def ui_to_pg_query_range(
    start_local: TsLike,
    stop_local: TsLike,
) -> Tuple[str, str]:
    """Convert a UI time range to PostgreSQL query timestamps (Z-strings).

    Args:
        start_local: Range start (local time or UTC-aware).
        stop_local: Range end (local time or UTC-aware).

    Returns:
        A ``(start_z, stop_z)`` tuple of Z-suffixed ISO strings in true UTC.
    """
    return to_utc_z_string(start_local), to_utc_z_string(stop_local)


def ui_to_influx_query_range(
    start_local: TsLike,
    stop_local: TsLike,
    compat_z_suffix: bool = True,
) -> Tuple[str, str]:
    """Convert a UI time range to InfluxDB SQL query timestamps.

    Both modes now produce true UTC Z-strings since InfluxDB stores
    real UTC timestamps after the Fake-UTC fix.  The *compat_z_suffix*
    parameter is retained for API compatibility but has no effect.

    Args:
        start_local: Range start (local time or UTC-aware).
        stop_local: Range end (local time or UTC-aware).
        compat_z_suffix: Retained for backward compatibility (ignored).

    Returns:
        A ``(start_str, stop_str)`` tuple of Z-suffixed UTC time strings.
    """
    return to_utc_z_string(start_local), to_utc_z_string(stop_local)


def normalize_time_for_ui(
    obj: Union[pd.Series, pd.DataFrame],
    time_cols: Optional[Iterable[str]] = None,
) -> Union[pd.Series, pd.DataFrame]:
    """Normalize timestamps returned by InfluxDB for UI display.

    Converts UTC-aware timestamps to naive local wall-clock time using
    the configured timezone (with automatic DST handling).

    Args:
        obj: A Series or DataFrame containing timestamp data.
        time_cols: Column names to normalize.  Defaults to ``["time"]``
            when the column exists.

    Returns:
        A copy of *obj* with normalized, tz-naive local timestamps.
    """
    if isinstance(obj, pd.Series):
        return _normalize_series(obj)

    df = obj.copy() if isinstance(obj, pd.DataFrame) else pd.DataFrame()
    cols: List[str] = list(time_cols) if time_cols is not None else (["time"] if "time" in df.columns else [])
    for c in cols:
        if c in df.columns:
            df[c] = _normalize_datetime_column(df[c])
    if isinstance(df.index, pd.DatetimeIndex):
        idx = pd.to_datetime(df.index, errors="coerce", utc=False)
        if idx.tz is None:
            idx = idx.tz_localize("UTC")
        idx = idx.tz_convert(_LOCAL_TZ_NAME).tz_localize(None)
        df.index = idx
        df = df.sort_index()
    if "time" in df.columns:
        df = df.sort_values("time")
    return df


def _normalize_series(s_in: pd.Series) -> pd.Series:
    """Normalize a single datetime Series to naive local time.

    Args:
        s_in: Input Series (datetime or object dtype).

    Returns:
        A copy with tz-naive local timestamps.
    """
    s = s_in.copy()
    if pd.api.types.is_datetime64_any_dtype(s) or pd.api.types.is_object_dtype(s):
        s = pd.to_datetime(s, errors="coerce", utc=False)
        if s.dt.tz is None:
            s = s.dt.tz_localize("UTC")
        s = s.dt.tz_convert(_LOCAL_TZ_NAME).dt.tz_localize(None)
    return s


def _normalize_datetime_column(col: pd.Series) -> pd.Series:
    """Normalize a single DataFrame column of timestamps.

    Args:
        col: Series containing datetime values.

    Returns:
        Series with tz-naive local timestamps.
    """
    ts = pd.to_datetime(col, errors="coerce", utc=False)
    if ts.dt.tz is None:
        ts = ts.dt.tz_localize("UTC")
    ts = ts.dt.tz_convert(_LOCAL_TZ_NAME).dt.tz_localize(None)
    return ts
