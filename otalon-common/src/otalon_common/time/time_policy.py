"""Configurable timezone policy and timestamp conversion utilities.

All time conversion functions accept both ``pd.Timestamp`` and ``datetime.datetime``.
"""

from datetime import datetime
from zoneinfo import ZoneInfo

import pandas as pd

_local_tz: ZoneInfo = ZoneInfo("Europe/Berlin")


def configure_timezone(tz_name: str) -> None:
    """Set the module-level timezone used by all time operations.

    Args:
        tz_name: A valid IANA timezone name (e.g., ``"America/New_York"``).
    """
    global _local_tz
    _local_tz = ZoneInfo(tz_name)


def get_local_tz() -> ZoneInfo:
    """Return the currently configured local timezone.

    Returns:
        The ``ZoneInfo`` instance for the configured timezone.
        Defaults to ``ZoneInfo("Europe/Berlin")`` if not configured.
    """
    return _local_tz


def to_utc(dt: pd.Timestamp | datetime) -> pd.Timestamp:
    """Convert a timestamp to a UTC-aware ``pd.Timestamp``.

    Naive timestamps are assumed to be UTC. Aware timestamps are converted.

    Args:
        dt: A ``pd.Timestamp`` or ``datetime.datetime``.

    Returns:
        A UTC-aware ``pd.Timestamp``.
    """
    ts = _ensure_pd_timestamp(dt)
    if ts.tzinfo is None:
        return ts.tz_localize("UTC")
    return ts.tz_convert("UTC")


def to_utc_z_string(dt: pd.Timestamp | datetime) -> str:
    """Convert a timestamp to a UTC ISO string with Z suffix for InfluxDB queries.

    Args:
        dt: A ``pd.Timestamp`` or ``datetime.datetime``.

    Returns:
        A string like ``"2026-04-03T12:00:00Z"``.
    """
    utc_ts = to_utc(dt)
    return utc_ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def to_local(dt: pd.Timestamp | datetime) -> pd.Timestamp:
    """Convert a timestamp to the configured local timezone.

    Args:
        dt: A ``pd.Timestamp`` or ``datetime.datetime``.

    Returns:
        A timezone-aware ``pd.Timestamp`` in the configured local timezone.
    """
    utc_ts = to_utc(dt)
    return utc_ts.tz_convert(_local_tz)


def to_local_offset_string(dt: pd.Timestamp | datetime) -> str:
    """Convert a timestamp to a local-time string with UTC offset for UI display.

    Args:
        dt: A ``pd.Timestamp`` or ``datetime.datetime``.

    Returns:
        A string like ``"2026-04-03T14:00:00+02:00"``.
    """
    local_ts = to_local(dt)
    return local_ts.isoformat()


def _ensure_pd_timestamp(dt: pd.Timestamp | datetime) -> pd.Timestamp:
    """Convert a datetime to pd.Timestamp if necessary.

    Args:
        dt: A ``pd.Timestamp`` or ``datetime.datetime``.

    Returns:
        A ``pd.Timestamp``.
    """
    if isinstance(dt, pd.Timestamp):
        return dt
    return pd.Timestamp(dt)
