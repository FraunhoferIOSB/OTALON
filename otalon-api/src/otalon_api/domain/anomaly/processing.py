"""Anomaly domain processing logic.

Provides pure functions for UCI parsing, timeseries-bounds merging, and
dashboard signal-color computation.  These are intentionally stateless
and framework-independent so they can be unit-tested without any I/O.
"""

from __future__ import annotations

import math
from typing import Any, cast

import numpy as np
import pandas as pd
from otalon_common.types.anomaly_types import BENIGN_TYPES as BENIGN_TYPES

UCI_SEGMENT_NAMES: tuple[str, ...] = (
    "src_mac",
    "dst_mac",
    "vlan",
    "ip_proto",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocols",
)

UCI_DISPLAY_NAMES: tuple[str, ...] = (
    "Source MAC",
    "Destination MAC",
    "VLAN",
    "IP Proto",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocols",
)


def parse_uci(uci: str) -> dict[str, str]:
    """Parse a 9-segment UCI string into a labeled dictionary.

    The UCI format is
    ``src_mac/dst_mac/vlan/ip_proto/src_ip/dst_ip/src_port/dst_port/protocols``.
    Missing segments are filled with empty strings.

    Args:
        uci: The raw UCI string.

    Returns:
        A dict with keys from :data:`UCI_SEGMENT_NAMES` mapped to their
        string values.
    """
    parts = uci.split("/", 8)
    parts += [""] * (9 - len(parts))
    return dict(zip(UCI_SEGMENT_NAMES, parts))


def parse_uci_to_entity(uci: str) -> dict[str, str]:
    """Parse a UCI string into a display-friendly entity dictionary.

    Returns a dict whose keys match the GD-08 golden-data column names
    (``"Source MAC"``, ``"Destination MAC"``, etc.) plus a ``"UCI"`` key
    holding the original string.

    Args:
        uci: The raw UCI string.

    Returns:
        A dict with human-readable keys and a trailing ``UCI`` entry.
    """
    parts = uci.split("/", 8)
    parts += [""] * (9 - len(parts))
    entity: dict[str, str] = {
        "Source MAC": parts[0],
        "Destination MAC": parts[1],
        "Source IP": parts[4],
        "Destination IP": parts[5],
        "Source Port": parts[6],
        "Destination Port": parts[7],
        "VLAN": parts[2],
        "IP Proto": parts[3],
        "Protocols": parts[8],
        "UCI": uci,
    }
    return entity


def prepare_timeseries_with_bounds(
    timeseries_df: pd.DataFrame,
    bounds: list[dict[str, Any]],
    metric: str,
) -> list[dict[str, Any]]:
    """Merge timeseries data with boundary thresholds for a single metric.

    Combines InfluxDB timeseries rows with PostgreSQL bound rows to
    produce the GD-05 output format.  Violations are computed where both
    the value and the bound are non-NaN.

    NaN values are converted to ``None`` so that downstream JSON
    serialization emits ``null`` instead of the invalid ``NaN`` token.

    Args:
        timeseries_df: DataFrame with at least a ``time`` column and
            the *metric* column (plus optional ``<metric>_min`` /
            ``<metric>_max`` columns from aggregation).
        bounds: List of bound row dicts as returned by
            :meth:`PostgresRepository.query_bounds`.  Each dict should
            contain ``lb_<metric>`` / ``ub_<metric>`` keys.
        metric: The feature name to extract (e.g. ``"mean_packet_size"``).

    Returns:
        A list of dicts suitable for JSON serialization, each containing
        ``time``, ``value``, ``value_min``, ``value_max``,
        ``lower_bound``, ``upper_bound``, ``violation_low``, and
        ``violation_high``.
    """
    if timeseries_df is None or timeseries_df.empty:
        return []

    data = timeseries_df.copy()

    lower_bound = _extract_nested_bound(bounds, "lower_bounds", metric)
    upper_bound = _extract_nested_bound(bounds, "upper_bounds", metric)

    col_min = f"{metric}_min"
    col_max = f"{metric}_max"
    has_agg = col_min in data.columns and col_max in data.columns

    if metric in data.columns:
        values = pd.to_numeric(data[metric], errors="coerce")
    elif has_agg:
        values = pd.to_numeric((data[col_min] + data[col_max]) / 2.0, errors="coerce")
    else:
        values = pd.Series(np.nan, index=data.index, dtype="float64")

    if has_agg:
        values_min = pd.to_numeric(data[col_min], errors="coerce")
        values_max = pd.to_numeric(data[col_max], errors="coerce")
    else:
        values_min = values.copy()
        values_max = values.copy()

    result: list[dict[str, Any]] = []
    for idx in range(len(data)):
        row_time = data["time"].iloc[idx]
        val = values.iloc[idx]
        v_min = values_min.iloc[idx]
        v_max = values_max.iloc[idx]
        viol_low, viol_high = _compute_aggregate_violations(val, v_min, v_max, lower_bound, upper_bound)

        result.append(
            {
                "time": _format_timestamp(row_time),
                "value": _nan_to_none(val),
                "value_min": _nan_to_none(v_min),
                "value_max": _nan_to_none(v_max),
                "lower_bound": _nan_to_none(lower_bound),
                "upper_bound": _nan_to_none(upper_bound),
                "violation_low": viol_low,
                "violation_high": viol_high,
            }
        )

    return result


def compute_signal_color(anomaly_count: int, group_count: int) -> str:
    """Compute the dashboard traffic-light signal color.

    The simple heuristic mirrors the Panel-UI logic:
      - ``"danger"`` if there are any unconfirmed non-benign anomalies
      - ``"warning"`` if there are only benign anomalies
      - ``"success"`` if there are no anomalies at all

    For the API-level service this simplified version uses raw counts
    because full primary_type analysis happens in
    :class:`DashboardKpiService`.

    Args:
        anomaly_count: Total number of alarm groups.
        group_count: Number of distinct alarm groups.

    Returns:
        One of ``"success"``, ``"warning"``, ``"danger"``.
    """
    if anomaly_count <= 0 and group_count <= 0:
        return "success"
    if group_count > 0:
        return "danger"
    return "warning"


def compute_signal_color_from_groups(groups: list[dict[str, Any]]) -> str:
    """Compute signal color from full alarm group data.

    Inspects ``confirmed`` and ``primary_type`` fields to determine the
    traffic-light color following the same logic as the Panel-UI
    ``DashboardKpiService.compute_signal_color()``.

    Args:
        groups: List of alarm group dicts with at least ``confirmed``
            and ``primary_type`` keys.

    Returns:
        One of ``"success"``, ``"warning"``, ``"danger"``.
    """
    if not groups:
        return "success"

    unconfirmed = [g for g in groups if not bool(g.get("confirmed", False))]
    if not unconfirmed:
        return "success"

    has_red = any(_is_red_type(g.get("primary_type", "")) for g in unconfirmed)
    if has_red:
        return "danger"

    has_yellow = any(_is_yellow_type(g.get("primary_type", "")) for g in unconfirmed)
    return "warning" if has_yellow else "success"


def _is_red_type(primary_type: Any) -> bool:
    """Check whether a primary_type indicates a red (danger) signal.

    Args:
        primary_type: The primary_type value from an alarm group.

    Returns:
        ``True`` if the type is neither benign nor unknown.
    """
    types = _extract_types(primary_type)
    return any((t not in BENIGN_TYPES) and (t.lower() != "unknown") for t in types)


def _is_yellow_type(primary_type: Any) -> bool:
    """Check whether a primary_type indicates a yellow (warning) signal.

    Args:
        primary_type: The primary_type value from an alarm group.

    Returns:
        ``True`` if the type is a known benign type.
    """
    types = _extract_types(primary_type)
    return any(t in BENIGN_TYPES for t in types)


def _extract_types(value: Any) -> list[str]:
    """Normalize a primary_type value to a list of type strings.

    Args:
        value: The raw primary_type (string, list, or None).

    Returns:
        A list of type name strings.
    """
    if value is None:
        return ["unknown"]
    if isinstance(value, list):
        return [str(x) for x in value] if value else ["unknown"]
    s = str(value).strip()
    if not s:
        return ["unknown"]
    return [s]


def _extract_nested_bound(bounds: list[dict[str, Any]], json_col: str, metric: str) -> float:
    """Extract a bound value from the nested JSON column of the first bounds row.

    The PostgreSQL ``bounds`` table stores lower/upper bounds as JSON objects
    in ``lower_bounds`` and ``upper_bounds`` columns, keyed by metric name.

    Falls back to the legacy flat-key format (``lb_<metric>`` / ``ub_<metric>``)
    if the JSON column is not found.

    Args:
        bounds: List of bound dicts from PostgreSQL.
        json_col: Column name containing the JSON object (``"lower_bounds"`` or ``"upper_bounds"``).
        metric: Feature name to look up inside the JSON object.

    Returns:
        The numeric bound value, or ``NaN`` if unavailable.
    """
    if not bounds:
        return float("nan")
    first = bounds[0]
    json_obj = first.get(json_col)
    if isinstance(json_obj, dict):
        raw = json_obj.get(metric)
        if raw is not None:
            try:
                val = float(raw)
                return val if not math.isnan(val) else float("nan")
            except (TypeError, ValueError):
                pass
    prefix = "lb_" if "lower" in json_col else "ub_"
    return _extract_bound_value(bounds, f"{prefix}{metric}")


def _extract_bound_value(bounds: list[dict[str, Any]], key: str) -> float:
    """Extract a single bound value from the first bounds row.

    Args:
        bounds: List of bound dicts from PostgreSQL.
        key: Column name (e.g. ``"lb_mean_packet_size"``).

    Returns:
        The numeric bound value, or ``NaN`` if unavailable.
    """
    if not bounds:
        return float("nan")
    first = bounds[0]
    raw = first.get(key)
    if raw is None:
        return float("nan")
    try:
        val = float(raw)
        return val if not math.isnan(val) else float("nan")
    except (TypeError, ValueError):
        return float("nan")


def _compute_violations(value: float, lower: float, upper: float) -> tuple[bool, bool]:
    """Compute bound violations in a NaN-safe manner.

    Both flags are ``False`` when any input is NaN.

    Args:
        value: The observed metric value.
        lower: Lower bound threshold.
        upper: Upper bound threshold.

    Returns:
        A ``(violation_low, violation_high)`` tuple.
    """
    try:
        if math.isnan(value) or math.isnan(lower) or math.isnan(upper):
            return False, False
    except (TypeError, ValueError):
        return False, False
    return bool(value < lower), bool(value > upper)


def _compute_aggregate_violations(
    value: float,
    value_min: float,
    value_max: float,
    lower: float,
    upper: float,
) -> tuple[bool, bool]:
    """Detect violations from aggregate mean and preserved bucket extrema."""
    candidates_low = [value, value_min]
    candidates_high = [value, value_max]
    valid_low = [item for item in candidates_low if _is_finite_number(item)]
    valid_high = [item for item in candidates_high if _is_finite_number(item)]
    if not _is_finite_number(lower) or not _is_finite_number(upper):
        return False, False
    return bool(valid_low and min(valid_low) < lower), bool(valid_high and max(valid_high) > upper)


def _is_finite_number(value: Any) -> bool:
    """Return whether value can participate in numeric bound comparisons."""
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError):
        return False


def _nan_to_none(value: Any) -> float | int | None:
    """Convert NaN/inf float values to ``None`` and numpy scalars to native Python types.

    Ensures that returned values are JSON-serializable by converting
    ``numpy.int64`` / ``numpy.float64`` to native ``int`` / ``float``.

    Args:
        value: A numeric value (possibly a numpy scalar).

    Returns:
        ``None`` if the value is NaN or infinity, a native Python numeric
        type otherwise.
    """
    if value is None:
        return None
    try:
        if math.isnan(float(value)) or math.isinf(float(value)):
            return None
    except (TypeError, ValueError):
        pass
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    return cast(float | int | None, value)


def _format_timestamp(ts: Any) -> str:
    """Format a timestamp to a naive ISO-8601 string without timezone suffix.

    After ``normalize_time_for_ui()`` the timestamps are naive local
    wall-clock time.  No ``Z`` suffix is appended so the frontend does
    not re-interpret them as UTC.

    Args:
        ts: A datetime-like value.

    Returns:
        Naive ISO-8601 string (e.g. ``2024-01-15T14:30:00``).
    """
    if ts is None:
        return ""
    try:
        t = pd.Timestamp(ts)
        if t.tz is not None:
            t = t.tz_localize(None)
        return t.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return str(ts)
