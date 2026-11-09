"""FS-C feature extraction for alarm-group classification.

Mirrors ``workshop/ml-baseline/extract_features.py`` (feature set C):
51 features per alarm = 10 numeric metrics aggregated as
``sum/mean/max/std`` plus 11 meta features capturing alarm-level
properties.
"""

from __future__ import annotations

import math
import re
from typing import Sequence

import numpy as np
import polars as pl

METRIC_COLS: tuple[str, ...] = (
    "packet_count",
    "total_volume",
    "mean_packet_size",
    "min_packet_size",
    "max_packet_size",
    "std_packet_size",
    "mean_interarrival_time",
    "min_interarrival_time",
    "max_interarrival_time",
    "std_interarrival_time",
)

PROTO_TOKENS: tuple[str, ...] = (
    "ARP",
    "TCP",
    "UDP",
    "ICMP",
    "OPC-UA",
    "PROFINET",
)


def feature_names() -> list[str]:
    """Return the list of FS-C feature column names in deterministic order.

    The order is fixed across train and inference. It matches the schema
    used by the trained model so that prediction-time feature vectors are
    aligned with the training-time column ordering.

    Returns:
        Ordered list of 51 feature names.
    """
    names: list[str] = []
    for col in METRIC_COLS:
        names.append(f"{col}__sum")
        names.append(f"{col}__mean")
        names.append(f"{col}__max")
        names.append(f"{col}__std")
    names.append("meta__n_series_ids_alert")
    names.append("meta__n_series_ids_observed")
    names.append("meta__n_rows")
    names.append("meta__duration_sec")
    names.append("meta__n_protocols")
    for tok in PROTO_TOKENS:
        names.append(f"meta__has_{_proto_key(tok)}")
    return names


def series_ids_to_regex(series_ids: Sequence[str]) -> re.Pattern[str]:
    """Compile a single regex matching any of an alarm's series_ids.

    Wildcards (``*``) within a series_id are translated to ``[^/]*``
    so that ephemeral ports inside a slash-separated UCI segment do not
    break the match. All other regex meta characters are escaped.

    Args:
        series_ids: List of series identifier strings, possibly with wildcards.

    Returns:
        Compiled regex pattern.
    """
    parts: list[str] = []
    for sid in series_ids:
        chunks = sid.split("*")
        escaped = "[^/]*".join(re.escape(c) for c in chunks)
        parts.append(f"(?:{escaped})")
    pattern = "^(?:" + "|".join(parts) + ")$"
    return re.compile(pattern)


def extract_alarm_features(
    influx_rows: pl.DataFrame,
    series_ids_count: int,
    duration_seconds: float,
) -> tuple[np.ndarray, list[str]]:
    """Compute the FS-C feature vector for a single alarm.

    Args:
        influx_rows: Polars DataFrame of network metrics rows already
            filtered to the alarm's time window and series_ids.
            Must contain a ``uci`` column and the metric columns listed
            in :data:`METRIC_COLS`.
        series_ids_count: Number of series_ids declared on the alarm
            (used as the ``meta__n_series_ids_alert`` feature; can differ
            from the count of UCIs actually observed in the rows).
        duration_seconds: Alarm duration in seconds.

    Returns:
        Tuple of ``(feature_vector, feature_names)`` where the vector
        has shape ``(51,)`` and the names list has the same length and
        order.
    """
    names = feature_names()
    values: list[float] = []

    is_empty = influx_rows.is_empty()
    for col in METRIC_COLS:
        sum_v, mean_v, max_v, std_v = _aggregate_metric(influx_rows, col, is_empty)
        values.append(sum_v)
        values.append(mean_v)
        values.append(max_v)
        values.append(std_v)

    meta = _meta_features(influx_rows, series_ids_count, duration_seconds)
    values.extend(meta)

    return np.asarray(values, dtype=np.float64), names


def _aggregate_metric(
    df: pl.DataFrame,
    col: str,
    is_empty: bool,
) -> tuple[float, float, float, float]:
    """Aggregate a single metric column to ``(sum, mean, max, std)``.

    Args:
        df: Influx rows DataFrame.
        col: Metric column name.
        is_empty: Whether the DataFrame is empty (computed once by caller).

    Returns:
        Tuple of four safe floats (NaNs/Infs are mapped to 0.0).
    """
    if is_empty or col not in df.columns:
        return 0.0, 0.0, 0.0, 0.0
    series = df[col].cast(pl.Float64, strict=False)
    return (
        _safe(series.sum()),
        _safe(series.mean()),
        _safe(series.max()),
        _safe(series.std(ddof=0)),
    )


def _meta_features(
    df: pl.DataFrame,
    series_ids_count: int,
    duration_seconds: float,
) -> list[float]:
    """Compute the 11 FS-C meta features.

    Args:
        df: Influx rows DataFrame.
        series_ids_count: Series-ID count declared on the alarm.
        duration_seconds: Alarm duration in seconds.

    Returns:
        List of 11 floats: ``n_series_ids_alert``, ``n_series_ids_observed``,
        ``n_rows``, ``duration_sec``, ``n_protocols``, plus six protocol
        presence flags.
    """
    if df.is_empty() or "uci" not in df.columns:
        unique_uci: list[str] = []
    else:
        unique_uci = df["uci"].drop_nulls().unique().to_list()

    protocol_set: set[str] = set()
    for uci in unique_uci:
        tail = str(uci).rsplit("/", 1)[-1]
        for tok in tail.split(":"):
            if tok:
                protocol_set.add(tok)

    meta: list[float] = [
        float(series_ids_count),
        float(len(unique_uci)),
        float(len(df)),
        float(duration_seconds),
        float(len(protocol_set)),
    ]
    for tok in PROTO_TOKENS:
        meta.append(1.0 if tok in protocol_set else 0.0)
    return meta


def _safe(val: object) -> float:
    """Return ``float(val)`` clamped against None / NaN / Inf.

    Args:
        val: Any numeric value, possibly None or non-finite.

    Returns:
        Sanitized float (defaults to 0.0).
    """
    if val is None:
        return 0.0
    try:
        out = float(val)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(out) or math.isinf(out):
        return 0.0
    return out


def _proto_key(token: str) -> str:
    """Convert a protocol token to its meta-feature key suffix.

    ``OPC-UA`` becomes ``opcua`` and ``ARP`` becomes ``arp``.

    Args:
        token: Protocol token (e.g. ``"OPC-UA"``).

    Returns:
        Lowercase key with hyphens removed.
    """
    return token.lower().replace("-", "")
