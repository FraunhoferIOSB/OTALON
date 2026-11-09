"""Registry-based metrics dispatcher for interval summarization.

Provides a dispatcher that routes metric summarization to module-specific
summarizers based on the module name. Falls back to a general summarizer
for unregistered modules.
"""

from __future__ import annotations

from typing import Any, Callable

import polars as pl
from loguru import logger

SummarizerFunc = Callable[[pl.DataFrame, str], dict[str, Any]]

_SUMMARIZER_REGISTRY: dict[str, SummarizerFunc] = {}


def register_summarizer(module_name: str, func: SummarizerFunc) -> None:
    """Register a metric summarizer function for a module.

    Args:
        module_name: Module name key (e.g., ``conn``, ``mac_traffic``).
        func: Summarizer function accepting (DataFrame, tag_key) and returning a dict.
    """
    if module_name in _SUMMARIZER_REGISTRY:
        logger.warning("Overwriting summarizer for module '{}'", module_name)
    _SUMMARIZER_REGISTRY[module_name] = func
    logger.debug("Registered metric summarizer for '{}'", module_name)


def get_summarizer(module_name: str) -> SummarizerFunc:
    """Look up a registered summarizer or return the general fallback.

    Args:
        module_name: Module name to look up.

    Returns:
        Registered summarizer or :func:`summarize_interval_general`.
    """
    return _SUMMARIZER_REGISTRY.get(module_name, summarize_interval_general)


def dispatch_summary(
    df: pl.DataFrame,
    module_name: str,
    tag_key: str,
) -> dict[str, Any]:
    """Dispatch metric summarization to the appropriate summarizer.

    Args:
        df: Interval DataFrame to summarize.
        module_name: Detection module name.
        tag_key: Series identifier column.

    Returns:
        Summary dict from the dispatched summarizer.
    """
    summarizer = get_summarizer(module_name)
    return summarizer(df, tag_key)


def summarize_interval_general(df: pl.DataFrame, tag_key: str) -> dict[str, Any]:
    """General-purpose interval summarizer for any module.

    Computes basic statistics (count, mean, std, min, max) for all
    numeric columns in the DataFrame.

    Args:
        df: Interval DataFrame.
        tag_key: Series identifier column (excluded from feature stats).

    Returns:
        Dict with ``row_count``, ``series_count``, and per-feature statistics.
    """
    if df.is_empty():
        return {"row_count": 0, "series_count": 0, "features": {}}

    series_count = df[tag_key].n_unique() if tag_key in df.columns else 0
    feature_stats = _compute_numeric_stats(df, tag_key)

    return {
        "row_count": len(df),
        "series_count": series_count,
        "features": feature_stats,
    }


def summarize_interval_connection(df: pl.DataFrame, tag_key: str) -> dict[str, Any]:
    """Connection-specific interval summarizer.

    Extends the general summary with connection-specific metrics like
    unique protocol stacks and packet size distributions.

    Args:
        df: Interval DataFrame for connection data.
        tag_key: Series identifier column (``uci``).

    Returns:
        Summary dict with connection-specific fields.
    """
    base = summarize_interval_general(df, tag_key)
    base["unique_protocols"] = _count_unique_protocols(df)
    base["packet_stats"] = _compute_packet_stats(df)
    return base


def _compute_numeric_stats(
    df: pl.DataFrame,
    tag_key: str,
) -> dict[str, dict[str, float]]:
    """Compute descriptive statistics for all numeric columns.

    Args:
        df: Input DataFrame.
        tag_key: Column to exclude from feature stats.

    Returns:
        Dict mapping column name to stat dict (mean, std, min, max).
    """
    exclude = {"time", tag_key, "is_anomaly", "anomaly_type", "confidence", "violated_features"}
    stats: dict[str, dict[str, float]] = {}

    for col_name in df.columns:
        if col_name in exclude:
            continue
        dtype = df[col_name].dtype
        if not _is_numeric_dtype(dtype):
            continue
        stats[col_name] = _single_column_stats(df[col_name])

    return stats


def _single_column_stats(series: pl.Series) -> dict[str, float]:
    """Compute mean, std, min, max for a single numeric series.

    Args:
        series: Polars numeric series.

    Returns:
        Dict with statistical values.
    """
    clean = series.drop_nulls().cast(pl.Float64)
    if len(clean) == 0:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0}
    return {
        "mean": float(clean.mean()),
        "std": float(clean.std(ddof=1)) if len(clean) > 1 else 0.0,
        "min": float(clean.min()),
        "max": float(clean.max()),
    }


def _count_unique_protocols(df: pl.DataFrame) -> int:
    """Count unique protocol stacks in connection data.

    Args:
        df: Connection DataFrame.

    Returns:
        Number of unique protocol stacks.
    """
    for col in ("protocol_stack", "protocol"):
        if col in df.columns:
            return df[col].n_unique()
    return 0


def _compute_packet_stats(df: pl.DataFrame) -> dict[str, float]:
    """Compute packet size statistics if available.

    Args:
        df: Connection DataFrame.

    Returns:
        Dict with packet size stats or empty dict.
    """
    for col in ("mean_packet_size", "total_volume", "packet_count"):
        if col in df.columns:
            return _single_column_stats(df[col])
    return {}


def _is_numeric_dtype(dtype: pl.DataType) -> bool:
    """Check whether a Polars dtype is numeric.

    Args:
        dtype: Polars data type.

    Returns:
        True if the dtype is a numeric type.
    """
    numeric_types = (
        pl.Int8,
        pl.Int16,
        pl.Int32,
        pl.Int64,
        pl.UInt8,
        pl.UInt16,
        pl.UInt32,
        pl.UInt64,
        pl.Float32,
        pl.Float64,
    )
    return isinstance(dtype, numeric_types)


def _register_builtins() -> None:
    """Register built-in summarizers for known modules."""
    register_summarizer("conn", summarize_interval_connection)
    register_summarizer("mac_traffic", summarize_interval_general)
    register_summarizer("proto_traffic", summarize_interval_general)


_register_builtins()
