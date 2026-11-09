"""Netcap data processing logic (Polars pipeline).

Contains data transformation and normalization routines for
network capture metrics retrieved from InfluxDB.

UCI expansion/collapse and port-collapsing functions are imported from
``otalon_common``.  API-specific functions (preprocessing,
wildcard filtering, Pandas conversion) remain here.
"""

from __future__ import annotations

from typing import Iterable

import pandas as pd
import polars as pl
from otalon_common.connection.port_collapsing import (
    aggregate_sparse_ports as aggregate_sparse_ports,
    port_wildcard as port_wildcard,
)
from otalon_common.uci.polars_ops import collapse_uci as collapse_uci, expand_uci as expand_uci


def preprocess(df: pl.DataFrame) -> pl.DataFrame:
    """Sort by time and normalize column types.

    Casts the ``time`` column to :class:`polars.Datetime` and the ``uci``
    column to :class:`polars.Utf8`, drops rows with null values, and
    returns a time-sorted DataFrame.

    Args:
        df: Polars DataFrame with at least ``time`` and ``uci`` columns.

    Returns:
        Cleaned and sorted Polars DataFrame.
    """
    out = df.with_columns([pl.col("time").cast(pl.Datetime, strict=False), pl.col("uci").cast(pl.Utf8)])
    out = out.drop_nulls()
    out = out.sort("time")
    return out


def extract_wildcard_timeseries(df: pl.DataFrame, wildcard_uci: str) -> pl.DataFrame:
    """Filter an aggregated DataFrame to a specific wildcard UCI.

    Supports two layouts:

    * If the DataFrame still carries the expanded UCI-field columns
      (``src_mac``, ``dst_mac``, …, ``src_port``, ``dst_port``,
      ``protocols``) the filter is built directly on those columns.
    * After ``apply_port_rules`` the UCI fields are dropped and only a
      collapsed ``uci`` column remains. In that case the filter falls
      back to comparing the ``uci`` strings, where each ``"*"`` in the
      pattern matches anything except a slash.

    Args:
        df: Polars DataFrame; either expanded or collapsed.
        wildcard_uci: UCI string to match; ``"*"`` in port positions
            acts as a wildcard.

    Returns:
        Filtered Polars DataFrame.
    """
    if "src_mac" in df.columns:
        return _filter_expanded(df, wildcard_uci)
    if "uci" in df.columns:
        return _filter_collapsed(df, wildcard_uci)
    return df.head(0)


def _filter_expanded(df: pl.DataFrame, wildcard_uci: str) -> pl.DataFrame:
    """Filter a DataFrame that still has the per-field UCI columns."""
    parts = wildcard_uci.split("/", 8)
    parts += [""] * (9 - len(parts))
    src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, src_port, dst_port, protocols = parts
    mask = (
        (pl.col("src_mac") == src_mac)
        & (pl.col("dst_mac") == dst_mac)
        & (pl.col("vlan") == vlan)
        & (pl.col("ip_proto") == ip_proto)
        & (pl.col("src_ip") == src_ip)
        & (pl.col("dst_ip") == dst_ip)
        & (pl.col("protocols") == protocols)
    )
    if src_port != "*":
        mask = mask & (pl.col("src_port") == src_port)
    if dst_port != "*":
        mask = mask & (pl.col("dst_port") == dst_port)
    return df.filter(mask)


def _filter_collapsed(df: pl.DataFrame, wildcard_uci: str) -> pl.DataFrame:
    """Filter a collapsed DataFrame using regex matching on the ``uci`` column.

    Builds a regex from the wildcard UCI where each ``"*"`` becomes
    ``[^/]*`` (matches anything but a slash) and other characters are
    escaped.  The match is anchored at both ends.

    Args:
        df: Polars DataFrame with a collapsed ``uci`` column.
        wildcard_uci: Wildcard pattern.

    Returns:
        Filtered Polars DataFrame.
    """
    import re

    chunks = wildcard_uci.split("*")
    pattern = "^" + "[^/]*".join(re.escape(c) for c in chunks) + "$"
    return df.filter(pl.col("uci").cast(pl.Utf8).str.contains(pattern))


def to_pandas_timeseries(df: pl.DataFrame, features: Iterable[str]) -> pd.DataFrame:
    """Convert a Polars DataFrame to a Pandas timeseries DataFrame.

    Selects ``time`` plus the requested *features* (including their
    ``_min`` / ``_max`` variants if present).  The ``time`` column
    remains as a regular column (not the index).

    Args:
        df: Polars DataFrame to convert.
        features: Feature column names to keep.

    Returns:
        Pandas DataFrame with ``time`` as the first column followed by
        matching feature columns.
    """
    out = df.to_pandas()
    if "time" in out.columns:
        out["time"] = pd.to_datetime(out["time"])
        out = out.set_index("time").sort_index()
    f = list(features or [])
    cols = f + [f"{x}_min" for x in f] + [f"{x}_max" for x in f]
    keep = [c for c in out.columns if c in cols]
    out = out[keep] if keep else pd.DataFrame(index=out.index)
    return out.reset_index()
