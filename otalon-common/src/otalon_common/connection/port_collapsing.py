"""Stateless port-collapsing fallback and port wildcard helper."""

import polars as pl
from otalon_common.uci.constants import UCI_BASE_KEYS, UCI_FIELDS


def port_wildcard(ports: list[str]) -> str:
    """Return the single port if exactly one unique non-empty value exists, otherwise ``"*"``.

    Args:
        ports: List of port value strings.

    Returns:
        The single port string or ``"*"``.
    """
    unique = set(p for p in ports if p)
    if len(unique) == 1:
        return unique.pop()
    return "*"


def aggregate_sparse_ports(
    df: pl.DataFrame,
    threshold: int,
    feature_cols: list[str] | None = None,
) -> pl.DataFrame:
    """Stateless fallback that collapses ports for sparse rows.

    Rows with ``packet_count <= threshold`` are grouped by base key. Ports
    that collapse into multiple distinct values become ``"*"``.
    Rows with ``packet_count > threshold`` are not affected.

    Args:
        df: DataFrame with expanded UCI columns and a ``packet_count`` column.
        threshold: Maximum packet count for a row to be considered sparse.
        feature_cols: Feature columns to sum during aggregation.
            Defaults to ``["packet_count"]``.

    Returns:
        DataFrame with sparse rows aggregated and non-sparse rows preserved.
    """
    if feature_cols is None:
        feature_cols = ["packet_count"]

    sparse_mask = pl.col("packet_count") <= threshold
    sparse_df = df.filter(sparse_mask)
    non_sparse_df = df.filter(~sparse_mask)

    if sparse_df.is_empty():
        return df

    aggregated = _aggregate_sparse_group(sparse_df, feature_cols)
    return pl.concat([non_sparse_df, aggregated], how="diagonal_relaxed")


def _aggregate_sparse_group(
    sparse_df: pl.DataFrame,
    feature_cols: list[str],
) -> pl.DataFrame:
    """Aggregate sparse rows by base key, wildcarding heterogeneous ports.

    Args:
        sparse_df: DataFrame of sparse rows (all with packet_count <= threshold).
        feature_cols: Feature columns to sum.

    Returns:
        Aggregated DataFrame with wildcarded ports.
    """
    base_keys = list(UCI_BASE_KEYS)

    agg_exprs: list[pl.Expr] = [
        pl.col("src_port").unique().alias("_src_ports"),
        pl.col("dst_port").unique().alias("_dst_ports"),
    ]

    available_cols = set(sparse_df.columns)
    for col_name in feature_cols:
        if col_name in available_cols:
            agg_exprs.append(pl.col(col_name).sum())

    grouped = sparse_df.group_by(base_keys).agg(agg_exprs)

    grouped = grouped.with_columns(
        pl.when(pl.col("_src_ports").list.len() == 1)
        .then(pl.col("_src_ports").list.first())
        .otherwise(pl.lit("*"))
        .alias("src_port"),
        pl.when(pl.col("_dst_ports").list.len() == 1)
        .then(pl.col("_dst_ports").list.first())
        .otherwise(pl.lit("*"))
        .alias("dst_port"),
    ).drop("_src_ports", "_dst_ports")

    grouped = grouped.with_columns(
        pl.concat_str([pl.col(f) for f in UCI_FIELDS], separator="/").alias("uci")
    )

    return grouped
