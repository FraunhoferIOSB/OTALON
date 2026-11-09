"""Polars DataFrame/LazyFrame operations for UCI expansion and collapsing."""

import polars as pl
from otalon_common.uci.constants import UCI_FIELDS


def expand_uci(df: pl.DataFrame | pl.LazyFrame) -> pl.DataFrame | pl.LazyFrame:
    """Split a ``uci`` column into 9 individual columns named after UCI_FIELDS.

    Uses ``str.split_exact("/", 8)`` to produce exactly 9 fields.

    Args:
        df: A Polars DataFrame or LazyFrame with a ``uci`` column.

    Returns:
        The input frame with 9 new columns (one per UCI field) added.
        The original ``uci`` column is preserved.
    """
    split_expr = pl.col("uci").str.split_exact("/", 8)
    field_exprs = [
        split_expr.struct.field(f"field_{i}").alias(name)
        for i, name in enumerate(UCI_FIELDS)
    ]
    return df.with_columns(field_exprs)


def collapse_uci(
    df: pl.DataFrame | pl.LazyFrame,
    drop_uci_fields: bool = False,
) -> pl.DataFrame | pl.LazyFrame:
    """Re-assemble a ``uci`` column from 9 individual UCI field columns.

    Args:
        df: A Polars DataFrame or LazyFrame with columns named after UCI_FIELDS.
        drop_uci_fields: If True, remove the 9 individual field columns after collapsing.

    Returns:
        The input frame with a ``uci`` column containing the re-joined values.
    """
    concat_expr = pl.concat_str(
        [pl.col(name) for name in UCI_FIELDS], separator="/"
    ).alias("uci")
    result = df.with_columns(concat_expr)

    if drop_uci_fields:
        result = result.drop(list(UCI_FIELDS))

    return result
