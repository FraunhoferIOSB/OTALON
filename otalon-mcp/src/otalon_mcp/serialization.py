"""Serialization helpers for the OTALON MCP server."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
import pandas as pd


def _is_null(value: Any) -> bool:
    """Return True if value should be considered null/NA.

    Avoid ambiguous truth-value checks on arrays/series by handling them explicitly.
    """
    if value is None:
        return True
    # Arrays, sequences, mappings are not treated as "null" here; they will be serialized later.
    if isinstance(value, (list, tuple, Mapping, np.ndarray, pd.Series)):
        return False
    try:
        res = pd.isna(value)
        # pd.isna may return array-like for some types; consider "all NA" as null in that case.
        if isinstance(res, (np.ndarray, pd.Series)):
            try:
                return bool(np.all(res))
            except Exception:
                return False
        return bool(res)
    except Exception:
        return False


def _serialize_sequence(items: Sequence[Any]) -> list[Any]:
    return [_serialize_value(item) for item in items]


def _serialize_mapping(items: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): _serialize_value(value) for key, value in items.items()}


def _serialize_value(value: Any) -> Any:
    if _is_null(value):
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, pd.Timedelta):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, Mapping):
        return _serialize_mapping(value)
    if isinstance(value, (list, tuple)):
        return _serialize_sequence(value)
    if isinstance(value, np.ndarray):
        return _serialize_sequence(value.tolist())
    return value


def _prepare_dataframe(df: pd.DataFrame, include_index: bool, index_name: str | None) -> pd.DataFrame:
    if not include_index:
        return df
    idx_name = index_name or (df.index.name or "index")
    return df.reset_index().rename(columns={df.index.name or "index": idx_name})


def dataframe_to_table(
    df: pd.DataFrame,
    *,
    include_index: bool = False,
    index_name: str | None = None,
) -> dict[str, Any]:
    """Convert a pandas DataFrame to a table payload."""
    if df is None or df.empty:
        prepared = _prepare_dataframe(df if df is not None else pd.DataFrame(), include_index, index_name)
        columns = [str(col) for col in prepared.columns]
        return {"columns": columns, "rows": [], "rowcount": 0}
    prepared = _prepare_dataframe(df, include_index, index_name)
    columns = [str(col) for col in prepared.columns]
    rows = [[_serialize_value(cell) for cell in row] for row in prepared.itertuples(index=False, name=None)]
    return {"columns": columns, "rows": rows, "rowcount": len(rows)}


def dataframe_to_records(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Convert a pandas DataFrame to a list of dictionaries."""
    if df is None or df.empty:
        return []
    records = df.to_dict(orient="records")
    return [_serialize_mapping(record) for record in records]  # type: ignore[arg-type]


def ensure_dataframe(value: Any, columns: Iterable[str] | None = None) -> pd.DataFrame:
    """Return a DataFrame for arbitrary iterable input."""
    if isinstance(value, pd.DataFrame):
        return value
    if isinstance(value, list):
        if not value:
            return pd.DataFrame(columns=list(columns or []))
        if isinstance(value[0], Mapping):
            return pd.DataFrame(value)
        return pd.DataFrame(value, columns=list(columns or []))
    raise TypeError("Unsupported value for DataFrame conversion.")
