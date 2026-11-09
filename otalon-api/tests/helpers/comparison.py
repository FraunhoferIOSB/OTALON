"""Test comparison helpers for golden-data and schema validation."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from pydantic import BaseModel


def assert_dataframes_equal(
    actual: pd.DataFrame,
    expected: pd.DataFrame,
    rtol: float = 1e-5,
    atol: float = 1e-8,
    check_dtype: bool = False,
) -> None:
    """Assert that two DataFrames are equal within tolerance.

    Compares column sets, row counts, and cell values.  Numeric columns
    are compared with ``np.allclose`` (NaN-aware); datetime columns are
    compared as int64 timestamps; object/string columns require exact
    equality.

    Args:
        actual: The DataFrame produced by the code under test.
        expected: The golden / reference DataFrame.
        rtol: Relative tolerance for numeric comparisons.
        atol: Absolute tolerance for numeric comparisons.
        check_dtype: When ``True``, also assert matching dtypes per column.

    Raises:
        AssertionError: If the DataFrames differ beyond tolerance.
    """
    assert set(actual.columns) == set(expected.columns), (
        f"Column mismatch: actual={sorted(actual.columns)}, " f"expected={sorted(expected.columns)}"
    )

    assert len(actual) == len(expected), f"Row count mismatch: actual={len(actual)}, expected={len(expected)}"

    for col in expected.columns:
        act_series = actual[col]
        exp_series = expected[col]

        if check_dtype:
            assert act_series.dtype == exp_series.dtype, (
                f"Dtype mismatch for column '{col}': " f"actual={act_series.dtype}, expected={exp_series.dtype}"
            )

        if pd.api.types.is_datetime64_any_dtype(exp_series):
            act_ns = act_series.astype("int64")
            exp_ns = exp_series.astype("int64")
            if not np.array_equal(act_ns.values, exp_ns.values):
                diff_mask = act_ns.values != exp_ns.values
                first_idx = int(np.argmax(diff_mask))
                raise AssertionError(
                    f"Datetime column '{col}' differs at row {first_idx}: "
                    f"actual={act_series.iloc[first_idx]}, "
                    f"expected={exp_series.iloc[first_idx]}"
                )

        elif pd.api.types.is_numeric_dtype(exp_series):
            act_vals = act_series.values.astype(float)
            exp_vals = exp_series.values.astype(float)
            nan_match = np.isnan(act_vals) == np.isnan(exp_vals)
            if not nan_match.all():
                first_idx = int(np.argmax(~nan_match))
                raise AssertionError(
                    f"NaN pattern mismatch in column '{col}' at row {first_idx}: "
                    f"actual_nan={np.isnan(act_vals[first_idx])}, "
                    f"expected_nan={np.isnan(exp_vals[first_idx])}"
                )
            finite_mask = ~np.isnan(exp_vals)
            if finite_mask.any():
                if not np.allclose(
                    act_vals[finite_mask],
                    exp_vals[finite_mask],
                    rtol=rtol,
                    atol=atol,
                ):
                    diffs = np.abs(act_vals[finite_mask] - exp_vals[finite_mask])
                    worst_idx = int(np.argmax(diffs))
                    raise AssertionError(
                        f"Numeric column '{col}' differs beyond tolerance "
                        f"(rtol={rtol}, atol={atol}). "
                        f"Worst diff={diffs[worst_idx]:.2e} at finite index {worst_idx}"
                    )

        else:
            mismatches = act_series != exp_series
            if mismatches.any():
                first_idx = int(np.argmax(mismatches.values))
                raise AssertionError(
                    f"String/object column '{col}' differs at row {first_idx}: "
                    f"actual={act_series.iloc[first_idx]!r}, "
                    f"expected={exp_series.iloc[first_idx]!r}"
                )


def assert_json_structure_equal(actual: Any, expected: Any) -> None:
    """Assert that two JSON-serializable structures have the same shape.

    Keys and list lengths are compared recursively; scalar leaf values
    are ignored.

    Args:
        actual: The actual JSON-like object.
        expected: The expected JSON-like object.

    Raises:
        AssertionError: If the structures differ.
    """
    _compare_structure(actual, expected, path="$")


def _compare_structure(actual: Any, expected: Any, path: str) -> None:
    """Recursively compare JSON structure without comparing leaf values.

    Args:
        actual: The actual value at this path.
        expected: The expected value at this path.
        path: Diagnostic JSON-path string.

    Raises:
        AssertionError: On structural mismatch.
    """
    actual_type = _json_type(actual)
    expected_type = _json_type(expected)
    assert actual_type == expected_type, f"Type mismatch at {path}: actual={actual_type}, expected={expected_type}"

    if isinstance(expected, dict):
        assert set(actual.keys()) == set(expected.keys()), (
            f"Key mismatch at {path}: "
            f"missing={set(expected.keys()) - set(actual.keys())}, "
            f"extra={set(actual.keys()) - set(expected.keys())}"
        )
        for key in expected:
            _compare_structure(actual[key], expected[key], f"{path}.{key}")

    elif isinstance(expected, list):
        assert len(actual) == len(expected), (
            f"List length mismatch at {path}: " f"actual={len(actual)}, expected={len(expected)}"
        )
        for i, (a_item, e_item) in enumerate(zip(actual, expected)):
            _compare_structure(a_item, e_item, f"{path}[{i}]")


def _json_type(value: Any) -> str:
    """Return a string label for the JSON type of a value.

    Args:
        value: Any JSON-serializable Python value.

    Returns:
        One of ``"dict"``, ``"list"``, ``"str"``, ``"number"``,
        ``"bool"``, ``"null"``.
    """
    if isinstance(value, dict):
        return "dict"
    if isinstance(value, list):
        return "list"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "str"
    if value is None:
        return "null"
    return type(value).__name__


def assert_schema_matches(data: dict[str, Any] | list[Any], schema_class: type) -> None:
    """Assert that data validates against a Pydantic model.

    If *data* is a list, each element is validated individually.

    Args:
        data: A dictionary or list of dictionaries to validate.
        schema_class: The Pydantic model class to validate against.

    Raises:
        AssertionError: If validation fails for any element.
    """
    if not issubclass(schema_class, BaseModel):
        raise TypeError(f"{schema_class} is not a Pydantic BaseModel subclass")

    items = data if isinstance(data, list) else [data]
    for i, item in enumerate(items):
        try:
            schema_class.model_validate(item)
        except Exception as exc:
            raise AssertionError(f"Schema validation failed for element {i}: {exc}") from exc
