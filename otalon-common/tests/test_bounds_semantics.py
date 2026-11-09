"""Tests for shared bounds correction semantics."""

import pytest
from otalon_common.bounds_semantics import calculate_bounds_correction


def test_expand_widens_only_and_preserves_features() -> None:
    result = calculate_bounds_correction(
        "expand", {"a": 5, "b": 10}, {"a": 50, "b": 100}, {"a": 1}, {"a": 80}
    )
    assert result.lower == {"a": 1, "b": 10}
    assert result.upper == {"a": 80, "b": 100}


def test_strict_expand_rejects_missing_features() -> None:
    with pytest.raises(ValueError, match="missing features: b"):
        calculate_bounds_correction(
            "expand",
            {"a": 1, "b": 2},
            {"a": 3, "b": 4},
            {"a": 0},
            {"a": 5},
            required_features={"a", "b"},
        )


def test_replace_and_create_prior_snapshot() -> None:
    replaced = calculate_bounds_correction(
        "replace", {"a": 1}, {"a": 2}, {"a": 10}, {"a": 20}
    )
    created = calculate_bounds_correction("create", None, None, {"a": 1}, {"a": 2})
    assert replaced.prior_lower == {"a": 1}
    assert replaced.lower == {"a": 10}
    assert created.prior_lower is None
