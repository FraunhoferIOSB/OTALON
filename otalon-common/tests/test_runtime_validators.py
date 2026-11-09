"""Unit tests for the shared runtime-configuration validator factories.

The raised messages are a cross-subproject contract: otalon-clas repository
tests match on the substrings ``boolean literal``, ``float``, and
``in (0, 0.5]``.
"""

from __future__ import annotations

import pytest

from otalon_common.runtime import bool_literal, float_interval, int_range


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    ["true", "false", "1", "0", "yes", "no", "on", "off", "TRUE", " True ", "Off"],
)
def test_bool_literal_accepts_recognized_literals(value: str) -> None:
    """Recognized boolean literals pass regardless of case and padding."""
    bool_literal()(value)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["sometimes", "", "2", "truthy", "ja", "None"])
def test_bool_literal_rejects_other_values(value: str) -> None:
    """Unrecognized values are rejected naming a boolean literal."""
    with pytest.raises(ValueError, match="boolean literal"):
        bool_literal()(value)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["10", "3600", "120", " 300 "])
def test_int_range_accepts_values_inside_inclusive_bounds(value: str) -> None:
    """Both boundaries of an integer range are inclusive."""
    int_range(10, 3600)(value)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["9", "3601", "0", "-1"])
def test_int_range_rejects_values_outside_bounds(value: str) -> None:
    """Values beyond either boundary are rejected naming the interval."""
    with pytest.raises(ValueError, match=r"in \[10, 3600\]"):
        int_range(10, 3600)(value)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["not-a-number", "", "12.5", "1e3"])
def test_int_range_rejects_non_integer_values(value: str) -> None:
    """Non-integer input is rejected naming the expected type."""
    with pytest.raises(ValueError, match="integer"):
        int_range(10, 3600)(value)


@pytest.mark.unit
def test_int_range_exposes_its_domain_notation() -> None:
    """The validator publishes the domain string used by the manifest."""
    assert int_range(30, 86400).domain == "[30, 86400]"


@pytest.mark.unit
def test_int_range_rejects_an_inverted_range() -> None:
    """Constructing a range with ``lo > hi`` fails immediately."""
    with pytest.raises(ValueError, match="lo <= hi"):
        int_range(100, 10)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["0.0001", "0.1", "0.5", "0.49999"])
def test_float_interval_accepts_quantile_values(value: str) -> None:
    """Values inside ``(0, 0.5]`` pass, including the inclusive upper bound."""
    float_interval(0.0, 0.5, inclusive_hi=True)(value)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["0", "0.0", "-0.1", "0.51", "0.9", "1"])
def test_float_interval_rejects_values_outside_the_quantile_domain(value: str) -> None:
    """Zero, negatives, and anything above the upper bound are rejected."""
    with pytest.raises(ValueError, match=r"in \(0, 0.5\]"):
        float_interval(0.0, 0.5, inclusive_hi=True)(value)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["not-a-number", "", "abc"])
def test_float_interval_rejects_unparsable_values(value: str) -> None:
    """Unparsable input is rejected naming the expected type."""
    with pytest.raises(ValueError, match="float"):
        float_interval(0.0, 0.5, inclusive_hi=True)(value)


@pytest.mark.unit
def test_float_interval_upper_bound_can_be_exclusive() -> None:
    """With ``inclusive_hi=False`` the upper bound itself is rejected."""
    validator = float_interval(0.0, 1.0, inclusive_hi=False)
    validator("0.999")
    with pytest.raises(ValueError, match=r"in \(0, 1\)"):
        validator("1.0")


@pytest.mark.unit
def test_float_interval_exposes_its_domain_notation() -> None:
    """The validator publishes the domain string used by the manifest."""
    assert float_interval(0.0, 0.5, inclusive_hi=True).domain == "(0, 0.5]"
    assert float_interval(0.0, 1.0, inclusive_hi=False).domain == "(0, 1)"


@pytest.mark.unit
def test_float_interval_rejects_an_inverted_interval() -> None:
    """Constructing an interval with ``lo >= hi`` fails immediately."""
    with pytest.raises(ValueError, match="lo < hi"):
        float_interval(0.5, 0.5)


@pytest.mark.unit
def test_validators_compare_equal_for_identical_parameters() -> None:
    """Equal parameters yield equal validators, keeping registration idempotent."""
    assert bool_literal() == bool_literal()
    assert int_range(10, 3600) == int_range(10, 3600)
    assert float_interval(0.0, 0.5) == float_interval(0.0, 0.5)
    assert int_range(10, 3600) != int_range(10, 60)
