"""Tests for canonical anomaly type constants and classification helpers."""

from otalon_common.types.anomaly_types import (BENIGN_TYPES, AnomalyType,
                                                    is_benign_type, is_ml_type)


class TestAnomalyTypeConstants:
    """Tests for AnomalyType constant values."""

    def test_bound_violation_matches_db(self) -> None:
        assert AnomalyType.BOUND_VIOLATION == "BoundViolation"

    def test_no_bounds_matches_db(self) -> None:
        assert AnomalyType.NO_BOUNDS == "NoBounds"


class TestBenignTypes:
    """Tests for BENIGN_TYPES frozenset."""

    def test_contains_correct_values(self) -> None:
        assert BENIGN_TYPES == frozenset({"BoundViolation", "NoBounds"})

    def test_is_frozenset(self) -> None:
        assert isinstance(BENIGN_TYPES, frozenset)

    def test_immutable(self) -> None:
        assert not hasattr(BENIGN_TYPES, "add")


class TestIsBenignType:
    """Tests for is_benign_type()."""

    def test_bound_violation_is_benign(self) -> None:
        assert is_benign_type("BoundViolation") is True

    def test_no_bounds_is_benign(self) -> None:
        assert is_benign_type("NoBounds") is True

    def test_reconnaissance_not_benign(self) -> None:
        assert is_benign_type("Reconnaissance") is False

    def test_empty_string_not_benign(self) -> None:
        assert is_benign_type("") is False


class TestIsMlType:
    """Tests for is_ml_type()."""

    def test_reconnaissance_is_ml(self) -> None:
        assert is_ml_type("Reconnaissance") is True

    def test_bound_violation_not_ml(self) -> None:
        assert is_ml_type("BoundViolation") is False

    def test_no_bounds_not_ml(self) -> None:
        assert is_ml_type("NoBounds") is False
