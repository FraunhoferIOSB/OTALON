"""Tests for canonical multi-interval training input."""

import pytest

from otalon_api.domain.time.intervals import normalize_intervals
from otalon_api.services.runtime_retrain_service import RuntimeRetrainValidationError


def test_normalize_intervals_merges_sorted_berlin_ranges_to_utc() -> None:
    """Overlap and adjacency produce one deterministic union."""
    result = normalize_intervals(
        [
            ("2026-07-06 18:00:00", "2026-07-06 19:00:00"),
            ("2026-07-06 16:00:00", "2026-07-06 17:00:00"),
            ("2026-07-06 17:00:00", "2026-07-06 18:30:00"),
        ]
    )
    assert result == [("2026-07-06T14:00:00+00:00", "2026-07-06T17:00:00+00:00")]


def test_normalize_intervals_preserves_disjoint_union() -> None:
    """Disjoint windows remain separate and ordered."""
    assert normalize_intervals(
        [
            ("2026-01-01 12:00:00", "2026-01-01 13:00:00"),
            ("2026-01-01 10:00:00", "2026-01-01 11:00:00"),
        ]
    ) == [
        ("2026-01-01T09:00:00+00:00", "2026-01-01T10:00:00+00:00"),
        ("2026-01-01T11:00:00+00:00", "2026-01-01T12:00:00+00:00"),
    ]


def test_normalize_intervals_supports_legacy_pair() -> None:
    """The old single-window request maps to canonical intervals."""
    assert normalize_intervals(window_start="2026-01-01 10:00:00", window_stop="2026-01-01 11:00:00")


def test_normalize_intervals_rejects_partial_legacy_pair() -> None:
    """Partial legacy input fails closed."""
    with pytest.raises(RuntimeRetrainValidationError):
        normalize_intervals(window_start="2026-01-01 10:00:00")


@pytest.mark.parametrize("value", ["2026-03-29 02:30:00", "2026-10-25 02:30:00"])
def test_normalize_intervals_rejects_dst_nonexistent_or_ambiguous_wall_time(value: str) -> None:
    """DST gaps and folds require an explicit offset instead of guessing."""
    with pytest.raises(RuntimeRetrainValidationError):
        normalize_intervals(window_start=value, window_stop="2026-12-01 03:30:00")


def test_normalize_intervals_accepts_browser_minute_precision_to_utc() -> None:
    """Browser ``datetime-local`` (YYYY-MM-DDTHH:MM, no seconds) normalizes.

    Chrome/Firefox emit minute precision from ``<input type="datetime-local">``.
    The canonical interval must still resolve to an aware UTC interval with the
    same Europe/Berlin -> UTC offset the second-bearing form produces.
    """
    result = normalize_intervals([("2026-07-06T16:00", "2026-07-06T19:00")])
    assert result == [("2026-07-06T14:00:00+00:00", "2026-07-06T17:00:00+00:00")]
