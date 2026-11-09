"""Unit tests for the group-classifier stale-training-window guard (CLAS-031).

The alarm-group classifier keeps a manual batch training path whose window
is pinned in ``config.json`` (``group_classifier.training.window_start`` /
``window_stop``). CLAS-031 accepted that path instead of building an API
retrain endpoint, on the condition that a stale window can no longer be
silent: training against a window that is months old must announce itself.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

import pytest
from loguru import logger

from otalon_clas.main import (
    GROUP_CLASSIFIER_STALE_WINDOW_DAYS,
    warn_on_stale_training_window,
)


@pytest.fixture()
def warn_records(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    """Route loguru WARNING records into ``caplog``."""
    handler_id = logger.add(caplog.handler, format="{message}", level="WARNING")
    yield caplog
    logger.remove(handler_id)


def _window(age_days: float) -> tuple[datetime, datetime]:
    """Build a one-hour window whose stop lies ``age_days`` in the past."""
    now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    stop = now - timedelta(days=age_days)
    return stop - timedelta(hours=1), stop


class TestWarnOnStaleTrainingWindow:
    """Behaviour of :func:`warn_on_stale_training_window`."""

    def test_stale_window_warns_with_age(self, warn_records: pytest.LogCaptureFixture) -> None:
        """A window older than the threshold logs a WARNING naming its age."""
        now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        start, stop = _window(age_days=136)

        is_stale = warn_on_stale_training_window(start, stop, now=now)

        assert is_stale is True
        messages = [record.getMessage() for record in warn_records.records]
        assert any("stale training window" in message for message in messages)
        assert any("136 days old" in message for message in messages)

    def test_fresh_window_is_silent(self, warn_records: pytest.LogCaptureFixture) -> None:
        """A recent window produces no WARNING."""
        now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        start, stop = _window(age_days=1)

        is_stale = warn_on_stale_training_window(start, stop, now=now)

        assert is_stale is False
        assert warn_records.records == []

    def test_threshold_boundary_is_not_stale(self, warn_records: pytest.LogCaptureFixture) -> None:
        """A window exactly at the threshold age is still accepted silently."""
        now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        start, stop = _window(age_days=GROUP_CLASSIFIER_STALE_WINDOW_DAYS)

        assert warn_on_stale_training_window(start, stop, now=now) is False
        assert warn_records.records == []

    def test_naive_window_is_treated_as_utc(self, warn_records: pytest.LogCaptureFixture) -> None:
        """Naive timestamps do not raise and are compared as UTC."""
        now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        start = datetime(2026, 4, 18, 22, 0)
        stop = datetime(2026, 4, 19, 17, 0)

        assert warn_on_stale_training_window(start, stop, now=now) is True
        assert any("stale training window" in r.getMessage() for r in warn_records.records)

    def test_warning_names_the_configured_window(self, warn_records: pytest.LogCaptureFixture) -> None:
        """The WARNING quotes the window bounds so the operator can act."""
        now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        start = datetime(2026, 4, 18, 22, 0, tzinfo=timezone.utc)
        stop = datetime(2026, 4, 19, 17, 0, tzinfo=timezone.utc)

        warn_on_stale_training_window(start, stop, now=now)

        joined = " ".join(record.getMessage() for record in warn_records.records)
        assert "2026-04-18T22:00:00+00:00" in joined
        assert "2026-04-19T17:00:00+00:00" in joined

    def test_default_now_does_not_raise(self) -> None:
        """Omitting ``now`` uses the current UTC time."""
        start = datetime(2026, 4, 18, 22, 0, tzinfo=timezone.utc)
        stop = datetime(2026, 4, 19, 17, 0, tzinfo=timezone.utc)

        assert isinstance(warn_on_stale_training_window(start, stop), bool)
