"""Unit tests for ``otalon_api.api.schemas.common`` shared models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from otalon_api.api.schemas.common import (
    ComponentStatus,
    ErrorResponse,
    PaginationParams,
    ReadinessResponse,
    TimeRangeParams,
)


class TestErrorResponse:
    """Validate :class:`ErrorResponse` accepts plain and structured forms."""

    @pytest.mark.unit
    def test_minimal(self) -> None:
        """``detail`` is the only required field."""
        err = ErrorResponse(detail="boom")
        assert err.detail == "boom"
        assert err.code is None
        assert err.context is None

    @pytest.mark.unit
    def test_full(self) -> None:
        """Optional ``code`` and ``context`` are preserved verbatim."""
        err = ErrorResponse(detail="boom", code="db_timeout", context={"latency_ms": 1200})
        assert err.code == "db_timeout"
        assert err.context == {"latency_ms": 1200}

    @pytest.mark.unit
    def test_detail_required(self) -> None:
        """Missing ``detail`` raises a validation error."""
        with pytest.raises(ValidationError):
            ErrorResponse()  # type: ignore[call-arg]


class TestPaginationParams:
    """Validate :class:`PaginationParams` defaults and bounds."""

    @pytest.mark.unit
    def test_defaults(self) -> None:
        """Defaults: ``limit=100``, ``offset=0``."""
        p = PaginationParams()
        assert p.limit == 100
        assert p.offset == 0

    @pytest.mark.unit
    @pytest.mark.parametrize("limit", [0, -1, 1001])
    def test_limit_out_of_range(self, limit: int) -> None:
        """``limit`` outside [1, 1000] is rejected."""
        with pytest.raises(ValidationError):
            PaginationParams(limit=limit)

    @pytest.mark.unit
    def test_offset_negative(self) -> None:
        """Negative ``offset`` is rejected."""
        with pytest.raises(ValidationError):
            PaginationParams(offset=-1)


class TestTimeRangeParams:
    """Validate :class:`TimeRangeParams` ordering and optionality."""

    @pytest.mark.unit
    def test_both_none(self) -> None:
        """Both bounds optional."""
        tr = TimeRangeParams()
        assert tr.start is None
        assert tr.stop is None

    @pytest.mark.unit
    def test_valid_order(self) -> None:
        """``start`` strictly before ``stop`` is accepted."""
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        stop = datetime(2026, 1, 2, tzinfo=timezone.utc)
        tr = TimeRangeParams(start=start, stop=stop)
        assert tr.start == start
        assert tr.stop == stop

    @pytest.mark.unit
    def test_start_equals_stop_rejected(self) -> None:
        """``start == stop`` is rejected (range must be non-empty)."""
        t = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(ValidationError):
            TimeRangeParams(start=t, stop=t)

    @pytest.mark.unit
    def test_start_after_stop_rejected(self) -> None:
        """``start > stop`` is rejected."""
        start = datetime(2026, 1, 2, tzinfo=timezone.utc)
        stop = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(ValidationError):
            TimeRangeParams(start=start, stop=stop)

    @pytest.mark.unit
    def test_one_sided_open(self) -> None:
        """A range with only one side bound is accepted."""
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        tr = TimeRangeParams(start=start)
        assert tr.start == start
        assert tr.stop is None


class TestReadinessResponse:
    """Validate :class:`ReadinessResponse` envelope."""

    @pytest.mark.unit
    def test_round_trip(self) -> None:
        """Round-trip serialization preserves nested ComponentStatus values."""
        body = ReadinessResponse(
            status="ready",
            components=[
                ComponentStatus(name="postgres", ready=True, detail="ok in 4 ms"),
                ComponentStatus(name="influxdb", ready=True, detail="ok in 11 ms"),
            ],
        )
        as_json = body.model_dump()
        restored = ReadinessResponse.model_validate(as_json)
        assert restored == body

    @pytest.mark.unit
    def test_component_default_detail(self) -> None:
        """``ComponentStatus.detail`` defaults to empty string."""
        c = ComponentStatus(name="x", ready=False)
        assert c.detail == ""
