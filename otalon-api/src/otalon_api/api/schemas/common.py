"""Common / shared API schemas.

Reusable Pydantic v2 models for cross-cutting concerns: error responses,
pagination query parameters, time-range query parameters, and the
readiness-probe response envelope.

These models are deliberately small and free of router-specific fields.
Endpoint-specific request/response models continue to live in their
respective domain modules (``anomalies.py``, ``timeseries.py``, ...).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ErrorResponse(BaseModel):
    """Uniform error envelope for non-2xx HTTP responses.

    Mirrors the shape FastAPI uses for ``HTTPException`` payloads
    (``{"detail": ...}``) but adds optional structured fields so
    endpoints can attach machine-readable error codes and a free-form
    context dictionary.

    Example::

        {"detail": "Database query timed out", "code": "db_timeout"}
    """

    detail: str = Field(description="Human-readable error message.")
    code: str | None = Field(
        default=None,
        description="Optional machine-readable error code (e.g. 'db_timeout').",
    )
    context: dict[str, Any] | None = Field(
        default=None,
        description="Optional structured context with additional diagnostic data.",
    )


class PaginationParams(BaseModel):
    """Common ``limit`` / ``offset`` pagination query parameters.

    Endpoints that accept these can declare a single
    ``params: PaginationParams = Depends()`` rather than two separate
    ``Query(...)`` parameters. Validation keeps ``limit`` in
    ``[1, 1000]`` and ``offset`` non-negative.
    """

    limit: int = Field(default=100, ge=1, le=1000, description="Maximum number of items to return.")
    offset: int = Field(default=0, ge=0, description="Number of items to skip before returning results.")


class TimeRangeParams(BaseModel):
    """Common ``start`` / ``stop`` time-range query parameters.

    Both bounds are optional so endpoints can mark either side open.
    When both are provided, ``start`` must be strictly before ``stop``.
    """

    start: datetime | None = Field(default=None, description="Inclusive start of the time range.")
    stop: datetime | None = Field(default=None, description="Exclusive end of the time range.")

    @model_validator(mode="after")
    def _validate_order(self) -> TimeRangeParams:
        """Reject ranges where ``start`` is not before ``stop``.

        Returns:
            The validated instance.

        Raises:
            ValueError: If both bounds are set and ``start >= stop``.
        """
        if self.start is not None and self.stop is not None and self.start >= self.stop:
            raise ValueError("start must be strictly before stop")
        return self


class ComponentStatus(BaseModel):
    """Health/readiness status of a single dependent component.

    Used as a building block in :class:`ReadinessResponse`. Mirrors
    the per-service shape produced by ``HealthService`` but is kept
    intentionally minimal — only what is needed for readiness probes.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Component name, e.g. 'postgres' or 'influxdb'.")
    ready: bool = Field(description="Whether the component is reachable and ready.")
    detail: str = Field(
        default="",
        description="Optional diagnostic detail (latency, error message).",
    )


class ReadinessResponse(BaseModel):
    """Response envelope for the ``/readyz`` readiness probe.

    Returned with HTTP 200 when all components are ready and HTTP 503
    when at least one component is not ready. The same shape is used
    in both cases so clients can render structured diagnostics
    regardless of overall status.
    """

    status: str = Field(description="Overall readiness: 'ready' or 'not_ready'.")
    components: list[ComponentStatus] = Field(
        default_factory=list,
        description="Per-component readiness details.",
    )
