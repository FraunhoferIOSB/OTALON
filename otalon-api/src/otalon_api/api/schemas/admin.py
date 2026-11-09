"""Admin API schemas for Docker, Compose, ENV, and Health endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ContainerInfoResponse(BaseModel):
    """Status information for a single Docker container."""

    name: str
    status: str
    image: str
    created: str
    ports: dict[str, Any] = {}
    health: str = ""


class ContainerListResponse(BaseModel):
    """Response containing a list of container statuses."""

    containers: list[ContainerInfoResponse]


class ContainerLogsResponse(BaseModel):
    """Response containing container log output."""

    name: str
    lines: int
    logs: str


class ComposeActionResponse(BaseModel):
    """Response for a Docker Compose action."""

    service: str
    action: str
    exit_code: int
    output: str
    success: bool


class EnvResponse(BaseModel):
    """Response containing masked environment variables."""

    env: dict[str, str]
    editable_keys: list[str]


class EnvUpdateRequest(BaseModel):
    """Request to update environment variables."""

    updates: dict[str, str]


class EnvUpdateResponse(BaseModel):
    """Response after updating environment variables."""

    env: dict[str, str]
    changed_keys: list[str]
    backup_path: str | None = None


class DbTruncateResponse(BaseModel):
    """Response for a database truncate operation."""

    table: str
    success: bool
    message: str


class HealthCheckItem(BaseModel):
    """Health status of a single service."""

    name: str
    running: bool
    detail: str
    timestamp: float
    classification: str = Field(
        default="core",
        description="Service classification: 'core' or 'optional'.",
    )
    status: str = Field(
        default="healthy",
        description=(
            "Explicit service status distinct from a mere running flag: "
            "'healthy' (reachable), 'failed' (core service unreachable), "
            "'not-configured' (optional service that is not configured / not "
            "reachable and does not count as a failure), or 'disabled'. "
            "Consumers SHOULD render 'not-configured'/'disabled' differently "
            "from 'failed'."
        ),
    )
    latency_ms: float | None = None
    latency_budget_ms: float | None = None


class HealthResponse(BaseModel):
    """Response containing health check results for all services.

    The ``caches`` field is optional and only populated when the
    backend wires a :class:`CacheManager` into its DI chain. Each entry
    is the result of :meth:`CacheManager.stats_snapshot` for one cache
    namespace.
    """

    services: list[HealthCheckItem]
    overall_status: str = Field(description="Overall system health: healthy, degraded, or unhealthy")
    caches: dict[str, dict[str, Any]] | None = Field(
        default=None,
        description="Per-cache statistics (hits, misses, hit_ratio, size, maxsize, ttl).",
    )
    active_incidents: list[dict[str, Any]] = Field(default_factory=list)
    recent_incidents: list[dict[str, Any]] = Field(default_factory=list)
    unacknowledged_incidents: list[dict[str, Any]] = Field(default_factory=list)
