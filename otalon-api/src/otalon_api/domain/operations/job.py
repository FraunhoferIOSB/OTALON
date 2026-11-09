"""Operations job domain models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

JobState = Literal["queued", "running", "cancelling", "completed", "failed", "cancelled", "rejected"]
JobType = Literal["training", "ingest", "backup", "service", "maintenance", "detection_gate_change"]


class OperationsJob(BaseModel):
    """Canonical durable operations job.

    The schema intentionally contains no percentage/progress column ---
    progress is truthful state plus optional phase/step/latest-event.
    """

    id: int
    display_id: str
    type: JobType
    title: str
    state: JobState
    trigger: str
    actor: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
    phase_current: int | None = None
    phase_total: int | None = None
    phase_label: str | None = None
    latest_event: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    log: list[Any] = Field(default_factory=list)
    error: str | None = None
    result: str | None = None
    can_cancel: bool = False
    can_retry: bool = False
    retried_as_id: int | None = None
    idempotency_key: str | None = None

    @field_validator("params", mode="before")
    @classmethod
    def _ensure_dict(cls, value: Any) -> Any:
        if value is None:
            return {}
        return value

    @field_validator("log", mode="before")
    @classmethod
    def _ensure_list(cls, value: Any) -> Any:
        if value is None:
            return []
        return value


class OperationsJobSummary(BaseModel):
    """Compact job row displayed in list views."""

    id: int
    display_id: str
    type: JobType
    title: str
    state: JobState
    trigger: str
    actor: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
    latest_event: str | None = None
    can_cancel: bool = False
    can_retry: bool = False


class OperationsJobCreate(BaseModel):
    """Internal payload for creating a job."""

    type: JobType
    title: str
    trigger: str
    actor: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    can_cancel: bool = False
    can_retry: bool = False
    idempotency_key: str | None = None


class OperationsJobUpdate(BaseModel):
    """Internal payload for advancing a job."""

    state: JobState | None = None
    phase_current: int | None = None
    phase_total: int | None = None
    phase_label: str | None = None
    latest_event: str | None = None
    log_append: list[Any] | Any | None = None
    error: str | None = None
    result: str | None = None
    can_cancel: bool | None = None
    can_retry: bool | None = None
    ended_at: datetime | None = None
