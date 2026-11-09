"""Schemas for generic runtime configuration and passive-seeder status."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RuntimeConfigItem(BaseModel):
    """Manifest metadata and current value for one runtime key."""

    service: str
    key: str
    value: str
    value_prev: str | None = None
    updated_at: datetime | None = None
    updated_by: str | None = None
    type: str
    domain: str | None = None
    description: str


class RuntimeConfigResponse(BaseModel):
    """Runtime configuration collection."""

    items: list[RuntimeConfigItem]


class RuntimeConfigWrite(BaseModel):
    """One validated runtime configuration update."""

    service: str
    key: str
    value: str
    reason: str = Field(default="", max_length=500)


class RuntimeConfigApplyResponse(RuntimeConfigResponse):
    """Updated collection and live-configuration change metadata."""

    changed_keys: list[str]
    restart_required: bool


class RuntimeConfigJobRequest(BaseModel):
    """Batch of runtime writes executed as one operations job."""

    updates: list[RuntimeConfigWrite] = Field(min_length=1, max_length=3)


class PassiveSeederStatusResponse(BaseModel):
    """Persisted passive-seeder operational state."""

    service: str
    state: str
    last_cycle_at: datetime | None = None
    last_error: str | None = None
    rows_seeded: int = 0
    poll_interval_s: int | None = None
    updated_at: datetime | None = None
