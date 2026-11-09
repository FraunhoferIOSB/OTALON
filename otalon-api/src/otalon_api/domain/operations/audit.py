"""Operations Change Audit domain models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

AuditCategory = Literal["config", "bounds", "reset", "service", "job", "access"]


class OperationsAuditEntry(BaseModel):
    """Immutable Change Audit entry.

    Provenance columns ``source``/``source_id`` make imports from other
    audit origins idempotent through ``UNIQUE (source, source_id)``.
    """

    id: int
    at: datetime
    category: AuditCategory
    actor: str
    action: str
    target: str
    reason: str | None = None
    detail: str | None = None
    source: str = "operations"
    source_id: str | None = None


class OperationsAuditAppend(BaseModel):
    """Internal payload for appending an audit row."""

    category: AuditCategory
    actor: str
    action: str
    target: str
    reason: str | None = None
    detail: str | None = None


class OperationsAuditImport(BaseModel):
    """Internal payload for idempotent backfill/adapter imports."""

    source: str
    source_id: str | None
    at: datetime | None = None
    category: AuditCategory
    actor: str
    action: str
    target: str
    reason: str | None = None
    detail: str | None = None

    model_config = {"extra": "forbid"}


class AuditQueryFilters(BaseModel):
    """Filters for the Change Audit read API.

    ``actor`` and ``q`` are bounded because both reach a double-wildcard
    ``ILIKE`` in :meth:`OperationsAuditRepository.query`, where an
    unbounded pattern is a cheap per-request CPU amplifier (QUA-12). The
    router applies the same caps; this model is the backstop for any
    non-HTTP caller.
    """

    category: AuditCategory | None = None
    actor: str | None = Field(default=None, max_length=120)
    since: datetime | None = None
    q: str | None = Field(default=None, max_length=200, description="Free-text search over action/target")
