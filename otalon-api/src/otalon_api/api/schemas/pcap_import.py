"""Request/response schemas for the PCAP import surface (UI-078, Wave B)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from otalon_api.domain.operations import JobState


class PcapImportAccepted(BaseModel):
    """Envelope returned when an upload has been accepted and enqueued."""

    display_id: str = Field(description="Public job identifier used for status polling")
    job_id: int = Field(description="Internal operations_jobs row id")
    state: JobState = Field(description="Lifecycle state right after creation")
    filename: str = Field(description="Server-generated storage filename")
    original_filename: str | None = Field(default=None, description="Caller-declared name, metadata only")
    size_bytes: int = Field(description="Number of bytes actually stored")
    sha256: str = Field(description="Digest of the stored file; doubles as the idempotency key")
    time_start: datetime | None = Field(default=None, description="First packet timestamp")
    time_end: datetime | None = Field(default=None, description="Last packet timestamp")
    forced: bool = Field(default=False, description="Whether the overlap check was explicitly overridden")
    delivered: bool = Field(default=False, description="Whether the worker accepted the job immediately")


class PcapImportConflict(BaseModel):
    """Body of the ``409`` emitted when the capture overlaps existing data."""

    message: str
    conflict_start: datetime
    conflict_end: datetime
    measurement: str


class PcapImportResult(BaseModel):
    """Outcome payload surfaced once an import has completed."""

    records_processed: int | None = None
    points_written: int | None = None
    time_start: datetime | None = None
    time_end: datetime | None = None


class PcapImportStatus(BaseModel):
    """Progress and outcome of a single import job."""

    display_id: str
    job_id: int
    state: JobState
    phase_current: int | None = None
    phase_total: int | None = None
    phase_label: str | None = None
    latest_event: str | None = None
    original_filename: str | None = None
    size_bytes: int | None = None
    time_start: datetime | None = None
    time_end: datetime | None = None
    forced: bool = False
    started_at: datetime | None = None
    ended_at: datetime | None = None
    error: str | None = None
    result: PcapImportResult | None = None


class PcapImportList(BaseModel):
    """Newest-first listing of import jobs for the "Recent Imports" surface.

    Carries the very same :class:`PcapImportStatus` envelope the detail
    endpoint returns, so a consumer needs exactly one shape for both
    surfaces.
    """

    items: list[PcapImportStatus]
    total: int = Field(description="Number of entries in ``items`` (post-filter, post-limit)")


class PcapImportReport(BaseModel):
    """Partial progress/outcome report pushed by the import worker.

    Every field is optional on purpose: the worker omits what it has no
    information about (``exclude_none``), so an absent field means "no
    change", never "set to null".
    """

    state: Literal["running", "completed", "failed", "cancelled"] | None = None
    phase_current: int | None = None
    phase_total: int | None = None
    phase_label: str | None = None
    latest_event: str | None = None
    error: str | None = None
    result: dict[str, Any] | None = None


class PcapImportReportAck(BaseModel):
    """Acknowledgement returned to the worker after a report was applied."""

    display_id: str
    state: JobState
    applied: bool
