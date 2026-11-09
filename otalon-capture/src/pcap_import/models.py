"""Request, response and progress models of the PCAP import worker.

These models are the wire contract between the job owner (otalon-api) and
the worker. State names follow the ``operations_jobs`` CHECK constraint —
``completed``, not ``succeeded``.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator

FILE_PATH_MAX_LENGTH = 4096
"""Upper bound for ``file_path``, matching Linux ``PATH_MAX``.

The field carried ``min_length=1`` and no ceiling at all, so an arbitrarily
long string was accepted at the model layer and only failed deep in the
runner (audit V3).
"""


class ImportPhase(str, Enum):
    """Coarse phases an import moves through, reported to the job owner."""

    ACCEPTED = "accepted"
    VALIDATING = "validating"
    READING = "reading"
    WRITING = "writing"
    FINISHED = "finished"


class ImportState(str, Enum):
    """Worker-side job states, aligned with the operations job store."""

    IDLE = "idle"
    RUNNING = "running"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATES = frozenset(
    {
        ImportState.COMPLETED,
        ImportState.FAILED,
        ImportState.CANCELLED,
    }
)

PHASE_TOTAL = 3

PHASE_ORDINALS: Dict[ImportPhase, int] = {
    ImportPhase.ACCEPTED: 0,
    ImportPhase.VALIDATING: 1,
    ImportPhase.READING: 2,
    ImportPhase.WRITING: 3,
    ImportPhase.FINISHED: 3,
}

PHASE_LABELS: Dict[ImportPhase, str] = {
    ImportPhase.ACCEPTED: "Auftrag angenommen",
    ImportPhase.VALIDATING: "Datei validiert",
    ImportPhase.READING: "Netcap++ liest",
    ImportPhase.WRITING: "Influx-Write",
    ImportPhase.FINISHED: "Abgeschlossen",
}


class ImportRequest(BaseModel):
    """An import job pushed to the worker by its owner.

    Attributes:
        display_id: Identifier of the owning job record; used as the path
            segment when reporting progress back.
        file_path: Absolute path of the capture file inside the shared import
            volume. The worker reads it; it never constructs it from user input.
        time_start: Start of the capture's time range as determined by the owner.
        time_end: End of the capture's time range as determined by the owner.
        original_filename: Client-supplied name, carried for diagnostics only.
        force: Whether the owner overrode its overlap check for this job.
    """

    display_id: str = Field(min_length=1, max_length=128)
    file_path: str = Field(min_length=1, max_length=FILE_PATH_MAX_LENGTH)
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None
    original_filename: Optional[str] = None
    force: bool = False

    @field_validator("file_path")
    @classmethod
    def _validate_file_path_shape(cls, value: str) -> str:
        """Reject values that cannot be a capture path inside the volume.

        This is defence in depth only. The real security boundary stays
        :func:`pcap_import.runner.resolve_capture_path`, which resolves the
        path against the import root and refuses anything that escapes it.
        What is added here is the declarative layer that was missing: an
        obviously malformed value is answered with a 422 naming the problem
        instead of failing late inside the runner (audit V3).

        Args:
            value: The path as supplied by the job owner.

        Returns:
            The unchanged value when its shape is usable.

        Raises:
            ValueError: When the value is not an absolute POSIX path, or
                carries a NUL byte, an empty segment or a ``.``/``..``
                segment.
        """

        if "\x00" in value:
            raise ValueError("file_path must not contain a NUL byte")
        if not value.startswith("/"):
            raise ValueError("file_path must be an absolute path")
        segments = value.split("/")[1:]
        if any(segment == "" for segment in segments[:-1]) or segments[-1] == "":
            raise ValueError("file_path must not contain an empty path segment")
        if any(segment in {".", ".."} for segment in segments):
            raise ValueError("file_path must not contain '.' or '..' segments")
        return value


class ImportAccepted(BaseModel):
    """Acknowledgement returned when a job is taken for processing."""

    display_id: str
    state: ImportState = ImportState.RUNNING
    accepted_at: datetime


class ImportStatus(BaseModel):
    """Current worker status, also returned by the health endpoint."""

    state: ImportState
    display_id: Optional[str] = None
    phase: Optional[ImportPhase] = None
    phase_current: Optional[int] = None
    phase_total: int = PHASE_TOTAL
    latest_event: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    """Health payload analogous to the recorder's ``GET /health``."""

    status: str
    busy: bool
    state: ImportState
    display_id: Optional[str] = None


class JobUpdate(BaseModel):
    """Payload sent to ``PATCH {job_path_template}`` on the job owner.

    Only fields that carry information are serialised, so a progress ping does
    not overwrite the owner's record with nulls.
    """

    state: Optional[ImportState] = None
    phase_current: Optional[int] = None
    phase_total: Optional[int] = None
    phase_label: Optional[str] = None
    latest_event: Optional[str] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
