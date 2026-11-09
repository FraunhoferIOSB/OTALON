"""Builders for synthetic capture files and a fake operations job store.

Shared by the PCAP-import unit tests (UI-078 Wave B, task B13). The pcap
bytes are assembled by hand so a test can control the exact magic and the
exact packet timestamps without shipping a binary fixture.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Any, Iterable

from otalon_api.domain.operations import OperationsJob, OperationsJobUpdate

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def pcap_bytes(timestamps: Iterable[float] = (), payload_size: int = 4) -> bytes:
    """Build a little-endian classic pcap file with the given packet times.

    Args:
        timestamps: POSIX timestamps, one per synthetic packet.
        payload_size: Bytes of filler per packet.

    Returns:
        A structurally valid pcap byte string.
    """
    out = bytearray(PCAP_MAGIC_LE)
    out += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for stamp in timestamps:
        seconds = int(stamp)
        micros = int(round((stamp - seconds) * 1_000_000))
        out += struct.pack("<IIII", seconds, micros, payload_size, payload_size)
        out += b"\x00" * payload_size
    return bytes(out)


def padded_pcap_bytes(total_size: int) -> bytes:
    """Return a valid pcap padded with packets until it exceeds *total_size*."""
    base = pcap_bytes([1_700_000_000.0])
    filler_packet_payload = 1024
    out = bytearray(base)
    while len(out) < total_size:
        out += struct.pack("<IIII", 1_700_000_000, 0, filler_packet_payload, filler_packet_payload)
        out += b"\x00" * filler_packet_payload
    return bytes(out)


def pcapng_bytes(timestamps: Iterable[float] = ()) -> bytes:
    """Build a little-endian pcapng file with the given packet times."""
    out = bytearray()
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out += _ng_block(0x0A0D0D0A, shb_body)
    idb_body = struct.pack("<HHI", 1, 0, 0) + struct.pack("<HHI", 9, 1, 6)[:6] + b"\x00\x00" + struct.pack("<HH", 0, 0)
    out += _ng_block(0x00000001, idb_body)
    for stamp in timestamps:
        micros = int(round(stamp * 1_000_000))
        body = struct.pack("<IIIII", 0, micros >> 32, micros & 0xFFFFFFFF, 4, 4) + b"\x00" * 4
        out += _ng_block(0x00000006, body)
    return bytes(out)


def _ng_block(block_type: int, body: bytes) -> bytes:
    """Wrap *body* in a pcapng block frame with matching length trailers."""
    padded = body + b"\x00" * (-len(body) % 4)
    total = len(padded) + 12
    return struct.pack("<II", block_type, total) + padded + struct.pack("<I", total)


class FakeJobsService:
    """In-memory stand-in for :class:`OperationsJobsService`.

    Implements exactly the surface :class:`~otalon_api.services.pcap_import_service.
    PcapImportService` uses, so a router or service test never opens a
    PostgreSQL connection.
    """

    def __init__(self) -> None:
        """Start with an empty store and a fresh id counter."""
        self.jobs: dict[int, OperationsJob] = {}
        self._next_id = 1

    def seed(self, **overrides: Any) -> OperationsJob:
        """Insert a job row directly, bypassing the create path."""
        job_id = overrides.pop("id", self._next_id)
        self._next_id = max(self._next_id, int(job_id)) + 1
        payload: dict[str, Any] = {
            "id": job_id,
            "display_id": f"J-{job_id}",
            "type": "ingest",
            "title": "PCAP-Import",
            "state": "queued",
            "trigger": "operator",
            "started_at": datetime.now(timezone.utc),
            "params": {"kind": "pcap-import"},
            "can_cancel": True,
        }
        payload.update(overrides)
        job = OperationsJob.model_validate(payload)
        self.jobs[job.id] = job
        return job

    async def record_job(
        self,
        type_: str,
        title: str,
        trigger: str,
        params: dict[str, Any] | None = None,
        actor: str | None = None,
        can_cancel: bool = False,
        can_retry: bool = False,
        idempotency_key: str | None = None,
    ) -> OperationsJob:
        """Create a queued job row."""
        return self.seed(
            type=type_,
            title=title,
            trigger=trigger,
            actor=actor,
            params=params or {},
            can_cancel=can_cancel,
            can_retry=can_retry,
            idempotency_key=idempotency_key,
        )

    async def update_job(
        self,
        job_id: int,
        update: OperationsJobUpdate,
        allowed_from: set[str] | None = None,
    ) -> OperationsJob | None:
        """Apply a guarded partial update, mirroring the repository guard."""
        job = self.jobs.get(job_id)
        if job is None:
            return None
        allowed = allowed_from or {"queued", "running", "cancelling"}
        if job.state not in allowed:
            return None
        data = update.model_dump(exclude_unset=True, exclude_none=True)
        log_append = data.pop("log_append", None)
        updated = job.model_copy(update=data)
        if log_append is not None:
            entries = log_append if isinstance(log_append, list) else [log_append]
            updated = updated.model_copy(update={"log": [*updated.log, *entries]})
        self.jobs[job_id] = updated
        return updated

    async def get_job(self, job_id: int) -> OperationsJob | None:
        """Return one job by internal id."""
        return self.jobs.get(job_id)

    async def get_job_by_display_id(self, display_id: str) -> OperationsJob | None:
        """Return one job by public display id."""
        return next((j for j in self.jobs.values() if j.display_id == display_id), None)

    async def list_jobs(self, state: str | None = None, type_: str | None = None, **_: Any) -> list[OperationsJob]:
        """Return jobs matching the optional state/type filters."""
        return [
            job
            for job in self.jobs.values()
            if (state is None or job.state == state) and (type_ is None or job.type == type_)
        ]

    async def complete_job(self, job_id: int, result: str | None = None, **_: Any) -> OperationsJob | None:
        """Drive a running job to terminal ``completed``."""
        return await self._terminal(job_id, "completed", {"running"}, {"result": result})

    async def fail_job(self, job_id: int, error: str | None = None) -> OperationsJob | None:
        """Drive a non-terminal job to terminal ``failed``."""
        return await self._terminal(job_id, "failed", {"queued", "running", "cancelling"}, {"error": error})

    async def cancel_job(self, job_id: int, stops_immediately: bool | None = None, **_: Any) -> OperationsJob | None:
        """Cancel a cancellable job."""
        state = "cancelled" if stops_immediately is not False else "cancelling"
        return await self._terminal(job_id, state, {"queued", "running", "cancelling"}, {})

    async def _terminal(
        self,
        job_id: int,
        state: str,
        allowed: set[str],
        extra: dict[str, Any],
    ) -> OperationsJob | None:
        """Apply a guarded terminal transition."""
        job = self.jobs.get(job_id)
        if job is None or job.state not in allowed:
            return None
        payload: dict[str, Any] = {"state": state, "ended_at": datetime.now(timezone.utc)}
        payload.update({k: v for k, v in extra.items() if v is not None})
        updated = job.model_copy(update=payload)
        self.jobs[job_id] = updated
        return updated
