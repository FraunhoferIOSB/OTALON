"""Pydantic wire models for the vulnerability/CVE endpoints (SCAN-033 extraction).

Moved verbatim out of :mod:`otalon_scan.api.server`; shapes unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ...repositories.models import VulnStatus

__all__ = [
    "CveLookupItem",
    "CveLookupsListResponse",
    "StopLookupResponse",
    "VulnerabilityItem",
    "VulnerabilityLookupRequest",
    "VulnerabilityLookupResponse",
    "VulnerabilityPatchRequest",
]


class StopLookupResponse(BaseModel):
    """Response for a stop-requested CVE lookup (R-02).

    ``stopped`` is ``True`` when a live lookup task was flagged for
    cooperative cancellation, ``False`` when the job was unknown or had
    already reached a terminal state (nothing to cancel).
    """

    job_id: str
    stopped: bool


class VulnerabilityPatchRequest(BaseModel):
    """Mutable triage fields for ``PATCH /vulnerabilities/{vuln_id}`` (B-E1).

    All fields are optional; only the supplied ones are written. ``status``
    is validated against :class:`~otalon_scan.repositories.models.VulnStatus`
    (``active`` / ``mitigated`` / ``false_positive`` / ``resolved``).
    """

    status: Optional[VulnStatus] = None
    severity: Optional[str] = None
    summary: Optional[str] = None
    status_changed_by: Optional[str] = None


class VulnerabilityItem(BaseModel):
    """Updated vulnerability row returned by ``PATCH /vulnerabilities/{id}``.

    Flat projection of
    :class:`~otalon_scan.repositories.models.VulnerabilityObservation` with
    ISO-8601 timestamps and the enum value rendered as its string.
    """

    id: int
    scan_id: str
    device_id: Optional[int] = None
    interface_id: Optional[int] = None
    source_module: Optional[str] = None
    vuln_id: Optional[str] = None
    severity: Optional[str] = None
    summary: Optional[str] = None
    status: str
    status_changed_at: Optional[str] = None
    status_changed_by: Optional[str] = None
    detected_at: Optional[str] = None
    last_seen_at: Optional[str] = None


class VulnerabilityLookupRequest(BaseModel):
    """Payload for ``POST /vulnerabilities/lookup`` (Welle C / Task 3.1).

    Either ``device_ids`` (scoped to specific assets) or ``all=True``
    (every eligible asset) must be provided.  The endpoint still applies
    the D4 identity cutoff: only devices with vendor AND product AND
    version are actually looked up.
    """

    device_ids: Optional[list[int]] = Field(
        default=None,
        description="Specific device PKs to look up.  Only eligible ones are processed.",
    )
    all: bool = Field(
        default=False,
        description="When ``True``, look up every eligible asset in the inventory.",
    )


class VulnerabilityLookupResponse(BaseModel):
    """Accepted-job body returned by ``POST /vulnerabilities/lookup`` (WA.4).

    The endpoint is now async (SCAN-026 / design.md § D3): it creates a
    tracked job and returns ``202 Accepted`` with the ``job_id``
    immediately — it does **not** wait for the lookup to finish. The
    caller polls ``GET /vulnerabilities/lookups/{id}`` or subscribes to
    the SSE stream (Welle B) for progress and the final summary.
    """

    job_id: str = Field(description="The CVE-lookup job id (correlation key over API/SSE/DB).")
    status: str = Field(description="Lifecycle status at accept time (``running``).")
    eligible_assets: int = Field(description="Number of eligible assets the job will look up.")


class CveLookupItem(BaseModel):
    """Single CVE-lookup job-header row (``GET /vulnerabilities/lookups``).

    Flat wire shape of a :class:`~otalon_scan.repositories.models.CveLookup`
    row: the ``job_id`` (the record ``id``), the request parameters
    (``scope`` / ``device_id`` / ``source`` / ``api_key_used``), the
    lifecycle ``status`` (lowercase enum value), the aggregated
    ``summary`` (CONCEPT §6 shape; ``None`` while pending/running), an
    optional ``error`` (set on ``failed``) and the start/finish
    timestamps as ISO-8601 strings. Drives the Recent-Lookups list and
    the V2 detail pane (WB.1).
    """

    job_id: str
    scope: str
    device_id: Optional[int] = None
    source: str
    api_key_used: bool
    status: str
    summary: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


class CveLookupsListResponse(BaseModel):
    """Envelope for ``GET /vulnerabilities/lookups``.

    The list is wrapped in a ``lookups`` key (not a bare top-level
    array) to leave room for pagination metadata without a breaking
    shape change later — mirroring :class:`ScansListResponse`.
    """

    lookups: List[CveLookupItem]
