"""Pydantic wire models for the scan endpoints (SCAN-033 extraction).

Moved verbatim out of :mod:`otalon_scan.api.server` when the inline ``@app.*``
routes were split into ``APIRouter`` modules. Shapes are unchanged — the
OpenAPI document generated from these models is byte-identical to the
pre-split one.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ValidationError, model_validator

from ...core.module_config import MODULE_SCHEMA_REGISTRY, resolve_module_slug
from ...core.validators import MIRROR_OVERRIDE_CONTEXT_KEY

__all__ = [
    "BulkDeleteScansRequest",
    "BulkDeleteScansResponse",
    "FinishedScansResponse",
    "RunningScansResponse",
    "ScanItem",
    "ScansListResponse",
    "StartScanRequest",
    "StartScanResponse",
    "StopScanResponse",
]


class StartScanRequest(BaseModel):
    """Payload for starting a scan.

    The ``overrides`` field is dispatched to the per-module Pydantic schema
    registered in :data:`otalon_scan.core.module_config.MODULE_SCHEMA_REGISTRY`
    based on the canonical leaf slug derived from ``module_name``
    (``"modules/arp_scan"`` and ``"arp_scan"`` both resolve to
    ``arp_scan``). Unknown ``module_name`` values and any ``overrides``
    payload that fails per-module validation (unknown keys, wrong types,
    invalid values) surface as HTTP 422 (Pydantic ``ValidationError``,
    FastAPI's natural response code for request-body validation
    failures).

    SCAN-037: ``allow_mirror_interface`` is the deliberate operator opt-in
    that permits a ``network_interface`` override pointing at a mirror/SPAN
    port. It is a top-level request field rather than a per-module override
    key, so it can never be smuggled in through an ``overrides`` payload and
    never reaches a module's ``config.json`` merge.
    """

    module_name: str = Field(
        ...,
        description="Module identifier (e.g., 'modules/arp_scan', 'modules/port_scan').",
    )
    overrides: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Optional configuration overrides merged with the module's "
            "config.json. Validated against the per-module override schema "
            "(see otalon_scan.core.module_config.MODULE_SCHEMA_REGISTRY); unknown "
            "keys are rejected."
        ),
    )
    allow_mirror_interface: bool = Field(
        default=False,
        description=(
            "Deliberate operator override (SCAN-037): permit binding this "
            "scan to an interface classified as a mirror/SPAN port. Actively "
            "transmitting on a passive SPAN/TAP port is an operational fault "
            "on an ICS/OT network, so the default is to reject such an "
            "interface. Setting this to true is logged at WARNING."
        ),
    )

    @model_validator(mode="after")
    def _validate_overrides_against_module_schema(self) -> "StartScanRequest":
        """Dispatch ``overrides`` validation to the per-module schema.

        Unknown ``module_name`` → ``ValueError`` → HTTP 422.
        Schema violations → ``ValueError`` (carrying the original Pydantic
        error messages) → HTTP 422.

        SCAN-037: ``allow_mirror_interface`` is forwarded to the per-module
        schema as Pydantic validation *context*, which
        :func:`otalon_scan.core.validators.validate_network_interface` consults
        before accepting a mirror/SPAN bind interface. Absent context means
        "reject" — the safe default holds for every caller that validates a
        module override schema directly.

        On success the validated, normalised override payload replaces the
        original ``overrides`` dict so downstream consumers see canonical
        values (e.g. ``ipaddress``-normalised IPs/subnets).
        """
        slug = resolve_module_slug(self.module_name)
        schema = MODULE_SCHEMA_REGISTRY.get(slug)
        if schema is None:
            raise ValueError(
                f"unknown module_name {self.module_name!r}: no override schema "
                f"registered for slug {slug!r}. Known slugs: "
                f"{sorted(MODULE_SCHEMA_REGISTRY.keys())}"
            )

        if self.overrides is None:
            return self

        try:
            validated = schema.model_validate(
                self.overrides,
                context={MIRROR_OVERRIDE_CONTEXT_KEY: self.allow_mirror_interface},
            )
        except ValidationError as exc:
            raise ValueError(f"overrides for module {slug!r} failed validation: {exc}") from exc

        # Replace raw dict with the canonical, normalised form (excluding
        # unset fields so module-level config.json defaults still win for
        # anything the caller did not explicitly override).
        object.__setattr__(
            self,
            "overrides",
            validated.model_dump(exclude_unset=True, mode="json"),
        )
        return self


class StartScanResponse(BaseModel):
    """Response for a started scan."""

    run_id: str
    scan_id: str
    module_name: str
    status: str


class StopScanResponse(BaseModel):
    """Response for a stopped scan."""

    run_id: str
    stopped: bool


class RunningScansResponse(BaseModel):
    """Response with running scans mapping."""

    running: Dict[str, str]


class FinishedScansResponse(BaseModel):
    """Response with finished scans mapping."""

    finished: Dict[str, str]


class ScanItem(BaseModel):
    """Single row of the ``GET /scans`` listing.

    Shape mirrors the UI's ``ScanItem`` contract
    (``otalon-ui/app/types/scans.ts``): a flat record with
    ``scan_id``, ``module``, ``status`` (lowercase enum value),
    ``started_at`` and optional ``finished_at`` ISO-8601 timestamps.
    Additional fields (``error_message``, ``parameters``) are included
    forward-compatibly so callers that need them do not need a second
    round-trip via ``GET /scans/{scan_id}``.
    """

    scan_id: str
    module: str
    status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error_message: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    # L-02: per-scan findings snapshot (list of DeviceFinding dicts). Only
    # populated on the single-scan detail endpoint; ``None`` on list rows.
    findings: Optional[List[Dict[str, Any]]] = None


class ScansListResponse(BaseModel):
    """Envelope for ``GET /scans``.

    The list is wrapped in a ``scans`` key (not a bare top-level array)
    to keep room for pagination metadata (``next_offset`` etc.) without a
    breaking shape change later. UI normaliser accepts both shapes.
    """

    scans: List[ScanItem]


class BulkDeleteScansRequest(BaseModel):
    """Request body for ``DELETE /scans`` (bulk reaper).

    The ``ids`` list MUST contain between 1 and 500 scan UUID strings.
    Empty lists are rejected with HTTP 422. The 500-id ceiling caps the
    blast radius of a runaway operator action.
    """

    ids: List[str] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="List of scans.id UUID strings to hard-delete.",
    )


class BulkDeleteScansResponse(BaseModel):
    """Response body for ``DELETE /scans`` (bulk reaper).

    Reports which ids were actually removed (``deleted``) and which did
    not match any ``scans`` row (``not_found``). Per-id 404s are
    intentionally absent — the bulk endpoint succeeds as long as the
    transaction commits, even if some ids did not exist.
    """

    deleted: List[str] = Field(default_factory=list, description="Ids that existed and were removed.")
    not_found: List[str] = Field(default_factory=list, description="Ids that did not match any scans row.")
