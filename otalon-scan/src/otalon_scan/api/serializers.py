"""ORM row → wire item projections for the otalon-scan HTTP surface.

Extracted from :mod:`otalon_scan.api.server` by SCAN-033. Pure functions: no I/O,
no application state, no logging. Every timestamp column is emitted as an
ISO-8601 string so the wire shape is JSON-portable without depending on
the consumer to handle native ``datetime`` payloads.
"""

from __future__ import annotations

from typing import Any

from ..repositories.models import (
    CveLookup,
    Device,
    Scan,
    ServiceObservation,
    VulnerabilityObservation,
)
from .schemas.devices import DeviceItem, ServiceObservationItem
from .schemas.scans import ScanItem
from .schemas.vulnerabilities import CveLookupItem, VulnerabilityItem

__all__ = [
    "cve_lookup_row_to_item",
    "device_row_to_item",
    "observation_row_to_item",
    "scan_row_to_item",
    "serialize_module_results",
    "vuln_row_to_item",
]


def device_row_to_item(row: Device) -> DeviceItem:
    """Project a :class:`Device` row into its identity wire item (SCAN-023)."""
    return DeviceItem(
        id=int(row.id),
        primary_mac=row.primary_mac,
        hostname=row.hostname,
        vendor=row.vendor,
        device_family=row.device_family,
        device_type=row.device_type,
        article_number=row.article_number,
        firmware_version=row.firmware_version,
        product_name=row.product_name,
        hw_version=row.hw_version,
        sw_version=row.sw_version,
        manual_identity_fields=list(row.manual_identity_fields or []),
        last_scan_at=row.last_scan_at.isoformat() if row.last_scan_at else None,
    )


def scan_row_to_item(row: Scan, *, include_findings: bool = False) -> ScanItem:
    """Convert a SQLAlchemy :class:`Scan` row into the UI-facing :class:`ScanItem`.

    Timestamp columns are emitted as ISO-8601 strings (UTC, ``Z`` suffix
    via :meth:`datetime.isoformat`) so the wire shape is JSON-portable
    without depending on the UI to handle native ``datetime`` payloads.

    Args:
        row: The persisted scan row.
        include_findings: When ``True`` (L-02, single-scan detail), attach
            the persisted ``findings`` snapshot so the history detail view can
            render the discovered devices/services. List endpoints leave this
            ``False`` to keep listing payloads lean.
    """
    return ScanItem(
        scan_id=str(row.id),
        module=row.module_name,
        status=row.status.value,
        started_at=row.started_at.isoformat() if row.started_at else None,
        finished_at=row.finished_at.isoformat() if row.finished_at else None,
        error_message=row.error_message,
        parameters=row.parameters,
        findings=row.findings if include_findings else None,
    )


def cve_lookup_row_to_item(row: CveLookup) -> CveLookupItem:
    """Convert a :class:`CveLookup` job-header row into its wire item.

    Timestamp columns are emitted as ISO-8601 strings so the wire shape
    is JSON-portable, exactly like :func:`scan_row_to_item`.
    """
    return CveLookupItem(
        job_id=str(row.id),
        scope=row.scope,
        device_id=row.device_id,
        source=row.source,
        api_key_used=bool(row.api_key_used),
        status=row.status.value,
        summary=row.summary,
        error=row.error,
        started_at=row.started_at.isoformat() if row.started_at else None,
        finished_at=row.finished_at.isoformat() if row.finished_at else None,
    )


def observation_row_to_item(row: ServiceObservation) -> ServiceObservationItem:
    """Convert a :class:`ServiceObservation` row into its flat wire item."""
    return ServiceObservationItem(
        id=int(row.id),
        scan_id=str(row.scan_id),
        interface_id=row.interface_id,
        ip_address=str(row.ip_address) if row.ip_address is not None else None,
        mac_address=str(row.mac_address) if row.mac_address is not None else None,
        port=row.port,
        transport=row.transport,
        protocol=row.protocol,
        service_name=row.service_name,
        product=row.product,
        version=row.version,
        cpe=row.cpe,
        extra_info=row.extra_info,
        first_seen_at=row.first_seen_at.isoformat() if row.first_seen_at else None,
        last_seen_at=row.last_seen_at.isoformat() if row.last_seen_at else None,
    )


def vuln_row_to_item(row: VulnerabilityObservation) -> VulnerabilityItem:
    """Convert a :class:`VulnerabilityObservation` row into its wire item."""
    return VulnerabilityItem(
        id=int(row.id),
        scan_id=str(row.scan_id),
        device_id=row.device_id,
        interface_id=row.interface_id,
        source_module=row.source_module,
        vuln_id=row.vuln_id,
        severity=row.severity,
        summary=row.summary,
        status=row.status.value,
        status_changed_at=(row.status_changed_at.isoformat() if row.status_changed_at else None),
        status_changed_by=row.status_changed_by,
        detected_at=row.detected_at.isoformat() if row.detected_at else None,
        last_seen_at=row.last_seen_at.isoformat() if row.last_seen_at else None,
    )


def serialize_module_results(results: Any) -> Any:
    """Convert module results to JSON-serializable structures (recursive).

    HC7 note (2026-05-18): the five ``except Exception`` blocks inside
    ``_normalize`` are intentional duck-typing fallbacks — each block
    tries one possible shape (pandas / numpy / pydantic / dataclass)
    and falls through to the next on failure. The outer block returns
    ``str(obj)`` as the final last-resort serialisation. Logging here
    would be noise because the failures are the *expected* signal that
    the object is not of that shape. The catch-alls remain as
    documented ``# noqa: BLE001`` fallbacks per HC7 acceptance
    criterion (c) — "documented ``# noqa`` with begründung".
    """

    def _normalize(obj: Any) -> Any:
        try:
            if obj is None or isinstance(obj, (str, int, float, bool)):
                return obj

            # Pandas DataFrame (duck-typing)
            if hasattr(obj, "to_dict") and hasattr(obj, "columns"):
                try:
                    return obj.to_dict(orient="records")
                except Exception:  # noqa: BLE001 -- duck-typing fallback
                    pass

            # Objects with tolist (numpy arrays, etc.)
            if hasattr(obj, "tolist") and not isinstance(obj, dict):
                try:
                    return obj.tolist()
                except Exception:  # noqa: BLE001 -- duck-typing fallback
                    pass

            # Pydantic BaseModel
            try:
                from pydantic import BaseModel as _BM

                if isinstance(obj, _BM):
                    return obj.model_dump()
            except Exception:  # noqa: BLE001 -- import or model_dump failure tolerated
                pass

            # Dataclass
            try:
                from dataclasses import asdict, is_dataclass

                # ``is_dataclass`` accepts both instances and the class
                # itself; only the instance form is serialisable via
                # ``asdict``, so narrow with the ``not isinstance(obj, type)``
                # guard mypy understands.
                if is_dataclass(obj) and not isinstance(obj, type):
                    return _normalize(asdict(obj))
            except Exception:  # noqa: BLE001 -- duck-typing fallback
                pass

            if isinstance(obj, dict):
                return {str(k): _normalize(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple, set)):
                return [_normalize(v) for v in list(obj)]
            return str(obj)
        except Exception:  # noqa: BLE001 -- last-resort str() fallback
            return str(obj)

    return _normalize(results)
