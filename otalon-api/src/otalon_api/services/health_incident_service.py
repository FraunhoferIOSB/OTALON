"""Correlation service for canonical health-emitter samples."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from otalon_api.repositories.health_incidents_repo import HealthIncidentRepository

# Module-level alias so annotations do not resolve to the ``list`` *method*
# defined on the service class (which shadows the ``list`` builtin inside the
# class body under ``from __future__ import annotations``).
IncidentRows = list[dict[str, Any]]

RECENT_WINDOW_MINUTES = 15

PROBE_SERVICE_IDS: dict[str, str] = {
    "Postgres": "postgres",
    "InfluxDB": "influxdb3",
    "Network Traffic Recorder": "otalon-capture",
    "OTALON-SCAN": "otalon-scan",
    "OTALON-MCP": "otalon-mcp",
    "OTALON-CLAS": "otalon-clas",
    "OTALON-AI": "otalon-ai",
}
OWNING_SERVICE_BY_PROBE = PROBE_SERVICE_IDS
SYSTEM_SERVICE_ID_BY_PROBE = PROBE_SERVICE_IDS


class HealthIncidentService:
    """Turn canonical health snapshots into stable incident evidence.

    All persistence is synchronous ``psycopg2``. The async entry points offload
    that work with :func:`asyncio.to_thread` so the event loop stays responsive
    while a repository call blocks on the database.
    """

    def __init__(self, repository: HealthIncidentRepository) -> None:
        """Initialize service with incident persistence."""
        self._repository = repository

    def record(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Record every core service sample once and return summaries."""
        now = datetime.now(timezone.utc)
        for service in payload.get("services", []):
            if service.get("classification") == "optional":
                continue
            sample = self._sample(service)
            if not sample["in_budget"] or self._repository.active(str(sample["service"])):
                self._repository.upsert_sample(sample, now)
        self._repository.prune(now)
        summaries = self.summaries()
        self.latch_overall_status(payload, summaries)
        return summaries

    async def record_async(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Offload :meth:`record` so the event loop is never blocked."""
        return await asyncio.to_thread(self.record, payload)

    def summaries(self) -> dict[str, list[dict[str, Any]]]:
        """Return active and recently recovered incident summaries.

        ``active_incidents`` is derived from a status-scoped ``active`` query
        that is UNFILTERED by acknowledgement (bounded to one row per service by
        the unique active index), so acknowledging an active incident never
        removes it from the latch input and cannot falsify header/service health
        (CAPTURE 45). ``unacknowledged_incidents`` is derived from a DEDICATED
        query returning every unacknowledged active/recovered incident within
        the 7-day retention window — NOT from the 50-row history page, which
        could otherwise let 50 newer incidents truncate a still-valid reminder
        off Overview. ``recent`` is the 15-minute recovered-and-unacknowledged
        ring. No user-facing projection is capped by the 50-item history page.
        """
        active = [self._summary(row) for row in self._repository.list(status="active")]
        unack_rows = self._repository.unacknowledged()
        unacknowledged = [self._summary(row) for row in unack_rows]
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=RECENT_WINDOW_MINUTES)
        recent = [
            self._summary(row)
            for row in unack_rows
            if row["status"] == "recovered" and row.get("recovered_at") and row["recovered_at"] >= cutoff
        ]
        return {
            "active_incidents": active,
            "unacknowledged_incidents": unacknowledged,
            "recent_incidents": recent,
        }

    def acknowledge(self, incident_id: UUID, actor: str = "operator") -> dict[str, Any] | None:
        """Persist acknowledgement without changing operational incident state."""
        row = self._repository.acknowledge(incident_id, actor, datetime.now(timezone.utc))
        return self._summary(row, detail=True) if row else None

    async def acknowledge_async(self, incident_id: UUID, actor: str = "operator") -> dict[str, Any] | None:
        """Offload acknowledgement and its audit write from the event loop."""
        return await asyncio.to_thread(self.acknowledge, incident_id, actor)

    async def summaries_async(self) -> dict[str, list[dict[str, Any]]]:
        """Offload :meth:`summaries` so the event loop is never blocked."""
        return await asyncio.to_thread(self.summaries)

    @staticmethod
    def latch_overall_status(payload: dict[str, Any], summaries: dict[str, Any]) -> None:
        """Force the effective aggregate to at least degraded while active.

        An active core incident that survives one intermittent raw-probe
        success MUST keep both the REST snapshot and the SSE payload degraded,
        so the header/Overview never flap to healthy before a real two-success
        recovery.
        """
        if summaries.get("active_incidents") and payload.get("overall_status") == "healthy":
            payload["overall_status"] = "degraded"

    def list(self, status: str | None = None, service: str | None = None, limit: int = 50) -> IncidentRows:
        """Return bounded incident history."""
        return [self._summary(row) for row in self._repository.list(status, service, limit)]

    async def list_async(self, status: str | None = None, service: str | None = None, limit: int = 50) -> IncidentRows:
        """Offload :meth:`list` so the event loop is never blocked."""
        return await asyncio.to_thread(self.list, status, service, limit)

    def detail(self, incident_id: UUID) -> dict[str, Any] | None:
        """Return full incident evidence by stable ID."""
        row = self._repository.get(incident_id)
        return self._summary(row, detail=True) if row else None

    async def detail_async(self, incident_id: UUID) -> dict[str, Any] | None:
        """Offload :meth:`detail` so the event loop is never blocked."""
        return await asyncio.to_thread(self.detail, incident_id)

    @staticmethod
    def _sample(service: dict[str, Any]) -> dict[str, Any]:
        """Normalize health service output to structured evidence."""
        name = service["name"]
        detail = str(service.get("detail", ""))
        timeout = "timeout" in detail.lower()
        latency = float(service.get("latency_ms", 0.0))
        budget = float(service.get("latency_budget_ms", 3000.0))
        return {
            "service": name,
            "owning_service": OWNING_SERVICE_BY_PROBE.get(name, ""),
            "probe_target": HealthIncidentService._probe_target(service),
            "running": bool(service.get("running")),
            "in_budget": bool(service.get("running")) and latency <= budget,
            "category": "probe_timeout" if timeout else "probe_failure",
            "cause": "health probe timeout" if timeout else "health probe failed",
            "latency_ms": latency,
            "latency_budget_ms": budget,
            "timestamp": service.get("timestamp"),
            "detail": detail,
        }

    @staticmethod
    def _probe_target(service: dict[str, Any]) -> str:
        """Return a safe, secret-free probe-target identifier for the drawer."""
        target = service.get("probe_target")
        if isinstance(target, str) and target:
            return target
        return str(service["name"])

    @staticmethod
    def _summary(row: dict[str, Any], detail: bool = False) -> dict[str, Any]:
        """Map database row to API-safe evidence."""
        result = {
            key: row.get(key)
            for key in (
                "id",
                "service",
                "owning_service",
                "probe_target",
                "category",
                "cause",
                "status",
                "first_seen",
                "last_seen",
                "recovered_at",
                "sample_count",
                "failure_count",
                "latency_budget_ms",
                "worst_latency_ms",
                "acknowledged_at",
                "acknowledged_by",
            )
        }
        result["id"] = str(result["id"]) if result.get("id") is not None else None
        result["evidence_type"] = "operational_health"
        result["acknowledged"] = result["acknowledged_at"] is not None
        result["system_service_id"] = SYSTEM_SERVICE_ID_BY_PROBE.get(str(row.get("service", "")))
        if detail:
            result["samples"] = row.get("samples", [])
        return result
