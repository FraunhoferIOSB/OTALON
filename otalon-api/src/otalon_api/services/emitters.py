"""Background emitter tasks for Server-Sent Events.

Each emitter runs as an asyncio task and periodically fetches data
from the relevant service and publishes it to the EventBus.  Emitters
are designed to be resilient: a transient exception is logged and the
loop continues; only ``asyncio.CancelledError`` terminates an emitter.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from otalon_api.services.anomaly_service import AnomalyService
    from otalon_api.services.dashboard_kpi_service import DashboardKpiService
    from otalon_api.services.event_bus import EventBus
    from otalon_api.services.health_incident_service import HealthIncidentService
    from otalon_api.services.health_service import HealthService
    from otalon_api.services.topology_service import TopologyService


KPI_INTERVAL_S: float = 3.0
HEALTH_INTERVAL_S: float = 5.0
ANOMALY_INTERVAL_S: float = 3.0
TOPOLOGY_INTERVAL_S: float = 30.0

TOPOLOGY_WINDOW_MINUTES: int = 30
DEFAULT_LIVE_WINDOW_MINUTES: int = 5


async def kpi_emitter(bus: EventBus, service: DashboardKpiService) -> None:
    """Periodically fetch KPI data and publish to the ``kpi`` topic.

    Uses a rolling time window of ``DEFAULT_LIVE_WINDOW_MINUTES`` minutes
    ending at the current UTC time, matching the default frontend live
    mode window.  Extracts ``result["data"][0]`` from the service envelope
    before publishing.

    Args:
        bus: The EventBus to publish events to.
        service: The DashboardKpiService used for data retrieval.
    """
    while True:
        await asyncio.sleep(KPI_INTERVAL_S)
        try:
            stop = datetime.now(tz=timezone.utc)
            start = stop - timedelta(minutes=DEFAULT_LIVE_WINDOW_MINUTES)
            result = await service.get_kpis(start=start, stop=stop)
            data = result["data"][0] if result.get("data") else None
            if data:
                await bus.publish("kpi", data)
        except asyncio.CancelledError:
            break
        except Exception:
            logger.opt(exception=True).warning("kpi_emitter: failed to fetch/publish KPI data")


async def health_emitter(
    bus: EventBus, service: HealthService, incident_service: HealthIncidentService | None = None
) -> None:
    """Periodically fetch health status and publish to the ``health`` topic.

    Publishes the full health payload directly — the frontend handler expects
    the same shape as the service output (``services`` list + ``overall_status``).

    Args:
        bus: The EventBus to publish events to.
        service: The HealthService used for parallel probe execution.
    """
    while True:
        await asyncio.sleep(HEALTH_INTERVAL_S)
        try:
            data = await service.check_all()
            if incident_service is not None:
                data.update(await incident_service.record_async(data))
            await bus.publish("health", data)
        except asyncio.CancelledError:
            break
        except Exception:
            logger.opt(exception=True).warning("health_emitter: failed to fetch/publish health data")


async def anomaly_emitter(bus: EventBus, service: AnomalyService) -> None:
    """Periodically fetch anomaly groups and publish new or changed ones.

    Uses a rolling time window of ``DEFAULT_LIVE_WINDOW_MINUTES`` minutes
    ending at the current UTC time, consistent with the frontend live mode.
    Implements change-detection by caching the last known ``end_timestamp``
    for each group ID.  Only groups whose ``end_timestamp`` changed (or that
    are entirely new) are published.  The frontend handler expects a single
    ``AnomalyGroupItem`` per event, not an array, so each changed group is
    published individually.

    Args:
        bus: The EventBus to publish events to.
        service: The AnomalyService used for alarm group retrieval.
    """
    known: dict[str, str] = {}

    while True:
        await asyncio.sleep(ANOMALY_INTERVAL_S)
        try:
            stop = datetime.now(tz=timezone.utc)
            start = stop - timedelta(minutes=DEFAULT_LIVE_WINDOW_MINUTES)
            result = await service.get_anomaly_groups(
                start=start,
                stop=stop,
                limit=200,
            )
            groups = result.get("data", [])

            for group in groups:
                group_id = group.get("id")
                end_ts = str(group.get("end_timestamp", ""))
                if group_id and known.get(group_id) != end_ts:
                    await bus.publish("anomaly", group)
                    known[group_id] = end_ts
        except asyncio.CancelledError:
            break
        except Exception:
            logger.opt(exception=True).warning("anomaly_emitter: failed to fetch/publish anomaly data")


async def topology_emitter(bus: EventBus, service: TopologyService) -> None:
    """Periodically fetch the topology graph and publish to the ``topology`` topic.

    Uses a rolling time window of ``TOPOLOGY_WINDOW_MINUTES`` minutes ending
    at the current UTC time, consistent with the frontend live mode behaviour.
    Publishes the full topology payload directly.

    Args:
        bus: The EventBus to publish events to.
        service: The TopologyService used for graph construction.
    """
    while True:
        await asyncio.sleep(TOPOLOGY_INTERVAL_S)
        try:
            stop = datetime.now(tz=timezone.utc)
            start = stop - timedelta(minutes=TOPOLOGY_WINDOW_MINUTES)
            data = await service.get_topology(start=start, stop=stop)
            await bus.publish("topology", data)
        except asyncio.CancelledError:
            break
        except Exception:
            logger.opt(exception=True).warning("topology_emitter: failed to fetch/publish topology data")
