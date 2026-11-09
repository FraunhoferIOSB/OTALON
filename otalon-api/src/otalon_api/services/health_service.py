"""Health service for checking dependent service availability.

Performs parallel TCP, HTTP, and Docker container health probes against
PostgreSQL, InfluxDB, Network Traffic Recorder, CyberScan-ICS,
OTALON-MCP, and Cyberclas-ICS.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
from loguru import logger

from otalon_api.settings import Settings


@dataclass(frozen=True)
class ServiceProbe:
    """Configuration for a single health probe."""

    name: str
    probe_type: str
    host: str
    port: int
    path: str = "/health"
    timeout_s: float = 3.0
    headers: dict[str, str] | None = None
    container_name: str = ""
    optional: bool = False


class HealthService:
    """Checks health of all dependent services via parallel probes."""

    def __init__(self, settings: Settings) -> None:
        """Initialize HealthService with application settings.

        Args:
            settings: Application settings containing host/port configuration.
        """
        self._settings = settings

    def _build_probes(self) -> list[ServiceProbe]:
        """Build the list of service probes from current settings.

        Returns:
            A list of ServiceProbe definitions for all monitored services.
        """
        timeout = self._settings.health_check_timeout_s
        probes = [
            ServiceProbe(
                name="Postgres",
                probe_type="tcp",
                host=self._settings.postgres_host,
                port=self._settings.postgres_port,
                timeout_s=timeout,
            ),
            ServiceProbe(
                name="InfluxDB",
                probe_type="http",
                host=self._settings.influxdb_host,
                port=self._settings.influxdb_port,
                path="/health",
                timeout_s=timeout,
                headers=(
                    {"Authorization": f"Bearer {self._settings.influxdb_token}"}
                    if self._settings.influxdb_token
                    else None
                ),
            ),
            ServiceProbe(
                name="Network Traffic Recorder",
                probe_type="http",
                host=self._settings.pcap_recorder_host,
                port=self._settings.pcap_recorder_port,
                path="/health",
                timeout_s=timeout,
            ),
            ServiceProbe(
                name="CyberScan-ICS",
                probe_type="http",
                host=self._settings.otalon_scan_host,
                port=self._settings.otalon_scan_port,
                path="/health",
                timeout_s=timeout,
            ),
            ServiceProbe(
                name="OTALON-MCP",
                probe_type="http",
                host=self._settings.mcp_host,
                port=self._settings.mcp_port,
                path="/health",
                timeout_s=timeout,
            ),
            ServiceProbe(
                name="OTALON-CLAS",
                probe_type="docker",
                host="",
                port=0,
                container_name=self._settings.otalon_clas_container_name,
                timeout_s=timeout,
            ),
            self._build_ai_probe(timeout),
        ]
        return probes

    def _build_ai_probe(self, timeout: float) -> ServiceProbe:
        """Build the optional OTALON-AI HTTP probe from settings.

        Args:
            timeout: Probe timeout in seconds.

        Returns:
            A :class:`ServiceProbe` marked ``optional=True``.
        """
        parsed = urlparse(self._settings.ai_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 9100
        return ServiceProbe(
            name="OTALON-AI",
            probe_type="http",
            host=host,
            port=port,
            path="/health",
            timeout_s=timeout,
            optional=True,
        )

    async def check_all(self) -> dict[str, Any]:
        """Run all health probes in parallel and return aggregated results.

        Returns:
            A dict with ``services`` (list of check results) and
            ``overall_status`` (``healthy``, ``degraded``, or ``unhealthy``).
        """
        probes = self._build_probes()
        tasks = []
        for probe in probes:
            if probe.probe_type == "tcp":
                tasks.append(self._check_tcp(probe))
            elif probe.probe_type == "docker":
                tasks.append(self._check_docker(probe))
            else:
                tasks.append(self._check_http(probe))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        services: list[dict[str, Any]] = []
        for i, result in enumerate(results):
            probe = probes[i]
            if isinstance(result, BaseException):
                item: dict[str, Any] = {
                    "name": probe.name,
                    "running": False,
                    "detail": f"probe failed: {type(result).__name__}",
                    "timestamp": time.time(),
                    "classification": "optional" if probe.optional else "core",
                    "latency_ms": probe.timeout_s * 1000.0,
                    "latency_budget_ms": probe.timeout_s * 1000.0,
                }
            else:
                item = result
                item["classification"] = "optional" if probe.optional else "core"
            item["status"] = self._derive_status(
                running=bool(item.get("running")),
                optional=probe.optional,
            )
            services.append(item)

        overall = self._compute_overall_status(services)
        return {"services": services, "overall_status": overall}

    @staticmethod
    def _derive_status(running: bool, optional: bool) -> str:
        """Map a probe result to an explicit truthful status.

        A reachable service is ``healthy``. A core service that is not
        reachable is ``failed``. An optional service that is not reachable is
        ``not-configured`` — a distinct, non-failure state so the Overview does
        not brand an unconfigured optional component as a failure.

        Args:
            running: Whether the probe succeeded.
            optional: Whether the probe is for an optional service.

        Returns:
            One of ``healthy``, ``failed`` or ``not-configured``.
        """
        if running:
            return "healthy"
        return "not-configured" if optional else "failed"

    async def _check_tcp(self, probe: ServiceProbe) -> dict[str, Any]:
        """Perform a TCP connection probe.

        Args:
            probe: The probe configuration with host and port.

        Returns:
            A dict with name, running, detail, and timestamp fields.
        """
        t0 = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(probe.host, probe.port),
                timeout=probe.timeout_s,
            )
            writer.close()
            await writer.wait_closed()
            ms = round((time.perf_counter() - t0) * 1000)
            return self._result(probe, True, f"ok in {ms} ms", ms)
        except Exception as exc:
            ms = round((time.perf_counter() - t0) * 1000)
            logger.warning("TCP probe failed for {}: {} ({} ms)", probe.name, exc, ms)
            return self._result(probe, False, self._failure_detail(exc, ms), ms)

    async def _check_http(self, probe: ServiceProbe) -> dict[str, Any]:
        """Perform an HTTP GET health probe.

        Args:
            probe: The probe configuration with host, port, and path.

        Returns:
            A dict with name, running, detail, and timestamp fields.
        """
        url = f"http://{probe.host}:{probe.port}{probe.path}"
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=probe.timeout_s) as client:
                resp = await client.get(url, headers=probe.headers or {})
                resp.raise_for_status()
            ms = round((time.perf_counter() - t0) * 1000)
            return self._result(probe, True, f"ok in {ms} ms", ms)
        except Exception as exc:
            ms = round((time.perf_counter() - t0) * 1000)
            logger.warning("HTTP probe failed for {}: {} ({} ms)", probe.name, exc, ms)
            return self._result(probe, False, self._failure_detail(exc, ms), ms)

    async def _check_docker(self, probe: ServiceProbe) -> dict[str, Any]:
        """Check service health by inspecting its Docker container status.

        Args:
            probe: The probe configuration with container_name.

        Returns:
            A dict with name, running, detail, and timestamp fields.
        """
        return await asyncio.to_thread(self._check_docker_sync, probe)

    def _check_docker_sync(self, probe: ServiceProbe) -> dict[str, Any]:
        """Synchronous Docker container status check.

        Args:
            probe: The probe configuration with container_name.

        Returns:
            A dict with name, running, detail, and timestamp fields.
        """
        t0 = time.perf_counter()
        try:
            import docker as docker_lib

            client = docker_lib.from_env()
            container = client.containers.get(probe.container_name)
            ms = round((time.perf_counter() - t0) * 1000)
            if container.status == "running":
                return self._result(probe, True, f"ok in {ms} ms", ms)
            return self._result(probe, False, f"container {container.status} ({ms} ms)", ms)
        except Exception as exc:
            ms = round((time.perf_counter() - t0) * 1000)
            logger.warning("Docker probe failed for {}: {} ({} ms)", probe.name, exc, ms)
            return self._result(probe, False, self._failure_detail(exc, ms), ms)

    @staticmethod
    def _failure_detail(exc: Exception, ms: int) -> str:
        """Return truthful bounded failure text without fabricating a cause."""
        if isinstance(exc, (asyncio.TimeoutError, httpx.TimeoutException)):
            return f"probe timeout after {ms} ms"
        return f"probe failed: {type(exc).__name__} ({ms} ms)"

    @staticmethod
    def _result(probe: ServiceProbe, running: bool, detail: str, ms: int) -> dict[str, Any]:
        """Build backward-compatible structured probe output."""
        return {
            "name": probe.name,
            "running": running,
            "detail": detail,
            "timestamp": time.time(),
            "latency_ms": float(ms),
            "latency_budget_ms": probe.timeout_s * 1000.0,
        }

    @staticmethod
    def _compute_overall_status(services: list[dict[str, Any]]) -> str:
        """Derive overall system health from individual probe results.

        Optional services (``classification == "optional"``) are excluded
        from the aggregate so that an unconfigured optional component does
        not fail the suite.

        Args:
            services: List of individual service health check dicts.

        Returns:
            ``healthy`` if all core services are running, ``unhealthy`` if
            no core service is running, ``degraded`` otherwise.
        """
        if not services:
            return "unhealthy"
        core = [s for s in services if s.get("classification") != "optional"]
        considered = core if core else services
        running_count = sum(1 for s in considered if s.get("running"))
        if running_count == len(considered):
            return "healthy"
        if running_count == 0:
            return "unhealthy"
        return "degraded"
