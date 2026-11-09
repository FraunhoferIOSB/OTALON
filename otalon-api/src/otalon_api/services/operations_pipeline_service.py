"""Operations pipeline freshness service.

Computes read-only freshness state for the data path consumed by the
Operations Overview. All storage queries are issued through the injected
repositories and wrapped with ``asyncio.to_thread`` so the FastAPI event
loop remains unblocked.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal

import pandas as pd
from loguru import logger

if TYPE_CHECKING:
    from otalon_api.repositories.influx_repo import InfluxRepository
    from otalon_api.repositories.postgres_repo import PostgresRepository
    from otalon_api.settings import Settings

SOURCE_MEASUREMENTS: dict[str, str] = {
    "conn": "network_metrics",
    "mac": "mac_traffic",
    "proto": "proto_traffic",
}

FRIENDLY_LABELS: dict[str, str] = {
    "conn": "Connections",
    "mac": "Assets",
    "proto": "Protocols",
}


def _humanize_stale_age(age_seconds: int | None) -> str:
    """Render a stale age as a human phrase, never a misleading ``0 min``.

    Args:
        age_seconds: The age of the last record in seconds (may be ``None``).

    Returns:
        ``"<1 min"`` for anything under a minute (including ``None``/zero),
        otherwise ``"<n> min"``.
    """
    if age_seconds is None or age_seconds < 60:
        return "<1 min"
    return f"{age_seconds // 60} min"


@dataclass(frozen=True)
class SourceFreshness:
    """Per-source freshness result."""

    name: str
    last_record: datetime | None
    age_seconds: int | None
    state: "Literal['current', 'stale', 'no-data']"
    records_per_hour: int
    expected_interval_seconds: int


@dataclass(frozen=True)
class InfluxFreshness:
    """Latest observed monitored-source record freshness.

    ``last_write`` is the most recent ``last_record`` across the monitored
    source measurements (not an independent Influx write-health probe);
    ``age_seconds`` is its age.
    """

    last_write: datetime | None
    age_seconds: int | None


@dataclass(frozen=True)
class DetectionFreshness:
    """Detection-cycle freshness."""

    last_cycle: datetime | None
    age_seconds: int | None
    duration_seconds: float | None
    series_evaluated: int | None


@dataclass(frozen=True)
class PipelineFreshness:
    """Complete pipeline freshness snapshot."""

    sources: list[SourceFreshness]
    influx: InfluxFreshness
    detection: DetectionFreshness
    backlog: int | None


class OperationsPipelineService:
    """Compute read-only pipeline freshness for the Operations Overview."""

    STALE_MULTIPLIER: int = 3
    RECENT_WINDOW_SECONDS: int = 3600

    def __init__(
        self,
        influx_repo: "InfluxRepository",
        postgres_repo: "PostgresRepository",
        settings: "Settings",
    ) -> None:
        """Initialize with repository and settings dependencies.

        Args:
            influx_repo: Repository for InfluxDB queries.
            postgres_repo: Repository for PostgreSQL metadata queries.
            settings: Application settings for thresholds and cadence.
        """
        self._influx = influx_repo
        self._postgres = postgres_repo
        self._settings = settings

    @property
    def _expected_interval_seconds(self) -> int:
        """API-side expected freshness interval in seconds.

        Sourced from the deployer-aligned ``pipeline_poll_interval_seconds``
        setting, not read live from the otalon-clas runtime. Used only to
        derive the ``stale`` threshold.
        """
        return self._settings.pipeline_poll_interval_seconds or 5

    @property
    def _lookback_delta(self) -> timedelta:
        """Maximum lookback for the ``no-data`` decision."""
        hours = self._settings.pipeline_lookback_hours or 24
        return timedelta(hours=hours)

    def _now(self) -> datetime:
        """Return current time in UTC."""
        return datetime.now(timezone.utc)

    async def get_pipeline(self) -> PipelineFreshness:
        """Fetch and derive the full pipeline freshness snapshot.

        Returns:
            A :class:`PipelineFreshness` with source, Influx, detection and
            backlog fields.
        """
        now = self._now()
        threshold_seconds = self.STALE_MULTIPLIER * self._expected_interval_seconds
        sources = await asyncio.gather(
            *[
                self._get_source(name, measurement, now, threshold_seconds)
                for name, measurement in SOURCE_MEASUREMENTS.items()
            ]
        )
        detection_task = asyncio.create_task(self._get_detection(now))
        detection = await detection_task

        # ``influx.last_write`` is the freshest record observed across the
        # monitored source measurements — an observed-source-freshness signal,
        # NOT an independent Influx write-health probe.
        latest_source = max(
            (s.last_record for s in sources if s.last_record is not None),
            default=None,
        )
        influx_age = None if latest_source is None else int((now - latest_source).total_seconds())

        return PipelineFreshness(
            sources=list(sources),
            influx=InfluxFreshness(last_write=latest_source, age_seconds=influx_age),
            detection=detection,
            backlog=None,
        )

    async def _get_source(
        self,
        name: str,
        measurement: str,
        now: datetime,
        threshold_seconds: int,
    ) -> SourceFreshness:
        """Derive freshness for one source."""

        lookback_hours = self._settings.pipeline_lookback_hours or 24
        # Share the single ``now`` boundary with the repo query so the bounded
        # lookback window and the freshness classification below use the exact
        # same clock (prevents a boundary-edge record from being fetched by the
        # query yet rejected here).
        now_ts = pd.Timestamp(now)

        def _run() -> SourceFreshness:
            last_record = self._influx.query_last_record_time(measurement, lookback_hours, now=now_ts)
            if last_record is None or (now - last_record) > self._lookback_delta:
                return SourceFreshness(
                    name=name,
                    last_record=last_record,
                    age_seconds=None,
                    state="no-data",
                    records_per_hour=0,
                    expected_interval_seconds=self._expected_interval_seconds,
                )
            age_seconds = int((now - last_record).total_seconds())
            since = now - timedelta(seconds=self.RECENT_WINDOW_SECONDS)
            recent_count = self._influx.query_record_count_since(measurement, pd.Timestamp(since))
            records_per_hour = recent_count * (3600 // self.RECENT_WINDOW_SECONDS)
            state: Literal["current", "stale", "no-data"] = "current" if age_seconds <= threshold_seconds else "stale"
            return SourceFreshness(
                name=name,
                last_record=last_record,
                age_seconds=age_seconds,
                state=state,
                records_per_hour=records_per_hour,
                expected_interval_seconds=self._expected_interval_seconds,
            )

        return await asyncio.to_thread(_run)

    async def _get_detection(self, now: datetime) -> DetectionFreshness:
        """Derive detection-cycle freshness."""

        def _run() -> DetectionFreshness:
            last_cycle = self._postgres.query_last_anomaly_time()
            if last_cycle is None:
                return DetectionFreshness(
                    last_cycle=None,
                    age_seconds=None,
                    duration_seconds=None,
                    series_evaluated=None,
                )
            age_seconds = int((now - last_cycle).total_seconds())
            since = last_cycle - timedelta(seconds=self.RECENT_WINDOW_SECONDS)
            series_evaluated = self._postgres.query_recent_anomaly_series_count(since, last_cycle)
            return DetectionFreshness(
                last_cycle=last_cycle,
                age_seconds=age_seconds,
                duration_seconds=None,
                series_evaluated=series_evaluated,
            )

        return await asyncio.to_thread(_run)

    async def get_attention(self) -> list[dict[str, Any]]:
        """Aggregate available operational attention findings.

        Wave A only emits findings for stale pipeline sources. Additional
        fact sources (NoBounds, storage, backup) will be added by later
        waves and are intentionally omitted rather than fabricated.

        Returns:
            A list of attention finding dicts matching
            :class:`AttentionFinding`.
        """
        findings: list[dict[str, Any]] = []
        pipeline = await self.get_pipeline()
        for source in pipeline.sources:
            label = FRIENDLY_LABELS.get(source.name, source.name)
            if source.state == "stale":
                age_text = _humanize_stale_age(source.age_seconds)
                findings.append(
                    {
                        "priority": "High",
                        "kind": "warn",
                        "title": f"{label} source stale — {age_text} since last record",
                        "link": {"label": "Data Sources", "route": "/operations/data-sources"},
                    }
                )
            elif source.state == "no-data":
                findings.append(
                    {
                        "priority": "High",
                        "kind": "err",
                        "title": f"{label} source has no data",
                        "link": {"label": "Data Sources", "route": "/operations/data-sources"},
                    }
                )

        logger.debug("Operations attention findings: {} available", len(findings))
        return findings
