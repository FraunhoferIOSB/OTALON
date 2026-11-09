"""Anomaly details service for alarm group drill-down data.

Provides methods for retrieving detailed anomaly information including
parsed UCI entities for an alarm group.
"""

from __future__ import annotations

from typing import Any

from loguru import logger

from otalon_api.domain.anomaly.processing import parse_uci_to_entity
from otalon_api.domain.netcap.proto_resolver import ProtoHashResolver
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.settings import Settings
from otalon_api.utils import run_in_thread


class AnomalyDetailsService:
    """Service for detailed anomaly drill-down data."""

    def __init__(
        self,
        postgres_repo: PostgresRepository,
        settings: Settings,
        proto_resolver: ProtoHashResolver | None = None,
    ) -> None:
        """Initialize the anomaly details service.

        Args:
            postgres_repo: PostgreSQL repository for anomaly data access.
            settings: Application settings.
            proto_resolver: Optional resolver for proto hash → protocol.
        """
        self._repo = postgres_repo
        self._settings = settings
        self._proto_resolver = proto_resolver

    @run_in_thread
    def get_group_entities(self, group_id: str) -> dict[str, Any]:
        """Retrieve parsed UCI entities for an alarm group.

        Loads the alarm group by ID, extracts its ``series_ids``, and
        parses each UCI into a human-readable entity dict matching the
        GD-08 golden-data format.

        Args:
            group_id: The alarm group UUID.

        Returns:
            Response dict with ``data``, ``row_count``, and ``parameters``.

        Raises:
            ValueError: If the group_id is not found.
        """
        logger.debug("get_group_entities group_id={}", group_id)

        group = self._repo.get_anomaly_group_by_id(group_id)
        if group is None:
            raise ValueError(f"Alarm group not found: {group_id}")

        series_ids = group.get("series_ids", [])
        if not isinstance(series_ids, list):
            series_ids = []

        if group.get("module") == "proto_traffic" and self._proto_resolver is not None:
            entities = [
                {
                    "series_id": str(sid),
                    "protocol": self._proto_resolver.resolve(str(sid)),
                }
                for sid in series_ids
            ]
        else:
            entities = [parse_uci_to_entity(str(sid)) for sid in series_ids]

        logger.debug(
            "get_group_entities result: {} entities for group {}",
            len(entities),
            group_id,
        )

        return {
            "data": entities,
            "row_count": len(entities),
            "parameters": {
                "alarm_id": group_id,
                "total_series": len(series_ids),
            },
        }

    @run_in_thread
    def get_group_anomalies(self, group_id: str) -> dict[str, Any]:
        """Retrieve individual anomaly records for an alarm group.

        Args:
            group_id: The alarm group UUID.

        Returns:
            Response dict with ``data``, ``row_count``, and ``parameters``.

        Raises:
            ValueError: If the group_id is not found.
        """
        logger.debug("get_group_anomalies group_id={}", group_id)

        group = self._repo.get_anomaly_group_by_id(group_id)
        if group is None:
            raise ValueError(f"Alarm group not found: {group_id}")

        rows = self._repo.query_anomaly_group_series(group_id)
        rows = _normalize_timestamps_in_rows(rows)
        if group.get("module") == "proto_traffic" and self._proto_resolver is not None:
            for row in rows:
                row["protocol"] = self._proto_resolver.resolve(row.get("series_id", ""))

        return {
            "data": rows,
            "row_count": len(rows),
            "parameters": {"alarm_group_id": group_id},
        }


def _normalize_timestamps_in_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert datetime objects to ISO-8601 Z-strings in row dicts.

    Args:
        rows: List of row dicts from PostgreSQL.

    Returns:
        The same list with timestamp values formatted as strings.
    """
    import pandas as pd

    ts_keys = ("start_ts", "end_ts", "start_timestamp", "end_timestamp")
    for row in rows:
        for key in ts_keys:
            if key in row and row[key] is not None:
                try:
                    t = pd.Timestamp(row[key])
                    if t.tz is not None:
                        t = t.tz_localize(None)
                    row[key] = t.strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    row[key] = str(row[key])
    return rows
