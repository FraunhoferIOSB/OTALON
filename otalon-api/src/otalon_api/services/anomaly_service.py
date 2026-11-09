"""Anomaly service for alarm group management and anomaly queries.

Provides methods for querying anomaly detection results, alarm groups,
alarm intervals, and updating alarm group status via PostgreSQL.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from loguru import logger

from otalon_api.domain.netcap.proto_resolver import ProtoHashResolver
from otalon_api.domain.time import time_policy
from otalon_api.domain.topology.uci import base_key_without_ports, parse_uci
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.settings import Settings
from otalon_api.utils import run_in_thread


class AnomalyService:
    """Service for anomaly data retrieval and processing."""

    def __init__(
        self,
        postgres_repo: PostgresRepository,
        settings: Settings,
        proto_resolver: ProtoHashResolver | None = None,
    ) -> None:
        """Initialize the anomaly service.

        Args:
            postgres_repo: PostgreSQL repository for anomaly data access.
            settings: Application settings.
            proto_resolver: Optional resolver for proto hash → protocol.
        """
        self._repo = postgres_repo
        self._settings = settings
        self._proto_resolver = proto_resolver

    @run_in_thread
    def get_anomaly_series(
        self,
        module: str,
        series_id: str | None = None,
        start: datetime | None = None,
        stop: datetime | None = None,
    ) -> dict[str, Any]:
        """Query anomaly intervals for a given module and optional series.

        Args:
            module: Detection module name (e.g. ``"netcap"``).
            series_id: Optional UCI / series identifier to filter by.
            start: Optional range start in local time.
            stop: Optional range end in local time.

        Returns:
            Response dict with ``data``, ``row_count``, and ``parameters``.
        """
        time_range = None
        start_str, stop_str = None, None
        if start is not None and stop is not None:
            start_str, stop_str = time_policy.ui_to_pg_query_range(start, stop)
            time_range = (start_str, stop_str)

        logger.debug(
            "get_anomaly_series module={} series_id={} time_range={}",
            module,
            series_id,
            time_range,
        )

        rows = self._repo.query_anomalies(module=module, series_id=series_id, time_range=time_range)
        rows = _normalize_timestamps_in_rows(rows)
        if module == "proto_traffic" and self._proto_resolver is not None:
            for row in rows:
                row["protocol"] = self._proto_resolver.resolve(row.get("series_id", ""))

        return {
            "data": rows,
            "row_count": len(rows),
            "parameters": {
                "module": module,
                "series_id": series_id,
                "start": start_str,
                "stop": stop_str,
            },
        }

    @run_in_thread
    def get_anomaly_groups(
        self,
        module: str | None = None,
        start: datetime | None = None,
        stop: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Query alarm groups with optional module and time-range filters.

        The ``anomaly_type_stats`` JSON column is automatically
        deserialized by the repository layer.

        Args:
            module: Optional module filter (e.g. ``"netcap"``).
            start: Optional range start in local time.
            stop: Optional range end in local time.
            limit: Maximum number of groups to return.
            offset: Number of groups to skip for pagination.

        Returns:
            Response dict with ``data``, ``row_count`` (total matching, not page count), and ``parameters``.
        """
        time_range = None
        if start is not None and stop is not None:
            start_str, stop_str = time_policy.ui_to_pg_query_range(start, stop)
            time_range = (start_str, stop_str)

        logger.debug(
            "get_anomaly_groups module={} time_range={} limit={} offset={}",
            module,
            time_range,
            limit,
            offset,
        )

        total_count = self._repo.count_anomaly_groups(module=module, time_range=time_range)
        rows = self._repo.query_anomaly_groups(
            module=module,
            time_range=time_range,
            limit=limit,
            offset=offset,
        )
        rows = _normalize_timestamps_in_rows(rows)
        rows = _stringify_ids(rows)
        for row in rows:
            series_ids = row.get("series_ids", [])
            if isinstance(series_ids, list):
                row["series_ids"] = _expand_series_ids_with_wildcards(
                    [str(s) for s in series_ids],
                )
        if self._proto_resolver is not None:
            for row in rows:
                series_ids = row.get("series_ids", [])
                if not isinstance(series_ids, list):
                    continue
                hash_ids = [str(s) for s in series_ids if str(s).isdigit()]
                resolved = dict(zip(hash_ids, self._proto_resolver.resolve_many(hash_ids)))
                row["protocols"] = [resolved.get(str(series_id)) for series_id in series_ids]

        return {
            "data": rows,
            "row_count": total_count,
            "parameters": {"module": module, "limit": limit, "offset": offset},
        }

    @run_in_thread
    def get_anomaly_intervals(
        self,
        uci: str,
        module: str | None = None,
        start: datetime | None = None,
        stop: datetime | None = None,
        limit: int = 200,
        match_uci: str | None = None,
    ) -> dict[str, Any]:
        """Get alarm intervals that overlap with a specific UCI.

        Loads alarm groups, filters those whose ``series_ids`` contain
        the match key, and returns simplified interval records.

        For most modules the plaintext ``uci`` is matched directly. The
        ``proto_traffic`` module persists ``series_ids`` as a stable hash
        of the protocol stack, so the caller passes the hashed key via
        ``match_uci`` while ``uci`` stays the human-readable stack used
        in the response ``parameters``.

        Args:
            uci: Unique communication identifier; echoed in parameters.
            module: Optional module filter.
            start: Optional range start in local time.
            stop: Optional range end in local time.
            limit: Maximum number of groups to scan.
            match_uci: Optional override key matched against
                ``series_ids`` instead of ``uci`` (e.g. the proto hash).

        Returns:
            Response dict with ``data``, ``row_count``, and ``parameters``.
        """
        time_range = None
        start_str, stop_str = None, None
        if start is not None and stop is not None:
            start_str, stop_str = time_policy.ui_to_pg_query_range(start, stop)
            time_range = (start_str, stop_str)

        logger.debug(
            "get_anomaly_intervals uci={} module={} time_range={}",
            uci,
            module,
            time_range,
        )

        groups = self._repo.query_anomaly_groups(module=module, time_range=time_range, limit=limit)
        for group in groups:
            series_ids = group.get("series_ids", [])
            if isinstance(series_ids, list):
                group["series_ids"] = _expand_series_ids_with_wildcards(
                    [str(s) for s in series_ids],
                )

        intervals = _build_intervals_for_uci(groups, match_uci if match_uci is not None else uci)

        return {
            "data": intervals,
            "row_count": len(intervals),
            "parameters": {
                "uci": uci,
                "start": start_str,
                "stop": stop_str,
                "groups_count": len(groups),
            },
        }

    @run_in_thread
    def update_group_confirmed(self, group_id: str, confirmed: bool) -> dict[str, Any]:
        """Update the confirmed status of an alarm group.

        Args:
            group_id: The alarm group UUID.
            confirmed: New confirmed status value.

        Returns:
            Response dict with the update result.

        Raises:
            ValueError: If the group_id is not found.
        """
        logger.debug("update_group_confirmed group_id={} confirmed={}", group_id, confirmed)
        existing = self._repo.get_anomaly_group_by_id(group_id)
        if existing is None:
            raise ValueError(f"Alarm group not found: {group_id}")

        success = self._repo.update_alarm_group_confirmed(group_id, confirmed)
        if not success:
            raise ValueError(f"Failed to update alarm group: {group_id}")

        updated = self._repo.get_anomaly_group_by_id(group_id)
        return {
            "data": updated,
            "parameters": {"group_id": group_id, "confirmed": confirmed},
        }

    @run_in_thread
    def update_group_primary_type(self, group_id: str, primary_type: str) -> dict[str, Any]:
        """Replace the ``primary_type`` of an alarm group.

        Used by the *Adopt Subagent Classification* operator action: the
        operator overrides the supervised-ML attack-method label with the
        zero-shot LLM subagent's Step-1 ``technical_method``. The change is
        non-destructive in the sense that all original anomaly statistics
        remain intact; only the headline label changes.

        Args:
            group_id: The alarm group ID.
            primary_type: New attack-method label (free-form string).

        Returns:
            Response dict with the updated alarm row and parameters.

        Raises:
            ValueError: If the group is not found or update fails.
        """
        logger.debug(
            "update_group_primary_type group_id={} primary_type={}",
            group_id,
            primary_type,
        )
        if not primary_type or not primary_type.strip():
            raise ValueError("primary_type must be a non-empty string")
        existing = self._repo.get_anomaly_group_by_id(group_id)
        if existing is None:
            raise ValueError(f"Alarm group not found: {group_id}")

        success = self._repo.update_alarm_group_primary_type(group_id, primary_type.strip())
        if not success:
            raise ValueError(f"Failed to update alarm group: {group_id}")

        updated = self._repo.get_anomaly_group_by_id(group_id)
        return {
            "data": updated,
            "parameters": {"group_id": group_id, "primary_type": primary_type.strip()},
        }


def _expand_series_ids_with_wildcards(series_ids: list[str]) -> list[str]:
    """Expand conn-style series IDs to include wildcard UCI variants.

    When multiple conn UCIs in *series_ids* share the same base key but
    differ in port numbers, a wildcard UCI (with ``*`` in the
    heterogeneous port position(s)) is appended.  This ensures alarm
    filters on the connections page match wildcard-grouped rows that the
    frontend displays after UI-002.

    Non-conn identifiers (MACs, proto hashes, etc.) are left untouched.

    Args:
        series_ids: List of series identifier strings from an alarm group.

    Returns:
        The original identifiers plus any newly-derived wildcard UCIs.
    """
    result = list(series_ids)
    conn_ucis = [sid for sid in series_ids if isinstance(sid, str) and sid.count("/") == 8]
    if len(conn_ucis) < 2:
        return result

    groups: dict[tuple[str, ...], list[str]] = {}
    for uci in conn_ucis:
        key = base_key_without_ports(uci)
        groups.setdefault(key, []).append(uci)

    for members in groups.values():
        if len(members) < 2:
            continue
        src_ports = {parse_uci(m).src_port for m in members}
        dst_ports = {parse_uci(m).dst_port for m in members}
        sp = next(iter(src_ports)) if len(src_ports) == 1 else "*"
        dp = next(iter(dst_ports)) if len(dst_ports) == 1 else "*"
        src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, protocols = base_key_without_ports(members[0])
        wildcard = "/".join([src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, sp, dp, protocols])
        if wildcard not in result:
            result.append(wildcard)

    return result


def _build_intervals_for_uci(groups: list[dict[str, Any]], uci: str) -> list[dict[str, Any]]:
    """Filter alarm groups to those containing the given UCI.

    Args:
        groups: List of alarm group dicts.
        uci: UCI string to match in ``series_ids``.

    Returns:
        List of simplified interval dicts.
    """
    intervals: list[dict[str, Any]] = []
    for group in groups:
        series_ids = group.get("series_ids", [])
        if not isinstance(series_ids, list):
            continue
        if uci not in series_ids:
            continue
        start_ts = group.get("start_timestamp")
        end_ts = group.get("end_timestamp")
        raw_type = group.get("primary_type")
        if isinstance(raw_type, list):
            anomaly_type = ", ".join(str(t) for t in raw_type)
        elif raw_type is not None:
            anomaly_type = str(raw_type)
        else:
            anomaly_type = None
        intervals.append(
            {
                "start_timestamp": _format_ts(start_ts),
                "end_timestamp": _format_ts(end_ts),
                "alarm_group_id": str(group.get("id", "")),
                "anomaly_type": anomaly_type,
            }
        )
    return intervals


def _normalize_timestamps_in_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert datetime objects to naive local-time ISO-8601 strings in row dicts.

    Handles ``start_timestamp``, ``end_timestamp``, ``start_ts``,
    ``end_ts``, and ``last_alarm_timestamp`` column names.

    Args:
        rows: List of row dicts from PostgreSQL.

    Returns:
        The same list with timestamp values formatted as strings.
    """
    ts_keys = (
        "start_timestamp",
        "end_timestamp",
        "start_ts",
        "end_ts",
        "last_alarm_timestamp",
    )
    for row in rows:
        for key in ts_keys:
            if key in row and row[key] is not None:
                row[key] = _format_ts(row[key])
    return rows


def _stringify_ids(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ensure ``id`` fields are strings (UUIDs may be UUID objects).

    Args:
        rows: List of row dicts.

    Returns:
        The same list with ``id`` values cast to strings.
    """
    for row in rows:
        if "id" in row and row["id"] is not None:
            row["id"] = str(row["id"])
    return rows


def _format_ts(ts: Any) -> str:
    """Format a timestamp as a local-time ISO-8601 string with UTC offset.

    PostgreSQL stores UTC timestamps.  The frontend displays timestamps
    as-is without conversion, so we convert to local wall-clock time
    before formatting.  The string carries the explicit UTC offset so
    UTC clients interpret it correctly (API-072).

    Args:
        ts: A datetime-like value.

    Returns:
        Local-time ISO-8601 string with offset, or empty string on failure.
    """
    if ts is None:
        return ""
    try:
        return time_policy.to_local_offset_string(ts)
    except Exception:
        return str(ts)
