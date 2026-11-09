"""Dashboard KPI service for aggregated metrics computation.

Provides methods for computing key performance indicators displayed on
the main dashboard including signal color, anomaly counts, device and
connection counts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, cast

from loguru import logger

from otalon_api.domain.anomaly.processing import compute_signal_color_from_groups
from otalon_api.domain.netcap.models import proto_series_hash
from otalon_api.domain.time import time_policy
from otalon_api.domain.topology.uci import base_key_without_ports, parse_uci
from otalon_api.repositories.cache import CacheManager
from otalon_api.repositories.influx_repo import InfluxRepository, is_broadcast_or_multicast_mac
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.settings import Settings
from otalon_api.utils import run_in_thread

_DEFAULT_THROUGHPUT_WINDOW = timedelta(hours=1)


class DashboardKpiService:
    """Service for dashboard KPI computation."""

    def __init__(
        self,
        postgres_repo: PostgresRepository,
        influx_repo: InfluxRepository,
        settings: Settings,
        cache_manager: CacheManager | None = None,
    ) -> None:
        """Initialize the dashboard KPI service.

        Args:
            postgres_repo: PostgreSQL repository for data access.
            influx_repo: InfluxDB repository for time-series queries.
            settings: Application settings.
            cache_manager: Optional shared cache manager. When provided,
                :meth:`get_kpis` results are cached under the
                ``"dashboard_kpis"`` namespace for the cache's TTL.
                When ``None``, the legacy uncached behaviour is used —
                keeping the constructor backward-compatible for tests
                that instantiate the service directly.
        """
        self._repo = postgres_repo
        self._influx_repo = influx_repo
        self._settings = settings
        self._cache = cache_manager

    @run_in_thread
    def get_vulnerability_summary(self) -> dict[str, Any]:
        """Fetch aggregated vulnerability data for the dashboard widget.

        Returns:
            Response dict with ``data`` (a single VulnerabilitySummaryData
            record) and ``parameters``.
        """
        summary = self._repo.query_vulnerability_summary()
        return {
            "data": summary,
            "parameters": {},
        }

    @run_in_thread
    def get_throughput(
        self,
        start: datetime | None = None,
        stop: datetime | None = None,
        buckets: int = 60,
    ) -> dict[str, Any]:
        """Query aggregated network throughput for the sparkline widget.

        Delegates to :meth:`InfluxRepository.query_network_throughput`
        and wraps the result in a response dict matching
        :class:`ThroughputResponse`.

        Args:
            start: Optional range start in local time.  Defaults to
                one hour ago.
            stop: Optional range end in local time.  Defaults to now.
            buckets: Desired number of time buckets (default 60).

        Returns:
            Response dict with ``data``, ``bucket_seconds``, and
            ``parameters`` keys.
        """
        stop_str = _resolve_stop(stop)
        if start is None:
            start_dt = datetime.now(tz=timezone.utc) - _DEFAULT_THROUGHPUT_WINDOW
            start_str = _resolve_since(start_dt)
        else:
            start_str = _resolve_since(start)

        logger.debug("get_throughput start={} stop={} buckets={}", start_str, stop_str, buckets)

        rows, bucket_seconds = self._influx_repo.query_network_throughput(
            measurement=self._settings.netcap_measurement,
            start=start_str,
            stop=stop_str,
            buckets=buckets,
        )

        return {
            "data": rows,
            "bucket_seconds": bucket_seconds,
            "parameters": {
                "start": _format_ts(start) if start else start_str,
                "stop": _format_ts(stop) if stop else stop_str,
                "buckets": buckets,
            },
        }

    @run_in_thread
    def get_kpis(
        self,
        start: datetime | None = None,
        stop: datetime | None = None,
    ) -> dict[str, Any]:
        """Compute dashboard KPIs for the given time window.

        Aggregates anomaly counts, group counts, device counts, and
        connection counts from PostgreSQL.  The signal color is derived
        from the alarm group data.

        When a shared :class:`CacheManager` was injected, the result is
        cached under the ``"dashboard_kpis"`` namespace keyed by
        ``(start_iso, stop_iso)``. The cache uses a short TTL (default
        30 s) — no write-path invalidation — so KPI panels can refresh
        rapidly without paying the full aggregation cost on every poll.

        Args:
            start: Optional range start in local time.
            stop: Optional range end in local time.

        Returns:
            Response dict with ``data`` (list containing one KPI record),
            ``row_count``, and ``parameters``.
        """
        since_str = _resolve_since(start)
        stop_str = _resolve_stop(stop)

        if self._cache is not None:
            cache_key = f"kpis:{since_str}|{stop_str}"
            return cast(
                dict[str, Any],
                self._cache.get_or_compute(
                    "dashboard_kpis",
                    cache_key,
                    lambda: self._compute_kpis(start, stop, since_str, stop_str),
                ),
            )

        return self._compute_kpis(start, stop, since_str, stop_str)

    @run_in_thread
    def get_top_assets(
        self,
        start: datetime | None = None,
        stop: datetime | None = None,
        limit: int = 5,
    ) -> dict[str, Any]:
        """Compute top assets (MAC addresses) for the given time window.

        Queries InfluxDB ``mac_traffic`` for the busiest MACs by packet
        count, fetches per-MAC sparklines, and cross-references
        ``mac_traffic`` alarm groups from PostgreSQL to set the anomaly
        flag.

        Args:
            start: Optional range start in local time.
            stop: Optional range end in local time.
            limit: Number of top assets to return (default 5).

        Returns:
            Response dict with ``data`` (list of top asset records),
            ``row_count``, and ``parameters``.
        """
        since_str = _resolve_since(start)
        stop_str = _resolve_stop(stop)

        logger.debug("get_top_assets since={} stop={} limit={}", since_str, stop_str, limit)

        raw_rows = self._influx_repo.query_top_mac_addresses(
            start=since_str,
            stop=stop_str,
            limit=limit,
        )

        mac_ids = [row["id"] for row in raw_rows]
        sparklines = _fetch_mac_sparklines(self._influx_repo, mac_ids, since_str, stop_str)

        groups = self._repo.query_anomaly_groups(
            module="mac_traffic",
            time_range=(since_str, stop_str),
            limit=200,
        )
        anomaly_ids = _extract_anomaly_series_ids(groups)

        data = []
        for row in raw_rows:
            mac = row["id"]
            data.append(
                {
                    "id": mac,
                    "packet_count": row["total_packets"],
                    "byte_count": row["total_bytes"],
                    "is_anomaly": mac in anomaly_ids,
                    "sparkline": sparklines.get(mac, []),
                }
            )

        return {
            "data": data,
            "row_count": len(data),
            "parameters": {
                "start": _format_ts(start) if start else None,
                "stop": _format_ts(stop) if stop else None,
                "limit": limit,
            },
        }

    @run_in_thread
    def get_top_protocols(
        self,
        start: datetime | None = None,
        stop: datetime | None = None,
        limit: int = 5,
    ) -> dict[str, Any]:
        """Compute top protocols for the given time window.

        Queries InfluxDB ``proto_traffic`` for the busiest protocol
        stacks by packet count, fetches per-protocol sparklines, and
        cross-references ``proto_traffic`` alarm groups from PostgreSQL.
        Because proto anomaly groups persist ``series_ids`` as a stable
        hash of the plaintext protocol, each protocol is hashed before
        the anomaly lookup.

        Args:
            start: Optional range start in local time.
            stop: Optional range end in local time.
            limit: Number of top protocols to return (default 5).

        Returns:
            Response dict with ``data`` (list of top protocol records),
            ``row_count``, and ``parameters``.
        """
        since_str = _resolve_since(start)
        stop_str = _resolve_stop(stop)

        logger.debug("get_top_protocols since={} stop={} limit={}", since_str, stop_str, limit)

        raw_rows = self._influx_repo.query_top_protocols(
            start=since_str,
            stop=stop_str,
            limit=limit,
        )

        proto_ids = [row["id"] for row in raw_rows]
        sparklines = _fetch_proto_sparklines(self._influx_repo, proto_ids, since_str, stop_str)

        groups = self._repo.query_anomaly_groups(
            module="proto_traffic",
            time_range=(since_str, stop_str),
            limit=200,
        )
        anomaly_hashes = _extract_anomaly_series_ids(groups)

        data = []
        for row in raw_rows:
            proto = row["id"]
            proto_hash = proto_series_hash(proto)
            data.append(
                {
                    "id": proto,
                    "protocol": proto,
                    "packet_count": row["total_packets"],
                    "byte_count": row["total_bytes"],
                    "is_anomaly": proto_hash in anomaly_hashes,
                    "sparkline": sparklines.get(proto, []),
                }
            )

        return {
            "data": data,
            "row_count": len(data),
            "parameters": {
                "start": _format_ts(start) if start else None,
                "stop": _format_ts(stop) if stop else None,
                "limit": limit,
            },
        }

    def _compute_kpis(
        self,
        start: datetime | None,
        stop: datetime | None,
        since_str: str,
        stop_str: str,
    ) -> dict[str, Any]:
        """Pure-compute body of :meth:`get_kpis` (extracted for caching).

        Args:
            start: Original ``start`` argument (kept for parameter echo).
            stop: Original ``stop`` argument (kept for parameter echo).
            since_str: Pre-resolved ``start`` string for repository
                queries.
            stop_str: Pre-resolved ``stop`` string for repository
                queries.

        Returns:
            Same shape as :meth:`get_kpis`.
        """

        logger.debug("get_kpis since={} stop={}", since_str, stop_str)

        kpi_row = self._repo.query_dashboard_kpis(since=since_str)

        groups = self._repo.query_anomaly_groups(
            module=None,
            time_range=(since_str, stop_str),
            limit=200,
        )

        signal_color = compute_signal_color_from_groups(groups)

        anomaly_count = int(kpi_row.get("total_alarm_groups", 0) or 0)
        classified_count = _count_classified(groups)
        anomaly_limit_reached = bool(kpi_row.get("anomaly_limit_reached", False))

        active_devices = self._influx_repo.list_ids_between(
            measurement="mac_traffic",
            id_tag="mac_address",
            start=since_str,
            stop=stop_str,
        )
        device_count = sum(not is_broadcast_or_multicast_mac(mac) for mac in active_devices)
        protocol_count = self._influx_repo.query_protocol_count(start=since_str, stop=stop_str)
        active_ucis = self._influx_repo.list_ids_between(
            measurement=self._settings.netcap_measurement,
            id_tag=self._settings.netcap_id_tag,
            start=since_str,
            stop=stop_str,
        )
        connection_count = _count_wildcard_groups(active_ucis)

        all_connections_raw = self._influx_repo.query_top_connections(
            measurement=self._settings.netcap_measurement,
            id_tag=self._settings.netcap_id_tag,
            start=since_str,
            stop=stop_str,
            limit=10000,
        )

        top_grouped = _aggregate_top_connections(all_connections_raw, limit=5)

        anomaly_ucis = _extract_anomaly_ucis(groups)

        all_member_ucis: list[str] = []
        for entry in top_grouped:
            all_member_ucis.extend(entry["members"])
        sparklines = _fetch_sparklines(self._influx_repo, all_member_ucis, since_str, stop_str)

        top_connections = []
        for entry in top_grouped:
            merged_sparkline = _merge_sparklines(sparklines, entry["members"])
            has_anomaly = any(m in anomaly_ucis for m in entry["members"])
            top_connections.append(
                {
                    "uci": entry["uci"],
                    "packet_count": entry["total_packets"],
                    "byte_count": entry["total_bytes"],
                    "is_anomaly": has_anomaly,
                    "sparkline": merged_sparkline,
                }
            )

        kpi_data = {
            "signal_color": signal_color,
            "anomaly_count": anomaly_count,
            "classified_count": classified_count,
            "device_count": device_count,
            "protocol_count": protocol_count,
            "connection_count": connection_count,
            "top_connections": top_connections,
            "anomaly_limit_reached": anomaly_limit_reached,
        }

        logger.debug("get_kpis result: {}", kpi_data)

        return {
            "data": [kpi_data],
            "row_count": 1,
            "parameters": {
                "start": _format_ts(start) if start else None,
                "stop": _format_ts(stop) if stop else None,
            },
        }


def _extract_anomaly_ucis(groups: list[dict[str, Any]]) -> set[str]:
    """Extract UCIs from active, unconfirmed alarm groups.

    Args:
        groups: List of alarm group dicts from PostgreSQL.

    Returns:
        Set of UCI strings that appear in active unconfirmed groups.
    """
    return _extract_anomaly_series_ids(groups)


def _extract_anomaly_series_ids(groups: list[dict[str, Any]]) -> set[str]:
    """Extract series IDs from active, unconfirmed alarm groups.

    Args:
        groups: List of alarm group dicts from PostgreSQL.

    Returns:
        Set of series ID strings that appear in active unconfirmed groups.
    """
    ids: set[str] = set()
    for g in groups:
        if g.get("is_active") and not g.get("confirmed"):
            for sid in g.get("series_ids", []):
                ids.add(str(sid))
    return ids


def _count_wildcard_groups(ucis: list[str]) -> int:
    """Count connections after wildcard grouping.

    UCIs that share the same base key (MAC pair, VLAN, IP proto, IPs,
    protocol) but differ only in ports are collapsed into a single
    group — matching the Connection table on the frontend.

    Args:
        ucis: Raw UCI strings from InfluxDB.

    Returns:
        Number of distinct connection groups.
    """
    if not ucis:
        return 0
    keys: set[tuple[str, ...]] = set()
    for uci in ucis:
        try:
            keys.add(base_key_without_ports(uci))
        except Exception:
            keys.add((uci,))
    return len(keys)


def _count_classified(groups: list[dict[str, Any]]) -> int:
    """Count alarm groups that have a non-unknown primary_type.

    Args:
        groups: List of alarm group dicts.

    Returns:
        Number of classified groups.
    """
    count = 0
    for g in groups:
        ptype = g.get("primary_type", "unknown")
        if ptype and str(ptype).lower() != "unknown":
            count += 1
    return count


def _resolve_since(start: datetime | None) -> str:
    """Convert start datetime to a Z-string for PostgreSQL queries.

    Falls back to epoch (``"1970-01-01T00:00:00Z"``) if *start* is not
    provided, effectively querying all data.

    Args:
        start: Optional start datetime.

    Returns:
        An ISO-8601 Z-string.
    """
    if start is None:
        return "1970-01-01T00:00:00Z"
    start_str, _ = time_policy.ui_to_pg_query_range(start, start)
    return start_str


def _resolve_stop(stop: datetime | None) -> str:
    """Convert stop datetime to a Z-string for PostgreSQL queries.

    Falls back to the current UTC time if *stop* is not provided.

    Args:
        stop: Optional stop datetime.

    Returns:
        An ISO-8601 Z-string.
    """
    if stop is None:
        return time_policy.to_utc_z_string(datetime.now(tz=timezone.utc))
    _, stop_str = time_policy.ui_to_pg_query_range(stop, stop)
    return stop_str


def _format_ts(dt: datetime) -> str:
    """Format a datetime to a local-time ISO-8601 string with UTC offset.

    Converts UTC-aware timestamps to local wall-clock time before
    formatting, since the frontend displays timestamps as-is.  The
    string carries the explicit UTC offset so UTC clients interpret
    it correctly (API-072).

    Args:
        dt: A datetime value.

    Returns:
        Local-time ISO-8601 string with UTC offset.
    """
    try:
        return time_policy.to_local_offset_string(dt)
    except Exception:
        return str(dt)


def _fetch_sparklines(
    influx_repo: InfluxRepository,
    ucis: list[str],
    start: str,
    stop: str,
) -> dict[str, list[int]]:
    """Fetch sparkline data for a list of UCIs.

    Delegates to :meth:`InfluxRepository.query_connection_sparklines`.
    Returns an empty dict when the UCI list is empty or the query fails.

    Args:
        influx_repo: InfluxDB repository instance.
        ucis: List of UCI strings to query sparklines for.
        start: ISO-8601 start timestamp.
        stop: ISO-8601 stop timestamp.

    Returns:
        Dict mapping UCI to a list of total_volume integers per bucket.
    """
    if not ucis:
        return {}
    try:
        return influx_repo.query_connection_sparklines(ucis, start, stop)
    except Exception as exc:
        logger.warning("Failed to fetch sparklines for top connections: {}", exc)
        return {}


def _fetch_mac_sparklines(
    influx_repo: InfluxRepository,
    macs: list[str],
    start: str,
    stop: str,
) -> dict[str, list[int]]:
    """Fetch sparkline data for a list of MAC addresses.

    Delegates to :meth:`InfluxRepository.query_mac_sparklines`.
    Returns an empty dict when the MAC list is empty or the query fails.

    Args:
        influx_repo: InfluxDB repository instance.
        macs: List of MAC address strings.
        start: ISO-8601 start timestamp.
        stop: ISO-8601 stop timestamp.

    Returns:
        Dict mapping MAC to a list of total bytes integers per bucket.
    """
    if not macs:
        return {}
    try:
        return influx_repo.query_mac_sparklines(macs, start, stop)
    except Exception as exc:
        logger.warning("Failed to fetch sparklines for top assets: {}", exc)
        return {}


def _fetch_proto_sparklines(
    influx_repo: InfluxRepository,
    protocols: list[str],
    start: str,
    stop: str,
) -> dict[str, list[int]]:
    """Fetch sparkline data for a list of protocol stacks.

    Delegates to :meth:`InfluxRepository.query_proto_sparklines`.
    Returns an empty dict when the protocol list is empty or the query fails.

    Args:
        influx_repo: InfluxDB repository instance.
        protocols: List of protocol stack strings.
        start: ISO-8601 start timestamp.
        stop: ISO-8601 stop timestamp.

    Returns:
        Dict mapping protocol to a list of total bytes integers per bucket.
    """
    if not protocols:
        return {}
    try:
        return influx_repo.query_proto_sparklines(protocols, start, stop)
    except Exception as exc:
        logger.warning("Failed to fetch sparklines for top protocols: {}", exc)
        return {}


def _aggregate_top_connections(
    raw_rows: list[dict[str, Any]],
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Group raw UCI rows by base key and rank by aggregated volume.

    UCIs that share the same base key (MAC pair, VLAN, IP proto, IPs,
    protocol) but differ only in ports are merged into a single wildcard
    group.  Volumes are summed across all members.  The result is sorted
    by ``total_packets`` descending and limited to *limit* entries.

    Each returned entry contains the wildcard UCI string, aggregated
    totals, and the list of member UCIs for sparkline fetching.

    Args:
        raw_rows: Per-UCI rows from ``query_top_connections()``, each
            with keys ``uci``, ``total_packets``, ``total_bytes``.
        limit: Maximum number of groups to return.

    Returns:
        List of dicts with ``uci``, ``total_packets``, ``total_bytes``,
        and ``members``.
    """
    groups: dict[tuple[str, str, str, str, str, str, str], dict[str, Any]] = {}

    for row in raw_rows:
        uci = row.get("uci", "")
        try:
            key = base_key_without_ports(uci)
        except Exception:
            key = (uci, "", "", "", "", "", "")
        if key not in groups:
            groups[key] = {
                "total_packets": 0,
                "total_bytes": 0,
                "members": [],
            }
        groups[key]["total_packets"] += int(row.get("total_packets", 0) or 0)
        groups[key]["total_bytes"] += int(row.get("total_bytes", 0) or 0)
        groups[key]["members"].append(uci)

    ranked: list[dict[str, Any]] = []
    for key, data in groups.items():
        src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, protocols = key
        members = data["members"]
        src_ports = {parse_uci(m)[6] for m in members}
        dst_ports = {parse_uci(m)[7] for m in members}
        sp = next(iter(src_ports)) if len(src_ports) == 1 else "*"
        dp = next(iter(dst_ports)) if len(dst_ports) == 1 else "*"
        wildcard_uci = "/".join([src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, sp, dp, protocols])

        ranked.append(
            {
                "uci": wildcard_uci,
                "total_packets": data["total_packets"],
                "total_bytes": data["total_bytes"],
                "members": members,
            }
        )

    ranked.sort(key=lambda x: x["total_packets"], reverse=True)
    return ranked[:limit]


def _merge_sparklines(
    sparklines: dict[str, list[int]],
    member_ucis: list[str],
) -> list[int]:
    """Merge sparkline data from multiple member UCIs into one.

    Sums the per-bucket values across all member UCIs.  If no member
    has sparkline data, returns an empty list.

    Args:
        sparklines: Dict mapping UCI to sparkline (list of ints per bucket).
        member_ucis: List of member UCI strings belonging to the group.

    Returns:
        Merged sparkline as a list of integers, or empty list.
    """
    member_data = [sparklines[u] for u in member_ucis if u in sparklines]
    if not member_data:
        return []
    max_len = max(len(s) for s in member_data)
    merged = [0] * max_len
    for series in member_data:
        for i, val in enumerate(series):
            merged[i] += val
    return merged
