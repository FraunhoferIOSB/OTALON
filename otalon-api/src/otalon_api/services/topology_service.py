"""Topology service.

Builds and queries the network topology graph from PostgreSQL scan
results, InfluxDB traffic data, and anomaly information.

Ported from the retired Panel-based UI's ``topology_service`` with
adaptations for the API-server architecture (no Panel cache, no direct
InfluxDB/PG client management, async-ready interface). The current
``otalon-ui`` is a Nuxt SPA and carries no counterpart.
"""

from __future__ import annotations

import ast
import ipaddress
from datetime import datetime, timedelta
from typing import Any, Sequence, cast

from loguru import logger

from otalon_api.domain.time import time_policy
from otalon_api.domain.topology.classification import (
    DEVICE_TYPE_OTHER,
    VALID_DEVICE_TYPES,
    classify_device_type,
)
from otalon_api.domain.topology.schemas import (
    DevicesResponse,
    DeviceTypeOverrideResponse,
    TopologyGraph,
    TopologyGraphMeta,
)
from otalon_api.domain.topology.uci import match_uci_pattern, parse_uci
from otalon_api.repositories.cache import CacheManager
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.services.device_type_override_store import DeviceTypeOverrideStore
from otalon_api.settings import Settings
from otalon_api.utils import run_in_thread

UNRESOLVED_ID_PREFIX = "unresolved:"

# PROFINET real-time families that ride directly on Ethernet (L2) with no
# IPv4/IPv6 header — PROFINET RT cyclic IO data, the PTCP clock-sync frames,
# and the DCP discovery/configuration frames.  Because these carry no IP, the
# IP-CIDR subnet filter in :meth:`TopologyService.get_subnet_protocols` cannot
# see them; they must be detected purely from the protocol stack.  The
# IP-bearing PROFINET context channel (``PROFINET_DCE_RPC``, over IPv4/UDP) is
# deliberately NOT listed here — it is already caught by the IP filter.
PROFINET_L2_PROTOCOLS: frozenset[str] = frozenset(
    {
        "PROFINET_RT_IO",
        "PROFINET_RT_PTCP",
        "PROFINET_RT_DCP",
    }
)


def _protocol_tokens(protocols: str) -> list[str]:
    """Split a ``:``-delimited protocol stack into its component tokens.

    The ``protocols`` UCI segment is an Ethernet protocol stack such as
    ``"Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO"``.  Empty input yields an
    empty list.

    Args:
        protocols: The raw ``protocols`` segment of a UCI.

    Returns:
        The non-empty, whitespace-stripped tokens of the stack.
    """
    return [tok.strip() for tok in protocols.split(":") if tok.strip()]


def _l2_profinet_in_stack(protocols: str) -> bool:
    """Return whether a protocol stack carries an L2-only PROFINET family.

    Matches only the exact PROFINET real-time L2 families in
    :data:`PROFINET_L2_PROTOCOLS` so that non-PROFINET traffic — and the
    IP-bearing ``PROFINET_DCE_RPC`` context channel — are never misclassified
    by this L2 signal.

    Args:
        protocols: The raw ``protocols`` segment of a UCI.

    Returns:
        ``True`` if any token is an L2-only PROFINET real-time family.
    """
    return any(tok in PROFINET_L2_PROTOCOLS for tok in _protocol_tokens(protocols))


def _normalize_mac(value: str) -> str:
    """Normalize a MAC address to lower-case colon-separated format.

    Args:
        value: Raw MAC string.

    Returns:
        Normalized MAC string.
    """
    s = str(value or "").strip().lower()
    return s.replace("-", ":")


def _parse_ip_list(cell: Any) -> list[str]:
    """Parse a DB cell value into a list of IP address strings.

    Handles Python list objects, JSON-like strings, and comma-separated
    values.

    Args:
        cell: Raw cell value from a query result.

    Returns:
        List of non-empty IP address strings.
    """
    if cell is None:
        return []
    if isinstance(cell, list):
        return [str(x).strip() for x in cell if str(x).strip()]
    s = str(cell).strip()
    if not s:
        return []
    try:
        v = ast.literal_eval(s)
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
    except Exception:
        pass
    s_stripped = s.strip("[]").strip()
    if not s_stripped:
        return []
    parts = [p.strip().strip("'").strip('"') for p in s_stripped.split(",")]
    return [p for p in parts if p]


def _node_label(name: str, alias: str, dtype: str, ip: str, mac: str) -> str:
    """Derive a human-readable label for a topology node.

    Tries name, alias, device-type, IP, and MAC in order, returning the
    first non-empty value.

    Args:
        name: Device name.
        alias: Device alias.
        dtype: Device type name.
        ip: Primary IP address.
        mac: MAC address.

    Returns:
        The best available label string.
    """
    for candidate in (name, alias, dtype, ip, mac):
        s = str(candidate or "").strip()
        if s:
            return s
    return ""


def _make_unresolved_id(key: str) -> str:
    """Build a node ID for an unresolved (unknown) device.

    Args:
        key: Identifying string (IP or MAC).

    Returns:
        Prefixed ID string.
    """
    return f"{UNRESOLVED_ID_PREFIX}{key}"


def _parse_series_ids_cell(cell: Any) -> list[str]:
    """Parse a ``series_ids`` column value into a list of UCI patterns.

    Args:
        cell: Raw column value (list, JSON string, or None).

    Returns:
        List of UCI pattern strings.
    """
    if cell is None:
        return []
    if isinstance(cell, list):
        return [str(x) for x in cell]
    s = str(cell).strip()
    if not s:
        return []
    try:
        v = ast.literal_eval(s)
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, dict):
            return [str(x) for x in v.values()]
    except Exception:
        pass
    return []


def _is_intended_device(device: dict[str, Any]) -> bool:
    """Keep inventory devices associated with configured 192.168.0.0/24 segment."""
    network = ipaddress.ip_network("192.168.0.0/24")
    for interface in device.get("interfaces", []):
        value = interface.get("ipv4_address")
        if not value:
            continue
        try:
            if ipaddress.ip_address(value) in network:
                return True
        except ValueError:
            continue
    return False


class TopologyService:
    """Service for network topology graph construction and queries.

    Builds a graph of network nodes and edges by combining device data
    from PostgreSQL, UCI identifiers from InfluxDB, and anomaly
    information from both databases.
    """

    def __init__(
        self,
        postgres_repo: PostgresRepository,
        influx_repo: InfluxRepository,
        settings: Settings,
        override_store: DeviceTypeOverrideStore | None = None,
        cache_manager: CacheManager | None = None,
    ) -> None:
        """Initialize the topology service.

        Args:
            postgres_repo: PostgreSQL repository for device/anomaly data.
            influx_repo: InfluxDB repository for UCI listing.
            settings: Application settings.
            override_store: Optional override store for device type classifications.
            cache_manager: Optional shared cache manager. When provided,
                :meth:`get_topology` results are cached under the
                ``"topology"`` namespace for the cache's TTL. When
                ``None``, the legacy uncached behaviour is used —
                keeping the constructor backward-compatible for tests
                that instantiate the service directly.
        """
        self._pg = postgres_repo
        self._influx = influx_repo
        self._settings = settings
        self._override_store = override_store or DeviceTypeOverrideStore()
        self._cache = cache_manager

    def _load_stations(
        self,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, int], dict[str, int]]:
        """Load devices from PostgreSQL and build lookup indices.

        Reads the canonical ``devices`` table together with the joined
        ``network_interfaces`` rows so the resolver can map MAC and IPv4
        addresses observed on the wire back to their owning device. The
        node label prefers a device-vendor / family combination over the
        raw MAC so the topology graph carries human-readable labels.

        Returns:
            A tuple of ``(node_map, ip_index, mac_index)`` where
            *node_map* maps station-ID strings to node dicts,
            *ip_index* maps IPs to station IDs, and
            *mac_index* maps MACs to station IDs.
        """
        node_map: dict[str, dict[str, Any]] = {}
        ip_index: dict[str, int] = {}
        mac_index: dict[str, int] = {}

        try:
            rows = self._pg.query_devices()
        except Exception as exc:
            logger.error("_load_stations failed: {}", exc)
            return node_map, ip_index, mac_index

        device_ids: list[int] = []
        for row in rows:
            sid_raw = row.get("id")
            if sid_raw is None:
                continue
            try:
                device_ids.append(int(sid_raw))
            except (ValueError, TypeError):
                continue

        try:
            interfaces_by_id = self._pg.query_network_interfaces_for_devices(device_ids)
        except Exception as exc:
            logger.warning("_load_stations: interface lookup failed (continuing): {}", exc)
            interfaces_by_id = {}

        for row in rows:
            sid_raw = row.get("id")
            if sid_raw is None:
                continue
            try:
                sid = int(sid_raw)
            except (ValueError, TypeError):
                continue

            vendor = str(row.get("vendor", "") or "").strip()
            family = str(row.get("device_family", "") or "").strip()
            dtype_name = str(row.get("device_type", "") or "").strip()
            role = str(row.get("device_role", "") or "").strip()
            description = str(row.get("description", "") or "").strip()

            ips: list[str] = []
            mac = ""
            for iface in interfaces_by_id.get(sid, []):
                ip4 = iface.get("ipv4_address")
                if ip4:
                    ips.append(str(ip4))
                if not mac and iface.get("mac_address"):
                    mac = _normalize_mac(str(iface["mac_address"]))

            display_name = family or dtype_name or vendor
            alias = vendor if family else ""

            ip_first = ips[0] if ips else ""
            dtype = classify_device_type(dtype_name or role)
            label = _node_label(display_name, alias, dtype_name, ip_first, mac)

            node_map[str(sid)] = {
                "id": str(sid),
                "label": label,
                "type": dtype,
                "isAnomaly": False,
                "meta": {
                    "name": display_name,
                    "alias": alias,
                    "device_type_name": dtype_name,
                    "device_role": role,
                    "description": description,
                    "vendor": vendor,
                    "mac": mac,
                    "ip4": ips,
                },
            }

            for ip in ips:
                if ip:
                    ip_index[str(ip)] = sid
            if mac:
                mac_index[str(mac)] = sid

        return node_map, ip_index, mac_index

    def _list_ucis_between(self, start: datetime, stop: datetime) -> list[str]:
        """Query distinct UCI strings from InfluxDB for a time range.

        Args:
            start: Range start.
            stop: Range end.

        Returns:
            Sorted list of UCI strings.
        """
        try:
            start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)
            return self._influx.list_ids_between(
                measurement=self._settings.netcap_measurement,
                id_tag=self._settings.netcap_id_tag,
                start=start_str,
                stop=stop_str,
            )
        except Exception as exc:
            logger.error("_list_ucis_between failed: {}", exc)
            return []

    def _load_anomaly_sets(self, start: datetime, stop: datetime) -> tuple[dict[int, bool], list[str]]:
        """Load anomaly flags for nodes and edge patterns from PostgreSQL.

        Args:
            start: Range start.
            stop: Range end.

        Returns:
            Tuple of ``(node_anoms, edge_patterns)`` where *node_anoms*
            maps station IDs to ``True`` and *edge_patterns* is a list
            of UCI wildcard patterns from alarm groups.
        """
        node_anoms: dict[int, bool] = {}
        edge_patterns: list[str] = []

        try:
            start_utc, stop_utc = time_policy.ui_to_pg_query_range(start, stop)
            # Connection/UCI alarm groups carry the ``conn`` module label; the
            # legacy ``netcap`` value silently returned no rows and broke the
            # anomaly highlight on the topology graph.
            groups = self._pg.query_anomaly_groups(module="conn", time_range=(start_utc, stop_utc))
            for grp in groups:
                pats = _parse_series_ids_cell(grp.get("series_ids"))
                edge_patterns.extend([str(p) for p in pats if str(p).strip()])
        except Exception as exc:
            logger.error("_load_anomaly_sets failed: {}", exc)

        return node_anoms, edge_patterns

    def _map_ucis_to_edges(
        self,
        ucis: Sequence[str],
        ip_index: dict[str, int],
        mac_index: dict[str, int],
    ) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
        """Map UCI strings to topology edges and unresolved nodes.

        For each UCI, resolves source and destination to known stations
        via IP or MAC lookup.  Creates unresolved placeholder nodes for
        unknown endpoints.

        Args:
            ucis: List of UCI strings.
            ip_index: IP-to-station-ID mapping.
            mac_index: MAC-to-station-ID mapping.

        Returns:
            Tuple of ``(unresolved_nodes, edges)`` dicts.
        """
        unresolved_nodes: dict[str, dict[str, Any]] = {}
        edges: dict[tuple[str, str], dict[str, Any]] = {}

        for u in ucis or []:
            sm, dm, _vlan, _ip_proto, sip, dip, sport, dport, prot = parse_uci(str(u))

            src_sid = ip_index.get(str(sip).strip())
            if src_sid is None:
                src_sid = mac_index.get(_normalize_mac(sm))

            dst_sid = ip_index.get(str(dip).strip())
            if dst_sid is None:
                dst_sid = mac_index.get(_normalize_mac(dm))

            if src_sid is None:
                src_key = str(sip or sm or "").strip()
                src_label = src_key if src_key else DEVICE_TYPE_OTHER
                src_id = _make_unresolved_id(src_key if src_key else "other")
                if src_id not in unresolved_nodes:
                    unresolved_nodes[src_id] = {
                        "id": src_id,
                        "label": src_label,
                        "type": DEVICE_TYPE_OTHER,
                        "isAnomaly": False,
                        "meta": {"mac": sm, "ip": sip},
                    }
            else:
                src_id = str(src_sid)

            if dst_sid is None:
                dst_key = str(dip or dm or "").strip()
                dst_label = dst_key if dst_key else DEVICE_TYPE_OTHER
                dst_id = _make_unresolved_id(dst_key if dst_key else "other")
                if dst_id not in unresolved_nodes:
                    unresolved_nodes[dst_id] = {
                        "id": dst_id,
                        "label": dst_label,
                        "type": DEVICE_TYPE_OTHER,
                        "isAnomaly": False,
                        "meta": {"mac": dm, "ip": dip},
                    }
            else:
                dst_id = str(dst_sid)

            key = (src_id, dst_id)
            entry = edges.get(key)
            if entry is None:
                entry = {
                    "source": src_id,
                    "target": dst_id,
                    "ucis": set(),
                    "protocols": set(),
                    "src_ports": set(),
                    "dst_ports": set(),
                    "count": 0,
                    "is_anomaly": False,
                }
                edges[key] = entry

            entry["ucis"].add(str(u))
            if prot:
                entry["protocols"].add(str(prot))
            if sport:
                entry["src_ports"].add(str(sport))
            if dport:
                entry["dst_ports"].add(str(dport))
            entry["count"] += 1

        return unresolved_nodes, edges

    @staticmethod
    def _mark_anomalies(
        node_map: dict[str, dict[str, Any]],
        unresolved_nodes: dict[str, dict[str, Any]],
        edges: dict[tuple[str, str], dict[str, Any]],
        node_anoms: dict[int, bool],
        edge_patterns: list[str],
    ) -> None:
        """Flag anomalous nodes and edges in-place.

        Args:
            node_map: Resolved station-ID-to-node mapping.
            unresolved_nodes: Unresolved node mapping.
            edges: Edge mapping keyed by ``(src_id, dst_id)``.
            node_anoms: Map of station IDs with anomaly status.
            edge_patterns: UCI wildcard patterns from alarm groups.
        """
        for sid, payload in node_map.items():
            try:
                if node_anoms.get(int(sid), False):
                    payload["isAnomaly"] = True
            except (ValueError, TypeError):
                pass

        for _key, payload in unresolved_nodes.items():
            payload["isAnomaly"] = False

        anomalous_endpoints: set[str] = set()
        for key, entry in edges.items():
            has = False
            ucis: list[str] = list(entry.get("ucis", []))
            for pat in edge_patterns or []:
                for u in ucis:
                    if match_uci_pattern(str(pat), str(u)):
                        has = True
                        break
                if has:
                    break
            entry["is_anomaly"] = bool(has)
            if has:
                src_id, dst_id = key
                anomalous_endpoints.add(str(src_id))
                anomalous_endpoints.add(str(dst_id))

        # Propagate edge-level anomalies onto the connected nodes so the
        # topology graph can render an "affected by alarm" highlight even
        # when the alarm carries no per-node station IDs.
        for sid, payload in node_map.items():
            if str(sid) in anomalous_endpoints:
                payload["isAnomaly"] = True

        for node_key, payload in unresolved_nodes.items():
            if str(node_key) in anomalous_endpoints:
                payload["isAnomaly"] = True

    @staticmethod
    def _build_wildcard_for_edge(ucis: Sequence[str]) -> str:
        """Derive a wildcard UCI pattern for an edge's UCI set.

        Replaces source and destination port fields with ``*``.

        Args:
            ucis: List of UCIs belonging to one edge.

        Returns:
            Wildcard UCI string, or empty string if *ucis* is empty.
        """
        if not ucis:
            return ""
        sm, dm, vlan, ip_proto, sip, dip, _sp, _dp, prot = parse_uci(str(ucis[0]))
        parts = [sm, dm, vlan, ip_proto, sip, dip, "*", "*", prot]
        return "/".join(parts)

    @staticmethod
    def _sort_nodes_deterministic(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sort topology nodes deterministically for stable truncation.

        Priority: anomaly nodes first, then alphabetically by label.

        Args:
            nodes: List of node dicts.

        Returns:
            Sorted copy of the node list.
        """
        return sorted(
            nodes,
            key=lambda n: (
                0 if n.get("isAnomaly") else 1,
                str(n.get("label", "")).lower(),
            ),
        )

    def build_graph(
        self,
        start: datetime,
        stop: datetime,
        node_limit: int = 100,
        include_anomalies: bool = True,
        show_unresolved: bool = True,
    ) -> dict[str, Any]:
        """Build the full topology graph for a time range.

        Steps:
        1. Load stations from PostgreSQL
        2. List UCIs from InfluxDB for the time range
        3. Map UCIs to edges and unresolved nodes
        4. Optionally load and mark anomaly data
        5. Deterministically sort and truncate to *node_limit*
        6. Build and return the topology graph dict

        Args:
            start: Range start in local time.
            stop: Range end in local time.
            node_limit: Maximum number of nodes to include.
            include_anomalies: Whether to load and flag anomalies.
            show_unresolved: Whether to include unresolved nodes.

        Returns:
            Dict matching the GD-10 topology structure with ``nodes``,
            ``edges``, and ``meta`` keys.
        """
        try:
            node_map, ip_index, mac_index = self._load_stations()
            ucis = self._list_ucis_between(start, stop)
            unresolved_nodes, edges = self._map_ucis_to_edges(ucis, ip_index, mac_index)

            if include_anomalies:
                node_anoms, edge_patterns = self._load_anomaly_sets(start, stop)
                self._mark_anomalies(node_map, unresolved_nodes, edges, node_anoms, edge_patterns)
        except Exception as exc:
            logger.error("build_graph failed primary data retrieval: {}", exc)
            return TopologyGraph(
                nodes=[],
                edges=[],
                meta=TopologyGraphMeta(node_count=0, edge_count=0),
            ).model_dump()

        used_ids: set[str] = set()
        for src_id, dst_id in edges:
            if str(src_id).isdigit():
                used_ids.add(str(src_id))
            if str(dst_id).isdigit():
                used_ids.add(str(dst_id))
        keep_ids = used_ids if used_ids else set(node_map.keys())

        nodes: list[dict[str, Any]] = []
        for _sid, payload in node_map.items():
            if payload["id"] not in keep_ids:
                continue
            nodes.append(
                {
                    "id": payload["id"],
                    "label": payload["label"],
                    "type": payload.get("type", DEVICE_TYPE_OTHER),
                    "isAnomaly": bool(payload.get("isAnomaly", False)),
                    "meta": dict(payload.get("meta", {})),
                }
            )

        if show_unresolved:
            for _key, payload in unresolved_nodes.items():
                nodes.append(
                    {
                        "id": payload["id"],
                        "label": payload["label"],
                        "type": payload.get("type", DEVICE_TYPE_OTHER),
                        "isAnomaly": bool(payload.get("isAnomaly", False)),
                        "meta": dict(payload.get("meta", {})),
                    }
                )

        nodes = self._sort_nodes_deterministic(nodes)
        truncated = len(nodes) > node_limit
        if truncated:
            nodes = nodes[:node_limit]
            visible_ids = {n["id"] for n in nodes}
            edges = {
                k: v for k, v in edges.items() if v.get("source") in visible_ids and v.get("target") in visible_ids
            }

        edges_out: list[dict[str, Any]] = []
        node_id_set = {n["id"] for n in nodes}
        for (src_id, dst_id), entry in edges.items():
            if str(src_id) not in node_id_set or str(dst_id) not in node_id_set:
                continue
            eid = f"{src_id}-{dst_id}"
            is_anom = bool(entry.get("is_anomaly", False))
            ucis_list = sorted(entry.get("ucis", []))
            wildcard = self._build_wildcard_for_edge(ucis_list)
            edges_out.append(
                {
                    "id": eid,
                    "source": src_id,
                    "target": dst_id,
                    "label": "",
                    "isAnomaly": is_anom,
                    "meta": {
                        "ucis": ucis_list,
                        "protocols": sorted(entry.get("protocols", set())),
                        "src_ports": sorted(entry.get("src_ports", set())),
                        "dst_ports": sorted(entry.get("dst_ports", set())),
                        "wildcard": wildcard,
                    },
                }
            )

        return {
            "nodes": nodes,
            "edges": edges_out,
            "meta": {
                "node_count": len(nodes),
                "edge_count": len(edges_out),
                "truncated": truncated,
            },
        }

    @run_in_thread
    def get_topology(
        self,
        start: datetime,
        stop: datetime,
        node_limit: int = 100,
        include_anomalies: bool = True,
    ) -> dict[str, Any]:
        """Entry point for topology graph retrieval.

        Delegates to :meth:`build_graph` and wraps the result. Runs in
        a thread pool to avoid blocking the event loop.

        When a shared :class:`CacheManager` was injected, the result is
        cached under the ``"topology"`` namespace keyed by
        ``(start, stop, node_limit, include_anomalies)``. The cache
        uses a short TTL (default 30 s) — no write-path invalidation —
        so frequent topology polls hit the cache instead of repeating
        the full Postgres + InfluxDB aggregation.

        Args:
            start: Range start in local time.
            stop: Range end in local time.
            node_limit: Maximum number of nodes.
            include_anomalies: Whether to include anomaly flags.

        Returns:
            Topology graph dict with ``nodes``, ``edges``, ``meta``.
        """
        if self._cache is not None:
            cache_key = f"graph:{start.isoformat()}|{stop.isoformat()}|" f"{node_limit}|{int(include_anomalies)}"
            return cast(
                dict[str, Any],
                self._cache.get_or_compute(
                    "topology",
                    cache_key,
                    lambda: self.build_graph(
                        start=start,
                        stop=stop,
                        node_limit=node_limit,
                        include_anomalies=include_anomalies,
                    ),
                ),
            )

        return self.build_graph(
            start=start,
            stop=stop,
            node_limit=node_limit,
            include_anomalies=include_anomalies,
        )

    @run_in_thread
    def get_devices(self, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """Load paginated device inventory from PostgreSQL.

        Reads the ``devices`` table joined with all matching ``network_interfaces``
        rows so each returned device carries its MAC/IP addresses inline.
        Runs in a thread pool to avoid blocking the event loop.

        Args:
            limit: Maximum number of devices to return.
            offset: Pagination offset.

        Returns:
            Dict with ``devices`` list and ``total`` count matching
            the GD-13 structure.
        """
        try:
            rows = self._pg.query_devices(limit=limit, offset=offset)
            total = self._pg.query_devices_total_count()
        except Exception as exc:
            logger.error("get_devices failed: {}", exc)
            return DevicesResponse(devices=[], total=0).model_dump()

        device_ids = [int(r["id"]) for r in rows if r.get("id") is not None]
        try:
            interfaces_by_id = self._pg.query_network_interfaces_for_devices(device_ids)
        except Exception as exc:
            logger.warning("query_network_interfaces failed (skipping): {}", exc)
            interfaces_by_id = {}

        # F-01: ``vulnerabilities`` and ``open_ports_summary`` are now
        # served by Postgres views. Pre-compute the lookup dicts here so
        # _format_device_row stays a pure projection.
        all_iface_ids = [
            int(iface["id"]) for ifaces in interfaces_by_id.values() for iface in ifaces if iface.get("id") is not None
        ]
        try:
            vulns_by_device = self._pg.query_device_topology_view(device_ids)
        except Exception as exc:
            logger.warning("query_device_topology_view failed (defaulting to []): {}", exc)
            vulns_by_device = {}
        try:
            ports_by_iface = self._pg.query_network_interface_ports_view(all_iface_ids)
        except Exception as exc:
            logger.warning("query_network_interface_ports_view failed (defaulting to []): {}", exc)
            ports_by_iface = {}

        devices = [self._format_device_row(row, interfaces_by_id, vulns_by_device, ports_by_iface) for row in rows]
        devices = [device for device in devices if _is_intended_device(device)]
        return {"devices": devices, "total": len(devices)}

    @staticmethod
    def _format_device_row(
        row: dict[str, Any],
        interfaces_by_id: dict[int, list[dict[str, Any]]],
        vulns_by_device: dict[int, list[dict[str, Any]]] | None = None,
        ports_by_iface: dict[int, list[dict[str, Any]]] | None = None,
    ) -> dict[str, Any]:
        """Convert a raw devices-table row into the API response shape.

        Joins the matching rows from ``interfaces_by_id`` and stringifies
        all timestamp / inet / cidr fields so the result is JSON-serializable.

        F-01: ``vulnerabilities`` and ``open_ports_summary`` are now
        sourced from the Postgres views (passed in as
        ``vulns_by_device`` and ``ports_by_iface``), not from the
        underlying jsonb cache columns (which were dropped). The default
        ``None`` arguments keep the legacy call-shape working — they
        produce empty arrays — so any caller still on the pre-F-01
        signature observes an empty list rather than a hard failure.
        """

        def _to_str(value: Any) -> str | None:
            return None if value is None else str(value)

        device_id = int(row["id"]) if row.get("id") is not None else 0
        raw_interfaces = interfaces_by_id.get(device_id, [])
        ports_lookup = ports_by_iface or {}
        interfaces = [
            {
                "id": int(iface.get("id", 0) or 0),
                "mac_address": _to_str(iface.get("mac_address")),
                "ipv4_address": _to_str(iface.get("ipv4_address")),
                "ipv6_address": _to_str(iface.get("ipv6_address")),
                "subnet": _to_str(iface.get("subnet")),
                "open_ports_summary": ports_lookup.get(int(iface.get("id", 0) or 0), []),
                "last_scan_at": _to_str(iface.get("last_scan_at")),
                "notes": iface.get("notes"),
                "source": iface.get("source"),
            }
            for iface in raw_interfaces
        ]

        vulns_lookup = vulns_by_device or {}
        return {
            "id": device_id,
            "hostname": row.get("hostname"),
            "vendor": row.get("vendor"),
            "device_family": row.get("device_family"),
            "device_type": row.get("device_type"),
            "description": row.get("description"),
            "article_number": row.get("article_number"),
            "device_role": row.get("device_role"),
            "firmware_version": row.get("firmware_version"),
            "product_name": row.get("product_name"),
            "hw_version": row.get("hw_version"),
            "sw_version": row.get("sw_version"),
            "serial_number": row.get("serial_number"),
            "vulnerabilities": vulns_lookup.get(device_id, []),
            "update_available": bool(row.get("update_available", False)),
            "last_scan_at": _to_str(row.get("last_scan_at")),
            "notes": row.get("notes"),
            "created_at": _to_str(row.get("created_at")),
            "updated_at": _to_str(row.get("updated_at")),
            "interfaces": interfaces,
        }

    def _update_device_type_sync(self, device_id: int, device_type: str) -> DeviceTypeOverrideResponse:
        """Set a device type override for a known device.

        Validates that the device exists in PostgreSQL and that the
        requested type is a recognized classification, then persists
        the override.

        Args:
            device_id: Primary key of the device in the ``devices`` table.
            device_type: Target device type (must be in :data:`VALID_DEVICE_TYPES`).

        Returns:
            A :class:`DeviceTypeOverrideResponse` with the updated mapping.

        Raises:
            ValueError: If the device does not exist.
        """
        row = self._pg.query_device_by_id(device_id)
        if row is None:
            raise ValueError(f"Device {device_id} not found")

        auto_type = classify_device_type(row.get("device_type") or row.get("device_role"))
        current_effective = self._override_store.resolve(str(device_id), auto_type)

        previous = self._override_store.set(str(device_id), device_type)

        return DeviceTypeOverrideResponse(
            device_id=device_id,
            device_type=device_type,
            previous_type=previous or current_effective,
            message="Device type override applied",
        )

    @run_in_thread
    def update_device_type(self, device_id: int, device_type: str) -> DeviceTypeOverrideResponse:
        """Set a device type override for a known device (async wrapper).

        Runs :meth:`_update_device_type_sync` in a thread pool to avoid
        blocking the event loop.

        Args:
            device_id: Primary key of the device in the ``devices`` table.
            device_type: Target device type (must be in :data:`VALID_DEVICE_TYPES`).

        Returns:
            A :class:`DeviceTypeOverrideResponse` with the updated mapping.

        Raises:
            ValueError: If the device does not exist.
        """
        return self._update_device_type_sync(device_id, device_type)

    def _bulk_update_device_types_sync(
        self,
        items: Sequence[tuple[int, str]],
    ) -> list[DeviceTypeOverrideResponse]:
        """Atomically apply a batch of device-type overrides.

        Performs all validation (device exists in PostgreSQL, target
        type is in :data:`VALID_DEVICE_TYPES`) before any mutation. If
        any check fails, no override is written. Then delegates to
        :meth:`DeviceTypeOverrideStore.set_many` for a single batched
        persist.

        Args:
            items: Sequence of ``(device_id, device_type)`` pairs. The
                caller is expected to have already rejected an empty
                sequence at the API boundary.

        Returns:
            A list of :class:`DeviceTypeOverrideResponse` entries in
            the same order as the input, each describing the applied
            override and the previous effective type.

        Raises:
            ValueError: If any device does not exist, or any target
                device type is invalid. The error message identifies
                the offending entry. Raised before any state mutation.
        """
        invalid_types: list[tuple[int, str]] = [(did, dtype) for did, dtype in items if dtype not in VALID_DEVICE_TYPES]
        if invalid_types:
            did, dtype = invalid_types[0]
            raise ValueError(
                f"Invalid device_type '{dtype}' for device_id {did}. " f"Must be one of: {sorted(VALID_DEVICE_TYPES)}"
            )

        rows_by_id: dict[int, dict[str, Any]] = {}
        missing: list[int] = []
        for did, _dtype in items:
            row = self._pg.query_device_by_id(did)
            if row is None:
                missing.append(did)
            else:
                rows_by_id[did] = row
        if missing:
            raise ValueError(f"Devices not found: {sorted(set(missing))}")

        current_effective: dict[int, str] = {}
        for did, _dtype in items:
            row = rows_by_id[did]
            auto_type = classify_device_type(row.get("device_type") or row.get("device_role"))
            current_effective[did] = self._override_store.resolve(str(did), auto_type)

        previous_map = self._override_store.set_many({str(did): dtype for did, dtype in items})

        responses: list[DeviceTypeOverrideResponse] = []
        for did, dtype in items:
            prev = previous_map.get(str(did)) or current_effective.get(did)
            responses.append(
                DeviceTypeOverrideResponse(
                    device_id=did,
                    device_type=dtype,
                    previous_type=prev,
                    message="Device type override applied",
                )
            )
        return responses

    @run_in_thread
    def bulk_update_device_types(
        self,
        items: Sequence[tuple[int, str]],
    ) -> list[DeviceTypeOverrideResponse]:
        """Async wrapper around :meth:`_bulk_update_device_types_sync`.

        Runs in a thread pool so the blocking PostgreSQL and file-system
        calls do not stall the event loop.

        Args:
            items: Sequence of ``(device_id, device_type)`` pairs.

        Returns:
            List of override responses, one per input item, in order.

        Raises:
            ValueError: As documented on the sync variant.
        """
        return self._bulk_update_device_types_sync(items)

    @run_in_thread
    def get_subnet_protocols(self, subnet: str) -> dict[str, Any]:
        """Return the union of protocol tokens observed within *subnet*.

        Queries all UCIs ever seen (no time window in v1) and checks
        whether the source or destination IP of each UCI falls inside
        the given CIDR.  The returned ``protocols`` list is sorted and
        deduplicated; ``seen`` is ``True`` when at least one protocol
        was found.

        PROFINET real-time families that ride directly on Ethernet
        (``PROFINET_RT_IO`` / ``PROFINET_RT_PTCP`` / ``PROFINET_RT_DCP``)
        carry no IP header, so the IP-CIDR filter cannot place them in any
        subnet.  Because these are an L2 segment-wide signal — and the
        ``pn_discovery`` scan they drive is itself an L2 discovery — their
        bare protocol tokens are emitted whenever observed anywhere in the
        mirror traffic.  Matching is restricted to the exact PROFINET L2
        families so non-PROFINET traffic is never misclassified.

        Args:
            subnet: IPv4 or IPv6 CIDR string (e.g. ``"192.168.0.0/24"``).

        Returns:
            Dict with ``subnet``, ``protocols`` (list of strings), and
            ``seen`` (boolean).
        """
        network = ipaddress.ip_network(subnet, strict=False)

        lookback = self._settings.topology_subnet_protocols_lookback_hours
        start = datetime.now() - timedelta(hours=lookback)
        stop = datetime.now() + timedelta(days=1)
        ucis = self._list_ucis_between(start, stop)

        protocols: set[str] = set()
        for u in ucis:
            parts = parse_uci(str(u))
            sip, dip, prot = parts.src_ip, parts.dst_ip, parts.protocols
            in_subnet = False
            if sip:
                try:
                    if ipaddress.ip_address(sip) in network:
                        in_subnet = True
                except ValueError:
                    pass
            if not in_subnet and dip:
                try:
                    if ipaddress.ip_address(dip) in network:
                        in_subnet = True
                except ValueError:
                    pass
            if in_subnet and prot:
                protocols.add(str(prot))
            elif not in_subnet and prot and _l2_profinet_in_stack(str(prot)):
                # L2-only PROFINET RT frames have no IP and cannot match the
                # CIDR; surface the matched family tokens as a segment-wide
                # PROFINET-present signal.
                for tok in _protocol_tokens(str(prot)):
                    if tok in PROFINET_L2_PROTOCOLS:
                        protocols.add(tok)

        return {
            "subnet": subnet,
            "protocols": sorted(protocols),
            "seen": bool(protocols),
        }
