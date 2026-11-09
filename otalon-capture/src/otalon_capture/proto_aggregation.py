"""Streaming protocol aggregation for Netcap++ records.

Aggregates raw network traffic per (second, protocol) into 18 features
(3 Volume + 5 PacketSize + 4 IAT + 3 Topology + 3 Behavior) plus meta-column
``protocol``.  The logic mirrors the offline Polars pipeline in
``create_proto_aggregated_features.py`` but operates incrementally.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .aggregation import _safe_int, _safe_num, _uci_to_parts
from .mac_aggregation import ProtoKey, _coerce_proto_key


@dataclass
class ProtoAggregatedRecord:
    """Aggregated representation of per-protocol traffic emitted after bucketing."""

    time: int
    protocol: str
    proto_conn_count: float
    proto_total_packets: float
    proto_total_volume: float
    proto_mean_packet_size: float
    proto_std_packet_size: float
    proto_min_packet_size: float
    proto_max_packet_size: float
    proto_range_packet_size: float
    proto_mean_interarrival: float
    proto_std_interarrival: float
    proto_min_interarrival: float
    proto_max_interarrival: float
    proto_unique_src_mac: float
    proto_unique_dst_mac: float
    proto_unique_mac_pairs: float
    proto_mean_packets_per_conn: float
    proto_std_packets_per_conn: float
    proto_mean_volume_per_conn: float

    def get_time(self) -> int:
        """Return the timestamp in milliseconds."""
        return self.time

    def get_protocol(self) -> str:
        """Return the protocol tag value."""
        return self.protocol

    def get_proto_conn_count(self) -> float:
        """Return the connection count for this protocol."""
        return self.proto_conn_count

    def get_proto_total_packets(self) -> float:
        """Return the total packet count for this protocol."""
        return self.proto_total_packets

    def get_proto_total_volume(self) -> float:
        """Return the total volume for this protocol."""
        return self.proto_total_volume

    def get_proto_mean_packet_size(self) -> float:
        """Return the weighted mean packet size."""
        return self.proto_mean_packet_size

    def get_proto_std_packet_size(self) -> float:
        """Return the mean standard deviation of packet size."""
        return self.proto_std_packet_size

    def get_proto_min_packet_size(self) -> float:
        """Return the minimum packet size."""
        return self.proto_min_packet_size

    def get_proto_max_packet_size(self) -> float:
        """Return the maximum packet size."""
        return self.proto_max_packet_size

    def get_proto_range_packet_size(self) -> float:
        """Return the range of packet sizes (max - min)."""
        return self.proto_range_packet_size

    def get_proto_mean_interarrival(self) -> float:
        """Return the weighted mean interarrival time."""
        return self.proto_mean_interarrival

    def get_proto_std_interarrival(self) -> float:
        """Return the mean standard deviation of interarrival time."""
        return self.proto_std_interarrival

    def get_proto_min_interarrival(self) -> float:
        """Return the minimum interarrival time."""
        return self.proto_min_interarrival

    def get_proto_max_interarrival(self) -> float:
        """Return the maximum interarrival time."""
        return self.proto_max_interarrival

    def get_proto_unique_src_mac(self) -> float:
        """Return the unique source MAC count."""
        return self.proto_unique_src_mac

    def get_proto_unique_dst_mac(self) -> float:
        """Return the unique destination MAC count."""
        return self.proto_unique_dst_mac

    def get_proto_unique_mac_pairs(self) -> float:
        """Return the unique MAC pair count."""
        return self.proto_unique_mac_pairs

    def get_proto_mean_packets_per_conn(self) -> float:
        """Return the mean packets per connection."""
        return self.proto_mean_packets_per_conn

    def get_proto_std_packets_per_conn(self) -> float:
        """Return the sample standard deviation of packets per connection."""
        return self.proto_std_packets_per_conn

    def get_proto_mean_volume_per_conn(self) -> float:
        """Return the mean volume per connection."""
        return self.proto_mean_volume_per_conn


@dataclass
class ProtoBucket:
    """Accumulator for one protocol in one second.

    Mirrors the Polars ``aggregate_protocol_features`` logic with incremental
    updates.
    """

    conn_count: int = 0
    total_packets: int = 0
    total_volume: float = 0.0
    weighted_mps_sum: float = 0.0
    sum_std_ps: float = 0.0
    min_ps: Optional[int] = None
    max_ps: Optional[int] = None
    weighted_iat_sum: float = 0.0
    sum_std_iat: float = 0.0
    min_iat: Optional[float] = None
    max_iat: Optional[float] = None
    src_macs: Set[str] = field(default_factory=set)
    dst_macs: Set[str] = field(default_factory=set)
    mac_pairs: Set[str] = field(default_factory=set)
    packets_per_conn: List[int] = field(default_factory=list)
    volumes_per_conn: List[float] = field(default_factory=list)

    def add(self, raw: Dict[str, Any], src_mac: str, dst_mac: str) -> None:
        """Update bucket from a raw Netcap record dict.

        Args:
            raw: Raw record dict with standard Netcap fields.
            src_mac: Source MAC address extracted from UCI.
            dst_mac: Destination MAC address extracted from UCI.
        """
        pc = _safe_int(raw.get("packet_count", 0))
        vol = _safe_num(raw.get("total_volume", 0.0))
        mean_ps = _safe_num(raw.get("mean_packet_size", 0.0))
        std_ps = _safe_num(raw.get("std_packet_size", 0.0))
        min_ps = _safe_int(raw.get("min_packet_size", 0))
        max_ps = _safe_int(raw.get("max_packet_size", 0))
        mean_iat = _safe_num(raw.get("mean_interarrival_time", 0.0))
        std_iat = _safe_num(raw.get("std_interarrival_time", 0.0))
        min_iat = _safe_num(raw.get("min_interarrival_time", 0.0))
        max_iat = _safe_num(raw.get("max_interarrival_time", 0.0))

        self.conn_count += 1
        self.total_packets += pc
        self.total_volume += vol
        self.weighted_mps_sum += mean_ps * float(pc)
        self.sum_std_ps += std_ps
        self.min_ps = min(min_ps, self.min_ps) if self.min_ps is not None else min_ps
        self.max_ps = max(max_ps, self.max_ps) if self.max_ps is not None else max_ps
        self.weighted_iat_sum += mean_iat * float(pc)
        self.sum_std_iat += std_iat
        self.min_iat = min(min_iat, self.min_iat) if self.min_iat is not None else min_iat
        self.max_iat = max(max_iat, self.max_iat) if self.max_iat is not None else max_iat
        self.src_macs.add(src_mac)
        self.dst_macs.add(dst_mac)
        self.mac_pairs.add(f"{src_mac}|{dst_mac}")
        self.packets_per_conn.append(pc)
        self.volumes_per_conn.append(vol)

    def build(self, sec_ts: int, protocol_name: str) -> ProtoAggregatedRecord:
        """Finalize bucket into a :class:`ProtoAggregatedRecord`.

        Args:
            sec_ts: Second-aligned timestamp in milliseconds.
            protocol_name: Resolved protocol string name.

        Returns:
            Fully populated protocol aggregated record.
        """
        tp = float(self.total_packets)
        safe_tp = tp if tp > 0 else 1.0

        mean_ps = self.weighted_mps_sum / safe_tp
        std_ps = self.sum_std_ps / self.conn_count if self.conn_count > 0 else 0.0
        min_ps_val = float(self.min_ps or 0)
        max_ps_val = float(self.max_ps or 0)
        range_ps = max_ps_val - min_ps_val

        mean_iat = self.weighted_iat_sum / safe_tp
        std_iat = self.sum_std_iat / self.conn_count if self.conn_count > 0 else 0.0
        min_iat_val = self.min_iat if self.min_iat is not None else 0.0
        max_iat_val = self.max_iat if self.max_iat is not None else 0.0

        mean_ppc = float(self.total_packets) / self.conn_count if self.conn_count > 0 else 0.0
        std_ppc = _safe_stdev(self.packets_per_conn)
        mean_vpc = self.total_volume / self.conn_count if self.conn_count > 0 else 0.0

        return ProtoAggregatedRecord(
            time=sec_ts,
            protocol=protocol_name,
            proto_conn_count=float(self.conn_count),
            proto_total_packets=tp,
            proto_total_volume=self.total_volume,
            proto_mean_packet_size=mean_ps,
            proto_std_packet_size=std_ps,
            proto_min_packet_size=min_ps_val,
            proto_max_packet_size=max_ps_val,
            proto_range_packet_size=range_ps,
            proto_mean_interarrival=mean_iat,
            proto_std_interarrival=std_iat,
            proto_min_interarrival=min_iat_val,
            proto_max_interarrival=max_iat_val,
            proto_unique_src_mac=float(len(self.src_macs)),
            proto_unique_dst_mac=float(len(self.dst_macs)),
            proto_unique_mac_pairs=float(len(self.mac_pairs)),
            proto_mean_packets_per_conn=mean_ppc,
            proto_std_packets_per_conn=std_ppc,
            proto_mean_volume_per_conn=mean_vpc,
        )


def _safe_stdev(values: List[int]) -> float:
    """Compute sample standard deviation (ddof=1), returning 0.0 for fewer than 2 values.

    Matches Polars ``pl.col(...).std(ddof=1).fill_null(0.0)`` behavior.

    Args:
        values: List of integer values.

    Returns:
        Sample standard deviation as float.
    """
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


class ProtoAggregator:
    """Streaming aggregator for protocol-level traffic features.

    Uses **data-driven flush**: a second bucket ``S`` is only emitted when
    the first record with a *later* second ``S+1`` arrives.  This avoids
    premature flushes caused by wall-clock drift or queue latency in
    threaded pipelines.

    - ``add(raw_dict)`` ingests one record and returns flushed results if due.
    - ``flush(force=False)`` returns pending or all buffered results.
    """

    def __init__(
        self,
        enabled: bool,
        emit_interval_ms: int = 1000,
        protocol_map: Optional[Dict[ProtoKey, str]] = None,
    ) -> None:
        self.enabled = enabled
        self.emit_interval_ms = int(emit_interval_ms)
        self.protocol_map: Dict[ProtoKey, str] = protocol_map or {}
        self.buckets: Dict[int, Dict[ProtoKey, ProtoBucket]] = {}

    def add(self, value: Dict[str, Any]) -> List[ProtoAggregatedRecord]:
        """Ingest a raw Netcap record and return flushed aggregates if due.

        Flush is **data-driven**: all second-buckets strictly older than the
        current record's second are emitted.  This guarantees that no bucket
        is flushed while records for that second are still arriving.

        Args:
            value: Raw dict with keys ``time``, ``uci``, ``packet_count``, etc.

        Returns:
            List of finalized :class:`ProtoAggregatedRecord` objects (may be empty).
        """
        if not self.enabled:
            return []

        rs_ms = value.get("time", 0)
        sec_ts = int(rs_ms // 1000 * 1000)

        uci_str = value.get("uci", "unknown")
        parts = _uci_to_parts(uci_str)
        src_mac = parts[0]
        dst_mac = parts[1]
        proto_key = _coerce_proto_key(value.get("protocols") or parts[8] or "unknown")

        sec_map = self.buckets.get(sec_ts)
        if sec_map is None:
            sec_map = {}
            self.buckets[sec_ts] = sec_map

        bucket = sec_map.get(proto_key)
        if bucket is None:
            bucket = ProtoBucket()
            sec_map[proto_key] = bucket
        bucket.add(value, src_mac, dst_mac)

        return self._flush_older_seconds(sec_ts)

    def flush(self, force: bool = False) -> List[ProtoAggregatedRecord]:
        """Flush buffered aggregates.

        When ``force`` is ``False``, this is a no-op because flushing is
        entirely data-driven inside :meth:`add`.  The worker thread calls
        ``flush()`` during idle periods; without new data no second
        boundaries can be determined, so nothing is emitted.

        Args:
            force: If ``True``, flush all buckets regardless of time.

        Returns:
            List of finalized :class:`ProtoAggregatedRecord` objects.
        """
        if not self.enabled:
            return []
        if force:
            return self._flush_all()
        return []

    def _resolve_protocol_name(self, proto_key: ProtoKey) -> str:
        """Map a protocol key (int or str) to its display name."""
        if isinstance(proto_key, str) and proto_key not in self.protocol_map:
            return proto_key
        return self.protocol_map.get(proto_key, f"proto_{proto_key}")

    def _flush_older_seconds(self, current_sec_ts: int) -> List[ProtoAggregatedRecord]:
        """Flush all second-buckets strictly older than ``current_sec_ts``.

        This is the data-driven flush: when a record from second ``S``
        arrives, all buckets for seconds ``< S`` are guaranteed complete
        and can be safely emitted.

        Args:
            current_sec_ts: Second-aligned timestamp of the current record (ms).

        Returns:
            List of finalized records from expired seconds.
        """
        flushed: List[ProtoAggregatedRecord] = []
        expired = sorted(s for s in self.buckets if s < current_sec_ts)
        for second_bucket in expired:
            proto_map = self.buckets.pop(second_bucket, {})
            flushed.extend(
                bucket.build(second_bucket, self._resolve_protocol_name(proto_key))
                for proto_key, bucket in proto_map.items()
            )
        return flushed

    def _flush_all(self) -> List[ProtoAggregatedRecord]:
        """Flush every second bucket regardless of time."""
        flushed: List[ProtoAggregatedRecord] = []
        for second_bucket in sorted(self.buckets.keys()):
            proto_map = self.buckets.pop(second_bucket, {})
            flushed.extend(
                bucket.build(second_bucket, self._resolve_protocol_name(proto_key))
                for proto_key, bucket in proto_map.items()
            )
        return flushed
