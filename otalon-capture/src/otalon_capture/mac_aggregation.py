"""Streaming MAC-address aggregation for Netcap++ records.

Aggregates raw network traffic per (second, MAC address) into 26 features
(11 outbound + 11 inbound + 4 ratio) plus meta-columns ``mac_address`` and
``dominant_protocol``.  The logic mirrors the offline Polars pipeline in
``create_mac_aggregated_features.py`` but operates incrementally on individual
records.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union

from .aggregation import _safe_int, _safe_num, _uci_to_parts

ProtoKey = Union[int, str]


def _coerce_proto_key(value: Any) -> ProtoKey:
    """Coerce a raw protocol value to a usable dict key.

    Accepts both numeric protocol IDs (int) and protocol name strings.

    Args:
        value: Raw protocol value from the record.

    Returns:
        An ``int`` if numeric, otherwise the string representation.
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return str(value) if value else "unknown"


@dataclass
class MacAggregatedRecord:
    """Aggregated representation of per-MAC traffic emitted after bucketing."""

    time: int
    mac_address: str
    dominant_protocol: str
    out_conn_count: float
    out_total_packets: float
    out_total_volume: float
    out_mean_packet_size: float
    out_std_packet_size: float
    out_min_packet_size: float
    out_max_packet_size: float
    out_mean_interarrival: float
    out_std_interarrival: float
    out_unique_dst_count: float
    out_unique_proto_count: float
    in_conn_count: float
    in_total_packets: float
    in_total_volume: float
    in_mean_packet_size: float
    in_std_packet_size: float
    in_min_packet_size: float
    in_max_packet_size: float
    in_mean_interarrival: float
    in_std_interarrival: float
    in_unique_src_count: float
    in_unique_proto_count: float
    ratio_in_out_packets: float
    ratio_in_out_volume: float
    total_conn_count: float
    total_unique_peers: float

    def get_time(self) -> int:
        """Return the timestamp in milliseconds."""
        return self.time

    def get_out_conn_count(self) -> float:
        """Return the outbound connection count."""
        return self.out_conn_count

    def get_out_total_packets(self) -> float:
        """Return the outbound total packet count."""
        return self.out_total_packets

    def get_out_total_volume(self) -> float:
        """Return the outbound total volume."""
        return self.out_total_volume

    def get_out_mean_packet_size(self) -> float:
        """Return the outbound weighted mean packet size."""
        return self.out_mean_packet_size

    def get_out_std_packet_size(self) -> float:
        """Return the outbound mean standard deviation of packet size."""
        return self.out_std_packet_size

    def get_out_min_packet_size(self) -> float:
        """Return the outbound minimum packet size."""
        return self.out_min_packet_size

    def get_out_max_packet_size(self) -> float:
        """Return the outbound maximum packet size."""
        return self.out_max_packet_size

    def get_out_mean_interarrival(self) -> float:
        """Return the outbound weighted mean interarrival time."""
        return self.out_mean_interarrival

    def get_out_std_interarrival(self) -> float:
        """Return the outbound mean standard deviation of interarrival time."""
        return self.out_std_interarrival

    def get_out_unique_dst_count(self) -> float:
        """Return the outbound unique destination MAC count."""
        return self.out_unique_dst_count

    def get_out_unique_proto_count(self) -> float:
        """Return the outbound unique protocol count."""
        return self.out_unique_proto_count

    def get_in_conn_count(self) -> float:
        """Return the inbound connection count."""
        return self.in_conn_count

    def get_in_total_packets(self) -> float:
        """Return the inbound total packet count."""
        return self.in_total_packets

    def get_in_total_volume(self) -> float:
        """Return the inbound total volume."""
        return self.in_total_volume

    def get_in_mean_packet_size(self) -> float:
        """Return the inbound weighted mean packet size."""
        return self.in_mean_packet_size

    def get_in_std_packet_size(self) -> float:
        """Return the inbound mean standard deviation of packet size."""
        return self.in_std_packet_size

    def get_in_min_packet_size(self) -> float:
        """Return the inbound minimum packet size."""
        return self.in_min_packet_size

    def get_in_max_packet_size(self) -> float:
        """Return the inbound maximum packet size."""
        return self.in_max_packet_size

    def get_in_mean_interarrival(self) -> float:
        """Return the inbound weighted mean interarrival time."""
        return self.in_mean_interarrival

    def get_in_std_interarrival(self) -> float:
        """Return the inbound mean standard deviation of interarrival time."""
        return self.in_std_interarrival

    def get_in_unique_src_count(self) -> float:
        """Return the inbound unique source MAC count."""
        return self.in_unique_src_count

    def get_in_unique_proto_count(self) -> float:
        """Return the inbound unique protocol count."""
        return self.in_unique_proto_count

    def get_ratio_in_out_packets(self) -> float:
        """Return the ratio of inbound to outbound packets."""
        return self.ratio_in_out_packets

    def get_ratio_in_out_volume(self) -> float:
        """Return the ratio of inbound to outbound volume."""
        return self.ratio_in_out_volume

    def get_total_conn_count(self) -> float:
        """Return the total connection count (in + out)."""
        return self.total_conn_count

    def get_total_unique_peers(self) -> float:
        """Return the total unique peer count."""
        return self.total_unique_peers


@dataclass
class DirectionalMacBucket:
    """Accumulator for one direction (in or out) of a MAC per second.

    Mirrors the Polars ``_build_directional_agg`` logic with incremental
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
    peer_macs: Set[str] = field(default_factory=set)
    protocols: Set[ProtoKey] = field(default_factory=set)

    def add(self, raw: Dict[str, Any], peer_mac: str, proto_key: ProtoKey = 0) -> None:
        """Update bucket from a raw Netcap record dict.

        Args:
            raw: Raw record dict with standard Netcap fields.
            peer_mac: The peer MAC address (dst for outbound, src for inbound).
            proto_key: Coerced protocol key (int or str).
        """
        pc = _safe_int(raw.get("packet_count", 0))
        vol = _safe_num(raw.get("total_volume", 0.0))
        mean_ps = _safe_num(raw.get("mean_packet_size", 0.0))
        std_ps = _safe_num(raw.get("std_packet_size", 0.0))
        min_ps = _safe_int(raw.get("min_packet_size", 0))
        max_ps = _safe_int(raw.get("max_packet_size", 0))
        mean_iat = _safe_num(raw.get("mean_interarrival_time", 0.0))
        std_iat = _safe_num(raw.get("std_interarrival_time", 0.0))

        self.conn_count += 1
        self.total_packets += pc
        self.total_volume += vol
        self.weighted_mps_sum += mean_ps * float(pc)
        self.sum_std_ps += std_ps
        self.min_ps = min(min_ps, self.min_ps) if self.min_ps is not None else min_ps
        self.max_ps = max(max_ps, self.max_ps) if self.max_ps is not None else max_ps
        self.weighted_iat_sum += mean_iat * float(pc)
        self.sum_std_iat += std_iat
        self.peer_macs.add(peer_mac)
        self.protocols.add(proto_key)

    def build(self, prefix: str) -> Dict[str, float]:
        """Finalize bucket into a dict of 11 directional features.

        Args:
            prefix: ``"out"`` or ``"in"`` to prefix feature names.

        Returns:
            Dictionary with 11 named features.
        """
        tp = float(self.total_packets)
        safe_tp = tp if tp > 0 else 1.0
        mean_ps = self.weighted_mps_sum / safe_tp
        std_ps = self.sum_std_ps / self.conn_count if self.conn_count > 0 else 0.0
        mean_iat = self.weighted_iat_sum / safe_tp
        std_iat = self.sum_std_iat / self.conn_count if self.conn_count > 0 else 0.0

        peer_key = "unique_dst_count" if prefix == "out" else "unique_src_count"

        return {
            f"{prefix}_conn_count": float(self.conn_count),
            f"{prefix}_total_packets": tp,
            f"{prefix}_total_volume": self.total_volume,
            f"{prefix}_mean_packet_size": mean_ps,
            f"{prefix}_std_packet_size": std_ps,
            f"{prefix}_min_packet_size": float(self.min_ps or 0),
            f"{prefix}_max_packet_size": float(self.max_ps or 0),
            f"{prefix}_mean_interarrival": mean_iat,
            f"{prefix}_std_interarrival": std_iat,
            f"{prefix}_{peer_key}": float(len(self.peer_macs)),
            f"{prefix}_unique_proto_count": float(len(self.protocols)),
        }


@dataclass
class MacSecondBucket:
    """Holds outbound and inbound buckets plus protocol tracking for one MAC in one second."""

    out_bucket: DirectionalMacBucket = field(default_factory=DirectionalMacBucket)
    in_bucket: DirectionalMacBucket = field(default_factory=DirectionalMacBucket)
    protocol_counter: Counter = field(default_factory=Counter)

    def dominant_protocol(self, protocol_map: Dict[ProtoKey, str]) -> str:
        """Return the most frequent protocol name, preferring outbound.

        The offline pipeline uses ``coalesce(dom_out, dom_in)`` — outbound
        protocol counts are checked first, falling back to inbound.

        Args:
            protocol_map: Mapping from protocol key (int or str) to display name.

        Returns:
            Protocol name string.
        """
        if not self.protocol_counter:
            return "unknown"
        dominant_key = self.protocol_counter.most_common(1)[0][0]
        if isinstance(dominant_key, str) and dominant_key not in protocol_map:
            return dominant_key
        return protocol_map.get(dominant_key, f"proto_{dominant_key}")


class MacAggregator:
    """Streaming aggregator for MAC-level traffic features.

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
        self.buckets: Dict[int, Dict[str, MacSecondBucket]] = {}

    def add(self, value: Dict[str, Any]) -> List[MacAggregatedRecord]:
        """Ingest a raw Netcap record and return flushed aggregates if due.

        Flush is **data-driven**: all second-buckets strictly older than the
        current record's second are emitted.  This guarantees that no bucket
        is flushed while records for that second are still arriving.

        Args:
            value: Raw dict with keys ``time``, ``uci``, ``packet_count``, etc.

        Returns:
            List of finalized :class:`MacAggregatedRecord` objects (may be empty).
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

        self._update_mac_bucket(sec_ts, src_mac, dst_mac, proto_key, value, is_outbound=True)
        self._update_mac_bucket(sec_ts, dst_mac, src_mac, proto_key, value, is_outbound=False)

        return self._flush_older_seconds(sec_ts)

    def flush(self, force: bool = False) -> List[MacAggregatedRecord]:
        """Flush buffered aggregates.

        When ``force`` is ``False``, this is a no-op because flushing is
        entirely data-driven inside :meth:`add`.  The worker thread calls
        ``flush()`` during idle periods; without new data no second
        boundaries can be determined, so nothing is emitted.

        Args:
            force: If ``True``, flush all buckets regardless of time.

        Returns:
            List of finalized :class:`MacAggregatedRecord` objects.
        """
        if not self.enabled:
            return []
        if force:
            return self._flush_all()
        return []

    def _update_mac_bucket(
        self,
        sec_ts: int,
        mac: str,
        peer_mac: str,
        proto_key: ProtoKey,
        raw: Dict[str, Any],
        is_outbound: bool,
    ) -> None:
        """Add record data to the appropriate directional bucket."""
        sec_map = self.buckets.get(sec_ts)
        if sec_map is None:
            sec_map = {}
            self.buckets[sec_ts] = sec_map

        mac_bucket = sec_map.get(mac)
        if mac_bucket is None:
            mac_bucket = MacSecondBucket()
            sec_map[mac] = mac_bucket

        if is_outbound:
            mac_bucket.out_bucket.add(raw, peer_mac, proto_key)
            mac_bucket.protocol_counter[proto_key] += 1
        else:
            mac_bucket.in_bucket.add(raw, peer_mac, proto_key)
            if not mac_bucket.protocol_counter:
                mac_bucket.protocol_counter[proto_key] += 1

    def _build_record(self, sec_ts: int, mac: str, bucket: MacSecondBucket) -> MacAggregatedRecord:
        """Finalize a MacSecondBucket into a MacAggregatedRecord."""
        out_features = bucket.out_bucket.build("out")
        in_features = bucket.in_bucket.build("in")

        out_total_packets = out_features["out_total_packets"]
        in_total_packets = in_features["in_total_packets"]
        out_total_volume = out_features["out_total_volume"]
        in_total_volume = in_features["in_total_volume"]

        safe_out_pkt = out_total_packets if out_total_packets > 0 else 1.0
        safe_out_vol = out_total_volume if out_total_volume > 0 else 1.0

        ratio_in_out_packets = in_total_packets / safe_out_pkt
        ratio_in_out_volume = in_total_volume / safe_out_vol
        total_conn_count = out_features["out_conn_count"] + in_features["in_conn_count"]
        total_unique_peers = out_features["out_unique_dst_count"] + in_features["in_unique_src_count"]

        dominant_protocol = bucket.dominant_protocol(self.protocol_map)

        return MacAggregatedRecord(
            time=sec_ts,
            mac_address=mac,
            dominant_protocol=dominant_protocol,
            out_conn_count=out_features["out_conn_count"],
            out_total_packets=out_total_packets,
            out_total_volume=out_total_volume,
            out_mean_packet_size=out_features["out_mean_packet_size"],
            out_std_packet_size=out_features["out_std_packet_size"],
            out_min_packet_size=out_features["out_min_packet_size"],
            out_max_packet_size=out_features["out_max_packet_size"],
            out_mean_interarrival=out_features["out_mean_interarrival"],
            out_std_interarrival=out_features["out_std_interarrival"],
            out_unique_dst_count=out_features["out_unique_dst_count"],
            out_unique_proto_count=out_features["out_unique_proto_count"],
            in_conn_count=in_features["in_conn_count"],
            in_total_packets=in_total_packets,
            in_total_volume=in_total_volume,
            in_mean_packet_size=in_features["in_mean_packet_size"],
            in_std_packet_size=in_features["in_std_packet_size"],
            in_min_packet_size=in_features["in_min_packet_size"],
            in_max_packet_size=in_features["in_max_packet_size"],
            in_mean_interarrival=in_features["in_mean_interarrival"],
            in_std_interarrival=in_features["in_std_interarrival"],
            in_unique_src_count=in_features["in_unique_src_count"],
            in_unique_proto_count=in_features["in_unique_proto_count"],
            ratio_in_out_packets=ratio_in_out_packets,
            ratio_in_out_volume=ratio_in_out_volume,
            total_conn_count=total_conn_count,
            total_unique_peers=total_unique_peers,
        )

    def _flush_older_seconds(self, current_sec_ts: int) -> List[MacAggregatedRecord]:
        """Flush all second-buckets strictly older than ``current_sec_ts``.

        This is the data-driven flush: when a record from second ``S``
        arrives, all buckets for seconds ``< S`` are guaranteed complete
        and can be safely emitted.

        Args:
            current_sec_ts: Second-aligned timestamp of the current record (ms).

        Returns:
            List of finalized records from expired seconds.
        """
        flushed: List[MacAggregatedRecord] = []
        expired = sorted(s for s in self.buckets if s < current_sec_ts)
        for second_bucket in expired:
            mac_map = self.buckets.pop(second_bucket, {})
            flushed.extend(self._build_record(second_bucket, mac, bucket) for mac, bucket in mac_map.items())
        return flushed

    def _flush_all(self) -> List[MacAggregatedRecord]:
        """Flush every second bucket regardless of time."""
        flushed: List[MacAggregatedRecord] = []
        for second_bucket in sorted(self.buckets.keys()):
            mac_map = self.buckets.pop(second_bucket, {})
            flushed.extend(self._build_record(second_bucket, mac, bucket) for mac, bucket in mac_map.items())
        return flushed
