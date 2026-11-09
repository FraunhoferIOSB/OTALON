"""Aggregation helpers for Netcap++ sparse port records."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

def _uci_to_parts(uci: str) -> List[str]:
    """Split a UCI string into exactly nine components, padding missing parts."""

    parts = uci.split("/")
    if len(parts) < 9:
        parts = parts + [""] * (9 - len(parts))
    return parts[:9]

def _safe_num(x: Any, default: float = 0.0) -> float:
    """Return ``value`` converted to ``float`` or ``default`` on failure."""
    
    try:
        return float(x)
    except Exception:
        return default

def _safe_int(x: Any, default: int = 0) -> int:
    """Return ``value`` converted to ``int`` or ``default`` on failure."""
    
    try:
        return int(x)
    except Exception:
        return default

@dataclass
class AggregatedNetcapRecord:
    """Aggregated representation of a Netcap record emitted after bucketing."""
    
    time: int
    uci: str
    packet_count: int
    total_volume: int
    mean_packet_size: float
    min_packet_size: int
    max_packet_size: int
    std_packet_size: float
    mean_interarrival_time: float
    min_interarrival_time: float
    max_interarrival_time: float
    std_interarrival_time: float
    collapsed_port_count: Optional[int] = None

    def get_time(self) -> int:
        """Return the start timestamp of the aggregated record in milliseconds."""

        return self.time

    def get_uci(self) -> str:
        """Return the aggregated UCI string."""

        return self.uci

    def get_total_packet_count(self) -> int:
        """Return the aggregated packet count."""

        return self.packet_count

    def get_total_volume(self) -> int:
        """Return the aggregated total volume."""

        return self.total_volume

    def get_mean_packet_size(self) -> float:
        """Return the mean packet size."""

        return self.mean_packet_size

    def get_min_packet_size(self) -> int:
        """Return the minimum packet size."""

        return self.min_packet_size

    def get_max_packet_size(self) -> int:
        """Return the maximum packet size."""

        return self.max_packet_size

    def get_sd_packet_size(self) -> float:
        """Return the standard deviation of the packet size."""

        return self.std_packet_size

    def get_mean_packet_inter_arrival_time(self) -> float:
        """Return the mean packet inter-arrival time."""

        return self.mean_interarrival_time

    def get_min_packet_inter_arrival_time(self) -> float:
        """Return the minimum packet inter-arrival time."""

        return self.min_interarrival_time

    def get_max_packet_inter_arrival_time(self) -> float:
        """Return the maximum packet inter-arrival time."""

        return self.max_interarrival_time

    def get_sd_packet_inter_arrival_time(self) -> float:
        """Return the standard deviation of the packet inter-arrival time."""

        return self.std_interarrival_time

    def get_collapsed_port_count(self) -> Optional[int]:
        """Return the number of distinct ports collapsed into a wildcard."""

        return self.collapsed_port_count


@dataclass
class AggregationBucket:
    """Collect metrics for multiple Netcap records sharing the same UCI base."""
    
    src_ports: Set[str] = field(default_factory=set)
    dst_ports: Set[str] = field(default_factory=set)
    total_packet_count: int = 0
    total_volume: float = 0.0
    min_packet_size: Optional[int] = None
    max_packet_size: Optional[int] = None
    sum_std_packet_size: float = 0.0
    std_ps_count: int = 0
    mit_weight: float = 0.0
    pc_weight: float = 0.0
    min_iat: Optional[float] = None
    max_iat: Optional[float] = None
    sum_std_iat: float = 0.0
    std_iat_count: int = 0
    
    def add(self, v: Dict) -> None:
        """Update aggregation statistics with a raw Netcap ``record``."""
        
        uci_str = v.get("uci", "unknown")
        p = _uci_to_parts(uci_str)
        self.src_ports.add(p[6])
        self.dst_ports.add(p[7])

        pc = _safe_int(v.get("packet_count", 0))
        vol = _safe_num(v.get("total_volume", 0.0))
        min_ps = _safe_int(v.get("min_packet_size", 0))
        max_ps = _safe_int(v.get("max_packet_size", 0))
        std_ps = _safe_num(v.get("std_packet_size", 0.0))
        
        mit = _safe_num(v.get("mean_interarrival_time", 0.0))
        min_iat = _safe_num(v.get("min_interarrival_time", 0.0))
        max_iat = _safe_num(v.get("max_interarrival_time", 0.0))
        std_iat = _safe_num(v.get("std_interarrival_time", 0.0))
        
        self.total_packet_count += pc
        self.total_volume += vol
        self.min_packet_size = min(min_ps, self.min_packet_size) if self.min_packet_size is not None else min_ps
        self.max_packet_size = max(max_ps, self.max_packet_size) if self.max_packet_size is not None else max_ps
        self.sum_std_packet_size += std_ps
        self.std_ps_count += 1

        self.mit_weight += mit * float(pc)
        self.pc_weight += float(pc)
        self.min_iat = min(min_iat, self.min_iat) if self.min_iat is not None else min_iat
        self.max_iat = max(max_iat, self.max_iat) if self.max_iat is not None else max_iat
        self.sum_std_iat += std_iat
        self.std_iat_count += 1

    def build(self, sec_ts: int, uci_base: Tuple[str, str, str, str, str, str, str]) -> AggregatedNetcapRecord:
        """Create an :class:`AggregatedNetcapRecord` from the accumulated values."""
        
        src_port_final = next(iter(self.src_ports)) if len(self.src_ports) == 1 else "*"
        dst_port_final = next(iter(self.dst_ports)) if len(self.dst_ports) == 1 else "*"

        collapsed_port_count = None
        if len(self.src_ports) > 1 or len(self.dst_ports) > 1:
            collapsed_port_count = (
                (len(self.src_ports) if len(self.src_ports) > 1 else 0)
                + (len(self.dst_ports) if len(self.dst_ports) > 1 else 0)
            )

        src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, protocols = uci_base
        uci_final = "/".join([src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, src_port_final, dst_port_final, protocols])

        total_pc = int(self.total_packet_count)
        total_vol = int(self.total_volume)
        mean_ps = float(total_vol / total_pc) if total_pc > 0 else 0.0
        std_ps = float(self.sum_std_packet_size / self.std_ps_count) if self.std_ps_count > 0 else 0.0

        mean_iat = float(self.mit_weight / self.pc_weight) if self.pc_weight > 0.0 else 0.0
        std_iat = float(self.sum_std_iat / self.std_iat_count) if self.std_iat_count > 0 else 0.0

        return AggregatedNetcapRecord(
            time=sec_ts,
            uci=uci_final,
            packet_count=total_pc,
            total_volume=total_vol,
            mean_packet_size=mean_ps,
            min_packet_size=int(self.min_packet_size or 0),
            max_packet_size=int(self.max_packet_size or 0),
            std_packet_size=std_ps,
            mean_interarrival_time=mean_iat,
            min_interarrival_time=float(self.min_iat or 0.0),
            max_interarrival_time=float(self.max_iat or 0.0),
            std_interarrival_time=std_iat,
            collapsed_port_count=collapsed_port_count,
        )


class SparsePortAggregator:
    """Aggregate sparse port metrics into coarser buckets before writing."""
    
    def __init__(self, enabled: bool, emit_interval_ms: int = 1000) -> None:
        self.enabled = enabled
        self.emit_interval_ms = int(emit_interval_ms)
        self.buckets: Dict[int, Dict[Tuple[str, str, str, str, str, str, str], AggregationBucket]] = {}
        self._last_tick_ms: Optional[float] = None
        self._time_provider = time.time
        self._monotonic_provider = time.monotonic
        self._latest_record_ms: Optional[int] = None
        """Highest record timestamp seen, in ms.

        Buckets are keyed by RECORD time, but flush eligibility used to be
        decided against the wall clock. The two are unrelated whenever the
        data is not arriving live: replaying a PCAP from last week made
        every bucket instantly "expired" (so aggregation degenerated to
        pass-through), while a processing backlog or a clock step could
        expire buckets that were still filling and split one second's
        traffic across several emitted records (audit CAP-05).
        """

    def add(self, value: Dict) -> List[Any]:
        """Add a single Netcap ``record`` and return flushed aggregates if due."""
        if not self.enabled:
            return [value]

        rs_ms = value.get("time", 0)
        sec_ts = int(rs_ms // 1000 * 1000)
        # Track the data's own clock; it, not the wall clock, decides which
        # buckets can no longer receive records (audit CAP-05).
        if self._latest_record_ms is None or sec_ts > self._latest_record_ms:
            self._latest_record_ms = sec_ts

        uci_str = value.get("uci", "unknown")
        parts = _uci_to_parts(uci_str)
        base_key = (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[8])

        sec_map = self.buckets.get(sec_ts)
        if sec_map is None:
            sec_map = {}
            self.buckets[sec_ts] = sec_map

        bucket = sec_map.get(base_key)
        if bucket is None:
            bucket = AggregationBucket()
            sec_map[base_key] = bucket
        bucket.add(value)

        return self._flush_due()

    def flush(self, force: bool = False) -> List[AggregatedNetcapRecord]:
        """Flush buffered aggregates, optionally forcing all buckets to emit."""

        if not self.enabled:
            return []
        if force:
            return self._flush_all()
        return self._flush_due()

    def _flush_due(self) -> List[AggregatedNetcapRecord]:
        now_ms = self._monotonic_provider() * 1000.0
        if self._last_tick_ms is None:
            self._last_tick_ms = now_ms
            return []
        if (now_ms - self._last_tick_ms) < float(self.emit_interval_ms):
            return []
        self._last_tick_ms = now_ms
        return self._flush_expired_buckets(self._current_second_bucket())

    def _flush_all(self) -> List[AggregatedNetcapRecord]:
        flushed: List[AggregatedNetcapRecord] = []
        for second_bucket in sorted(self.buckets.keys()):
            second_map = self.buckets.pop(second_bucket, {})
            flushed.extend(
                bucket.build(second_bucket, base_key) for base_key, bucket in second_map.items()
            )
        return flushed

    def _flush_expired_buckets(self, cutoff_ms: int) -> List[AggregatedNetcapRecord]:
        flushed: List[AggregatedNetcapRecord] = []
        expired = sorted(second for second in self.buckets if second < cutoff_ms)
        for second_bucket in expired:
            second_map = self.buckets.pop(second_bucket, {})
            flushed.extend(
                bucket.build(second_bucket, base_key) for base_key, bucket in second_map.items()
            )
        return flushed

    def _current_second_bucket(self) -> int:
        """Return the cutoff below which buckets can be safely emitted.

        Derived from the newest RECORD timestamp, so it tracks the data
        being processed rather than the host clock. Records arrive in
        non-decreasing second order per capture, so every bucket strictly
        older than the newest one is complete.

        Falls back to the wall clock only before the first record, when
        there is no data-side clock yet (and no buckets to flush either).
        """
        if self._latest_record_ms is not None:
            return self._latest_record_ms
        epoch_seconds = int(self._time_provider() // 1)
        return epoch_seconds * 1000
