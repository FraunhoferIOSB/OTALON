"""Pydantic configuration and rule models for port-collapsing."""

from typing import Literal

from pydantic import BaseModel


class PortCollapseConfig(BaseModel):
    """Configuration for the port-collapse rule determination algorithm.

    Attributes:
        strategy: Wildcard strategy (``"heuristic_frequency"`` or ``"always_wildcard_src"``).
        port_variation_threshold: Number of distinct ports above which wildcarding is considered.
        dominance_threshold: Ratio above which a dominant port prevents wildcarding. Interpreted
            as a temporal-persistence threshold: the fraction of time buckets that must be won by
            the single most-common bucket-winner for the port to be preserved instead of wildcarded.
        service_ports: Well-known service ports that are treated preferentially.
        persistence_bucket_seconds: Width in seconds of the time buckets used by the
            temporal-persistence dominance gate. A port that runs for hours occupies many buckets,
            so a slowly-rotating ephemeral port has different bucket-winners across the window and
            is detected as rotation, while a stable service port wins (almost) every bucket.
            Default 300 (5 min): coarse enough to be cheap, fine enough to detect rotation.
        persistence_min_share: Minimum fraction of time buckets a port must win to count as a
            "relevant bucket-winner". Wildcarding triggers when at least two ports each clear this
            share (= genuine rotation), which is more robust than a single top-ratio threshold: a
            stable service port with sporadic outliers has only one relevant winner (the rest never
            clear the share), whereas a slowly-rotating port has multiple. Default 0.10.
    """

    strategy: Literal["heuristic_frequency", "always_wildcard_src"] = (
        "heuristic_frequency"
    )
    port_variation_threshold: int = 2
    dominance_threshold: float = 0.7
    service_ports: list[int] = [80, 443, 4840]
    persistence_bucket_seconds: int = 300
    persistence_min_share: float = 0.10


class DynamicBucketConfig(BaseModel):
    """Configuration for dynamic time-bucket sizing.

    Attributes:
        allowed_seconds: Candidate bucket sizes in ascending order.
        target_events_min: Minimum expected events per bucket.
        target_events_max: Maximum expected events per bucket.
        occupancy_threshold: Minimum ratio of non-empty buckets.
        fallback_bucket_seconds: Default bucket size when no candidate satisfies constraints.
    """

    allowed_seconds: list[int] = [1, 5, 10, 30, 60, 120, 300, 600]
    target_events_min: int = 1
    target_events_max: int = 100
    occupancy_threshold: float = 0.2
    fallback_bucket_seconds: int = 60


class PortCollapseRule(BaseModel):
    """A computed port-collapse rule for a connection group.

    Attributes:
        src_mac: Source MAC address.
        dst_mac: Destination MAC address.
        vlan: VLAN identifier.
        ip_proto: IP protocol number.
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        protocols: Protocol stack string.
        normalized_uci: Full 9-field UCI with wildcarded ports applied.
        wildcard_src_port: Whether the source port was wildcarded.
        wildcard_dst_port: Whether the destination port was wildcarded.
        bucket_seconds: Optimal time-bucket size in seconds.
    """

    src_mac: str
    dst_mac: str
    vlan: str
    ip_proto: str
    src_ip: str
    dst_ip: str
    protocols: str
    normalized_uci: str
    wildcard_src_port: bool = False
    wildcard_dst_port: bool = False
    bucket_seconds: int = 1
