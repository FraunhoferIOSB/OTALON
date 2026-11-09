"""Canonical UCI field constants."""

UCI_FIELDS: tuple[str, ...] = (
    "src_mac",
    "dst_mac",
    "vlan",
    "ip_proto",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocols",
)
"""All 9 UCI field names in positional order."""

UCI_BASE_KEYS: tuple[str, ...] = (
    "src_mac",
    "dst_mac",
    "vlan",
    "ip_proto",
    "src_ip",
    "dst_ip",
    "protocols",
)
"""7 base-key field names (UCI without ports) for port-collapse grouping."""

UCI_SEGMENT_COUNT: int = 9
"""Expected number of segments in a fully-formed UCI string."""
