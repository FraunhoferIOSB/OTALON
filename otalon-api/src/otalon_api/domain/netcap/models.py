"""Domain constants and types for netcap data processing.

Defines UCI field names, separators, and feature column lists used
throughout the netcap processing pipeline.

``UCI_FIELDS`` is re-exported from ``otalon_common.uci.constants``
as a list for backward compatibility with existing API callers that
expect ``list[str]`` rather than ``tuple[str, ...]``.
"""

from __future__ import annotations

import hashlib

from otalon_common.uci.constants import UCI_FIELDS as _UCI_FIELDS_TUPLE

# Must mirror otalon-clas ``detection/cross_source.py`` /
# ``preprocessing/passthrough.py`` exactly: the proto detection pipeline
# hash-encodes the ``protocol`` tag, so a proto anomaly's / proto bound's
# ``series_id`` is the stringified stable hash of the protocol stack.
_PROTO_HASH_MODULUS: int = 2**31


def proto_series_hash(protocol: str) -> str:
    """Hash a protocol-stack string to its persisted proto series_id.

    The proto preprocessor in otalon-clas hash-encodes the ``protocol``
    tag before training, so bounds and anomalies are persisted under the
    stringified hash, not the plaintext stack.  The InfluxDB
    ``proto_traffic`` measurement, however, still tags by the plaintext
    ``protocol``.  This helper lets the API bridge the two: query Influx by
    plaintext, query PostgreSQL bounds by hash.

    Args:
        protocol: Protocol-stack string (e.g. ``"Ethernet:ARP"``).

    Returns:
        The stringified stable hash matching the persisted series_id.
    """
    digest = hashlib.sha1(protocol.encode("utf-8")).digest()
    return str(int.from_bytes(digest[:8], "big") % _PROTO_HASH_MODULUS)


UCI_FIELDS: list[str] = list(_UCI_FIELDS_TUPLE)

UCI_SEPARATOR: str = "/"

DEFAULT_FEATURES: list[str] = [
    "packet_count",
    "total_volume",
    "mean_packet_size",
]

ALL_FEATURES: list[str] = [
    "packet_count",
    "total_volume",
    "mean_packet_size",
    "min_packet_size",
    "max_packet_size",
    "std_packet_size",
    "mean_interarrival_time",
    "min_interarrival_time",
    "max_interarrival_time",
    "std_interarrival_time",
]

MAC_FEATURES: list[str] = [
    "out_conn_count",
    "out_total_packets",
    "out_total_volume",
    "out_unique_dst_count",
    "out_unique_proto_count",
    "in_conn_count",
    "in_total_packets",
    "in_total_volume",
    "in_unique_src_count",
    "ratio_in_out_packets",
    "ratio_in_out_volume",
    "total_unique_peers",
    "total_conn_count",
]

PROTO_FEATURES: list[str] = [
    "proto_conn_count",
    "proto_total_packets",
    "proto_total_volume",
    "proto_unique_src_mac",
    "proto_unique_dst_mac",
    "proto_unique_mac_pairs",
    "proto_mean_packets_per_conn",
    "proto_mean_volume_per_conn",
    "proto_mean_packet_size",
    "proto_std_packet_size",
]
