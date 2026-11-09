"""UCI (Unique Connection Identifier) parsing, matching, and Polars operations."""

from otalon_common.uci.constants import UCI_BASE_KEYS, UCI_FIELDS, UCI_SEGMENT_COUNT
from otalon_common.uci.matching import (
    base_key_without_ports,
    is_wildcard_uci,
    match_uci_pattern,
    matches_port_collapse_sibling,
)
from otalon_common.uci.parser import (
    UciParts,
    normalize_uci,
    parse_uci,
    parse_uci_to_dict,
)
from otalon_common.uci.polars_ops import collapse_uci, expand_uci

__all__ = [
    "UCI_BASE_KEYS",
    "UCI_FIELDS",
    "UCI_SEGMENT_COUNT",
    "UciParts",
    "base_key_without_ports",
    "collapse_uci",
    "expand_uci",
    "is_wildcard_uci",
    "match_uci_pattern",
    "matches_port_collapse_sibling",
    "normalize_uci",
    "parse_uci",
    "parse_uci_to_dict",
]
