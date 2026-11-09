"""Port-collapsing rule engine, sparse-port aggregation, and wildcard grouping."""

from otalon_common.connection.models import (
    DynamicBucketConfig,
    PortCollapseConfig,
    PortCollapseRule,
)
from otalon_common.connection.port_collapsing import (
    aggregate_sparse_ports,
    port_wildcard,
)
from otalon_common.connection.rule_engine import (
    apply_port_rules,
    determine_port_collapse_rules,
    rule_covers_ports,
)
from otalon_common.connection.wildcard_groups import build_wildcard_groups

__all__ = [
    "DynamicBucketConfig",
    "PortCollapseConfig",
    "PortCollapseRule",
    "aggregate_sparse_ports",
    "apply_port_rules",
    "build_wildcard_groups",
    "determine_port_collapse_rules",
    "port_wildcard",
    "rule_covers_ports",
]
