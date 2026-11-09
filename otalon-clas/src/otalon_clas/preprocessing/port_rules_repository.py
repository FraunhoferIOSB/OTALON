"""PostgreSQL-backed repository for port-collapse rules.

Persists per-module ``PortCollapseRule`` instances in the
``port_collapse_rules`` table so that training and live prediction
share the same rule set across process restarts.
"""

from __future__ import annotations

from datetime import datetime, timezone

from loguru import logger
from otalon_common.connection import PortCollapseRule
from otalon_common.uci.parser import parse_uci

from otalon_clas.common.postgres_connector import (
    PortCollapseRuleRecord,
    PostgresConnector,
)


def _enforce_star_invariant(rule: PortCollapseRule) -> PortCollapseRule:
    """Ensure a rule's wildcard flags match the ``*`` markers in its UCI.

    The ``normalized_uci`` port positions and the ``wildcard_*_port`` flags must
    agree: a ``*`` port implies the flag is True and vice versa. The rule engine
    guarantees this (CLAS-035), but a stale or legacy rule may violate it. The
    ``normalized_uci`` is treated as authoritative — when it disagrees with a
    flag, the flag is corrected and a warning is logged so the drift is visible.
    A ``*`` port with a False flag is the contamination case the fix targets; the
    reverse (concrete port with a True flag) is also corrected so the persisted
    rule is self-consistent.

    Args:
        rule: The rule to validate.

    Returns:
        The original rule when the invariant holds, otherwise a corrected copy.
    """
    parts = parse_uci(rule.normalized_uci)
    src_star = parts.src_port == "*"
    dst_star = parts.dst_port == "*"
    if src_star == rule.wildcard_src_port and dst_star == rule.wildcard_dst_port:
        return rule
    logger.warning(
        "PortCollapseRulesRepository: star-invariant mismatch for {} — "
        "correcting wildcard_src_port {}->{}, wildcard_dst_port {}->{}",
        rule.normalized_uci,
        rule.wildcard_src_port,
        src_star,
        rule.wildcard_dst_port,
        dst_star,
    )
    return rule.model_copy(
        update={"wildcard_src_port": src_star, "wildcard_dst_port": dst_star}
    )


class PortCollapseRulesRepository:
    """Persists port-collapse rules to and loads them from PostgreSQL.

    Args:
        connector: PostgreSQL connector providing session management.
    """

    def __init__(self, connector: PostgresConnector) -> None:
        """Initialize the rules repository."""
        self._connector = connector

    def save(self, module: str, rules: list[PortCollapseRule]) -> int:
        """Replace all rules for a module with the supplied set.

        Existing rows for the module are deleted before the new rules
        are inserted to avoid stale rules surviving repeated training
        runs.

        Args:
            module: Detection module name (e.g. ``"conn"``).
            rules: List of PortCollapseRule instances to persist.

        Returns:
            Number of rule rows written.
        """
        with self._connector.session() as session:
            session.query(PortCollapseRuleRecord).filter(
                PortCollapseRuleRecord.module == module
            ).delete()
            for rule in rules:
                corrected = _enforce_star_invariant(rule)
                record = PortCollapseRuleRecord(
                    module=module,
                    src_mac=corrected.src_mac,
                    dst_mac=corrected.dst_mac,
                    vlan=corrected.vlan,
                    ip_proto=corrected.ip_proto,
                    src_ip=corrected.src_ip,
                    dst_ip=corrected.dst_ip,
                    protocols=corrected.protocols,
                    normalized_uci=corrected.normalized_uci,
                    wildcard_src_port=corrected.wildcard_src_port,
                    wildcard_dst_port=corrected.wildcard_dst_port,
                    bucket_seconds=corrected.bucket_seconds,
                )
                session.add(record)
        logger.info(
            "PortCollapseRulesRepository[{}]: persisted {} rules to PostgreSQL",
            module,
            len(rules),
        )
        return len(rules)

    def snapshot_module(self, module: str) -> list[PortCollapseRule]:
        """Return the persisted rules for ``module`` as a rollback snapshot.

        Named to mirror ``BoundsRepository.snapshot_module`` so the
        JobRunner's compensation path treats every persisted artifact the
        same way (audit CLAS-02).

        Args:
            module: Module name to snapshot.

        Returns:
            The currently persisted rules; empty when the module has none.
        """
        return self.load(module)

    def restore_module(self, module: str, rules: list[PortCollapseRule]) -> int:
        """Restore a previously captured rule snapshot for ``module``.

        Replaces whatever is currently stored, including restoring the
        empty state when the module had no rules before.

        Args:
            module: Module name to restore.
            rules: Snapshot previously returned by :meth:`snapshot_module`.

        Returns:
            Number of rules written.
        """
        return self.save(module, list(rules))

    def load(self, module: str) -> list[PortCollapseRule]:
        """Load all rules for the given module.

        Args:
            module: Detection module name.

        Returns:
            List of PortCollapseRule instances; empty when no rules exist.
        """
        with self._connector.session() as session:
            rows = (
                session.query(PortCollapseRuleRecord)
                .filter(PortCollapseRuleRecord.module == module)
                .all()
            )
            rules = [
                PortCollapseRule(
                    src_mac=str(row.src_mac),
                    dst_mac=str(row.dst_mac),
                    vlan=str(row.vlan),
                    ip_proto=str(row.ip_proto),
                    src_ip=str(row.src_ip),
                    dst_ip=str(row.dst_ip),
                    protocols=str(row.protocols),
                    normalized_uci=str(row.normalized_uci),
                    wildcard_src_port=bool(row.wildcard_src_port),
                    wildcard_dst_port=bool(row.wildcard_dst_port),
                    bucket_seconds=int(row.bucket_seconds),
                )
                for row in rows
            ]
        logger.info(
            "PortCollapseRulesRepository[{}]: loaded {} rules from PostgreSQL",
            module,
            len(rules),
        )
        return rules

    def upsert_rules(self, module: str, rules: list[PortCollapseRule]) -> int:
        """Insert or update rules for a module without deleting existing rows.

        Each rule is merged on the composite primary key (``module`` plus the
        7 base-key fields): a matching row is updated in place (``created_at``
        preserved, ``updated_at`` refreshed to the current time), while a new
        base key is inserted. Unlike :meth:`save`, no rows are deleted, so a
        refresh cycle that only recomputes a subset of rules never drops the
        rest.

        Args:
            module: Detection module name (e.g. ``"conn"``).
            rules: List of PortCollapseRule instances to upsert.

        Returns:
            Number of rule rows written.
        """
        now = datetime.now(timezone.utc)
        with self._connector.session() as session:
            for rule in rules:
                corrected = _enforce_star_invariant(rule)
                record = PortCollapseRuleRecord(
                    module=module,
                    src_mac=corrected.src_mac,
                    dst_mac=corrected.dst_mac,
                    vlan=corrected.vlan,
                    ip_proto=corrected.ip_proto,
                    src_ip=corrected.src_ip,
                    dst_ip=corrected.dst_ip,
                    protocols=corrected.protocols,
                    normalized_uci=corrected.normalized_uci,
                    wildcard_src_port=corrected.wildcard_src_port,
                    wildcard_dst_port=corrected.wildcard_dst_port,
                    bucket_seconds=corrected.bucket_seconds,
                    updated_at=now,
                )
                session.merge(record)
        logger.info(
            "PortCollapseRulesRepository[{}]: upserted {} rules to PostgreSQL",
            module,
            len(rules),
        )
        return len(rules)
