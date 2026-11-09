"""Netcap aggregation service.

Provides methods for aggregating sparse-port time-series data
for wildcard UCI identifiers.  When pre-computed port-collapse rules
are available in PostgreSQL, the service uses rule-aware aggregation
via ``otalon_common``.  Otherwise it falls back to stateless
sparse-port aggregation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, cast

import pandas as pd
import polars as pl
from loguru import logger
from otalon_common.connection.models import PortCollapseRule
from otalon_common.connection.rule_engine import apply_port_rules

from otalon_api.domain.netcap import processing
from otalon_api.domain.time import time_policy
from otalon_api.domain.topology.uci import base_key_without_ports, match_uci_pattern, parse_uci
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.repositories.port_collapse_repo import PortCollapseRepository
from otalon_api.settings import Settings


def _df_to_rules(rules_df: pl.DataFrame) -> list[PortCollapseRule]:
    """Convert a rules DataFrame (from PostgreSQL) to PortCollapseRule objects.

    Args:
        rules_df: DataFrame with columns matching PortCollapseRule fields.

    Returns:
        A list of PortCollapseRule Pydantic model instances.
    """
    return [PortCollapseRule(**row) for row in rules_df.to_dicts()]


class NetcapAggregationService:
    """Service for wildcard UCI aggregation of sparse-port timeseries."""

    def __init__(
        self,
        influx_repo: InfluxRepository,
        settings: Settings,
        port_collapse_repo: Optional[PortCollapseRepository] = None,
    ) -> None:
        """Initialize the aggregation service.

        Args:
            influx_repo: InfluxDB repository for data access.
            settings: Application settings.
            port_collapse_repo: Optional port-collapse repository for
                rule-aware aggregation.  When ``None``, stateless
                fallback is always used.
        """
        self._repo = influx_repo
        self._settings = settings
        self._port_collapse_repo = port_collapse_repo

    def _load_rules(self) -> Optional[list[PortCollapseRule]]:
        """Attempt to load port-collapse rules for the ``"conn"`` module.

        Returns:
            A list of rules, or ``None`` if no rules are available.
        """
        if self._port_collapse_repo is None:
            return None
        rules_df = self._port_collapse_repo.get_rules("conn")
        if rules_df is None:
            return None
        return _df_to_rules(rules_df)

    def aggregate_wildcard_timeseries(
        self,
        wildcard_uci: str,
        members: list[str],
        start: datetime,
        stop: datetime,
        features: list[str],
    ) -> pd.DataFrame:
        """Aggregate sparse-port timeseries for a wildcard UCI.

        Tries rule-aware aggregation first (via ``apply_port_rules``
        from ``otalon_common``).  Falls back to stateless
        ``aggregate_sparse_ports`` when no rules are available.

        Args:
            wildcard_uci: The wildcard UCI string (with ``"*"`` in port
                positions).
            members: List of concrete UCI strings belonging to this
                wildcard group.
            start: Range start in local time.
            stop: Range end in local time.
            features: List of feature column names to aggregate.

        Returns:
            A pandas DataFrame with ``time`` as a column followed by
            the requested features.
        """
        start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)

        required_cols = {"packet_count", "total_volume"}
        extra = [c for c in sorted(required_cols) if c not in features]
        query_fields = list(dict.fromkeys(list(features) + extra))

        logger.debug(
            "aggregate_wildcard_timeseries uci={} members={} start={} stop={} query_fields={}",
            wildcard_uci,
            len(members),
            start_str,
            stop_str,
            query_fields,
        )

        df_raw = self._repo.query_timeseries_multi_ids_chunked(
            measurement=self._settings.netcap_measurement,
            id_tag=self._settings.netcap_id_tag,
            fields=query_fields,
            start=start_str,
            stop=stop_str,
            ids=list(members),
        )

        if df_raw.empty:
            logger.debug("aggregate_wildcard_timeseries: empty raw result")
            return pd.DataFrame(columns=["time", *list(features)])

        pl_df = pl.DataFrame(df_raw.to_dict(orient="records"))
        pl_df = processing.preprocess(pl_df)
        pl_df = cast(pl.DataFrame, processing.expand_uci(pl_df))

        rules = self._load_rules()
        if rules is not None:
            pl_df = apply_port_rules(pl_df, rules)
            logger.debug("aggregate_wildcard_timeseries: applied {} rules", len(rules))
            if "_bucket_epoch" in pl_df.columns and "time" not in pl_df.columns:
                pl_df = pl_df.with_columns(pl.from_epoch(pl.col("_bucket_epoch"), time_unit="s").alias("time"))
        else:
            pl_df = processing.aggregate_sparse_ports(
                pl_df,
                threshold=self._settings.netcap_sparse_port_threshold,
                feature_cols=features,
            )

        pl_sel = processing.extract_wildcard_timeseries(pl_df, wildcard_uci=wildcard_uci)

        if pl_sel.is_empty():
            logger.debug("aggregate_wildcard_timeseries: no rows after wildcard filter")
            return pd.DataFrame(columns=["time", *list(features)])

        result = processing.to_pandas_timeseries(pl_sel, features=features)
        result = cast(pd.DataFrame, time_policy.normalize_time_for_ui(result, time_cols=["time"]))

        logger.debug("aggregate_wildcard_timeseries result: {} rows", len(result))
        return result

    def build_wildcard_groups(self, ucis: list[str]) -> dict[str, tuple[list[str], bool]]:
        """Group UCIs by base key (without ports) and create wildcard patterns.

        When port-collapse rules are available, wildcard groups are
        derived from the ``normalized_uci`` column of the rules
        DataFrame.  Otherwise falls back to computing groups from the
        raw UCI list.

        Args:
            ucis: List of raw UCI strings from InfluxDB.

        Returns:
            Mapping of wildcard (or concrete) UCI to ``(members,
            rule_trained)``. Single-member groups retain their original
            concrete UCI as key.
        """
        rules = self._load_rules()
        if rules is not None:
            return self._build_groups_from_rules(rules, ucis)
        return {wildcard: (members, False) for wildcard, members in self._build_groups_stateless(ucis).items()}

    def _build_groups_from_rules(
        self,
        rules: list[PortCollapseRule],
        ucis: list[str],
    ) -> dict[str, tuple[list[str], bool]]:
        """Build wildcard groups using pre-computed port-collapse rules.

        Maps each concrete UCI to the rule whose base key matches, using the
        rule's ``normalized_uci`` as the wildcard group key.  A concrete-port
        rule only relabels a runtime UCI whose ports agree with the rule's
        ``normalized_uci`` on every non-wildcarded port dimension; when a
        runtime UCI carries a concrete port that differs from a non-wildcarded
        rule port (e.g. an endpoint that rotated its ephemeral port after the
        rule was trained), the UCI is left unmatched and falls through to
        stateless grouping instead of being relabeled with the stale rule port.

        Args:
            rules: List of port-collapse rules.
            ucis: List of concrete UCI strings.

        Returns:
            Mapping of normalized (wildcard) UCIs to member lists.
        """
        rule_lookup: dict[tuple[str, ...], PortCollapseRule] = {}
        for rule in rules:
            rule_key = (
                rule.src_mac,
                rule.dst_mac,
                rule.vlan,
                rule.ip_proto,
                rule.src_ip,
                rule.dst_ip,
                rule.protocols,
            )
            rule_lookup[rule_key] = rule

        result: dict[str, tuple[list[str], bool]] = {}
        unmatched: list[str] = []
        for uci_val in ucis:
            base = base_key_without_ports(uci_val)
            matched_rule = rule_lookup.get(base)
            if matched_rule is None:
                unmatched.append(uci_val)
                continue
            runtime_parts = parse_uci(uci_val)
            rule_parts = parse_uci(matched_rule.normalized_uci)
            src_port_ok = runtime_parts.src_port == rule_parts.src_port or matched_rule.wildcard_src_port
            dst_port_ok = runtime_parts.dst_port == rule_parts.dst_port or matched_rule.wildcard_dst_port
            if not (src_port_ok and dst_port_ok):
                unmatched.append(uci_val)
                continue
            members, _ = result.get(matched_rule.normalized_uci, ([], True))
            members.append(uci_val)
            result[matched_rule.normalized_uci] = (members, True)

        for wildcard, (members, rule_trained) in list(result.items()):
            result[wildcard] = (sorted(members), rule_trained)
        for wildcard, members in self._build_groups_stateless(unmatched).items():
            result[wildcard] = (members, False)
        return result

    def _build_groups_stateless(self, ucis: list[str]) -> dict[str, list[str]]:
        """Build wildcard groups using stateless port analysis.

        UCIs that share the same base key but differ in source or
        destination port are merged into a single wildcard UCI with
        ``"*"`` replacing the heterogeneous port field(s).

        Args:
            ucis: List of raw UCI strings from InfluxDB.

        Returns:
            Mapping of wildcard (or concrete) UCI to its member UCIs.
        """
        groups: dict[tuple[str, str, str, str, str, str, str], list[str]] = {}
        for uci_val in ucis:
            key = base_key_without_ports(uci_val)
            groups.setdefault(key, []).append(uci_val)

        result: dict[str, list[str]] = {}
        for key, members in groups.items():
            src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, protocols = key
            src_ports = {parse_uci(m).src_port for m in members}
            dst_ports = {parse_uci(m).dst_port for m in members}
            sp = next(iter(src_ports)) if len(src_ports) == 1 else "*"
            dp = next(iter(dst_ports)) if len(dst_ports) == 1 else "*"
            wildcard = "/".join([src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, sp, dp, protocols])
            result[wildcard] = sorted(members)
        return result

    def resolve_and_aggregate(
        self,
        wildcard_uci: str,
        start: datetime,
        stop: datetime,
        features: list[str],
    ) -> pd.DataFrame:
        """Resolve members for a wildcard UCI and aggregate their timeseries.

        When port-collapse rules are available, member UCIs are derived
        from the rules (base-key match) instead of loading all UCIs
        from InfluxDB.  Falls back to full UCI scan when no rules exist.

        Args:
            wildcard_uci: The wildcard UCI string (contains ``"*"``).
            start: Range start in local time.
            stop: Range end in local time.
            features: List of feature column names to aggregate.

        Returns:
            A pandas DataFrame with ``time`` as a column followed by
            the requested features.
        """
        members = self._resolve_members(wildcard_uci, start, stop)

        logger.debug(
            "resolve_and_aggregate wildcard={} resolved {} members",
            wildcard_uci,
            len(members),
        )

        if not members:
            return pd.DataFrame(columns=["time", *list(features)])

        return self.aggregate_wildcard_timeseries(
            wildcard_uci=wildcard_uci,
            members=members,
            start=start,
            stop=stop,
            features=features,
        )

    def _resolve_members(
        self,
        wildcard_uci: str,
        start: datetime,
        stop: datetime,
    ) -> list[str]:
        """Resolve concrete member UCIs for a wildcard pattern.

        Tries rules first for an optimized lookup, then falls back to
        querying all UCIs from InfluxDB and filtering.

        Args:
            wildcard_uci: The wildcard UCI pattern.
            start: Range start.
            stop: Range end.

        Returns:
            List of concrete UCI strings matching the wildcard.
        """
        rules = self._load_rules()
        if rules is not None:
            members = self._members_from_rules(wildcard_uci, rules)
            concrete = [m for m in members if "*" not in m]
            if concrete:
                return concrete

        return self._members_from_influx(wildcard_uci, start, stop)

    def _members_from_rules(
        self,
        wildcard_uci: str,
        rules: list[PortCollapseRule],
    ) -> list[str]:
        """Derive member UCIs from rules by base-key matching.

        Args:
            wildcard_uci: The wildcard UCI pattern.
            rules: Pre-computed port-collapse rules.

        Returns:
            List of matching normalized UCIs from rules, or empty
            list if the wildcard doesn't match any rule.
        """
        wc_base = base_key_without_ports(wildcard_uci)
        members: list[str] = []
        for rule in rules:
            rule_base = (
                rule.src_mac,
                rule.dst_mac,
                rule.vlan,
                rule.ip_proto,
                rule.src_ip,
                rule.dst_ip,
                rule.protocols,
            )
            if rule_base == wc_base:
                members.append(rule.normalized_uci)
        return members

    def _members_from_influx(
        self,
        wildcard_uci: str,
        start: datetime,
        stop: datetime,
    ) -> list[str]:
        """Resolve member UCIs by scanning all UCIs from InfluxDB.

        Args:
            wildcard_uci: The wildcard UCI pattern.
            start: Range start.
            stop: Range end.

        Returns:
            List of concrete UCIs matching the wildcard pattern.
        """
        start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)

        all_ids = self._repo.list_ids_between(
            measurement=self._settings.netcap_measurement,
            id_tag=self._settings.netcap_id_tag,
            start=start_str,
            stop=stop_str,
        )

        return [uid for uid in all_ids if match_uci_pattern(wildcard_uci, uid)]
