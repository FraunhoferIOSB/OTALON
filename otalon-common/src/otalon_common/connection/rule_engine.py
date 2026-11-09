"""Port-collapse rule determination and application.

Implements the canonical rule engine based on port-variance analysis, dominance
ratios, service-port awareness, and dynamic bucketing.
"""

from datetime import datetime
from typing import cast

import polars as pl
from otalon_common.connection.models import (
    DynamicBucketConfig,
    PortCollapseConfig,
    PortCollapseRule,
)
from otalon_common.uci.constants import UCI_BASE_KEYS, UCI_FIELDS
from otalon_common.uci.parser import parse_uci

FEATURE_AGGREGATIONS: dict[str, str] = {
    "packet_count": "sum",
    "total_volume": "sum",
    "min_packet_size": "min",
    "max_packet_size": "max",
    "min_interarrival_time": "min",
    "max_interarrival_time": "max",
    "std_packet_size": "mean",
    "std_interarrival_time": "mean",
}
"""Mapping of feature column names to their aggregation method."""

WEIGHTED_MEAN_FEATURES: tuple[str, ...] = ("mean_packet_size", "mean_interarrival_time")
"""Features aggregated via weighted mean (weighted by packet_count)."""


def determine_port_collapse_rules(
    df_expanded: pl.DataFrame,
    port_config: PortCollapseConfig | None = None,
    bucket_config: DynamicBucketConfig | None = None,
) -> list[PortCollapseRule]:
    """Analyze port variance per base-key group and compute collapse rules.

    Args:
        df_expanded: DataFrame with expanded UCI columns (all 9 fields present).
        port_config: Configuration for port-collapse heuristics. Uses defaults if None.
        bucket_config: Configuration for dynamic bucket sizing. Uses defaults if None.

    Returns:
        A list of PortCollapseRule instances, one per base-key group.
    """
    if port_config is None:
        port_config = PortCollapseConfig()
    if bucket_config is None:
        bucket_config = DynamicBucketConfig()

    base_keys = list(UCI_BASE_KEYS)
    groups = df_expanded.group_by(base_keys)

    rules: list[PortCollapseRule] = []
    for group_keys, group_df in groups:
        rule = _compute_group_rule(
            cast(tuple[str, ...], group_keys),
            group_df,
            base_keys,
            port_config,
            bucket_config,
        )
        rules.append(rule)

    return rules


def _compute_group_rule(
    group_keys: tuple[str, ...],
    group_df: pl.DataFrame,
    base_keys: list[str],
    port_config: PortCollapseConfig,
    bucket_config: DynamicBucketConfig,
) -> PortCollapseRule:
    """Compute the port-collapse rule for a single base-key group.

    Args:
        group_keys: Tuple of base-key values for this group.
        group_df: DataFrame subset for this group.
        base_keys: List of base-key column names.
        port_config: Port-collapse configuration.
        bucket_config: Dynamic bucket configuration.

    Returns:
        A PortCollapseRule for this group.
    """
    key_dict = dict(zip(base_keys, group_keys))

    wildcard_src = _should_wildcard_port(group_df, "src_port", port_config)
    wildcard_dst = _should_wildcard_port(group_df, "dst_port", port_config)

    if port_config.strategy == "always_wildcard_src":
        wildcard_src = True

    src_port = "*" if wildcard_src else _representative_port(group_df, "src_port")
    dst_port = "*" if wildcard_dst else _representative_port(group_df, "dst_port")

    normalized_uci = "/".join(
        [
            key_dict["src_mac"],
            key_dict["dst_mac"],
            key_dict["vlan"],
            key_dict["ip_proto"],
            key_dict["src_ip"],
            key_dict["dst_ip"],
            src_port,
            dst_port,
            key_dict["protocols"],
        ]
    )

    bucket_seconds = _compute_bucket_seconds(group_df, bucket_config)

    return PortCollapseRule(
        **key_dict,
        normalized_uci=normalized_uci,
        wildcard_src_port=wildcard_src,
        wildcard_dst_port=wildcard_dst,
        bucket_seconds=bucket_seconds,
    )


def _should_wildcard_port(
    group_df: pl.DataFrame,
    port_col: str,
    port_config: PortCollapseConfig,
) -> bool:
    """Determine whether a port field should be wildcarded for a group.

    The decision is based on **temporal persistence**, not global row count. The
    group's rows are partitioned into time buckets of width
    ``port_config.persistence_bucket_seconds``; for each non-empty bucket the
    most-frequent port (the "bucket-winner") is taken. A port collapses to ``*``
    when at least two distinct ports each win a relevant share
    (``port_config.persistence_min_share``) of the time buckets — i.e. genuine
    rotation across time. A single port that wins (almost) all buckets, with at
    most sporadic outliers that never clear the share, is a stable service port
    and is preserved.

    This "two relevant winners" rule is more robust than a single top-ratio
    threshold: a slowly-rotating ephemeral port whose currently-active value runs
    for a long contiguous period can still win a majority of buckets (e.g. 0.75),
    yet a real second port clears the share (e.g. 0.11) — which a bare ratio gate
    near 0.7 would miss. A stable service port never has a relevant second winner.

    When the ``time`` column is absent, the legacy row-count dominance gate is used
    so behaviour is never worse than before.

    Star contamination (CLAS-035): a ``*`` port value is the capture adapter's
    signal that an aggregation bucket collapsed many varying ports ("port
    varies"). It is never a concrete stable port, so the data contract forces
    the dimension to wildcard whenever a ``*`` is observed. The
    distinct/persistence/dominance statistics below only ever see concrete
    ports — when ``*`` is present this guard short-circuits, and when it is
    absent the statistics run unchanged — so behaviour for ``*``-free inputs is
    identical to before.

    Args:
        group_df: DataFrame subset for the group.
        port_col: Column name (``"src_port"`` or ``"dst_port"``).
        port_config: Port-collapse configuration.

    Returns:
        True if the port should be wildcarded.
    """
    if group_df.filter(pl.col(port_col) == "*").height > 0:
        return True
    distinct_ports = group_df[port_col].unique()
    distinct_count = len(distinct_ports)

    if distinct_count <= port_config.port_variation_threshold:
        return False

    service_port_strs = {str(p) for p in port_config.service_ports}
    port_values = set(distinct_ports.to_list())
    if port_values & service_port_strs:
        return False

    if "time" not in group_df.columns:
        # Legacy fallback: wildcard only when no single port dominates the rows.
        return (
            _row_count_dominance_ratio(group_df, port_col)
            < port_config.dominance_threshold
        )

    # Wildcard when EITHER signal fires:
    #  (a) slow rotation — >= 2 ports each persist across a relevant share of time
    #      buckets (the active port can still hold a majority of buckets/rows);
    #  (b) fast scan / flat burst — many ports with no single row-count dominator,
    #      possibly all within one time bucket (so (a) cannot see >1 winner).
    # (a) handles the slow-rotation class this fix targets; (b) preserves the
    # original port-scan collapse behaviour that a pure per-bucket-winner test
    # would otherwise lose when every port lands in the same bucket.
    if _has_multiple_persistent_winners(group_df, port_col, port_config):
        return True
    return (
        _row_count_dominance_ratio(group_df, port_col) < port_config.dominance_threshold
    )


def _has_multiple_persistent_winners(
    group_df: pl.DataFrame,
    port_col: str,
    port_config: PortCollapseConfig,
) -> bool:
    """Whether >= 2 ports each win a relevant share of time buckets (rotation).

    Partitions rows into ``persistence_bucket_seconds`` time buckets, picks the
    most-frequent port per non-empty bucket (bucket-winner), and counts how many
    distinct ports win at least ``persistence_min_share`` of the buckets. Two or
    more such ports indicate genuine rotation across time → wildcard.

    Args:
        group_df: DataFrame subset for the group.
        port_col: Column name.
        port_config: Port-collapse configuration.

    Returns:
        True if at least two ports each clear the persistence share.
    """
    bucket_width = port_config.persistence_bucket_seconds
    bucketed = group_df.with_columns(
        (pl.col("time").dt.epoch("s") // bucket_width).alias("_pbucket")
    )
    winners = (
        bucketed.group_by(["_pbucket", port_col])
        .len()
        .sort("len", descending=True)
        .group_by("_pbucket")
        .agg(pl.col(port_col).first().alias("_winner"))
    )
    total_buckets = winners.height
    if total_buckets == 0:
        return False
    winner_counts = winners.group_by("_winner").len()
    shares = winner_counts["len"] / float(total_buckets)
    relevant = int((shares >= port_config.persistence_min_share).sum())
    return relevant >= 2


def _row_count_dominance_ratio(group_df: pl.DataFrame, port_col: str) -> float:
    """Legacy dominance: share of rows held by the single most-frequent port.

    Args:
        group_df: DataFrame subset for the group.
        port_col: Column name.

    Returns:
        ``max_port_rows / total_rows`` in ``[0.0, 1.0]``.
    """
    total_rows = len(group_df)
    if total_rows == 0:
        return 0.0
    max_count = cast(int, group_df.group_by(port_col).len()["len"].max())
    return float(max_count) / float(total_rows)


def _representative_port(group_df: pl.DataFrame, port_col: str) -> str:
    """Select the most frequent concrete port value as the representative.

    A ``*`` port value is the capture adapter's "port varies" marker, never a
    concrete port, so it is excluded from the representative selection (the
    wildcard flag carries that meaning instead). When no concrete port remains
    the dimension is wildcarded (CLAS-035) and the representative is unused for
    matching, so the empty string is returned.

    Args:
        group_df: DataFrame subset for the group.
        port_col: Column name.

    Returns:
        The most frequent concrete port value as a string, or ``""`` when the
        column holds only ``*`` values.
    """
    concrete = group_df.filter(pl.col(port_col) != "*")
    if concrete.height == 0:
        return ""
    port_counts = concrete.group_by(port_col).len().sort("len", descending=True)
    return str(port_counts[port_col][0])


def _compute_bucket_seconds(
    group_df: pl.DataFrame,
    bucket_config: DynamicBucketConfig,
) -> int:
    """Compute the optimal bucket size for a group based on data density.

    Args:
        group_df: DataFrame subset for the group.
        bucket_config: Dynamic bucket configuration.

    Returns:
        The selected bucket size in seconds.
    """
    if "time" not in group_df.columns:
        return bucket_config.fallback_bucket_seconds

    total_events = len(group_df)
    time_col = group_df["time"]

    if total_events < 2:
        return bucket_config.fallback_bucket_seconds

    time_max = cast(datetime, time_col.max())
    time_min = cast(datetime, time_col.min())
    time_span = (time_max - time_min).total_seconds()
    if time_span <= 0:
        return bucket_config.fallback_bucket_seconds

    for candidate in bucket_config.allowed_seconds:
        total_buckets = time_span / candidate
        if total_buckets < 1:
            continue

        non_empty = group_df.with_columns(
            (pl.col("time").dt.epoch("s") // candidate).alias("_bucket")
        )["_bucket"].n_unique()
        occupancy = non_empty / total_buckets
        events_per_bucket = total_events / non_empty if non_empty > 0 else 0.0

        if (
            events_per_bucket >= bucket_config.target_events_min
            and events_per_bucket <= bucket_config.target_events_max
            and occupancy >= bucket_config.occupancy_threshold
        ):
            return candidate

    return bucket_config.fallback_bucket_seconds


def apply_port_rules(
    df_expanded: pl.DataFrame,
    rules: list[PortCollapseRule],
    default_bucket_seconds: int = 60,
) -> pl.DataFrame:
    """Join raw data with rules, replace UCIs, and aggregate features per time bucket.

    A rule is matched on the 7 base keys (UCI without ports), so the only
    fields that may differ between a row and its rule are the two port
    positions. Each port position is resolved independently:

    * the rule wildcards the port -> the port becomes ``"*"``, collapsing
      every port variant of the base key into one series;
    * the rule does NOT wildcard the port -> the row keeps its OWN
      observed port.

    The second branch is what keeps ``series_id`` and the feature values
    attributable to the same underlying series. A rule's
    ``normalized_uci`` carries a *representative* port chosen at training
    time, which is not necessarily the port a given row was measured on.
    Adopting it verbatim would relabel a row as a series it never
    belonged to. That happens in practice when the netcap adapter
    collapses ports per aggregation bucket
    (``AggregationBucket.build()``): a reconnect burst spanning several
    ports inside one bucket is written as a ``*/*`` UCI, while the
    trained rule for that connection still names fixed ports. Rewriting
    the ``*/*`` row onto the fixed-port UCI produced an anomaly record
    whose ``feature_summary`` came from a different series than its
    ``series_id`` (CLAS-025) — and the fixed-port series was in fact
    silent for that bucket.

    Args:
        df_expanded: DataFrame with expanded UCI columns and feature columns.
        rules: Pre-computed port-collapse rules.
        default_bucket_seconds: Bucket size for rows without matching rules.

    Returns:
        Aggregated DataFrame with normalized UCIs and time-bucketed features.
    """
    if not rules:
        return df_expanded

    rules_df = _rules_to_dataframe(rules)
    base_keys = list(UCI_BASE_KEYS)

    joined = df_expanded.join(rules_df, on=base_keys, how="left")

    joined = joined.with_columns(
        _resolved_uci_expr().alias("uci"),
        pl.when(pl.col("bucket_seconds").is_not_null())
        .then(pl.col("bucket_seconds"))
        .otherwise(pl.lit(default_bucket_seconds))
        .alias("_bucket_seconds"),
    )

    return _aggregate_features(joined)


def _resolved_port_expr(port_field: str, wildcard_flag: str) -> pl.Expr:
    """Build the expression resolving one port position of the target UCI.

    Args:
        port_field: Name of the row's own port column (``src_port`` /
            ``dst_port``).
        wildcard_flag: Name of the rule's wildcard flag column for that
            port position.

    Returns:
        Expression yielding ``"*"`` when the matched rule wildcards this
        port, and the row's own port value otherwise (which also covers
        rows without a matching rule, where the flag is null).
    """
    return (
        pl.when(pl.col(wildcard_flag).fill_null(False))
        .then(pl.lit("*"))
        .otherwise(pl.col(port_field))
    )


def _resolved_uci_expr() -> pl.Expr:
    """Build the expression assembling the post-collapse ``uci`` column.

    Non-port fields are taken from the row; they are identical to the
    rule's by construction, since the rule was joined on exactly those
    base keys. Port positions are resolved by
    :func:`_resolved_port_expr`.

    Returns:
        Expression producing the resolved 9-segment UCI string.
    """
    port_exprs = {
        "src_port": _resolved_port_expr("src_port", "wildcard_src_port"),
        "dst_port": _resolved_port_expr("dst_port", "wildcard_dst_port"),
    }
    segments = [port_exprs.get(field, pl.col(field)) for field in UCI_FIELDS]
    return pl.concat_str(segments, separator="/")


def _rules_to_dataframe(rules: list[PortCollapseRule]) -> pl.DataFrame:
    """Convert a list of rules to a Polars DataFrame for joining.

    Args:
        rules: List of PortCollapseRule instances.

    Returns:
        A DataFrame with base-key columns plus rule metadata.
    """
    records = [r.model_dump() for r in rules]
    return pl.DataFrame(records).select(
        list(UCI_BASE_KEYS)
        + ["normalized_uci", "wildcard_src_port", "wildcard_dst_port", "bucket_seconds"]
    )


def _aggregate_features(df: pl.DataFrame) -> pl.DataFrame:
    """Aggregate features per (uci, time_bucket).

    Args:
        df: Joined DataFrame with ``uci``, ``_bucket_seconds``, and feature columns.

    Returns:
        Aggregated DataFrame.
    """
    available_cols = set(df.columns)
    group_cols = ["uci"]

    if "time" in available_cols:
        df = df.with_columns(
            (
                pl.col("time").dt.epoch("s")
                // pl.col("_bucket_seconds")
                * pl.col("_bucket_seconds")
            ).alias("_bucket_epoch")
        )
        group_cols.append("_bucket_epoch")

    agg_exprs: list[pl.Expr] = []

    for col_name, method in FEATURE_AGGREGATIONS.items():
        if col_name not in available_cols:
            continue
        if method == "sum":
            agg_exprs.append(pl.col(col_name).sum())
        elif method == "min":
            agg_exprs.append(pl.col(col_name).min())
        elif method == "max":
            agg_exprs.append(pl.col(col_name).max())
        elif method == "mean":
            agg_exprs.append(pl.col(col_name).mean())

    for col_name in WEIGHTED_MEAN_FEATURES:
        if col_name not in available_cols or "packet_count" not in available_cols:
            continue
        agg_exprs.append(
            (pl.col(col_name) * pl.col("packet_count")).sum()
            / pl.col("packet_count").sum()
        )
        agg_exprs[-1] = agg_exprs[-1].alias(col_name)

    if not agg_exprs:
        return df.select(group_cols).unique()

    return df.group_by(group_cols).agg(agg_exprs)


def rule_covers_ports(rule: PortCollapseRule, src_port: str, dst_port: str) -> bool:
    """Whether a concrete port pair is covered by a port-collapse rule.

    A rule covers ``(src_port, dst_port)`` when, for each port position,
    either the rule wildcards that position (``"*"``) or the observed port
    equals the rule's representative port. This mirrors the coverage
    resolution performed by :func:`apply_port_rules` (join on the 7 base
    keys, then resolve each port position independently) and the API-040
    coverage guard used by the aggregation service.

    Args:
        rule: The port-collapse rule to test against.
        src_port: The observed source port.
        dst_port: The observed destination port.

    Returns:
        True if the rule covers the port pair.
    """
    parts = parse_uci(rule.normalized_uci)
    src_ok = rule.wildcard_src_port or src_port == parts.src_port
    dst_ok = rule.wildcard_dst_port or dst_port == parts.dst_port
    return src_ok and dst_ok
