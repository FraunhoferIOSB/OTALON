"""Port-collapse rule refresh thread (CLAS-033).

A daemon thread that periodically detects port-rotation drift in live
InfluxDB data, recomputes affected port-collapse rules over a bounded
lookback window, and upserts only the changed rules. Follows the
``BoundsInvalidator`` daemon-thread pattern.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, cast

import polars as pl
from loguru import logger
from otalon_common.connection import (
    DynamicBucketConfig,
    PortCollapseConfig,
    PortCollapseRule,
    determine_port_collapse_rules,
    rule_covers_ports,
)
from otalon_common.uci import UCI_BASE_KEYS, expand_uci
from otalon_common.uci.parser import parse_uci

from otalon_clas.common.influx_connector import InfluxModule
from otalon_clas.common.postgres_connector import PostgresConnector
from otalon_clas.common.settings import PortRuleRefreshConfig
from otalon_clas.preprocessing.port_rules_repository import PortCollapseRulesRepository
from otalon_clas.runtime.retrain_job_repository import RetrainJobRepository
from otalon_clas.runtime.runtime_config_repository import RuntimeConfigRepository


@dataclass(frozen=True)
class _PortCandidate:
    """A coverage-violation candidate tracked across refresh cycles."""

    base_key: tuple[str, ...]
    port_dim: Literal["src_port", "dst_port"]
    port_value: str
    rotation_signal: bool = False


class PortRuleRefresher:
    """Daemon thread that detects and repairs port-rule drift (CLAS-033).

    Each cycle: load persisted rules, fetch distinct UCIs from InfluxDB
    over a bounded lookback window, find base-keys whose observed ports
    are no longer covered by their rule, apply transient guards (D2-D4),
    recompute confirmed base-keys, and upsert only changed rules (D5).
    The cycle skips while a retrain job is non-terminal (D6). Hot-override
    via ``runtime_config`` re-reads effective parameters every cycle.
    """

    def __init__(
        self,
        pg_connector: PostgresConnector,
        influx_connector: InfluxModule,
        rules_repository: PortCollapseRulesRepository,
        port_config: PortCollapseConfig,
        bucket_config: DynamicBucketConfig,
        refresh_config: PortRuleRefreshConfig,
        module_name: str,
        reload_callback: Callable[[], None],
    ) -> None:
        """Wire the refresher without starting its background thread.

        Args:
            pg_connector: PostgreSQL connector for retrain-job mutex checks.
            influx_connector: InfluxDB module for fetching distinct UCIs
                and raw time-series data.
            rules_repository: Port-collapse rules repository for loading
                and upserting rules.
            port_config: Port-collapse heuristics configuration.
            bucket_config: Dynamic bucket-sizing configuration.
            refresh_config: Static refresh-thread defaults; hot-overridden
                via ``runtime_config`` each cycle.
            module_name: Detection module name (e.g. ``"conn"``).
            reload_callback: Called after a successful upsert so the live
                preprocessor reloads its rules cache.
        """
        self._pg = pg_connector
        self._influx = influx_connector
        self._rules_repo = rules_repository
        self._port_config = port_config
        self._bucket_config = bucket_config
        self._refresh_config = refresh_config
        self._module_name = module_name
        self._reload_callback = reload_callback
        self._runtime_config = RuntimeConfigRepository(pg_connector)
        self._job_repo = RetrainJobRepository(pg_connector)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._first_seen: dict[_PortCandidate, int] = {}

    def start(self) -> bool:
        """Start the refresh daemon thread.

        Returns:
            ``True`` if the thread was started or was already running.
        """
        if self._thread is not None:
            return True
        self._thread = threading.Thread(
            target=self._run,
            name="cyberclas-port-rule-refresher",
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the refresh thread and wait for its exit.

        Args:
            timeout: Maximum seconds to wait for the thread to finish.
        """
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run(self) -> None:
        """Run the refresh loop until stopped, swallowing per-cycle errors."""
        while not self._stop_event.wait(self._resolve_interval_seconds()):
            try:
                self._run_once()
            except Exception as exc:
                logger.exception("PortRuleRefresher: cycle failed: {}", exc)

    def _resolve_interval_seconds(self) -> int:
        """Return the hot-overridable cycle interval, clamped to at least 1 s."""
        try:
            cfg = self._refresh_config.resolve(self._runtime_config)
            return max(1, cfg.interval_seconds)
        except Exception:
            return max(1, self._refresh_config.interval_seconds)

    def _run_once(self) -> None:
        """Execute one refresh cycle per the CLAS-033 design algorithm."""
        cfg = self._refresh_config.resolve(self._runtime_config)
        if not cfg.enabled:
            return

        if self._job_repo.list_non_terminal():
            logger.debug("PortRuleRefresher: skipping cycle (retrain job active)")
            return

        rules = self._rules_repo.load(self._module_name)
        if not rules:
            logger.debug("PortRuleRefresher: no rules loaded, skipping")
            return

        rule_lookup = _build_rule_lookup(rules)

        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=cfg.lookback_hours)).isoformat()
        stop = now.isoformat()
        ucis = self._influx.fetch_distinct_tag_values(start, stop)
        if not ucis:
            logger.debug("PortRuleRefresher: no UCIs in lookback window, skipping")
            return

        current_candidates = _find_candidates(
            ucis, rule_lookup, cfg.rotation_distinct_ports
        )
        confirmed = self._update_hysteresis(current_candidates, cfg.confirm_cycles)
        if not confirmed:
            logger.debug("PortRuleRefresher: no confirmed candidates")
            return

        upserts = self._recompute(confirmed, start, stop, rule_lookup, cfg.min_samples)
        if not upserts:
            return

        self._rules_repo.upsert_rules(self._module_name, upserts)
        self._reload_callback()
        logger.info("PortRuleRefresher: upserted {} rules", len(upserts))

    def _update_hysteresis(
        self,
        current: set[_PortCandidate],
        confirm_cycles: int,
    ) -> list[_PortCandidate]:
        """Update the D3 ``first_seen`` dict and return confirmed candidates.

        Candidates seen this cycle increment their consecutive-seen count;
        candidates absent this cycle are dropped from the dict. A candidate
        is confirmed when its count reaches ``confirm_cycles``.

        Args:
            current: Candidates observed in this cycle.
            confirm_cycles: Minimum consecutive cycles for confirmation.

        Returns:
            Candidates whose consecutive-seen count meets the threshold.
        """
        confirmed: list[_PortCandidate] = []
        for cand in current:
            count = self._first_seen.get(cand, 0) + 1
            self._first_seen[cand] = count
            if count >= confirm_cycles:
                confirmed.append(cand)
        stale = set(self._first_seen.keys()) - current
        for cand in stale:
            del self._first_seen[cand]
        return confirmed

    def _recompute(
        self,
        confirmed: list[_PortCandidate],
        start: str,
        stop: str,
        rule_lookup: dict[tuple[str, ...], PortCollapseRule],
        min_samples: int,
    ) -> list[PortCollapseRule]:
        """Recompute rules for confirmed candidates, returning changed rules.

        Groups confirmed candidates by base-key, fetches the full window
        data, applies D2 (persistence buckets) and D4 (min samples) guards,
        recomputes the rule via :func:`determine_port_collapse_rules`, and
        applies the D5 no-change guard.
        """
        by_base: dict[tuple[str, ...], list[_PortCandidate]] = {}
        for cand in confirmed:
            by_base.setdefault(cand.base_key, []).append(cand)

        raw = self._influx.fetch(start, stop, use_polars=True)
        df = raw if isinstance(raw, pl.DataFrame) else pl.from_pandas(raw)
        df_expanded = cast(pl.DataFrame, expand_uci(df))

        upserts: list[PortCollapseRule] = []
        bucket_seconds = self._port_config.persistence_bucket_seconds
        for base_key, cands in by_base.items():
            group_df = _filter_base_key(df_expanded, base_key)
            if group_df.height < min_samples:
                continue
            if not _any_port_persistent(group_df, cands, bucket_seconds):
                continue
            new_rules = determine_port_collapse_rules(
                group_df,
                port_config=self._port_config,
                bucket_config=self._bucket_config,
            )
            if not new_rules:
                continue
            old_rule = rule_lookup[base_key]
            if new_rules[0] == old_rule:
                continue
            upserts.append(new_rules[0])
        return upserts


def _build_rule_lookup(
    rules: list[PortCollapseRule],
) -> dict[tuple[str, ...], PortCollapseRule]:
    """Build a base-key → rule lookup from a list of rules.

    Args:
        rules: Port-collapse rules to index.

    Returns:
        Dictionary keyed by the 7-element base-key tuple.
    """
    lookup: dict[tuple[str, ...], PortCollapseRule] = {}
    for rule in rules:
        base_key = (
            rule.src_mac,
            rule.dst_mac,
            rule.vlan,
            rule.ip_proto,
            rule.src_ip,
            rule.dst_ip,
            rule.protocols,
        )
        lookup[base_key] = rule
    return lookup


def _find_candidates(
    ucis: list[str],
    rule_lookup: dict[tuple[str, ...], PortCollapseRule],
    rotation_distinct_ports: int = 3,
) -> set[_PortCandidate]:
    """Find coverage-violation and rotation candidates from distinct UCIs.

    A UCI whose base-key matches a rule but whose observed ports are not
    covered by that rule produces one candidate per uncovered port
    dimension. Additionally, when a base-key accumulates at least
    ``rotation_distinct_ports`` distinct concrete port values (excluding
    ``"*"``) on a non-wildcarded dimension, a rotation candidate with
    ``port_value="*"`` is emitted so the recomputed rule wildcards that
    dimension.

    Args:
        ucis: Distinct UCI strings from the lookback window.
        rule_lookup: Base-key → rule lookup.
        rotation_distinct_ports: Minimum distinct concrete ports on a
            single dimension to trigger a rotation candidate. When ``0``
            or negative, rotation candidates are suppressed.

    Returns:
        Set of candidates (base-key, port dimension, port value).
    """
    candidates: set[_PortCandidate] = set()
    distinct_ports: dict[tuple[str, ...], dict[str, set[str]]] = {}
    for uci in ucis:
        parts = parse_uci(uci)
        base_key = (
            parts.src_mac,
            parts.dst_mac,
            parts.vlan,
            parts.ip_proto,
            parts.src_ip,
            parts.dst_ip,
            parts.protocols,
        )
        rule = rule_lookup.get(base_key)
        if rule is None:
            continue
        dim_ports = distinct_ports.setdefault(
            base_key, {"src_port": set(), "dst_port": set()}
        )
        if parts.src_port != "*":
            dim_ports["src_port"].add(parts.src_port)
        if parts.dst_port != "*":
            dim_ports["dst_port"].add(parts.dst_port)
        if rule_covers_ports(rule, parts.src_port, parts.dst_port):
            continue
        rule_parts = parse_uci(rule.normalized_uci)
        if not rule.wildcard_src_port and parts.src_port != rule_parts.src_port:
            candidates.add(_PortCandidate(base_key, "src_port", parts.src_port))
        if not rule.wildcard_dst_port and parts.dst_port != rule_parts.dst_port:
            candidates.add(_PortCandidate(base_key, "dst_port", parts.dst_port))
    if rotation_distinct_ports > 0:
        for bk, dim_ports in distinct_ports.items():
            rule = rule_lookup[bk]
            if (
                not rule.wildcard_src_port
                and len(dim_ports["src_port"]) >= rotation_distinct_ports
            ):
                candidates.add(
                    _PortCandidate(bk, "src_port", "*", rotation_signal=True)
                )
            if (
                not rule.wildcard_dst_port
                and len(dim_ports["dst_port"]) >= rotation_distinct_ports
            ):
                candidates.add(
                    _PortCandidate(bk, "dst_port", "*", rotation_signal=True)
                )
    return candidates


def _filter_base_key(
    df: pl.DataFrame,
    base_key: tuple[str, ...],
) -> pl.DataFrame:
    """Filter an expanded DataFrame to rows matching a base-key.

    Args:
        df: Expanded DataFrame with UCI field columns.
        base_key: 7-element base-key tuple matching ``UCI_BASE_KEYS`` order.

    Returns:
        Filtered DataFrame containing only rows for the given base-key.
    """
    mask = pl.lit(True)
    for col_name, col_val in zip(UCI_BASE_KEYS, base_key):
        mask = mask & (pl.col(col_name) == col_val)
    return df.filter(mask)


def _any_port_persistent(
    group_df: pl.DataFrame,
    candidates: list[_PortCandidate],
    bucket_seconds: int,
) -> bool:
    """Check if any candidate port appears in at least 2 persistence buckets.

    Rotation candidates (``rotation_signal=True``) short-circuit to True:
    observing many distinct ports across the lookback window is itself
    evidence of persistent rotation that warrants wildcarding, without
    requiring a specific port value to span multiple time buckets.

    Args:
        group_df: DataFrame filtered to a single base-key group.
        candidates: Candidates sharing this base-key.
        bucket_seconds: Persistence bucket width in seconds.

    Returns:
        True if at least one candidate port spans 2+ distinct time buckets
        or a rotation candidate is present.
    """
    if "time" not in group_df.columns or group_df.height == 0:
        return False
    for cand in candidates:
        if cand.rotation_signal:
            return True
        port_df = group_df.filter(pl.col(cand.port_dim) == cand.port_value)
        if port_df.height == 0:
            continue
        bucketed = port_df.with_columns(
            (pl.col("time").dt.epoch("s") // bucket_seconds).alias("_pbucket")
        )
        n_buckets = bucketed["_pbucket"].n_unique()
        if n_buckets >= 2:
            return True
    return False
