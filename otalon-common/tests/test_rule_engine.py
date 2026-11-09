"""Tests for port-collapse rule determination and application."""

from datetime import datetime, timedelta

import polars as pl
from otalon_common.connection.models import PortCollapseConfig, PortCollapseRule
from otalon_common.connection.rule_engine import (
    _representative_port,
    apply_port_rules,
    determine_port_collapse_rules,
    rule_covers_ports,
)
from otalon_common.uci.parser import parse_uci

_BASE_TIME = datetime(2026, 5, 5, 0, 0, 0)


def _make_expanded_df(
    src_ports: list[str],
    dst_ports: list[str],
    packet_counts: list[int] | None = None,
) -> pl.DataFrame:
    """Helper to create a test DataFrame with expanded UCI columns."""
    n = len(src_ports)
    if packet_counts is None:
        packet_counts = [10] * n
    return pl.DataFrame(
        {
            "src_mac": ["aa:bb"] * n,
            "dst_mac": ["cc:dd"] * n,
            "vlan": ["100"] * n,
            "ip_proto": ["6"] * n,
            "src_ip": ["1.1.1.1"] * n,
            "dst_ip": ["2.2.2.2"] * n,
            "src_port": src_ports,
            "dst_port": dst_ports,
            "protocols": ["TCP"] * n,
            "packet_count": packet_counts,
        }
    )


def _make_timed_df(
    dst_ports: list[str],
    offsets_seconds: list[int],
    src_ports: list[str] | None = None,
) -> pl.DataFrame:
    """Build an expanded DataFrame with a ``time`` column.

    Args:
        dst_ports: Destination port value per row.
        offsets_seconds: Offset in seconds from ``_BASE_TIME`` per row (defines the
            time bucket each row falls into).
        src_ports: Optional source port per row (defaults to a fixed ephemeral port).

    Returns:
        A DataFrame with the 9 expanded UCI columns plus ``time`` and ``packet_count``.
    """
    n = len(dst_ports)
    if src_ports is None:
        src_ports = ["50000"] * n
    times = [_BASE_TIME + timedelta(seconds=s) for s in offsets_seconds]
    return pl.DataFrame(
        {
            "src_mac": ["aa:bb"] * n,
            "dst_mac": ["cc:dd"] * n,
            "vlan": ["100"] * n,
            "ip_proto": ["6"] * n,
            "src_ip": ["192.168.0.4"] * n,
            "dst_ip": ["192.168.0.41"] * n,
            "src_port": src_ports,
            "dst_port": dst_ports,
            "protocols": ["PROFINET_DCE_RPC"] * n,
            "packet_count": [10] * n,
            "time": times,
        }
    )


class TestDeterminePortCollapseRules:
    """Tests for determine_port_collapse_rules()."""

    def test_high_variance_triggers_wildcard(self) -> None:
        df = _make_expanded_df(
            src_ports=["1000"] * 15,
            dst_ports=[str(i) for i in range(15)],
        )
        rules = determine_port_collapse_rules(
            df, PortCollapseConfig(port_variation_threshold=2)
        )
        assert len(rules) == 1
        assert rules[0].wildcard_dst_port is True

    def test_low_variance_no_wildcard(self) -> None:
        df = _make_expanded_df(
            src_ports=["1000", "1000"],
            dst_ports=["443", "443"],
        )
        rules = determine_port_collapse_rules(
            df, PortCollapseConfig(port_variation_threshold=2)
        )
        assert len(rules) == 1
        assert rules[0].wildcard_dst_port is False
        assert rules[0].wildcard_src_port is False

    def test_dominant_port_prevents_wildcard(self) -> None:
        dst_ports = ["443"] * 85 + [str(i) for i in range(15)]
        df = _make_expanded_df(
            src_ports=["1000"] * 100,
            dst_ports=dst_ports,
        )
        config = PortCollapseConfig(port_variation_threshold=2, dominance_threshold=0.7)
        rules = determine_port_collapse_rules(df, config)
        assert len(rules) == 1
        assert rules[0].wildcard_dst_port is False

    def test_service_port_prevents_wildcard(self) -> None:
        df = _make_expanded_df(
            src_ports=["1000"] * 10,
            dst_ports=[
                "443",
                "8080",
                "9090",
                "1234",
                "5678",
                "443",
                "8080",
                "9090",
                "1234",
                "5678",
            ],
        )
        config = PortCollapseConfig(
            port_variation_threshold=2, dominance_threshold=0.99, service_ports=[443]
        )
        rules = determine_port_collapse_rules(df, config)
        assert len(rules) == 1
        assert rules[0].wildcard_dst_port is False

    def test_always_wildcard_src_strategy(self) -> None:
        df = _make_expanded_df(
            src_ports=["1000", "1000"],
            dst_ports=["443", "443"],
        )
        config = PortCollapseConfig(strategy="always_wildcard_src")
        rules = determine_port_collapse_rules(df, config)
        assert len(rules) == 1
        assert rules[0].wildcard_src_port is True

    def test_normalized_uci_format(self) -> None:
        df = _make_expanded_df(
            src_ports=["1000"] * 15,
            dst_ports=[str(i) for i in range(15)],
        )
        rules = determine_port_collapse_rules(df)
        assert len(rules) == 1
        assert (
            "/*/" in rules[0].normalized_uci or rules[0].normalized_uci.count("/") == 8
        )

    def test_default_configs_used(self) -> None:
        df = _make_expanded_df(src_ports=["1000"], dst_ports=["443"])
        rules = determine_port_collapse_rules(df)
        assert len(rules) == 1


class TestApplyPortRules:
    """Tests for apply_port_rules()."""

    def test_rules_applied(self) -> None:
        df = _make_expanded_df(
            src_ports=["1000", "2000"],
            dst_ports=["443", "443"],
            packet_counts=[10, 20],
        )
        rules = [
            PortCollapseRule(
                src_mac="aa:bb",
                dst_mac="cc:dd",
                vlan="100",
                ip_proto="6",
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
                protocols="TCP",
                normalized_uci="aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/443/TCP",
                wildcard_src_port=True,
                wildcard_dst_port=False,
                bucket_seconds=60,
            )
        ]
        result = apply_port_rules(df, rules)
        assert len(result) == 1
        assert result["uci"][0] == "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/443/TCP"
        assert result["packet_count"][0] == 30

    def test_empty_rules_passthrough(self) -> None:
        df = _make_expanded_df(src_ports=["1000"], dst_ports=["443"])
        result = apply_port_rules(df, [])
        assert len(result) == len(df)

    def test_unmatched_rows_keep_original_uci(self) -> None:
        df = _make_expanded_df(
            src_ports=["1000"],
            dst_ports=["443"],
            packet_counts=[10],
        )
        rules = [
            PortCollapseRule(
                src_mac="xx:yy",
                dst_mac="zz:ww",
                vlan="200",
                ip_proto="17",
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocols="UDP",
                normalized_uci="xx:yy/zz:ww/200/17/10.0.0.1/10.0.0.2/*/*/UDP",
                wildcard_src_port=True,
                wildcard_dst_port=True,
                bucket_seconds=60,
            )
        ]
        result = apply_port_rules(df, rules)
        assert len(result) == 1
        assert "aa:bb" in result["uci"][0]


class TestPortCollapseSeriesAttribution:
    """Regression cases for series attribution across a port collapse (CLAS-025).

    The netcap adapter may collapse a single aggregation bucket to a
    ``*/*`` UCI (``AggregationBucket.build()``) while the trained rule
    for the same connection still names fixed ports. Applying the rule's
    ``normalized_uci`` verbatim relabelled such a row onto the
    fixed-port series, so the resulting anomaly row's
    ``feature_summary`` came from a series it did not reference.
    """

    @staticmethod
    def _fixed_port_rule() -> PortCollapseRule:
        """Return a rule that wildcards neither port (a stable connection)."""
        return PortCollapseRule(
            src_mac="aa:bb",
            dst_mac="cc:dd",
            vlan="100",
            ip_proto="6",
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            protocols="TCP",
            normalized_uci="aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/50000/50065/TCP",
            wildcard_src_port=False,
            wildcard_dst_port=False,
            bucket_seconds=60,
        )

    def test_no_collapse_keeps_fixed_port_series(self) -> None:
        """Without a collapse the fixed-port rows keep their own series."""
        df = _make_expanded_df(
            src_ports=["50000", "50000"],
            dst_ports=["50065", "50065"],
            packet_counts=[1, 1],
        )
        result = apply_port_rules(df, [self._fixed_port_rule()])

        assert result["uci"].unique().to_list() == [
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/50000/50065/TCP"
        ]
        assert result["packet_count"].sum() == 2

    def test_mid_window_collapse_keeps_its_own_series(self) -> None:
        """A ``*/*`` burst row is not relabelled onto the fixed-port series.

        Mirrors live alarm ``b9cf486606d84cc8b77c5b929f80f173``: the
        wildcard bucket carried ``packet_count=5`` while the fixed-port
        series was silent for that bucket.
        """
        df = _make_expanded_df(
            src_ports=["50000", "*"],
            dst_ports=["50065", "*"],
            packet_counts=[1, 5],
        )
        result = apply_port_rules(df, [self._fixed_port_rule()])

        by_uci = dict(zip(result["uci"].to_list(), result["packet_count"].to_list()))
        assert by_uci == {
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/50000/50065/TCP": 1,
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/*/TCP": 5,
        }

    def test_oscillation_back_to_fixed_port_is_not_misattributed(self) -> None:
        """A wildcard bucket between two fixed-port buckets attributes each way."""
        df = _make_expanded_df(
            src_ports=["50000", "*", "50000"],
            dst_ports=["50065", "*", "50065"],
            packet_counts=[1, 5, 1],
        )
        result = apply_port_rules(df, [self._fixed_port_rule()])

        by_uci = dict(zip(result["uci"].to_list(), result["packet_count"].to_list()))
        assert by_uci == {
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/50000/50065/TCP": 2,
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/*/TCP": 5,
        }

    def test_wildcarding_rule_still_collapses_port_variants(self) -> None:
        """A rule that DOES wildcard still merges its port variants.

        Guards the fix against over-correcting into "never collapse".
        """
        df = _make_expanded_df(
            src_ports=["1000", "2000", "3000"],
            dst_ports=["443", "443", "443"],
            packet_counts=[10, 20, 30],
        )
        rules = [
            PortCollapseRule(
                src_mac="aa:bb",
                dst_mac="cc:dd",
                vlan="100",
                ip_proto="6",
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
                protocols="TCP",
                normalized_uci="aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/443/TCP",
                wildcard_src_port=True,
                wildcard_dst_port=False,
                bucket_seconds=60,
            )
        ]
        result = apply_port_rules(df, rules)

        assert len(result) == 1
        assert result["uci"][0] == "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/443/TCP"
        assert result["packet_count"][0] == 60


class TestTemporalPersistenceGolden:
    """Golden regression cases for the temporal-persistence dominance gate (UI-017b).

    These pin the three discriminating cases (slow rotation, port scan, stable
    service port) plus the missing-time fallback, so a future re-tune of
    ``dominance_threshold`` / ``persistence_bucket_seconds`` stays safe.
    """

    def test_b1_slow_rotation_with_dominant_active_port_collapses(self) -> None:
        """B1: one port holds ~97% of rows AND wins a majority of buckets -> wildcard.

        Mirrors the real DCE_RPC data: the currently-active port (54686) runs
        contiguously and both dominates the row count (~0.97) AND wins a majority of
        time buckets (~0.75). A single top-ratio gate near 0.7 would WRONGLY preserve
        it. The "two relevant winners" rule collapses it because a second port (53092)
        also clears ``persistence_min_share`` of the buckets — genuine rotation.
        """
        bucket = 300
        dst_ports: list[str] = []
        offsets: list[int] = []
        # Buckets 0..5 (6 buckets): active port 54686 wins, ~100 rows each (row-count
        # dominance ~0.96, AND top bucket-winner share 6/8 = 0.75 — above 0.7).
        for b in range(6):
            for i in range(100):
                dst_ports.append("54686")
                offsets.append(b * bucket + i)
        # Buckets 6 and 7: a real second rotated port (53092) wins each -> 2/8 = 0.25
        # share, clearing persistence_min_share (0.10) -> second relevant winner.
        for b in (6, 7):
            for i in range(5):
                dst_ports.append("53092")
                offsets.append(b * bucket + i)
        # A few more sporadic rotated ports so distinct_count clears the variation
        # threshold (mirrors the real 5-distinct-port DCE_RPC connection).
        for idx, port in enumerate(["54414", "54805", "50013"]):
            dst_ports.append(port)
            offsets.append((idx % 6) * bucket + 200)
        df = _make_timed_df(dst_ports=dst_ports, offsets_seconds=offsets)
        # Row-count dominance must be high to prove the old gate would have failed.
        row_dominance = dst_ports.count("54686") / len(dst_ports)
        assert row_dominance > 0.95
        config = PortCollapseConfig(
            port_variation_threshold=2,
            dominance_threshold=0.7,
            persistence_bucket_seconds=bucket,
            service_ports=[],
        )
        rules = determine_port_collapse_rules(df, config)
        assert len(rules) == 1
        assert rules[0].wildcard_dst_port is True

    def test_b2_genuine_port_scan_collapses(self) -> None:
        """B2: flat distribution, many distinct ports across buckets -> wildcard."""
        bucket = 300
        dst_ports = [str(40000 + i) for i in range(12)]
        offsets = [i * 60 for i in range(12)]  # spread across multiple buckets
        df = _make_timed_df(dst_ports=dst_ports, offsets_seconds=offsets)
        config = PortCollapseConfig(
            port_variation_threshold=2,
            dominance_threshold=0.7,
            persistence_bucket_seconds=bucket,
        )
        rules = determine_port_collapse_rules(df, config)
        assert len(rules) == 1
        assert rules[0].wildcard_dst_port is True

    def test_b2b_fast_port_scan_single_bucket_collapses(self) -> None:
        """B2b: a fast scan with all ports in ONE time bucket still collapses.

        Regression guard: the per-bucket-winner test alone sees only one bucket (one
        winner) here and would NOT fire. The row-count dominance fallback (flat
        distribution, no dominant port) must still trigger the wildcard so a fast
        port scan is never silently preserved.
        """
        bucket = 300
        dst_ports = [str(40000 + i) for i in range(50)]
        offsets = list(range(50))  # all within the first 300s bucket
        df = _make_timed_df(dst_ports=dst_ports, offsets_seconds=offsets)
        config = PortCollapseConfig(
            port_variation_threshold=2,
            dominance_threshold=0.7,
            persistence_bucket_seconds=bucket,
            service_ports=[],
        )
        rules = determine_port_collapse_rules(df, config)
        assert len(rules) == 1
        assert rules[0].wildcard_dst_port is True

    def test_b3_stable_service_port_over_collapse_guard(self) -> None:
        """B3 (OVER-COLLAPSE GUARD): stable 443 in (almost) every bucket -> NOT wildcard.

        443 is the most-frequent port in every one of the 10 buckets, with a couple of
        sporadic outlier ports in two buckets. Persistence ratio = 10/10 = 1.0 >= 0.7,
        so the service port is preserved. Service ports are configured empty here so the
        decision rests purely on the temporal-persistence gate (the harder guard).
        """
        bucket = 300
        dst_ports: list[str] = []
        offsets: list[int] = []
        for b in range(10):
            for i in range(20):
                dst_ports.append("443")
                offsets.append(b * bucket + i)
        # Sporadic outliers (still a minority within their buckets).
        dst_ports += ["51000", "51001"]
        offsets += [2 * bucket + 250, 6 * bucket + 250]
        df = _make_timed_df(dst_ports=dst_ports, offsets_seconds=offsets)
        config = PortCollapseConfig(
            port_variation_threshold=2,
            dominance_threshold=0.7,
            persistence_bucket_seconds=bucket,
            service_ports=[],
        )
        rules = determine_port_collapse_rules(df, config)
        assert len(rules) == 1
        assert rules[0].wildcard_dst_port is False

    def test_b4_missing_time_column_falls_back_to_row_count(self) -> None:
        """B4: no ``time`` column -> legacy row-count dominance gate.

        With one port at 97% of rows and no time column, the legacy row-count
        dominance (>= 0.7) preserves it (no wildcard) exactly as before the fix.
        """
        dst_ports = ["54686"] * 97 + [str(50000 + i) for i in range(3)]
        df = _make_expanded_df(src_ports=["50000"] * 100, dst_ports=dst_ports)
        assert "time" not in df.columns
        config = PortCollapseConfig(
            port_variation_threshold=2,
            dominance_threshold=0.7,
            service_ports=[],
        )
        rules = determine_port_collapse_rules(df, config)
        assert len(rules) == 1
        assert rules[0].wildcard_dst_port is False

    def test_b4b_missing_time_low_row_dominance_still_wildcards(self) -> None:
        """B4 companion: no time column + flat distribution -> legacy gate wildcards."""
        dst_ports = [str(40000 + i) for i in range(12)]
        df = _make_expanded_df(src_ports=["50000"] * 12, dst_ports=dst_ports)
        config = PortCollapseConfig(
            port_variation_threshold=2,
            dominance_threshold=0.7,
            service_ports=[],
        )
        rules = determine_port_collapse_rules(df, config)
        assert len(rules) == 1
        assert rules[0].wildcard_dst_port is True


class TestRuleCoversPorts:
    """Tests for rule_covers_ports() — coverage of a concrete port pair by a rule.

    Mirrors the API-040 coverage guard: a rule covers a port pair when each
    port position is either wildcarded by the rule or matches the rule's
    representative port exactly.
    """

    @staticmethod
    def _make_coverage_rule(
        wildcard_src: bool = False,
        wildcard_dst: bool = False,
        src_port: str = "50000",
        dst_port: str = "443",
    ) -> PortCollapseRule:
        """Build a rule with a canonical base-key and the given port flags."""
        src_p = "*" if wildcard_src else src_port
        dst_p = "*" if wildcard_dst else dst_port
        normalized = f"aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/{src_p}/{dst_p}/TCP"
        return PortCollapseRule(
            src_mac="aa:bb",
            dst_mac="cc:dd",
            vlan="100",
            ip_proto="6",
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            protocols="TCP",
            normalized_uci=normalized,
            wildcard_src_port=wildcard_src,
            wildcard_dst_port=wildcard_dst,
            bucket_seconds=60,
        )

    def test_exact_match(self) -> None:
        """Both ports concrete and matching -> covered."""
        rule = self._make_coverage_rule(src_port="50000", dst_port="443")
        assert rule_covers_ports(rule, "50000", "443") is True

    def test_wildcard_dst_concrete_src_any_dst(self) -> None:
        """Wildcard dst + concrete src -> any dst covered when src matches."""
        rule = self._make_coverage_rule(wildcard_dst=True, src_port="50000")
        assert rule_covers_ports(rule, "50000", "9999") is True
        assert rule_covers_ports(rule, "50000", "443") is True

    def test_wildcard_dst_mismatched_src_not_covered(self) -> None:
        """Wildcard dst does not rescue a mismatched concrete src."""
        rule = self._make_coverage_rule(wildcard_dst=True, src_port="50000")
        assert rule_covers_ports(rule, "49999", "9999") is False

    def test_concrete_both_mismatched_dst(self) -> None:
        """Both concrete, dst mismatched -> not covered."""
        rule = self._make_coverage_rule(src_port="50000", dst_port="443")
        assert rule_covers_ports(rule, "50000", "9999") is False

    def test_concrete_both_mismatched_src(self) -> None:
        """Both concrete, src mismatched -> not covered."""
        rule = self._make_coverage_rule(src_port="50000", dst_port="443")
        assert rule_covers_ports(rule, "49999", "443") is False

    def test_wildcard_both_any_ports(self) -> None:
        """Both ports wildcarded -> any port pair covered."""
        rule = self._make_coverage_rule(wildcard_src=True, wildcard_dst=True)
        assert rule_covers_ports(rule, "12345", "9999") is True
        assert rule_covers_ports(rule, "50000", "443") is True

    def test_service_port_rule_matching_port(self) -> None:
        """A preserved service-port rule (dst=443) covers only its own port."""
        rule = self._make_coverage_rule(src_port="50000", dst_port="443")
        assert rule_covers_ports(rule, "50000", "443") is True
        assert rule_covers_ports(rule, "50000", "80") is False


class TestStarContamination:
    """Star-contamination guard for ingested ``*`` port values (CLAS-035).

    The netcap capture adapter writes a literal ``*`` in a port column when an
    aggregation bucket collapsed many varying ports ("port varies"). A ``*`` is
    never a concrete stable port, so the data contract forces the dimension to
    wildcard whenever one is observed, and the representative-port selection must
    never return ``*``.
    """

    def test_star_in_src_port_forces_wildcard_src(self) -> None:
        """A ``*`` among src ports forces ``wildcard_src_port`` regardless of the
        concrete ports also present; the representative never becomes ``*``."""
        df = _make_expanded_df(
            src_ports=["*", "50000", "50001"],
            dst_ports=["161", "161", "161"],
        )
        rules = determine_port_collapse_rules(
            df, PortCollapseConfig(port_variation_threshold=2)
        )
        assert len(rules) == 1
        rule = rules[0]
        assert rule.wildcard_src_port is True
        assert rule.wildcard_dst_port is False
        parts = parse_uci(rule.normalized_uci)
        assert parts.src_port == "*"
        assert parts.dst_port == "161"
        rep = _representative_port(df, "src_port")
        assert rep != "*"
        assert rep in {"50000", "50001"}

    def test_star_in_dst_port_forces_wildcard_dst(self) -> None:
        """Mirror of the src case: a ``*`` among dst ports forces
        ``wildcard_dst_port`` while the concrete src port is preserved."""
        df = _make_expanded_df(
            src_ports=["50000", "50000", "50000"],
            dst_ports=["*", "161", "162"],
        )
        rules = determine_port_collapse_rules(
            df, PortCollapseConfig(port_variation_threshold=2)
        )
        assert len(rules) == 1
        rule = rules[0]
        assert rule.wildcard_dst_port is True
        assert rule.wildcard_src_port is False
        parts = parse_uci(rule.normalized_uci)
        assert parts.src_port == "50000"
        assert parts.dst_port == "*"
        rep = _representative_port(df, "dst_port")
        assert rep != "*"
        assert rep in {"161", "162"}

    def test_concrete_one_shot_rotation_unaffected_by_star_fix(self) -> None:
        """Concrete-only rotation (no ``*``) is unchanged by the star guard.

        Regression pin: the ``*`` short-circuit and the concrete filter added to
        ``_representative_port`` are no-ops when no ``*`` is present, so the
        pre-existing flat-distribution wildcard behaviour is preserved and the
        representative stays a concrete, non-empty port.
        """
        df = _make_expanded_df(
            src_ports=["50000"] * 6,
            dst_ports=["40001", "40002", "40003", "40004", "40005", "40006"],
        )
        rules = determine_port_collapse_rules(
            df, PortCollapseConfig(port_variation_threshold=2)
        )
        assert len(rules) == 1
        rule = rules[0]
        assert rule.wildcard_dst_port is True
        assert rule.wildcard_src_port is False
        rep = _representative_port(df, "dst_port")
        assert rep != ""
        assert rep != "*"
        assert rep in {"40001", "40002", "40003", "40004", "40005", "40006"}
