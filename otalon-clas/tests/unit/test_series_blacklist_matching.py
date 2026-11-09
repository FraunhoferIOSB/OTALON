"""CLAS-061 regression: blacklist entries must actually match series.

The ``conn`` module identifies series by the 9-field compound UCI while
``SERIES_BLACKLIST`` carries single field values (one MAC, one IP, an
L3 name). The three detection consumers (BoundsTrainer, BoundsManager,
FrequencyMonitor) matched exact/prefix on the whole identifier, so no
entry could ever hit — the configured exclusions were ignored. This
suite pins the field-aware semantics of
:class:`otalon_clas.detection.series_blacklist.SeriesBlacklist` and the
consumers' behaviour against the production pattern set and real-world
series shapes (F-007 / CLAS-039).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import polars as pl
import pytest
from otalon_common.uci import UCI_SEGMENT_COUNT, parse_uci

from otalon_clas.detection.bounds_manager import BoundsManager, BoundsTrainer
from otalon_clas.detection.frequency_monitor import FrequencyMonitor
from otalon_clas.detection.series_blacklist import SeriesBlacklist

pytestmark = pytest.mark.unit

_PRODUCTION_PATTERNS: list[str] = [
    "IPv6",
    "ff:ff:ff:ff:ff:ff",
    "8.8.8.8",
    "192.168.0.212",
    "192.168.1.241",
    "192.168.1.242",
    "50:61:d6:00:ba:b2",
    "50:61:d6:06:3b:34",
    "50:61:d6:00:ef:b8",
    "127.0.0.1",
]
"""The production ``SERIES_BLACKLIST`` entry set from ``.env``."""

_HMI1_SERIES = "50:61:d6:00:ba:b2/50:61:d6:06:3b:34//IPv4/192.168.0.51/192.168.0.141/49152/8080/Ethernet:IPv4:TCP"
"""HMI1↔IPC HTTP series in the shape the tester reported as mislabelled."""

_OPCUA_SERIES = "a8:74:1d:02:99:8d/a8:74:1d:18:c6:96//IPv4/192.168.0.41/192.168.0.10/4840/*/Ethernet:IPv4:TCP"
"""A real OPC UA series that must never be excluded (CLAS-038 fixture)."""

_V6_MULTICAST_SERIES = "a8:74:1d:02:99:8d/33:33:00:00:00:02//IPv6/fe80::1/ff02::2/*/*/Ethernet:IPv6:ICMPv6"
"""IPv6 multicast noise the ``IPv6`` entry is meant to exclude."""

_V6_UNICAST_SERIES = "aa:bb:cc:dd:ee:ff/00:11:22:33:44:55//IPv6/fe80::1/fe80::2/53/*/Ethernet:IPv6:UDP:DNS"
"""Legitimate IPv6 unicast that a naive match would wrongly swallow."""


def _uci_df(uci: str, rows: int = 6) -> pl.DataFrame:
    """Build a small DataFrame with the given UCI and feature columns.

    Args:
        uci: Series identifier.
        rows: Number of time rows to synthesize.

    Returns:
        DataFrame with ``uci``, ``time`` and one feature column.
    """
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return pl.DataFrame(
        {
            "uci": [uci] * rows,
            "time": [base + timedelta(seconds=60 * i) for i in range(rows)],
            "packet_count": [10.0] * rows,
        }
    )


class TestSeriesBlacklistMatching:
    """Field-aware semantics of the shared policy object."""

    def test_production_patterns_match_hmi_series(self) -> None:
        """A blacklisted MAC field inside a compound UCI is excluded."""
        blacklist = SeriesBlacklist(_PRODUCTION_PATTERNS)
        assert blacklist.matches(_HMI1_SERIES)

    def test_production_patterns_match_dns_resolver_flow(self) -> None:
        """A blacklisted IP field (8.8.8.8) inside a compound UCI is excluded."""
        blacklist = SeriesBlacklist(_PRODUCTION_PATTERNS)
        assert blacklist.matches(
            "80:39:5f:00:ab:d2/a8:74:1d:18:c6:96//IPv4/192.168.0.77/8.8.8.8/49698/53/Ethernet:IPv4:UDP:DNS"
        )

    def test_production_patterns_match_v6_multicast_noise(self) -> None:
        """The IPv6 entry excludes multicast/broadcast IPv6 flows."""
        assert SeriesBlacklist(_PRODUCTION_PATTERNS).matches(_V6_MULTICAST_SERIES)

    def test_production_patterns_keep_v6_unicast(self) -> None:
        """The IPv6 entry must not swallow legitimate IPv6 unicast."""
        assert not SeriesBlacklist(_PRODUCTION_PATTERNS).matches(_V6_UNICAST_SERIES)

    def test_production_patterns_keep_opcua_series(self) -> None:
        """A real OPC UA series with no blacklisted field survives."""
        assert not SeriesBlacklist(_PRODUCTION_PATTERNS).matches(_OPCUA_SERIES)

    def test_plain_tag_exact_and_prefix_unchanged(self) -> None:
        """Legacy exact/prefix semantics for plain tags are preserved."""
        blacklist = SeriesBlacklist(["ff:ff:ff:ff:ff:ff", "33:33:*"])
        assert blacklist.matches("ff:ff:ff:ff:ff:ff")
        assert blacklist.matches("33:33:00:00:00:02")
        assert not blacklist.matches("aa:bb:cc:dd:ee:ff")

    def test_uci_shaped_pattern_matches_fieldwise(self) -> None:
        """A UCI-shaped pattern is applied field by field with wildcards."""
        blacklist = SeriesBlacklist(["50:61:d6:00:ba:b2/*/*/IPv4/192.168.0.51"])
        assert blacklist.matches(_HMI1_SERIES)
        assert not blacklist.matches(_OPCUA_SERIES)

    def test_single_string_legacy_form_still_wraps(self) -> None:
        """A bare string is treated as one pattern (CLAS-038 shape)."""
        assert SeriesBlacklist("ff:ff:ff:ff:ff:ff").matches("ff:ff:ff:ff:ff:ff")

    def test_empty_blacklist_matches_nothing(self) -> None:
        """No patterns configured means nothing is excluded."""
        blacklist = SeriesBlacklist([])
        assert blacklist.is_empty
        assert not blacklist.matches(_HMI1_SERIES)

    def test_empty_series_id_matches_nothing(self) -> None:
        """An empty identifier is never excluded."""
        assert not SeriesBlacklist(_PRODUCTION_PATTERNS).matches("")


class TestWildcardTokenInsideCompoundUci:
    """CLAS-071 D5: wildcard value tokens match field-wise inside UCIs.

    A token such as ``33:33:*`` used to hit only plain tags; against a
    compound UCI it matched nothing, so the mac_traffic boot default
    never excluded the corresponding ``conn`` flows. It now
    prefix-matches the four endpoint fields exactly like the plain-tag
    path, while the CLAS-039 multicast guard on L3 tokens stays
    untouched.
    """

    _MULTICAST_UCI = (
        "7c:cb:e2:ea:0d:65/33:33:00:00:00:01/0/IPv6/192.168.0.196/ff02::2/1234/502/Ethernet:IPv4:TCP:MODBUS"
    )
    """Real 9-field UCI whose dst_mac is the multicast 33:33:00:00:00:01."""

    _UNICAST_UCI = (
        "7c:cb:e2:ea:0d:65/30:b8:51:31:06:84/0/IPv4/192.168.0.196/192.168.0.1/1234/502/Ethernet:IPv4:TCP:MODBUS"
    )
    """Same flow shape with unicast endpoints only."""

    def test_mac_wildcard_matches_multicast_uci(self) -> None:
        """``33:33:*`` excludes the flow whose dst_mac is 33:33:00:00:00:01."""
        blacklist = SeriesBlacklist(["33:33:*"])
        assert blacklist.matches(self._MULTICAST_UCI)

    def test_mac_wildcard_does_not_match_unicast_uci(self) -> None:
        """``33:33:*`` leaves a unicast flow untouched."""
        blacklist = SeriesBlacklist(["33:33:*"])
        assert not blacklist.matches(self._UNICAST_UCI)

    def test_mac_wildcard_matches_src_mac_field(self) -> None:
        """The prefix match covers src_mac as well as dst_mac."""
        uci = self._UNICAST_UCI.replace("7c:cb:e2:ea:0d:65", "33:33:00:00:00:01", 1)
        assert SeriesBlacklist(["33:33:*"]).matches(uci)

    def test_ipv4_multicast_wildcards_behave_identically(self) -> None:
        """``01:00:5e:*`` / ``01:80:c2:*`` carry the same UCI semantics."""
        for token, concrete in (
            ("01:00:5e:*", "01:00:5e:00:00:01"),
            ("01:80:c2:*", "01:80:c2:00:00:01"),
        ):
            uci = f"7c:cb:e2:ea:0d:65/{concrete}/0/IPv4/192.168.0.196/192.168.0.1/1234/502/Ethernet:IPv4:TCP"
            unicast = "7c:cb:e2:ea:0d:65/30:b8:51:31:06:84/0/IPv4/192.168.0.196/192.168.0.1/1234/502/Ethernet:IPv4:TCP"
            blacklist = SeriesBlacklist([token])
            assert blacklist.matches(uci), token
            assert not blacklist.matches(unicast), token

    def test_mac_wildcard_still_matches_plain_tags(self) -> None:
        """The plain-tag behaviour of a wildcard token is unchanged."""
        blacklist = SeriesBlacklist(["33:33:*"])
        assert blacklist.matches("33:33:00:00:00:02")
        assert not blacklist.matches("aa:bb:cc:dd:ee:ff")

    def test_ip_prefix_wildcard_matches_endpoint_field(self) -> None:
        """An IP-shaped wildcard prefix also hits endpoint fields."""
        uci = self._UNICAST_UCI.replace("192.168.0.1", "192.168.0.99")
        assert SeriesBlacklist(["192.168.0.*"]).matches(uci)
        assert not SeriesBlacklist(["192.168.9.*"]).matches(uci)

    def test_l3_guard_still_blocks_unicast(self) -> None:
        """CLAS-039: an L3 token still matches only multicast/broadcast flows."""
        v6_multicast = "a8:74:1d:02:99:8d/33:33:00:00:00:02//IPv6/fe80::1/ff02::2/*/*/Ethernet:IPv6:ICMPv6"
        blacklist = SeriesBlacklist(["IPv6"])
        assert blacklist.matches(v6_multicast)
        assert not blacklist.matches(_V6_UNICAST_SERIES)

    def test_wildcard_token_parsed_via_parse_uci_shape(self) -> None:
        """The matched UCIs are exactly 9 fields under ``parse_uci``."""
        fields = parse_uci(self._MULTICAST_UCI)
        assert len(fields) == UCI_SEGMENT_COUNT
        assert fields.dst_mac == "33:33:00:00:00:01"
        assert fields.src_mac == "7c:cb:e2:ea:0d:65"


class TestConsumersApplyFieldAwareBlacklist:
    """The three detection consumers share the policy and act on it."""

    def test_bounds_manager_skips_blacklisted_uci_series(self) -> None:
        """A blacklisted conn series is annotated clean despite no bounds.

        Without the fix the blacklist never matched a compound UCI, so
        the series fell through to the NoBounds path instead of being
        skipped, feeding the perpetual tcp_flood/port_scan anomaly
        stream behind F-007.
        """
        manager = BoundsManager(module_name="conn", blacklist=_PRODUCTION_PATTERNS)
        manager.load_bounds({})
        result = manager.check(df=_uci_df(_HMI1_SERIES), tag_key="uci", features=["packet_count"])
        assert not result["is_anomaly"].any()
        assert not (result["anomaly_type"] == "NoBounds").any()

    def test_bounds_manager_keeps_unlisted_uci_series(self) -> None:
        """A series without blacklisted fields keeps its NoBounds flag."""
        manager = BoundsManager(module_name="conn", blacklist=_PRODUCTION_PATTERNS)
        manager.load_bounds({})
        result = manager.check(df=_uci_df(_OPCUA_SERIES), tag_key="uci", features=["packet_count"])
        assert result["is_anomaly"].all()
        assert (result["anomaly_type"] == "NoBounds").all()

    def test_bounds_trainer_excludes_blacklisted_uci_from_training(self) -> None:
        """Bounds training drops blacklisted series entirely.

        The 5-hour coverage guard (CLAS-028) would skip the small
        fixture window, so the guard is disabled for this test via a
        zero ``min_series_coverage_hours``.
        """
        from otalon_clas.common.settings import BoundaryTrainingConfig

        frame = pl.concat([_uci_df(_HMI1_SERIES), _uci_df(_OPCUA_SERIES)])
        bounds = BoundsTrainer(blacklist=_PRODUCTION_PATTERNS).train(
            frame,
            tag_key="uci",
            features=["packet_count"],
            config=BoundaryTrainingConfig(min_series_coverage_hours=0.0),
        )
        assert _HMI1_SERIES not in bounds
        assert _OPCUA_SERIES in bounds

    def test_frequency_monitor_excludes_blacklisted_uci_from_absence(self) -> None:
        """A blacklisted series never reports absence (F-007 perpetuation path).

        The perpetual anomaly stream on mislabelled blacklisted series
        kept alarms open; absence monitoring of an excluded series is
        silence-by-design, so the excluded profile must stay unchecked.
        """
        monitor = FrequencyMonitor(absence_timeout_factor=1.0, blacklist=_PRODUCTION_PATTERNS)
        last_seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
        from otalon_clas.detection.frequency_monitor import _SeriesFrequencyProfile

        monitor._profiles = {
            _HMI1_SERIES: _SeriesFrequencyProfile(10.0, 1.0, last_seen=last_seen),
            _OPCUA_SERIES: _SeriesFrequencyProfile(10.0, 1.0, last_seen=last_seen),
        }
        results = monitor.check(
            pl.DataFrame({"time": [], "uci": []}),
            tag_key="uci",
            current_time="2026-01-01T00:05:00+00:00",
        )
        assert [r.series_id for r in results] == [_OPCUA_SERIES]

    def test_frequency_monitor_excludes_blacklisted_uci_from_observation(self) -> None:
        """A blacklisted series yields no frequency anomaly from live rows."""
        monitor = FrequencyMonitor(
            frequency_tolerance_factor=2.0,
            min_intervals=1,
            blacklist=_PRODUCTION_PATTERNS,
        )
        from otalon_clas.detection.frequency_monitor import _SeriesFrequencyProfile

        last_seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
        monitor._profiles = {
            _HMI1_SERIES: _SeriesFrequencyProfile(60.0, 1.0, last_seen=last_seen),
        }
        results = monitor.check(
            df=_uci_df(_HMI1_SERIES, rows=12),
            tag_key="uci",
            current_time="2026-01-01T01:00:00+00:00",
        )
        assert results == []
