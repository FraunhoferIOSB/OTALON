"""Tests for UCI matching utilities: wildcard detection, pattern matching."""

from otalon_common.uci.matching import (
    base_key_without_ports,
    is_wildcard_uci,
    match_uci_pattern,
    matches_port_collapse_sibling,
)


class TestBaseKeyWithoutPorts:
    """Tests for base_key_without_ports()."""

    def test_extracts_7_fields(self) -> None:
        result = base_key_without_ports(
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP"
        )
        assert result == "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/TCP"

    def test_wildcard_ports_excluded(self) -> None:
        result = base_key_without_ports("aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/*/TCP")
        assert result == "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/TCP"


class TestIsWildcardUci:
    """Tests for is_wildcard_uci()."""

    def test_wildcard_src_port(self) -> None:
        assert is_wildcard_uci("aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/9000/TCP") is True

    def test_wildcard_dst_port(self) -> None:
        assert is_wildcard_uci("aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/*/TCP") is True

    def test_both_wildcard(self) -> None:
        assert is_wildcard_uci("aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/*/TCP") is True

    def test_no_wildcard(self) -> None:
        assert (
            is_wildcard_uci("aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP") is False
        )


class TestMatchUciPattern:
    """Tests for match_uci_pattern()."""

    def test_exact_match(self) -> None:
        uci = "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP"
        assert match_uci_pattern(uci, uci) is True

    def test_wildcard_ports_match(self) -> None:
        uci = "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP"
        pattern = "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/*/TCP"
        assert match_uci_pattern(uci, pattern) is True

    def test_different_base_key_no_match(self) -> None:
        uci = "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP"
        pattern = "xx:yy/cc:dd/100/6/1.1.1.1/2.2.2.2/*/*/TCP"
        assert match_uci_pattern(uci, pattern) is False

    def test_wildcard_src_only(self) -> None:
        uci = "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP"
        pattern = "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/50000/TCP"
        assert match_uci_pattern(uci, pattern) is True

    def test_different_protocol_no_match(self) -> None:
        uci = "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP"
        pattern = "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/*/UDP"
        assert match_uci_pattern(uci, pattern) is False


class TestMatchesPortCollapseSibling:
    """Tests for matches_port_collapse_sibling() (UI-CLAS-057 parity)."""

    _CONCRETE = (
        "00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/"
        "192.168.0.2/192.168.0.41/50000/56247/Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
    )
    _FULL_WILD = (
        "00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/"
        "192.168.0.2/192.168.0.41/*/*/Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
    )
    _PARTIAL_WILD = (
        "00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/"
        "192.168.0.2/192.168.0.41/56247/*/Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
    )
    _ROTATED_PORTS = (
        "00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/"
        "192.168.0.2/192.168.0.41/56247/50000/Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
    )
    _REVERSE_WILD = (
        "a8:74:1d:02:99:8d/00:01:05:2b:ae:a2//IPv4/"
        "192.168.0.41/192.168.0.2/56247/*/Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
    )
    _REVERSE_CONCRETE = (
        "a8:74:1d:02:99:8d/00:01:05:2b:ae:a2//IPv4/"
        "192.168.0.41/192.168.0.2/56247/50000/"
        "Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
    )
    _UNRELATED = "de:ad:be:ef:00:01/00:02:03:04:05:06//IPv4/10.0.0.1/10.0.0.2/*/*/Ethernet:IPv4:TCP:HTTP"
    _BCAST_CONCRETE = "38:4b:3c:00:00:01/ff:ff:ff:ff:ff:ff//IPv4/192.168.1.5/192.168.1.255/0/0/Ethernet:IPv4:UDP"
    _BCAST_WILD_SAME = "38:4b:3c:00:00:01/ff:ff:ff:ff:ff:ff//IPv4/192.168.1.5/192.168.1.255/*/*/Ethernet:IPv4:UDP"
    _BCAST_REVERSE = "ff:ff:ff:ff:ff:ff/38:4b:3c:00:00:01//IPv4/192.168.1.255/192.168.1.5/*/*/Ethernet:IPv4:UDP"
    _MCAST_REVERSE = "33:33:00:00:00:fb/38:4b:3c:00:00:01//IPv6/fe80::1/ff02::fb/*/*/Ethernet:IPv6:UDP:mDNS"

    def test_exact_match(self) -> None:
        assert matches_port_collapse_sibling(self._CONCRETE, self._CONCRETE) is True

    def test_full_wildcard_direct_sibling(self) -> None:
        assert matches_port_collapse_sibling(self._FULL_WILD, self._CONCRETE) is True

    def test_partial_wildcard_direct_sibling(self) -> None:
        assert matches_port_collapse_sibling(self._PARTIAL_WILD, self._CONCRETE) is True

    def test_rotated_concrete_ports_direct_sibling(self) -> None:
        assert (
            matches_port_collapse_sibling(self._ROTATED_PORTS, self._CONCRETE) is True
        )

    def test_reverse_direction_wildcard_sibling(self) -> None:
        assert matches_port_collapse_sibling(self._REVERSE_WILD, self._CONCRETE) is True

    def test_reverse_direction_concrete_sibling(self) -> None:
        assert (
            matches_port_collapse_sibling(self._REVERSE_CONCRETE, self._CONCRETE)
            is True
        )

    def test_unrelated_identity_no_match(self) -> None:
        assert matches_port_collapse_sibling(self._UNRELATED, self._CONCRETE) is False

    def test_broadcast_mac_not_reverse_matched(self) -> None:
        assert (
            matches_port_collapse_sibling(self._BCAST_REVERSE, self._BCAST_CONCRETE)
            is False
        )

    def test_broadcast_mac_same_direction_still_matches(self) -> None:
        assert (
            matches_port_collapse_sibling(self._BCAST_WILD_SAME, self._BCAST_CONCRETE)
            is True
        )

    def test_multicast_mac_not_reverse_matched(self) -> None:
        assert (
            matches_port_collapse_sibling(self._MCAST_REVERSE, self._CONCRETE) is False
        )

    def test_reverse_with_mismatched_protocol_no_match(self) -> None:
        wrong_proto = (
            "a8:74:1d:02:99:8d/00:01:05:2b:ae:a2//IPv4/"
            "192.168.0.41/192.168.0.2/56247/*/Ethernet:IPv4:TCP:HTTP"
        )
        assert matches_port_collapse_sibling(wrong_proto, self._CONCRETE) is False
