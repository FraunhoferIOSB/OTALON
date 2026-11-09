"""Tests for UCI parsing: standard UCI, short UCI, IPv6, edge cases."""

from otalon_common.uci.parser import (UciParts, normalize_uci, parse_uci,
                                           parse_uci_to_dict)


class TestParseUci:
    """Tests for parse_uci()."""

    def test_standard_uci(self) -> None:
        result = parse_uci(
            "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/100/6/192.168.1.1/10.0.0.1/443/50000/TCP"
        )
        assert result == UciParts(
            src_mac="aa:bb:cc:dd:ee:ff",
            dst_mac="11:22:33:44:55:66",
            vlan="100",
            ip_proto="6",
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port="443",
            dst_port="50000",
            protocols="TCP",
        )

    def test_short_uci_pads_empty(self) -> None:
        result = parse_uci("aa:bb/cc:dd/100")
        assert result.src_mac == "aa:bb"
        assert result.dst_mac == "cc:dd"
        assert result.vlan == "100"
        assert result.ip_proto == ""
        assert result.src_ip == ""
        assert result.dst_ip == ""
        assert result.src_port == ""
        assert result.dst_port == ""
        assert result.protocols == ""

    def test_protocol_stack_with_slash(self) -> None:
        result = parse_uci("aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/80/9000/TCP/HTTP")
        assert result.protocols == "TCP/HTTP"

    def test_empty_string(self) -> None:
        result = parse_uci("")
        assert result.src_mac == ""
        assert all(f == "" for f in result)

    def test_returns_named_tuple(self) -> None:
        result = parse_uci("aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/80/9000/TCP")
        assert isinstance(result, UciParts)
        assert len(result) == 9


class TestParseUciToDict:
    """Tests for parse_uci_to_dict()."""

    def test_returns_dict_with_all_keys(self) -> None:
        result = parse_uci_to_dict("aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/80/9000/TCP")
        assert set(result.keys()) == {
            "src_mac",
            "dst_mac",
            "vlan",
            "ip_proto",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocols",
        }
        assert result["src_mac"] == "aa:bb"
        assert result["protocols"] == "TCP"


class TestNormalizeUci:
    """Tests for normalize_uci()."""

    def test_ipv6_normalization(self) -> None:
        result = normalize_uci("aa:bb/cc:dd/0/6/::1/0:0:0:0:0:0:0:1/80/9000/TCP")
        parts = parse_uci(result)
        assert parts.src_ip == "::1"
        assert parts.dst_ip == "::1"

    def test_ipv4_unchanged(self) -> None:
        uci = "aa:bb/cc:dd/100/6/192.168.1.1/10.0.0.1/80/9000/TCP"
        result = normalize_uci(uci)
        assert result == uci

    def test_empty_ip_unchanged(self) -> None:
        result = normalize_uci("aa:bb/cc:dd/100")
        parts = parse_uci(result)
        assert parts.src_ip == ""
        assert parts.dst_ip == ""
