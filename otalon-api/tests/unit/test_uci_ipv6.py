"""Unit tests for IPv6 UCI parsing and normalization."""

from otalon_api.domain.topology.uci import normalize_uci, parse_uci


class TestParseUciIpv6:
    """Tests for parse_uci with IPv6 addresses."""

    def test_parse_ipv6_compressed(self) -> None:
        """Verify parse_uci correctly extracts compressed IPv6 addresses."""
        uci = "a8:74:1d:18:c6:96/33:33:00:00:00:02//IPv6/fe80::aa74:1dff:fe18:c696/ff02::2/0/0/Ethernet:IPv6:ICMPv6"
        parts = parse_uci(uci)
        assert parts[0] == "a8:74:1d:18:c6:96"
        assert parts[1] == "33:33:00:00:00:02"
        assert parts[2] == ""
        assert parts[3] == "IPv6"
        assert parts[4] == "fe80::aa74:1dff:fe18:c696"
        assert parts[5] == "ff02::2"
        assert parts[6] == "0"
        assert parts[7] == "0"
        assert parts[8] == "Ethernet:IPv6:ICMPv6"

    def test_parse_ipv6_link_local(self) -> None:
        """Verify parse_uci handles link-local IPv6 addresses."""
        uci = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66//IPv6/fe80::1/fe80::2/0/0/Ethernet:IPv6"
        parts = parse_uci(uci)
        assert parts[4] == "fe80::1"
        assert parts[5] == "fe80::2"

    def test_parse_ipv6_multicast(self) -> None:
        """Verify parse_uci handles IPv6 multicast addresses."""
        uci = "aa:bb:cc:dd:ee:ff/33:33:00:00:00:01//IPv6/fe80::1/ff02::1/0/0/Ethernet:IPv6:ICMPv6"
        parts = parse_uci(uci)
        assert parts[5] == "ff02::1"


class TestNormalizeUci:
    """Tests for normalize_uci IPv6 address canonicalization."""

    def test_normalize_compressed_ipv6_unchanged(self) -> None:
        """Verify already-compressed IPv6 addresses are preserved."""
        uci = "a8:74:1d:18:c6:96/33:33:00:00:00:02//IPv6/fe80::aa74:1dff:fe18:c696/ff02::2/0/0/Ethernet:IPv6:ICMPv6"
        result = normalize_uci(uci)
        assert result == uci

    def test_normalize_expanded_ipv6_compresses(self) -> None:
        """Verify fully expanded IPv6 addresses are compressed."""
        uci = (
            "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/IPv6/"
            "fe80:0000:0000:0000:0000:0000:0000:0001/"
            "ff02:0000:0000:0000:0000:0000:0000:0002/0/0/Ethernet:IPv6:ICMPv6"
        )
        result = normalize_uci(uci)
        assert "fe80::1/" in result
        assert "/ff02::2/" in result

    def test_normalize_mixed_zeros_ipv6(self) -> None:
        """Verify partially-expanded IPv6 addresses are compressed."""
        uci = (
            "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/IPv6/"
            "fe80:0:0:0:aa74:1dff:fe18:c696/"
            "ff02:0:0:0:0:0:0:2/0/0/Ethernet:IPv6:ICMPv6"
        )
        result = normalize_uci(uci)
        assert "fe80::aa74:1dff:fe18:c696" in result
        assert "ff02::2" in result

    def test_normalize_ipv4_unchanged(self) -> None:
        """Verify IPv4 UCIs pass through normalization unchanged."""
        uci = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/IPv4/192.168.1.1/192.168.1.2/12345/80/Ethernet:IPv4:TCP"
        result = normalize_uci(uci)
        assert result == uci

    def test_normalize_empty_ip_fields(self) -> None:
        """Verify UCIs with empty IP fields are unchanged."""
        uci = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/ARP///0/0/Ethernet:ARP"
        result = normalize_uci(uci)
        assert result == uci

    def test_normalize_preserves_all_nine_fields(self) -> None:
        """Verify normalization preserves the 9-field UCI structure."""
        uci = "a8:74:1d:18:c6:96/33:33:00:00:00:02//IPv6/fe80::1/ff02::2/0/0/Ethernet:IPv6:ICMPv6"
        result = normalize_uci(uci)
        parts = result.split("/")
        assert len(parts) == 9

    def test_normalize_uppercase_hex_ipv6(self) -> None:
        """Verify uppercase hex in IPv6 addresses is lowercased."""
        uci = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/IPv6/FE80::AA74:1DFF:FE18:C696/FF02::2/0/0/Ethernet:IPv6"
        result = normalize_uci(uci)
        assert "fe80::aa74:1dff:fe18:c696" in result
        assert "ff02::2" in result

    def test_normalize_invalid_ipv6_left_unchanged(self) -> None:
        """Verify invalid IPv6-like strings are not modified."""
        uci = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/IPv6/not:a:valid:ipv6/also:invalid/0/0/Ethernet:IPv6"
        result = normalize_uci(uci)
        assert "not:a:valid:ipv6" in result
        assert "also:invalid" in result

    def test_normalize_mac_addresses_not_touched(self) -> None:
        """Verify MAC addresses (which contain colons) are not modified."""
        uci = "a8:74:1d:18:c6:96/33:33:00:00:00:02//IPv6/fe80::1/ff02::2/0/0/Ethernet:IPv6"
        result = normalize_uci(uci)
        assert result.startswith("a8:74:1d:18:c6:96/33:33:00:00:00:02/")
