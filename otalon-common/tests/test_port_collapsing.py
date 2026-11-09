"""Tests for stateless port-collapsing fallback and port wildcard helper."""

import polars as pl
from otalon_common.connection.port_collapsing import (
    aggregate_sparse_ports, port_wildcard)


class TestPortWildcard:
    """Tests for port_wildcard()."""

    def test_single_unique_port(self) -> None:
        assert port_wildcard(["443", "443", "443"]) == "443"

    def test_multiple_ports(self) -> None:
        assert port_wildcard(["443", "8080", "443"]) == "*"

    def test_single_port(self) -> None:
        assert port_wildcard(["80"]) == "80"

    def test_empty_list(self) -> None:
        assert port_wildcard([]) == "*"

    def test_empty_strings_ignored(self) -> None:
        assert port_wildcard(["443", "", "443"]) == "443"


class TestAggregateSparsePortsSmoke:
    """Tests for aggregate_sparse_ports()."""

    def test_sparse_rows_aggregated(self) -> None:
        df = pl.DataFrame(
            {
                "src_mac": ["aa:bb", "aa:bb", "aa:bb"],
                "dst_mac": ["cc:dd", "cc:dd", "cc:dd"],
                "vlan": ["100", "100", "100"],
                "ip_proto": ["6", "6", "6"],
                "src_ip": ["1.1.1.1", "1.1.1.1", "1.1.1.1"],
                "dst_ip": ["2.2.2.2", "2.2.2.2", "2.2.2.2"],
                "src_port": ["1000", "2000", "3000"],
                "dst_port": ["443", "443", "443"],
                "protocols": ["TCP", "TCP", "TCP"],
                "packet_count": [2, 3, 4],
            }
        )
        result = aggregate_sparse_ports(df, threshold=10)
        assert len(result) == 1
        assert result["src_port"][0] == "*"
        assert result["dst_port"][0] == "443"
        assert result["packet_count"][0] == 9

    def test_non_sparse_rows_preserved(self) -> None:
        df = pl.DataFrame(
            {
                "src_mac": ["aa:bb"],
                "dst_mac": ["cc:dd"],
                "vlan": ["100"],
                "ip_proto": ["6"],
                "src_ip": ["1.1.1.1"],
                "dst_ip": ["2.2.2.2"],
                "src_port": ["1000"],
                "dst_port": ["443"],
                "protocols": ["TCP"],
                "packet_count": [50],
            }
        )
        result = aggregate_sparse_ports(df, threshold=10)
        assert len(result) == 1
        assert result["packet_count"][0] == 50

    def test_mixed_sparse_and_non_sparse(self) -> None:
        df = pl.DataFrame(
            {
                "src_mac": ["aa:bb", "aa:bb", "xx:yy"],
                "dst_mac": ["cc:dd", "cc:dd", "zz:ww"],
                "vlan": ["100", "100", "200"],
                "ip_proto": ["6", "6", "17"],
                "src_ip": ["1.1.1.1", "1.1.1.1", "10.0.0.1"],
                "dst_ip": ["2.2.2.2", "2.2.2.2", "10.0.0.2"],
                "src_port": ["1000", "2000", "5000"],
                "dst_port": ["443", "443", "8080"],
                "protocols": ["TCP", "TCP", "UDP"],
                "packet_count": [2, 3, 100],
            }
        )
        result = aggregate_sparse_ports(df, threshold=10)
        assert len(result) == 2
