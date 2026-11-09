"""Unit tests for netcap processing functions (M-08 and M-09).

Tests aggregate_sparse_ports() Polars-based sparse-port aggregation
and extract_wildcard_timeseries() wildcard UCI extraction.
"""

from __future__ import annotations

from datetime import datetime

import polars as pl
import pytest

from otalon_api.domain.netcap.processing import aggregate_sparse_ports, extract_wildcard_timeseries

SAMPLE_FEATURES = ["packet_count", "total_volume", "mean_packet_size"]


def _make_expanded_df(rows: list[dict]) -> pl.DataFrame:
    """Build a Polars DataFrame with expanded UCI fields and feature columns.

    Each row dict must contain UCI field values and feature values.
    The function constructs the DataFrame directly without going through
    expand_uci() to avoid coupling test helpers to the tested code.

    Args:
        rows: List of dicts with keys from UCI_FIELDS plus feature columns.

    Returns:
        Polars DataFrame suitable for aggregate_sparse_ports().
    """
    return pl.DataFrame(rows)


def _make_uci_row(
    src_mac: str = "00:01:05:00:00:01",
    dst_mac: str = "01:80:c2:00:00:0e",
    vlan: str = "",
    ip_proto: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    src_port: str = "",
    dst_port: str = "",
    protocols: str = "Ethernet:LLDP",
    time: datetime | None = None,
    packet_count: int = 10,
    total_volume: int = 500,
    mean_packet_size: float = 50.0,
) -> dict:
    """Create a single row dict for the expanded UCI DataFrame.

    Args:
        src_mac: Source MAC address.
        dst_mac: Destination MAC address.
        vlan: VLAN tag.
        ip_proto: IP protocol.
        src_ip: Source IP.
        dst_ip: Destination IP.
        src_port: Source port.
        dst_port: Destination port.
        protocols: Protocol stack string.
        time: Timestamp for the row.
        packet_count: Packet count value.
        total_volume: Total volume value.
        mean_packet_size: Mean packet size value.

    Returns:
        Dictionary representing one DataFrame row.
    """
    return {
        "time": time or datetime(2025, 1, 1, 12, 0, 0),
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "vlan": vlan,
        "ip_proto": ip_proto,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocols": protocols,
        "packet_count": packet_count,
        "total_volume": total_volume,
        "mean_packet_size": mean_packet_size,
    }


@pytest.mark.unit
class TestM08AggregateSparsePortss:
    """M-08: Tests for processing.aggregate_sparse_ports()."""

    def test_ports_below_threshold_become_wildcard(self):
        """M-08: Ports appearing less than threshold times are replaced with '*'."""
        rows = [
            _make_uci_row(src_port="1234", dst_port="80", packet_count=2),
            _make_uci_row(src_port="5678", dst_port="443", packet_count=3),
        ]
        df = _make_expanded_df(rows)

        result = aggregate_sparse_ports(df, threshold=5, feature_cols=SAMPLE_FEATURES)

        assert "uci" in result.columns
        uci_values = result["uci"].to_list()
        assert any("*" in uci for uci in uci_values)

    def test_ports_above_threshold_unchanged(self):
        """M-08: Ports appearing >= threshold times keep their values."""
        rows = [
            _make_uci_row(src_port="80", dst_port="443", packet_count=100),
        ]
        df = _make_expanded_df(rows)

        result = aggregate_sparse_ports(df, threshold=5, feature_cols=SAMPLE_FEATURES)

        assert result["src_port"].to_list() == ["80"]
        assert result["dst_port"].to_list() == ["443"]

    def test_features_summed_on_aggregation(self):
        """M-08: Feature values are summed when ports are merged."""
        rows = [
            _make_uci_row(src_port="1234", dst_port="80", packet_count=2, total_volume=100),
            _make_uci_row(src_port="5678", dst_port="443", packet_count=3, total_volume=200),
        ]
        df = _make_expanded_df(rows)

        result = aggregate_sparse_ports(df, threshold=5, feature_cols=SAMPLE_FEATURES)

        total_packets = result["packet_count"].sum()
        total_vol = result["total_volume"].sum()
        assert total_packets == 5
        assert total_vol == 300

    def test_empty_dataframe_returns_empty(self):
        """M-08: Empty expanded DataFrame returns empty result."""
        schema = {
            "time": pl.Datetime,
            "src_mac": pl.Utf8,
            "dst_mac": pl.Utf8,
            "vlan": pl.Utf8,
            "ip_proto": pl.Utf8,
            "src_ip": pl.Utf8,
            "dst_ip": pl.Utf8,
            "src_port": pl.Utf8,
            "dst_port": pl.Utf8,
            "protocols": pl.Utf8,
            "packet_count": pl.Int64,
            "total_volume": pl.Int64,
            "mean_packet_size": pl.Float64,
        }
        df = pl.DataFrame(schema=schema)

        result = aggregate_sparse_ports(df, threshold=5, feature_cols=SAMPLE_FEATURES)

        assert result.is_empty()

    def test_threshold_zero_no_aggregation(self):
        """M-08: threshold=0 means no ports are wildcarded (all have count > 0)."""
        rows = [
            _make_uci_row(src_port="80", dst_port="443", packet_count=1),
            _make_uci_row(src_port="8080", dst_port="8443", packet_count=2),
        ]
        df = _make_expanded_df(rows)

        result = aggregate_sparse_ports(df, threshold=0, feature_cols=SAMPLE_FEATURES)

        for src_port in result["src_port"].to_list():
            assert src_port != "*"
        for dst_port in result["dst_port"].to_list():
            assert dst_port != "*"

    def test_fields_preserved_correctly(self):
        """M-08: UCI fields are preserved correctly in the output."""
        rows = [
            _make_uci_row(
                src_mac="AA:BB:CC:DD:EE:FF",
                dst_mac="11:22:33:44:55:66",
                protocols="Ethernet:IP:TCP",
                src_port="80",
                dst_port="443",
                packet_count=100,
            ),
        ]
        df = _make_expanded_df(rows)

        result = aggregate_sparse_ports(df, threshold=5, feature_cols=SAMPLE_FEATURES)

        assert len(result) == 1
        assert result["src_mac"][0] == "AA:BB:CC:DD:EE:FF"
        assert result["dst_mac"][0] == "11:22:33:44:55:66"
        assert result["protocols"][0] == "Ethernet:IP:TCP"

    def test_both_src_and_dst_ports_wildcarded(self):
        """M-08: Both src_port AND dst_port can become '*' independently."""
        rows = [
            _make_uci_row(src_port="1111", dst_port="2222", packet_count=1),
            _make_uci_row(src_port="3333", dst_port="4444", packet_count=1),
            _make_uci_row(src_port="5555", dst_port="6666", packet_count=1),
        ]
        df = _make_expanded_df(rows)

        result = aggregate_sparse_ports(df, threshold=5, feature_cols=SAMPLE_FEATURES)

        uci_values = result["uci"].to_list()
        assert len(uci_values) == 1
        parts = uci_values[0].split("/")
        assert parts[6] == "*"
        assert parts[7] == "*"

    def test_time_column_preserved(self):
        """M-08: time column exists in output and has correct values."""
        ts = datetime(2025, 6, 15, 10, 30, 0)
        rows = [
            _make_uci_row(src_port="80", dst_port="443", packet_count=100, time=ts),
        ]
        df = _make_expanded_df(rows)

        result = aggregate_sparse_ports(df, threshold=5, feature_cols=SAMPLE_FEATURES)

        assert "time" in result.columns
        assert result["time"].to_list()[0] == ts

    def test_mixed_above_and_below_threshold(self):
        """M-08: Rows with packet_count above threshold are kept separate from merged rows."""
        rows = [
            _make_uci_row(src_port="80", dst_port="443", packet_count=100),
            _make_uci_row(src_port="1111", dst_port="2222", packet_count=1),
            _make_uci_row(src_port="3333", dst_port="4444", packet_count=2),
        ]
        df = _make_expanded_df(rows)

        result = aggregate_sparse_ports(df, threshold=5, feature_cols=SAMPLE_FEATURES)

        assert len(result) == 2
        packet_counts = sorted(result["packet_count"].to_list())
        assert packet_counts == [3, 100]


@pytest.mark.unit
class TestM09ExtractWildcardTimeseries:
    """M-09: Tests for processing.extract_wildcard_timeseries()."""

    def _build_aggregated_df(self, ucis: list[str]) -> pl.DataFrame:
        """Build a DataFrame with expanded UCI fields for multiple UCIs.

        Args:
            ucis: List of UCI strings to include.

        Returns:
            Polars DataFrame with expanded UCI fields.
        """
        rows = []
        for i, uci in enumerate(ucis):
            parts = uci.split("/", 8)
            parts += [""] * (9 - len(parts))
            row = {
                "time": datetime(2025, 1, 1, 12, i, 0),
                "src_mac": parts[0],
                "dst_mac": parts[1],
                "vlan": parts[2],
                "ip_proto": parts[3],
                "src_ip": parts[4],
                "dst_ip": parts[5],
                "src_port": parts[6],
                "dst_port": parts[7],
                "protocols": parts[8],
                "packet_count": (i + 1) * 10,
                "total_volume": (i + 1) * 100,
                "mean_packet_size": 50.0,
                "uci": uci,
            }
            rows.append(row)
        return pl.DataFrame(rows)

    def test_matching_uci_extracted(self):
        """M-09: Rows matching the wildcard UCI are extracted."""
        target_uci = "00:01:05:00:00:01/01:80:c2:00:00:0e///////Ethernet:LLDP"
        other_uci = "AA:BB:CC:DD:EE:FF/11:22:33:44:55:66///////Ethernet:IP"
        df = self._build_aggregated_df([target_uci, other_uci])

        result = extract_wildcard_timeseries(df, target_uci)

        assert len(result) == 1
        assert result["src_mac"][0] == "00:01:05:00:00:01"

    def test_non_matching_uci_returns_empty(self):
        """M-09: Non-existent UCI returns empty DataFrame."""
        uci = "00:01:05:00:00:01/01:80:c2:00:00:0e///////Ethernet:LLDP"
        df = self._build_aggregated_df([uci])

        result = extract_wildcard_timeseries(df, "FF:FF:FF:FF:FF:FF/00:00:00:00:00:00///////Ethernet:ARP")

        assert result.is_empty()

    def test_only_time_and_features_present(self):
        """M-09: Output contains time and feature columns among others."""
        target_uci = "00:01:05:00:00:01/01:80:c2:00:00:0e///////Ethernet:LLDP"
        df = self._build_aggregated_df([target_uci])

        result = extract_wildcard_timeseries(df, target_uci)

        assert "time" in result.columns
        assert "packet_count" in result.columns

    def test_empty_input_returns_empty(self):
        """M-09: Empty input DataFrame returns empty result."""
        schema = {
            "time": pl.Datetime,
            "src_mac": pl.Utf8,
            "dst_mac": pl.Utf8,
            "vlan": pl.Utf8,
            "ip_proto": pl.Utf8,
            "src_ip": pl.Utf8,
            "dst_ip": pl.Utf8,
            "src_port": pl.Utf8,
            "dst_port": pl.Utf8,
            "protocols": pl.Utf8,
            "packet_count": pl.Int64,
            "total_volume": pl.Int64,
            "mean_packet_size": pl.Float64,
            "uci": pl.Utf8,
        }
        df = pl.DataFrame(schema=schema)

        result = extract_wildcard_timeseries(df, "00:01:05:00:00:01/01:80:c2:00:00:0e///////Ethernet:LLDP")

        assert result.is_empty()

    def test_multiple_ucis_only_target_extracted(self):
        """M-09: DataFrame with multiple UCIs only returns the target one."""
        uci_a = "00:01:05:00:00:01/01:80:c2:00:00:0e///////Ethernet:LLDP"
        uci_b = "AA:BB:CC:DD:EE:FF/11:22:33:44:55:66///////Ethernet:IP"
        uci_c = "CC:DD:EE:00:00:01/FF:00:11:22:33:44///////Ethernet:ARP"
        df = self._build_aggregated_df([uci_a, uci_b, uci_c])

        result = extract_wildcard_timeseries(df, uci_b)

        assert len(result) == 1
        assert result["src_mac"][0] == "AA:BB:CC:DD:EE:FF"
        assert result["dst_mac"][0] == "11:22:33:44:55:66"

    def test_wildcard_port_matches_any_port(self):
        """M-09: UCI with '*' in port positions matches any port value."""
        df = pl.DataFrame(
            [
                {
                    "time": datetime(2025, 1, 1, 12, 0, 0),
                    "src_mac": "AA:BB:CC:DD:EE:FF",
                    "dst_mac": "11:22:33:44:55:66",
                    "vlan": "",
                    "ip_proto": "6",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "src_port": "12345",
                    "dst_port": "80",
                    "protocols": "Ethernet:IP:TCP",
                    "packet_count": 10,
                    "total_volume": 500,
                    "uci": "AA:BB:CC:DD:EE:FF/11:22:33:44:55:66//6/10.0.0.1/10.0.0.2/12345/80/Ethernet:IP:TCP",
                },
                {
                    "time": datetime(2025, 1, 1, 12, 1, 0),
                    "src_mac": "AA:BB:CC:DD:EE:FF",
                    "dst_mac": "11:22:33:44:55:66",
                    "vlan": "",
                    "ip_proto": "6",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "src_port": "54321",
                    "dst_port": "443",
                    "protocols": "Ethernet:IP:TCP",
                    "packet_count": 20,
                    "total_volume": 1000,
                    "uci": "AA:BB:CC:DD:EE:FF/11:22:33:44:55:66//6/10.0.0.1/10.0.0.2/54321/443/Ethernet:IP:TCP",
                },
            ]
        )

        wildcard_uci = "AA:BB:CC:DD:EE:FF/11:22:33:44:55:66//6/10.0.0.1/10.0.0.2/*/*/Ethernet:IP:TCP"
        result = extract_wildcard_timeseries(df, wildcard_uci)

        assert len(result) == 2

    def test_wildcard_src_port_only(self):
        """M-09: UCI with '*' in src_port but specific dst_port filters correctly."""
        df = pl.DataFrame(
            [
                {
                    "time": datetime(2025, 1, 1, 12, 0, 0),
                    "src_mac": "AA:BB:CC:DD:EE:FF",
                    "dst_mac": "11:22:33:44:55:66",
                    "vlan": "",
                    "ip_proto": "6",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "src_port": "12345",
                    "dst_port": "80",
                    "protocols": "Ethernet:IP:TCP",
                    "packet_count": 10,
                    "total_volume": 500,
                    "uci": "AA:BB:CC:DD:EE:FF/11:22:33:44:55:66//6/10.0.0.1/10.0.0.2/12345/80/Ethernet:IP:TCP",
                },
                {
                    "time": datetime(2025, 1, 1, 12, 1, 0),
                    "src_mac": "AA:BB:CC:DD:EE:FF",
                    "dst_mac": "11:22:33:44:55:66",
                    "vlan": "",
                    "ip_proto": "6",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "src_port": "54321",
                    "dst_port": "443",
                    "protocols": "Ethernet:IP:TCP",
                    "packet_count": 20,
                    "total_volume": 1000,
                    "uci": "AA:BB:CC:DD:EE:FF/11:22:33:44:55:66//6/10.0.0.1/10.0.0.2/54321/443/Ethernet:IP:TCP",
                },
            ]
        )

        wildcard_uci = "AA:BB:CC:DD:EE:FF/11:22:33:44:55:66//6/10.0.0.1/10.0.0.2/*/80/Ethernet:IP:TCP"
        result = extract_wildcard_timeseries(df, wildcard_uci)

        assert len(result) == 1
        assert result["dst_port"][0] == "80"
