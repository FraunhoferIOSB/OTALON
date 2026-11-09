"""Edge-case tests for anomaly domain processing (M-03, M-07).

M-03: NaN handling in prepare_timeseries_with_bounds
M-07: UCI parsing edge cases
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from otalon_api.domain.anomaly.processing import parse_uci, prepare_timeseries_with_bounds


class TestM03NanHandling:
    """M-03: NaN handling in prepare_timeseries_with_bounds."""

    @pytest.mark.unit
    def test_nan_values_converted_to_none(self) -> None:
        """NaN values in timeseries should become None in the output."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00", "2026-01-01T00:01:00"]),
                "metric_a": [float("nan"), 42.0],
            }
        )
        bounds = [{"lb_metric_a": 10.0, "ub_metric_a": 100.0}]

        result = prepare_timeseries_with_bounds(df, bounds, "metric_a")

        assert len(result) == 2
        assert result[0]["value"] is None
        assert result[1]["value"] == 42.0

    @pytest.mark.unit
    def test_nan_values_no_violations(self) -> None:
        """NaN values should not trigger violations."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00"]),
                "metric_a": [float("nan")],
            }
        )
        bounds = [{"lb_metric_a": 10.0, "ub_metric_a": 100.0}]

        result = prepare_timeseries_with_bounds(df, bounds, "metric_a")

        assert result[0]["violation_low"] is False
        assert result[0]["violation_high"] is False

    @pytest.mark.unit
    def test_empty_bounds_no_match(self) -> None:
        """Empty bounds list should produce NaN bounds → None in output."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00"]),
                "metric_a": [50.0],
            }
        )

        result = prepare_timeseries_with_bounds(df, [], "metric_a")

        assert len(result) == 1
        assert result[0]["value"] == 50.0
        assert result[0]["lower_bound"] is None
        assert result[0]["upper_bound"] is None
        assert result[0]["violation_low"] is False
        assert result[0]["violation_high"] is False

    @pytest.mark.unit
    def test_partial_bounds_only_some_metrics(self) -> None:
        """Bounds with only some metrics should leave others as None."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00"]),
                "metric_a": [50.0],
            }
        )
        bounds = [{"lb_metric_b": 10.0, "ub_metric_b": 100.0}]

        result = prepare_timeseries_with_bounds(df, bounds, "metric_a")

        assert result[0]["lower_bound"] is None
        assert result[0]["upper_bound"] is None

    @pytest.mark.unit
    def test_empty_dataframe_returns_empty_list(self) -> None:
        """Empty DataFrame should return empty result list."""
        df = pd.DataFrame()

        result = prepare_timeseries_with_bounds(df, [], "metric_a")

        assert result == []

    @pytest.mark.unit
    def test_none_dataframe_returns_empty_list(self) -> None:
        """None DataFrame should return empty result list."""
        result = prepare_timeseries_with_bounds(None, [], "metric_a")

        assert result == []

    @pytest.mark.unit
    def test_nan_in_bounds_converted_to_none(self) -> None:
        """NaN values in bounds should become None in output."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00"]),
                "metric_a": [50.0],
            }
        )
        bounds = [{"lb_metric_a": float("nan"), "ub_metric_a": float("nan")}]

        result = prepare_timeseries_with_bounds(df, bounds, "metric_a")

        assert result[0]["lower_bound"] is None
        assert result[0]["upper_bound"] is None

    @pytest.mark.unit
    def test_aggregated_columns_min_max(self) -> None:
        """Aggregated data with _min/_max columns should populate value_min/value_max."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00"]),
                "metric_a": [50.0],
                "metric_a_min": [45.0],
                "metric_a_max": [55.0],
            }
        )
        bounds = [{"lb_metric_a": 10.0, "ub_metric_a": 100.0}]

        result = prepare_timeseries_with_bounds(df, bounds, "metric_a")

        assert result[0]["value"] == 50.0
        assert result[0]["value_min"] == 45.0
        assert result[0]["value_max"] == 55.0

    @pytest.mark.unit
    def test_violation_detection(self) -> None:
        """Values outside bounds should trigger violation flags."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(
                    [
                        "2026-01-01T00:00:00",
                        "2026-01-01T00:01:00",
                        "2026-01-01T00:02:00",
                    ]
                ),
                "metric_a": [5.0, 50.0, 150.0],
            }
        )
        bounds = [{"lb_metric_a": 10.0, "ub_metric_a": 100.0}]

        result = prepare_timeseries_with_bounds(df, bounds, "metric_a")

        assert result[0]["violation_low"] is True
        assert result[0]["violation_high"] is False
        assert result[1]["violation_low"] is False
        assert result[1]["violation_high"] is False
        assert result[2]["violation_low"] is False
        assert result[2]["violation_high"] is True

    @pytest.mark.unit
    def test_numpy_nan_converted(self) -> None:
        """numpy NaN values should also be converted to None."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00"]),
                "metric_a": [np.nan],
            }
        )
        bounds = [{"lb_metric_a": 10.0, "ub_metric_a": 100.0}]

        result = prepare_timeseries_with_bounds(df, bounds, "metric_a")

        assert result[0]["value"] is None


class TestM07UciParsing:
    """M-07: UCI parsing edge cases."""

    @pytest.mark.unit
    def test_parse_full_uci(self) -> None:
        """Parse a complete UCI with all 9 segments filled."""
        uci = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/100/IPv4/10.0.0.1/10.0.0.2/80/443/Ethernet:IPv4:TCP"

        result = parse_uci(uci)

        assert result["src_mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["dst_mac"] == "11:22:33:44:55:66"
        assert result["vlan"] == "100"
        assert result["ip_proto"] == "IPv4"
        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "10.0.0.2"
        assert result["src_port"] == "80"
        assert result["dst_port"] == "443"
        assert result["protocols"] == "Ethernet:IPv4:TCP"

    @pytest.mark.unit
    def test_parse_uci_empty_segments(self) -> None:
        """Parse a UCI with empty segments (Layer 2 only)."""
        uci = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66///////Ethernet:LLDP"

        result = parse_uci(uci)

        assert result["src_mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["dst_mac"] == "11:22:33:44:55:66"
        assert result["vlan"] == ""
        assert result["ip_proto"] == ""
        assert result["src_ip"] == ""
        assert result["dst_ip"] == ""
        assert result["src_port"] == ""
        assert result["dst_port"] == ""
        assert result["protocols"] == "Ethernet:LLDP"

    @pytest.mark.unit
    def test_parse_uci_too_few_segments(self) -> None:
        """Parse a UCI with fewer than 9 segments — missing segments become empty."""
        uci = "aa:bb/cc:dd"

        result = parse_uci(uci)

        assert result["src_mac"] == "aa:bb"
        assert result["dst_mac"] == "cc:dd"
        assert result["vlan"] == ""
        assert result["protocols"] == ""
        assert len(result) == 9

    @pytest.mark.unit
    def test_parse_uci_too_many_segments(self) -> None:
        """Parse a UCI with more than 9 segments — extras stay in last segment."""
        uci = "a/b/c/d/e/f/g/h/i/j/k"

        result = parse_uci(uci)

        assert result["src_mac"] == "a"
        assert result["protocols"] == "i/j/k"
        assert len(result) == 9

    @pytest.mark.unit
    def test_parse_uci_single_segment(self) -> None:
        """Parse a UCI with a single segment — all others empty."""
        uci = "only-src-mac"

        result = parse_uci(uci)

        assert result["src_mac"] == "only-src-mac"
        assert result["dst_mac"] == ""
        assert result["protocols"] == ""
        assert len(result) == 9

    @pytest.mark.unit
    def test_parse_uci_empty_string(self) -> None:
        """Parse an empty UCI string — first segment empty, rest filled with empty."""
        result = parse_uci("")

        assert result["src_mac"] == ""
        assert len(result) == 9
        assert all(v == "" for v in result.values())

    @pytest.mark.unit
    def test_parse_uci_all_segments_filled_real_data(self) -> None:
        """Parse a realistic PROFINET UCI with VLAN segment."""
        uci = "00:01:05:93:50:9b/a8:74:1d:02:99:8d/0//////Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO"

        result = parse_uci(uci)

        assert result["src_mac"] == "00:01:05:93:50:9b"
        assert result["dst_mac"] == "a8:74:1d:02:99:8d"
        assert result["vlan"] == "0"
        assert result["protocols"] == "Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO"
