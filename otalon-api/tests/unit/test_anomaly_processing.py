"""Unit tests for anomaly domain processing logic.

Tests compute_signal_color, compute_signal_color_from_groups, parse_uci,
and prepare_timeseries_with_bounds.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from otalon_api.domain.anomaly.processing import (
    compute_signal_color,
    compute_signal_color_from_groups,
    parse_uci,
    prepare_timeseries_with_bounds,
)


class TestComputeSignalColor:
    """Tests for compute_signal_color(anomaly_count, group_count)."""

    @pytest.mark.unit
    def test_no_anomalies_returns_success(self) -> None:
        """Zero anomaly count and group count → 'success' (green)."""
        result = compute_signal_color(anomaly_count=0, group_count=0)
        assert result == "success"

    @pytest.mark.unit
    def test_groups_present_returns_danger(self) -> None:
        """Non-zero group count → 'danger' (red)."""
        result = compute_signal_color(anomaly_count=3, group_count=2)
        assert result == "danger"

    @pytest.mark.unit
    def test_anomalies_but_no_groups_returns_warning(self) -> None:
        """Anomalies but zero groups → 'warning' (yellow)."""
        result = compute_signal_color(anomaly_count=5, group_count=0)
        assert result == "warning"

    @pytest.mark.unit
    def test_single_group_returns_danger(self) -> None:
        """Even a single group → 'danger'."""
        result = compute_signal_color(anomaly_count=1, group_count=1)
        assert result == "danger"

    @pytest.mark.unit
    def test_negative_counts_success(self) -> None:
        """Negative counts treated as zero → 'success'."""
        result = compute_signal_color(anomaly_count=-1, group_count=-1)
        assert result == "success"


class TestComputeSignalColorFromGroups:
    """Tests for compute_signal_color_from_groups(groups)."""

    @pytest.mark.unit
    def test_empty_groups_returns_success(self) -> None:
        """Empty group list → 'success'."""
        result = compute_signal_color_from_groups([])
        assert result == "success"

    @pytest.mark.unit
    def test_all_confirmed_returns_success(self) -> None:
        """All confirmed groups → 'success'."""
        groups = [
            {"confirmed": True, "primary_type": "T0846/pn_discovery"},
            {"confirmed": True, "primary_type": "BoundViolation"},
        ]
        result = compute_signal_color_from_groups(groups)
        assert result == "success"

    @pytest.mark.unit
    def test_unconfirmed_non_benign_returns_danger(self) -> None:
        """Unconfirmed non-benign group → 'danger'."""
        groups = [
            {"confirmed": False, "primary_type": "T0846/pn_discovery"},
        ]
        result = compute_signal_color_from_groups(groups)
        assert result == "danger"

    @pytest.mark.unit
    def test_unconfirmed_benign_only_returns_warning(self) -> None:
        """Only unconfirmed benign groups → 'warning'."""
        groups = [
            {"confirmed": False, "primary_type": "BoundViolation"},
        ]
        result = compute_signal_color_from_groups(groups)
        assert result == "warning"

    @pytest.mark.unit
    def test_mixed_confirmed_and_unconfirmed_benign(self) -> None:
        """Mix of confirmed and unconfirmed benign → 'warning'."""
        groups = [
            {"confirmed": True, "primary_type": "T0846/pn_discovery"},
            {"confirmed": False, "primary_type": "NoBounds"},
        ]
        result = compute_signal_color_from_groups(groups)
        assert result == "warning"

    @pytest.mark.unit
    def test_unconfirmed_unknown_type_returns_success(self) -> None:
        """Unconfirmed unknown-type groups → 'success' (not yellow/red)."""
        groups = [
            {"confirmed": False, "primary_type": "unknown"},
        ]
        result = compute_signal_color_from_groups(groups)
        assert result == "success"

    @pytest.mark.unit
    def test_none_primary_type_treated_as_unknown(self) -> None:
        """None primary_type treated as unknown."""
        groups = [
            {"confirmed": False, "primary_type": None},
        ]
        result = compute_signal_color_from_groups(groups)
        assert result == "success"


class TestParseUci:
    """Tests for parse_uci() function."""

    @pytest.mark.unit
    def test_standard_nine_segment_uci(self) -> None:
        """Standard 9-segment UCI is parsed into all fields."""
        uci = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/100/IPv4/10.0.0.1/10.0.0.2/80/443/TCP"

        result = parse_uci(uci)

        assert result["src_mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["dst_mac"] == "11:22:33:44:55:66"
        assert result["vlan"] == "100"
        assert result["ip_proto"] == "IPv4"
        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "10.0.0.2"
        assert result["src_port"] == "80"
        assert result["dst_port"] == "443"
        assert result["protocols"] == "TCP"

    @pytest.mark.unit
    def test_layer2_only_uci(self) -> None:
        """Layer-2-only UCI with empty IP/port segments."""
        uci = "00:01:05:93:50:9b/01:0e:cf:00:00:00/0//////Ethernet:LLDP"

        result = parse_uci(uci)

        assert result["src_mac"] == "00:01:05:93:50:9b"
        assert result["dst_mac"] == "01:0e:cf:00:00:00"
        assert result["vlan"] == "0"
        assert result["src_ip"] == ""
        assert result["dst_ip"] == ""
        assert result["src_port"] == ""
        assert result["dst_port"] == ""
        assert result["protocols"] == "Ethernet:LLDP"

    @pytest.mark.unit
    def test_short_uci_pads_empty(self) -> None:
        """UCI with fewer than 9 segments fills missing with empty strings."""
        uci = "mac1/mac2/vlan"

        result = parse_uci(uci)

        assert result["src_mac"] == "mac1"
        assert result["dst_mac"] == "mac2"
        assert result["vlan"] == "vlan"
        assert result["ip_proto"] == ""
        assert result["src_ip"] == ""
        assert result["dst_ip"] == ""
        assert result["src_port"] == ""
        assert result["dst_port"] == ""
        assert result["protocols"] == ""

    @pytest.mark.unit
    def test_long_uci_extras_in_last(self) -> None:
        """UCI with > 9 segments collapses extras into the last field."""
        uci = "a/b/c/d/e/f/g/h/proto1/extra1/extra2"

        result = parse_uci(uci)

        assert result["src_mac"] == "a"
        assert result["protocols"] == "proto1/extra1/extra2"

    @pytest.mark.unit
    def test_empty_uci(self) -> None:
        """Empty string produces dict with 9 empty fields."""
        result = parse_uci("")

        assert len(result) == 9
        assert all(v == "" for v in result.values())

    @pytest.mark.unit
    def test_return_type_is_dict(self) -> None:
        """parse_uci always returns a dict with exactly 9 keys."""
        result = parse_uci("a/b/c/d/e/f/g/h/i")

        expected_keys = {
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
        assert set(result.keys()) == expected_keys


class TestPrepareTimeseriesWithBoundsNan:
    """Tests for NaN handling in prepare_timeseries_with_bounds."""

    @pytest.mark.unit
    def test_nan_value_becomes_none(self) -> None:
        """NaN values in the metric column should become None."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00"]),
                "metric": [float("nan")],
            }
        )
        result = prepare_timeseries_with_bounds(df, [], "metric")

        assert result[0]["value"] is None

    @pytest.mark.unit
    def test_numpy_nan_value_becomes_none(self) -> None:
        """numpy.nan in the metric column should become None."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00"]),
                "metric": [np.nan],
            }
        )
        result = prepare_timeseries_with_bounds(df, [], "metric")

        assert result[0]["value"] is None

    @pytest.mark.unit
    def test_nan_bounds_become_none(self) -> None:
        """NaN in lb/ub columns should become None."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00"]),
                "metric": [50.0],
            }
        )
        bounds = [{"lb_metric": float("nan"), "ub_metric": float("nan")}]

        result = prepare_timeseries_with_bounds(df, bounds, "metric")

        assert result[0]["lower_bound"] is None
        assert result[0]["upper_bound"] is None

    @pytest.mark.unit
    def test_mixed_nan_and_valid(self) -> None:
        """Mix of NaN and valid values in same output."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00", "2026-01-01T00:01:00"]),
                "metric": [np.nan, 42.0],
            }
        )
        bounds = [{"lb_metric": 10.0, "ub_metric": 100.0}]

        result = prepare_timeseries_with_bounds(df, bounds, "metric")

        assert result[0]["value"] is None
        assert result[1]["value"] == 42.0
        assert result[0]["lower_bound"] == 10.0
        assert result[1]["upper_bound"] == 100.0

    @pytest.mark.unit
    def test_time_formatting(self) -> None:
        """Time values should be formatted as ISO strings."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-03-15T14:30:00"]),
                "metric": [42.0],
            }
        )
        result = prepare_timeseries_with_bounds(df, [], "metric")

        assert isinstance(result[0]["time"], str)
        assert "2026-03-15" in result[0]["time"]

    @pytest.mark.unit
    def test_violation_boundary_exact(self) -> None:
        """Values exactly at the boundary should not be violations."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00", "2026-01-01T00:01:00"]),
                "metric": [10.0, 100.0],
            }
        )
        bounds = [{"lb_metric": 10.0, "ub_metric": 100.0}]

        result = prepare_timeseries_with_bounds(df, bounds, "metric")

        assert result[0]["violation_low"] is False
        assert result[0]["violation_high"] is False
        assert result[1]["violation_low"] is False
        assert result[1]["violation_high"] is False

    @pytest.mark.unit
    def test_aggregated_extrema_violate_when_mean_is_in_bounds(self) -> None:
        """Bucket extrema remain visible even when bucket mean is normal."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00"]),
                "metric": [10.0],
                "metric_min": [2.0],
                "metric_max": [18.0],
            }
        )
        result = prepare_timeseries_with_bounds(df, [{"lb_metric": 5.0, "ub_metric": 15.0}], "metric")

        assert result[0]["violation_low"] is True
        assert result[0]["violation_high"] is True
