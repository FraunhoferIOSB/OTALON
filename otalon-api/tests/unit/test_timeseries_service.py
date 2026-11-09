"""Unit tests for TimeseriesService (M-04 and M-05).

Tests _decimate_dataframe() downsampling logic and _round_time_columns()
timestamp rounding behavior.
"""

from __future__ import annotations

from datetime import datetime

import numpy as np
import pandas as pd
import pytest

from otalon_api.services.timeseries_service import TimeseriesService


@pytest.mark.unit
class TestM04DecimateDataframe:
    """M-04: Tests for TimeseriesService._decimate_dataframe()."""

    def test_fewer_rows_than_target_returns_unchanged(self):
        """M-04: DataFrame with fewer rows than target_points is returned as-is."""
        df = pd.DataFrame(
            {
                "time": pd.date_range("2025-01-01", periods=5, freq="s"),
                "value": range(5),
            }
        )

        result = TimeseriesService._decimate_dataframe(df, target_points=10)

        assert len(result) == 5
        pd.testing.assert_frame_equal(result, df)

    def test_exact_target_points_returns_unchanged(self):
        """M-04: DataFrame with exactly target_points rows is returned as-is."""
        df = pd.DataFrame(
            {
                "time": pd.date_range("2025-01-01", periods=10, freq="s"),
                "value": range(10),
            }
        )

        result = TimeseriesService._decimate_dataframe(df, target_points=10)

        assert len(result) == 10
        pd.testing.assert_frame_equal(result, df)

    def test_more_rows_downsampled_to_target(self):
        """M-04: DataFrame with more rows is downsampled to exactly target_points."""
        df = pd.DataFrame(
            {
                "time": pd.date_range("2025-01-01", periods=100, freq="s"),
                "value": range(100),
            }
        )

        result = TimeseriesService._decimate_dataframe(df, target_points=20)

        assert len(result) == 20

    def test_empty_dataframe_returns_empty(self):
        """M-04: Empty DataFrame is handled gracefully."""
        df = pd.DataFrame(columns=["time", "value"])

        result = TimeseriesService._decimate_dataframe(df, target_points=10)

        assert len(result) == 0

    def test_linspace_indices_are_evenly_distributed(self):
        """M-04: Selected indices are evenly distributed across the range."""
        df = pd.DataFrame({"idx": range(100)})

        result = TimeseriesService._decimate_dataframe(df, target_points=5)

        expected_indices = np.linspace(0, 99, 5).astype(int)
        expected_values = [df.iloc[i]["idx"] for i in expected_indices]
        assert list(result["idx"]) == expected_values

    def test_first_and_last_row_preserved(self):
        """M-04: First and last row are always in the decimated result."""
        df = pd.DataFrame({"value": range(50)})

        result = TimeseriesService._decimate_dataframe(df, target_points=5)

        assert result.iloc[0]["value"] == 0
        assert result.iloc[-1]["value"] == 49

    def test_single_row_dataframe(self):
        """M-04: Single-row DataFrame returns single row."""
        df = pd.DataFrame({"time": [pd.Timestamp("2025-01-01")], "value": [42]})

        result = TimeseriesService._decimate_dataframe(df, target_points=5)

        assert len(result) == 1
        assert result.iloc[0]["value"] == 42

    def test_none_target_returns_unchanged(self):
        """M-04: target_points=None disables decimation."""
        df = pd.DataFrame({"value": range(100)})

        result = TimeseriesService._decimate_dataframe(df, target_points=None)

        assert len(result) == 100

    def test_zero_target_returns_unchanged(self):
        """M-04: target_points=0 disables decimation."""
        df = pd.DataFrame({"value": range(50)})

        result = TimeseriesService._decimate_dataframe(df, target_points=0)

        assert len(result) == 50

    def test_negative_target_returns_unchanged(self):
        """M-04: Negative target_points disables decimation."""
        df = pd.DataFrame({"value": range(50)})

        result = TimeseriesService._decimate_dataframe(df, target_points=-5)

        assert len(result) == 50

    def test_result_has_reset_index(self):
        """M-04: Decimated result has a reset integer index starting at 0."""
        df = pd.DataFrame({"value": range(20)})

        result = TimeseriesService._decimate_dataframe(df, target_points=5)

        assert list(result.index) == list(range(5))


@pytest.mark.unit
class TestM05RoundTimeColumns:
    """M-05: Tests for TimeseriesService._round_time_columns()."""

    def test_subsecond_timestamps_rounded(self):
        """M-05: Timestamps with milliseconds are rounded to seconds."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(
                    [
                        "2025-01-01T12:00:00.499Z",
                        "2025-01-01T12:00:00.500Z",
                        "2025-01-01T12:00:00.999Z",
                    ]
                ),
                "value": [1, 2, 3],
            }
        )

        result = TimeseriesService._round_time_columns(df)

        assert result["time"].iloc[0] == pd.Timestamp("2025-01-01T12:00:00Z")
        assert result["time"].iloc[1] == pd.Timestamp("2025-01-01T12:00:00Z")
        assert result["time"].iloc[2] == pd.Timestamp("2025-01-01T12:00:01Z")

    def test_integer_columns_unchanged(self):
        """M-05: Non-datetime columns are not modified."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2025-01-01T12:00:00.500Z"]),
                "count": [42],
                "name": ["test"],
            }
        )

        result = TimeseriesService._round_time_columns(df)

        assert result["count"].iloc[0] == 42
        assert result["name"].iloc[0] == "test"

    def test_multiple_datetime_columns(self):
        """M-05: All datetime columns are rounded, not just 'time'."""
        df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2025-01-01T12:00:00.600Z"]),
                "created_at": pd.to_datetime(["2025-01-01T13:30:00.700Z"]),
                "value": [10],
            }
        )

        result = TimeseriesService._round_time_columns(df)

        assert result["time"].iloc[0] == pd.Timestamp("2025-01-01T12:00:01Z")
        assert result["created_at"].iloc[0] == pd.Timestamp("2025-01-01T13:30:01Z")

    def test_empty_dataframe(self):
        """M-05: Empty DataFrame with datetime columns handles gracefully."""
        df = pd.DataFrame(
            {
                "time": pd.Series(dtype="datetime64[ns]"),
                "value": pd.Series(dtype="float64"),
            }
        )

        result = TimeseriesService._round_time_columns(df)

        assert len(result) == 0
        assert "time" in result.columns

    def test_already_rounded_unchanged(self):
        """M-05: Already second-precision timestamps remain unchanged."""
        ts = pd.to_datetime(["2025-01-01T12:00:00Z", "2025-01-01T12:00:01Z"])
        df = pd.DataFrame({"time": ts, "value": [1, 2]})

        result = TimeseriesService._round_time_columns(df)

        pd.testing.assert_series_equal(result["time"], df["time"])

    def test_datetime_index_rounded(self):
        """M-05: DatetimeIndex is also rounded to seconds."""
        idx = pd.to_datetime(["2025-01-01T12:00:00.600Z", "2025-01-01T12:00:01.400Z"])
        df = pd.DataFrame({"value": [1, 2]}, index=idx)

        result = TimeseriesService._round_time_columns(df)

        assert result.index[0] == pd.Timestamp("2025-01-01T12:00:01Z")
        assert result.index[1] == pd.Timestamp("2025-01-01T12:00:01Z")

    def test_non_dataframe_returns_as_is(self):
        """M-05: Non-DataFrame input is returned unchanged."""
        result = TimeseriesService._round_time_columns(None)

        assert result is None


class _StubInfluxRepo:
    """Minimal stub returning a fixed UCI list for ``list_ids_between``."""

    def __init__(self, ids: list[str]) -> None:
        self._ids = ids
        self.calls: list[dict[str, object]] = []

    def list_ids_between(self, **kwargs: object) -> list[str]:
        self.calls.append(kwargs)
        return self._ids


class _StubSettings:
    """Minimal settings shim exposing the netcap measurement/tag fields."""

    netcap_measurement = "network_metrics"
    netcap_id_tag = "uci"


@pytest.mark.unit
class TestFindActiveSiblings:
    """UI-017b Wave D1: base-key sibling lookup for the empty-metrics hint."""

    _BASE = "aa:bb/cc:dd/100/6/192.168.0.4/192.168.0.41"
    _PROTO = "PROFINET_DCE_RPC"
    _START = datetime(2026, 5, 5, 0, 0, 0)
    _STOP = datetime(2026, 5, 12, 0, 0, 0)

    def _make_service(self, ids: list[str]) -> tuple[TimeseriesService, _StubInfluxRepo]:
        repo = _StubInfluxRepo(ids)
        service = TimeseriesService(repo, _StubSettings())  # type: ignore[arg-type]
        return service, repo

    def test_returns_sibling_with_different_dst_port(self):
        """A same-base-key UCI on a different dst port is returned as a sibling."""
        selected = f"{self._BASE}/50000/41/{self._PROTO}"
        sibling = f"{self._BASE}/50000/53092/{self._PROTO}"
        service, repo = self._make_service([selected, sibling])

        result = service.find_active_siblings(selected, self._START, self._STOP)

        assert len(result) == 1
        assert result[0]["uci"] == sibling
        assert result[0]["dst_port"] == "53092"
        assert repo.calls[0]["nonzero"] is True

    def test_excludes_self_and_other_base_keys(self):
        """The queried UCI and unrelated base keys are not returned."""
        selected = f"{self._BASE}/50000/41/{self._PROTO}"
        other_base = f"aa:bb/cc:dd/100/6/10.0.0.1/10.0.0.2/50000/99/{self._PROTO}"
        service, _ = self._make_service([selected, other_base])

        result = service.find_active_siblings(selected, self._START, self._STOP)

        assert result == []

    def test_no_siblings_returns_empty(self):
        """When only the selected UCI has data, no siblings are returned."""
        selected = f"{self._BASE}/50000/41/{self._PROTO}"
        service, _ = self._make_service([selected])

        result = service.find_active_siblings(selected, self._START, self._STOP)

        assert result == []
