"""Unit tests for the time_policy domain module.

Covers timezone conversions between UTC and Europe/Berlin (CET/CEST),
including DST transition edge cases and roundtrip consistency.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
import pytest

from otalon_api.domain.time import time_policy

UTC = timezone.utc

CET_WINTER_LOCAL = "2026-01-15T14:30:00"
CET_WINTER_UTC = "2026-01-15T13:30:00Z"

CEST_SUMMER_LOCAL = "2026-07-15T14:30:00"
CEST_SUMMER_UTC = "2026-07-15T12:30:00Z"

DST_SPRING_FORWARD_DATE = "2026-03-29"


@pytest.fixture(autouse=True)
def _reset_timezone() -> None:
    """Reset timezone to Europe/Berlin before each test."""
    time_policy.configure_timezone("Europe/Berlin")


@pytest.mark.unit
class TestConfigureTimezone:
    """Tests for configure_timezone changing the active timezone."""

    def test_configure_timezone_affects_utc_conversion(self) -> None:
        """Switching to UTC+0 timezone should produce identical local and UTC strings."""
        time_policy.configure_timezone("UTC")
        result = time_policy.to_utc_z_string("2026-01-15T14:30:00")
        assert result == "2026-01-15T14:30:00Z"

    def test_configure_timezone_to_us_eastern(self) -> None:
        """US/Eastern (UTC-5 in winter) should shift naive local time +5h to UTC."""
        time_policy.configure_timezone("US/Eastern")
        result = time_policy.to_utc_z_string("2026-01-15T10:00:00")
        assert result == "2026-01-15T15:00:00Z"

    def test_configure_timezone_back_to_berlin(self) -> None:
        """Reconfiguring back to Europe/Berlin restores CET behavior."""
        time_policy.configure_timezone("US/Eastern")
        time_policy.configure_timezone("Europe/Berlin")
        result = time_policy.to_utc_z_string(CET_WINTER_LOCAL)
        assert result == CET_WINTER_UTC


@pytest.mark.unit
class TestToUtcZStringCET:
    """Tests for to_utc_z_string during CET (winter, UTC+1)."""

    def test_naive_local_cet(self) -> None:
        """Naive local 14:30 CET should produce 13:30Z."""
        result = time_policy.to_utc_z_string(CET_WINTER_LOCAL)
        assert result == CET_WINTER_UTC

    def test_utc_aware_timestamp(self) -> None:
        """UTC-aware datetime should pass through as-is to Z-string."""
        dt = datetime(2026, 1, 15, 13, 30, 0, tzinfo=UTC)
        result = time_policy.to_utc_z_string(dt)
        assert result == CET_WINTER_UTC

    def test_pandas_timestamp_utc(self) -> None:
        """UTC-aware pd.Timestamp should produce the correct Z-string."""
        ts = pd.Timestamp("2026-01-15T13:30:00", tz="UTC")
        result = time_policy.to_utc_z_string(ts)
        assert result == CET_WINTER_UTC

    def test_microseconds_stripped(self) -> None:
        """Microseconds should be truncated from the output."""
        result = time_policy.to_utc_z_string("2026-01-15T14:30:00.123456")
        assert result == CET_WINTER_UTC


@pytest.mark.unit
class TestToUtcZStringCEST:
    """Tests for to_utc_z_string during CEST (summer, UTC+2)."""

    def test_naive_local_cest(self) -> None:
        """Naive local 14:30 CEST should produce 12:30Z."""
        result = time_policy.to_utc_z_string(CEST_SUMMER_LOCAL)
        assert result == CEST_SUMMER_UTC

    def test_utc_aware_summer(self) -> None:
        """UTC-aware datetime in summer should produce correct Z-string."""
        dt = datetime(2026, 7, 15, 12, 30, 0, tzinfo=UTC)
        result = time_policy.to_utc_z_string(dt)
        assert result == CEST_SUMMER_UTC


@pytest.mark.unit
class TestToUtcZStringDST:
    """Tests for to_utc_z_string near the DST spring-forward boundary."""

    def test_before_spring_forward(self) -> None:
        """01:30 local on 2026-03-29 is still CET (UTC+1) -> 00:30Z."""
        result = time_policy.to_utc_z_string(f"{DST_SPRING_FORWARD_DATE}T01:30:00")
        assert result == f"{DST_SPRING_FORWARD_DATE}T00:30:00Z"

    def test_after_spring_forward(self) -> None:
        """03:30 local on 2026-03-29 is CEST (UTC+2) -> 01:30Z."""
        result = time_policy.to_utc_z_string(f"{DST_SPRING_FORWARD_DATE}T03:30:00")
        assert result == f"{DST_SPRING_FORWARD_DATE}T01:30:00Z"


@pytest.mark.unit
class TestToLocalOffsetString:
    """Tests for to_local_offset_string (API-072: output carries an offset)."""

    def test_utc_aware_cet_period(self) -> None:
        """UTC 13:30Z in January (CET) should produce local 14:30+01:00."""
        dt = datetime(2026, 1, 15, 13, 30, 0, tzinfo=UTC)
        result = time_policy.to_local_offset_string(dt)
        assert result == "2026-01-15T14:30:00+01:00"

    def test_utc_aware_cest_period(self) -> None:
        """UTC 12:30Z in July (CEST) should produce local 14:30+02:00."""
        dt = datetime(2026, 7, 15, 12, 30, 0, tzinfo=UTC)
        result = time_policy.to_local_offset_string(dt)
        assert result == "2026-07-15T14:30:00+02:00"

    def test_naive_timestamp_localized(self) -> None:
        """Naive timestamp is assumed local and localized with its offset."""
        result = time_policy.to_local_offset_string("2026-01-15T14:30:00")
        assert result == "2026-01-15T14:30:00+01:00"

    def test_output_carries_tz_offset(self) -> None:
        """Output must always carry an explicit +/- offset (API-072)."""
        dt = datetime(2026, 1, 15, 13, 30, 0, tzinfo=UTC)
        result = time_policy.to_local_offset_string(dt)
        assert result.endswith("+01:00")


@pytest.mark.unit
class TestUiToInfluxQueryRange:
    """Tests for ui_to_influx_query_range."""

    def test_cet_range(self) -> None:
        """UTC-aware CET range should produce correct Z-strings."""
        start = datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)
        stop = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)
        assert start_str == "2026-01-15T10:00:00Z"
        assert stop_str == "2026-01-15T12:00:00Z"

    def test_cest_range(self) -> None:
        """UTC-aware CEST range should produce correct Z-strings."""
        start = datetime(2026, 7, 15, 10, 0, 0, tzinfo=UTC)
        stop = datetime(2026, 7, 15, 14, 0, 0, tzinfo=UTC)
        start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)
        assert start_str == "2026-07-15T10:00:00Z"
        assert stop_str == "2026-07-15T14:00:00Z"

    def test_compat_z_suffix_has_no_effect(self) -> None:
        """compat_z_suffix=True and False must produce identical output."""
        start = datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)
        stop = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        result_true = time_policy.ui_to_influx_query_range(start, stop, compat_z_suffix=True)
        result_false = time_policy.ui_to_influx_query_range(start, stop, compat_z_suffix=False)
        assert result_true == result_false

    def test_naive_local_range_cet(self) -> None:
        """Naive local range in CET should be localized then converted to UTC."""
        start_str, stop_str = time_policy.ui_to_influx_query_range("2026-01-15T10:00:00", "2026-01-15T12:00:00")
        assert start_str == "2026-01-15T09:00:00Z"
        assert stop_str == "2026-01-15T11:00:00Z"


@pytest.mark.unit
class TestUiToPgQueryRange:
    """Tests for ui_to_pg_query_range."""

    def test_same_as_influx(self) -> None:
        """ui_to_pg_query_range should produce the same output as ui_to_influx_query_range."""
        start = datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)
        stop = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        pg_result = time_policy.ui_to_pg_query_range(start, stop)
        influx_result = time_policy.ui_to_influx_query_range(start, stop)
        assert pg_result == influx_result

    def test_naive_local_cest(self) -> None:
        """Naive local CEST range should produce correct UTC Z-strings."""
        start_str, stop_str = time_policy.ui_to_pg_query_range("2026-07-15T10:00:00", "2026-07-15T12:00:00")
        assert start_str == "2026-07-15T08:00:00Z"
        assert stop_str == "2026-07-15T10:00:00Z"


@pytest.mark.unit
class TestNormalizeTimeForUiDataFrame:
    """Tests for normalize_time_for_ui with DataFrame inputs."""

    def test_utc_time_column_cet(self) -> None:
        """UTC 'time' column in CET period should shift +1h and become naive."""
        utc_times = pd.to_datetime(["2026-01-15T13:00:00", "2026-01-15T14:00:00"], utc=True)
        df = pd.DataFrame({"time": utc_times, "value": [1, 2]})
        result = time_policy.normalize_time_for_ui(df)
        assert result["time"].dt.tz is None
        expected = pd.to_datetime(["2026-01-15T14:00:00", "2026-01-15T15:00:00"])
        pd.testing.assert_index_equal(
            pd.DatetimeIndex(result["time"]),
            pd.DatetimeIndex(expected),
            check_names=False,
        )

    def test_utc_time_column_cest(self) -> None:
        """UTC 'time' column in CEST period should shift +2h and become naive."""
        utc_times = pd.to_datetime(["2026-07-15T12:00:00", "2026-07-15T13:00:00"], utc=True)
        df = pd.DataFrame({"time": utc_times, "value": [1, 2]})
        result = time_policy.normalize_time_for_ui(df)
        assert result["time"].dt.tz is None
        expected = pd.to_datetime(["2026-07-15T14:00:00", "2026-07-15T15:00:00"])
        pd.testing.assert_index_equal(
            pd.DatetimeIndex(result["time"]),
            pd.DatetimeIndex(expected),
            check_names=False,
        )

    def test_datetime_index(self) -> None:
        """DataFrame with UTC DatetimeIndex should normalize the index to naive local."""
        idx = pd.DatetimeIndex(pd.to_datetime(["2026-01-15T13:00:00", "2026-01-15T14:00:00"], utc=True))
        df = pd.DataFrame({"value": [1, 2]}, index=idx)
        result = time_policy.normalize_time_for_ui(df)
        result_idx = pd.DatetimeIndex(result.index)
        assert result_idx.tz is None
        expected_idx = pd.DatetimeIndex(pd.to_datetime(["2026-01-15T14:00:00", "2026-01-15T15:00:00"]))
        pd.testing.assert_index_equal(result_idx, expected_idx)

    def test_sorted_by_time_column(self) -> None:
        """Result DataFrame should be sorted by the 'time' column."""
        utc_times = pd.to_datetime(["2026-01-15T15:00:00", "2026-01-15T13:00:00"], utc=True)
        df = pd.DataFrame({"time": utc_times, "value": [2, 1]})
        result = time_policy.normalize_time_for_ui(df)
        assert list(result["value"]) == [1, 2]


@pytest.mark.unit
class TestNormalizeTimeForUiSeries:
    """Tests for normalize_time_for_ui with Series inputs."""

    def test_utc_series_cet(self) -> None:
        """UTC-aware Series in CET should become naive local (+1h)."""
        s = pd.Series(pd.to_datetime(["2026-01-15T13:00:00", "2026-01-15T14:00:00"], utc=True))
        result = time_policy.normalize_time_for_ui(s)
        assert result.dt.tz is None
        expected = pd.to_datetime(["2026-01-15T14:00:00", "2026-01-15T15:00:00"])
        pd.testing.assert_index_equal(
            pd.DatetimeIndex(result.to_numpy()),
            pd.DatetimeIndex(expected),
        )

    def test_utc_series_cest(self) -> None:
        """UTC-aware Series in CEST should become naive local (+2h)."""
        s = pd.Series(pd.to_datetime(["2026-07-15T12:00:00", "2026-07-15T13:00:00"], utc=True))
        result = time_policy.normalize_time_for_ui(s)
        assert result.dt.tz is None
        expected = pd.to_datetime(["2026-07-15T14:00:00", "2026-07-15T15:00:00"])
        pd.testing.assert_index_equal(
            pd.DatetimeIndex(result.to_numpy()),
            pd.DatetimeIndex(expected),
        )


@pytest.mark.unit
class TestMakeAwareLocal:
    """Tests for make_aware_local."""

    def test_naive_timestamp_returned_as_naive_local(self) -> None:
        """Naive timestamp should be interpreted as local and returned as naive datetime."""
        result = time_policy.make_aware_local("2026-01-15T14:30:00")
        assert isinstance(result, datetime)
        assert result.tzinfo is None
        assert result == datetime(2026, 1, 15, 14, 30, 0)

    def test_utc_aware_converted_to_local_cet(self) -> None:
        """UTC-aware datetime should be converted to local naive (CET = UTC+1)."""
        dt = datetime(2026, 1, 15, 13, 30, 0, tzinfo=UTC)
        result = time_policy.make_aware_local(dt)
        assert result.tzinfo is None
        assert result == datetime(2026, 1, 15, 14, 30, 0)

    def test_utc_aware_converted_to_local_cest(self) -> None:
        """UTC-aware datetime should be converted to local naive (CEST = UTC+2)."""
        dt = datetime(2026, 7, 15, 12, 30, 0, tzinfo=UTC)
        result = time_policy.make_aware_local(dt)
        assert result.tzinfo is None
        assert result == datetime(2026, 7, 15, 14, 30, 0)

    def test_pandas_timestamp_input(self) -> None:
        """pd.Timestamp input should also be converted correctly."""
        ts = pd.Timestamp("2026-01-15T13:30:00", tz="UTC")
        result = time_policy.make_aware_local(ts)
        assert isinstance(result, datetime)
        assert result == datetime(2026, 1, 15, 14, 30, 0)


@pytest.mark.unit
class TestRoundtrip:
    """Roundtrip consistency tests: UTC -> local -> UTC."""

    def test_utc_to_local_and_back_cet(self) -> None:
        """UTC -> normalize_time_for_ui -> to_utc_z_string should return original UTC."""
        utc_str = "2026-01-15T13:30:00Z"
        utc_ts = pd.Timestamp(utc_str)
        s = pd.Series([utc_ts])
        local_s = time_policy.normalize_time_for_ui(s)
        local_iso = local_s.iloc[0].isoformat()
        back_to_utc = time_policy.to_utc_z_string(local_iso)
        assert back_to_utc == "2026-01-15T13:30:00Z"

    def test_utc_to_local_and_back_cest(self) -> None:
        """UTC -> normalize_time_for_ui -> to_utc_z_string should return original UTC (summer)."""
        utc_str = "2026-07-15T12:30:00Z"
        utc_ts = pd.Timestamp(utc_str)
        s = pd.Series([utc_ts])
        local_s = time_policy.normalize_time_for_ui(s)
        local_iso = local_s.iloc[0].isoformat()
        back_to_utc = time_policy.to_utc_z_string(local_iso)
        assert back_to_utc == "2026-07-15T12:30:00Z"

    def test_make_aware_then_to_utc(self) -> None:
        """make_aware_local then to_utc_z_string should roundtrip correctly."""
        original_utc = datetime(2026, 1, 15, 13, 30, 0, tzinfo=UTC)
        local_naive = time_policy.make_aware_local(original_utc)
        back_to_utc = time_policy.to_utc_z_string(local_naive)
        assert back_to_utc == "2026-01-15T13:30:00Z"
