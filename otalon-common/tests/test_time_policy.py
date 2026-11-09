"""Tests for timezone configuration and timestamp conversions."""

from datetime import datetime
from zoneinfo import ZoneInfo

import pandas as pd
from otalon_common.time.time_policy import (configure_timezone,
                                                 get_local_tz, to_local,
                                                 to_local_offset_string,
                                                 to_utc, to_utc_z_string)


class TestConfigureTimezone:
    """Tests for configure_timezone() and get_local_tz()."""

    def test_default_timezone(self) -> None:
        configure_timezone("Europe/Berlin")
        assert get_local_tz() == ZoneInfo("Europe/Berlin")

    def test_configure_new_timezone(self) -> None:
        configure_timezone("America/New_York")
        tz = get_local_tz()
        assert tz == ZoneInfo("America/New_York")
        configure_timezone("Europe/Berlin")


class TestToUtc:
    """Tests for to_utc()."""

    def test_aware_timestamp_converted(self) -> None:
        ts = pd.Timestamp("2026-04-03 14:00:00", tz="Europe/Berlin")
        result = to_utc(ts)
        assert result == pd.Timestamp("2026-04-03 12:00:00", tz="UTC")

    def test_naive_timestamp_assumed_utc(self) -> None:
        ts = pd.Timestamp("2026-04-03 12:00:00")
        result = to_utc(ts)
        assert result == pd.Timestamp("2026-04-03 12:00:00", tz="UTC")

    def test_datetime_object_converted(self) -> None:
        dt = datetime(2026, 4, 3, 14, 0, 0, tzinfo=ZoneInfo("Europe/Berlin"))
        result = to_utc(dt)
        assert result == pd.Timestamp("2026-04-03 12:00:00", tz="UTC")


class TestToUtcZString:
    """Tests for to_utc_z_string()."""

    def test_z_string_format(self) -> None:
        ts = pd.Timestamp("2026-04-03 14:00:00", tz="Europe/Berlin")
        result = to_utc_z_string(ts)
        assert result == "2026-04-03T12:00:00Z"

    def test_naive_timestamp(self) -> None:
        ts = pd.Timestamp("2026-04-03 12:00:00")
        result = to_utc_z_string(ts)
        assert result == "2026-04-03T12:00:00Z"


class TestToLocal:
    """Tests for to_local()."""

    def test_utc_to_berlin(self) -> None:
        configure_timezone("Europe/Berlin")
        ts = pd.Timestamp("2026-04-03 12:00:00", tz="UTC")
        result = to_local(ts)
        assert result.hour == 14
        assert str(result.tzinfo) == "Europe/Berlin"

    def test_utc_to_new_york(self) -> None:
        configure_timezone("America/New_York")
        ts = pd.Timestamp("2026-04-03 12:00:00", tz="UTC")
        result = to_local(ts)
        assert result.hour == 8
        configure_timezone("Europe/Berlin")


class TestToLocalOffsetString:
    """Tests for to_local_offset_string()."""

    def test_offset_string_format(self) -> None:
        configure_timezone("Europe/Berlin")
        ts = pd.Timestamp("2026-04-03 12:00:00", tz="UTC")
        result = to_local_offset_string(ts)
        assert result == "2026-04-03T14:00:00+02:00"

    def test_datetime_input(self) -> None:
        configure_timezone("Europe/Berlin")
        dt = datetime(2026, 4, 3, 12, 0, 0, tzinfo=ZoneInfo("UTC"))
        result = to_local_offset_string(dt)
        assert result == "2026-04-03T14:00:00+02:00"
