"""Isolated raw timeseries serializers preserve fractional identity and sanitization."""

import pandas as pd
import pytest

from otalon_api.api.v1.timeseries import _df_to_records as network_records
from otalon_api.api.v1.timeseries_mac_proto import _df_to_records as source_records


@pytest.mark.unit
@pytest.mark.parametrize("serialize", [network_records, source_records])
@pytest.mark.parametrize("zone", [None, "UTC"])
def test_exact_iso_times_and_duplicate_rows_survive(serialize, zone):
    times = pd.DatetimeIndex(["2025-02-03T04:05:06.123", "2025-02-03T04:05:06.187", "2025-02-03T04:05:06.187"], tz=zone)
    df = pd.DataFrame({"time": times, "value": [2, 3, 5]})
    before = df.copy(deep=True)
    rows = serialize(df)
    assert [row["time"] for row in rows] == [t.isoformat() for t in times]
    assert [row["value"] for row in rows] == [2, 3, 5]
    pd.testing.assert_frame_equal(df, before)


@pytest.mark.unit
@pytest.mark.parametrize("serialize", [network_records, source_records])
def test_invalid_times_and_nonfinite_metrics_remain_json_safe(serialize):
    df = pd.DataFrame({"time": ["invalid", None], "value": [float("nan"), float("inf")]})
    assert serialize(df) == [{"time": None, "value": None}, {"time": None, "value": None}]
