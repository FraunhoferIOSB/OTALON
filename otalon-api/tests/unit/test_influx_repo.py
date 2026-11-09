"""Unit tests for InfluxRepository (M-01, M-02, and F-13).

Tests query_timeseries() SQL generation, parameter handling,
list_ids_between() UCI listing with nonzero filtering, and
query_connection_sparklines() sparkline data retrieval.
"""

# mypy: disable-error-code="no-untyped-def"

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from otalon_api.repositories.influx_repo import InfluxRepository, is_broadcast_or_multicast_mac


@pytest.fixture()
def mock_influx_client():
    """Create an InfluxRepository with a mocked InfluxDBClient3.

    Returns:
        A tuple of (InfluxRepository, MagicMock) where the mock represents
        the underlying ``_client``.
    """
    with patch("otalon_api.repositories.influx_repo.InfluxDBClient3", autospec=True) as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        repo = InfluxRepository(
            host="localhost",
            port=8181,
            token="test-token",
            org="test-org",
            database="netcap",
        )
        yield repo, mock_client


def _make_query_result(df: pd.DataFrame) -> MagicMock:
    """Wrap a DataFrame in a mock query result with a ``to_pandas()`` method.

    Args:
        df: DataFrame to return from the mock.

    Returns:
        MagicMock with ``to_pandas`` returning *df*.
    """
    result = MagicMock()
    result.to_pandas.return_value = df
    return result


def _rows_between(stored: list[pd.Timestamp], query: str) -> MagicMock:
    """Answer an edge probe from an in-memory set of stored timestamps.

    Emulates the InfluxDB behaviour the probes rely on: a window bounded on
    both sides, ordered, returning at most one row.

    Args:
        stored: The timestamps the fake measurement contains.
        query: The SQL the repository issued.

    Returns:
        A mock query result holding the matching edge row, if any.
    """
    bounds = re.findall(r"'([0-9T:.\-]+Z)'", query)
    start, stop = pd.Timestamp(bounds[0]), pd.Timestamp(bounds[1])
    hits = sorted(ts for ts in stored if start <= ts <= stop)
    if not hits:
        return _make_query_result(pd.DataFrame({"time": []}))
    edge = hits[-1] if "DESC" in query else hits[0]
    return _make_query_result(pd.DataFrame({"time": [edge]}))


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mac", "expected"),
    [
        ("aa:bb:cc:dd:ee:ff", False),
        ("FF:FF:FF:FF:FF:FF", True),
        ("01:00:5e:00:00:16", True),
        ("33:33:00:00:00:01", True),
    ],
)
def test_is_broadcast_or_multicast_mac(mac: str, expected: bool) -> None:
    """MAC classifier follows broadcast and multicast-bit rules."""
    assert is_broadcast_or_multicast_mac(mac) is expected


@pytest.mark.unit
class TestQueryDataExtent:
    """Tests for bounded edge-probe data extent discovery."""

    def test_reports_full_span_when_data_spans_beyond_recent_window(self, mock_influx_client):
        """Regression (UI-079): historic data must not be cut to the recent window.

        The previous implementation searched widening windows and returned at
        the first one that yielded rows. Live capture always writes inside the
        1-day window, so it always reported a 24-hour extent even though years
        of data were stored, which made the UI claim "no data" for any older
        range it was in fact rendering.
        """
        repo, client = mock_influx_client
        stored = [
            pd.Timestamp("2024-02-08T10:00:00Z"),
            pd.Timestamp("2026-02-10T12:00:00Z"),
            pd.Timestamp("2026-07-29T08:45:00Z"),
        ]
        client.query.side_effect = lambda query, **_: _rows_between(stored, query)

        result = repo.query_data_extent("network_metrics", now=pd.Timestamp("2026-07-29T09:00:00Z"))

        assert result == (pd.Timestamp("2024-02-08T10:00:00Z"), pd.Timestamp("2026-07-29T08:45:00Z"))

    def test_finds_first_ts_behind_a_gap(self, mock_influx_client):
        """An isolated old capture must win over a nearer contiguous block."""
        repo, client = mock_influx_client
        stored = [
            pd.Timestamp("2017-07-14T02:40:00Z"),
            pd.Timestamp("2026-07-29T08:45:00Z"),
        ]
        client.query.side_effect = lambda query, **_: _rows_between(stored, query)

        result = repo.query_data_extent("network_metrics", now=pd.Timestamp("2026-07-29T09:00:00Z"))

        assert result == (pd.Timestamp("2017-07-14T02:40:00Z"), pd.Timestamp("2026-07-29T08:45:00Z"))

    def test_recent_only_data_reports_recent_extent(self, mock_influx_client):
        repo, client = mock_influx_client
        stored = [pd.Timestamp("2026-07-29T08:00:00Z"), pd.Timestamp("2026-07-29T08:30:00Z")]
        client.query.side_effect = lambda query, **_: _rows_between(stored, query)

        result = repo.query_data_extent("network_metrics", now=pd.Timestamp("2026-07-29T09:00:00Z"))

        assert result == (pd.Timestamp("2026-07-29T08:00:00Z"), pd.Timestamp("2026-07-29T08:30:00Z"))

    def test_probes_stay_bounded_and_never_aggregate(self, mock_influx_client):
        """Every probe must be a bounded LIMIT 1 read, never a min/max scan."""
        repo, client = mock_influx_client
        stored = [pd.Timestamp("2026-07-29T08:45:00Z")]
        client.query.side_effect = lambda query, **_: _rows_between(stored, query)

        repo.query_data_extent("network_metrics", now=pd.Timestamp("2026-07-29T09:00:00Z"))

        issued = [call.args[0] for call in client.query.call_args_list]
        assert issued, "expected at least one probe"
        for query in issued:
            assert "LIMIT 1" in query
            assert "min(" not in query and "max(" not in query
            assert query.count("time >=") == 1 and query.count("time <=") == 1

    def test_returns_none_when_measurement_is_empty(self, mock_influx_client):
        repo, client = mock_influx_client
        client.query.return_value = _make_query_result(pd.DataFrame({"time": []}))
        assert repo.query_data_extent("network_metrics", now=pd.Timestamp("2026-07-29T09:00:00Z")) is None

    def test_returns_none_on_query_failure(self, mock_influx_client):
        repo, client = mock_influx_client
        client.query.side_effect = RuntimeError("Influx unavailable")
        assert repo.query_data_extent("network_metrics") is None

    def test_caches_result_until_invalidated(self, mock_influx_client):
        repo, client = mock_influx_client
        stored = [pd.Timestamp("2026-07-29T08:45:00Z")]
        client.query.side_effect = lambda query, **_: _rows_between(stored, query)
        now = pd.Timestamp("2026-07-29T09:00:00Z")

        first = repo.query_data_extent("network_metrics", now=now)
        calls_after_first = client.query.call_count
        second = repo.query_data_extent("network_metrics", now=now)

        assert second == first
        assert client.query.call_count == calls_after_first

        repo.invalidate_data_extent_cache("network_metrics")
        repo.query_data_extent("network_metrics", now=now)
        assert client.query.call_count > calls_after_first


@pytest.mark.unit
class TestM01QueryTimeseries:
    """M-01: Tests for InfluxRepository.query_timeseries()."""

    def test_raw_query_no_aggregation(self, mock_influx_client):
        """M-01: Raw query returns DataFrame with time as column (not index)."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "time": pd.to_datetime(["2025-01-01T00:00:00Z", "2025-01-01T00:01:00Z"]),
                "uci": ["a/b/c/d/e/f/g/h/TCP", "a/b/c/d/e/f/g/h/TCP"],
                "packet_count": [10, 20],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert "time" in result.columns
        assert "time" != result.index.name
        assert len(result) == 2

    def test_aggregate_mean_uses_date_bin(self, mock_influx_client):
        """M-01: Aggregate=mean generates SQL with DATE_BIN."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "agg_time": pd.to_datetime(["2025-01-01T00:00:00Z"]),
                "packet_count": [15.0],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            aggregate="mean",
            sample_max_points=100,
        )

        sql = client.query.call_args[0][0]
        assert "date_bin(" in sql.lower()
        assert 'mean("packet_count")' in sql

    def test_preserve_extrema_adds_min_max_columns(self, mock_influx_client):
        """M-01: preserve_extrema=True selects min/max columns per field."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "agg_time": pd.to_datetime(["2025-01-01T00:00:00Z"]),
                "packet_count": [15.0],
                "packet_count_min": [5.0],
                "packet_count_max": [25.0],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            aggregate="mean",
            sample_max_points=100,
            preserve_extrema=True,
        )

        sql = client.query.call_args[0][0]
        assert 'min("packet_count") AS "packet_count_min"' in sql
        assert 'max("packet_count") AS "packet_count_max"' in sql

    def test_bucket_seconds_in_attrs(self, mock_influx_client):
        """M-01: bucket_seconds is stored in df.attrs['bucket_seconds']."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "agg_time": pd.to_datetime(["2025-01-01T00:00:00Z"]),
                "packet_count": [15.0],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            aggregate="mean",
            sample_max_points=100,
        )

        assert "bucket_seconds" in result.attrs
        assert isinstance(result.attrs["bucket_seconds"], int)
        assert result.attrs["bucket_seconds"] > 0

    def test_empty_result_returns_empty_df_with_columns(self, mock_influx_client):
        """M-01: Empty query returns DataFrame with correct columns but 0 rows."""
        repo, client = mock_influx_client
        client.query.side_effect = Exception("no data")

        result = repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count", "total_volume"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert len(result) == 0
        assert "time" in result.columns
        assert "packet_count" in result.columns
        assert "total_volume" in result.columns

    def test_sample_max_points_calculates_every_seconds(self, mock_influx_client):
        """M-01: sample_max_points controls DATE_BIN interval calculation."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "agg_time": pd.to_datetime(["2025-01-01T00:00:00Z"]),
                "packet_count": [10.0],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            aggregate="mean",
            sample_max_points=60,
        )

        sql = client.query.call_args[0][0]
        assert "INTERVAL" in sql
        assert "date_bin" in sql.lower()

    def test_time_column_is_not_index(self, mock_influx_client):
        """M-01: Returned DataFrame has 'time' as a regular column, not as index."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "time": pd.to_datetime(["2025-01-01T00:00:00Z"]),
                "uci": ["a/b/c/d/e/f/g/h/TCP"],
                "packet_count": [10],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert "time" in result.columns
        assert not isinstance(result.index, pd.DatetimeIndex)

    def test_limit_parameter_appended_to_sql(self, mock_influx_client):
        """M-01: limit parameter adds LIMIT clause to SQL query."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "time": pd.to_datetime(["2025-01-01T00:00:00Z"]),
                "uci": ["a/b/c/d/e/f/g/h/TCP"],
                "packet_count": [10],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            limit=42,
        )

        sql = client.query.call_args[0][0]
        assert "LIMIT 42" in sql

    def test_no_aggregation_bucket_seconds_is_none(self, mock_influx_client):
        """M-01: Without aggregation, bucket_seconds in attrs is None."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "time": pd.to_datetime(["2025-01-01T00:00:00Z"]),
                "uci": ["a/b/c/d/e/f/g/h/TCP"],
                "packet_count": [10],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result.attrs["bucket_seconds"] is None

    def test_agg_time_renamed_to_time(self, mock_influx_client):
        """M-01: Aggregated query renames 'agg_time' column to 'time'."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "agg_time": pd.to_datetime(["2025-01-01T00:00:00Z", "2025-01-01T00:01:00Z"]),
                "packet_count": [10.0, 20.0],
                "uci": ["a/b/c/d/e/f/g/h/TCP", "a/b/c/d/e/f/g/h/TCP"],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            aggregate="mean",
            sample_max_points=100,
        )

        assert "time" in result.columns
        assert "agg_time" not in result.columns

    def test_tag_filter_in_where_clause(self, mock_influx_client):
        """M-01: Tag filters appear in the WHERE clause."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "time": pd.to_datetime(["2025-01-01T00:00:00Z"]),
                "packet_count": [10],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            tags={"uci": "a/b/c/d/e/f/g/h/TCP"},
        )

        sql = client.query.call_args[0][0]
        assert '"uci" = ' in sql
        assert "a/b/c/d/e/f/g/h/TCP" in sql


@pytest.mark.unit
class TestM02ListIdsBetween:
    """M-02: Tests for InfluxRepository.list_ids_between()."""

    def test_returns_sorted_list(self, mock_influx_client):
        """M-02: UCI list is sorted alphabetically."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "uci": [
                    "cc:dd:ee:00:00:01/ff:00:11:22:33:44///////Ethernet:ARP",
                    "00:01:05:00:00:01/01:80:c2:00:00:0e///////Ethernet:LLDP",
                    "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66///////Ethernet:IP",
                ]
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.list_ids_between(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == sorted(result)
        assert len(result) == 3

    def test_nonzero_filter_applied(self, mock_influx_client):
        """M-02: nonzero=True generates GROUP BY and sum expressions."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "uci": [
                    "00:01:05:00:00:01/01:80:c2:00:00:0e///////Ethernet:LLDP",
                    "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66///////Ethernet:IP",
                ],
                "packet_count_sum": [100.0, 0.0],
                "total_volume_sum": [5000.0, 0.0],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.list_ids_between(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            nonzero=True,
            fields=["packet_count", "total_volume"],
        )

        sql = client.query.call_args[0][0]
        assert "sum(" in sql.lower()
        assert "GROUP BY" in sql
        assert len(result) == 1
        assert result[0] == "00:01:05:00:00:01/01:80:c2:00:00:0e///////Ethernet:LLDP"

    def test_empty_result_returns_empty_list(self, mock_influx_client):
        """M-02: Empty time range returns []."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame()
        client.query.return_value = _make_query_result(df_result)

        result = repo.list_ids_between(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T00:00:01Z",
        )

        assert result == []

    def test_fields_parameter_used_in_nonzero_filter(self, mock_influx_client):
        """M-02: Custom fields parameter affects nonzero filter clause."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "uci": ["aa:bb:cc:dd:ee:ff/11:22:33:44:55:66///////Ethernet:IP"],
                "mean_packet_size_sum": [42.0],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        repo.list_ids_between(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            nonzero=True,
            fields=["mean_packet_size"],
        )

        sql = client.query.call_args[0][0]
        assert 'sum("mean_packet_size")' in sql

    def test_nonzero_false_uses_distinct_query(self, mock_influx_client):
        """M-02: nonzero=False uses SELECT DISTINCT instead of GROUP BY."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame({"uci": ["aa:bb:cc:dd:ee:ff/11:22:33:44:55:66///////Ethernet:IP"]})
        client.query.return_value = _make_query_result(df_result)

        repo.list_ids_between(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            nonzero=False,
        )

        sql = client.query.call_args[0][0]
        assert "DISTINCT" in sql
        assert "GROUP BY" not in sql

    def test_exception_returns_empty_list(self, mock_influx_client):
        """M-02: Query exception returns empty list instead of raising."""
        repo, client = mock_influx_client
        client.query.side_effect = Exception("connection refused")

        result = repo.list_ids_between(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == []


@pytest.mark.unit
class TestQueryCollapsedPortCounts:
    """Tests for InfluxRepository.query_collapsed_port_counts()."""

    def test_returns_dict_of_counts(self, mock_influx_client):
        """query_collapsed_port_counts returns a dict mapping UCI to count."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "uci": [
                    "a/b/c/d/e/f/*/*/TCP",
                    "a/b/c/d/e/f/*/80/TCP",
                ],
                "collapsed_port_count": [5, 3],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_collapsed_port_counts(
            measurement="network_metrics",
            id_tag="uci",
            ids=["a/b/c/d/e/f/*/*/TCP", "a/b/c/d/e/f/*/80/TCP"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == {"a/b/c/d/e/f/*/*/TCP": 5, "a/b/c/d/e/f/*/80/TCP": 3}

    def test_empty_ids_returns_empty_dict(self, mock_influx_client):
        """query_collapsed_port_counts with empty ids returns {} without querying."""
        repo, client = mock_influx_client

        result = repo.query_collapsed_port_counts(
            measurement="network_metrics",
            id_tag="uci",
            ids=[],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == {}
        client.query.assert_not_called()

    def test_null_values_excluded(self, mock_influx_client):
        """UCIs with NULL collapsed_port_count are omitted from the result."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "uci": ["a/b/c/d/e/f/*/*/TCP", "a/b/c/d/e/f/80/443/TCP"],
                "collapsed_port_count": [5, None],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_collapsed_port_counts(
            measurement="network_metrics",
            id_tag="uci",
            ids=["a/b/c/d/e/f/*/*/TCP", "a/b/c/d/e/f/80/443/TCP"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == {"a/b/c/d/e/f/*/*/TCP": 5}

    def test_exception_returns_empty_dict(self, mock_influx_client):
        """query_collapsed_port_counts returns {} on exception."""
        repo, client = mock_influx_client
        client.query.side_effect = Exception("connection refused")

        result = repo.query_collapsed_port_counts(
            measurement="network_metrics",
            id_tag="uci",
            ids=["a/b/c/d/e/f/*/*/TCP"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == {}


@pytest.mark.unit
class TestQueryTopConnections:
    """Tests for InfluxRepository.query_top_connections()."""

    def test_returns_list_of_dicts(self, mock_influx_client):
        """query_top_connections returns list of dicts with uci, total_packets, total_bytes."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "uci": ["a/b/c/d/e/f/g/h/TCP", "x/y/z/d/e/f/g/h/UDP"],
                "total_packets": [100, 50],
                "total_bytes": [5000, 2000],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_top_connections(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert len(result) == 2
        assert result[0]["uci"] == "a/b/c/d/e/f/g/h/TCP"
        assert result[0]["total_packets"] == 100
        assert result[0]["total_bytes"] == 5000

    def test_sql_contains_sum_and_group_by(self, mock_influx_client):
        """query_top_connections generates SQL with SUM, GROUP BY, ORDER BY, LIMIT."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame({"uci": [], "total_packets": [], "total_bytes": []})
        client.query.return_value = _make_query_result(df_result)

        repo.query_top_connections(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            limit=3,
            metric="byte_count",
        )

        sql = client.query.call_args[0][0]
        assert "SUM" in sql
        assert "GROUP BY" in sql
        assert "ORDER BY" in sql
        assert "total_bytes" in sql
        assert "LIMIT 3" in sql
        assert "total_volume" in sql
        assert "byte_count" not in sql

    def test_empty_result_returns_empty_list(self, mock_influx_client):
        """query_top_connections returns empty list when no data."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame()
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_top_connections(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == []

    def test_exception_returns_empty_list(self, mock_influx_client):
        """query_top_connections returns empty list on exception."""
        repo, client = mock_influx_client
        client.query.side_effect = Exception("connection refused")

        result = repo.query_top_connections(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == []

    def test_default_metric_is_packet_count(self, mock_influx_client):
        """Default metric orders by total_packets."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame({"uci": [], "total_packets": [], "total_bytes": []})
        client.query.return_value = _make_query_result(df_result)

        repo.query_top_connections(
            measurement="network_metrics",
            id_tag="uci",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        sql = client.query.call_args[0][0]
        assert "total_packets" in sql


@pytest.mark.unit
class TestQueryConnectionSparklines:
    """F-13: Tests for InfluxRepository.query_connection_sparklines()."""

    def test_returns_dict_with_sparkline_data(self, mock_influx_client):
        """query_connection_sparklines returns per-UCI sparkline lists."""
        repo, client = mock_influx_client
        buckets = pd.to_datetime(
            [
                "2025-01-01T00:00:00Z",
                "2025-01-01T00:05:00Z",
                "2025-01-01T00:10:00Z",
            ]
        )
        df_result = pd.DataFrame(
            {
                "bucket": list(buckets) * 2,
                "uci": (["a/b/c/d/e/f/g/h/TCP"] * 3 + ["x/y/z/d/e/f/g/h/UDP"] * 3),
                "total_bytes": [100, 200, 300, 10, 20, 30],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_connection_sparklines(
            ucis=["a/b/c/d/e/f/g/h/TCP", "x/y/z/d/e/f/g/h/UDP"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result["a/b/c/d/e/f/g/h/TCP"] == [100, 200, 300]
        assert result["x/y/z/d/e/f/g/h/UDP"] == [10, 20, 30]

    def test_sql_contains_date_bin_and_in_clause(self, mock_influx_client):
        """query_connection_sparklines generates SQL with DATE_BIN, SUM, IN clause."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame()
        client.query.return_value = _make_query_result(df_result)

        repo.query_connection_sparklines(
            ucis=["a/b/TCP", "x/y/UDP"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        sql = client.query.call_args[0][0]
        assert "date_bin(" in sql.lower()
        assert "SUM" in sql
        assert "GROUP BY" in sql
        assert "'a/b/TCP'" in sql
        assert "'x/y/UDP'" in sql

    def test_empty_ucis_returns_empty_dict(self, mock_influx_client):
        """query_connection_sparklines with empty UCIs returns {} without querying."""
        repo, client = mock_influx_client

        result = repo.query_connection_sparklines(
            ucis=[],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == {}
        client.query.assert_not_called()

    def test_empty_result_returns_empty_dict(self, mock_influx_client):
        """query_connection_sparklines returns {} when InfluxDB returns no rows."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame()
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_connection_sparklines(
            ucis=["a/b/TCP"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == {}

    def test_exception_returns_empty_dict(self, mock_influx_client):
        """query_connection_sparklines returns {} on exception."""
        repo, client = mock_influx_client
        client.query.side_effect = Exception("connection refused")

        result = repo.query_connection_sparklines(
            ucis=["a/b/TCP"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result == {}

    def test_missing_uci_omitted_from_result(self, mock_influx_client):
        """UCIs with no data in the response are omitted from the dict."""
        repo, client = mock_influx_client
        buckets = pd.to_datetime(["2025-01-01T00:00:00Z", "2025-01-01T00:05:00Z"])
        df_result = pd.DataFrame(
            {
                "bucket": list(buckets),
                "uci": ["a/b/TCP", "a/b/TCP"],
                "total_bytes": [100, 200],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_connection_sparklines(
            ucis=["a/b/TCP", "missing/UCI"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert "a/b/TCP" in result
        assert "missing/UCI" not in result

    def test_zero_fill_for_missing_buckets(self, mock_influx_client):
        """Missing buckets for a UCI are filled with 0."""
        repo, client = mock_influx_client
        buckets = pd.to_datetime(
            [
                "2025-01-01T00:00:00Z",
                "2025-01-01T00:05:00Z",
                "2025-01-01T00:10:00Z",
            ]
        )
        df_result = pd.DataFrame(
            {
                "bucket": [buckets[0], buckets[1], buckets[2], buckets[0], buckets[2]],
                "uci": ["a/b/TCP", "a/b/TCP", "a/b/TCP", "x/y/UDP", "x/y/UDP"],
                "total_bytes": [100, 200, 300, 10, 30],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        result = repo.query_connection_sparklines(
            ucis=["a/b/TCP", "x/y/UDP"],
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert result["a/b/TCP"] == [100, 200, 300]
        assert result["x/y/UDP"] == [10, 0, 30]


@pytest.mark.unit
class TestPivotSparklineDataframe:
    """F-13: Tests for InfluxRepository._pivot_sparkline_dataframe()."""

    def test_pivot_basic(self):
        """Pivot produces correct per-UCI lists from a multi-UCI DataFrame."""
        buckets = pd.to_datetime(["2025-01-01T00:00:00Z", "2025-01-01T00:05:00Z"])
        df = pd.DataFrame(
            {
                "bucket": list(buckets) * 2,
                "uci": ["a", "a", "b", "b"],
                "total_bytes": [10, 20, 30, 40],
            }
        )

        result = InfluxRepository._pivot_sparkline_dataframe(df, ["a", "b"])

        assert result["a"] == [10, 20]
        assert result["b"] == [30, 40]

    def test_pivot_empty_dataframe(self):
        """Pivot returns empty dict for empty DataFrame."""
        df = pd.DataFrame()

        result = InfluxRepository._pivot_sparkline_dataframe(df, ["a"])

        assert result == {}

    def test_pivot_zero_fill(self):
        """Pivot fills missing buckets with 0."""
        buckets = pd.to_datetime(
            [
                "2025-01-01T00:00:00Z",
                "2025-01-01T00:05:00Z",
                "2025-01-01T00:10:00Z",
            ]
        )
        df = pd.DataFrame(
            {
                "bucket": [buckets[0], buckets[2], buckets[0], buckets[1], buckets[2]],
                "uci": ["a", "a", "b", "b", "b"],
                "total_bytes": [100, 300, 10, 20, 30],
            }
        )

        result = InfluxRepository._pivot_sparkline_dataframe(df, ["a", "b"])

        assert result["a"] == [100, 0, 300]
        assert result["b"] == [10, 20, 30]

    def test_pivot_uci_not_in_data_omitted(self):
        """UCIs in the ucis list but not in the DataFrame are omitted."""
        buckets = pd.to_datetime(["2025-01-01T00:00:00Z"])
        df = pd.DataFrame(
            {
                "bucket": list(buckets),
                "uci": ["a"],
                "total_bytes": [100],
            }
        )

        result = InfluxRepository._pivot_sparkline_dataframe(df, ["a", "missing"])

        assert "a" in result
        assert "missing" not in result


@pytest.mark.unit
def test_query_record_count_since_accepts_influx_cnt_alias(mock_influx_client) -> None:
    """InfluxDB v3 COUNT(*) returns the explicit ``cnt`` alias used by the query."""
    repo, client = mock_influx_client
    client.query.return_value = _make_query_result(pd.DataFrame({"cnt": [20261]}))

    count = repo.query_record_count_since("network_metrics", pd.Timestamp("2026-07-21T03:00:00Z"))

    assert count == 20261
