"""Tests for InfluxDB SQL helper functions."""

import pytest

from otalon_common.influx.sql_helpers import (
    NICE_BUCKETS,
    distinct_values,
    nice_bucket_seconds,
    sql_identifier,
    sql_quote,
    to_sql_interval_literal,
)


class TestNiceBuckets:
    """Tests for NICE_BUCKETS constant."""

    def test_is_sorted_ascending(self) -> None:
        for i in range(len(NICE_BUCKETS) - 1):
            assert NICE_BUCKETS[i] < NICE_BUCKETS[i + 1]

    def test_exact_values(self) -> None:
        assert NICE_BUCKETS == (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600)


class TestNiceBucketSeconds:
    """Tests for nice_bucket_seconds()."""

    def test_short_range(self) -> None:
        result = nice_bucket_seconds(300, max_points=500)
        assert result == 1

    def test_long_range(self) -> None:
        result = nice_bucket_seconds(86400, max_points=500)
        assert result >= 173

    def test_very_long_range_returns_largest(self) -> None:
        result = nice_bucket_seconds(1_000_000, max_points=1)
        assert result == 3600

    def test_exact_fit(self) -> None:
        result = nice_bucket_seconds(500, max_points=500)
        assert result == 1


class TestToSqlIntervalLiteral:
    """Tests for to_sql_interval_literal()."""

    def test_seconds(self) -> None:
        assert to_sql_interval_literal(5) == "5 seconds"

    def test_one_second(self) -> None:
        assert to_sql_interval_literal(1) == "1 second"

    def test_one_minute(self) -> None:
        assert to_sql_interval_literal(60) == "1 minute"

    def test_multiple_minutes(self) -> None:
        assert to_sql_interval_literal(300) == "5 minutes"

    def test_one_hour(self) -> None:
        assert to_sql_interval_literal(3600) == "1 hour"

    def test_multiple_hours(self) -> None:
        assert to_sql_interval_literal(7200) == "2 hours"


class TestSqlQuote:
    """Tests for sql_quote()."""

    def test_simple_string(self) -> None:
        assert sql_quote("hello") == "'hello'"

    def test_single_quote_escaped(self) -> None:
        assert sql_quote("O'Brien") == "'O''Brien'"

    def test_empty_string(self) -> None:
        assert sql_quote("") == "''"

    def test_injection_prevention(self) -> None:
        result = sql_quote("'; DROP TABLE --")
        assert result == "'''; DROP TABLE --'"


class TestSqlIdentifier:
    """Tests for sql_identifier()."""

    def test_simple_identifier(self) -> None:
        assert sql_identifier("uci") == '"uci"'

    def test_underscore_and_digits(self) -> None:
        assert sql_identifier("src_mac2") == '"src_mac2"'

    @pytest.mark.parametrize(
        "bad",
        [
            'x"; DROP TABLE--',
            'uci" , (SELECT 1) AS "x',
            "uci; DROP TABLE t",
            "2col",
            "col-name",
            "col name",
            "",
            "col\n",
            "täg",
            "*",
        ],
    )
    def test_rejects_invalid_identifier(self, bad: str) -> None:
        with pytest.raises(ValueError):
            sql_identifier(bad)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(TypeError):
            sql_identifier(5)  # type: ignore[arg-type]

    def test_rejects_overlong_identifier(self) -> None:
        with pytest.raises(ValueError):
            sql_identifier("a" * 256)


class TestDistinctValues:
    """Tests for distinct_values()."""

    def test_generates_expression(self) -> None:
        assert distinct_values("uci") == 'DISTINCT "uci"'

    def test_different_column(self) -> None:
        assert distinct_values("src_mac") == 'DISTINCT "src_mac"'

    def test_rejects_injection_identifier(self) -> None:
        with pytest.raises(ValueError):
            distinct_values('x"; DROP TABLE--')

    def test_rejects_quote_break_out(self) -> None:
        with pytest.raises(ValueError):
            distinct_values('uci" , "secret')

    def test_error_message_names_column(self) -> None:
        with pytest.raises(ValueError, match="invalid SQL identifier"):
            distinct_values("bad column")
