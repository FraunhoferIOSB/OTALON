"""Unit tests for persisted frequency-history aggregation."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from otalon_api.repositories.postgres_repo import PostgresRepository


@pytest.mark.unit
def test_count_recent_frequency_anomalies_batches_and_filters_frequency_rows() -> None:
    """Frequency history count uses one grouped query with the expected filter."""
    repo = object.__new__(PostgresRepository)
    since = datetime(2026, 8, 1, tzinfo=timezone.utc)

    with patch.object(
        repo, "_execute_query", return_value=[{"series_id": "series-a", "frequency_count": 3}]
    ) as execute:
        result = repo.count_recent_frequency_anomalies("conn", ["series-a", "series-b"], since)

    assert result == {"series-a": 3}
    sql, params = execute.call_args.args
    assert "anomaly_type = 'FrequencyAnomaly'" in sql
    assert "start_ts >= %(since)s" in sql
    assert params == {"module": "conn", "since": since, "series_ids": ["series-a", "series-b"]}


@pytest.mark.unit
def test_count_recent_frequency_anomalies_skips_empty_series_list() -> None:
    """Empty fleet input avoids an unnecessary database round-trip."""
    repo = object.__new__(PostgresRepository)

    with patch.object(repo, "_execute_query") as execute:
        assert repo.count_recent_frequency_anomalies("conn", [], datetime.now(timezone.utc)) == {}
    execute.assert_not_called()


@pytest.mark.unit
def test_recent_frequency_events_are_newest_first_and_bounded() -> None:
    """The operator timeline query is capped and ordered for review."""
    repo = object.__new__(PostgresRepository)
    since = datetime(2026, 8, 1, tzinfo=timezone.utc)

    with patch.object(repo, "_execute_query", return_value=[]) as execute:
        repo.query_recent_frequency_events("conn", "series-a", since, limit=25)

    sql, params = execute.call_args.args
    assert "anomaly_type IN ('FrequencyAnomaly', 'AbsenceAnomaly')" in sql
    assert "ORDER BY start_ts DESC" in sql
    assert "LIMIT %(limit)s" in sql
    assert "start_ts >= %(since)s" in sql
    assert params == {"module": "conn", "series_id": "series-a", "since": since, "limit": 25}


@pytest.mark.unit
def test_recent_frequency_events_without_since_omit_the_lower_bound() -> None:
    """The All range has no start instant, so no bound may be invented."""
    repo = object.__new__(PostgresRepository)

    with patch.object(repo, "_execute_query", return_value=[]) as execute:
        repo.query_recent_frequency_events("conn", "series-a", None, limit=10)

    sql, params = execute.call_args.args
    assert "start_ts >=" not in sql
    assert "since" not in params


@pytest.mark.unit
def test_correct_frequency_overrides_discards_connection_after_rollback() -> None:
    repo = PostgresRepository("localhost", 5432, "user", "password", "db")
    conn = MagicMock()
    cursor = MagicMock()
    cursor.execute.side_effect = RuntimeError("database failure")
    conn.cursor.return_value.__enter__.return_value = cursor
    repo._pool = MagicMock()
    repo._pool.closed = False
    repo._pool.getconn.return_value = conn

    with pytest.raises(RuntimeError, match="database failure"):
        repo.correct_frequency_overrides(
            "conn",
            "series",
            1.1,
            2.2,
            {"tolerance_factor_override": None, "absence_factor_override": None},
            "ticket",
            "operator",
        )

    repo._pool.putconn.assert_called_once_with(conn, close=True)
