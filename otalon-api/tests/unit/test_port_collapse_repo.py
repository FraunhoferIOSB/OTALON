"""Unit tests for PortCollapseRepository (mock DB, test cache behavior)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import polars as pl
import psycopg2
import pytest

from otalon_api.repositories.port_collapse_repo import PortCollapseRepository

_SAMPLE_ROWS = [
    {
        "src_mac": "aa:bb:cc:dd:ee:01",
        "dst_mac": "aa:bb:cc:dd:ee:02",
        "vlan": "0",
        "ip_proto": "",
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.2",
        "protocols": "Ethernet:IPv4:TCP",
        "normalized_uci": "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1/192.168.1.2/*/80/Ethernet:IPv4:TCP",
        "wildcard_src_port": True,
        "wildcard_dst_port": False,
        "bucket_seconds": 10,
    },
    {
        "src_mac": "aa:bb:cc:dd:ee:03",
        "dst_mac": "aa:bb:cc:dd:ee:04",
        "vlan": "0",
        "ip_proto": "",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocols": "Ethernet:IPv4:UDP",
        "normalized_uci": "aa:bb:cc:dd:ee:03/aa:bb:cc:dd:ee:04/0//10.0.0.1/10.0.0.2/*/*/Ethernet:IPv4:UDP",
        "wildcard_src_port": True,
        "wildcard_dst_port": True,
        "bucket_seconds": 60,
    },
]


def _make_mock_cursor(rows: list[dict]):
    """Create a mock cursor that returns the given rows from fetchall.

    Args:
        rows: List of dicts to return.

    Returns:
        A MagicMock cursor.
    """
    cursor = MagicMock()
    cursor.fetchall.return_value = rows
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)
    return cursor


def _make_mock_conn(rows: list[dict]):
    """Create a mock psycopg2 connection with a cursor returning given rows.

    Args:
        rows: List of dicts for the cursor to return.

    Returns:
        A MagicMock connection.
    """
    conn = MagicMock()
    cursor = _make_mock_cursor(rows)
    conn.cursor.return_value = cursor
    return conn


@pytest.mark.unit
class TestGetRules:
    """Tests for PortCollapseRepository.get_rules()."""

    @patch("otalon_api.repositories.port_collapse_repo.psycopg2")
    def test_returns_dataframe_when_rules_exist(self, mock_psycopg2: MagicMock) -> None:
        """get_rules returns a Polars DataFrame when rules exist in the DB."""
        mock_psycopg2.connect.return_value = _make_mock_conn(_SAMPLE_ROWS)
        repo = PortCollapseRepository(dsn="host=localhost dbname=test")

        result = repo.get_rules("conn")

        assert isinstance(result, pl.DataFrame)
        assert len(result) == 2
        assert "normalized_uci" in result.columns
        assert "wildcard_src_port" in result.columns
        assert "bucket_seconds" in result.columns

    @patch("otalon_api.repositories.port_collapse_repo.psycopg2")
    def test_returns_none_when_no_rules(self, mock_psycopg2: MagicMock) -> None:
        """get_rules returns None when no rules exist for the module."""
        mock_psycopg2.connect.return_value = _make_mock_conn([])
        repo = PortCollapseRepository(dsn="host=localhost dbname=test")

        result = repo.get_rules("conn")

        assert result is None

    @patch("otalon_api.repositories.port_collapse_repo.psycopg2")
    def test_returns_none_on_missing_table(self, mock_psycopg2: MagicMock) -> None:
        """get_rules returns None when the table does not exist (fresh DB)."""
        conn = MagicMock()
        cursor = MagicMock()
        cursor.execute.side_effect = psycopg2.ProgrammingError("relation does not exist")
        cursor.__enter__ = MagicMock(return_value=cursor)
        cursor.__exit__ = MagicMock(return_value=False)
        conn.cursor.return_value = cursor
        mock_psycopg2.connect.return_value = conn
        mock_psycopg2.errors.UndefinedTable = psycopg2.errors.UndefinedTable
        mock_psycopg2.ProgrammingError = psycopg2.ProgrammingError
        mock_psycopg2.Error = psycopg2.Error

        repo = PortCollapseRepository(dsn="host=localhost dbname=test")
        result = repo.get_rules("conn")

        assert result is None


@pytest.mark.unit
class TestCacheBehavior:
    """Tests for TTL-based caching in PortCollapseRepository."""

    @patch("otalon_api.repositories.port_collapse_repo.psycopg2")
    def test_second_call_uses_cache(self, mock_psycopg2: MagicMock) -> None:
        """get_rules called twice within TTL executes only one DB query."""
        mock_psycopg2.connect.return_value = _make_mock_conn(_SAMPLE_ROWS)
        repo = PortCollapseRepository(dsn="host=localhost dbname=test", ttl=300)

        result1 = repo.get_rules("conn")
        result2 = repo.get_rules("conn")

        assert result1 is not None
        assert result2 is not None
        assert mock_psycopg2.connect.call_count == 1

    @patch("otalon_api.repositories.port_collapse_repo.psycopg2")
    def test_invalidate_forces_refetch(self, mock_psycopg2: MagicMock) -> None:
        """invalidate_cache followed by get_rules re-fetches from DB."""
        mock_psycopg2.connect.return_value = _make_mock_conn(_SAMPLE_ROWS)
        repo = PortCollapseRepository(dsn="host=localhost dbname=test", ttl=300)

        repo.get_rules("conn")
        repo.invalidate_cache("conn")
        repo.get_rules("conn")

        assert mock_psycopg2.connect.call_count == 2

    @patch("otalon_api.repositories.port_collapse_repo.psycopg2")
    def test_invalidate_all_clears_all_modules(self, mock_psycopg2: MagicMock) -> None:
        """invalidate_cache(None) clears all cached modules."""
        mock_psycopg2.connect.return_value = _make_mock_conn(_SAMPLE_ROWS)
        repo = PortCollapseRepository(dsn="host=localhost dbname=test", ttl=300)

        repo.get_rules("conn")
        repo.get_rules("mac_traffic")
        repo.invalidate_cache(None)
        repo.get_rules("conn")

        assert mock_psycopg2.connect.call_count == 3

    @patch("otalon_api.repositories.port_collapse_repo.psycopg2")
    def test_none_result_is_cached(self, mock_psycopg2: MagicMock) -> None:
        """None result (no rules) is also cached to avoid repeated DB queries."""
        mock_psycopg2.connect.return_value = _make_mock_conn([])
        repo = PortCollapseRepository(dsn="host=localhost dbname=test", ttl=300)

        result1 = repo.get_rules("conn")
        result2 = repo.get_rules("conn")

        assert result1 is None
        assert result2 is None
        assert mock_psycopg2.connect.call_count == 1


@pytest.mark.unit
class TestGetNormalizedUcis:
    """Tests for PortCollapseRepository.get_normalized_ucis()."""

    @patch("otalon_api.repositories.port_collapse_repo.psycopg2")
    def test_returns_sorted_unique_ucis(self, mock_psycopg2: MagicMock) -> None:
        """get_normalized_ucis returns a sorted list of unique UCIs."""
        mock_psycopg2.connect.return_value = _make_mock_conn(_SAMPLE_ROWS)
        repo = PortCollapseRepository(dsn="host=localhost dbname=test")

        result = repo.get_normalized_ucis("conn")

        assert isinstance(result, list)
        assert len(result) == 2
        assert result == sorted(result)

    @patch("otalon_api.repositories.port_collapse_repo.psycopg2")
    def test_returns_empty_list_when_no_rules(self, mock_psycopg2: MagicMock) -> None:
        """get_normalized_ucis returns empty list when no rules exist."""
        mock_psycopg2.connect.return_value = _make_mock_conn([])
        repo = PortCollapseRepository(dsn="host=localhost dbname=test")

        result = repo.get_normalized_ucis("conn")

        assert result == []
