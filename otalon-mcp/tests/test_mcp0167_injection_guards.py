"""Regression tests for MCP-016 and MCP-017 (injection guards).

MCP-016 pins the two destructive statements in
:mod:`otalon_mcp.repositories.postgres_repo` (``truncate_table`` /
``delete_all_rows``): the table name must pass
``_require_identifier`` AND an explicit, non-empty allow-list. A missing
or empty allow-list is a rejection, not a skipped guard.

MCP-017 pins the ``layer`` argument of
:func:`otalon_mcp.tools.pcap.conversations`, which used to be
interpolated into the tshark argument string without validation.
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import event, text

from otalon_mcp.repositories.postgres_repo import PostgresRepo
from otalon_mcp.tools import pcap as pcap_tools
from otalon_mcp.validation import CONVERSATION_LAYERS

INJECTION_TABLE = "alarms; DROP TABLE anomalies"


@pytest.fixture()
def repo(tmp_path: Path) -> PostgresRepo:
    """Return a repository backed by a throwaway SQLite database."""
    instance = PostgresRepo(f"sqlite:///{tmp_path / 'mcp0167.db'}")
    with instance.engine.begin() as conn:
        conn.execute(text("CREATE TABLE alarms (id INTEGER PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE anomalies (id INTEGER PRIMARY KEY)"))
        conn.execute(text("INSERT INTO alarms (id) VALUES (1), (2)"))
    return instance


class TestTruncateTableGuards:
    """MCP-016 — ``truncate_table`` fails closed."""

    def test_missing_allowlist_is_rejected(self, repo: PostgresRepo) -> None:
        ok, message = repo.truncate_table("alarms", allowlist=None)
        assert ok is False
        assert "allow" in message.lower() or "whitelist" in message.lower()

    def test_empty_allowlist_is_rejected(self, repo: PostgresRepo) -> None:
        ok, _ = repo.truncate_table("alarms", allowlist=[])
        assert ok is False

    def test_non_identifier_table_is_rejected(self, repo: PostgresRepo) -> None:
        ok, _ = repo.truncate_table(INJECTION_TABLE, allowlist=[INJECTION_TABLE])
        assert ok is False

    def test_unknown_table_is_rejected(self, repo: PostgresRepo) -> None:
        ok, _ = repo.truncate_table("devices", allowlist=["devices"])
        assert ok is False

    def test_allowlisted_table_reaches_the_statement(self, repo: PostgresRepo) -> None:
        """SQLite has no TRUNCATE, so the emitted SQL is what is pinned."""
        statements: list[str] = []

        @event.listens_for(repo.engine, "before_cursor_execute")
        def _record(
            conn: Any,
            cursor: Any,
            statement: str,
            parameters: Any,
            context: Any,
            executemany: bool,
        ) -> None:
            statements.append(statement)

        repo.truncate_table("alarms", allowlist=["alarms"])
        assert any(stmt.startswith('TRUNCATE TABLE "alarms"') for stmt in statements)


class TestDeleteAllRowsGuards:
    """MCP-016 — ``delete_all_rows`` fails closed."""

    def test_missing_allowlist_is_rejected(self, repo: PostgresRepo) -> None:
        deleted, message = repo.delete_all_rows("alarms", allowlist=None)
        assert deleted == -1
        assert "allow" in message.lower() or "whitelist" in message.lower()
        with repo.engine.begin() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM alarms")).scalar() == 2

    def test_empty_allowlist_is_rejected(self, repo: PostgresRepo) -> None:
        deleted, _ = repo.delete_all_rows("alarms", allowlist=[])
        assert deleted == -1

    def test_non_identifier_table_is_rejected(self, repo: PostgresRepo) -> None:
        deleted, _ = repo.delete_all_rows(INJECTION_TABLE, allowlist=[INJECTION_TABLE])
        assert deleted == -1
        with repo.engine.begin() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM anomalies")).scalar() == 0

    def test_unknown_table_is_rejected(self, repo: PostgresRepo) -> None:
        deleted, _ = repo.delete_all_rows("devices", allowlist=["devices"])
        assert deleted == -1

    def test_allowlisted_table_is_emptied(self, repo: PostgresRepo) -> None:
        deleted, message = repo.delete_all_rows("alarms", allowlist=["alarms"])
        assert deleted == 2
        assert message == "ok"


class TestConversationLayerGuard:
    """MCP-017 — ``conversations`` allow-lists the tshark layer."""

    @pytest.fixture(autouse=True)
    def _init_pcap(self) -> None:
        pcap_tools.init(pcap_url="http://fake:9090", timeout=5)

    @staticmethod
    def _response(text_body: str) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 200
        resp.text = text_body
        resp.raise_for_status = MagicMock()
        return resp

    @pytest.mark.parametrize("layer", sorted(CONVERSATION_LAYERS))
    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_legal_layers_reach_the_recorder(self, mock_get: MagicMock, layer: str) -> None:
        mock_get.return_value = self._response(f"{layer} conversations")
        result = pcap_tools.conversations(chunk_id="20260225_133027.pcap", layer=layer)
        assert result["ok"] is True
        params = mock_get.call_args.kwargs["params"]
        assert params["tshark_args"] == f"-q -z conv,{layer}"

    @pytest.mark.parametrize(
        "layer",
        [
            "eth -r /etc/passwd",
            "ip;rm -rf /",
            "ETH",
            "ipv6",
            "",
            "conv,eth -T fields",
        ],
    )
    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_illegal_layers_are_rejected_before_the_request(self, mock_get: MagicMock, layer: str) -> None:
        result = pcap_tools.conversations(chunk_id="20260225_133027.pcap", layer=layer)
        assert result["ok"] is False
        assert "layer" in result["error"].lower()
        mock_get.assert_not_called()
