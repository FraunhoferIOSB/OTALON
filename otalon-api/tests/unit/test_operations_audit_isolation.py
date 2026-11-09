"""Audit/systemtest data-isolation contract tests.

Prove the guarded ownership-marker cleanup only removes rows for an explicit
non-native ``source`` and can never delete live operator history. The delete
path is exercised through the real repository method against a fake Postgres
so the SQL guard and scoping are verified without a live database.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from otalon_api.domain.operations.audit import AuditQueryFilters
from otalon_api.repositories.operations_audit_repo import OperationsAuditRepository


class _FakePostgres:
    """Minimal Postgres double capturing DELETE scope and returning ids."""

    def __init__(self, rows_by_source: dict[str, list[int]]) -> None:
        self._rows_by_source = rows_by_source
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _execute_query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.calls.append((sql, dict(params or {})))
        source = (params or {}).get("source")
        return [{"id": rid} for rid in self._rows_by_source.get(str(source), [])]


@pytest.mark.unit
def test_delete_by_source_scopes_to_marker_only() -> None:
    """Only rows under the given marker are removed; native rows untouched."""
    pg = _FakePostgres({"systemtest-abc": [1, 2, 3], "operations": [9]})
    repo = OperationsAuditRepository(pg)
    removed = repo.delete_by_source("systemtest-abc")
    assert removed == 3
    sql, params = pg.calls[-1]
    assert "DELETE FROM operations_audit WHERE source = %(source)s" in sql
    assert params["source"] == "systemtest-abc"


@pytest.mark.unit
@pytest.mark.parametrize("bad_source", ["", "   ", "operations"])
def test_delete_by_source_refuses_native_and_empty(bad_source: str) -> None:
    """The native operations source and empty markers are rejected."""
    pg = _FakePostgres({"operations": [1, 2]})
    repo = OperationsAuditRepository(pg)
    with pytest.raises(ValueError):
        repo.delete_by_source(bad_source)
    assert pg.calls == []


class _FakeQueryPostgres:
    """Postgres double that applies case-insensitive substring ILIKE.

    Models the ``operations_audit`` rows and applies the same substring
    semantics PostgreSQL ``ILIKE %val%`` would, so a repository query for
    actor ``oper`` returns the ``operator`` row.
    """

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self.last_sql = ""
        self.last_params: dict[str, Any] = {}

    def _execute_query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.last_sql = sql
        self.last_params = dict(params or {})
        actor = self.last_params.get("actor")
        matched = list(self._rows)
        if actor is not None:
            needle = str(actor).strip("%").lower()
            matched = [row for row in matched if needle in str(row["actor"]).lower()]
        return matched


@pytest.mark.unit
def test_actor_filter_matches_case_insensitive_substring() -> None:
    """API actor=``oper`` returns the ``operator`` row via bound ILIKE."""
    now = datetime(2026, 7, 20, tzinfo=timezone.utc)
    pg = _FakeQueryPostgres(
        [
            {
                "id": 1,
                "at": now,
                "category": "bounds",
                "actor": "operator",
                "action": "correction",
                "target": "conn:uci-1",
            },
            {
                "id": 2,
                "at": now,
                "category": "config",
                "actor": "service-account",
                "action": "update",
                "target": "env:TZ",
            },
        ]
    )
    repo = OperationsAuditRepository(pg)
    results = repo.query(AuditQueryFilters(actor="oper"))

    assert [entry.actor for entry in results] == ["operator"]
    # SQL uses a bound ILIKE with substring wrapping, mirroring action/target.
    assert "actor ILIKE %(actor)s" in pg.last_sql
    assert pg.last_params["actor"] == "%oper%"
