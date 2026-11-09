"""Tests for the bounds write/expand/replace MCP tools (FP-Workflow).

Uses an in-memory SQLite database with the same schema as the production
PostgreSQL ``bounds`` and ``bounds_history`` tables. SQLAlchemy's JSON
type works on both backends, so the repo methods can be exercised
end-to-end without a live PG instance.

The tool wrappers (``tools.postgres.write_bounds`` etc.) are exercised
via the registered MCP tool surface (FakeMCP) to confirm that
docstrings, parameter forwarding, and the empty-reason guard all behave
as expected.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import pytest
from sqlalchemy import text

# Ensure we can import from src
from otalon_mcp.mcp_tools import Defaults, init_mcp_tools
from otalon_mcp.repositories.postgres_repo import PostgresRepo

ROOT = os.path.dirname(os.path.dirname(__file__))


class FakeMCP:
    """Minimal stand-in for ``FastMCP`` used by ``init_mcp_tools``."""

    def __init__(self) -> None:
        self.tools: Dict[str, Any] = {}
        self.annotations: Dict[str, Any] = {}

    def tool(self, name: str, annotations: Any = None, **kwargs: Any):
        """Mirror ``FastMCP.tool``: accept and record the annotations kwarg.

        ``init_mcp_tools`` registers an async wrapper (so blocking helper
        calls are offloaded off the event loop) and passes MCP
        ``ToolAnnotations``. The wrapper carries the original synchronous
        handler on ``__wrapped__``; tests keep calling tools
        synchronously, so unwrap it here.
        """

        def decorator(fn):
            self.annotations[name] = annotations
            self.tools[name] = getattr(fn, "__wrapped__", fn)
            return fn

        return decorator


class _FakeInfluxRepo:
    """Stub that satisfies ``init_mcp_tools`` without doing any I/O."""

    def list_ids(self, *_args, **_kwargs) -> list:
        return []

    def list_ids_between(self, *_args, **_kwargs) -> list:
        return []

    def query_timeseries(self, *_args, **_kwargs):  # pragma: no cover - unused
        raise NotImplementedError

    def query_timeseries_multi_ids_chunked(self, *_args, **_kwargs):  # pragma: no cover - unused
        raise NotImplementedError


# ── fixtures ────────────────────────────────────────────────────────────


@pytest.fixture()
def sqlite_repo(tmp_path) -> PostgresRepo:
    """Return a ``PostgresRepo`` backed by a fresh SQLite file."""
    db_path = tmp_path / "bounds.sqlite"
    repo = PostgresRepo(f"sqlite:///{db_path}")
    # Create the ``bounds`` and ``bounds_history`` tables by hand —
    # production uses otalon-clas ORM ``Base.metadata.create_all``;
    # for the test we need the same shape.
    with repo.engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE bounds ("
                " module VARCHAR NOT NULL,"
                " series_id VARCHAR NOT NULL,"
                " lower_bounds JSON NOT NULL,"
                " upper_bounds JSON NOT NULL,"
                " trained_at TIMESTAMP NOT NULL,"
                " first_ts TIMESTAMP,"
                " last_ts TIMESTAMP,"
                " PRIMARY KEY (module, series_id)"
                ")"
            )
        )
        conn.execute(
            text(
                "CREATE TABLE bounds_history ("
                " id VARCHAR PRIMARY KEY,"
                " module VARCHAR NOT NULL,"
                " series_id VARCHAR NOT NULL,"
                " action VARCHAR NOT NULL,"
                " old_lower JSON,"
                " old_upper JSON,"
                " new_lower JSON NOT NULL,"
                " new_upper JSON NOT NULL,"
                " reason TEXT NOT NULL,"
                " changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
                ")"
            )
        )
    yield repo
    repo.close()


def _make_tools(sqlite_repo, defaults: Defaults | None = None):
    """Register MCP tools against ``sqlite_repo`` with the given defaults."""
    mcp = FakeMCP()
    init_mcp_tools(
        mcp,
        pg_repo=sqlite_repo,
        influx_repo=_FakeInfluxRepo(),
        defaults=defaults or Defaults(),
        pcap_url="http://fake:9090",
        stix_path=os.path.join(ROOT, "data", "ics-attack.json"),
    )
    return mcp.tools


@pytest.fixture()
def tools_factory(sqlite_repo):
    """Return a callable that builds a tools dict against ``sqlite_repo``.

    Tests that exercise expand/replace semantics with custom ad-hoc
    feature names pass the matching feature set explicitly so the strict
    feature-completeness guard does not short-circuit them. Strict-mode
    behaviour is covered separately in
    ``test_bounds_strict_validation.py``.
    """

    def _factory(fields: list[str] | None = None):
        return _make_tools(
            sqlite_repo,
            defaults=Defaults(fields=fields) if fields else Defaults(),
        )

    return _factory


@pytest.fixture()
def tools_with_repo(tools_factory):
    """Register MCP tools with a relaxed superset of all legacy field names."""
    return tools_factory(["a", "b", "x", "z", "new_feature"])


def _history_rows(repo: PostgresRepo, series_id: str) -> List[Dict[str, Any]]:
    """Return all bounds_history rows for the given series_id, oldest first."""
    with repo.engine.begin() as conn:
        result = conn.execute(
            text(
                "SELECT id, module, series_id, action, old_lower, old_upper, "
                "new_lower, new_upper, reason "
                "FROM bounds_history WHERE series_id = :s ORDER BY changed_at"
            ),
            {"s": series_id},
        )
        rows = [dict(row._mapping) for row in result]
    # SQLite returns JSON as text; decode for ergonomic assertions.
    for row in rows:
        for col in ("old_lower", "old_upper", "new_lower", "new_upper"):
            if isinstance(row[col], str):
                row[col] = json.loads(row[col])
    return rows


def _bounds_row(repo: PostgresRepo, module: str, series_id: str) -> Dict[str, Any]:
    """Return the single bounds row for (module, series_id), JSON-decoded."""
    with repo.engine.begin() as conn:
        row = conn.execute(
            text("SELECT lower_bounds, upper_bounds FROM bounds " "WHERE module = :m AND series_id = :s"),
            {"m": module, "s": series_id},
        ).fetchone()
    assert row is not None, f"no bounds row for ({module!r}, {series_id!r})"
    lower = row[0] if isinstance(row[0], dict) else json.loads(row[0])
    upper = row[1] if isinstance(row[1], dict) else json.loads(row[1])
    return {"lower": lower, "upper": upper}


# ── write_bounds ────────────────────────────────────────────────────────


def test_write_bounds_creates_row_and_history(tools_with_repo, sqlite_repo):
    res = tools_with_repo["postgres.write_bounds"](
        module="netcap",
        series_id="series_A",
        lower_bounds={"packet_count": 0, "total_volume": 100},
        upper_bounds={"packet_count": 10, "total_volume": 1000},
        reason="initial training",
    )
    assert res["ok"] is True
    assert res["action"] == "write"
    assert res["module"] == "netcap"
    assert res["series_id"] == "series_A"
    assert isinstance(res["history_id"], str) and res["history_id"]

    stored = _bounds_row(sqlite_repo, "netcap", "series_A")
    assert stored["lower"] == {"packet_count": 0, "total_volume": 100}
    assert stored["upper"] == {"packet_count": 10, "total_volume": 1000}

    history = _history_rows(sqlite_repo, "series_A")
    assert len(history) == 1
    h = history[0]
    assert h["action"] == "write"
    assert h["old_lower"] is None and h["old_upper"] is None
    assert h["new_lower"] == {"packet_count": 0, "total_volume": 100}
    assert h["new_upper"] == {"packet_count": 10, "total_volume": 1000}
    assert h["reason"] == "initial training"


def test_write_bounds_duplicate_raises(tools_with_repo):
    tools_with_repo["postgres.write_bounds"](
        module="netcap",
        series_id="series_dup",
        lower_bounds={"x": 0},
        upper_bounds={"x": 10},
        reason="first",
    )
    res = tools_with_repo["postgres.write_bounds"](
        module="netcap",
        series_id="series_dup",
        lower_bounds={"x": 5},
        upper_bounds={"x": 50},
        reason="second",
    )
    assert res["ok"] is False
    assert "already exist" in res["error"].lower()


# ── expand_bounds ───────────────────────────────────────────────────────


def test_expand_bounds_widens_per_feature(tools_factory, sqlite_repo):
    tools = tools_factory(["a", "b"])
    tools["postgres.write_bounds"](
        module="conn",
        series_id="series_widen",
        lower_bounds={"a": 5, "b": 10},
        upper_bounds={"a": 100, "b": 50},
        reason="baseline",
    )
    res = tools["postgres.expand_bounds"](
        module="conn",
        series_id="series_widen",
        lower_bounds={
            "a": 1,
            "b": 99,
        },  # new lower for a (down), b stays (already 10 < 99)
        upper_bounds={"a": 80, "b": 60},  # a upper stays (100), b upper goes up to 60
        reason="widen for FP",
    )
    assert res["ok"] is True
    assert res["action"] == "expand"

    stored = _bounds_row(sqlite_repo, "conn", "series_widen")
    # lower = min(old, new); upper = max(old, new)
    assert stored["lower"] == {"a": 1, "b": 10}
    assert stored["upper"] == {"a": 100, "b": 60}


def test_expand_bounds_keeps_untouched_features(tools_factory, sqlite_repo):
    """null-valued features act as 'do-not-expand' no-op markers and preserve old."""
    tools = tools_factory(["a", "b"])
    tools["postgres.write_bounds"](
        module="conn",
        series_id="series_keep",
        lower_bounds={"a": 5, "b": 10},
        upper_bounds={"a": 100, "b": 50},
        reason="baseline",
    )
    # Mention "a" with real values, "b" with null → "b" must survive untouched.
    res = tools["postgres.expand_bounds"](
        module="conn",
        series_id="series_keep",
        lower_bounds={"a": 1, "b": None},
        upper_bounds={"a": 200, "b": None},
        reason="widen only a",
    )
    assert res["ok"] is True
    stored = _bounds_row(sqlite_repo, "conn", "series_keep")
    assert stored["lower"] == {"a": 1, "b": 10}
    assert stored["upper"] == {"a": 200, "b": 50}


def test_expand_bounds_adds_new_features(tools_factory, sqlite_repo):
    tools = tools_factory(["a", "new_feature"])
    tools["postgres.write_bounds"](
        module="conn",
        series_id="series_add",
        lower_bounds={"a": 5, "new_feature": 7},
        upper_bounds={"a": 100, "new_feature": 42},
        reason="baseline",
    )
    res = tools["postgres.expand_bounds"](
        module="conn",
        series_id="series_add",
        lower_bounds={"a": 1, "new_feature": 7},
        upper_bounds={"a": 100, "new_feature": 42},
        reason="add new feature",
    )
    assert res["ok"] is True
    stored = _bounds_row(sqlite_repo, "conn", "series_add")
    assert stored["lower"] == {"a": 1, "new_feature": 7}
    assert stored["upper"] == {"a": 100, "new_feature": 42}


def test_expand_bounds_missing_row_raises(tools_factory):
    tools = tools_factory(["a"])
    res = tools["postgres.expand_bounds"](
        module="conn",
        series_id="series_missing",
        lower_bounds={"a": 0},
        upper_bounds={"a": 10},
        reason="expand",
    )
    assert res["ok"] is False
    assert "no bounds row" in res["error"].lower()


# ── replace_bounds ──────────────────────────────────────────────────────


def test_replace_bounds_overwrites(tools_factory, sqlite_repo):
    # Replace requires a full active feature set; the test exercises
    # transitioning the stored set from {a, b} to {z} by setting the
    # active feature set to {z} for the second call.
    tools_ab = tools_factory(["a", "b"])
    tools_ab["postgres.write_bounds"](
        module="conn",
        series_id="series_replace",
        lower_bounds={"a": 0, "b": 10},
        upper_bounds={"a": 100, "b": 50},
        reason="initial",
    )
    tools_z = tools_factory(["z"])
    res = tools_z["postgres.replace_bounds"](
        module="conn",
        series_id="series_replace",
        lower_bounds={"z": 5},
        upper_bounds={"z": 9},
        reason="full overwrite",
    )
    assert res["ok"] is True
    assert res["action"] == "replace"

    stored = _bounds_row(sqlite_repo, "conn", "series_replace")
    # Whole dict is replaced — "a" and "b" are gone.
    assert stored["lower"] == {"z": 5}
    assert stored["upper"] == {"z": 9}


def test_replace_bounds_creates_if_missing(tools_factory, sqlite_repo):
    tools = tools_factory(["a"])
    res = tools["postgres.replace_bounds"](
        module="conn",
        series_id="series_new_replace",
        lower_bounds={"a": 1},
        upper_bounds={"a": 9},
        reason="bootstrap via replace",
    )
    assert res["ok"] is True
    stored = _bounds_row(sqlite_repo, "conn", "series_new_replace")
    assert stored["lower"] == {"a": 1}
    assert stored["upper"] == {"a": 9}

    history = _history_rows(sqlite_repo, "series_new_replace")
    assert len(history) == 1
    assert history[0]["action"] == "replace"
    # Replace on a missing row records NULL old payload.
    assert history[0]["old_lower"] is None
    assert history[0]["old_upper"] is None


# ── history audit shape ─────────────────────────────────────────────────


def test_history_row_has_correct_action_and_old_new(tools_factory, sqlite_repo):
    """All three actions produce a history row with the right shape."""
    tools = tools_factory(["a"])
    # write
    tools["postgres.write_bounds"](
        module="conn",
        series_id="series_hist",
        lower_bounds={"a": 0},
        upper_bounds={"a": 10},
        reason="write",
    )
    # expand
    tools["postgres.expand_bounds"](
        module="conn",
        series_id="series_hist",
        lower_bounds={"a": -5},
        upper_bounds={"a": 15},
        reason="expand",
    )
    # replace
    tools["postgres.replace_bounds"](
        module="conn",
        series_id="series_hist",
        lower_bounds={"a": 100},
        upper_bounds={"a": 200},
        reason="replace",
    )

    history = _history_rows(sqlite_repo, "series_hist")
    assert [h["action"] for h in history] == ["write", "expand", "replace"]

    # write: old NULL, new = first payload
    assert history[0]["old_lower"] is None
    assert history[0]["old_upper"] is None
    assert history[0]["new_lower"] == {"a": 0}
    assert history[0]["new_upper"] == {"a": 10}

    # expand: old = write payload, new = widened
    assert history[1]["old_lower"] == {"a": 0}
    assert history[1]["old_upper"] == {"a": 10}
    assert history[1]["new_lower"] == {"a": -5}
    assert history[1]["new_upper"] == {"a": 15}

    # replace: old = expand payload, new = replacement
    assert history[2]["old_lower"] == {"a": -5}
    assert history[2]["old_upper"] == {"a": 15}
    assert history[2]["new_lower"] == {"a": 100}
    assert history[2]["new_upper"] == {"a": 200}


# ── reason guard ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "tool_name",
    ["postgres.write_bounds", "postgres.expand_bounds", "postgres.replace_bounds"],
)
@pytest.mark.parametrize("reason", ["", "   ", "\n\t "])
def test_empty_reason_rejected(tools_with_repo, tool_name, reason):
    res = tools_with_repo[tool_name](
        module="conn",
        series_id="series_no_reason",
        lower_bounds={"a": 0},
        upper_bounds={"a": 1},
        reason=reason,
    )
    assert res["ok"] is False
    assert "reason" in res["error"].lower()


# ── tool registration ───────────────────────────────────────────────────


def test_all_three_tools_registered(tools_with_repo):
    for name in (
        "postgres.write_bounds",
        "postgres.expand_bounds",
        "postgres.replace_bounds",
    ):
        assert name in tools_with_repo, f"tool {name!r} not registered"


def test_tool_docstrings_disambiguate_actions(tools_with_repo):
    """Docstrings must clearly distinguish the three tools for LLM routing."""
    write_doc = tools_with_repo["postgres.write_bounds"].__doc__ or ""
    expand_doc = tools_with_repo["postgres.expand_bounds"].__doc__ or ""
    replace_doc = tools_with_repo["postgres.replace_bounds"].__doc__ or ""

    assert "errors" in write_doc.lower() or "already exist" in write_doc.lower()
    assert "widen" in expand_doc.lower() or "min/max" in expand_doc.lower()
    assert "overwrite" in replace_doc.lower() and "destructive" in replace_doc.lower()
