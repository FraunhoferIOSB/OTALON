"""Tests for the anomaly-suppression MCP tools (add/list/remove).

Uses an in-memory SQLite database so the repo methods can be exercised
end-to-end without a live PostgreSQL instance. The SQLite branch of the
repository encodes ``suppressed_types`` as a comma-separated TEXT
column; the production Postgres branch uses native ``TEXT[]`` arrays.
Both branches must round-trip the same Python ``list[str]`` shape, so
the tests assert against that and trust the dialect-specific encoding
to be transparent.

In addition, the existing bounds-write tools are re-exercised here to
confirm that ``read_bounds``, ``expand_bounds`` and ``replace_bounds``
attach a ``classification`` block surfacing any active suppression for
the queried UCI.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

import pytest
from sqlalchemy import text

from otalon_mcp.mcp_tools import Defaults, init_mcp_tools
from otalon_mcp.repositories.postgres_repo import PostgresRepo

ROOT = os.path.dirname(os.path.dirname(__file__))

# --------------------------------------------------------------------------- #
# fixtures + helpers
# --------------------------------------------------------------------------- #


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

    def list_ids(self, *_args: Any, **_kwargs: Any) -> list:
        return []

    def list_ids_between(self, *_args: Any, **_kwargs: Any) -> list:
        return []

    def query_timeseries(self, *_args: Any, **_kwargs: Any):  # pragma: no cover
        raise NotImplementedError

    def query_timeseries_multi_ids_chunked(self, *_args: Any, **_kwargs: Any):  # pragma: no cover
        raise NotImplementedError


@pytest.fixture()
def sqlite_repo(tmp_path) -> PostgresRepo:
    """Return a ``PostgresRepo`` backed by a fresh SQLite file."""
    db_path = tmp_path / "suppression.sqlite"
    repo = PostgresRepo(f"sqlite:///{db_path}")
    # Create the bounds table for the read_bounds-with-classification
    # test; the suppression table is created lazily by the repo.
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


@pytest.fixture()
def tools_with_repo(sqlite_repo: PostgresRepo) -> Dict[str, Any]:
    """Register all MCP tools against ``sqlite_repo`` and return the dict."""
    mcp = FakeMCP()
    init_mcp_tools(
        mcp,
        pg_repo=sqlite_repo,
        influx_repo=_FakeInfluxRepo(),
        defaults=Defaults(),
        pcap_url="http://fake:9090",
        stix_path=os.path.join(ROOT, "data", "ics-attack.json"),
    )
    return mcp.tools


def _suppression_rows(repo: PostgresRepo) -> List[Dict[str, Any]]:
    """Return all suppression rows, JSON-decoded for ergonomic asserts."""
    with repo.engine.begin() as conn:
        result = conn.execute(
            text(
                "SELECT id, series_id, suppressed_types, reason, "
                "       created_by, expires_at "
                "FROM anomaly_suppression ORDER BY id"
            )
        )
        rows = [dict(row._mapping) for row in result]
    return rows


# --------------------------------------------------------------------------- #
# add_anomaly_suppression
# --------------------------------------------------------------------------- #


def test_add_creates_new_row(tools_with_repo, sqlite_repo):
    """Adding a brand-new suppression returns ``action=create`` with the row id."""
    res = tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="cc:82:7f:a1:8a:37/ff:ff:ff:ff:ff:ff/Ethernet:ARP",
        suppressed_types=["arp_scan", "arp_spoofing"],
        reason="legitimate ARP discovery from managed switch",
        created_by="operator-alice",
    )
    assert res["ok"] is True
    assert res["action"] == "create"
    assert res["series_id"].endswith("/Ethernet:ARP")
    assert sorted(res["suppressed_types"]) == ["arp_scan", "arp_spoofing"]
    assert isinstance(res["id"], int) and res["id"] > 0

    rows = _suppression_rows(sqlite_repo)
    assert len(rows) == 1
    assert rows[0]["reason"] == "legitimate ARP discovery from managed switch"
    assert rows[0]["created_by"] == "operator-alice"


def test_add_unions_existing_types(tools_with_repo, sqlite_repo):
    """Calling add twice with overlapping types unions the set in place."""
    tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s1",
        suppressed_types=["arp_scan"],
        reason="first",
    )
    res = tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s1",
        suppressed_types=["arp_scan", "arp_spoofing"],
        reason="add spoofing too",
    )
    assert res["ok"] is True
    assert res["action"] == "update"
    assert sorted(res["suppressed_types"]) == ["arp_scan", "arp_spoofing"]
    assert len(_suppression_rows(sqlite_repo)) == 1


def test_add_idempotent_same_types(tools_with_repo):
    """Calling add twice with the same types is a stable no-op union."""
    first = tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s2",
        suppressed_types=["arp_scan"],
        reason="r",
    )
    second = tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s2",
        suppressed_types=["arp_scan"],
        reason="r2",
    )
    assert first["ok"] and second["ok"]
    assert second["action"] == "update"
    assert second["suppressed_types"] == ["arp_scan"]


def test_add_rejects_empty_reason(tools_with_repo):
    """Empty / whitespace ``reason`` is rejected at the tool boundary."""
    for bad in ("", "   ", "\t"):
        res = tools_with_repo["postgres.add_anomaly_suppression"](
            series_id="s_bad",
            suppressed_types=["arp_scan"],
            reason=bad,
        )
        assert res["ok"] is False
        assert "reason" in res["error"].lower()


def test_add_rejects_empty_types(tools_with_repo):
    """Empty / all-blank ``suppressed_types`` is rejected before INSERT."""
    res = tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s_bad",
        suppressed_types=[],
        reason="r",
    )
    assert res["ok"] is False

    res2 = tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s_bad",
        suppressed_types=["", "  "],
        reason="r",
    )
    assert res2["ok"] is False


def test_add_with_expires_at_round_trips(tools_with_repo, sqlite_repo):
    """``expires_at`` ISO-8601 strings are accepted and stored."""
    res = tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s_exp",
        suppressed_types=["arp_scan"],
        reason="temporary",
        expires_at="2026-12-31T23:59:59+00:00",
    )
    assert res["ok"] is True
    listing = tools_with_repo["postgres.list_anomaly_suppressions"](series_id="s_exp")
    assert listing["ok"] is True
    assert listing["records"][0]["expires_at"].startswith("2026-12-31")


def test_add_rejects_invalid_expires_at(tools_with_repo):
    """Garbage ``expires_at`` is rejected, leaving no row behind."""
    res = tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s_bad_exp",
        suppressed_types=["arp_scan"],
        reason="r",
        expires_at="not-a-date",
    )
    assert res["ok"] is False
    assert "expires_at" in res["error"].lower()


# --------------------------------------------------------------------------- #
# list_anomaly_suppressions
# --------------------------------------------------------------------------- #


def test_list_returns_all_when_unfiltered(tools_with_repo):
    """Without ``series_id`` filter, the list returns every active row."""
    tools_with_repo["postgres.add_anomaly_suppression"](series_id="s_a", suppressed_types=["arp_scan"], reason="r")
    tools_with_repo["postgres.add_anomaly_suppression"](series_id="s_b", suppressed_types=["port_scan"], reason="r")
    res = tools_with_repo["postgres.list_anomaly_suppressions"]()
    assert res["ok"] is True
    assert res["count"] == 2
    series_ids = {r["series_id"] for r in res["records"]}
    assert series_ids == {"s_a", "s_b"}


def test_list_filters_by_series_id(tools_with_repo):
    """``series_id`` filter narrows the list to a single UCI."""
    tools_with_repo["postgres.add_anomaly_suppression"](series_id="s_a", suppressed_types=["arp_scan"], reason="r")
    tools_with_repo["postgres.add_anomaly_suppression"](series_id="s_b", suppressed_types=["port_scan"], reason="r")
    res = tools_with_repo["postgres.list_anomaly_suppressions"](series_id="s_a")
    assert res["count"] == 1
    assert res["records"][0]["series_id"] == "s_a"


def test_list_excludes_expired_by_default(tools_with_repo):
    """Expired rows are hidden unless ``include_expired=True``."""
    tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s_active",
        suppressed_types=["arp_scan"],
        reason="active",
    )
    tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s_expired",
        suppressed_types=["arp_scan"],
        reason="expired",
        expires_at="2020-01-01T00:00:00+00:00",
    )
    default = tools_with_repo["postgres.list_anomaly_suppressions"]()
    assert {r["series_id"] for r in default["records"]} == {"s_active"}

    with_expired = tools_with_repo["postgres.list_anomaly_suppressions"](include_expired=True)
    assert {r["series_id"] for r in with_expired["records"]} == {
        "s_active",
        "s_expired",
    }


# --------------------------------------------------------------------------- #
# remove_anomaly_suppression
# --------------------------------------------------------------------------- #


def test_remove_deletes_row_when_types_none(tools_with_repo, sqlite_repo):
    """Passing ``suppressed_types=None`` deletes the row outright."""
    tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s1", suppressed_types=["arp_scan", "arp_spoofing"], reason="r"
    )
    res = tools_with_repo["postgres.remove_anomaly_suppression"](series_id="s1")
    assert res["ok"] is True
    assert res["action"] == "delete"
    assert res["remaining_types"] == []
    assert _suppression_rows(sqlite_repo) == []


def test_remove_keeps_remaining_types(tools_with_repo):
    """Removing a subset of types updates the row in place."""
    tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s1",
        suppressed_types=["arp_scan", "arp_spoofing", "port_scan"],
        reason="r",
    )
    res = tools_with_repo["postgres.remove_anomaly_suppression"](
        series_id="s1",
        suppressed_types=["arp_spoofing"],
    )
    assert res["ok"] is True
    assert res["action"] == "update"
    assert sorted(res["remaining_types"]) == ["arp_scan", "port_scan"]


def test_remove_deletes_when_all_types_dropped(tools_with_repo, sqlite_repo):
    """Removing every remaining type triggers a row delete."""
    tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s1",
        suppressed_types=["arp_scan", "arp_spoofing"],
        reason="r",
    )
    res = tools_with_repo["postgres.remove_anomaly_suppression"](
        series_id="s1",
        suppressed_types=["arp_scan", "arp_spoofing"],
    )
    assert res["ok"] is True
    assert res["action"] == "delete"
    assert _suppression_rows(sqlite_repo) == []


def test_remove_noop_for_unknown_series(tools_with_repo):
    """Removing a non-existent suppression returns ``action=noop``."""
    res = tools_with_repo["postgres.remove_anomaly_suppression"](series_id="never_added")
    assert res["ok"] is True
    assert res["action"] == "noop"


# --------------------------------------------------------------------------- #
# read_bounds / expand_bounds / replace_bounds — classification block
# --------------------------------------------------------------------------- #


def test_read_bounds_attaches_classification_when_suppressed(tools_with_repo, sqlite_repo):
    """``read_bounds`` exposes the suppression warning when one exists."""
    tools_with_repo["postgres.write_bounds"](
        module="conn",
        series_id="series_with_supp",
        lower_bounds={"packet_count": 0},
        upper_bounds={"packet_count": 10},
        reason="init",
    )
    tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="series_with_supp",
        suppressed_types=["arp_scan"],
        reason="legit",
    )
    res = tools_with_repo["postgres.read_bounds"](module="conn", series_id="series_with_supp")
    assert res["ok"] is True
    cls = res["classification"]
    assert cls["has_active_suppression"] is True
    assert cls["suppressed_types"] == ["arp_scan"]
    assert "warning" in cls


def test_read_bounds_classification_false_without_suppression(tools_with_repo, sqlite_repo):
    """Without a suppression row, the classification reports ``False``."""
    tools_with_repo["postgres.write_bounds"](
        module="conn",
        series_id="clean_series",
        lower_bounds={"packet_count": 0},
        upper_bounds={"packet_count": 10},
        reason="init",
    )
    res = tools_with_repo["postgres.read_bounds"](module="conn", series_id="clean_series")
    cls = res["classification"]
    assert cls["has_active_suppression"] is False
    assert cls["suppressed_types"] == []


_FULL_FEATURE_LO = {
    "packet_count": 0,
    "total_volume": 0,
    "mean_packet_size": 0,
    "min_packet_size": 0,
    "max_packet_size": 0,
    "std_packet_size": 0,
    "mean_interarrival_time": 0,
    "min_interarrival_time": 0,
    "max_interarrival_time": 0,
    "std_interarrival_time": 0,
}
_FULL_FEATURE_HI = {k: 1000 for k in _FULL_FEATURE_LO}


def test_expand_bounds_attaches_classification(tools_with_repo):
    """``expand_bounds`` carries the warning back to the caller."""
    tools_with_repo["postgres.write_bounds"](
        module="conn",
        series_id="s_expand",
        lower_bounds=dict(_FULL_FEATURE_LO),
        upper_bounds=dict(_FULL_FEATURE_HI),
        reason="init",
    )
    tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s_expand",
        suppressed_types=["arp_scan"],
        reason="legit",
    )
    widen_upper = dict(_FULL_FEATURE_HI)
    widen_upper["packet_count"] = 2000  # actually widen so it's not all-tighter
    res = tools_with_repo["postgres.expand_bounds"](
        module="conn",
        series_id="s_expand",
        lower_bounds=dict(_FULL_FEATURE_LO),
        upper_bounds=widen_upper,
        reason="raise upper",
    )
    assert res["ok"] is True
    assert res["classification"]["has_active_suppression"] is True
    assert "warning" in res["classification"]


def test_replace_bounds_attaches_classification(tools_with_repo):
    """``replace_bounds`` (potentially destructive) also surfaces the warning."""
    tools_with_repo["postgres.add_anomaly_suppression"](
        series_id="s_replace",
        suppressed_types=["port_scan"],
        reason="legit",
    )
    res = tools_with_repo["postgres.replace_bounds"](
        module="conn",
        series_id="s_replace",
        lower_bounds=dict(_FULL_FEATURE_LO),
        upper_bounds=dict(_FULL_FEATURE_HI),
        reason="tighter envelope",
    )
    assert res["ok"] is True
    assert res["classification"]["has_active_suppression"] is True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
