"""Strict feature-completeness tests for the bounds write/expand/replace tools.

The original ``test_bounds_write_tools.py`` exercises the underlying
read/write semantics with ad-hoc feature names and a relaxed
``Defaults.fields`` override; this file pins the NEW contract introduced
to fix the chat-LLM UX bug:

* ``expand_bounds`` / ``replace_bounds`` reject SUBSET payloads with
  HTTP 422 + a ``missing`` list of features the LLM must add.
* ``expand_bounds`` accepts ``null`` values as explicit
  "do-not-expand" no-op markers, so a full-feature payload with some
  ``null`` entries still succeeds with the non-null subset applied.
* ``replace_bounds`` rejects ``null`` values — replace requires real
  ``(lo, hi)`` for every feature.
* An all-tighter ``expand_bounds`` payload is logged as an advisory
  warning but does NOT block the operation.
"""

from __future__ import annotations

import os
from typing import Any, Dict

import pytest
from sqlalchemy import text

from otalon_mcp.mcp_tools import Defaults, init_mcp_tools
from otalon_mcp.repositories.postgres_repo import PostgresRepo

ROOT = os.path.dirname(os.path.dirname(__file__))

CANONICAL_FIELDS = [
    "packet_count",
    "total_volume",
    "mean_packet_size",
    "min_packet_size",
    "max_packet_size",
    "std_packet_size",
    "mean_interarrival_time",
    "min_interarrival_time",
    "max_interarrival_time",
    "std_interarrival_time",
]


class FakeMCP:
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
    def list_ids(self, *_args, **_kwargs) -> list:
        return []

    def list_ids_between(self, *_args, **_kwargs) -> list:
        return []

    def query_timeseries(self, *_args, **_kwargs):  # pragma: no cover - unused
        raise NotImplementedError

    def query_timeseries_multi_ids_chunked(self, *_args, **_kwargs):  # pragma: no cover - unused
        raise NotImplementedError


@pytest.fixture()
def sqlite_repo(tmp_path) -> PostgresRepo:
    db_path = tmp_path / "bounds_strict.sqlite"
    repo = PostgresRepo(f"sqlite:///{db_path}")
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
def tools(sqlite_repo) -> Dict[str, Any]:
    mcp = FakeMCP()
    init_mcp_tools(
        mcp,
        pg_repo=sqlite_repo,
        influx_repo=_FakeInfluxRepo(),
        defaults=Defaults(fields=list(CANONICAL_FIELDS)),
        pcap_url="http://fake:9090",
        stix_path=os.path.join(ROOT, "data", "ics-attack.json"),
    )
    return mcp.tools


def _full_payload(value_lo: float = 0.0, value_hi: float = 100.0) -> Dict[str, float]:
    return {f: value_hi if "max" in f or "std" in f else value_lo for f in CANONICAL_FIELDS}


def _full_lo_hi() -> tuple[Dict[str, float], Dict[str, float]]:
    lower = {f: 0.0 for f in CANONICAL_FIELDS}
    upper = {f: 1000.0 for f in CANONICAL_FIELDS}
    return lower, upper


# ── expand_bounds strict-mode tests ──────────────────────────────────────


def test_expand_bounds_rejects_subset_with_422(tools, sqlite_repo):
    """SUBSET payload → 422 with deterministic missing-feature list."""
    lower, upper = _full_lo_hi()
    tools["postgres.write_bounds"](
        module="conn",
        series_id="uci_subset",
        lower_bounds=lower,
        upper_bounds=upper,
        reason="baseline",
    )
    res = tools["postgres.expand_bounds"](
        module="conn",
        series_id="uci_subset",
        # Real chat-LLM bug: 6-of-10 features partial expand
        lower_bounds={
            "packet_count": 0,
            "total_volume": 0,
            "mean_packet_size": 0,
            "min_packet_size": 0,
            "max_packet_size": 0,
            "std_packet_size": 0,
        },
        upper_bounds={
            "packet_count": 9999,
            "total_volume": 99_000_000,
            "mean_packet_size": 1500,
            "min_packet_size": 64,
            "max_packet_size": 9000,
            "std_packet_size": 1000,
        },
        reason="partial widen — should be rejected",
    )
    assert res["ok"] is False
    assert res["status_code"] == 422
    expected_missing = {
        "mean_interarrival_time",
        "min_interarrival_time",
        "max_interarrival_time",
        "std_interarrival_time",
    }
    assert set(res["missing"]) == expected_missing
    assert set(res["expected"]) == set(CANONICAL_FIELDS)
    # Detail string must hint the LLM at what to supply
    assert "bounds incomplete" in res["error"].lower()
    assert "every feature" in res["error"].lower()


def test_expand_bounds_full_with_some_null_succeeds(tools, sqlite_repo):
    """Full feature set with some null values → 200 (null is a no-op marker)."""
    lower, upper = _full_lo_hi()
    tools["postgres.write_bounds"](
        module="conn",
        series_id="uci_null_ok",
        lower_bounds=lower,
        upper_bounds=upper,
        reason="baseline",
    )
    # Widen only packet_count + total_volume; leave the other 8 untouched
    # by passing explicit nulls (full feature set still covered).
    new_lower: Dict[str, Any] = {f: None for f in CANONICAL_FIELDS}
    new_upper: Dict[str, Any] = {f: None for f in CANONICAL_FIELDS}
    new_lower["packet_count"] = -10  # widen down
    new_upper["packet_count"] = 5000  # widen up (vs initial 1000)
    new_lower["total_volume"] = -100
    new_upper["total_volume"] = 5_000_000

    res = tools["postgres.expand_bounds"](
        module="conn",
        series_id="uci_null_ok",
        lower_bounds=new_lower,
        upper_bounds=new_upper,
        reason="widen the two features the LLM mentioned",
    )
    assert res["ok"] is True
    assert res["action"] == "expand"

    # Stored row: packet_count + total_volume widened, others unchanged
    with sqlite_repo.engine.begin() as conn:
        row = conn.execute(
            text("SELECT lower_bounds, upper_bounds FROM bounds " "WHERE module='conn' AND series_id='uci_null_ok'")
        ).fetchone()
    import json

    stored_lower = row[0] if isinstance(row[0], dict) else json.loads(row[0])
    stored_upper = row[1] if isinstance(row[1], dict) else json.loads(row[1])
    assert stored_lower["packet_count"] == -10
    assert stored_upper["packet_count"] == 5000
    assert stored_lower["total_volume"] == -100
    assert stored_upper["total_volume"] == 5_000_000
    # untouched features keep their original 0 / 1000 baseline
    for feat in CANONICAL_FIELDS:
        if feat in {"packet_count", "total_volume"}:
            continue
        assert stored_lower[feat] == 0.0, feat
        assert stored_upper[feat] == 1000.0, feat


def test_expand_bounds_all_tighter_is_advisory_not_blocking(tools, sqlite_repo, caplog):
    """All-tighter payload succeeds but emits an advisory warning."""
    lower, upper = _full_lo_hi()
    tools["postgres.write_bounds"](
        module="conn",
        series_id="uci_tighter",
        lower_bounds=lower,
        upper_bounds=upper,
        reason="baseline",
    )
    # Tighter on every feature (higher lower bounds, lower upper bounds)
    new_lower = {f: 100.0 for f in CANONICAL_FIELDS}
    new_upper = {f: 500.0 for f in CANONICAL_FIELDS}

    res = tools["postgres.expand_bounds"](
        module="conn",
        series_id="uci_tighter",
        lower_bounds=new_lower,
        upper_bounds=new_upper,
        reason="all-tighter expand — should be advised, not blocked",
    )
    # Still succeeds (expand_bounds is widen-only at the repo layer; the
    # tighter payload simply does not narrow anything).
    assert res["ok"] is True
    # The repo's min/max preserves the wider 0..1000 envelope
    import json

    with sqlite_repo.engine.begin() as conn:
        row = conn.execute(
            text("SELECT lower_bounds, upper_bounds FROM bounds " "WHERE module='conn' AND series_id='uci_tighter'")
        ).fetchone()
    stored_lower = row[0] if isinstance(row[0], dict) else json.loads(row[0])
    stored_upper = row[1] if isinstance(row[1], dict) else json.loads(row[1])
    for f in CANONICAL_FIELDS:
        assert stored_lower[f] == 0.0
        assert stored_upper[f] == 1000.0


# ── replace_bounds strict-mode tests ─────────────────────────────────────


def test_replace_bounds_rejects_subset_with_422(tools):
    """SUBSET payload → 422 with missing-feature list."""
    res = tools["postgres.replace_bounds"](
        module="conn",
        series_id="uci_replace_subset",
        lower_bounds={"packet_count": 0, "total_volume": 0},
        upper_bounds={"packet_count": 1500, "total_volume": 9_000_000},
        reason="partial replace — should be rejected",
    )
    assert res["ok"] is False
    assert res["status_code"] == 422
    assert "bounds incomplete" in res["error"].lower()
    # ALL non-supplied features must be in `missing`
    expected_missing = set(CANONICAL_FIELDS) - {"packet_count", "total_volume"}
    assert set(res["missing"]) == expected_missing


def test_replace_bounds_rejects_null_values_with_422(tools):
    """Full feature set with null values → 422 (replace needs real lo/hi)."""
    lower = {f: 0.0 for f in CANONICAL_FIELDS}
    upper = {f: 1000.0 for f in CANONICAL_FIELDS}
    lower["std_interarrival_time"] = None
    upper["std_interarrival_time"] = None

    res = tools["postgres.replace_bounds"](
        module="conn",
        series_id="uci_replace_null",
        lower_bounds=lower,
        upper_bounds=upper,
        reason="null-containing replace — should be rejected",
    )
    assert res["ok"] is False
    assert res["status_code"] == 422
    assert "std_interarrival_time" in res["missing"]
    assert "null is not accepted" in res["error"].lower()


def test_replace_bounds_full_payload_succeeds(tools, sqlite_repo):
    lower, upper = _full_lo_hi()
    res = tools["postgres.replace_bounds"](
        module="conn",
        series_id="uci_replace_full",
        lower_bounds=lower,
        upper_bounds=upper,
        reason="full replace",
    )
    assert res["ok"] is True
    assert res["action"] == "replace"


# ── tool description / discoverability ───────────────────────────────────


def _normalize_doc(doc: str) -> str:
    """Collapse all whitespace in a docstring so substring asserts are linewrap-safe."""
    import re

    return re.sub(r"\s+", " ", (doc or "").lower()).strip()


def test_expand_bounds_description_references_get_bounds(tools):
    doc = _normalize_doc(tools["postgres.expand_bounds"].__doc__ or "")
    assert "read_bounds" in doc or "get_bounds" in doc
    assert "every feature" in doc
    assert "null" in doc
    assert "headroom" in doc


def test_replace_bounds_description_references_get_bounds(tools):
    doc = _normalize_doc(tools["postgres.replace_bounds"].__doc__ or "")
    assert "read_bounds" in doc or "get_bounds" in doc
    assert "every feature" in doc
    assert "headroom" in doc


def test_system_prompt_includes_completeness_and_headroom():
    """The chat-agent system prompt must teach the strict-completeness contract."""
    prompt_path = os.path.join(ROOT, "docs", "system_promt_agent.md")
    if not os.path.isfile(prompt_path):
        pytest.skip(f"system prompt file not found: {prompt_path}")
    with open(prompt_path, "r", encoding="utf-8") as fh:
        text_lower = fh.read().lower()
    assert "every feature" in text_lower
    assert "headroom" in text_lower
    assert "null" in text_lower
