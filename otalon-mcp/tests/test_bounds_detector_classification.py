"""Tests for the detector-classification block (Task B).

Verifies that:

* ``read_bounds(series_id=...)`` returns a
  ``recent_alarm_classification`` block reporting which detector family
  produced the most recent anomalies for the UCI and whether the bounds
  write tools are actionable for those alarms.
* ``expand_bounds`` / ``replace_bounds`` annotate their response with a
  ``warning`` field when the recent alarms are NOT bounds-derived
  (advisory only — the operation still succeeds with ``ok=True``).
* When recent alarms ARE bounds-derived, the warning field is absent
  and ``actionable_by_bounds_tools`` is ``True``.

Backed by a SQLite database with the same ``anomalies`` + ``bounds``
table shape the production PostgreSQL deployment uses; the helper
functions go through the real ``PostgresRepo`` and never mock.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

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
def repo(tmp_path) -> PostgresRepo:
    db_path = tmp_path / "detector.sqlite"
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
        # Minimal anomalies table — only the columns ``query_anomalies``
        # filters on. We deliberately mirror the live schema's column
        # names so the helper SQL works unchanged.
        conn.execute(
            text(
                "CREATE TABLE anomalies ("
                " id VARCHAR PRIMARY KEY,"
                " module VARCHAR NOT NULL,"
                " series_id VARCHAR NOT NULL,"
                " anomaly_type VARCHAR NOT NULL,"
                " start_ts TIMESTAMP NOT NULL,"
                " end_ts TIMESTAMP NOT NULL,"
                " metric VARCHAR,"
                " is_anomaly BOOLEAN NOT NULL DEFAULT 1"
                ")"
            )
        )
        # anomaly_suppressions table — `_resolve_classification` reads it.
        conn.execute(
            text(
                "CREATE TABLE anomaly_suppressions ("
                " id VARCHAR PRIMARY KEY,"
                " series_id VARCHAR NOT NULL UNIQUE,"
                " suppressed_types JSON NOT NULL,"
                " reason TEXT NOT NULL,"
                " created_by VARCHAR,"
                " created_at TIMESTAMP NOT NULL,"
                " expires_at TIMESTAMP"
                ")"
            )
        )
    yield repo
    repo.close()


@pytest.fixture()
def tools(repo) -> Dict[str, Any]:
    mcp = FakeMCP()
    init_mcp_tools(
        mcp,
        pg_repo=repo,
        influx_repo=_FakeInfluxRepo(),
        defaults=Defaults(fields=list(CANONICAL_FIELDS)),
        pcap_url="http://fake:9090",
        stix_path=os.path.join(ROOT, "data", "ics-attack.json"),
    )
    return mcp.tools


def _iso(dt: datetime) -> str:
    """Format a datetime so SQLite's lexicographic compare matches the query.

    ``PostgresRepo.query_anomalies`` emits a WHERE clause comparing
    ``end_ts`` against the ISO-8601 ``YYYY-MM-DDTHH:MM:SSZ`` form
    produced by ``time_range_default``. Mirror that exact shape on the
    insert side so SQLite (whose TIMESTAMP comparisons are string
    comparisons) matches reality.
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _insert_anomalies(
    repo: PostgresRepo,
    series_id: str,
    types: List[str],
    module: str = "conn",
) -> None:
    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    with repo.engine.begin() as conn:
        for offset, atype in enumerate(types):
            start = now - timedelta(minutes=10 + offset)
            end = now - timedelta(minutes=offset)
            conn.execute(
                text(
                    "INSERT INTO anomalies (id, module, series_id, anomaly_type, "
                    "start_ts, end_ts, metric, is_anomaly) "
                    "VALUES (:id, :m, :s, :t, :st, :et, :metric, 1)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "m": module,
                    "s": series_id,
                    "t": atype,
                    "st": _iso(start),
                    "et": _iso(end),
                    "metric": "packet_count",
                },
            )


def _seed_bounds(repo: PostgresRepo, series_id: str, module: str = "conn") -> None:
    """Seed a baseline bounds row so expand_bounds has something to widen."""
    lower = {f: 0.0 for f in CANONICAL_FIELDS}
    upper = {f: 1000.0 for f in CANONICAL_FIELDS}
    repo.write_bounds(
        module=module,
        series_id=series_id,
        lower_bounds=lower,
        upper_bounds=upper,
        reason="baseline for detector-classification tests",
    )


# ── read_bounds.recent_alarm_classification ──────────────────────────────


def test_read_bounds_no_anomalies_returns_none_detector(tools, repo):
    _seed_bounds(repo, "uci_empty")
    res = tools["postgres.read_bounds"](module="conn", series_id="uci_empty")
    assert res["ok"] is True
    rac = res.get("recent_alarm_classification")
    assert rac is not None
    assert rac["detector"] == "none"
    assert rac["count_in_window"] == 0
    assert rac["actionable_by_bounds_tools"] is False
    # The recommended_action must guide the LLM somewhere useful.
    assert rac["recommended_action"]


def test_read_bounds_bounds_derived_alarms_actionable(tools, repo):
    _seed_bounds(repo, "uci_bv")
    _insert_anomalies(repo, "uci_bv", ["BoundViolation", "BoundViolation", "NoBounds"])
    res = tools["postgres.read_bounds"](module="conn", series_id="uci_bv")
    assert res["ok"] is True
    rac = res["recent_alarm_classification"]
    assert rac["detector"] == "bounds"
    assert rac["actionable_by_bounds_tools"] is True
    assert rac["count_in_window"] == 3
    assert rac["bounds_derived_count"] == 3
    assert rac["ml_derived_count"] == 0
    assert "expand_bounds" in rac["recommended_action"].lower()


def test_read_bounds_ml_derived_alarms_not_actionable(tools, repo):
    _seed_bounds(repo, "uci_ml")
    _insert_anomalies(
        repo,
        "uci_ml",
        ["T0846/arp_scan", "T0846/arp_scan", "arp_spoofing"],
    )
    res = tools["postgres.read_bounds"](module="conn", series_id="uci_ml")
    assert res["ok"] is True
    rac = res["recent_alarm_classification"]
    assert rac["detector"] == "ml_rule"
    assert rac["actionable_by_bounds_tools"] is False
    assert rac["bounds_derived_count"] == 0
    assert rac["ml_derived_count"] == 3
    rec = rac["recommended_action"].lower()
    assert "add_anomaly_suppression" in rec or "suppression" in rec


def test_read_bounds_frequency_alarms_not_actionable(tools, repo):
    _seed_bounds(repo, "uci_freq")
    _insert_anomalies(repo, "uci_freq", ["FrequencyAnomaly", "AbsenceAnomaly"])
    res = tools["postgres.read_bounds"](module="conn", series_id="uci_freq")
    rac = res["recent_alarm_classification"]
    assert rac["detector"] == "frequency"
    assert rac["actionable_by_bounds_tools"] is False
    assert rac["frequency_derived_count"] == 2


def test_read_bounds_fusion_alarms_marked_actionable(tools, repo):
    _seed_bounds(repo, "uci_mix")
    _insert_anomalies(
        repo,
        "uci_mix",
        ["BoundViolation", "T0846/arp_scan", "FrequencyAnomaly"],
    )
    res = tools["postgres.read_bounds"](module="conn", series_id="uci_mix")
    rac = res["recent_alarm_classification"]
    assert rac["detector"] == "fusion"
    # Fusion: bounds tools can address part of the issue
    assert rac["actionable_by_bounds_tools"] is True
    assert rac["bounds_derived_count"] == 1
    assert rac["ml_derived_count"] == 1
    assert rac["frequency_derived_count"] == 1


# ── expand_bounds / replace_bounds warning field ─────────────────────────


def _full_lo_hi() -> tuple[Dict[str, float], Dict[str, float]]:
    return (
        {f: 0.0 for f in CANONICAL_FIELDS},
        {f: 1000.0 for f in CANONICAL_FIELDS},
    )


def test_expand_bounds_warns_on_ml_only_recent_alarms(tools, repo):
    _seed_bounds(repo, "uci_ml_warn")
    _insert_anomalies(repo, "uci_ml_warn", ["T0846/arp_scan", "arp_spoofing"])
    lower, upper = _full_lo_hi()
    # widen marginally so the call goes through repo
    upper["packet_count"] = 1500
    res = tools["postgres.expand_bounds"](
        module="conn",
        series_id="uci_ml_warn",
        lower_bounds=lower,
        upper_bounds=upper,
        reason="widen — but recent alarms are ML",
    )
    assert res["ok"] is True
    warning = res.get("warning", "")
    assert warning, "expected a warning when recent alarms are not bounds-derived"
    assert "not bounds-derived" in warning.lower() or "ml" in warning.lower() or "suppression" in warning.lower()


def test_expand_bounds_no_warning_on_bounds_recent_alarms(tools, repo):
    _seed_bounds(repo, "uci_bv_no_warn")
    _insert_anomalies(repo, "uci_bv_no_warn", ["BoundViolation"])
    lower, upper = _full_lo_hi()
    upper["packet_count"] = 1500
    res = tools["postgres.expand_bounds"](
        module="conn",
        series_id="uci_bv_no_warn",
        lower_bounds=lower,
        upper_bounds=upper,
        reason="widen — recent alarms ARE bounds",
    )
    assert res["ok"] is True
    # No detector-warning expected. (An all-tighter advisory could still
    # fire, but our payload widens at least one feature, so it won't.)
    warning = res.get("warning", "")
    assert "not bounds-derived" not in warning.lower()


def test_replace_bounds_warns_on_ml_only_recent_alarms(tools, repo):
    _seed_bounds(repo, "uci_replace_ml")
    _insert_anomalies(repo, "uci_replace_ml", ["T0846/arp_scan"])
    lower, upper = _full_lo_hi()
    res = tools["postgres.replace_bounds"](
        module="conn",
        series_id="uci_replace_ml",
        lower_bounds=lower,
        upper_bounds=upper,
        reason="replace — but recent alarms are ML",
    )
    assert res["ok"] is True
    warning = res.get("warning", "")
    assert warning, "expected a warning when recent alarms are not bounds-derived"
    assert "suppression" in warning.lower() or "ml" in warning.lower()


def test_read_bounds_no_series_id_skips_classification(tools, repo):
    """When no series_id is passed, recent_alarm_classification is omitted."""
    res = tools["postgres.read_bounds"](module="conn")
    assert res["ok"] is True
    assert "recent_alarm_classification" not in res
