"""Regression tests for the MCP-013 P1 hardening batch.

Covers the eight audited findings:

* MCP-01 — SQL injection through the PostgreSQL read helpers.
* MCP-02 — Influx ``start``/``stop`` injection.
* MCP-03 — Influx identifier / aggregate-function injection.
* MCP-04 — pcap.* tools sending no ``X-API-Key`` header.
* MCP-05 — tool handlers registered as blocking ``def``.
* MCP-06 — database errors surfacing as empty (``ok: true``) results.
* MCP-07 — missing ``ToolAnnotations`` on the tool surface.
* MCP-08 — ``read_alarms(type_=)`` filtering on a non-existent column.
"""

import asyncio
import inspect
import os
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from sqlalchemy import text

from otalon_mcp.mcp_tools import Defaults, init_mcp_tools
from otalon_mcp.repositories.influx_repo import (
    _aggregate_function,
    _quote_identifier,
    _time_literal,
)
from otalon_mcp.repositories.postgres_repo import PostgresRepo
from otalon_mcp.settings import InfluxConfig, PostgresConfig, Settings
from otalon_mcp.tools import pcap as pcap_tools

ROOT = os.path.dirname(os.path.dirname(__file__))

pytestmark = pytest.mark.unit


class FakeMCP:
    """Records registered tools, their annotations and their coroutines."""

    def __init__(self) -> None:
        self.tools: Dict[str, Any] = {}
        self.registered: Dict[str, Any] = {}
        self.annotations: Dict[str, Any] = {}

    def tool(self, name: str, annotations: Any = None, **kwargs: Any):
        def decorator(fn):
            self.annotations[name] = annotations
            self.registered[name] = fn
            self.tools[name] = getattr(fn, "__wrapped__", fn)
            return fn

        return decorator


class _FakeInfluxRepo:
    """Inert Influx stand-in — these tests never touch the time-series path."""

    def list_ids(self, *args: Any, **kwargs: Any) -> List[str]:
        return []

    def list_ids_between(self, *args: Any, **kwargs: Any) -> List[str]:
        return []

    def query_timeseries(self, *args: Any, **kwargs: Any) -> pd.DataFrame:
        return pd.DataFrame()

    def query_timeseries_multi_ids_chunked(self, *args: Any, **kwargs: Any) -> pd.DataFrame:
        return pd.DataFrame()


@pytest.fixture()
def sqlite_repo(tmp_path) -> PostgresRepo:
    """A PostgresRepo backed by SQLite with a minimal alarms/anomalies schema."""
    repo = PostgresRepo(f"sqlite:///{tmp_path / 'mcp013.db'}")
    with repo.engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE alarms («»"
                " id VARCHAR PRIMARY KEY,"
                " module VARCHAR NOT NULL,"
                " start_timestamp TIMESTAMP NOT NULL,"
                " end_timestamp TIMESTAMP NOT NULL,"
                " primary_type VARCHAR,"
                " confirmed BOOLEAN NOT NULL DEFAULT 0"
                ")".replace("«»", "")
            )
        )
        conn.execute(
            text(
                "CREATE TABLE bounds ("
                " module VARCHAR NOT NULL,"
                " series_id VARCHAR NOT NULL,"
                " lower_bounds JSON NOT NULL,"
                " upper_bounds JSON NOT NULL,"
                " trained_at TIMESTAMP,"
                " PRIMARY KEY (module, series_id)"
                ")"
            )
        )
        for alarm_id, module, ptype in (
            ("a1", "conn", "tcp_flood"),
            ("a2", "conn", "BoundViolation"),
            ("a3", "mac_traffic", "tcp_flood"),
        ):
            conn.execute(
                text(
                    "INSERT INTO alarms (id, module, start_timestamp, "
                    "end_timestamp, primary_type, confirmed) VALUES "
                    "(:id, :m, '2026-01-01T00:00:00Z', "
                    "'2026-01-01T01:00:00Z', :p, 0)"
                ),
                {"id": alarm_id, "m": module, "p": ptype},
            )
        conn.execute(
            text(
                "INSERT INTO bounds (module, series_id, lower_bounds, "
                "upper_bounds) VALUES ('conn', 'secret-series', '{}', '{}')"
            )
        )
    yield repo
    repo.close()


# ── MCP-01: SQL injection through the PostgreSQL read helpers ──────────


def test_query_bounds_treats_injection_payload_as_a_literal(sqlite_repo):
    """The live PoC (``zzz' OR '1'='1``) must return zero rows, not all rows."""
    df = sqlite_repo.query_bounds(module="conn", series_id="zzz' OR '1'='1")
    assert df.empty, "injected series_id must not match any row"


def test_query_bounds_still_matches_a_legitimate_series(sqlite_repo):
    df = sqlite_repo.query_bounds(module="conn", series_id="secret-series")
    assert len(df) == 1


def test_query_table_rejects_a_table_outside_the_allowlist(sqlite_repo):
    with pytest.raises(ValueError, match="not readable"):
        sqlite_repo.query_table("sqlite_master")


def test_query_table_rejects_a_non_identifier_table(sqlite_repo):
    with pytest.raises(ValueError, match="invalid table name"):
        sqlite_repo.query_table("alarms; DROP TABLE alarms")


def test_query_table_rejects_a_non_identifier_column(sqlite_repo):
    with pytest.raises(ValueError, match="invalid column name"):
        sqlite_repo.query_table("alarms", columns=["id", "1) OR (1=1"])


def test_query_table_rejects_an_inlined_literal_in_where(sqlite_repo):
    with pytest.raises(ValueError, match="bind parameters"):
        sqlite_repo.query_table("alarms", where="module = 'conn'")


def test_query_anomaly_groups_binds_the_module_filter(sqlite_repo):
    df = sqlite_repo.query_anomaly_groups(module="conn' OR '1'='1")
    assert df.empty


def test_get_anomaly_group_by_id_binds_the_id(sqlite_repo):
    df = sqlite_repo.get_anomaly_group_by_id("a1' OR '1'='1")
    assert df.empty
    assert len(sqlite_repo.get_anomaly_group_by_id("a1")) == 1


# ── MCP-08: read_alarms(type_=) filters on primary_type ────────────────


def test_query_anomaly_groups_filters_on_primary_type(sqlite_repo):
    """``type_`` must actually narrow the result set."""
    df = sqlite_repo.query_anomaly_groups(type_="tcp_flood")
    assert len(df) == 2
    assert set(df["id"]) == {"a1", "a3"}


def test_query_anomaly_groups_type_filter_excludes_other_types(sqlite_repo):
    df = sqlite_repo.query_anomaly_groups(type_="BoundViolation")
    assert list(df["id"]) == ["a2"]


def test_query_anomaly_groups_unknown_type_returns_nothing(sqlite_repo):
    assert sqlite_repo.query_anomaly_groups(type_="does_not_exist").empty


def test_alarm_count_tool_defaults_target_primary_type():
    """The old ``type`` default silently produced empty output."""
    import otalon_mcp.tools.postgres as pg_tools

    assert inspect.signature(pg_tools.get_top_alarm_counts).parameters["group_by"].default == "primary_type"
    assert inspect.signature(pg_tools.get_most_common_alarm).parameters["group_by"].default == "primary_type"


# ── MCP-06: database errors must not look like empty results ───────────


def test_query_table_propagates_database_errors(sqlite_repo):
    """A missing table is an error, not "no rows"."""
    sqlite_repo.engine.dispose()
    with sqlite_repo.engine.begin() as conn:
        conn.execute(text("DROP TABLE alarms"))
    with pytest.raises(Exception):
        sqlite_repo.query_anomaly_groups(module="conn")


def test_read_alarms_reports_a_failure_envelope(sqlite_repo):
    """The tool layer converts the propagated error into ``ok: false``."""
    import otalon_mcp.tools.postgres as pg_tools

    mcp = FakeMCP()
    init_mcp_tools(
        mcp,
        pg_repo=sqlite_repo,
        influx_repo=_FakeInfluxRepo(),
        defaults=Defaults(),
        pcap_url="http://fake:9090",
        stix_path=os.path.join(ROOT, "data", "ics-attack.json"),
    )
    with sqlite_repo.engine.begin() as conn:
        conn.execute(text("DROP TABLE alarms"))
    result = pg_tools.read_alarms(module="conn")
    assert result["ok"] is False
    assert "error" in result


# ── MCP-02 / MCP-03: Influx literal and identifier validation ──────────


@pytest.mark.parametrize(
    "payload",
    [
        "2026-01-01T00:00:00Z' OR '1'='1",
        "'; DROP TABLE x --",
        "not-a-timestamp",
        "",
    ],
)
def test_time_literal_rejects_non_iso_input(payload):
    with pytest.raises(ValueError, match="invalid start timestamp"):
        _time_literal(payload, "start")


@pytest.mark.parametrize(
    "value",
    ["2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00", "2026-01-01 00:00:00"],
)
def test_time_literal_accepts_iso_input(value):
    assert _time_literal(value, "start") == f"'{value}'"


@pytest.mark.parametrize(
    "payload",
    ['uci" ; DROP TABLE x --', "a-b", "1abc", "", 'x" OR "1"="1'],
)
def test_quote_identifier_rejects_non_identifiers(payload):
    with pytest.raises(ValueError, match="invalid identifier"):
        _quote_identifier(payload)


def test_quote_identifier_accepts_a_bare_identifier():
    assert _quote_identifier("packet_count") == '"packet_count"'


@pytest.mark.parametrize(
    "payload",
    ["sum(x) FROM y --", "evil", "count; DROP TABLE x", ""],
)
def test_aggregate_function_rejects_anything_off_the_allowlist(payload):
    with pytest.raises(ValueError, match="invalid aggregate"):
        _aggregate_function(payload)


@pytest.mark.parametrize("name", ["avg", "MIN", "Max", "sum", "count", "median"])
def test_aggregate_function_accepts_allowlisted_names(name):
    assert _aggregate_function(name) == name.lower()


def test_query_timeseries_rejects_an_injected_measurement():
    from otalon_mcp.repositories.influx_repo import InfluxRepo

    repo = InfluxRepo.__new__(InfluxRepo)
    repo.database = "netcap"
    repo.client = MagicMock()
    with pytest.raises(ValueError, match="invalid measurement"):
        repo.query_timeseries(
            measurement='network_metrics" WHERE 1=1 --',
            id_tag="uci",
            fields=["packet_count"],
            start="2026-01-01T00:00:00Z",
            stop="2026-01-01T01:00:00Z",
        )
    repo.client.query.assert_not_called()


def test_query_timeseries_rejects_an_injected_aggregate():
    from otalon_mcp.repositories.influx_repo import InfluxRepo

    repo = InfluxRepo.__new__(InfluxRepo)
    repo.database = "netcap"
    repo.client = MagicMock()
    with pytest.raises(ValueError, match="invalid aggregate"):
        repo.query_timeseries(
            measurement="network_metrics",
            id_tag="uci",
            fields=["packet_count"],
            start="2026-01-01T00:00:00Z",
            stop="2026-01-01T01:00:00Z",
            aggregate="sum(1) FROM secrets --",
        )
    repo.client.query.assert_not_called()


# ── MCP-04: pcap tools must authenticate ───────────────────────────────


def _init_pcap_from_environment() -> None:
    """Initialise the pcap helper the way the server does.

    MCP-014 moved the ``PCAP_RECORDER_API_KEY`` / ``ADMIN_API_KEY``
    lookup into ``otalon_mcp.settings``; these tests keep asserting the
    end-to-end env-to-header behaviour by going through that resolver.
    """
    settings = Settings(
        postgres=PostgresConfig(dsn="postgresql://u@h/db"),
        influx=InfluxConfig(url="http://influx:8181"),
    ).with_env_overrides()
    pcap_tools.init(
        pcap_url="http://fake:9090",
        timeout=5,
        api_key=settings.pcap_recorder.api_key,
    )


def test_pcap_get_sends_the_operator_api_key():
    with patch.dict(os.environ, {"PCAP_RECORDER_API_KEY": "k-123"}, clear=False):
        _init_pcap_from_environment()
        with patch("otalon_mcp.tools.pcap.requests.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200)
            pcap_tools._get("/health")
    _, kwargs = mock_get.call_args
    assert kwargs["headers"] == {"X-API-Key": "k-123"}


def test_pcap_post_sends_the_operator_api_key():
    with patch.dict(os.environ, {"PCAP_RECORDER_API_KEY": "k-123"}, clear=False):
        _init_pcap_from_environment()
        with patch("otalon_mcp.tools.pcap.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            pcap_tools._post("/anomalies/flag", json_body={"a": 1})
    _, kwargs = mock_post.call_args
    assert kwargs["headers"] == {"X-API-Key": "k-123"}


def test_pcap_falls_back_to_admin_api_key():
    env = {"ADMIN_API_KEY": "admin-key"}
    with patch.dict(os.environ, env, clear=False):
        os.environ.pop("PCAP_RECORDER_API_KEY", None)
        _init_pcap_from_environment()
        assert pcap_tools._auth_headers() == {"X-API-Key": "admin-key"}


def test_pcap_prefers_the_recorder_specific_key():
    env = {"PCAP_RECORDER_API_KEY": "recorder-key", "ADMIN_API_KEY": "admin-key"}
    with patch.dict(os.environ, env, clear=False):
        _init_pcap_from_environment()
        assert pcap_tools._auth_headers() == {"X-API-Key": "recorder-key"}


def test_pcap_warns_when_no_key_is_configured(caplog):
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("PCAP_RECORDER_API_KEY", None)
        os.environ.pop("ADMIN_API_KEY", None)
        handler_id = pcap_tools.logger.add(caplog.handler, format="{message}")
        try:
            _init_pcap_from_environment()
        finally:
            pcap_tools.logger.remove(handler_id)
    assert any("no recorder API key" in r.getMessage() for r in caplog.records)
    assert pcap_tools._auth_headers() == {}


# ── MCP-05 / MCP-07: async registration + annotations ──────────────────


@pytest.fixture()
def registered(sqlite_repo) -> FakeMCP:
    mcp = FakeMCP()
    init_mcp_tools(
        mcp,
        pg_repo=sqlite_repo,
        influx_repo=_FakeInfluxRepo(),
        defaults=Defaults(),
        pcap_url="http://fake:9090",
        stix_path=os.path.join(ROOT, "data", "ics-attack.json"),
    )
    return mcp


def test_every_tool_is_registered_as_a_coroutine(registered):
    """A blocking ``def`` handler would stall the whole event loop."""
    sync = [name for name, fn in registered.registered.items() if not inspect.iscoroutinefunction(fn)]
    assert not sync, f"tools still registered as blocking def: {sorted(sync)}"


def test_registration_preserves_the_tool_schema_source(registered):
    """FastMCP derives the input schema from the wrapped signature."""
    fn = registered.registered["postgres.read_alarms"]
    assert fn.__doc__ and "alarm" in fn.__doc__.lower()
    params = inspect.signature(fn).parameters
    assert {"module", "type_", "confirmed", "limit"} <= set(params)


def test_async_wrapper_offloads_to_a_worker_thread(registered):
    """The handler must not execute on the event loop thread."""
    import threading

    loop_thread: Dict[str, Any] = {}

    async def drive():
        loop_thread["loop"] = threading.current_thread().name
        return await registered.registered["core.ping"]()

    result = asyncio.run(drive())
    assert result["ok"] is True
    assert loop_thread["loop"] == threading.current_thread().name


def test_every_tool_carries_annotations(registered):
    missing = [n for n, a in registered.annotations.items() if a is None]
    assert not missing, f"tools without ToolAnnotations: {sorted(missing)}"


def test_read_tools_are_annotated_read_only(registered):
    for name in (
        "postgres.read_alarms",
        "postgres.read_bounds",
        "postgres.read_anomalies",
        "influx.read_single_time_series",
        "pcap.list_chunks",
        "mitre.list_tactics",
    ):
        ann = registered.annotations[name]
        assert ann.readOnlyHint is True, name
        assert ann.destructiveHint is False, name
        assert ann.idempotentHint is True, name


def test_destructive_tools_are_flagged(registered):
    for name in (
        "postgres.replace_bounds",
        "postgres.delete_device",
        "postgres.delete_interface",
        "pcap.flag_anomaly",
        "mitre.update_stix_data",
    ):
        ann = registered.annotations[name]
        assert ann.readOnlyHint is False, name
        assert ann.destructiveHint is True, name


def test_additive_writes_are_not_flagged_destructive(registered):
    for name in ("postgres.write_bounds", "postgres.add_device"):
        ann = registered.annotations[name]
        assert ann.readOnlyHint is False, name
        assert ann.destructiveHint is False, name


def test_non_idempotent_tools_are_flagged(registered):
    assert registered.annotations["postgres.add_device"].idempotentHint is False
    assert registered.annotations["training.retrain_boundaries"].idempotentHint is False
    assert registered.annotations["postgres.update_device"].idempotentHint is True


# ── Registration against a real FastMCP instance ───────────────────────
#
# The FakeMCP doubles never introspect the handler, which is how a
# registration-breaking defect (postponed annotations vs. FastMCP's
# ``issubclass`` probe) survived unnoticed. These tests drive the real
# server object.


@pytest.fixture()
def real_server(sqlite_repo):
    fastmcp = pytest.importorskip("mcp.server.fastmcp")
    server = fastmcp.FastMCP("mcp013-test")
    init_mcp_tools(
        server,
        pg_repo=sqlite_repo,
        influx_repo=_FakeInfluxRepo(),
        defaults=Defaults(),
        pcap_url="http://fake:9090",
        stix_path=os.path.join(ROOT, "data", "ics-attack.json"),
    )
    return server


def test_tools_register_against_a_real_fastmcp(real_server):
    """Registration must not raise and must expose every tool."""
    tools = asyncio.run(real_server.list_tools())
    assert len(tools) == 64


def test_real_fastmcp_exposes_annotations_for_every_tool(real_server):
    tools = asyncio.run(real_server.list_tools())
    assert [t.name for t in tools if t.annotations is None] == []
    assert sum(1 for t in tools if t.annotations.readOnlyHint) == 45
    assert sum(1 for t in tools if t.annotations.destructiveHint) == 6


def test_real_fastmcp_builds_the_expected_input_schema(real_server):
    """Postponed annotations must be resolved into a real schema."""
    tools = {t.name: t for t in asyncio.run(real_server.list_tools())}
    schema = tools["postgres.read_bounds"].inputSchema
    assert set(schema["properties"]) == {"module", "series_id", "features"}
    assert tools["postgres.read_bounds"].description


def test_a_blocking_tool_does_not_stall_the_event_loop(real_server):
    """MCP-05: a slow query must not delay an unrelated tool call."""
    import time

    class _SlowRepo:
        def query_bounds(self, *args: Any, **kwargs: Any) -> pd.DataFrame:
            time.sleep(0.5)
            return pd.DataFrame()

        def __getattr__(self, _name: str):
            def _noop(*args: Any, **kwargs: Any) -> pd.DataFrame:
                return pd.DataFrame()

            return _noop

    import otalon_mcp.tools.postgres as pg_tools

    original = pg_tools.PG_REPO
    pg_tools.PG_REPO = _SlowRepo()
    try:

        async def scenario() -> float:
            slow = asyncio.create_task(
                real_server.call_tool("postgres.read_bounds", {"module": "conn", "series_id": "x"})
            )
            await asyncio.sleep(0.05)
            started = time.perf_counter()
            await real_server.call_tool("core.ping", {})
            latency = time.perf_counter() - started
            await slow
            return latency

        latency = asyncio.run(scenario())
    finally:
        pg_tools.PG_REPO = original

    assert latency < 0.2, f"ping blocked for {latency * 1000:.0f} ms behind a slow query"
