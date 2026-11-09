import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pandas as pd
import pytest

# Optional dependencies for server smoke test
try:
    import influxdb_client_3  # noqa: F401

    HAS_INFLUX3 = True
except Exception:
    HAS_INFLUX3 = False

try:
    import mcp.server.fastmcp  # noqa: F401

    HAS_MCP = True
except Exception:
    HAS_MCP = False

# Ensure we can import from src

from otalon_mcp.mcp_tools import Defaults, init_mcp_tools

ROOT = os.path.dirname(os.path.dirname(__file__))


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


class FakePostgresRepo:
    def __init__(self) -> None:
        pass

    def query_bounds(
        self,
        module: str,
        series_id: Optional[str] = None,
        features: Optional[List[str]] = None,
    ) -> pd.DataFrame:
        lower = [
            {"packet_count": 1, "total_volume": 100},
            {"packet_count": 2, "total_volume": 200},
        ]
        upper = [
            {"packet_count": 10, "total_volume": 1000},
            {"packet_count": 20, "total_volume": 2000},
        ]
        df = pd.DataFrame(
            {
                "module": [module, module],
                "series_id": [series_id or "A", series_id or "B"],
                "lower_bounds": lower,
                "upper_bounds": upper,
                "trained_at": ["2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z"],
            }
        )
        return df

    def query_anomalies(
        self,
        module: str,
        series_id: Optional[str | int] = None,
        metric: Optional[str] = None,
        time_range: Optional[Sequence[str]] = None,
    ) -> pd.DataFrame:
        df = pd.DataFrame(
            {
                "module": [module] * 3,
                "series_id": [series_id or "A", series_id or "B", series_id or "C"],
                "metric": [metric or "packet_count"] * 3,
                "start_ts": ["2025-01-01T00:00:00Z"] * 3,
                "end_ts": ["2025-01-01T00:10:00Z"] * 3,
                "score": [0.1, 0.5, 0.9],
            }
        )
        return df

    def query_anomaly_groups(
        self,
        module: Optional[str] = None,
        type_: Optional[str] = None,
        confirmed: Optional[bool] = None,
        time_range: Optional[Sequence[str]] = None,
        limit: Optional[int] = None,
    ) -> pd.DataFrame:
        # Include a numpy-array-like column to verify robust serialization
        arr_col = [pd.Series([1, 2]).to_numpy(), pd.Series([3, 4]).to_numpy()]
        df = pd.DataFrame(
            {
                "module": [module or "netcap", module or "netcap"],
                "type": [type_ or "ALARM_X", type_ or "ALARM_Y"],
                "confirmed": [confirmed if confirmed is not None else False, True],
                "start_timestamp": [time_range[0] if time_range else "2025-01-01T00:00:00Z"] * 2,
                "end_timestamp": [time_range[1] if time_range else "2025-01-01T00:10:00Z"] * 2,
                "payload": arr_col,
            }
        )
        if isinstance(limit, int) and limit > 0:
            df = df.head(limit)
        return df

    def get_anomaly_group_by_id(self, alarm_id: str) -> pd.DataFrame:
        df = pd.DataFrame({"id": [alarm_id], "type": ["ALARM_X"], "confirmed": [False]})
        return df


class FakeInfluxRepo:
    def __init__(self) -> None:
        pass

    def list_ids(self, measurement: str, id_tag: str, minutes: int = 10) -> List[str]:
        return ["A", "B", "C"]

    def list_ids_between(
        self,
        measurement: str,
        id_tag: str,
        start: str,
        stop: str,
        nonzero: bool = False,
        fields: Optional[List[str]] = None,
        threshold: Optional[float] = 0.0,
    ) -> List[str]:
        return ["X", "Y"]

    def query_timeseries(
        self,
        measurement: str,
        id_tag: str,
        fields: List[str],
        start: str,
        stop: str,
        tags: Optional[Dict[str, str | int | float | bool]] = None,
        limit: Optional[int] = None,
        aggregate: Optional[str | Dict[str, str]] = None,
        sample_max_points: Optional[int] = None,
        preserve_extrema: bool = True,
    ) -> pd.DataFrame:
        # Construct a small DataFrame with a time index
        df = pd.DataFrame(
            {
                "time": ["2025-01-01T00:00:00Z", "2025-01-01T00:01:00Z"],
                fields[0]: [1, 2],
            }
        )
        df["time"] = pd.to_datetime(df["time"])
        df = df.set_index("time")
        return df

    def query_timeseries_multi_ids_chunked(
        self,
        measurement: str,
        id_tag: str,
        fields: List[str],
        start: str,
        stop: str,
        ids: Sequence[str],
        limit: Optional[int] = None,
        initial_chunk_size: int = 5000,
    ) -> pd.DataFrame:
        df = pd.DataFrame(
            {
                "time": ["2025-01-01T00:00:00Z", "2025-01-01T00:01:00Z"],
                id_tag: [ids[0], ids[-1]],
                fields[0]: [1, 2],
            }
        )
        return df


STIX_PATH = str(Path(__file__).resolve().parents[1] / "data" / "ics-attack.json")


def build_registered_tools() -> Dict[str, Any]:
    """Build a FakeMCP instance with all tools registered and return the tools dict."""
    mcp = FakeMCP()
    pg_repo = FakePostgresRepo()
    influx_repo = FakeInfluxRepo()
    defaults = Defaults()
    init_mcp_tools(
        mcp,
        pg_repo=pg_repo,
        influx_repo=influx_repo,
        defaults=defaults,
        pcap_url="http://fake:9090",
        stix_path=STIX_PATH,
    )
    return mcp.tools


def test_core_ping():
    tools = build_registered_tools()
    res = tools["core.ping"]()
    assert isinstance(res, dict)
    assert res.get("ok") is True
    assert res.get("message") == "pong"


def test_core_capabilities():
    tools = build_registered_tools()
    res = tools["core.capabilities"]()
    assert isinstance(res, dict)
    assert res.get("ok") is True
    assert "defaults" in res
    defaults = res["defaults"]
    assert "measurement" in defaults and "id_tag" in defaults and "fields" in defaults


def test_postgres_read_recent_alarms_serialization_arrays():
    tools = build_registered_tools()
    res = tools["postgres.read_recent_alarms"](minutes=60, limit=2)
    assert res["ok"] is True
    assert isinstance(res["records"], list)
    assert res["count"] == len(res["records"])
    # Ensure payload column (numpy arrays) serialized safely
    assert all(isinstance(rec.get("payload"), list) for rec in res["records"])


def test_postgres_get_top_alarm_counts():
    tools = build_registered_tools()
    res = tools["postgres.get_top_alarm_counts"](k=2, minutes=60)
    assert res["ok"] is True
    rows = res["rows"]
    assert isinstance(rows, list)
    assert res["k"] == len(rows)


def test_postgres_get_most_common_alarm():
    tools = build_registered_tools()
    res = tools["postgres.get_most_common_alarm"](minutes=60)
    assert res["ok"] is True
    assert "most_common" in res and isinstance(res["most_common"], str)


def test_postgres_read_bounds_flatten():
    tools = build_registered_tools()
    res = tools["postgres.read_bounds"]()
    assert res["ok"] is True
    assert isinstance(res["records"], list)
    # Records should contain lb_*/ub_* fields
    first = res["records"][0]
    has_lb = any(k.startswith("lb_") for k in first.keys())
    has_ub = any(k.startswith("ub_") for k in first.keys())
    assert has_lb and has_ub


def test_influx_list_recent_time_series_ids():
    tools = build_registered_tools()
    res = tools["influx.list_recent_time_series_ids"](minutes=5)
    assert res["ok"] is True
    assert res["count"] == len(res["ids"])
    assert res["ids"] == ["A", "B", "C"]


def test_influx_list_time_series_defaults_and_nonzero():
    tools = build_registered_tools()
    # defaults path (no start/stop)
    res = tools["influx.list_time_series"](nonzero=False)
    assert res["ok"] is True
    assert res["ids"] == ["X", "Y"]
    # nonzero path with fields/threshold
    res2 = tools["influx.list_time_series"](nonzero=True, fields=["packet_count"], threshold=1.0)
    assert res2["ok"] is True
    assert res2["ids"] == ["X", "Y"]


def test_influx_read_single_time_series_table_payload():
    tools = build_registered_tools()
    res = tools["influx.read_single_time_series"](series_id="A", fields=["packet_count"])
    assert res["ok"] is True
    data = res["data"]
    assert isinstance(data, dict)
    assert "columns" in data and "rows" in data and "rowcount" in data


def test_influx_read_multiple_time_series_fallback_ids():
    tools = build_registered_tools()
    res = tools["influx.read_multiple_time_series"](ids=None, fields=["packet_count"], default_recent_minutes=5)
    assert res["ok"] is True
    assert "ids" in res and isinstance(res["ids"], list)
    assert "data" in res and isinstance(res["data"], dict)


PCAP_TOOL_NAMES = [
    "pcap.health",
    "pcap.list_chunks",
    "pcap.list_anomaly_chunks",
    "pcap.get_chunks_by_alarm_id",
    "pcap.get_chunk_meta",
    "pcap.read_chunk_text",
    "pcap.analyze_chunk",
    "pcap.inspect_timewindow",
    "pcap.protocol_stats",
    "pcap.conversations",
    "pcap.io_stats",
    "pcap.flag_anomaly",
]


def test_pcap_tools_registered():
    tools = build_registered_tools()
    for name in PCAP_TOOL_NAMES:
        assert name in tools, f"Expected tool '{name}' to be registered but it was not found."


def test_pcap_tools_count():
    tools = build_registered_tools()
    registered_pcap = [k for k in tools if k.startswith("pcap.")]
    assert len(registered_pcap) == 14, f"Expected 14 pcap tools, got {len(registered_pcap)}: {registered_pcap}"


MITRE_TOOL_NAMES = [
    "mitre.list_tactics",
    "mitre.list_techniques",
    "mitre.get_technique_by_id",
    "mitre.get_techniques_by_tactic",
    "mitre.search_techniques",
    "mitre.get_subtechniques",
    "mitre.stats",
    "mitre.ping",
    "mitre.update_stix_data",
]


@pytest.mark.unit
def test_mitre_tools_registered():
    """All 9 MITRE tools are registered in the MCP server."""
    tools = build_registered_tools()
    for name in MITRE_TOOL_NAMES:
        assert name in tools, f"Expected tool '{name}' to be registered but it was not found."


@pytest.mark.unit
def test_mitre_tools_count():
    """Exactly 9 mitre.* tools are registered."""
    tools = build_registered_tools()
    registered_mitre = [k for k in tools if k.startswith("mitre.")]
    assert len(registered_mitre) == 9, f"Expected 9 mitre tools, got {len(registered_mitre)}: {registered_mitre}"


@pytest.mark.unit
def test_total_tool_count_after_integration():
    """Total tool count includes all registered MCP tools.

    Bumped from 50 -> 60 after the asset-CRUD batch (devices /
    network_interfaces, 10 new tools) shipped on
    ``night/2026-06-04-job1-mcp``: list/get/add/update/delete_device
    plus list/get/add/update/delete_interface.

    Bumped from 60 -> 62 by OpenSpec change
    ``add-chat-triggered-boundary-retraining``: two new tools
    ``training.retrain_boundaries`` + ``training.get_retrain_status``.

    Bumped from 62 -> 63 by OpenSpec change
    ``runtime-retraining-control-plane``: adds ``training.retrain_classifier``
    (runtime classifier retrain proxy, no container restart).

    Bumped from 63 -> 64: ``correct_rhythm_profile`` (frequency-profile
    correction) was registered without updating this count, leaving the
    assertion failing on ``main`` before MCP-013.
    """
    tools = build_registered_tools()
    assert len(tools) == 64, f"Expected 64 total tools, got {len(tools)}: {sorted(tools.keys())}"


@pytest.mark.unit
def test_mitre_ping_via_mcp():
    """mitre.ping returns 'pong' when called through FakeMCP."""
    tools = build_registered_tools()
    res = asyncio.get_event_loop().run_until_complete(tools["mitre.ping"]())
    assert res == "pong"


@pytest.mark.unit
def test_mitre_list_tactics_via_mcp():
    """mitre.list_tactics returns a non-empty list through FakeMCP."""
    tools = build_registered_tools()
    res = asyncio.get_event_loop().run_until_complete(tools["mitre.list_tactics"]())
    assert isinstance(res, list)
    assert len(res) > 0
    assert "tactic" in res[0]


@pytest.mark.unit
def test_mitre_search_via_mcp():
    """mitre.search_techniques finds results for known queries."""
    tools = build_registered_tools()
    res = asyncio.get_event_loop().run_until_complete(tools["mitre.search_techniques"](query="manipulation"))
    assert isinstance(res, dict)
    assert res.get("ok") is True
    assert len(res.get("techniques", res.get("results", []))) > 0


@pytest.mark.unit
def test_mitre_get_technique_via_mcp():
    """mitre.get_technique_by_id returns data for T0829."""
    tools = build_registered_tools()
    res = asyncio.get_event_loop().run_until_complete(tools["mitre.get_technique_by_id"](external_id="T0829"))
    assert isinstance(res, dict)
    assert res.get("ok") is True
    assert "T0829" in res.get("external_id", res.get("technique", {}).get("external_id", ""))


@pytest.mark.unit
def test_mitre_stats_via_mcp():
    """mitre.stats returns ok=True with technique count."""
    tools = build_registered_tools()
    res = asyncio.get_event_loop().run_until_complete(tools["mitre.stats"]())
    assert isinstance(res, dict)
    assert res.get("ok") is True
    assert isinstance(res.get("technique_count", res.get("techniques", 0)), int)


@pytest.mark.skipif(
    not HAS_INFLUX3 or not HAS_MCP,
    reason="Server smoke test requires influxdb_client_3 and mcp[fast] installed.",
)
def test_server_startup_smoke():
    """Start server with temporary environment and verify it runs and prints startup logs."""
    env = os.environ.copy()
    env["POSTGRES_DSN"] = "sqlite:///:memory:"
    env["INFLUX_URL"] = "http://localhost:8181"
    env["INFLUX_TOKEN"] = "dev-token"
    env["MCP_LOG_FILE"] = "otalon-mcp.log"
    env["PCAP_RECORDER_URL"] = "http://localhost:9090"
    env["OTALON_MCP_TRANSPORT"] = "streamable-http"
    # Launched as a module, not as a script path: after SUITE-032 the server
    # lives inside the ``otalon_mcp`` package, so ``src`` must be the sys.path
    # root rather than the file's own directory.
    env["PYTHONPATH"] = os.path.join(ROOT, "src")
    cmd = [sys.executable, "-m", "otalon_mcp.server"]
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        started = False
        uvicorn_running = False
        deadline = time.time() + 6.0
        buffer: List[str] = []
        while time.time() < deadline and proc.poll() is None:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            buffer.append(line)
            if "Starting OTALON MCP server" in line:
                started = True
            if "Uvicorn running on" in line:
                uvicorn_running = True
                break
        assert started or uvicorn_running, "Server did not print startup logs:\n" + "".join(buffer)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.mark.unit
def test_chat_tool_registered():
    """The chat tool is registered in the MCP server."""
    tools = build_registered_tools()
    assert "chat" in tools, "Expected 'chat' tool to be registered but it was not found."


@pytest.mark.unit
def test_chat_tool_returns_stub_response():
    """The chat tool returns a stub response string."""
    tools = build_registered_tools()
    result = tools["chat"](message="Hello")
    assert isinstance(result, str)
    assert "development" in result.lower() or "mcp" in result.lower()


@pytest.mark.unit
def test_chat_tool_accepts_history():
    """The chat tool accepts an optional history parameter."""
    tools = build_registered_tools()
    history = [
        {"role": "user", "content": "Hi"},
        {"role": "assistant", "content": "Hello"},
    ]
    result = tools["chat"](message="Follow up", history=history)
    assert isinstance(result, str)


@pytest.mark.unit
def test_validate_uuid_accepts_valid():
    """_validate_uuid returns None for a valid UUID."""
    from otalon_mcp.mcp_tools import _validate_uuid

    assert _validate_uuid("1088d146-d807-49d7-b10f-0dc7d7d918a9") is None
    assert _validate_uuid("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE") is None


@pytest.mark.unit
def test_validate_uuid_treats_empty_as_optional():
    """Empty / None values are not validated (caller decides)."""
    from otalon_mcp.mcp_tools import _validate_uuid

    assert _validate_uuid("") is None
    assert _validate_uuid(None) is None


@pytest.mark.unit
def test_validate_uuid_rejects_truncated():
    """Truncated UUIDs return an error with a hint about length."""
    from otalon_mcp.mcp_tools import _validate_uuid

    err = _validate_uuid("1088d146-d807", "alarm_id")
    assert err is not None
    assert err["ok"] is False
    assert "alarm_id" in err["error"]
    # Current _validate_uuid wording reports the observed character count
    # instead of using the word "truncated" — assert on the length hint.
    assert "characters" in err["error"].lower()


@pytest.mark.unit
def test_validate_uuid_rejects_extra_characters():
    """UUIDs longer than 36 chars return an error."""
    from otalon_mcp.mcp_tools import _validate_uuid

    err = _validate_uuid("1088d146-d807-49d7-b10f-0dc7d7d918a9XXX", "id")
    assert err is not None
    assert err["ok"] is False
    assert "characters" in err["error"].lower()


@pytest.mark.unit
def test_validate_uuid_rejects_wrong_format():
    """Garbage strings of length 36 still return an error."""
    from otalon_mcp.mcp_tools import _validate_uuid

    err = _validate_uuid("not-a-real-uuid-but-thirty-six-chars!!", "id")
    assert err is not None
    assert err["ok"] is False


@pytest.mark.unit
def test_postgres_read_alarm_details_validates_uuid():
    """postgres.read_alarm_details rejects invalid IDs without DB call."""
    tools = build_registered_tools()
    res = tools["postgres.read_alarm_details"](id="not-a-uuid")
    assert res["ok"] is False
    assert "Invalid ID" in res["error"]


@pytest.mark.unit
def test_pcap_get_chunks_by_alarm_id_validates_uuid():
    """pcap.get_chunks_by_alarm_id rejects invalid IDs without HTTP call."""
    tools = build_registered_tools()
    res = tools["pcap.get_chunks_by_alarm_id"](alarm_id="bogus")
    assert res["ok"] is False
    assert "Invalid ID" in res["error"]
    assert "alarm_id" in res["error"]
