"""Regression tests for the SUITE-044 P2 validation batch.

Covers the two missing-input-validation findings of the otalon-mcp
consistency re-audit:

* QUA-11 — tool input schemas carried no bounds/enums, so an
  LLM-supplied ``limit=-5`` or ``minutes=0`` reached the database layer.
* QUA-07 — ``chunk_id`` was interpolated into ``/chunks/{chunk_id}``
  unvalidated, so ``"../status"`` escaped the recorder's ``/chunks/``
  namespace and hit arbitrary pcap_recorder endpoints.

Both directions are asserted for every finding: an out-of-range or
traversal value must be REJECTED with a validation error, and a
realistic live value must still be ACCEPTED.
"""

import asyncio
import os
from typing import Any, Callable, Dict, List, cast
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from mcp.server.fastmcp import FastMCP

import otalon_mcp.validation as validation
from otalon_mcp.mcp_tools import Defaults, init_mcp_tools
from otalon_mcp.repositories.influx_repo import InfluxRepo
from otalon_mcp.repositories.postgres_repo import PostgresRepo
from otalon_mcp.tools import pcap as pcap_tools
from otalon_mcp.validation import ChunkIdError, ensure_chunk_id

ROOT = os.path.dirname(os.path.dirname(__file__))

pytestmark = pytest.mark.unit


# ── Fixtures ────────────────────────────────────────────────────────────


class _InertRepo:
    """Stand-in repository — these tests never reach a real backend.

    Mirrors the two return shapes of the real repositories: the asset CRUD
    helpers return a list of row mappings, everything else a DataFrame.
    """

    _RECORD_METHODS = ("list_devices", "list_interfaces", "get_device", "get_interface")

    def __getattr__(self, name: str) -> Callable[..., Any]:
        returns_records = name in self._RECORD_METHODS

        def _call(*args: Any, **kwargs: Any) -> Any:
            return [] if returns_records else pd.DataFrame()

        return _call


@pytest.fixture(scope="module")
def server() -> FastMCP:
    """A real FastMCP instance with every tool registered.

    A real server (not the ``FakeMCP`` double used elsewhere) is required
    here: the point of QUA-11 is that the constraint must survive into the
    schema FastMCP publishes AND be enforced by its Pydantic argument
    model before the handler body runs.
    """
    mcp = FastMCP("suite044-probe")
    init_mcp_tools(
        mcp,
        # ``_InertRepo`` satisfies the runtime contract via ``__getattr__``
        # but is not a nominal subclass of the concrete repository types.
        pg_repo=cast(PostgresRepo, _InertRepo()),
        influx_repo=cast(InfluxRepo, _InertRepo()),
        defaults=Defaults(),
        pcap_url="http://fake:9090",
        stix_path=os.path.join(ROOT, "data", "ics-attack.json"),
    )
    return mcp


@pytest.fixture(scope="module")
def schemas(server: FastMCP) -> Dict[str, Dict[str, Any]]:
    """Map tool name to its published JSON input schema."""
    tools = asyncio.run(server.list_tools())
    return {tool.name: tool.inputSchema for tool in tools}


@pytest.fixture(autouse=True)
def _init_pcap() -> None:
    """Point the pcap helpers at a fake recorder before every test."""
    pcap_tools.init(pcap_url="http://fake:9090", timeout=5)


def _mock_response(text: str = "", json_data: Any = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = text
    resp.json.return_value = {} if json_data is None else json_data
    resp.raise_for_status = MagicMock()
    return resp


def _call(server: FastMCP, name: str, args: Dict[str, Any]) -> Any:
    return asyncio.run(server.call_tool(name, args))


def _property(schemas: Dict[str, Dict[str, Any]], tool: str, param: str) -> Dict[str, Any]:
    prop: Dict[str, Any] = schemas[tool]["properties"][param]
    return prop


def _numeric_variants(prop: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the schema branches that describe a number, incl. ``anyOf``."""
    branches = [prop, *prop.get("anyOf", [])]
    return [b for b in branches if b.get("type") in ("integer", "number")]


# ── QUA-11: bounds reach the published input schema ─────────────────────


@pytest.mark.parametrize(
    ("tool", "param", "minimum", "maximum"),
    [
        ("postgres.read_anomalies", "limit", 1, validation.MAX_ROW_LIMIT),
        ("postgres.read_alarms", "limit", 1, validation.MAX_ROW_LIMIT),
        ("postgres.read_recent_alarms", "minutes", 1, validation.MAX_WINDOW_MINUTES),
        ("postgres.list_devices", "offset", 0, validation.MAX_ROW_OFFSET),
        ("postgres.get_top_alarm_counts", "k", 1, validation.MAX_TOP_K),
        ("pcap.read_chunk_text", "max_lines", 1, validation.MAX_OUTPUT_LINES),
        ("pcap.io_stats", "interval_sec", 1, validation.MAX_INTERVAL_SECONDS),
        ("mitre.search_techniques", "limit", 1, validation.MAX_MITRE_LIMIT),
        ("core.web_search_duckduckgo", "max_results", 1, validation.MAX_SEARCH_RESULTS),
        ("agent.classify_alert", "timeout_seconds", 1, validation.MAX_TIMEOUT_SECONDS),
    ],
)
def test_numeric_bounds_are_published_in_the_input_schema(
    schemas: Dict[str, Dict[str, Any]],
    tool: str,
    param: str,
    minimum: int,
    maximum: int,
) -> None:
    """The model must SEE the constraint, not just be rejected by it."""
    variants = _numeric_variants(_property(schemas, tool, param))
    assert variants, f"{tool}.{param} is not a numeric schema"
    assert variants[0]["minimum"] == minimum
    assert variants[0]["maximum"] == maximum


def test_every_numeric_tool_parameter_carries_a_lower_bound(
    schemas: Dict[str, Dict[str, Any]],
) -> None:
    """No int/float tool argument may reach a backend unconstrained.

    ``threshold`` and the rhythm ``*_factor_override`` parameters are
    genuinely open-ended magnitudes (a traffic-volume floor and two
    tolerance multipliers), not resource limits, so they are exempt.
    """
    exempt = {
        ("influx.list_time_series", "threshold"),
        ("influx.list_baseline_time_series", "threshold"),
        ("correct_rhythm_profile", "tolerance_factor_override"),
        ("correct_rhythm_profile", "absence_factor_override"),
    }
    unbounded = [
        f"{tool}.{param}"
        for tool, schema in schemas.items()
        for param, prop in schema.get("properties", {}).items()
        if _numeric_variants(prop)
        and not any("minimum" in v for v in _numeric_variants(prop))
        and (tool, param) not in exempt
    ]
    assert not unbounded, f"unbounded numeric parameters: {sorted(unbounded)}"


# ── QUA-11: out-of-range input is rejected before the backend ───────────


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("postgres.read_anomalies", {"limit": -5}),
        ("postgres.read_anomalies", {"limit": 0}),
        ("postgres.read_anomalies", {"limit": validation.MAX_ROW_LIMIT + 1}),
        ("postgres.read_alarms", {"limit": -1}),
        ("postgres.read_recent_alarms", {"minutes": 0}),
        ("postgres.read_recent_alarms", {"minutes": -120}),
        ("postgres.list_devices", {"offset": -1}),
        ("postgres.list_devices", {"limit": 0}),
        ("postgres.get_top_alarm_counts", {"k": 0}),
        ("postgres.get_device", {"device_id": 0}),
        ("postgres.get_device", {"device_id": -3}),
        ("pcap.read_chunk_text", {"chunk_id": "20260225_133027.pcap", "max_lines": 0}),
        ("pcap.io_stats", {"chunk_id": "20260225_133027.pcap", "interval_sec": 0}),
        ("pcap.list_chunks", {"last_hours": -1}),
        ("mitre.search_techniques", {"query": "modbus", "limit": 0}),
        ("core.web_search_duckduckgo", {"query": "opc ua", "max_results": -2}),
        ("agent.classify_alert", {"alarm_id": "a" * 32, "timeout_seconds": 0}),
    ],
)
def test_out_of_range_arguments_are_rejected(server: FastMCP, tool: str, args: Dict[str, Any]) -> None:
    """``limit=-5`` must never reach the DB layer (audit QUA-11)."""
    with pytest.raises(Exception) as excinfo:
        _call(server, tool, args)
    assert "validation error" in str(excinfo.value).lower()


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("postgres.read_anomalies", {"limit": 100}),
        ("postgres.read_alarms", {"limit": 200, "default_window_minutes": 1440}),
        ("postgres.read_recent_alarms", {"minutes": 120, "limit": 50}),
        ("postgres.list_devices", {"limit": 200, "offset": 0}),
        ("postgres.get_top_alarm_counts", {"k": 10, "minutes": 1440}),
        ("postgres.list_interfaces", {"device_id": 0}),
        ("mitre.search_techniques", {"query": "modbus", "limit": 10}),
    ],
)
def test_realistic_arguments_still_pass_validation(server: FastMCP, tool: str, args: Dict[str, Any]) -> None:
    """The shipped defaults and live-scale values must remain accepted."""
    result = _call(server, tool, args)
    assert result is not None


def test_live_scale_values_are_within_the_caps() -> None:
    """Caps sit far above the largest values observed in the live system.

    Live maxima at the time of the fix: 1.40M anomaly rows, 3624 alarms,
    ~11.7k recorder chunks, a 25-day alarm history (~35.4k minutes) and
    device/interface ids below 1.4M.
    """
    assert validation.MAX_ROW_LIMIT >= 100_000
    assert validation.MAX_ROW_OFFSET >= 1_403_523
    assert validation.MAX_WINDOW_MINUTES >= 35_417
    assert validation.MAX_CHUNK_COUNT >= 11_650
    assert validation.MAX_ROW_ID >= 1_342_850


# ── QUA-11: enum parameters ─────────────────────────────────────────────


def test_conversation_layer_is_published_as_an_enum(
    schemas: Dict[str, Dict[str, Any]],
) -> None:
    prop = _property(schemas, "pcap.conversations", "layer")
    assert prop["enum"] == ["eth", "ip", "tcp", "udp"]


def test_conversation_layer_rejects_an_unknown_value(server: FastMCP) -> None:
    with pytest.raises(Exception):
        _call(
            server,
            "pcap.conversations",
            {"chunk_id": "20260225_133027.pcap", "layer": "evil"},
        )


def test_prompt_variant_is_published_as_an_enum(
    schemas: Dict[str, Dict[str, Any]],
) -> None:
    prop = _property(schemas, "agent.classify_alert", "prompt_variant")
    assert prop["enum"] == ["open", "expert"]


# ── QUA-07: chunk_id identifier format ──────────────────────────────────


@pytest.mark.parametrize(
    "chunk_id",
    [
        "20260225_133027.pcap",
        "20260831_115454.pcap",
        "20260513_223218.pcap.gz",
        "20260513_223218.pcap.zst",
        "20260513_223218.pcap.l19.zst",
    ],
)
def test_ensure_chunk_id_accepts_real_recorder_filenames(chunk_id: str) -> None:
    """Every shape present on the live recorder must stay usable."""
    assert ensure_chunk_id(chunk_id) == chunk_id


@pytest.mark.parametrize(
    "payload",
    [
        "../status",
        "../../etc/passwd",
        "..%2fstatus",
        "/health",
        "20260225_133027.pcap/../../health",
        "20260225_133027.pcap?format=text",
        "20260225_133027.pcap#frag",
        "chunk with spaces.pcap",
        "test.pcap",
        "20260225_133027.pcapX",
        "",
        "   ",
    ],
)
def test_ensure_chunk_id_rejects_traversal_and_junk(payload: str) -> None:
    """The live PoC (``"../status"``) must not survive validation."""
    with pytest.raises(ChunkIdError):
        ensure_chunk_id(payload)


def test_ensure_chunk_id_rejects_an_over_long_value() -> None:
    with pytest.raises(ChunkIdError) as excinfo:
        ensure_chunk_id("2" * (validation.CHUNK_ID_MAX_LENGTH + 1))
    assert "exceeds" in str(excinfo.value)


def test_chunk_id_pattern_is_published_in_the_input_schema(
    schemas: Dict[str, Dict[str, Any]],
) -> None:
    """The model should see the identifier format, not guess it."""
    for tool in (
        "pcap.get_chunk_meta",
        "pcap.read_chunk_text",
        "pcap.analyze_chunk",
        "pcap.inspect_timewindow",
        "pcap.protocol_stats",
        "pcap.conversations",
        "pcap.io_stats",
    ):
        prop = _property(schemas, tool, "chunk_id")
        assert prop["pattern"] == validation.CHUNK_ID_PATTERN
        assert prop["maxLength"] == validation.CHUNK_ID_MAX_LENGTH


@pytest.mark.parametrize(
    "tool",
    [
        "pcap.get_chunk_meta",
        "pcap.read_chunk_text",
        "pcap.analyze_chunk",
        "pcap.inspect_timewindow",
        "pcap.protocol_stats",
        "pcap.conversations",
        "pcap.io_stats",
    ],
)
def test_traversal_chunk_id_is_rejected_by_every_pcap_tool(server: FastMCP, tool: str) -> None:
    """No pcap.* tool may forward ``"../status"`` to the recorder."""
    with pytest.raises(Exception) as excinfo:
        _call(server, tool, {"chunk_id": "../status"})
    assert "validation error" in str(excinfo.value).lower()


@patch("otalon_mcp.tools.pcap.requests.get")
def test_helper_rejects_traversal_without_issuing_a_request(mock_get: MagicMock) -> None:
    """Defence in depth: the helper itself must not call the recorder."""
    result = pcap_tools.get_chunk_meta(chunk_id="../status")
    assert result["ok"] is False
    assert "not a chunk identifier" in result["error"]
    mock_get.assert_not_called()


@pytest.mark.parametrize(
    ("helper", "kwargs"),
    [
        (pcap_tools.get_chunk_meta, {}),
        (pcap_tools.read_chunk_text, {"max_lines": 10}),
        (pcap_tools.analyze_chunk, {"tshark_args": "-c 5"}),
        (pcap_tools.inspect_timewindow, {"start_sec": 0.0, "end_sec": 1.0}),
        (pcap_tools.protocol_stats, {}),
        (pcap_tools.conversations, {"layer": "ip"}),
        (pcap_tools.io_stats, {"interval_sec": 1}),
    ],
)
@patch("otalon_mcp.tools.pcap.requests.get")
def test_every_helper_guards_its_chunk_path(
    mock_get: MagicMock, helper: Callable[..., Dict[str, Any]], kwargs: Dict[str, Any]
) -> None:
    result = helper(chunk_id="/health", **kwargs)
    assert result["ok"] is False
    mock_get.assert_not_called()


@patch("otalon_mcp.tools.pcap.requests.get")
def test_valid_chunk_id_still_reaches_the_recorder_path(mock_get: MagicMock) -> None:
    """A realistic identifier must produce the unchanged request URL."""
    mock_get.return_value = _mock_response(json_data={"chunk_id": "20260225_133027.pcap"})
    result = pcap_tools.get_chunk_meta(chunk_id="20260225_133027.pcap")
    assert result["ok"] is True
    url = mock_get.call_args.args[0]
    assert url == "http://fake:9090/chunks/20260225_133027.pcap"


@patch("otalon_mcp.tools.pcap.requests.get")
def test_valid_chunk_id_is_accepted_end_to_end(mock_get: MagicMock, server: FastMCP) -> None:
    """The full tool path accepts a live chunk identifier."""
    mock_get.return_value = _mock_response(text="line-1\nline-2\n")
    result = _call(
        server,
        "pcap.read_chunk_text",
        {"chunk_id": "20260831_115454.pcap", "max_lines": 50},
    )
    assert result is not None
    assert mock_get.call_args.args[0].endswith("/chunks/20260831_115454.pcap")
