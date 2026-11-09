"""Unit tests for outbound X-API-Key header injection in proxy services.

API-024: every proxy (SubagentService, ScanProxyService, PcapProxyService)
must send the ``X-API-Key`` header on both REST and SSE/streaming outbound
calls.  An empty key must produce a startup WARNING instead of silent
degradation.

Uses ``respx`` to mock upstream HTTP — asserts on the real request headers
sent by ``httpx``, not on helper return values.
"""

from __future__ import annotations

from typing import Iterator

import httpx
import pytest
import respx
from loguru import logger

from otalon_api.services.pcap_proxy_service import PcapProxyService
from otalon_api.services.scan_proxy_service import ScanProxyService
from otalon_api.services.subagent_service import SubagentService

UPSTREAM_AI = "http://otalon-ai:9100"
UPSTREAM_SCAN = "http://otalon-scan:8091"
UPSTREAM_PCAP = "http://pcap-recorder:9090"
API_KEY = "api024-test-key-xyz"

# ── Helpers ─────────────────────────────────────────────────────────


def _assert_carry_key(route: respx.Route, expected_key: str = API_KEY) -> None:
    """Assert the outbound request carried the expected X-API-Key."""
    assert route.called
    sent = route.calls.last.request
    assert sent.headers.get("X-API-Key") == expected_key


def _assert_no_key(route: respx.Route) -> None:
    """Assert the outbound request did NOT carry X-API-Key."""
    assert route.called
    sent = route.calls.last.request
    assert "X-API-Key" not in sent.headers


# ═══════════════════════════════════════════════════════════════════
#  1 — SubagentService
# ═══════════════════════════════════════════════════════════════════


@pytest.fixture()
def subagent_service() -> SubagentService:
    return SubagentService(base_url=UPSTREAM_AI, api_key=API_KEY, timeout=2.0)


@pytest.fixture()
def mock_ai() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False, base_url=UPSTREAM_AI) as mock:
        yield mock


@pytest.mark.asyncio
async def test_subagent_rest_sends_key(subagent_service: SubagentService, mock_ai: respx.MockRouter) -> None:
    """SubagentService REST call (start_classification) sends X-API-Key."""
    route = mock_ai.post("/jobs").mock(return_value=httpx.Response(200, json={"job_id": "j-1"}))
    result = await subagent_service.start_classification(alarm_id="a-1", payload={"trigger_source": "test"})
    assert result["job_id"] == "j-1"
    _assert_carry_key(route)


@pytest.mark.asyncio
async def test_subagent_sse_sends_key(subagent_service: SubagentService, mock_ai: respx.MockRouter) -> None:
    """SubagentService SSE stream sends X-API-Key."""
    payload = b'event: progress\ndata: {"pct": 50}\n\n'
    route = mock_ai.get("/jobs/j-1/events").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/event-stream"}, content=payload)
    )
    chunks: list[bytes] = []
    async for chunk in subagent_service.stream_events("j-1"):
        chunks.append(chunk)
    assert b"progress" in b"".join(chunks)
    _assert_carry_key(route)


# ═══════════════════════════════════════════════════════════════════
#  2 — ScanProxyService
# ═══════════════════════════════════════════════════════════════════


@pytest.fixture()
def scan_service() -> ScanProxyService:
    return ScanProxyService(base_url=UPSTREAM_SCAN, api_key=API_KEY, timeout=2.0)


@pytest.fixture()
def mock_scan() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False, base_url=UPSTREAM_SCAN) as mock:
        yield mock


@pytest.mark.asyncio
async def test_scan_rest_sends_key(scan_service: ScanProxyService, mock_scan: respx.MockRouter) -> None:
    """ScanProxyService REST call (_request) sends X-API-Key."""
    route = mock_scan.get("/modules").mock(return_value=httpx.Response(200, json={"modules": []}))
    status, body = await scan_service._request("GET", "/modules")
    assert status == 200
    _assert_carry_key(route)


@pytest.mark.asyncio
async def test_scan_sse_sends_key(scan_service: ScanProxyService, mock_scan: respx.MockRouter) -> None:
    """ScanProxyService SSE stream sends X-API-Key."""
    payload = b'event: progress\ndata: {"pct": 50}\n\n'
    route = mock_scan.get("/scans/s-1/events").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/event-stream"}, content=payload)
    )
    chunks: list[bytes] = []
    async for chunk in scan_service._stream("/scans/s-1/events"):
        chunks.append(chunk)
    assert b"progress" in b"".join(chunks)
    _assert_carry_key(route)


# ═══════════════════════════════════════════════════════════════════
#  3 — PcapProxyService
# ═══════════════════════════════════════════════════════════════════


@pytest.fixture()
def pcap_service() -> PcapProxyService:
    return PcapProxyService(base_url=UPSTREAM_PCAP, api_key=API_KEY, timeout=2.0)


@pytest.fixture()
def mock_pcap() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False, base_url=UPSTREAM_PCAP) as mock:
        yield mock


@pytest.mark.asyncio
async def test_pcap_rest_sends_key(pcap_service: PcapProxyService, mock_pcap: respx.MockRouter) -> None:
    """PcapProxyService REST call (_request) sends X-API-Key."""
    route = mock_pcap.get("/health").mock(return_value=httpx.Response(200, json={"status": "ok"}))
    status, body = await pcap_service._request("GET", "/health")
    assert status == 200
    _assert_carry_key(route)


@pytest.mark.asyncio
async def test_pcap_stream_sends_key(pcap_service: PcapProxyService, mock_pcap: respx.MockRouter) -> None:
    """PcapProxyService chunk stream sends X-API-Key."""
    chunk_data = b"\x00\x01\x02\x03" * 256
    route = mock_pcap.get("/chunks/test.pcap").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "application/octet-stream"},
            content=chunk_data,
        )
    )
    received = bytearray()
    async for piece in pcap_service.stream_chunk("test.pcap", byte_chunk_size=512):
        received.extend(piece)
    assert bytes(received) == chunk_data
    _assert_carry_key(route)


# ═══════════════════════════════════════════════════════════════════
#  4 — Empty key behaviour: no header sent
# ═══════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_subagent_empty_key_omits_header() -> None:
    """SubagentService with empty api_key does NOT send X-API-Key."""
    svc = SubagentService(base_url=UPSTREAM_AI, api_key="", timeout=2.0)
    with respx.mock(assert_all_called=False, base_url=UPSTREAM_AI) as mock:
        route = mock.post("/jobs").mock(return_value=httpx.Response(200, json={"job_id": "j-1"}))
        await svc.start_classification(alarm_id="a-1", payload={})
        _assert_no_key(route)


@pytest.mark.asyncio
async def test_pcap_empty_key_omits_header() -> None:
    """PcapProxyService with empty api_key does NOT send X-API-Key."""
    svc = PcapProxyService(base_url=UPSTREAM_PCAP, api_key="", timeout=2.0)
    with respx.mock(assert_all_called=False, base_url=UPSTREAM_PCAP) as mock:
        route = mock.get("/health").mock(return_value=httpx.Response(200, json={"status": "ok"}))
        await svc._request("GET", "/health")
        _assert_no_key(route)


# ═══════════════════════════════════════════════════════════════════
#  5 — Startup guard: empty key triggers WARNING
# ═══════════════════════════════════════════════════════════════════


def test_subagent_empty_key_warning() -> None:
    """SubagentService with empty api_key logs WARNING at init."""
    records: list[str] = []
    handler_id = logger.add(lambda msg: records.append(msg), format="{message}")
    try:
        SubagentService(base_url=UPSTREAM_AI, api_key="", timeout=2.0)
    finally:
        logger.remove(handler_id)
    assert any("no api_key configured" in r for r in records), records


def test_pcap_empty_key_warning() -> None:
    """PcapProxyService with empty api_key logs WARNING at init."""
    records: list[str] = []
    handler_id = logger.add(lambda msg: records.append(msg), format="{message}")
    try:
        PcapProxyService(base_url=UPSTREAM_PCAP, api_key="", timeout=2.0)
    finally:
        logger.remove(handler_id)
    assert any("no api_key configured" in r for r in records), records


def test_scan_nonempty_key_no_warning() -> None:
    """ScanProxyService with valid key does NOT log the warning."""
    records: list[str] = []
    handler_id = logger.add(lambda msg: records.append(msg), format="{message}")
    try:
        ScanProxyService(base_url=UPSTREAM_SCAN, api_key=API_KEY, timeout=2.0)
    finally:
        logger.remove(handler_id)
    assert not any("no api_key configured" in r for r in records), records
