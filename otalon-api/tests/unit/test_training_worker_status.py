"""Strict producer-shaped status decoding using a synthetic HTTP transport."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
import pytest
import respx

from otalon_api.services.pcap_import_worker_client import PcapImportWorkerClient

pytestmark = pytest.mark.unit
BASE = "http://worker.invalid"


def status_body(state: str = "completed", display_id: str | None = "J-1") -> dict[str, Any]:
    """Match exactly ImportStatus.model_dump(mode='json') emitted fields."""
    return dict(
        state=state,
        display_id=display_id,
        phase="finished",
        phase_current=3,
        phase_total=3,
        latest_event="Import settled",
        started_at="2026-06-01T10:00:00Z",
        finished_at="2026-06-01T10:01:00Z",
        error=None,
        result={"points_written": 7},
    )


@respx.mock
async def test_status_authenticated_exact_path_and_health_stays_keyless() -> None:
    """The existing configured key is routed only to approved control paths."""
    route = respx.get(f"{BASE}/status").respond(200, json=status_body())
    health = respx.get(f"{BASE}/health").respond(200, json={"busy": False, "state": "idle"})
    client = PcapImportWorkerClient(BASE, timeout=1.0, api_key="synthetic-key")
    snapshot = await client.status()
    assert snapshot.state == "completed" and snapshot.display_id == "J-1"
    assert snapshot.finished_at == datetime(2026, 6, 1, 10, 1, tzinfo=timezone.utc)
    assert snapshot.result == {"points_written": 7}
    assert route.calls[0].request.headers["X-API-Key"] == "synthetic-key"
    assert "timeout" in route.calls[0].request.extensions
    assert set(route.calls[0].request.extensions["timeout"].values()) == {1.0}
    await client.health()
    assert "X-API-Key" not in health.calls[0].request.headers


@pytest.mark.parametrize("state", ("idle", "running", "cancelling", "completed", "failed", "cancelled"))
@respx.mock
async def test_all_actual_worker_states_decode(state: str) -> None:
    """Wire vocabulary is the producer's, not the consumer job enum."""
    respx.get(f"{BASE}/status").respond(200, json=status_body(state))
    assert (await PcapImportWorkerClient(BASE, api_key="synthetic-key").status()).state == state


@pytest.mark.parametrize(
    "body",
    (
        None,
        [],
        {},
        {"state": "unknown"},
        {**status_body(), "extra": True},
        {**status_body(), "display_id": 1},
        {**status_body(), "display_id": "x" * 129},
        {**status_body(), "phase": "unknown"},
        {**status_body(), "phase_current": True},
        {**status_body(), "phase_current": -1},
        {**status_body(), "phase_current": 4},
        {**status_body(), "phase_total": "3"},
        {**status_body(), "phase_total": 4},
        {**status_body(), "latest_event": []},
        {**status_body(), "error": 3},
        {**status_body(), "started_at": 0},
        {**status_body(), "finished_at": "bad"},
        {**status_body(), "finished_at": "2026-06-01T10:01:00"},
        {**status_body(), "result": []},
        {**status_body(), "result": {"points_written": -1}},
        {**status_body(), "result": {"points_written": True}},
        {**status_body(), "result": {"time_start": 0}},
    ),
)
@respx.mock
async def test_malformed_unknown_or_unbounded_status_is_unknown(body: Any) -> None:
    """No type coercion can turn malformed data into settlement proof."""
    respx.get(f"{BASE}/status").respond(200, json=body)
    assert await PcapImportWorkerClient(BASE, api_key="synthetic-key").status() is None


@pytest.mark.parametrize("code,key", ((401, None), (403, "wrong"), (503, "synthetic-key")))
@respx.mock
async def test_status_auth_or_upstream_failure_is_unknown(code: int, key: str | None) -> None:
    """No alternate endpoint or credential is tried after a refusal."""
    route = respx.get(f"{BASE}/status").respond(code, json={"detail": "refused"})
    assert await PcapImportWorkerClient(BASE, api_key=key).status() is None
    assert route.call_count == 1
    assert route.calls[0].request.headers.get("X-API-Key") == key


@respx.mock
async def test_status_timeout_and_non_json_are_unknown() -> None:
    """Both transport and decoding failures remain unknown."""
    route = respx.get(f"{BASE}/status").mock(side_effect=httpx.ReadTimeout("synthetic timeout"))
    client = PcapImportWorkerClient(BASE, api_key="synthetic-key")
    assert await client.status() is None
    route.respond(200, text="not json")
    assert await client.status() is None


@respx.mock
async def test_no_configured_key_cannot_turn_a_200_into_authenticated_proof() -> None:
    """An accidental open upstream is not authenticated settlement evidence."""
    respx.get(f"{BASE}/status").respond(200, json=status_body())
    assert await PcapImportWorkerClient(BASE).status() is None


@respx.mock
async def test_status_body_budget_is_bounded_before_decoding() -> None:
    """An oversized result cannot become stop proof or an unbounded decoder input."""
    body = status_body()
    body["result"] = {"oversized": "x" * 65_536}
    respx.get(f"{BASE}/status").respond(200, json=body)
    assert await PcapImportWorkerClient(BASE, api_key="synthetic-key").status() is None
