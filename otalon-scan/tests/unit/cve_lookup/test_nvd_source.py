"""Unit tests for the key-optional NvdSource (Welle B / Task 2.2, D2).

No live network: a :class:`httpx.MockTransport` replays the recorded NVD
fixture, so the source's CPE-query → match pipeline is exercised
deterministically. Covers:

- a keyed and an un-keyed fetch both return ≥1 CVE (key-optional, D2);
- the no-key throttling path applies the slower spacing and the keyed
  path the faster spacing, asserted via the injected sleep recorder;
- a transient HTTP failure is retried with backoff and then yields no
  hits rather than raising.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from otalon_scan.cve_lookup.sources.base import LookupAsset
from otalon_scan.cve_lookup.sources.nvd import (
    DELAY_WITH_KEY_S,
    DELAY_WITHOUT_KEY_S,
    NvdSource,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "nvd_siemens_s7_1500.json"


@pytest.fixture
def fixture_payload() -> dict[str, Any]:
    """The recorded NVD response payload."""
    return dict(json.loads(_FIXTURE.read_text()))


@pytest.fixture
def s7_asset() -> LookupAsset:
    """An eligible Siemens S7-1500 CPU 1516-3 at firmware V2.9.0."""
    return LookupAsset(
        device_id=1,
        vendor="Siemens",
        product="S7-1500",
        version="V2.9.0",
        device_family="SIMATIC S7-1500",
        article_number="6ES7 516-3AP03-0AB0",
    )


def _replay_client(payload: dict[str, Any]) -> httpx.AsyncClient:
    """Return an AsyncClient whose transport replays ``payload`` for any GET."""

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    return httpx.AsyncClient(transport=httpx.MockTransport(_handler))


class _SleepRecorder:
    """Async no-op sleep that records the delays it was asked to wait."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


async def test_fetch_without_key_returns_hit(fixture_payload: dict[str, Any], s7_asset: LookupAsset) -> None:
    """No API key: the slow path still returns ≥1 deterministic CVE."""
    sleeper = _SleepRecorder()
    src = NvdSource(client=_replay_client(fixture_payload), sleep=sleeper)
    assert src.has_key is False
    assert src.request_delay_s == DELAY_WITHOUT_KEY_S
    hits = await src.fetch(s7_asset)
    assert [h.vuln_id for h in hits] == ["CVE-2022-30694"]
    assert hits[0].severity == "critical"
    assert hits[0].metadata["fixed_in"] == "2.9.2"


async def test_fetch_with_key_uses_fast_throttle(fixture_payload: dict[str, Any], s7_asset: LookupAsset) -> None:
    """With an API key: the fast spacing is applied between CPE queries."""
    sleeper = _SleepRecorder()
    src = NvdSource(api_key="secret", client=_replay_client(fixture_payload), sleep=sleeper)
    assert src.has_key is True
    assert src.request_delay_s == DELAY_WITH_KEY_S
    hits = await src.fetch(s7_asset)
    assert len(hits) >= 1
    # Multiple CPE prefixes → at least one inter-request delay, all keyed.
    assert sleeper.calls, "expected at least one throttling delay"
    assert all(d == DELAY_WITH_KEY_S for d in sleeper.calls)


async def test_no_key_throttle_uses_slow_spacing(fixture_payload: dict[str, Any], s7_asset: LookupAsset) -> None:
    """The no-key throttling path spaces requests at the slow rate (D2)."""
    sleeper = _SleepRecorder()
    src = NvdSource(client=_replay_client(fixture_payload), sleep=sleeper)
    await src.fetch(s7_asset)
    assert sleeper.calls, "expected at least one throttling delay"
    assert all(d == DELAY_WITHOUT_KEY_S for d in sleeper.calls)


async def test_transient_failure_retries_then_returns_empty(s7_asset: LookupAsset) -> None:
    """A persistent HTTP 503 is retried with backoff, then yields no hits."""
    attempts: list[int] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(503, json={"message": "service unavailable"})

    sleeper = _SleepRecorder()
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    src = NvdSource(client=client, sleep=sleeper)
    hits = await src.fetch(s7_asset)
    assert hits == []
    # At least one prefix retried _MAX_RETRIES (3) times.
    assert len(attempts) >= 3


async def test_unparsable_firmware_skips_without_request(s7_asset: LookupAsset) -> None:
    """An asset whose firmware has no digits is skipped (no network call)."""
    called: list[int] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        called.append(1)
        return httpx.Response(200, json={"vulnerabilities": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    src = NvdSource(client=client, sleep=_SleepRecorder())
    bad = s7_asset.model_copy(update={"version": "unknown"})
    hits = await src.fetch(bad)
    assert hits == []
    assert called == []
