"""Unit tests for the stateless lookup core (Welle B / Task 2.3, D3).

``run_lookup`` is exercised against a fake :class:`CveSource` — no network
and no database — pinning the spec scenario "Eligible asset with a
matching CPE yields a CVE hit": the core calls the source per asset,
aggregates the hits, and performs no DB write.
"""

from __future__ import annotations

from otalon_scan.cve_lookup.core import LookupResult, run_lookup
from otalon_scan.cve_lookup.sources.base import CveHit, CveSource, LookupAsset


class _FakeSource:
    """A deterministic in-memory CveSource keyed by device id."""

    def __init__(self, hits_by_device: dict[int, list[CveHit]]) -> None:
        self._hits = hits_by_device
        self.calls: list[int] = []

    async def fetch(self, asset: LookupAsset) -> list[CveHit]:
        self.calls.append(asset.device_id)
        return list(self._hits.get(asset.device_id, []))


def _asset(device_id: int) -> LookupAsset:
    return LookupAsset(
        device_id=device_id,
        vendor="Siemens",
        product="S7-1500",
        version="V2.9.0",
    )


def _hit(vuln_id: str, score: float) -> CveHit:
    return CveHit(vuln_id=vuln_id, severity="high", cvss_score=score)


async def test_run_lookup_aggregates_per_asset() -> None:
    """The core aggregates hits per asset and totals them (D3)."""
    source: CveSource = _FakeSource(
        {
            1: [_hit("CVE-1", 9.8), _hit("CVE-2", 7.1)],
            2: [],
        }
    )
    result = await run_lookup([_asset(1), _asset(2)], source)
    assert isinstance(result, LookupResult)
    assert result.assets_checked == 2
    assert result.total_hits == 2
    assert result.per_asset[0].device_id == 1
    assert [h.vuln_id for h in result.per_asset[0].hits] == ["CVE-1", "CVE-2"]
    assert result.per_asset[1].hits == []


async def test_run_lookup_calls_source_once_per_asset() -> None:
    """Each asset triggers exactly one source.fetch call, in order."""
    fake = _FakeSource({1: [_hit("CVE-1", 5.0)], 3: [_hit("CVE-9", 6.0)]})
    await run_lookup([_asset(1), _asset(3)], fake)
    assert fake.calls == [1, 3]


async def test_run_lookup_empty_asset_set() -> None:
    """An empty asset set yields an empty, zero-count result."""
    result = await run_lookup([], _FakeSource({}))
    assert result.assets_checked == 0
    assert result.total_hits == 0
    assert result.per_asset == []
