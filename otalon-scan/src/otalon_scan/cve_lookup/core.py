"""Stateless CVE lookup core (Welle B / Task 2.3, D3).

:func:`run_lookup` is the pure, stateless heart of the CVE pipeline: it
calls a :class:`~otalon_scan.cve_lookup.sources.base.CveSource` for every asset in
the set and aggregates the result into a :class:`LookupResult`. It
performs **no database write** (design.md § D3) — persistence is the
upsert repository's job (Task 2.4). Both triggers (the operator button
and the auto-loop) call this same function so their write behaviour is
identical (CONCEPT §10.5).

Because it is source-injected and DB-free, the core is unit-testable
against a fake :class:`CveSource` with no network and no Postgres.
"""

from __future__ import annotations

from typing import Callable, Iterable, Optional

from pydantic import BaseModel, ConfigDict, Field

from .sources.base import CveHit, CveSource, LookupAsset


class LookupCancelled(Exception):
    """Raised by :func:`run_lookup` when cooperative cancellation fires.

    The job wrapper (:mod:`otalon_scan.cve_lookup.job`) catches this to finalize
    the lookup as ``aborted`` (R-02) — distinct from a genuine failure,
    so an operator-requested Stop is recorded honestly rather than as a
    ``failed`` job.
    """


class AssetCves(BaseModel):
    """The CVE hits resolved for a single asset.

    Attributes:
        device_id: PK of the looked-up ``devices`` row.
        hits: The CVEs the source returned for this asset (possibly
            empty).
    """

    model_config = ConfigDict(frozen=True)

    device_id: int
    hits: list[CveHit]


class LookupResult(BaseModel):
    """Aggregated outcome of a :func:`run_lookup` call.

    Attributes:
        assets_checked: How many assets were looked up.
        total_hits: Total number of CVE hits across all assets.
        per_asset: One :class:`AssetCves` per input asset, preserving
            input order so callers can map results back to devices.
    """

    model_config = ConfigDict(frozen=True)

    assets_checked: int
    total_hits: int
    per_asset: list[AssetCves] = Field(default_factory=list)


async def run_lookup(
    asset_set: Iterable[LookupAsset],
    source: CveSource,
    *,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_asset: Optional[Callable[[int, int, AssetCves], None]] = None,
) -> LookupResult:
    """Look up CVEs for every asset via ``source`` and aggregate (D3).

    Pure and stateless: calls ``source.fetch`` once per asset, collects
    the hits, and returns a :class:`LookupResult`. Performs no DB write —
    the caller persists the result through the upsert repository.

    Cooperative cancellation (R-02): ``should_cancel`` is polled before
    each asset's NVD query. When it returns ``True`` the sweep stops
    issuing further queries and raises :class:`LookupCancelled` — the
    caller finalizes the job as ``aborted``. The check sits between
    assets, so a multi-asset lookup stops cleanly at the next iteration
    boundary rather than mid-query.

    Args:
        asset_set: The eligible assets to look up (already past the
            Welle A identity cutoff).
        source: The CVE provider to query per asset.
        should_cancel: Optional predicate polled before each asset; when
            it returns ``True`` the lookup raises :class:`LookupCancelled`.
        on_asset: Optional callback invoked after each asset is resolved
            with ``(index, total, asset_cves)`` so the caller can stream
            live per-asset progress during the sweep instead of only
            after it completes.

    Returns:
        A :class:`LookupResult` aggregating per-asset hits and totals.

    Raises:
        LookupCancelled: When ``should_cancel`` fires before an asset.
    """
    assets = list(asset_set)
    total_assets = len(assets)
    per_asset: list[AssetCves] = []
    total = 0
    for index, asset in enumerate(assets, start=1):
        if should_cancel is not None and should_cancel():
            raise LookupCancelled()
        hits = await source.fetch(asset)
        total += len(hits)
        resolved = AssetCves(device_id=asset.device_id, hits=hits)
        per_asset.append(resolved)
        if on_asset is not None:
            on_asset(index, total_assets, resolved)
    return LookupResult(
        assets_checked=len(per_asset),
        total_hits=total,
        per_asset=per_asset,
    )
