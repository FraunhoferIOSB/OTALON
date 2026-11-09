"""Pure provider abstraction for CVE lookups (Welle B / Task 2.1, D2).

This module is the contract between the lookup core
(:func:`otalon_scan.cve_lookup.core.run_lookup`) and any concrete CVE data
source. It is intentionally **pure**: it carries no database driver and
no HTTP-client import, only value objects and a :class:`typing.Protocol`.
That keeps the interface trivially mypy-checkable and lets the core
depend on the abstraction rather than on NVD specifics (design.md § D2).

The first concrete implementation is
:class:`otalon_scan.cve_lookup.sources.nvd.NvdSource`; a ``CertVdeSource`` MAY
later sit behind the same protocol (implementation out of scope).
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class LookupAsset(BaseModel):
    """The identity an asset is looked up by (one ``devices`` row).

    Only the fields the CPE/firmware matching needs are carried. The
    cutoff gate (Welle A) guarantees ``vendor``, ``product`` and
    ``version`` are non-empty before an asset reaches a source, but the
    extra descriptors (``device_family``, ``article_number``,
    ``description``) sharpen the CPE/model-token matching ported from the
    PoC and are therefore optional.

    Attributes:
        device_id: PK of the parent ``devices`` row.
        vendor: Manufacturer name (e.g. ``"Siemens"``).
        product: Product name; maps onto ``devices.product_name``.
        version: Firmware version; maps onto ``devices.firmware_version``.
        device_family: Optional product family (e.g. ``"SIMATIC S7-1500"``).
        article_number: Optional vendor article/MLFB number.
        description: Optional free-form device description.
    """

    model_config = ConfigDict(frozen=True)

    device_id: int
    vendor: str
    product: str
    version: str
    device_family: Optional[str] = None
    article_number: Optional[str] = None
    description: Optional[str] = None


class CveHit(BaseModel):
    """One CVE that applies to a looked-up asset.

    This is the source-agnostic unit aggregated by the lookup core and
    later upserted into ``vulnerability_observations``. ``severity`` is
    the human-facing label (``critical``/``high``/``medium``/``low``/
    ``none``) derived from ``cvss_score`` — the highest standard CVSS
    base score (v3.1 preferred over v2, design.md § D6). All raw CVSS
    scores per version live in ``metadata`` so no information is lost.

    Attributes:
        vuln_id: The CVE id (e.g. ``"CVE-2024-12345"``) — the natural
            key half against ``(device_id, vuln_id)``.
        severity: Standard-CVSS severity label for ``cvss_score``.
        cvss_score: The highest standard CVSS base score selected.
        summary: Short human-readable description.
        metadata: Raw provenance — all CVSS scores per version, vector,
            references, CPE-match info, ``fixed_in`` when known.
    """

    model_config = ConfigDict(frozen=True)

    vuln_id: str
    severity: str
    cvss_score: float = 0.0
    summary: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class CveSource(Protocol):
    """Provider protocol: resolve an asset's applicable CVEs (D2).

    A concrete source implements a single asynchronous method,
    :meth:`fetch`, which returns every :class:`CveHit` that applies to
    the given :class:`LookupAsset`. Implementations own their own I/O,
    throttling and backoff; the lookup core only ever sees the resulting
    hits. ``@runtime_checkable`` lets tests assert ``isinstance`` against
    fakes without importing a concrete source.
    """

    async def fetch(self, asset: LookupAsset) -> list[CveHit]:
        """Return the CVEs that apply to ``asset``.

        Args:
            asset: The eligible asset's identity to look up.

        Returns:
            The applicable hits; an empty list when nothing matches.
        """
        ...
