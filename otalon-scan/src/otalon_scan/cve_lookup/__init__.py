"""CVE-Lookup asset-enrichment module (Feature 3, otalon-scan).

Sits beside :mod:`otalon_scan.passive_source` as a second asset-anrichment
surface (design.md § D1). Welle A shipped the identity-cutoff gate (D4):
the pure eligibility selector that decides which devices carry a complete
enough identity (vendor AND product AND version) to be queried against a
CVE source. Welle B adds the lookup core: the :class:`CveSource` provider
protocol, the key-optional :class:`NvdSource`, and the stateless,
DB-free :func:`run_lookup` aggregator. Welle C adds the trigger endpoint
(:func:`otalon_scan.api.server.lookup_vulnerabilities`) and the auto-loop
container (:mod:`otalon_scan.cve_lookup.entrypoint`).

Public exports:

- :class:`DeviceIdentity` — the identity view of a ``devices`` row.
- :class:`EligibilityResult` — eligible flag + missing-field list.
- :func:`evaluate_eligibility` — pure single-device cutoff evaluation.
- :func:`select_eligible` — pure batch partition over identities.
- :class:`CveSource` / :class:`NvdSource` — provider protocol + NVD impl.
- :class:`CveHit` / :class:`LookupAsset` — source value objects.
- :func:`run_lookup` / :class:`LookupResult` — stateless lookup core.
"""

from __future__ import annotations

from .core import AssetCves, LookupResult, run_lookup
from .eligibility import (
    DeviceIdentity,
    EligibilityResult,
    evaluate_eligibility,
    select_eligible,
)
from .job import LookupJobRegistry
from .sources import CveHit, CveSource, LookupAsset, NvdSource

__all__ = [
    "AssetCves",
    "CveHit",
    "CveSource",
    "DeviceIdentity",
    "EligibilityResult",
    "LookupAsset",
    "LookupJobRegistry",
    "LookupResult",
    "NvdSource",
    "evaluate_eligibility",
    "run_lookup",
    "select_eligible",
]
