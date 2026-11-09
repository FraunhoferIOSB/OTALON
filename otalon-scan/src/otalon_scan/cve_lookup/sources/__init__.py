"""CVE source providers for the otalon-scan lookup core (Welle B).

A source is anything that, given a :class:`~otalon_scan.cve_lookup.sources.base.LookupAsset`
(an eligible device's identity), returns the list of CVEs that apply to
it. The provider abstraction (:class:`~otalon_scan.cve_lookup.sources.base.CveSource`,
design.md § D2) keeps the lookup core (:func:`otalon_scan.cve_lookup.core.run_lookup`)
independent of any concrete CVE data source, so a future ``CertVdeSource``
can sit behind the same interface without touching the core.

Public exports:

- :class:`CveHit` — one CVE applicable to an asset.
- :class:`LookupAsset` — the identity an asset is looked up by.
- :class:`CveSource` — the provider protocol (``fetch``).
- :class:`NvdSource` — the first concrete, key-optional NVD provider.
"""

from __future__ import annotations

from .base import CveHit, CveSource, LookupAsset
from .nvd import NvdSource

__all__ = [
    "CveHit",
    "CveSource",
    "LookupAsset",
    "NvdSource",
]
