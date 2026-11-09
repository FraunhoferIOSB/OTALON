"""CVSS severity selection for CVE hits (Welle B / Task 2.5, D6).

The severity assigned to a :class:`~otalon_scan.cve_lookup.sources.base.CveHit`
is the **highest standard CVSS base score**, with CVSS v3.1 preferred
over v3.0 and both preferred over v2 when scores tie on priority
(design.md § D6). Every raw score across all CVSS versions present in
the NVD envelope is preserved in the hit's ``metadata`` so no
information is lost and the downstream UI / ICS-aware re-weighting
(SCAN-024) can re-derive severity later.

This module is pure (no I/O) so the selection rule is unit-testable
against a recorded multi-CVSS envelope.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

# NVD ``metrics`` keys in descending CVSS-version priority. v3.1 beats
# v3.0 beats v2 at equal base score; a strictly higher base score from a
# lower-priority version still wins (the spec asks for the *highest*
# standard base score).
_METRIC_KEYS: tuple[str, ...] = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


class CvssSelection(BaseModel):
    """Result of choosing a representative CVSS score for a CVE.

    Attributes:
        score: The chosen highest standard CVSS base score.
        version: The metric key the chosen score came from (e.g.
            ``"cvssMetricV31"``), or ``None`` when no metric was present.
        vector: The chosen metric's vector string, when available.
        raw_scores: Every standard base score keyed by metric version,
            preserved for ``metadata`` (design.md § D6).
    """

    model_config = ConfigDict(frozen=True)

    score: float
    version: Optional[str] = None
    vector: Optional[str] = None
    raw_scores: dict[str, float] = {}


def severity_from_score(score: float) -> str:
    """Map a CVSS base score onto the NVD qualitative severity band.

    Args:
        score: A CVSS base score in the ``0.0``–``10.0`` range.

    Returns:
        ``"critical"`` (≥9.0), ``"high"`` (≥7.0), ``"medium"`` (≥4.0),
        ``"low"`` (>0) or ``"none"`` (0). Ported verbatim from the PoC
        ``severity_from_score`` (``scripts/cve_lookup.py``).
    """
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def select_cvss(metrics: dict[str, Any]) -> CvssSelection:
    """Pick the highest standard CVSS base score from an NVD ``metrics``.

    Walks every standard CVSS version present, records each base score in
    ``raw_scores``, and selects the highest. Ties are broken by version
    priority (v3.1 > v3.0 > v2) because :data:`_METRIC_KEYS` is iterated
    in that order and a strictly-greater score is required to displace an
    already-chosen one.

    Args:
        metrics: The ``cve.metrics`` object from an NVD vulnerability
            envelope.

    Returns:
        A :class:`CvssSelection` carrying the chosen score plus every raw
        score for ``metadata``.
    """
    raw: dict[str, float] = {}
    best_score = 0.0
    best_version: Optional[str] = None
    best_vector: Optional[str] = None
    for key in _METRIC_KEYS:
        items = metrics.get(key)
        if not items:
            continue
        cvss = items[0].get("cvssData", {})
        score = float(cvss.get("baseScore", 0) or 0)
        raw[key] = score
        if best_version is None or score > best_score:
            best_score = score
            best_version = key
            best_vector = cvss.get("vectorString")
    return CvssSelection(
        score=best_score,
        version=best_version,
        vector=best_vector,
        raw_scores=raw,
    )
