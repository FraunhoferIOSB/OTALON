"""Unit tests for CVSS severity selection (Welle B / Task 2.5, D6).

Pins the spec scenario "Severity is the highest CVSS base with raw scores
retained": a CVE carrying both a v3.1 and a v2 base score SHALL resolve to
the highest standard base (v3.1 preferred) with every raw score kept.
"""

from __future__ import annotations

from otalon_scan.cve_lookup.sources.severity import select_cvss, severity_from_score


def test_severity_bands() -> None:
    """severity_from_score maps onto the NVD qualitative bands."""
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(4.0) == "medium"
    assert severity_from_score(0.1) == "low"
    assert severity_from_score(0.0) == "none"


def test_select_cvss_prefers_v31_and_keeps_raw_scores() -> None:
    """v3.1 wins over v2 and both raw scores are preserved (D6)."""
    metrics = {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "VEC31"}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 7.5, "vectorString": "VEC2"}}],
    }
    sel = select_cvss(metrics)
    assert sel.score == 9.8
    assert sel.version == "cvssMetricV31"
    assert sel.vector == "VEC31"
    assert sel.raw_scores == {"cvssMetricV31": 9.8, "cvssMetricV2": 7.5}


def test_select_cvss_higher_lower_priority_score_still_wins() -> None:
    """A strictly higher lower-priority base displaces a lower v3.1 base."""
    metrics = {
        "cvssMetricV31": [{"cvssData": {"baseScore": 3.0}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}],
    }
    sel = select_cvss(metrics)
    assert sel.score == 7.5
    assert sel.version == "cvssMetricV2"
    assert sel.raw_scores == {"cvssMetricV31": 3.0, "cvssMetricV2": 7.5}


def test_select_cvss_empty_metrics() -> None:
    """No metrics → score 0.0, no version, empty raw map."""
    sel = select_cvss({})
    assert sel.score == 0.0
    assert sel.version is None
    assert sel.raw_scores == {}
