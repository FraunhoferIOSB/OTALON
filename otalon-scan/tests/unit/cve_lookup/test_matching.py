"""Unit tests for the ported PoC CPE/firmware matching (Welle B, D7).

Exercises the pure matching logic against the recorded NVD fixture so the
port from ``scripts/cve_lookup.py`` is pinned: an in-range own-CPU CVE
applies, a sibling-CPU CVE is rejected, and version normalisation /
CPE-prefix composition behave as in the PoC.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from otalon_scan.cve_lookup.sources.base import LookupAsset
from otalon_scan.cve_lookup.sources.matching import (
    build_cpe_search_prefixes,
    cmp_versions,
    device_matches,
    extract_cve_summary,
    model_tokens,
    normalise_version,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "nvd_siemens_s7_1500.json"


@pytest.fixture
def envelopes() -> list[dict[str, Any]]:
    """Load the recorded NVD vulnerabilities array."""
    return list(json.loads(_FIXTURE.read_text())["vulnerabilities"])


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


def test_normalise_and_cmp_versions() -> None:
    """Version normalisation + comparison match the PoC semantics."""
    assert normalise_version("V2.9.0") == (2, 9, 0)
    assert normalise_version("2025.0.3 (25.0.3.99)") == (2025, 0, 3)
    assert normalise_version("none") is None
    assert cmp_versions((2, 9), (2, 9, 0)) == 0
    assert cmp_versions((2, 9, 1), (2, 9, 2)) == -1


def test_model_tokens_extracts_cpu_submodel(s7_asset: LookupAsset) -> None:
    """The Siemens MLFB article yields the ``1516`` CPU token + family."""
    tokens = model_tokens(s7_asset)
    assert "1516" in tokens
    assert "s71500" in tokens


def test_build_cpe_prefixes_includes_submodel(s7_asset: LookupAsset) -> None:
    """A Siemens asset gets family + sub-model CPU CPE prefixes."""
    prefixes = build_cpe_search_prefixes(s7_asset)
    assert any("simatic_s7-1500_firmware" in p for p in prefixes)
    assert any("_cpu_1516_firmware" in p for p in prefixes)


def test_own_cpu_cve_applies(envelopes: list[dict[str, Any]], s7_asset: LookupAsset) -> None:
    """The in-range own-CPU CVE applies; ``fixed_in`` is surfaced."""
    fw = normalise_version(s7_asset.version)
    assert fw is not None
    tokens = model_tokens(s7_asset)
    applies, fixed_in = device_matches(envelopes[0], fw, expected_vendor=s7_asset.vendor, expected_model_tokens=tokens)
    assert applies is True
    assert fixed_in == "2.9.2"


def test_sibling_cpu_cve_rejected(envelopes: list[dict[str, Any]], s7_asset: LookupAsset) -> None:
    """A CVE for a sibling 1511c CPU does NOT apply to our 1516-3."""
    fw = normalise_version(s7_asset.version)
    assert fw is not None
    tokens = model_tokens(s7_asset)
    applies, _ = device_matches(envelopes[1], fw, expected_vendor=s7_asset.vendor, expected_model_tokens=tokens)
    assert applies is False


def test_extract_cve_summary_is_typed_hit(envelopes: list[dict[str, Any]]) -> None:
    """extract_cve_summary emits a CveHit with severity + raw scores."""
    hit = extract_cve_summary(envelopes[0])
    assert hit.vuln_id == "CVE-2022-30694"
    assert hit.severity == "critical"
    assert hit.cvss_score == 9.8
    assert hit.metadata["cvss_raw_scores"] == {
        "cvssMetricV31": 9.8,
        "cvssMetricV2": 7.5,
    }
