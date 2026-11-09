"""Golden regression tests for the SCALANCE XC208G CVE false positives (SCAN-027).

A single Siemens CVE bundles dozens of products, each with its own
``cpeMatch`` carrying an independent fix-version range. Before the fix, a
*sibling* product's looser range (e.g. ``scalance_m-800_firmware`` fixed
at 6.4) leaked into the affected decision for our XC208G @ V4.3.1 — a
cross-product false positive — because an empty ``device_family``
degraded the model tokens to a near-useless set that no longer rejected
non-aligned product CPEs.

These tests pin the vendor-agnostic fix: product alignment must derive
tokens from the asset's ``product`` (``"SCALANCE XC208G"`` →
``xc208g`` + the ``xc2`` series prefix), so a sibling product CPE is
rejected while the generic ``scalance_xc-200`` family CPE still aligns.
The verdicts mirror the live NVD audit recorded in
``.dev/runtime/cve-falsepositive-audit.md`` / ``nvd_audit_v3.tsv``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from otalon_scan.cve_lookup.sources.base import LookupAsset
from otalon_scan.cve_lookup.sources.matching import device_matches, model_tokens, normalise_version

pytestmark = pytest.mark.unit

_FIXTURE = Path(__file__).parent / "fixtures" / "nvd_siemens_scalance_xc208g.json"

# Audit verdicts for SCALANCE XC208G @ V4.3.1 (.dev/runtime/cve-falsepositive-audit.md).
# The four False entries are the false positives this change removes; the two True
# entries are genuine matches that must keep matching (no over-strict regression).
_EXPECTED_APPLIES = {
    "CVE-2019-6569": False,
    "CVE-2020-28400": False,
    "CVE-2021-25667": False,
    "CVE-2021-3449": False,
    "CVE-2020-15800": True,
    "CVE-2017-12736": True,
}


@pytest.fixture
def envelopes() -> dict[str, dict[str, Any]]:
    """The recorded SCALANCE multi-product envelopes keyed by CVE id."""
    raw = json.loads(_FIXTURE.read_text())["vulnerabilities"]
    return {env["cve"]["id"]: env for env in raw}


@pytest.fixture
def xc208g_no_family() -> LookupAsset:
    """XC208G with an EMPTY ``device_family`` — the original FP trigger."""
    return LookupAsset(
        device_id=169684,
        vendor="Siemens",
        product="SCALANCE XC208G",
        version="V4.3.1",
        device_family=None,
        article_number="6GK5 208-0GA00-2AC2",
    )


@pytest.fixture
def xc208g_with_family() -> LookupAsset:
    """XC208G with a populated ``device_family`` (the SCAN-023 happy path)."""
    return LookupAsset(
        device_id=169684,
        vendor="Siemens",
        product="SCALANCE XC208G",
        version="V4.3.1",
        device_family="SCALANCE XC-200",
        article_number="6GK5 208-0GA00-2AC2",
    )


def test_literal_repro_sibling_range_does_not_apply() -> None:
    """The exact task repro: a sibling m-800 range must not mark us vulnerable.

    Our product's matching CPE (``scalance_xc-200``) says patched at 4.3
    (V4.3.1 is newer), so the looser ``scalance_m-800`` range (fixed 6.4)
    must NOT win even with the degraded weak token set.
    """
    fw = normalise_version("Version V04.03.01")
    assert fw == (4, 3, 1)
    env = {
        "cve": {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:siemens:scalance_xc-200_firmware:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "4.3",
                                },
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:siemens:scalance_m-800_firmware:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "6.4",
                                },
                            ]
                        }
                    ]
                }
            ]
        }
    }
    applies, fixed_in = device_matches(env, fw, expected_vendor="Siemens", expected_model_tokens={"1208"})
    assert applies is False
    assert fixed_in is None


def test_product_tokens_include_series_prefix(xc208g_no_family: LookupAsset) -> None:
    """``model_tokens`` mines ``product`` for the exact + series-prefix tokens."""
    tokens = model_tokens(xc208g_no_family)
    assert "xc208g" in tokens
    assert "xc2" in tokens


@pytest.mark.parametrize("cve_id", sorted(_EXPECTED_APPLIES))
def test_audit_verdicts_empty_family(
    envelopes: dict[str, dict[str, Any]],
    xc208g_no_family: LookupAsset,
    cve_id: str,
) -> None:
    """Each audited CVE yields its verdict with an EMPTY device_family."""
    fw = normalise_version(xc208g_no_family.version)
    assert fw is not None
    tokens = model_tokens(xc208g_no_family)
    applies, _ = device_matches(envelopes[cve_id], fw, expected_vendor="Siemens", expected_model_tokens=tokens)
    assert applies is _EXPECTED_APPLIES[cve_id]


@pytest.mark.parametrize("cve_id", sorted(_EXPECTED_APPLIES))
def test_audit_verdicts_populated_family(
    envelopes: dict[str, dict[str, Any]],
    xc208g_with_family: LookupAsset,
    cve_id: str,
) -> None:
    """The verdicts hold identically when ``device_family`` is populated."""
    fw = normalise_version(xc208g_with_family.version)
    assert fw is not None
    tokens = model_tokens(xc208g_with_family)
    applies, _ = device_matches(envelopes[cve_id], fw, expected_vendor="Siemens", expected_model_tokens=tokens)
    assert applies is _EXPECTED_APPLIES[cve_id]


def test_fixed_in_comes_from_aligned_cpe(
    envelopes: dict[str, dict[str, Any]],
    xc208g_no_family: LookupAsset,
) -> None:
    """``fixed_in`` for a genuine hit comes from our aligned CPE, not a sibling.

    CVE-2020-15800 lists the exact ``scalance_xc208g`` (fix 5.2.5) plus a
    sibling ``scalance_m-800`` (fix 6.4); the surfaced fix must be 5.2.5.
    """
    fw = normalise_version(xc208g_no_family.version)
    assert fw is not None
    tokens = model_tokens(xc208g_no_family)
    applies, fixed_in = device_matches(
        envelopes["CVE-2020-15800"], fw, expected_vendor="Siemens", expected_model_tokens=tokens
    )
    assert applies is True
    assert fixed_in == "5.2.5"
