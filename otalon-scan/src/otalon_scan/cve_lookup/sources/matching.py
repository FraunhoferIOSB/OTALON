"""Pure CPE / firmware-range matching ported from the PoC (Welle B, D7).

design.md § D7 mandates reusing the PoC's CPE/firmware-range matching
(``scripts/cve_lookup.py``) rather than reinventing it. This module ports
that logic — version normalisation, CPE-token extraction, the
range-inclusion check and the two-pass ``device_matches`` evaluator —
keeping it **pure** (no I/O) so it stays directly unit-testable and the
NVD source (:mod:`otalon_scan.cve_lookup.sources.nvd`) can apply it to recorded
or live envelopes identically.

The Siemens sub-model precedence (own CPU CPE beats sibling CPU CPE beats
family rollup) is preserved verbatim from the PoC because it is the
fact-critical part of avoiding false positives on ICS controllers.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .base import CveHit, LookupAsset
from .severity import select_cvss, severity_from_score

_VERSION_TOKEN_RE = re.compile(r"\d+")
_MODEL_NUMBER_RE = re.compile(
    r"\b[a-z]{1,4}\d{2,5}[a-z]?\b" r"|\b[a-z]{1,4}[\s_-]?\d{1,2}[\s_-]?\d{3,5}\b" r"|\bS7[\s_-]?\d{3,5}\b",
    re.IGNORECASE,
)
_RANGE_KEYS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)
_FAMILY_NAMESPACE_DIGITS = {"1200", "1500", "1700"}
_PRODUCT_SUFFIXES = ("firmware", "controller", "module")


def normalise_version(raw: str | None) -> tuple[int, ...] | None:
    """Convert a free-form firmware string to a comparable int tuple.

    ``"V4.0.4"`` → ``(4, 0, 4)``; ``"2025.0.3 (25.0.3.99)"`` →
    ``(2025, 0, 3)``. Returns ``None`` when no digit groups exist.
    Ported from the PoC ``normalise_version``.
    """
    if not raw:
        return None
    head = raw.split("(", 1)[0]
    parts = _VERSION_TOKEN_RE.findall(head)
    if not parts:
        return None
    return tuple(int(p) for p in parts)


def cmp_versions(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Return -1/0/+1 for ``a`` vs ``b`` (zero-padded). Ported from PoC."""
    pad = max(len(a), len(b))
    a2 = a + (0,) * (pad - len(a))
    b2 = b + (0,) * (pad - len(b))
    if a2 < b2:
        return -1
    if a2 > b2:
        return 1
    return 0


def _cpe_vendor(match: dict[str, Any]) -> str:
    """Lowercase vendor token from a CPE 2.3 ``criteria`` string."""
    parts = match.get("criteria", "").split(":")
    return parts[3].lower() if len(parts) > 3 else ""


def _cpe_product(match: dict[str, Any]) -> str:
    """Lowercase product token from a CPE 2.3 ``criteria`` string."""
    parts = match.get("criteria", "").split(":")
    return parts[4].lower() if len(parts) > 4 else ""


def _cpe_product_normalised(match: dict[str, Any]) -> str:
    """Product token with all non-alphanumerics stripped."""
    return re.sub(r"[^a-z0-9]", "", _cpe_product(match))


def _vendor_token(name: str) -> str:
    """First-word lowercase token of a vendor name. Ported from PoC."""
    return (name or "").strip().split()[0].lower() if name else ""


#: Map DB vendor names to the CPE vendor token that NVD actually uses.
#: The DB stores the legal entity name (e.g. from MAC-OUI or SNMP sysDescr),
#: but NVD CPEs use a short, often concatenated form. Without this map the
#: ``virtualMatchString`` CPE search returns zero results.
_VENDOR_TO_CPE: dict[str, str] = {
    "phoenix contact electronics gmbh": "phoenixcontact",
    "phoenix contact": "phoenixcontact",
    "siemens ag": "siemens",
    "siemens": "siemens",
    "abb ltd": "abb",
    "abb": "abb",
    "rockwell automation": "rockwellautomation",
    "rockwell": "rockwellautomation",
    "schneider electric": "schneiderelectric",
    "schneider": "schneiderelectric",
    "hirschmann automation and control gmbh": "belden",
    "hirschmann": "belden",
    "moxa inc.": "moxa",
    "moxa": "moxa",
    "wago kontakttechnik gmbh": "wago",
    "wago": "wago",
    "beckhoff automation gmbh": "beckhoff",
    "beckhoff": "beckhoff",
    "pilz gmbh": "pilz",
    "pilz": "pilz",
    "festo ag": "festo",
    "festo": "festo",
}


def _vendor_cpe_token(name: str) -> str:
    """Map a DB vendor name to the NVD CPE vendor token.

    Uses a lookup table for known vendors; falls back to underscored
    lowercase for unknown names (preserves the original PoC behaviour).
    """
    lower = (name or "").strip().lower()
    if not lower:
        return ""
    mapped = _VENDOR_TO_CPE.get(lower)
    if mapped:
        return mapped
    return re.sub(r"\s+", "_", lower)


def _family_prefix_token(model_token: str) -> str | None:
    """Derive a vendor-agnostic product-series prefix from a model token.

    Keeps the leading alphabetic run plus its first digit
    (``"xc208g"`` → ``"xc2"``, ``"m800"`` → ``"m8"``). This series root
    lets a generic family CPE (``scalance_xc-200``) align with a specific
    asset (``XC208G``) while still rejecting a sibling product
    (``scalance_m-800``) in the same multi-product CVE. Returns ``None``
    when the token has no ``<alpha><digit>`` head.
    """
    head = re.match(r"^([a-z]+)(\d)", model_token)
    return f"{head.group(1)}{head.group(2)}" if head else None


def model_tokens(asset: LookupAsset) -> set[str]:
    """Return distinctive model-number tokens for an asset.

    Ported from the PoC ``_model_tokens`` (operating on a
    :class:`LookupAsset` instead of a raw dict): mines ``product``,
    ``device_family``, ``article_number`` and ``description`` for
    identifiers like ``xc208g`` / ``s71500`` / ``bk9103`` and composes the
    Siemens ``1<XYZ>`` CPU token from an MLFB ``article_number`` when
    present.

    Mining ``product`` (e.g. ``"SCALANCE XC208G"``) and deriving a
    series-prefix token (``"xc2"``) is what keeps a multi-product CVE's
    sibling CPE (``scalance_m-800``) from leaking into the affected
    decision when ``device_family`` is empty, while still letting the
    generic family CPE (``scalance_xc-200``) align — a vendor-agnostic
    guard against cross-product false positives.
    """
    tokens: set[str] = set()
    fields = (
        ("product", asset.product),
        ("device_family", asset.device_family),
        ("article_number", asset.article_number),
        ("description", asset.description),
    )
    for key, value in fields:
        s = str(value or "")
        for m in _MODEL_NUMBER_RE.findall(s):
            normalised = re.sub(r"[^a-z0-9]", "", m.lower())
            if len(normalised) >= 4:
                tokens.add(normalised)
                prefix = _family_prefix_token(normalised)
                if prefix:
                    tokens.add(prefix)
        if key in {"product", "device_family"} and value:
            full = re.sub(r"[^a-z0-9]", "", s.lower())
            if len(full) >= 5:
                tokens.add(full)
    art = asset.article_number or ""
    sub = re.match(r"\s*[0-9]{1,2}[a-z]{2}[0-9]?\s+(\d{3})", art, re.IGNORECASE)
    if sub and sub.group(1).isdigit():
        tokens.add(f"1{sub.group(1)}")
    return tokens


def build_cpe_search_prefixes(asset: LookupAsset) -> list[str]:
    """Compose ``virtualMatchString`` CPE prefixes for an asset.

    Ported from the PoC ``build_cpe_search_prefixes``: best-effort CPE
    2.3 prefixes from vendor + family (+ Siemens MLFB sub-model) used to
    query NVD for CVEs whose description never names the product.
    Returns an empty list when the vendor cannot be tokenised.
    """
    vendor_cpe = _vendor_cpe_token(asset.vendor)
    if not vendor_cpe:
        return []
    candidates: list[str] = []
    family = (asset.device_family or asset.product or "").strip().lower()
    family_norm = re.sub(r"[\s/]+", "_", re.sub(r"[^a-z0-9\s\-/]", "", family)).strip("_-")
    suffix = ":*:*:*:*:*:*:*:*"
    if family_norm:
        candidates.append(f"cpe:2.3:o:{vendor_cpe}:{family_norm}_firmware{suffix}")
        candidates.append(f"cpe:2.3:o:{vendor_cpe}:{family_norm}{suffix}")
    art = asset.article_number or ""
    if family_norm and vendor_cpe == "siemens":
        m = re.match(r"\s*[0-9]{1,2}[a-z]{2}[0-9]?\s+(\d{3})", art, re.IGNORECASE)
        if m:
            candidates.append(f"cpe:2.3:o:{vendor_cpe}:{family_norm}_cpu_1{m.group(1)}_firmware{suffix}")
    return candidates


def _range_includes(match: dict[str, Any], fw: tuple[int, ...]) -> bool:
    """True iff ``fw`` lies inside the explicit range of ``match``. Ported from PoC."""
    start_inc = normalise_version(match.get("versionStartIncluding"))
    start_exc = normalise_version(match.get("versionStartExcluding"))
    end_inc = normalise_version(match.get("versionEndIncluding"))
    end_exc = normalise_version(match.get("versionEndExcluding"))
    if start_inc and cmp_versions(fw, start_inc) < 0:
        return False
    if start_exc and cmp_versions(fw, start_exc) <= 0:
        return False
    if end_inc and cmp_versions(fw, end_inc) > 0:
        return False
    if end_exc and cmp_versions(fw, end_exc) >= 0:
        return False
    return True


def _vendor_aligns(match: dict[str, Any], expected_vendor: str) -> bool:
    """Bidirectional substring vendor-token check (PoC semantics)."""
    cpe_v = _cpe_vendor(match)
    want = _vendor_token(expected_vendor)
    if not cpe_v or not want:
        return True
    return want in cpe_v or cpe_v in want


def _product_aligns(match: dict[str, Any], tokens: list[str]) -> bool:
    """Family + sub-model alignment check ported from ``_cpe_vendor_product_aligns``."""
    if not tokens:
        return True
    product_norm = _cpe_product_normalised(match)
    if not product_norm:
        return True
    sub_models = [t for t in tokens if t.isdigit() and 3 <= len(t) <= 4]
    family = [t for t in tokens if not (t.isdigit() and 3 <= len(t) <= 4)]
    if family and not any(t in product_norm for t in family):
        return False
    if sub_models and family:
        return _sub_model_aligns(product_norm, family, sub_models)
    if sub_models and not family:
        return any(s in product_norm for s in sub_models)
    return True


def _sub_model_aligns(product_norm: str, family: list[str], sub_models: list[str]) -> bool:
    """True if a family-wide CPE or one naming our sub-model (PoC trailing-digit rule)."""
    for fam in family:
        idx = product_norm.find(fam)
        if idx < 0:
            continue
        tail_subs = re.findall(r"\d{3,4}", product_norm[idx + len(fam) :])
        if not tail_subs:
            return True
        if any(s in tail_subs for s in sub_models):
            return True
    return False


def _iter_cpe_matches(envelope: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield every ``cpeMatch`` entry across an NVD envelope's configurations."""
    for config in envelope.get("cve", {}).get("configurations", []):
        for node in config.get("nodes", []):
            yield from node.get("cpeMatch", [])


def device_matches(
    envelope: dict[str, Any],
    fw: tuple[int, ...],
    *,
    expected_vendor: str = "",
    expected_model_tokens: Iterable[str] = (),
) -> tuple[bool, str | None]:
    """Two-pass evaluation: does ``envelope`` affect ``fw``? Ported from PoC.

    Range-pass: any vendor/model-aligned CPE whose explicit range
    *includes* ``fw`` makes the device affected; a range that *excludes*
    it is recorded as contrary evidence. Wildcard-fallback: a wildcard
    ("all versions") CPE only applies when no contrary range existed.
    Returns ``(applies, fixed_in)``.
    """
    tokens = list(expected_model_tokens)
    range_applies = False
    range_excludes = False
    wildcard_seen = False
    fixed_in: str | None = None
    for match in _iter_cpe_matches(envelope):
        if not match.get("vulnerable", False):
            continue
        if not _vendor_aligns(match, expected_vendor) or not _product_aligns(match, tokens):
            continue
        if any(match.get(k) for k in _RANGE_KEYS):
            if _range_includes(match, fw):
                range_applies = True
                end_ex = match.get("versionEndExcluding")
                if end_ex and not fixed_in:
                    fixed_in = end_ex
            else:
                range_excludes = True
            continue
        cpe_version = (match.get("criteria", "").split(":") + ["*"] * 6)[5]
        if cpe_version in {"*", "-", ""}:
            wildcard_seen = True
        else:
            cpe_tuple = normalise_version(cpe_version)
            if cpe_tuple and cmp_versions(fw, cpe_tuple) == 0:
                range_applies = True
    if range_applies:
        return True, fixed_in
    if wildcard_seen and not range_excludes:
        return True, None
    return False, None


def extract_cve_summary(envelope: dict[str, Any]) -> CveHit:
    """Flatten an NVD vulnerability envelope into a :class:`CveHit`.

    Ported from the PoC ``extract_cve_summary`` but emitting the typed
    :class:`CveHit`: severity is the highest standard CVSS base score
    (v3.1 preferred, design.md § D6) and every raw CVSS score plus the
    vector / references / NVD URL is retained in ``metadata``.
    """
    cve = envelope.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    desc_en = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    selection = select_cvss(cve.get("metrics", {}))
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    metadata: dict[str, Any] = {
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "description": desc_en,
        "cvss_score": selection.score,
        "cvss_version": selection.version,
        "cvss_raw_scores": selection.raw_scores,
        "vector": selection.vector,
        "published": cve.get("published"),
        "references": refs[:3],
    }
    summary = desc_en[:160] + ("…" if len(desc_en) > 160 else "")
    return CveHit(
        vuln_id=cve_id,
        severity=severity_from_score(selection.score),
        cvss_score=selection.score,
        summary=summary or None,
        metadata=metadata,
    )
