"""Key-optional NVD CVE source (Welle B / Task 2.2, D2).

Ports the PoC NVD client (``_nvd_request``, ``nvd_query_cpe``) to an
async-first :class:`~otalon_scan.cve_lookup.sources.base.CveSource`. The source
is **key-optional** (design.md § D2): with an NVD API key it uses the
higher rate limit (~50 req/30s ⇒ ~0.6 s spacing); without a key it falls
back to the conservative limit (~5 req/30s ⇒ ~6 s spacing). Requests run
sequentially with exponential backoff on transient failures, respecting
NVD throttling.

The CPE/firmware matching (:mod:`otalon_scan.cve_lookup.sources.matching`) and the
CVSS severity selection (:mod:`otalon_scan.cve_lookup.sources.severity`) are the
ported PoC logic; this module only adds the async HTTP transport and the
throttling/backoff policy around them.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import httpx
from loguru import logger

from .base import CveHit, LookupAsset
from .matching import (
    build_cpe_search_prefixes,
    device_matches,
    extract_cve_summary,
    model_tokens,
    normalise_version,
)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "otalon-ics/cve_lookup/1.0"

# Request spacing (seconds) by key presence — the key-optional throttling
# policy (design.md § D2). Without a key NVD allows ~5 req/30s; with a key
# ~50 req/30s. We stay safely inside both budgets.
DELAY_WITH_KEY_S = 0.6
DELAY_WITHOUT_KEY_S = 6.0

_DEFAULT_TIMEOUT_S = 30.0
_DEFAULT_PER_PAGE = 200
_MAX_RETRIES = 3
_BACKOFF_BASE_S = 2.0


class NvdSource:
    """Concrete :class:`CveSource` backed by the NIST NVD REST API.

    Args:
        api_key: Optional NVD API key. When present the source uses the
            higher-rate throttling path; when absent it uses the slower
            fallback path but remains fully functional.
        client: Optional injected :class:`httpx.AsyncClient` (tests pass a
            mock-transport client so no live network is touched). When
            ``None`` a client is created per :meth:`fetch` call.
        sleep: Injectable async sleep (tests pass a no-op to keep the
            throttling path fast and deterministic).
        per_page: NVD ``resultsPerPage`` for CPE queries.
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
        sleep: Any = asyncio.sleep,
        per_page: int = _DEFAULT_PER_PAGE,
    ) -> None:
        self._api_key = api_key or None
        self._client = client
        self._sleep = sleep
        self._per_page = per_page

    @property
    def request_delay_s(self) -> float:
        """Inter-request spacing for the active throttling path (D2)."""
        return DELAY_WITH_KEY_S if self._api_key else DELAY_WITHOUT_KEY_S

    @property
    def has_key(self) -> bool:
        """Whether the higher-rate (keyed) throttling path is active."""
        return self._api_key is not None

    async def fetch(self, asset: LookupAsset) -> list[CveHit]:
        """Return the CVEs that apply to ``asset`` (CveSource protocol).

        Queries NVD by every composed CPE prefix sequentially (with the
        active throttling delay between calls), de-duplicates envelopes by
        CVE id, then keeps only those whose CPE/firmware range covers the
        asset's firmware. Returns an empty list when the firmware cannot
        be parsed or no prefix is composable.
        """
        fw = normalise_version(asset.version)
        prefixes = build_cpe_search_prefixes(asset)
        if fw is None or not prefixes:
            logger.bind(op="nvd_fetch").debug(
                "skip device_id={} fw={} prefixes={}", asset.device_id, asset.version, len(prefixes)
            )
            return []
        envelopes = await self._collect_envelopes(prefixes)
        tokens = model_tokens(asset)
        return self._match_envelopes(envelopes, fw, asset.vendor, tokens)

    async def _collect_envelopes(self, prefixes: list[str]) -> list[dict[str, Any]]:
        """Query each CPE prefix sequentially, de-duplicating by CVE id."""
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_S)
        try:
            for idx, prefix in enumerate(prefixes):
                if idx > 0:
                    await self._sleep(self.request_delay_s)
                for env in await self._nvd_request(client, {"virtualMatchString": prefix}):
                    cid = env.get("cve", {}).get("id")
                    if cid and cid not in seen:
                        seen.add(cid)
                        out.append(env)
        finally:
            if owns_client:
                await client.aclose()
        return out

    def _match_envelopes(
        self,
        envelopes: list[dict[str, Any]],
        fw: tuple[int, ...],
        vendor: str,
        tokens: set[str],
    ) -> list[CveHit]:
        """Keep envelopes whose CPE/firmware range covers ``fw``; emit hits."""
        hits: list[CveHit] = []
        seen: set[str] = set()
        for env in envelopes:
            applies, fixed_in = device_matches(env, fw, expected_vendor=vendor, expected_model_tokens=tokens)
            if not applies:
                continue
            hit = extract_cve_summary(env)
            if hit.vuln_id in seen:
                continue
            seen.add(hit.vuln_id)
            if fixed_in:
                hit = hit.model_copy(update={"metadata": {**hit.metadata, "fixed_in": fixed_in}})
            hits.append(hit)
        hits.sort(key=lambda h: (-h.cvss_score, h.vuln_id))
        return hits

    async def _nvd_request(
        self,
        client: httpx.AsyncClient,
        params: dict[str, str],
    ) -> list[dict[str, Any]]:
        """GET the NVD CVE endpoint with exponential backoff on failure.

        Ported from the PoC ``_nvd_request`` (async transport). Retries
        transient failures up to :data:`_MAX_RETRIES` times with
        exponential backoff; returns an empty list when all attempts
        fail so a single bad query never aborts a whole lookup run.
        """
        query = {**params, "resultsPerPage": str(self._per_page)}
        headers = {"User-Agent": _USER_AGENT}
        if self._api_key:
            headers["apiKey"] = self._api_key
        for attempt in range(_MAX_RETRIES):
            try:
                resp = await client.get(NVD_BASE_URL, params=query, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                return list(vulns) if isinstance(vulns, list) else []
            except (httpx.HTTPError, ValueError) as exc:
                wait = _BACKOFF_BASE_S * (2**attempt)
                logger.bind(op="nvd_request").warning(
                    "NVD request failed (attempt {}/{}): {}; backoff {}s",
                    attempt + 1,
                    _MAX_RETRIES,
                    exc,
                    wait,
                )
                if attempt + 1 < _MAX_RETRIES:
                    await self._sleep(wait)
        return []
