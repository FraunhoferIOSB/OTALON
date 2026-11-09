"""Reverse-lookup helper for proto_traffic hash-encoded series_ids.

Builds and caches a hash → protocol map by querying the distinct
``protocol`` tag values from InfluxDB and hashing them with the same
stable ``proto_series_hash`` used by the detection pipeline.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from loguru import logger

from otalon_api.domain.netcap.models import proto_series_hash

if TYPE_CHECKING:
    from otalon_api.repositories.influx_repo import InfluxRepository


class ProtoHashResolver:
    """Resolves proto series_id hashes back to human-readable protocol strings."""

    def __init__(self, influx_repo: InfluxRepository, ttl_seconds: float = 300.0) -> None:
        """Initialize the resolver with an InfluxDB repository.

        Args:
            influx_repo: Repository used to refresh the protocol vocabulary.
            ttl_seconds: Cache time-to-live in seconds (default 5 min).
        """
        self._influx_repo = influx_repo
        self._ttl = max(0.0, ttl_seconds)
        self._cache: dict[str, str] = {}
        self._last_refresh: float = 0.0

    def resolve(self, hash_value: str) -> str:
        """Return the plaintext protocol for a hash, or the hash on unknown.

        On a cache miss the vocabulary is refreshed once from InfluxDB
        before falling back to the raw hash.

        Args:
            hash_value: The stringified hash used as persisted series_id.

        Returns:
            The readable protocol stack, or *hash_value* if not found.
        """
        if hash_value in self._cache:
            return self._cache[hash_value]
        self._refresh()
        return self._cache.get(hash_value, hash_value)

    def resolve_many(self, hash_values: list[str]) -> list[str]:
        """Resolve multiple hashes, refreshing once if any are missing.

        Args:
            hash_values: List of stringified hashes.

        Returns:
            Parallel list of readable protocols (fallback = raw hash).
        """
        missing = [h for h in hash_values if h not in self._cache]
        if missing:
            self._refresh()
        return [self._cache.get(h, h) for h in hash_values]

    def refresh(self) -> None:
        """Force an immediate cache refresh from InfluxDB."""
        self._refresh(force=True)

    def _refresh(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_refresh < self._ttl:
            return
        try:
            protocols = self._influx_repo.query_distinct_tags(
                measurement="proto_traffic",
                tag="protocol",
            )
            self._cache = {proto_series_hash(p): p for p in protocols}
            self._last_refresh = now
            logger.debug(
                "ProtoHashResolver refreshed: {} protocols cached",
                len(self._cache),
            )
        except Exception as exc:
            logger.warning("ProtoHashResolver refresh failed: {}", exc)
