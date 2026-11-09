"""Cache abstraction layer.

Provides a unified caching interface using ``cachetools`` for
frequently-accessed read paths (dashboard KPIs, topology graph,
station lists, anomaly summaries, port-collapse rules).

Each named cache is a :class:`cachetools.TTLCache` (no complex
invalidation — pure time-based expiry). The manager additionally
tracks per-cache hit/miss counters so the hit ratio can be exposed
via the health endpoint.

B-09 deliberately wires only short-TTL caches (≤ 60 s) onto
read-mostly aggregation paths. Write paths intentionally do not bust
the cache; staleness for one TTL interval is the documented contract.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from cachetools import TTLCache


@dataclass
class _CacheStats:
    """Hit / miss counters for a single named cache.

    Counters are intentionally not thread-locked: the manager API
    callers already serialize at the cachetools.TTLCache layer, and a
    +-1 race on the counter is harmless (it is observability data,
    not a correctness signal).
    """

    hits: int = 0
    misses: int = 0

    @property
    def total(self) -> int:
        """Total cache lookups recorded for this cache."""
        return self.hits + self.misses

    @property
    def hit_ratio(self) -> float:
        """Hit ratio in ``[0.0, 1.0]``; ``0.0`` when never queried."""
        total = self.total
        return self.hits / total if total else 0.0


@dataclass
class _NamedCache:
    """Bundle of a TTLCache and its hit/miss counters."""

    cache: TTLCache[str, Any]
    stats: _CacheStats = field(default_factory=_CacheStats)


# Default TTLs (seconds). Short by design — B-09 uses pure time-based
# expiry instead of write-path invalidation, so the TTL is the upper
# bound on staleness shown to the UI after a write.
_DEFAULT_STATIONS_TTL = 60
_DEFAULT_ANOMALIES_TTL = 20
_DEFAULT_PORT_RULES_TTL = 120
_DEFAULT_DASHBOARD_KPIS_TTL = 30
_DEFAULT_TOPOLOGY_TTL = 30


class CacheManager:
    """Manages in-memory TTL caches for various read paths.

    Each named cache provides:

    * ``cache_name.cache`` — the underlying :class:`cachetools.TTLCache`.
    * ``cache_name.stats`` — hit/miss counters.

    Use :meth:`get_or_compute` to wrap a callable in a cache lookup so
    hit/miss counters are updated consistently across call sites.
    """

    def __init__(
        self,
        stations_ttl: int = _DEFAULT_STATIONS_TTL,
        anomalies_ttl: int = _DEFAULT_ANOMALIES_TTL,
        port_rules_ttl: int = _DEFAULT_PORT_RULES_TTL,
        dashboard_kpis_ttl: int = _DEFAULT_DASHBOARD_KPIS_TTL,
        topology_ttl: int = _DEFAULT_TOPOLOGY_TTL,
    ) -> None:
        """Initialize cache instances.

        Args:
            stations_ttl: TTL in seconds for station-list cache entries.
            anomalies_ttl: TTL in seconds for anomaly-summary cache entries.
            port_rules_ttl: TTL in seconds for port-collapse rule cache entries.
            dashboard_kpis_ttl: TTL in seconds for dashboard-KPI cache entries.
            topology_ttl: TTL in seconds for topology-graph cache entries.
        """
        self._lock = threading.Lock()

        self._stations = _NamedCache(TTLCache(maxsize=128, ttl=stations_ttl))
        self._anomalies = _NamedCache(TTLCache(maxsize=256, ttl=anomalies_ttl))
        self._port_rules = _NamedCache(TTLCache(maxsize=16, ttl=port_rules_ttl))
        self._dashboard_kpis = _NamedCache(TTLCache(maxsize=64, ttl=dashboard_kpis_ttl))
        self._topology = _NamedCache(TTLCache(maxsize=64, ttl=topology_ttl))

    # ── Backwards-compatible attribute access (pre-B-09 callers
    # access ``mgr.stations`` etc. directly as a TTLCache). ───────────
    @property
    def stations(self) -> TTLCache[str, Any]:
        """Underlying TTLCache for the stations namespace."""
        return self._stations.cache

    @property
    def anomalies(self) -> TTLCache[str, Any]:
        """Underlying TTLCache for the anomalies namespace."""
        return self._anomalies.cache

    @property
    def port_rules(self) -> TTLCache[str, Any]:
        """Underlying TTLCache for the port-rules namespace."""
        return self._port_rules.cache

    @property
    def dashboard_kpis(self) -> TTLCache[str, Any]:
        """Underlying TTLCache for the dashboard-KPIs namespace."""
        return self._dashboard_kpis.cache

    @property
    def topology(self) -> TTLCache[str, Any]:
        """Underlying TTLCache for the topology-graph namespace."""
        return self._topology.cache

    def clear_all(self) -> None:
        """Evict all entries from every cache. Hit/miss stats are kept."""
        with self._lock:
            self._stations.cache.clear()
            self._anomalies.cache.clear()
            self._port_rules.cache.clear()
            self._dashboard_kpis.cache.clear()
            self._topology.cache.clear()

    def get_or_compute(
        self,
        name: str,
        key: str,
        compute: Callable[[], Any],
    ) -> Any:
        """Return a cached value or compute, store, and return it.

        Lookups update the hit/miss counters of the named cache.

        Args:
            name: Cache namespace name (one of ``"stations"``,
                ``"anomalies"``, ``"port_rules"``, ``"dashboard_kpis"``,
                ``"topology"``).
            key: Lookup key within the cache.
            compute: Zero-argument callable that produces the value on
                a miss. Called at most once per miss.

        Returns:
            The cached value (on hit) or the newly computed value (on
            miss), also persisted into the cache for subsequent
            lookups within the TTL window.

        Raises:
            KeyError: If *name* is not a known cache namespace.
        """
        named = self._named(name)
        try:
            value = named.cache[key]
            named.stats.hits += 1
            return value
        except KeyError:
            named.stats.misses += 1
            value = compute()
            named.cache[key] = value
            return value

    def stats_snapshot(self) -> dict[str, dict[str, Any]]:
        """Return a JSON-serializable snapshot of all caches' statistics.

        The shape is stable and intended for inclusion in the health
        endpoint payload:

        ``{name: {hits, misses, total, hit_ratio, size, maxsize, ttl}}``

        Returns:
            Mapping of cache namespace name to a stats dict.
        """
        result: dict[str, dict[str, Any]] = {}
        for name, named in (
            ("stations", self._stations),
            ("anomalies", self._anomalies),
            ("port_rules", self._port_rules),
            ("dashboard_kpis", self._dashboard_kpis),
            ("topology", self._topology),
        ):
            result[name] = {
                "hits": named.stats.hits,
                "misses": named.stats.misses,
                "total": named.stats.total,
                "hit_ratio": round(named.stats.hit_ratio, 4),
                "size": len(named.cache),
                "maxsize": named.cache.maxsize,
                "ttl": named.cache.ttl,
            }
        return result

    def _named(self, name: str) -> _NamedCache:
        """Look up a named cache or raise ``KeyError`` with a clear message.

        Args:
            name: Cache namespace name.

        Returns:
            The :class:`_NamedCache` bundle.

        Raises:
            KeyError: If *name* is not a known namespace.
        """
        try:
            return {
                "stations": self._stations,
                "anomalies": self._anomalies,
                "port_rules": self._port_rules,
                "dashboard_kpis": self._dashboard_kpis,
                "topology": self._topology,
            }[name]
        except KeyError as exc:
            raise KeyError(f"Unknown cache namespace: {name!r}") from exc
