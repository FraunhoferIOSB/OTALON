"""Runtime source of the series blacklist (CLAS-071, decisions D1/D2/D3).

:class:`SeriesBlacklistSource` resolves the single runtime key
``("otalon-clas", "detection.series_blacklist")`` into an immutable
:class:`~otalon_clas.detection.series_blacklist.SeriesBlacklist` instance
with three reinforcement layers:

1. **TTL pull** — the key is re-read from ``runtime_config`` at most once
   per :data:`TTL_SECONDS` (30 s, decision D13), so the worst-case uptake
   delay without any NOTIFY is one TTL window.
2. **NOTIFY accelerator** — :class:`SeriesBlacklistListener` (or any caller)
   sets a dirty flag that forces the very next :meth:`current` call to
   re-read, making the typical uptake delay sub-second.
3. **Last-valid retention** — a read or parse failure never takes the
   running detector down: after the first successful read the last valid
   instance stays active with a warning log.

:meth:`current` returns ``None`` exactly when NO runtime row governs the
service — no row at all, or (before any row was ever read) a failing or
invalid first read. The wiring layer translates ``None`` into "keep the
per-module ``config.json`` boot defaults" (spec scenario "No row keeps
boot defaults", decision D3): a deployment without a DB row behaves
exactly as before the runtime key existed.

Publication is copy-on-write (decision D2): every accepted value builds a
NEW immutable :class:`SeriesBlacklist` and installs it via one reference
assignment, so in-flight workers keep a fully coherent view.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Protocol

from loguru import logger
from otalon_common.runtime import (
    OTALON_CLAS_SERVICE,
    ListEntryValidationError,
    series_blacklist_syntax_validator,
)

from otalon_clas.detection.series_blacklist import SeriesBlacklist

SERIES_BLACKLIST_KEY = "detection.series_blacklist"
"""Runtime-config key carrying the shared series-blacklist JSON array.

Mirrors the manifest declaration (service ``otalon-clas``) added in
CLAS-071 wave 1; the otalon-clas registration test pins the two against
each other via ``manifest_for_service``.
"""

TTL_SECONDS: float = 30.0
"""Cache TTL and periodic-dirty interval (CLAS-071 D13, fixed)."""


class SeriesBlacklistReader(Protocol):
    """Minimal repository read surface the source depends on."""

    def get(self, service: str, key: str, default: str | None = None) -> str | None:
        """Return the persisted value or *default* when no row exists."""
        ...


class SeriesBlacklistSource:
    """Resolves the series blacklist from ``runtime_config`` per TTL.

    Args:
        repository: Reader for the ``runtime_config`` table (typically a
            :class:`~otalon_clas.runtime.runtime_config_repository.RuntimeConfigRepository`).
    """

    def __init__(self, repository: SeriesBlacklistReader) -> None:
        """Wire the source without touching the repository."""
        self._repository = repository
        self._lock = threading.Lock()
        self._dirty = False
        self._last_pull: float | None = None
        self._cached: SeriesBlacklist | None = None
        self._have_row = False
        logger.info("SeriesBlacklistSource: ready (runtime key {})", SERIES_BLACKLIST_KEY)

    @property
    def is_dirty(self) -> bool:
        """Return whether a forced re-read is pending (test/diagnostic)."""
        with self._lock:
            return self._dirty

    def mark_dirty(self) -> None:
        """Force the next :meth:`current` call to re-read the key.

        Called by the NOTIFY listener and by the periodic fallback. Safe
        to call from any thread.
        """
        with self._lock:
            self._dirty = True

    def current(self) -> SeriesBlacklist | None:
        """Return the effective blacklist, re-reading when stale or dirty.

        Returns:
            The cached instance while clean and TTL-fresh; otherwise a
            freshly resolved value. ``None`` means "no runtime row
            governs the service" — the caller keeps the per-module
            ``config.json`` boot defaults (decision D3). Never a
            partially applied state.
        """
        if not self._needs_reload():
            return self._cached
        return self._reload()

    def _needs_reload(self) -> bool:
        """Return whether the cached instance is dirty or TTL-expired."""
        with self._lock:
            now = time.monotonic()
            expired = self._last_pull is None or (now - self._last_pull) >= TTL_SECONDS
            if self._dirty or expired:
                self._dirty = False
                return True
            return False

    def _reload(self) -> SeriesBlacklist | None:
        """Read, validate and swap in a new instance; retain last valid on failure.

        The single ``self._cached = candidate`` assignment is the
        copy-on-write swap: ``SeriesBlacklist`` is immutable, so any
        worker still holding the previous reference keeps a consistent
        view (decision D2).
        """
        try:
            raw = self._repository.get(OTALON_CLAS_SERVICE, SERIES_BLACKLIST_KEY)
        except Exception:
            self._handle_read_failure()
            return self._cached
        if raw is None:
            # No persisted row: report "no row" so the wiring keeps the
            # per-module boot defaults active (spec: "No row keeps boot
            # defaults"). Still record the pull so the TTL applies and a
            # later INSERT is picked up within TTL.
            with self._lock:
                self._cached = None
                self._have_row = False
                self._last_pull = time.monotonic()
            return None
        try:
            patterns = _parse_pattern_array(raw)
        except (ValueError, ListEntryValidationError) as exc:
            logger.warning(
                "SeriesBlacklistSource: invalid persisted blacklist {!r} kept last valid instance: {}",
                raw[:64],
                exc,
            )
            with self._lock:
                if not self._have_row:
                    self._cached = None
                self._last_pull = time.monotonic()
            return self._cached
        candidate = SeriesBlacklist(patterns)
        with self._lock:
            self._cached = candidate
            self._have_row = True
            self._last_pull = time.monotonic()
        self._log_active_source("runtime_config row")
        return candidate

    def _handle_read_failure(self) -> None:
        """Retain the last valid instance and log which source stays active."""
        source = "last valid instance" if self._have_row else "per-module boot defaults"
        logger.warning(
            "SeriesBlacklistSource: runtime_config read failed; keeping {} active",
            source,
        )
        with self._lock:
            # Leave ``_last_pull`` untouched on failure: the next call
            # retries immediately rather than waiting out a full TTL
            # after a transient database outage.
            self._dirty = True

    def _log_active_source(self, source: str) -> None:
        """Announce which source produced the now-active instance."""
        logger.info(
            "SeriesBlacklistSource: {} active ({} pattern(s))",
            source,
            len(self._cached.patterns) if self._cached is not None else 0,
        )


def _parse_pattern_array(raw: str) -> list[str]:
    """Parse a persisted runtime value into a validated pattern list.

    Defense-in-depth behind the API (decision D7): the value must be a
    JSON array of strings whose entries pass the shared syntax
    validator, even though the API already rejects invalid writes.

    Args:
        raw: Persisted value text.

    Returns:
        The validated pattern list.

    Raises:
        ValueError: When the value is not a JSON array of strings.
        ListEntryValidationError: When an entry violates the syntax.
    """
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
        raise ValueError("value is not a JSON array of strings")
    series_blacklist_syntax_validator(raw)
    return [str(item) for item in parsed]
