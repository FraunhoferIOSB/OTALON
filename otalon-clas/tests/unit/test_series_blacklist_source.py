"""Unit tests for the series-blacklist runtime source and listener (CLAS-071).

Covers the CLAS-071 wave-2 group-3 contract with a fake repository:

* TTL expiry triggers a reload; a clean+fresh cache does not touch it;
* the dirty flag forces a reload before the TTL;
* an invalid persisted value keeps the last valid instance;
* a read failure keeps the last valid instance (and reports "no row"
  before the first successful read);
* a missing row reports "no row" so the wiring keeps per-module boot
  defaults (decision D3);
* the listener sets the dirty flag only for matching payloads.
"""

from __future__ import annotations

import json
from typing import cast

import pytest

from otalon_clas.common.postgres_connector import PostgresConnector
from otalon_clas.runtime.bounds_invalidator import BoundsInvalidator
from otalon_clas.runtime.series_blacklist_listener import SeriesBlacklistListener
from otalon_clas.runtime.series_blacklist_source import (
    SERIES_BLACKLIST_KEY,
    TTL_SECONDS,
    SeriesBlacklistSource,
)

pytestmark = pytest.mark.unit

_BOOT_PATTERNS = ["01:00:5e:*"]
_ROW_ONE = json.dumps(["ff:ff:ff:ff:ff:ff"])
_ROW_TWO = json.dumps(["33:33:*"])


class _FakeRepository:
    """In-memory ``runtime_config`` reader double with failure control."""

    def __init__(self, value: str | None = None, fail: bool = False) -> None:
        self.value = value
        self.fail = fail
        self.calls = 0

    def get(self, service: str, key: str, default: str | None = None) -> str | None:
        """Return the configured row value or the default when absent."""
        assert service == "otalon-clas"
        assert key == SERIES_BLACKLIST_KEY
        self.calls += 1
        if self.fail:
            raise RuntimeError("database unavailable")
        return self.value


class _StubEngine:
    """Minimal engine double whose dialect is NOT postgresql."""

    @property
    def dialect(self) -> _StubDialect:
        """Report a non-postgresql dialect so the listener degrades."""
        return _StubDialect()


class _StubDialect:
    """Dialect double with the one name attribute the listener reads."""

    name = "sqlite"


class _FakeConnector:
    """Connector double exposing only the engine the listener reads."""

    def __init__(self) -> None:
        self.engine = _StubEngine()


def _listener_double() -> SeriesBlacklistListener:
    """Build a listener around a non-PostgreSQL stub for dispatch tests."""
    return SeriesBlacklistListener(
        connector=cast("PostgresConnector", _FakeConnector()),
        on_invalidation=lambda: None,
    )


def _source_with_spy() -> tuple[SeriesBlacklistSource, _FakeRepository]:
    repo = _FakeRepository(value=_ROW_ONE)
    return SeriesBlacklistSource(repository=repo), repo


def test_first_current_reads_the_persisted_row() -> None:
    """A persisted row overrides the boot defaults from the first read."""
    source, repo = _source_with_spy()

    current = source.current()

    assert repo.calls == 1
    assert current is not None
    assert current.patterns == frozenset({"ff:ff:ff:ff:ff:ff"})


def test_fresh_cache_does_not_touch_the_repository() -> None:
    """Within the TTL a clean source returns the cached instance."""
    source, repo = _source_with_spy()

    first = source.current()
    second = source.current()

    assert repo.calls == 1
    assert first is second


def test_dirty_flag_forces_reload_before_ttl() -> None:
    """A NOTIFY-driven dirty mark forces an immediate re-read."""
    source, repo = _source_with_spy()
    first = source.current()
    repo.value = _ROW_TWO

    source.mark_dirty()
    second = source.current()

    assert repo.calls == 2
    assert first is not None and second is not None
    assert first is not second
    assert second.patterns == frozenset({"33:33:*"})


def test_ttl_expiry_triggers_reload() -> None:
    """An expired cache re-reads even without the dirty flag (missed-NOTIFY self-heal)."""
    source, repo = _source_with_spy()
    source.current()
    repo.value = _ROW_TWO
    source._last_pull = None  # simulate TTL expiry (monotonic clock friendly)

    second = source.current()

    assert repo.calls == 2
    assert second is not None
    assert second.patterns == frozenset({"33:33:*"})


def test_ttl_expiry_via_monotonic_stamp() -> None:
    """A stale ``last_pull`` timestamp older than the TTL reloads."""
    source, repo = _source_with_spy()
    source.current()
    repo.value = _ROW_TWO
    source._last_pull -= TTL_SECONDS + 1.0  # type: ignore[operator]

    current = source.current()
    assert current is not None
    assert current.patterns == frozenset({"33:33:*"})


def test_invalid_persisted_value_keeps_last_valid() -> None:
    """An entry failing the shared validator never replaces the active instance."""
    source, repo = _source_with_spy()
    first = source.current()
    repo.value = json.dumps(["totally invalid entry!!"])

    source.mark_dirty()
    second = source.current()

    assert first is not None and second is not None
    assert second is first
    assert second.patterns == frozenset({"ff:ff:ff:ff:ff:ff"})


def test_non_array_persisted_value_keeps_last_valid() -> None:
    """Structurally broken JSON text also keeps the last valid instance."""
    source, repo = _source_with_spy()
    first = source.current()
    repo.value = '{"not": "an array"}'

    source.mark_dirty()
    assert source.current() is first


def test_read_failure_keeps_last_valid_after_first_success() -> None:
    """A DB outage returns the last valid instance instead of raising."""
    source, repo = _source_with_spy()
    first = source.current()
    repo.fail = True

    source.mark_dirty()
    second = source.current()

    assert second is first


def test_first_read_failure_falls_back_to_no_row() -> None:
    """Before any successful read, a failure reports "no row" (boot defaults)."""
    repo = _FakeRepository(fail=True)
    source = SeriesBlacklistSource(repository=repo)

    current = source.current()

    assert current is None
    assert source.current() is None


def test_missing_row_reports_no_row() -> None:
    """No persisted row reports "no row" so wiring keeps boot defaults."""
    repo = _FakeRepository(value=None)
    source = SeriesBlacklistSource(repository=repo)

    current = source.current()

    assert repo.calls == 1
    assert current is None


def test_construction_logs_ready_line_once(caplog: pytest.LogCaptureFixture) -> None:
    """Construction announces the runtime key the source resolves."""
    from loguru import logger

    handler_id = logger.add(caplog.handler, format="{message}")
    try:
        SeriesBlacklistSource(repository=_FakeRepository())
    finally:
        logger.remove(handler_id)

    ready_lines = [
        record.getMessage() for record in caplog.records if "SeriesBlacklistSource: ready" in record.getMessage()
    ]
    assert len(ready_lines) == 1, ready_lines


class TestListenerDispatch:
    """Payload matching of the invalidation listener."""

    def _collecting_listener(self) -> tuple[SeriesBlacklistListener, list[str]]:
        marked: list[str] = []

        def _mark() -> None:
            marked.append("dirty")

        listener = SeriesBlacklistListener(
            connector=cast("PostgresConnector", _FakeConnector()),
            on_invalidation=_mark,
        )
        return listener, marked

    def test_matching_payload_sets_dirty(self) -> None:
        """The exact service+key payload marks the source dirty."""
        listener, marked = self._collecting_listener()
        listener._dispatch(json.dumps({"service": "otalon-clas", "key": SERIES_BLACKLIST_KEY}))
        assert marked == ["dirty"]

    def test_foreign_key_payload_is_ignored(self) -> None:
        """A payload for another key does not set the dirty flag."""
        listener, marked = self._collecting_listener()
        listener._dispatch(json.dumps({"service": "otalon-clas", "key": "detection.conn.bounds_enabled"}))
        assert marked == []

    def test_foreign_service_payload_is_ignored(self) -> None:
        """A payload for another service does not set the dirty flag."""
        listener, marked = self._collecting_listener()
        listener._dispatch(json.dumps({"service": "otalon-scan", "key": SERIES_BLACKLIST_KEY}))
        assert marked == []

    def test_malformed_payload_is_ignored(self) -> None:
        """Non-JSON payloads never raise."""
        listener, marked = self._collecting_listener()
        listener._dispatch("not-json")
        listener._dispatch(json.dumps(["not", "an object"]))
        assert marked == []


def test_listener_stop_is_idempotent() -> None:
    """Stopping an unstarted (or twice-stopped) listener is a no-op."""
    listener = _listener_double()
    listener.stop()
    listener.stop()


def test_periodic_fallback_marks_dirty_on_non_postgres() -> None:
    """The poll-only degradation path sets the dirty flag periodically."""
    import threading

    source = SeriesBlacklistSource(repository=_FakeRepository())
    listener = SeriesBlacklistListener(
        connector=cast("PostgresConnector", _FakeConnector()),
        on_invalidation=source.mark_dirty,
    )
    listener._periodic_interval = 0.01
    marked = threading.Event()
    listener._on_invalidation = marked.set
    thread = threading.Thread(target=listener._run_periodic_only, daemon=True)
    thread.start()
    assert marked.wait(timeout=5.0), "periodic fallback never set the dirty flag"
    listener.stop()
    thread.join(timeout=5.0)


def test_bounds_invalidator_channel_constant_differs() -> None:
    """The blacklist listener owns its own channel (no reuse of bounds')."""
    from otalon_clas.runtime.series_blacklist_listener import (
        SERIES_BLACKLIST_INVALIDATION_CHANNEL,
    )

    assert SERIES_BLACKLIST_INVALIDATION_CHANNEL == "cyberclas_runtime_invalidation"
    assert SERIES_BLACKLIST_INVALIDATION_CHANNEL != "cyberclas_bounds_invalidation"
    assert BoundsInvalidator is not None
