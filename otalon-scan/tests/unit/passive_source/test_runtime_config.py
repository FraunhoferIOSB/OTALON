"""Unit tests for the seeder's async runtime-configuration reader.

Covers task C14 of ``passive-seeder-runtime-control``:

- a runtime row overrides the boot value,
- a missing row keeps the boot value (never a type default),
- an out-of-domain row is ignored rather than adopted,
- a database error degrades to the boot configuration.

The engine is stubbed at the SQLAlchemy boundary (``connect`` /
``execute``) so no PostgreSQL instance is required.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import TracebackType
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from otalon_scan.passive_source.runtime_config import RuntimeConfigReader
from otalon_scan.passive_source.settings import PassiveSeederSettings


@dataclass
class _StubResult:
    """Minimal stand-in for a SQLAlchemy ``Result``."""

    rows: list[tuple[str, str | None]]

    def fetchall(self) -> list[tuple[str, str | None]]:
        return self.rows


@dataclass
class _StubConnection:
    """Async connection returning a fixed row set."""

    rows: list[tuple[str, str | None]]
    raises: Exception | None = None
    executed: list[dict[str, Any]] = field(default_factory=list)

    async def execute(self, _statement: Any, params: dict[str, Any]) -> _StubResult:
        self.executed.append(params)
        if self.raises is not None:
            raise self.raises
        return _StubResult(self.rows)

    async def __aenter__(self) -> "_StubConnection":
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        return None


@dataclass
class _StubEngine:
    """Async engine handing out a single stub connection."""

    connection: _StubConnection

    def connect(self) -> _StubConnection:
        return self.connection


def _boot_settings() -> PassiveSeederSettings:
    """Boot settings distinct from every value used as a runtime override."""
    return PassiveSeederSettings.model_construct(
        enabled=False,
        poll_interval_s=60,
        lookback_window_s=300,
        influx_url="http://stub:8181",
        influx_token="stub",
        influx_bucket="netcap",
        drop_laa=False,
    )


def _reader(rows: list[tuple[str, str | None]], *, raises: Exception | None = None) -> RuntimeConfigReader:
    """Build a reader over a stub engine yielding *rows*."""
    return RuntimeConfigReader(_StubEngine(_StubConnection(rows=rows, raises=raises)))  # type: ignore[arg-type]


class TestPrecedence:
    """Boot value versus runtime row."""

    async def test_runtime_row_overrides_boot_value(self) -> None:
        """SCENARIO: A runtime row overrides the boot value."""
        reader = _reader([("lookback_window_s", "900"), ("enabled", "true")])
        config = await reader.resolve(_boot_settings())
        assert config.lookback_window_s == 900
        assert config.enabled is True

    async def test_missing_row_preserves_boot_value(self) -> None:
        """SCENARIO: A missing runtime row preserves the boot value."""
        config = await _reader([]).resolve(_boot_settings())
        assert config.poll_interval_s == 60
        assert config.lookback_window_s == 300
        assert config.enabled is False
        assert config.drop_laa is False

    async def test_partial_rows_only_override_present_keys(self) -> None:
        """Keys without a row keep the boot value while others are overridden."""
        config = await _reader([("poll_interval_s", "120")]).resolve(_boot_settings())
        assert config.poll_interval_s == 120
        assert config.lookback_window_s == 300

    async def test_null_value_is_ignored(self) -> None:
        """A row with a NULL value falls back to the boot value."""
        config = await _reader([("poll_interval_s", None)]).resolve(_boot_settings())
        assert config.poll_interval_s == 60


class TestValidation:
    """A stored value must still satisfy its registered domain."""

    async def test_out_of_domain_value_is_ignored(self) -> None:
        """A poll interval below the floor keeps the boot value."""
        config = await _reader([("poll_interval_s", "1")]).resolve(_boot_settings())
        assert config.poll_interval_s == 60

    async def test_unregistered_key_is_ignored(self) -> None:
        """A row for a key outside the allow-list has no effect."""
        config = await _reader([("influx_bucket", "other")]).resolve(_boot_settings())
        assert config.poll_interval_s == 60
        assert config.enabled is False

    async def test_query_scopes_to_the_service_identifier(self) -> None:
        """Rows are resolved under the service, not the container name."""
        connection = _StubConnection(rows=[])
        reader = RuntimeConfigReader(_StubEngine(connection))  # type: ignore[arg-type]
        await reader.resolve(_boot_settings())
        assert connection.executed[0]["service"] == "otalon-scan"


class TestDegradation:
    """A database problem must not stop the worker."""

    async def test_database_error_falls_back_to_boot(self) -> None:
        """A read failure returns the boot configuration instead of raising."""
        failure = OperationalError("SELECT 1", {}, Exception("down"))
        config = await _reader([], raises=failure).resolve(_boot_settings())
        assert config.poll_interval_s == 60
        assert config.enabled is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("1", True), ("on", True), ("false", False), ("0", False)],
)
async def test_bool_literals_are_coerced(raw: str, expected: bool) -> None:
    """Every accepted boolean literal coerces to the matching Python bool."""
    config = await _reader([("enabled", raw)]).resolve(_boot_settings())
    assert config.enabled is expected
