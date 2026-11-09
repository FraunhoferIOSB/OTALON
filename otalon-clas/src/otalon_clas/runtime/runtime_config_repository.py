"""Runtime configuration repository for hot-reconfigurable parameters.

Provides read/write access to the shared ``runtime_config`` table with
boot-precedence resolution and shared registry validation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, cast, overload

from otalon_clas.common.postgres_connector import PostgresConnector, RuntimeConfig

from otalon_common.runtime import validate_write

_BOOL_TRUE: frozenset[str] = frozenset({"true", "1", "yes", "on"})


def _coerce_bool(value: Any) -> bool:
    """Coerce a stored string to bool."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _BOOL_TRUE


class RuntimeConfigRepository:
    """Accessor for ``runtime_config`` rows.

    Args:
        connector: PostgreSQL connector providing SQLAlchemy sessions.
    """

    def __init__(self, connector: PostgresConnector) -> None:
        """Initialize the repository."""
        self._connector = connector

    def get(
        self,
        service: str,
        key: str,
        default: str | None = None,
    ) -> str | None:
        """Read the effective value for a key, falling back to *default*."""
        with self._connector.session() as session:
            row = session.query(RuntimeConfig).get({"service": service, "key": key})
            if row is None:
                return default
            return cast(str, row.value)

    @overload
    def get_bool(
        self,
        service: str,
        key: str,
        default: None = None,
    ) -> bool | None: ...
    @overload
    def get_bool(
        self,
        service: str,
        key: str,
        default: bool,
    ) -> bool: ...

    def get_bool(
        self,
        service: str,
        key: str,
        default: bool | None = None,
    ) -> bool | None:
        """Read a key as a boolean, returning *default* when absent."""
        raw = self.get(service, key)
        if raw is None:
            return default
        return _coerce_bool(raw)

    @overload
    def get_int(
        self,
        service: str,
        key: str,
        default: None = None,
    ) -> int | None: ...
    @overload
    def get_int(
        self,
        service: str,
        key: str,
        default: int,
    ) -> int: ...

    def get_int(
        self,
        service: str,
        key: str,
        default: int | None = None,
    ) -> int | None:
        """Read a key as an integer, returning *default* when absent."""
        raw = self.get(service, key)
        if raw is None:
            return default
        try:
            return int(str(raw).strip())
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"runtime_config[({service!r}, {key!r})] is not an int: {raw!r}"
            ) from exc

    def get_float(
        self,
        service: str,
        key: str,
        default: float | None = None,
    ) -> float | None:
        """Read a key as a float, returning *default* when absent."""
        raw = self.get(service, key)
        if raw is None:
            return default
        try:
            return float(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"runtime_config[({service!r}, {key!r})] is not a float: {raw!r}"
            ) from exc

    def upsert(
        self,
        service: str,
        key: str,
        value: str,
        updated_by: str | None = None,
    ) -> None:
        """Persist a hot config value, moving the prior value to ``value_prev``.

        The ``(service, key)`` pair must be in the v1 allow-list and the
        value must pass that key's typed/domain validator (audit B-09).

        Raises:
            ValueError: When *key* matches a secret pattern, is not in the
                allow-list, or the value fails domain validation.
        """
        validate_write(service, key, str(value))
        now = datetime.now(tz=timezone.utc)
        string_value = str(value)
        with self._connector.session() as session:
            row = session.query(RuntimeConfig).get({"service": service, "key": key})
            if row is None:
                row = RuntimeConfig(
                    service=service,
                    key=key,
                    value=string_value,
                    value_prev=None,
                    updated_at=now,
                    updated_by=updated_by,
                )
                session.add(row)
                return
            row.value_prev = row.value
            row.value = string_value
            row.updated_at = now
            row.updated_by = updated_by
