"""Asynchronous runtime-configuration reader for the passive asset seeder.

The seeder runs on the async SQLAlchemy stack (``create_async_engine`` /
``AsyncSession`` with asyncpg); no synchronous PostgreSQL driver is installed in
its image. It therefore reads the shared ``runtime_config`` table itself instead
of reusing the synchronous repository owned by otalon-clas — the shared
contract is the table and the validation registry, not a Python class.

Precedence: the environment seeds :class:`PassiveSeederSettings` at boot; a
``runtime_config`` row overrides that value from the next cycle onward. A
missing row means "use the boot value", never "use the type default", so
``.env.compose`` stays meaningful. A row whose value fails its registered
validator is ignored with one WARNING and the boot value is kept, because a bad
row must not be able to stop an already-running worker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from loguru import logger
from otalon_common.runtime import OTALON_SCAN_SERVICE, lookup
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from .runtime_keys import (
    HOT_KEYS,
    KEY_DROP_LAA,
    KEY_ENABLED,
    KEY_LOOKBACK_WINDOW_S,
    KEY_POLL_INTERVAL_S,
)
from .settings import PassiveSeederSettings

_BOOL_TRUE: frozenset[str] = frozenset({"true", "1", "yes", "on"})

_SELECT_RUNTIME_CONFIG = text("SELECT key, value FROM runtime_config WHERE service = :service AND key = ANY(:keys)")


@dataclass(frozen=True)
class EffectiveConfig:
    """The hot configuration a single poll cycle runs with.

    Attributes:
        enabled: Whether the cycle performs work or idles.
        poll_interval_s: Seconds to wait after this cycle.
        lookback_window_s: Seconds of InfluxDB history this cycle reads.
        drop_laa: Whether locally administered MAC addresses are dropped.
    """

    enabled: bool
    poll_interval_s: int
    lookback_window_s: int
    drop_laa: bool


def _coerce_bool(value: str) -> bool:
    """Coerce a stored runtime-config string to a boolean."""
    return value.strip().lower() in _BOOL_TRUE


def _validated(key: str, value: str) -> str | None:
    """Return *value* when it satisfies the key's registered validator.

    A key with no registration, or a value outside the registered domain, is
    rejected here and the caller falls back to the boot value.
    """
    spec = lookup(OTALON_SCAN_SERVICE, key)
    if spec is None:
        logger.warning(
            "passive_seeder: runtime_config key not registered key={} " "event=runtime_config_unknown_key",
            key,
        )
        return None
    try:
        spec.validate(value)
    except ValueError as exc:
        logger.warning(
            "passive_seeder: runtime_config value rejected key={} value={!r} "
            "reason={} event=runtime_config_invalid_value",
            key,
            value,
            str(exc),
        )
        return None
    return value


def _merge(settings: PassiveSeederSettings, rows: Mapping[str, str]) -> EffectiveConfig:
    """Overlay validated ``runtime_config`` rows onto the boot settings."""
    enabled = rows.get(KEY_ENABLED)
    interval = rows.get(KEY_POLL_INTERVAL_S)
    lookback = rows.get(KEY_LOOKBACK_WINDOW_S)
    drop_laa = rows.get(KEY_DROP_LAA)
    return EffectiveConfig(
        enabled=_coerce_bool(enabled) if enabled is not None else settings.enabled,
        poll_interval_s=int(interval) if interval is not None else settings.poll_interval_s,
        lookback_window_s=(int(lookback) if lookback is not None else settings.lookback_window_s),
        drop_laa=_coerce_bool(drop_laa) if drop_laa is not None else settings.drop_laa,
    )


class RuntimeConfigReader:
    """Async reader resolving the seeder's hot keys in one query per cycle.

    Args:
        engine: Async engine bound to the otalon-scan PostgreSQL database.
        keys: Keys to resolve; defaults to every registered seeder hot key.
    """

    def __init__(self, engine: AsyncEngine, *, keys: Iterable[str] | None = None) -> None:
        """Initialize the reader."""
        self._engine = engine
        self._keys: tuple[str, ...] = tuple(keys) if keys is not None else HOT_KEYS

    async def _fetch(self) -> dict[str, str]:
        """Read the raw ``runtime_config`` rows for the configured keys."""
        async with self._engine.connect() as conn:
            result = await conn.execute(
                _SELECT_RUNTIME_CONFIG,
                {"service": OTALON_SCAN_SERVICE, "keys": list(self._keys)},
            )
            return {str(row[0]): str(row[1]) for row in result.fetchall() if row[1] is not None}

    async def resolve(self, settings: PassiveSeederSettings) -> EffectiveConfig:
        """Return the configuration the next cycle runs with.

        A database error is not fatal: the boot configuration is returned so a
        transient PostgreSQL outage degrades to "keep running as configured at
        boot" rather than stopping the worker.

        Args:
            settings: Boot settings providing the fallback value per key.

        Returns:
            The effective hot configuration for the next cycle.
        """
        try:
            raw = await self._fetch()
        except SQLAlchemyError as exc:
            logger.warning(
                "passive_seeder: runtime_config read failed exception={} " "event=runtime_config_read_failed",
                type(exc).__name__,
            )
            return _merge(settings, {})
        accepted = {key: ok for key, value in raw.items() if (ok := _validated(key, value)) is not None}
        return _merge(settings, accepted)
