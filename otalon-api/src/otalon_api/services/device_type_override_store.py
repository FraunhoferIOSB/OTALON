"""Device type override store.

Provides thread-safe, JSON-file-backed persistence for manual device
type classification overrides.  Overrides take precedence over the
automatic classification from :func:`classify_device_type`.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from loguru import logger

from otalon_api.domain.topology.classification import VALID_DEVICE_TYPES

_DEFAULT_OVERRIDE_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "device_type_overrides.json"


class DeviceTypeOverrideStore:
    """Thread-safe, JSON-file-backed store for device type overrides.

    Overrides are keyed by device ID (string) and map to a device type
    category string (PLC, IPC, IO, HMI, Other).

    Args:
        path: Filesystem path for the JSON persistence file.
    """

    def __init__(self, path: Path | None = None) -> None:
        """Initialize the override store.

        Args:
            path: Path to the JSON override file.  Falls back to
                ``config/device_type_overrides.json`` if ``None``.
        """
        self._path = path or _DEFAULT_OVERRIDE_PATH
        self._lock = threading.Lock()
        self._overrides: dict[str, str] = self._load()

    def _load(self) -> dict[str, str]:
        """Load overrides from the JSON file on disk.

        Returns:
            Dictionary mapping device IDs to device type strings.
        """
        if not self._path.exists():
            logger.debug("Override file not found at {}, starting empty", self._path)
            return {}
        try:
            with open(self._path, encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                logger.warning("Override file has unexpected format, starting empty")
                return {}
            logger.info("Loaded {} device type overrides from {}", len(data), self._path)
            return {str(k): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load override file {}: {}", self._path, exc)
            return {}

    def _persist(self) -> None:
        """Write the current overrides to the JSON file on disk."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(self._overrides, fh, indent=2, ensure_ascii=False)
            logger.debug("Persisted {} overrides to {}", len(self._overrides), self._path)
        except OSError as exc:
            logger.error("Failed to persist overrides to {}: {}", self._path, exc)

    def get(self, device_id: str) -> str | None:
        """Look up the override for a device.

        Args:
            device_id: The device identifier (numeric ID or unresolved key).

        Returns:
            The overridden device type string, or ``None`` if no override exists.
        """
        with self._lock:
            return self._overrides.get(str(device_id))

    def get_all(self) -> dict[str, str]:
        """Return a copy of all current overrides.

        Returns:
            Dictionary mapping device IDs to device type strings.
        """
        with self._lock:
            return dict(self._overrides)

    def set(self, device_id: str, device_type: str) -> str | None:
        """Set or update the device type override for a device.

        Args:
            device_id: The device identifier.
            device_type: The new device type classification.

        Returns:
            The previous device type override, or ``None`` if none existed.

        Raises:
            ValueError: If *device_type* is not a valid classification.
        """
        if device_type not in VALID_DEVICE_TYPES:
            raise ValueError(f"Invalid device_type '{device_type}'. " f"Must be one of: {sorted(VALID_DEVICE_TYPES)}")
        with self._lock:
            previous = self._overrides.get(str(device_id))
            self._overrides[str(device_id)] = device_type
            self._persist()
        logger.info(
            "Device type override set: device_id={}, type={} (was={})",
            device_id,
            device_type,
            previous,
        )
        return previous

    def set_many(self, items: dict[str, str]) -> dict[str, str | None]:
        """Atomically set or update overrides for multiple devices.

        All device types are validated before any write occurs. The
        underlying JSON file is persisted exactly once after the batch
        is applied, so the store is never observed in a half-applied
        state (validation failure -> no writes; persistence failure
        -> in-memory state is still rolled back to the snapshot taken
        before the batch).

        Args:
            items: Mapping of device identifier (string) to target
                device type. The dictionary is required to be non-empty;
                callers are expected to enforce that at the API
                boundary.

        Returns:
            Mapping of device identifier to the previous override
            value (``None`` if no override existed before).

        Raises:
            ValueError: If any value in *items* is not a valid
                classification. Raised before any state mutation,
                identifying the first offending entry.
        """
        for device_id, device_type in items.items():
            if device_type not in VALID_DEVICE_TYPES:
                raise ValueError(
                    f"Invalid device_type '{device_type}' for device_id "
                    f"'{device_id}'. Must be one of: "
                    f"{sorted(VALID_DEVICE_TYPES)}"
                )

        previous: dict[str, str | None] = {}
        with self._lock:
            snapshot = dict(self._overrides)
            try:
                for device_id, device_type in items.items():
                    key = str(device_id)
                    previous[key] = self._overrides.get(key)
                    self._overrides[key] = device_type
                self._persist()
            except Exception:
                # Roll back in-memory state on any failure during the
                # batched apply so the store stays consistent with the
                # last-good persisted snapshot.
                self._overrides = snapshot
                raise
        logger.info(
            "Device type overrides applied in bulk: count={}, ids={}",
            len(items),
            sorted(items.keys()),
        )
        return previous

    def delete(self, device_id: str) -> str | None:
        """Remove the device type override for a device.

        Args:
            device_id: The device identifier.

        Returns:
            The removed device type, or ``None`` if no override existed.
        """
        with self._lock:
            previous = self._overrides.pop(str(device_id), None)
            if previous is not None:
                self._persist()
        return previous

    def resolve(self, device_id: str, auto_type: str) -> str:
        """Resolve the effective device type, preferring overrides.

        Args:
            device_id: The device identifier.
            auto_type: The automatically classified device type.

        Returns:
            The override type if one exists, otherwise *auto_type*.
        """
        override = self.get(str(device_id))
        if override is not None:
            return override
        return auto_type
