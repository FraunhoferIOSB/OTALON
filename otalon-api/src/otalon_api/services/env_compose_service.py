"""Environment / Docker Compose configuration service.

Reads and updates ``.env.compose`` configuration values used by Docker
Compose deployments. Supports backup creation, atomic writes, key
validation, and sensitive value masking.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime

from loguru import logger

from otalon_api.settings import Settings

ALLOWED_ENV_KEYS: list[str] = [
    "INFLUX_URL",
    "INFLUX_TOKEN",
    "POSTGRES_PASSWORD",
    "TZ",
    "AGENT_LLM_PROVIDER",
    "LITELLM_BASE_URL",
    "LITELLM_API_KEY",
    "CHAT_LLM_MODEL",
    "JOBS_LLM_MODEL",
]

# Editable boot keys. ``POSTGRES_DSN`` is intentionally excluded: it is a
# derived DSN that embeds ``POSTGRES_PASSWORD`` (and host/port/db), so
# mutating it directly would either desync it from the real secret or
# require the operator to retype the password in cleartext. It is exposed
# read-only via :data:`READONLY_BOOT_ENV_KEYS` instead.
BOOT_ENV_KEYS: tuple[str, ...] = (
    "INFLUX_URL",
    "INFLUX_TOKEN",
    "POSTGRES_PASSWORD",
    "TZ",
)

# Boot keys shown for transparency but never editable through the API.
READONLY_BOOT_ENV_KEYS: tuple[str, ...] = ("POSTGRES_DSN",)

# Every boot key surfaced (editable + read-only), preserving declared order.
DISPLAY_BOOT_ENV_KEYS: tuple[str, ...] = (
    "INFLUX_URL",
    "INFLUX_TOKEN",
    "POSTGRES_PASSWORD",
    "POSTGRES_DSN",
    "TZ",
)

AI_ENV_KEYS: tuple[str, ...] = (
    "AGENT_LLM_PROVIDER",
    "LITELLM_BASE_URL",
    "LITELLM_API_KEY",
    "CHAT_LLM_MODEL",
    "JOBS_LLM_MODEL",
)

# Training keys are intentionally kept OUT of ``ALLOWED_ENV_KEYS`` so the
# public ``PUT /api/v1/admin/env/{key}`` endpoint cannot toggle the
# boot-training mode of otalon-clas. They are only writeable through
# :meth:`EnvComposeService.update_training_keys`, which is invoked
# exclusively by the boundary-retraining / classifier-retraining
# orchestrator (see OpenSpec change ``add-chat-triggered-boundary-retraining``
# and ``.dev/concepts/ml-training-decoupling.md``).
#
# The ``TRAINING_CLASSIFICATION_*`` keys were added by the ML-training
# decoupling change so the classifier-retrain orchestrator can flip the
# new ``$TRAINING_CLASSIFICATION_ENABLED`` flag (which gates the ML
# stage in otalon-clas's ``_train_module``) and parametrise the ML
# training window + MITRE technique file. Bounds-retrain piggybacks on
# the same allowlist to FORCE ``TRAINING_CLASSIFICATION_ENABLED=false``
# at SET time so a bounds run can never drag ML training along.
TRAINING_ENV_KEYS: tuple[str, ...] = (
    "TRAINING_ENABLED",
    "TRAINING_BOUNDARY_TRAIN_WINDOW_START",
    "TRAINING_BOUNDARY_TRAIN_WINDOW_STOP",
    "TRAINING_CLASSIFICATION_ENABLED",
    "TRAINING_CLASSIFICATION_WINDOW_START",
    "TRAINING_CLASSIFICATION_WINDOW_STOP",
    "TRAINING_CLASSIFICATION_MITRE_TECHNIQUE_FILE",
)

AFFECTED_SERVICES_BY_KEY: dict[str, list[str]] = {
    "INFLUX_URL": ["influxdb3", "otalon-capture", "otalon-clas", "otalon-api"],
    "INFLUX_TOKEN": [
        "influxdb3",
        "otalon-capture",
        "otalon-clas",
        "otalon-api",
    ],
    "POSTGRES_PASSWORD": ["postgres"],
    "POSTGRES_DSN": ["otalon-clas", "otalon-api"],
    "TZ": [
        "postgres",
        "influxdb3",
        "otalon-capture",
        "otalon-clas",
        "otalon-api",
        "otalon-ui",
    ],
    "AGENT_LLM_PROVIDER": ["otalon-ai"],
    "LITELLM_BASE_URL": ["otalon-ai"],
    "LITELLM_API_KEY": ["otalon-ai"],
    "CHAT_LLM_MODEL": ["otalon-ai"],
    "JOBS_LLM_MODEL": ["otalon-ai"],
}


@dataclass(frozen=True)
class EnvEntry:
    """A single line entry from a .env file."""

    kind: str
    line: str
    key: str | None = None
    value: str | None = None
    sep: str = "="


class EnvComposeService:
    """Service for managing .env.compose configuration."""

    def __init__(self, settings: Settings, max_backups: int = 10) -> None:
        """Initialize the ENV compose service.

        Args:
            settings: Application settings containing the env_compose_path.
            max_backups: Maximum number of backup files to keep.
        """
        self._path = settings.env_compose_path
        self._dir = os.path.dirname(self._path) or "."
        self._max_backups = max_backups
        self._entries: list[EnvEntry] = []
        self._kv_index: dict[str, int] = {}
        self._loaded: bool = False

    def load(self) -> None:
        """Load and parse the .env.compose file.

        Re-reads the file from disk on every call to ensure freshness.
        """
        lines: list[str] = []
        try:
            with open(self._path, encoding="utf-8") as f:
                lines = f.read().splitlines(keepends=False)
        except FileNotFoundError:
            logger.warning(".env file not found: {} (will be created on save)", self._path)
        except Exception as exc:
            logger.error(".env file could not be read: {}", exc)

        self._entries = []
        self._kv_index = {}
        kv_pattern = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$")

        for raw in lines:
            line = raw.rstrip("\n")
            if not line.strip():
                self._entries.append(EnvEntry(kind="blank", line=line))
                continue
            if line.strip().startswith("#"):
                self._entries.append(EnvEntry(kind="comment", line=line))
                continue
            m = kv_pattern.match(line)
            if m:
                key, value = m.group(1), m.group(2)
                entry = EnvEntry(kind="kv", line=line, key=key, value=value, sep="=")
                self._entries.append(entry)
                if key not in self._kv_index:
                    self._kv_index[key] = len(self._entries) - 1
            else:
                self._entries.append(EnvEntry(kind="other", line=line))

        self._loaded = True

    def to_dict(self) -> dict[str, str]:
        """Return all key-value pairs as a dictionary.

        Returns:
            A dict mapping ENV keys to their string values.
        """
        self._ensure_loaded()
        out: dict[str, str] = {}
        for entry in self._entries:
            if entry.kind == "kv" and entry.key is not None:
                out[entry.key] = entry.value or ""
        return out

    def get_masked_env(self, reveal_sensitive: bool = False, full_mask_sensitive: bool = False) -> dict[str, str]:
        """Return ENV vars with sensitive values masked.

        Args:
            reveal_sensitive: If True, show full values for sensitive keys.

        Returns:
            A dict of ENV key-value pairs with sensitive values masked.
        """
        raw = self.to_dict()
        out: dict[str, str] = {}
        for key, value in raw.items():
            if _is_sensitive(key) and not reveal_sensitive:
                out[key] = _mask_value(value, full=full_mask_sensitive)
            else:
                out[key] = value
        return out

    def update_and_save(
        self, updates: dict[str, str], create_backup: bool = True
    ) -> tuple[dict[str, str], list[str], str | None]:
        """Validate, update, and atomically write ENV changes.

        Args:
            updates: Mapping of keys to their new values.
            create_backup: Whether to create a backup before writing.

        Returns:
            A tuple of (new_env_dict, changed_keys, backup_path).

        Raises:
            ValueError: If any key is not in the allowed list or validation fails.
        """
        self.load()
        errors = _validate_updates(updates)
        if errors:
            raise ValueError("; ".join(errors))

        current = self.to_dict()
        effective_updates = {k: v for k, v in updates.items() if k in ALLOWED_ENV_KEYS}
        if not effective_updates:
            return current, [], None

        backup_path: str | None = None
        if create_backup:
            backup_path = self._backup()

        new_entries = list(self._entries)
        changed_keys: list[str] = []
        for key, new_value in effective_updates.items():
            old_value = current.get(key)
            if str(old_value) != str(new_value):
                self._set_or_append_kv(new_entries, key, str(new_value))
                changed_keys.append(key)

        if not changed_keys:
            return current, [], backup_path

        lines = [entry.line for entry in new_entries]
        self._write_atomic(lines)
        self._entries = new_entries
        new_env = self.to_dict()
        return new_env, changed_keys, backup_path

    def update_training_keys(
        self, updates: dict[str, str], create_backup: bool = True
    ) -> tuple[dict[str, str], list[str], str | None]:
        """Atomically write the three boot-training control keys.

        Bypasses :data:`ALLOWED_ENV_KEYS` (which guards the operator-facing
        ``PUT /api/v1/admin/env/{key}`` endpoint) and instead enforces a
        bounded micro-allowlist matching :data:`TRAINING_ENV_KEYS`. The
        method is invoked exclusively by the boundary-retraining
        orchestrator (OpenSpec change
        ``add-chat-triggered-boundary-retraining`` § 1.2 / § 1.5).
        Keeping the training keys out of the public allowlist preserves
        the constraint that a chat-triggered retrain is the only path
        that can flip ``TRAINING_ENABLED``.

        Update semantics, atomic write and backup behaviour are identical
        to :meth:`update_and_save`; only the allowlist differs.

        Args:
            updates: Subset of :data:`TRAINING_ENV_KEYS` to update.
            create_backup: Whether to create a backup before writing.

        Returns:
            ``(new_env_dict, changed_keys, backup_path)``.

        Raises:
            ValueError: If any key is not in :data:`TRAINING_ENV_KEYS` or
                any value fails its per-key validation.
        """
        # Always re-read from disk: the orchestrator may run hours apart
        # from any other env change and we must never write back stale
        # cached entries.
        self.load()

        errors: list[str] = []
        bool_keys = {"TRAINING_ENABLED", "TRAINING_CLASSIFICATION_ENABLED"}
        for key, value in (updates or {}).items():
            if key not in TRAINING_ENV_KEYS:
                errors.append(f"Key '{key}' is not a training control key. " f"Allowed: {list(TRAINING_ENV_KEYS)}.")
                continue
            if key in bool_keys:
                norm = str(value).strip().lower()
                if norm not in ("true", "false"):
                    errors.append(f"{key} must be 'true' or 'false' (got: {value!r}).")
            else:
                # Window timestamps + MITRE technique file path. Phase-6
                # F3 (audit ``add-chat-triggered-boundary-retraining``):
                # the orchestrator must be able to CLEAR the window /
                # path keys (set to empty string) during its FINALLY
                # reset so a stale fully-armed retrain config is not
                # left on disk. An empty string is therefore valid; any
                # non-empty value still has to be non-blank.
                # otalon-clas tolerates empty window/path values when
                # ``TRAINING_ENABLED=false``.
                s = str(value)
                if s != "" and not s.strip():
                    errors.append(f"{key} must be either empty (cleared) or a " "non-blank value.")
        if errors:
            raise ValueError("; ".join(errors))

        current = self.to_dict()
        effective_updates = {k: v for k, v in updates.items() if k in TRAINING_ENV_KEYS}
        if not effective_updates:
            return current, [], None

        backup_path: str | None = None
        if create_backup:
            backup_path = self._backup()

        new_entries = list(self._entries)
        changed_keys: list[str] = []
        for key, new_value in effective_updates.items():
            old_value = current.get(key)
            if str(old_value) != str(new_value):
                self._set_or_append_kv(new_entries, key, str(new_value))
                changed_keys.append(key)

        if not changed_keys:
            return current, [], backup_path

        lines = [entry.line for entry in new_entries]
        self._write_atomic(lines)
        self._entries = new_entries
        new_env = self.to_dict()
        logger.info(
            "EnvComposeService.update_training_keys: changed_keys={} backup={}",
            changed_keys,
            backup_path,
        )
        return new_env, changed_keys, backup_path

    def _ensure_loaded(self) -> None:
        """Load the file if not already loaded."""
        if not self._loaded:
            self.load()

    def _backup(self) -> str | None:
        """Create a timestamped backup of the .env.compose file.

        Returns:
            The path to the backup file, or None if backup was not possible.
        """
        if not os.path.exists(self._path):
            return None
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        dest = os.path.join(self._dir, f".env.compose.bak.{ts}")
        try:
            shutil.copy2(self._path, dest)
        except Exception as exc:
            logger.error("Backup failed: {}", exc)
            return None

        self._cleanup_old_backups()
        return dest

    def _cleanup_old_backups(self) -> None:
        """Remove old backups exceeding the max_backups limit."""
        try:
            backups = sorted(f for f in os.listdir(self._dir) if f.startswith(".env.compose.bak."))
            if len(backups) > self._max_backups:
                for old in backups[: len(backups) - self._max_backups]:
                    try:
                        os.remove(os.path.join(self._dir, old))
                    except Exception:
                        pass
        except Exception:
            pass

    def _write_atomic(self, new_lines: list[str]) -> None:
        """Atomically write lines to the .env.compose file.

        Args:
            new_lines: The complete list of lines to write.

        Raises:
            ValueError: If any line would produce multi-line output.
            OSError: If the write operation fails.
        """
        for line in new_lines:
            if "\n" in line or "\r" in line:
                raise ValueError("refusing to write multi-line content to .env.compose")
        os.makedirs(self._dir, exist_ok=True)
        metadata = os.stat(self._path, follow_symlinks=False) if os.path.exists(self._path) else None
        if os.path.islink(self._path) or metadata is not None and metadata.st_nlink != 1:
            raise ValueError("unsafe environment file")
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self._dir, prefix=".env.compose.tmp.")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8", newline="\n") as tmp:
                for line in new_lines:
                    tmp.write(line.rstrip("\n"))
                    tmp.write("\n")
                tmp.flush()
                os.fsync(tmp.fileno())
            if metadata is not None:
                os.chown(tmp_path, metadata.st_uid, metadata.st_gid)
                os.chmod(tmp_path, metadata.st_mode & 0o777)
            os.replace(tmp_path, self._path)
        except Exception as exc:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            raise exc

    def _set_or_append_kv(self, entries: list[EnvEntry], key: str, new_value: str) -> None:
        """Update an existing key or append a new key-value pair.

        Args:
            entries: The mutable list of entries to modify.
            key: The ENV key to set.
            new_value: The new value for the key.
        """
        fmt_val = _format_value(new_value)
        if key in self._kv_index:
            idx = self._kv_index[key]
            entry = entries[idx]
            if entry.kind == "kv":
                new_line = f"{key}{entry.sep}{fmt_val}"
                entries[idx] = EnvEntry(kind="kv", line=new_line, key=key, value=new_value, sep=entry.sep)
            else:
                entries.append(EnvEntry(kind="kv", line=f"{key}={fmt_val}", key=key, value=new_value))
        else:
            if entries and entries[-1].kind != "blank":
                entries.append(EnvEntry(kind="blank", line=""))
            entries.append(EnvEntry(kind="kv", line=f"{key}={fmt_val}", key=key, value=new_value))
            self._kv_index[key] = len(entries) - 1


def _is_sensitive(key: str) -> bool:
    """Determine if an ENV key holds a sensitive value.

    Args:
        key: The ENV variable name.

    Returns:
        True if the key likely contains a secret.
    """
    k = (key or "").upper()
    return (
        "TOKEN" in k
        or "PASSWORD" in k
        or "DSN" in k
        or k.endswith("_SECRET")
        or k.endswith("_KEY")
        or k.endswith("_ALLOWED_KEYS")
    )


def _mask_value(value: str, full: bool = False) -> str:
    """Mask a sensitive value, optionally without exposing raw characters.

    Args:
        value: The raw value to mask.

    Returns:
        The masked value string.
    """
    v = str(value or "")
    if not v:
        return ""
    if full or len(v) <= 6:
        return "*" * len(v)
    return v[:3] + "*" * max(3, len(v) - 6) + v[-3:]


ENV_VALUE_MAX_LENGTH = 4096


def _check_value_safe(key: str, value: str) -> str | None:
    """Return an error message if a value cannot be serialised safely.

    A value that contains CR/LF would inject extra lines into
    ``.env.compose``; a ``"`` or ``$`` would break out of quoting or
    trigger compose variable interpolation. The raw value is never
    echoed back because it may be a secret.

    Args:
        key: The ENV key the value belongs to (for the error message).
        value: The proposed value.

    Returns:
        An error message, or None if the value is safe to serialise.
    """
    s = str(value)
    if "\n" in s or "\r" in s:
        return f"{key} must be a single-line value (no CR/LF characters)."
    if '"' in s or "$" in s:
        return f"{key} must not contain double quotes or '$' characters."
    if len(s) > ENV_VALUE_MAX_LENGTH:
        return f"{key} exceeds the maximum length of {ENV_VALUE_MAX_LENGTH} characters."
    return None


def _format_value(value: str) -> str:
    """Format a value for writing into an .env file, quoting if needed.

    Args:
        value: The value to format.

    Returns:
        The possibly-quoted value string.

    Raises:
        ValueError: If the value cannot be serialised as a single safe line.
    """
    s = str(value) if value is not None else ""
    unsafe = _check_value_safe("value", s)
    if unsafe is not None:
        raise ValueError(unsafe)
    if re.search(r"\s", s):
        return f'"{s}"'
    return s


def _validate_updates(updates: dict[str, str]) -> list[str]:
    """Validate proposed ENV variable updates against the allowlist and rules.

    Args:
        updates: Mapping of keys to their proposed values.

    Returns:
        A list of validation error messages (empty if all valid).
    """
    errors: list[str] = []
    for key, value in (updates or {}).items():
        if key not in ALLOWED_ENV_KEYS:
            errors.append(f"Key '{key}' is not allowed.")
            continue
        if key == "TZ" and not str(value).strip():
            errors.append("TZ must not be empty.")
        if key == "INFLUX_URL" and not str(value).strip().startswith(("http://", "https://")):
            errors.append("INFLUX_URL must start with http:// or https://.")
        if key in ("INFLUX_TOKEN", "POSTGRES_PASSWORD") and not str(value).strip():
            errors.append(f"{key} must not be empty.")
    return errors
