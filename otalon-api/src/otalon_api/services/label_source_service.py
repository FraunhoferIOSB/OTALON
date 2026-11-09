"""Validated shared-folder management for classifier ground-truth files."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

LABEL_SOURCE_MAX_BYTES = 5 * 1024 * 1024
# Single max-basename contract, in characters, for the part of the filename
# BEFORE the ``.json`` suffix. ``_FILENAME_RE`` is generated from this constant
# so the regex quantifier can never drift from it. The character class is
# ASCII-only ([A-Za-z0-9._-]), so one character is exactly one UTF-8 byte here:
# the maximum basename is 128 characters == 128 bytes, and the full filename is
# at most 128 + len(".json") = 133 bytes. Unicode is disallowed by the class, so
# a multi-byte code point can never inflate the byte length past the char limit.
LABEL_SOURCE_MAX_BASENAME_CHARS = 128
_FILENAME_SUFFIX = ".json"
LABEL_SOURCE_MAX_FILENAME_BYTES = LABEL_SOURCE_MAX_BASENAME_CHARS + len(_FILENAME_SUFFIX)
# Bounded ceiling for the raw ``{filename, content}`` JSON request body. The
# ``content`` field carries the label file as a JSON *string*, and JSON string
# escaping can inflate a valid <=5 MiB decoded file well beyond ~5 MiB on the
# wire: ``json.dumps`` escapes every control character and every non-ASCII code
# point to a 6-byte ``\uXXXX`` sequence, so the worst realistic expansion is
# ~6x the decoded content. The transport ceiling is therefore 6x the content
# limit plus a small bounded envelope (filename + JSON punctuation), keeping
# request buffering bounded while never rejecting a structurally valid upload
# whose *decoded* content is <=5 MiB. Decoded content is still validated strict
# <=5 MiB downstream (see ``validate_label_content`` / ``save_upload``).
LABEL_SOURCE_ENVELOPE_BYTES = LABEL_SOURCE_MAX_FILENAME_BYTES + 256
LABEL_SOURCE_MAX_TRANSPORT_BYTES = 6 * LABEL_SOURCE_MAX_BYTES + LABEL_SOURCE_ENVELOPE_BYTES
LABEL_SOURCE_WORKER_DIR = "/app/models"
# First char + up to (MAX_BASENAME_CHARS - 1) more, then the ``.json`` suffix.
_FILENAME_RE = re.compile(rf"^[A-Za-z0-9][A-Za-z0-9._-]{{0,{LABEL_SOURCE_MAX_BASENAME_CHARS - 1}}}\{_FILENAME_SUFFIX}$")
# Downstream-safe calendar-date grammar for the DATE component of a timestamp.
# ``datetime.fromisoformat`` (3.11+) also accepts ISO week-date
# (``2026-W30-3``) and ordinal-date (``2026-100``) forms that the consumer's
# ``pandas.Timestamp`` rejects, so upload validation would be a *superset* of
# downstream acceptance. Constrain the date to extended (``YYYY-MM-DD``) or
# basic (``YYYYMMDD``) calendar form only, which is the subset pandas parses,
# without importing pandas into the API. Time/offset/fractional handling is
# still delegated to ``fromisoformat`` after this gate.
_CALENDAR_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$|^\d{8}$")


class LabelSource(BaseModel):
    """Worker-visible metadata for one validated ground-truth file."""

    filename: str
    worker_path: str
    size_bytes: int = Field(ge=0)
    label_count: int = Field(ge=1)


class LabelSourceList(BaseModel):
    """Response containing validated sources and aggregate invalid-file state."""

    items: list[LabelSource]
    invalid_file_count: int = Field(ge=0)
    warning: str | None = None


class LabelSourceValidationError(ValueError):
    """Raised when uploaded or discovered content is not a valid label file."""


class LabelSourceTooLargeError(LabelSourceValidationError):
    """Raised when decoded label content exceeds the strict 5 MiB limit.

    A dedicated subclass so the API can answer ``413 Payload Too Large`` for a
    clearly-oversized *decoded* file (as opposed to ``422`` for a malformed but
    reasonably-sized one) while service callers that only care about validity
    can still catch the :class:`LabelSourceValidationError` base.
    """


class LabelSourceConflictError(FileExistsError):
    """Raised when an upload would overwrite an existing source."""


class LabelSourceService:
    """List and atomically persist safe, worker-readable label files."""

    def __init__(self, model_dir: str | Path, worker_dir: str = LABEL_SOURCE_WORKER_DIR) -> None:
        self._model_dir = Path(model_dir).resolve()
        self._worker_dir = worker_dir.rstrip("/") or LABEL_SOURCE_WORKER_DIR

    def list_sources(self) -> LabelSourceList:
        """Return only directly stored, valid JSON regular files."""
        if not self._model_dir.is_dir():
            return LabelSourceList(items=[], invalid_file_count=0)
        items: list[LabelSource] = []
        invalid_count = 0
        for path in sorted(self._model_dir.iterdir(), key=lambda item: item.name):
            if path.suffix.lower() != ".json":
                continue
            if not self._is_regular_file(path):
                invalid_count += 1
                continue
            try:
                content = path.read_bytes()
                label_count = validate_label_content(content)
            except (OSError, LabelSourceValidationError):
                invalid_count += 1
                continue
            items.append(self._metadata(path.name, len(content), label_count))
        warning = f"{invalid_count} JSON file(s) excluded because validation failed." if invalid_count else None
        return LabelSourceList(items=items, invalid_file_count=invalid_count, warning=warning)

    def save_upload(self, filename: str, content: bytes) -> LabelSource:
        """Validate and atomically create one source without overwriting."""
        safe_name = validate_filename(filename)
        if len(content) > LABEL_SOURCE_MAX_BYTES:
            raise LabelSourceTooLargeError("label source exceeds the 5 MiB size limit")
        label_count = validate_label_content(content)
        self._model_dir.mkdir(parents=True, exist_ok=True)
        destination = self._model_dir / safe_name
        if destination.exists() or destination.is_symlink():
            raise LabelSourceConflictError(f"label source '{safe_name}' already exists")
        temp_path: Path | None = None
        try:
            fd, temp_name = tempfile.mkstemp(prefix=".label-source.", suffix=".tmp", dir=self._model_dir)
            temp_path = Path(temp_name)
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temp_path, destination)
            except FileExistsError as exc:
                raise LabelSourceConflictError(f"label source '{safe_name}' already exists") from exc
            directory_fd = os.open(self._model_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            temp_path.unlink()
            temp_path = None
            return self._metadata(safe_name, len(content), label_count)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def _metadata(self, filename: str, size_bytes: int, label_count: int) -> LabelSource:
        return LabelSource(
            filename=filename,
            worker_path=f"{self._worker_dir}/{filename}",
            size_bytes=size_bytes,
            label_count=label_count,
        )

    @staticmethod
    def _is_regular_file(path: Path) -> bool:
        return not path.is_symlink() and path.is_file()


def validate_filename(filename: str) -> str:
    """Validate a basename-only JSON filename."""
    if Path(filename).name != filename or not _FILENAME_RE.fullmatch(filename):
        raise LabelSourceValidationError("filename must be a safe basename ending in .json")
    return filename


def validate_label_content(content: bytes) -> int:
    """Validate label JSON shape, fields, timestamps, and downstream-safe types."""
    if len(content) > LABEL_SOURCE_MAX_BYTES:
        raise LabelSourceTooLargeError("label source exceeds the 5 MiB size limit")
    try:
        raw = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LabelSourceValidationError("content must be valid UTF-8 JSON") from exc
    entries = [raw] if isinstance(raw, dict) else raw
    if not isinstance(entries, list) or not entries:
        raise LabelSourceValidationError("content must be a non-empty object or list")
    for index, entry in enumerate(entries):
        _validate_entry(entry, index)
    return len(entries)


def _validate_entry(entry: Any, index: int) -> None:
    if not isinstance(entry, dict):
        raise LabelSourceValidationError(f"entry {index} must be an object")
    for field in ("module_name", "start_time", "end_time"):
        if not isinstance(entry.get(field), str) or not entry[field].strip():
            raise LabelSourceValidationError(f"entry {index} requires non-empty string '{field}'")
    start = _parse_timestamp(entry["start_time"], index, "start_time")
    end = _parse_timestamp(entry["end_time"], index, "end_time")
    if start > end:
        raise LabelSourceValidationError(f"entry {index} start_time must not be after end_time")
    for field in ("technical_method", "protocol", "source_ip", "source_mac"):
        if field in entry and not isinstance(entry[field], str):
            raise LabelSourceValidationError(f"entry {index} field '{field}' must be a string")
    for field in ("target_ip", "target_mac"):
        if field in entry and (
            not isinstance(entry[field], list) or any(not isinstance(item, str) for item in entry[field])
        ):
            raise LabelSourceValidationError(f"entry {index} field '{field}' must be a list of strings")
    if "technique_id" in entry and (
        not isinstance(entry["technique_id"], list) or any(not isinstance(item, str) for item in entry["technique_id"])
    ):
        raise LabelSourceValidationError(f"entry {index} field 'technique_id' must be a list of strings")


def _parse_timestamp(value: str, index: int, field: str) -> datetime:
    normalized = value.replace("Z", "+00:00").replace(" ", "T")
    _reject_non_calendar_date(normalized, index, field)
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise LabelSourceValidationError(f"entry {index} field '{field}' must be an ISO-8601 timestamp") from exc


def _reject_non_calendar_date(normalized: str, index: int, field: str) -> None:
    """Reject ISO forms whose date component pandas will not parse downstream.

    Splits off the date component (before the ``T`` time separator) and requires
    it to be an extended or basic *calendar* date, rejecting ISO week-date and
    ordinal-date forms that ``datetime.fromisoformat`` accepts but the consumer's
    ``pandas.Timestamp`` rejects.
    """
    date_part = normalized.split("T", 1)[0]
    if not _CALENDAR_DATE_RE.match(date_part):
        raise LabelSourceValidationError(f"entry {index} field '{field}' must be a calendar-date ISO-8601 timestamp")
