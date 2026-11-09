"""Match alarm groups to MITRE ground-truth labels for training.

Loads a ``mitre_techniques_log.json`` file, then assigns each alarm a
``technical_method`` label by finding the ground-truth entry whose time
window overlaps the alarm window. The MITRE-attack-method label space
matches the workshop ``ml-baseline`` baseline.

The ground-truth file uses *naive* timestamps that are interpreted in a
configurable local timezone (default ``Europe/Berlin``); this matches
the convention used in CISF logs and the workshop ``ml-baseline``
config.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from zoneinfo import ZoneInfo

from loguru import logger

DEFAULT_GROUND_TRUTH_TIMEZONE: str = "Europe/Berlin"


@dataclass(frozen=True, slots=True)
class GroundTruthEntry:
    """A single ground-truth attack episode."""

    technical_method: str
    module_name: str
    start_time: datetime
    end_time: datetime


class GroupAlarmLabeler:
    """Assigns ``technical_method`` labels to alarms.

    An alarm matches a ground-truth entry when the two time windows
    overlap, accounting for an optional symmetric tolerance margin. When
    multiple ground-truth entries overlap, the entry with the largest
    overlap duration wins.

    Args:
        ground_truth_path: Path to a JSON file containing a list of
            ground-truth entries with ``technical_method`` and
            ``start_time`` / ``end_time`` keys.
        time_margin_seconds: Symmetric tolerance applied to ground-truth
            windows during matching.
        ground_truth_timezone: IANA timezone name used to localize
            naive timestamps in the ground-truth file. The workshop
            convention is ``Europe/Berlin``.
    """

    def __init__(
        self,
        ground_truth_path: str | Path,
        time_margin_seconds: int = 30,
        ground_truth_timezone: str = DEFAULT_GROUND_TRUTH_TIMEZONE,
    ) -> None:
        """Initialize the labeler from a ground-truth file."""
        self._entries: list[GroundTruthEntry] = []
        self._margin = timedelta(seconds=time_margin_seconds)
        try:
            self._gt_tz: ZoneInfo | None = ZoneInfo(ground_truth_timezone)
        except Exception:
            logger.warning(
                "Unknown ground_truth_timezone '{}', falling back to UTC",
                ground_truth_timezone,
            )
            self._gt_tz = None
        self._load(Path(ground_truth_path))

    def _load(self, path: Path) -> None:
        """Read the ground-truth JSON and populate the entry list.

        Args:
            path: Path to the ground-truth file.

        Raises:
            FileNotFoundError: If ``path`` does not exist.
        """
        if not path.exists():
            msg = f"Ground-truth file not found: {path}"
            raise FileNotFoundError(msg)

        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            msg = "Ground-truth file must contain a JSON array of entries"
            raise ValueError(msg)

        loaded = 0
        for item in raw:
            method = str(item.get("technical_method", "")).strip()
            module = str(item.get("module_name", "")).strip()
            start = _parse_iso(item.get("start_time"), default_tz=self._gt_tz)
            end = _parse_iso(item.get("end_time"), default_tz=self._gt_tz)
            if not method or start is None or end is None:
                continue
            self._entries.append(
                GroundTruthEntry(
                    technical_method=method,
                    module_name=module,
                    start_time=start,
                    end_time=end,
                )
            )
            loaded += 1

        logger.info(
            "GroupAlarmLabeler: loaded {} ground-truth entries from {}",
            loaded,
            path,
        )

    @property
    def technical_methods(self) -> set[str]:
        """Return the set of distinct technical_method labels in the GT file."""
        return {e.technical_method for e in self._entries}

    def label(self, start_ts: datetime, end_ts: datetime) -> str | None:
        """Return the label for an alarm window, or ``None`` if none matches.

        Uses temporal overlap with a symmetric margin: the alarm window
        ``[start_ts, end_ts]`` is compared against
        ``[entry.start - margin, entry.end + margin]``. The entry with
        the largest overlap wins. Zero-duration alarm windows
        (``start_ts == end_ts``) are supported because the comparison
        uses ``>=``: a point-in-time alarm that falls inside the
        margin-padded ground-truth window matches with overlap zero.

        Args:
            start_ts: Alarm start timestamp.
            end_ts: Alarm end timestamp.

        Returns:
            ``technical_method`` of the best-matching ground-truth
            entry, or ``None`` when no entry overlaps within the
            configured tolerance.
        """
        a_start = _ensure_utc(start_ts)
        a_end = _ensure_utc(end_ts)

        best_method: str | None = None
        best_overlap: timedelta | None = None

        for entry in self._entries:
            gt_start = entry.start_time - self._margin
            gt_end = entry.end_time + self._margin
            overlap_start = max(a_start, gt_start)
            overlap_end = min(a_end, gt_end)
            if overlap_end < overlap_start:
                continue
            overlap = overlap_end - overlap_start
            if best_overlap is None or overlap > best_overlap:
                best_overlap = overlap
                best_method = entry.technical_method

        return best_method

    def label_alarms(
        self,
        alarms: Iterable[tuple[str, datetime, datetime]],
    ) -> list[tuple[str, str | None]]:
        """Bulk-label a sequence of ``(alarm_id, start_ts, end_ts)`` tuples.

        Args:
            alarms: Iterable of alarm key/window triples.

        Returns:
            List of ``(alarm_id, label_or_none)`` tuples preserving order.
        """
        return [(aid, self.label(start, end)) for aid, start, end in alarms]


def _parse_iso(value: object, default_tz: ZoneInfo | None = None) -> datetime | None:
    """Parse a timestamp value to a UTC-aware datetime.

    Accepts ``datetime`` objects, ISO 8601 strings with or without
    timezone information, and the legacy ``"YYYY-MM-DD HH:MM:SS"`` form.
    Naive timestamps are localized using ``default_tz`` (defaults to
    UTC when ``None``) before being converted to UTC.

    Args:
        value: Raw value from the ground-truth JSON.
        default_tz: Timezone to assume for naive inputs.

    Returns:
        UTC-aware datetime, or ``None`` if the value cannot be parsed.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return _localize_and_utc(value, default_tz)
    text = str(value).strip()
    if not text:
        return None
    candidate = text.replace(" ", "T")
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return _localize_and_utc(dt, default_tz)


def _localize_and_utc(dt: datetime, default_tz: ZoneInfo | None) -> datetime:
    """Attach ``default_tz`` to naive datetimes, then convert to UTC.

    Args:
        dt: Datetime to normalize.
        default_tz: Timezone for naive inputs (``None`` falls back to UTC).

    Returns:
        UTC-aware datetime.
    """
    if dt.tzinfo is None:
        if default_tz is not None:
            dt = dt.replace(tzinfo=default_tz)
        else:
            dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure the datetime carries UTC timezone information."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
