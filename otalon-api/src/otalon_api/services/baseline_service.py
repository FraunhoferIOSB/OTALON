"""Baseline lifecycle service.

Manages curated baseline-traffic windows. A baseline is:
- a row in the ``baselines`` PostgreSQL table that pins a time window,
- a directory ``shared/pcap/baseline/<id>/`` containing hardlinks to all
  PCAP chunks recorded inside that window (so they survive ring-buffer
  rotation),
- ``index.json`` analogous to the PCAP-Recorder layout.

InfluxDB data is **not** duplicated — the agent's baseline tools query
the live bucket using the time window from PostgreSQL.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID
from zoneinfo import ZoneInfo

import psycopg2
import psycopg2.extras
from loguru import logger

from otalon_api.dependencies import get_postgres_repo
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.settings import Settings


def _to_dt(value: Any) -> Optional[datetime]:
    """Parse an ISO timestamp into a tz-aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _local_tz() -> tzinfo:
    """Resolve the local timezone the PCAP recorder uses.

    Priority: ``TZ`` env var → ``/etc/timezone`` file → system local.
    Falls back to UTC if nothing else is available.
    """
    # Raw environment read on purpose (API-043): TZ is a process-environment
    # concern read by the C library and every other process in the container,
    # not part of this service's configuration.
    name = os.environ.get("TZ")
    if not name:
        try:
            with open("/etc/timezone", "r", encoding="utf-8") as fh:
                name = fh.read().strip()
        except OSError:
            name = None
    if name:
        try:
            return ZoneInfo(name)
        except Exception:
            pass
    return datetime.now().astimezone().tzinfo or timezone.utc


_LOCAL_TZ = _local_tz()


def _filename_to_dt(filename: str) -> Optional[datetime]:
    """Convert a ``YYYYMMDD_HHMMSS.pcap`` filename to a tz-aware datetime.

    PCAP-Recorder writes filenames with the host's local clock; we attach
    the resolved local timezone (Europe/Berlin in the default deployment)
    so the value can be compared with tz-aware operator-supplied windows.
    """
    base = filename.replace(".pcap", "")
    try:
        naive = datetime.strptime(base, "%Y%m%d_%H%M%S")
    except ValueError:
        return None
    return naive.replace(tzinfo=_LOCAL_TZ)


class BaselineValidationError(Exception):
    """Raised when a baseline candidate does not meet thresholds."""

    def __init__(self, payload: Dict[str, Any]):
        super().__init__(payload.get("detail", "validation failed"))
        self.payload = payload


class BaselineNotFound(Exception):
    pass


class BaselineConflict(Exception):
    pass


class BaselineService:
    """Read-write CRUD + PCAP hardlink orchestration for baselines."""

    SQL_INIT = """
    CREATE TABLE IF NOT EXISTS baselines (
        id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name             VARCHAR(128) NOT NULL UNIQUE,
        description      TEXT,
        start_ts         TIMESTAMPTZ NOT NULL,
        end_ts           TIMESTAMPTZ NOT NULL,
        is_active        BOOLEAN NOT NULL DEFAULT FALSE,
        pcap_chunk_count INTEGER,
        uci_count        INTEGER,
        size_bytes       BIGINT,
        audit_log        JSONB NOT NULL DEFAULT '[]'::jsonb,
        archived_at      TIMESTAMPTZ,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       VARCHAR(64)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uq_baselines_active
        ON baselines (is_active) WHERE is_active = TRUE;
    CREATE INDEX IF NOT EXISTS ix_baselines_window
        ON baselines (start_ts, end_ts);
    """

    def __init__(self, settings: Settings, influx: Optional[InfluxRepository] = None) -> None:
        self._settings = settings
        self._influx = influx
        self._pg = get_postgres_repo()
        self._buffer_dir = Path(settings.pcap_buffer_dir)
        self._archive_dir = Path(settings.pcap_archive_dir)
        self._baseline_dir = Path(settings.pcap_baseline_dir)

    def ensure_schema(self) -> None:
        """Create the baselines table if missing (idempotent)."""
        with self._pg.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(self.SQL_INIT)
            conn.commit()
        logger.info("BaselineService.ensure_schema applied")

    # ── Listing / read ──────────────────────────────────────────────

    def list(self) -> List[Dict[str, Any]]:
        with self._pg.connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM baselines ORDER BY created_at DESC")
                rows = cur.fetchall()
        return [self._row_to_api(r) for r in rows]

    def get(self, baseline_id: UUID) -> Dict[str, Any]:
        with self._pg.connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM baselines WHERE id = %s", (str(baseline_id),))
                row = cur.fetchone()
        if not row:
            raise BaselineNotFound(str(baseline_id))
        return self._row_to_api(row)

    def get_active(self) -> Optional[Dict[str, Any]]:
        with self._pg.connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM baselines WHERE is_active = TRUE LIMIT 1")
                row = cur.fetchone()
        return self._row_to_api(row) if row else None

    # ── Preview ─────────────────────────────────────────────────────

    def preview(self, start_ts: datetime, end_ts: datetime) -> Dict[str, Any]:
        """Return derived stats for a candidate window without inserting."""
        chunks = self._chunks_in_window(start_ts, end_ts)
        uci_count = self._count_distinct_ucis(start_ts, end_ts)
        anomaly_count = sum(1 for c in chunks if c.get("is_anomaly"))
        size_bytes = sum(int(c.get("size_bytes", 0)) for c in chunks)
        thresholds = {
            "min_uci_count": self._settings.baseline_min_uci_count,
            "min_pcap_chunks": self._settings.baseline_min_pcap_chunks,
        }
        meets = uci_count >= thresholds["min_uci_count"] and len(chunks) >= thresholds["min_pcap_chunks"]
        return {
            "start_ts": start_ts.isoformat(),
            "end_ts": end_ts.isoformat(),
            "pcap_chunk_count": len(chunks),
            "uci_count": uci_count,
            "anomaly_count": anomaly_count,
            "size_bytes": size_bytes,
            "thresholds": thresholds,
            "meets_thresholds": meets,
        }

    # ── Create ──────────────────────────────────────────────────────

    def create(
        self,
        *,
        name: str,
        description: Optional[str],
        start_ts: datetime,
        end_ts: datetime,
        created_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        if end_ts <= start_ts:
            raise BaselineValidationError(
                {
                    "detail": "end_ts must be after start_ts",
                    "start_ts": start_ts.isoformat(),
                    "end_ts": end_ts.isoformat(),
                }
            )
        if (end_ts - start_ts).total_seconds() < 600:
            raise BaselineValidationError({"detail": "baseline window must be at least 10 minutes"})
        if end_ts > datetime.now(timezone.utc):
            raise BaselineValidationError({"detail": "baseline window must be in the past"})

        # Threshold validation
        chunks = self._chunks_in_window(start_ts, end_ts)
        uci_count = self._count_distinct_ucis(start_ts, end_ts)
        if len(chunks) < self._settings.baseline_min_pcap_chunks:
            raise BaselineValidationError(
                {
                    "detail": "insufficient PCAP chunks for baseline",
                    "pcap_chunk_count": len(chunks),
                    "min_pcap_chunks": self._settings.baseline_min_pcap_chunks,
                }
            )
        if uci_count < self._settings.baseline_min_uci_count:
            raise BaselineValidationError(
                {
                    "detail": "insufficient UCIs for baseline",
                    "uci_count": uci_count,
                    "min_uci_count": self._settings.baseline_min_uci_count,
                }
            )

        # Insert PG row
        try:
            with self._pg.connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        INSERT INTO baselines (name, description, start_ts, end_ts, created_by)
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING *
                        """,
                        (name, description, start_ts, end_ts, created_by),
                    )
                    row = cur.fetchone()
                conn.commit()
        except psycopg2.errors.UniqueViolation as exc:
            raise BaselineConflict(f"baseline name '{name}' already exists") from exc

        baseline_id = row["id"]
        # Hardlink PCAP chunks
        try:
            chunk_count, size_bytes, used_copy_fallback = self._materialise_chunks(baseline_id, chunks, name=name)
        except Exception:
            # Roll back DB on filesystem failure
            with self._pg.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM baselines WHERE id = %s", (str(baseline_id),))
                conn.commit()
            raise

        # Update derived stats
        with self._pg.connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    UPDATE baselines
                    SET pcap_chunk_count = %s, uci_count = %s, size_bytes = %s
                    WHERE id = %s
                    RETURNING *
                    """,
                    (chunk_count, uci_count, size_bytes, str(baseline_id)),
                )
                row = cur.fetchone()
            conn.commit()
        logger.info(
            "Baseline created id={} name={} chunks={} uci_count={} copy_fallback={}",
            baseline_id,
            name,
            chunk_count,
            uci_count,
            used_copy_fallback,
        )
        return self._row_to_api(row)

    # ── Activate ────────────────────────────────────────────────────

    def activate(self, baseline_id: UUID, user: Optional[str] = None) -> Dict[str, Any]:
        with self._pg.connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT id, is_active FROM baselines WHERE id = %s", (str(baseline_id),))
                row = cur.fetchone()
                if not row:
                    raise BaselineNotFound(str(baseline_id))
                if row["is_active"]:
                    cur.execute("SELECT * FROM baselines WHERE id = %s", (str(baseline_id),))
                    return self._row_to_api(cur.fetchone())
                # Find prior active
                cur.execute("SELECT id FROM baselines WHERE is_active = TRUE LIMIT 1")
                prior = cur.fetchone()
                prior_id = prior["id"] if prior else None
                # Deactivate prior
                if prior_id:
                    cur.execute(
                        """
                        UPDATE baselines SET is_active = FALSE,
                            audit_log = audit_log || jsonb_build_array(jsonb_build_object(
                                'action', 'deactivated_by_activation_of',
                                'timestamp', to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                                'new_active_id', %s,
                                'user', %s
                            ))
                        WHERE id = %s
                        """,
                        (str(baseline_id), user, str(prior_id)),
                    )
                # Activate target
                cur.execute(
                    """
                    UPDATE baselines SET is_active = TRUE,
                        audit_log = audit_log || jsonb_build_array(jsonb_build_object(
                            'action', 'activated',
                            'timestamp', to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                            'previous_active_id', %s,
                            'user', %s
                        ))
                    WHERE id = %s
                    RETURNING *
                    """,
                    (str(prior_id) if prior_id else None, user, str(baseline_id)),
                )
                row = cur.fetchone()
            conn.commit()
        logger.info("Baseline activated id={} previous_active={}", baseline_id, prior_id)
        return self._row_to_api(row)

    # ── Delete ──────────────────────────────────────────────────────

    def delete(self, baseline_id: UUID) -> None:
        with self._pg.connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT id, is_active FROM baselines WHERE id = %s", (str(baseline_id),))
                row = cur.fetchone()
                if not row:
                    raise BaselineNotFound(str(baseline_id))
                if row["is_active"]:
                    raise BaselineConflict("cannot delete active baseline; activate another first")
                cur.execute("DELETE FROM baselines WHERE id = %s", (str(baseline_id),))
            conn.commit()
        # Remove hardlink directory
        target_dir = self._baseline_dir / str(baseline_id)
        if target_dir.exists():
            try:
                shutil.rmtree(target_dir)
                logger.info("Baseline deleted id={} removed dir={}", baseline_id, target_dir)
            except Exception as exc:
                logger.warning("Could not remove baseline dir {}: {}", target_dir, exc)

    # ── Internals ───────────────────────────────────────────────────

    def _chunks_in_window(self, start_ts: datetime, end_ts: datetime) -> List[Dict[str, Any]]:
        """Walk buffer + archive dirs, return all matching chunks."""
        chunks: List[Dict[str, Any]] = []
        for source_dir in (self._buffer_dir, self._archive_dir):
            if not source_dir.is_dir():
                continue
            try:
                entries = sorted(os.listdir(source_dir))
            except OSError:
                continue
            for fn in entries:
                if not fn.endswith(".pcap"):
                    continue
                dt = _filename_to_dt(fn)
                if dt is None:
                    continue
                if start_ts <= dt < end_ts:
                    full = source_dir / fn
                    try:
                        size = full.stat().st_size
                    except OSError:
                        size = 0
                    is_anomaly = self._is_anomaly_chunk(fn)
                    chunks.append(
                        {
                            "filename": fn,
                            "source_path": str(full),
                            "start_ts": dt.isoformat(),
                            "end_ts": (dt.replace(tzinfo=timezone.utc).timestamp() + 30),
                            "size_bytes": size,
                            "is_anomaly": is_anomaly,
                        }
                    )
        return chunks

    def _is_anomaly_chunk(self, filename: str) -> bool:
        """Best-effort lookup of the chunk's anomaly flag from buffer index."""
        idx = self._buffer_dir / "pcap_index.json"
        if not idx.is_file():
            return False
        try:
            with open(idx, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return False
        for entry in data:
            if entry.get("filename") == filename:
                return bool(entry.get("is_anomaly"))
        return False

    def _count_distinct_ucis(self, start_ts: datetime, end_ts: datetime) -> int:
        """Count distinct UCIs (id_tag) observed in the window via InfluxDB.

        Best-effort: returns 0 if InfluxDB is unavailable.
        """
        if self._influx is None:
            return 0
        try:
            ids = self._influx.list_ids_between(
                measurement=self._settings.netcap_measurement,
                id_tag=self._settings.netcap_id_tag,
                start=start_ts.isoformat(),
                stop=end_ts.isoformat(),
            )
            return len(set(ids or []))
        except Exception as exc:
            logger.warning("Could not count UCIs from InfluxDB: {}", exc)
            return 0

    def _materialise_chunks(
        self, baseline_id: UUID, chunks: List[Dict[str, Any]], *, name: str
    ) -> Tuple[int, int, bool]:
        """Hardlink (or copy) all chunks into the baseline dir. Write index.json."""
        target_dir = self._baseline_dir / str(baseline_id)
        target_dir.mkdir(parents=True, exist_ok=True)
        used_copy = False
        size_total = 0
        index: List[Dict[str, Any]] = []
        for c in chunks:
            src = Path(c["source_path"])
            dst = target_dir / c["filename"]
            if dst.exists():
                continue
            try:
                os.link(src, dst)
            except OSError as exc:
                if exc.errno == errno.EXDEV:
                    if not used_copy:
                        logger.warning(
                            "Cross-filesystem detected, falling back to copy for baseline {}",
                            baseline_id,
                        )
                    used_copy = True
                    shutil.copy2(src, dst)
                else:
                    raise
            try:
                size_total += dst.stat().st_size
            except OSError:
                pass
            index.append(
                {
                    "filename": c["filename"],
                    "start_ts": c["start_ts"],
                    "size_bytes": c["size_bytes"],
                    "is_anomaly": c.get("is_anomaly", False),
                    "labels": {"baseline_id": str(baseline_id), "baseline_name": name},
                }
            )
        # Write index
        idx_path = target_dir / "index.json"
        with open(idx_path, "w", encoding="utf-8") as fh:
            json.dump(index, fh, ensure_ascii=False, indent=2)
        return len(index), size_total, used_copy

    @staticmethod
    def _row_to_api(row: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(row)
        for key in ("id",):
            if key in out and out[key] is not None:
                out[key] = str(out[key])
        for key in ("start_ts", "end_ts", "created_at", "archived_at"):
            v = out.get(key)
            if isinstance(v, datetime):
                out[key] = v.isoformat()
        return out
