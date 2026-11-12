"""Capture-owned durable custody, versioned carry and exact-write outbox.

Receipts acknowledge bytes, never detector coverage. A file end does not seal a
logical packet window. SQLite and immutable blobs are kept on a local POSIX FS.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import threading
import time
from pathlib import Path

from .pcap import validate

IDENTITY = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
MAX_STATE = 96_000_000
MAX_PAYLOAD = 32_000_000


class Ledger:
    def __init__(self, root: Path, max_bytes: int = 2_000_000_000, min_free: int = 0):
        self.root = Path(root).absolute()
        for part in (self.root, *self.root.parents):
            if part.is_symlink():
                raise ValueError("unsafe ledger root")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.raw = self.root / "raw"
        self.raw.mkdir(exist_ok=True, mode=0o700)
        if self.raw.is_symlink() or (self.root / "progress.sqlite3").is_symlink():
            raise ValueError("unsafe ledger files")
        self.max_bytes, self.min_free = max_bytes, min_free
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.root / "progress.sqlite3", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS metadata(version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,
     predecessor TEXT UNIQUE REFERENCES runs(id),
     seq INTEGER UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS run_config(run TEXT PRIMARY KEY REFERENCES runs(id),
     interface TEXT NOT NULL,
     fingerprint TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chunks(id TEXT PRIMARY KEY,
     run TEXT REFERENCES runs(id),
     ordinal INTEGER NOT NULL,
     hash TEXT NOT NULL,
     size INTEGER NOT NULL,
     path TEXT NOT NULL,
     packets INTEGER NOT NULL,
     first_ns INTEGER,
     last_ns INTEGER,
     consumed INTEGER NOT NULL DEFAULT 0,
     UNIQUE(run,
    ordinal));
CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS batches(id INTEGER PRIMARY KEY AUTOINCREMENT,
     chunk TEXT NOT NULL REFERENCES chunks(id),
     payload TEXT NOT NULL,
     committed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS run_ends(run TEXT PRIMARY KEY REFERENCES runs(id), last_ordinal INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL, seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS consumer_ack(module TEXT PRIMARY KEY, batch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS points(identity TEXT PRIMARY KEY,fields TEXT NOT NULL);
""")
        row = self.db.execute("SELECT version FROM metadata").fetchone()
        if row is None:
            self.db.execute("INSERT INTO metadata VALUES(1)")
            self.db.commit()
        elif row[0] != 1:
            raise ValueError("unsupported ledger version")
        if self.db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("ledger integrity failure")
        self._observation_at: float | None = None

    def close(self):
        self.db.close()

    def register_run(self, run: str, predecessor: str | None, interface: str = "fixture", fingerprint: str = ""):
        if not IDENTITY.fullmatch(run) or predecessor is not None and not IDENTITY.fullmatch(predecessor):
            raise ValueError("invalid run")
        if not interface or len(interface) > 256 or fingerprint and not HASH.fullmatch(fingerprint):
            raise ValueError("invalid run configuration")
        with self.lock, self.db:
            old = self.db.execute("SELECT * FROM runs WHERE id=?", (run,)).fetchone()
            config = self.db.execute("SELECT * FROM run_config WHERE run=?", (run,)).fetchone()
            if old:
                if (
                    old["predecessor"] != predecessor
                    or config
                    and (config["interface"], config["fingerprint"]) != (interface, fingerprint)
                ):
                    raise ValueError("run configuration conflict")
                return
            last = self.db.execute("SELECT * FROM runs ORDER BY seq DESC LIMIT 1").fetchone()
            if predecessor != (last["id"] if last else None):
                raise ValueError("unknown predecessor")
            if last:
                prior = self.db.execute("SELECT * FROM run_config WHERE run=?", (last["id"],)).fetchone()
                if prior and (prior["interface"], prior["fingerprint"]) != (interface, fingerprint):
                    raise ValueError("capture configuration conflict: new segment requires explicit reconciliation")
            self.db.execute("INSERT INTO runs VALUES(?,?,?)", (run, predecessor, last["seq"] + 1 if last else 0))
            self.db.execute("INSERT INTO run_config VALUES(?,?,?)", (run, interface, fingerprint))

    def receive(self, run: str, ordinal: int, data: bytes):
        if ordinal < 0 or ordinal > 2**31 - 1 or not IDENTITY.fullmatch(run):
            raise ValueError("invalid identity")
        count, first, last = validate(data)
        digest = hashlib.sha256(data).hexdigest()
        ident = hashlib.sha256((run + ":" + str(ordinal)).encode()).hexdigest()
        with self.lock, self.db:
            old = self.db.execute("SELECT * FROM chunks WHERE run=? AND ordinal=?", (run, ordinal)).fetchone()
            if old:
                if old["hash"] != digest:
                    raise ValueError("immutable chunk conflict")
                return {"id": old["id"], "hash": old["hash"], "accepted": True}
            if not self.db.execute("SELECT 1 FROM runs WHERE id=?", (run,)).fetchone():
                raise ValueError("run unregistered")
            end = self.db.execute("SELECT last_ordinal FROM run_ends WHERE run=?", (run,)).fetchone()
            if end and ordinal > end[0]:
                raise ValueError("final ordinal conflict")
            total = self.db.execute("SELECT COALESCE(SUM(size),0) FROM chunks").fetchone()[0]
            if total + len(data) > self.max_bytes or shutil.disk_usage(self.root).free - len(data) < self.min_free:
                raise ValueError("custody storage full")
            if self.db.execute("SELECT count(*) FROM chunks WHERE consumed=0").fetchone()[0] >= 1024:
                raise ValueError("custody queue full")
            path = self.raw / ("rx_" + ident[:40] + ".pcap")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(path, flags, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError:
                if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise ValueError("raw identity conflict")
            fd = os.open(self.raw, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            self.db.execute(
                "INSERT INTO chunks VALUES(?,?,?,?,?,?,?,?,?,0)",
                (ident, run, ordinal, digest, len(data), str(path), count, first, last),
            )
            return {"id": ident, "hash": digest, "accepted": True}

    def receipt(self, run, ordinal):
        with self.lock:
            row = self.db.execute("SELECT * FROM chunks WHERE run=? AND ordinal=?", (run, ordinal)).fetchone()
            if not row:
                return None
            pending = self.db.execute("SELECT 1 FROM batches WHERE chunk=? AND committed=0", (row["id"],)).fetchone()
            return {
                "id": row["id"],
                "hash": row["hash"],
                "size_bytes": row["size"],
                "custody": "accepted",
                "processing": "pending" if not row["consumed"] else "prepared" if pending else "carry_or_published",
            }

    def next_chunk(self):
        with self.lock:
            for run in self.db.execute("SELECT * FROM runs ORDER BY seq"):
                consumed = self.db.execute(
                    "SELECT MAX(ordinal) FROM chunks WHERE run=? AND consumed=1", (run["id"],)
                ).fetchone()[0]
                ordinal = 0 if consumed is None else consumed + 1
                row = self.db.execute("SELECT * FROM chunks WHERE run=? AND ordinal=?", (run["id"], ordinal)).fetchone()
                if row and not row["consumed"]:
                    return dict(row)
                end = self.db.execute("SELECT last_ordinal FROM run_ends WHERE run=?", (run["id"],)).fetchone()
                if not end or ordinal <= end[0]:
                    return None
            return None

    def close_run(self, run, last_ordinal):
        if last_ordinal < -1:
            raise ValueError("invalid final ordinal")
        with self.lock, self.db:
            if not self.db.execute("SELECT 1 FROM runs WHERE id=?", (run,)).fetchone():
                raise ValueError("run unregistered")
            maximum = self.db.execute("SELECT MAX(ordinal) FROM chunks WHERE run=?", (run,)).fetchone()[0]
            if maximum is not None and maximum > last_ordinal:
                raise ValueError("final ordinal excludes received chunks")
            old = self.db.execute("SELECT last_ordinal FROM run_ends WHERE run=?", (run,)).fetchone()
            if old and old[0] != last_ordinal:
                raise ValueError("run end conflict")
            self.db.execute("INSERT OR IGNORE INTO run_ends VALUES(?,?)", (run, last_ordinal))

    def mark_consumed(self, ident):
        with self.lock, self.db:
            self.db.execute("UPDATE chunks SET consumed=1 WHERE id=?", (ident,))

    def prepare(self, ident, state, payload):
        state_json = json.dumps(state, separators=(",", ":"), allow_nan=False)
        payload_json = json.dumps(payload, separators=(",", ":"), allow_nan=False)
        if len(state_json) > MAX_STATE or len(payload_json) > MAX_PAYLOAD:
            raise ValueError("checkpoint or prepared payload resource limit")
        with self.lock, self.db:
            if self.db.execute("SELECT count(*) FROM batches WHERE committed=0").fetchone()[0] >= 2:
                raise ValueError("prepared backlog full")
            row = self.db.execute("SELECT consumed FROM chunks WHERE id=?", (ident,)).fetchone()
            if not row or row[0]:
                raise ValueError("preparation cursor conflict")
            for part in payload:
                for record in part.get("records", []):
                    tags = part.get("tag_keys", [])
                    identity = json.dumps(
                        [
                            part["database"],
                            part["measurement"],
                            record["time"],
                            [(tag, record.get(tag)) for tag in sorted(tags)],
                        ],
                        sort_keys=True,
                    )
                    fields = json.dumps(
                        {k: v for k, v in record.items() if k != "time" and k not in tags},
                        sort_keys=True,
                        allow_nan=False,
                    )
                    old = self.db.execute("SELECT fields FROM points WHERE identity=?", (identity,)).fetchone()
                    if old and old[0] != fields:
                        raise ValueError("point identity conflict")
                    self.db.execute("INSERT OR IGNORE INTO points VALUES(?,?)", (identity, fields))
            self.db.execute(
                "INSERT INTO checkpoint VALUES(1,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state", (state_json,)
            )
            self.db.execute("INSERT INTO batches(chunk,payload) VALUES(?,?)", (ident, payload_json))
            self.db.execute("UPDATE chunks SET consumed=1 WHERE id=?", (ident,))

    def load_checkpoint(self):
        with self.lock:
            row = self.db.execute("SELECT state FROM checkpoint WHERE id=1").fetchone()
            return json.loads(row[0]) if row else None

    def pending_batches(self):
        with self.lock:
            return [
                dict(r, payload=json.loads(r["payload"]))
                for r in self.db.execute("SELECT * FROM batches WHERE committed=0 ORDER BY id LIMIT 2")
            ]

    def commit_batch(self, ident):
        with self.lock, self.db:
            self.db.execute("UPDATE batches SET committed=1 WHERE id=?", (ident,))

    def committed_batches(self, after: int, limit: int = 50):
        with self.lock:
            return [
                dict(r, payload=json.loads(r["payload"]))
                for r in self.db.execute(
                    "SELECT * FROM batches WHERE committed=1 AND id>? ORDER BY id LIMIT ?",
                    (after, max(1, min(limit, 50))),
                )
            ]

    def observe(self, value):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO observations VALUES(1,?,?) "
                "ON CONFLICT(id) DO UPDATE SET value=excluded.value,seen=excluded.seen",
                (json.dumps(value), time.time()),
            )
            self._observation_at = time.monotonic()

    def observation(self):
        with self.lock:
            if self._observation_at is None or time.monotonic() - self._observation_at >= 6:
                return None
            row = self.db.execute("SELECT value FROM observations WHERE id=1").fetchone()
            return json.loads(row[0]) if row else None
