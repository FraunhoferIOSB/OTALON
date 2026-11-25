"""Capture-owned durable custody, versioned carry and exact-write outbox.

Receipts acknowledge bytes, never detector coverage. A file end does not seal a
logical packet window. SQLite and immutable blobs are kept on a local POSIX FS.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import struct
import tempfile
import threading
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .pcap import validate

IDENTITY = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
MAX_STATE = 96_000_000
MAX_PAYLOAD = 32_000_000
DEFAULT_CUSTODY_BYTES = 2_000_000_000
COPY_CHUNK = 65536


class HistoricalCustodyError(ValueError):
    """Existing custody cannot be read safely; never repair it for a read."""


class EmptyLedger:
    """Truthful read view of an uninitialized volume, with no SQLite connection."""

    def __init__(self, root, *, unavailable=False):
        self.root = root
        self.raw = root / "raw"
        self._unavailable = unavailable

    def _read_existing(self):
        if self._unavailable:
            raise HistoricalCustodyError("Historical custody unavailable")

    def close(self):
        pass

    def receipt(self, run, ordinal):
        self._read_existing()
        return None

    def load_checkpoint(self):
        self._read_existing()
        return None

    def pending_batches(self):
        self._read_existing()
        return []

    def committed_batches(self, after, limit=50):
        self._read_existing()
        return []

    def observation(self):
        return None

    def observation_age_seconds(self):
        return None

    def historical_status(self):
        self._read_existing()
        return {"received": 0, "pending_writes": 0, "checkpoint_present": False}


class Ledger:
    @classmethod
    def open_existing_readonly(cls, root):
        """Open only existing custody, deferring failures to historical operations."""
        root = Path(root).absolute()
        for part in (root, *root.parents):
            if part.is_symlink() or part.exists() and not part.is_dir():
                raise ValueError("unsafe ledger root")
        for name in ("raw", "progress.sqlite3", "progress.sqlite3-wal", "progress.sqlite3-shm", "pcap_index.json"):
            path = root / name
            if (
                path.is_symlink()
                or path.exists()
                and (not path.is_dir() if name == "raw" else not path.is_file() or path.stat().st_nlink != 1)
            ):
                raise ValueError("unsafe ledger files")
        if not (root / "progress.sqlite3").exists():
            return EmptyLedger(
                root,
                unavailable=(
                    any((root / name).exists() for name in ("progress.sqlite3-wal", "progress.sqlite3-shm"))
                    or (root / "raw").is_dir()
                    and any((root / "raw").iterdir())
                ),
            )
        view = cls.__new__(cls)
        view.root, view.raw = root, root / "raw"
        view.lock = threading.RLock()
        view._readonly = True
        view._observation_at = None
        view.db = None
        view._scratch = None
        view._closed = False
        return view

    def _snapshot_existing(self):
        """Acquire once from ordinary file descriptors, never original SQLite.

        Two byte-identical passes and unchanged POSIX identities/timestamps are
        conservative acquisition checks, not a general concurrent/VFS proof.
        SQLite and WAL validation happen only on the resulting owned copy.
        """

        def signature(info):
            return (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )

        def unsafe():
            raise HistoricalCustodyError("Historical custody unavailable")

        with ExitStack() as handles:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory = os.open(self.root.anchor, flags)
            handles.callback(os.close, directory)
            directories = []
            for name in self.root.parts[1:]:
                before = os.stat(name, dir_fd=directory, follow_symlinks=False)
                child = os.open(name, flags, dir_fd=directory)
                handles.callback(os.close, child)
                if not stat.S_ISDIR(before.st_mode) or signature(os.fstat(child)) != signature(before):
                    unsafe()
                directories.append((directory, name, child, signature(before)[:3]))
                directory = child

            root_signature = signature(os.fstat(directory))

            names = ("progress.sqlite3", "progress.sqlite3-wal", "progress.sqlite3-shm", "raw")
            originals = {}
            sources = {}
            total = 0
            for name in names:
                try:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    if name == "progress.sqlite3":
                        unsafe()
                    originals[name] = None
                    continue
                if name == "raw":
                    if not stat.S_ISDIR(info.st_mode):
                        unsafe()
                elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    unsafe()
                originals[name] = signature(info)
                if name in names[:2]:
                    total += info.st_size
                    sources[name] = info
            if total > DEFAULT_CUSTODY_BYTES:
                unsafe()

            descriptors = {}
            for name, info in sources.items():
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                handles.callback(os.close, fd)
                if signature(os.fstat(fd)) != signature(info):
                    unsafe()
                descriptors[name] = fd

            def unchanged():
                for parent, name, child, expected in directories:
                    if (
                        signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:3] != expected
                        or signature(os.fstat(child))[:3] != expected
                    ):
                        unsafe()
                if signature(os.fstat(directory)) != root_signature:
                    unsafe()
                for name, expected in originals.items():
                    try:
                        current = signature(os.stat(name, dir_fd=directory, follow_symlinks=False))
                    except FileNotFoundError:
                        current = None
                    if current != expected:
                        unsafe()
                for name, fd in descriptors.items():
                    if signature(os.fstat(fd)) != originals[name]:
                        unsafe()

            unchanged()
            temporary_parent = Path(tempfile.gettempdir()).resolve()
            if temporary_parent.is_relative_to(self.root):
                unsafe()
            self._scratch = tempfile.TemporaryDirectory(prefix="otalon-custody-read-", dir=temporary_parent)
            scratch = Path(self._scratch.name)
            if scratch.is_relative_to(self.root):
                unsafe()
            digests = {}
            for copying in (True, False):
                for name, fd in descriptors.items():
                    os.lseek(fd, 0, os.SEEK_SET)
                    digest = hashlib.sha256()
                    remaining = sources[name].st_size
                    with (scratch / name).open("xb") if copying else ExitStack() as output:
                        while remaining:
                            block = os.read(fd, min(COPY_CHUNK, remaining))
                            if not block:
                                unsafe()
                            remaining -= len(block)
                            digest.update(block)
                            if copying:
                                output.write(block)
                        if os.read(fd, 1):
                            unsafe()
                    if copying:
                        digests[name] = digest.digest()
                    elif digest.digest() != digests[name]:
                        unsafe()
                unchanged()
            self._validate_snapshot_wal(scratch)
            unchanged()
            return scratch / "progress.sqlite3"

    @staticmethod
    def _validate_snapshot_wal(scratch):
        """Refuse torn/reset/corrupt WAL rather than silently losing its commits."""
        wal = scratch / "progress.sqlite3-wal"
        if not wal.exists() or wal.stat().st_size == 0:
            return
        with wal.open("rb") as stream:
            header = stream.read(32)
            if len(header) != 32:
                raise HistoricalCustodyError("Historical custody unavailable")
            magic, version, page_size, _, salt1, salt2, check1, check2 = struct.unpack(">8I", header)
            if (
                magic not in (0x377F0682, 0x377F0683)
                or version != 3007000
                or page_size < 512
                or page_size > 65536
                or page_size & (page_size - 1)
                or (wal.stat().st_size - 32) % (24 + page_size)
            ):
                raise HistoricalCustodyError("Historical custody unavailable")
            with (scratch / "progress.sqlite3").open("rb") as main:
                db_header = main.read(100)
            db_page_size = int.from_bytes(db_header[16:18], "big")
            if db_page_size == 1:
                db_page_size = 65536
            if db_header[:16] != b"SQLite format 3\x00" or db_page_size != page_size:
                raise HistoricalCustodyError("Historical custody unavailable")
            endian = "<2I" if magic == 0x377F0682 else ">2I"
            sums = (0, 0)

            def checksum(block):
                nonlocal sums
                first, second = sums
                for x, y in struct.iter_unpack(endian, block):
                    first = (first + x + second) & 0xFFFFFFFF
                    second = (second + y + first) & 0xFFFFFFFF
                sums = (first, second)

            checksum(header[:24])
            if sums != (check1, check2):
                raise HistoricalCustodyError("Historical custody unavailable")
            while frame := stream.read(24):
                page, _, frame_salt1, frame_salt2, check1, check2 = struct.unpack(">6I", frame)
                if page == 0 or (frame_salt1, frame_salt2) != (salt1, salt2):
                    raise HistoricalCustodyError("Historical custody unavailable")
                checksum(frame[:8])
                checksum(stream.read(page_size))
                if sums != (check1, check2):
                    raise HistoricalCustodyError("Historical custody unavailable")

    def _read_existing(self):
        if not getattr(self, "_readonly", False):
            return
        if self._closed:
            raise HistoricalCustodyError("Historical custody unavailable")
        if self.db is None:
            try:
                path = self._snapshot_existing()
                self.db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, check_same_thread=False)
                self.db.row_factory = sqlite3.Row
                self.db.execute("PRAGMA query_only=ON")
                versions = self.db.execute("SELECT version FROM metadata LIMIT 2").fetchall()
                if len(versions) != 1 or versions[0][0] != 1:
                    raise HistoricalCustodyError("Historical custody unavailable")
                if [row[0] for row in self.db.execute("PRAGMA quick_check")] != ["ok"]:
                    raise HistoricalCustodyError("Historical custody unavailable")
                required = {
                    "runs": "id,predecessor,seq",
                    "run_config": "run,interface,fingerprint",
                    "chunks": "id,run,ordinal,hash,size,path,packets,first_ns,last_ns,consumed",
                    "checkpoint": "id,state",
                    "batches": "id,chunk,payload,committed",
                    "run_ends": "run,last_ordinal",
                    "observations": "id,value,seen",
                    "consumer_ack": "module,batch",
                    "points": "identity,fields",
                }
                for table, columns in required.items():
                    self.db.execute(f"SELECT {columns} FROM {table} LIMIT 0")
            except BaseException as exc:
                self.close()
                if isinstance(exc, (sqlite3.Error, OSError, ValueError)):
                    raise HistoricalCustodyError("Historical custody unavailable") from exc
                raise

    @contextmanager
    def _historical_read(self):
        with self.lock:
            try:
                self._read_existing()
                yield
            except BaseException:
                if getattr(self, "_readonly", False):
                    self.close()
                raise

    def historical_status(self):
        with self._historical_read():
            return {
                "received": self.db.execute("SELECT count(*) FROM chunks").fetchone()[0],
                "pending_writes": self.db.execute("SELECT count(*) FROM batches WHERE committed=0").fetchone()[0],
                "checkpoint_present": self.load_checkpoint() is not None,
            }

    def _require_writable(self):
        if getattr(self, "_readonly", False):
            raise ValueError("read-only custody")

    def __init__(self, root: Path, max_bytes: int = DEFAULT_CUSTODY_BYTES, min_free: int = 0):
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
        self.db.executescript(
            """
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
"""
        )
        row = self.db.execute("SELECT version FROM metadata").fetchone()
        if row is None:
            self.db.execute("INSERT INTO metadata VALUES(1)")
            self.db.commit()
        elif row[0] != 1:
            raise ValueError("unsupported ledger version")
        if self.db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("ledger integrity failure")
        self._observation_at: float | None = None
        self._observation_listener = None

    def close(self):
        with self.lock:
            try:
                if self.db is not None:
                    self.db.close()
            finally:
                self.db = None
                if getattr(self, "_readonly", False):
                    self._closed = True
                    if self._scratch is not None:
                        self._scratch.cleanup()
                        self._scratch = None

    def register_run(self, run: str, predecessor: str | None, interface: str = "fixture", fingerprint: str = ""):
        self._require_writable()
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
        self._require_writable()
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
        with self._historical_read():
            row = self.db.execute("SELECT * FROM chunks WHERE run=? AND ordinal=?", (run, ordinal)).fetchone()
            if not row:
                return None
            if getattr(self, "_readonly", False):
                path = Path(row["path"])
                if path.parent != self.raw or path.name != "rx_" + row["id"][:40] + ".pcap":
                    raise HistoricalCustodyError("unsafe custody path")
                if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
                    raise HistoricalCustodyError("unsafe custody path")
                if path.stat().st_size != row["size"]:
                    raise HistoricalCustodyError("Historical custody unavailable")
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    while block := stream.read(65536):
                        digest.update(block)
                if digest.hexdigest() != row["hash"]:
                    raise HistoricalCustodyError("Historical custody unavailable")
            pending = self.db.execute("SELECT 1 FROM batches WHERE chunk=? AND committed=0", (row["id"],)).fetchone()
            return {
                "id": row["id"],
                "hash": row["hash"],
                "size_bytes": row["size"],
                "custody": "accepted",
                "processing": "pending" if not row["consumed"] else "prepared" if pending else "carry_or_published",
            }

    def next_chunk(self):
        with self._historical_read():
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
        self._require_writable()
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
        self._require_writable()
        with self.lock, self.db:
            self.db.execute("UPDATE chunks SET consumed=1 WHERE id=?", (ident,))

    def prepare(self, ident, state, payload):
        self._require_writable()
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
        with self._historical_read():
            row = self.db.execute("SELECT state FROM checkpoint WHERE id=1").fetchone()
            return json.loads(row[0]) if row else None

    def pending_batches(self):
        with self._historical_read():
            return [
                dict(r, payload=json.loads(r["payload"]))
                for r in self.db.execute("SELECT * FROM batches WHERE committed=0 ORDER BY id LIMIT 2")
            ]

    def commit_batch(self, ident):
        self._require_writable()
        with self.lock, self.db:
            self.db.execute("UPDATE batches SET committed=1 WHERE id=?", (ident,))

    def committed_batches(self, after: int, limit: int = 50):
        with self._historical_read():
            return [
                dict(r, payload=json.loads(r["payload"]))
                for r in self.db.execute(
                    "SELECT * FROM batches WHERE committed=1 AND id>? ORDER BY id LIMIT ?",
                    (after, max(1, min(limit, 50))),
                )
            ]

    def observe(self, value):
        self._require_writable()
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO observations VALUES(1,?,?) "
                "ON CONFLICT(id) DO UPDATE SET value=excluded.value,seen=excluded.seen",
                (json.dumps(value), time.time()),
            )
            self._observation_at = time.monotonic()
            if self._observation_listener is not None:
                self._observation_listener()

    def observation_age_seconds(self):
        """Age of this process's accepted receipt, never persisted wall-time seen."""
        with self.lock:
            if self._observation_at is None:
                return None
            age = time.monotonic() - self._observation_at
            return max(0.0, age) if math.isfinite(age) else None

    def observation(self):
        with self.lock:
            age = self.observation_age_seconds()
            if age is None or age >= 6:
                return None
            row = self.db.execute("SELECT value FROM observations WHERE id=1").fetchone()
            return json.loads(row[0]) if row else None
