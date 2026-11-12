"""Local durable batch/work/checkpoint/outcome spool during database outages."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path


class LocalProgress:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.root / "recovery.sqlite3", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.db.executescript("""PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS batches(id INTEGER PRIMARY KEY, hash TEXT NOT NULL,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS work(module TEXT,
    batch_id INTEGER REFERENCES batches(id),
    done INTEGER DEFAULT 0,
    result TEXT,
    PRIMARY KEY(module,
    batch_id));
CREATE TABLE IF NOT EXISTS checkpoint(module TEXT PRIMARY KEY,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outcomes(id TEXT PRIMARY KEY,
    module TEXT NOT NULL,
    payload TEXT NOT NULL,
    persisted INTEGER DEFAULT 0);
""")

    def close(self):
        self.db.close()

    def cursor(self):
        with self.lock:
            return self.db.execute("SELECT COALESCE(MAX(id),0) FROM batches").fetchone()[0]

    def register(self, batch, modules):
        payload = json.dumps(batch, sort_keys=True, separators=(",", ":"), allow_nan=False)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        if len(payload) > 32_000_000:
            raise ValueError("batch payload limit")
        with self.lock, self.db:
            old = self.db.execute("SELECT hash FROM batches WHERE id=?", (batch["id"],)).fetchone()
            if old and old[0] != digest:
                raise ValueError("batch identity conflict")
            if (
                self.db.execute("SELECT COALESCE(SUM(length(payload)),0) FROM batches").fetchone()[0] + len(payload)
                > 2_000_000_000
            ):
                raise ValueError("recovery storage full")
            self.db.execute("INSERT OR IGNORE INTO batches VALUES(?,?,?)", (batch["id"], digest, payload))
            for module in modules:
                self.db.execute("INSERT OR IGNORE INTO work(module,batch_id) VALUES(?,?)", (module, batch["id"]))

    def next_work(self, module):
        with self.lock:
            row = self.db.execute(
                "SELECT b.* FROM work w JOIN batches b ON b.id=w.batch_id "
                "WHERE w.module=? AND w.done=0 ORDER BY b.id LIMIT 1",
                (module,),
            ).fetchone()
            return {"id": row["id"], "hash": row["hash"], "batch": json.loads(row["payload"])} if row else None

    def previous_records(self, module, measurement, before, start_time=None, max_records=100000):
        if not 1 <= max_records <= 100000:
            raise ValueError("invalid recovery context limit")
        with self.lock:
            # JSON1 applies the bound before Python materializes records. Never
            # deserialize the full retained stream to build one short context.
            query = """SELECT r.value FROM batches AS b,
                json_each(b.payload, '$.payload') AS p,
                json_each(p.value, '$.records') AS r
                WHERE b.id<=? AND json_extract(p.value,'$.measurement')=?"""
            params = [before, measurement]
            if start_time is not None:
                query += " AND julianday(json_extract(r.value,'$.time'))>=julianday(?)"
                params.append(start_time)
            query += " ORDER BY b.id, p.key, r.key LIMIT ?"
            params.append(max_records + 1)
            rows = self.db.execute(query, params).fetchall()
            if len(rows) > max_records:
                raise ValueError("recovery context limit")
            return [json.loads(row[0]) for row in rows]

    def checkpoint(self, module):
        with self.lock:
            row = self.db.execute("SELECT state FROM checkpoint WHERE module=?", (module,)).fetchone()
            return json.loads(row[0]) if row else None

    def complete(self, module, batch, state, anomaly_links, result):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO checkpoint VALUES(?,?) ON CONFLICT(module) DO UPDATE SET state=excluded.state",
                (module, json.dumps(state, allow_nan=False)),
            )
            self.db.execute(
                "UPDATE work SET done=1,result=? WHERE module=? AND batch_id=?",
                (json.dumps(dict(result, anomaly_links=anomaly_links)), module, batch),
            )

    def put_outcome(self, ident, module, payload):
        encoded = json.dumps(payload, allow_nan=False)
        if len(encoded) > 16_000_000:
            raise ValueError("outcome limit")
        with self.lock, self.db:
            old = self.db.execute("SELECT payload FROM outcomes WHERE id=?", (ident,)).fetchone()
            if old and old[0] != encoded:
                raise ValueError("outcome identity conflict")
            self.db.execute("INSERT OR IGNORE INTO outcomes VALUES(?,?,?,0)", (ident, module, encoded))

    def outcomes(self):
        with self.lock:
            return [
                dict(r, payload=json.loads(r["payload"]))
                for r in self.db.execute("SELECT * FROM outcomes WHERE persisted=0 ORDER BY rowid LIMIT 10")
            ]

    def ack_outcome(self, ident):
        with self.lock, self.db:
            self.db.execute("UPDATE outcomes SET persisted=1 WHERE id=?", (ident,))
