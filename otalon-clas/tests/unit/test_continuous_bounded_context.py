"""Historical context queries stay bounded after the live stream grows."""

import hashlib
import inspect
import json
import sqlite3

import pytest

from otalon_clas.recovery.progress import LocalProgress


def test_previous_context_reads_only_the_requested_time_range(tmp_path):
    p = LocalProgress(tmp_path)
    for i in range(1, 31):
        minute = i - 1
        p.register(
            {
                "id": i,
                "chunk": str(i),
                "payload": [
                    {
                        "measurement": "network_metrics",
                        "records": [{"time": f"2020-01-01T00:{minute:02}:00+00:00", "uci": "s", "packet_count": i}],
                    }
                ],
            },
            ["conn"],
        )
    assert (
        "start_time" in inspect.signature(p.previous_records).parameters
    ), "historical context has no bounded lower timestamp"
    rows = p.previous_records("conn", "network_metrics", 30, start_time="2020-01-01T00:28:00+00:00", max_records=2)
    assert [r["packet_count"] for r in rows] == [29, 30]
    p.close()


def original_context(db, measurement, before, start_time=None, max_records=100000):
    query = """SELECT r.value FROM batches AS b,
        json_each(b.payload, '$.payload') AS p,
        json_each(p.value, '$.records') AS r
        WHERE b.id<=? AND json_extract(p.value,'$.measurement')=?"""
    params = [before, measurement]
    if start_time is not None:
        query += " AND julianday(json_extract(r.value,'$.time'))>=julianday(?)"
        params.append(start_time)
    query += " ORDER BY b.id, p.key, r.key LIMIT ?"
    rows = db.execute(query, [*params, max_records + 1]).fetchall()
    if len(rows) > max_records:
        raise ValueError("recovery context limit")
    return [json.loads(row[0]) for row in rows]


def mixed_batches():
    return [
        {"id": 1, "payload": [
            {"measurement": "network_metrics", "records": [
                {"time": "2020-01-01T01:00:00Z", "packet_count": 11},
                {"time": "2020-01-01T00:00:00Z", "packet_count": 12},
            ]},
            {"measurement": "other", "records": [{"time": "2030-01-01T00:00:00Z", "packet_count": 13}]},
            {"measurement": "network_metrics", "records": [
                {"time": "2020-01-01T00:59:00+01:00", "packet_count": 14},
                {"time": "2020-01-01T01:00:01Z", "packet_count": 15},
            ]},
        ]},
        {"id": 2, "payload": [{"measurement": "network_metrics", "records": [
            {"time": "2020-01-01T00:01:00Z", "packet_count": 21},
        ]}]},
        {"id": 3, "payload": [
            {"measurement": "network_metrics", "records": [
                {"time": None, "packet_count": 31},
                {"packet_count": 32},
                {"time": "not-a-time", "packet_count": 33},
            ]},
            {"measurement": "network_metrics", "records": []},
            {"measurement": "network_metrics"},
            {"records": [{"time": "2020-01-01T01:00:00Z", "packet_count": 34}]},
        ]},
        {"id": 4, "payload": []},
        {"id": 5, "payload": [{"measurement": "network_metrics", "records": [
            {"time": "2020-01-01T00:59:59.999Z", "packet_count": 51},
            {"time": "2020-01-01T02:00:00+01:00", "packet_count": 52},
            {"time": 2458849.5416666665, "packet_count": 53},
            {"time": "2020-01-01T01:00:02Z", "packet_count": 54},
        ]}]},
        {"id": 6, "payload": [{"measurement": "network_metrics", "records": [
            {"time": "2020-01-01T03:00:00Z", "packet_count": 61},
            {"time": "2020-01-01T01:00:00Z", "packet_count": 62},
        ]}]},
    ]


@pytest.mark.parametrize("measurement", ["network_metrics", "other", "absent", None])
@pytest.mark.parametrize("before", [0, 1, 3, 5, 6])
@pytest.mark.parametrize("start_time", [None, "2020-01-01T01:00:00Z", "2020-01-01T02:00:00Z", "invalid"])
def test_indexed_context_matches_original_with_shuffled_times_parts_and_gaps(tmp_path, measurement, before, start_time):
    p = LocalProgress(tmp_path)
    for batch in reversed(mixed_batches()):
        p.register(batch, ["conn", "other_module"])
    p.complete("conn", 1, {"version": 1}, [], {})
    expected = original_context(p.db, measurement, before, start_time)
    for module in ("conn", "other_module", "unknown"):
        assert p.previous_records(module, measurement, before, start_time) == expected
    p.close()


def test_metadata_aggregates_all_parts_and_keeps_null_times(tmp_path):
    p = LocalProgress(tmp_path)
    for batch in mixed_batches():
        p.register(batch, ["conn"])
    last_time = p.db.execute(
        "SELECT last_time FROM batch_times WHERE batch_id=1 AND measurement='network_metrics'"
    ).fetchone()[0]
    assert last_time == p.db.execute("SELECT julianday('2020-01-01T01:00:01Z')").fetchone()[0]
    assert p.db.execute("SELECT last_time FROM batch_times WHERE batch_id=3").fetchone()[0] is None
    assert p.db.execute("SELECT COUNT(*) FROM batch_times WHERE batch_id=4").fetchone()[0] == 0
    assert [r["packet_count"] for r in p.previous_records("conn", "network_metrics", 5, "2020-01-01T01:00:00Z")] == [
        11, 15, 52, 53, 54,
    ]
    p.close()


@pytest.mark.parametrize("start_time", [None, "2020-01-01T01:00:00Z"])
def test_indexed_context_retains_limit_and_overflow_behavior(tmp_path, start_time):
    p = LocalProgress(tmp_path)
    for batch in mixed_batches():
        p.register(batch, ["conn"])
    expected = original_context(p.db, "network_metrics", 5, start_time)
    assert p.previous_records("conn", "network_metrics", 5, start_time, len(expected)) == expected
    for query in (original_context, lambda db, *args: p.previous_records("conn", *args)):
        with pytest.raises(ValueError, match="^recovery context limit$"):
            query(p.db, "network_metrics", 5, start_time, len(expected) - 1)
    for limit in (0, -1, 100001):
        with pytest.raises(ValueError, match="^invalid recovery context limit$"):
            p.previous_records("conn", "network_metrics", 5, start_time, limit)
    p.close()


def test_legacy_migration_preserves_batches_work_checkpoints_and_outcomes(tmp_path, monkeypatch):
    db = sqlite3.connect(tmp_path / "recovery.sqlite3")
    db.executescript("""PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE batches(id INTEGER PRIMARY KEY,hash TEXT NOT NULL,payload TEXT NOT NULL);
        CREATE TABLE work(module TEXT,batch_id INTEGER REFERENCES batches(id),done INTEGER DEFAULT 0,
            result TEXT,PRIMARY KEY(module,batch_id));
        CREATE TABLE checkpoint(module TEXT PRIMARY KEY,state TEXT NOT NULL);
        CREATE TABLE outcomes(id TEXT PRIMARY KEY,module TEXT NOT NULL,payload TEXT NOT NULL,persisted INTEGER DEFAULT 0);
    """)
    for batch in mixed_batches():
        payload = json.dumps(batch, sort_keys=True, separators=(",", ":"), allow_nan=False)
        db.execute("INSERT INTO batches VALUES(?,?,?)", (batch["id"], hashlib.sha256(payload.encode()).hexdigest(), payload))
        db.execute("INSERT INTO work VALUES(?,?,?,?)", ("conn", batch["id"], int(batch["id"] == 1), '{"old": true}'))
    db.execute("INSERT INTO checkpoint VALUES(?,?)", ("conn", '{"version": 1, "last_seen": "unchanged"}'))
    db.execute("INSERT INTO outcomes VALUES(?,?,?,?)", ("pending", "conn", '{"number": 1}', 0))
    db.execute("INSERT INTO outcomes VALUES(?,?,?,?)", ("persisted", "other", '{"number": 2}', 1))
    db.commit()
    tables = ("batches", "work", "checkpoint", "outcomes")
    original = {table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall() for table in tables}
    db.close()

    p = LocalProgress(tmp_path)
    assert {table: [tuple(r) for r in p.db.execute(f"SELECT * FROM {table} ORDER BY rowid")] for table in tables} == original
    assert p.cursor() == 6
    assert p.next_work("conn")["id"] == 2
    assert p.checkpoint("conn") == {"version": 1, "last_seen": "unchanged"}
    assert p.outcome("pending")["payload"] == {"number": 1}
    assert p.outcome("persisted") is None
    assert p.db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert p.db.execute("PRAGMA synchronous").fetchone()[0] == 2
    assert p.previous_records("conn", "network_metrics", 5, "2020-01-01T01:00:00Z") == original_context(
        p.db, "network_metrics", 5, "2020-01-01T01:00:00Z"
    )
    metadata = [tuple(r) for r in p.db.execute("SELECT * FROM batch_times ORDER BY batch_id,measurement")]
    p.close()

    def unexpected_reindex(self, batch_id):
        pytest.fail("already migrated immutable history was reindexed")

    monkeypatch.setattr(LocalProgress, "_index_batch", unexpected_reindex)
    p = LocalProgress(tmp_path)
    assert [tuple(r) for r in p.db.execute("SELECT * FROM batch_times ORDER BY batch_id,measurement")] == metadata
    p.register(mixed_batches()[0], ["other_module"])
    assert p.next_work("other_module")["id"] == 1
    assert [tuple(r) for r in p.db.execute("SELECT * FROM batch_times ORDER BY batch_id,measurement")] == metadata
    with pytest.raises(ValueError, match="batch identity conflict"):
        p.register({"id": 1, "payload": []}, ["conn"])
    p.close()


def test_registration_metadata_is_atomic_with_batches_and_work(tmp_path, monkeypatch):
    p = LocalProgress(tmp_path)
    original_index = p._index_batch

    def fail_after_index(batch_id):
        original_index(batch_id)
        raise RuntimeError("interrupted registration")

    monkeypatch.setattr(p, "_index_batch", fail_after_index)
    with pytest.raises(RuntimeError, match="interrupted registration"):
        p.register(mixed_batches()[0], ["conn"])
    for table in ("batches", "batch_times", "work"):
        assert p.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    monkeypatch.setattr(p, "_index_batch", original_index)
    p.register(mixed_batches()[0], ["conn"])
    assert p.next_work("conn")["id"] == 1
    assert p.db.execute("SELECT COUNT(*) FROM batch_times").fetchone()[0] == 2
    p.close()


def test_failed_legacy_backfill_rolls_back_metadata_schema(tmp_path, monkeypatch):
    p = LocalProgress(tmp_path)
    for batch in mixed_batches():
        p.register(batch, ["conn"])
    p.db.execute("DROP TABLE batch_times")
    p.db.commit()
    p.close()
    original_index = LocalProgress._index_batch
    interrupted = []

    def fail_after_index(self, batch_id):
        interrupted.append(self)
        original_index(self, batch_id)
        raise RuntimeError("interrupted migration")

    monkeypatch.setattr(LocalProgress, "_index_batch", fail_after_index)
    with pytest.raises(RuntimeError, match="interrupted migration"):
        LocalProgress(tmp_path)
    interrupted[0].close()
    with sqlite3.connect(tmp_path / "recovery.sqlite3") as db:
        assert db.execute("SELECT 1 FROM sqlite_master WHERE name='batch_times'").fetchone() is None
        assert db.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 6
        assert db.execute("SELECT COUNT(*) FROM work WHERE done=0").fetchone()[0] == 6
    monkeypatch.setattr(LocalProgress, "_index_batch", original_index)
    p = LocalProgress(tmp_path)
    assert p.previous_records("conn", "network_metrics", 5, "2020-01-01T01:00:00Z") == original_context(
        p.db, "network_metrics", 5, "2020-01-01T01:00:00Z"
    )
    p.close()


@pytest.mark.parametrize("token", ["now", "NoW", "subsec", "SUBSECOND", "now\u0000ignored"])
def test_clock_relative_times_are_not_skipped_after_restart(tmp_path, token):
    p = LocalProgress(tmp_path)
    p.db.create_function("julianday", 1, lambda value: 2451544.5)
    batch = {"id": 1, "payload": [{"measurement": "network_metrics", "records": [{"time": token}]}]}
    p.register(batch, ["conn"])
    assert p.db.execute("SELECT last_time FROM batch_times").fetchone()[0] == float("inf")
    p.close()
    p = LocalProgress(tmp_path)
    p.db.create_function("julianday", 1, lambda value: 2460000.0 if value.lower() == token.lower() else 2459999.0)
    assert p.previous_records("conn", "network_metrics", 1, "2020-01-01T00:00:00Z") == [{"time": token}]
    p.close()


def test_storage_guard_still_rejects_without_registering_metadata_or_work(tmp_path):
    p = LocalProgress(tmp_path)
    p.register(mixed_batches()[0], ["conn"])
    p.db.create_function("length", 1, lambda value: 2_000_000_001)
    with pytest.raises(ValueError, match="^recovery storage full$"):
        p.register(mixed_batches()[1], ["conn"])
    assert p.cursor() == 1
    assert p.db.execute("SELECT COUNT(*) FROM batch_times").fetchone()[0] == 2
    assert p.db.execute("SELECT COUNT(*) FROM work").fetchone()[0] == 1
    p.close()


def test_time_index_prunes_old_payloads_before_json_expansion(tmp_path):
    p = LocalProgress(tmp_path)
    for number in range(1, 1001):
        p.register({"id": number, "payload": [{"measurement": "network_metrics", "records": [
            {"time": "2020-01-01T00:00:00Z", "packet_count": number},
        ]}]}, ["conn"])
    for number in (1001, 1002):
        p.register({"id": number, "payload": [{"measurement": "network_metrics", "records": [
            {"time": "2020-01-02T00:00:00Z", "packet_count": number},
        ]}]}, ["conn"])
    queries = []
    p.db.set_trace_callback(queries.append)
    assert p.previous_records("conn", "network_metrics", 1001, "2020-01-02T00:00:00Z") == [
        {"time": "2020-01-02T00:00:00Z", "packet_count": 1001},
    ]
    p.db.set_trace_callback(None)
    plan = [row[3] for row in p.db.execute("EXPLAIN QUERY PLAN " + queries[-1])]
    assert "batch_times_measurement_time" in plan[0]
    assert "measurement=? AND last_time>?" in plan[0]
    assert "SEARCH b USING INTEGER PRIMARY KEY" in plan[1]
    assert all("VIRTUAL TABLE" in step for step in plan[2:4])
    assert p.db.execute("""SELECT COUNT(*) FROM batch_times
        WHERE measurement=? AND last_time>=julianday(?) AND batch_id<=?""",
        ("network_metrics", "2020-01-02T00:00:00Z", 1001)).fetchone()[0] == 1

    # A payload that cannot match must not be touched by either JSON1 expansion.
    p.db.execute("UPDATE batches SET payload='not json' WHERE id<=1000")
    p.db.commit()
    assert len(p.previous_records("conn", "network_metrics", 1001, "2020-01-02T00:00:00Z")) == 1
    with pytest.raises(sqlite3.OperationalError, match="malformed JSON"):
        original_context(p.db, "network_metrics", 1001, "2020-01-02T00:00:00Z")
    p.close()
