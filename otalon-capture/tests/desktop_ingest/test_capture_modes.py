"""Receiver NONE contracts using owned disposable custody and real app factories."""

import asyncio
import builtins
import importlib
import json
import os
import sqlite3
import struct
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from capture_runtime import CaptureIntent
from desktop_ingest.api import create_ingest_app
from desktop_ingest.ledger import HistoricalCustodyError, Ledger
from pcap_recorder.index import PcapChunkMeta, PcapIndex

DISABLED = {
    "detail": "Automatic capture is disabled (CAPTURE_TYPE=NONE); stop the Windows collector explicitly. "
    "Pending custody is retained."
}
SOURCE = "disposable-public-source-value-00000001"
OPERATOR = "disposable-public-operator-value"
WRITES = [
    ("PUT", "/ingest/v1/runs/new"),
    ("POST", "/ingest/v1/runs/r/end"),
    ("PUT", "/ingest/v1/runs/r/chunks/99"),
    ("POST", "/ingest/v1/observation"),
]
TABLES = [
    "metadata",
    "runs",
    "run_config",
    "chunks",
    "checkpoint",
    "batches",
    "run_ends",
    "observations",
    "consumer_ack",
    "points",
    "sqlite_sequence",
]


def forbidden(*args, **kwargs):
    pytest.fail("NONE must not initialize, schedule, mutate or consume a body")


def packet(ms):
    frame = bytes.fromhex("0200000000020200000000010806") + bytes(46)
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", ms // 1000, ms % 1000 * 1000, len(frame), len(frame))
        + frame
    )


def rows(ledger):
    return {
        table: [tuple(row) for row in ledger.db.execute(f"SELECT * FROM {table} ORDER BY rowid")] for table in TABLES
    }


def files(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def custody(tmp_path):
    ledger = Ledger(tmp_path / "custody")  # Actual established writable fixture construction.
    ledger.register_run("r", None, "fixture", "a" * 64)
    ids = [ledger.receive("r", i, packet(1000 + i * 1000))["id"] for i in range(3)]
    payload = [
        {
            "database": "test",
            "measurement": "network",
            "tag_keys": [],
            "records": [{"time": "1970-01-01T00:00:01Z", "packet_count": 1}],
            "lines": ["network packet_count=1i 1000"],
            "writer": "network",
        }
    ]
    ledger.prepare(ids[0], {"version": 2, "marker": "original carry"}, payload)
    ledger.commit_batch(1)
    ledger.prepare(ids[1], {"version": 2, "marker": "pending carry"}, payload)
    ledger.close_run("r", 2)
    ledger.observe({"interface": "fixture", "recording": True})
    with ledger.db:
        ledger.db.execute("INSERT INTO consumer_ack VALUES('consumer',1)")
    index = PcapIndex(ledger.root / "pcap_index.json")
    from datetime import datetime, timezone

    for row in ledger.db.execute("SELECT * FROM chunks"):
        path = Path(row["path"])
        index._entries[path.name] = PcapChunkMeta(
            path.name,
            path,
            datetime.fromtimestamp(row["first_ns"] / 1e9, timezone.utc),
            datetime.fromtimestamp(row["last_ns"] / 1e9, timezone.utc),
            row["size"],
        )
    index._persist()
    yield ledger
    ledger.close()


def none_app(ledger, **kwargs):
    from desktop_ingest.main import build_app

    return build_app(None, ledger, None, OPERATOR, intent=CaptureIntent.NONE, **kwargs)


@pytest.mark.parametrize("intent", [None, "NONE"])
def test_main_none_before_key_settings_ledger_and_network_import(tmp_path, monkeypatch, intent):
    import desktop_ingest.main as main

    if intent is None:
        monkeypatch.delenv("CAPTURE_TYPE", raising=False)
    else:
        monkeypatch.setenv("CAPTURE_TYPE", intent)
    for name in ["CAPTURE_SOURCE", "CONTINUOUS_SOURCE_KEY_FILE", "ADMIN_API_KEY", "OTALON_API_ALLOWED_KEYS"]:
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "absent"
    monkeypatch.setenv("CONTINUOUS_ROOT", str(root))
    monkeypatch.setenv("CONTINUOUS_MAX_BYTES", "unused-invalid")
    monkeypatch.setenv("CONTINUOUS_MIN_FREE_BYTES", "unused-invalid")
    monkeypatch.setattr(main, "load_settings", forbidden)
    monkeypatch.setattr(Ledger, "__init__", forbidden)
    original_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if (
            name in {"desktop_ingest.pipeline", "network_capture"}
            or name.startswith(("influxdb", "otalon_capture.influxdb_writer"))
            or (name == "pipeline" and kwargs.get("level", args[3] if len(args) > 3 else 0))
        ):
            forbidden()
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    importlib.reload(main)

    def serve(app, **kwargs):
        with TestClient(app) as client:
            assert client.get("/health").json() == {"status": "ok"}
            status = client.get("/status").json()
            legacy_fields = ["interface", "link_up", "recording", "drops_24h_pct", "overflows"]
            assert {name: status[name] for name in legacy_fields} == dict.fromkeys(legacy_fields)
            assert status == {
                **dict.fromkeys(legacy_fields),
                "capture_type": "NONE",
                "backend": "wsl",
                "source_state": "disabled",
                "reason_code": "none_selected",
                "retry_attempt": 0,
                "retry_limit": 5,
                "retry_in_seconds": None,
                "retry_exhausted": False,
                "observation_age_seconds": None,
            }
            assert client.get("/internal/continuous/status").status_code == 503
            assert client.get("/ingest/v1/runs/r/chunks/0").status_code == 503
            for method, path in WRITES:
                response = client.request(
                    method, path, content=b"{malformed", headers={"content-type": "application/json"}
                )
                assert response.status_code == 503 and response.json() == DISABLED
        assert not root.exists()

    monkeypatch.setattr(main.uvicorn, "run", serve)
    main.main()


@pytest.mark.parametrize("value", ["", "PCAP", "live", "AUTO"])
def test_invalid_intent_precedes_all_initialization(monkeypatch, value):
    import desktop_ingest.main as main

    monkeypatch.setenv("CAPTURE_TYPE", value)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Ledger, "__init__", forbidden)
    monkeypatch.setattr(main, "load_settings", forbidden)
    with pytest.raises(ValueError, match="CAPTURE_TYPE"):
        main.main()


@pytest.mark.parametrize("method,path", WRITES)
@pytest.mark.parametrize("credentials", [{}, {"X-Source-Key": SOURCE}, {"X-API-Key": OPERATOR}])
@pytest.mark.asyncio
async def test_none_refusal_asgi_never_receives_or_resolves_key(method, path, credentials, monkeypatch):
    ledger = SimpleNamespace(register_run=forbidden, close_run=forbidden, receive=forbidden, observe=forbidden)
    app = create_ingest_app(ledger, None, None, intent=CaptureIntent.NONE, source_key_file=Path("unused"))
    monkeypatch.setattr(Path, "read_text", forbidden)
    messages = []

    async def receive():
        forbidden()

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "server": ("test", 80),
        "client": ("test", 1),
        "headers": [(b"content-type", b"application/json"), (b"content-length", b"999999999")]
        + [(key.lower().encode(), value.encode()) for key, value in credentials.items()],
    }
    await app(scope, receive, send)
    assert messages[0]["status"] == 503
    assert json.loads(b"".join(m.get("body", b"") for m in messages)) == DISABLED


def test_none_preserves_all_pending_bytes_rows_start_each_refusal_shutdown(custody, monkeypatch):
    before_rows, before_files = rows(custody), files(custody.root)
    readonly = Ledger.open_existing_readonly(custody.root)
    monkeypatch.setattr(asyncio, "create_task", forbidden)
    monkeypatch.setattr(PcapIndex, "flush", forbidden)
    monkeypatch.setattr(PcapIndex, "_persist", forbidden)
    monkeypatch.setenv("ADMIN_API_KEY", OPERATOR)
    with TestClient(none_app(readonly)) as client:
        assert rows(custody) == before_rows and files(custody.root) == before_files
        for method, path in WRITES:
            response = client.request(method, path, content=b"bad json")
            assert response.status_code == 503 and response.json() == DISABLED
            assert rows(custody) == before_rows and files(custody.root) == before_files
        assert client.get("/status").json()["recording"] is None
        assert client.get("/internal/continuous/status", headers={"X-API-Key": OPERATOR}).json() == {
            "received": 3,
            "pending_writes": 1,
            "checkpoint_present": True,
        }
        assert client.get("/internal/continuous/batches", headers={"X-API-Key": OPERATOR}).json() == {
            "batches": custody.committed_batches(0, 1)
        }
        assert client.get("/internal/continuous/status", headers={"X-API-Key": SOURCE}).status_code == 401
    readonly.close()
    assert rows(custody) == before_rows and files(custody.root) == before_files


@pytest.mark.parametrize("existing", [False, True])
def test_empty_read_view_creates_no_files(tmp_path, existing):
    root = tmp_path / "empty"
    if existing:
        root.mkdir()
    readonly = Ledger.open_existing_readonly(root)
    with TestClient(none_app(readonly)) as client:
        assert client.get("/internal/continuous/status", headers={"X-API-Key": OPERATOR}).json() == {
            "received": 0,
            "pending_writes": 0,
            "checkpoint_present": False,
        }
        assert client.get("/internal/continuous/batches", headers={"X-API-Key": OPERATOR}).json() == {"batches": []}
    readonly.close()
    assert root.exists() == existing
    assert not list(root.rglob("*"))


def test_readonly_legitimate_committed_wal_visible_and_query_only(custody):
    assert (custody.root / "progress.sqlite3-wal").stat().st_size > 0
    before = files(custody.root)
    readonly = Ledger.open_existing_readonly(custody.root)
    assert readonly.receipt("r", 2) == custody.receipt("r", 2)
    assert readonly.load_checkpoint() == custody.load_checkpoint()
    assert readonly.pending_batches() == custody.pending_batches()
    assert rows(readonly) == rows(custody)
    assert readonly.db.execute("PRAGMA query_only").fetchone()[0] == 1
    with pytest.raises(sqlite3.DatabaseError):
        readonly.db.execute("UPDATE chunks SET consumed=1")
    readonly.close()
    assert files(custody.root) == before


@pytest.mark.parametrize("operation", ["register", "receive", "end", "consume", "prepare", "commit", "observe"])
def test_readonly_view_refuses_direct_mutators_before_any_bytes(custody, operation):
    readonly = Ledger.open_existing_readonly(custody.root)
    readonly.receipt("r", 2)
    before_rows, before_files = rows(custody), files(custody.root)
    calls = {
        "register": lambda: readonly.register_run("next", "r"),
        "receive": lambda: readonly.receive("r", 99, packet(9999)),
        "end": lambda: readonly.close_run("r", 99),
        "consume": lambda: readonly.mark_consumed(custody.next_chunk()["id"]),
        "prepare": lambda: readonly.prepare(custody.next_chunk()["id"], {}, []),
        "commit": lambda: readonly.commit_batch(2),
        "observe": lambda: readonly.observe({"interface": "new", "recording": False}),
    }
    with pytest.raises(ValueError, match="read-only"):
        calls[operation]()
    readonly.close()
    assert rows(custody) == before_rows and files(custody.root) == before_files


def test_closed_custody_reads_without_creating_wal_or_shm(tmp_path):
    writer = Ledger(tmp_path / "closed")
    writer.register_run("r", None)
    expected = writer.receive("r", 0, packet(1000))
    writer.prepare(expected["id"], {"version": 2, "marker": "closed carry"}, [])
    writer.commit_batch(1)
    writer.db.execute("INSERT INTO consumer_ack VALUES('closed-consumer',1)")
    writer.db.commit()
    expected_rows = rows(writer)
    expected_batches = writer.committed_batches(0, 1)
    expected_receipt = writer.receipt("r", 0)
    writer.close()
    before = files(writer.root)
    assert "progress.sqlite3-wal" not in before and "progress.sqlite3-shm" not in before
    key = tmp_path / "public-closed-key"
    key.write_text(SOURCE)
    readonly = Ledger.open_existing_readonly(writer.root)
    assert readonly.receipt("r", 0)["hash"] == expected["hash"]
    with TestClient(none_app(readonly, source_key_file=key)) as client:
        response = client.get("/internal/continuous/status", headers={"X-API-Key": OPERATOR})
        assert response.status_code == 200
        assert response.json() == {"received": 1, "pending_writes": 0, "checkpoint_present": True}
        response = client.get("/internal/continuous/batches", headers={"X-API-Key": OPERATOR})
        assert response.status_code == 200 and response.json() == {"batches": expected_batches}
        response = client.get("/ingest/v1/runs/r/chunks/0", headers={"X-Source-Key": SOURCE})
        assert response.status_code == 200 and response.json() == expected_receipt
        assert rows(readonly) == expected_rows
    readonly.close()
    assert files(writer.root) == before


def test_closed_wal_custody_failure_is_visible_and_does_not_create_files(tmp_path):
    writer = Ledger(tmp_path / "closed")
    writer.register_run("r", None)
    writer.receive("r", 0, packet(1000))
    writer.close()
    with (writer.root / "progress.sqlite3").open("r+b") as stream:
        stream.truncate(100)  # Invalid disposable custody, not the valid closed-history case.
    before = files(writer.root)
    readonly = Ledger.open_existing_readonly(writer.root)
    with TestClient(none_app(readonly)) as client:
        response = client.get("/internal/continuous/status", headers={"X-API-Key": OPERATOR})
        assert response.status_code == 503
        assert response.json() == {"detail": "Historical custody unavailable"}
        assert client.post("/ingest/v1/observation", content=b"{").json() == DISABLED
    readonly.close()
    assert files(writer.root) == before


def test_orphan_custody_is_not_healthy_empty_history(tmp_path):
    root = tmp_path / "orphan"
    (root / "raw").mkdir(parents=True)
    (root / "raw" / "rx_orphan.pcap").write_bytes(packet(1000))
    before = files(root)
    readonly = Ledger.open_existing_readonly(root)
    with TestClient(none_app(readonly)) as client:
        response = client.get("/internal/continuous/status", headers={"X-API-Key": OPERATOR})
        assert response.status_code == 503
        assert response.json() == {"detail": "Historical custody unavailable"}
    readonly.close()
    assert files(root) == before


@pytest.mark.parametrize("key_state", ["missing", "empty", "short", "wrong", "same", "valid"])
def test_receipt_key_is_lazy_explicit_and_separate(custody, tmp_path, monkeypatch, key_state):
    key = tmp_path / "public-unit-key"
    if key_state != "missing":
        key.write_text({"empty": "", "short": "short", "same": OPERATOR}.get(key_state, SOURCE))
    original_read = Path.read_text
    reads = []

    def read(path, *args, **kwargs):
        if path == key:
            reads.append(path)
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    readonly = Ledger.open_existing_readonly(custody.root)
    app = none_app(readonly, source_key_file=key)
    assert reads == []
    with TestClient(app) as client:
        assert reads == []
        assert client.put("/ingest/v1/runs/new", content=b"{").json() == DISABLED
        assert reads == []
        response = client.get(
            "/ingest/v1/runs/r/chunks/2", headers={"X-Source-Key": "wrong" if key_state == "wrong" else SOURCE}
        )
        assert response.status_code == (200 if key_state == "valid" else 401 if key_state == "wrong" else 503)
        if key_state == "valid":
            assert response.json() == custody.receipt("r", 2)
            assert client.get("/ingest/v1/runs/r/chunks/2", headers={"X-API-Key": OPERATOR}).status_code == 401
            assert client.get("/ingest/v1/runs/r/chunks/99", headers={"X-Source-Key": SOURCE}).status_code == 404
    assert bool(reads) == (key_state != "missing")
    readonly.close()


@pytest.mark.parametrize("damage", ["corrupt", "version", "schema", "checkpoint", "payload"])
def test_invalid_ledger_history_visibly_fails_preserving_bytes(tmp_path, monkeypatch, damage):
    ledger = Ledger(tmp_path / "bad")
    ledger.register_run("r", None)
    ident = ledger.receive("r", 0, packet(1000))["id"]
    ledger.prepare(ident, {"version": 2}, [])
    ledger.commit_batch(1)
    with ledger.db:
        if damage == "version":
            ledger.db.execute("UPDATE metadata SET version=99")
        if damage == "schema":
            ledger.db.execute("DROP TABLE consumer_ack")
        if damage == "checkpoint":
            ledger.db.execute("UPDATE checkpoint SET state='{'")
        if damage == "payload":
            ledger.db.execute("UPDATE batches SET payload='{'")
    if damage == "corrupt":
        ledger.close()
        (ledger.root / "progress.sqlite3").write_bytes(b"invalid disposable sqlite")
    else:
        ledger.db.execute("SELECT count(*) FROM chunks").fetchone()
    before = files(ledger.root)
    readonly = Ledger.open_existing_readonly(ledger.root)
    with TestClient(none_app(readonly)) as client:
        route = "/internal/continuous/batches" if damage == "payload" else "/internal/continuous/status"
        response = client.get(route, headers={"X-API-Key": OPERATOR})
        assert response.status_code == 503
        assert response.json() == {"detail": "Historical custody unavailable"}
        assert client.put("/ingest/v1/runs/new", content=b"{").json() == DISABLED
    readonly.close()
    assert files(ledger.root) == before
    if damage != "corrupt":
        ledger.close()


@pytest.mark.parametrize("target", ["root", "ancestor", "raw", "db", "wal", "shm", "index", "blob"])
def test_unsafe_custody_links_refused_without_following(custody, tmp_path, target):
    root = custody.root
    if target in {"root", "ancestor"}:
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        with pytest.raises(ValueError, match="unsafe"):
            Ledger.open_existing_readonly(alias if target == "root" else alias / "child")
        return
    path = {
        "raw": root / "raw",
        "db": root / "progress.sqlite3",
        "wal": root / "progress.sqlite3-wal",
        "shm": root / "progress.sqlite3-shm",
        "index": root / "pcap_index.json",
        "blob": Path(custody.next_chunk()["path"]),
    }[target]
    saved = path.with_name(path.name + ".saved")
    path.rename(saved)
    path.symlink_to(saved, target_is_directory=target == "raw")
    before = saved.read_bytes() if saved.is_file() else files(saved)
    if target == "blob":
        readonly = Ledger.open_existing_readonly(root)
        with pytest.raises(ValueError, match="unsafe"):
            readonly.receipt("r", 2)
        readonly.close()
    else:
        with pytest.raises(ValueError, match="unsafe"):
            Ledger.open_existing_readonly(root)
    assert (saved.read_bytes() if saved.is_file() else files(saved)) == before


@pytest.mark.parametrize("index_bytes", [b"{broken", b"{}", b"[{}]", None])
def test_corrupt_index_fails_evidence_only_without_quarantine(custody, monkeypatch, index_bytes):
    if index_bytes is None:
        (custody.root / "pcap_index.json").unlink()
    else:
        (custody.root / "pcap_index.json").write_bytes(index_bytes)
    before = files(custody.root)
    monkeypatch.setenv("ADMIN_API_KEY", OPERATOR)
    readonly = Ledger.open_existing_readonly(custody.root)
    with TestClient(none_app(readonly)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/internal/continuous/status", headers={"X-API-Key": OPERATOR}).status_code == 200
        response = client.get(
            "/chunks",
            params={"start_ts": "1970-01-01T00:00:00Z", "end_ts": "1970-01-01T00:00:04Z"},
            headers={"X-API-Key": OPERATOR},
        )
        assert response.status_code == 503 and response.json() == {"detail": "Historical evidence unavailable"}
        assert (
            client.post(
                "/anomalies/flag",
                headers={"X-API-Key": OPERATOR},
                json={"start_ts": "1970-01-01T00:00:00Z", "end_ts": "1970-01-01T00:00:04Z"},
            ).status_code
            == 503
        )
    readonly.close()
    assert files(custody.root) == before


@pytest.mark.parametrize("damage", ["missing", "hash", "size"])
def test_receipt_never_attests_missing_or_changed_custody(custody, tmp_path, damage):
    path = Path(custody.next_chunk()["path"])
    original = path.read_bytes()
    if damage == "missing":
        path.unlink()
    elif damage == "hash":
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    else:
        path.write_bytes(original + b"changed")
    key = tmp_path / "public-unit-key"
    key.write_text(SOURCE)
    before_rows, before_files = rows(custody), files(custody.root)
    readonly = Ledger.open_existing_readonly(custody.root)
    with TestClient(none_app(readonly, source_key_file=key)) as client:
        response = client.get("/ingest/v1/runs/r/chunks/2", headers={"X-Source-Key": SOURCE})
        assert response.status_code == 503 and response.json() == {"detail": "Historical custody unavailable"}
    readonly.close()
    assert rows(custody) == before_rows and files(custody.root) == before_files


def test_real_evidence_routes_auth_text_detail_validation_and_explicit_pin(custody, monkeypatch):
    import pcap_recorder.api as api

    monkeypatch.setenv("ADMIN_API_KEY", OPERATOR)
    monkeypatch.delenv("OTALON_API_ALLOWED_KEYS", raising=False)
    before_rows, before_files = rows(custody), files(custody.root)
    readonly = Ledger.open_existing_readonly(custody.root)
    calls = []

    def subprocess(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="synthetic decoded unit text", stderr="")

    monkeypatch.setattr(api.subprocess, "run", subprocess)
    monkeypatch.setattr(api.os, "geteuid", lambda: 10006)
    with TestClient(none_app(readonly)) as client:
        params = {"start_ts": "1970-01-01T00:00:00Z", "end_ts": "1970-01-01T00:00:04Z"}
        assert client.get("/chunks", params=params).status_code == 401
        monkeypatch.delenv("ADMIN_API_KEY")
        assert client.get("/chunks", params=params, headers={"X-API-Key": OPERATOR}).status_code == 503
        monkeypatch.setenv("ADMIN_API_KEY", OPERATOR)
        h = {"X-API-Key": OPERATOR}
        response = client.get("/chunks", params=params, headers=h)
        assert response.status_code == 200 and len(response.json()) == 3
        name = response.json()[0]["chunk_id"]
        path = custody.root / "raw" / name
        assert client.get("/chunks/" + name, headers=h).content == path.read_bytes()
        assert (
            client.get("/chunks/" + name, params={"format": "json"}, headers=h).json()["size_bytes"]
            == path.stat().st_size
        )
        assert client.get("/chunks/" + name, params={"format": "text"}, headers=h).text == "synthetic decoded unit text"
        assert (
            client.get("/chunks/" + name, params={"format": "detail", "tshark_args": "-c 1"}, headers=h).text
            == "synthetic decoded unit text"
        )
        assert calls[0][0] == ["/usr/local/bin/tcpdump-read", "-r", str(path), "-q", "-tttt", "-n"]
        assert calls[1][0] == ["tshark", "-r", str(path), "-c", "1"]
        assert calls[1][1]["preexec_fn"] is None
        assert (
            client.get(
                "/chunks/" + name, params={"format": "detail", "tshark_args": "-w /tmp/no"}, headers=h
            ).status_code
            == 400
        )
        assert client.get("/chunks/" + name, params={"format": "unknown"}, headers=h).status_code == 422
        assert len(calls) == 2
        assert files(custody.root) == before_files
        pin = dict(params, labels={"alarm_id": "public-unit"})
        assert client.post("/anomalies/flag", json=pin, headers={"X-API-Key": SOURCE}).status_code == 401
        assert client.post("/anomalies/flag", json=pin, headers=h).json() == {
            "chunk_ids": [r["chunk_id"] for r in response.json()]
        }
    readonly.close()
    assert rows(custody) == before_rows
    after = files(custody.root)
    assert {k: v for k, v in after.items() if k != "pcap_index.json"} == {
        k: v for k, v in before_files.items() if k != "pcap_index.json"
    }
    assert all(
        entry["pinned"] and entry["labels"] == {"alarm_id": "public-unit"}
        for entry in json.loads(after["pcap_index.json"])
    )


def test_live_factory_credential_distinction_remains_explicit(tmp_path):
    ledger = Ledger(tmp_path)
    for source, operator in [(None, OPERATOR), (SOURCE, None), (SOURCE, SOURCE)]:
        with pytest.raises(ValueError, match="separate source/operator"):
            create_ingest_app(ledger, source, operator)
    ledger.close()


def test_snapshot_lazy_authenticated_scratch_only_sidefiles_and_lifespan_cleanup(custody, tmp_path, monkeypatch):
    import desktop_ingest.ledger as module

    key = tmp_path / "public-snapshot-key"
    key.write_text(SOURCE)
    before_rows, before_files = rows(custody), files(custody.root)
    readonly = Ledger.open_existing_readonly(custody.root)
    original_connect = sqlite3.connect
    connections = []

    def connect(database, *args, **kwargs):
        assert str(custody.root) not in str(database)
        assert "mode=ro" in str(database) and "immutable" not in str(database)
        connections.append(database)
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(module.sqlite3, "connect", connect)
    assert readonly._scratch is None
    with TestClient(none_app(readonly, source_key_file=key)) as client:
        assert readonly._scratch is None
        assert client.get("/health").status_code == 200
        assert client.get("/internal/continuous/status").status_code == 401
        assert client.get("/ingest/v1/runs/r/chunks/2", headers={"X-Source-Key": "wrong"}).status_code == 401
        assert client.put("/ingest/v1/runs/new", content=b"{").json() == DISABLED
        assert readonly._scratch is None and not connections
        assert client.get("/internal/continuous/status", headers={"X-API-Key": OPERATOR}).status_code == 200
        scratch = Path(readonly._scratch.name)
        assert not scratch.is_relative_to(custody.root)
        assert scratch.stat().st_mode & 0o777 == 0o700
        assert (scratch / "progress.sqlite3-wal").is_file()
        assert (scratch / "progress.sqlite3-shm").is_file()
        assert (scratch / "progress.sqlite3-shm").read_bytes() != before_files["progress.sqlite3-shm"]
        assert client.get("/internal/continuous/batches", headers={"X-API-Key": OPERATOR}).json() == {
            "batches": custody.committed_batches(0, 1)
        }
        assert client.get("/ingest/v1/runs/r/chunks/2", headers={"X-Source-Key": SOURCE}).json() == custody.receipt(
            "r", 2
        )
        assert readonly.root == custody.root and readonly.raw == custody.raw
        assert len(connections) == 1 and Path(readonly._scratch.name) == scratch
        assert rows(custody) == before_rows and files(custody.root) == before_files
    assert not scratch.exists() and readonly.db is None and readonly._scratch is None
    readonly.close()
    readonly.close()
    with pytest.raises(HistoricalCustodyError):
        readonly.historical_status()
    assert rows(custody) == before_rows and files(custody.root) == before_files


def test_snapshot_committed_wal_visibility_preserves_distinct_source_read_mark(custody):
    custody.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    stale_reader = sqlite3.connect(custody.root / "progress.sqlite3")
    try:
        stale_reader.execute("BEGIN")
        assert stale_reader.execute("SELECT version FROM metadata").fetchone()[0] == 1
        with custody.db:
            custody.db.execute("INSERT INTO consumer_ack VALUES('wal-only',7)")
        custody.db.execute("SELECT count(*) FROM consumer_ack").fetchone()
        # Native-endian SHM read marks: writer and held reader see different commits.
        marks = struct.unpack("=5I", (custody.root / "progress.sqlite3-shm").read_bytes()[100:120])
        assert len({mark for mark in marks if mark != 0xFFFFFFFF}) >= 2
        assert stale_reader.execute("SELECT batch FROM consumer_ack WHERE module='wal-only'").fetchone() is None
        expected = rows(custody)
        before = files(custody.root)
        readonly = Ledger.open_existing_readonly(custody.root)
        try:
            assert readonly.historical_status()["received"] == 3
            assert rows(readonly) == expected
            assert readonly.db.execute("SELECT batch FROM consumer_ack WHERE module='wal-only'").fetchone()[0] == 7
            assert readonly.committed_batches(0) == custody.committed_batches(0)
            assert readonly.pending_batches() == custody.pending_batches()
            assert readonly.load_checkpoint() == custody.load_checkpoint()
        finally:
            readonly.close()
        assert files(custody.root) == before and rows(custody) == expected
    finally:
        stale_reader.close()


@pytest.mark.parametrize("name", ["progress.sqlite3", "progress.sqlite3-wal", "progress.sqlite3-shm"])
def test_snapshot_rejects_metadata_hardlinks_before_scratch(custody, tmp_path, name):
    target = custody.root / name
    os.link(target, tmp_path / (name + ".alias"))
    before = files(custody.root)
    with pytest.raises(ValueError, match="unsafe"):
        Ledger.open_existing_readonly(custody.root)
    assert files(custody.root) == before


@pytest.mark.parametrize("damage", ["header", "frame-checksum", "frame-salt", "torn-frame"])
def test_snapshot_invalid_wal_never_returns_mixed_healthy_history(custody, monkeypatch, damage):
    import desktop_ingest.ledger as module

    wal = custody.root / "progress.sqlite3-wal"
    with wal.open("r+b") as stream:
        if damage == "torn-frame":
            stream.truncate(wal.stat().st_size - 1)
        else:
            stream.seek({"header": 8, "frame-checksum": 48, "frame-salt": 40}[damage])
            original = stream.read(1)
            stream.seek(-1, 1)
            stream.write(bytes([original[0] ^ 1]))
    before = files(custody.root)
    original_temp = module.tempfile.TemporaryDirectory
    scratches = []

    def temporary(*args, **kwargs):
        result = original_temp(*args, **kwargs)
        scratches.append(Path(result.name))
        return result

    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", temporary)
    readonly = Ledger.open_existing_readonly(custody.root)
    with TestClient(none_app(readonly)) as client:
        response = client.get("/internal/continuous/status", headers={"X-API-Key": OPERATOR})
        assert response.status_code == 503 and response.json() == {"detail": "Historical custody unavailable"}
        response = client.get("/internal/continuous/batches", headers={"X-API-Key": OPERATOR})
        assert response.status_code == 503 and response.json() == {"detail": "Historical custody unavailable"}
        assert len(scratches) == 1 and not scratches[0].exists()
        assert readonly.db is None and readonly._scratch is None
    readonly.close()
    assert files(custody.root) == before


def test_snapshot_held_uncommitted_transaction_returns_only_committed_state(custody):
    expected = rows(custody)
    custody.db.execute("BEGIN")
    try:
        custody.db.execute("UPDATE checkpoint SET state='{}'")
        custody.db.execute("UPDATE batches SET committed=1 WHERE id=2")
        custody.db.execute("INSERT INTO consumer_ack VALUES('not-committed',9)")
        before = files(custody.root)
        readonly = Ledger.open_existing_readonly(custody.root)
        try:
            assert readonly.historical_status() == {"received": 3, "pending_writes": 1, "checkpoint_present": True}
            assert rows(readonly) == expected
            assert readonly.load_checkpoint() == {"version": 2, "marker": "pending carry"}
            assert [row["id"] for row in readonly.committed_batches(0)] == [1]
            assert [row["id"] for row in readonly.pending_batches()] == [2]
        finally:
            readonly.close()
        assert files(custody.root) == before
    finally:
        custody.db.rollback()


@pytest.mark.parametrize("offset", [-1, 0])
def test_snapshot_budget_counts_main_and_wal_total(custody, monkeypatch, offset):
    import desktop_ingest.ledger as module

    total = sum((custody.root / name).stat().st_size for name in ("progress.sqlite3", "progress.sqlite3-wal"))
    before = files(custody.root)
    monkeypatch.setattr(module, "DEFAULT_CUSTODY_BYTES", total + offset)
    readonly = Ledger.open_existing_readonly(custody.root)
    try:
        if offset < 0:
            monkeypatch.setattr(module.tempfile, "TemporaryDirectory", forbidden)
            with pytest.raises(HistoricalCustodyError):
                readonly.historical_status()
            assert readonly._scratch is None and readonly.db is None
        else:
            assert readonly.historical_status()["received"] == 3
            scratch = Path(readonly._scratch.name)
            assert (
                sum((scratch / name).stat().st_size for name in ("progress.sqlite3", "progress.sqlite3-wal")) == total
            )
    finally:
        readonly.close()
    assert files(custody.root) == before


@pytest.mark.parametrize("name", ["progress.sqlite3", "progress.sqlite3-wal", "progress.sqlite3-shm"])
def test_snapshot_rechecks_nonregular_source_type_before_allocation(custody, monkeypatch, name):
    import desktop_ingest.ledger as module

    readonly = Ledger.open_existing_readonly(custody.root)
    path = custody.root / name
    path.rename(path.with_name(name + ".saved"))
    os.mkfifo(path)
    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", forbidden)
    with pytest.raises(HistoricalCustodyError):
        readonly.historical_status()
    assert readonly._scratch is None and readonly.db is None
    readonly.close()
    path.unlink()


def test_snapshot_copy_descriptors_close_after_failure(custody, monkeypatch):
    import desktop_ingest.ledger as module

    readonly = Ledger.open_existing_readonly(custody.root)
    original_open = os.open
    opened = []

    def open_file(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def read(*args, **kwargs):
        raise OSError("constructed descriptor-cleanup error")

    monkeypatch.setattr(module.os, "open", open_file)
    monkeypatch.setattr(module.os, "read", read)
    with pytest.raises(HistoricalCustodyError):
        readonly.historical_status()
    assert opened
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert readonly._scratch is None and readonly.db is None
    readonly.close()


def test_snapshot_custody_temporary_parent_refused_before_allocation(custody, monkeypatch):
    import desktop_ingest.ledger as module

    before = files(custody.root)
    readonly = Ledger.open_existing_readonly(custody.root)
    monkeypatch.setattr(module.tempfile, "gettempdir", lambda: str(custody.root))
    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", forbidden)
    with pytest.raises(HistoricalCustodyError):
        readonly.historical_status()
    assert readonly._scratch is None and readonly.db is None
    readonly.close()
    assert files(custody.root) == before


def test_snapshot_second_pass_byte_mismatch_refuses_before_sqlite(custody, monkeypatch):
    import desktop_ingest.ledger as module

    before = files(custody.root)
    main = custody.root / "progress.sqlite3"
    identity = (main.stat().st_dev, main.stat().st_ino)
    original_read = os.read
    first = []

    def read(fd, size):
        result = original_read(fd, size)
        info = os.fstat(fd)
        if result and (info.st_dev, info.st_ino) == identity and not first:
            first.append(True)
            return bytes([result[0] ^ 1]) + result[1:]
        return result

    monkeypatch.setattr(module.os, "read", read)
    monkeypatch.setattr(module.sqlite3, "connect", forbidden)
    readonly = Ledger.open_existing_readonly(custody.root)
    with pytest.raises(HistoricalCustodyError):
        readonly.historical_status()
    assert first == [True]
    assert readonly._scratch is None and readonly.db is None
    readonly.close()
    assert files(custody.root) == before


@pytest.mark.parametrize("name", ["progress.sqlite3", "progress.sqlite3-wal", "progress.sqlite3-shm", "raw"])
def test_snapshot_rechecks_lazy_link_race(custody, name):
    readonly = Ledger.open_existing_readonly(custody.root)
    path = custody.root / name
    saved = path.with_name(path.name + ".saved")
    path.rename(saved)
    path.symlink_to(saved, target_is_directory=name == "raw")
    before = saved.read_bytes() if saved.is_file() else files(saved)
    with pytest.raises(HistoricalCustodyError):
        readonly.historical_status()
    assert readonly.db is None and readonly._scratch is None
    assert (saved.read_bytes() if saved.is_file() else files(saved)) == before
    readonly.close()


@pytest.mark.parametrize("change", ["transaction", "checkpoint", "replace", "same-size", "wal-disappear", "shm-link"])
def test_snapshot_source_change_during_stream_refuses_and_cleans(custody, monkeypatch, change):
    import desktop_ingest.ledger as module

    readonly = Ledger.open_existing_readonly(custody.root)
    original_read = os.read
    original_temp = module.tempfile.TemporaryDirectory
    scratches = []
    changed = []
    after_mutation = []
    main = custody.root / "progress.sqlite3"
    identity = (main.stat().st_dev, main.stat().st_ino)

    def temporary(*args, **kwargs):
        result = original_temp(*args, **kwargs)
        scratches.append(Path(result.name))
        return result

    def read(fd, size):
        result = original_read(fd, size)
        info = os.fstat(fd)
        if result and (info.st_dev, info.st_ino) == identity and not changed:
            changed.append(change)
            if change == "transaction":
                with custody.db:
                    custody.db.execute("UPDATE checkpoint SET state='{}'")
            elif change == "checkpoint":
                assert custody.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
            elif change == "replace":
                replacement = main.with_suffix(".replacement")
                replacement.write_bytes(main.read_bytes())
                replacement.replace(main)
            elif change == "same-size":
                stamp = main.stat()
                with main.open("r+b") as stream:
                    stream.seek(80)
                    stream.write(b"changed!")
                os.utime(main, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            elif change == "wal-disappear":
                (custody.root / "progress.sqlite3-wal").rename(custody.root / "saved-wal")
            else:
                shm = custody.root / "progress.sqlite3-shm"
                saved = custody.root / "saved-shm"
                shm.rename(saved)
                shm.symlink_to(saved)
            after_mutation.append(files(custody.root))
        return result

    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", temporary)
    monkeypatch.setattr(module.os, "read", read)
    with TestClient(none_app(readonly)) as client:
        response = client.get("/internal/continuous/status", headers={"X-API-Key": OPERATOR})
        assert response.status_code == 503 and response.json() == {"detail": "Historical custody unavailable"}
        assert changed == [change] and len(scratches) == 1
        assert readonly.db is None and readonly._scratch is None
        assert not scratches[0].exists()
        assert files(custody.root) == after_mutation[0]
        assert client.get("/internal/continuous/status", headers={"X-API-Key": OPERATOR}).status_code == 503
        assert len(scratches) == 1  # Failed view never starts a repeated acquisition loop.
    readonly.close()


def test_snapshot_copy_limit_refuses_before_allocation_or_source_reads(tmp_path, monkeypatch):
    import desktop_ingest.ledger as module

    writer = Ledger(tmp_path / "bounded")
    writer.close()
    path = writer.root / "progress.sqlite3"
    monkeypatch.setattr(module, "DEFAULT_CUSTODY_BYTES", 4096)
    before = files(writer.root)
    readonly = Ledger.open_existing_readonly(writer.root)
    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", forbidden)
    monkeypatch.setattr(module.os, "read", forbidden)
    with pytest.raises(HistoricalCustodyError):
        readonly.historical_status()
    assert path.stat().st_size > 4096
    assert readonly._scratch is None and readonly.db is None
    readonly.close()
    assert files(writer.root) == before


def test_snapshot_streaming_copy_has_bounded_reads_and_python_memory(tmp_path, monkeypatch):
    import desktop_ingest.ledger as module

    writer = Ledger(tmp_path / "streamed")
    writer.observe({"interface": "constructed-memory-fixture", "padding": "x" * (4 * 1024 * 1024)})
    writer.close()
    main = writer.root / "progress.sqlite3"
    before = files(writer.root)
    source_identity = (main.stat().st_dev, main.stat().st_ino)
    original_read = os.read
    sizes, copied = [], []

    def read(fd, size):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == source_identity:
            sizes.append(size)
            assert 0 < size <= 65536
        result = original_read(fd, size)
        if (info.st_dev, info.st_ino) == source_identity:
            copied.append(len(result))
        return result

    monkeypatch.setattr(module.os, "read", read)
    readonly = Ledger.open_existing_readonly(writer.root)
    tracemalloc.start()
    try:
        assert readonly.historical_status() == {"received": 0, "pending_writes": 0, "checkpoint_present": False}
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        scratch = Path(readonly._scratch.name) if readonly._scratch else None
        readonly.close()
    assert max(sizes) == 65536 and sum(copied) == 2 * main.stat().st_size
    assert peak < 2 * 1024 * 1024
    assert scratch is not None and not scratch.exists()
    assert files(writer.root) == before


@pytest.mark.parametrize("failure", ["corrupt", "schema", "checkpoint", "blob", "connect", "copy"])
def test_snapshot_cleanup_on_corruption_and_read_errors(custody, tmp_path, monkeypatch, failure):
    import desktop_ingest.ledger as module

    if failure == "corrupt":
        custody.close()
        (custody.root / "progress.sqlite3").write_bytes(b"invalid constructed custody")
    elif failure == "schema":
        with custody.db:
            custody.db.execute("DROP TABLE consumer_ack")
    elif failure == "checkpoint":
        with custody.db:
            custody.db.execute("UPDATE checkpoint SET state='{' ")
    elif failure == "blob":
        Path(custody.next_chunk()["path"]).unlink()
    before = files(custody.root)
    original_temp = module.tempfile.TemporaryDirectory
    scratches = []

    def temporary(*args, **kwargs):
        result = original_temp(*args, **kwargs)
        scratches.append(Path(result.name))
        return result

    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", temporary)
    if failure == "connect":

        def connect(*args, **kwargs):
            raise sqlite3.OperationalError("constructed connection error")

        monkeypatch.setattr(module.sqlite3, "connect", connect)
    if failure == "copy":

        def read(*args, **kwargs):
            raise OSError("constructed copy error")

        monkeypatch.setattr(module.os, "read", read)
    readonly = Ledger.open_existing_readonly(custody.root)
    key = tmp_path / "public-error-key"
    key.write_text(SOURCE)
    with TestClient(none_app(readonly, source_key_file=key)) as client:
        route = "/ingest/v1/runs/r/chunks/2" if failure == "blob" else "/internal/continuous/status"
        headers = {"X-Source-Key": SOURCE} if failure == "blob" else {"X-API-Key": OPERATOR}
        response = client.get(route, headers=headers)
        assert response.status_code == 503 and response.json() == {"detail": "Historical custody unavailable"}
        assert len(scratches) == 1 and not scratches[0].exists()
        assert readonly._scratch is None and readonly.db is None
    readonly.close()
    readonly.close()
    assert files(custody.root) == before
