"""Real ingress app authentication, durable receipt and streaming limits."""

import importlib.util

from fastapi.testclient import TestClient
from test_ledger import pcap


def test_source_key_does_not_authorize_operator_routes(tmp_path):
    assert importlib.util.find_spec("desktop_ingest.api"), "continuous HTTP ingress missing"
    from desktop_ingest.api import create_ingest_app
    from desktop_ingest.ledger import Ledger

    ledger = Ledger(tmp_path, max_bytes=1000000)
    app = create_ingest_app(ledger, "source-test-key", "operator-test-key")
    c = TestClient(app)
    assert (
        c.put(
            "/ingest/v1/runs/r1",
            json={"version": 1, "interface_id": "fixture", "capture_fingerprint": "a" * 64, "predecessor": None},
        ).status_code
        == 401
    )
    import hashlib

    h = {"X-Source-Key": "source-test-key", "X-Chunk-SHA256": hashlib.sha256(pcap([1000])).hexdigest()}
    assert (
        c.put(
            "/ingest/v1/runs/r1",
            headers=h,
            json={"version": 1, "interface_id": "fixture", "capture_fingerprint": "a" * 64, "predecessor": None},
        ).status_code
        == 200
    )
    r = c.put("/ingest/v1/runs/r1/chunks/0", headers=h, content=pcap([1000]))
    assert r.status_code == 200
    assert c.put("/ingest/v1/runs/r1/chunks/0", headers=h, content=pcap([1000])).json() == r.json()
    conflict_headers = dict(h, **{"X-Chunk-SHA256": hashlib.sha256(pcap([2000])).hexdigest()})
    assert c.put("/ingest/v1/runs/r1/chunks/0", headers=conflict_headers, content=pcap([2000])).status_code == 409
    assert c.get("/internal/continuous/batches", headers=h).status_code == 401
    assert c.get("/internal/continuous/batches", headers={"X-API-Key": "operator-test-key"}).status_code == 200
    assert c.put("/ingest/v1/runs/r1/chunks/1", headers=h, content=b"x" * 201).status_code in (413, 422)


def test_successor_waits_for_closed_predecessor_and_missing_ordinal(tmp_path):
    from desktop_ingest.ledger import Ledger

    ledger = Ledger(tmp_path)
    ledger.register_run("r1", None)
    ledger.receive("r1", 0, pcap([1000]))
    ledger.close_run("r1", 1)
    ledger.register_run("r2", "r1")
    ledger.receive("r2", 0, pcap([3000]))
    ledger.mark_consumed(ledger.next_chunk()["id"])
    assert ledger.next_chunk() is None
    ledger.receive("r1", 1, pcap([2000]))
    ledger.mark_consumed(ledger.next_chunk()["id"])
    assert ledger.next_chunk()["run"] == "r2"
