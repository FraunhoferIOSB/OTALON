"""Resource/identity/coverage gates for the real collector protocol."""

import hashlib

from desktop_ingest.api import create_ingest_app
from desktop_ingest.ledger import Ledger
from fastapi.testclient import TestClient
from test_ledger import pcap


def test_versioned_run_and_receipt_digest_required(tmp_path):
    ledger = Ledger(tmp_path)
    c = TestClient(create_ingest_app(ledger, "source-only", "operator-only"))
    h = {"X-Source-Key": "source-only"}
    run = "abc123"
    body = {"version": 1, "interface_id": "physical-test", "capture_fingerprint": "a" * 64, "predecessor": None}
    assert c.put("/ingest/v1/runs/" + run, headers=h, json=body).status_code == 200
    data = pcap([1000])
    path = "/ingest/v1/runs/" + run + "/chunks/0"
    assert c.put(path, headers=h, content=data).status_code == 422
    h["X-Chunk-SHA256"] = hashlib.sha256(data).hexdigest()
    response = c.put(path, headers=h, content=data)
    assert response.status_code == 200
    receipt = c.get(path, headers=h).json()
    assert receipt["hash"] == h["X-Chunk-SHA256"] and receipt["size_bytes"] == len(data)
    assert receipt["custody"] == "accepted" and receipt["processing"] == "pending"
    body["capture_fingerprint"] = "b" * 64
    assert c.put("/ingest/v1/runs/" + run, headers=h, json=body).status_code == 409


def test_committed_chunk_is_not_complete_while_native_tail_remains(tmp_path):
    ledger = Ledger(tmp_path)
    ledger.register_run("r1", None)
    chunk = ledger.receive("r1", 0, pcap([1000]))
    ledger.prepare(chunk["id"], {"version": 1}, [])
    ledger.commit_batch(ledger.pending_batches()[0]["id"])
    assert ledger.receipt("r1", 0)["processing"] != "complete"


def test_end_ordinal_cannot_exclude_already_received_records(tmp_path):
    ledger = Ledger(tmp_path)
    ledger.register_run("r1", None)
    ledger.receive("r1", 1, pcap([1000]))
    import pytest

    with pytest.raises(ValueError):
        ledger.close_run("r1", 0)
