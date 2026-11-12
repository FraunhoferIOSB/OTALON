"""Receiver evidence, real HTTP app, least privilege and index persistence."""

import hashlib
import json
import time
from pathlib import Path

from desktop_ingest.ledger import Ledger
from desktop_ingest.main import build_app, load_settings
from fastapi.testclient import TestClient
from test_ledger import pcap


def test_receiver_uses_real_recorder_index_without_native_capture(tmp_path, monkeypatch):
    raw = json.loads((Path(__file__).parents[2] / "config/config.json").read_text())
    for key in ["influx", "mac_influx", "proto_influx"]:
        raw[key]["host"] = "http://127.0.0.1:1"
        raw[key]["token"] = "unit-only"
        raw[key]["database"] = "netcap"
    cfg = tmp_path / "config"
    cfg.write_text(json.dumps(raw))
    settings = load_settings(cfg)
    ledger = Ledger(tmp_path / "durable")
    monkeypatch.setenv("ADMIN_API_KEY", "operator-only")
    app = build_app(settings, ledger, "source-only", "operator-only")
    import pcap_recorder.api as api

    assert "rx_" in api.CHUNK_ID_PATTERN, (api.__file__, api.CHUNK_ID_PATTERN)
    assert (
        app.openapi()["paths"]["/chunks/{chunk_id}"]["get"]["parameters"][0]["schema"]["pattern"]
        == api.CHUNK_ID_PATTERN
    )
    with TestClient(app) as client:
        h = {"X-Source-Key": "source-only"}
        body = {"version": 1, "interface_id": "fixture", "capture_fingerprint": "a" * 64, "predecessor": None}
        assert client.put("/ingest/v1/runs/r1", headers=h, json=body).status_code == 200
        data = pcap([1000, 1100])
        h["X-Chunk-SHA256"] = hashlib.sha256(data).hexdigest()
        assert client.put("/ingest/v1/runs/r1/chunks/0", headers=h, content=data).status_code == 200
        for _ in range(30):
            reply = client.get(
                "/chunks",
                params={"start_ts": "1970-01-01T00:00:00Z", "end_ts": "1970-01-01T00:00:02Z"},
                headers={"X-API-Key": "operator-only"},
            )
            if reply.status_code == 200 and reply.json():
                break
            time.sleep(0.05)
        assert reply.status_code == 200 and len(reply.json()) == 1
        chunk = reply.json()[0]
        assert chunk["chunk_id"].startswith("rx_")
        download = client.get("/chunks/" + chunk["chunk_id"], headers={"X-API-Key": "operator-only"})
        assert download.status_code == 200, (chunk["chunk_id"], download.text)
        assert download.content == data
        assert client.get("/chunks/" + chunk["chunk_id"], headers={"X-API-Key": "source-only"}).status_code == 401
        assert client.get("/status").json()["recording"] is None
        assert (
            client.post(
                "/anomalies/flag",
                headers={"X-API-Key": "operator-only"},
                json={
                    "start_ts": "1970-01-01T00:00:01Z",
                    "end_ts": "1970-01-01T00:00:02Z",
                    "labels": {"alarm_id": "test-alarm"},
                },
            ).status_code
            == 200
        )
    persisted = json.loads((ledger.root / "pcap_index.json").read_text())
    assert persisted[0]["pinned"] and persisted[0]["labels"]["alarm_id"] == "test-alarm"
