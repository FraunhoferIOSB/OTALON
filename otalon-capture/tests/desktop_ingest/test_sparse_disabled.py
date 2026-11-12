"""Both producer modes retain all packet metrics with real native records."""

import json
from pathlib import Path

from desktop_ingest.ledger import Ledger
from desktop_ingest.main import load_settings
from desktop_ingest.pipeline import ContinuousPipeline
from test_ledger import pcap


def test_no_sparse_aggregation_keeps_packet_count_and_volume(tmp_path):
    raw = json.loads((Path(__file__).parents[2] / "config/config.json").read_text())
    raw["preprocess"]["aggregate_sparse_ports"] = False
    for key in ["influx", "mac_influx", "proto_influx"]:
        raw[key].update(host="http://127.0.0.1:1", token="fixture")
    (tmp_path / "cfg").write_text(json.dumps(raw))
    settings = load_settings(tmp_path / "cfg")
    ledger = Ledger(tmp_path / "ledger")
    ledger.register_run("r", None)
    ledger.receive("r", 0, pcap([1000200, 1000900, 1001300, 1002400]))
    pipe = ContinuousPipeline(settings, ledger, False)
    pipe.process_one()
    parts = [p for b in ledger.pending_batches() for p in b["payload"] if p["writer"] == "network"]
    assert parts
    assert parts[0]["records"][0]["packet_count"] == 2
    assert parts[0]["records"][0]["total_volume"] == 120
