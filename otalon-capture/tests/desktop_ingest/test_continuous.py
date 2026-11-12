"""Continuous producer preserves native/Python state and exact retry payloads."""

import importlib.util
import json
from pathlib import Path

from test_ledger import pcap


def test_every_file_split_and_restart_matches_uninterrupted(tmp_path):
    assert importlib.util.find_spec("desktop_ingest.pipeline"), "continuous pipeline missing"
    from desktop_ingest.ledger import Ledger
    from desktop_ingest.pipeline import ContinuousPipeline
    from otalon_capture.settings import Settings

    config = json.loads((Path(__file__).parents[2] / "config/config.json").read_text())
    config["capture"]["source"] = "offline-test"
    config["capture"]["type"] = "PCAP"
    for k in ["influx", "mac_influx", "proto_influx"]:
        if k in config:
            config[k]["host"] = "http://127.0.0.1:1"
            config[k]["token"] = "test-only"
    settings = Settings.model_validate(config)
    packets = [1000200, 1000900, 1001300, 1001600, 1002400, 1003500]
    results = []
    for split in [len(packets), 1, 2, 3, 4]:
        root = tmp_path / str(split)
        ledger = Ledger(root, max_bytes=1000000)
        ledger.register_run("r1", None)
        pipeline = ContinuousPipeline(settings, ledger, write_enabled=False)
        ledger.receive("r1", 0, pcap(packets[:split]))
        pipeline.process_one()
        pipeline = ContinuousPipeline(settings, ledger, write_enabled=False)
        if split < len(packets):
            ledger.receive("r1", 1, pcap(packets[split:]))
            pipeline.process_one()
        payload = [x for b in ledger.pending_batches() for x in b["payload"]]
        records = {k: [] for k in ["network_metrics", "mac_traffic", "proto_traffic"]}
        for part in payload:
            records[part["measurement"]] += part["lines"]
        results.append(records)
    assert all(r == results[0] for r in results)
    assert all(results[0][k] for k in results[0])
