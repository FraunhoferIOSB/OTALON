"""Real recorder/receiver app and selected metric settings, no physical NIC."""

import json
from pathlib import Path

from test_ledger import pcap


def test_metric_loader_does_not_require_native_nic_or_llm(tmp_path, monkeypatch):
    from desktop_ingest.main import load_settings

    source = json.loads((Path(__file__).parents[2] / "config/config.json").read_text())
    for name in ["INFLUX_URL", "INFLUX_MAC_URL", "INFLUX_PROTO_URL"]:
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    monkeypatch.setenv("INFLUX_TOKEN", "unit-only")
    monkeypatch.setenv("INFLUX_DATABASE", "netcap")
    monkeypatch.setenv("INFLUX_MAC_DATABASE", "netcap")
    monkeypatch.setenv("INFLUX_PROTO_DATABASE", "netcap")
    monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(source))
    settings = load_settings(path)
    assert not hasattr(settings, "capture")
    assert settings.interval_ms == 1000


def test_window_manifest_keeps_real_points_and_no_false_success_on_writer_fault(tmp_path, monkeypatch):
    from desktop_ingest.ledger import Ledger
    from desktop_ingest.pipeline import ContinuousPipeline
    from otalon_capture.settings import Settings

    raw = json.loads((Path(__file__).parents[2] / "config/config.json").read_text())
    raw["capture"] = {"source": "test", "type": "PCAP", "interval": 1000}
    for k in ["influx", "mac_influx", "proto_influx"]:
        raw[k]["host"] = "http://127.0.0.1:1"
        raw[k]["token"] = "unit-only"
        raw[k]["database"] = "netcap"
    settings = Settings.model_validate(raw)
    ledger = Ledger(tmp_path)
    ledger.register_run("r1", None)
    pipeline = ContinuousPipeline(settings, ledger, write_enabled=False)
    ledger.receive("r1", 0, pcap([1000200, 1001300, 1002400]))
    pipeline.process_one()

    class Failed:
        def write(self, **kwargs):
            raise OSError("write failed")

    for w in pipeline.writers.values():
        w.client = Failed()
    pipeline.write_enabled = True
    import pytest

    with pytest.raises(OSError):
        pipeline.publish_pending()
    assert ledger.pending_batches() and not ledger.committed_batches(0)
    pipeline.write_enabled = False
    restored = ContinuousPipeline(settings, ledger, write_enabled=False)
    assert restored.checkpoint() == pipeline.checkpoint()
