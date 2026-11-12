"""Frequency interarrival recovery needs predecessor rows across file boundaries."""

from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord
from otalon_clas.common.settings import ModuleConfig, PipelinePostProcessingConfig
from otalon_clas.detection.bounds_manager import BoundsManager
from otalon_clas.detection.frequency_monitor import FrequencyMonitor, _SeriesFrequencyProfile
from otalon_clas.pipeline.builder import PipelineBuilder
from otalon_clas.preprocessing.passthrough import PassthroughPreprocessor
from otalon_clas.recovery.progress import LocalProgress
from otalon_clas.recovery.repository import RecoveryRepository
from otalon_clas.recovery.worker import RecoveryWorker
from otalon_clas.runtime.module_bundle import ModuleBundle


def test_recovery_detects_interarrival_shift_across_chunks(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "db"))
    Alarm.__table__.create(engine)
    AnomalyRecord.__table__.create(engine)
    bounds = BoundsManager("fixture")
    bounds.load_bounds({"fixture": {"packet_count": (0.0, 50.0)}})
    config = ModuleConfig(
        name="fixture",
        measurement="network_metrics",
        tag_key="uci",
        features=["packet_count"],
        preprocessor={"type": "passthrough"},
    )
    freq = FrequencyMonitor(module_name="fixture", min_intervals=2)
    future = datetime(2030, 1, 1, tzinfo=timezone.utc)
    freq._profiles = {"fixture": _SeriesFrequencyProfile(1, 0.01, future)}
    freq._rebuild_profile_index()
    bundle = ModuleBundle(
        config,
        None,
        PassthroughPreprocessor("uci", ["packet_count"]),
        bounds,
        None,
        None,
        freq,
        SimpleNamespace(backend=None, scaler=None),
    )
    progress = LocalProgress(tmp_path / "progress")
    repo = RecoveryRepository(engine)
    worker = RecoveryWorker([bundle], progress, repo, PipelineBuilder(PipelinePostProcessingConfig(stages=[])))
    for i, second in enumerate([0, 4, 8], 1):
        progress.register(
            {
                "id": i,
                "chunk": str(i),
                "payload": [
                    {
                        "measurement": "network_metrics",
                        "records": [
                            {
                                "time": f"2020-01-01T00:00:{second:02}:00+00:00".replace(":00+00:00", "+00:00"),
                                "uci": "fixture",
                                "packet_count": 1,
                            }
                        ],
                    }
                ],
            },
            ["fixture"],
        )
        assert worker.process_one()
    with Session(engine) as session:
        results = session.query(AnomalyRecord).all()
        assert any(
            "FrequencyAnomaly" in str(row.anomaly_type) for row in results
        ), "chunk boundaries hid a known interarrival shift"
    assert freq._profiles["fixture"].last_seen == future
