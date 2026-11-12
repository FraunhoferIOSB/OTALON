"""Actual native-metric records drive existing bounds and retry-safe recovery."""

import importlib.util
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord
from otalon_clas.common.settings import ModuleConfig, PipelinePostProcessingConfig
from otalon_clas.detection.frequency_monitor import FrequencyMonitor
from otalon_clas.pipeline.builder import PipelineBuilder
from otalon_clas.preprocessing.passthrough import PassthroughPreprocessor
from otalon_clas.runtime.module_bundle import ModuleBundle


def test_actual_worker_persists_bound_result_once_and_keeps_live_last_seen(tmp_path):
    assert importlib.util.find_spec("otalon_clas.recovery.worker"), "source-driven continuous worker missing"
    from otalon_clas.recovery.progress import LocalProgress
    from otalon_clas.recovery.repository import RecoveryRepository
    from otalon_clas.recovery.worker import RecoveryWorker

    engine = create_engine("sqlite:///" + str(tmp_path / "db"))
    Alarm.__table__.create(engine)
    AnomalyRecord.__table__.create(engine)
    from otalon_clas.detection.bounds_manager import BoundsManager

    bounds = BoundsManager("fixture")
    bounds.load_bounds({"fixture": {"packet_count": (0.0, 5.0)}})
    config = ModuleConfig(
        name="fixture",
        measurement="network_metrics",
        tag_key="uci",
        features=["packet_count"],
        preprocessor={"type": "passthrough"},
    )
    freq = FrequencyMonitor(module_name="fixture")
    live_before = dict(freq._profiles)
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
    batch = {
        "id": 1,
        "chunk": "owned",
        "payload": [
            {
                "measurement": "network_metrics",
                "records": [{"time": "2020-01-01T00:00:00+00:00", "uci": "fixture", "packet_count": 10}],
            }
        ],
    }
    progress.register(batch, ["fixture"])
    worker = RecoveryWorker(
        [bundle], progress, RecoveryRepository(engine), PipelineBuilder(PipelinePostProcessingConfig(stages=[]))
    )
    assert worker.process_one()
    assert not worker.process_one()
    assert freq._profiles == live_before
    with Session(engine) as session:
        assert session.query(AnomalyRecord).count() == 1
        assert session.query(Alarm).count() == 1
    progress.close()
    progress = LocalProgress(tmp_path / "progress")
    assert progress.next_work("fixture") is None
