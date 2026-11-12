"""Recovery policy must reuse operator suppressions, not an unconfigured persister."""

from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord
from otalon_clas.common.settings import ModuleConfig, PipelinePostProcessingConfig
from otalon_clas.detection.frequency_monitor import FrequencyMonitor
from otalon_clas.pipeline.builder import PipelineBuilder
from otalon_clas.preprocessing.passthrough import PassthroughPreprocessor
from otalon_clas.recovery.progress import LocalProgress
from otalon_clas.recovery.repository import RecoveryRepository
from otalon_clas.recovery.worker import RecoveryWorker
from otalon_clas.runtime.module_bundle import ModuleBundle


def test_recovery_honours_suppression_before_creating_historical_rows(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "db"))
    Alarm.__table__.create(engine)
    AnomalyRecord.__table__.create(engine)
    from otalon_clas.detection.anomaly_persister import AnomalyPersister
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
    progress.register(
        {
            "id": 1,
            "chunk": "owned",
            "payload": [
                {
                    "measurement": "network_metrics",
                    "records": [{"time": "2020-01-01T00:00:00+00:00", "uci": "fixture", "packet_count": 10}],
                }
            ],
        },
        ["fixture"],
    )

    class Suppression:
        def is_suppressed(self, series_id, anomaly_type):
            return SimpleNamespace(suppression_id="fixture", reason="operator suppression")

    policy = AnomalyPersister(None, suppression_service=Suppression())
    worker = RecoveryWorker(
        [bundle],
        progress,
        RecoveryRepository(engine),
        PipelineBuilder(PipelinePostProcessingConfig(stages=[])),
        persistence_policy=policy,
    )
    assert worker.process_one()
    with Session(engine) as session:
        assert session.query(AnomalyRecord).count() == 0
        assert session.query(Alarm).count() == 0
