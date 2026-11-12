"""Live persistence survives a database outage without changing live IDs/grouping."""

import importlib.util
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord
from otalon_clas.detection.anomaly_persister import _AnomalyInterval


def test_live_outcome_remains_durable_until_transaction_succeeds(tmp_path):
    assert importlib.util.find_spec("otalon_clas.recovery.live_outbox"), "durable live outcome spool missing"
    from otalon_clas.recovery.live_outbox import LiveOutboxPersister
    from otalon_clas.recovery.progress import LocalProgress

    engine = create_engine("sqlite:///" + str(tmp_path / "db"))
    Alarm.__table__.create(engine)
    AnomalyRecord.__table__.create(engine)

    class Connector:
        failing = True

        @contextmanager
        def session(self):
            if self.failing:
                raise ConnectionError("fixture PG outage")
            with Session(engine) as session, session.begin():
                yield session

    connector = Connector()
    progress = LocalProgress(tmp_path / "spool")
    persister = LiveOutboxPersister(connector, progress)
    stamp = datetime(2020, 1, 1, tzinfo=timezone.utc)
    interval = _AnomalyInterval(
        module="conn",
        series_id="fixture",
        anomaly_type="BoundViolation",
        start_ts=stamp,
        end_ts=stamp,
        rows=[{"confidence": 0.9, "severity": 1.0, "packet_count": 10}],
    )
    assert persister._upsert_intervals([interval]) == 0
    assert progress.outcomes()
    progress.close()
    progress = LocalProgress(tmp_path / "spool")
    persister = LiveOutboxPersister(connector, progress)
    connector.failing = False
    assert persister.retry() == 1
    assert persister.retry() == 0
    with Session(engine) as session:
        record = session.query(AnomalyRecord).one()
        assert record.module == "conn" and not record.is_grouped
        assert session.query(Alarm).count() == 0
