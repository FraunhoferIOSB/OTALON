"""Historical outcome pages must not starve real live database retry."""

from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord
from otalon_clas.detection.anomaly_persister import _AnomalyInterval
from otalon_clas.recovery.live_outbox import LiveOutboxPersister
from otalon_clas.recovery.progress import LocalProgress


def test_live_database_retry_reachable_after_more_than_page_of_historical_work(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "db"))
    Alarm.__table__.create(engine)
    AnomalyRecord.__table__.create(engine)

    class Connector:
        @contextmanager
        def session(self):
            with Session(engine) as session, session.begin():
                yield session

    progress = LocalProgress(tmp_path / "progress")
    for number in range(11):
        progress.put_outcome(str(number), "conn", {"number": number})
    stamp = datetime(2020, 1, 1, tzinfo=timezone.utc)
    interval = _AnomalyInterval(
        module="conn",
        series_id="fixture",
        anomaly_type="BoundViolation",
        start_ts=stamp,
        end_ts=stamp,
        rows=[{"confidence": 0.9, "severity": 1.0, "packet_count": 10}],
    )
    persister = LiveOutboxPersister(Connector(), progress)
    assert persister._upsert_intervals([interval]) == 1, "historical page hid retryable live anomaly"
    with Session(engine) as session:
        assert session.query(AnomalyRecord).count() == 1
    assert persister.retry() == 0
    assert len(progress.outcomes()) == 10
