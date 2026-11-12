"""Historical replay must not mutate canonical live anomaly identity or state."""

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord
from otalon_clas.detection.anomaly_persister import _AnomalyInterval, _build_record
from otalon_clas.recovery.repository import RecoveryRepository


def test_historical_outcome_has_own_identity_and_leaves_live_record_intact(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "database"))
    Alarm.__table__.create(engine)
    AnomalyRecord.__table__.create(engine)
    stamp = datetime(2020, 1, 1, tzinfo=timezone.utc)
    interval = _AnomalyInterval(
        module="conn",
        series_id="fixture",
        anomaly_type="BoundViolation",
        start_ts=stamp,
        end_ts=stamp,
        rows=[{"confidence": 0.9, "severity": 1.0, "packet_count": 10}],
    )
    live = _build_record(interval)
    with Session(engine, expire_on_commit=False) as session, session.begin():
        live.confirmed = True
        session.add(live)
    values = {
        column.name: (value.isoformat() if isinstance(value, datetime) else value)
        for column in live.__table__.columns
        if (value := getattr(live, column.name)) is not None
    }
    payload = {
        "id": "owned-work",
        "module": "conn",
        "batch_id": 1,
        "batch_hash": "a" * 64,
        "checkpoint": {},
        "result": {"bounds": "evaluated"},
        "records": [values],
    }
    repo = RecoveryRepository(engine, "owned-source")
    links = repo.persist(payload)
    assert links != [live.id], "historical replay reused and overwrote the live anomaly identity"
    assert repo.persist(payload) == links
    with Session(engine) as session:
        assert session.query(AnomalyRecord).count() == 2
        original = session.get(AnomalyRecord, live.id)
        assert original.confirmed and original.alarm_id is None
        historical = session.get(AnomalyRecord, links[0])
        assert not historical.confirmed
        assert historical.alarm_id.startswith("cc_")
