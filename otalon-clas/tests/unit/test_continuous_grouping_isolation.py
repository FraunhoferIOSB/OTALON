"""Live grouping cannot select a historical replay alarm as its target."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord
from otalon_clas.detection.grouping import _create_alarm_from_anomaly, incremental_group_ungrouped_anomalies


def test_live_grouping_does_not_merge_into_historical_alarm(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "database"))
    Alarm.__table__.create(engine)
    AnomalyRecord.__table__.create(engine)
    stamp = datetime.now(timezone.utc) - timedelta(seconds=2)
    historical_anomaly = AnomalyRecord(
        id="ccr_owned",
        module="conn",
        series_id="fixture",
        anomaly_type="bound",
        start_ts=stamp,
        end_ts=stamp,
        violated_features=[],
        is_anomaly=True,
        is_grouped=True,
    )
    historical = _create_alarm_from_anomaly(historical_anomaly)
    historical.id = "cc_owned"
    historical_anomaly.alarm_id = historical.id
    live = AnomalyRecord(
        id="owned-live",
        module="conn",
        series_id="fixture",
        anomaly_type="bound",
        start_ts=stamp,
        end_ts=stamp,
        violated_features=[],
        is_anomaly=True,
        is_grouped=False,
    )
    with Session(engine) as session, session.begin():
        session.add(historical)
        session.add(historical_anomaly)
        session.add(live)

    class Connector:
        @contextmanager
        def session(self):
            with Session(engine) as session, session.begin():
                yield session

    touched = incremental_group_ungrouped_anomalies(Connector())
    with Session(engine) as session:
        assert (
            session.get(AnomalyRecord, "owned-live").alarm_id != "cc_owned"
        ), "live grouping selected a historical alarm"
        assert session.get(AnomalyRecord, "ccr_owned").alarm_id == "cc_owned"
    assert len(touched) == 1
