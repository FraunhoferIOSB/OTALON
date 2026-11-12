"""Live alarm maintenance is not authorized to consume historical replay groups."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import Alarm
from otalon_clas.detection.grouping import fetch_alarms_pending_classification
from otalon_clas.main import _deactivate_stale_alarms


def test_live_maintenance_preserves_historical_group_state(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "database"))
    Alarm.__table__.create(engine)
    stamp = datetime.now(timezone.utc) - timedelta(seconds=120)
    with Session(engine) as session, session.begin():
        for ident in ["cc_owned", "owned-live"]:
            session.add(
                Alarm(
                    id=ident,
                    module="conn",
                    start_timestamp=stamp,
                    end_timestamp=stamp,
                    series_ids=["fixture"],
                    anomaly_type_stats={},
                    is_active=True,
                )
            )

    class Connector:
        @contextmanager
        def session(self):
            with Session(engine) as session, session.begin():
                yield session

    connector = Connector()
    pending = fetch_alarms_pending_classification(connector)
    assert [alarm.id for alarm in pending] == ["owned-live"], "live classifier consumed historical groups"
    _deactivate_stale_alarms(connector, 30)
    with Session(engine) as session:
        assert session.get(Alarm, "cc_owned").is_active
        assert not session.get(Alarm, "owned-live").is_active
