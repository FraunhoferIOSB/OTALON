"""Unit tests for :class:`PortCollapseRulesRepository.upsert_rules`.

Covers the incremental upsert path (CLAS-033 Wave B): merge-on-composite-PK
preserves ``created_at`` while refreshing ``updated_at``, never deletes
existing rows, and leaves untouched rules in the same module intact.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterator, cast

import pytest
from loguru import logger
from otalon_common.connection import PortCollapseRule

from otalon_clas.common.postgres_connector import (
    PortCollapseRuleRecord,
    PostgresConnector,
)
from otalon_clas.preprocessing.port_rules_repository import (
    PortCollapseRulesRepository,
)

_OLD_TS = datetime(2020, 1, 1, 0, 0, 0)


def _make_sqlite_connector(tmp_path: Path) -> PostgresConnector:
    """Build a PostgresConnector backed by a fresh SQLite file."""
    db_path = tmp_path / "port_rules.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db_path}", pool_size=1, max_overflow=0)
    PortCollapseRuleRecord.__table__.create(pg.engine, checkfirst=True)
    return pg


def _make_rule(
    src_mac: str = "aa:bb",
    wildcard_src: bool = False,
    wildcard_dst: bool = False,
    src_port: str = "50000",
    dst_port: str = "443",
) -> PortCollapseRule:
    """Build a rule with a canonical base key varying by ``src_mac``."""
    src_p = "*" if wildcard_src else src_port
    dst_p = "*" if wildcard_dst else dst_port
    return PortCollapseRule(
        src_mac=src_mac,
        dst_mac="cc:dd",
        vlan="100",
        ip_proto="6",
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        protocols="TCP",
        normalized_uci=f"{src_mac}/cc:dd/100/6/1.1.1.1/2.2.2.2/{src_p}/{dst_p}/TCP",
        wildcard_src_port=wildcard_src,
        wildcard_dst_port=wildcard_dst,
        bucket_seconds=60,
    )


def _seed_record(
    pg: PostgresConnector,
    src_mac: str = "aa:bb",
    wildcard_src: bool = False,
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> None:
    """Insert a raw rule row with explicit timestamps for upsert comparison."""
    with pg.session() as session:
        session.add(
            PortCollapseRuleRecord(
                module="conn",
                src_mac=src_mac,
                dst_mac="cc:dd",
                vlan="100",
                ip_proto="6",
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
                protocols="TCP",
                normalized_uci=f"{src_mac}/cc:dd/100/6/1.1.1.1/2.2.2.2/50000/443/TCP",
                wildcard_src_port=wildcard_src,
                wildcard_dst_port=False,
                bucket_seconds=60,
                created_at=created_at,
                updated_at=updated_at,
            )
        )
        session.commit()


def _timestamps(
    pg: PostgresConnector,
) -> dict[str, tuple[datetime | None, datetime | None]]:
    """Return ``(created_at, updated_at)`` per rule keyed by ``src_mac``."""
    with pg.session() as session:
        rows = session.query(PortCollapseRuleRecord).all()
        return {
            str(row.src_mac): (
                cast(datetime | None, row.created_at),
                cast(datetime | None, row.updated_at),
            )
            for row in rows
        }


def test_upsert_new_rule_inserts_with_timestamps(tmp_path: Path) -> None:
    """Upsert of a new base key inserts a row with created_at and updated_at set."""
    pg = _make_sqlite_connector(tmp_path)
    repo = PortCollapseRulesRepository(pg)

    repo.upsert_rules("conn", [_make_rule(src_mac="aa:bb")])

    assert len(repo.load("conn")) == 1
    created, updated = _timestamps(pg)["aa:bb"]
    assert created is not None
    assert updated is not None


def test_upsert_existing_rule_preserves_created_refreshes_updated(
    tmp_path: Path,
) -> None:
    """Upsert of an existing base key preserves created_at, refreshes updated_at."""
    pg = _make_sqlite_connector(tmp_path)
    repo = PortCollapseRulesRepository(pg)
    _seed_record(pg, src_mac="aa:bb", created_at=_OLD_TS, updated_at=_OLD_TS)

    repo.upsert_rules("conn", [_make_rule(src_mac="aa:bb", wildcard_src=True)])

    loaded = repo.load("conn")
    assert len(loaded) == 1
    assert loaded[0].wildcard_src_port is True
    assert loaded[0].normalized_uci == "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/443/TCP"
    created, updated = _timestamps(pg)["aa:bb"]
    assert created == _OLD_TS
    assert updated is not None
    assert updated != _OLD_TS


def test_upsert_does_not_touch_other_rules_in_module(tmp_path: Path) -> None:
    """Upserting one base key leaves another rule's data and timestamps intact."""
    pg = _make_sqlite_connector(tmp_path)
    repo = PortCollapseRulesRepository(pg)
    _seed_record(pg, src_mac="aa:bb", created_at=_OLD_TS, updated_at=_OLD_TS)
    _seed_record(pg, src_mac="bb:cc", created_at=_OLD_TS, updated_at=_OLD_TS)

    repo.upsert_rules("conn", [_make_rule(src_mac="aa:bb", wildcard_src=True)])

    loaded = {r.src_mac: r for r in repo.load("conn")}
    assert len(loaded) == 2
    assert loaded["aa:bb"].wildcard_src_port is True
    assert loaded["bb:cc"].wildcard_src_port is False
    ts = _timestamps(pg)
    assert ts["aa:bb"][1] != _OLD_TS
    assert ts["bb:cc"][1] == _OLD_TS
    assert ts["bb:cc"][0] == _OLD_TS


def test_upsert_does_not_delete_rows(tmp_path: Path) -> None:
    """Upsert of a subset never deletes rules absent from the input list."""
    pg = _make_sqlite_connector(tmp_path)
    repo = PortCollapseRulesRepository(pg)
    repo.save(
        "conn",
        [
            _make_rule(src_mac="aa:bb"),
            _make_rule(src_mac="bb:cc"),
            _make_rule(src_mac="cc:dd"),
        ],
    )
    assert len(repo.load("conn")) == 3

    repo.upsert_rules("conn", [_make_rule(src_mac="aa:bb", wildcard_src=True)])

    loaded = repo.load("conn")
    assert len(loaded) == 3
    aa = next(r for r in loaded if r.src_mac == "aa:bb")
    assert aa.wildcard_src_port is True
    others = {r.src_mac for r in loaded if r.src_mac != "aa:bb"}
    assert others == {"bb:cc", "cc:dd"}


@pytest.fixture
def loguru_caplog(
    caplog: pytest.LogCaptureFixture,
) -> Iterator[pytest.LogCaptureFixture]:
    """Bridge loguru records into pytest's caplog for one test."""
    caplog.set_level("WARNING")
    handler_id = logger.add(caplog.handler, format="{message}", level="WARNING")
    yield caplog
    logger.remove(handler_id)


def _make_star_src_mismatch_rule(src_mac: str = "aa:bb") -> PortCollapseRule:
    """Stale rule: UCI carries a ``*`` src port but the wildcard flag is False."""
    return PortCollapseRule(
        src_mac=src_mac,
        dst_mac="cc:dd",
        vlan="100",
        ip_proto="6",
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        protocols="TCP",
        normalized_uci=f"{src_mac}/cc:dd/100/6/1.1.1.1/2.2.2.2/*/443/TCP",
        wildcard_src_port=False,
        wildcard_dst_port=False,
        bucket_seconds=60,
    )


def _make_star_dst_mismatch_rule(src_mac: str = "aa:bb") -> PortCollapseRule:
    """Stale rule: UCI carries a ``*`` dst port but the wildcard flag is False."""
    return PortCollapseRule(
        src_mac=src_mac,
        dst_mac="cc:dd",
        vlan="100",
        ip_proto="6",
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        protocols="TCP",
        normalized_uci=f"{src_mac}/cc:dd/100/6/1.1.1.1/2.2.2.2/50000/*/TCP",
        wildcard_src_port=False,
        wildcard_dst_port=False,
        bucket_seconds=60,
    )


def _make_reverse_mismatch_rule(src_mac: str = "aa:bb") -> PortCollapseRule:
    """Stale rule: concrete src port in UCI but the wildcard flag is True."""
    return PortCollapseRule(
        src_mac=src_mac,
        dst_mac="cc:dd",
        vlan="100",
        ip_proto="6",
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        protocols="TCP",
        normalized_uci=f"{src_mac}/cc:dd/100/6/1.1.1.1/2.2.2.2/50000/443/TCP",
        wildcard_src_port=True,
        wildcard_dst_port=False,
        bucket_seconds=60,
    )


def test_save_corrects_star_src_without_flag(tmp_path: Path) -> None:
    """save() forces wildcard_src_port True when the UCI src port is ``*``."""
    pg = _make_sqlite_connector(tmp_path)
    repo = PortCollapseRulesRepository(pg)

    repo.save("conn", [_make_star_src_mismatch_rule()])

    loaded = repo.load("conn")
    assert len(loaded) == 1
    assert loaded[0].wildcard_src_port is True
    assert loaded[0].wildcard_dst_port is False
    assert loaded[0].normalized_uci == "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/443/TCP"


def test_save_corrects_star_dst_without_flag(tmp_path: Path) -> None:
    """save() forces wildcard_dst_port True when the UCI dst port is ``*``."""
    pg = _make_sqlite_connector(tmp_path)
    repo = PortCollapseRulesRepository(pg)

    repo.save("conn", [_make_star_dst_mismatch_rule()])

    loaded = repo.load("conn")
    assert len(loaded) == 1
    assert loaded[0].wildcard_src_port is False
    assert loaded[0].wildcard_dst_port is True


def test_save_corrects_concrete_port_with_true_flag(tmp_path: Path) -> None:
    """save() forces wildcard_src_port False when the UCI src port is concrete."""
    pg = _make_sqlite_connector(tmp_path)
    repo = PortCollapseRulesRepository(pg)

    repo.save("conn", [_make_reverse_mismatch_rule()])

    loaded = repo.load("conn")
    assert len(loaded) == 1
    assert loaded[0].wildcard_src_port is False
    assert loaded[0].wildcard_dst_port is False


def test_upsert_corrects_star_invariant(tmp_path: Path) -> None:
    """upsert_rules() applies the same star-invariant correction as save()."""
    pg = _make_sqlite_connector(tmp_path)
    repo = PortCollapseRulesRepository(pg)

    repo.upsert_rules("conn", [_make_star_src_mismatch_rule()])

    loaded = repo.load("conn")
    assert len(loaded) == 1
    assert loaded[0].wildcard_src_port is True


def test_save_leaves_consistent_rule_unchanged(tmp_path: Path) -> None:
    """A rule that already satisfies the invariant is stored verbatim."""
    pg = _make_sqlite_connector(tmp_path)
    repo = PortCollapseRulesRepository(pg)

    repo.save("conn", [_make_rule(src_mac="aa:bb", wildcard_src=True)])

    loaded = repo.load("conn")
    assert len(loaded) == 1
    assert loaded[0].wildcard_src_port is True
    assert loaded[0].normalized_uci == "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/*/443/TCP"


def test_save_logs_warning_on_star_invariant_mismatch(
    tmp_path: Path, loguru_caplog: pytest.LogCaptureFixture
) -> None:
    """A star-invariant mismatch is surfaced via a loguru warning."""
    pg = _make_sqlite_connector(tmp_path)
    repo = PortCollapseRulesRepository(pg)

    repo.save("conn", [_make_star_src_mismatch_rule()])

    assert "star-invariant mismatch" in loguru_caplog.text
