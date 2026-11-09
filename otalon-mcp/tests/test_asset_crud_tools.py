"""Tests for the asset CRUD MCP tools (devices / network_interfaces).

Backed by SQLite with the same column shape as the production
PostgreSQL ``devices`` and ``network_interfaces`` tables. The FK
``network_interfaces.device_id`` is configured with ``ON DELETE SET
NULL`` so the non-cascade ``delete_device`` orphans interfaces — the
same behaviour as the live deployment.

Schema reference: otalon-scan/src/repositories/models.py — `devices`
has NO `source` and NO `hostname` columns; `network_interfaces` has a
`source` column with default `"active"` (we default to `"manual"` for
MCP-originated rows in ``add_interface``).
"""

from __future__ import annotations

import os
from typing import Any, Dict

import pytest
from sqlalchemy import text

from otalon_mcp.mcp_tools import Defaults, init_mcp_tools
from otalon_mcp.repositories.postgres_repo import PostgresRepo

ROOT = os.path.dirname(os.path.dirname(__file__))


class FakeMCP:
    def __init__(self) -> None:
        self.tools: Dict[str, Any] = {}
        self.annotations: Dict[str, Any] = {}

    def tool(self, name: str, annotations: Any = None, **kwargs: Any):
        """Mirror ``FastMCP.tool``: accept and record the annotations kwarg.

        ``init_mcp_tools`` registers an async wrapper (so blocking helper
        calls are offloaded off the event loop) and passes MCP
        ``ToolAnnotations``. The wrapper carries the original synchronous
        handler on ``__wrapped__``; tests keep calling tools
        synchronously, so unwrap it here.
        """

        def decorator(fn):
            self.annotations[name] = annotations
            self.tools[name] = getattr(fn, "__wrapped__", fn)
            return fn

        return decorator


class _FakeInfluxRepo:
    def list_ids(self, *_a, **_k) -> list:
        return []

    def list_ids_between(self, *_a, **_k) -> list:
        return []

    def query_timeseries(self, *_a, **_k):  # pragma: no cover - unused
        raise NotImplementedError

    def query_timeseries_multi_ids_chunked(self, *_a, **_k):  # pragma: no cover
        raise NotImplementedError


@pytest.fixture()
def repo(tmp_path) -> PostgresRepo:
    db = tmp_path / "assets.sqlite"
    repo = PostgresRepo(f"sqlite:///{db}")
    with repo.engine.begin() as conn:
        # SQLite stand-ins for the otalon-scan models.py schema. INET
        # / CIDR columns are stored as TEXT here.
        conn.execute(text("PRAGMA foreign_keys = ON"))
        conn.execute(
            text(
                "CREATE TABLE devices ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " primary_mac TEXT,"
                " vendor TEXT,"
                " device_family TEXT,"
                " device_type TEXT,"
                " description TEXT,"
                " article_number TEXT,"
                " device_role TEXT,"
                " firmware_version TEXT,"
                " update_available BOOLEAN NOT NULL DEFAULT 0,"
                " last_scan_at TIMESTAMP,"
                " notes TEXT,"
                " created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                " updated_at TIMESTAMP"
                ")"
            )
        )
        conn.execute(
            text(
                "CREATE TABLE network_interfaces ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,"
                " mac_address TEXT UNIQUE,"
                " ipv4_address TEXT UNIQUE,"
                " ipv6_address TEXT UNIQUE,"
                " subnet TEXT,"
                " last_scan_at TIMESTAMP,"
                " notes TEXT,"
                " source TEXT NOT NULL DEFAULT 'active',"
                " first_seen_passive_at TIMESTAMP,"
                " last_seen_passive_at TIMESTAMP,"
                " created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                " updated_at TIMESTAMP"
                ")"
            )
        )
    yield repo
    repo.close()


@pytest.fixture()
def tools(repo) -> Dict[str, Any]:
    mcp = FakeMCP()
    init_mcp_tools(
        mcp,
        pg_repo=repo,
        influx_repo=_FakeInfluxRepo(),
        defaults=Defaults(),
        pcap_url="http://fake:9090",
        stix_path=os.path.join(ROOT, "data", "ics-attack.json"),
    )
    return mcp.tools


# ── tool registration ────────────────────────────────────────────────────


def test_all_asset_tools_registered(tools):
    expected = {
        "postgres.list_devices",
        "postgres.get_device",
        "postgres.add_device",
        "postgres.update_device",
        "postgres.delete_device",
        "postgres.list_interfaces",
        "postgres.get_interface",
        "postgres.add_interface",
        "postgres.update_interface",
        "postgres.delete_interface",
    }
    assert expected.issubset(set(tools.keys())), f"missing tools: {expected - set(tools.keys())}"


# ── devices: add / get / list / update / delete ─────────────────────────


def test_add_device_minimal(tools):
    res = tools["postgres.add_device"](vendor="Siemens", device_type="PLC", device_role="controller")
    assert res["ok"] is True
    rec = res["record"]
    assert rec["id"] > 0
    assert rec["vendor"] == "Siemens"
    assert rec["device_type"] == "PLC"
    assert rec["device_role"] == "controller"


def test_add_device_rejects_unknown_columns(tools):
    # The chat-LLM should not be able to inject a `source` or `hostname`
    # column — devices has neither. Going through the wrapper, only the
    # whitelisted columns reach add_device, so unknown ones come from
    # the underlying repo guard via ValueError.
    from otalon_mcp.repositories.postgres_repo import PostgresRepo as _PR

    pr = tools["postgres.add_device"].__globals__["pg_tools"].PG_REPO
    assert isinstance(pr, _PR)
    with pytest.raises(ValueError) as exc:
        pr.add_device({"source": "manual"})
    assert "unknown columns" in str(exc.value).lower()
    assert "source" in str(exc.value)


def test_get_device_round_trip(tools):
    add = tools["postgres.add_device"](vendor="Beckhoff")
    res = tools["postgres.get_device"](device_id=add["record"]["id"])
    assert res["ok"] is True
    assert res["record"]["vendor"] == "Beckhoff"


def test_get_device_not_found(tools):
    res = tools["postgres.get_device"](device_id=999_999)
    assert res["ok"] is False
    assert "not found" in res["error"].lower()


def test_list_devices_pagination(tools):
    for i in range(5):
        tools["postgres.add_device"](vendor=f"v{i}")
    page1 = tools["postgres.list_devices"](limit=2, offset=0)
    page2 = tools["postgres.list_devices"](limit=2, offset=2)
    page3 = tools["postgres.list_devices"](limit=2, offset=4)
    assert page1["count"] == 2
    assert page2["count"] == 2
    assert page3["count"] == 1
    assert page1["records"][0]["vendor"] == "v0"
    assert page2["records"][0]["vendor"] == "v2"


def test_update_device_partial(tools):
    add = tools["postgres.add_device"](vendor="orig", device_type="PLC")
    did = add["record"]["id"]
    res = tools["postgres.update_device"](device_id=did, vendor="updated", notes="touched")
    assert res["ok"] is True
    assert res["record"]["vendor"] == "updated"
    assert res["record"]["device_type"] == "PLC"  # untouched
    assert res["record"]["notes"] == "touched"


def test_update_device_not_found(tools):
    res = tools["postgres.update_device"](device_id=999_999, vendor="x")
    assert res["ok"] is False
    assert "not found" in res["error"].lower()


def test_delete_device_orphans_interfaces_by_default(tools):
    """Non-cascade delete: child interfaces survive with device_id=NULL."""
    add = tools["postgres.add_device"](vendor="parent")
    did = add["record"]["id"]
    if1 = tools["postgres.add_interface"](device_id=did, mac_address="aa:bb:cc:dd:ee:01")
    if2 = tools["postgres.add_interface"](device_id=did, mac_address="aa:bb:cc:dd:ee:02")
    assert if1["ok"] is True and if2["ok"] is True

    res = tools["postgres.delete_device"](device_id=did)
    assert res["ok"] is True
    assert res["cascade_interfaces"] is False
    assert res["orphaned_interfaces"] == 2
    assert res["deleted_interfaces"] == 0

    # Interfaces still exist but their device_id is NULL.
    orphans = tools["postgres.list_interfaces"](device_id=0)
    assert orphans["count"] == 2
    assert all(r["device_id"] is None for r in orphans["records"])


def test_delete_device_cascade_deletes_interfaces(tools):
    add = tools["postgres.add_device"](vendor="parent_cas")
    did = add["record"]["id"]
    tools["postgres.add_interface"](device_id=did, mac_address="aa:bb:cc:dd:ee:11")
    tools["postgres.add_interface"](device_id=did, mac_address="aa:bb:cc:dd:ee:12")

    res = tools["postgres.delete_device"](device_id=did, cascade_interfaces=True)
    assert res["ok"] is True
    assert res["cascade_interfaces"] is True
    assert res["deleted_interfaces"] == 2

    # No orphans remain.
    orphans = tools["postgres.list_interfaces"](device_id=0)
    assert orphans["count"] == 0


def test_delete_device_not_found(tools):
    res = tools["postgres.delete_device"](device_id=999_999)
    assert res["ok"] is False
    assert "not found" in res["error"].lower()


# ── network_interfaces: add / list / get / update / delete ──────────────


def test_add_interface_defaults_source_to_manual(tools):
    res = tools["postgres.add_interface"](mac_address="aa:bb:cc:dd:ee:99")
    assert res["ok"] is True
    assert res["record"]["source"] == "manual", "MCP-originated rows must carry source='manual' for audit traceability"


def test_add_interface_explicit_source_respected(tools):
    res = tools["postgres.add_interface"](mac_address="aa:bb:cc:dd:ef:99", source="active")
    assert res["record"]["source"] == "active"


def test_add_interface_rejects_unknown_columns(tools):
    pr = tools["postgres.add_interface"].__globals__["pg_tools"].PG_REPO
    with pytest.raises(ValueError) as exc:
        pr.add_interface({"hostname": "foo"})  # not a real column
    assert "unknown columns" in str(exc.value).lower()


def test_list_interfaces_filter_by_device(tools):
    d1 = tools["postgres.add_device"](vendor="d1")["record"]["id"]
    d2 = tools["postgres.add_device"](vendor="d2")["record"]["id"]
    tools["postgres.add_interface"](device_id=d1, mac_address="aa:bb:cc:dd:e1:01")
    tools["postgres.add_interface"](device_id=d1, mac_address="aa:bb:cc:dd:e1:02")
    tools["postgres.add_interface"](device_id=d2, mac_address="aa:bb:cc:dd:e2:01")

    only_d1 = tools["postgres.list_interfaces"](device_id=d1)
    only_d2 = tools["postgres.list_interfaces"](device_id=d2)
    assert only_d1["count"] == 2
    assert only_d2["count"] == 1
    assert all(r["device_id"] == d1 for r in only_d1["records"])


def test_get_interface_round_trip(tools):
    add = tools["postgres.add_interface"](ipv4_address="10.0.0.5", mac_address="aa:bb:cc:dd:ff:01")
    res = tools["postgres.get_interface"](interface_id=add["record"]["id"])
    assert res["ok"] is True
    assert res["record"]["ipv4_address"] == "10.0.0.5"


def test_get_interface_not_found(tools):
    res = tools["postgres.get_interface"](interface_id=999_999)
    assert res["ok"] is False


def test_update_interface_partial(tools):
    add = tools["postgres.add_interface"](mac_address="aa:bb:cc:dd:ff:10")
    iid = add["record"]["id"]
    res = tools["postgres.update_interface"](interface_id=iid, ipv4_address="10.0.0.99", notes="linked manually")
    assert res["ok"] is True
    assert res["record"]["ipv4_address"] == "10.0.0.99"
    assert res["record"]["mac_address"] == "aa:bb:cc:dd:ff:10"  # untouched
    assert res["record"]["notes"] == "linked manually"


def test_update_interface_not_found(tools):
    res = tools["postgres.update_interface"](interface_id=999_999, notes="x")
    assert res["ok"] is False


def test_delete_interface_removes_row(tools):
    add = tools["postgres.add_interface"](mac_address="aa:bb:cc:de:ff:01")
    iid = add["record"]["id"]
    res = tools["postgres.delete_interface"](interface_id=iid)
    assert res["ok"] is True
    assert res["deleted_interface_id"] == iid
    # And it really is gone.
    assert tools["postgres.get_interface"](interface_id=iid)["ok"] is False


def test_delete_interface_not_found(tools):
    res = tools["postgres.delete_interface"](interface_id=999_999)
    assert res["ok"] is False


# ── audit logging ────────────────────────────────────────────────────────


def test_mutation_logs_emitted_on_writes(tools, caplog):
    """Each mutating tool emits exactly one `mcp_asset_mutation` event."""
    import logging

    # loguru → propagate to stdlib so caplog captures it.
    from loguru import logger as loguru_logger

    handler_id = loguru_logger.add(
        lambda msg: logging.getLogger("loguru-test").info(msg.rstrip()),
        level="INFO",
    )
    try:
        caplog.set_level(logging.INFO, logger="loguru-test")
        add_d = tools["postgres.add_device"](vendor="audit_v")
        did = add_d["record"]["id"]
        tools["postgres.update_device"](device_id=did, notes="audited")
        add_i = tools["postgres.add_interface"](device_id=did, mac_address="aa:bb:cc:de:ff:50")
        iid = add_i["record"]["id"]
        tools["postgres.update_interface"](interface_id=iid, notes="audited")
        tools["postgres.delete_interface"](interface_id=iid)
        tools["postgres.delete_device"](device_id=did)
    finally:
        loguru_logger.remove(handler_id)

    audit_lines = [rec.message for rec in caplog.records if "mcp_asset_mutation" in rec.message]
    # 6 mutating calls -> 6 audit entries
    assert len(audit_lines) == 6, audit_lines
    # Each call must carry by=mcp-prod for traceability
    assert all("by=mcp-prod" in line for line in audit_lines)
    # Read-only tools (list_devices / get_device / list_interfaces /
    # get_interface) MUST NOT emit asset_mutation events.
    tools["postgres.list_devices"]()
    tools["postgres.list_interfaces"]()
    assert len([rec.message for rec in caplog.records if "mcp_asset_mutation" in rec.message]) == 6
