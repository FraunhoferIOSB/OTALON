"""D-T2 — Snapshot tests for API response shapes and module final reports.

Covers ``.dev/TODO_otalon-scan.md`` D-T2 acceptance criteria. The
goal is to pin the *shape* of structured outputs (top-level keys,
nested dict keys, value types) so an accidental rename / reshape
fails the test even when raw text searches would still hit.

Six snapshots:

1. ``ModulesResponse`` (``GET /modules``) — module-listing envelope.
2. ``RunningScansResponse`` (``GET /scans/running``) — running-scans
   envelope.
3. ``FinishedScansResponse`` (``GET /scans/finished``) — finished-scans
   envelope.
4. ``StartScanResponse`` (``POST /scans/start``) — created-response.
5. ``ScanResult`` for ``arp_scan`` — module final-report shape.
6. ``ScanResult`` for ``port_scan`` — module final-report shape.
7. (bonus) ``ScanResult`` for ``pn_discovery`` — module final-report
   shape. Counted as part of #5/#6 deliverable in the TODO since
   the spec asked for 6 paths and adding a third module report is
   cheap.

The snapshots are serialised via ``syrupy`` (Amber serializer) under
``tests/__snapshots__/``. The reviewer workflow note in
``tests/README.md`` documents the convention: any diff should be
*reviewed*, not blindly accepted via ``--snapshot-update``.

Determinism notes:
- API-envelope snapshots use static input (empty dicts / known names)
  so no time / UUID escapes.
- Module-report snapshots build the ``ScanResult`` model directly
  from fixed inputs, then ``model_dump(mode="json", exclude={"started_at",
  "finished_at"})`` strips timestamp drift.
"""

from __future__ import annotations

from typing import Any, Dict

from otalon_scan.api.schemas.modules import ModulesResponse
from otalon_scan.api.schemas.scans import (
    FinishedScansResponse,
    RunningScansResponse,
    StartScanResponse,
)
from otalon_scan.core.models import DeviceFinding, ScanResult
from otalon_scan.repositories.models import ScanStatus

# ---- 1-4: API envelope shapes ----


def test_snapshot_modules_response(snapshot: Any) -> None:
    """``ModulesResponse`` envelope SHALL match the snapshotted shape."""
    payload = ModulesResponse(
        modules=["arp_scan", "opcua_discover", "pn_discovery", "port_scan", "snmp_scan"]
    ).model_dump()
    assert payload == snapshot


def test_snapshot_running_scans_response_empty(snapshot: Any) -> None:
    """``RunningScansResponse`` envelope (empty) SHALL match snapshot."""
    payload = RunningScansResponse(running={}).model_dump()
    assert payload == snapshot


def test_snapshot_finished_scans_response_one_entry(snapshot: Any) -> None:
    """``FinishedScansResponse`` envelope SHALL match snapshot."""
    payload = FinishedScansResponse(finished={"deadbeef-0000-0000-0000-000000000001": "arp_scan"}).model_dump()
    assert payload == snapshot


def test_snapshot_start_scan_response(snapshot: Any) -> None:
    """``StartScanResponse`` envelope SHALL match snapshot."""
    payload = StartScanResponse(
        run_id="11111111-1111-1111-1111-111111111111",
        scan_id="22222222-2222-2222-2222-222222222222",
        module_name="modules/arp_scan",
        status=ScanStatus.RUNNING.value,
    ).model_dump()
    assert payload == snapshot


# ---- 5-7: Module ScanResult report shapes ----


def _stable_scan_result_dict(result: ScanResult) -> Dict[str, Any]:
    """Strip timestamps so the snapshot is reproducible across runs.

    ``ScanResult.started_at`` / ``finished_at`` carry wall-clock
    timestamps the test cannot freeze without monkey-patching
    ``datetime.utcnow``; excluding them keeps the snapshot stable
    while still locking the rest of the field set + values.
    """
    return result.model_dump(
        mode="json",
        exclude={"started_at", "finished_at"},
    )


def test_snapshot_arp_scan_result(snapshot: Any) -> None:
    """``arp_scan``'s final ``ScanResult`` payload SHALL match snapshot."""
    result = ScanResult(
        module_name="T1018/arp_scan",
        protocol="arp",
        findings=[
            DeviceFinding(ipv4="10.0.0.10", mac="aa:bb:cc:dd:ee:01"),
            DeviceFinding(ipv4="10.0.0.11", mac="aa:bb:cc:dd:ee:02"),
        ],
        raw_results=[
            {"ip": "10.0.0.10", "mac": "aa:bb:cc:dd:ee:01"},
            {"ip": "10.0.0.11", "mac": "aa:bb:cc:dd:ee:02"},
        ],
    )
    assert _stable_scan_result_dict(result) == snapshot


def test_snapshot_port_scan_result(snapshot: Any) -> None:
    """``port_scan``'s final ``ScanResult`` payload SHALL match snapshot."""
    result = ScanResult(
        module_name="T1046/port_scan",
        protocol="ethernet:ipv4:tcp",
        findings=[
            DeviceFinding(
                ipv4="10.0.0.20",
                open_ports_summary={"tcp": [22, 502]},
            ),
        ],
        raw_results=[
            {
                "host": "10.0.0.20",
                "ports": [
                    {"port": 22, "proto": "tcp", "state": "open", "service": "ssh"},
                    {"port": 502, "proto": "tcp", "state": "open", "service": "modbus"},
                ],
            }
        ],
    )
    assert _stable_scan_result_dict(result) == snapshot


def test_snapshot_pn_discovery_result(snapshot: Any) -> None:
    """``pn_discovery``'s final ``ScanResult`` payload SHALL match snapshot."""
    result = ScanResult(
        module_name="T0846/pn_discovery",
        protocol="profinet",
        findings=[
            DeviceFinding(
                ipv4="10.0.0.30",
                mac="00:1b:1b:00:00:01",
                vendor="Siemens",
                device_type="S7-1500",
                device_role="Primary",
                description="Station: PLC-01",
            ),
        ],
        raw_results=[
            {
                "mac_address": "00:1b:1b:00:00:01",
                "ip_address": "10.0.0.30",
                "vendor_value": "Siemens",
                "device_role": "Primary",
                "name_of_station": "PLC-01",
            }
        ],
    )
    assert _stable_scan_result_dict(result) == snapshot
