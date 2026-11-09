"""Regression tests for the SUITE-033 otalon-clas fixes.

* QUA-12 — a corrupt model artifact used to crash the whole service at boot
  (only ``FileNotFoundError`` was handled), and a fallback to the legacy flat
  files was indistinguishable from a healthy manifest load because the flat
  ``meta.json`` may still carry a stale ``_version``.
* QUA-09 — ground-truth ``target_ip`` entries written in CIDR
  (``192.168.0.0/24``) never matched, because the comparison was string
  equality. 50 entries in the live CISF ground truth are affected — every
  ``arp_scan`` label. Separately, an entry with no IP *and* no MAC selector
  matched every row in its time window.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from otalon_clas.common.artifact_integrity import dump_sealed
from otalon_clas.common.model_store import ModelStore
from otalon_clas.ml.labeling import _ip_selector_matches, load_labels

pytestmark = pytest.mark.unit


class _Model:
    """Trivial picklable stand-in for a trained estimator."""

    def __init__(self, tag: str = "m") -> None:
        self.tag = tag


def _write_flat(base: Path, module: str, metadata: dict[str, Any]) -> None:
    """Write a legacy flat model that an operator has already sealed.

    The artifact carries a CLAS-048 integrity sidecar because these
    tests are about the QUA-12 ``_version`` stamping of the fallback
    path, which is only reachable for an artifact that passes the
    integrity check. Refusal of an *unsealed* flat artifact is pinned
    separately in ``tests/unit/test_artifact_integrity.py``.
    """
    dump_sealed({"model": _Model(), "scaler": _Model("s")}, base / f"{module}_classifier.joblib")
    (base / f"{module}_classifier_meta.json").write_text(json.dumps(metadata))


class TestLegacyFlatIsMarked:
    """QUA-12 — a fallback load must be identifiable as degraded."""

    def test_legacy_load_stamps_the_version(self, tmp_path: Path) -> None:
        _write_flat(tmp_path, "conn", {"label_map": {"0": "benign"}})
        store = ModelStore(str(tmp_path))

        _model, _scaler, metadata = store.load("conn")

        assert metadata["_version"] == "legacy-flat"

    def test_a_stale_version_in_the_flat_file_is_overwritten(self, tmp_path: Path) -> None:
        """The dangerous case: flat meta claiming a real version."""
        _write_flat(
            tmp_path,
            "conn",
            {"label_map": {"0": "benign"}, "_version": "1784431335350_1"},
        )
        store = ModelStore(str(tmp_path))

        _model, _scaler, metadata = store.load("conn")

        assert metadata["_version"] == "legacy-flat"

    def test_the_rest_of_the_metadata_survives(self, tmp_path: Path) -> None:
        _write_flat(tmp_path, "conn", {"label_map": {"0": "benign"}, "algorithm": "random_forest"})
        store = ModelStore(str(tmp_path))

        _model, _scaler, metadata = store.load("conn")

        assert metadata["algorithm"] == "random_forest"
        assert metadata["label_map"] == {"0": "benign"}

    def test_a_missing_model_still_raises_file_not_found(self, tmp_path: Path) -> None:
        store = ModelStore(str(tmp_path))

        with pytest.raises(FileNotFoundError):
            store.load("conn")


class TestCidrGroundTruthMatching:
    """QUA-09 — subnet selectors must match by containment."""

    @pytest.mark.parametrize(
        "candidate", ["192.168.0.1", "192.168.0.41", "192.168.0.201", "192.168.0.255"]
    )
    def test_addresses_inside_the_subnet_match(self, candidate: str) -> None:
        assert _ip_selector_matches("192.168.0.0/24", (candidate, ""))

    @pytest.mark.parametrize("candidate", ["10.0.0.1", "192.168.1.1", "172.16.0.5"])
    def test_addresses_outside_the_subnet_do_not_match(self, candidate: str) -> None:
        assert not _ip_selector_matches("192.168.0.0/24", (candidate, ""))

    def test_a_plain_address_still_compares_exactly(self) -> None:
        assert _ip_selector_matches("192.168.0.10", ("192.168.0.10", ""))
        assert not _ip_selector_matches("192.168.0.10", ("192.168.0.11", ""))

    def test_a_host_prefix_is_accepted(self) -> None:
        assert _ip_selector_matches("192.168.0.10/32", ("192.168.0.10", ""))

    def test_a_non_strict_network_is_accepted(self) -> None:
        """``192.168.0.5/24`` has host bits set; strict=False tolerates it."""
        assert _ip_selector_matches("192.168.0.5/24", ("192.168.0.99", ""))

    def test_a_malformed_selector_matches_nothing(self) -> None:
        assert not _ip_selector_matches("not-an-ip/24", ("192.168.0.1", ""))

    def test_an_empty_selector_matches_nothing(self) -> None:
        assert not _ip_selector_matches("", ("192.168.0.1", ""))

    def test_a_malformed_candidate_is_skipped(self) -> None:
        assert not _ip_selector_matches("192.168.0.0/24", ("garbage", ""))

    def test_ipv6_subnets_work(self) -> None:
        assert _ip_selector_matches("2001:db8::/32", ("2001:db8::1", ""))


def _gt_entry(**overrides: Any) -> dict[str, Any]:
    entry = {
        "module_name": "T0846/arp_scan",
        "technical_method": "arp_scan",
        "start_time": "2026-03-06 21:08:31",
        "end_time": "2026-03-06 21:08:33",
        "target_ip": ["192.168.0.0/24"],
        "target_mac": [],
        "protocol": "arp",
        "source_ip": "192.168.0.201",
        "source_mac": "",
    }
    entry.update(overrides)
    return entry


def _write_gt(tmp_path: Path, entries: list[dict[str, Any]]) -> Path:
    path = tmp_path / "gt.json"
    path.write_text(json.dumps(entries))
    return path


class TestSelectorLessEntriesAreRejected:
    """QUA-09 — an entry with no host selector is a config error."""

    def test_an_entry_without_ip_or_mac_is_skipped(self, tmp_path: Path) -> None:
        path = _write_gt(
            tmp_path,
            [_gt_entry(target_ip=[], source_ip="", target_mac=[], source_mac="")],
        )

        assert load_labels(path) == []

    def test_a_valid_entry_alongside_it_still_loads(self, tmp_path: Path) -> None:
        path = _write_gt(
            tmp_path,
            [
                _gt_entry(target_ip=[], source_ip="", target_mac=[], source_mac=""),
                _gt_entry(module_name="T0802/opcua_enum"),
            ],
        )

        labels = load_labels(path)

        assert [label.module_name for label in labels] == ["T0802/opcua_enum"]

    def test_the_skip_is_logged_as_an_error(self, tmp_path: Path, caplog: Any) -> None:
        from otalon_clas.ml import labeling

        path = _write_gt(
            tmp_path,
            [_gt_entry(target_ip=[], source_ip="", target_mac=[], source_mac="")],
        )

        handler_id = labeling.logger.add(caplog.handler, format="{message}", level="ERROR")
        try:
            load_labels(path)
        finally:
            labeling.logger.remove(handler_id)

        assert any("would match every row" in record.getMessage() for record in caplog.records)

    @pytest.mark.parametrize(
        "overrides",
        [
            {"target_ip": ["192.168.0.1"], "source_ip": "", "target_mac": [], "source_mac": ""},
            {"target_ip": [], "source_ip": "192.168.0.1", "target_mac": [], "source_mac": ""},
            {"target_ip": [], "source_ip": "", "target_mac": ["aa:bb:cc:dd:ee:01"], "source_mac": ""},
            {"target_ip": [], "source_ip": "", "target_mac": [], "source_mac": "aa:bb:cc:dd:ee:01"},
        ],
    )
    def test_any_single_selector_is_enough(self, tmp_path: Path, overrides: Any) -> None:
        path = _write_gt(tmp_path, [_gt_entry(**overrides)])

        assert len(load_labels(path)) == 1


class TestCidrLabellingEndToEnd:
    """The defect as it appears in the live ground truth."""

    def test_a_cidr_entry_labels_a_matching_row(self, tmp_path: Path) -> None:
        import pandas as pd
        import polars as pl

        from otalon_clas.ml.labeling import ConnectionLabeler

        path = _write_gt(tmp_path, [_gt_entry(protocol="")])
        labels = load_labels(path, time_margin_seconds=5)
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06T20:08:32Z")],
                "uci": [
                    "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02//IPv4/"
                    "192.168.0.201/192.168.0.41/1/2/Ethernet:IPv4:ARP"
                ],
            }
        )

        labeled = ConnectionLabeler(labels).apply_labels(df)

        assert labeled["label"].to_list() == ["T0846/arp_scan"]

    def test_a_row_outside_the_subnet_stays_benign(self, tmp_path: Path) -> None:
        import pandas as pd
        import polars as pl

        from otalon_clas.ml.labeling import ConnectionLabeler

        path = _write_gt(tmp_path, [_gt_entry(protocol="", source_ip="")])
        labels = load_labels(path, time_margin_seconds=5)
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06T20:08:32Z")],
                "uci": [
                    "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02//IPv4/"
                    "10.0.0.1/10.0.0.2/1/2/Ethernet:IPv4:ARP"
                ],
            }
        )

        labeled = ConnectionLabeler(labels).apply_labels(df)

        assert labeled["label"].to_list() == ["benign"]
