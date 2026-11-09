"""Regression test for CLAS-02 — port-collapse rules must survive a failed job.

Training-mode preprocessing persists freshly computed port-collapse rules
(``PortCollapseRulesRepository.save`` is a DELETE + INSERT of every rule for
the module) and overwrites the live preprocessor cache. That happens during
the *staging* phase, before any publish decision, yet the publication backups
captured only bounds/frequency/model state.

A job that failed after staging therefore left the live UCI normalization and
per-series ``bucket_seconds`` permanently replaced while ``bounds`` still held
the old series ids — every subsequent row then flagged NoBounds. These tests
drive the real repository against SQLite and assert the previous rules are
restored.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from otalon_common.connection import PortCollapseRule

from otalon_clas.common.postgres_connector import (
    PortCollapseRuleRecord,
    PostgresConnector,
)
from otalon_clas.preprocessing.port_rules_repository import PortCollapseRulesRepository

pytestmark = pytest.mark.unit


def _connector(tmp_path: Path) -> PostgresConnector:
    pg = PostgresConnector(dsn=f"sqlite:///{tmp_path / 'rules.sqlite'}", pool_size=1, max_overflow=0)
    PortCollapseRuleRecord.__table__.create(pg.engine, checkfirst=True)
    return pg


def _rule(dst_ip: str, bucket_seconds: int) -> PortCollapseRule:
    return PortCollapseRule(
        src_mac="aa:bb:cc:dd:ee:01",
        dst_mac="aa:bb:cc:dd:ee:02",
        vlan="",
        ip_proto="IPv4",
        src_ip="192.168.0.10",
        dst_ip=dst_ip,
        protocols="Ethernet:IPv4:TCP",
        normalized_uci=(
            f"aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02//IPv4/192.168.0.10/{dst_ip}/4840/*/Ethernet:IPv4:TCP"
        ),
        wildcard_src_port=False,
        wildcard_dst_port=True,
        bucket_seconds=bucket_seconds,
    )


class TestSnapshotRestoreRoundTrip:
    """The repository must expose a usable snapshot/restore pair."""

    def test_snapshot_returns_persisted_rules(self, tmp_path: Path) -> None:
        repo = PortCollapseRulesRepository(_connector(tmp_path))
        repo.save("conn", [_rule("192.168.0.20", 60)])

        snapshot = repo.snapshot_module("conn")

        assert len(snapshot) == 1
        assert snapshot[0].bucket_seconds == 60

    def test_restore_puts_the_previous_rules_back(self, tmp_path: Path) -> None:
        repo = PortCollapseRulesRepository(_connector(tmp_path))
        repo.save("conn", [_rule("192.168.0.20", 60)])
        snapshot = repo.snapshot_module("conn")

        # Staging overwrites the rules with a different bucket width.
        repo.save("conn", [_rule("192.168.0.99", 300)])
        assert repo.load("conn")[0].bucket_seconds == 300

        repo.restore_module("conn", snapshot)

        restored = repo.load("conn")
        assert len(restored) == 1
        assert restored[0].bucket_seconds == 60
        assert restored[0].dst_ip == "192.168.0.20"

    def test_restoring_an_empty_snapshot_clears_the_module(self, tmp_path: Path) -> None:
        """A module that had no rules must end up with none again."""
        repo = PortCollapseRulesRepository(_connector(tmp_path))
        snapshot = repo.snapshot_module("conn")
        assert snapshot == []

        repo.save("conn", [_rule("192.168.0.99", 300)])
        repo.restore_module("conn", snapshot)

        assert repo.load("conn") == []

    def test_restore_does_not_touch_other_modules(self, tmp_path: Path) -> None:
        repo = PortCollapseRulesRepository(_connector(tmp_path))
        repo.save("conn", [_rule("192.168.0.20", 60)])
        repo.save("mac_traffic", [_rule("192.168.0.30", 120)])
        snapshot = repo.snapshot_module("conn")

        repo.save("conn", [_rule("192.168.0.99", 300)])
        repo.restore_module("conn", snapshot)

        assert len(repo.load("mac_traffic")) == 1
        assert repo.load("mac_traffic")[0].bucket_seconds == 120


class _Preprocessor:
    """Preprocessor stub exposing the attributes the JobRunner reads."""

    def __init__(self, repository: PortCollapseRulesRepository) -> None:
        self._rules_repository = repository
        self.reloaded = False

    def reload_rules_cache(self) -> None:
        self.reloaded = True


class _Bundle:
    def __init__(self, name: str, repository: PortCollapseRulesRepository) -> None:
        from types import SimpleNamespace

        self.config = SimpleNamespace(name=name)
        self.preprocessor = _Preprocessor(repository)


class TestJobRunnerRuleCompensation:
    """The JobRunner must capture before staging and restore on failure."""

    def _runner(self, bundles: list[Any]) -> Any:
        from otalon_clas.runtime.job_runner import JobRunner

        runner = JobRunner.__new__(JobRunner)
        runner._bundles = bundles
        return runner

    def test_capture_records_pre_staging_rules(self, tmp_path: Path) -> None:
        from otalon_clas.runtime.job_runner import _StagedArtifacts

        repo = PortCollapseRulesRepository(_connector(tmp_path))
        repo.save("conn", [_rule("192.168.0.20", 60)])
        bundle = _Bundle("conn", repo)
        runner = self._runner([bundle])
        staged = _StagedArtifacts()

        runner._capture_rule_backup(staged, bundle)

        assert "conn" in staged.rule_backups
        assert staged.rule_backups["conn"][0].bucket_seconds == 60

    def test_capture_is_idempotent_per_module(self, tmp_path: Path) -> None:
        """A second capture must not overwrite the pre-staging snapshot."""
        from otalon_clas.runtime.job_runner import _StagedArtifacts

        repo = PortCollapseRulesRepository(_connector(tmp_path))
        repo.save("conn", [_rule("192.168.0.20", 60)])
        bundle = _Bundle("conn", repo)
        runner = self._runner([bundle])
        staged = _StagedArtifacts()

        runner._capture_rule_backup(staged, bundle)
        repo.save("conn", [_rule("192.168.0.99", 300)])
        runner._capture_rule_backup(staged, bundle)

        assert staged.rule_backups["conn"][0].bucket_seconds == 60

    def test_restore_reverts_a_staging_rewrite(self, tmp_path: Path) -> None:
        from otalon_clas.runtime.job_runner import _StagedArtifacts

        repo = PortCollapseRulesRepository(_connector(tmp_path))
        repo.save("conn", [_rule("192.168.0.20", 60)])
        bundle = _Bundle("conn", repo)
        runner = self._runner([bundle])
        staged = _StagedArtifacts()

        runner._capture_rule_backup(staged, bundle)
        # Simulate what preprocess_for_training used to do mid-staging.
        repo.save("conn", [_rule("192.168.0.99", 300)])

        runner._restore_rule_backups(staged)

        restored = repo.load("conn")
        assert restored[0].bucket_seconds == 60
        assert restored[0].dst_ip == "192.168.0.20"

    def test_restore_invalidates_the_live_rule_cache(self, tmp_path: Path) -> None:
        """The live preprocessor must not keep serving the rolled-back rules."""
        from otalon_clas.runtime.job_runner import _StagedArtifacts

        repo = PortCollapseRulesRepository(_connector(tmp_path))
        repo.save("conn", [_rule("192.168.0.20", 60)])
        bundle = _Bundle("conn", repo)
        runner = self._runner([bundle])
        staged = _StagedArtifacts()

        runner._capture_rule_backup(staged, bundle)
        runner._restore_rule_backups(staged)

        assert bundle.preprocessor.reloaded is True
