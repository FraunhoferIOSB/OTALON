"""Schema-shape tests for CVE lookup worker status migration."""

from __future__ import annotations

from pathlib import Path


def test_cve_lookup_status_migration_has_expected_revision_chain() -> None:
    """Migration 0014 follows passive-seeder status migration 0013."""
    source = Path(__file__).parents[2] / "alembic/versions/0014_cve_lookup_worker_status.py"
    text = source.read_text(encoding="utf-8")
    assert 'revision: str = "0014"' in text
    assert 'down_revision: Union[str, None] = "0013"' in text
    assert '"cve_lookup_worker_status"' in text
