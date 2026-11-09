"""Deployment-wiring test for the runtime MITRE path allow-list.

Proves the production ``RuntimeSupervisor`` derives a non-empty allowed
parent directory from each module's configured ``mitre_technique_file``.
Combined with ``tests/unit/test_job_runner.py`` (which proves a runtime
``mitre_file`` outside an allow-listed parent is rejected before read or
training), this verifies the end-to-end allow-list contract is active in a
deployment that configures ``mitre_technique_file`` (as the production
``config/config.json`` does for every module).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from otalon_clas.runtime.runtime_supervisor import RuntimeSupervisor


@dataclass
class _Classification:
    mitre_technique_file: str = ""


@dataclass
class _Module:
    classification: _Classification


@dataclass
class _Config:
    modules: list[_Module] = field(default_factory=list)


def _make_supervisor(config: _Config) -> RuntimeSupervisor:
    supervisor = RuntimeSupervisor.__new__(RuntimeSupervisor)
    supervisor._config = config  # type: ignore[attr-defined]
    return supervisor


def test_configured_mitre_file_yields_non_empty_allowed_parent(tmp_path: Path) -> None:
    """A configured mitre_technique_file contributes its parent to the allow-list."""
    label_file = tmp_path / "labels" / "mitre_techniques_log.json"
    label_file.parent.mkdir(parents=True)
    label_file.write_text("{}", encoding="utf-8")

    config = _Config(modules=[_Module(_Classification(str(label_file)))])
    supervisor = _make_supervisor(config)

    allowed = supervisor._allowed_mitre_dirs()

    assert allowed == (str(label_file.resolve().parent),)
    assert allowed  # non-empty -> the worker allow-list guard is active


def test_shared_label_dir_across_modules_deduplicates_to_one_parent(tmp_path: Path) -> None:
    """Modules sharing one label directory collapse to a single allowed parent."""
    label_dir = tmp_path / "shared"
    label_dir.mkdir()
    file_a = label_dir / "a.json"
    file_b = label_dir / "b.json"
    file_a.write_text("{}", encoding="utf-8")
    file_b.write_text("{}", encoding="utf-8")

    config = _Config(
        modules=[
            _Module(_Classification(str(file_a))),
            _Module(_Classification(str(file_b))),
        ]
    )
    supervisor = _make_supervisor(config)

    assert supervisor._allowed_mitre_dirs() == (str(label_dir.resolve()),)


def test_no_configured_mitre_file_leaves_allow_list_empty() -> None:
    """With no configured label file the allow-list is empty (documented caveat)."""
    config = _Config(modules=[_Module(_Classification(""))])
    supervisor = _make_supervisor(config)

    assert supervisor._allowed_mitre_dirs() == ()
