"""Import-purity tests pinning the no-database-dependency contract.

otalon-common is documented as a shared library without database or web
dependencies. The shared runtime-configuration registry must therefore never
pull a database driver or ORM into the module graph, directly or transitively.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_FORBIDDEN_MODULES: tuple[str, ...] = ("sqlalchemy", "psycopg2", "asyncpg")

_SRC_DIR = Path(__file__).resolve().parents[1] / "src"

_PROBE = """
import sys

import otalon_common.runtime  # noqa: F401

forbidden = [name for name in sys.modules if name.split(".")[0] in {modules!r}]
print(",".join(sorted(forbidden)))
"""


def _run_clean_import_probe(source: str) -> str:
    """Import in a fresh interpreter and return the probe's stdout."""
    completed = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        check=False,
        env={"PYTHONPATH": str(_SRC_DIR), "PATH": "/usr/bin:/bin"},
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


@pytest.mark.unit
def test_runtime_import_pulls_in_no_database_library() -> None:
    """Importing the runtime package loads no SQLAlchemy/psycopg2/asyncpg."""
    loaded = _run_clean_import_probe(_PROBE.format(modules=set(_FORBIDDEN_MODULES)))
    assert loaded == ""


@pytest.mark.unit
def test_runtime_submodules_import_no_database_library() -> None:
    """The registry and manifest submodules are equally database-free."""
    probe = _PROBE.replace(
        "import otalon_common.runtime  # noqa: F401",
        "import otalon_common.runtime.manifest  # noqa: F401\n"
        "import otalon_common.runtime.registry  # noqa: F401",
    )
    loaded = _run_clean_import_probe(probe.format(modules=set(_FORBIDDEN_MODULES)))
    assert loaded == ""


@pytest.mark.unit
def test_runtime_source_contains_no_database_import() -> None:
    """No runtime source file names a database library in an import."""
    runtime_dir = _SRC_DIR / "otalon_common" / "runtime"
    for path in sorted(runtime_dir.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for module in _FORBIDDEN_MODULES:
            assert f"import {module}" not in text, f"{path.name} imports {module}"
