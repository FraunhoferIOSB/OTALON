from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Iterator

import pytest

from testsupport import POSTGRES_AVAILABLE, requires_postgres  # noqa: F401,E402

__all__ = ["POSTGRES_AVAILABLE", "requires_postgres"]


# Ensure the project root is importable in tests so absolute imports of the
# form ``from otalon_scan.core.protocols import ScanModule`` resolve. Modules under
# ``src/otalon_scan/modules`` use proper relative imports and absolute ``src.*`` imports;
# no separate src/ entry on sys.path is needed.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


@pytest.fixture(autouse=True, scope="session")
def _set_env_for_tests() -> Iterator[None]:
    """
    Set sane defaults for env placeholders used by config/config.json and server startup.

    - Use loopback-friendly paths and network defaults for safer tests
    - Module discovery uses the static path configured in config/config.json (src/otalon_scan/modules)
    - Provide a DSN to satisfy config placeholder; tests will mock DB access where needed
    - Provide a default ``OTALON_SCAN_ALLOWED_KEYS`` allow-list so the FastAPI
      lifespan can start under test (Phase 5 / scan--api-auth). The
      dedicated auth integration tests in
      ``tests/integration/test_api_auth.py`` override the allow-list
      directly via ``otalon_scan.core.auth.set_allowed_keys``; the value seeded
      here just keeps the existing ``test_api_server.py`` lifespan happy.
    """
    os.environ.setdefault("POSTGRES_DSN", "postgresql://postgres:test123@localhost:5432/otalon-clas")
    os.environ.setdefault("OTALON_SCAN_LOG_FILE", str(_PROJECT_ROOT / "logs" / "test_otalon_scan.log"))

    _allowed_keys_env = "OTALON_SCAN_ALLOWED_KEYS"
    _previous_allowed_keys = os.environ.get(_allowed_keys_env)
    os.environ[_allowed_keys_env] = "test-viewer:viewer:viewer-test-key,test-operator:operator:operator-test-key"

    (_PROJECT_ROOT / "logs").mkdir(parents=True, exist_ok=True)

    yield

    if _previous_allowed_keys is None:
        os.environ.pop(_allowed_keys_env, None)
    else:
        os.environ[_allowed_keys_env] = _previous_allowed_keys
