"""Typed FastAPI dependencies over :class:`~otalon_scan.api.state.ApiState` (SCAN-033).

Handlers used to read module-level globals directly from
:mod:`otalon_scan.api.server`. They now declare what they need and receive it
through these dependencies, which resolve ``request.app.state.api_state``.

Split into two layers, deliberately:

- **Injectors** (``get_api_state``, ``get_optional_*``) are what handlers
  put in their signature. They never raise.
- **Guards** (``require_manager``, ``require_repo``, ``require_runtime``)
  are called in the first line of the handler body and raise the
  ``HTTPException`` the pre-split inline guard raised.

The split exists for **ordering fidelity**, not style. FastAPI resolves a
route's dependencies *before* it validates the request body, so a raising
``Depends(get_repo)`` would answer 500 for a request that used to be
rejected with 422 (``tests/integration/test_delete_devices_api.py::
test_bulk_delete_empty_list_returns_422`` catches exactly this). Keeping
the raise inside the handler body reproduces the original evaluation
order: params and body validate first, the state guard runs second.

Every guard reproduces the **exact** status code and ``detail`` string of
the inline guard clause it replaces — including the falsy test
(``if not x``) the original handlers used rather than an ``is None``
test. Silently promoting one of those 500s to a different status, or
rewording a detail string, is a client-visible regression: the
delete-device/-scan integration tests assert the literal body.

Three distinct guard shapes exist and are kept distinct:

- :func:`require_manager` — ``"Module manager not initialized"``
- :func:`require_repo` — ``"Repository not initialized"``
- :func:`require_runtime` — ``"Service not initialized"``, the *pair*
  guard (``if not _manager or not _repo``) used by the scan start/stop
  handlers. It is deliberately NOT composed from the two guards above,
  because that composition would emit the wrong detail string.

``GET /health`` uses the injectors without any guard: it degrades
gracefully when startup has not completed and answers 503 (not 500) on a
missing repository.

All injectors take only ``Request``, so FastAPI adds no query, header,
cookie or body parameter to the OpenAPI schema of any route using them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException, Request

from ..core.module_manager import ModuleManager
from ..repositories.postgres_repo import ScannerPostgresRepo
from ..settings import Settings
from .state import ApiState

__all__ = [
    "ScanRuntime",
    "get_api_state",
    "get_optional_manager",
    "get_optional_repo",
    "get_optional_settings",
    "require_manager",
    "require_repo",
    "require_runtime",
]


@dataclass(frozen=True)
class ScanRuntime:
    """The manager + repository pair the scan start/stop handlers need.

    Attributes:
        manager: The initialised scanner module manager.
        repo: The initialised PostgreSQL repository.
    """

    manager: ModuleManager
    repo: ScannerPostgresRepo


def get_api_state(request: Request) -> ApiState:
    """Return the shared :class:`ApiState` container of the running app.

    The container is created at application construction time, so this
    never fails for a request served by the otalon-scan app.

    Args:
        request: The incoming request, used to reach ``app.state``.

    Returns:
        The application's :class:`ApiState` instance.
    """
    state: ApiState = request.app.state.api_state
    return state


def get_optional_manager(request: Request) -> Optional[ModuleManager]:
    """Return the module manager, or ``None`` when startup has not run."""
    return get_api_state(request).manager


def get_optional_repo(request: Request) -> Optional[ScannerPostgresRepo]:
    """Return the repository, or ``None`` when startup has not run."""
    return get_api_state(request).repo


def get_optional_settings(request: Request) -> Optional[Settings]:
    """Return the parsed settings, or ``None`` when startup has not run."""
    return get_api_state(request).settings


def require_manager(manager: Optional[ModuleManager]) -> ModuleManager:
    """Narrow an injected module manager to a non-``None`` value.

    Args:
        manager: The injected manager, possibly ``None`` when the lifespan
            startup has not completed.

    Returns:
        The same manager, typed as non-optional.

    Raises:
        HTTPException: 500 ``"Module manager not initialized"``.
    """
    if not manager:
        raise HTTPException(status_code=500, detail="Module manager not initialized")
    return manager


def require_repo(repo: Optional[ScannerPostgresRepo]) -> ScannerPostgresRepo:
    """Narrow an injected repository to a non-``None`` value.

    Args:
        repo: The injected repository, possibly ``None`` when the lifespan
            startup has not completed.

    Returns:
        The same repository, typed as non-optional.

    Raises:
        HTTPException: 500 ``"Repository not initialized"``.
    """
    if not repo:
        raise HTTPException(status_code=500, detail="Repository not initialized")
    return repo


def require_runtime(
    manager: Optional[ModuleManager],
    repo: Optional[ScannerPostgresRepo],
) -> ScanRuntime:
    """Narrow the manager + repository pair, both required.

    Mirrors the ``if not _manager or not _repo`` guard the scan
    start/stop handlers used, which reports a single combined error
    rather than naming whichever half is missing.

    Args:
        manager: The injected manager, possibly ``None``.
        repo: The injected repository, possibly ``None``.

    Returns:
        A :class:`ScanRuntime` carrying both initialised objects.

    Raises:
        HTTPException: 500 ``"Service not initialized"`` when either half
            has not been populated by the lifespan startup.
    """
    if not manager or not repo:
        raise HTTPException(status_code=500, detail="Service not initialized")
    return ScanRuntime(manager=manager, repo=repo)
