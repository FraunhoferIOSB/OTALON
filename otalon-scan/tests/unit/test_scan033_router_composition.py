"""SCAN-033 — router composition + state-dependency regression guards.

Pins the structural contract the router split established, so a later
change cannot quietly reintroduce the god module or the module-level
mutable state that made the handlers untestable:

* ``src/otalon_scan/api/server.py`` is a composition root — no route decorators, no
  state globals, and it still exports the ``app`` symbol the container
  entrypoint (``uvicorn otalon_scan.api.server:app``) is pinned to.
* Every module under ``src/otalon_scan/api/routers/`` exports an ``APIRouter``.
* The path-ordering that keeps ``/scans/interfaces`` reachable ahead of
  the catch-all ``/scans/{scan_id}`` survives router inclusion.
* Each raising state guard reproduces the exact status code and detail
  string of the inline guard it replaced. These strings are asserted
  verbatim by the delete-device / delete-scan integration tests, so a
  reword is a client-visible break, not a cosmetic one.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI, HTTPException

from otalon_scan.api import routers as routers_pkg
from otalon_scan.api.dependencies import (
    get_api_state,
    get_optional_manager,
    get_optional_repo,
    get_optional_settings,
    require_manager,
    require_repo,
    require_runtime,
)
from otalon_scan.api.server import app
from otalon_scan.api.state import ApiState

_SERVER_PY = Path(__file__).resolve().parents[2] / "src" / "otalon_scan" / "api" / "server.py"

_ROUTE_DECORATOR_ATTRS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "trace",
    "api_route",
    "websocket",
    "on_event",
}

_STATE_GLOBALS = {
    "_manager",
    "_repo",
    "_settings",
    "_main_loop",
    "_run_to_scan_map",
    "_finished_runs",
    "_lookup_registry",
}


def _server_tree() -> ast.Module:
    """Parse ``src/otalon_scan/api/server.py`` into an AST."""
    return ast.parse(_SERVER_PY.read_text(encoding="utf-8"))


class TestCompositionRoot:
    """``server.py`` composes the app; it does not serve requests."""

    def test_no_inline_route_decorators(self) -> None:
        """No ``@app.<method>`` decorator SHALL remain in the composition root."""
        offenders: list[str] = []
        for node in ast.walk(_server_tree()):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for deco in node.decorator_list:
                call = deco.func if isinstance(deco, ast.Call) else deco
                if (
                    isinstance(call, ast.Attribute)
                    and isinstance(call.value, ast.Name)
                    and call.value.id == "app"
                    and call.attr in _ROUTE_DECORATOR_ATTRS
                ):
                    offenders.append(f"{node.name} (@app.{call.attr})")
        assert offenders == [], f"inline route decorators reintroduced in server.py: {offenders}"

    def test_includes_routers(self) -> None:
        """The composition root SHALL attach its routers via ``include_router``."""
        calls = [
            node
            for node in ast.walk(_server_tree())
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "include_router"
        ]
        assert calls, "server.py registers no routers"

    def test_no_module_level_state_globals(self) -> None:
        """The seven pre-SCAN-033 state globals SHALL NOT reappear."""
        assigned: set[str] = set()
        for node in _server_tree().body:
            if isinstance(node, ast.Assign):
                assigned.update(t.id for t in node.targets if isinstance(t, ast.Name))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                assigned.add(node.target.id)
        offenders = sorted(assigned & _STATE_GLOBALS)
        assert offenders == [], f"module-level state globals reintroduced: {offenders}"

    def test_app_symbol_is_exported(self) -> None:
        """``otalon_scan.api.server:app`` is the pinned container entrypoint."""
        assert isinstance(app, FastAPI)

    def test_state_container_exists_before_lifespan(self) -> None:
        """``app.state.api_state`` SHALL exist without the lifespan running."""
        state = app.state.api_state
        assert isinstance(state, ApiState)
        # The CVE-lookup registry must be eager: ``POST /vulnerabilities/lookup``
        # dispatches a job without waiting on startup.
        assert state.lookup_registry is not None


class TestRouterModules:
    """Every router module exposes exactly one ``APIRouter``."""

    @pytest.mark.parametrize(
        "module_name",
        [m.name for m in pkgutil.iter_modules(routers_pkg.__path__)],
    )
    def test_module_exports_router(self, module_name: str) -> None:
        """Each ``otalon_scan.api.routers.<module>`` SHALL export ``router``."""
        module = importlib.import_module(f"otalon_scan.api.routers.{module_name}")
        assert isinstance(getattr(module, "router", None), APIRouter)


class TestRouteOrdering:
    """Include order preserves Starlette's first-match path precedence."""

    @pytest.mark.parametrize(
        "literal_path",
        [
            "/scans/interfaces",
            "/scans/running",
            "/scans/finished",
            "/scans/modules/{name}/schema",
        ],
    )
    def test_literal_scan_path_precedes_catch_all(self, literal_path: str) -> None:
        """A literal ``/scans/...`` route SHALL be registered before ``/scans/{scan_id}``."""
        paths = [r.path for r in app.routes if hasattr(r, "path")]
        assert paths.index(literal_path) < paths.index("/scans/{scan_id}")

    def test_scan_id_route_carries_both_verbs(self) -> None:
        """``/scans/{scan_id}`` stays ONE route advertising GET and DELETE (UI-014)."""
        matches = [r for r in app.routes if getattr(r, "path", None) == "/scans/{scan_id}"]
        assert len(matches) == 1
        assert {"GET", "DELETE"} <= set(getattr(matches[0], "methods", set()))


class TestStateGuardFidelity:
    """The guards raise byte-identical errors to the inline clauses they replaced."""

    def test_require_manager_message(self) -> None:
        """A missing manager SHALL raise 500 ``Module manager not initialized``."""
        with pytest.raises(HTTPException) as excinfo:
            require_manager(None)
        assert excinfo.value.status_code == 500
        assert excinfo.value.detail == "Module manager not initialized"

    def test_require_repo_message(self) -> None:
        """A missing repository SHALL raise 500 ``Repository not initialized``."""
        with pytest.raises(HTTPException) as excinfo:
            require_repo(None)
        assert excinfo.value.status_code == 500
        assert excinfo.value.detail == "Repository not initialized"

    @pytest.mark.parametrize(
        ("manager", "repo"),
        [(None, None), (object(), None), (None, object())],
    )
    def test_require_runtime_message(self, manager: Any, repo: Any) -> None:
        """Either half missing SHALL raise 500 ``Service not initialized``.

        The pair guard reports one combined error rather than naming the
        missing half — matching the pre-split ``if not _manager or not _repo``.
        """
        with pytest.raises(HTTPException) as excinfo:
            require_runtime(manager, repo)
        assert excinfo.value.status_code == 500
        assert excinfo.value.detail == "Service not initialized"

    def test_require_helpers_pass_through_populated_objects(self) -> None:
        """A populated object SHALL be returned unchanged (identity preserved)."""
        manager, repo = object(), object()
        assert require_manager(manager) is manager  # type: ignore[arg-type]
        assert require_repo(repo) is repo  # type: ignore[arg-type]
        runtime = require_runtime(manager, repo)  # type: ignore[arg-type]
        assert runtime.manager is manager
        assert runtime.repo is repo

    def test_optional_accessors_never_raise(self) -> None:
        """The ``/health`` accessors SHALL return ``None`` on empty state."""
        from testsupport import make_state_request

        request = make_state_request(ApiState())
        assert get_optional_manager(request) is None
        assert get_optional_repo(request) is None
        assert get_optional_settings(request) is None

    def test_get_api_state_returns_the_app_instance(self) -> None:
        """``get_api_state`` SHALL return the very object stored on the app."""
        from testsupport import make_state_request

        state = ApiState()
        assert get_api_state(make_state_request(state)) is state


class TestStateDependenciesAreSchemaInvisible:
    """State injection SHALL NOT leak parameters into the OpenAPI document."""

    def test_no_state_parameter_in_any_operation(self) -> None:
        """No operation SHALL expose ``manager`` / ``repo`` / ``state`` as a parameter."""
        schema = app.openapi()
        leaked: list[str] = []
        for path, item in schema["paths"].items():
            for method, operation in item.items():
                for param in operation.get("parameters", []):
                    if param.get("name") in {
                        "manager",
                        "repo",
                        "state",
                        "settings",
                        "runtime",
                    }:
                        leaked.append(f"{method.upper()} {path}:{param['name']}")
        assert leaked == [], f"state dependencies leaked into the request schema: {leaked}"
