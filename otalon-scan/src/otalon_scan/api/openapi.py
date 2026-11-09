"""Deterministic OpenAPI generation for otalon-scan (SCAN-035).

FastAPI derives an operation's ``operationId`` from the *route*, not from
the route/method pair: :func:`fastapi.utils.generate_unique_id` builds
``f"{route.name}{route.path_format}_{list(route.methods)[0].lower()}"``.
Both properties break on a multi-method route such as the merged
``GET|DELETE /scans/{scan_id}`` (UI-014):

1. **Collision** — every method of the route reuses the one route-level
   id, so the GET and DELETE operations are emitted with an identical
   ``operationId``. FastAPI raises
   ``UserWarning: Duplicate Operation ID ...``, and the resulting
   document is invalid: OpenAPI 3.1 §4.8.10 requires ``operationId`` to
   be unique among all operations.
2. **Non-determinism** — ``list(route.methods)[0]`` indexes an unordered
   ``set``, so the trailing ``_get`` / ``_delete`` depends on the process
   hash seed. Two runs of the same source produced two different
   documents.

Splitting the route into two single-method routes would fix the ids but
regress UI-014: Starlette answers ``OPTIONS`` from the *first*
path-matching route only, so ``Allow`` would drop back to ``GET`` and
``DELETE`` would be shadowed behind a 405.

The generator below keeps the routing table untouched (one route, both
verbs) and expands multi-method routes into one schema-only shallow copy
per method, each carrying an explicit unique ``operation_id``. Methods
are sorted so the emitted operation order is stable regardless of set
iteration order.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Sequence

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
from starlette.routing import BaseRoute

__all__ = ["expand_multi_method_routes", "build_openapi", "install_openapi"]


def _explode(route: APIRoute) -> List[BaseRoute]:
    """Return one schema-only copy of ``route`` per HTTP method.

    Each copy advertises a single method and an explicit
    ``operation_id`` of the form ``<handler name>_<method>``, which is
    unique across the application because handler names are unique per
    path. The copies are shallow: they share the original's dependant,
    response fields and callbacks, and are used exclusively for schema
    generation -- never for request dispatch.

    Args:
        route: The multi-method route to expand.

    Returns:
        One :class:`~fastapi.routing.APIRoute` copy per method, ordered
        by method name so the output is independent of ``set`` ordering.
    """
    exploded: List[BaseRoute] = []
    for method in sorted(route.methods or ()):
        clone = copy.copy(route)
        clone.methods = {method}
        clone.operation_id = route.operation_id or f"{route.name}_{method.lower()}"
        exploded.append(clone)
    return exploded


def expand_multi_method_routes(routes: Sequence[BaseRoute]) -> List[BaseRoute]:
    """Split every multi-method :class:`APIRoute` into per-method copies.

    Single-method routes and non-API routes (mounts, static files, the
    Prometheus ``/metrics`` endpoint) are passed through unchanged and
    keep their FastAPI-generated ``operationId``, so this function only
    affects routes that would otherwise collide.

    Args:
        routes: The application's route table, in registration order.

    Returns:
        A new list in which no :class:`APIRoute` carries more than one
        method. Registration order is preserved.
    """
    expanded: List[BaseRoute] = []
    for route in routes:
        if isinstance(route, APIRoute) and len(route.methods or ()) > 1:
            expanded.extend(_explode(route))
        else:
            expanded.append(route)
    return expanded


def build_openapi(app: FastAPI) -> Dict[str, Any]:
    """Generate the OpenAPI document for ``app`` without id collisions.

    Mirrors :meth:`fastapi.FastAPI.openapi`, but feeds
    :func:`expand_multi_method_routes` to the generator so each HTTP
    method gets its own operation and therefore its own unique,
    hash-seed-independent ``operationId``.

    Args:
        app: The application whose schema should be generated.

    Returns:
        The OpenAPI document as a plain ``dict``.
    """
    return get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        summary=app.summary,
        description=app.description,
        terms_of_service=app.terms_of_service,
        contact=app.contact,
        license_info=app.license_info,
        routes=expand_multi_method_routes(app.routes),
        webhooks=app.webhooks.routes,
        tags=app.openapi_tags,
        servers=app.servers,
        separate_input_output_schemas=app.separate_input_output_schemas,
    )


def install_openapi(app: FastAPI) -> None:
    """Point ``app.openapi`` at :func:`build_openapi`, preserving caching.

    FastAPI memoizes the document on ``app.openapi_schema`` and serves
    ``/openapi.json``, ``/docs`` and ``/redoc`` from it; the override
    keeps that contract so the deterministic document is what every
    consumer sees.

    Args:
        app: The application to patch in place.
    """

    def _openapi() -> Dict[str, Any]:
        if not app.openapi_schema:
            app.openapi_schema = build_openapi(app)
        return app.openapi_schema

    app.openapi = _openapi  # type: ignore[method-assign]
