"""Regression tests for SCAN-035: operationId collision on ``/scans/{scan_id}``.

FastAPI builds ``operationId`` from the *route*, not the route/method
pair, so the merged two-verb route introduced by UI-014 emitted the same
id for GET and DELETE (``UserWarning: Duplicate Operation ID ...``) and
picked its suffix from ``list(route.methods)[0]`` -- an unordered ``set``,
hence hash-seed dependent.

These tests pin all three halves of the fix:

* no duplicate ``operationId`` anywhere in the document,
* the document is byte-stable across repeated generation,
* the public routing surface (one route, both verbs) is untouched, so
  the UI-014 ``Allow``-header behaviour cannot regress as a side effect.
"""

from __future__ import annotations

import json
import subprocess  # noqa: S404
import sys
import warnings
from collections import Counter
from pathlib import Path
from typing import Dict, List

import pytest
from fastapi.routing import APIRoute

from otalon_scan.api.openapi import build_openapi, expand_multi_method_routes
from otalon_scan.api.server import app

_SRC = Path(__file__).resolve().parents[2] / "src"


def _operation_ids(schema: Dict[str, object]) -> List[str]:
    """Collect every ``operationId`` in the document, duplicates included."""
    ids: List[str] = []
    paths = schema["paths"]
    assert isinstance(paths, dict)
    for item in paths.values():
        for operation in item.values():
            ids.append(operation["operationId"])
    return ids


class TestNoOperationIdCollision:
    def test_all_operation_ids_are_unique(self) -> None:
        """OpenAPI 3.1 requires ``operationId`` to be unique among operations."""
        counts = Counter(_operation_ids(app.openapi()))
        duplicates = {oid: n for oid, n in counts.items() if n > 1}

        assert duplicates == {}, f"duplicate operationIds: {duplicates}"

    def test_generation_emits_no_duplicate_warning(self) -> None:
        """Schema generation SHALL NOT warn about a duplicate operation id."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            build_openapi(app)

        offenders = [str(w.message) for w in caught if "Duplicate Operation ID" in str(w.message)]
        assert offenders == [], f"FastAPI still reports collisions: {offenders}"

    def test_scan_id_verbs_get_distinct_ids(self) -> None:
        """GET and DELETE on ``/scans/{scan_id}`` SHALL carry different ids."""
        item = app.openapi()["paths"]["/scans/{scan_id}"]

        assert item["get"]["operationId"] == "get_or_delete_scan_by_id_get"
        assert item["delete"]["operationId"] == "get_or_delete_scan_by_id_delete"


class TestDeterministicGeneration:
    def test_repeated_generation_is_byte_identical(self) -> None:
        """Two generations of the same app SHALL serialise identically."""
        first = json.dumps(build_openapi(app))
        second = json.dumps(build_openapi(app))

        assert first == second

    @pytest.mark.parametrize("hash_seed", ["0", "1", "4", "7"])
    def test_schema_is_stable_across_hash_seeds(self, hash_seed: str) -> None:
        """``operationId`` SHALL NOT depend on ``PYTHONHASHSEED``.

        The pre-fix suffix came from ``list(route.methods)[0]``, so the
        document changed between interpreter runs. Each seed runs in a
        fresh subprocess because ``PYTHONHASHSEED`` is fixed at startup.
        """
        script = (
            "import json, warnings;"
            "warnings.simplefilter('ignore');"
            "from otalon_scan.api.server import app;"
            "print(json.dumps(app.openapi()))"
        )
        baseline = json.dumps(build_openapi(app))

        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
            env={"PYTHONHASHSEED": hash_seed, "PYTHONPATH": str(_SRC), "PATH": "/usr/bin:/bin"},
        )

        assert result.stdout.strip() == baseline


class TestPublicSurfaceUnchanged:
    """The fix is schema-only; dispatch must be exactly as before."""

    def test_scan_id_remains_one_route_with_both_verbs(self) -> None:
        """UI-014: splitting the route would reintroduce the DELETE 405."""
        matches = [r for r in app.routes if isinstance(r, APIRoute) and r.path == "/scans/{scan_id}"]

        assert len(matches) == 1
        assert {"GET", "DELETE"} <= set(matches[0].methods)

    def test_expansion_does_not_mutate_the_routing_table(self) -> None:
        """Expansion SHALL copy routes, never edit the originals in place."""
        route = next(r for r in app.routes if isinstance(r, APIRoute) and r.path == "/scans/{scan_id}")
        before = set(route.methods)

        expand_multi_method_routes(app.routes)

        assert set(route.methods) == before
        assert route.operation_id is None

    def test_every_schema_route_carries_exactly_one_method(self) -> None:
        """After expansion no APIRoute may hold more than one verb."""
        offenders = [
            (r.path, sorted(r.methods))
            for r in expand_multi_method_routes(app.routes)
            if isinstance(r, APIRoute) and len(r.methods) != 1
        ]

        assert offenders == []

    def test_documented_paths_and_methods_are_preserved(self) -> None:
        """The set of documented path/method pairs SHALL be unchanged."""
        documented = {(path, method.upper()) for path, item in app.openapi()["paths"].items() for method in item}
        registered = {
            (r.path_format, m)
            for r in app.routes
            if isinstance(r, APIRoute) and r.include_in_schema
            for m in r.methods
            if m != "HEAD"
        }

        assert documented == registered
