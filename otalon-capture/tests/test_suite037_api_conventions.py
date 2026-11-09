"""Convention tests for the capture-side HTTP surfaces (SUITE-037).

Pins the conventions from ``documentation/agents/api-conventions.md``:

* HC32 — every FastAPI app carries ``title``/``version``/``description``.
  ``pcap_recorder`` previously passed none at all.
* HC34 — ``GET /health`` is unversioned and answers ``{"status": "ok"}``.

``pcap_recorder`` deliberately keeps its OpenAPI schema and docs disabled
(hardened under PCAP-006); metadata is still mandatory, and a test pins
that the schema stays unpublished so the two decisions are not conflated.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from pcap_import.api import create_app as create_import_app
from pcap_import.service import ImportService
from pcap_recorder.api import PcapService, create_app as create_recorder_app


class _Index:
    def find_by_timerange(self, *args: Any, **kwargs: Any) -> List[Any]:
        return []

    def list_all(self) -> List[Any]:
        return []

    def mark_anomaly(self, *args: Any, **kwargs: Any) -> List[Any]:
        return []


class _Ringbuffer:
    def archive_chunks(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {}


class _Runner:
    def run(self, job: Any, progress: Any, cancel_event: Any) -> Dict[str, Any]:
        return {}


@pytest.fixture()
def recorder_app() -> Any:
    return create_recorder_app(PcapService(index=_Index(), ringbuffer=_Ringbuffer()))


@pytest.fixture()
def import_app() -> Any:
    return create_import_app(ImportService(runner=_Runner()))


class TestRecorderMetadata:
    def test_title_follows_the_naming_form(self, recorder_app: Any) -> None:
        assert recorder_app.title == "OTALON PCAP Recorder"

    def test_version_is_set(self, recorder_app: Any) -> None:
        assert recorder_app.version

    def test_description_names_its_consumers(self, recorder_app: Any) -> None:
        assert recorder_app.description
        assert "otalon-api" in recorder_app.description

    def test_the_schema_stays_unpublished(self, recorder_app: Any) -> None:
        """Metadata is mandatory; publishing the schema is a separate call."""
        assert recorder_app.openapi_url is None
        assert recorder_app.docs_url is None
        assert recorder_app.redoc_url is None

    def test_openapi_json_is_not_served(self, recorder_app: Any) -> None:
        with TestClient(recorder_app) as client:
            assert client.get("/openapi.json").status_code == 404


class TestImportWorkerMetadata:
    def test_title_follows_the_naming_form(self, import_app: Any) -> None:
        assert import_app.title == "OTALON PCAP Import Worker"

    def test_version_is_set(self, import_app: Any) -> None:
        assert import_app.version

    def test_description_names_its_consumers(self, import_app: Any) -> None:
        assert import_app.description
        assert "otalon-api" in import_app.description


class TestHealthConvention:
    """HC34 — unversioned, unauthenticated, ``{"status": "ok"}``."""

    def test_recorder_health_shape(self, recorder_app: Any) -> None:
        with TestClient(recorder_app) as client:
            response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_recorder_health_needs_no_api_key(self, recorder_app: Any) -> None:
        """The recorder's other routes require an operator key; /health must not."""
        with TestClient(recorder_app) as client:
            assert client.get("/health").status_code == 200

    def test_import_health_is_reachable_without_a_key(self, import_app: Any) -> None:
        """/import and /status require a key (CAP-02); /health is the probe."""
        with TestClient(import_app) as client:
            assert client.get("/health").status_code == 200

    def test_import_health_reports_state(self, import_app: Any) -> None:
        with TestClient(import_app) as client:
            body = client.get("/health").json()

        assert "state" in body
