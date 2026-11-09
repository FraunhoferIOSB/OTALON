"""Unit tests for the PUT /api/v1/topology/devices/{id}/type endpoint.

Covers successful type updates, 404 for unknown devices, 422 for invalid
device types, and 401 for missing or wrong API keys.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import get_override_store, get_postgres_repo, get_settings, get_topology_service
from otalon_api.domain.topology.classification import VALID_DEVICE_TYPES
from otalon_api.main import app
from otalon_api.services.device_type_override_store import DeviceTypeOverrideStore
from otalon_api.services.topology_service import TopologyService
from otalon_api.settings import Settings

ENDPOINT = "/api/v1/topology/devices/{device_id}/type"
TEST_API_KEY = "test-secret-key"


def _make_settings(api_key: str = TEST_API_KEY) -> Settings:
    """Create test settings with the given admin API key.

    Args:
        api_key: Value for ``admin_api_key``.

    Returns:
        A Settings instance suitable for testing.
    """
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influx_token="test-token",
        influxdb_org="test-org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="test",
        postgres_password="test",
        postgres_database="test",
        admin_api_key=api_key,
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


def _make_device_row(device_id: int = 1, device_type: str = "PLC Controller") -> dict[str, Any]:
    """Build a mock device row matching the ``devices`` table schema.

    Args:
        device_id: Device primary key.
        device_type: Raw device type string.

    Returns:
        Dictionary with device column values.
    """
    return {
        "id": device_id,
        "vendor": "Siemens",
        "device_family": "S7",
        "device_type": device_type,
        "description": "Test PLC",
        "article_number": "6ES7",
        "device_role": "controller",
        "firmware_version": "1.0",
        "vulnerabilities": None,
        "update_available": False,
        "last_scan_at": "2025-01-01T00:00:00",
        "notes": None,
        "created_at": "2025-01-01T00:00:00",
        "updated_at": "2025-01-01T00:00:00",
        "name": "PLC-01",
        "alias": "",
        "device_type_name": device_type,
        "mac": "aa:bb:cc:dd:ee:ff",
        "ip4_addresses": ["192.168.1.10"],
    }


def _build_test_client(
    mock_pg: MagicMock,
    override_store: DeviceTypeOverrideStore,
    settings: Settings | None = None,
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> TestClient:
    """Wire up dependency overrides and return a test client.

    Args:
        mock_pg: Mocked PostgresRepository.
        override_store: Override store instance (typically with tmp_path).
        settings: Optional test settings; defaults to key-protected settings.
        monkeypatch: When provided, also arms the auth middleware (which reads
            settings via a direct function call, not FastAPI's ``Depends``,
            so ``app.dependency_overrides`` alone cannot reach it) with the
            same settings object used for the route-level override.

    Returns:
        A configured ``TestClient``.
    """
    settings = settings or _make_settings()
    mock_influx = MagicMock()
    mock_influx.list_ids_between = MagicMock(return_value=[])

    service = TopologyService(mock_pg, mock_influx, settings, override_store)

    app.dependency_overrides[get_topology_service] = lambda: service
    app.dependency_overrides[get_postgres_repo] = lambda: mock_pg
    app.dependency_overrides[get_override_store] = lambda: override_store
    app.dependency_overrides[get_settings] = lambda: settings
    if monkeypatch is not None:
        monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: settings)

    client = TestClient(app, raise_server_exceptions=False)
    return client


@pytest.fixture(autouse=True)
def _cleanup_overrides() -> Any:
    """Remove dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


class TestUpdateDeviceTypeSuccess:
    """Tests for successful device type override updates."""

    @pytest.mark.unit
    def test_put_device_type_returns_200(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """PUT with valid device_type and API key returns 200."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            ENDPOINT.format(device_id=1),
            json={"device_type": "HMI"},
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["device_id"] == 1
        assert data["device_type"] == "HMI"
        assert data["message"] == "Device type override applied"

    @pytest.mark.unit
    def test_put_device_type_persists_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Override is persisted to the JSON file after PUT."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        client.put(
            ENDPOINT.format(device_id=1),
            json={"device_type": "Field I/O"},
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert store.get("1") == "Field I/O"

    @pytest.mark.unit
    def test_put_device_type_returns_previous(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Response includes the previous effective type."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        store.set("1", "PLC")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            ENDPOINT.format(device_id=1),
            json={"device_type": "Workstation"},
            headers={"X-API-Key": TEST_API_KEY},
        )

        data = response.json()
        assert data["previous_type"] == "PLC"
        assert data["device_type"] == "Workstation"

    @pytest.mark.unit
    @pytest.mark.parametrize("device_type", sorted(VALID_DEVICE_TYPES))
    def test_all_valid_device_types_accepted(
        self, tmp_path: Path, device_type: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """All values from VALID_DEVICE_TYPES are accepted."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            ENDPOINT.format(device_id=1),
            json={"device_type": device_type},
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 200
        assert response.json()["device_type"] == device_type


class TestUpdateDeviceTypeNotFound:
    """Tests for 404 responses when device does not exist."""

    @pytest.mark.unit
    def test_unknown_device_returns_404(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """PUT for a non-existent device ID returns 404."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=None)

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            ENDPOINT.format(device_id=9999),
            json={"device_type": "PLC"},
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 404
        assert "9999" in response.json()["detail"]


class TestUpdateDeviceTypeValidation:
    """Tests for 422 responses on invalid input."""

    @pytest.mark.unit
    def test_invalid_device_type_returns_422(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """PUT with an unrecognized device_type returns 422."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            ENDPOINT.format(device_id=1),
            json={"device_type": "InvalidType"},
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 422
        assert "InvalidType" in response.json()["detail"]

    @pytest.mark.unit
    def test_empty_device_type_returns_422(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """PUT with an empty device_type string returns 422."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            ENDPOINT.format(device_id=1),
            json={"device_type": ""},
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 422

    @pytest.mark.unit
    def test_missing_body_returns_422(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """PUT without a request body returns 422."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            ENDPOINT.format(device_id=1),
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 422


class TestUpdateDeviceTypeAuth:
    """Tests for API key authentication on the PUT endpoint."""

    @pytest.mark.unit
    def test_no_api_key_returns_401(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """PUT without X-API-Key header returns 401."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            ENDPOINT.format(device_id=1),
            json={"device_type": "PLC"},
        )

        assert response.status_code == 401

    @pytest.mark.unit
    def test_wrong_api_key_returns_401(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """PUT with incorrect X-API-Key returns 401."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            ENDPOINT.format(device_id=1),
            json={"device_type": "PLC"},
            headers={"X-API-Key": "wrong-key"},
        )

        assert response.status_code == 401

    @pytest.mark.unit
    def test_auth_disabled_when_key_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """API-029: an unconfigured registry now fails closed (503), not open.

        Pre-API-029 behavior treated an empty ``admin_api_key`` as "auth
        disabled". The deny-by-default hardening (see
        ``src/otalon_api/middleware/auth.py``) intentionally reverses this: an
        unconfigured key registry must reject every request with 503
        (service unavailable), matching the convention used everywhere
        else in the suite (operations, capture-status, dashboard-layout).
        """
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))
        settings = _make_settings(api_key="")

        client = _build_test_client(mock_pg, store, settings=settings, monkeypatch=monkeypatch)
        response = client.put(
            ENDPOINT.format(device_id=1),
            json={"device_type": "PLC"},
        )

        assert response.status_code == 503


class TestDeviceTypeOverrideStore:
    """Unit tests for the DeviceTypeOverrideStore itself."""

    @pytest.mark.unit
    def test_set_and_get(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """set() stores a value retrievable by get()."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        store.set("1", "PLC")
        assert store.get("1") == "PLC"

    @pytest.mark.unit
    def test_get_nonexistent_returns_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """get() for a missing key returns None."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        assert store.get("999") is None

    @pytest.mark.unit
    def test_set_returns_previous(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """set() returns the previously stored value."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        store.set("1", "PLC")
        previous = store.set("1", "HMI")
        assert previous == "PLC"

    @pytest.mark.unit
    def test_set_invalid_type_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """set() with an invalid device type raises ValueError."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        with pytest.raises(ValueError, match="Invalid device_type"):
            store.set("1", "InvalidType")

    @pytest.mark.unit
    def test_delete_removes_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """delete() removes the override and returns the old value."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        store.set("1", "PLC")
        removed = store.delete("1")
        assert removed == "PLC"
        assert store.get("1") is None

    @pytest.mark.unit
    def test_persistence_survives_reload(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Overrides persisted to disk survive a store reload."""
        path = tmp_path / "overrides.json"
        store1 = DeviceTypeOverrideStore(path=path)
        store1.set("42", "Field I/O")

        store2 = DeviceTypeOverrideStore(path=path)
        assert store2.get("42") == "Field I/O"

    @pytest.mark.unit
    def test_resolve_with_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """resolve() returns the override when one exists."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        store.set("1", "HMI")
        assert store.resolve("1", "PLC") == "HMI"

    @pytest.mark.unit
    def test_resolve_without_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """resolve() falls back to auto_type when no override exists."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        assert store.resolve("1", "PLC") == "PLC"

    @pytest.mark.unit
    def test_get_all_returns_copy(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_all() returns all overrides as a dict."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        store.set("1", "PLC")
        store.set("2", "Field I/O")
        all_overrides = store.get_all()
        assert all_overrides == {"1": "PLC", "2": "Field I/O"}

    @pytest.mark.unit
    def test_set_many_applies_all(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """set_many() applies every entry and persists once."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        previous = store.set_many({"1": "PLC", "2": "Field I/O", "3": "HMI"})
        assert previous == {"1": None, "2": None, "3": None}
        assert store.get("1") == "PLC"
        assert store.get("2") == "Field I/O"
        assert store.get("3") == "HMI"

    @pytest.mark.unit
    def test_set_many_returns_previous(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """set_many() returns prior values for entries that existed."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        store.set("1", "PLC")
        previous = store.set_many({"1": "Field I/O", "2": "HMI"})
        assert previous == {"1": "PLC", "2": None}

    @pytest.mark.unit
    def test_set_many_validates_all_before_write(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """set_many() with any invalid type writes nothing (atomic)."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        store.set("1", "PLC")
        with pytest.raises(ValueError, match="Invalid device_type"):
            store.set_many({"1": "Field I/O", "2": "InvalidType"})
        # Pre-existing override unchanged; new ID not added.
        assert store.get("1") == "PLC"
        assert store.get("2") is None


BULK_ENDPOINT = "/api/v1/topology/devices/types"


class TestBulkUpdateDeviceTypesSuccess:
    """B-11 happy-path tests for PUT /api/v1/topology/devices/types."""

    @pytest.mark.unit
    def test_bulk_applies_all_overrides(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """N valid overrides are all applied; response carries each result."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(side_effect=lambda did: _make_device_row(did))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            BULK_ENDPOINT,
            json={
                "items": [
                    {"device_id": 1, "device_type": "PLC"},
                    {"device_id": 2, "device_type": "Field I/O"},
                    {"device_id": 3, "device_type": "HMI"},
                ]
            },
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 3
        applied = data["applied"]
        assert len(applied) == 3
        assert [a["device_id"] for a in applied] == [1, 2, 3]
        assert [a["device_type"] for a in applied] == ["PLC", "Field I/O", "HMI"]
        assert store.get("1") == "PLC"
        assert store.get("2") == "Field I/O"
        assert store.get("3") == "HMI"

    @pytest.mark.unit
    def test_bulk_single_item_works(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A bulk request with a single item is also accepted."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            BULK_ENDPOINT,
            json={"items": [{"device_id": 1, "device_type": "Workstation"}]},
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 200
        assert response.json()["count"] == 1
        assert store.get("1") == "Workstation"

    @pytest.mark.unit
    def test_bulk_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Applying the same bulk request twice yields the same state."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(side_effect=lambda did: _make_device_row(did))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        body = {
            "items": [
                {"device_id": 1, "device_type": "PLC"},
                {"device_id": 2, "device_type": "Field I/O"},
            ]
        }
        first = client.put(BULK_ENDPOINT, json=body, headers={"X-API-Key": TEST_API_KEY})
        second = client.put(BULK_ENDPOINT, json=body, headers={"X-API-Key": TEST_API_KEY})

        assert first.status_code == 200
        assert second.status_code == 200
        assert store.get("1") == "PLC"
        assert store.get("2") == "Field I/O"


class TestBulkUpdateDeviceTypesAtomicity:
    """B-11 partial-invalid tests: one bad id -> whole request rejected."""

    @pytest.mark.unit
    def test_one_unknown_id_rejects_whole_request(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """If any device_id is unknown, no overrides are applied."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(side_effect=lambda did: _make_device_row(did) if did != 9999 else None)

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            BULK_ENDPOINT,
            json={
                "items": [
                    {"device_id": 1, "device_type": "PLC"},
                    {"device_id": 9999, "device_type": "Field I/O"},
                    {"device_id": 2, "device_type": "HMI"},
                ]
            },
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 404
        assert "9999" in response.json()["detail"]
        # Nothing applied even for the valid entries before the failing one.
        assert store.get("1") is None
        assert store.get("2") is None

    @pytest.mark.unit
    def test_one_invalid_type_rejects_whole_request(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """If any device_type is invalid, no overrides are applied."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(side_effect=lambda did: _make_device_row(did))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            BULK_ENDPOINT,
            json={
                "items": [
                    {"device_id": 1, "device_type": "PLC"},
                    {"device_id": 2, "device_type": "GarbageType"},
                ]
            },
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 422
        assert "GarbageType" in response.json()["detail"]
        assert store.get("1") is None
        assert store.get("2") is None

    @pytest.mark.unit
    def test_duplicate_device_ids_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Duplicate device_ids in a single request are rejected (422)."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            BULK_ENDPOINT,
            json={
                "items": [
                    {"device_id": 1, "device_type": "PLC"},
                    {"device_id": 1, "device_type": "Field I/O"},
                ]
            },
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 422
        assert "1" in response.json()["detail"]
        assert store.get("1") is None


class TestBulkUpdateDeviceTypesValidation:
    """B-11 input-validation tests."""

    @pytest.mark.unit
    def test_empty_items_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty items list is rejected at the schema level (422).

        B-11 contract: empty list -> 4xx (decided: schema-level 422).
        """
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            BULK_ENDPOINT,
            json={"items": []},
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 422

    @pytest.mark.unit
    def test_missing_items_key_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A request body without the ``items`` key is rejected (422)."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            BULK_ENDPOINT,
            json={},
            headers={"X-API-Key": TEST_API_KEY},
        )

        assert response.status_code == 422


class TestBulkUpdateDeviceTypesAuth:
    """B-11 API-key authentication on the bulk endpoint."""

    @pytest.mark.unit
    def test_no_api_key_returns_401(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """PUT without X-API-Key header returns 401."""
        store = DeviceTypeOverrideStore(path=tmp_path / "overrides.json")
        mock_pg = MagicMock()
        mock_pg.query_device_by_id = MagicMock(return_value=_make_device_row(1))

        client = _build_test_client(mock_pg, store, monkeypatch=monkeypatch)
        response = client.put(
            BULK_ENDPOINT,
            json={"items": [{"device_id": 1, "device_type": "PLC"}]},
        )

        assert response.status_code == 401
