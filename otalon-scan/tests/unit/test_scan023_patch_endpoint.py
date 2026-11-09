"""Unit tests for ``PATCH /devices/{device_id}`` (SCAN-023).

Proves acceptance criterion (c): the PATCH endpoint validates its body
and calls :meth:`ScannerPostgresRepo.set_manual_identity` with exactly
the supplied fields, and maps the repo result onto the wire shape /
HTTP status. The repository is replaced with a lightweight fake so the
test needs no PostgreSQL (it runs in the ``not integration`` tier).

Also covers the request-model contract:

- ``extra="forbid"`` rejects a non-identity key (HTTP 422 via Pydantic).
- an empty body is rejected by the ``_at_least_one_field`` validator.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from otalon_scan.api.dependencies import require_repo
from otalon_scan.api.routers.devices import patch_device_identity
from otalon_scan.api.schemas.devices import DeviceIdentityPatchRequest
from otalon_scan.repositories.models import Device


class _FakeRepo:
    """Records the ``set_manual_identity`` call and returns a canned row."""

    def __init__(self, row: Optional[Device]) -> None:
        self._row = row
        self.calls: list[tuple[int, Dict[str, Any]]] = []
        self.raise_value_error = False

    async def set_manual_identity(
        self,
        device_id: int,
        fields: Dict[str, Optional[str]],
    ) -> Optional[Device]:
        self.calls.append((device_id, dict(fields)))
        if self.raise_value_error:
            raise ValueError("not lockable identity fields: ['bogus']")
        return self._row


def _make_device_row() -> Device:
    """Build a detached :class:`Device` ORM row for the fake repo."""
    row = Device()
    row.id = 7
    row.primary_mac = "aa:bb:cc:dd:ee:ff"
    row.vendor = "Siemens"
    row.firmware_version = "V4.3"
    row.manual_identity_fields = ["firmware_version", "vendor"]
    row.last_scan_at = datetime(2026, 6, 21, 12, 0, tzinfo=timezone.utc)
    return row


class TestDeviceIdentityPatchRequest:
    """Request-model validation contract."""

    def test_rejects_unknown_field(self) -> None:
        """A non-identity key SHALL fail validation (``extra=forbid``)."""
        with pytest.raises(ValidationError):
            DeviceIdentityPatchRequest.model_validate({"bogus": "x"})

    def test_rejects_empty_body(self) -> None:
        """An empty patch body SHALL fail the at-least-one validator."""
        with pytest.raises(ValidationError):
            DeviceIdentityPatchRequest.model_validate({})

    def test_accepts_partial_identity(self) -> None:
        """A single identity field SHALL validate and expose only that field."""
        req = DeviceIdentityPatchRequest.model_validate({"vendor": "Siemens"})
        assert req.model_dump(exclude_unset=True) == {"vendor": "Siemens"}

    def test_null_value_is_kept_in_set(self) -> None:
        """An explicit ``null`` is a set field (clears value, still locks)."""
        req = DeviceIdentityPatchRequest.model_validate({"firmware_version": None})
        assert req.model_dump(exclude_unset=True) == {"firmware_version": None}

    def test_accepts_mitre_device_type(self) -> None:
        """A catalog device type validates as an identity field."""
        req = DeviceIdentityPatchRequest.model_validate({"device_type": "Field I/O"})
        assert req.device_type == "Field I/O"

    def test_rejects_non_catalog_device_type(self) -> None:
        """Values outside the catalog fail request validation for HTTP 422."""
        with pytest.raises(ValidationError):
            DeviceIdentityPatchRequest.model_validate({"device_type": "IPC"})


class TestPatchDeviceIdentityEndpoint:
    """Endpoint behaviour against a fake repo (no DB)."""

    async def test_calls_repo_with_only_set_fields(self) -> None:
        """The handler SHALL forward exactly the supplied identity fields."""
        fake = _FakeRepo(_make_device_row())
        payload = DeviceIdentityPatchRequest.model_validate({"vendor": "Siemens", "firmware_version": "V4.3"})
        result = await patch_device_identity(7, payload, repo=fake)  # type: ignore[arg-type]
        assert fake.calls == [(7, {"vendor": "Siemens", "firmware_version": "V4.3"})]
        assert result.id == 7
        assert result.vendor == "Siemens"
        assert result.manual_identity_fields == ["firmware_version", "vendor"]
        assert result.last_scan_at == "2026-06-21T12:00:00+00:00"

    async def test_missing_device_raises_404(self) -> None:
        """A ``None`` repo result SHALL surface as HTTP 404."""
        payload = DeviceIdentityPatchRequest.model_validate({"vendor": "X"})
        with pytest.raises(HTTPException) as excinfo:
            await patch_device_identity(123, payload, repo=_FakeRepo(None))  # type: ignore[arg-type]
        assert excinfo.value.status_code == 404

    async def test_repo_value_error_becomes_422(self) -> None:
        """A repo ``ValueError`` SHALL surface as HTTP 422."""
        fake = _FakeRepo(_make_device_row())
        fake.raise_value_error = True
        payload = DeviceIdentityPatchRequest.model_validate({"vendor": "X"})
        with pytest.raises(HTTPException) as excinfo:
            await patch_device_identity(7, payload, repo=fake)  # type: ignore[arg-type]
        assert excinfo.value.status_code == 422

    async def test_uninitialised_repo_raises_500(self) -> None:
        """A missing repo (startup not complete) SHALL surface as HTTP 500.

        SCAN-033 moved this guard out of the handler body into the
        shared ``require_repo`` narrowing helper, which the handler calls
        on its first line. Status code and detail string are unchanged.
        """
        with pytest.raises(HTTPException) as excinfo:
            require_repo(None)
        assert excinfo.value.status_code == 500
        assert excinfo.value.detail == "Repository not initialized"
