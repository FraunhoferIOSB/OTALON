"""Unit tests for ``GET /scans/modules/{name}/schema``.

Verifies:

- ``requires_auth`` is read from the Override-schema ``ClassVar`` (no
  hard-coded mapping in the endpoint).
- ``accepted_keys`` matches the model_fields of each module's override
  schema.
- ``extensible`` is always ``False`` in v1.
- Unknown module names raise HTTPException 404.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from otalon_scan.api.routers.scans import get_module_schema
from otalon_scan.core.module_config import MODULE_SCHEMA_REGISTRY


class TestModuleSchemaEndpoint:
    """Tests for :func:`get_module_schema`."""

    @pytest.mark.asyncio
    async def test_opcua_discover_schema(self) -> None:
        """opcua_discover SHALL have the expected keys and ``requires_auth=False``."""
        resp = await get_module_schema("opcua_discover")
        assert resp.module == "opcua_discover"
        assert resp.requires_auth is False
        assert resp.extensible is False
        keys = {k.key for k in resp.accepted_keys}
        assert keys == {"target_ip", "target_port", "network_interface"}

    @pytest.mark.asyncio
    async def test_snmp_scan_requires_auth(self) -> None:
        """snmp_scan SHALL report ``requires_auth=True``."""
        resp = await get_module_schema("snmp_scan")
        assert resp.module == "snmp_scan"
        assert resp.requires_auth is True

    @pytest.mark.asyncio
    async def test_all_modules_keys_match_registry(self) -> None:
        """For every registered module, accepted_keys SHALL equal ``model_fields``."""
        for slug in MODULE_SCHEMA_REGISTRY:
            resp = await get_module_schema(slug)
            expected_keys = set(MODULE_SCHEMA_REGISTRY[slug].model_fields.keys())
            actual_keys = {k.key for k in resp.accepted_keys}
            assert actual_keys == expected_keys, f"{slug}: key mismatch"

    @pytest.mark.asyncio
    async def test_unknown_module_raises_404(self) -> None:
        """An unknown module name SHALL raise HTTPException 404."""
        with pytest.raises(HTTPException) as excinfo:
            await get_module_schema("does_not_exist")
        assert excinfo.value.status_code == 404

    @pytest.mark.asyncio
    async def test_arp_scan_requires_auth_false(self) -> None:
        """arp_scan SHALL report ``requires_auth=False``."""
        resp = await get_module_schema("arp_scan")
        assert resp.requires_auth is False

    @pytest.mark.asyncio
    async def test_port_scan_requires_auth_false(self) -> None:
        """port_scan SHALL report ``requires_auth=False``."""
        resp = await get_module_schema("port_scan")
        assert resp.requires_auth is False

    @pytest.mark.asyncio
    async def test_pn_discovery_requires_auth_false(self) -> None:
        """pn_discovery SHALL report ``requires_auth=False``."""
        resp = await get_module_schema("pn_discovery")
        assert resp.requires_auth is False
