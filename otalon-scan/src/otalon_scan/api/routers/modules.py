"""Module-catalogue router (SCAN-033 extraction).

Owns ``GET /modules`` and ``GET /modules/{module_name}/config``. The
schema-introspection endpoint lives on the scan router because its path
is ``/scans/modules/{name}/schema``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException

from ...core.auth import verify_api_key
from ...core.config_utils import load_json
from ...core.module_manager import ModuleManager
from ..dependencies import get_optional_manager, require_manager
from ..schemas.modules import ModulesResponse

__all__ = ["router"]

router = APIRouter()


@router.get(
    "/modules",
    response_model=ModulesResponse,
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def list_modules(
    manager: Optional[ModuleManager] = Depends(get_optional_manager),
) -> ModulesResponse:
    """List available scanner modules."""
    return ModulesResponse(modules=require_manager(manager).get_module_names())


@router.get(
    "/modules/{module_name}/config",
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def get_module_config(
    module_name: str,
    manager: Optional[ModuleManager] = Depends(get_optional_manager),
) -> Dict[str, Any]:
    """Return the default config.json content for a module."""
    info = require_manager(manager).get_module_info(module_name)
    cfg_path = info.get("config_path")
    if not cfg_path:
        raise HTTPException(status_code=404, detail="Module not found")
    data = load_json(cfg_path)
    if data is None:
        raise HTTPException(status_code=404, detail="Config not found or invalid")
    return {"config": data}
