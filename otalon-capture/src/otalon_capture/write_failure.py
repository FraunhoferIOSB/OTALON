"""Numeric permanent-write refusal classification and sanitized owner signal."""

from __future__ import annotations

import importlib
from types import ModuleType

from influxdb_client_3 import InfluxDBError
from influxdb_client_3.write_client.rest import ApiException
from urllib3 import HTTPResponse

httpx: ModuleType | None
try:
    httpx = importlib.import_module("httpx")
except ImportError:
    httpx = None


class TerminalWriteError(RuntimeError):
    """Public terminal signal containing no transport diagnostics or raw cause."""

    category = "permanent_auth_refusal"

    def __init__(self, status: int) -> None:
        if status not in (401, 403) or not isinstance(status, int):
            raise ValueError("terminal write status must be HTTP 401 or 403")
        self.status = int(status)
        super().__init__(f"InfluxDB write refused: {self.category} (HTTP {self.status}).")


def permanent_auth_status(exception: BaseException) -> int | None:
    """Inspect only established numeric HTTP shapes in a bounded causal graph."""
    pending = [exception]
    seen: set[int] = set()
    for _ in range(32):
        if not pending:
            break
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        status = None
        if isinstance(current, ApiException):
            status = current.status
        elif isinstance(current, InfluxDBError) and isinstance(current.response, HTTPResponse):
            status = current.response.status
        elif httpx is not None and isinstance(current, httpx.HTTPStatusError):
            status = current.response.status_code
        if isinstance(status, int) and status in (401, 403):
            return int(status)
        for linked in (current.__context__, current.__cause__):
            if linked is not None and id(linked) not in seen:
                pending.append(linked)
    return None
