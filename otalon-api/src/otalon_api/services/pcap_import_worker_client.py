"""Outbound HTTP client for the netcap pcap-import worker (UI-078, Wave B).

The worker (``otalon-capture/src/pcap_import/``, Wave A, commit ``d4c522d``)
is a passive receiver with **one** slot and **no** internal queue. Three
outcomes therefore matter to the caller and are modelled explicitly:

* ``202`` — accepted, the import runs asynchronously;
* ``409`` — busy with another import; the job must stay pending on our
  side and be delivered again later;
* transport failure — the worker is unreachable; likewise pending.

Everything else (``422`` and any other non-2xx) is a permanent rejection
of that particular payload and surfaces as :class:`WorkerRejected`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
from loguru import logger


class WorkerUnavailable(Exception):
    """The worker could not be reached at all (transport-level failure)."""


class WorkerBusy(Exception):
    """The worker refused delivery because it is running another import."""

    def __init__(self, running_display_id: str | None = None) -> None:
        """Record which job the worker is currently occupied with."""
        super().__init__(f"worker busy with {running_display_id or 'another import'}")
        self.running_display_id = running_display_id


class WorkerRejected(Exception):
    """The worker permanently refused the payload (validation failure)."""

    def __init__(self, status_code: int, detail: Any) -> None:
        """Record the upstream status and body for diagnostics."""
        super().__init__(f"worker rejected delivery with HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class WorkerHealth:
    """Snapshot of the worker's single-slot state."""

    busy: bool
    state: str
    display_id: str | None


class PcapImportWorkerClient:
    """Thin async client for the worker's ``/import`` control surface."""

    def __init__(self, base_url: str, *, timeout: float = 10.0, api_key: str | None = None) -> None:
        """Configure the upstream endpoint.

        Args:
            base_url: Worker base URL, e.g. ``http://netcap-pcap-import:9092``.
            timeout: Per-request timeout in seconds.
            api_key: Operator API key used by the worker's import controls.
        """
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._api_key = api_key

    @property
    def base_url(self) -> str:
        """Return the configured worker base URL."""
        return self._base

    async def deliver(
        self,
        display_id: str,
        file_path: str,
        *,
        time_start: datetime | None = None,
        time_end: datetime | None = None,
        original_filename: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """Push one import job to the worker.

        Args:
            display_id: Public job id; becomes the report-channel path segment.
            file_path: Absolute path of the capture inside the shared volume.
            time_start: First packet timestamp, when known.
            time_end: Last packet timestamp, when known.
            original_filename: Caller-declared name, metadata only.
            force: Records that the overlap check was overridden.

        Returns:
            The parsed ``202`` acceptance body.

        Raises:
            WorkerBusy: The worker is occupied; keep the job pending.
            WorkerUnavailable: The worker is unreachable; keep it pending.
            WorkerRejected: The worker refused this payload permanently.
        """
        payload: dict[str, Any] = {"display_id": display_id, "file_path": file_path, "force": force}
        if time_start is not None:
            payload["time_start"] = time_start.isoformat()
        if time_end is not None:
            payload["time_end"] = time_end.isoformat()
        if original_filename is not None:
            payload["original_filename"] = original_filename
        status, body = await self._request("POST", "/import", json_body=payload)
        if status == 202:
            return body if isinstance(body, dict) else {}
        if status == 409:
            raise WorkerBusy(_running_display_id(body))
        raise WorkerRejected(status, body)

    async def cancel(self, display_id: str) -> bool:
        """Ask the worker to abort the running import.

        Args:
            display_id: The job expected to be running (diagnostics only).

        Returns:
            ``True`` when the worker accepted the cancellation.
        """
        try:
            status, _body = await self._request("POST", "/import/cancel", json_body={"display_id": display_id})
        except WorkerUnavailable:
            return False
        return status == 202

    async def health(self) -> WorkerHealth | None:
        """Return the worker's slot state, or ``None`` when unreachable."""
        try:
            status, body = await self._request("GET", "/health")
        except WorkerUnavailable:
            return None
        if status != 200 or not isinstance(body, dict):
            return None
        return WorkerHealth(
            busy=bool(body.get("busy")),
            state=str(body.get("state") or "unknown"),
            display_id=body.get("display_id"),
        )

    async def _request(self, method: str, path: str, *, json_body: Any = None) -> tuple[int, Any]:
        """Issue one upstream call and return ``(status, parsed_body)``.

        Raises:
            WorkerUnavailable: On any transport-level failure.
        """
        url = f"{self._base}{path}"
        headers = {"X-API-Key": self._api_key} if self._api_key and path in {"/import", "/import/cancel"} else None
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.request(method, url, headers=headers, json=json_body)
        except httpx.TransportError as exc:
            logger.warning("pcap-import worker unreachable ({} {}): {}", method, path, exc)
            raise WorkerUnavailable(f"{type(exc).__name__}: {exc}") from exc
        try:
            body: Any = response.json()
        except ValueError:
            body = {"detail": response.text}
        return response.status_code, body


def _running_display_id(body: Any) -> str | None:
    """Extract ``detail.running_display_id`` from a worker ``409`` body."""
    if not isinstance(body, dict):
        return None
    detail = body.get("detail")
    if isinstance(detail, dict):
        value = detail.get("running_display_id")
        return str(value) if value else None
    return None
