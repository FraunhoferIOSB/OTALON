"""Internal service and REST API for the PCAP recorder."""

from __future__ import annotations

import os
import pwd
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import (
    Annotated,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Protocol,
    Tuple,
    get_args,
    runtime_checkable,
)

from fastapi import Depends, FastAPI, HTTPException
from fastapi import Path as PathParam
from fastapi import Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from loguru import logger
from pydantic import BaseModel
from starlette.status import HTTP_404_NOT_FOUND

from capture_settings_base import OperatorAuthSettings, encode_api_key

from .index import PcapChunkMeta, PcapIndex
from .ringbuffer import RingbufferManager
from .security_headers import SecurityHeadersMiddleware
from .settings import ApiConfig
from .tshark_args import MAX_RAW_LENGTH, TsharkArgError, parse_tshark_args

DEFAULT_SUBPROCESS_TIMEOUT_S = 30
TSHARK_USER = "pcapuser"

# Network interface names are short kernel identifiers; restrict to a safe
# character set so a status probe can never be steered into path traversal
# when composing ``/sys/class/net/<iface>/operstate``.
_SAFE_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")
_OPERSTATE_ROOT = Path("/sys/class/net")


class FlagRequest(BaseModel):
    start_ts: datetime
    end_ts: datetime
    labels: Optional[Dict[str, str]] = None


@runtime_checkable
class RecorderLike(Protocol):
    """Read-only view of the recorder needed for status reporting.

    Only non-mutating members are declared so the status provider can never
    call ``start``/``stop``/``build_command`` on the recorder it observes.
    """

    @property
    def interface(self) -> str:
        """Configured capture interface name."""
        ...

    @property
    def is_running(self) -> bool:
        """Whether the capture subprocess is currently alive."""
        ...


class CaptureStatusResponse(BaseModel):
    """Read-only capture status snapshot for downstream consumers.

    Every field is nullable so the recorder never fabricates a value it
    cannot source truthfully. ``recording`` reflects the live subprocess
    poll, ``interface`` comes from recorder config, and ``link_up`` is the
    host carrier state read from ``operstate`` (``None`` when unknown).
    ``drops_24h_pct`` and ``overflows`` stay ``None`` until a truthful
    counter source exists — they are never invented as zero.
    """

    interface: Optional[str] = None
    link_up: Optional[bool] = None
    recording: Optional[bool] = None
    drops_24h_pct: Optional[float] = None
    overflows: Optional[int] = None


def _read_link_up(interface: Optional[str]) -> Optional[bool]:
    """Return the carrier state of ``interface`` from sysfs, if knowable.

    Reads ``/sys/class/net/<iface>/operstate`` using the standard library
    only. The interface name is validated against a strict allow-list and any
    dot-only traversal component (``.``/``..``) is rejected before it is used
    in a path, preventing traversal above the net root. Any read failure or a
    non-definitive state (e.g. ``unknown``) yields ``None`` rather than a
    fabricated boolean.
    """

    if not interface or not _SAFE_INTERFACE_RE.match(interface):
        return None
    # The allow-list still admits the relative path components ``.`` and
    # ``..`` (both are pure-dot tokens). Because ``pathlib`` performs no
    # normalisation, ``_OPERSTATE_ROOT / ".." / "operstate"`` stays lexically
    # ``/sys/class/net/../operstate`` and would slip past the structural check
    # below while resolving one level *above* the net root. Reject any dot-only
    # traversal component explicitly before it is placed in a path.
    if interface in {os.curdir, os.pardir} or set(Path(interface).parts) & {os.curdir, os.pardir}:
        return None
    # Guard against traversal via the interface name by confirming the
    # *constructed* path sits directly under the net root as
    # ``<root>/<iface>/operstate`` before any symlink is followed. sysfs
    # entries like ``/sys/class/net/eth0`` are symlinks into ``/sys/devices``,
    # so the resolved target legitimately leaves the net root — we therefore
    # validate the pre-resolution structure, not the resolved parents.
    operstate_path = _OPERSTATE_ROOT / interface / "operstate"
    if operstate_path.parent.parent != _OPERSTATE_ROOT or operstate_path.name != "operstate":
        return None
    try:
        state = operstate_path.read_text(encoding="ascii").strip().lower()
    except OSError:
        return None
    if state == "up":
        return True
    if state == "down":
        return False
    return None


class CaptureStatusProvider:
    """Build a read-only capture status from a recorder view.

    The provider is deliberately non-mutating: it only reads the recorder's
    running state and configured interface, and inspects host carrier state
    via sysfs. It never starts, stops or reconfigures capture.
    """

    def __init__(self, recorder: RecorderLike) -> None:
        """Store the read-only recorder view.

        Args:
            recorder: An object exposing ``interface`` and ``is_running``.
        """

        self._recorder = recorder

    def get_status(self) -> CaptureStatusResponse:
        """Return the current capture status snapshot.

        Returns:
            A :class:`CaptureStatusResponse`; ``drops_24h_pct`` and
            ``overflows`` are ``None`` because the recorder exposes no
            truthful counter source today.
        """

        interface = self._recorder.interface or None
        return CaptureStatusResponse(
            interface=interface,
            link_up=_read_link_up(interface),
            recording=bool(self._recorder.is_running),
            drops_24h_pct=None,
            overflows=None,
        )


class ChunkResponse(BaseModel):
    chunk_id: str
    start_ts: datetime
    end_ts: datetime
    size_bytes: int
    is_anomaly: bool
    labels: Dict[str, str] = {}


class PcapService:
    """Internal coordination between index, ringbuffer, and REST layer."""

    def __init__(
        self,
        index: PcapIndex,
        ringbuffer: RingbufferManager,
        api_config: Optional[ApiConfig] = None,
    ) -> None:
        self._index = index
        self._ringbuffer = ringbuffer
        self._api_config = api_config

    @property
    def subprocess_timeout_s(self) -> int:
        """Subprocess timeout sourced from config or module-level default."""
        if self._api_config is not None:
            return self._api_config.subprocess_timeout_s
        return DEFAULT_SUBPROCESS_TIMEOUT_S

    def flag_anomaly(
        self,
        time_start: datetime,
        time_end: datetime,
        labels: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """Flag chunks overlapping a time range as anomalies."""

        chunks = self._index.find_by_timerange(time_start, time_end)
        chunk_ids = [chunk.filename for chunk in chunks]
        self._ringbuffer.archive_chunks(chunk_ids)
        self._index.mark_anomaly(chunk_ids, labels)
        logger.info("Flagged {count} chunk(s) as anomaly.", count=len(chunk_ids))
        return chunk_ids

    def get_chunks_by_time(self, time_start: datetime, time_end: datetime) -> List[PcapChunkMeta]:
        """Return chunks overlapping the given time range."""

        return self._index.find_by_timerange(time_start, time_end)

    def get_chunks_by_id(self, chunk_ids: Iterable[str]) -> List[PcapChunkMeta]:
        """Return chunks matching the requested IDs."""

        return [meta for meta in self._index.list_all() if meta.filename in chunk_ids]


def _tcpdump_read_text(pcap_path: Path, timeout_s: int = DEFAULT_SUBPROCESS_TIMEOUT_S) -> str:
    """Run ``tcpdump -r`` on a PCAP file and return the human-readable output."""

    command = ["tcpdump", "-r", str(pcap_path), "-q", "-tttt", "-n"]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except FileNotFoundError as error:
        raise RuntimeError("tcpdump executable not found on PATH.") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"tcpdump timed out after {timeout_s}s.") from error

    if result.returncode != 0:
        logger.warning(
            "tcpdump returned exit code {code}: {err}",
            code=result.returncode,
            err=result.stderr.strip(),
        )
        return result.stdout + "\n--- stderr ---\n" + result.stderr

    if result.stderr:
        logger.debug("tcpdump stderr (non-fatal): {msg}", msg=result.stderr.strip())
    return result.stdout


def _build_privilege_dropper() -> Optional[Callable[[], None]]:
    """Return a ``preexec_fn`` that drops to :data:`TSHARK_USER`, or ``None``.

    ``None`` is returned whenever the recorder is *not* root, which is the
    normal deployment: the image runs it as ``pcapuser`` (euid 10006). An
    unprivileged process may not call ``initgroups``/``setgroups``/``setgid``
    at all — every one of them raises ``PermissionError``, and ``subprocess``
    surfaces that as ``SubprocessError: Exception occurred in preexec_fn``,
    which FastAPI maps to 500. The drop was therefore both a no-op (the
    target uid was the uid already held) and the sole reason every
    ``format=detail`` request failed (PCAP-008).

    When the process *is* root the returned callable performs the drop, and
    three things must hold (audit CAP-06):

    * the group id must come from ``pw_gid``. Passing ``pw_uid`` to
      ``setgid`` set the process group to whatever group happens to share
      that numeric id — an unrelated, possibly privileged one.
    * supplementary groups must be replaced, otherwise the child keeps every
      group the parent belonged to (root's ``pcap``, ``docker`` …) no matter
      what ``setgid`` did.
    * the order is fixed: groups, then ``setgid``, then ``setuid``. After
      ``setuid`` the process has lost the privilege required to change
      groups at all, so any later call silently leaves them in place.

    Returns:
        The drop callable when running as root, otherwise ``None``.

    Raises:
        RuntimeError: If running as root while :data:`TSHARK_USER` does not
            exist — running tshark as root instead would be worse.
    """

    if os.geteuid() != 0:
        return None
    try:
        tshark_pw = pwd.getpwnam(TSHARK_USER)
    except KeyError as error:
        raise RuntimeError(f"tshark user '{TSHARK_USER}' does not exist.") from error
    tshark_uid = tshark_pw.pw_uid
    tshark_gid = tshark_pw.pw_gid

    def drop_privileges() -> None:
        """Drop to the unprivileged tshark account in the correct order."""

        try:
            os.initgroups(TSHARK_USER, tshark_gid)
        except (OSError, PermissionError):
            # Not privileged enough to set the full group list; drop every
            # supplementary group instead. Never continue with the
            # parent's groups intact.
            os.setgroups([tshark_gid])
        os.setgid(tshark_gid)
        os.setuid(tshark_uid)

    return drop_privileges


def _tshark_read(
    pcap_path: Path,
    timeout_s: int = DEFAULT_SUBPROCESS_TIMEOUT_S,
    extra_args: Optional[List[str]] = None,
) -> str:
    """Run a read-only ``tshark -r`` command and return stdout.

    Args:
        pcap_path: The chunk to read. Always passed via ``-r`` as the first
            argument pair, so a later ``-r`` in *extra_args* could not
            silently redirect the read — the allow-list rejects one anyway.
        timeout_s: Subprocess timeout.
        extra_args: Already validated additional argv produced by
            :func:`pcap_recorder.tshark_args.parse_tshark_args`. Never a raw
            caller string, and never passed through a shell.

    Returns:
        The tshark stdout.

    Raises:
        RuntimeError: If tshark is missing, cannot be started, or exceeds
            the timeout.
    """

    command = ["tshark", "-r", str(pcap_path), *(extra_args or [])]
    drop_privileges = _build_privilege_dropper()

    logger.debug("Running tshark: {cmd}", cmd=" ".join(command))
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            preexec_fn=drop_privileges,
        )
    except FileNotFoundError as error:
        raise RuntimeError("tshark executable not found on PATH.") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"tshark timed out after {timeout_s}s.") from error
    except subprocess.SubprocessError as error:
        # A failure inside ``preexec_fn`` arrives here as a bare
        # ``SubprocessError`` with no context (PCAP-008). Naming the stage
        # keeps the next such regression out of a raw stack trace.
        raise RuntimeError(f"tshark could not be started: {error}") from error

    if result.returncode != 0:
        logger.warning("tshark returned exit code {code}: {err}", code=result.returncode, err=result.stderr.strip())
        return result.stdout

    if result.stderr:
        logger.debug("tshark stderr (non-fatal): {msg}", msg=result.stderr.strip())
    return result.stdout


ChunkFormat = Literal["json", "pcap", "text", "detail"]
"""Rendering formats both chunk routes accept.

This is the single source of truth. Declaring it as a ``Literal`` makes
FastAPI reject an unknown value with a 422 *before* the handler body runs,
so the allowed set is part of the request contract instead of being
discovered by trial and error against a 400 raised at the bottom of an
if-chain (audit V1).
"""

SUPPORTED_FORMAT_VALUES: Tuple[str, ...] = get_args(ChunkFormat)
"""The accepted format values, derived from :data:`ChunkFormat`."""

SUPPORTED_FORMATS = ", ".join(f"'{value}'" for value in SUPPORTED_FORMAT_VALUES)
"""Human-readable rendering of the accepted formats, never hand-maintained."""

CHUNK_ID_PATTERN = r"^(?:pcap_)?\d{8}_\d{6}\.pcap(?:\.l\d{1,2})?(?:\.(?:gz|zst))?$"
"""Exact shape of a chunk identifier, derived from the producing code.

``TcpdumpRecorder.build_command`` writes ``%Y%m%d_%H%M%S.pcap`` into the
ringbuffer directory (``recorder.py``) and :class:`PcapIndex` keys every
entry by the bare ``path.name``, so a chunk id is exactly that filename.
Archived chunks may additionally carry a compression suffix (``.gz``,
``.zst``, ``.lNN.zst``).

The optional ``pcap_`` prefix is the recorder's own legacy shape: the
output pattern carried it until the ringbuffer layout was reworked, and
:meth:`PcapIndex._parse_timestamp` still strips it, so an index carried
across that change can hold prefixed entries. Accepting it here keeps the
route from rejecting an identifier its own index hands out. No live chunk
uses the prefix any more, which is why the client-side pattern in
``otalon-mcp/src/validation.py`` is deliberately stricter.

Anchoring is what matters for safety: it keeps a value such as
``"../pcap_index.json"`` from ever reaching a filesystem lookup (audit V2).
"""

CHUNK_ID_MAX_LENGTH = 64
"""Length ceiling; the longest shape the pattern admits is 33 characters."""


def _render_chunk_text(chunk: PcapChunkMeta, svc: PcapService) -> PlainTextResponse:
    """Helper that renders a chunk via ``tcpdump -r``."""

    try:
        text_output = _tcpdump_read_text(chunk.path, timeout_s=svc.subprocess_timeout_s)
    except RuntimeError as error:
        raise HTTPException(status_code=500, detail=str(error)) from error
    return PlainTextResponse(content=text_output)


def _render_chunk_detail(
    chunk: PcapChunkMeta,
    svc: PcapService,
    tshark_args: Optional[str] = None,
) -> PlainTextResponse:
    """Helper that renders a chunk via ``tshark -r`` plus validated arguments.

    Args:
        chunk: The chunk to render.
        svc: The coordination service, consulted for the subprocess timeout.
        tshark_args: Optional caller-supplied argument string. It is parsed
            against the allow-list in :mod:`pcap_recorder.tshark_args`; a
            rejected value is a 400, never a subprocess.

    Returns:
        The tshark output as ``text/plain``.

    Raises:
        HTTPException: 400 when the arguments are rejected, 500 when tshark
            itself fails.
    """

    try:
        extra_args = parse_tshark_args(tshark_args or "")
    except TsharkArgError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    try:
        detail_output = _tshark_read(
            chunk.path,
            timeout_s=svc.subprocess_timeout_s,
            extra_args=extra_args,
        )
    except RuntimeError as error:
        raise HTTPException(status_code=500, detail=str(error)) from error
    return PlainTextResponse(content=detail_output)


_encode_api_key = encode_api_key
"""Historic name of the shared key encoder, kept for existing call sites.

The implementation moved to ``capture_settings_base`` with PCAP-007 so the
import worker compares credentials exactly the way the recorder does.
"""


def _render_chunk_json(chunk: PcapChunkMeta) -> ChunkResponse:
    """Helper that builds a JSON metadata response for a single chunk."""

    return ChunkResponse(
        chunk_id=chunk.filename,
        start_ts=chunk.start_ts,
        end_ts=chunk.end_ts,
        size_bytes=chunk.size_bytes,
        is_anomaly=chunk.is_anomaly,
        labels=chunk.labels,
    )


def create_app(service: PcapService, status_provider: Optional[CaptureStatusProvider] = None) -> FastAPI:
    """Build and return the FastAPI application wired to *service*.

    Args:
        service: The internal PCAP coordination service (index + ringbuffer).
        status_provider: Optional read-only capture status provider. When
            supplied, a ``GET /status`` route is exposed. It is an explicit,
            non-mutating object rather than a handle to the recorder's
            control surface, so the request handler can never start, stop or
            reconfigure capture. When ``None``, ``/status`` returns 503,
            preserving backward compatibility for existing call sites/tests.
    """

    # Metadata is set for parity with the other suite services (HC32).
    # The interactive docs and the OpenAPI schema stay disabled: PCAP-006
    # hardened this surface deliberately, and the recorder serves capture
    # data to two internal consumers only (otalon-api, otalon-mcp), so
    # there is no reason to publish its schema.
    app = FastAPI(
        title="OTALON PCAP Recorder",
        version="0.1.0",
        description=(
            "Ringbuffer PCAP capture and chunk retrieval for the OTALON "
            "network monitoring suite. Internal service; consumed by "
            "otalon-api and otalon-mcp."
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(SecurityHeadersMiddleware)

    async def require_operator_api_key(request: Request) -> None:
        """Require established suite ``X-API-Key`` operator credential.

        Resolved per request, not per application: the credential is part of
        the deployment environment, and the recorder's own tests (plus the
        Compose start order) rely on a key exported after ``create_app``.
        """
        auth = OperatorAuthSettings.from_env()
        if not auth.is_configured:
            raise HTTPException(status_code=503, detail="API key authentication unavailable")
        if not auth.matches(request.headers.get("X-API-Key", "")):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    def get_service() -> PcapService:
        return service

    def get_status_provider() -> CaptureStatusProvider:
        if status_provider is None:
            raise HTTPException(status_code=503, detail="Capture status provider not configured")
        return status_provider

    @app.get("/health")
    def healthcheck() -> JSONResponse:
        # logger.debug("Health check endpoint called")
        return JSONResponse({"status": "ok"})

    @app.get("/status", response_model=CaptureStatusResponse)
    def capture_status(provider: CaptureStatusProvider = Depends(get_status_provider)) -> CaptureStatusResponse:
        """Return read-only capture status (interface/link/recording).

        This endpoint only reads recorder state and host carrier state. It
        never starts, stops or reconfigures capture. Drops/overflows are
        reported as ``null`` until a truthful counter source exists.
        """

        return provider.get_status()

    @app.post("/anomalies/flag")
    def flag_anomaly(
        request: FlagRequest,
        svc: PcapService = Depends(get_service),
        _auth: None = Depends(require_operator_api_key),
    ) -> JSONResponse:
        # Flagging pins chunks against ringbuffer eviction and writes
        # operator-visible labels, so it is a mutation of retention state.
        # It carried only the service dependency while the read-only
        # ``/chunks`` route was already authenticated (audit CAP-01).
        if request.start_ts > request.end_ts:
            raise HTTPException(status_code=400, detail="start_ts must not be after end_ts")
        chunk_ids = svc.flag_anomaly(request.start_ts, request.end_ts, request.labels)
        logger.info(
            "Flag anomaly request handled (start={start}, end={end}, chunks={count})",
            start=request.start_ts,
            end=request.end_ts,
            count=len(chunk_ids),
        )
        return JSONResponse({"chunk_ids": chunk_ids})

    @app.get("/chunks", response_model=None)
    def get_chunks(
        start_ts: datetime,
        end_ts: datetime,
        format: Annotated[
            ChunkFormat,
            Query(description=f"Rendering format. One of {SUPPORTED_FORMATS}."),
        ] = "json",
        svc: PcapService = Depends(get_service),
        _auth: None = Depends(require_operator_api_key),
    ) -> List[ChunkResponse] | FileResponse | PlainTextResponse:
        if start_ts > end_ts:
            raise HTTPException(status_code=400, detail="start_ts must not be after end_ts")
        chunks = svc.get_chunks_by_time(start_ts, end_ts)
        logger.debug(
            "Chunk query handled (start={start}, end={end}, count={count}, format={fmt})",
            start=start_ts,
            end=end_ts,
            count=len(chunks),
            fmt=format,
        )
        # ``format`` is a ``Literal``, so an unknown value never reaches this
        # body — FastAPI answers 422 during validation. The if-chain is
        # therefore exhaustive and needs no trailing "unsupported" branch.
        if format == "json":
            return [_render_chunk_json(chunk) for chunk in chunks]
        if not chunks:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="No chunks found")
        if format == "pcap":
            return FileResponse(path=chunks[0].path)
        if format == "text":
            return _render_chunk_text(chunks[0], svc)
        return _render_chunk_detail(chunks[0], svc)

    @app.get("/chunks/{chunk_id}", response_model=None)
    def get_chunk_by_id(
        chunk_id: Annotated[
            str,
            PathParam(
                pattern=CHUNK_ID_PATTERN,
                max_length=CHUNK_ID_MAX_LENGTH,
                description="Recorder chunk filename, e.g. '20260213_120000.pcap'.",
            ),
        ],
        format: Annotated[
            ChunkFormat,
            Query(description=f"Rendering format. One of {SUPPORTED_FORMATS}."),
        ] = "pcap",
        tshark_args: Annotated[
            Optional[str],
            Query(
                max_length=MAX_RAW_LENGTH,
                description=(
                    "Additional tshark arguments for format='detail', e.g. "
                    "'-q -z io,phs' or '-Y lldp -T fields -e eth.src'. "
                    "Validated against a read-only allow-list; ignored for "
                    "every other format."
                ),
            ),
        ] = None,
        svc: PcapService = Depends(get_service),
        _auth: None = Depends(require_operator_api_key),
    ) -> ChunkResponse | FileResponse | PlainTextResponse:
        # The identifier is constrained to the recorder's own filename shape
        # by the route signature (audit V2), so a malformed value is a 422
        # and never becomes an index lookup or a filesystem path.
        matches = svc.get_chunks_by_id([chunk_id])
        if not matches:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Chunk not found")
        chunk = matches[0]
        logger.debug(
            "Chunk fetched by id {chunk_id} (format={fmt}, tshark_args={args!r})",
            chunk_id=chunk_id,
            fmt=format,
            args=tshark_args or "",
        )
        # Exhaustive by construction: ``format`` is a validated ``Literal``.
        if format == "text":
            return _render_chunk_text(chunk, svc)
        if format == "detail":
            return _render_chunk_detail(chunk, svc, tshark_args)
        if format == "json":
            return _render_chunk_json(chunk)
        return FileResponse(path=chunk.path)

    return app
