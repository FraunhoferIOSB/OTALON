"""PCAP recorder helper functions for MCP tools.

This module delegates to the pcap_recorder REST API (default port 9090)
and wraps responses in the standard ``{"ok": bool, ...}`` envelope used
by all OTALON-MCP tools.

It is initialized via ``tools.__init__.init()`` which passes the base URL
and timeout.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from loguru import logger

from otalon_mcp.validation import (
    ChunkIdError,
    ConversationLayerError,
    ensure_chunk_id,
    ensure_conversation_layer,
)

_PCAP_URL: str = ""
_TIMEOUT: int = 30
_API_KEY: str = ""

API_KEY_ENV_VARS: Tuple[str, ...] = ("PCAP_RECORDER_API_KEY", "ADMIN_API_KEY")
"""Environment variables ``otalon_mcp.settings`` searches for the operator key.

Named here only for the startup warning below; the lookup itself lives in
the settings layer (MCP-014).

``pcap_recorder`` protects ``/anomalies/flag``, ``/chunks`` and
``/chunks/{id}`` with ``Depends(require_operator_api_key)``, which
compares the ``X-API-Key`` request header against ``ADMIN_API_KEY`` and
the operator entries of ``OTALON_API_ALLOWED_KEYS``. Without the header
every pcap.* tool got HTTP 401 (audit MCP-04).
"""

# Maximum characters to include in raw tshark output to keep responses
# bounded for the LLM context window. Outputs larger than this are
# truncated with a hint pointing at narrower filters or stat tools.
MAX_OUTPUT_CHARS: int = 50_000


def init(pcap_url: str, timeout: int = 30, api_key: str = "") -> None:
    """Initialize the PCAP helper with the recorder base URL and timeout.

    The operator key is resolved once in ``otalon_mcp.settings`` (see
    :data:`API_KEY_ENV_VARS`) and injected here. The recorder rejects
    unauthenticated requests with HTTP 401, so a missing key means every
    pcap.* tool is dead on arrival; that is surfaced as a loud startup
    warning rather than 11 identical 401s at call time (audit MCP-04).

    Parameters
    ----------
    pcap_url : str
        Base URL of the pcap_recorder REST API (e.g. ``http://localhost:9090``).
    timeout : int
        Default request timeout in seconds.
    api_key : str
        Operator key sent as ``X-API-Key``; empty means unauthenticated.
    """
    global _PCAP_URL, _TIMEOUT, _API_KEY
    _PCAP_URL = pcap_url.rstrip("/")
    _TIMEOUT = timeout
    _API_KEY = api_key.strip()
    if not _API_KEY:
        logger.warning(
            "tools.pcap.init: no recorder API key found in {vars}; "
            "all pcap.* tools will fail with HTTP 401 until one is set",
            vars=", ".join(API_KEY_ENV_VARS),
        )
    logger.debug(
        "tools.pcap.init: url={url}, timeout={timeout}, api_key={state}",
        url=_PCAP_URL,
        timeout=_TIMEOUT,
        state="configured" if _API_KEY else "MISSING",
    )


def _auth_headers() -> Dict[str, str]:
    """Return the recorder auth header, or an empty dict when unset.

    Sending no header at all (rather than an empty one) keeps the
    recorder's 401 response semantically accurate when no key is
    configured.
    """
    return {"X-API-Key": _API_KEY} if _API_KEY else {}


def _chunk_path(chunk_id: str) -> str:
    """Return the ``/chunks/<id>`` path for a validated chunk identifier.

    ``requests`` normalises ``..`` segments before sending, so a raw
    ``chunk_id`` of ``"../status"`` interpolated into the path resolved to
    an unrelated recorder endpoint (audit QUA-07). Building the path here
    guarantees the identifier is checked against
    :data:`validation.CHUNK_ID_PATTERN` even when a helper is called
    directly rather than through the MCP tool schema.

    Parameters
    ----------
    chunk_id : str
        Candidate chunk identifier.

    Returns
    -------
    str
        The request path relative to the recorder base URL.

    Raises
    ------
    validation.ChunkIdError
        If the identifier is not a plain recorder chunk name.
    """
    return f"/chunks/{ensure_chunk_id(chunk_id)}"


def _invalid_chunk_id(tool: str, exc: ChunkIdError) -> Dict[str, Any]:
    """Return the error envelope for a rejected chunk identifier.

    Kept distinct from the generic failure envelope so the caller can tell
    a malformed argument apart from a recorder-side error and self-correct
    without a retry against the recorder.

    Parameters
    ----------
    tool : str
        Helper name used in the log line.
    exc : ChunkIdError
        The rejection raised by :func:`validation.ensure_chunk_id`.

    Returns
    -------
    dict
        ``{"ok": False, "error": str}``.
    """
    err = {"ok": False, "error": str(exc)}
    logger.warning("tools.pcap.{tool} rejected chunk_id: {err}", tool=tool, err=err)
    return err


def _get(path: str, params: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None) -> requests.Response:
    """Execute a GET request against the pcap_recorder API.

    Parameters
    ----------
    path : str
        URL path relative to the base (e.g. ``/health``).
    params : dict, optional
        Query parameters.
    timeout : int, optional
        Override the default timeout for this request.

    Returns
    -------
    requests.Response
        The HTTP response object.
    """
    url = f"{_PCAP_URL}{path}"
    return requests.get(
        url,
        params=params,
        headers=_auth_headers(),
        timeout=timeout or _TIMEOUT,
    )


def _post(path: str, json_body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None) -> requests.Response:
    """Execute a POST request against the pcap_recorder API.

    Parameters
    ----------
    path : str
        URL path relative to the base (e.g. ``/anomalies/flag``).
    json_body : dict, optional
        JSON payload to send in the request body.
    timeout : int, optional
        Override the default timeout for this request.

    Returns
    -------
    requests.Response
        The HTTP response object.
    """
    url = f"{_PCAP_URL}{path}"
    return requests.post(
        url,
        json=json_body,
        headers=_auth_headers(),
        timeout=timeout or _TIMEOUT,
    )


def _truncate(text: str, max_lines: int) -> Tuple[str, int, bool]:
    """Split text into lines, truncate if needed, and return metadata.

    Parameters
    ----------
    text : str
        Raw text content.
    max_lines : int
        Maximum number of lines to keep.

    Returns
    -------
    tuple[str, int, bool]
        ``(possibly_truncated_text, total_lines, was_truncated)``
    """
    lines = text.splitlines()
    total = len(lines)
    if total <= max_lines:
        return text, total, False
    truncated_text = "\n".join(lines[:max_lines])
    return truncated_text, total, True


def _resolve_time_window(
    start_ts: str = "",
    end_ts: str = "",
    last_minutes: int = 0,
    last_hours: int = 0,
) -> Tuple[str, str]:
    """Convert relative time parameters to absolute ISO 8601 timestamps.

    Priority: ``last_hours`` > ``last_minutes`` > ``start_ts/end_ts``.
    If relative parameters are given they take precedence over explicit
    timestamps.  ``end_ts`` defaults to "now" when relative mode is used.

    Parameters
    ----------
    start_ts : str
        Explicit ISO 8601 start timestamp (used when no relative params).
    end_ts : str
        Explicit ISO 8601 end timestamp (used when no relative params).
    last_minutes : int
        Minutes to look back from now.
    last_hours : int
        Hours to look back from now (convenience; converted to minutes).

    Returns
    -------
    tuple[str, str]
        ``(resolved_start_ts, resolved_end_ts)`` as ISO 8601 strings.

    Raises
    ------
    ValueError
        When neither relative nor explicit timestamps are provided.
    """
    if last_hours > 0:
        last_minutes = last_hours * 60

    if last_minutes > 0:
        now = datetime.now(timezone.utc)
        resolved_end = now
        resolved_start = now - timedelta(minutes=last_minutes)
        return resolved_start.isoformat(), resolved_end.isoformat()

    if start_ts and end_ts:
        return start_ts, end_ts

    raise ValueError("Either (start_ts + end_ts) or (last_minutes / last_hours) must be provided.")


def _newest_chunks(chunks: List[Dict[str, Any]], count: int) -> List[Dict[str, Any]]:
    """Return the *count* most recent chunks sorted by start_ts descending.

    Parameters
    ----------
    chunks : list
        List of chunk metadata dicts (must contain ``start_ts``).
    count : int
        Maximum number of chunks to return.

    Returns
    -------
    list
        The newest *count* chunks, sorted newest-first.
    """
    sorted_chunks = sorted(chunks, key=lambda c: c.get("start_ts", ""), reverse=True)
    return sorted_chunks[:count]


def health() -> Dict[str, Any]:
    """Check reachability of the pcap_recorder service.

    Returns
    -------
    dict
        ``{"ok": True, "status": "ok"}`` on success, or
        ``{"ok": False, "error": str}`` on failure.
    """
    try:
        resp = _get("/health", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return {"ok": True, "status": data.get("status", "ok")}
    except Exception as exc:
        err = {"ok": False, "error": f"pcap_recorder health check failed: {exc}"}
        logger.error("tools.pcap.health error: {err}", err=err)
        return err


def list_chunks(
    start_ts: str = "",
    end_ts: str = "",
    last_minutes: int = 0,
    last_hours: int = 0,
    last_chunks: int = 0,
) -> Dict[str, Any]:
    """List PCAP chunks within a time window or by relative time.

    The LLM does not know the current wall-clock time, so prefer
    ``last_minutes``, ``last_hours``, or ``last_chunks`` over explicit
    timestamps when the user says e.g. "last 2 hours".

    Time resolution priority: ``last_hours`` > ``last_minutes`` >
    ``start_ts/end_ts``.  If ``last_chunks`` is set, a broad 24-hour
    window is queried and only the *N* newest chunks are returned.

    Parameters
    ----------
    start_ts : str
        ISO 8601 start timestamp (optional when relative params used).
    end_ts : str
        ISO 8601 end timestamp (optional when relative params used).
    last_minutes : int
        Look-back window in minutes from now (e.g. 120 for 2 hours).
    last_hours : int
        Look-back window in hours from now (convenience alias).
    last_chunks : int
        Return only the N most recent chunks (queries last 24 h).

    Returns
    -------
    dict
        ``{"ok": True, "chunks": list, "count": int}`` or error.
    """
    try:
        if last_chunks > 0:
            now = datetime.now(timezone.utc)
            resolved_start = (now - timedelta(hours=24)).isoformat()
            resolved_end = now.isoformat()
        else:
            resolved_start, resolved_end = _resolve_time_window(start_ts, end_ts, last_minutes, last_hours)
        resp = _get("/chunks", params={"start_ts": resolved_start, "end_ts": resolved_end, "format": "json"})
        resp.raise_for_status()
        chunks = resp.json()
        if last_chunks > 0:
            chunks = _newest_chunks(chunks, last_chunks)
        return {"ok": True, "chunks": chunks, "count": len(chunks)}
    except Exception as exc:
        err = {"ok": False, "error": f"pcap list_chunks failed: {exc}"}
        logger.error("tools.pcap.list_chunks error: {err}", err=err)
        return err


def list_anomaly_chunks(
    start_ts: str = "",
    end_ts: str = "",
    last_minutes: int = 0,
    last_hours: int = 0,
    last_chunks: int = 0,
) -> Dict[str, Any]:
    """List only anomaly-flagged PCAP chunks, with relative time support.

    Internally fetches all chunks and filters client-side for
    ``is_anomaly == True``.  Includes ``labels`` if the pcap_recorder API
    returns them.

    The LLM does not know the current wall-clock time, so prefer
    ``last_minutes``, ``last_hours``, or ``last_chunks`` over explicit
    timestamps.

    Parameters
    ----------
    start_ts : str
        ISO 8601 start timestamp (optional when relative params used).
    end_ts : str
        ISO 8601 end timestamp (optional when relative params used).
    last_minutes : int
        Look-back window in minutes from now.
    last_hours : int
        Look-back window in hours from now (convenience alias).
    last_chunks : int
        Return only the N most recent anomaly chunks (queries last 24 h).

    Returns
    -------
    dict
        ``{"ok": True, "chunks": list, "count": int}`` or error.
    """
    try:
        if last_chunks > 0:
            now = datetime.now(timezone.utc)
            resolved_start = (now - timedelta(hours=24)).isoformat()
            resolved_end = now.isoformat()
        else:
            resolved_start, resolved_end = _resolve_time_window(start_ts, end_ts, last_minutes, last_hours)
        resp = _get("/chunks", params={"start_ts": resolved_start, "end_ts": resolved_end, "format": "json"})
        resp.raise_for_status()
        all_chunks = resp.json()
        anomaly_chunks = [c for c in all_chunks if c.get("is_anomaly") is True]
        if last_chunks > 0:
            anomaly_chunks = _newest_chunks(anomaly_chunks, last_chunks)
        return {"ok": True, "chunks": anomaly_chunks, "count": len(anomaly_chunks)}
    except Exception as exc:
        err = {"ok": False, "error": f"pcap list_anomaly_chunks failed: {exc}"}
        logger.error("tools.pcap.list_anomaly_chunks error: {err}", err=err)
        return err


def get_chunks_by_alarm_id(alarm_id: str, last_hours: int = 24) -> Dict[str, Any]:
    """Return all PCAP chunks associated with a specific alarm ID.

    When the ML pipeline flags an anomaly, it archives matching PCAP chunks
    and attaches labels including ``alarm_id``.  This tool retrieves all
    chunks that share the same ``alarm_id``, making it easy to collect the
    full set of network captures for a given alarm.

    Internally queries all chunks in a broad time window and filters
    client-side for ``labels.alarm_id == alarm_id``.

    Parameters
    ----------
    alarm_id : str
        The alarm UUID to search for (e.g. ``"1088d146-d807-49d7-b10f-0dc7d7d918a9"``).
    last_hours : int
        How far back to search in hours (default 24).  Increase if the alarm
        may be older.

    Returns
    -------
    dict
        ``{"ok": True, "alarm_id": str, "chunks": list, "count": int}`` or error.
        Each chunk includes full metadata and labels.
    """
    try:
        # The PCAP-Recorder stores chunk timestamps as naive local time
        # in its ``index.json`` and compares incoming ``start_ts``/
        # ``end_ts`` parameters against those naive strings. Sending a
        # tz-aware UTC string (the obvious default) silently filters
        # everything out — see issue: alarm-flagged chunks remained
        # unreachable via this tool. We therefore convert to naive
        # local time before forwarding the request.
        now_local = datetime.now().astimezone().replace(tzinfo=None)
        resolved_start = (now_local - timedelta(hours=last_hours)).isoformat()
        resolved_end = now_local.isoformat()
        resp = _get(
            "/chunks",
            params={"start_ts": resolved_start, "end_ts": resolved_end, "format": "json"},
        )
        resp.raise_for_status()
        all_chunks = resp.json()
        matched = [c for c in all_chunks if (c.get("labels") or {}).get("alarm_id") == alarm_id]
        matched = sorted(matched, key=lambda c: c.get("start_ts", ""))
        return {
            "ok": True,
            "alarm_id": alarm_id,
            "chunks": matched,
            "count": len(matched),
        }
    except Exception as exc:
        err = {"ok": False, "error": f"pcap get_chunks_by_alarm_id failed: {exc}"}
        logger.error("tools.pcap.get_chunks_by_alarm_id error: {err}", err=err)
        return err


def get_chunk_meta(chunk_id: str) -> Dict[str, Any]:
    """Retrieve metadata for a single PCAP chunk.

    Parameters
    ----------
    chunk_id : str
        Chunk filename (e.g. ``20260225_133027.pcap``).

    Returns
    -------
    dict
        ``{"ok": True, "chunk": dict}`` or error.
    """
    try:
        resp = _get(_chunk_path(chunk_id), params={"format": "json"})
        resp.raise_for_status()
        chunk = resp.json()
        return {"ok": True, "chunk": chunk}
    except ChunkIdError as exc:
        return _invalid_chunk_id("get_chunk_meta", exc)
    except Exception as exc:
        err = {"ok": False, "error": f"pcap get_chunk_meta failed: {exc}"}
        logger.error("tools.pcap.get_chunk_meta error: {err}", err=err)
        return err


def read_chunk_text(chunk_id: str, max_lines: int = 50) -> Dict[str, Any]:
    """Read tcpdump plain-text output of a PCAP chunk.

    Parameters
    ----------
    chunk_id : str
        Chunk filename.
    max_lines : int
        Maximum lines to return (default 50).

    Returns
    -------
    dict
        ``{"ok": True, "text": str, "lines": int, "truncated": bool}`` or error.
    """
    try:
        resp = _get(_chunk_path(chunk_id), params={"format": "text"})
        resp.raise_for_status()
        text, total_lines, was_truncated = _truncate(resp.text, max_lines)
        return {"ok": True, "text": text, "lines": total_lines, "truncated": was_truncated}
    except ChunkIdError as exc:
        return _invalid_chunk_id("read_chunk_text", exc)
    except Exception as exc:
        err = {"ok": False, "error": f"pcap read_chunk_text failed: {exc}"}
        logger.error("tools.pcap.read_chunk_text error: {err}", err=err)
        return err


def analyze_chunk(chunk_id: str, tshark_args: str = "", max_lines: int = 200) -> Dict[str, Any]:
    """Run a tshark analysis on a PCAP chunk with freely configurable arguments.

    This is the most flexible analysis tool.  Pass any valid tshark arguments
    as a single string via *tshark_args*.  The pcap_recorder will execute
    ``tshark <tshark_args> -r <chunk>`` and return the output.

    tshark_args examples (pass as a single string):

    | Purpose                      | tshark_args value                                        |
    |------------------------------|----------------------------------------------------------|
    | First N packets summary      | "-c 50"                                                  |
    | Protocol hierarchy stats     | "-q -z io,phs" (prefer pcap.protocol_stats)              |
    | Ethernet conversations       | "-q -z conv,eth" (prefer pcap.conversations)             |
    | IP endpoints                 | "-q -z endpoints,ip"                                     |
    | I/O rate per second          | "-q -z io,stat,1" (prefer pcap.io_stats)                 |
    | Packet length distribution   | "-q -z plen,tree"                                        |
    | Only PROFINET RT packets     | "-Y pn_rt"                                               |
    | Only LLDP packets            | "-Y lldp"                                                |
    | Only HTTP traffic            | "-Y http"                                                |
    | Filter by MAC address        | "-Y eth.addr==aa:bb:cc:dd:ee:ff"                         |
    | TCP SYN (new connections)    | '-Y "tcp.flags.syn==1 and tcp.flags.ack==0"'             |
    | Extract specific fields      | "-T fields -e ip.src -e ip.dst -e frame.protocols"       |
    | Extract Info column          | "-T fields -e frame.number -e _ws.col.Info"              |
    | Time window within chunk     | '-Y "frame.time_relative>=0 and frame.time_relative<=5"' |
    |                              | (prefer pcap.inspect_timewindow)                         |
    | Filter + field extraction    | "-Y pn_rt -T fields -e pn_rt.frame_id -e pn_rt.cycle_counter" |

    Notes:
    - Filters with 'and'/'or' must be quoted in the tshark_args string.
    - A 30s chunk of an industrial network may contain ~37,000 packets.
      Use filters or statistics to keep output manageable.
    - Prefer dedicated tools (pcap.protocol_stats, pcap.conversations,
      pcap.io_stats, pcap.inspect_timewindow) for common analysis tasks.

    Parameters
    ----------
    chunk_id : str
        Chunk filename.
    tshark_args : str
        tshark CLI arguments as a single string (default: empty for verbose decode).
    max_lines : int
        Maximum output lines to return (default 200).

    Returns
    -------
    dict
        ``{"ok": True, "output": str, "lines": int, "truncated": bool}`` or error.
    """
    try:
        params: Dict[str, Any] = {"format": "detail"}
        if tshark_args:
            params["tshark_args"] = tshark_args
        resp = _get(_chunk_path(chunk_id), params=params)
        resp.raise_for_status()
        output, total_lines, was_truncated = _truncate(resp.text, max_lines)
        return {"ok": True, "output": output, "lines": total_lines, "truncated": was_truncated}
    except ChunkIdError as exc:
        return _invalid_chunk_id("analyze_chunk", exc)
    except Exception as exc:
        err = {"ok": False, "error": f"pcap analyze_chunk failed: {exc}"}
        logger.error("tools.pcap.analyze_chunk error: {err}", err=err)
        return err


def inspect_timewindow(
    chunk_id: str,
    start_sec: float = 0.0,
    end_sec: float = 5.0,
    max_lines: int = 100,
) -> Dict[str, Any]:
    """Inspect a time window within a PCAP chunk using standard field extraction.

    Builds a tshark display filter on ``frame.time_relative`` and extracts
    commonly useful fields: frame number, timestamp, source/destination MAC,
    protocol stack, and the Wireshark Info column.

    Parameters
    ----------
    chunk_id : str
        Chunk filename.
    start_sec : float
        Start offset in seconds relative to the chunk start (default 0.0).
    end_sec : float
        End offset in seconds relative to the chunk start (default 5.0).
    max_lines : int
        Maximum output lines to return (default 100).

    Returns
    -------
    dict
        ``{"ok": True, "output": str, "lines": int, "truncated": bool}`` or error.
    """
    try:
        display_filter = f'"frame.time_relative>={start_sec} and frame.time_relative<={end_sec}"'
        tshark_args = (
            f"-Y {display_filter} "
            "-T fields "
            "-e frame.number "
            "-e frame.time "
            "-e eth.src "
            "-e eth.dst "
            "-e frame.protocols "
            "-e _ws.col.Info"
        )
        params: Dict[str, Any] = {"format": "detail", "tshark_args": tshark_args}
        resp = _get(_chunk_path(chunk_id), params=params)
        resp.raise_for_status()
        output, total_lines, was_truncated = _truncate(resp.text, max_lines)
        return {"ok": True, "output": output, "lines": total_lines, "truncated": was_truncated}
    except ChunkIdError as exc:
        return _invalid_chunk_id("inspect_timewindow", exc)
    except Exception as exc:
        err = {"ok": False, "error": f"pcap inspect_timewindow failed: {exc}"}
        logger.error("tools.pcap.inspect_timewindow error: {err}", err=err)
        return err


def protocol_stats(chunk_id: str) -> Dict[str, Any]:
    """Retrieve the protocol hierarchy statistics for a PCAP chunk.

    Parameters
    ----------
    chunk_id : str
        Chunk filename.

    Returns
    -------
    dict
        ``{"ok": True, "output": str}`` or error.
    """
    try:
        params: Dict[str, Any] = {"format": "detail", "tshark_args": "-q -z io,phs"}
        resp = _get(_chunk_path(chunk_id), params=params)
        resp.raise_for_status()
        output = resp.text
        truncated = False
        original_length = len(output)
        if original_length > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + (
                f"\n\n... TRUNCATED ({original_length:,} chars total, " f"showing first {MAX_OUTPUT_CHARS:,})."
            )
            truncated = True
        result: Dict[str, Any] = {"ok": True, "output": output}
        if truncated:
            result["truncated"] = True
            result["original_length"] = original_length
        return result
    except ChunkIdError as exc:
        return _invalid_chunk_id("protocol_stats", exc)
    except Exception as exc:
        err = {"ok": False, "error": f"pcap protocol_stats failed: {exc}"}
        logger.error("tools.pcap.protocol_stats error: {err}", err=err)
        return err


def conversations(chunk_id: str, layer: str = "eth") -> Dict[str, Any]:
    """Retrieve conversation statistics for a PCAP chunk.

    Parameters
    ----------
    chunk_id : str
        Chunk filename.
    layer : str
        Network layer for conversation grouping — one of
        :data:`validation.CONVERSATION_LAYERS` (``"eth"``, ``"ip"``,
        ``"tcp"``, ``"udp"``; default ``"eth"``). The value is inlined
        into the tshark argument string, so anything outside that set is
        rejected before the request is built (audit MCP-017).

    Returns
    -------
    dict
        ``{"ok": True, "output": str}`` or error.
    """
    try:
        safe_layer = ensure_conversation_layer(layer)
        tshark_args = f"-q -z conv,{safe_layer}"
        params: Dict[str, Any] = {"format": "detail", "tshark_args": tshark_args}
        resp = _get(_chunk_path(chunk_id), params=params)
        resp.raise_for_status()
        output = resp.text
        truncated = False
        original_length = len(output)
        if original_length > MAX_OUTPUT_CHARS:
            lines = output.split("\n")
            header = "\n".join(lines[:5])
            remaining = MAX_OUTPUT_CHARS - len(header) - 200
            body = output[len(header) : len(header) + max(0, remaining)]
            output = (
                f"{header}\n{body}\n\n"
                f"... TRUNCATED ({original_length:,} chars total, "
                f"showing first {MAX_OUTPUT_CHARS:,}). "
                f"Too many conversations for layer '{safe_layer}'. "
                "Try layer='ip' for a more compact view, or use "
                "pcap.io_stats for aggregate rates."
            )
            truncated = True
        result: Dict[str, Any] = {"ok": True, "output": output}
        if truncated:
            result["truncated"] = True
            result["original_length"] = original_length
        return result
    except ConversationLayerError as exc:
        err = {"ok": False, "error": str(exc)}
        logger.warning("tools.pcap.conversations rejected layer: {err}", err=err)
        return err
    except ChunkIdError as exc:
        return _invalid_chunk_id("conversations", exc)
    except Exception as exc:
        err = {"ok": False, "error": f"pcap conversations failed: {exc}"}
        logger.error("tools.pcap.conversations error: {err}", err=err)
        return err


def io_stats(chunk_id: str, interval_sec: int = 1, filter: str = "") -> Dict[str, Any]:
    """Retrieve I/O rate statistics for a PCAP chunk.

    Parameters
    ----------
    chunk_id : str
        Chunk filename.
    interval_sec : int
        Time interval in seconds for the rate calculation (default 1).
    filter : str
        Optional Wireshark display filter (e.g. ``"pn_rt"``).

    Returns
    -------
    dict
        ``{"ok": True, "output": str}`` or error.
    """
    try:
        # Clamp interval to at least 1s to prevent excessive output rows.
        interval_sec = max(1, int(interval_sec))
        tshark_args = f"-q -z io,stat,{interval_sec}"
        if filter:
            tshark_args += f",{filter}"
        params: Dict[str, Any] = {"format": "detail", "tshark_args": tshark_args}
        resp = _get(_chunk_path(chunk_id), params=params)
        resp.raise_for_status()
        output = resp.text
        truncated = False
        original_length = len(output)
        if original_length > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + (
                f"\n\n... TRUNCATED ({original_length:,} chars total, "
                f"showing first {MAX_OUTPUT_CHARS:,}). "
                "Try a larger interval_sec."
            )
            truncated = True
        result: Dict[str, Any] = {"ok": True, "output": output}
        if truncated:
            result["truncated"] = True
            result["original_length"] = original_length
        return result
    except ChunkIdError as exc:
        return _invalid_chunk_id("io_stats", exc)
    except Exception as exc:
        err = {"ok": False, "error": f"pcap io_stats failed: {exc}"}
        logger.error("tools.pcap.io_stats error: {err}", err=err)
        return err


def flag_anomaly(
    start_ts: str,
    end_ts: str,
    labels: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Flag a time window as anomaly in the pcap_recorder.

    Matching chunks are moved from the ring buffer to the archive directory.

    Parameters
    ----------
    start_ts : str
        ISO 8601 start timestamp.
    end_ts : str
        ISO 8601 end timestamp.
    labels : dict, optional
        Arbitrary labels to attach (e.g. ``{"reason": "...", "uci": "..."}``).

    Returns
    -------
    dict
        ``{"ok": True, "chunk_ids": list, "count": int}`` or error.
    """
    try:
        body: Dict[str, Any] = {"start_ts": start_ts, "end_ts": end_ts}
        if labels:
            body["labels"] = labels
        resp = _post("/anomalies/flag", json_body=body)
        resp.raise_for_status()
        data = resp.json()
        chunk_ids = data.get("chunk_ids", [])
        return {"ok": True, "chunk_ids": chunk_ids, "count": len(chunk_ids)}
    except Exception as exc:
        err = {"ok": False, "error": f"pcap flag_anomaly failed: {exc}"}
        logger.error("tools.pcap.flag_anomaly error: {err}", err=err)
        return err
