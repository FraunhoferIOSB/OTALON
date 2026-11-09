"""Declarative input constraints for the MCP tool surface (audit QUA-11 / QUA-07).

Every tool handler in :mod:`mcp_tools` takes its arguments straight from
LLM-controlled JSON. Before this module the parameters were bare ``int`` /
``str`` annotations, so ``limit=-5`` or ``minutes=-1`` travelled unchecked
into the PostgreSQL / InfluxDB layer (QUA-11) and a ``chunk_id`` of
``"../status"`` escaped the recorder's ``/chunks/`` namespace (QUA-07).

The bounds are expressed as :pep:`593` ``Annotated`` aliases carrying a
Pydantic ``Field``. FastMCP builds each tool's published input schema from
the handler signature, so a constraint declared here is BOTH advertised to
the model (``minimum`` / ``maximum`` / ``pattern`` in ``inputSchema``) and
enforced by Pydantic before the handler body runs. Out-of-range input
raises a validation error; nothing is silently clamped.

Caps are deliberately generous: they are 50-500x the shipped defaults so
no realistic operator query is rejected, while still keeping an
adversarial value from reaching a database or a URL path.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal, Optional

from pydantic import Field

# ── Numeric ceilings ────────────────────────────────────────────────────

MAX_ROW_LIMIT: int = 100_000
"""Upper bound for row ``limit`` parameters (defaults in use: 5-200)."""

MAX_ROW_OFFSET: int = 10_000_000
"""Upper bound for pagination ``offset``.

Set an order of magnitude above the largest live table (``anomalies``,
~1.4M rows) so paging never hits the ceiling.
"""

MAX_WINDOW_MINUTES: int = 527_040
"""366 days in minutes — ceiling for every minutes-shaped look-back."""

MAX_WINDOW_HOURS: int = 8_784
"""366 days in hours — ceiling for every hours-shaped look-back."""

MAX_CHUNK_COUNT: int = 100_000
"""Upper bound for ``last_chunks`` (live recorder holds ~11.7k chunks)."""

MAX_OUTPUT_LINES: int = 100_000
"""Upper bound for ``max_lines`` (defaults 50/100/200); output is also
character-bounded by ``tools.pcap.MAX_OUTPUT_CHARS``."""

MAX_TOP_K: int = 1_000
"""Upper bound for top-k aggregations (default 10)."""

MAX_SEARCH_RESULTS: int = 50
"""Upper bound for web-search result counts (default 6)."""

MAX_SAMPLE_POINTS: int = 1_000_000
"""Upper bound for time-series down-sampling targets (default 1000)."""

MAX_QUERY_CHUNK_SIZE: int = 1_000_000
"""Upper bound for the Influx multi-id query chunk size (default 5000)."""

MAX_INTERVAL_SECONDS: int = 3_600
"""Upper bound for tshark I/O-stat bucket width (default 1; chunks are 30s)."""

MAX_OFFSET_SECONDS: float = 86_400.0
"""Upper bound for in-chunk time offsets (default window 0.0-5.0s)."""

MAX_TIMEOUT_SECONDS: int = 3_600
"""Upper bound for subagent job timeouts (default 600)."""

MAX_ROW_ID: int = 2_147_483_647
"""PostgreSQL ``integer`` ceiling for surrogate primary keys."""

MAX_MITRE_LIMIT: int = 1_000
"""Upper bound for MITRE result counts (the ICS bundle holds 95 techniques)."""

# ── Identifier formats ──────────────────────────────────────────────────

CHUNK_ID_PATTERN: str = r"^\d{8}_\d{6}\.pcap(?:\.l\d{1,2})?(?:\.(?:gz|zst))?$"
"""Exact shape of a pcap_recorder chunk identifier.

The recorder names chunks from ``tcpdump -w %Y%m%d_%H%M%S.pcap`` (see
``otalon-capture/src/pcap_recorder/recorder.py``) and indexes them by bare
filename. Archived chunks may additionally carry a compression suffix
(``.gz``, ``.zst``, ``.lNN.zst``). Anchoring the pattern is what stops
``"../status"`` or ``"/health"`` from being interpolated into
``/chunks/{chunk_id}`` and reaching an unrelated recorder endpoint.
"""

CHUNK_ID_RE = re.compile(CHUNK_ID_PATTERN)
"""Compiled form of :data:`CHUNK_ID_PATTERN`."""

CHUNK_ID_MAX_LENGTH: int = 64
"""Generous length ceiling; the longest live identifier is 28 characters."""


class ChunkIdError(ValueError):
    """Raised when a chunk identifier is not a plain recorder chunk name."""


def ensure_chunk_id(value: str, param_name: str = "chunk_id") -> str:
    """Return ``value`` if it is a plain chunk identifier, else raise.

    This is the last line of defence for QUA-07: the helpers in
    :mod:`tools.pcap` interpolate the identifier into the request path
    (``/chunks/{chunk_id}``), and ``requests`` normalises ``..`` segments
    before sending, so an unvalidated value reaches arbitrary recorder
    endpoints. Callers that build a URL path MUST route the identifier
    through this function.

    Args:
        value: The candidate chunk identifier.
        param_name: Parameter name used in the error message.

    Returns:
        The stripped, validated identifier.

    Raises:
        ChunkIdError: If the value is empty, over-long, or does not match
            :data:`CHUNK_ID_PATTERN`.
    """
    candidate = (value or "").strip()
    if not candidate:
        raise ChunkIdError(f"Invalid {param_name}: must not be empty.")
    if len(candidate) > CHUNK_ID_MAX_LENGTH:
        raise ChunkIdError(
            f"Invalid {param_name}: {len(candidate)} characters exceeds the " f"{CHUNK_ID_MAX_LENGTH}-character limit."
        )
    if not CHUNK_ID_RE.match(candidate):
        raise ChunkIdError(
            f"Invalid {param_name}: {candidate!r} is not a chunk identifier. "
            "Expected 'YYYYMMDD_HHMMSS.pcap' (optionally '.gz' / '.zst'), "
            "e.g. '20260225_133027.pcap'. Path segments such as '..' or a "
            "leading '/' are rejected."
        )
    return candidate


# ── Annotated parameter aliases ─────────────────────────────────────────

LimitParam = Annotated[int, Field(ge=1, le=MAX_ROW_LIMIT)]
"""Row limit: at least one row, capped at :data:`MAX_ROW_LIMIT`."""

OptionalLimitParam = Annotated[Optional[int], Field(ge=1, le=MAX_ROW_LIMIT)]
"""Row limit where ``None`` means "no explicit limit"."""

OffsetParam = Annotated[int, Field(ge=0, le=MAX_ROW_OFFSET)]
"""Pagination offset: zero-based, capped at :data:`MAX_ROW_OFFSET`."""

MinutesParam = Annotated[int, Field(ge=1, le=MAX_WINDOW_MINUTES)]
"""Look-back window in minutes; must select a non-empty range."""

RelativeMinutesParam = Annotated[int, Field(ge=0, le=MAX_WINDOW_MINUTES)]
"""Look-back window in minutes where ``0`` disables the relative filter."""

OptionalRelativeMinutesParam = Annotated[Optional[int], Field(ge=0, le=MAX_WINDOW_MINUTES)]
"""Optional minutes look-back; ``None`` disables the relative filter."""

HoursParam = Annotated[int, Field(ge=1, le=MAX_WINDOW_HOURS)]
"""Look-back window in hours; must select a non-empty range."""

RelativeHoursParam = Annotated[int, Field(ge=0, le=MAX_WINDOW_HOURS)]
"""Look-back window in hours where ``0`` disables the relative filter."""

OptionalRelativeHoursParam = Annotated[Optional[int], Field(ge=0, le=MAX_WINDOW_HOURS)]
"""Optional hours look-back; ``None`` disables the relative filter."""

ChunkCountParam = Annotated[int, Field(ge=0, le=MAX_CHUNK_COUNT)]
"""Newest-N chunk selector where ``0`` means "no count filter"."""

OptionalChunkCountParam = Annotated[Optional[int], Field(ge=0, le=MAX_CHUNK_COUNT)]
"""Optional newest-N chunk selector; ``None`` means "no count filter"."""

MaxLinesParam = Annotated[int, Field(ge=1, le=MAX_OUTPUT_LINES)]
"""Maximum output lines returned to the model."""

TopKParam = Annotated[int, Field(ge=1, le=MAX_TOP_K)]
"""Top-k aggregation size."""

MitreLimitParam = Annotated[int, Field(ge=1, le=MAX_MITRE_LIMIT)]
"""MITRE result count."""

OptionalMitreLimitParam = Annotated[Optional[int], Field(ge=1, le=MAX_MITRE_LIMIT)]
"""Optional MITRE result count; ``None`` returns every match."""

SearchResultsParam = Annotated[int, Field(ge=1, le=MAX_SEARCH_RESULTS)]
"""Web-search result count."""

OptionalSamplePointsParam = Annotated[Optional[int], Field(ge=1, le=MAX_SAMPLE_POINTS)]
"""Down-sampling target; ``None`` disables down-sampling."""

QueryChunkSizeParam = Annotated[int, Field(ge=1, le=MAX_QUERY_CHUNK_SIZE)]
"""Batch size for chunked multi-series Influx reads."""

IntervalSecondsParam = Annotated[int, Field(ge=1, le=MAX_INTERVAL_SECONDS)]
"""tshark I/O-stat bucket width in seconds."""

OffsetSecondsParam = Annotated[float, Field(ge=0.0, le=MAX_OFFSET_SECONDS)]
"""Time offset in seconds relative to the start of a chunk."""

TimeoutSecondsParam = Annotated[int, Field(ge=1, le=MAX_TIMEOUT_SECONDS)]
"""Subagent job timeout in seconds."""

RowIdParam = Annotated[int, Field(ge=1, le=MAX_ROW_ID)]
"""Surrogate primary key of a ``devices`` / ``network_interfaces`` row."""

OptionalRowIdParam = Annotated[Optional[int], Field(ge=1, le=MAX_ROW_ID)]
"""Optional surrogate primary key; ``None`` means "no filter"."""

DeviceFilterIdParam = Annotated[Optional[int], Field(ge=0, le=MAX_ROW_ID)]
"""Device filter for ``postgres.list_interfaces``.

``None`` lists every interface and the sentinel ``0`` selects the orphan
set (``device_id IS NULL``), so unlike :data:`OptionalRowIdParam` this
alias admits zero.
"""

ChunkIdParam = Annotated[
    str,
    Field(max_length=CHUNK_ID_MAX_LENGTH, pattern=CHUNK_ID_PATTERN),
]
"""Recorder chunk identifier interpolated into a ``/chunks/{id}`` path."""

OptionalChunkIdParam = Annotated[
    Optional[str],
    Field(max_length=CHUNK_ID_MAX_LENGTH, pattern=CHUNK_ID_PATTERN),
]
"""Optional chunk identifier; ``None`` selects a chunk automatically."""

CONVERSATION_LAYERS: frozenset[str] = frozenset({"eth", "ip", "tcp", "udp"})
"""tshark conversation layers the recorder's ``-z conv,<layer>`` accepts.

The MCP tool schema constrains ``layer`` through
:data:`ConversationLayer`, but ``tools.pcap.conversations`` is also
callable directly, and it interpolates the value into the tshark
argument string. The runtime allow-list is the guard that stops a
crafted value from adding arguments of its own (audit MCP-017); the
member set mirrors ``pcap_recorder.tshark_args`` minus ``ipv6``, which
the recorder accepts but this tool has never advertised.
"""

ConversationLayer = Literal["eth", "ip", "tcp", "udp"]
"""tshark conversation-statistics layer accepted by the recorder."""


class ConversationLayerError(ValueError):
    """Raised when a conversation layer is not in :data:`CONVERSATION_LAYERS`."""


def ensure_conversation_layer(value: str, param_name: str = "layer") -> str:
    """Return ``value`` if it is an allow-listed conversation layer, else raise.

    Args:
        value: Candidate layer name.
        param_name: Parameter name used in the error message.

    Returns:
        The stripped, validated layer name.

    Raises:
        ConversationLayerError: If the value is not a member of
            :data:`CONVERSATION_LAYERS`.
    """
    candidate = (value or "").strip()
    if candidate not in CONVERSATION_LAYERS:
        raise ConversationLayerError(
            f"Invalid {param_name}: {value!r} is not a conversation layer. "
            f"Expected one of {sorted(CONVERSATION_LAYERS)}."
        )
    return candidate


PromptVariant = Literal["open", "expert"]
"""Subagent prompt variant (``expert`` is the paper-validated default)."""


__all__ = [
    "CHUNK_ID_MAX_LENGTH",
    "CHUNK_ID_PATTERN",
    "CHUNK_ID_RE",
    "CONVERSATION_LAYERS",
    "ChunkCountParam",
    "ChunkIdError",
    "ChunkIdParam",
    "ConversationLayer",
    "ConversationLayerError",
    "DeviceFilterIdParam",
    "HoursParam",
    "IntervalSecondsParam",
    "LimitParam",
    "MAX_CHUNK_COUNT",
    "MAX_INTERVAL_SECONDS",
    "MAX_MITRE_LIMIT",
    "MAX_OFFSET_SECONDS",
    "MAX_OUTPUT_LINES",
    "MAX_QUERY_CHUNK_SIZE",
    "MAX_ROW_ID",
    "MAX_ROW_LIMIT",
    "MAX_ROW_OFFSET",
    "MAX_SAMPLE_POINTS",
    "MAX_SEARCH_RESULTS",
    "MAX_TIMEOUT_SECONDS",
    "MAX_TOP_K",
    "MAX_WINDOW_HOURS",
    "MAX_WINDOW_MINUTES",
    "MaxLinesParam",
    "MinutesParam",
    "MitreLimitParam",
    "OffsetParam",
    "OffsetSecondsParam",
    "OptionalChunkCountParam",
    "OptionalChunkIdParam",
    "OptionalLimitParam",
    "OptionalMitreLimitParam",
    "OptionalRelativeHoursParam",
    "OptionalRelativeMinutesParam",
    "OptionalRowIdParam",
    "OptionalSamplePointsParam",
    "PromptVariant",
    "QueryChunkSizeParam",
    "RelativeHoursParam",
    "RelativeMinutesParam",
    "RowIdParam",
    "SearchResultsParam",
    "TimeoutSecondsParam",
    "TopKParam",
    "ensure_chunk_id",
    "ensure_conversation_layer",
]
