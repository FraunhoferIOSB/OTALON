"""Unified MCP tools module for OTALON.

This file consolidates all @mcp.tool-decorated functions into a single module.
Each tool function delegates to helper logic in tools/* modules and
uses injected repository instances and default configuration provided by the server.

Server is expected to:
- Read settings (Postgres DSN, Influx URL/token) directly in server.py
- Construct PostgresRepo and InfluxRepo instances
- Provide default measurement/id_tag/field configuration
- Call init_mcp_tools(mcp, pg_repo, influx_repo, defaults)

Docstrings are written in English as per workspace rules.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import re
import typing
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from loguru import logger
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

import otalon_mcp.tools.agent as agent_tools
import otalon_mcp.tools.baseline as baseline_tools
import otalon_mcp.tools.core as core_tools
import otalon_mcp.tools.frequency as frequency_tools
import otalon_mcp.tools.influx as influx_tools
import otalon_mcp.tools.mitre as mitre_tools
import otalon_mcp.tools.pcap as pcap_tools
import otalon_mcp.tools.postgres as pg_tools
import otalon_mcp.tools.training as training_tools
import otalon_mcp.tools.web as web_tools
from otalon_mcp.repositories.influx_repo import InfluxRepo
from otalon_mcp.repositories.postgres_repo import PostgresRepo

# Helper modules for actual implementations
from otalon_mcp.tools import init as tools_init
from otalon_mcp.validation import (
    ChunkCountParam,
    ChunkIdParam,
    ConversationLayer,
    DeviceFilterIdParam,
    IntervalSecondsParam,
    LimitParam,
    MaxLinesParam,
    MinutesParam,
    MitreLimitParam,
    OffsetParam,
    OffsetSecondsParam,
    OptionalChunkCountParam,
    OptionalChunkIdParam,
    OptionalLimitParam,
    OptionalMitreLimitParam,
    OptionalRelativeHoursParam,
    OptionalRelativeMinutesParam,
    OptionalRowIdParam,
    OptionalSamplePointsParam,
    PromptVariant,
    QueryChunkSizeParam,
    RelativeHoursParam,
    RelativeMinutesParam,
    RowIdParam,
    SearchResultsParam,
    TimeoutSecondsParam,
    TopKParam,
)

# Two accepted ID shapes for `postgres.read_alarm_details` and friends:
# - 36-char canonical UUID with dashes (8-4-4-4-12), used by `subagent_jobs`
#   and `baselines` tables in the live system.
# - 32-char hex string without dashes, used as the primary key of the
#   `alarms` table (Cyberclas-ICS legacy format, see ``alarms.id`` schema:
#   ``character varying``). The live UI surfaces alarm-ids in this shape.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX32_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)


def _validate_uuid(value: Optional[str], param_name: str = "id") -> Optional[Dict[str, Any]]:
    """Validate that a value is a recognisable ID and return an error dict if not.

    Accepts EITHER a canonical UUID (36 chars with dashes) OR a 32-character
    hex string without dashes (the format used by ``alarms.id`` in the live
    OTALON deployment). Returns ``None`` for valid values or empty
    input (caller treats empty as optional). Returns ``{"ok": False, ...}``
    with a descriptive hint when the value is malformed so the LLM can
    self-correct without further round-trips.
    """
    if not value:
        return None
    candidate = value.strip()
    if _UUID_RE.match(candidate) or _HEX32_RE.match(candidate):
        return None
    length = len(candidate)
    if length not in (32, 36):
        hint = (
            f" The provided value has {length} characters; expected either a "
            f"32-char hex string (alarms.id format) or a 36-char canonical UUID "
            f"with dashes (8-4-4-4-12)."
        )
    elif length == 36:
        hint = " 36 chars but not a canonical UUID. Verify the dash positions (8-4-4-4-12)."
    else:  # length == 32 but contains non-hex
        hint = " 32 chars but contains non-hex characters. Use only [0-9a-f]."
    return {
        "ok": False,
        "error": f"Invalid ID for parameter '{param_name}': '{candidate}'.{hint}",
    }


@dataclass(frozen=True)
class Defaults:
    """Default configuration passed from server to tools."""

    measurement: str = "network_metrics"
    id_tag: str = "uci"
    fields: List[str] = field(
        default_factory=lambda: [
            "packet_count",
            "total_volume",
            "mean_packet_size",
            "min_packet_size",
            "max_packet_size",
            "std_packet_size",
            "mean_interarrival_time",
            "min_interarrival_time",
            "max_interarrival_time",
            "std_interarrival_time",
        ]
    )


_DESTRUCTIVE_TOOLS: frozenset[str] = frozenset(
    {
        "postgres.replace_bounds",
        "postgres.delete_device",
        "postgres.delete_interface",
        "postgres.remove_anomaly_suppression",
        "pcap.flag_anomaly",
        "mitre.update_stix_data",
    }
)
"""Tools that overwrite or remove existing state.

``replace_bounds`` can NARROW thresholds (unlike ``expand_bounds``),
``delete_*`` remove rows, ``remove_anomaly_suppression`` lifts an
operator decision, ``flag_anomaly`` mutates recorder-side chunk labels
and ``update_stix_data`` overwrites the local STIX bundle from a remote
fetch. Everything else either only reads or only adds (audit MCP-07).
"""

_NON_IDEMPOTENT_TOOLS: frozenset[str] = frozenset(
    {
        "postgres.add_device",
        "postgres.add_interface",
        "postgres.expand_bounds",
        "pcap.flag_anomaly",
        "agent.classify_alert",
        "chat",
        "training.retrain_boundaries",
        "training.retrain_classifier",
        "correct_rhythm_profile",
        "mitre.update_stix_data",
        "core.web_search_duckduckgo",
    }
)
"""Mutating tools whose repetition changes the outcome.

``add_*`` insert a new row per call, ``expand_bounds`` widens cumulatively,
``retrain_*`` enqueue a fresh job, and the LLM/search-backed tools are
non-deterministic. The remaining mutators (``write_bounds``,
``replace_bounds``, ``update_*``, ``delete_*``,
``add_anomaly_suppression``, ``remove_anomaly_suppression``) converge on
the same state when repeated and are therefore idempotent.
"""

_OPEN_WORLD_TOOLS: frozenset[str] = frozenset(
    {
        "core.web_search_duckduckgo",
        "mitre.update_stix_data",
        "chat",
        "agent.classify_alert",
    }
)
"""Tools that reach outside the closed OTALON deployment."""


def _tool_annotations(name: str, *, read_only: bool) -> ToolAnnotations:
    """Build the MCP annotations advertised for one tool.

    Args:
        name: Registered tool name (e.g. ``"postgres.read_alarms"``).
        read_only: Whether the tool only reads state.

    Returns:
        Populated :class:`ToolAnnotations`. Read-only tools are always
        non-destructive and idempotent; mutating tools consult
        :data:`_DESTRUCTIVE_TOOLS` and :data:`_NON_IDEMPOTENT_TOOLS`.
    """
    if read_only:
        return ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=name in _OPEN_WORLD_TOOLS,
        )
    return ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=name in _DESTRUCTIVE_TOOLS,
        idempotentHint=name not in _NON_IDEMPOTENT_TOOLS,
        openWorldHint=name in _OPEN_WORLD_TOOLS,
    )


def _register(mcp: FastMCP, name: str, *, read_only: bool) -> Callable[[Any], Any]:
    """Register a synchronous tool handler as a non-blocking async tool.

    Every handler in this module delegates to a helper that performs
    blocking IO (PostgreSQL, InfluxDB, the PCAP recorder REST API, the
    agent/API HTTP calls). Registering them as plain ``def`` made the MCP
    server run them directly on the event loop, so one slow query stalled
    every other in-flight request (audit MCP-05). This wrapper registers
    an ``async`` shim that offloads the call via
    :func:`asyncio.to_thread`, while ``functools.wraps`` preserves the
    signature and docstring FastMCP uses to build the tool schema.

    The undecorated function is returned so the module-local name still
    refers to the plain callable, which keeps the existing test harness
    (which invokes registered tools synchronously) working.

    Args:
        mcp: The FastMCP instance to register on.
        name: Tool name to expose.
        read_only: Whether the tool only reads state; drives the
            advertised annotations (audit MCP-07).

    Returns:
        A decorator that registers the handler and returns it unchanged.
    """
    annotations = _tool_annotations(name, read_only=read_only)

    def decorator(fn: Any) -> Any:
        @functools.wraps(fn)
        async def _async_tool(*args: Any, **kwargs: Any) -> Any:
            return await asyncio.to_thread(fn, *args, **kwargs)

        _apply_resolved_signature(_async_tool, fn)
        mcp.tool(name, annotations=annotations)(_async_tool)
        return fn

    return decorator


def _apply_resolved_signature(wrapper: Any, fn: Any) -> None:
    """Give ``wrapper`` ``fn``'s signature with real (non-string) annotations.

    This module uses ``from __future__ import annotations``, so every
    annotation is a string at runtime. FastMCP introspects the handler
    with ``issubclass(param.annotation, Context)`` to find an optional
    context parameter, which raises ``TypeError`` on a string — so tool
    registration against a real ``FastMCP`` fails outright. (This is a
    latent defect that predates MCP-013; the test suite's ``FakeMCP``
    never introspected the handler, so it went unnoticed.)

    Setting ``__signature__`` explicitly is required because
    :func:`inspect.signature` otherwise follows ``__wrapped__`` (set by
    :func:`functools.wraps`) straight back to the unresolved original.

    ``include_extras=True`` keeps the :pep:`593` metadata attached to the
    annotations. FastMCP derives every tool's published input schema from
    this signature, so dropping the extras would erase the Pydantic
    ``Field`` bounds declared in :mod:`validation` — the schema would omit
    ``minimum`` / ``maximum`` / ``pattern`` and nothing would be enforced
    (audit QUA-11, QUA-07).

    Args:
        wrapper: The async wrapper being registered.
        fn: The original synchronous handler.
    """
    try:
        hints = typing.get_type_hints(fn, include_extras=True)
    except Exception:  # pragma: no cover - defensive, unresolved forward ref
        logger.warning(
            "could not resolve type hints for {name}; registering as-is",
            name=getattr(fn, "__name__", fn),
        )
        return

    signature = inspect.signature(fn)
    parameters = [
        param.replace(annotation=hints.get(param.name, param.annotation)) for param in signature.parameters.values()
    ]
    wrapper.__signature__ = signature.replace(
        parameters=parameters,
        return_annotation=hints.get("return", signature.return_annotation),
    )
    wrapper.__annotations__ = dict(hints)


def init_mcp_tools(
    mcp: FastMCP,
    pg_repo: PostgresRepo,
    influx_repo: InfluxRepo,
    defaults: Defaults,
    pcap_url: str = "",
    pcap_timeout: int = 30,
    pcap_api_key: str = "",
    stix_path: str = "",
    agent_url: str = "",
    agent_timeout: float = 5.0,
    pg_dsn: str = "",
    baseline_dir: str = "/app/pcap/baseline",
    api_url: str = "",
    api_key: str = "",
    api_timeout: float = 10.0,
    confirm_nonce_ttl: float = 300.0,
) -> None:
    """Register all tools on the given MCP instance and wire helper modules."""

    # Initialize helper modules with dependencies
    tools_init(
        pg_repo=pg_repo,
        influx_repo=influx_repo,
        defaults=defaults,
        pcap_url=pcap_url,
        pcap_timeout=pcap_timeout,
        pcap_api_key=pcap_api_key,
        stix_path=stix_path,
        agent_url=agent_url,
        agent_timeout=agent_timeout,
        pg_dsn=pg_dsn,
        baseline_dir=baseline_dir,
        api_url=api_url,
        api_key=api_key,
        api_timeout=api_timeout,
        confirm_nonce_ttl=confirm_nonce_ttl,
    )

    @_register(mcp, "core.ping", read_only=True)
    def core_ping() -> Dict[str, Any]:
        """Ping the MCP server to verify reachability."""
        logger.debug("core.ping called")
        tool_result = core_tools.ping()
        logger.debug("core.ping returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "core.capabilities", read_only=True)
    def core_capabilities() -> Dict[str, Any]:
        """List capability groups and current default configuration."""
        logger.debug("core.capabilities called")
        tool_result = core_tools.capabilities()
        logger.debug("core.capabilities returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "core.web_search_duckduckgo", read_only=False)
    def core_web_search_duckduckgo(
        query: str,
        max_results: SearchResultsParam = 6,
    ) -> Dict[str, Any]:
        """Perform a web search using DuckDuckGo and return the top results."""
        logger.debug(
            "core.web_search_duckduckgo called with query={query}, max_results={max_results}",
            query=query,
            max_results=max_results,
        )
        tool_result = web_tools.web_search_duckduckgo(query=query, max_results=max_results)
        logger.debug(
            "core.web_search_duckduckgo returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "influx.list_recent_time_series_ids", read_only=True)
    def influx_list_recent_time_series_ids(
        measurement: Optional[str] = None,
        id_tag: Optional[str] = None,
        minutes: MinutesParam = 10,
    ) -> Dict[str, Any]:
        """List distinct time series IDs observed in the last N minutes."""
        logger.debug(
            "influx.list_recent_time_series_ids called with "
            "measurement={measurement}, id_tag={id_tag}, minutes={minutes}",
            measurement=measurement,
            id_tag=id_tag,
            minutes=minutes,
        )
        tool_result = influx_tools.list_recent_time_series_ids(measurement, id_tag, minutes)
        logger.debug(
            "influx.list_recent_time_series_ids returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "influx.list_time_series", read_only=True)
    def influx_list_time_series(
        start: Optional[str] = None,
        stop: Optional[str] = None,
        measurement: Optional[str] = None,
        id_tag: Optional[str] = None,
        nonzero: bool = False,
        fields: Optional[List[str]] = None,
        threshold: Optional[float] = 0.0,
        default_window_minutes: MinutesParam = 60,
    ) -> Dict[str, Any]:
        """List distinct time series IDs (UCIs) observed between two timestamps.

        Returns UCIs in the format ``"srcMAC/dstMAC/VLAN/IPv4/srcIP/dstIP/srcPort/dstPort/Protocols"``.
        Use ``start``/``stop`` (ISO-8601 UTC) to define the time window — alarm
        timestamps from ``postgres.read_alarms`` can be passed directly. If
        omitted, defaults to the last ``default_window_minutes``.
        Set ``nonzero=True`` to only return series whose summed ``fields`` exceed
        ``threshold`` in the window. The ``measurement``, ``id_tag``, and
        ``fields`` parameters have sensible defaults and rarely need to be changed."""
        logger.debug(
            "influx.list_time_series called with start={start}, stop={stop}, "
            "measurement={measurement}, id_tag={id_tag}, nonzero={nonzero}, "
            "fields={fields}, threshold={threshold}, "
            "default_window_minutes={default_window_minutes}",
            start=start,
            stop=stop,
            measurement=measurement,
            id_tag=id_tag,
            nonzero=nonzero,
            fields=fields,
            threshold=threshold,
            default_window_minutes=default_window_minutes,
        )
        tool_result = influx_tools.list_time_series(
            start=start,
            stop=stop,
            measurement=measurement,
            id_tag=id_tag,
            nonzero=nonzero,
            fields=fields,
            threshold=threshold,
            default_window_minutes=default_window_minutes,
        )
        logger.debug("influx.list_time_series returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "influx.read_single_time_series", read_only=True)
    def influx_read_single_time_series(
        series_id: str,
        fields: Optional[List[str]] = None,
        start: Optional[str] = None,
        stop: Optional[str] = None,
        measurement: Optional[str] = None,
        id_tag: Optional[str] = None,
        tags: Optional[Dict[str, str | int | float | bool]] = None,
        limit: OptionalLimitParam = None,
        aggregate: Optional[str | Dict[str, str]] = "avg",
        sample_max_points: OptionalSamplePointsParam = 1000,
        preserve_extrema: bool = True,
        default_window_minutes: MinutesParam = 60,
    ) -> Dict[str, Any]:
        """Read a single time series for the given series_id.

        ``series_id`` is a UCI (Unique Connection Identifier) in the format
        ``"srcMAC/dstMAC/VLAN/IPv4/srcIP/dstIP/srcPort/dstPort/Protocols"``.
        Copy UCIs from alarm ``series_ids`` or from ``influx.list_time_series``.
        Available metrics (pass via ``fields`` to subset; default = all):
        ``packet_count``, ``total_volume``,
        ``mean_packet_size`` / ``min_packet_size`` / ``max_packet_size`` / ``std_packet_size``,
        ``mean_interarrival_time`` / ``min_interarrival_time`` /
        ``max_interarrival_time`` / ``std_interarrival_time``.
        ``start``/``stop`` are ISO-8601 UTC timestamps — pass alarm timestamps
        directly. If omitted, defaults to the last ``default_window_minutes``.
        Parameters ``measurement``, ``id_tag``, ``tags``, ``aggregate``,
        ``sample_max_points``, and ``preserve_extrema`` have sensible defaults
        and rarely need to be changed."""
        logger.debug(
            "influx.read_single_time_series called with series_id={series_id}, "
            "fields={fields}, start={start}, stop={stop}, "
            "measurement={measurement}, id_tag={id_tag}, tags={tags}, "
            "limit={limit}, aggregate={aggregate}, "
            "sample_max_points={sample_max_points}, "
            "preserve_extrema={preserve_extrema}, "
            "default_window_minutes={default_window_minutes}",
            series_id=series_id,
            fields=fields,
            start=start,
            stop=stop,
            measurement=measurement,
            id_tag=id_tag,
            tags=tags,
            limit=limit,
            aggregate=aggregate,
            sample_max_points=sample_max_points,
            preserve_extrema=preserve_extrema,
            default_window_minutes=default_window_minutes,
        )
        tool_result = influx_tools.read_single_time_series(
            series_id=series_id,
            fields=fields,
            start=start,
            stop=stop,
            measurement=measurement,
            id_tag=id_tag,
            tags=tags,
            limit=limit,
            aggregate=aggregate,
            sample_max_points=sample_max_points,
            preserve_extrema=preserve_extrema,
            default_window_minutes=default_window_minutes,
        )
        logger.debug(
            "influx.read_single_time_series returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "influx.read_multiple_time_series", read_only=True)
    def influx_read_multiple_time_series(
        ids: Optional[List[str]] = None,
        fields: Optional[List[str]] = None,
        start: Optional[str] = None,
        stop: Optional[str] = None,
        measurement: Optional[str] = None,
        id_tag: Optional[str] = None,
        limit: OptionalLimitParam = None,
        initial_chunk_size: QueryChunkSizeParam = 5000,
        default_recent_minutes: MinutesParam = 10,
        default_window_minutes: MinutesParam = 60,
        fallback_k: TopKParam = 5,
    ) -> Dict[str, Any]:
        """Read multiple time series for a list of UCI strings in one batch call.

        Pass ``ids`` as a list of UCI strings (from alarm ``series_ids`` or
        ``influx.list_time_series``). ``start``/``stop`` are ISO-8601 UTC
        timestamps — alarm timestamps can be passed directly. If ``ids`` is
        omitted, the top ``fallback_k`` recently active UCIs are used.
        More efficient than calling ``influx.read_single_time_series`` repeatedly.
        Parameters ``measurement``, ``id_tag``, ``initial_chunk_size``,
        ``default_recent_minutes``, ``default_window_minutes``, and
        ``fallback_k`` have sensible defaults and rarely need to be changed."""
        logger.debug(
            "influx.read_multiple_time_series called with ids={ids}, "
            "fields={fields}, start={start}, stop={stop}, "
            "measurement={measurement}, id_tag={id_tag}, limit={limit}, "
            "initial_chunk_size={initial_chunk_size}, "
            "default_recent_minutes={default_recent_minutes}, "
            "default_window_minutes={default_window_minutes}, "
            "fallback_k={fallback_k}",
            ids=ids,
            fields=fields,
            start=start,
            stop=stop,
            measurement=measurement,
            id_tag=id_tag,
            limit=limit,
            initial_chunk_size=initial_chunk_size,
            default_recent_minutes=default_recent_minutes,
            default_window_minutes=default_window_minutes,
            fallback_k=fallback_k,
        )
        tool_result = influx_tools.read_multiple_time_series(
            ids=ids,
            fields=fields,
            start=start,
            stop=stop,
            measurement=measurement,
            id_tag=id_tag,
            limit=limit,
            initial_chunk_size=initial_chunk_size,
            default_recent_minutes=default_recent_minutes,
            default_window_minutes=default_window_minutes,
            fallback_k=fallback_k,
        )
        logger.debug(
            "influx.read_multiple_time_series returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "postgres.read_bounds", read_only=True)
    def postgres_read_bounds(
        module: str = "conn",
        series_id: Optional[str] = None,
        features: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Read trained statistical bounds (upper/lower thresholds) for anomaly detection.

        Bounds define the normal range for each metric of a time series.
        ``module`` is typically ``"conn"`` (the connection-level detection module).
        Use ``series_id`` (UCI) to get bounds for a specific connection.
        Available ``features``: ``packet_count``, ``total_volume``,
        ``mean_packet_size``, ``min_packet_size``, ``max_packet_size``,
        ``std_packet_size``, ``mean_interarrival_time``, ``min_interarrival_time``,
        ``max_interarrival_time``, ``std_interarrival_time``.
        Returns ``{"ok": True, "records": [...]}`` with flattened ``lb_*`` /
        ``ub_*`` columns plus metadata."""
        logger.debug(
            "postgres.read_bounds called with module={module}, series_id={series_id}, features={features}",
            module=module,
            series_id=series_id,
            features=features,
        )
        tool_result = pg_tools.read_bounds(module=module, series_id=series_id, features=features)
        logger.debug("postgres.read_bounds returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "postgres.write_bounds", read_only=False)
    def postgres_write_bounds(
        module: str,
        series_id: str,
        lower_bounds: Dict[str, Any],
        upper_bounds: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        """Create new bounds. Errors if bounds already exist for this (module, series_id).

        Use this only when the operator wants to record bounds for a
        previously-untrained ``(module, series_id)`` pair. ``lower_bounds``
        and ``upper_bounds`` are feature-keyed dicts (e.g.
        ``{"packet_count": 0, "total_volume": 0}``). ``reason`` is mandatory
        and is persisted to ``bounds_history``. Returns ``{"ok": True,
        "history_id": ...}`` on success; an error dict otherwise (including
        the case where bounds already exist — switch to ``expand_bounds``
        or ``replace_bounds`` in that case)."""
        logger.debug(
            "postgres.write_bounds called: module={module}, series_id={series_id}, "
            "lower_bounds={lower_bounds}, upper_bounds={upper_bounds}, reason={reason}",
            module=module,
            series_id=series_id,
            lower_bounds=lower_bounds,
            upper_bounds=upper_bounds,
            reason=reason,
        )
        tool_result = pg_tools.write_bounds(
            module=module,
            series_id=series_id,
            lower_bounds=lower_bounds,
            upper_bounds=upper_bounds,
            reason=reason,
        )
        logger.debug("postgres.write_bounds returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "postgres.expand_bounds", read_only=False)
    def postgres_expand_bounds(
        module: str,
        series_id: str,
        lower_bounds: Dict[str, Any],
        upper_bounds: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        """Widen existing bounds per-feature (min/max).

        Preferred tool for false-positive remediation — it never narrows
        existing thresholds. Fails (422) if no bounds row exists yet —
        call ``write_bounds`` first. ``reason`` is mandatory and
        persisted to ``bounds_history``.

        CRITICAL — feature completeness:
          You MUST supply a value for EVERY feature in the active feature
          set (``packet_count``, ``total_volume``, ``mean_packet_size``,
          ``min_packet_size``, ``max_packet_size``, ``std_packet_size``,
          ``mean_interarrival_time``, ``min_interarrival_time``,
          ``max_interarrival_time``, ``std_interarrival_time``), not just
          the ones the alarm mentioned. A SUBSET payload is rejected with
          HTTP 422 and the response's ``missing`` field lists the
          features you must add. Use ``null`` as an explicit "do-not-
          expand this feature" no-op marker for features you want to
          leave untouched. If unsure which features exist, call
          ``read_bounds`` (a.k.a. get_bounds) first.

        Headroom guidance:
          Pick bounds with ~5–10% headroom on each side of the observed
          legitimate range. Tight bounds at the last observed value
          re-fire immediately because sensors fluctuate. Example: if the
          last legitimate ``packet_count`` peak was 1000, pass
          ``upper_bounds={"packet_count": 1100, ...}`` rather than 1000.

        Example minimal payload (all-feature, partial expand):

          lower_bounds = {
            "packet_count": 0, "total_volume": 0,
            "mean_packet_size": null, "min_packet_size": null,
            "max_packet_size": null, "std_packet_size": null,
            "mean_interarrival_time": null, "min_interarrival_time": null,
            "max_interarrival_time": null, "std_interarrival_time": null,
          }
          upper_bounds = { ...same shape, with real numbers where you
                           want to widen and null elsewhere... }

        Semantics: for each feature carrying a real value, the persisted
        lower bound becomes ``min(old, new)`` and the upper bound becomes
        ``max(old, new)``. Features whose value is ``null`` are skipped.

        Response: ``{"ok": true, "history_id": ...,
        "classification": {...}, "warning"?: str}``. ``warning`` appears
        when the most recent alarms for this UCI are not bounds-derived
        — see ``recommended_action`` on the ``read_bounds`` response."""
        logger.debug(
            "postgres.expand_bounds called: module={module}, series_id={series_id}, "
            "lower_bounds={lower_bounds}, upper_bounds={upper_bounds}, reason={reason}",
            module=module,
            series_id=series_id,
            lower_bounds=lower_bounds,
            upper_bounds=upper_bounds,
            reason=reason,
        )
        tool_result = pg_tools.expand_bounds(
            module=module,
            series_id=series_id,
            lower_bounds=lower_bounds,
            upper_bounds=upper_bounds,
            reason=reason,
        )
        logger.debug("postgres.expand_bounds returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "postgres.replace_bounds", read_only=False)
    def postgres_replace_bounds(
        module: str,
        series_id: str,
        lower_bounds: Dict[str, Any],
        upper_bounds: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        """Full overwrite — destructive.

        Use only when the operator explicitly says replace — this can
        NARROW bounds and is destructive.

        CRITICAL — feature completeness:
          You MUST supply real ``(lo, hi)`` numeric values for every
          feature in the active feature set (``packet_count``,
          ``total_volume``, ``mean_packet_size``, ``min_packet_size``,
          ``max_packet_size``, ``std_packet_size``,
          ``mean_interarrival_time``, ``min_interarrival_time``,
          ``max_interarrival_time``, ``std_interarrival_time``). Unlike
          ``expand_bounds``, ``null`` values are NOT accepted — replace
          requires a complete envelope. A subset / null-containing
          payload is rejected with HTTP 422 and the response's ``missing``
          field lists the features you must add. If unsure which features
          exist, call ``read_bounds`` (a.k.a. get_bounds) first to learn
          the current envelope.

        Headroom guidance:
          Pick bounds with ~5–10% headroom on each side of the observed
          legitimate range. Tight bounds at the last observed value
          re-fire immediately because sensors fluctuate.

        Semantics: replaces ``lower_bounds`` and ``upper_bounds``
        wholesale with the provided dicts. Creates the row if it does
        not yet exist (acting like ``write_bounds`` in that case). Any
        feature missing from the new payload is DROPPED, and existing
        thresholds may be tightened. Reserve this for the explicit
        operator instruction "replace bounds". ``reason`` is mandatory
        and persisted to ``bounds_history``.

        Response: ``{"ok": true, "history_id": ...,
        "classification": {...}, "warning"?: str}``. ``warning`` appears
        when the most recent alarms for this UCI are not bounds-derived
        — see ``recommended_action`` on the ``read_bounds`` response."""
        logger.debug(
            "postgres.replace_bounds called: module={module}, series_id={series_id}, "
            "lower_bounds={lower_bounds}, upper_bounds={upper_bounds}, reason={reason}",
            module=module,
            series_id=series_id,
            lower_bounds=lower_bounds,
            upper_bounds=upper_bounds,
            reason=reason,
        )
        tool_result = pg_tools.replace_bounds(
            module=module,
            series_id=series_id,
            lower_bounds=lower_bounds,
            upper_bounds=upper_bounds,
            reason=reason,
        )
        logger.debug("postgres.replace_bounds returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "postgres.add_anomaly_suppression", read_only=False)
    def postgres_add_anomaly_suppression(
        series_id: str,
        suppressed_types: List[str],
        reason: str,
        created_by: Optional[str] = None,
        expires_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add or update a per-UCI anomaly-type suppression rule.

        Tells the otalon-clas persistence layer to DROP any anomaly with
        ``series_id`` and an ``anomaly_type`` in ``suppressed_types``
        before the row reaches the ``anomalies`` / ``alarms`` tables. Use
        this when an operator has confirmed that the named types are
        legitimate traffic on this UCI (e.g. ``arp_scan`` from a managed
        switch's neighbour discovery, ``port_scan`` from an asset
        inventory probe). Idempotent: passing the same types twice is a
        no-op; new types are unioned onto the existing set. ``reason`` is
        mandatory and must explain WHY this is a confirmed FP. ``expires_at``
        is an optional ISO-8601 UTC timestamp; leave empty for permanent
        suppression. ``created_by`` is an optional free-form attribution
        string (operator handle, chat session, ticket id)."""
        logger.debug(
            "postgres.add_anomaly_suppression called: series_id={s}, types={t}, "
            "reason={r}, created_by={cb}, expires_at={exp}",
            s=series_id,
            t=suppressed_types,
            r=reason,
            cb=created_by,
            exp=expires_at,
        )
        tool_result = pg_tools.add_suppression(
            series_id=series_id,
            suppressed_types=suppressed_types,
            reason=reason,
            created_by=created_by,
            expires_at=expires_at,
        )
        logger.debug(
            "postgres.add_anomaly_suppression returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "postgres.list_anomaly_suppressions", read_only=True)
    def postgres_list_anomaly_suppressions(
        series_id: Optional[str] = None,
        include_expired: bool = False,
    ) -> Dict[str, Any]:
        """List active anomaly-type suppressions.

        Use this to check whether a UCI already has suppression rules
        before adding new ones (e.g. when investigating an alarm and
        wondering why no recent anomalies appeared). ``series_id``
        narrows the list to a single UCI; omit to return every active
        rule. ``include_expired=True`` also returns rows whose
        ``expires_at`` has passed (useful for audits). Returns each row
        with ``suppressed_types``, ``reason``, ``created_by``,
        ``created_at`` and ``expires_at`` (ISO-8601 strings)."""
        logger.debug(
            "postgres.list_anomaly_suppressions called: series_id={s}, include_expired={ie}",
            s=series_id,
            ie=include_expired,
        )
        tool_result = pg_tools.list_suppressions(series_id=series_id, include_expired=include_expired)
        logger.debug(
            "postgres.list_anomaly_suppressions returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "postgres.remove_anomaly_suppression", read_only=False)
    def postgres_remove_anomaly_suppression(
        series_id: str,
        suppressed_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Remove anomaly-type suppression(s) for a UCI.

        Two modes:

        * ``suppressed_types=None`` (default): delete the row entirely —
          the UCI no longer has any active suppression. Use this when the
          operator says "remove the suppression for X" without qualifying
          which types.
        * ``suppressed_types=[...]``: remove only the listed types. If the
          resulting set is empty, the row is deleted; otherwise it is
          updated in place. Use this when the operator wants to keep
          suppressing some types but lift others.

        The result reports ``action`` (``delete``, ``update``, or ``noop``
        when no row existed) and the ``remaining_types`` left after the
        change."""
        logger.debug(
            "postgres.remove_anomaly_suppression called: series_id={s}, types={t}",
            s=series_id,
            t=suppressed_types,
        )
        tool_result = pg_tools.remove_suppression(series_id=series_id, suppressed_types=suppressed_types)
        logger.debug(
            "postgres.remove_anomaly_suppression returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "postgres.read_anomalies", read_only=True)
    def postgres_read_anomalies(
        module: str = "conn",
        series_id: Optional[str] = None,
        metric: Optional[str] = None,
        start: Optional[str] = None,
        stop: Optional[str] = None,
        limit: LimitParam = 100,
        default_window_minutes: MinutesParam = 1440,
    ) -> Dict[str, Any]:
        """Read anomalies filtered by module, series/metric and time range.

        ``start``/``stop`` are ISO-8601 UTC timestamps — alarm timestamps from
        ``postgres.read_alarm_details`` can be passed directly. Use ``series_id``
        to filter by a specific UCI. ``metric`` can be any of: ``packet_count``,
        ``total_volume``, ``mean_packet_size``, etc. If omitted, returns all
        metrics. ``module`` is typically ``"conn"``. If ``start``/``stop``
        are omitted, defaults to the last ``default_window_minutes``
        (1440 = 24 hours)."""
        logger.debug(
            "postgres.read_anomalies called with module={module}, "
            "series_id={series_id}, metric={metric}, start={start}, "
            "stop={stop}, limit={limit}, "
            "default_window_minutes={default_window_minutes}",
            module=module,
            series_id=series_id,
            metric=metric,
            start=start,
            stop=stop,
            limit=limit,
            default_window_minutes=default_window_minutes,
        )
        tool_result = pg_tools.read_anomalies(
            module=module,
            series_id=series_id,
            metric=metric,
            start=start,
            stop=stop,
            limit=limit,
            default_window_minutes=default_window_minutes,
        )
        logger.debug("postgres.read_anomalies returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "postgres.read_alarms", read_only=True)
    def postgres_read_alarms(
        module: Optional[str] = None,
        type_: Optional[str] = None,
        confirmed: Optional[bool] = None,
        start: Optional[str] = None,
        stop: Optional[str] = None,
        limit: LimitParam = 200,
        default_window_minutes: MinutesParam = 1440,
    ) -> Dict[str, Any]:
        """Read alarm groups with optional filters.

        Returns a list of alarms with ``id``, ``module``, ``primary_type``,
        time range (``start_timestamp`` / ``end_timestamp``), and
        ``confirmed`` status. ``type_`` filters on ``primary_type`` — pass
        the plain label (e.g. ``"tcp_flood"``, ``"BoundViolation"``). Use
        ``start``/``stop`` (ISO-8601 UTC) to filter by time. Defaults to
        the last ``default_window_minutes`` (1440 = 24 hours) if no time
        range is given. Call ``postgres.read_alarm_details`` with the
        alarm id for full details."""
        logger.debug(
            "postgres.read_alarms called with module={module}, type_={type_}, "
            "confirmed={confirmed}, start={start}, stop={stop}, "
            "limit={limit}, default_window_minutes={default_window_minutes}",
            module=module,
            type_=type_,
            confirmed=confirmed,
            start=start,
            stop=stop,
            limit=limit,
            default_window_minutes=default_window_minutes,
        )
        tool_result = pg_tools.read_alarms(
            module=module,
            type_=type_,
            confirmed=confirmed,
            start=start,
            stop=stop,
            limit=limit,
            default_window_minutes=default_window_minutes,
        )
        logger.debug("postgres.read_alarms returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "postgres.read_alarm_details", read_only=True)
    def postgres_read_alarm_details(
        id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Read details for a single alarm by its ID.

        ``id`` must be the alarm's UUID (format: 8-4-4-4-12 hex digits)
        as returned by ``postgres.read_alarms``. Returns the alarm time
        range (``start_timestamp``, ``end_timestamp``), affected
        ``series_ids`` (UCIs), and the anomaly summary."""
        logger.debug("postgres.read_alarm_details called with id={id}", id=id)
        err = _validate_uuid(id, "id")
        if err:
            logger.warning("postgres.read_alarm_details: {err}", err=err)
            return err
        tool_result = pg_tools.read_alarm_details(id=id)
        logger.debug(
            "postgres.read_alarm_details returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "postgres.read_recent_alarms", read_only=True)
    def postgres_read_recent_alarms(
        minutes: MinutesParam = 120,
        limit: LimitParam = 50,
    ) -> Dict[str, Any]:
        """Read recent alarms within the last N minutes."""
        logger.debug(
            "postgres.read_recent_alarms called with minutes={minutes}, limit={limit}",
            minutes=minutes,
            limit=limit,
        )
        tool_result = pg_tools.read_recent_alarms(minutes=minutes, limit=limit)
        logger.debug(
            "postgres.read_recent_alarms returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "postgres.get_top_alarm_counts", read_only=True)
    def postgres_get_top_alarm_counts(
        k: TopKParam = 10,
        group_by: str = "primary_type",
        minutes: MinutesParam = 1440,
    ) -> Dict[str, Any]:
        """Read the top-k alarm values and their counts.

        ``group_by`` names a column of the ``alarms`` table; it defaults
        to ``primary_type`` (the alarm's classification). The table has
        no ``type`` column."""
        logger.debug(
            "postgres.get_top_alarm_counts called with k={k}, group_by={group_by}, minutes={minutes}",
            k=k,
            group_by=group_by,
            minutes=minutes,
        )
        tool_result = pg_tools.get_top_alarm_counts(k=k, group_by=group_by, minutes=minutes)
        logger.debug(
            "postgres.get_top_alarm_counts returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "postgres.get_most_common_alarm", read_only=True)
    def postgres_get_most_common_alarm(
        group_by: str = "primary_type",
        minutes: MinutesParam = 1440,
    ) -> Dict[str, Any]:
        """Read the most common alarm value within the recent window.

        ``group_by`` names a column of the ``alarms`` table; it defaults
        to ``primary_type`` (the alarm's classification). The table has
        no ``type`` column."""
        logger.debug(
            "postgres.get_most_common_alarm called with group_by={group_by}, minutes={minutes}",
            group_by=group_by,
            minutes=minutes,
        )
        tool_result = pg_tools.get_most_common_alarm(group_by=group_by, minutes=minutes)
        logger.debug(
            "postgres.get_most_common_alarm returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    # Note: The following existing tools are removed per refactor requirements:
    # - postgres.list_columns
    # - postgres.fetch_rows
    # - postgres.set_anomaly_group_confirmed
    # - postgres.whitelisted_tables

    # ── pcap.* tools ───────────────────────────────────────────────────

    @_register(mcp, "pcap.health", read_only=True)
    def pcap_health() -> Dict[str, Any]:
        """Check reachability of the pcap_recorder service."""
        logger.debug("pcap.health called")
        tool_result = pcap_tools.health()
        logger.debug("pcap.health returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "pcap.list_chunks", read_only=True)
    def pcap_list_chunks(
        start_ts: str = "",
        end_ts: str = "",
        last_minutes: RelativeMinutesParam = 0,
        last_hours: RelativeHoursParam = 0,
        last_chunks: ChunkCountParam = 0,
    ) -> Dict[str, Any]:
        """List PCAP chunks within a time window or by relative time.

        The agent does not know the current wall-clock time.  Use
        ``last_minutes``, ``last_hours``, or ``last_chunks`` instead of
        explicit ISO 8601 timestamps when the user says e.g. "last 2 hours".

        Priority: last_hours > last_minutes > start_ts/end_ts.
        ``last_chunks`` queries the last 24 h and returns only the N newest.
        """
        logger.debug(
            "pcap.list_chunks called with start_ts={start_ts}, end_ts={end_ts}, "
            "last_minutes={last_minutes}, last_hours={last_hours}, last_chunks={last_chunks}",
            start_ts=start_ts,
            end_ts=end_ts,
            last_minutes=last_minutes,
            last_hours=last_hours,
            last_chunks=last_chunks,
        )
        tool_result = pcap_tools.list_chunks(
            start_ts=start_ts,
            end_ts=end_ts,
            last_minutes=last_minutes,
            last_hours=last_hours,
            last_chunks=last_chunks,
        )
        logger.debug("pcap.list_chunks returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "pcap.list_anomaly_chunks", read_only=True)
    def pcap_list_anomaly_chunks(
        start_ts: str = "",
        end_ts: str = "",
        last_minutes: RelativeMinutesParam = 0,
        last_hours: RelativeHoursParam = 0,
        last_chunks: ChunkCountParam = 0,
    ) -> Dict[str, Any]:
        """List only anomaly-flagged PCAP chunks, with relative time support.

        Includes ``labels`` metadata if available.  Use ``last_minutes``,
        ``last_hours``, or ``last_chunks`` instead of explicit timestamps
        when the user says e.g. "last 30 minutes".
        """
        logger.debug(
            "pcap.list_anomaly_chunks called with start_ts={start_ts}, end_ts={end_ts}, "
            "last_minutes={last_minutes}, last_hours={last_hours}, last_chunks={last_chunks}",
            start_ts=start_ts,
            end_ts=end_ts,
            last_minutes=last_minutes,
            last_hours=last_hours,
            last_chunks=last_chunks,
        )
        tool_result = pcap_tools.list_anomaly_chunks(
            start_ts=start_ts,
            end_ts=end_ts,
            last_minutes=last_minutes,
            last_hours=last_hours,
            last_chunks=last_chunks,
        )
        logger.debug("pcap.list_anomaly_chunks returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "pcap.get_chunks_by_alarm_id", read_only=True)
    def pcap_get_chunks_by_alarm_id(
        alarm_id: str,
        last_hours: RelativeHoursParam = 24,
    ) -> Dict[str, Any]:
        """Return all PCAP chunks associated with a specific alarm ID.

        ``alarm_id`` must be the alarm's UUID (format: 8-4-4-4-12 hex digits)
        as returned by ``postgres.read_alarms`` or ``postgres.read_alarm_details``.
        When the ML pipeline flags an anomaly, matching PCAP chunks are archived
        with a ``labels.alarm_id`` tag. Returns chunk filenames that can be
        passed to analysis tools (``pcap.protocol_stats``, ``pcap.conversations``,
        ``pcap.read_chunk_text``, etc.).

        Increase ``last_hours`` if the alarm is older than 24 hours.
        """
        logger.debug(
            "pcap.get_chunks_by_alarm_id called with alarm_id={alarm_id}, last_hours={last_hours}",
            alarm_id=alarm_id,
            last_hours=last_hours,
        )
        err = _validate_uuid(alarm_id, "alarm_id")
        if err:
            logger.warning("pcap.get_chunks_by_alarm_id: {err}", err=err)
            return err
        tool_result = pcap_tools.get_chunks_by_alarm_id(alarm_id=alarm_id, last_hours=last_hours)
        logger.debug(
            "pcap.get_chunks_by_alarm_id returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "pcap.get_chunk_meta", read_only=True)
    def pcap_get_chunk_meta(
        chunk_id: ChunkIdParam,
    ) -> Dict[str, Any]:
        """Retrieve JSON metadata for a single PCAP chunk by its ID."""
        logger.debug("pcap.get_chunk_meta called with chunk_id={chunk_id}", chunk_id=chunk_id)
        tool_result = pcap_tools.get_chunk_meta(chunk_id=chunk_id)
        logger.debug("pcap.get_chunk_meta returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "pcap.read_chunk_text", read_only=True)
    def pcap_read_chunk_text(
        chunk_id: ChunkIdParam,
        max_lines: MaxLinesParam = 50,
    ) -> Dict[str, Any]:
        """Read tcpdump plain-text output of a PCAP chunk (truncated to max_lines)."""
        logger.debug(
            "pcap.read_chunk_text called with chunk_id={chunk_id}, max_lines={max_lines}",
            chunk_id=chunk_id,
            max_lines=max_lines,
        )
        tool_result = pcap_tools.read_chunk_text(chunk_id=chunk_id, max_lines=max_lines)
        logger.debug("pcap.read_chunk_text returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "pcap.analyze_chunk", read_only=True)
    def pcap_analyze_chunk(
        chunk_id: ChunkIdParam,
        tshark_args: str = "",
        max_lines: MaxLinesParam = 200,
    ) -> Dict[str, Any]:
        """Run a tshark analysis on a PCAP chunk with freely configurable arguments.

        This is the most flexible PCAP analysis tool.  Pass any valid tshark
        arguments as a single string via *tshark_args*.

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
        """
        logger.debug(
            "pcap.analyze_chunk called with chunk_id={chunk_id}, tshark_args={tshark_args}, max_lines={max_lines}",
            chunk_id=chunk_id,
            tshark_args=tshark_args,
            max_lines=max_lines,
        )
        tool_result = pcap_tools.analyze_chunk(chunk_id=chunk_id, tshark_args=tshark_args, max_lines=max_lines)
        logger.debug("pcap.analyze_chunk returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "pcap.inspect_timewindow", read_only=True)
    def pcap_inspect_timewindow(
        chunk_id: ChunkIdParam,
        start_sec: OffsetSecondsParam = 0.0,
        end_sec: OffsetSecondsParam = 5.0,
        max_lines: MaxLinesParam = 100,
    ) -> Dict[str, Any]:
        """Inspect a time window within a PCAP chunk using standard field extraction.

        Extracts frame number, timestamp, source/destination MAC, protocol stack,
        and the Wireshark Info column for packets within the given time offset range.
        """
        logger.debug(
            "pcap.inspect_timewindow called with chunk_id={chunk_id}, "
            "start_sec={start_sec}, end_sec={end_sec}, max_lines={max_lines}",
            chunk_id=chunk_id,
            start_sec=start_sec,
            end_sec=end_sec,
            max_lines=max_lines,
        )
        tool_result = pcap_tools.inspect_timewindow(
            chunk_id=chunk_id, start_sec=start_sec, end_sec=end_sec, max_lines=max_lines
        )
        logger.debug("pcap.inspect_timewindow returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "pcap.protocol_stats", read_only=True)
    def pcap_protocol_stats(
        chunk_id: ChunkIdParam,
    ) -> Dict[str, Any]:
        """Retrieve protocol hierarchy statistics for a PCAP chunk.

        Shows the count and percentage of frames per protocol layer
        (e.g. Ethernet, IPv4, TCP, ARP, OPC-UA, PROFINET). Useful to
        quickly identify which protocols are present and their relative
        volume. Output is bounded to ~50 KB; very large outputs are
        truncated with a ``truncated: true`` flag."""
        logger.debug("pcap.protocol_stats called with chunk_id={chunk_id}", chunk_id=chunk_id)
        tool_result = pcap_tools.protocol_stats(chunk_id=chunk_id)
        logger.debug("pcap.protocol_stats returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "pcap.conversations", read_only=True)
    def pcap_conversations(
        chunk_id: ChunkIdParam,
        layer: ConversationLayer = "eth",
    ) -> Dict[str, Any]:
        """Retrieve conversation statistics for a PCAP chunk.

        Available ``layer`` values: ``"eth"`` (MAC pairs), ``"ip"`` (IP pairs),
        ``"tcp"`` (TCP sessions), ``"udp"`` (UDP flows). Recommend
        ``layer="ip"`` or ``layer="tcp"`` for most analyses — ``"eth"`` can
        produce very large output on busy industrial networks. Output is
        bounded to ~50 KB and truncated with a hint when exceeded."""
        logger.debug(
            "pcap.conversations called with chunk_id={chunk_id}, layer={layer}",
            chunk_id=chunk_id,
            layer=layer,
        )
        tool_result = pcap_tools.conversations(chunk_id=chunk_id, layer=layer)
        logger.debug("pcap.conversations returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "pcap.io_stats", read_only=True)
    def pcap_io_stats(
        chunk_id: ChunkIdParam,
        interval_sec: IntervalSecondsParam = 1,
        filter: str = "",
    ) -> Dict[str, Any]:
        """Retrieve I/O rate statistics for a PCAP chunk at configurable intervals.

        ``interval_sec`` is the bucket width in seconds (clamped to a minimum
        of 1). The optional ``filter`` uses tshark display-filter syntax
        (e.g. ``"arp"``, ``"tcp"``, ``"tcp.port==4840"``). Output is
        bounded to ~50 KB; if exceeded, prefer a larger ``interval_sec``."""
        logger.debug(
            "pcap.io_stats called with chunk_id={chunk_id}, interval_sec={interval_sec}, filter={filter}",
            chunk_id=chunk_id,
            interval_sec=interval_sec,
            filter=filter,
        )
        tool_result = pcap_tools.io_stats(chunk_id=chunk_id, interval_sec=interval_sec, filter=filter)
        logger.debug("pcap.io_stats returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "pcap.flag_anomaly", read_only=False)
    def pcap_flag_anomaly(
        start_ts: str,
        end_ts: str,
        labels: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Flag a time window as anomaly — matching chunks are archived."""
        logger.debug(
            "pcap.flag_anomaly called with start_ts={start_ts}, end_ts={end_ts}, labels={labels}",
            start_ts=start_ts,
            end_ts=end_ts,
            labels=labels,
        )
        tool_result = pcap_tools.flag_anomaly(start_ts=start_ts, end_ts=end_ts, labels=labels)
        logger.debug("pcap.flag_anomaly returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "mitre.list_tactics", read_only=True)
    async def mitre_list_tactics() -> list[dict]:
        """List all MITRE ICS ATT&CK tactics with technique counts."""
        logger.debug("mitre.list_tactics called")
        tool_result = mitre_tools.list_tactics()
        logger.debug("mitre.list_tactics returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "mitre.list_techniques", read_only=True)
    async def mitre_list_techniques(tactic: str | None = None, limit: OptionalMitreLimitParam = None) -> list[dict]:
        """List MITRE ICS techniques, optionally filtered by tactic."""
        logger.debug(
            "mitre.list_techniques called with tactic={tactic}, limit={limit}",
            tactic=tactic,
            limit=limit,
        )
        tool_result = mitre_tools.list_techniques(tactic=tactic, limit=limit)
        logger.debug("mitre.list_techniques returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "mitre.get_technique_by_id", read_only=True)
    async def mitre_get_technique_by_id(external_id: str) -> dict:
        """Get detailed information about a MITRE ICS technique by its external ID (e.g. T0829)."""
        logger.debug(
            "mitre.get_technique_by_id called with external_id={external_id}",
            external_id=external_id,
        )
        tool_result = mitre_tools.get_technique_by_external_id(external_id=external_id)
        logger.debug("mitre.get_technique_by_id returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "mitre.get_techniques_by_tactic", read_only=True)
    async def mitre_get_techniques_by_tactic(tactic: str, limit: OptionalMitreLimitParam = None) -> dict:
        """Get all techniques associated with a specific MITRE ICS ATT&CK tactic."""
        logger.debug(
            "mitre.get_techniques_by_tactic called with tactic={tactic}, limit={limit}",
            tactic=tactic,
            limit=limit,
        )
        tool_result = mitre_tools.get_techniques_by_tactic(tactic=tactic, limit=limit)
        logger.debug(
            "mitre.get_techniques_by_tactic returning {tool_result}",
            tool_result=tool_result,
        )
        return tool_result

    @_register(mcp, "mitre.search_techniques", read_only=True)
    async def mitre_search_techniques(query: str, limit: MitreLimitParam = 10) -> dict:
        """Full-text search across MITRE ICS technique names and descriptions."""
        logger.debug(
            "mitre.search_techniques called with query={query}, limit={limit}",
            query=query,
            limit=limit,
        )
        tool_result = mitre_tools.search_techniques(query=query, limit=limit)
        logger.debug("mitre.search_techniques returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "mitre.get_subtechniques", read_only=True)
    async def mitre_get_subtechniques(parent_external_id: str) -> dict:
        """Get sub-techniques of a parent MITRE ICS technique."""
        logger.debug(
            "mitre.get_subtechniques called with parent_external_id={parent_external_id}",
            parent_external_id=parent_external_id,
        )
        tool_result = mitre_tools.get_subtechniques(parent_external_id=parent_external_id)
        logger.debug("mitre.get_subtechniques returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "mitre.stats", read_only=True)
    async def mitre_stats() -> dict:
        """Get statistics about the loaded MITRE ICS ATT&CK dataset including version info."""
        logger.debug("mitre.stats called")
        tool_result = mitre_tools.stats()
        logger.debug("mitre.stats returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "mitre.ping", read_only=True)
    async def mitre_ping() -> str:
        """Health check for MITRE ICS tools."""
        logger.debug("mitre.ping called")
        tool_result = mitre_tools.ping()
        logger.debug("mitre.ping returning {tool_result}", tool_result=tool_result)
        return tool_result

    @_register(mcp, "mitre.update_stix_data", read_only=False)
    async def mitre_update_stix_data() -> dict:
        """Download the latest MITRE ICS ATT&CK STIX data from GitHub and reload the index."""
        logger.debug("mitre.update_stix_data called")
        tool_result = mitre_tools.update_stix_data()
        logger.debug("mitre.update_stix_data returning {tool_result}", tool_result=tool_result)
        return tool_result

    # ── baseline.* (curated quiet-traffic comparison) ────────────────

    @_register(mcp, "influx.list_baseline_time_series", read_only=True)
    def influx_list_baseline_time_series(
        start: Optional[str] = None,
        stop: Optional[str] = None,
        measurement: Optional[str] = None,
        id_tag: Optional[str] = None,
        nonzero: bool = False,
        fields: Optional[List[str]] = None,
        threshold: Optional[float] = 0.0,
        baseline_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List distinct UCIs observed in the active (or specified) baseline window.

        The optional ``start``/``stop`` clamp the query to a sub-range of
        the baseline window. Returns the resolved ``baseline_id`` for
        transparency.
        """
        logger.debug("influx.list_baseline_time_series called")
        return baseline_tools.list_baseline_time_series(
            start=start,
            stop=stop,
            measurement=measurement,
            id_tag=id_tag,
            nonzero=nonzero,
            fields=fields,
            threshold=threshold,
            baseline_id=baseline_id,
        )

    @_register(mcp, "influx.get_baseline_single_time_series", read_only=True)
    def influx_get_baseline_single_time_series(
        series_id: str,
        baseline_id: Optional[str] = None,
        chunk_filename: OptionalChunkIdParam = None,
        fields: Optional[List[str]] = None,
        measurement: Optional[str] = None,
        id_tag: Optional[str] = None,
        limit: OptionalLimitParam = None,
        aggregate: Optional[str] = "avg",
        sample_max_points: OptionalSamplePointsParam = 1000,
        preserve_extrema: bool = True,
    ) -> Dict[str, Any]:
        """Read one baseline UCI for a chosen (or random) baseline PCAP chunk window."""
        logger.debug("influx.get_baseline_single_time_series called: series_id={}", series_id)
        return baseline_tools.get_baseline_single_time_series(
            series_id=series_id,
            baseline_id=baseline_id,
            chunk_filename=chunk_filename,
            fields=fields,
            measurement=measurement,
            id_tag=id_tag,
            limit=limit,
            aggregate=aggregate,
            sample_max_points=sample_max_points,
            preserve_extrema=preserve_extrema,
        )

    @_register(mcp, "influx.get_baseline_multiple_time_series", read_only=True)
    def influx_get_baseline_multiple_time_series(
        series_ids: List[str],
        baseline_id: Optional[str] = None,
        chunk_filename: OptionalChunkIdParam = None,
        fields: Optional[List[str]] = None,
        measurement: Optional[str] = None,
        id_tag: Optional[str] = None,
        limit: OptionalLimitParam = None,
        initial_chunk_size: QueryChunkSizeParam = 5000,
    ) -> Dict[str, Any]:
        """Read multiple baseline UCIs for one baseline PCAP chunk window."""
        logger.debug("influx.get_baseline_multiple_time_series called: n={}", len(series_ids))
        return baseline_tools.get_baseline_multiple_time_series(
            series_ids=series_ids,
            baseline_id=baseline_id,
            chunk_filename=chunk_filename,
            fields=fields,
            measurement=measurement,
            id_tag=id_tag,
            limit=limit,
            initial_chunk_size=initial_chunk_size,
        )

    @_register(mcp, "pcap.list_baseline_chunks", read_only=True)
    def pcap_list_baseline_chunks(
        baseline_id: Optional[str] = None,
        start_ts: Optional[str] = None,
        end_ts: Optional[str] = None,
        last_minutes: OptionalRelativeMinutesParam = None,
        last_hours: OptionalRelativeHoursParam = None,
        last_chunks: OptionalChunkCountParam = None,
    ) -> Dict[str, Any]:
        """List baseline PCAP chunks in the current (or given) baseline."""
        logger.debug("pcap.list_baseline_chunks called")
        return baseline_tools.list_baseline_chunks(
            baseline_id=baseline_id,
            start_ts=start_ts,
            end_ts=end_ts,
            last_minutes=last_minutes,
            last_hours=last_hours,
            last_chunks=last_chunks,
        )

    @_register(mcp, "pcap.get_baseline_chunks", read_only=True)
    def pcap_get_baseline_chunks(baseline_id: Optional[str] = None, limit: LimitParam = 5) -> Dict[str, Any]:
        """Return up to `limit` randomly sampled baseline chunks (quick lookup)."""
        logger.debug("pcap.get_baseline_chunks called: limit={}", limit)
        return baseline_tools.get_baseline_chunks(baseline_id=baseline_id, limit=limit)

    # ── agent.* (subagent classification) ─────────────────────────────

    @_register(mcp, "agent.classify_alert", read_only=False)
    def agent_classify_alert(
        alarm_id: str,
        prompt_variant: PromptVariant = "expert",
        llm_provider: Optional[str] = None,
        llm_model: Optional[str] = None,
        baseline_id: Optional[str] = None,
        timeout_seconds: TimeoutSecondsParam = 600,
    ) -> Dict[str, Any]:
        """Trigger a fresh, unbiased subagent classification on the given alarm.

        Returns IMMEDIATELY with a ``job_id`` — the worker (~2-7 minutes,
        GPT-5.4 expert prompt) runs asynchronously. Use the returned
        ``job_id`` and embed the literal token ``[subagent-job:<job_id>]``
        in your reply text so the chat overlay can render an inline live
        trace card. Use ``agent.get_classification_status`` to poll the
        result later.

        ``prompt_variant`` is "open" or "expert" (default expert; the
        paper-validated 89% S2-Eff. configuration).
        """
        logger.debug(
            "agent.classify_alert called: alarm_id={} prompt={} provider={} model={}",
            alarm_id,
            prompt_variant,
            llm_provider,
            llm_model,
        )
        return agent_tools.classify_alert(
            alarm_id=alarm_id,
            prompt_variant=prompt_variant,
            llm_provider=llm_provider,
            llm_model=llm_model,
            baseline_id=baseline_id,
            timeout_seconds=timeout_seconds,
        )

    @_register(mcp, "agent.get_classification_status", read_only=True)
    def agent_get_classification_status(job_id: str) -> Dict[str, Any]:
        """Poll the current state of a subagent classification job.

        Returns the full job record including status, step1_technical
        (attack method), step2_classification (MITRE techniques), and a
        truncated tool_trace when the trace would be too large.
        """
        logger.debug("agent.get_classification_status called: job_id={}", job_id)
        return agent_tools.get_classification_status(job_id=job_id)

    @_register(mcp, "agent.list_classifications_for_alert", read_only=True)
    def agent_list_classifications_for_alert(alarm_id: str, limit: LimitParam = 10) -> Dict[str, Any]:
        """List prior subagent classifications for one alarm (newest first)."""
        logger.debug(
            "agent.list_classifications_for_alert called: alarm_id={} limit={}",
            alarm_id,
            limit,
        )
        return agent_tools.list_classifications_for_alert(alarm_id=alarm_id, limit=limit)

    @_register(mcp, "chat", read_only=False)
    def chat(message: str, history: list[dict] | None = None) -> str:
        """Process a chat message from the OTALON UI.

        This is a stub implementation that returns a static response.
        Replace with a real AI backend integration (e.g. OpenAI, Ollama,
        n8n workflow) when available.

        Args:
            message: The user's chat message.
            history: Optional conversation history as list of role/content dicts.

        Returns:
            The assistant's response text.
        """
        logger.debug("chat called with message={message}", message=message)
        return (
            "The AI chat integration is currently in development. "
            "Available MCP tools can be used for: "
            "InfluxDB time-series queries, PostgreSQL anomaly/alarm data, "
            "PCAP network capture analysis, and MITRE ICS ATT&CK lookups. "
            "Please use the MCP client tools directly for data queries."
        )

    # ── asset CRUD: devices / network_interfaces ─────────────────────

    @_register(mcp, "postgres.list_devices", read_only=True)
    def postgres_list_devices(limit: LimitParam = 200, offset: OffsetParam = 0) -> Dict[str, Any]:
        """List devices (read-only).

        Paginated by ``limit``/``offset``. Returns ``{"ok": true,
        "records": [...], "count": int}``. The ``devices`` table has NO
        ``source`` and NO ``hostname`` columns; provenance lives on
        ``network_interfaces.source`` instead."""
        return pg_tools.list_devices(limit=limit, offset=offset)

    @_register(mcp, "postgres.get_device", read_only=True)
    def postgres_get_device(device_id: RowIdParam) -> Dict[str, Any]:
        """Get one device by id (read-only). Returns ``{"ok": true,
        "record": {...}}`` or an error dict."""
        return pg_tools.get_device(device_id=device_id)

    @_register(mcp, "postgres.add_device", read_only=False)
    def postgres_add_device(
        primary_mac: Optional[str] = None,
        vendor: Optional[str] = None,
        device_family: Optional[str] = None,
        device_type: Optional[str] = None,
        description: Optional[str] = None,
        article_number: Optional[str] = None,
        device_role: Optional[str] = None,
        firmware_version: Optional[str] = None,
        update_available: Optional[bool] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Insert a new device row. Logs an ``mcp_asset_mutation`` audit event.

        All columns are optional; every column on ``devices`` is
        nullable or has a server default. ``primary_mac`` must be
        lowercase colon-separated (e.g. ``aa:bb:cc:dd:ee:ff``) when
        supplied — the DB enforces this via ``ck_devices_primary_mac_format``.
        Unknown columns are rejected. The ``devices`` table has NO
        ``source`` and NO ``hostname`` columns."""
        return pg_tools.add_device(
            primary_mac=primary_mac,
            vendor=vendor,
            device_family=device_family,
            device_type=device_type,
            description=description,
            article_number=article_number,
            device_role=device_role,
            firmware_version=firmware_version,
            update_available=update_available,
            notes=notes,
        )

    @_register(mcp, "postgres.update_device", read_only=False)
    def postgres_update_device(
        device_id: RowIdParam,
        primary_mac: Optional[str] = None,
        vendor: Optional[str] = None,
        device_family: Optional[str] = None,
        device_type: Optional[str] = None,
        description: Optional[str] = None,
        article_number: Optional[str] = None,
        device_role: Optional[str] = None,
        firmware_version: Optional[str] = None,
        update_available: Optional[bool] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Partial update of a device row.

        Only parameters that are NOT ``None`` are written. To explicitly
        clear a column to NULL, use raw SQL outside MCP — this tool
        treats ``None`` as 'do not touch'. Logs an audit event."""
        return pg_tools.update_device(
            device_id=device_id,
            primary_mac=primary_mac,
            vendor=vendor,
            device_family=device_family,
            device_type=device_type,
            description=description,
            article_number=article_number,
            device_role=device_role,
            firmware_version=firmware_version,
            update_available=update_available,
            notes=notes,
        )

    @_register(mcp, "postgres.delete_device", read_only=False)
    def postgres_delete_device(device_id: RowIdParam, cascade_interfaces: bool = False) -> Dict[str, Any]:
        """HARD-delete a device row.

        ``cascade_interfaces=False`` (the default) lets the FK
        ``network_interfaces.device_id ON DELETE SET NULL`` orphan every
        owned interface — they keep existing but are no longer linked
        to a device. ``cascade_interfaces=True`` also deletes every
        owned interface (and their attached service / vulnerability
        observations via further cascades). Logs an audit event.
        Returns ``{"ok": true, "deleted_device_id": int,
        "deleted_interfaces": int, "orphaned_interfaces": int,
        "cascade_interfaces": bool}``."""
        return pg_tools.delete_device(device_id=device_id, cascade_interfaces=cascade_interfaces)

    @_register(mcp, "postgres.list_interfaces", read_only=True)
    def postgres_list_interfaces(
        device_id: DeviceFilterIdParam = None,
        limit: LimitParam = 200,
        offset: OffsetParam = 0,
    ) -> Dict[str, Any]:
        """List network interfaces (read-only).

        Set ``device_id`` to narrow the query to one device's
        interfaces. ``device_id=0`` returns the orphan set
        (interfaces with ``device_id IS NULL`` — useful after a
        non-cascade ``delete_device``)."""
        return pg_tools.list_interfaces(device_id=device_id, limit=limit, offset=offset)

    @_register(mcp, "postgres.get_interface", read_only=True)
    def postgres_get_interface(interface_id: RowIdParam) -> Dict[str, Any]:
        """Get one network interface by id (read-only)."""
        return pg_tools.get_interface(interface_id=interface_id)

    @_register(mcp, "postgres.add_interface", read_only=False)
    def postgres_add_interface(
        device_id: OptionalRowIdParam = None,
        mac_address: Optional[str] = None,
        ipv4_address: Optional[str] = None,
        ipv6_address: Optional[str] = None,
        subnet: Optional[str] = None,
        notes: Optional[str] = None,
        source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Insert a new network_interfaces row.

        ``source`` defaults to ``"manual"`` (MCP-originated) so the
        row is distinguishable from active-scan (``"active"``) and
        passive-seeder (``"passive"``) rows in audits. Pass an explicit
        ``device_id`` to link the interface to a device; omit it for
        an orphan interface that an operator can link later. Logs an
        audit event."""
        return pg_tools.add_interface(
            device_id=device_id,
            mac_address=mac_address,
            ipv4_address=ipv4_address,
            ipv6_address=ipv6_address,
            subnet=subnet,
            notes=notes,
            source=source,
        )

    @_register(mcp, "postgres.update_interface", read_only=False)
    def postgres_update_interface(
        interface_id: RowIdParam,
        device_id: OptionalRowIdParam = None,
        mac_address: Optional[str] = None,
        ipv4_address: Optional[str] = None,
        ipv6_address: Optional[str] = None,
        subnet: Optional[str] = None,
        notes: Optional[str] = None,
        source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Partial update of a network_interfaces row. Logs an audit event."""
        return pg_tools.update_interface(
            interface_id=interface_id,
            device_id=device_id,
            mac_address=mac_address,
            ipv4_address=ipv4_address,
            ipv6_address=ipv6_address,
            subnet=subnet,
            notes=notes,
            source=source,
        )

    @_register(mcp, "postgres.delete_interface", read_only=False)
    def postgres_delete_interface(interface_id: RowIdParam) -> Dict[str, Any]:
        """HARD-delete a network_interfaces row.

        Cascades service- and vulnerability-observations attached to
        the interface (their FKs use ``ON DELETE CASCADE``). Logs an
        audit event."""
        return pg_tools.delete_interface(interface_id=interface_id)

    @_register(mcp, "training.retrain_boundaries", read_only=False)
    def training_retrain_boundaries(
        window_start: str,
        window_stop: str,
        nonce: str = "",
        intervals: Optional[List[List[str]]] = None,
    ) -> Dict[str, Any]:
        """Trigger a chat-driven BOUNDARY RETRAINING of otalon-clas.

        Use this only after the operator has explicitly confirmed they
        want to retrain detection boundaries for a specific time window
        (e.g. "retrain the bounds for last Tuesday 12:15-12:30"). The
        run is a HEAVY compute operation but does NOT restart or recreate
        otalon-clas — the training is executed in-process and detection
        stays online.

          1. Pre-training snapshot of the current productive bounds into
             ``bounds_history`` (so the previous envelope is recoverable
             on failure or on a bad window).
          2. A ``retrain_jobs`` row is queued and the running otalon-clas
             is notified via PostgreSQL.
          3. otalon-clas trains bounds + frequency in-process and
             publishes the results atomically.

        ALWAYS confirm the requested window with the operator before
        calling this tool. Refuse vague phrasings like "retrain everything".

        Args:
            window_start: ISO-8601 retrain-window start
                (``YYYY-MM-DD HH:MM:SS`` or ``YYYY-MM-DDTHH:MM:SS``).
                Must be strictly less than ``window_stop``.
            window_stop: ISO-8601 retrain-window stop.
            intervals: Optional multiple disjoint ``[start, stop]`` pairs.

        Returns:
            ``{"ok": True, "state", "job_ref", "started_at",
            "window_start", "window_stop", "detail", "hint"}`` on
            success.

            ``{"ok": False, "error": ...}`` on validation failure
            (handled locally with NO network call).

            ``{"ok": False, "status": "busy", "error": ...}`` when
            another retrain is already in progress (HTTP 409). Try
            again once ``training.get_retrain_status`` reports state
            ``succeeded`` or ``failed``.

        After a successful start the chat agent SHOULD poll
        ``training.get_retrain_status`` every 10–30 seconds and surface
        the ``state`` and ``detail`` until the state is ``succeeded`` or
        ``failed``.
        """
        logger.info(
            "training.retrain_boundaries called: window_start={} window_stop={}",
            window_start,
            window_stop,
        )
        return training_tools.retrain_boundaries(
            window_start=window_start,
            window_stop=window_stop,
            nonce=nonce,
            intervals=intervals,
        )

    @_register(mcp, "correct_rhythm_profile", read_only=False)
    def correct_rhythm_profile(
        series_id: str,
        tolerance_factor_override: Optional[float] = None,
        absence_factor_override: Optional[float] = None,
        reason: str = "",
        module: str = "conn",
    ) -> Dict[str, Any]:
        """Preview and apply one audited rhythm-profile correction.

        ``reason`` is optional, matching the API contract. The API performs
        exactly one audit write and notifies the running detector to reload.
        A stale Preview snapshot is returned as a clear HTTP 409 error.
        """
        return frequency_tools.correct_rhythm_profile(
            series_id=series_id,
            tolerance_factor_override=tolerance_factor_override,
            absence_factor_override=absence_factor_override,
            reason=reason,
            module=module,
        )

    @_register(mcp, "training.retrain_classifier", read_only=False)
    def training_retrain_classifier(
        window_start: str,
        window_stop: str,
        mitre_file: str,
        intervals: Optional[List[List[str]]] = None,
    ) -> Dict[str, Any]:
        """Trigger a chat-driven CLASSIFIER RETRAINING of otalon-clas.

        Use this only after the operator has explicitly confirmed they
        want to retrain the ML classifier for a specific window and MITRE
        file. The run is a HEAVY compute operation but does NOT restart or
        recreate otalon-clas — the new model is atomically published and
        reloaded in-process, and detection stays online.

        ALWAYS confirm the requested window and MITRE file before calling.
        """
        logger.info(
            "training.retrain_classifier called: window_start={} window_stop={} mitre_file={}",
            window_start,
            window_stop,
            mitre_file,
        )
        return training_tools.retrain_classifier(
            window_start=window_start,
            window_stop=window_stop,
            mitre_file=mitre_file,
            intervals=intervals,
        )

    @_register(mcp, "training.get_retrain_status", read_only=True)
    def training_get_retrain_status() -> Dict[str, Any]:
        """Poll the current state of the runtime retrain orchestrator.

        Side-effect free. The runtime state set is
        ``idle | queued | running | publishing | succeeded | failed``.
        After a run terminates the single-flight lock is released, but
        the polled ``state`` still reports the terminal value of the last
        run until a new run starts.

        Returns:
            ``{"ok": True, "state", "detail", "job_ref", "started_at",
            "finished_at", "window_start", "window_stop",
            "history_snapshot_rows", "error", "scope", "mitre_file"}``
            on success.
        """
        logger.debug("training.get_retrain_status called")
        return training_tools.get_retrain_status()

    logger.info("MCP tools initialized: core + influx + postgres + pcap + mitre + chat + assets + training")
