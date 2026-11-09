"""Current-time context for the chat surface (AI-037).

The canonical system prompt mounted from
``otalon-mcp/docs/system_promt_agent.md`` explicitly tells the model
"You do not know the current wall-clock time" (twice, in the
``pcap.list_chunks`` / ``pcap.list_anomaly_chunks`` sections). Nothing
in the chat pipeline ever contradicted that: no turn carried a clock,
so every relative-time question ("last hour", "today", "recently") was
resolved against whatever instant the model invented.

Observed failure (AI-037): asked "How many alarms were recorded in the
last hour?" the model called ``postgres.read_alarms`` with
``start=2026-09-01T11:17:00Z / stop=2026-09-01T12:17:00Z`` while real
UTC was ``02:22Z``. The window sat ~9 h in the FUTURE, so it returned
zero rows and the agent answered "0" although an active alarm existed.
The answer even re-cited the (wrong) parameters, so it read as
trustworthy.

This module renders a small deterministic block that
:class:`otalon_ai.chat.agent_loop.ChatAgentLoop` appends to the system
prompt on EVERY turn. It is rendered per turn (never cached at
startup) so a long-lived process cannot serve a stale clock, and the
instant is taken from an injectable clock so tests can pin it.

Rendering is a pure function of its argument: the same ``datetime`` in
always produces the same string out. That is what lets the regression
test skew the clock and observe the original failure end-to-end.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

TIME_CONTEXT_HEADER = "CURRENT TIME CONTEXT (authoritative)"

NOW_UTC_LABEL = "now_utc"


def utc_now() -> datetime:
    """Return the current instant as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def _iso_z(moment: datetime) -> str:
    """Format an aware datetime as ISO-8601 UTC with a trailing ``Z``."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _local_line(moment: datetime) -> str:
    """Render the ``now_local`` line with tz name and numeric UTC offset."""
    local = moment.astimezone()
    offset = local.utcoffset() or timedelta(0)
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    hours, minutes = divmod(abs(total_minutes), 60)
    name = local.tzname() or "local"
    return f"• now_local: {local.isoformat(timespec='seconds')} ({name}, UTC{sign}{hours:02d}:{minutes:02d})"


def render_time_context(now: datetime) -> str:
    """Render the authoritative time block appended to the system prompt.

    Args:
        now: The instant to present as "now". Any aware datetime is
            accepted and normalised to UTC; a naive one is read as UTC
            rather than rejected, because the agent loop must never fail
            a turn over a clock-formatting detail.

    Returns:
        A block prefixed with two newlines so it can be concatenated
        directly onto the system prompt.
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now_utc = now.astimezone(timezone.utc).replace(microsecond=0)
    day_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    lines: List[str] = [
        "",
        "",
        f"{TIME_CONTEXT_HEADER} — this supersedes any statement in this",
        "prompt or in any tool documentation claiming you do not know the",
        "current wall-clock time. You DO know it; it is stated here.",
        f"• {NOW_UTC_LABEL}: {_iso_z(now_utc)}",
        _local_line(now_utc),
        f"• unix_epoch_seconds: {int(now_utc.timestamp())}",
        "",
        "Precomputed windows (ISO-8601 UTC, safe to pass verbatim as",
        "`start` / `stop` tool parameters):",
        f"• last hour     → start={_iso_z(now_utc - timedelta(hours=1))} stop={_iso_z(now_utc)}",
        f"• last 24 hours → start={_iso_z(now_utc - timedelta(hours=24))} stop={_iso_z(now_utc)}",
        f"• today (UTC)   → start={_iso_z(day_start)} stop={_iso_z(now_utc)}",
        "",
        "Rules for relative time:",
        f"• {NOW_UTC_LABEL} above is the ONLY valid source of the current time. Never derive 'now'",
        "  from your training data, from timestamps seen in tool results, or from the history.",
        "• Resolve every relative expression ('last hour', 'today', 'since this morning', 'the past",
        f"  15 minutes') against {NOW_UTC_LABEL}, and pass ISO-8601 UTC timestamps ending in 'Z'.",
        f"• A `start` or `stop` later than {NOW_UTC_LABEL} is always wrong: such a window lies in the",
        "  future and necessarily returns zero rows. Re-check your arithmetic before reporting an",
        "  empty result — an empty window is far more often a wrong window than a quiet network.",
        "• When a tool offers relative parameters (`last_minutes`, `last_hours`, `minutes`,",
        "  `last_chunks`), prefer them over explicit timestamps.",
    ]
    return "\n".join(lines)
