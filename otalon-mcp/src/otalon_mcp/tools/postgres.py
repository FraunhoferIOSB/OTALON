"""PostgreSQL helper functions for MCP tools.

This module encapsulates logic for OTALON PostgreSQL data access:
- bounds reading
- anomalies and alarms querying
- simple aggregations for alarm counts

It is initialized via tools.__init__.init() which passes the PostgresRepo and Defaults.

Docstrings are written in English as per workspace rules.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from loguru import logger

from otalon_mcp.repositories.postgres_repo import PostgresRepo
from otalon_mcp.serialization import dataframe_to_records

from .utils import time_range_default

PG_REPO: PostgresRepo | None = None
DEFAULTS: Any | None = None


# Anomaly types produced by bounds-derived detection (otalon-clas
# `BoundsManager`). Bounds-write tools (write/expand/replace_bounds) only
# affect alarms whose anomalies carry one of these types. ML / MITRE
# classifications (every other label) are not actionable via bounds.
BOUNDS_DERIVED_TYPES: frozenset[str] = frozenset({"BoundViolation", "NoBounds"})


def init(pg_repo: PostgresRepo, defaults: Any) -> None:
    """Initialize postgres helpers with shared dependencies."""
    global PG_REPO, DEFAULTS
    PG_REPO = pg_repo
    DEFAULTS = defaults
    logger.debug("tools.postgres.init: repo and defaults injected")


def _active_feature_set() -> list[str]:
    """Return the canonical active feature set the bounds tools enforce.

    Falls back to an empty list when ``DEFAULTS`` has not been wired up
    (test contexts that skip ``init``). The list mirrors
    ``Defaults.fields`` and is the contract every bounds-write payload is
    validated against.
    """
    if DEFAULTS is None:
        return []
    fields = getattr(DEFAULTS, "fields", None)
    return list(fields) if fields else []


def _validate_feature_completeness(
    lower_bounds: Dict[str, Any],
    upper_bounds: Dict[str, Any],
    *,
    allow_null_values: bool,
    tool_name: str,
) -> Optional[Dict[str, Any]]:
    """Validate that the bounds payloads cover every feature in the active set.

    Returns ``None`` when the payload is acceptable. Otherwise returns an
    MCP-style error dict ``{"ok": False, "error": ..., "missing": [...],
    "supplied": [...], "expected": [...], "status_code": 422}`` so the
    calling LLM can self-correct with a single follow-up call.

    Rules:
    * ``lower_bounds`` and ``upper_bounds`` MUST each carry a key for
      every feature in the active set. Extra keys outside the active set
      are tolerated (forwards-compatible with future feature additions)
      but a SUBSET is rejected.
    * When ``allow_null_values`` is ``False`` (``replace_bounds``), a key
      whose value is ``None`` counts as missing — replace requires real
      ``(lo, hi)`` for every feature.
    * When ``allow_null_values`` is ``True`` (``expand_bounds``), ``None``
      is a valid "do-not-expand this feature" no-op marker and is treated
      as present.
    """
    active = _active_feature_set()
    if not active:
        return None

    def _missing(payload: Dict[str, Any]) -> list[str]:
        gaps: list[str] = []
        for feat in active:
            if feat not in payload:
                gaps.append(feat)
            elif not allow_null_values and payload.get(feat) is None:
                gaps.append(feat)
        return gaps

    lower_payload = lower_bounds or {}
    upper_payload = upper_bounds or {}
    missing_lower = _missing(lower_payload)
    missing_upper = _missing(upper_payload)
    if not missing_lower and not missing_upper:
        return None

    # Surface a single deduplicated, deterministically ordered list so the
    # LLM can fill in every gap with one follow-up call.
    missing_combined = sorted({*missing_lower, *missing_upper})
    supplied_combined = sorted({*lower_payload.keys(), *upper_payload.keys()})
    detail = (
        f"bounds incomplete — got {supplied_combined}, expected {active}; "
        "you must supply a value for every feature in the active feature set "
    )
    if allow_null_values:
        detail += "(null is a valid 'do-not-expand' no-op marker)."
    else:
        detail += "(replace_bounds requires real lo/hi values; null is not accepted)."
    err: Dict[str, Any] = {
        "ok": False,
        "error": detail,
        "missing": missing_combined,
        "missing_lower": missing_lower,
        "missing_upper": missing_upper,
        "supplied": supplied_combined,
        "expected": list(active),
        "status_code": 422,
    }
    logger.warning(
        "tools.postgres.{tool} rejected: incomplete feature set " "(missing={missing}, supplied={supplied})",
        tool=tool_name,
        missing=missing_combined,
        supplied=supplied_combined,
    )
    return err


def _check_all_tighter_warning(
    series_id: str,
    module: str,
    lower_bounds: Dict[str, Any],
    upper_bounds: Dict[str, Any],
) -> Optional[str]:
    """Emit an advisory warning when every supplied bound is tighter than current.

    Bounds-tuning to NARROW thresholds across the board for an expand
    call is almost always a misuse — the operator likely intended
    ``replace_bounds`` or has misread the data. We return a string the
    caller can attach as ``warning`` (operation still succeeds), or
    ``None`` when no advisory is warranted (read failure, no prior row,
    at least one widened feature).
    """
    if PG_REPO is None:
        return None
    try:
        df = PG_REPO.query_bounds(module=module, series_id=series_id, features=None)
        if df is None or df.empty:
            return None
        # query_bounds returns the raw lower_bounds/upper_bounds dicts in
        # those columns when no `features` flattening is requested.
        try:
            old_lower = df["lower_bounds"].iloc[0] or {}
            old_upper = df["upper_bounds"].iloc[0] or {}
        except (KeyError, IndexError):
            return None
        old_lower = old_lower if isinstance(old_lower, dict) else {}
        old_upper = old_upper if isinstance(old_upper, dict) else {}

        any_widened = False
        any_tighter = False
        for feat, new_lo in (lower_bounds or {}).items():
            if new_lo is None:
                continue
            old_lo = old_lower.get(feat)
            if old_lo is None:
                # New feature — counts as a widening
                any_widened = True
                continue
            try:
                if float(new_lo) < float(old_lo):
                    any_widened = True
                elif float(new_lo) > float(old_lo):
                    any_tighter = True
            except (TypeError, ValueError):
                continue
        for feat, new_hi in (upper_bounds or {}).items():
            if new_hi is None:
                continue
            old_hi = old_upper.get(feat)
            if old_hi is None:
                any_widened = True
                continue
            try:
                if float(new_hi) > float(old_hi):
                    any_widened = True
                elif float(new_hi) < float(old_hi):
                    any_tighter = True
            except (TypeError, ValueError):
                continue
        if any_tighter and not any_widened:
            msg = (
                "Every supplied bound is tighter than the current stored "
                "value — expand_bounds is intended to WIDEN bounds for "
                "false-positive remediation. If you meant to tighten the "
                "envelope, call replace_bounds with an explicit operator "
                "confirmation."
            )
            logger.warning(
                "tools.postgres.expand_bounds advisory: all-tighter payload for " "series_id={s}",
                s=series_id,
            )
            return msg
    except Exception as exc:
        logger.debug(
            "tools.postgres._check_all_tighter_warning skipped: series_id={s}, exc={e}",
            s=series_id,
            e=exc,
        )
    return None


def _resolve_classification(series_id: Optional[str]) -> Dict[str, Any]:
    """Return a ``classification`` summary for ``series_id``.

    Surfaces three pieces of operator-relevant context next to the bounds
    payload so the LLM agent can decide whether to expand/replace bounds
    or suppress anomalies instead:

    * ``has_active_suppression`` — bool
    * ``suppressed_types`` — list[str] (empty when no suppression)
    * ``warning`` — short, human-readable string when a suppression
      already exists (so the agent reconsiders before mutating bounds)

    Failures to query are non-fatal: the function returns a sentinel block
    with ``error`` set and the boolean fields default to False/empty so
    the caller can still surface bounds.
    """
    if not series_id or PG_REPO is None:
        return {"has_active_suppression": False, "suppressed_types": []}
    try:
        listing = PG_REPO.list_suppressions(series_id=series_id, include_expired=False)
        if not listing.get("ok"):
            return {
                "has_active_suppression": False,
                "suppressed_types": [],
                "error": listing.get("error", "list_suppressions failed"),
            }
        records = listing.get("records") or []
        if not records:
            return {"has_active_suppression": False, "suppressed_types": []}
        first = records[0]
        types = list(first.get("suppressed_types") or [])
        return {
            "has_active_suppression": True,
            "suppressed_types": types,
            "reason": first.get("reason", ""),
            "expires_at": first.get("expires_at"),
            "warning": (
                "An active anomaly suppression exists for this series_id. "
                "Anomalies of the listed types are dropped before persistence; "
                "expanding bounds here will not change that. Consider whether "
                "the operator wants to lift the suppression or refine its types "
                "instead of widening bounds."
            ),
        }
    except Exception as exc:
        logger.warning(
            "tools.postgres._resolve_classification failed: series_id={s}, exc={e}",
            s=series_id,
            e=exc,
        )
        return {
            "has_active_suppression": False,
            "suppressed_types": [],
            "error": str(exc),
        }


def _classify_recent_alarms(
    series_id: Optional[str],
    lookback_minutes: int = 1440,
) -> Optional[Dict[str, Any]]:
    """Classify the most recent alarms for a UCI by detector family.

    Returns a ``recent_alarm_classification`` payload of the shape::

        {
          "detector": "bounds" | "ml_rule" | "frequency" | "fusion" | "none",
          "anomaly_type": "BoundViolation" | "T0846/arp_scan" | ... | "",
          "last_seen": "<ISO-8601 UTC>" | "",
          "count_in_window": int,
          "bounds_derived_count": int,
          "ml_derived_count": int,
          "actionable_by_bounds_tools": bool,
          "recommended_action": str,
          "window_minutes": int,
        }

    Returns ``None`` when ``series_id`` is empty or the lookup cannot run
    (e.g. repo not initialised), so the caller can omit the block. A
    successful lookup with zero matching anomalies still returns a payload
    with ``detector="none"`` and an instructive ``recommended_action`` so
    the LLM does not silently skip the signal.

    Detector classification follows ``otalon-common``'s anomaly-type
    taxonomy: ``BoundViolation`` / ``NoBounds`` are bounds-derived;
    ``FrequencyAnomaly`` / ``AbsenceAnomaly`` are frequency-derived;
    every other label (MITRE technique strings, ``arp_scan`` /
    ``port_scan`` short labels, etc.) is ML-derived (``ml_rule``). If
    both kinds appear in the window the detector is reported as
    ``fusion``.
    """
    if not series_id or PG_REPO is None:
        return None
    records: list[dict[str, Any]] = []
    try:
        # Query the anomalies table directly. Production stores rows
        # under ``module="conn"`` (the live deployment); legacy
        # deployments use ``netcap``. Try each in turn, then fall back
        # to a module-agnostic raw query so we don't silently miss
        # alarms after a module rename.
        tr = time_range_default(lookback_minutes)
        for module_filter in ("conn", "netcap"):
            try:
                df = PG_REPO.query_anomalies(
                    module=module_filter,
                    series_id=series_id,
                    metric=None,
                    time_range=tr,
                )
                if df is not None and not df.empty:
                    records = dataframe_to_records(df)
                    break
            except Exception as exc:
                logger.debug(
                    "tools.postgres._classify_recent_alarms partial query " "failed: module_filter={m!r}, exc={e}",
                    m=module_filter,
                    e=exc,
                )
                continue
        if not records:
            # Final fallback: raw query without module filter via
            # ``query_table`` so deployments using a non-standard
            # module label still classify.
            try:
                where = "series_id = :series_id " "AND start_ts <= :stop AND end_ts >= :start"
                df = PG_REPO.query_table(
                    "anomalies",
                    where=where,
                    params={
                        "series_id": series_id,
                        "start": tr[0],
                        "stop": tr[1],
                    },
                )
                if df is not None and not df.empty:
                    records = dataframe_to_records(df)
            except Exception as exc:
                logger.debug(
                    "tools.postgres._classify_recent_alarms raw fallback " "failed: exc={e}",
                    e=exc,
                )
    except Exception as exc:
        logger.debug(
            "tools.postgres._classify_recent_alarms read failed: " "series_id={s}, exc={e}",
            s=series_id,
            e=exc,
        )
        return None

    if not records:
        return {
            "detector": "none",
            "anomaly_type": "",
            "last_seen": "",
            "count_in_window": 0,
            "bounds_derived_count": 0,
            "ml_derived_count": 0,
            "frequency_derived_count": 0,
            "actionable_by_bounds_tools": False,
            "recommended_action": (
                f"No anomalies recorded for series_id={series_id!r} in the "
                f"last {lookback_minutes} minutes. If you are tuning bounds "
                "pre-emptively, prefer write_bounds (first-time) or expand_bounds "
                "(widen). If you expected alarms, check list_anomaly_suppressions "
                "for an active suppression."
            ),
            "window_minutes": lookback_minutes,
        }

    bounds_count = 0
    ml_count = 0
    freq_count = 0
    latest_ts = ""
    latest_type = ""
    for rec in records:
        atype = str(rec.get("anomaly_type") or rec.get("type") or "")
        ts = str(
            rec.get("end_ts") or rec.get("start_ts") or rec.get("end_timestamp") or rec.get("start_timestamp") or ""
        )
        if ts > latest_ts:
            latest_ts = ts
            latest_type = atype
        if atype in BOUNDS_DERIVED_TYPES:
            bounds_count += 1
        elif atype in {"FrequencyAnomaly", "AbsenceAnomaly"}:
            freq_count += 1
        elif atype:
            ml_count += 1

    if bounds_count and (ml_count or freq_count):
        detector = "fusion"
    elif bounds_count:
        detector = "bounds"
    elif ml_count:
        detector = "ml_rule"
    elif freq_count:
        detector = "frequency"
    else:
        detector = "none"

    actionable = detector in {"bounds", "fusion"}
    if detector == "bounds":
        recommendation = (
            "Recent alarms are bounds-derived. Calling expand_bounds with a "
            "wider envelope (~5–10% headroom) should silence them."
        )
    elif detector == "ml_rule":
        recommendation = (
            f"Recent alarms are ML-derived (detector={detector}). Bounds "
            "tools will not help — call add_anomaly_suppression with the "
            "confirmed-benign anomaly types instead."
        )
    elif detector == "frequency":
        recommendation = (
            "Recent alarms are frequency-derived (FrequencyAnomaly / "
            "AbsenceAnomaly). Bounds tools will not help — adjust the "
            "frequency monitor configuration or call add_anomaly_suppression "
            "for the FrequencyAnomaly / AbsenceAnomaly types."
        )
    elif detector == "fusion":
        recommendation = (
            "Recent alarms mix bounds-derived and non-bounds-derived types. "
            "Use expand_bounds for the bounds-derived part AND "
            "add_anomaly_suppression for the ML / frequency-derived part."
        )
    else:
        recommendation = f"No classifiable anomalies in the last {lookback_minutes} minutes."

    return {
        "detector": detector,
        "anomaly_type": latest_type,
        "last_seen": latest_ts,
        "count_in_window": len(records),
        "bounds_derived_count": bounds_count,
        "ml_derived_count": ml_count,
        "frequency_derived_count": freq_count,
        "actionable_by_bounds_tools": actionable,
        "recommended_action": recommendation,
        "window_minutes": lookback_minutes,
    }


def _resolve_detector_warning(series_id: Optional[str]) -> Optional[str]:
    """Return a one-line advisory when the most recent alarms aren't bounds-derived.

    Used by ``expand_bounds`` / ``replace_bounds`` to surface that
    further bounds tuning is unlikely to silence the operator-observed
    alarms. The operation still succeeds — this is advisory text only.
    """
    classification = _classify_recent_alarms(series_id)
    if not classification:
        return None
    if classification.get("actionable_by_bounds_tools"):
        return None
    if classification.get("count_in_window", 0) == 0:
        return None
    detector = classification.get("detector", "unknown")
    n = classification.get("count_in_window", 0)
    return (
        f"The most recent {n} alarm(s) for this series_id were not "
        f"bounds-derived (detector={detector}). Updating bounds is unlikely "
        "to stop them. Consider add_anomaly_suppression instead — see the "
        "recommended_action on read_bounds for the full classification."
    )


def read_bounds(
    module: str = "netcap",
    series_id: Optional[str] = None,
    features: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Read trained bounds for a module and optional series_id.

    When ``series_id`` is set, the result also carries a
    ``classification`` block surfacing any active anomaly suppression so
    the caller can decide between expanding bounds and lifting the
    suppression, plus a ``recent_alarm_classification`` block reporting
    whether the most recent alarms for this UCI are bounds-derived
    (``actionable_by_bounds_tools=True``) or ML- / frequency-derived
    (``actionable_by_bounds_tools=False`` + a ``recommended_action`` that
    points the caller at ``add_anomaly_suppression`` instead).
    """
    if PG_REPO is None or DEFAULTS is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.read_bounds error: {err}", err=err)
        return err

    try:
        feat = features or list(DEFAULTS.fields)
        df = PG_REPO.query_bounds(module=module, series_id=series_id, features=feat)

        if df is not None and not df.empty and ("lower_bounds" in df.columns or "upper_bounds" in df.columns):
            lower_raw = (
                df["lower_bounds"] if "lower_bounds" in df.columns else pd.Series([{}] * len(df), dtype="object")
            )
            upper_raw = (
                df["upper_bounds"] if "upper_bounds" in df.columns else pd.Series([{}] * len(df), dtype="object")
            )
            lower_df = pd.json_normalize(lower_raw.to_list())
            upper_df = pd.json_normalize(upper_raw.to_list())

            if feat:
                keep_lb = [c for c in feat if c in lower_df.columns]
                keep_ub = [c for c in feat if c in upper_df.columns]
                lower_df = lower_df[keep_lb] if keep_lb else pd.DataFrame(index=lower_df.index)
                upper_df = upper_df[keep_ub] if keep_ub else pd.DataFrame(index=upper_df.index)

            lower_df.columns = [f"lb_{c.split('.')[-1]}" for c in lower_df.columns]
            upper_df.columns = [f"ub_{c.split('.')[-1]}" for c in upper_df.columns]

            drop_meta = [
                "lower_bounds",
                "upper_bounds",
                "trained_at",
                "first_ts",
                "last_ts",
            ]
            meta = df.drop(columns=drop_meta, errors="ignore").reset_index(drop=True)
            df = pd.concat(
                [
                    meta,
                    lower_df.reset_index(drop=True),
                    upper_df.reset_index(drop=True),
                ],
                axis=1,
            )

        records = dataframe_to_records(df)
        result: Dict[str, Any] = {"ok": True, "records": records}
        result["classification"] = _resolve_classification(series_id)
        recent_classification = _classify_recent_alarms(series_id)
        if recent_classification is not None:
            result["recent_alarm_classification"] = recent_classification
        return result
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.read_bounds error: {err}", err=err)
        return err


def write_bounds(
    module: str,
    series_id: str,
    lower_bounds: Dict[str, Any],
    upper_bounds: Dict[str, Any],
    reason: str,
) -> Dict[str, Any]:
    """Create new bounds for ``(module, series_id)``.

    Errors if a bounds row already exists. Use ``expand_bounds`` or
    ``replace_bounds`` for existing rows. Always returns a dict with
    ``ok`` and either ``history_id`` or ``error``.
    """
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.write_bounds error: {err}", err=err)
        return err
    if not reason or not str(reason).strip():
        err = {"ok": False, "error": "Parameter 'reason' must be a non-empty string."}
        logger.warning("tools.postgres.write_bounds rejected: {err}", err=err)
        return err
    try:
        return PG_REPO.write_bounds(
            module=module,
            series_id=series_id,
            lower_bounds=lower_bounds or {},
            upper_bounds=upper_bounds or {},
            reason=reason,
        )
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.write_bounds error: {err}", err=err)
        return err


def expand_bounds(
    module: str,
    series_id: str,
    lower_bounds: Dict[str, Any],
    upper_bounds: Dict[str, Any],
    reason: str,
) -> Dict[str, Any]:
    """Widen the existing bounds row per-feature (min lower, max upper).

    Fails if no bounds row exists for ``(module, series_id)``. Validates
    that the payload covers EVERY feature in the active feature set
    before mutating; a feature value of ``null`` is a valid
    "do-not-expand" no-op marker. Annotates the response with a
    ``warning`` when the most recent alarms for this UCI are not
    bounds-derived (advisory only — operation still succeeds).
    """
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.expand_bounds error: {err}", err=err)
        return err
    if not reason or not str(reason).strip():
        err = {"ok": False, "error": "Parameter 'reason' must be a non-empty string."}
        logger.warning("tools.postgres.expand_bounds rejected: {err}", err=err)
        return err
    validation_err = _validate_feature_completeness(
        lower_bounds or {},
        upper_bounds or {},
        allow_null_values=True,
        tool_name="expand_bounds",
    )
    if validation_err is not None:
        return validation_err

    # Advisory: detect all-tighter payloads BEFORE mutation; record them
    # but do not block. Bounds remain widened-only by repo semantics.
    advisory = _check_all_tighter_warning(
        series_id=series_id,
        module=module,
        lower_bounds=lower_bounds or {},
        upper_bounds=upper_bounds or {},
    )

    # Strip ``null`` markers — they are explicit no-ops, and forwarding
    # them to the repo would either crash the JSON column or be silently
    # treated as "0 / inf". Filtering keeps the contract simple:
    # null in -> feature untouched.
    effective_lower = {k: v for k, v in (lower_bounds or {}).items() if v is not None}
    effective_upper = {k: v for k, v in (upper_bounds or {}).items() if v is not None}

    try:
        result = PG_REPO.expand_bounds(
            module=module,
            series_id=series_id,
            lower_bounds=effective_lower,
            upper_bounds=effective_upper,
            reason=reason,
        )
        if isinstance(result, dict) and result.get("ok"):
            result["classification"] = _resolve_classification(series_id)
            detector_warning = _resolve_detector_warning(series_id)
            warnings: list[str] = []
            if advisory:
                warnings.append(advisory)
            if detector_warning:
                warnings.append(detector_warning)
            if warnings:
                result["warning"] = " | ".join(warnings)
        return result
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.expand_bounds error: {err}", err=err)
        return err


def replace_bounds(
    module: str,
    series_id: str,
    lower_bounds: Dict[str, Any],
    upper_bounds: Dict[str, Any],
    reason: str,
) -> Dict[str, Any]:
    """Fully overwrite the bounds row (destructive).

    Creates the row if missing. May NARROW bounds — only call when the
    operator explicitly says replace. Validates that the payload covers
    EVERY feature in the active feature set with real ``(lo, hi)``
    values; ``null`` is NOT permitted. Annotates the response with a
    ``warning`` when the most recent alarms for this UCI are not
    bounds-derived.
    """
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.replace_bounds error: {err}", err=err)
        return err
    if not reason or not str(reason).strip():
        err = {"ok": False, "error": "Parameter 'reason' must be a non-empty string."}
        logger.warning("tools.postgres.replace_bounds rejected: {err}", err=err)
        return err
    validation_err = _validate_feature_completeness(
        lower_bounds or {},
        upper_bounds or {},
        allow_null_values=False,
        tool_name="replace_bounds",
    )
    if validation_err is not None:
        return validation_err

    try:
        result = PG_REPO.replace_bounds(
            module=module,
            series_id=series_id,
            lower_bounds=lower_bounds or {},
            upper_bounds=upper_bounds or {},
            reason=reason,
        )
        if isinstance(result, dict) and result.get("ok"):
            result["classification"] = _resolve_classification(series_id)
            detector_warning = _resolve_detector_warning(series_id)
            if detector_warning:
                result["warning"] = detector_warning
        return result
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.replace_bounds error: {err}", err=err)
        return err


def add_suppression(
    series_id: str,
    suppressed_types: List[str],
    reason: str,
    created_by: Optional[str] = None,
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Add or update a per-UCI anomaly-type suppression.

    Persists the rule that ``otalon-clas`` consults in the persistence
    layer to drop confirmed false positives before they reach the
    ``anomalies`` / ``alarms`` tables. Idempotent: calling twice with the
    same types is a no-op; passing additional types unions them onto the
    existing set.
    """
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.add_suppression error: {err}", err=err)
        return err
    if not reason or not str(reason).strip():
        err = {"ok": False, "error": "reason must be a non-empty string"}
        logger.warning("tools.postgres.add_suppression rejected: {err}", err=err)
        return err
    try:
        return PG_REPO.add_suppression(
            series_id=series_id,
            suppressed_types=suppressed_types,
            reason=reason,
            created_by=created_by,
            expires_at=expires_at,
        )
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.add_suppression error: {err}", err=err)
        return err


def list_suppressions(
    series_id: Optional[str] = None,
    include_expired: bool = False,
) -> Dict[str, Any]:
    """List active anomaly-type suppressions, optionally for one ``series_id``.

    ``include_expired=False`` skips rows whose ``expires_at`` is in the
    past. Returns ``{"ok": True, "records": [...], "count": N}`` with one
    record per UCI, including its ``suppressed_types`` list, ``reason``,
    ``created_by``, ``created_at``, and ``expires_at`` (ISO-8601 strings).
    """
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.list_suppressions error: {err}", err=err)
        return err
    try:
        return PG_REPO.list_suppressions(series_id=series_id, include_expired=include_expired)
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.list_suppressions error: {err}", err=err)
        return err


def remove_suppression(
    series_id: str,
    suppressed_types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Remove suppression(s) for a UCI.

    ``suppressed_types=None`` deletes the row entirely. A non-empty list
    removes those types and either updates the remaining set or — when
    the resulting set is empty — deletes the row. Returns ``{"ok": True,
    "action": "delete"|"update"|"noop", "remaining_types": [...]}``.
    """
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.remove_suppression error: {err}", err=err)
        return err
    try:
        return PG_REPO.remove_suppression(series_id=series_id, suppressed_types=suppressed_types)
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.remove_suppression error: {err}", err=err)
        return err


def read_anomalies(
    module: str = "netcap",
    series_id: Optional[str] = None,
    metric: Optional[str] = None,
    start: Optional[str] = None,
    stop: Optional[str] = None,
    limit: int = 100,
    default_window_minutes: int = 1440,
) -> Dict[str, Any]:
    """Read anomalies filtered by module, optional series/metric and optional time range."""
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.read_anomalies error: {err}", err=err)
        return err

    try:
        tr: Optional[Tuple[str, str]]
        if start and stop:
            tr = (start, stop)
        else:
            tr = time_range_default(default_window_minutes)

        df = PG_REPO.query_anomalies(module=module, series_id=series_id, metric=metric, time_range=tr)
        if isinstance(limit, int) and limit > 0:
            df = df.head(limit)
        records = dataframe_to_records(df)
        return {"ok": True, "records": records, "count": len(records)}
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.read_anomalies error: {err}", err=err)
        return err


def read_alarms(
    module: Optional[str] = None,
    type_: Optional[str] = None,
    confirmed: Optional[bool] = None,
    start: Optional[str] = None,
    stop: Optional[str] = None,
    limit: int = 200,
    default_window_minutes: int = 1440,
) -> Dict[str, Any]:
    """Read alarm groups with optional filters."""
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.read_alarms error: {err}", err=err)
        return err

    try:
        tr: Optional[Tuple[str, str]]
        if start and stop:
            tr = (start, stop)
        else:
            tr = time_range_default(default_window_minutes)

        df = PG_REPO.query_anomaly_groups(
            module=module,
            type_=type_,
            confirmed=confirmed,
            time_range=tr,
            limit=limit,
        )
        records = dataframe_to_records(df)
        return {"ok": True, "records": records, "count": len(records)}
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.read_alarms error: {err}", err=err)
        return err


def read_alarm_details(id: Optional[str] = None) -> Dict[str, Any]:
    """Read details for a single alarm by its ID."""
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.read_alarm_details error: {err}", err=err)
        return err

    if not id:
        err = {"ok": False, "error": "Parameter 'id' is required."}
        logger.error("tools.postgres.read_alarm_details error: {err}", err=err)
        return err

    try:
        df = PG_REPO.get_anomaly_group_by_id(id)
        recs = dataframe_to_records(df)
        record = recs[0] if recs else {}
        return {"ok": True, "record": record}
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.read_alarm_details error: {err}", err=err)
        return err


def read_recent_alarms(minutes: int = 120, limit: int = 50) -> Dict[str, Any]:
    """Read recent alarms within the last N minutes."""
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.read_recent_alarms error: {err}", err=err)
        return err

    try:
        start_ts, stop_ts = time_range_default(minutes)
        df = PG_REPO.query_anomaly_groups(time_range=(start_ts, stop_ts), limit=limit)
        records = dataframe_to_records(df)
        return {"ok": True, "records": records, "count": len(records)}
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.read_recent_alarms error: {err}", err=err)
        return err


def get_top_alarm_counts(k: int = 10, group_by: str = "primary_type", minutes: int = 1440) -> Dict[str, Any]:
    """Read the top-k alarm values and their counts.

    ``group_by`` defaults to ``primary_type`` because the ``alarms``
    table has no ``type`` column; the previous default silently produced
    an empty result for every call (audit MCP-08).
    """
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.get_top_alarm_counts error: {err}", err=err)
        return err

    try:
        start_ts, stop_ts = time_range_default(minutes)
        df = PG_REPO.query_anomaly_groups(time_range=(start_ts, stop_ts))
        if df is None or df.empty or group_by not in df.columns:
            return {"ok": True, "rows": [], "k": 0, "total": 0}
        vc = df[group_by].astype(str).value_counts(dropna=False)
        top = [(str(idx), int(ct)) for idx, ct in vc.head(max(1, k)).items()]
        total = int(vc.sum())
        return {"ok": True, "rows": top, "k": len(top), "total": total}
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.get_top_alarm_counts error: {err}", err=err)
        return err


def _log_asset_mutation(
    tool: str,
    args: Dict[str, Any],
    target_id: Optional[int] = None,
    ok: bool = True,
) -> None:
    """Structured audit log for asset/device/interface write tools.

    Emits a single ``mcp_asset_mutation`` event so operators can trace
    every CRUD call through MCP back to a user / chat session. Logged
    at INFO so it surfaces in the default otalon-mcp.log without
    requiring debug-level configuration.
    """
    logger.info(
        "mcp_asset_mutation tool={tool} target_id={target_id} ok={ok} " "by={by} args={args}",
        tool=tool,
        target_id=target_id,
        ok=ok,
        by="mcp-prod",
        args=args,
    )


def _err(tool: str, msg: str) -> Dict[str, Any]:
    err = {"ok": False, "error": msg}
    logger.error("tools.postgres.{t} error: {e}", t=tool, e=err)
    return err


# ── devices ─────────────────────────────────────────────────────────────


def list_devices(limit: int = 200, offset: int = 0) -> Dict[str, Any]:
    """List devices (paginated). Read-only — no audit log."""
    if PG_REPO is None:
        return _err("list_devices", "Postgres helpers not initialized")
    try:
        records = PG_REPO.list_devices(limit=limit, offset=offset)
        return {"ok": True, "records": records, "count": len(records)}
    except Exception as exc:
        return _err("list_devices", str(exc))


def get_device(device_id: int) -> Dict[str, Any]:
    """Get one device by id."""
    if PG_REPO is None:
        return _err("get_device", "Postgres helpers not initialized")
    try:
        row = PG_REPO.get_device(int(device_id))
        if row is None:
            return {"ok": False, "error": f"device {device_id} not found"}
        return {"ok": True, "record": row}
    except Exception as exc:
        return _err("get_device", str(exc))


def add_device(
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
    """Insert a new device row. Logs an audit event."""
    if PG_REPO is None:
        return _err("add_device", "Postgres helpers not initialized")
    payload: Dict[str, Any] = {
        k: v
        for k, v in {
            "primary_mac": primary_mac,
            "vendor": vendor,
            "device_family": device_family,
            "device_type": device_type,
            "description": description,
            "article_number": article_number,
            "device_role": device_role,
            "firmware_version": firmware_version,
            "update_available": update_available,
            "notes": notes,
        }.items()
        if v is not None
    }
    try:
        row = PG_REPO.add_device(payload)
        _log_asset_mutation("add_device", payload, target_id=int(row.get("id") or 0), ok=True)
        return {"ok": True, "record": row}
    except Exception as exc:
        _log_asset_mutation("add_device", payload, target_id=None, ok=False)
        return _err("add_device", str(exc))


def update_device(
    device_id: int,
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
    """Partial update of a device row. Only non-None values are written."""
    if PG_REPO is None:
        return _err("update_device", "Postgres helpers not initialized")
    payload: Dict[str, Any] = {
        k: v
        for k, v in {
            "primary_mac": primary_mac,
            "vendor": vendor,
            "device_family": device_family,
            "device_type": device_type,
            "description": description,
            "article_number": article_number,
            "device_role": device_role,
            "firmware_version": firmware_version,
            "update_available": update_available,
            "notes": notes,
        }.items()
        if v is not None
    }
    try:
        row = PG_REPO.update_device(int(device_id), payload)
        if row is None:
            return {"ok": False, "error": f"device {device_id} not found"}
        _log_asset_mutation("update_device", payload, target_id=int(device_id), ok=True)
        return {"ok": True, "record": row}
    except Exception as exc:
        _log_asset_mutation("update_device", payload, target_id=int(device_id), ok=False)
        return _err("update_device", str(exc))


def delete_device(device_id: int, cascade_interfaces: bool = False) -> Dict[str, Any]:
    """Hard-delete a device row.

    ``cascade_interfaces=False`` (default) lets the table-level FK
    ``ON DELETE SET NULL`` orphan all owned interfaces (they keep
    existing as bare network identities). ``cascade_interfaces=True``
    deletes every owned interface and their cascaded service /
    vulnerability observations.
    """
    if PG_REPO is None:
        return _err("delete_device", "Postgres helpers not initialized")
    args = {"device_id": int(device_id), "cascade_interfaces": bool(cascade_interfaces)}
    try:
        result = PG_REPO.delete_device(int(device_id), cascade_interfaces=bool(cascade_interfaces))
        _log_asset_mutation(
            "delete_device",
            args,
            target_id=int(device_id),
            ok=bool(result.get("ok")),
        )
        return result
    except Exception as exc:
        _log_asset_mutation("delete_device", args, target_id=int(device_id), ok=False)
        return _err("delete_device", str(exc))


# ── network_interfaces ──────────────────────────────────────────────────


def list_interfaces(
    device_id: Optional[int] = None,
    limit: int = 200,
    offset: int = 0,
) -> Dict[str, Any]:
    """List network interfaces (paginated, optional device filter)."""
    if PG_REPO is None:
        return _err("list_interfaces", "Postgres helpers not initialized")
    try:
        records = PG_REPO.list_interfaces(device_id=device_id, limit=limit, offset=offset)
        return {"ok": True, "records": records, "count": len(records)}
    except Exception as exc:
        return _err("list_interfaces", str(exc))


def get_interface(interface_id: int) -> Dict[str, Any]:
    if PG_REPO is None:
        return _err("get_interface", "Postgres helpers not initialized")
    try:
        row = PG_REPO.get_interface(int(interface_id))
        if row is None:
            return {"ok": False, "error": f"interface {interface_id} not found"}
        return {"ok": True, "record": row}
    except Exception as exc:
        return _err("get_interface", str(exc))


def add_interface(
    device_id: Optional[int] = None,
    mac_address: Optional[str] = None,
    ipv4_address: Optional[str] = None,
    ipv6_address: Optional[str] = None,
    subnet: Optional[str] = None,
    notes: Optional[str] = None,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    """Insert a new network_interfaces row. Logs an audit event.

    ``source`` defaults to ``"manual"`` so MCP-originated rows are
    distinguishable from active-scan (``"active"``) and passive-seeder
    (``"passive"``) rows in audits.
    """
    if PG_REPO is None:
        return _err("add_interface", "Postgres helpers not initialized")
    payload: Dict[str, Any] = {
        k: v
        for k, v in {
            "device_id": device_id,
            "mac_address": mac_address,
            "ipv4_address": ipv4_address,
            "ipv6_address": ipv6_address,
            "subnet": subnet,
            "notes": notes,
            "source": source,
        }.items()
        if v is not None
    }
    try:
        row = PG_REPO.add_interface(payload)
        _log_asset_mutation("add_interface", payload, target_id=int(row.get("id") or 0), ok=True)
        return {"ok": True, "record": row}
    except Exception as exc:
        _log_asset_mutation("add_interface", payload, target_id=None, ok=False)
        return _err("add_interface", str(exc))


def update_interface(
    interface_id: int,
    device_id: Optional[int] = None,
    mac_address: Optional[str] = None,
    ipv4_address: Optional[str] = None,
    ipv6_address: Optional[str] = None,
    subnet: Optional[str] = None,
    notes: Optional[str] = None,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    """Partial update of a network_interfaces row."""
    if PG_REPO is None:
        return _err("update_interface", "Postgres helpers not initialized")
    payload: Dict[str, Any] = {
        k: v
        for k, v in {
            "device_id": device_id,
            "mac_address": mac_address,
            "ipv4_address": ipv4_address,
            "ipv6_address": ipv6_address,
            "subnet": subnet,
            "notes": notes,
            "source": source,
        }.items()
        if v is not None
    }
    try:
        row = PG_REPO.update_interface(int(interface_id), payload)
        if row is None:
            return {"ok": False, "error": f"interface {interface_id} not found"}
        _log_asset_mutation("update_interface", payload, target_id=int(interface_id), ok=True)
        return {"ok": True, "record": row}
    except Exception as exc:
        _log_asset_mutation("update_interface", payload, target_id=int(interface_id), ok=False)
        return _err("update_interface", str(exc))


def delete_interface(interface_id: int) -> Dict[str, Any]:
    """Hard-delete a network_interfaces row.

    Cascades service- and vulnerability-observations attached to the
    interface (table-level FK ``ON DELETE CASCADE``).
    """
    if PG_REPO is None:
        return _err("delete_interface", "Postgres helpers not initialized")
    args = {"interface_id": int(interface_id)}
    try:
        result = PG_REPO.delete_interface(int(interface_id))
        _log_asset_mutation(
            "delete_interface",
            args,
            target_id=int(interface_id),
            ok=bool(result.get("ok")),
        )
        return result
    except Exception as exc:
        _log_asset_mutation("delete_interface", args, target_id=int(interface_id), ok=False)
        return _err("delete_interface", str(exc))


def get_most_common_alarm(group_by: str = "primary_type", minutes: int = 1440) -> Dict[str, Any]:
    """Read the most common alarm value within the recent window.

    ``group_by`` defaults to ``primary_type`` — see
    :func:`get_top_alarm_counts` (audit MCP-08).
    """
    if PG_REPO is None:
        err = {"ok": False, "error": "Postgres helpers not initialized"}
        logger.error("tools.postgres.get_most_common_alarm error: {err}", err=err)
        return err

    try:
        start_ts, stop_ts = time_range_default(minutes)
        df = PG_REPO.query_anomaly_groups(time_range=(start_ts, stop_ts))
        if df is None or df.empty or group_by not in df.columns:
            return {"ok": True, "most_common": "", "count": 0, "total": 0, "top5": []}
        vc = df[group_by].astype(str).value_counts(dropna=False)
        if vc.empty:
            return {"ok": True, "most_common": "", "count": 0, "total": 0, "top5": []}
        top_value = str(vc.index[0])
        top_count = int(vc.iloc[0])
        total = int(vc.sum())
        top5 = [(str(idx), int(ct)) for idx, ct in vc.head(5).items()]
        return {
            "ok": True,
            "most_common": top_value,
            "count": top_count,
            "total": total,
            "top5": top5,
        }
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.postgres.get_most_common_alarm error: {err}", err=err)
        return err
