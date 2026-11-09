"""Derived detection readiness and bound-review services."""

from __future__ import annotations

import json
import math
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from otalon_api.domain.netcap.models import proto_series_hash
from otalon_api.domain.netcap.proto_resolver import ProtoHashResolver
from otalon_api.domain.time import time_policy
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.settings import Settings

MODULES = ("conn", "mac_traffic", "proto_traffic")
REPLACE_MARGIN_FRACTION = 0.05
FEATURES = {
    "conn": (
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
    ),
    "mac_traffic": (
        "out_conn_count",
        "out_total_packets",
        "out_total_volume",
        "out_unique_dst_count",
        "out_unique_proto_count",
        "in_conn_count",
        "in_total_packets",
        "in_total_volume",
        "in_unique_src_count",
        "ratio_in_out_packets",
        "ratio_in_out_volume",
        "total_unique_peers",
        "total_conn_count",
    ),
    "proto_traffic": (
        "proto_conn_count",
        "proto_total_packets",
        "proto_total_volume",
        "proto_unique_src_mac",
        "proto_unique_dst_mac",
        "proto_unique_mac_pairs",
        "proto_mean_packets_per_conn",
        "proto_mean_volume_per_conn",
        "proto_mean_packet_size",
        "proto_std_packet_size",
    ),
}


def derive_readiness(
    *,
    enabled: bool,
    bounds_count: int,
    frequency_count: int,
    no_bounds_count: int,
    last_training: datetime | None,
    schema_compatible: bool,
    training: bool,
    observe_only: bool = False,
    query_failed: bool = False,
) -> str:
    """Derive canonical readiness from persisted/runtime facts.

    ``query_failed`` (API-073): a fact query raised, so the zero/empty counts
    it returned are not evidence of an untrained module. Never report ``ready``
    in that case.
    """
    if training:
        return "training"
    if observe_only:
        return "observe-only"
    if query_failed:
        return "degraded"
    if not enabled:
        return "untrained"
    if not schema_compatible or (bounds_count and no_bounds_count > bounds_count):
        return "degraded"
    if not bounds_count or not frequency_count or last_training is None:
        return "untrained"
    if no_bounds_count and no_bounds_count >= max(1, bounds_count // 2):
        return "degraded"
    return "ready"


class DetectionReadinessService:
    """Read persisted detection facts and derive readiness without a state machine."""

    def __init__(
        self,
        postgres: PostgresRepository,
        config_path: str,
        model_dir: str,
        influx: InfluxRepository | None = None,
        settings: Settings | None = None,
        proto_resolver: ProtoHashResolver | None = None,
    ) -> None:
        self._pg = postgres
        # API-073: set by a fact query that raised; reset per instance (the
        # factory builds one service per request, so this never leaks).
        self._query_failed = False
        self._config_path = Path(config_path)
        self._model_dir = Path(model_dir)
        self._influx = influx
        self._settings = settings
        self._proto_resolver = proto_resolver

    def suggest_bounds(
        self,
        module: str,
        series_id: str,
        action: str,
        window_start: datetime,
        window_end: datetime,
    ) -> dict[str, Any]:
        """Compute a deterministic, read-only proposal from observed values.

        Observed extrema are used as the explainable candidate. Replace and
        Create widen each observed span by 5% on both sides; when its span is
        zero, the margin is 5% of the largest observed magnitude, with 1.0 as
        fallback. Expand keeps every current feature and only widens it. No
        repository write path is called.
        """
        current_row = self._current_envelope(module, series_id)
        config = self._module_config().get(module)
        current = current_row or {"lower_bounds": {}, "upper_bounds": {}}
        conflict = self._action_conflict(action, current_row is not None)
        if conflict:
            return self._unavailable(module, series_id, action, window_start, window_end, conflict, current)
        if config is None or not self._valid_suggestion_config(config):
            return self._unavailable(
                module,
                series_id,
                action,
                window_start,
                window_end,
                "Module suggestion config unavailable",
                current,
            )
        if self._influx is None:
            return self._unavailable(
                module,
                series_id,
                action,
                window_start,
                window_end,
                "Timeseries source unavailable",
                current,
            )
        features = self._configured_features(config)
        frame = self._query_suggestion_series(config, module, series_id, features, window_start, window_end)
        proposals, rationale, evidence = self._proposal_from_frame(frame, features, current, action)
        status = "available" if evidence == len(features) else "partial" if evidence else "unavailable"
        message = (
            "Observed feature evidence supports this proposal" if evidence else "No usable feature values in [from, to)"
        )
        return {
            "module": module,
            "series_id": series_id,
            "action": action,
            "status": status,
            "window_from": window_start,
            "window_to": window_end,
            "evidence_count": int(sum(item["evidence_count"] for item in rationale.values())),
            "current": current,
            "proposed": proposals,
            "rationale": rationale,
            "message": message,
        }

    @staticmethod
    def _action_conflict(action: str, has_current: bool) -> str | None:
        if action == "create" and has_current:
            return "Create is unavailable because a current bounds envelope exists"
        if action != "create" and not has_current:
            return f"{action.title()} is unavailable without a current bounds envelope"
        return None

    @staticmethod
    def _configured_features(config: dict[str, Any]) -> list[str]:
        raw = config.get("features")
        if not isinstance(raw, list):
            return []
        return list(dict.fromkeys(str(feature) for feature in raw if isinstance(feature, str) and feature))

    @staticmethod
    def _valid_suggestion_config(config: dict[str, Any]) -> bool:
        return bool(
            isinstance(config.get("measurement"), str)
            and config["measurement"]
            and isinstance(config.get("tag_key"), str)
            and config["tag_key"]
            and DetectionReadinessService._configured_features(config)
        )

    def _current_envelope(self, module: str, series_id: str) -> dict[str, Any] | None:
        rows = self._pg.query_bounds(module, series_id)
        if not rows:
            return None
        row = rows[0]
        return {
            "lower_bounds": dict(row.get("lower_bounds") or {}),
            "upper_bounds": dict(row.get("upper_bounds") or {}),
        }

    def _query_suggestion_series(
        self,
        config: dict[str, Any],
        module: str,
        series_id: str,
        features: list[str],
        window_start: datetime,
        window_end: datetime,
    ) -> pd.DataFrame:
        measurement = str(config["measurement"])
        id_tag = str(config["tag_key"])
        query_id = series_id
        if module == "proto_traffic":
            query_id = self._protocol_from_hash(series_id, measurement, id_tag)
        start, stop = time_policy.ui_to_influx_query_range(window_start, window_end)
        influx = self._influx
        assert influx is not None
        frame = influx.query_timeseries(
            measurement=measurement,
            id_tag=id_tag,
            fields=features,
            start=start,
            stop=stop,
            tags={id_tag: query_id},
            preserve_extrema=False,
        )
        if "time" not in frame.columns:
            return frame.iloc[0:0].copy() if not frame.empty else frame
        timestamps = pd.to_datetime(frame["time"], utc=True, errors="coerce")
        window_from = pd.Timestamp(window_start).tz_convert("UTC")
        window_to = pd.Timestamp(window_end).tz_convert("UTC")
        mask = (timestamps >= window_from) & (timestamps < window_to)
        return pd.DataFrame(frame.loc[mask].copy())

    def _protocol_from_hash(self, series_id: str, measurement: str, id_tag: str) -> str:
        """Resolve persisted protocol hash against actual Influx tag values."""
        assert self._influx is not None
        for protocol in self._influx.query_distinct_tags(measurement, id_tag):
            if proto_series_hash(protocol) == series_id:
                return protocol
        return ""

    @staticmethod
    def _proposal_from_frame(
        frame: pd.DataFrame,
        features: list[str],
        current: dict[str, Any],
        action: str,
    ) -> tuple[dict[str, Any], dict[str, Any], int]:
        lower = dict(current["lower_bounds"])
        upper = dict(current["upper_bounds"])
        if action == "create":
            lower = {feature: None for feature in features}
            upper = {feature: None for feature in features}
        rationale: dict[str, Any] = {}
        evidence_features = 0
        for feature in features:
            values = pd.to_numeric(frame.get(feature, pd.Series(dtype=float)), errors="coerce").dropna()
            values = values[values.map(math.isfinite)]
            count = int(values.size)
            if count:
                observed_lower = float(values.min())
                observed_upper = float(values.max())
                margin = (
                    DetectionReadinessService._replace_margin(observed_lower, observed_upper)
                    if action in {"replace", "create"}
                    else 0.0
                )
                current_lower = lower.get(feature)
                current_upper = upper.get(feature)
                candidate_lower = (
                    observed_lower - margin
                    if action in {"replace", "create"} or not isinstance(current_lower, (int, float))
                    else min(float(current_lower), observed_lower)
                )
                candidate_upper = (
                    observed_upper + margin
                    if action in {"replace", "create"} or not isinstance(current_upper, (int, float))
                    else max(float(current_upper), observed_upper)
                )
                lower[feature] = candidate_lower
                upper[feature] = candidate_upper
                margin_action = action.title()
                rationale[feature] = {
                    "evidence_count": count,
                    "lower_rationale": (
                        f"Observed minimum {observed_lower:g}"
                        + (
                            f"; {margin_action} margin is {margin:g} (5% of observed span, or 5% of magnitude "
                            "with 1.0 fallback for zero span)"
                            if action in {"replace", "create"}
                            else "; Expand keeps the current envelope or widens it to observed evidence"
                        )
                        + " in strict [from, to)"
                    ),
                    "upper_rationale": (
                        f"Observed maximum {observed_upper:g}"
                        + (
                            f"; {margin_action} margin is {margin:g} (5% of observed span, or 5% of magnitude "
                            "with 1.0 fallback for zero span)"
                            if action in {"replace", "create"}
                            else "; Expand keeps the current envelope or widens it to observed evidence"
                        )
                        + " in strict [from, to)"
                    ),
                }
                evidence_features += 1
            else:
                rationale[feature] = {
                    "evidence_count": 0,
                    "lower_rationale": "No numeric values observed in strict [from, to)",
                    "upper_rationale": "No numeric values observed in strict [from, to)",
                }
        return (
            {"lower_bounds": lower, "upper_bounds": upper},
            rationale,
            evidence_features,
        )

    @staticmethod
    def _replace_margin(observed_lower: float, observed_upper: float) -> float:
        """Return deterministic Replace/Create margin from observed magnitude."""
        span = observed_upper - observed_lower
        if span > 0:
            return span * REPLACE_MARGIN_FRACTION
        magnitude = max(abs(observed_lower), abs(observed_upper))
        return max(magnitude * REPLACE_MARGIN_FRACTION, 1.0)

    @staticmethod
    def _unavailable(
        module: str,
        series_id: str,
        action: str,
        window_start: datetime,
        window_end: datetime,
        message: str,
        current: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        envelope = current or {"lower_bounds": {}, "upper_bounds": {}}
        return {
            "module": module,
            "series_id": series_id,
            "action": action,
            "status": "unavailable",
            "window_from": window_start,
            "window_to": window_end,
            "evidence_count": 0,
            "current": envelope,
            "proposed": envelope,
            "rationale": {},
            "message": message,
        }

    def _module_config(self) -> dict[str, dict[str, Any]]:
        try:
            payload = json.loads(self._config_path.read_text(encoding="utf-8"))
            return {str(item["name"]): item for item in payload.get("modules", [])}
        except (OSError, ValueError, KeyError, TypeError):
            return {}

    def readiness(self, running_modules: set[str]) -> list[dict[str, Any]]:
        configs = self._module_config()

        # Batched up-front instead of per module inside the loop (SUITE-045).
        # This turned 4N sequential round-trips into 1 + 1 + N: the two
        # anti-join counts and the frequency count are now one grouped query
        # each. query_bounds stays per module because it carries legacy
        # module-alias fallback semantics (conn <-> netcap) that a single
        # grouped statement cannot reproduce; those queries are ~1-2ms each
        # against a 79-row table, so they are not the bottleneck.
        frequency_counts = self._query_counts_by_module("frequency_profiles", MODULES)
        no_bounds_counts = self._query_no_bounds_by_module(MODULES)

        result = []
        for module in MODULES:
            bounds = self._pg.query_bounds(module)
            frequency = frequency_counts.get(module, 0)
            no_bounds, no_bounds_events = no_bounds_counts.get(module, (0, 0))
            trained_values = [
                trained for row in bounds if (trained := self._as_datetime(row.get("trained_at"))) is not None
            ]
            last_training = max(trained_values, default=None)
            config = configs.get(module, {})
            compatible = all(self._features_present(row) for row in bounds)
            classification_state = self._classification_state(module, config)
            bounds_state = self._bounds_state(module, config)
            frequency_state = self._frequency_state(module, config)
            result.append(
                {
                    "module": module,
                    "state": derive_readiness(
                        enabled=bool(config.get("enabled", False)),
                        bounds_count=len(bounds),
                        frequency_count=frequency,
                        no_bounds_count=no_bounds,
                        last_training=last_training,
                        schema_compatible=compatible,
                        training=module in running_modules,
                        query_failed=self._query_failed,
                    ),
                    "detection_mode": ("active" if config.get("enabled", False) else "observe-only"),
                    "bounds_series_count": len(bounds),
                    "no_bounds_count": no_bounds,
                    "no_bounds_event_count": no_bounds_events,
                    "no_bounds_series_count": no_bounds,
                    "frequency_profile_count": frequency,
                    "last_training": last_training,
                    "schema_version": "bounds-v1",
                    "schema_compatible": compatible,
                    "classification_state": classification_state,
                    "bounds_state": bounds_state,
                    "frequency_state": frequency_state,
                }
            )
        return result

    def live_poll_interval_seconds(self) -> int:
        """Return deployer's effective detector poll cadence for UI timing."""
        if self._settings is None:
            return 5
        return self._settings.pipeline_poll_interval_seconds

    def _classification_state(self, module: str, config: dict[str, Any]) -> str:
        """Return classification gate/artifact state for one module."""
        enabled = bool(config.get("classification", {}).get("enabled", False))
        try:
            rows = self._pg._execute_query(
                "SELECT value FROM runtime_config WHERE service = %(service)s AND key = %(key)s",
                {
                    "service": "otalon-clas",
                    "key": f"detection.{module}.classification_enabled",
                },
            )
            if rows:
                enabled = str(rows[0]["value"]).strip().lower() in {
                    "true",
                    "1",
                    "yes",
                    "on",
                }
        except Exception:
            pass
        if not enabled:
            return "disabled"
        if self._model_artifact_exists(module):
            return "enabled"
        return "unavailable"

    def _runtime_gate_state(self, module: str, gate: str, default: bool) -> bool:
        """Read one boolean detection gate with boot fallback."""
        enabled = default
        try:
            rows = self._pg._execute_query(
                "SELECT value FROM runtime_config WHERE service = %(service)s AND key = %(key)s",
                {"service": "otalon-clas", "key": f"detection.{module}.{gate}"},
            )
            if rows:
                enabled = str(rows[0]["value"]).strip().lower() in {
                    "true",
                    "1",
                    "yes",
                    "on",
                }
        except Exception:
            pass
        return enabled

    def _bounds_state(self, module: str, config: dict[str, Any]) -> str:
        """Return whether live bounds detection is enabled."""
        return "enabled" if self._runtime_gate_state(module, "bounds_enabled", True) else "disabled"

    def _frequency_state(self, module: str, config: dict[str, Any]) -> str:
        """Return whether coupled frequency and absence detection is enabled."""
        default = bool(config.get("frequency_monitor", {}).get("enabled", True))
        return "enabled" if self._runtime_gate_state(module, "frequency_enabled", default) else "disabled"

    def _model_artifact_exists(self, module: str) -> bool:
        """Check for a complete persisted classifier artifact pair."""
        legacy = (
            self._model_dir / f"{module}_classifier.joblib",
            self._model_dir / f"{module}_classifier_meta.json",
        )
        if all(path.exists() for path in legacy):
            return True
        current = self._model_dir / f"{module}_classifier" / "current.json"
        try:
            manifest = json.loads(current.read_text(encoding="utf-8"))
            version = str(manifest["version"])
        except (OSError, TypeError, ValueError, KeyError):
            return False
        version_dir = current.parent / "versions" / version
        return (version_dir / "model.joblib").exists() and (version_dir / "meta.json").exists()

    def bounds(
        self,
        module: str | None,
        state: str | None,
        since: datetime | None,
        query: str | None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return one aggregated row per Series/UCI for the strict ``[since, until)`` window.

        Status priority is NoBounds > Violation > OK: a series lacking a bound
        row is a single NoBounds row even when it also carries events. Affected
        Bounded-series features and timelines come from real anomaly data;
        NoBounds hints use tracked module features.
        """
        modules = (module,) if module else MODULES
        rows: list[dict[str, Any]] = []
        for name in modules:
            no_bound_events = self._group_no_bound_events(name, since, until)
            bound_series: set[str] = set()
            for bound in self._pg.query_bounds(name):
                series = str(bound.get("series_id", ""))
                bound_series.add(series)
                row = self._bounded_series_row(name, series, bound, since, until)
                if state and state != row["state"]:
                    continue
                rows.append(row)
            for series in sorted(no_bound_events):
                if series in bound_series:
                    continue
                if state and state != "NoBounds":
                    continue
                rows.append(self._no_bounds_row(name, series, no_bound_events[series]))
        self._add_display_values(rows)
        if query:
            needle = query.lower()
            rows = [
                row
                for row in rows
                if needle in str(row["series_id"]).lower() or needle in str(row.get("series_display") or "").lower()
            ]
        return rows

    def _bounded_series_row(
        self,
        module: str,
        series: str,
        bound: dict[str, Any],
        since: datetime | None,
        until: datetime | None,
    ) -> dict[str, Any]:
        """Build one aggregate row for a series that has a trained bounds envelope."""
        violations = self._pg.query_bound_violations(module, series, since, until)
        timeline_events = self._violation_timeline(violations)
        affected = sorted({feature for event in timeline_events for feature in event["features"]})
        lower = bound.get("lower_bounds") or {}
        upper = bound.get("upper_bounds") or {}
        latest = timeline_events[-1] if timeline_events else None
        return {
            "module": module,
            "series_id": series,
            "available_features": list(FEATURES[module]),
            "feature": None,
            "state": "BoundViolation" if violations else "OK",
            "current_bounds": {"lower_bounds": lower, "upper_bounds": upper},
            "lower": lower,
            "upper": upper,
            "violation_count": len(violations),
            "nobounds_count": 0,
            "last_event": latest["ts"] if latest else None,
            "latest_event_ts": latest["ts"] if latest else None,
            "latest_event_type": latest["type"] if latest else None,
            "affected_features": affected,
            "timeline": [event["ts"] for event in timeline_events],
            "timeline_events": timeline_events,
            "has_bounds": True,
            "last_trained_at": self._as_datetime(bound.get("trained_at")),
            "ok": not violations,
        }

    def _no_bounds_row(self, module: str, series: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Build one aggregate row for a series without a trained bounds envelope."""
        ordered = sorted(events, key=lambda event: event["event_ts"])
        timeline_events = [
            {
                "ts": event["event_ts"],
                "type": "NoBounds",
                "features": list(FEATURES[module]),
            }
            for event in ordered
        ]
        affected = sorted({feature for event in timeline_events for feature in event["features"]})
        return {
            "module": module,
            "series_id": series,
            "available_features": list(FEATURES[module]),
            "feature": None,
            "state": "NoBounds",
            "current_bounds": {"lower_bounds": {}, "upper_bounds": {}},
            "lower": {},
            "upper": {},
            "violation_count": len(ordered),
            "nobounds_count": len(ordered),
            "last_event": ordered[-1]["event_ts"] if ordered else None,
            "latest_event_ts": ordered[-1]["event_ts"] if ordered else None,
            "latest_event_type": "NoBounds" if ordered else None,
            "affected_features": affected,
            "timeline": [event["event_ts"] for event in ordered],
            "timeline_events": timeline_events,
            "has_bounds": False,
            "last_trained_at": None,
            "ok": False,
        }

    def _add_display_values(self, rows: list[dict[str, Any]]) -> None:
        """Resolve protocol hashes once for one Bound Review result set."""
        proto_rows = [row for row in rows if row["module"] == "proto_traffic"]
        if not proto_rows:
            return
        ids = [str(row["series_id"]) for row in proto_rows]
        displays = self._proto_resolver.resolve_many(ids) if self._proto_resolver else ids
        for row, display in zip(proto_rows, displays):
            row["series_display"] = display

    def _violation_timeline(self, violations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Turn raw BoundViolation rows into ascending structured timeline events."""
        events: list[dict[str, Any]] = []
        for violation in violations:
            timestamp = self._as_datetime(violation.get("event_ts") or violation.get("start_ts"))
            if timestamp is None:
                continue
            events.append(
                {
                    "ts": timestamp,
                    "type": str(violation.get("anomaly_type") or "BoundViolation"),
                    "features": self._violated_features(violation),
                }
            )
        events.sort(key=lambda event: event["ts"])
        return events

    @staticmethod
    def _violated_features(violation: dict[str, Any]) -> list[str]:
        """Extract real affected features from ``violated_features``/``_details`` JSON."""
        raw = violation.get("violated_features")
        if isinstance(raw, list):
            return sorted({str(feature) for feature in raw if feature})
        if isinstance(raw, str):
            return sorted({feature.strip() for feature in raw.split(",") if feature.strip()})
        details = violation.get("violated_feature_details")
        if isinstance(details, dict):
            return sorted({str(feature) for feature in details if feature})
        return []

    def artifacts(self) -> list[dict[str, Any]]:
        if not self._model_dir.exists():
            return []
        result = []
        for path in sorted(self._model_dir.glob("*_classifier_meta.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            data["artifact"] = path.name.replace("_meta.json", ".joblib")
            data["status"] = "production"
            result.append(data)
        return result

    def _query_counts_by_module(self, table: str, modules: tuple[str, ...]) -> dict[str, int]:
        """Return per-module row counts for ``table`` in ONE query.

        Replaces one ``COUNT(*)`` round-trip per module (SUITE-045). Modules
        with no rows are absent from the result; callers default to ``0``,
        matching the previous per-module behaviour.

        Args:
            table: Table name (trusted, call-site literal — not user input).
            modules: Module names to count.

        Returns:
            Mapping of module name to row count.
        """
        try:
            rows = self._pg._execute_query(
                f"SELECT module, COUNT(*) AS count FROM {table} " "WHERE module = ANY(%(modules)s) GROUP BY module",
                {"modules": list(modules)},
            )
            return {str(row["module"]): int(row["count"]) for row in rows}
        except Exception:
            self._query_failed = True  # API-073: fail closed, never ready
            return {}

    def _query_no_bounds_by_module(self, modules: tuple[str, ...]) -> dict[str, tuple[int, int]]:
        """Return unbounded (series_count, event_count) per module in ONE query.

        This is the hot path: the previous implementation ran two anti-join
        queries **per module**, each a sequential scan over ~1.4M ``anomalies``
        rows, which accounted for 3.93s of the endpoint's 3.99s (SUITE-045).

        Two changes make it ~4x faster while returning identical numbers:

        * one statement for all modules instead of 2N, so ``anomalies`` is
          scanned once rather than 2N times;
        * the distinct series are pre-aggregated in a CTE and the anti-join
          then runs against that small result, instead of
          ``COUNT(DISTINCT ...)`` over the full join output — which spilled
          ~32MB to a temp sort.

        Args:
            modules: Module names to aggregate.

        Returns:
            Mapping of module name to ``(unbounded_series_count,
            unbounded_event_count)``. Modules with no unbounded anomalies are
            absent; callers default to ``(0, 0)``.
        """
        try:
            rows = self._pg._execute_query(
                "WITH per_series AS ("
                "  SELECT module, series_id, COUNT(*) AS event_count"
                "  FROM anomalies WHERE module = ANY(%(modules)s)"
                "  GROUP BY module, series_id"
                ") "
                "SELECT p.module, COUNT(*) AS series_count, "
                "       COALESCE(SUM(p.event_count), 0) AS event_count "
                "FROM per_series p "
                "WHERE NOT EXISTS ("
                "  SELECT 1 FROM bounds b "
                "  WHERE b.module = p.module AND b.series_id = p.series_id"
                ") "
                "GROUP BY p.module",
                {"modules": list(modules)},
            )
            return {str(row["module"]): (int(row["series_count"]), int(row["event_count"])) for row in rows}
        except Exception:
            self._query_failed = True  # API-073: fail closed, never ready
            return {}

    def _query_count(self, table: str, module: str) -> int:
        try:
            rows = self._pg._execute_query(
                f"SELECT COUNT(*) AS count FROM {table} WHERE module = %(module)s",
                {"module": module},
            )
            return int(rows[0]["count"]) if rows else 0
        except Exception:
            self._query_failed = True  # API-073: fail closed, never ready
            return 0

    def _query_no_bounds(self, module: str) -> int:
        try:
            rows = self._pg._execute_query(
                "SELECT COUNT(DISTINCT a.series_id) AS count FROM anomalies a "
                "WHERE a.module = %(module)s AND NOT EXISTS ("
                "SELECT 1 FROM bounds b WHERE b.module = a.module "
                "AND b.series_id = a.series_id)",
                {"module": module},
            )
            return int(rows[0]["count"]) if rows else 0
        except Exception:
            self._query_failed = True  # API-073: fail closed, never ready
            return 0

    def _query_no_bounds_events(self, module: str) -> int:
        """Return raw unbounded anomaly rows separately from unique series."""
        try:
            rows = self._pg._execute_query(
                "SELECT COUNT(*) AS count FROM anomalies a WHERE a.module = %(module)s "
                "AND NOT EXISTS (SELECT 1 FROM bounds b WHERE b.module = a.module "
                "AND b.series_id = a.series_id)",
                {"module": module},
            )
            return int(rows[0]["count"]) if rows else 0
        except Exception:
            self._query_failed = True  # API-073: fail closed, never ready
            return 0

    def _query_no_bound_events(
        self, module: str, since: datetime | None, until: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Return per-series unbounded anomaly events for strict ``[since, until)``.

        Preserves each event timestamp so callers can derive a truthful event
        count, latest event, and ordered timeline per Series/UCI instead of
        hard-coded empty values. Unique-Series readiness stays a separate
        ``COUNT(DISTINCT series_id)`` query and is not derived from this row set.
        """
        try:
            clauses = [
                "a.module = %(module)s",
                "NOT EXISTS (SELECT 1 FROM bounds b WHERE b.module = a.module " "AND b.series_id = a.series_id)",
            ]
            params: dict[str, Any] = {"module": module}
            if since is not None:
                clauses.append("start_ts >= %(since)s")
                params["since"] = since
            if until is not None:
                clauses.append("start_ts < %(until)s")
                params["until"] = until
            return self._pg._execute_query(
                "SELECT series_id, start_ts AS event_ts, violated_features, "
                "violated_feature_details FROM anomalies a WHERE " + " AND ".join(clauses) + " ORDER BY start_ts DESC",
                params,
            )
        except Exception:
            self._query_failed = True  # API-073: fail closed, never ready
            return []

    def _group_no_bound_events(
        self, module: str, since: datetime | None, until: datetime | None = None
    ) -> dict[str, list[dict[str, Any]]]:
        """Group filtered unbounded anomaly events by series identifier."""
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in self._query_no_bound_events(module, since, until):
            series = row.get("series_id")
            event = self._as_datetime(row.get("event_ts"))
            if series is None or event is None:
                continue
            grouped.setdefault(str(series), []).append(row)
        return grouped

    def _features_present(self, row: dict[str, Any]) -> bool:
        module = str(row.get("module", "conn"))
        lower, upper = row.get("lower_bounds") or {}, row.get("upper_bounds") or {}
        required = FEATURES.get(module, ())
        return all(feature in lower and feature in upper for feature in required)

    def _as_datetime(self, value: Any) -> datetime | None:
        return value if isinstance(value, datetime) else None
