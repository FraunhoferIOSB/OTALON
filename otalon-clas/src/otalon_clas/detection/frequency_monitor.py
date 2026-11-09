"""Frequency and presence anomaly detection for time-series data.

Monitors per-series data point frequency to detect irregular sending
intervals (frequency anomalies) and prolonged silence (absence anomalies).

When persistence is enabled (config flag
``frequency_monitor.persistence_enabled``), the in-memory ``_profiles``
map is a write-through cache backed by the PostgreSQL
``frequency_profiles`` table. ``train()`` writes the stats columns via a
stats-only UPSERT that never touches the per-profile override columns,
so operator overrides applied through the MCP write tools survive
re-training. The detection hot path resolves the effective tolerance
and absence factors as ``override ?? global_default``.

When the flag is off, none of the persistence wiring engages; the
monitor behaves exactly as the legacy RAM-only implementation.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional, cast

import polars as pl
from loguru import logger
from otalon_common.uci.matching import base_key_without_ports, match_uci_pattern

from otalon_clas.detection.series_blacklist import SeriesBlacklist

if TYPE_CHECKING:
    from otalon_clas.detection.frequency_profile_repository import (
        FrequencyProfileRepository,
    )


FREQUENCY_ANOMALY: str = "FrequencyAnomaly"
ABSENCE_ANOMALY: str = "AbsenceAnomaly"

DEFAULT_LAST_SEEN_FLUSH_INTERVAL_S: int = 60
"""Default seconds between two batched ``last_seen`` writes to PostgreSQL.

Matches the existing ``frequency_monitor.refresh_interval_seconds``
safety-net cadence so the two background write/read rhythms stay
aligned instead of drifting into an unpredictable interleaving."""

DEFAULT_ABSENCE_RECOVERY_CYCLES: int = 5
"""Consecutive observed cycles required to close an absence episode.

Rationale, anchored on the detector's own cadence model rather than on
wall-clock guesswork: ``FrequencyMonitor`` judges a series by the mean
over at least ``min_intervals`` (default 5) inter-arrival intervals. A
series is therefore only credited with "the rhythm is back" once it has
supplied enough intervals for that same judgement — five consecutive
cycles carrying the series. Anything shorter would let a single relayed
packet certify a recovery the detector itself could not yet evaluate.

This directly targets the observed live failure mode: an ettercap MitM
*relays* packets rather than cutting the link, so the victim series dips
past its absence deadline, receives one stray relayed packet, and dips
again. Without hysteresis every dip minted a fresh ``anomalies`` row
(the deadline anchor moved with the new ``last_seen``), turning one
sustained disruption into ~8 short rows. With hysteresis the stray
packet is absorbed into the ongoing episode and the frozen deadline
anchor keeps the upsert landing on the SAME row.

The mechanism is bounded on purpose: it only coalesces re-openings that
occur while a recovery is still unproven. Two silences separated by a
genuinely restored rhythm (>= 5 observed cycles) remain two episodes, so
truly distinct outages are never merged.
"""


@dataclass
class _AbsenceEpisode:
    """State of one ongoing silence episode for a single series.

    ``since`` is the frozen absence deadline that anchors the persisted
    ``anomalies`` row. It is captured when the episode opens and is NOT
    recomputed while the episode lasts, so a stray packet mid-silence
    cannot mint a second row for what is one continuous disruption.

    ``healthy_cycles`` counts consecutive detection ticks in which the
    series was observed again; ``recovery_started_at`` is the instant of
    the first of those observations. Both reset to zero/None whenever
    the series falls silent again.
    """

    since: datetime
    healthy_cycles: int = 0
    recovery_started_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class FrequencyResult:
    """Result of a frequency/presence check for one series.

    ``absence_since`` is populated for :data:`ABSENCE_ANOMALY` results
    only. It carries the instant at which the absence timeout expired
    (``last_seen + max(mean_interval * effective_absence_factor,
    mean_interval + absence_timeout_std_factor * std_interval,
    absence_timeout_floor_seconds)``), i.e. the
    moment the series became formally absent — NOT the instant the check
    happened to run. Because it is derived from a frozen ``last_seen``,
    it stays constant for the whole silent episode, which lets the
    persistence layer treat consecutive ticks as one continuing
    interval instead of one row per poll.

    ``last_seen`` mirrors the profile timestamp the deadline was derived
    from so downstream consumers do not have to re-read the profile.
    """

    is_anomaly: bool
    anomaly_type: str
    confidence: float
    series_id: str
    absence_since: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class _SeriesFrequencyProfile:
    """Learned frequency statistics for a single series.

    ``tolerance_factor_override`` and ``absence_factor_override`` are
    nullable per-profile operator overrides. ``None`` means the
    detection hot path falls back to the global default supplied to
    :class:`FrequencyMonitor`. The two override fields are mirrored
    from the ``frequency_profiles`` table when persistence is enabled
    and are otherwise always ``None``.
    """

    mean_interval: float
    std_interval: float
    last_seen: datetime | None = None
    tolerance_factor_override: float | None = None
    absence_factor_override: float | None = None


class FrequencyMonitor:
    """Monitors per-series data arrival frequency and detects anomalies.

    Detects two types of anomalies:
    - **FrequencyAnomaly**: Data arrives at significantly irregular intervals.
      The observed mean inter-arrival is evaluated only once at least
      ``min_intervals`` intervals are present, and the deviation must
      exceed a robust threshold of
      ``max(effective_tolerance * std_interval,
      relative_floor_factor * mean_interval)`` where
      ``effective_tolerance = tolerance_factor_override ?? global_default``.
      The relative floor keeps strictly periodic real-time traffic
      (small ``std_interval``) from tripping on a single missing bucket.
    - **AbsenceAnomaly**: No data has arrived for a period exceeding
       ``max(mean_interval * effective_absence_factor,
        mean_interval + absence_timeout_std_factor * std_interval,
        absence_timeout_floor_seconds)``. The standard-deviation term
        protects high-variance series from false absence timeouts, while the
        floor protects against a timeout below the detector's sampling
        reality.
    """

    def __init__(
        self,
        frequency_tolerance_factor: float = 2.0,
        absence_timeout_factor: float = 3.0,
        absence_timeout_std_factor: float = 3.0,
        min_intervals: int = 5,
        relative_floor_factor: float = 0.5,
        repository: Optional["FrequencyProfileRepository"] = None,
        module_name: str = "",
        last_seen_flush_interval_seconds: int = DEFAULT_LAST_SEEN_FLUSH_INTERVAL_S,
        absence_recovery_cycles: int | None = None,
        absence_timeout_floor_seconds: float = 0.0,
        absence_interval_cap_seconds: float = 86400.0,
        blacklist: str | list[str] = "",
    ) -> None:
        """Initialize the frequency monitor.

        Args:
            frequency_tolerance_factor: Global default multiplier on
                standard deviation that defines the acceptable interval
                range. Used when a profile carries no
                ``tolerance_factor_override``.
            absence_timeout_factor: Global default multiplier on mean
                interval that defines the absence timeout threshold.
                Used when a profile carries no
                ``absence_factor_override``.
            absence_timeout_std_factor: Global multiplier on interval
                standard deviation added to the mean for the absence
                timeout threshold. Protects high-variance series while
                remaining a global setting without per-profile overrides.
            min_intervals: Minimum number of observed inter-arrival
                intervals (i.e. ``min_intervals + 1`` rows) required
                before a frequency deviation is evaluated. The detector
                runs on aggregated buckets, not true packet
                inter-arrivals, so a window with only one or two
                intervals carries a mean dominated by single-bucket
                jitter. Defaulting to 5 means the observed mean averages
                over at least five intervals, so a single late or missing
                bucket no longer flips the verdict. Below the floor the
                check returns ``None`` (insufficient evidence).
            relative_floor_factor: Fraction of ``mean_interval`` used as
                an absolute floor on the deviation threshold. On strictly
                periodic real-time traffic (e.g. PROFINET RT) the trained
                ``std_interval`` is small relative to the mean, so the
                pure ``tolerance * std`` threshold collapses and a single
                doubled bucket trips it. Flooring the threshold at
                ``relative_floor_factor * mean_interval`` keeps it
                tolerant of one missing bucket while staying sensitive to
                a sustained shift of the mean interval itself.
            repository: Optional persistence repository. When supplied,
                the monitor becomes write-through to PostgreSQL: training
                UPSERTs stats only, the repository's bootstrap load
                populates the RAM cache, and NOTIFY-driven invalidations
                refresh individual profiles without a restart. When
                ``None`` (feature flag off), no persistence wiring runs.
            module_name: Cyberclas module name (``"conn"``,
                ``"mac_traffic"``, ``"proto_traffic"``) used as the
                ``module`` primary-key component of
                ``frequency_profiles``. Required whenever
                ``repository`` is supplied.
            last_seen_flush_interval_seconds: Minimum seconds between
                two batched writes of the runtime ``last_seen`` values
                to PostgreSQL. See :meth:`flush_last_seen`.
            absence_recovery_cycles: Number of consecutive detection
                cycles in which a series must be observed again before
                its absence episode is considered closed. Defaults to
                :data:`DEFAULT_ABSENCE_RECOVERY_CYCLES`. Values below 1
                are clamped to 1 (no hysteresis).
            absence_timeout_floor_seconds: Lower bound for absence timeouts.
                The caller computes this from detector cadence. A timeout
                below ``poll_interval + delay`` is violated by construction
                on every missed read window and can only produce false
                positives. Values below zero are clamped to zero.
            absence_interval_cap_seconds: Upper bound on
                ``mean_interval`` for which absence monitoring is active.
                Profiles whose ``mean_interval`` exceeds this cap are
                silently excluded from absence checking: the deadline
                would be so far in the future that it is effectively
                never reached, making such profiles blind to absence.
                Default 86400 s (1 day) limits the worst-case absence
                deadline to 3 days at factor 3, which is still actionable
                while keeping very slow profiles from being permanently
                exempt via an unreachable deadline. Values below zero
                are clamped to zero (no cap).
        """
        self._frequency_tolerance_factor = frequency_tolerance_factor
        self._absence_timeout_factor = absence_timeout_factor
        self._absence_timeout_std_factor = absence_timeout_std_factor
        self._absence_timeout_floor_s = max(float(absence_timeout_floor_seconds), 0.0)
        self._absence_interval_cap_s = max(float(absence_interval_cap_seconds), 0.0)
        self._boot_blacklist = blacklist
        self._blacklist = SeriesBlacklist(blacklist)
        self._min_intervals = max(min_intervals, 1)
        self._relative_floor_factor = max(relative_floor_factor, 0.0)
        self._profiles: dict[str, _SeriesFrequencyProfile] = {}
        self._profile_base_index: dict[str, list[str]] = {}
        self._repository = repository
        self._module_name = module_name
        self._last_seen_flush_interval_s = max(int(last_seen_flush_interval_seconds), 1)
        self._dirty_last_seen: dict[str, datetime] = {}
        self._dirty_lock = threading.Lock()
        self._last_flush_monotonic = time.monotonic()
        self._absence_episodes: dict[str, _AbsenceEpisode] = {}
        self._absence_recovery_cycles = max(
            int(absence_recovery_cycles if absence_recovery_cycles is not None else DEFAULT_ABSENCE_RECOVERY_CYCLES),
            1,
        )

    @property
    def profiles(self) -> dict[str, _SeriesFrequencyProfile]:
        """Return the current per-series frequency profiles."""
        return dict(self._profiles)

    @property
    def blacklist(self) -> SeriesBlacklist:
        """Return the blacklist instance currently active for checking."""
        return self._blacklist

    def update_blacklist(self, blacklist: SeriesBlacklist | None) -> None:
        """Swap in the per-tick blacklist instance (copy-on-write, CLAS-071).

        ``None`` restores the per-module ``config.json`` boot default, so
        deleting the runtime-config row returns the monitor to its boot
        behavior on the next tick.

        Args:
            blacklist: Immutable instance resolved once for this tick, or
                ``None`` when no runtime row exists.
        """
        self._blacklist = blacklist if blacklist is not None else SeriesBlacklist(self._boot_blacklist)

    @property
    def series_count(self) -> int:
        """Return the number of series with trained profiles."""
        return len(self._profiles)

    @property
    def repository(self) -> Optional["FrequencyProfileRepository"]:
        """Return the persistence repository, or ``None`` when disabled."""
        return self._repository

    def effective_tolerance(self, series_id: str) -> float:
        """Resolve the effective frequency tolerance factor for a series.

        Returns the per-profile override when set, otherwise the global
        default from ``config.json``.
        """
        profile = self._resolve_profile(series_id)
        if profile is None or profile[1].tolerance_factor_override is None:
            return self._frequency_tolerance_factor
        return profile[1].tolerance_factor_override

    def effective_absence_factor(self, series_id: str) -> float:
        """Resolve the effective absence-timeout factor for a series.

        Returns the per-profile override when set, otherwise the global
        default from ``config.json``.
        """
        profile = self._resolve_profile(series_id)
        if profile is None or profile[1].absence_factor_override is None:
            return self._absence_timeout_factor
        return profile[1].absence_factor_override

    def bootstrap_from_repository(self, is_initial: bool = True) -> int:
        """Load persisted profiles for this module into the cache.

        Returns the number of profiles in the cache after the operation.
        When no repository is wired up, this is a no-op returning zero.

        Two-mode semantics (Audit M1 / A1 / C-05):

        * ``is_initial=True`` (default; called once at process start):
          Full load. The freshly fetched dict replaces the cache via
          atomic single-name rebind. Logs one INFO line.
        * ``is_initial=False`` (called by the periodic-refresh
          safety-net, ~60 s): Merge. For each series already in the
          in-memory cache, only the override columns
          (``tolerance_factor_override`` / ``absence_factor_override``)
          are refreshed from PostgreSQL; the in-memory ``last_seen``
          and runtime statistics are preserved so the hot path does
          NOT see a stale trained timestamp the moment the periodic
          tick fires (which would cause a spurious AbsenceAnomaly
          storm). Series newly appearing in the DB are inserted in
          full; series that disappeared from the DB are dropped from
          the cache. Logs only at DEBUG to avoid an INFO flood every
          60 s.

        The whole cache is rebuilt in a local dict and swapped in via
        a single-name rebind (``self._profiles = new_dict``), which is
        atomic in CPython. Readers therefore never observe a
        half-populated dict. The per-series ``last_seen`` mutation on
        the hot path mutates the profile object's attribute (not the
        dict itself), so it never races the swap.
        """
        if self._repository is None:
            return 0
        loaded = self._repository.load_all(self._module_name)
        if is_initial:
            # Atomic single-name rebind: readers see either the old or
            # the new dict, never a half-cleared one.
            self._profiles = dict(loaded)
            self._rebuild_profile_index()
            if not loaded:
                logger.info(
                    "FrequencyMonitor[{}] bootstrap: 0 persisted profiles found",
                    self._module_name or "?",
                )
            else:
                logger.info(
                    "FrequencyMonitor[{}] bootstrap: loaded {} persisted profile(s)",
                    self._module_name or "?",
                    len(loaded),
                )
            return len(loaded)

        # Periodic refresh: merge override columns into the existing
        # cache so runtime last_seen / runtime stats are preserved.
        current = self._profiles
        merged: dict[str, _SeriesFrequencyProfile] = {}
        for series_id, fresh in loaded.items():
            existing = current.get(series_id)
            if existing is None:
                # New series the cache had not seen yet → take the
                # freshly loaded profile in full.
                merged[series_id] = fresh
            else:
                # Preserve runtime state on the existing object;
                # refresh only the override columns from the DB.
                existing.tolerance_factor_override = fresh.tolerance_factor_override
                existing.absence_factor_override = fresh.absence_factor_override
                merged[series_id] = existing
        # Series that disappeared from the DB are intentionally not
        # carried over.
        self._profiles = merged
        self._rebuild_profile_index()
        logger.debug(
            "FrequencyMonitor[{}] periodic refresh: {} profile(s) in cache "
            "(overrides merged, runtime last_seen preserved)",
            self._module_name or "?",
            len(merged),
        )
        return len(merged)

    def apply_invalidation(self, series_id: str) -> None:
        """Reload a single profile from PG following a NOTIFY.

        Resilient: with no repository wired, this is a no-op. When the
        repository reports the row was deleted (rare; not currently
        emitted by the MCP tools), the cache entry is dropped.

        Audit M1 / A1: if the series already lives in the cache,
        only the override columns are merged in. The in-memory
        ``last_seen`` and runtime statistics are preserved so an
        invalidation NOTIFY does not look like "this series has not
        been seen since trained_at" to the absence check on the next
        detection tick.

        Audit M3 / A7 / B1: the whole-dict mutations rebuild a new
        dict locally and rebind ``self._profiles`` atomically (single
        name rebind is atomic in CPython). Per-series attribute
        updates mutate the profile object, not the dict.

        UI-101: an operator correction that widens
        ``absence_factor_override`` is meant to stop a false-positive
        absence. An episode opened under the OLD factor freezes its
        deadline anchor and re-emits it for as long as the silence
        lasts, so without dropping that episode the correction would
        not visibly take effect until the series recovered on its own.
        A changed effective factor therefore also clears the open
        episode for exactly this series; unrelated series keep theirs.
        Only THIS series is touched — the notification is per
        ``(module, series_id)`` and must not disturb any other
        profile's cached state.
        """
        if self._repository is None:
            return
        fresh = self._repository.load_one(self._module_name, series_id)
        current = self._profiles
        if fresh is None:
            if series_id in current:
                # Build a new dict without the dropped key and rebind atomically.
                new_dict = {k: v for k, v in current.items() if k != series_id}
                self._profiles = new_dict
            self._absence_episodes.pop(series_id, None)
            logger.debug(
                "FrequencyMonitor[{}] invalidation: dropped cache for series '{}'",
                self._module_name or "?",
                series_id,
            )
            return
        existing = current.get(series_id)
        if existing is None:
            # Series newly tracked → atomic insert via dict rebuild.
            new_dict = dict(current)
            new_dict[series_id] = fresh
            self._profiles = new_dict
            changed = True
        else:
            changed = (
                existing.tolerance_factor_override != fresh.tolerance_factor_override
                or existing.absence_factor_override != fresh.absence_factor_override
            )
            # Merge override columns into the existing profile object
            # so runtime last_seen survives.
            existing.tolerance_factor_override = fresh.tolerance_factor_override
            existing.absence_factor_override = fresh.absence_factor_override
        if changed:
            self._absence_episodes.pop(series_id, None)
            logger.info(
                "FrequencyMonitor[{}]: reloaded corrected profile for series '{}' "
                "(tolerance_override={}, absence_override={}); next evaluation uses it",
                self._module_name or "?",
                series_id,
                fresh.tolerance_factor_override,
                fresh.absence_factor_override,
            )
            return
        logger.debug(
            "FrequencyMonitor[{}] invalidation: refreshed cache for series '{}'",
            self._module_name or "?",
            series_id,
        )

    def train(
        self,
        df: pl.DataFrame,
        tag_key: str,
        *,
        notify_channel: str | None = None,
        replace: bool = False,
        discard_overrides: bool = False,
    ) -> None:
        """Learn expected frequency statistics per series from training data.

        Computes mean and standard deviation of inter-arrival times for each
        series identified by the tag column.

        When persistence is enabled, the freshly trained stats are
        flushed to PostgreSQL via a **stats-only UPSERT** that excludes
        the override columns, so operator overrides survive re-training
        (design.md Decision 3 / Fork 3 = a). Each surviving override is
        immediately mirrored back into the in-memory cache.

        Args:
            df: Training data with a ``time`` column and a tag column.
            tag_key: Column name identifying each series.
            notify_channel: Optional PostgreSQL NOTIFY channel. When
                provided and persistence is enabled, a cache-invalidation
                NOTIFY is emitted for every trained series so other
                listeners reload.
            replace: Forwarded to :meth:`publish_profiles`. ``True``
                makes the run replace the module's whole profile set;
                the default keeps the additive merge.
            discard_overrides: Explicitly allow replacement to delete stale
                profiles with operator overrides. Defaults to ``False``.
        """
        if df.is_empty():
            logger.warning("Empty DataFrame provided for frequency training")
            return

        new_profiles = self.compute_candidate_profiles(df, tag_key)
        if not new_profiles:
            # No series carried enough intervals to yield a profile. That
            # is missing evidence, not an empty topology, so a replace run
            # must NOT take it as "delete everything".
            logger.warning(
                "FrequencyMonitor[{}]: training produced no profile; " "keeping the existing profile set",
                self._module_name or "?",
            )
            return
        self.publish_profiles(
            new_profiles,
            notify_channel=notify_channel,
            replace=replace,
            discard_overrides=discard_overrides,
        )

    def compute_candidate_profiles(
        self,
        df: pl.DataFrame,
        tag_key: str,
    ) -> dict[str, _SeriesFrequencyProfile]:
        """Compute candidate frequency profiles WITHOUT mutating or persisting.

        Used by the runtime stage-then-publish JobRunner so a training
        failure in a later module never leaves partially-published
        frequency stats in PostgreSQL or the live cache (audit B-02).

        Args:
            df: Training data with a ``time`` column and a tag column.
            tag_key: Column name identifying each series.

        Returns:
            Freshly computed ``series_id -> profile`` mapping. Empty when
            the DataFrame is empty.
        """
        if df.is_empty():
            return {}
        candidates: dict[str, _SeriesFrequencyProfile] = {}
        for (series_id,), group_df in df.group_by(tag_key):
            profile = self._compute_series_profile(group_df, str(series_id))
            if profile is not None:
                candidates[str(series_id)] = profile
        return candidates

    def publish_profiles(
        self,
        new_profiles: dict[str, _SeriesFrequencyProfile],
        *,
        notify_channel: str | None = None,
        replace: bool = False,
        discard_overrides: bool = False,
    ) -> None:
        """Publish pre-computed candidate profiles into the cache + PostgreSQL.

        Mirrors the tail of :meth:`train` but takes already-computed
        candidates so the compute and publish phases can be separated by
        the runtime JobRunner. Preserves operator overrides and emits the
        per-series invalidation NOTIFYs.

        Args:
            new_profiles: Freshly computed ``series_id -> profile`` map.
            notify_channel: Optional PostgreSQL NOTIFY channel. When set
                and persistence is enabled, a cache-invalidation NOTIFY
                is emitted for every published series AND for every
                series the replace path deleted, so peer processes drop
                their cache entry for a profile that no longer exists.
            replace: When ``True``, the module's profile set — both in
                PostgreSQL and in the in-memory cache — is replaced by
                exactly ``new_profiles``; series an earlier run trained
                but this one no longer covers are dropped. When
                ``False`` (default) the legacy additive merge is kept,
                which is what a partial/scoped retrain needs so an
                observed series is not silently un-profiled.
            discard_overrides: Explicitly allow replacement to delete stale
                profiles with operator overrides. Defaults to ``False``.
        """
        current_profiles = self._profiles
        for series_id, profile in new_profiles.items():
            existing = current_profiles.get(series_id)
            if existing is not None:
                profile.tolerance_factor_override = existing.tolerance_factor_override
                profile.absence_factor_override = existing.absence_factor_override
                profile.last_seen = existing.last_seen

        deleted: tuple[str, ...] = ()
        preserved: tuple[str, ...] = ()
        if self._repository is not None and self._module_name:
            written = self._repository.upsert_stats(
                self._module_name,
                new_profiles,
                replace=replace,
                discard_overrides=discard_overrides,
            )
            deleted = written.deleted
            preserved = written.preserved
            for series_id, (tol, abs_) in written.survivors.items():
                candidate = new_profiles.get(series_id)
                if candidate is None:
                    continue
                candidate.tolerance_factor_override = tol
                candidate.absence_factor_override = abs_

            if notify_channel:
                self._emit_notifies(notify_channel, set(new_profiles) | set(deleted))

        if replace:
            published_profiles = dict(new_profiles)
            published_profiles.update(
                {series_id: current_profiles[series_id] for series_id in preserved if series_id in current_profiles}
            )
        else:
            published_profiles = dict(current_profiles)
            published_profiles.update(new_profiles)
        self._profiles = published_profiles
        self._rebuild_profile_index()
        for series_id in deleted:
            self._absence_episodes.pop(series_id, None)

        logger.info(
            "Published frequency profiles for {} series (replace={}, {} stale removed)",
            len(published_profiles),
            replace,
            len(deleted),
        )

    def restore_profiles(self, profiles: dict[str, _SeriesFrequencyProfile]) -> None:
        """Restore a previously captured live profile mapping."""
        self._profiles = dict(profiles)
        self._rebuild_profile_index()

    def _rebuild_profile_index(self) -> None:
        """Index profiles by their port-independent UCI base key."""
        index: dict[str, list[str]] = {}
        for series_id in self._profiles:
            index.setdefault(base_key_without_ports(series_id), []).append(series_id)
        self._profile_base_index = index

    def _resolve_profile(self, series_id: str) -> tuple[str, _SeriesFrequencyProfile] | None:
        """Resolve exact profiles first, then matching port wildcards."""
        profile = self._profiles.get(series_id)
        if profile is not None:
            return series_id, profile
        candidates = self._profile_base_index.get(base_key_without_ports(series_id), [])
        matches = [candidate for candidate in candidates if match_uci_pattern(series_id, candidate)]
        if not matches:
            return None
        selected = min(matches, key=lambda candidate: candidate.count("*"))
        return selected, self._profiles[selected]

    def _emit_notifies(self, channel: str, series_ids: set[str]) -> None:
        """Emit cache-invalidation NOTIFYs for the trained series."""
        from otalon_clas.detection.frequency_profile_repository import emit_notify

        for series_id in series_ids:
            try:
                repository = self._repository
                if repository is None:
                    continue
                emit_notify(repository._connector, channel, self._module_name, series_id)
            except Exception as exc:
                logger.warning(
                    "FrequencyMonitor[{}]: failed to emit NOTIFY for {}.{}: {}",
                    self._module_name,
                    series_id,
                    exc,
                )

    def _compute_series_profile(
        self,
        group_df: pl.DataFrame,
        series_id: str,
    ) -> _SeriesFrequencyProfile | None:
        """Compute frequency statistics for a single series.

        Args:
            group_df: Data for one series, must include a ``time`` column.
            series_id: Identifier of the series (for logging).

        Returns:
            Frequency profile or None if insufficient data points.
        """
        if "time" not in group_df.columns:
            logger.warning("Series '{}' has no 'time' column, skipping", series_id)
            return None

        sorted_df = group_df.sort("time")
        times = sorted_df["time"]

        if len(times) < 2:
            logger.debug("Series '{}' has fewer than 2 data points, skipping", series_id)
            return None

        return self._calculate_interval_stats(times, series_id)

    def _calculate_interval_stats(
        self,
        times: pl.Series,
        series_id: str,
    ) -> _SeriesFrequencyProfile:
        """Calculate mean and std of inter-arrival intervals from timestamps.

        Args:
            times: Sorted timestamp series.
            series_id: Identifier of the series (for logging).

        Returns:
            Frequency profile with computed statistics.
        """
        intervals = times.diff().drop_nulls()
        interval_seconds = intervals.dt.total_seconds().cast(pl.Float64)

        mean_interval = float(cast(float, interval_seconds.mean()))
        std_interval = float(cast(float, interval_seconds.std(ddof=1))) if len(interval_seconds) > 1 else 0.0

        if std_interval != std_interval:
            std_interval = 0.0

        logger.debug(
            "Series '{}': mean_interval={:.3f}s, std_interval={:.3f}s",
            series_id,
            mean_interval,
            std_interval,
        )
        return _SeriesFrequencyProfile(mean_interval=mean_interval, std_interval=std_interval)

    def check(
        self,
        df: pl.DataFrame,
        tag_key: str,
        current_time: str,
    ) -> list[FrequencyResult]:
        """Check for frequency and absence anomalies across all known series.

        Evaluates the incoming data against learned profiles and also checks
        for absence of data from previously seen series.

        Args:
            df: Current observation data with ``time`` and tag columns.
            tag_key: Column name identifying each series.
            current_time: ISO 8601 timestamp representing the current check time.

        Returns:
            List of FrequencyResult objects for each detected anomaly.
        """
        now = datetime.fromisoformat(current_time).replace(tzinfo=timezone.utc)
        observed_series = self._extract_observed_series(df, tag_key)
        results: list[FrequencyResult] = []

        for series_id, group_df in observed_series.items():
            result = self._check_series_frequency(group_df, series_id, now)
            if result is not None:
                results.append(result)

        absence_results = self._check_absent_series(observed_series, now)
        results.extend(absence_results)

        return results

    def _extract_observed_series(
        self,
        df: pl.DataFrame,
        tag_key: str,
    ) -> dict[str, pl.DataFrame]:
        """Group DataFrame by tag key into a dict of series DataFrames.

        Args:
            df: Input observation data.
            tag_key: Column identifying each series.

        Returns:
            Dict mapping series_id to its group DataFrame.
        """
        if df.is_empty():
            return {}
        groups: dict[str, pl.DataFrame] = {}
        for (series_id,), group_df in df.group_by(tag_key):
            series_key = str(series_id)
            if not self._is_blacklisted(series_key):
                groups[series_key] = group_df
        return groups

    def _is_blacklisted(self, series_id: str) -> bool:
        """Return whether series identifier matches configured exclusions."""
        return self._blacklist.matches(series_id)

    def _check_series_frequency(
        self,
        group_df: pl.DataFrame,
        series_id: str,
        now: datetime,
    ) -> FrequencyResult | None:
        """Check one observed series for frequency deviation anomalies.

        Updates the last-seen timestamp for the series.

        Args:
            group_df: Data for one series in the current window.
            series_id: Identifier of the series.
            now: Current timestamp.

        Returns:
            FrequencyResult if a frequency anomaly is detected, else None.
        """
        resolved = self._resolve_profile(series_id)
        self._update_last_seen(series_id, now, resolved)
        self._register_observation(series_id, now)

        if resolved is None:
            logger.debug("No frequency profile for series '{}', skipping check", series_id)
            return None

        _, profile = resolved
        # Require at least ``min_intervals`` inter-arrival intervals, i.e.
        # ``min_intervals + 1`` rows. The detector evaluates aggregated
        # buckets, so a window with one or two intervals carries a mean
        # dominated by single-bucket jitter and must be treated as
        # insufficient evidence rather than an anomaly.
        if "time" not in group_df.columns or len(group_df) < self._min_intervals + 1:
            return None

        return self._evaluate_interval_deviation(group_df, series_id, profile)

    def _evaluate_interval_deviation(
        self,
        group_df: pl.DataFrame,
        series_id: str,
        profile: _SeriesFrequencyProfile,
    ) -> FrequencyResult | None:
        """Evaluate whether observed intervals deviate beyond tolerance.

        Uses :meth:`_deviation_threshold`, which combines the per-profile
        ``effective_tolerance`` (operator overrides supersede the global
        default) with the mean-relative floor.

        Args:
            group_df: Data for one series (must have ``time`` column and
                at least ``min_intervals + 1`` rows).
            series_id: Identifier of the series.
            profile: Learned frequency profile for this series.

        Returns:
            FrequencyResult if deviation exceeds threshold, else None.
        """
        sorted_df = group_df.sort("time")
        intervals = sorted_df["time"].diff().drop_nulls()
        interval_seconds = intervals.dt.total_seconds().cast(pl.Float64)
        observed_mean = float(cast(float, interval_seconds.mean()))

        deviation = abs(observed_mean - profile.mean_interval)
        threshold = self._deviation_threshold(series_id, profile)

        if threshold > 0.0 and deviation > threshold:
            confidence = min(deviation / max(profile.mean_interval, 1e-9), 1.0)
            return FrequencyResult(
                is_anomaly=True,
                anomaly_type=FREQUENCY_ANOMALY,
                confidence=confidence,
                series_id=series_id,
            )
        return None

    def _deviation_threshold(
        self,
        series_id: str,
        profile: _SeriesFrequencyProfile,
    ) -> float:
        """Compute the robust interval-deviation threshold for a series.

        Combines the classic ``tolerance * std_interval`` dispersion
        bound with an absolute relative floor
        ``relative_floor_factor * mean_interval``. The floor prevents the
        threshold from collapsing on strictly periodic traffic (small
        ``std_interval`` relative to ``mean_interval``), where a single
        missing aggregated bucket would otherwise exceed a pure
        std-based bound. The mean-relative floor still scales with the
        series cadence, so a sustained shift of the mean interval itself
        is caught.

        Returns ``0.0`` only when the profile carries no usable
        cadence (``mean_interval <= 0`` and ``std_interval <= 0``), in
        which case no deviation can be evaluated.
        """
        std_bound = self.effective_tolerance(series_id) * profile.std_interval
        relative_floor = self._relative_floor_factor * max(profile.mean_interval, 0.0)
        return max(std_bound, relative_floor)

    def _check_absent_series(
        self,
        observed_series: dict[str, pl.DataFrame],
        now: datetime,
    ) -> list[FrequencyResult]:
        """Check all profiled series for absence anomalies.

        A series is absent if it has a last-seen timestamp but was not
        observed in the current window and the elapsed time exceeds the
        absence timeout.

        Args:
            observed_series: Dict of series observed in the current window.
            now: Current timestamp.

        Returns:
            List of FrequencyResult for each absent series exceeding timeout.
        """
        results: list[FrequencyResult] = []
        snapshot = self._profiles
        observed_profile_ids = {
            resolved[0]
            for observed_id in observed_series
            if (resolved := self._resolve_profile(observed_id)) is not None
        }
        # background invalidator/refresh thread swaps ``self._profiles``
        # atomically via single-name rebind; capturing the reference
        # here gives the iteration a stable view even if the swap
        # happens mid-loop. The per-series profile object is mutated in
        # place by ``_update_last_seen`` and by ``apply_invalidation``
        # for override columns; mutating attributes during iteration
        # over ``.items()`` is safe.
        snapshot = self._profiles
        for series_id, profile in snapshot.items():
            if self._is_blacklisted(series_id):
                continue
            if series_id in observed_profile_ids:
                continue
            if profile.last_seen is None:
                continue
            result = self._evaluate_absence(series_id, profile, now)
            if result is not None:
                results.append(result)
        self._prune_episodes(snapshot)
        return results

    def _prune_episodes(self, snapshot: dict[str, _SeriesFrequencyProfile]) -> None:
        """Drop absence episodes whose series no longer has a profile.

        Profiles disappear when a re-training run stops tracking a
        series or an operator deletes it. Pruning here (on the detection
        thread) rather than in the background refresh keeps
        ``_absence_episodes`` single-threaded.
        """
        stale = [series_id for series_id in self._absence_episodes if series_id not in snapshot]
        for series_id in stale:
            del self._absence_episodes[series_id]

    def _evaluate_absence(
        self,
        series_id: str,
        profile: _SeriesFrequencyProfile,
        now: datetime,
    ) -> FrequencyResult | None:
        """Evaluate whether a single series has been absent beyond its timeout.

        Uses :meth:`effective_absence_factor` so per-profile operator
        overrides supersede the global default.

        Absence interval cap: when``profile.mean_interval`` exceeds
        ``absence_interval_cap_seconds``, the series is excluded from
        absence monitoring. The deadline would be so far in the future
        that it is effectively never reached, making the profile blind
        to absence. The cap is configured via
        ``absence_interval_cap_seconds``.

        Episode hysteresis (see
        :data:`DEFAULT_ABSENCE_RECOVERY_CYCLES`): while an episode for
        this series is still open, its ORIGINAL deadline is re-emitted
        as ``absence_since`` instead of one derived from the latest
        ``last_seen``. The persisted row is keyed by that anchor, so a
        stray packet during a sustained disruption extends the existing
        episode rather than opening a new one.

        Args:
            series_id: Identifier of the series.
            profile: Frequency profile with last_seen timestamp.
            now: Current timestamp.

        Returns:
            FrequencyResult if absence timeout exceeded, else None.
        """
        if profile.last_seen is None:
            return None
        if self._absence_interval_cap_s > 0.0 and profile.mean_interval > self._absence_interval_cap_s:
            logger.debug(
                "Absence skip for series '{}': mean_interval={:.1f}s exceeds cap={:.1f}s",
                series_id,
                profile.mean_interval,
                self._absence_interval_cap_s,
            )
            return None
        elapsed = (now - profile.last_seen).total_seconds()
        timeout = max(
            profile.mean_interval * self.effective_absence_factor(series_id),
            profile.mean_interval + self._absence_timeout_std_factor * profile.std_interval,
            self._absence_timeout_floor_s,
        )

        if elapsed > timeout:
            confidence = min(elapsed / max(timeout, 1e-9), 1.0)
            deadline = self._absence_anchor(series_id, profile.last_seen + timedelta(seconds=timeout))
            logger.debug(
                "Absence anomaly for series '{}': elapsed={:.1f}s, timeout={:.1f}s",
                series_id,
                elapsed,
                timeout,
            )
            return FrequencyResult(
                is_anomaly=True,
                anomaly_type=ABSENCE_ANOMALY,
                confidence=confidence,
                series_id=series_id,
                absence_since=deadline,
                last_seen=profile.last_seen,
            )
        return None

    def _absence_anchor(self, series_id: str, deadline: datetime) -> datetime:
        """Return the deadline anchoring this series' absence episode.

        Opens a new episode at ``deadline`` when none is running,
        otherwise re-uses the open episode's frozen anchor and clears
        any partial recovery progress — the series is silent again, so
        the healthy-cycle streak restarts from zero.
        """
        episode = self._absence_episodes.get(series_id)
        if episode is None:
            self._absence_episodes[series_id] = _AbsenceEpisode(since=deadline)
            return deadline
        episode.healthy_cycles = 0
        episode.recovery_started_at = None
        return episode.since

    def _register_observation(self, series_id: str, now: datetime) -> None:
        """Credit one healthy cycle towards closing an absence episode.

        The episode is only dropped once
        ``absence_recovery_cycles`` consecutive cycles have carried the
        series, which is the same evidence volume the frequency check
        itself demands before judging a cadence.
        """
        episode = self._absence_episodes.get(series_id)
        if episode is None:
            return
        episode.healthy_cycles += 1
        if episode.recovery_started_at is None:
            episode.recovery_started_at = now
        if episode.healthy_cycles >= self._absence_recovery_cycles:
            del self._absence_episodes[series_id]
            logger.debug(
                "FrequencyMonitor[{}]: absence episode closed for series '{}' "
                "after {} consecutive observed cycle(s)",
                self._module_name or "?",
                series_id,
                self._absence_recovery_cycles,
            )

    def _update_last_seen(
        self,
        series_id: str,
        now: datetime,
        resolved: tuple[str, _SeriesFrequencyProfile] | None = None,
    ) -> None:
        """Update the last-seen timestamp for a series.

        If the series has a trained profile, updates its last_seen field
        and marks it dirty for the next batched flush to PostgreSQL.
        Otherwise this is a no-op.

        Args:
            series_id: Identifier of the series.
            now: Current timestamp.
        """
        if resolved is None:
            resolved = self._resolve_profile(series_id)
        if resolved is None:
            return
        profile_id, profile = resolved
        profile.last_seen = now
        with self._dirty_lock:
            self._dirty_last_seen[profile_id] = now

    def flush_last_seen(self, force: bool = False) -> int:
        """Write pending runtime ``last_seen`` values to PostgreSQL.

        Batched on purpose. The live loop polls every 5 s and the suite
        carries ~203 profiles, so writing one row per series per tick
        would mean up to ~40 UPDATEs/s of pure bookkeeping against a
        table nothing reads that often. Instead every observation only
        marks its series dirty in RAM, and this method drains the whole
        dirty set in ONE transaction at most every
        ``last_seen_flush_interval_seconds`` (default 60 s, matching the
        existing profile-refresh cadence).

        The chosen interval is bounded by what it is for: the persisted
        ``last_seen`` exists so a restart resumes absence detection from
        reality instead of the last training run, and so the UI can show
        real freshness. A worst-case staleness of one interval is
        immaterial against absence timeouts of ``mean_interval × 3``, and
        the in-memory value that the live absence check actually uses is
        always exact.

        Args:
            force: Flush regardless of the elapsed interval. Used for
                shutdown and by tests.

        Returns:
            Number of rows updated in PostgreSQL.
        """
        if self._repository is None or not self._module_name:
            return 0
        now = time.monotonic()
        with self._dirty_lock:
            if not force and (now - self._last_flush_monotonic) < self._last_seen_flush_interval_s:
                return 0
            if not self._dirty_last_seen:
                self._last_flush_monotonic = now
                return 0
            pending = dict(self._dirty_last_seen)
            self._dirty_last_seen.clear()
            self._last_flush_monotonic = now

        try:
            updated = self._repository.update_last_seen(self._module_name, pending)
        except Exception:
            # Re-arm the failed entries so the next flush retries them,
            # but never let a newer observation be overwritten by the
            # stale one we are putting back.
            with self._dirty_lock:
                for series_id, ts in pending.items():
                    current = self._dirty_last_seen.get(series_id)
                    if current is None or current < ts:
                        self._dirty_last_seen[series_id] = ts
            logger.exception(
                "FrequencyMonitor[{}]: last_seen flush failed for {} series",
                self._module_name,
                len(pending),
            )
            return 0

        logger.debug(
            "FrequencyMonitor[{}]: flushed last_seen for {}/{} series",
            self._module_name,
            updated,
            len(pending),
        )
        return updated
