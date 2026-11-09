/**
 * Pinia store for the UI-101 Rhythm Review surface.
 *
 * Owns the reviewable frequency-profile fleet for one module plus the
 * per-series correction contract: a non-mutating Preview, an audited
 * Apply guarded by the preview's exact `before_snapshot`, an advisory
 * server suggestion, and the per-series audit history.
 *
 * Correction safety is enforced here as well as in the API: Apply is
 * only ever called with a snapshot that a Preview returned, and an
 * HTTP 409 is surfaced as a typed conflict so the drawer can retain the
 * operator's entered values and demand a fresh Preview.
 *
 * @example
 * ```ts
 * const store = useRhythmReviewStore()
 * await store.loadFleet('conn')
 * const preview = await store.previewOverride('conn', uci, { absence_factor_override: 8 })
 * await store.applyOverride('conn', uci, { absence_factor_override: 8 }, preview.before_snapshot, 'why')
 * ```
 */
import { defineStore } from 'pinia'

import { useApi, type ApiError } from '~/composables/useApi'
import type {
  FrequencyEventRecord,
  FrequencyEventsResponse,
  FrequencyHistoryRecord,
  FrequencyHistoryResponse,
  FrequencyOverrideApplyResponse,
  FrequencyOverridePayload,
  FrequencyOverridePreviewResponse,
  FrequencyOverrideSnapshot,
  FrequencyOverrideSuggestion,
  FrequencyProfileListResponse,
  FrequencyProfileResponse,
} from '~/types/api'

/**
 * Encode a series id for use as a single URL path segment.
 *
 * A `conn` series id is a UCI carrying eight or more literal `/`
 * separators — the ordinary shape, not an edge case. Uvicorn
 * percent-decodes the path exactly once before Starlette matches the
 * route, so a singly-encoded `%2F` arrives as a real separator, the
 * segment splits, and the route 404s. Encoding twice makes that single
 * decode yield `%2F` again, keeping the id in one segment; the API then
 * unquotes it once more (`_resolve_series` in
 * `otalon-api/src/api/v1/frequency.py`).
 *
 * This mirrors the bound-correction calls in `detectionStore.ts` exactly.
 * The authoritative id also travels in the body/query, so the path stays
 * a fallback — but it must still *match a route* for the handler to run.
 *
 * @param seriesId - Raw series identifier.
 * @returns The doubly percent-encoded path segment.
 */
function seriesPathSegment(seriesId: string): string {
  return encodeURIComponent(encodeURIComponent(seriesId))
}

/**
 * Detection modules that carry frequency profiles.
 *
 * `netcap` is deliberately absent: it is the InfluxDB database name and
 * a legacy wire alias, never a module the frequency monitor profiles.
 */
export type RhythmModule = 'conn' | 'mac_traffic' | 'proto_traffic'
export type RhythmModuleFilter = RhythmModule | null

/**
 * Raised when the API rejects an Apply because the profile changed
 * between Preview and Apply.
 *
 * Carrying this as its own type keeps the drawer from having to sniff
 * status codes: a conflict must retain the operator's entered values and
 * require a new Preview, which is different from any other failure.
 */
export class RhythmCorrectionConflictError extends Error {
  /**
   * @param message - Server-supplied explanation of the stale state.
   */
  constructor(message: string) {
    super(message)
    this.name = 'RhythmCorrectionConflictError'
  }
}

/**
 * Reactive state of the Rhythm Review surface.
 */
export interface RhythmReviewState {
  module: RhythmModuleFilter
  profiles: FrequencyProfileResponse[]
  history: FrequencyHistoryRecord[]
  events: FrequencyEventRecord[]
  eventsTruncated: boolean
  loading: boolean
  error: string | null
  historyLoading: boolean
  eventsLoading: boolean
  fleetSeq: number
  historySeq: number
  eventsSeq: number
}

function messageOf(error: unknown, fallback: string): string {
  const apiError = error as ApiError
  if (typeof apiError?.detail === 'string' && apiError.detail) return apiError.detail
  if (apiError?.message) return apiError.message
  return fallback
}

export const useRhythmReviewStore = defineStore('rhythmReview', {
  state: (): RhythmReviewState => ({
    module: 'conn',
    profiles: [],
    history: [],
    events: [],
    eventsTruncated: false,
    loading: false,
    error: null,
    historyLoading: false,
    eventsLoading: false,
    fleetSeq: 0,
    historySeq: 0,
    eventsSeq: 0,
  }),

  getters: {
    /**
     * Profiles that carry at least one operator override.
     *
     * @returns The overridden subset of the loaded fleet.
     */
    overriddenProfiles: (state): FrequencyProfileResponse[] =>
      state.profiles.filter(
        (profile) => profile.tolerance_factor?.source === 'override' || profile.absence_factor?.source === 'override',
      ),

    /**
     * Number of loaded series that actually have a learned cadence.
     *
     * @returns Count of profiled series.
     */
    profiledCount: (state): number => state.profiles.filter((profile) => profile.has_profile).length,
  },

  actions: {
    /**
     * Load the reviewable profile fleet for one module or all modules.
     *
     * A `no_profile` entry is a normal state, not an error, and is kept
     * in the list so the operator can see the series exists.
     *
     * @param module - Detection module to review, or null for all modules.
     */
    async loadFleet(module: RhythmModuleFilter = 'conn', since?: string): Promise<void> {
      const seq = ++this.fleetSeq
      this.loading = true
      this.error = null
      try {
        const modules: RhythmModule[] = module ? [module] : ['conn', 'mac_traffic', 'proto_traffic']
        const responses = await Promise.all(
          modules.map((requestedModule) =>
            useApi().get<FrequencyProfileListResponse>('/api/v1/frequency/profiles', {
              module: requestedModule,
              ...(since ? { since } : {}),
            }),
          ),
        )
        if (seq !== this.fleetSeq) return
        this.module = module
        this.profiles = responses.flatMap((response) => response.data ?? [])
      } catch (error: unknown) {
        if (seq !== this.fleetSeq) return
        this.profiles = []
        this.error = messageOf(error, 'Rhythm profiles could not be loaded')
      } finally {
        if (seq === this.fleetSeq) this.loading = false
      }
    },

    /**
     * Reload one series and merge it into the loaded fleet in place.
     *
     * Used after a successful correction so the table reflects the new
     * effective factors without a full refetch.
     *
     * @param module - Detection module.
     * @param seriesId - Series identifier.
     * @returns The refreshed profile, or null when it could not be read.
     */
    async refreshProfile(
      module: RhythmModule,
      seriesId: string,
      since?: string,
    ): Promise<FrequencyProfileResponse | null> {
      try {
        const profile = await useApi().get<FrequencyProfileResponse>('/api/v1/frequency/profile', {
          uci: seriesId,
          module,
          ...(since ? { since } : {}),
        })
        const index = this.profiles.findIndex((entry) => entry.module === module && entry.series_id === seriesId)
        if (index >= 0) this.profiles.splice(index, 1, profile)
        return profile
      } catch {
        return null
      }
    },

    /**
     * Request a non-mutating correction preview.
     *
     * @param module - Detection module.
     * @param seriesId - Series identifier.
     * @param payload - Override fields the operator changed.
     * @param withSuggestion - Whether to attach an advisory proposal.
     * @returns The diff, `before_snapshot` and detector-threshold impact.
     */
    async previewOverride(
      module: RhythmModule,
      seriesId: string,
      payload: FrequencyOverridePayload,
      withSuggestion = false,
    ): Promise<FrequencyOverridePreviewResponse> {
      const query = `?module=${encodeURIComponent(module)}${withSuggestion ? '&suggest=true' : ''}`
      return useApi().post<FrequencyOverridePreviewResponse>(
        `/api/v1/frequency/${seriesPathSegment(seriesId)}/override/preview${query}`,
        { series_id: seriesId, ...payload },
      )
    },

    /**
     * Commit an audited correction for exactly one previewed snapshot.
     *
     * @param module - Detection module.
     * @param seriesId - Series identifier.
     * @param payload - Override fields the operator changed.
     * @param snapshot - The exact snapshot the Preview returned.
     * @param reason - Non-empty audited reason.
     * @returns The audit id, diff, refreshed profile and notification flag.
     * @throws RhythmCorrectionConflictError When the API answers 409.
     */
    async applyOverride(
      module: RhythmModule,
      seriesId: string,
      payload: FrequencyOverridePayload,
      snapshot: FrequencyOverrideSnapshot,
      reason: string,
    ): Promise<FrequencyOverrideApplyResponse> {
      try {
        return await useApi().post<FrequencyOverrideApplyResponse>(
          `/api/v1/frequency/${seriesPathSegment(seriesId)}/override/apply?module=${encodeURIComponent(module)}`,
          { series_id: seriesId, ...payload, before_snapshot: snapshot, reason },
        )
      } catch (error: unknown) {
        if ((error as ApiError)?.status === 409) {
          throw new RhythmCorrectionConflictError(
            messageOf(error, 'This profile changed since your preview. Preview again before applying.'),
          )
        }
        throw error
      }
    },

    /**
     * Fetch the advisory server suggestion for one series.
     *
     * @param module - Detection module.
     * @param seriesId - Series identifier.
     * @returns Suggested factors plus their evidence provenance.
     */
    async suggestOverride(module: RhythmModule, seriesId: string): Promise<FrequencyOverrideSuggestion> {
      return useApi().get<FrequencyOverrideSuggestion>(
        `/api/v1/frequency/${seriesPathSegment(seriesId)}/override/suggest`,
        { module, uci: seriesId },
      )
    },

    /**
     * Load the chronological correction history for one series.
     *
     * An empty history is a normal outcome for a series that was never
     * corrected, not an error.
     *
     * @param module - Detection module.
     * @param seriesId - Series identifier.
     */
    async loadHistory(module: RhythmModule, seriesId: string): Promise<void> {
      const seq = ++this.historySeq
      this.historyLoading = true
      try {
        const response = await useApi().get<FrequencyHistoryResponse>(
          `/api/v1/frequency/${seriesPathSegment(seriesId)}/history`,
          { module, uci: seriesId },
        )
        if (seq !== this.historySeq) return
        this.history = response.data ?? []
      } catch {
        if (seq !== this.historySeq) return
        this.history = []
      } finally {
        if (seq === this.historySeq) this.historyLoading = false
      }
    },

    /**
     * Drop the loaded history, e.g. when the drawer selection changes.
     */
    clearHistory(): void {
      this.historySeq += 1
      this.history = []
      this.historyLoading = false
    },

    /**
     * Load the rhythm anomaly episodes backing the drawer's timeline.
     *
     * `since` is deliberately optional: the "All" range has no lower
     * bound, and the API caps the response by `limit` either way, so an
     * unbounded timeline is expressible without an unbounded response.
     * An empty list is the normal outcome for a series that never
     * deviated from its cadence, not an error.
     *
     * @param module - Detection module.
     * @param seriesId - Series identifier.
     * @param since - Optional inclusive window start.
     */
    async loadEvents(module: RhythmModule, seriesId: string, since?: string): Promise<void> {
      const seq = ++this.eventsSeq
      this.eventsLoading = true
      try {
        const response = await useApi().get<FrequencyEventsResponse>(
          `/api/v1/frequency/${seriesPathSegment(seriesId)}/events`,
          { module, uci: seriesId, ...(since ? { since } : {}) },
        )
        if (seq !== this.eventsSeq) return
        this.events = response.data ?? []
        this.eventsTruncated = Boolean(response.truncated)
      } catch {
        if (seq !== this.eventsSeq) return
        this.events = []
        this.eventsTruncated = false
      } finally {
        if (seq === this.eventsSeq) this.eventsLoading = false
      }
    },

    /**
     * Drop the loaded event timeline, e.g. when the selection changes.
     */
    clearEvents(): void {
      this.eventsSeq += 1
      this.events = []
      this.eventsTruncated = false
      this.eventsLoading = false
    },
  },
})
