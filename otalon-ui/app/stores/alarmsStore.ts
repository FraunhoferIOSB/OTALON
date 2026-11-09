/**
 * Pinia store for the alarms page.
 *
 * Manages anomaly group state: fetching, client-side filtering,
 * selection, and PATCH mutations with optimistic updates.
 * Supports real-time SSE push updates via {@link handleAnomalyUpdate}.
 *
 * Uses the Options API pattern so that `$reset()` works automatically.
 */
import { defineStore } from 'pinia'

import type { AlarmFilter, AnomalyGroupItem, AnomalyGroupsResponse, UpdateGroupRequest } from '~/types/api'
import { getGroupsForSeries } from '~/utils/alarm-badge'

/**
 * Shape of the alarms store reactive state.
 */
export interface AlarmsState {
  groups: AnomalyGroupItem[]
  selectedGroupId: string | null
  filter: AlarmFilter
  isLoading: boolean
  isInitialLoad: boolean
  error: string | null
  patchingIds: string[]
  affectedFeaturesByGroup: Record<string, AffectedFeaturesCacheEntry>
  totalRowCount: number
  hasMore: boolean
  isLoadingMore: boolean
}

interface AffectedFeaturesCacheEntry {
  features: string[]
  state: 'NoBounds' | 'BoundViolation' | undefined
  bySeries: Record<string, AffectedFeaturesBySeriesEntry>
}

export interface AffectedFeaturesBySeriesEntry {
  features: string[]
  state: 'NoBounds' | 'BoundViolation' | undefined
  rhythmAnomaly: boolean
}

/**
 * Extract a human-readable error message from an unknown thrown value.
 *
 * Detects common network error patterns (connection refused, 502/503/504)
 * and returns a user-friendly message instead of raw HTTP details.
 *
 * @param error - The caught error value.
 * @returns A descriptive error message string.
 */
function extractErrorMessage(error: unknown): string {
  if (!error || typeof error !== 'object') {
    return 'An unknown error occurred'
  }
  const errObj = error as Record<string, unknown>
  const status = errObj.status ?? errObj.statusCode
  if (status === 502 || status === 503 || status === 504) {
    return 'Backend is unavailable — is otalon-api running on :8090?'
  }
  const msg = String(errObj.message ?? errObj.statusMessage ?? '')
  if (msg.includes('fetch failed') || msg.includes('ECONNREFUSED') || msg.includes('NetworkError')) {
    return 'Cannot reach backend — is otalon-api running on :8090?'
  }
  if (msg) return msg
  return 'An unknown error occurred'
}

/**
 * Build the query parameters object for the groups endpoint.
 *
 * Maps the client-side {@link AlarmFilter} to backend-compatible
 * query parameters. The `status` field is handled client-side
 * and is not forwarded to the backend.
 *
 * @param filter - The current alarm filter.
 * @returns Query parameters for `$fetch`.
 */
function buildQueryParams(filter: AlarmFilter): Record<string, unknown> {
  const params: Record<string, unknown> = {}
  if (filter.module) {
    params.module = filter.module
  }
  if (filter.limit) {
    params.limit = filter.limit
  }
  return params
}

export const useAlarmsStore = defineStore('alarms', {
  state: (): AlarmsState => ({
    groups: [],
    selectedGroupId: null,
    filter: { limit: 50 },
    isLoading: false,
    isInitialLoad: true,
    error: null,
    patchingIds: [],
    affectedFeaturesByGroup: {},
    totalRowCount: 0,
    hasMore: false,
    isLoadingMore: false,
  }),

  getters: {
    /**
     * The currently selected anomaly group.
     *
     * @returns The matching group, or `undefined` when nothing is selected.
     */
    selectedGroup(state): AnomalyGroupItem | undefined {
      if (!state.selectedGroupId) return undefined
      return state.groups.find((g) => g.id === state.selectedGroupId)
    },

    /**
     * Groups filtered by the client-side `status` filter.
     *
     * - `'active'` — only groups where `is_active` is `true`.
     * - `'confirmed'` — only groups where `confirmed` is `true`.
     * - `'all'` or unset — all groups.
     *
     * @returns Filtered array of anomaly groups.
     */
    filteredGroups(state): AnomalyGroupItem[] {
      const status = state.filter.status
      if (status === 'active') {
        return state.groups.filter((g) => g.is_active)
      }
      if (status === 'confirmed') {
        return state.groups.filter((g) => g.confirmed)
      }
      return state.groups
    },

    /**
     * Number of groups that are currently active.
     *
     * @returns Count of groups where `is_active` is `true`.
     */
    activeCount(state): number {
      return state.groups.filter((g) => g.is_active).length
    },

    /**
     * Number of groups that have been confirmed.
     *
     * @returns Count of groups where `confirmed` is `true`.
     */
    confirmedCount(state): number {
      return state.groups.filter((g) => g.confirmed).length
    },

    /**
     * Total number of groups matching the current filter (from backend, not just loaded page).
     *
     * @returns The total row count from the API response.
     */
    totalCount(state): number {
      return state.totalRowCount
    },

    /**
     * Number of unique series (connections) across all groups.
     *
     * Collects all `series_ids` from every group and counts the
     * distinct values.
     *
     * @returns Count of unique series IDs.
     */
    connectionCount(state): number {
      const ids = new Set<string>()
      for (const group of state.groups) {
        for (const sid of group.series_ids) {
          ids.add(sid)
        }
      }
      return ids.size
    },
  },

  actions: {
    /** Load persisted BoundViolation features and API-022 NoBounds features for a group. */
    async fetchAffectedFeatures(group: AnomalyGroupItem): Promise<string[]> {
      const cached = this.affectedFeaturesByGroup[group.id]
      if (cached) {
        group.affected_features = cached.features
        group.affected_feature_state = cached.state
        return cached.features
      }
      const modules = new Set<string>()
      if (group.module === 'multi') {
        const enrichment = group.enrichment
        for (const bucket of ['mac', 'proto'] as const) {
          const entries = enrichment?.[bucket]
          if (!Array.isArray(entries)) continue
          for (const entry of entries) {
            if (entry && typeof entry === 'object' && 'module' in entry) {
              modules.add(String((entry as Record<string, unknown>).module))
            }
          }
        }
        if (group.series_ids.some((seriesId) => typeof seriesId === 'string' && seriesId.includes('/'))) {
          modules.add('conn')
        }
      } else {
        modules.add(group.module === 'netcap' ? 'conn' : group.module)
      }
      const featuresBySeries = new Map<string, Set<string>>()
      const noBoundsBySeries = new Set<string>()
      const rhythmAnomalyBySeries = new Set<string>()
      const getSeriesFeatures = (seriesId: string): Set<string> => {
        let seriesFeatures = featuresBySeries.get(seriesId)
        if (!seriesFeatures) {
          seriesFeatures = new Set<string>()
          featuresBySeries.set(seriesId, seriesFeatures)
        }
        return seriesFeatures
      }
      const ids = group.series_ids.filter((value) => typeof value === 'string')
      await Promise.allSettled(
        [...modules].map(async (module) => {
          // Sibling of 10f9ff02: one request per module, not per series (P1 incident, 2026-08-20).
          const response = await $fetch<{ data?: unknown[] }>('/api/v1/anomalies/series', {
            params: { module, start: group.start_timestamp, stop: group.end_timestamp },
          })
          for (const row of response.data ?? []) {
            if (!row || typeof row !== 'object') continue
            const record = row as Record<string, unknown>
            const seriesId = String(record.series_id ?? '')
            if (!ids.includes(seriesId)) continue
            const raw = record.violated_features
            if (Array.isArray(raw)) {
              raw.forEach((feature) => typeof feature === 'string' && getSeriesFeatures(seriesId).add(feature))
            }
            if (record.anomaly_type === 'NoBounds') noBoundsBySeries.add(seriesId)
            if (record.anomaly_type === 'FrequencyAnomaly' || record.anomaly_type === 'AbsenceAnomaly') {
              rhythmAnomalyBySeries.add(seriesId)
            }
          }
        }),
      )
      const seriesWithoutFeatures = new Set(
        ids.filter((seriesId) => (featuresBySeries.get(seriesId)?.size ?? 0) === 0),
      )
      if (seriesWithoutFeatures.size > 0) {
        await Promise.allSettled(
          [...modules].map(async (module) => {
            // One request per module (not per series): the API already returns one
            // aggregated row per series for the window, and `q` is only a cheap
            // server-side substring filter over that same result set. Fetching it
            // per series turned into an N+1 fan-out (UI-143 regression, 2026-08-19)
            // that overloaded Postgres/API for groups with many series_ids.
            const response = await $fetch<{ items?: unknown[] }>('/api/v1/operations/bounds', {
              // Point alarms (start == end) are wanted per operator decision recorded in
              // TODO_otalon-ui.md (UI-195, 2026-10-30). The API window is half-open [from, to)
              // and rejects from >= to with 400, so widen a zero-length window by 1 ms.
              params: {
                module,
                from: group.start_timestamp,
                to: group.start_timestamp === group.end_timestamp
                  ? new Date(new Date(group.end_timestamp).getTime() + 1).toISOString()
                  : group.end_timestamp,
              },
            })
            for (const row of response.items ?? []) {
              if (!row || typeof row !== 'object') continue
              const record = row as Record<string, unknown>
              const seriesId = String(record.series_id ?? '')
              if (!seriesWithoutFeatures.has(seriesId)) continue
              const raw = record.affected_features
              if (Array.isArray(raw)) {
                raw.forEach((feature) => typeof feature === 'string' && getSeriesFeatures(seriesId).add(feature))
              }
              // NoBounds detection (P8-#3C): the bounds endpoint reports the
              // authoritative per-series bound state. If the series has no
              // trained bounds, mark it NoBounds here so the badge renders a
              // single red state badge instead of a misleading yellow
              // feature list (default BoundViolation would otherwise apply).
              const boundsState = String(record.state ?? '')
              const hasBounds = record.has_bounds
              const noBoundsCount = Number(record.nobounds_count ?? 0)
              if (boundsState === 'NoBounds' || hasBounds === false || noBoundsCount > 0) {
                noBoundsBySeries.add(seriesId)
              }
            }
          }),
        )
      }
      const bySeries = Object.fromEntries(
        ids.map((seriesId) => {
          const seriesFeatures = [...(featuresBySeries.get(seriesId) ?? new Set<string>())].sort()
          // A series with no violated features and no NoBounds signal has no
          // violation state at all (P8-#3D): defaulting to BoundViolation would
          // render a misleading badge for series that merely share a group.
          const seriesState = noBoundsBySeries.has(seriesId)
            ? 'NoBounds'
            : seriesFeatures.length > 0
              ? 'BoundViolation'
              : undefined
          return [
            seriesId,
            {
              features: seriesFeatures,
              state: seriesState,
              rhythmAnomaly: rhythmAnomalyBySeries.has(seriesId),
            },
          ]
        }),
      ) as Record<string, AffectedFeaturesBySeriesEntry>
      const result = [...new Set(Object.values(bySeries).flatMap((entry) => entry.features))].sort()
      const state: 'NoBounds' | 'BoundViolation' | undefined = Object.values(bySeries).some((entry) => entry.state === 'NoBounds')
        ? 'NoBounds'
        : Object.values(bySeries).some((entry) => entry.state === 'BoundViolation')
          ? 'BoundViolation'
          : undefined
      this.affectedFeaturesByGroup[group.id] = { features: result, state, bySeries }
      group.affected_features = result
      group.affected_feature_state = state
      return result
    },
    /**
     * Fetch anomaly groups from the backend and store them in state.
     *
     * Merges the provided filter with the current filter, builds
     * query parameters, and replaces the groups array on success.
     * The backend does not support a `status` query parameter;
     * status filtering is applied client-side via the
     * {@link filteredGroups} getter.
     *
     * @param filter - Optional filter overrides to apply before fetching.
     * @param timeParams - Optional time range with `start` and `stop` ISO timestamps.
     * @throws Sets `error` state on failure; does not re-throw.
     */
    async fetchGroups(filter?: AlarmFilter, timeParams?: { start?: string; stop?: string }): Promise<void> {
      if (filter) {
        this.filter = { ...this.filter, ...filter }
      }

      if (this.isInitialLoad) {
        this.isLoading = true
      }
      this.error = null

      try {
        const params = { ...buildQueryParams(this.filter), ...timeParams }
        const response = await $fetch<AnomalyGroupsResponse>('/api/v1/anomalies/groups', { params })
        this.applyGroupsPage(response, { append: false })
      } catch (error: unknown) {
        this.error = `Failed to fetch alarm groups: ${extractErrorMessage(error)}`
      } finally {
        this.isLoading = false
        this.isInitialLoad = false
      }
    },

    /**
     * Merge one page of anomaly groups into state.
     *
     * The single place where `groups`, `totalRowCount` and `hasMore` are
     * written. `fetchGroups` replaced the array while `loadMore` appended
     * to it, each maintaining the pagination counters its own way; a
     * refresh landing between two pages could therefore leave `hasMore`
     * and the array disagreeing (audit UI-07).
     *
     * Appended pages are de-duplicated by `id`: an alarm inserted upstream
     * between two requests shifts the offset window, so the same row can
     * legitimately arrive twice.
     *
     * @param response - The API page.
     * @param options - `append: true` to extend the list, otherwise replace.
     */
    applyGroupsPage(response: AnomalyGroupsResponse, options: { append: boolean }): void {
      const incoming = response.data ?? []
      if (options.append) {
        const seen = new Set(this.groups.map((group) => group.id))
        this.groups = [...this.groups, ...incoming.filter((group) => !seen.has(group.id))]
      } else {
        this.groups = incoming
      }
      this.totalRowCount = response.row_count ?? (options.append ? this.totalRowCount : 0)
      this.hasMore = this.groups.length < this.totalRowCount
    },

    /**
     * Load the next page of anomaly groups and append them.
     *
     * Uses the current filter's `limit` as page size and the current
     * `groups.length` as the offset. No-op when `hasMore` is false or
     * a load is already in progress.
     *
     * @param timeParams - Optional time range with `start` and `stop` ISO timestamps.
     * @throws Sets `error` state on failure; does not re-throw.
     */
    async loadMore(timeParams?: { start?: string; stop?: string }): Promise<void> {
      if (!this.hasMore || this.isLoadingMore) return
      this.isLoadingMore = true
      try {
        const offset = this.groups.length
        const limit = this.filter.limit ?? 50
        const params = { ...buildQueryParams(this.filter), offset, limit, ...timeParams }
        const response = await $fetch<AnomalyGroupsResponse>('/api/v1/anomalies/groups', { params })
        this.applyGroupsPage(response, { append: true })
      } catch (error: unknown) {
        this.error = `Failed to load more alarm groups: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingMore = false
      }
    },

    /**
     * Load affected-feature detail for every group covering `seriesIds`.
     *
     * The detail pages (connections, mac-timeseries, proto-timeseries) read
     * `affectedFeaturesByGroup` to render the violation badge and the
     * per-feature highlights, but nothing populated it when a *series* was
     * selected — `fetchAffectedFeatures` only ran from `selectGroup`, i.e.
     * when an alarm *group* was picked on the alarms page. A connection could
     * therefore show a red status in the list while its detail pane stayed
     * empty (audit SUITE-047).
     *
     * Group matching uses the same port-collapse-aware derivation as the
     * badge, so exactly the groups the badge will consult are fetched.
     * Already-cached groups are skipped by `fetchAffectedFeatures`, and the
     * requests run concurrently.
     *
     * @param seriesIds - Series/UCIs to load alarm detail for.
     */
    async loadAffectedFeaturesForSeries(seriesIds: string[]): Promise<void> {
      const relevant = getGroupsForSeries(this.groups, seriesIds).filter(
        (group) => !this.affectedFeaturesByGroup[group.id],
      )
      if (relevant.length === 0) return
      await Promise.allSettled(relevant.map((group) => this.fetchAffectedFeatures(group)))
    },

    /**
     * Set the currently selected anomaly group.
     *
     * Also lazily fetches affected features for the selected group
     * (if not already cached) — avoids the N+1 fan-out that happened
     * when all groups were enriched on load (API-041).
     *
     * @param groupId - The group ID to select, or `null` to clear selection.
     */
    selectGroup(groupId: string | null): void {
      this.selectedGroupId = groupId
      if (groupId) {
        const group = this.groups.find((g) => g.id === groupId)
        if (group && !this.affectedFeaturesByGroup[groupId]) {
          this.fetchAffectedFeatures(group)
        }
      }
    },

    /**
     * Confirm an anomaly group via optimistic PATCH update.
     *
     * Immediately sets `confirmed = true` in local state, sends
     * the PATCH request, and rolls back on failure.
     *
     * @param groupId - The ID of the group to confirm.
     * @throws Sets `error` state on failure; does not re-throw.
     */
    async confirmGroup(groupId: string): Promise<void> {
      const group = this.groups.find((g) => g.id === groupId)
      if (!group) return

      this.patchingIds.push(groupId)
      group.confirmed = true

      try {
        await $fetch(`/api/v1/anomalies/groups/${groupId}`, {
          method: 'PATCH',
          body: { confirmed: true } satisfies UpdateGroupRequest,
        })
      } catch (error: unknown) {
        group.confirmed = false
        this.error = `Failed to confirm group: ${extractErrorMessage(error)}`
      } finally {
        this.patchingIds = this.patchingIds.filter((id) => id !== groupId)
      }
    },

    /**
     * Unconfirm an anomaly group via optimistic PATCH update.
     *
     * Immediately sets `confirmed = false` in local state, sends
     * the PATCH request, and rolls back on failure.
     *
     * @param groupId - The ID of the group to unconfirm.
     * @throws Sets `error` state on failure; does not re-throw.
     */
    async unconfirmGroup(groupId: string): Promise<void> {
      const group = this.groups.find((g) => g.id === groupId)
      if (!group) return

      this.patchingIds.push(groupId)
      group.confirmed = false

      try {
        await $fetch(`/api/v1/anomalies/groups/${groupId}`, {
          method: 'PATCH',
          body: { confirmed: false } satisfies UpdateGroupRequest,
        })
      } catch (error: unknown) {
        group.confirmed = true
        this.error = `Failed to unconfirm group: ${extractErrorMessage(error)}`
      } finally {
        this.patchingIds = this.patchingIds.filter((id) => id !== groupId)
      }
    },

    /**
     * Adopt a free-form attack-method label as the alarm's primary_type.
     *
     * Used by the *Adopt Subagent Classification* operator action: the
     * subagent's Step-1 ``technical_method`` becomes the new primary_type.
     * Optimistic update (immediate local state change), rollback on
     * server error.
     *
     * @param groupId - The alarm group ID.
     * @param primaryType - The new attack-method label.
     * @returns ``true`` on success, ``false`` on failure (error stored).
     */
    async adoptPrimaryType(groupId: string, primaryType: string): Promise<boolean> {
      const group = this.groups.find((g) => g.id === groupId)
      if (!group) return false

      const previousPrimaryType = group.primary_type
      const previousMultiType = group.multi_type
      this.patchingIds.push(groupId)
      group.primary_type = primaryType
      group.multi_type = false

      try {
        await $fetch(`/api/v1/anomalies/groups/${groupId}/primary-type`, {
          method: 'PATCH',
          body: { primary_type: primaryType },
        })
        return true
      } catch (error: unknown) {
        group.primary_type = previousPrimaryType
        group.multi_type = previousMultiType
        this.error = `Failed to adopt primary_type: ${extractErrorMessage(error)}`
        return false
      } finally {
        this.patchingIds = this.patchingIds.filter((id) => id !== groupId)
      }
    },

    /**
     * Handle an incoming SSE anomaly group update.
     *
     * If the group already exists in local state, its properties
     * are merged. If it is a new group, it is prepended to the list.
     *
     * @param data - The anomaly group payload from the SSE event.
     */
    handleAnomalyUpdate(data: AnomalyGroupItem): void {
      const index = this.groups.findIndex((g) => g.id === data.id)
      if (index >= 0) {
        this.groups[index] = data
      } else {
        this.groups.unshift(data)
      }
    },
  },
})
