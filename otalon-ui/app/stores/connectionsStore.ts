/**
 * Pinia store for the connections page UCI selection and state.
 *
 * Manages the list of active network connections (UCIs) fetched from
 * the backend, the currently selected connection, and derived
 * connection metadata parsed from UCI strings.
 *
 * Uses the Options API pattern so that `$reset()` works automatically.
 */
import { defineStore } from 'pinia'

import type { FrequencyProfileListResponse, IdsResponse } from '~/types/api'
import type { Connection } from '~/types/golden-data'
import { parseUciToConnection } from '~/utils/uci'

/**
 * Shape of the connections store reactive state.
 */
export interface ConnectionsState {
  connections: Connection[]
  profiledUcis: string[]
  showSilentProfiled: boolean
  selectedUci: string | null
  isLoading: boolean
  error: string | null
  showPortColumn: boolean
}

/**
 * Extract a human-readable error message from an unknown thrown value.
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

export const useConnectionsStore = defineStore('connections', {
  state: (): ConnectionsState => ({
    connections: [],
    profiledUcis: [],
    showSilentProfiled: false,
    selectedUci: null,
    isLoading: false,
    error: null,
    showPortColumn: true,
  }),

  getters: {
    /**
     * Connections that have a learned frequency profile but no traffic in
     * the current window.
     *
     * These never appear in `connections` — that list is built from live
     * traffic — so without this derivation the operator cannot open the
     * RHYTHM lane of a connection that has gone silent, which is the very
     * situation the absence detector reports.
     *
     * @returns Silent profiled connections, marked `presence: 'silent'`.
     */
    silentProfiledConnections(state): Connection[] {
      const live = new Set(state.connections.map((c) => c.uci))
      return state.profiledUcis.filter((uci) => !live.has(uci)).map((uci) => parseUciToConnection({ uci }, 'silent'))
    },

    /**
     * The connections offered for selection.
     *
     * Live rows always come first and keep their order; silent profiled
     * rows are appended only while {@link ConnectionsState.showSilentProfiled}
     * is on, and stay tagged so the table can render them distinctly
     * instead of blending them into live traffic.
     *
     * @returns Live rows, optionally followed by silent profiled rows.
     */
    selectableConnections(state): Connection[] {
      const live = state.connections.map((c) => ({ ...c, presence: c.presence ?? ('live' as const) }))
      if (!state.showSilentProfiled) return live
      const liveUcis = new Set(live.map((c) => c.uci))
      const silent = state.profiledUcis
        .filter((uci) => !liveUcis.has(uci))
        .map((uci) => parseUciToConnection({ uci }, 'silent'))
      return [...live, ...silent]
    },

    /**
     * Number of profiled connections currently not sending.
     *
     * Drives the toggle's badge so the operator sees whether enabling it
     * would reveal anything before clicking.
     *
     * @returns Count of profiled UCIs absent from the live list.
     */
    silentProfiledCount(state): number {
      const live = new Set(state.connections.map((c) => c.uci))
      return state.profiledUcis.filter((uci) => !live.has(uci)).length
    },

    /**
     * The currently selected connection object.
     *
     * Resolves against the live list first and falls back to the silent
     * profiled rows, so a selected silent connection does not lose its
     * metadata the moment it stops appearing in live traffic.
     *
     * @returns The matching Connection, or `undefined` when nothing is selected.
     */
    selectedConnection(state): Connection | undefined {
      if (!state.selectedUci) return undefined
      const liveMatch = state.connections.find((c) => c.uci === state.selectedUci)
      if (liveMatch) return liveMatch
      if (!state.profiledUcis.includes(state.selectedUci)) return undefined
      return parseUciToConnection({ uci: state.selectedUci }, 'silent')
    },

    /**
     * Total number of connections loaded.
     *
     * @returns The length of the connections array.
     */
    connectionCount(state): number {
      return state.connections.length
    },
  },

  actions: {
    /**
     * Fetch the list of active UCIs from the backend for the given time range.
     *
     * Calls GET /api/v1/timeseries/ids with `nonzero=true` and
     * `group_wildcards=true` to get wildcard-grouped connections
     * with traffic in the specified time window. Each response item
     * is parsed into a Connection object with source/destination/protocol.
     *
     * @param start - ISO 8601 UTC start timestamp.
     * @param stop - ISO 8601 UTC stop timestamp.
     */
    async fetchConnections(start: string, stop: string): Promise<void> {
      if (this.connections.length === 0) {
        this.isLoading = true
      }
      this.error = null

      try {
        const response = await $fetch<IdsResponse>('/api/v1/timeseries/ids', {
          params: { start, stop, nonzero: true, group_wildcards: true },
        })
        this.connections = response.data.map((item) => parseUciToConnection(item, 'live'))
      } catch (error: unknown) {
        this.error = `Failed to fetch connections: ${extractErrorMessage(error)}`
      } finally {
        this.isLoading = false
      }
    },

    /**
     * Fetch the UCIs that carry a learned frequency profile.
     *
     * Calls `GET /api/v1/frequency/profiles`, which is independent of the
     * traffic window and therefore also returns connections that are
     * currently silent.
     *
     * A failure here is deliberately NOT written to {@link ConnectionsState.error}:
     * the profile list is an enrichment of the live table, so losing it
     * must not raise a page-level error banner over a table that still
     * works. The silent rows simply stay unavailable.
     *
     * @param module - Detection module name; defaults to `conn`.
     */
    async fetchProfiledUcis(module = 'conn'): Promise<void> {
      try {
        const response = await $fetch<FrequencyProfileListResponse>('/api/v1/frequency/profiles', {
          params: { module },
        })
        this.profiledUcis = response.data.filter((p) => p.has_profile).map((p) => p.series_id)
      } catch {
        this.profiledUcis = []
      }
    },

    /**
     * Show or hide the profiled-but-silent rows in the selector table.
     *
     * @param show - Whether silent profiled connections are offered.
     */
    setShowSilentProfiled(show: boolean): void {
      this.showSilentProfiled = show
    },

    /**
     * Set the currently selected connection by UCI string.
     *
     * @param uci - The UCI to select, or `null` to clear selection.
     */
    selectConnection(uci: string | null): void {
      this.selectedUci = uci
    },

    /**
     * Toggle visibility of the Port column in the connection table.
     *
     * @param show - Whether to show the Port column.
     */
    setShowPortColumn(show: boolean): void {
      this.showPortColumn = show
    },
  },
})
