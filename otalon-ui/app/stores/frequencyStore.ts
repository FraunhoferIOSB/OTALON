/**
 * Pinia store for the per-series frequency profile (RHYTHM lane).
 *
 * Holds the learned cadence and derived rhythm state served by
 * `GET /api/v1/frequency/profile`. Degrades quietly: a failing request
 * leaves `profile` null and records `error`, so a page keeps working
 * when the endpoint is unavailable.
 *
 * The store is a singleton shared by every page that renders a RHYTHM
 * lane (connections, Assets, Protocols). It therefore records WHICH
 * module and series the loaded profile belongs to, so a consumer can
 * refuse to render a profile that was loaded for a different page. See
 * `module` / `seriesId` and the `matches()` getter.
 *
 * Uses the Options API pattern so that `$reset()` works automatically.
 */
import { defineStore } from 'pinia'

import type { FrequencyProfileResponse } from '~/types/api'

/**
 * Detection modules for which otalon-clas trains frequency profiles.
 *
 * Mirrors `SUPPORTED_MODULES` in the API's frequency service. `netcap`
 * is deliberately absent: it is the InfluxDB database name, never a
 * module the frequency monitor writes profiles under.
 */
export type FrequencyModule = 'conn' | 'mac_traffic' | 'proto_traffic'

/**
 * Shape of the frequency store reactive state.
 */
export interface FrequencyState {
  profile: FrequencyProfileResponse | null
  seriesId: string | null
  module: FrequencyModule | null
  isLoading: boolean
  error: string | null
  requestSeq: number
}

/**
 * Extract a human-readable message from an unknown thrown value.
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
  return msg || 'An unknown error occurred'
}

export const useFrequencyStore = defineStore('frequency', {
  state: (): FrequencyState => ({
    profile: null,
    seriesId: null,
    module: null,
    isLoading: false,
    error: null,
    requestSeq: 0,
  }),

  getters: {
    /**
     * Whether the loaded state belongs to the given module and series.
     *
     * The store is shared across the connections, Assets and Protocols
     * pages. A lane must only render state it actually asked for, so it
     * gates its own rendering on this predicate rather than trusting
     * that whatever sits in the store is its own.
     *
     * @returns Predicate over a module/series pair.
     */
    matches(state): (module: FrequencyModule, seriesId: string | null) => boolean {
      return (module: FrequencyModule, seriesId: string | null): boolean =>
        state.module === module && state.seriesId !== null && state.seriesId === seriesId
    },
  },

  actions: {
    /**
     * Fetch the frequency profile for one series.
     *
     * A series without a trained profile is NOT an error: the API answers
     * 200 with `state: 'no_profile'`, which is stored like any other
     * state so the lane can render it plainly.
     *
     * Late responses are dropped. Switching page or row while a request
     * is in flight would otherwise let the older response overwrite the
     * newer selection, showing one page's cadence under another page's
     * heading.
     *
     * @param seriesId - The series identifier to fetch.
     * @param module - Detection module the series belongs to.
     */
    async fetchProfile(seriesId: string, module: FrequencyModule = 'conn'): Promise<void> {
      if (!seriesId) {
        this.clear()
        return
      }
      const seq = ++this.requestSeq
      this.isLoading = true
      this.error = null
      try {
        const response = await $fetch<FrequencyProfileResponse>('/api/v1/frequency/profile', {
          params: { uci: seriesId, module },
        })
        if (seq !== this.requestSeq) return
        this.profile = response
        this.seriesId = seriesId
        this.module = module
      } catch (error: unknown) {
        if (seq !== this.requestSeq) return
        this.profile = null
        this.seriesId = seriesId
        this.module = module
        this.error = extractErrorMessage(error)
      } finally {
        if (seq === this.requestSeq) {
          this.isLoading = false
        }
      }
    },

    /**
     * Drop any loaded profile, e.g. when the selection is cleared or the
     * page is left.
     *
     * Bumps the request sequence so a response still in flight for the
     * cleared selection cannot repopulate the store afterwards.
     */
    clear(): void {
      this.requestSeq += 1
      this.profile = null
      this.seriesId = null
      this.module = null
      this.error = null
      this.isLoading = false
    },
  },
})
