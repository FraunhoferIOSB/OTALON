/**
 * Pinia store for the Protocol time-series page source list.
 *
 * Manages the list of available protocol stacks and the currently
 * selected protocol. Fetches from the source-specific IDs endpoint.
 */
import { defineStore } from 'pinia'

import type { SourceIdsResponse } from '~/types/api'

/**
 * A protocol source item with readable protocol and underlying id (hash).
 */
export interface ProtoSourceItem {
  id: string
  protocol: string | null
  presence?: 'live' | 'silent'
}

export interface ProtoSourcesState {
  protos: ProtoSourceItem[]
  selectedProtoId: string | null
  isLoading: boolean
  error: string | null
  showIdColumn: boolean
}

function extractErrorMessage(error: unknown): string {
  if (!error || typeof error !== 'object') return 'An unknown error occurred'
  const errObj = error as Record<string, unknown>
  const status = errObj.status ?? errObj.statusCode
  if (status === 502 || status === 503 || status === 504) {
    return 'Backend is unavailable — is otalon-api running on :8090?'
  }
  const msg = String(errObj.message ?? errObj.statusMessage ?? '')
  if (msg.includes('fetch failed') || msg.includes('ECONNREFUSED') || msg.includes('NetworkError')) {
    return 'Cannot reach backend — is otalon-api running on :8090?'
  }
  return msg || 'An unknown error occurred'
}

export const useProtoSourcesStore = defineStore('protoSources', {
  state: (): ProtoSourcesState => ({
    protos: [],
    selectedProtoId: null,
    isLoading: false,
    error: null,
    showIdColumn: false,
  }),

  getters: {
    selectedProtoItem(state): ProtoSourceItem | undefined {
      if (!state.selectedProtoId) return undefined
      return state.protos.find((p) => p.id === state.selectedProtoId)
    },
  },

  actions: {
    /**
     * Fetch the list of protocol stacks from the backend for the given time range.
     *
     * Calls GET /api/v1/timeseries/proto/ids with `nonzero=true`.
     *
     * @param start - ISO 8601 UTC start timestamp.
     * @param stop - ISO 8601 UTC stop timestamp.
     */
    async fetchProtos(start: string, stop: string): Promise<void> {
      if (this.protos.length === 0) {
        this.isLoading = true
      }
      this.error = null

      try {
        const response = await $fetch<SourceIdsResponse>('/api/v1/timeseries/proto/ids', {
          params: { start, stop, nonzero: true },
        })
        this.protos = response.data.map((item) => ({
          id: item.id,
          protocol: item.protocol ?? null,
        }))
      } catch (error: unknown) {
        this.error = `Failed to fetch protocol list: ${extractErrorMessage(error)}`
      } finally {
        this.isLoading = false
      }
    },

    /**
     * Set the currently selected protocol id.
     *
     * @param id - The protocol id to select, or `null` to clear selection.
     */
    selectProto(id: string | null): void {
      this.selectedProtoId = id
    },

    /**
     * Toggle visibility of the ID column in the protocol table.
     *
     * @param show - Whether to show the ID column.
     */
    setShowIdColumn(show: boolean): void {
      this.showIdColumn = show
    },
  },
})
