/**
 * Pinia store for the MAC time-series page source list.
 *
 * Manages the list of available MAC addresses and the currently
 * selected MAC. Fetches from the source-specific IDs endpoint.
 */
import { defineStore } from 'pinia'

import type { SourceIdsResponse } from '~/types/api'

/**
 * A MAC source item enriched with optional device metadata.
 */
export interface MacSourceItem {
  mac: string
  name: string | null
  ip: string | null
  state?: 'anomaly' | 'normal'
  presence?: 'live' | 'silent'
}

export interface MacSourcesState {
  macs: MacSourceItem[]
  selectedMac: string | null
  isLoading: boolean
  error: string | null
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

export const useMacSourcesStore = defineStore('macSources', {
  state: (): MacSourcesState => ({
    macs: [],
    selectedMac: null,
    isLoading: false,
    error: null,
  }),

  getters: {
    selectedMacItem(state): MacSourceItem | undefined {
      if (!state.selectedMac) return undefined
      return state.macs.find((m) => m.mac === state.selectedMac)
    },
  },

  actions: {
    /**
     * Fetch the list of MAC addresses from the backend for the given time range.
     *
     * Calls GET /api/v1/timeseries/mac/ids with `nonzero=true`.
     *
     * @param start - ISO 8601 UTC start timestamp.
     * @param stop - ISO 8601 UTC stop timestamp.
     */
    async fetchMacs(start: string, stop: string): Promise<void> {
      if (this.macs.length === 0) {
        this.isLoading = true
      }
      this.error = null

      try {
        const response = await $fetch<SourceIdsResponse>('/api/v1/timeseries/mac/ids', {
          params: { start, stop, nonzero: true },
        })
        const oldMap = new Map<string, MacSourceItem>(this.macs.map((m) => [m.mac.toLowerCase(), m]))
        this.macs = response.data.map((item) => {
          const old = oldMap.get(item.id.toLowerCase())
          return {
            mac: item.id,
            name: old?.name ?? null,
            ip: old?.ip ?? null,
          }
        })
      } catch (error: unknown) {
        this.error = `Failed to fetch MAC list: ${extractErrorMessage(error)}`
      } finally {
        this.isLoading = false
      }
    },

    /**
     * Enrich the MAC list with device metadata (name / ip) from the
     * device inventory.  Merges by matching MAC address case-insensitively.
     *
     * @param devices - Device items from the topology endpoint.
     */
    enrichWithDevices(
      devices: {
        hostname: string | null
        product_name: string | null
        device_family: string | null
        interfaces: { mac_address: string | null; ipv4_address: string | null }[]
      }[],
    ): void {
      const macMap = new Map<string, { name: string | null; ip: string | null }>()
      for (const device of devices) {
        const name = device.hostname || device.product_name || device.device_family || null
        for (const iface of device.interfaces ?? []) {
          const mac = iface.mac_address
          if (!mac) continue
          const normalized = mac.toLowerCase()
          if (!macMap.has(normalized)) {
            macMap.set(normalized, { name, ip: iface.ipv4_address ?? null })
          }
        }
      }

      this.macs = this.macs.map((item) => {
        const enriched = macMap.get(item.mac.toLowerCase())
        if (enriched) {
          return { ...item, name: enriched.name, ip: enriched.ip }
        }
        return item
      })
    },

    /**
     * Set the currently selected MAC address.
     *
     * @param mac - The MAC to select, or `null` to clear selection.
     */
    selectMac(mac: string | null): void {
      this.selectedMac = mac
    },
  },
})
