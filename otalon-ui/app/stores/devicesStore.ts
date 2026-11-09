/**
 * Pinia store for the Devices page.
 *
 * Loads the device inventory (joined with network interfaces) from the
 * OTALON-API and exposes derived KPI metrics for the page header.
 *
 * Uses the Options API pattern so that ``$reset()`` works automatically.
 *
 * Owns the multi-select state (``selectedIds``) backing the bulk-delete
 * toolbar on the devices page. The set is stored as a plain
 * ``number[]`` so Pinia's reactivity tracks identity changes cheanly;
 * O(N) membership checks are fine for the realistic ceiling (≤ 500
 * selected, which matches the backend bulk-delete cap).
 */
import { defineStore } from 'pinia'

import type { DeviceItem, DevicesResponse } from '~/types/api'

/**
 * Response shape of ``DELETE /api/v1/devices`` (bulk reaper).
 */
export interface BulkDeleteDevicesResponse {
  deleted: number[]
  not_found: number[]
}

/**
 * Devices requested per page.
 *
 * The inventory used to issue exactly one request with `limit=200` and no
 * way to reach page two, so a deployment with more than 200 assets silently
 * showed a truncated inventory (audit UI-12).
 */
export const DEFAULT_PAGE_SIZE = 200

export interface DevicesState {
  devices: DeviceItem[]
  total: number
  isLoading: boolean
  error: string | null
  /**
   * Ids of currently-selected device rows. Plain array (not Set) so
   * Pinia's reactivity tracks identity, and so the toolbar can render
   * ``selectedIds.length`` without a getter.
   */
  selectedIds: number[]
  /** Page size used by {@link fetchDevices} and `loadMore`. */
  pageSize: number
  /** True while a `loadMore` page request is in flight. */
  isLoadingMore: boolean
}

/**
 * Translate an arbitrary thrown value into a user-friendly error string.
 */
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

/**
 * Decide whether a device's most recent scan timestamp counts as "online".
 *
 * A device is considered online when the last scan happened within the
 * configured grace period (default: one hour).
 */
function isRecent(timestamp: string | null, graceMinutes: number = 60): boolean {
  if (!timestamp) return false
  const t = new Date(timestamp).getTime()
  if (Number.isNaN(t)) return false
  return Date.now() - t <= graceMinutes * 60_000
}

export const useDevicesStore = defineStore('devices', {
  state: (): DevicesState => ({
    devices: [],
    total: 0,
    isLoading: false,
    error: null,
    selectedIds: [],
    pageSize: DEFAULT_PAGE_SIZE,
    isLoadingMore: false,
  }),

  getters: {
    /**
     * Number of devices that were last scanned within the grace period.
     */
    onlineCount(state): number {
      return state.devices.filter((d) => isRecent(d.last_scan_at)).length
    },

    /**
     * Number of devices flagged as having a firmware update available.
     */
    updatesAvailableCount(state): number {
      return state.devices.filter((d) => d.update_available).length
    },

    /**
     * Total CVE / vulnerability entries across all loaded devices.
     */
    vulnerabilityCount(state): number {
      let total = 0
      for (const d of state.devices) {
        const vulns = d.vulnerabilities
        if (Array.isArray(vulns)) total += vulns.length
      }
      return total
    },

    /**
     * Distinct vendor values found in the loaded devices, alphabetically sorted.
     * Used to populate the vendor filter dropdown.
     */
    vendorOptions(state): string[] {
      const vendors = new Set<string>()
      for (const d of state.devices) {
        if (d.vendor && d.vendor.length > 0) vendors.add(d.vendor)
      }
      return Array.from(vendors).sort((a, b) => a.localeCompare(b))
    },

    /**
     * Whether the backend holds devices beyond the ones already loaded.
     *
     * @returns `true` when another page can be fetched.
     */
    hasMoreDevices(state): boolean {
      return state.devices.length < state.total
    },

    /**
     * Distinct device_role values found in the loaded devices, alphabetically sorted.
     */
    roleOptions(state): string[] {
      const roles = new Set<string>()
      for (const d of state.devices) {
        if (d.device_role && d.device_role.length > 0) roles.add(d.device_role)
      }
      return Array.from(roles).sort((a, b) => a.localeCompare(b))
    },
  },

  actions: {
    /**
     * Fetch the device inventory page from the API.
     *
     * @param limit - Maximum number of devices to return (default 200).
     * @param offset - Pagination offset (default 0).
     */
    async fetchDevices(limit: number = DEFAULT_PAGE_SIZE, offset: number = 0): Promise<void> {
      this.isLoading = true
      this.error = null
      this.pageSize = limit
      try {
        const response = await $fetch<DevicesResponse>('/api/v1/topology/devices', {
          params: { limit, offset },
        })
        this.devices = response.devices ?? []
        this.total = response.total ?? this.devices.length
        // Prune any selected ids that vanished from the refreshed list
        // so the toolbar count never references stale rows.
        const validIds = new Set(this.devices.map((d) => d.id))
        this.selectedIds = this.selectedIds.filter((id) => validIds.has(id))
      } catch (error: unknown) {
        this.error = `Failed to fetch devices: ${extractErrorMessage(error)}`
        this.devices = []
        this.total = 0
        this.selectedIds = []
      } finally {
        this.isLoading = false
      }
    },

    /**
     * Append the next page of devices to the loaded list.
     *
     * No-op when everything is already loaded or a request is in flight.
     * Rows are de-duplicated by id because an insert upstream between two
     * requests shifts the offset window.
     */
    async loadMoreDevices(): Promise<void> {
      if (this.isLoadingMore || !this.hasMoreDevices) return
      this.isLoadingMore = true
      this.error = null
      try {
        const response = await $fetch<DevicesResponse>('/api/v1/topology/devices', {
          params: { limit: this.pageSize, offset: this.devices.length },
        })
        const incoming = response.devices ?? []
        const seen = new Set(this.devices.map((d) => d.id))
        this.devices = [...this.devices, ...incoming.filter((d) => !seen.has(d.id))]
        this.total = response.total ?? this.total
      } catch (error: unknown) {
        this.error = `Failed to load more devices: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingMore = false
      }
    },

    /**
     * Whether a given device id is currently selected.
     */
    isSelected(id: number): boolean {
      return this.selectedIds.includes(id)
    },

    /**
     * Toggle selection of one device id.
     */
    toggleSelect(id: number): void {
      const idx = this.selectedIds.indexOf(id)
      if (idx === -1) {
        this.selectedIds.push(id)
      } else {
        this.selectedIds.splice(idx, 1)
      }
    },

    /**
     * Replace the selection with every currently-loaded device id.
     */
    selectAll(): void {
      this.selectedIds = this.devices.map((d) => d.id)
    },

    /**
     * Drop every entry from the selection.
     */
    clearSelection(): void {
      this.selectedIds = []
    },

    /**
     * Replace the selection with an explicit set of device ids.
     *
     * Used by the table's ``v-model:selected`` binding so Quasar's
     * native multi-select drives the store rather than the other way
     * around.
     */
    setSelection(ids: number[]): void {
      this.selectedIds = Array.from(new Set(ids))
    },

    /**
     * Bulk-delete every currently-selected device id via
     * ``DELETE /api/v1/devices``.
     *
     * On success: drops deleted ids from the local ``devices`` list,
     * clears the selection, returns the upstream
     * :class:`BulkDeleteDevicesResponse` so callers can surface a
     * ``"X deleted, Y not found"`` notice. On HTTP / transport error
     * the selection is left intact and the error is re-thrown.
     */
    async bulkDeleteSelected(): Promise<BulkDeleteDevicesResponse> {
      if (this.selectedIds.length === 0) {
        return { deleted: [], not_found: [] }
      }
      const ids = [...this.selectedIds]
      const response = await $fetch<BulkDeleteDevicesResponse>('/api/v1/devices', {
        method: 'DELETE',
        body: { ids },
      })
      const deletedSet = new Set(response.deleted)
      this.devices = this.devices.filter((d) => !deletedSet.has(d.id))
      this.total = Math.max(0, this.total - response.deleted.length)
      this.selectedIds = this.selectedIds.filter((id) => !deletedSet.has(id))
      return response
    },
  },
})
