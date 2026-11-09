/**
 * Pinia store for the Vulnerabilities page (Welle D).
 *
 * Loads the active vulnerability inventory by flattening the
 * ``vulnerabilities`` array from ``GET /api/v1/topology/devices``.
 * Owns the lookup trigger (``POST /api/v1/vulnerabilities/lookup``) and
 * triage PATCH state.
 */
import { defineStore } from 'pinia'

import { useApi } from '~/composables/useApi'
import type {
  DeviceItem,
  DeviceVulnerabilityItem,
  VulnerabilityLookupRequest,
  VulnerabilityLookupResponse,
  VulnerabilityPatchRequest,
  VulnerabilityItem,
  CveLookupItem,
  CveLookupsListResponse,
} from '~/types/api'

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

/** Flattened row combining a vuln with its parent device context. */
export interface VulnRow {
  deviceId: number
  deviceVendor: string | null
  deviceFamily: string | null
  deviceType: string | null
  observationId: number
  vulnId: string
  severity: string | null
  summary: string | null
  status: string
  sourceModule: string | null
  detectedAt: string | null
  lastSeenAt: string | null
  /** Client-side mirror of ``status_changed_by`` from PATCH response. */
  statusChangedBy: string | null
}

export interface VulnerabilitiesState {
  devices: DeviceItem[]
  isLoading: boolean
  lookupLoading: boolean
  error: string | null
  lookupError: string | null
  lookupResult: VulnerabilityLookupResponse | null
  lookups: CveLookupItem[]
  lookupsLoading: boolean
  lookupsError: string | null
  selectedLookupId: string | null
}

export const useVulnerabilitiesStore = defineStore('vulnerabilities', {
  state: (): VulnerabilitiesState => ({
    devices: [],
    isLoading: false,
    lookupLoading: false,
    error: null,
    lookupError: null,
    lookupResult: null,
    lookups: [],
    lookupsLoading: false,
    lookupsError: null,
    selectedLookupId: null,
  }),

  getters: {
    /**
     * Flatten every active vulnerability from every loaded device into
     * a single searchable / sortable list.
     */
    rows(state): VulnRow[] {
      const out: VulnRow[] = []
      for (const d of state.devices) {
        const vulns = d.vulnerabilities
        if (!Array.isArray(vulns) || vulns.length === 0) continue
        for (const v of vulns) {
          out.push({
            deviceId: d.id,
            deviceVendor: d.vendor,
            deviceFamily: d.device_family,
            deviceType: d.device_type,
            observationId: Number(
              (v as DeviceVulnerabilityItem).id ?? (v as DeviceVulnerabilityItem).observation_id ?? 0,
            ),
            vulnId: String(v.vuln_id ?? v.cve ?? '?'),
            severity: v.severity ?? null,
            summary: v.summary ?? null,
            status: v.status ?? 'active',
            sourceModule: v.source_module ?? null,
            detectedAt: v.detected_at ?? null,
            lastSeenAt: v.last_seen_at ?? null,
            statusChangedBy: (v as DeviceVulnerabilityItem)._status_changed_by ?? null,
          })
        }
      }
      return out
    },

    totalCount(state): number {
      let total = 0
      for (const d of state.devices) {
        const vulns = d.vulnerabilities
        if (Array.isArray(vulns)) total += vulns.length
      }
      return total
    },
  },

  actions: {
    /**
     * Fetch the topology device list and extract vulnerabilities.
     * Reuses the existing ``GET /api/v1/topology/devices`` endpoint
     * because there is no dedicated vulnerability list endpoint.
     */
    async fetchDevices(): Promise<void> {
      this.isLoading = true
      this.error = null
      try {
        const response = await $fetch<{ devices: DeviceItem[]; total: number }>('/api/v1/topology/devices', {
          params: { limit: 200, offset: 0 },
        })
        this.devices = response.devices ?? []
      } catch (error: unknown) {
        this.error = `Failed to fetch vulnerabilities: ${extractErrorMessage(error)}`
        this.devices = []
      } finally {
        this.isLoading = false
      }
    },

    /**
     * Trigger a CVE lookup for eligible assets.
     *
     * @param body - ``device_ids`` scoped lookup or ``all: true``.
     */
    async runLookup(body: VulnerabilityLookupRequest): Promise<VulnerabilityLookupResponse> {
      this.lookupLoading = true
      this.lookupError = null
      this.lookupResult = null
      try {
        const api = useApi()
        const res = await api.post<VulnerabilityLookupResponse>('/api/v1/vulnerabilities/lookup', body)
        this.lookupResult = res
        return res
      } catch (error: unknown) {
        this.lookupError = extractErrorMessage(error)
        throw error
      } finally {
        this.lookupLoading = false
      }
    },

    /**
     * Request cooperative cancellation of an in-flight CVE lookup (R-02).
     *
     * Calls the upstream stop endpoint; the backend flags the running
     * lookup task so it stops issuing further NVD queries and finalizes
     * itself as ``aborted`` (with a terminal ``aborted`` SSE event the
     * dialog reacts to). Resolves to ``true`` when a live job was flagged.
     *
     * @param jobId - The lookup job id to stop.
     */
    async stopLookup(jobId: string): Promise<boolean> {
      const api = useApi()
      const res = await api.post<{ job_id: string; stopped: boolean }>(
        `/api/v1/vulnerabilities/lookups/${jobId}/stop`,
        {},
      )
      return res.stopped
    },

    /**
     * Fetch recent CVE-lookup jobs (newest first).
     */
    async fetchLookups(): Promise<void> {
      this.lookupsLoading = true
      this.lookupsError = null
      try {
        const api = useApi()
        const res = await api.get<CveLookupsListResponse>('/api/v1/vulnerabilities/lookups')
        this.lookups = res.lookups ?? []
      } catch (error: unknown) {
        this.lookupsError = extractErrorMessage(error)
        this.lookups = []
      } finally {
        this.lookupsLoading = false
      }
    },

    /**
     * Select a lookup for the detail pane.
     */
    selectLookup(jobId: string | null): void {
      this.selectedLookupId = jobId
    },

    /**
     * Patch the triage status of a single vulnerability observation.
     *
     * @param observationId - The ``vulnerability_observations.id`` primary key.
     * @param body - Fields to update; ``status_changed_by`` is set by
     *   the caller (usually ``'operator'``).
     * @returns The updated row from upstream.
     */
    async patchVulnerability(
      observationId: number,
      body: Omit<VulnerabilityPatchRequest, 'status_changed_by'>,
    ): Promise<VulnerabilityItem> {
      const api = useApi()
      const patchBody: VulnerabilityPatchRequest = {
        ...body,
        status_changed_by: 'operator',
      }
      const res = await api.patch<VulnerabilityItem>(`/api/v1/vulnerabilities/${observationId}`, patchBody)

      // Mirror ``status_changed_by`` back into exactly the observation
      // that was patched so the UI renders the lock badge without refetch.
      for (const d of this.devices) {
        const vulns = d.vulnerabilities
        if (!Array.isArray(vulns)) continue
        for (const v of vulns) {
          if (Number((v as DeviceVulnerabilityItem).observation_id ?? 0) === observationId) {
            v.status = res.status
            ;(v as DeviceVulnerabilityItem)._status_changed_by = res.status_changed_by
          }
        }
      }
      return res
    },
  },
})
