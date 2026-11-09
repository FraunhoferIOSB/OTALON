/**
 * Pinia store for the dashboard page.
 *
 * Manages KPIs, recent alarms (anomaly groups), and service health
 * state including loading and error indicators. Supports both
 * REST polling via `$fetch` and real-time SSE push updates.
 *
 * Uses the Options API pattern so that `$reset()` works automatically.
 */
import { defineStore } from 'pinia'

import type {
  AnomalyGroupItem,
  AnomalyGroupsResponse,
  DashboardKpisData,
  DashboardKpisResponse,
  DeviceItem,
  DevicesResponse,
  HealthCheckItem,
  HealthResponse,
  ThroughputDataPoint,
  ThroughputResponse,
  TopAssetItem,
  TopAssetsResponse,
  TopConnectionItem,
  TopProtocolItem,
  TopProtocolsResponse,
  VulnerabilitySummaryData,
} from '~/types/api'

export interface DashboardState {
  kpis: DashboardKpisData | null
  recentAlarms: AnomalyGroupItem[]
  health: HealthResponse | null
  throughput: ThroughputDataPoint[]
  macAssets: TopAssetItem[]
  protocolIds: TopProtocolItem[]
  deviceInventory: DeviceItem[]
  vulnerabilitySummary: VulnerabilitySummaryData | null
  isLoading: boolean
  isInitialLoad: boolean
  error: string | null
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

export const useDashboardStore = defineStore('dashboard', {
  state: (): DashboardState => ({
    kpis: null,
    recentAlarms: [],
    health: null,
    throughput: [],
    macAssets: [],
    protocolIds: [],
    deviceInventory: [],
    vulnerabilitySummary: null,
    isLoading: false,
    isInitialLoad: true,
    error: null,
  }),

  getters: {
    /**
     * Traffic-light signal color derived from the current KPI snapshot.
     *
     * @returns The signal color string, or `'info'` when no KPIs are loaded.
     */
    signalColor(state): string {
      return state.kpis?.signal_color ?? 'info'
    },

    /**
     * Total number of detected anomalies.
     *
     * @returns The anomaly count, or `0` when no KPIs are loaded.
     */
    anomalyCount(state): number {
      return state.kpis?.anomaly_count ?? 0
    },

    /**
     * Number of anomalies that have been classified.
     *
     * @returns The classified count, or `0` when no KPIs are loaded.
     */
    classifiedCount(state): number {
      return state.kpis?.classified_count ?? 0
    },

    /**
     * Total number of active network connections.
     *
     * @returns The connection count, or `0` when no KPIs are loaded.
     */
    connectionCount(state): number {
      return state.kpis?.connection_count ?? 0
    },

    /**
     * Total number of discovered network devices.
     *
     * @returns The device count, or `0` when no KPIs are loaded.
     */
    deviceCount(state): number {
      return state.kpis?.device_count ?? 0
    },

    /**
     * Top connections ranked by traffic volume.
     *
     * @returns Array of top connection items, or empty array when no KPIs are loaded.
     */
    topConnections(state): TopConnectionItem[] {
      return state.kpis?.top_connections ?? []
    },

    /**
     * Aggregate health status across all monitored services.
     *
     * @returns The overall status string, or `'unknown'` when unavailable.
     */
    overallHealthStatus(state): string {
      return state.health?.overall_status ?? 'unknown'
    },

    /**
     * List of individual service health checks.
     *
     * @returns Array of health check items, or an empty array when unavailable.
     */
    healthServices(state): HealthCheckItem[] {
      return state.health?.services ?? []
    },

    /**
     * Network throughput time series data points.
     *
     * @returns Array of throughput data points, or an empty array when unavailable.
     */
    throughputData(state): ThroughputDataPoint[] {
      return state.throughput
    },

    /**
     * MAC addresses with traffic in the current window.
     *
     * @returns Array of top asset items, or empty array when unavailable.
     */
    macAssetList(state): TopAssetItem[] {
      return state.macAssets
    },

    /**
     * Count of MAC assets with traffic.
     *
     * @returns Number of MAC assets, or 0 when unavailable.
     */
    macAssetCount(state): number {
      return state.macAssets.length
    },

    /**
     * Total number of distinct protocols observed.
     *
     * @returns The protocol count from KPIs, or `0` when unavailable.
     */
    protocolCount(state): number {
      return state.kpis?.protocol_count ?? 0
    },

    /**
     * Count of protocols with traffic (top list length).
     *
     * @returns Number of top protocol items, or 0 when unavailable.
     */
    topProtocolListCount(state): number {
      return state.protocolIds.length
    },
  },

  actions: {
    /**
     * Fetch the latest dashboard KPI snapshot from the backend.
     *
     * Extracts `data[0]` from the API envelope and stores it in state.
     *
     * @param params - Optional time range filter with `start` and `stop` ISO timestamps.
     * @throws Sets `error` state on failure; does not re-throw.
     */
    async fetchKpis(params?: { start?: string; stop?: string }): Promise<void> {
      try {
        const response = await $fetch<DashboardKpisResponse>('/api/v1/dashboard/kpis', {
          params,
        })
        this.kpis = response.data[0] ?? null
      } catch (error: unknown) {
        const message = extractErrorMessage(error)
        this.error = `Failed to fetch KPIs: ${message}`
      }
    },

    /**
     * Fetch the five most recent anomaly groups (alarms) from the backend.
     *
     * Results are sorted by `start_timestamp` descending and scoped to
     * the provided time window when given.
     *
     * @param params - Optional time range filter with `start` and `stop` ISO timestamps.
     * @throws Sets `error` state on failure; does not re-throw.
     */
    async fetchRecentAlarms(params?: { start?: string; stop?: string }): Promise<void> {
      try {
        const response = await $fetch<AnomalyGroupsResponse>('/api/v1/anomalies/groups', {
          params: { limit: 5, ...params },
        })
        this.recentAlarms = response.data
      } catch (error: unknown) {
        const message = extractErrorMessage(error)
        this.error = `Failed to fetch recent alarms: ${message}`
      }
    },

    /**
     * Fetch the current health status of all monitored services.
     *
     * @throws Sets `error` state on failure; does not re-throw.
     */
    async fetchHealth(): Promise<void> {
      try {
        const response = await $fetch<HealthResponse>('/api/v1/status/health', {
          params: { detail: 'true' },
        })
        this.health = response
      } catch (error: unknown) {
        const message = extractErrorMessage(error)
        this.error = `Failed to fetch health status: ${message}`
      }
    },

    /**
     * Fetch aggregated network throughput data for the sparkline widget.
     *
     * Throughput is non-critical UI data, so errors are silently handled
     * by resetting to an empty array without setting the global error state.
     *
     * @param params - Optional query parameters forwarded to the endpoint.
     */
    async fetchThroughput(params?: Record<string, string>): Promise<void> {
      try {
        const response = await $fetch<ThroughputResponse>('/api/v1/dashboard/throughput', { params })
        this.throughput = response.data
      } catch {
        this.throughput = []
      }
    },

    /**
     * Fetch top MAC addresses by traffic volume for the Assets widget.
     *
     * Errors are silently handled by resetting to an empty array
     * without setting the global error state (non-critical widget data).
     *
     * @param params - Optional time range with `start` and `stop` ISO timestamps.
     */
    async fetchMacAssets(params?: { start?: string; stop?: string }): Promise<void> {
      try {
        const response = await $fetch<TopAssetsResponse>('/api/v1/dashboard/top-assets', {
          params: { ...params, limit: 5 },
        })
        this.macAssets = response.data
      } catch {
        this.macAssets = []
      }
    },

    /**
     * Fetch top protocol stacks by traffic volume for the Top Protocols widget.
     *
     * Errors are silently handled by resetting to an empty array.
     *
     * @param params - Optional time range with `start` and `stop` ISO timestamps.
     */
    async fetchProtocols(params?: { start?: string; stop?: string }): Promise<void> {
      try {
        const response = await $fetch<TopProtocolsResponse>('/api/v1/dashboard/top-protocols', {
          params: { ...params, limit: 5 },
        })
        this.protocolIds = response.data
      } catch {
        this.protocolIds = []
      }
    },

    /**
     * Fetch the device inventory to enrich MAC assets with names and IPs.
     *
     * Errors are silently handled by resetting to an empty array.
     */
    async fetchDeviceInventory(): Promise<void> {
      try {
        const response = await $fetch<DevicesResponse>('/api/v1/topology/devices', {
          params: { limit: 1000, offset: 0 },
        })
        this.deviceInventory = response.devices
      } catch {
        this.deviceInventory = []
      }
    },

    /**
     * Fetch vulnerability summary for the dashboard widget.
     *
     * Errors are silently handled by resetting to null.
     */
    async fetchVulnerabilitySummary(): Promise<void> {
      try {
        const response = await $fetch<{ data: VulnerabilitySummaryData }>('/api/v1/dashboard/vulnerabilities-summary')
        this.vulnerabilitySummary = response.data
      } catch {
        this.vulnerabilitySummary = null
      }
    },

    /**
     * Fetch KPIs, recent alarms, health status, throughput, MAC assets,
     * protocols, device inventory, and vulnerability summary in parallel.
     *
     * Uses `Promise.allSettled` so that a single endpoint failure does not
     * block the other requests. Sets `isLoading` during the request cycle
     * and collects error messages from any rejected promises.
     *
     * @param params - Optional time range filter forwarded to `fetchKpis`.
     */
    async fetchAll(params?: { start?: string; stop?: string }): Promise<void> {
      if (this.isInitialLoad) {
        this.isLoading = true
      }
      this.error = null

      const results = await Promise.allSettled([
        this.fetchKpis(params),
        this.fetchRecentAlarms(params),
        this.fetchHealth(),
        this.fetchThroughput(params as Record<string, string>),
        this.fetchMacAssets(params),
        this.fetchProtocols(params),
        this.fetchDeviceInventory(),
        this.fetchVulnerabilitySummary(),
      ])

      const errors: string[] = []
      for (const result of results) {
        if (result.status === 'rejected') {
          errors.push(extractErrorMessage(result.reason))
        }
      }

      if (errors.length > 0 && !this.error) {
        this.error = errors.join('; ')
      }

      this.isLoading = false
      this.isInitialLoad = false
    },

    /**
     * SSE handler that merges incoming KPI data into the store state.
     *
     * Called by the SSE composable when a `kpi` event is received.
     *
     * @param data - The KPI payload from the SSE event.
     */
    handleKpiUpdate(data: DashboardKpisData): void {
      this.kpis = data
    },

    /**
     * SSE handler that replaces health state with the latest push update.
     *
     * Called by the SSE composable when a `health` event is received.
     *
     * @param data - The health payload from the SSE event.
     */
    handleHealthUpdate(data: HealthResponse): void {
      this.health = data
    },

    /**
     * SSE handler that upserts a single anomaly group into the recent alarms list.
     *
     * If the group already exists (by `id`), it is replaced in-place.
     * New groups are prepended so the most recent alarm appears first.
     * The list is capped at 5 entries to match the dashboard widget size.
     *
     * Called by the SSE composable when an `anomaly` event is received.
     *
     * @param data - A single anomaly group payload from the SSE event.
     */
    handleRecentAlarmUpdate(data: AnomalyGroupItem): void {
      const index = this.recentAlarms.findIndex((g) => g.id === data.id)
      if (index >= 0) {
        this.recentAlarms[index] = data
      } else {
        this.recentAlarms.unshift(data)
        if (this.recentAlarms.length > 5) {
          this.recentAlarms = this.recentAlarms.slice(0, 5)
        }
      }
    },
  },
})
