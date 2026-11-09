/**
 * Pinia store for the Operations Overview page.
 *
 * Aggregates pipeline freshness, attention findings and service health
 * into view models for the four KPIs, the data-path freshness strip,
 * the Service Health summary and the Attention Required list.
 */
import { defineStore } from 'pinia'

import {
  useApi,
  type UseApiReturn,
} from '~/composables/useApi'
import type {
  AttentionFinding,
  HealthCheckItem,
  HealthResponse,
  DetectionReadinessResponse,
  OperationsStorageResponse,
  PipelineResponse,
  PipelineSource,
} from '~/types/api'
import { operationErrorMessage } from '~/utils/permissions'

/**
 * Friendly UI labels for pipeline source ids.
 */
export const SOURCE_LABELS: Record<string, string> = {
  conn: 'Connections',
  mac: 'Assets',
  proto: 'Protocols',
}

/**
 * Visual descriptor for a service state badge.
 */
export interface ServiceBadge {
  kind: 'ok' | 'warn' | 'err' | 'info'
  label: string
  icon: string
}

/**
 * Derive a truthful badge for a service, keeping `not-configured`/`disabled`
 * optional states distinct from a real `failed`.
 *
 * @param service - The health item to describe.
 * @returns The badge kind, label and icon.
 */
export function serviceBadge(service: HealthCheckItem): ServiceBadge {
  const status =
    service.status ??
    (service.running ? 'healthy' : service.classification === 'optional' ? 'not-configured' : 'failed')
  switch (status) {
    case 'healthy':
      return { kind: 'ok', label: 'healthy', icon: 'check_circle' }
    case 'not-configured':
      return { kind: 'info', label: 'not configured', icon: 'extension' }
    case 'disabled':
      return { kind: 'info', label: 'disabled', icon: 'block' }
    default:
      return { kind: 'err', label: 'failed', icon: 'cancel' }
  }
}

/**
 * Reactive state shape for the Operations Overview store.
 */
export interface OperationsOverviewState {
  pipeline: PipelineResponse | null
  attention: AttentionFinding[]
  health: HealthResponse | null
  readiness: DetectionReadinessResponse | null
  storage: OperationsStorageResponse | null
  isLoadingPipeline: boolean
  isLoadingAttention: boolean
  isLoadingHealth: boolean
  pipelineError: string | null
  attentionError: string | null
  healthError: string | null
  readinessError: string | null
  storageError: string | null
}

/**
 * Extract a concise error message from a fetch failure.
 *
 * @param error - The value thrown by `useApi`.
 * @returns A user-facing message string.
 */
function extractErrorMessage(error: unknown): string {
  return operationErrorMessage(error, 'An unknown error occurred')
}

export const useOperationsOverviewStore = defineStore('operationsOverview', {
  state: (): OperationsOverviewState => ({
    pipeline: null,
    attention: [],
    health: null,
    readiness: null,
    storage: null,
    isLoadingPipeline: false,
    isLoadingAttention: false,
    isLoadingHealth: false,
    pipelineError: null,
    attentionError: null,
    healthError: null,
    readinessError: null,
    storageError: null,
  }),

  getters: {
    /**
     * Map each pipeline source to its friendly label.
     *
     * @returns A record of source id → display label.
     */
    sourceLabels(): Record<string, string> {
      return SOURCE_LABELS
    },

    /**
     * Aggregate suite KPI state derived from health checks.
     *
     * @returns Object with display value, signal color and subtext.
     */
    suiteKpi(state): { value: string; signal: 'green' | 'amber' | 'red' | 'grey'; sub: string } {
      const overall = state.health?.overall_status ?? 'unknown'
      switch (overall) {
        case 'healthy':
          return { value: 'Healthy', signal: 'green', sub: 'All core services operational' }
        case 'degraded':
          return { value: 'Degraded', signal: 'amber', sub: 'One or more services need attention' }
        case 'unhealthy':
          return { value: 'Unhealthy', signal: 'red', sub: 'Core services are down' }
        default:
          return { value: 'Unknown', signal: 'grey', sub: 'Health data unavailable' }
      }
    },

    /**
     * Pipeline KPI state derived from source freshness.
     *
     * @returns Object with display value, signal color and subtext.
     */
    pipelineKpi(state): { value: string; signal: 'green' | 'amber' | 'red' | 'grey'; sub: string } {
      const sources = state.pipeline?.sources ?? []
      if (sources.length === 0) {
        return { value: 'No data', signal: 'grey', sub: 'Pipeline freshness unavailable' }
      }
      const stale = sources.filter((s) => s.state === 'stale').length
      const noData = sources.filter((s) => s.state === 'no-data').length
      if (noData > 0) {
        return { value: 'No data', signal: 'red', sub: `${noData} source(s) have no recent records` }
      }
      if (stale > 0) {
        return { value: 'Needs attention', signal: 'amber', sub: `${stale} source(s) are stale` }
      }
      return { value: 'Current', signal: 'green', sub: 'All sources receiving data' }
    },

    detectionKpi(state): { value: string; signal: 'green' | 'amber' | 'grey'; sub: string } {
      const modules = state.readiness?.modules ?? []
      if (modules.length === 0) {
        return { value: 'Unknown', signal: 'grey', sub: 'Detection readiness unavailable' }
      }
      const ready = modules.filter((module) => module.state === 'ready').length
      if (ready === modules.length) {
        return { value: 'Ready', signal: 'green', sub: `${ready}/${modules.length} modules ready` }
      }
      return {
        value: 'Partially ready',
        signal: 'amber',
        sub: `${ready}/${modules.length} modules ready`,
      }
    },

    storageKpi(state): { value: string; signal: 'green' | 'amber' | 'red' | 'grey'; sub: string } {
      const usedPct = state.storage?.host.used_pct
      if (usedPct === undefined || state.storageError !== null) {
        return { value: 'Unknown', signal: 'grey', sub: 'Storage usage unavailable' }
      }
      const signal = usedPct >= 90 ? 'red' : usedPct >= 75 ? 'amber' : 'green'
      const label = signal === 'red' ? 'Critical' : signal === 'amber' ? 'Attention' : 'Normal'
      return { value: `${usedPct}% used`, signal, sub: label }
    },

    /**
     * List of services that are not running, for the Service Health summary.
     *
     * Includes both truly-failed core services and not-configured optional
     * services; the badge rendered for each is truthful (see
     * {@link serviceBadge}) so an optional not-configured service is never
     * labelled "failed".
     *
     * @returns Array of problem services.
     */
    problemServices(state): HealthCheckItem[] {
      return (state.health?.services ?? []).filter((s) => !s.running)
    },

    /**
     * Map a health item to its truthful state badge.
     *
     * @returns A function returning the badge for a given service.
     */
    badgeFor(): (service: HealthCheckItem) => ServiceBadge {
      return (service: HealthCheckItem) => serviceBadge(service)
    },

    /**
     * Count of healthy (reachable) services.
     *
     * @returns Number of running services.
     */
    healthyCount(state): number {
      return (state.health?.services ?? []).filter((s) => s.running).length
    },

    /**
     * Count of services classified as optional and not running.
     *
     * @returns Number of optional inactive services.
     */
    optionalOffCount(state): number {
      return (state.health?.services ?? []).filter(
        (s) => s.classification === 'optional' && !s.running,
      ).length
    },

    /**
     * Timestamp when the current health snapshot was polled.
     *
     * @returns A localized time string or null.
     */
    healthPolledAt(state): string | null {
      const first = state.health?.services?.[0]?.timestamp
      if (!first) return null
      return new Date(first * 1000).toLocaleTimeString()
    },
  },

  actions: {
    /**
     * Obtain a typed API client that injects the runtime API key.
     *
     * @returns The configured `useApi` client.
     */
    _api(): UseApiReturn {
      return useApi()
    },

    /**
     * Fetch pipeline freshness from `/api/v1/operations/pipeline`.
     */
    async fetchPipeline(): Promise<void> {
      this.isLoadingPipeline = true
      this.pipelineError = null
      try {
        this.pipeline = await this._api().get<PipelineResponse>('/api/v1/operations/pipeline')
      } catch (error: unknown) {
        this.pipelineError = `Failed to load pipeline freshness: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingPipeline = false
      }
    },

    /**
     * Fetch attention findings from `/api/v1/operations/attention`.
     */
    async fetchAttention(): Promise<void> {
      this.isLoadingAttention = true
      this.attentionError = null
      try {
        const response = await this._api().get<{ findings: AttentionFinding[] }>(
          '/api/v1/operations/attention',
        )
        this.attention = response.findings
      } catch (error: unknown) {
        this.attentionError = `Failed to load attention findings: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingAttention = false
      }
    },

    /**
     * Fetch service health from `/api/v1/status/health`.
     */
    async fetchHealth(): Promise<void> {
      this.isLoadingHealth = true
      this.healthError = null
      try {
        this.health = await this._api().get<HealthResponse>('/api/v1/status/health')
      } catch (error: unknown) {
        this.healthError = `Failed to load service health: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingHealth = false
      }
    },

    async fetchReadiness(): Promise<void> {
      this.readinessError = null
      try {
        this.readiness = await this._api().get<DetectionReadinessResponse>(
          '/api/v1/operations/detection/readiness',
        )
      } catch (error: unknown) {
        this.readiness = null
        this.readinessError = `Failed to load detection readiness: ${extractErrorMessage(error)}`
      }
    },

    async fetchStorage(): Promise<void> {
      this.storageError = null
      try {
        this.storage = await this._api().get<OperationsStorageResponse>('/api/v1/operations/storage')
      } catch (error: unknown) {
        this.storage = null
        this.storageError = `Failed to load storage usage: ${extractErrorMessage(error)}`
      }
    },

    /**
     * Load all Overview data in parallel.
     */
    async loadAll(): Promise<void> {
      await Promise.all([
        this.fetchPipeline(),
        this.fetchAttention(),
        this.fetchHealth(),
        this.fetchReadiness(),
        this.fetchStorage(),
      ])
    },

    /**
     * Replace health state from an SSE push.
     *
     * @param data - Health payload from the SSE event.
     */
    handleHealthUpdate(data: HealthResponse): void {
      this.health = data
    },
  },
})

export type { PipelineSource }
