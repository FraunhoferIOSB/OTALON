/**
 * Pinia store for the Operations / Data Sources page.
 *
 * Combines the WAVE A pipeline freshness endpoint with the WAVE C capture
 * status read surface and the passive-seeder operational status. Passive
 * discovery is status-only here; its runtime controls live on Operations →
 * Configuration → Runtime. PCAP replay and import history remain stable
 * markers until their owning backend tickets ship.
 */
import { defineStore } from 'pinia'

import { useApi } from '~/composables/useApi'
import {
  PCAP_IMPORT_TERMINAL_STATES,
  toRejection,
  usePcapImport,
  type PcapImportAccepted,
  type PcapImportRejection,
  type PcapImportStatus,
} from '~/composables/usePcapImport'
import type {
  CaptureStatus,
  PassiveDiscoveryStatus,
  PassiveSeederState,
  PassiveSeederStatus,
  PipelineResponse,
  PipelineSource,
} from '~/types/api'
import { operationErrorMessage } from '~/utils/permissions'

/**
 * Friendly primary labels for pipeline source ids.
 */
export const DATA_SOURCE_LABELS: Record<string, string> = {
  conn: 'Connections',
  mac: 'Assets',
  proto: 'Protocols',
}

/**
 * Canonical IDs supported by the source-freshness backend.
 */
export type SourceId = 'conn' | 'mac' | 'proto'

/**
 * Reactive state shape for the Data Sources store.
 */
export interface DataSourcesState {
  pipeline: PipelineResponse | null
  captureStatus: CaptureStatus | null
  passiveDiscovery: PassiveDiscoveryStatus | null
  seederStatus: PassiveSeederStatus | null
  isLoadingPipeline: boolean
  isLoadingCapture: boolean
  isLoadingPassive: boolean
  isLoadingSeeder: boolean
  pipelineError: string | null
  captureError: string | null
  passiveError: string | null
  seederError: string | null
  /** Capture currently being uploaded, or the one a conflict is pending on. */
  importFile: File | null
  isUploading: boolean
  /** Acceptance envelope of the most recent successful upload. */
  importAccepted: PcapImportAccepted | null
  /** Live status of the job being followed, refreshed by polling. */
  importStatus: PcapImportStatus | null
  /** Normalised rejection of the last upload attempt, or null. */
  importRejection: PcapImportRejection | null
  recentImports: PcapImportStatus[]
  isLoadingRecent: boolean
  recentError: string | null
  /** True once at least one listing fetch has settled, success or failure. */
  recentLoaded: boolean
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

/**
 * Build the stale-source banner text.
 *
 * The capture-status surface reports carrier state (`link_up`) only — it
 * carries no packet or drop counters — so the banner never asserts a causal
 * "broken ingest vs silent network" diagnosis. It truthfully states that the
 * affected sources are stale without inventing a cause. A causal claim would
 * only be justified by an explicit traffic-present signal, which this wave's
 * backend does not provide.
 *
 * @param sources - Pipeline sources.
 * @returns Banner text or null when there are no stale sources.
 */
export function staleBannerText(sources: PipelineSource[]): string | null {
  const stale = sources.filter((s) => s.state === 'stale')
  if (stale.length === 0) {
    return null
  }
  const labels = stale.map((s) => DATA_SOURCE_LABELS[s.name] ?? s.name)
  return `${labels.join(', ')} stale — source freshness is below the expected interval.`
}

/**
 * Best-known capture window of an import entry.
 *
 * The completion result is preferred over the pre-scan `params` window
 * because it reflects what was actually written; both are ISO strings.
 *
 * @param status - An import status envelope.
 * @returns The window, or `null` when neither source carries one.
 */
export function importRange(status: PcapImportStatus): { start: string; end: string } | null {
  const start = status.result?.time_start ?? status.time_start
  const end = status.result?.time_end ?? status.time_end
  if (!start || !end) return null
  return { start, end }
}

/**
 * Data Sources store.
 */
export const useDataSourcesStore = defineStore('dataSources', {
  state: (): DataSourcesState => ({
    pipeline: null,
    captureStatus: null,
    passiveDiscovery: null,
    seederStatus: null,
    isLoadingPipeline: false,
    isLoadingCapture: false,
    isLoadingPassive: false,
    isLoadingSeeder: false,
    pipelineError: null,
    captureError: null,
    passiveError: null,
    seederError: null,
    importFile: null,
    isUploading: false,
    importAccepted: null,
    importStatus: null,
    importRejection: null,
    recentImports: [],
    isLoadingRecent: false,
    recentError: null,
    recentLoaded: false,
  }),

  getters: {
    /**
     * Source rows in display order.
     */
    sourceRows(): PipelineSource[] {
      return this.pipeline?.sources ?? []
    },

    /**
     * Friendly label for a source id.
     *
     * @returns A function mapping source id -> label.
     */
    friendlyLabel(): (id: SourceId) => string {
      return (id: SourceId) => DATA_SOURCE_LABELS[id] ?? id
    },

    /**
     * Stale-source banner text, or null.
     */
    staleBanner(): string | null {
      if (!this.pipeline) {
        return null
      }
      return staleBannerText(this.pipeline.sources)
    },

    /**
     * True when at least one freshness fetch is in flight.
     */
    isLoading(): boolean {
      return this.isLoadingPipeline || this.isLoadingCapture || this.isLoadingPassive || this.isLoadingSeeder
    },

    /**
     * Passive-seeder operational state, defaulting to `unknown`.
     *
     * `unknown` is the honest answer both before the first fetch and when
     * the backend reports no persisted status row. It is deliberately not
     * collapsed into `disabled`, which is a distinct, seeder-reported state.
     */
    seederState(): PassiveSeederState {
      return this.seederStatus?.state ?? 'unknown'
    },

    /**
     * Badge descriptor for the seeder's operational state.
     *
     * @returns A label + kind for the seeder status badge.
     */
    seederBadge(): { label: string; kind: 'ok' | 'warn' | 'err' | 'muted' } {
      switch (this.seederState) {
        case 'running':
          return { label: 'running', kind: 'ok' }
        case 'disabled':
          return { label: 'disabled', kind: 'warn' }
        case 'error':
          return { label: 'error', kind: 'err' }
        default:
          return { label: 'unknown', kind: 'muted' }
      }
    },

    /**
     * Passive Discovery state badge descriptor.
     *
     * Reflects persisted producer truth: an active producer with a
     * current observation renders `active`, an aged observation renders
     * `stale`, and an empty inventory renders `no data`. This describes the
     * observed inventory, not the seeder process — see {@link seederBadge}
     * for the seeder's own operational state.
     *
     * @returns A label + kind for the status badge.
     */
    passiveBadge(): { label: string; kind: 'ok' | 'warn' | 'muted' } {
      const status = this.passiveDiscovery
      if (!status || status.freshness === 'no-data') {
        return { label: 'no data', kind: 'muted' }
      }
      if (status.freshness === 'stale') {
        return { label: 'stale', kind: 'warn' }
      }
      return { label: 'active', kind: 'ok' }
    },

    /**
     * True while an import job is being followed and has not settled.
     */
    isImportRunning(): boolean {
      const state = this.importStatus?.state ?? this.importAccepted?.state
      if (!state) return false
      return !PCAP_IMPORT_TERMINAL_STATES.includes(state)
    },

    /**
     * The pending overlap conflict, when the last upload hit one.
     *
     * Surfaced separately because it is the only rejection that offers a
     * follow-up action ("import anyway") rather than just a message.
     */
    importConflict(): PcapImportRejection | null {
      return this.importRejection?.kind === 'conflict' ? this.importRejection : null
    },

    /**
     * Import window of the followed job once it has completed, for the
     * "Set time range" action. `null` while no completed window is known.
     */
    completedImportRange(): { start: string; end: string } | null {
      const status = this.importStatus
      if (!status || status.state !== 'completed') return null
      return importRange(status)
    },
  },

  actions: {
    /**
     * Obtain a typed API client that injects the runtime API key.
     */
    _api() {
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
     * Fetch capture status from `/api/v1/operations/capture-status`.
     */
    async fetchCaptureStatus(): Promise<void> {
      this.isLoadingCapture = true
      this.captureError = null
      try {
        this.captureStatus = await this._api().get<CaptureStatus>('/api/v1/operations/capture-status')
      } catch (error: unknown) {
        this.captureError = `Failed to load capture status: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingCapture = false
      }
    },

    /**
     * Fetch passive-discovery producer status from
     * `/api/v1/operations/passive-discovery`.
     */
    async fetchPassiveDiscovery(): Promise<void> {
      this.isLoadingPassive = true
      this.passiveError = null
      try {
        this.passiveDiscovery = await this._api().get<PassiveDiscoveryStatus>('/api/v1/operations/passive-discovery')
      } catch (error: unknown) {
        this.passiveError = `Failed to load passive discovery status: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingPassive = false
      }
    },

    /**
     * Fetch passive-seeder operational status from
     * `/api/v1/operations/passive-seeder/status`.
     *
     * This is the seeder's own report (state, last cycle, rows written by
     * that cycle, effective poll interval), distinct from the derived
     * inventory truth in {@link fetchPassiveDiscovery}.
     */
    async fetchSeederStatus(): Promise<void> {
      this.isLoadingSeeder = true
      this.seederError = null
      try {
        this.seederStatus = await this._api().get<PassiveSeederStatus>('/api/v1/operations/passive-seeder/status')
      } catch (error: unknown) {
        this.seederError = `Failed to load passive seeder status: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingSeeder = false
      }
    },

    /**
     * Load all owned data for the Data Sources page.
     */
    async loadAll(): Promise<void> {
      await Promise.all([
        this.fetchPipeline(),
        this.fetchCaptureStatus(),
        this.fetchPassiveDiscovery(),
        this.fetchSeederStatus(),
        this.fetchRecentImports(),
      ])
    },

    /**
     * Fetch the newest import jobs for "Recent Imports".
     */
    async fetchRecentImports(): Promise<void> {
      this.isLoadingRecent = true
      this.recentError = null
      try {
        this.recentImports = await usePcapImport().fetchRecent()
      } catch (error: unknown) {
        this.recentError = `Failed to load recent imports: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingRecent = false
        this.recentLoaded = true
      }
    },

    /**
     * Upload a capture and start following the resulting job.
     *
     * A rejection is stored in {@link DataSourcesState.importRejection}
     * with the server's own wording preserved, and the file is retained so
     * an overlap conflict can be retried with `force` without asking the
     * operator to pick it again.
     *
     * @param file - The capture to import.
     * @param force - Bypass the server-side overlap check.
     * @returns `true` when the upload was accepted.
     */
    async uploadCapture(file: File, force = false): Promise<boolean> {
      this.isUploading = true
      this.importFile = file
      this.importRejection = null
      this.importStatus = null
      this.importAccepted = null
      try {
        this.importAccepted = await usePcapImport().uploadCapture(file, { force })
        await this.refreshImportStatus()
        await this.fetchRecentImports()
        return true
      } catch (error: unknown) {
        this.importRejection = toRejection(error)
        return false
      } finally {
        this.isUploading = false
      }
    },

    /**
     * Re-post the retained capture past an overlap conflict.
     *
     * @returns `true` when the forced upload was accepted.
     */
    async forceRetryUpload(): Promise<boolean> {
      const file = this.importFile
      if (!file) return false
      return await this.uploadCapture(file, true)
    },

    /**
     * Poll the followed import job once.
     *
     * Polling rather than SSE: the job event stream emits only on a state
     * change, so it never carries the phase/latest-event progress this
     * surface shows.
     */
    async refreshImportStatus(): Promise<void> {
      const displayId = this.importAccepted?.display_id
      if (!displayId) return
      try {
        this.importStatus = await usePcapImport().fetchStatus(displayId)
      } catch {
        // A transient status read failure must not clobber the last known
        // state or fabricate a failure the backend never reported.
      }
    },

    /**
     * Cancel the followed import job.
     */
    async cancelImport(): Promise<void> {
      const displayId = this.importAccepted?.display_id
      if (!displayId) return
      try {
        this.importStatus = await usePcapImport().cancelImport(displayId)
      } catch (error: unknown) {
        this.recentError = `Failed to cancel import: ${extractErrorMessage(error)}`
      }
      await this.fetchRecentImports()
    },

    /**
     * Drop the current upload, its outcome and any pending conflict.
     */
    resetImport(): void {
      this.importFile = null
      this.importAccepted = null
      this.importStatus = null
      this.importRejection = null
    },
  },
})
