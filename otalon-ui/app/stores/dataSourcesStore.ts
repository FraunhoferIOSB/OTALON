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
import { markRaw } from 'vue'

import { useApi } from '~/composables/useApi'
import {
  PCAP_IMPORT_TERMINAL_STATES,
  toRejection,
  usePcapImport,
  type PcapImportAccepted,
  type PcapImportActiveState,
  type PcapImportRejection,
  type PcapImportStatus,
  type PcapImportState,
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

/** Browser-local transfer state, separate from the persisted JobState. */
export type ImportUploadState = 'pending' | 'uploading' | 'accepted' | 'conflict' | 'failed' | 'cancelled' | 'uncertain'

/** One selection or exact-ID recovered owner; File bytes live only in this application. */
export interface ImportQueueItem {
  localId: number
  sequence: number
  file: File | null
  name: string
  sizeBytes: number | null
  lastModified: number | null
  uploadState: ImportUploadState
  uploadLoaded: number | null
  uploadTotal: number | null
  accepted: PcapImportAccepted | null
  /** Only a transport-observed identity, never inferred from history metadata. */
  observedDisplayId: string | null
  status: PcapImportStatus | null
  rejection: PcapImportRejection | null
  cancelError: string | null
  pollError: string | null
  cancellationRequested: boolean
  forceConfirmed: boolean
  forceSequence: number | null
}

const IMPORT_ACTIVE_STATES: readonly PcapImportActiveState[] = ['queued', 'running', 'cancelling']
const IMPORT_RECONCILIATION_MARKER = 'Cancellation needs reconciliation; worker settlement is unverified.'

function importIsTerminal(state: PcapImportState): boolean {
  return PCAP_IMPORT_TERMINAL_STATES.includes(state)
}

function importIdentity(row: ImportQueueItem): string | undefined {
  return row.accepted?.display_id ?? row.observedDisplayId ?? row.status?.display_id
}

function importBlocked(row: ImportQueueItem): boolean {
  return (
    row.status?.state === 'cancelling' &&
    (row.status.error === IMPORT_RECONCILIATION_MARKER || row.status.latest_event === IMPORT_RECONCILIATION_MARKER)
  )
}

function importOwnsBarrier(row: ImportQueueItem): boolean {
  if (row.uploadState === 'uploading' || row.uploadState === 'uncertain') return true
  const state = row.status?.state ?? row.accepted?.state
  return !!state && (!importIsTerminal(state) || !row.status)
}

function validImportStatus(value: unknown): value is PcapImportStatus {
  if (!value || typeof value !== 'object') return false
  const job = value as PcapImportStatus
  return (
    typeof job.display_id === 'string' &&
    job.display_id.length > 0 &&
    Number.isInteger(job.job_id) &&
    [...IMPORT_ACTIVE_STATES, ...PCAP_IMPORT_TERMINAL_STATES].includes(job.state)
  )
}

interface ImportQueueRuntime {
  active: boolean
  generation: number
  reconciled: boolean
  pump: Promise<void> | null
  refresh: Promise<void> | null
  timer: ReturnType<typeof setTimeout> | null
  uploads: Map<number, AbortController>
  polls: Map<string, Promise<void>>
  cancels: Map<string, Promise<void>>
  due: Map<string, number>
  failures: Map<string, number>
  waiters: Map<number, (accepted: boolean) => void>
}

// Runtime handles are neither persisted Pinia data nor a second ownership lane.
const importRuntimes = new WeakMap<object, ImportQueueRuntime>()

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
  importQueue: ImportQueueItem[]
  importSequence: number
  importForceSequence: number
  importSelectedId: number | null
  importQueueError: string | null
  importAuthStopped: boolean
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
    importQueue: [],
    importSequence: 0,
    importForceSequence: 0,
    importSelectedId: null,
    importQueueError: null,
    importAuthStopped: false,
    recentImports: [],
    isLoadingRecent: false,
    recentError: null,
    recentLoaded: false,
  }),

  getters: {
    /** Compatibility focus is an identity projection, never independent state. */
    selectedImport(): ImportQueueItem | null {
      return this.importQueue.find((row) => row.localId === this.importSelectedId) ?? null
    },
    importFile(): File | null {
      return this.selectedImport?.file ?? null
    },
    importAccepted(): PcapImportAccepted | null {
      return this.selectedImport?.accepted ?? null
    },
    importStatus(): PcapImportStatus | null {
      return this.selectedImport?.status ?? null
    },
    importRejection(): PcapImportRejection | null {
      return this.selectedImport?.rejection ?? null
    },
    isUploading(): boolean {
      return this.importQueue.some((row) => row.uploadState === 'pending' || row.uploadState === 'uploading')
    },
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
      return this.importQueue.some(importOwnsBarrier)
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
      const runtime = this._importRuntime()
      if (this.importAuthStopped) return
      const generation = runtime.generation
      this.isLoadingRecent = true
      this.recentError = null
      try {
        const items = await usePcapImport().fetchRecent()
        if (generation !== runtime.generation) return
        this.recentImports = items
      } catch (error: unknown) {
        if (generation !== runtime.generation) return
        this._stopImportOnAuth(error)
        this.recentError = `Failed to load recent imports: ${extractErrorMessage(error)}`
      } finally {
        if (generation === runtime.generation) {
          this.isLoadingRecent = false
          this.recentLoaded = true
        }
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
      const [id] = this.enqueueImports([file])
      if (id === undefined) return false
      const row = this.importQueue.find((item) => item.localId === id)!
      if (force) {
        row.forceConfirmed = true
        row.forceSequence = ++this.importForceSequence
      }
      return await this._waitImportUpload(row)
    },

    /**
     * Re-post the retained capture past an overlap conflict.
     *
     * @returns `true` when the forced upload was accepted.
     */
    async forceRetryUpload(): Promise<boolean> {
      const row = this.selectedImport
      if (!row?.file || row.uploadState !== 'conflict') return false
      this.confirmImportForce(row.localId)
      return await this._waitImportUpload(row)
    },

    /**
     * Poll the followed import job once.
     *
     * Polling rather than SSE: the job event stream emits only on a state
     * change, so it never carries the phase/latest-event progress this
     * surface shows.
     */
    async refreshImportStatus(): Promise<void> {
      const row = this.selectedImport
      if (!row || !importIdentity(row) || importBlocked(row) || this.importAuthStopped) return
      const runtime = this._importRuntime()
      const id = importIdentity(row)!
      if ((runtime.failures.get(id) ?? 0) > 0 && (runtime.due.get(id) ?? 0) > Date.now()) return
      await this._pollQueueImport(importIdentity(row)!)
      void this._scheduleImports()
    },

    /**
     * Cancel the followed import job.
     */
    async cancelImport(): Promise<void> {
      if (this.importSelectedId !== null) await this.cancelQueueImport(this.importSelectedId)
    },

    /**
     * Drop the current upload, its outcome and any pending conflict.
     */
    resetImport(): void {
      const row = this.selectedImport
      if (!row || importOwnsBarrier(row)) return
      if (row.uploadState === 'pending' || row.uploadState === 'conflict' || row.uploadState === 'failed') {
        row.uploadState = 'cancelled'
        row.file = null
      }
      this.importSelectedId = null
      void this._scheduleImports()
    },

    /** Acquire this store's sole scheduler and dispose/reset guards. */
    _importRuntime(): ImportQueueRuntime {
      let runtime = importRuntimes.get(this)
      if (!runtime) {
        runtime = {
          active: false,
          generation: 0,
          reconciled: false,
          pump: null,
          refresh: null,
          timer: null,
          uploads: new Map(),
          polls: new Map(),
          cancels: new Map(),
          due: new Map(),
          failures: new Map(),
          waiters: new Map(),
        }
        importRuntimes.set(this, runtime)
        const dispose = this.$dispose.bind(this)
        this.$dispose = () => {
          this.stopImportQueue()
          dispose()
        }
        const reset = this.$reset.bind(this)
        this.$reset = () => {
          this.stopImportQueue()
          const retained = {
            importQueue: this.importQueue,
            importSequence: this.importSequence,
            importForceSequence: this.importForceSequence,
            importSelectedId: this.importSelectedId,
            importQueueError: this.importQueueError,
            importAuthStopped: this.importAuthStopped,
          }
          reset()
          this.$patch(retained)
        }
      }
      return runtime
    },

    /** Append every File in selection order and start the application-owned queue. */
    enqueueImports(files: Iterable<File>): number[] {
      const ids: number[] = []
      for (const file of Array.from(files)) {
        const row = this._appendImportRow(file)
        ids.push(row.localId)
        this.importSelectedId = row.localId
      }
      void this.startImportQueue()
      return ids
    },

    _appendImportRow(file: File | null, status: PcapImportStatus | null = null): ImportQueueItem {
      const sequence = ++this.importSequence
      const row: ImportQueueItem = {
        localId: sequence,
        sequence,
        file: file ? markRaw(file) : null,
        name: file?.name ?? status?.original_filename ?? status?.display_id ?? 'Unknown capture',
        sizeBytes: file?.size ?? status?.size_bytes ?? null,
        lastModified: file?.lastModified ?? null,
        uploadState: file ? 'pending' : 'accepted',
        uploadLoaded: null,
        uploadTotal: null,
        accepted: null,
        observedDisplayId: null,
        status,
        rejection: null,
        cancelError: null,
        pollError: null,
        cancellationRequested: false,
        forceConfirmed: false,
        forceSequence: null,
      }
      this.importQueue.push(row)
      return this.importQueue[this.importQueue.length - 1]!
    },

    /** Start/reconcile without resetting File rows; navigation need not stop this lifecycle. */
    async startImportQueue(): Promise<void> {
      const runtime = this._importRuntime()
      if (this.importAuthStopped) return
      runtime.active = true
      await this._scheduleImports()
    },

    /** Stop only owned handles, retain all rows, and invalidate asynchronous continuations. */
    stopImportQueue(): void {
      const runtime = this._importRuntime()
      runtime.active = false
      runtime.generation++
      runtime.reconciled = false
      if (runtime.timer !== null) clearTimeout(runtime.timer)
      runtime.timer = null
      for (const [id, controller] of runtime.uploads) {
        const row = this.importQueue.find((item) => item.localId === id)
        if (row?.uploadState === 'uploading') {
          row.uploadState = 'uncertain'
          row.pollError = 'Upload stopped; server acceptance is unverified.'
        }
        controller.abort()
      }
      for (const resolve of runtime.waiters.values()) resolve(false)
      runtime.waiters.clear()
    },

    /** Explicit recovery after the established session/permission flow, never upload resubmission. */
    async resumeImportQueue(): Promise<void> {
      this.importAuthStopped = false
      await this.refreshImportQueue()
    },

    /** Explicit filtered reconciliation; history alone is never absence proof. */
    async refreshImportQueue(): Promise<void> {
      const runtime = this._importRuntime()
      if (this.importAuthStopped) return
      const generation = runtime.generation
      runtime.active = true
      runtime.reconciled = false
      await this._reconcileImportQueue()
      if (generation !== runtime.generation || this.importAuthStopped || !runtime.reconciled) return
      const blockedIds = [
        ...new Set(
          this.importQueue
            .filter(importBlocked)
            .map(importIdentity)
            .filter((id): id is string => !!id),
        ),
      ]
      for (const id of blockedIds) {
        await this._pollQueueImport(id, true)
        if (generation !== runtime.generation || this.importAuthStopped) return
      }
      await this._scheduleImports()
    },

    /** Confirm only this conflict, preserving confirmation order ahead of unstarted rows. */
    confirmImportForce(localId: number): void {
      const row = this.importQueue.find((item) => item.localId === localId)
      if (!row?.file || row.uploadState !== 'conflict') return
      row.forceConfirmed = true
      row.forceSequence = ++this.importForceSequence
      row.uploadState = 'pending'
      void this.startImportQueue()
    },

    _waitImportUpload(row: ImportQueueItem): Promise<boolean> {
      if (row.uploadState === 'accepted') return Promise.resolve(true)
      if (!['pending', 'uploading'].includes(row.uploadState)) return Promise.resolve(false)
      return new Promise((resolve) => {
        this._importRuntime().waiters.set(row.localId, resolve)
      })
    },

    _stopImportOnAuth(error: unknown): boolean {
      if (toRejection(error).kind !== 'unauthorized') return false
      this.importAuthStopped = true
      this.importQueueError = 'Import queue paused: authentication or permissions must be restored explicitly.'
      const runtime = this._importRuntime()
      if (runtime.timer !== null) clearTimeout(runtime.timer)
      runtime.timer = null
      return true
    },

    async _reconcileImportQueue(): Promise<void> {
      const runtime = this._importRuntime()
      if (runtime.refresh) return await runtime.refresh
      const generation = runtime.generation
      const work = async () => {
        this.importQueueError = null
        try {
          for (const state of IMPORT_ACTIVE_STATES) {
            const result = await usePcapImport().fetchByState(state, 200)
            if (generation !== runtime.generation || this.importAuthStopped) return
            if (
              !result ||
              !Array.isArray(result.items) ||
              !Number.isInteger(result.total) ||
              result.total !== result.items.length ||
              result.items.some((job) => !validImportStatus(job) || job.state !== state)
            ) {
              throw new Error(`Malformed or missing ${state} import listing; dispatch is blocked.`)
            }
            for (const job of result.items) {
              if (!this.importQueue.some((row) => importIdentity(row) === job.display_id))
                this._appendImportRow(null, job)
              this._applyImportStatus(job)
            }
            if (result.total >= 200 || result.items.length >= 200) {
              throw new Error(`The ${state} import listing reached 200 entries; older active work is unverified.`)
            }
          }
          runtime.reconciled = true
        } catch (error: unknown) {
          if (generation !== runtime.generation) return
          this._stopImportOnAuth(error)
          this.importQueueError = `Import reconciliation blocked: ${extractErrorMessage(error)}`
        }
      }
      runtime.refresh = work()
      try {
        await runtime.refresh
      } finally {
        runtime.refresh = null
      }
    },

    _applyImportStatus(job: PcapImportStatus): void {
      const runtime = this._importRuntime()
      for (const row of this.importQueue.filter((item) => importIdentity(item) === job.display_id)) {
        if (row.status && importIsTerminal(row.status.state)) continue
        if (row.status?.state === 'cancelling' && ['queued', 'running'].includes(job.state)) continue
        row.status = job
        row.uploadState = 'accepted'
        row.pollError = null
      }
      runtime.failures.delete(job.display_id)
      runtime.due.set(job.display_id, Date.now() + 2000)
      if (importIsTerminal(job.state)) runtime.reconciled = false
    },

    /** Coalesce all readers of an identity, including the temporary page polling wrapper. */
    async _pollQueueImport(displayId: string, recoverBlocked = false): Promise<void> {
      const runtime = this._importRuntime()
      if (runtime.polls.has(displayId)) return await runtime.polls.get(displayId)
      if (runtime.cancels.has(displayId)) return await runtime.cancels.get(displayId)
      if (
        this.importAuthStopped ||
        (!recoverBlocked && this.importQueue.some((row) => importIdentity(row) === displayId && importBlocked(row)))
      )
        return
      const generation = runtime.generation
      const work = async () => {
        try {
          const job = await usePcapImport().fetchStatus(displayId)
          if (generation !== runtime.generation) return
          if (!validImportStatus(job) || job.display_id !== displayId)
            throw new Error('Import detail identity/state is unverified.')
          // Explicit blocked recovery needs terminal truth, not permission to resume automatic polling.
          if (recoverBlocked && !importIsTerminal(job.state)) return
          this._applyImportStatus(job)
          if (importIsTerminal(job.state)) await this.fetchRecentImports()
        } catch (error: unknown) {
          if (generation !== runtime.generation) return
          this._stopImportOnAuth(error)
          for (const row of this.importQueue.filter((item) => importIdentity(item) === displayId)) {
            row.pollError = `Failed to poll import: ${extractErrorMessage(error)}`
          }
          const failures = (runtime.failures.get(displayId) ?? 0) + 1
          runtime.failures.set(displayId, failures)
          runtime.due.set(displayId, Date.now() + Math.min(30000, 2000 * 2 ** Math.min(failures - 1, 4)))
        }
      }
      const promise = work()
      runtime.polls.set(displayId, promise)
      try {
        await promise
      } finally {
        runtime.polls.delete(displayId)
      }
    },

    /** The only upload scheduler; acceptance is never its release oracle. */
    async _scheduleImports(): Promise<void> {
      const runtime = this._importRuntime()
      if (runtime.pump) return await runtime.pump
      if (!runtime.active || this.importAuthStopped) return
      if (runtime.timer !== null) clearTimeout(runtime.timer)
      runtime.timer = null
      const generation = runtime.generation
      const work = async () => {
        while (runtime.active && generation === runtime.generation && !this.importAuthStopped) {
          if (!runtime.reconciled) {
            await this._reconcileImportQueue()
            if (!runtime.reconciled || generation !== runtime.generation || this.importAuthStopped) return
          }
          const barriers = this.importQueue.filter(importOwnsBarrier)
          if (barriers.length) {
            const ids = [
              ...new Set(
                barriers
                  .filter((row) => !importBlocked(row))
                  .map(importIdentity)
                  .filter((id): id is string => !!id),
              ),
            ]
            for (const id of ids) {
              if ((runtime.due.get(id) ?? 0) <= Date.now()) await this._pollQueueImport(id)
              if (generation !== runtime.generation || this.importAuthStopped) return
            }
            if (!this.importQueue.some(importOwnsBarrier)) continue
            const due = ids
              .filter((id) =>
                this.importQueue.some(
                  (row) => importIdentity(row) === id && importOwnsBarrier(row) && !importBlocked(row),
                ),
              )
              .map((id) => runtime.due.get(id) ?? Date.now() + 2000)
            if (due.length) {
              runtime.timer = setTimeout(
                () => {
                  runtime.timer = null
                  void this._scheduleImports()
                },
                Math.max(0, Math.min(...due) - Date.now()),
              )
            }
            return
          }
          const row = this.importQueue
            .filter((item) => item.uploadState === 'pending' && item.file)
            .sort((a, b) => (a.forceSequence ?? Infinity) - (b.forceSequence ?? Infinity) || a.sequence - b.sequence)[0]
          if (!row?.file) return
          row.uploadState = 'uploading'
          row.rejection = null
          const controller = new AbortController()
          runtime.uploads.set(row.localId, controller)
          let success = false
          try {
            const envelope = await usePcapImport().uploadCapture(row.file, {
              force: row.forceConfirmed,
              signal: controller.signal,
              onUploadProgress: (progress) => {
                if (generation !== runtime.generation || row.uploadState !== 'uploading') return
                row.uploadLoaded = progress.loaded
                row.uploadTotal = progress.total
              },
            })
            if (generation !== runtime.generation) return
            if (envelope && typeof envelope.display_id === 'string' && envelope.display_id.length > 0) {
              row.observedDisplayId = envelope.display_id
            }
            if (!validImportStatus(envelope)) throw new Error('Upload acceptance identity/state is unverified.')
            row.accepted = envelope
            row.uploadState = 'accepted'
            await this._pollQueueImport(envelope.display_id)
            if (generation !== runtime.generation) return
            if (row.cancellationRequested) await this.cancelQueueImport(row.localId)
            await this.fetchRecentImports()
            success = true
          } catch (error: unknown) {
            if (generation !== runtime.generation) return
            row.rejection = toRejection(error)
            this._stopImportOnAuth(error)
            row.uploadState =
              row.rejection.status === 409
                ? 'conflict'
                : [400, 413, 422, 401, 403].includes(row.rejection.status)
                  ? 'failed'
                  : 'uncertain'
            // A transport may preserve an identity actually observed before interruption.
            // No filename/size/time comparison can supply this evidence.
            if (
              row.uploadState === 'uncertain' &&
              error &&
              typeof error === 'object' &&
              'display_id' in error &&
              typeof error.display_id === 'string' &&
              error.display_id.length > 0
            ) {
              row.observedDisplayId = error.display_id
              await this._pollQueueImport(error.display_id)
            }
          } finally {
            runtime.uploads.delete(row.localId)
            runtime.waiters.get(row.localId)?.(success)
            runtime.waiters.delete(row.localId)
          }
          // Every next POST receives a fresh bounded domain reconciliation.
          runtime.reconciled = false
        }
      }
      runtime.pump = work()
      try {
        await runtime.pump
      } finally {
        runtime.pump = null
        // Legacy single-file callers receive no acceptance while dispatch is held.
        for (const [id, resolve] of runtime.waiters) {
          const row = this.importQueue.find((item) => item.localId === id)
          resolve(row?.uploadState === 'accepted')
        }
        runtime.waiters.clear()
        if (runtime.active && generation !== runtime.generation && !this.importAuthStopped) void this._scheduleImports()
      }
    },

    /** Cancel only local eligibility or the exact persisted owner; no metadata matching. */
    async cancelQueueImport(localId: number): Promise<void> {
      const row = this.importQueue.find((item) => item.localId === localId)
      if (!row) return
      const runtime = this._importRuntime()
      const id = importIdentity(row)
      if (!id) {
        if (row.uploadState === 'uploading') {
          row.cancellationRequested = true
          row.uploadState = 'uncertain'
          row.pollError = 'Cancellation requested; server acceptance is unverified.'
          runtime.uploads.get(localId)?.abort()
        } else if (['pending', 'conflict', 'failed'].includes(row.uploadState)) {
          row.uploadState = 'cancelled'
          row.file = null
          runtime.waiters.get(localId)?.(false)
          runtime.waiters.delete(localId)
          void this._scheduleImports()
        }
        return
      }
      if (this.importAuthStopped || (row.status && importIsTerminal(row.status.state))) return
      if (runtime.cancels.has(id)) return await runtime.cancels.get(id)
      const generation = runtime.generation
      const work = async () => {
        await runtime.polls.get(id)
        if (generation !== runtime.generation || this.importAuthStopped) return
        row.cancelError = null
        row.cancellationRequested = true
        try {
          const job = await usePcapImport().cancelImport(id)
          if (generation !== runtime.generation) return
          if (!validImportStatus(job) || job.display_id !== id)
            throw new Error('Cancellation identity/state is unverified.')
          this._applyImportStatus(job)
        } catch (error: unknown) {
          if (generation !== runtime.generation) return
          this._stopImportOnAuth(error)
          row.cancelError = `Failed to cancel import: ${extractErrorMessage(error)}`
        }
        if (generation === runtime.generation) await this.fetchRecentImports()
      }
      const promise = work()
      runtime.cancels.set(id, promise)
      try {
        await promise
      } finally {
        runtime.cancels.delete(id)
      }
      void this._scheduleImports()
    },
  },
})
