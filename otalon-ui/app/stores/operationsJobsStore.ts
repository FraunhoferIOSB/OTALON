/**
 * Pinia store for the Operations Jobs & History page.
 *
 * Manages operations jobs, Change Audit entries, live updates via SSE,
 * and shell-level running/failed/completion notifications.
 */
import { defineStore } from 'pinia'

import { useApi, type UseApiReturn } from '~/composables/useApi'
import { useSse } from '~/composables/useSse'
import type {
  OperationsAuditCategory,
  OperationsAuditEntry,
  OperationsAuditResponse,
  OperationsJob,
  OperationsJobActionResponse,
  OperationsJobState,
  OperationsJobSummary,
  OperationsJobsResponse,
} from '~/types/api'
import { operationErrorMessage } from '~/utils/permissions'

/**
 * Active filter state for the jobs table.
 */
export interface JobsFilter {
  state: OperationsJobState | 'all'
  type: string
  actor: string
  since: string
}

/**
 * Active filter state for the Change Audit table.
 */
export interface AuditFilter {
  category: OperationsAuditCategory | 'all'
  actor: string
  since: string
  q: string
}

interface OperationsJobsState {
  jobs: OperationsJobSummary[]
  selectedJob: OperationsJob | null
  audit: OperationsAuditEntry[]
  jobsFilter: JobsFilter
  auditFilter: AuditFilter
  isLoadingJobs: boolean
  isLoadingAudit: boolean
  isLoadingDetail: boolean
  isCancelling: boolean
  isRetrying: boolean
  jobsError: string | null
  auditError: string | null
  lastNotifiedJobIds: string[]
  hasLoadedJobs: boolean
  // Guards a bounded refresh triggered by a broadcast for an unknown job so
  // concurrent unknown-id events coalesce into a single re-fetch (B-F10).
  isRefreshingUnknown: boolean
  // Monotonic sequence for job-detail fetches. A stale response (row A) whose
  // sequence no longer matches the latest request (row B) is discarded so it
  // never overwrites the current selection or leaks loading/error state (B-F3).
  detailSeq: number
}

// Debounce window for the unknown-job broadcast refresh (B-F10). Bounds how
// often an unknown broadcast id can trigger a full re-fetch.
const UNKNOWN_REFRESH_DEBOUNCE_MS = 750
const NOTIFIED_JOBS_STORAGE_KEY = 'operations:jobs:notified'
// Upper bound of remembered job ids. Matches the API list limit (1000), so every
// job the list can return fits; the cap only stops unbounded growth.
const NOTIFIED_JOBS_CAP = 1000

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000

function readNotifiedJobIds(): string[] {
  if (typeof window === 'undefined') return []
  try {
    const value = JSON.parse(localStorage.getItem(NOTIFIED_JOBS_STORAGE_KEY) ?? '[]')
    return Array.isArray(value) ? value.filter((id): id is string => typeof id === 'string').slice(0, NOTIFIED_JOBS_CAP) : []
  } catch {
    return []
  }
}

/**
 * Resolve the timestamp that anchors a terminal job in a 7-day KPI window.
 *
 * Terminal KPIs (Failed/Completed 7 d) measure when a job *ended*, so this
 * prefers `ended_at` and only falls back to `started_at` when a terminal row
 * unexpectedly lacks an end time. Returns epoch milliseconds.
 */
function terminalTimestamp(job: { started_at: string; ended_at?: string | null }): number {
  const anchor = job.ended_at ?? job.started_at
  return new Date(anchor).getTime()
}

/**
 * Extract an error message from the API client error shape.
 */
function extractErrorMessage(error: unknown): string {
  return operationErrorMessage(error, 'An unknown error occurred')
}

export const useOperationsJobsStore = defineStore('operationsJobs', {
  state: (): OperationsJobsState => ({
    jobs: [],
    selectedJob: null,
    audit: [],
    jobsFilter: {
      state: 'all',
      type: '',
      actor: '',
      since: '',
    },
    auditFilter: {
      category: 'all',
      actor: '',
      since: '',
      q: '',
    },
    isLoadingJobs: false,
    isLoadingAudit: false,
    isLoadingDetail: false,
    isCancelling: false,
    isRetrying: false,
    jobsError: null,
    auditError: null,
    lastNotifiedJobIds: readNotifiedJobIds(),
    hasLoadedJobs: false,
    isRefreshingUnknown: false,
    detailSeq: 0,
  }),

  getters: {
    filteredJobs(state): OperationsJobSummary[] {
      return state.jobs.filter((job) => {
        const filter = state.jobsFilter
        if (filter.state && filter.state !== 'all' && job.state !== filter.state) return false
        if (filter.type && filter.type.length > 0 && job.type !== filter.type) return false
        if (
          filter.actor &&
          filter.actor.length > 0 &&
          !(job.actor ?? '').toLowerCase().includes(filter.actor.toLowerCase())
        )
          return false
        if (filter.since && filter.since.length > 0 && new Date(job.started_at) < new Date(filter.since)) return false
        return true
      })
    },

    filteredAudit(state): OperationsAuditEntry[] {
      return state.audit.filter((entry) => {
        const filter = state.auditFilter
        if (filter.category && filter.category !== 'all' && entry.category !== filter.category) return false
        if (filter.actor && filter.actor.length > 0 && !entry.actor.toLowerCase().includes(filter.actor.toLowerCase()))
          return false
        if (filter.since && filter.since.length > 0 && new Date(entry.at) < new Date(filter.since)) return false
        if (filter.q && filter.q.length > 0) {
          const needle = filter.q.toLowerCase()
          const hay = `${entry.action} ${entry.target}`.toLowerCase()
          if (!hay.includes(needle)) return false
        }
        return true
      })
    },

    runningCount(state): number {
      return state.jobs.filter((j) => j.state === 'running' || j.state === 'cancelling').length
    },

    failed7dCount(state): number {
      const cutoff = Date.now() - SEVEN_DAYS_MS
      // "Failed (7 d)" = jobs that FAILED within the last 7 days, so the
      // window is anchored on the terminal ended_at (fallback to started_at
      // if a terminal row somehow lacks it).
      return state.jobs.filter((j) => j.state === 'failed' && terminalTimestamp(j) >= cutoff).length
    },

    completed7dCount(state): number {
      const cutoff = Date.now() - SEVEN_DAYS_MS
      // "Completed (7 d)" counts ONLY successfully completed jobs; cancelled
      // jobs are semantically distinct and excluded. Windowed on ended_at.
      return state.jobs.filter((j) => j.state === 'completed' && terminalTimestamp(j) >= cutoff).length
    },

    hasFailed(state): boolean {
      const cutoff = Date.now() - SEVEN_DAYS_MS
      return state.jobs.some((j) => j.state === 'failed' && terminalTimestamp(j) >= cutoff)
    },

    unnotifiedCompletions(state): OperationsJobSummary[] {
      return state.jobs.filter(
        (j) =>
          ['completed', 'failed', 'cancelled'].includes(j.state) && !state.lastNotifiedJobIds.includes(String(j.id)),
      )
    },
  },

  actions: {
    _api(): UseApiReturn {
      return useApi()
    },

    async fetchJobs(): Promise<void> {
      this.isLoadingJobs = true
      this.jobsError = null
      try {
        const response = await this._api().get<OperationsJobsResponse>('/api/v1/operations/jobs')
        this.jobs = response.items
        if (!this.hasLoadedJobs) {
          // UI-202: on the first load every terminal job the API returned is
          // history, not news. The old window (last 100 by insertion order, then
          // newest 100 by id) left jobs outside it unmarked, so they were toasted
          // on every reload. Mark all of them in memory, then persist ONCE: the
          // per-job localStorage write that blocked the renderer is what the
          // earlier cap was guarding against, a single write is not.
          const terminalIds = response.items
            .filter((j) => ['completed', 'failed', 'cancelled'].includes(j.state))
            .map((j) => String(j.id))
          const merged = Array.from(new Set([...this.lastNotifiedJobIds, ...terminalIds]))
          this.lastNotifiedJobIds = merged.sort((a, b) => Number(b) - Number(a)).slice(0, NOTIFIED_JOBS_CAP)
          this.persistNotifiedIds()
          this.hasLoadedJobs = true
        }
      } catch (error: unknown) {
        this.jobsError = `Failed to load jobs: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingJobs = false
      }
    },

    async fetchJobDetail(id: number): Promise<void> {
      // A monotonic sequence tracks the latest requested detail; a response for
      // a superseded row (or one requested after the panel was closed) is
      // dropped so it cannot overwrite the current selection or clobber the
      // loading/error state of a newer request (B-F3).
      const seq = ++this.detailSeq
      this.isLoadingDetail = true
      try {
        const detail = await this._api().get<OperationsJob>(`/api/v1/operations/jobs/${id}`)
        if (seq !== this.detailSeq) return
        this.selectedJob = detail
        this.jobsError = null
      } catch (error: unknown) {
        if (seq !== this.detailSeq) return
        this.jobsError = `Failed to load job detail: ${extractErrorMessage(error)}`
      } finally {
        if (seq === this.detailSeq) this.isLoadingDetail = false
      }
    },

    /**
     * Clear the selected job detail and invalidate any in-flight detail fetch
     * so a late response cannot repopulate a panel the operator has closed.
     */
    clearSelectedJob(): void {
      this.detailSeq += 1
      this.isLoadingDetail = false
      this.selectedJob = null
    },

    async fetchAudit(): Promise<void> {
      this.isLoadingAudit = true
      this.auditError = null
      try {
        const response = await this._api().get<OperationsAuditResponse>('/api/v1/operations/audit')
        this.audit = response.items
      } catch (error: unknown) {
        this.auditError = `Failed to load audit: ${extractErrorMessage(error)}`
      } finally {
        this.isLoadingAudit = false
      }
    },

    markNotified(jobId: number): void {
      const id = String(jobId)
      if (!this.lastNotifiedJobIds.includes(id)) {
        this.lastNotifiedJobIds.push(id)
        // UI-202: keep the newest entries by job id, not insertion order.
        this.lastNotifiedJobIds = this.lastNotifiedJobIds
          .sort((a, b) => Number(b) - Number(a))
          .slice(0, NOTIFIED_JOBS_CAP)
      }
    },

    /** Persist notified IDs to localStorage — call once after batch updates. */
    persistNotifiedIds(): void {
      if (typeof window !== 'undefined') {
        try {
          localStorage.setItem(NOTIFIED_JOBS_STORAGE_KEY, JSON.stringify(this.lastNotifiedJobIds))
        } catch {
          /* Storage is best-effort; in-memory dedup remains active. */
        }
      }
    },

    handleJobEvent(payload: unknown): void {
      if (!payload || typeof payload !== 'object') return
      const event = payload as Record<string, unknown>
      const jobId = event.job_id
      if (typeof jobId !== 'number') return

      const existing = this.jobs.find((j) => j.id === jobId)
      if (existing) {
        if (typeof event.state === 'string') {
          existing.state = event.state as OperationsJobState
        }
      } else {
        // A broadcast for a job this session has never seen — e.g. one
        // started by another operator/session, or a fresh retry successor.
        // Trigger a bounded re-fetch so it appears instead of being dropped.
        void this.refreshForUnknownJob()
      }
      if (this.selectedJob && this.selectedJob.id === jobId && typeof event.state === 'string') {
        this.selectedJob.state = event.state as OperationsJobState
      }
    },

    async refreshForUnknownJob(): Promise<void> {
      // Coalesce a burst of unknown-id broadcasts into one re-fetch and
      // release the guard after a short debounce so later new jobs still
      // trigger a refresh.
      if (this.isRefreshingUnknown) return
      this.isRefreshingUnknown = true
      try {
        await this.fetchJobs()
      } finally {
        setTimeout(() => {
          this.isRefreshingUnknown = false
        }, UNKNOWN_REFRESH_DEBOUNCE_MS)
      }
    },

    async cancelJob(id: number): Promise<OperationsJobActionResponse | null> {
      this.isCancelling = true
      try {
        return await this._api().post<OperationsJobActionResponse>(`/api/v1/operations/jobs/${id}/cancel`)
      } catch (error: unknown) {
        this.jobsError = `Cancel failed: ${extractErrorMessage(error)}`
        return null
      } finally {
        this.isCancelling = false
        await this.fetchJobs()
      }
    },

    async retryJob(id: number): Promise<OperationsJobActionResponse | null> {
      this.isRetrying = true
      try {
        return await this._api().post<OperationsJobActionResponse>(`/api/v1/operations/jobs/${id}/retry`)
      } catch (error: unknown) {
        this.jobsError = `Retry failed: ${extractErrorMessage(error)}`
        return null
      } finally {
        this.isRetrying = false
        await this.fetchJobs()
      }
    },

    setJobsFilter(filter: Partial<JobsFilter>): void {
      this.jobsFilter = { ...this.jobsFilter, ...filter }
    },

    setAuditFilter(filter: Partial<AuditFilter>): void {
      this.auditFilter = { ...this.auditFilter, ...filter }
    },
  },
})

/**
 * Composable that wires the operations-jobs SSE listener into the store.
 *
 * Returns the store instance; callers should invoke this from a component
 * so the SSE subscription is tied to the component lifecycle.
 */
export function useOperationsJobsStoreWithSse() {
  const store = useOperationsJobsStore()
  useSse('jobs', {
    onEvent: (_topic, data) => {
      store.handleJobEvent(data)
    },
  })
  return store
}
