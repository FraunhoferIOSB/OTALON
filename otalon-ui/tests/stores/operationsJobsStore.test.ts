/**
 * Unit tests for operationsJobsStore.
 *
 * Validates job/audit loading, filters, KPIs, SSE message handling,
 * cancel/retry actions and error states.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { server } from '../mocks/server'
import { http, HttpResponse } from 'msw'

import { useOperationsJobsStore } from '~/stores/operationsJobsStore'
import type {
  OperationsJobActionResponse,
  OperationsJobSummary,
  OperationsJobsResponse,
  OperationsAuditResponse,
  OperationsAuditEntry,
} from '~/types/api'

const MOCK_JOBS: OperationsJobSummary[] = [
  {
    id: 1,
    display_id: 'J-1',
    type: 'service',
    title: 'Restart otalon-api',
    state: 'running',
    trigger: 'operator (UI)',
    actor: 'operator',
    started_at: new Date().toISOString(),
    ended_at: null,
    latest_event: null,
    can_cancel: false,
    can_retry: false,
  },
  {
    id: 2,
    display_id: 'J-2',
    type: 'training',
    title: 'Boundary retrain',
    state: 'failed',
    trigger: 'operator (UI)',
    actor: 'operator',
    started_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    ended_at: new Date().toISOString(),
    latest_event: 'Training failed',
    can_cancel: false,
    can_retry: true,
  },
  {
    id: 3,
    display_id: 'J-3',
    type: 'backup',
    title: 'Cancelled backup',
    state: 'cancelled',
    trigger: 'operator (UI)',
    actor: 'operator',
    started_at: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
    ended_at: new Date().toISOString(),
    latest_event: 'Cancelled',
    can_cancel: false,
    can_retry: true,
  },
]

const MOCK_AUDIT: OperationsAuditEntry[] = [
  {
    id: 1,
    at: new Date().toISOString(),
    category: 'service',
    actor: 'operator',
    action: 'restart',
    target: 'otalon-api',
    reason: 'Requested from UI',
    detail: null,
  },
  {
    id: 2,
    at: new Date().toISOString(),
    category: 'job',
    actor: 'operator',
    action: 'cancel',
    target: 'job:J-3',
    reason: 'Operator cancelled',
    detail: null,
  },
]

function setupHandlers() {
  server.use(
    http.get('*/api/v1/operations/jobs', () => {
      return HttpResponse.json({ items: MOCK_JOBS, total: MOCK_JOBS.length } satisfies OperationsJobsResponse)
    }),
    http.get('*/api/v1/operations/audit', () => {
      return HttpResponse.json({ items: MOCK_AUDIT, total: MOCK_AUDIT.length } satisfies OperationsAuditResponse)
    }),
    http.get('*/api/v1/operations/jobs/:id', ({ params }) => {
      const id = Number(params.id)
      const job = MOCK_JOBS.find((j) => j.id === id)
      if (!job) return HttpResponse.json({ detail: 'Not found' }, { status: 404 })
      return HttpResponse.json({
        ...job,
        params: { intervals: [['2026-07-21T10:00:00Z', '2026-07-21T10:05:00Z']], module: 'conn' },
        log: [{ timestamp: '2026-07-21T10:01:00Z', phase: 'prepare', message: 'Started', records: 12 }],
        phase_current: null,
        phase_total: null,
        phase_label: null,
        error: null,
        result: null,
        retried_as_id: null,
      })
    }),
    http.post('*/api/v1/operations/jobs/:id/cancel', ({ params }) => {
      const id = Number(params.id)
      const cancelled = MOCK_JOBS.find((j) => j.id === id)
      if (!cancelled) return HttpResponse.json({ detail: 'Not found' }, { status: 404 })
      return HttpResponse.json({
        success: true,
        job: { ...cancelled, state: 'cancelled', can_retry: true },
        message: null,
      } satisfies OperationsJobActionResponse)
    }),
    http.post('*/api/v1/operations/jobs/:id/retry', ({ params }) => {
      const id = Number(params.id)
      const original = MOCK_JOBS.find((j) => j.id === id)
      if (!original) return HttpResponse.json({ detail: 'Not found' }, { status: 404 })
      return HttpResponse.json({
        success: true,
        job: { ...original, id: 99, display_id: 'J-99', state: 'running' },
        message: null,
      } satisfies OperationsJobActionResponse)
    }),
  )
}

describe('operationsJobsStore', () => {
  beforeEach(() => {
    localStorage.clear()
    setActivePinia(createPinia())
    setupHandlers()
  })

  describe('fetchJobs', () => {
    it('loads the jobs list', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      expect(store.jobs).toHaveLength(MOCK_JOBS.length)
      expect(store.jobs[0].display_id).toBe('J-1')
    })

    it('exposes KPIs from loaded jobs', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      expect(store.runningCount).toBe(1)
      expect(store.failed7dCount).toBe(1)
      expect(store.completed7dCount).toBe(0)
      expect(store.hasFailed).toBe(true)
    })
  })

  describe('filters', () => {
    it('filters jobs by state', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      store.setJobsFilter({ state: 'failed' })
      expect(store.filteredJobs).toHaveLength(1)
      expect(store.filteredJobs[0].display_id).toBe('J-2')
    })

    it('filters audit by category', async () => {
      const store = useOperationsJobsStore()
      await store.fetchAudit()
      store.setAuditFilter({ category: 'job' })
      expect(store.filteredAudit).toHaveLength(1)
      expect(store.filteredAudit[0].action).toBe('cancel')
    })
  })

  describe('actions', () => {
    it('cancels a job and refreshes the list', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      const result = await store.cancelJob(1)
      expect(result?.success).toBe(true)
      expect(store.jobs).toHaveLength(MOCK_JOBS.length)
    })

    it('retries a job and refreshes the list', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      const result = await store.retryJob(2)
      expect(result?.success).toBe(true)
    })
  })

  describe('_SSE message handling', () => {
    it('updates the state of an existing job from a push', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      store.handleJobEvent({ job_id: 1, state: 'completed' })
      expect(store.jobs.find((j) => j.id === 1)?.state).toBe('completed')
    })

    it('ignores a malformed or id-less payload', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      store.handleJobEvent(null)
      store.handleJobEvent({ state: 'completed' })
      // No throw, existing state intact.
      expect(store.jobs.find((j) => j.id === 1)?.state).toBe('running')
    })

    it('triggers a bounded refresh for an unknown broadcast job id (B-F10)', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()

      let fetchCount = 0
      server.use(
        http.get('*/api/v1/operations/jobs', () => {
          fetchCount += 1
          return HttpResponse.json({ items: MOCK_JOBS, total: MOCK_JOBS.length } satisfies OperationsJobsResponse)
        }),
      )

      // A job id this session has never seen must not be dropped.
      store.handleJobEvent({ job_id: 424242, state: 'running' })
      // Allow the async refresh to run.
      await new Promise((r) => setTimeout(r, 0))
      expect(fetchCount).toBeGreaterThanOrEqual(1)
    })

    it('coalesces concurrent unknown-id broadcasts into one refresh (B-F10)', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()

      let fetchCount = 0
      server.use(
        http.get('*/api/v1/operations/jobs', () => {
          fetchCount += 1
          return HttpResponse.json({ items: MOCK_JOBS, total: MOCK_JOBS.length } satisfies OperationsJobsResponse)
        }),
      )

      store.handleJobEvent({ job_id: 111111, state: 'running' })
      store.handleJobEvent({ job_id: 222222, state: 'running' })
      store.handleJobEvent({ job_id: 333333, state: 'running' })
      await new Promise((r) => setTimeout(r, 0))
      // Guard collapses the burst to a single in-flight refresh.
      expect(fetchCount).toBe(1)
    })
  })

  describe('KPI semantics (B-F07)', () => {
    it('excludes cancelled jobs from Completed (7 d)', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      // One cancelled + one failed + one running are loaded; none completed.
      expect(store.completed7dCount).toBe(0)
    })

    it('counts a genuinely completed job in Completed (7 d)', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      store.jobs.push({
        id: 4,
        display_id: 'J-4',
        type: 'ingest',
        title: 'Import done',
        state: 'completed',
        trigger: 'schedule',
        actor: 'schedule',
        started_at: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
        ended_at: new Date().toISOString(),
        latest_event: 'done',
        can_cancel: false,
        can_retry: false,
      })
      expect(store.completed7dCount).toBe(1)
    })

    it('windows terminal KPIs on ended_at, not started_at', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      // A job started 30 days ago but that FAILED just now must still count
      // in Failed (7 d) because the window is anchored on ended_at.
      store.jobs.push({
        id: 5,
        display_id: 'J-5',
        type: 'training',
        title: 'Long job failed recently',
        state: 'failed',
        trigger: 'schedule',
        actor: 'schedule',
        started_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        ended_at: new Date().toISOString(),
        latest_event: 'failed',
        can_cancel: false,
        can_retry: true,
      })
      // MOCK J-2 (failed within 7d) + the new recent-end failure = 2.
      expect(store.failed7dCount).toBe(2)
    })
  })

  describe('completion notifications (B-F08)', () => {
    it('does not surface historical terminal jobs as fresh completion notifications', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      expect(store.unnotifiedCompletions).toEqual([])
    })

    it('UI-202: does not surface the newest historical terminal jobs when there are more than 100', async () => {
      // Production shape: the API returns jobs id-descending; 143 terminal jobs, ids 1253..1111.
      // The first-load mark must cover the NEWEST 100 (1253..1154), not the oldest.
      const many = Array.from({ length: 143 }, (_, i) => ({
        ...MOCK_JOBS[0],
        id: 1253 - i,
        display_id: `J-${1253 - i}`,
        state: 'completed',
        started_at: '2026-10-26T16:00:00+01:00',
        ended_at: '2026-10-26T16:01:00+01:00',
      }))
      const store = useOperationsJobsStore()
      store._api = () => ({ get: async () => ({ items: many }) }) as never
      await store.fetchJobs()
      const surfaced = store.unnotifiedCompletions.map((j) => j.id)
      // every terminal job the list returned is marked on the first load, not a 100-window
      expect(surfaced).toEqual([])
      expect(store.lastNotifiedJobIds).toContain('1111')
      expect(store.lastNotifiedJobIds).toContain('1253')
    })

    it('UI-202: at the cap, the oldest marked job is evicted, never a newer one', () => {
      const store = useOperationsJobsStore()
      // fill to the cap with ids 1..1000, then mark a much newer id: the smallest id must go
      for (let i = 1; i <= 1000; i++) store.markNotified(i)
      expect(store.lastNotifiedJobIds).toHaveLength(1000)
      store.markNotified(5000)
      expect(store.lastNotifiedJobIds).toHaveLength(1000)
      expect(store.lastNotifiedJobIds).toContain('5000')
      expect(store.lastNotifiedJobIds).toContain('1000')
      expect(store.lastNotifiedJobIds).not.toContain('1')
    })

    it('markNotified dedups so a job is not notified twice', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      store.lastNotifiedJobIds = store.lastNotifiedJobIds.filter((id) => id !== '2')
      store.markNotified(2)
      store.markNotified(2)
      expect(store.lastNotifiedJobIds.filter((id) => id === '2')).toHaveLength(1)
      expect(store.unnotifiedCompletions.map((j) => j.id)).not.toContain(2)
      expect(JSON.parse(localStorage.getItem('operations:jobs:notified') ?? '[]')).toContain('2')
    })

    it('restores notified job ids across a fresh store instance', () => {
      localStorage.setItem('operations:jobs:notified', JSON.stringify(['2']))
      setActivePinia(createPinia())
      const store = useOperationsJobsStore()
      expect(store.lastNotifiedJobIds).toEqual(['2'])
    })

    it('surfaces a job that becomes terminal during the active session', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      store.handleJobEvent({ job_id: 1, state: 'completed' })
      expect(store.unnotifiedCompletions.map((job) => job.id)).toEqual([1])
    })
  })

  describe('error messaging (B-F11)', () => {
    it('does not reference a non-existent settings UI on auth failure', async () => {
      const store = useOperationsJobsStore()
      server.use(
        http.get('*/api/v1/operations/jobs', () => {
          return HttpResponse.json({ detail: 'unauthorized' }, { status: 401 })
        }),
      )
      await store.fetchJobs()
      expect(store.jobsError).toBeTruthy()
      expect(store.jobsError?.toLowerCase()).not.toContain('settings')
      expect(store.jobsError?.toLowerCase()).toContain('insufficient permissions')
    })
  })

  describe('selection-scoped detail race (B-F3)', () => {
    /**
     * Install a detail handler whose responses are held open until the returned
     * resolver map is invoked, so a deterministic A-after-B race can be staged.
     */
    function deferredDetailHandlers(): Map<number, () => void> {
      const releases = new Map<number, () => void>()
      server.use(
        http.get('*/api/v1/operations/jobs/:id', async ({ params }) => {
          const id = Number(params.id)
          await new Promise<void>((resolve) => releases.set(id, resolve))
          const job = MOCK_JOBS.find((j) => j.id === id)
          if (!job) return HttpResponse.json({ detail: 'Not found' }, { status: 404 })
          return HttpResponse.json({
            ...job,
            params: {},
            log: [],
            phase_current: null,
            phase_total: null,
            phase_label: null,
            error: null,
            result: null,
            retried_as_id: null,
          })
        }),
      )
      return releases
    }

    it('keeps row B when a slower row A resolves after it', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      const releases = deferredDetailHandlers()

      const fetchA = store.fetchJobDetail(1)
      const fetchB = store.fetchJobDetail(2)
      // Resolve the stale request (A) first, then the current one (B).
      await vi.waitFor(() => expect(releases.has(1)).toBe(true))
      releases.get(1)?.()
      await fetchA
      // A must not have populated the panel — B is the live selection.
      expect(store.selectedJob).toBeNull()

      await vi.waitFor(() => expect(releases.has(2)).toBe(true))
      releases.get(2)?.()
      await fetchB
      expect(store.selectedJob?.id).toBe(2)
      expect(store.isLoadingDetail).toBe(false)
    })

    it('drops a stale failure so it cannot blank or error the current selection', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      // First load a good detail for row 2 so there is a current selection.
      await store.fetchJobDetail(2)
      expect(store.selectedJob?.id).toBe(2)

      const releases = new Map<number, () => void>()
      const rejectA = { current: false }
      server.use(
        http.get('*/api/v1/operations/jobs/:id', async ({ params }) => {
          const id = Number(params.id)
          await new Promise<void>((resolve) => releases.set(id, resolve))
          if (id === 1 && rejectA.current) return HttpResponse.json({ detail: 'boom' }, { status: 500 })
          const job = MOCK_JOBS.find((j) => j.id === id)
          return HttpResponse.json({
            ...job,
            params: {},
            log: [],
            phase_current: null,
            phase_total: null,
            phase_label: null,
            error: null,
            result: null,
            retried_as_id: null,
          })
        }),
      )

      rejectA.current = true
      // Start a stale request for A, then supersede with B before A resolves.
      const fetchA = store.fetchJobDetail(1)
      const fetchB = store.fetchJobDetail(2)
      await vi.waitFor(() => expect(releases.has(1)).toBe(true))
      releases.get(1)?.()
      await fetchA
      // Stale failure discarded: no error leaked, selection intact.
      expect(store.jobsError).toBeNull()
      expect(store.selectedJob?.id).toBe(2)

      await vi.waitFor(() => expect(releases.has(2)).toBe(true))
      releases.get(2)?.()
      await fetchB
      expect(store.selectedJob?.id).toBe(2)
    })

    it('invalidates an in-flight fetch when the selection is cleared', async () => {
      const store = useOperationsJobsStore()
      await store.fetchJobs()
      const releases = deferredDetailHandlers()

      const fetchA = store.fetchJobDetail(1)
      await vi.waitFor(() => expect(releases.has(1)).toBe(true))
      store.clearSelectedJob()
      releases.get(1)?.()
      await fetchA
      // The closed panel stays empty even though A eventually resolved.
      expect(store.selectedJob).toBeNull()
      expect(store.isLoadingDetail).toBe(false)
    })
  })
})
