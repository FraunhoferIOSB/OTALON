import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'

const storeStub = vi.hoisted(() => ({
  runningCount: 0,
  failed7dCount: 0,
  completed7dCount: 1,
  jobs: [
    {
      id: 11,
      display_id: 'J-11',
      type: 'training',
      title: 'Boundary retrain',
      state: 'completed',
      actor: 'operator',
      started_at: '2026-07-21T10:00:00Z',
      can_cancel: false,
      can_retry: false,
    },
  ],
  filteredJobs: [
    {
      id: 11,
      display_id: 'J-11',
      type: 'training',
      title: 'Boundary retrain',
      state: 'completed',
      actor: 'operator',
      started_at: '2026-07-21T10:00:00Z',
      can_cancel: false,
      can_retry: false,
    },
  ],
  audit: [],
  filteredAudit: [],
  selectedJob: null,
  jobsFilter: { state: 'all', type: '', actor: '', since: '' },
  auditFilter: { category: 'all', actor: '', since: '', q: '' },
  isLoadingJobs: false,
  isLoadingAudit: false,
  jobsError: null,
  auditError: null,
  fetchJobs: vi.fn().mockResolvedValue(undefined),
  fetchAudit: vi.fn().mockResolvedValue(undefined),
  fetchJobDetail: vi.fn().mockResolvedValue(undefined),
  clearSelectedJob: vi.fn(),
  cancelJob: vi.fn().mockResolvedValue(undefined),
  retryJob: vi.fn().mockResolvedValue(undefined),
}))

const operationsRefresh = vi.hoisted(() => ({
  register: vi.fn(),
  unregister: vi.fn(),
  refresh: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('~/stores/operationsJobsStore', () => ({
  useOperationsJobsStore: () => storeStub,
}))
vi.mock('~/composables/usePolling', () => ({ usePolling: vi.fn() }))
vi.mock('~/composables/useOperationsRefresh', () => ({
  OPERATIONS_HEAVY_POLL_INTERVAL_MS: 30_000,
  useOperationsRefresh: () => operationsRefresh,
}))

async function mountPage() {
  const { mountWithPlugins } = await import('../helpers/mount')
  const mod = await import('~/pages/operations/jobs.vue')
  return mountWithPlugins(mod.default)
}

beforeEach(() => {
  operationsRefresh.register.mockReset()
  operationsRefresh.unregister.mockReset()
  operationsRefresh.refresh.mockReset().mockResolvedValue(undefined)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Jobs narrow status semantics', () => {
  it('keeps desktop badge in a local wrapper and exposes exact compact state text', async () => {
    const wrapper = await mountPage()
    await flushPromises()

    const row = wrapper.get('.job-row')
    expect(row.get('.job-row__state .cd-state-badge').text()).toBe('completed')
    expect(row.get('[data-test="job-compact-state"]').text()).toBe('completed')
    expect(row.attributes('aria-label')).toContain('state completed')
    expect(row.get('.job-row__open').attributes('aria-hidden')).toBe('true')
  })

  it('uses native Jobs Since datetime picker without a duplicate custom control', async () => {
    const wrapper = await mountPage()
    await flushPromises()

    const since = wrapper.get('[data-test="jobs-since"]')
    expect(since.get('input').attributes('type')).toBe('datetime-local')
    expect(since.find('.q-field__append .q-icon').exists()).toBe(false)
    expect(since.find('.q-popup-proxy').exists()).toBe(false)
  })
})

// The expanded-detail height behavior is a pure CSS-layout concern: happy-dom
// has no layout engine and `<style scoped>` is not applied to the mounted DOM,
// so `scrollHeight`/`clientHeight` cannot be measured here. This source-level
// regression pins the CAPTURE-30 contract deterministically; the real-browser
// `scrollHeight === clientHeight` assertion lives in the Playwright fixture
// spec `operations-jobs-natural-height.spec.ts`.
describe('Jobs detail natural-height CSS contract (CAPTURE 30 / finding 4)', () => {
  // Vitest runs with cwd at the otalon-ui package root; resolve the SFC
  // from there (import.meta.url is not guaranteed a file: URL under this env).
  const source = readFileSync(resolve(process.cwd(), 'app/pages/operations/jobs.vue'), 'utf-8')

  function ruleBodies(selector: string): string[] {
    // Extract every standalone `<selector> { ... }` block body from the SFC
    // source. `selector` must begin the rule (start of line), so a compound
    // group like `.jobs-list-panel, .job-detail-panel { ... }` is not matched
    // by `.job-detail-panel` — only its own dedicated rule is.
    const escaped = selector.replace(/[.]/g, '\\$&')
    const matches = [...source.matchAll(new RegExp(`(?:^|\\n)${escaped}\\s*\\{([^}]*)\\}`, 'g'))]
    expect(matches.length, `expected a dedicated CSS rule for ${selector}`).toBeGreaterThan(0)
    return matches.map((match) => match[1]!)
  }

  it('does not cap the ordinary detail panel height', () => {
    // The dedicated `.job-detail-panel { ... }` layout rule (flex column).
    const layoutRule = ruleBodies('.job-detail-panel').find((body) => body.includes('flex-direction'))
    expect(layoutRule, 'the flex-column .job-detail-panel rule').toBeTruthy()
    expect(layoutRule!).toContain('max-height: none')
    expect(layoutRule!).not.toMatch(/max-height:\s*min\(/)
    expect(layoutRule!).not.toMatch(/max-height:\s*\d/)
  })

  it('does not force the whole detail body to scroll', () => {
    const body = ruleBodies('.job-detail-panel__body')[0]!
    expect(body).not.toContain('overflow-y: auto')
    expect(body).not.toContain('overflow: hidden')
  })

  it('scopes the bounded scroll to the timeline log region only, with a materially larger cap', () => {
    // The only overflow-y:auto for detail content is on .job-log.
    const logRules = [...source.matchAll(/\.job-log\s*\{([^}]*)\}/g)].map((m) => m[1]!)
    const logBody = logRules.join('\n')
    expect(logBody).toContain('overflow-y: auto')
    // Materially larger than the retired 340px panel cap and viewport-responsive.
    expect(logBody).toMatch(/max-height:\s*max\(70vh,\s*620px\)/)

    // No other detail region reintroduces a body/panel scroll.
    expect(source).not.toMatch(/\.job-detail-panel__body[^{]*\{[^}]*overflow-y:\s*auto/)
  })
})
