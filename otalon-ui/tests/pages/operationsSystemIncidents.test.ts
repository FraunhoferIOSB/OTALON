/**
 * Page-level route-authority contract tests for Operations / System.
 *
 * CAPTURE follow-up 6 requirement 44 makes the `?incident=<id>` route query the
 * single deep-link source for the Health tab incident detail: selecting a row
 * updates the route first, an explicit close clears both store selection and the
 * query (so reload stays closed), and a rapid row switch is last-request-wins —
 * a stale/duplicate detail response may never restore the prior incident.
 *
 * These tests mount the real `system.vue` with a reactive route + a `navigateTo`
 * that mutates it AND the REAL Pinia `healthIncidentsStore` (only the network
 * layer `$fetch` is stubbed). The previous version replaced the store with a
 * stub that reimplemented the stale-drop guard via `__latestSelectId`, which was
 * self-fulfilling — it passed even if the production `detailRequestSeq` logic
 * regressed. The store is now real, so the route -> watch -> store.select ->
 * detailRequestSeq flow is genuinely exercised (audit Reviewer C P2).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { reactive } from 'vue'
import { createPinia, setActivePinia } from 'pinia'

import type { HealthIncidentSummary } from '~/types/api'
import { useHealthIncidentsStore } from '~/stores/healthIncidentsStore'

function makeIncident(id: string, overrides: Partial<HealthIncidentSummary> = {}): HealthIncidentSummary {
  return {
    id,
    service: 'Network Traffic Recorder',
    owning_service: 'otalon-capture',
    probe_target: 'Network Traffic Recorder',
    system_service_id: 'otalon-capture',
    category: 'probe_timeout',
    cause: `cause ${id}`,
    status: 'active',
    first_seen: '2026-07-23T10:00:00Z',
    last_seen: '2026-07-23T10:05:00Z',
    recovered_at: null,
    sample_count: 3,
    failure_count: 2,
    latency_budget_ms: 3000,
    worst_latency_ms: 5010,
    evidence_type: 'operational_health',
    ...overrides,
  }
}

// A reactive route plus a navigateTo that mutates it, so the component's
// `watch(() => [route.query.tab, route.query.incident])` fires exactly as it
// would under Nuxt's router.
const route = reactive<{ path: string; query: Record<string, string> }>({
  path: '/operations/system',
  query: {},
})

const systemStub = vi.hoisted(() => ({
  services: [] as unknown[],
  logs: {} as Record<string, string>,
  storage: null,
  backups: null,
  backupCatalog: [] as unknown[],
  selectedArtifactId: null,
  version: null,
  health: null,
  support: null,
  update: null,
  isLoading: false,
  error: null,
  actionError: null,
  load: vi.fn().mockResolvedValue(undefined),
  fetchLogs: vi.fn().mockResolvedValue(undefined),
  serviceAction: vi.fn().mockResolvedValue(undefined),
  runHealthCheck: vi.fn().mockResolvedValue(undefined),
  loadSupportPreview: vi.fn().mockResolvedValue(undefined),
  createSupportBundle: vi.fn().mockResolvedValue(null),
  checkUpdates: vi.fn().mockResolvedValue(undefined),
  runBackup: vi.fn().mockResolvedValue(null),
  restore: vi.fn().mockResolvedValue(null),
  reset: vi.fn().mockResolvedValue(null),
  previewPostgresqlReset: vi.fn().mockResolvedValue(null),
  previewInfluxReset: vi.fn().mockResolvedValue(null),
}))

const operationsRefresh = vi.hoisted(() => ({
  register: vi.fn(),
  unregister: vi.fn(),
  refresh: vi.fn().mockResolvedValue(undefined),
}))

// Only the systemStore + composables are mocked; healthIncidentsStore is REAL.
vi.mock('~/stores/systemStore', () => ({ useSystemStore: () => systemStub }))
vi.mock('~/composables/usePolling', () => ({ usePolling: vi.fn() }))
vi.mock('~/composables/useOperationsRefresh', () => ({
  OPERATIONS_HEAVY_POLL_INTERVAL_MS: 30_000,
  useOperationsRefresh: () => operationsRefresh,
}))

const navigateTo = vi.fn((target: { path: string; query?: Record<string, string> }) => {
  route.path = target.path
  route.query = { ...(target.query ?? {}) }
  return Promise.resolve()
})

// A deferred-capable $fetch stub for the detail endpoint. When `deferred` is
// true, GET /health-incidents/<id> resolves only when the test settles it, so
// out-of-order responses can be modelled against the REAL store.
interface FetchControl {
  deferred: boolean
  detailResolvers: Record<string, (value: HealthIncidentSummary) => void>
  detailRequests: string[]
  acknowledged: string[]
}
const control: FetchControl = { deferred: false, detailResolvers: {}, detailRequests: [], acknowledged: [] }

function installFetch(): void {
  const fetchMock = vi.fn((url: string, opts?: { method?: string }) => {
    const ackMatch = url.match(/\/health-incidents\/([^/]+)\/acknowledge$/)
    if (opts?.method === 'POST' && ackMatch) {
      const id = decodeURIComponent(ackMatch[1]!)
      control.acknowledged.push(id)
      return Promise.resolve(makeIncident(id, { acknowledged: true, acknowledged_by: 'operator' }))
    }
    if (url.endsWith('/health-incidents')) {
      return Promise.resolve({
        items: [makeIncident('incident-1'), makeIncident('incident-2')],
        retention: { max_incidents: 50, max_days: 7 },
      })
    }
    const detailMatch = url.match(/\/health-incidents\/([^/]+)$/)
    if (detailMatch) {
      const id = decodeURIComponent(detailMatch[1]!)
      control.detailRequests.push(id)
      if (!control.deferred) return Promise.resolve(makeIncident(id))
      return new Promise<HealthIncidentSummary>((resolve) => {
        control.detailResolvers[id] = resolve
      })
    }
    return Promise.resolve({ items: [], total: 0 })
  })
  vi.stubGlobal('$fetch', fetchMock)
}

async function mountPage() {
  const { mountWithPlugins } = await import('../helpers/mount')
  const mod = await import('~/pages/operations/system.vue')
  return mountWithPlugins(mod.default)
}

beforeEach(async () => {
  setActivePinia(createPinia())
  route.path = '/operations/system'
  route.query = {}
  control.deferred = false
  control.detailResolvers = {}
  control.detailRequests = []
  control.acknowledged = []
  navigateTo.mockClear()
  installFetch()
  ;(globalThis as Record<string, unknown>).navigateTo = navigateTo
  ;(globalThis as Record<string, unknown>).useRoute = () => route
  // Seed the real store's history so filteredIncidents renders rows.
  const store = useHealthIncidentsStore()
  store.history = [makeIncident('incident-1'), makeIncident('incident-2')]
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('Operations System — incident selection is route-authoritative (CAPTURE 44)', () => {
  it('selecting a row writes the route query first, then loads via the query watch', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    navigateTo({ path: '/operations/system', query: { tab: 'health' } })
    await flushPromises()
    expect(control.detailRequests).toEqual([])

    const rows = wrapper.findAll('.incident-selected, .q-item').filter((n) => n.text().includes('cause incident-1'))
    await rows[0]!.trigger('click')
    await flushPromises()

    expect(navigateTo).toHaveBeenCalledWith(
      expect.objectContaining({ query: expect.objectContaining({ incident: 'incident-1', tab: 'health' }) }),
    )
    expect(route.query.incident).toBe('incident-1')
    // The query watch drove a REAL store.select -> detail fetch for incident-1.
    expect(control.detailRequests).toContain('incident-1')
  })

  it('an incident query present on mount selects that incident (deep-link/reload open)', async () => {
    route.query = { tab: 'health', incident: 'incident-2' }
    await mountPage()
    await flushPromises()
    const store = useHealthIncidentsStore()
    expect(control.detailRequests).toContain('incident-2')
    expect(store.selected?.id).toBe('incident-2')
  })

  it('closing clears store selection and the incident query so a reload stays closed', async () => {
    route.query = { tab: 'health', incident: 'incident-1' }
    const wrapper = await mountPage()
    await flushPromises()
    const store = useHealthIncidentsStore()
    expect(store.selected?.id).toBe('incident-1')

    await wrapper.get('[aria-label="Close health evidence"]').trigger('click')
    await flushPromises()

    expect(route.query.incident).toBeUndefined()
    expect(route.query.tab).toBe('health')
    expect(store.selected).toBeNull()

    // Simulate a reload: fresh mount with the now-cleared query must not reselect.
    control.detailRequests = []
    await mountPage()
    await flushPromises()
    expect(control.detailRequests).toEqual([])
  })

  it('rapid row switch is last-request-wins via the REAL store: a stale response cannot restore the prior incident', async () => {
    control.deferred = true
    route.query = { tab: 'health', incident: 'incident-1' }
    await mountPage()
    await flushPromises()
    const store = useHealthIncidentsStore()
    // First selection is in flight (resolver parked), nothing committed yet.
    expect(control.detailRequests).toContain('incident-1')
    expect(store.selected).toBeNull()

    // Switch to incident-2 before the first resolves.
    navigateTo({ path: '/operations/system', query: { tab: 'health', incident: 'incident-2' } })
    await flushPromises()
    expect(control.detailRequests).toContain('incident-2')

    // Resolve the NEWER response first, then the STALE older one, OUT OF ORDER.
    control.detailResolvers['incident-2']?.(makeIncident('incident-2'))
    await flushPromises()
    expect(store.selected?.id).toBe('incident-2')

    control.detailResolvers['incident-1']?.(makeIncident('incident-1'))
    await flushPromises()
    // The stale first response must be dropped by the real detailRequestSeq guard.
    expect(store.selected?.id).toBe('incident-2')
  })

  it('switching to a non-health tab clears the incident selection', async () => {
    route.query = { tab: 'health', incident: 'incident-1' }
    await mountPage()
    await flushPromises()
    const store = useHealthIncidentsStore()
    expect(store.selected?.id).toBe('incident-1')

    navigateTo({ path: '/operations/system', query: { tab: 'services' } })
    await flushPromises()
    expect(store.selected).toBeNull()
  })
})

describe('Operations System — acknowledgement (CAPTURE 45)', () => {
  it('acknowledging a row issues a backend POST via the real store', async () => {
    route.query = { tab: 'health' }
    const wrapper = await mountPage()
    await flushPromises()

    const ackButton = wrapper.findAll('button').find((b) => b.text().includes('Acknowledge'))
    expect(ackButton).toBeTruthy()
    await ackButton!.trigger('click')
    await flushPromises()

    expect(control.acknowledged).toContain('incident-1')
  })

  it('acknowledge stops row-click propagation so it does not also change the route', async () => {
    route.query = { tab: 'health' }
    const wrapper = await mountPage()
    await flushPromises()
    navigateTo.mockClear()

    const ackButton = wrapper.findAll('button').find((b) => b.text().includes('Acknowledge'))
    await ackButton!.trigger('click')
    await flushPromises()

    // @click.stop on the Acknowledge button must prevent the row select from
    // firing a navigation.
    expect(navigateTo).not.toHaveBeenCalled()
    expect(control.acknowledged).toContain('incident-1')
  })

  it('renders an accessible acknowledge error when the backend POST fails', async () => {
    route.query = { tab: 'health' }
    const wrapper = await mountPage()
    await flushPromises()
    const store = useHealthIncidentsStore()
    // Force the acknowledge POST to fail through the real store.
    const failing = vi.fn().mockRejectedValue(new Error('backend down'))
    vi.stubGlobal('$fetch', failing)

    const ackButton = wrapper.findAll('button').find((b) => b.text().includes('Acknowledge'))
    await ackButton!.trigger('click')
    await flushPromises()

    expect(store.acknowledgeError).toBe('backend down')
    const banner = wrapper.find('[data-test="acknowledge-error"]')
    expect(banner.exists()).toBe(true)
    expect(banner.attributes('role')).toBe('alert')
    expect(banner.text()).toContain('backend down')
  })
})

describe('Operations System — reset confirmation (UI-104)', () => {
  it('opens confirmation with the preview scope without throwing', async () => {
    route.query = { tab: 'reset' }
    systemStub.previewPostgresqlReset.mockResolvedValue({
      target: 'postgresql',
      scope: 'anomaly-history',
      tables: [],
      executed: false,
    })

    const wrapper = await mountPage()
    await flushPromises()

    await wrapper.findAll('[data-test="reset-review"]')[0]!.trigger('click')
    await flushPromises()

    const continueButton = wrapper.get('[data-test="reset-confirm-open"]')
    await expect(continueButton.trigger('click')).resolves.not.toThrow()

    const exposed = wrapper.vm as unknown as {
      pendingReset: string | null
      confirmOpen: boolean
    }
    expect(exposed.pendingReset).toBe('anomaly-history')
    expect(exposed.confirmOpen).toBe(true)
  })
})
