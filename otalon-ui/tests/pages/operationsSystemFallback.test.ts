/**
 * Fallback-visibility contract for Operations / System (UI-191, F-026 T1).
 *
 * The Services card once carried a dead `v-if="false"` list, so its
 * `v-else-if="!store.isLoading"` fallback rendered "No service data is
 * available." *below* a filled service table. The Health card's empty-state
 * section paired `v-else` with the acknowledge-error banner instead of the
 * incident list, so "No incidents match selected filters." rendered under a
 * filled incident list.
 *
 * These tests pin the user-visible contract: a fallback text may only appear
 * when the corresponding list is actually empty.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { reactive } from 'vue'
import { createPinia, setActivePinia } from 'pinia'

import type { HealthIncidentSummary } from '~/types/api'
import { useHealthIncidentsStore } from '~/stores/healthIncidentsStore'

const SERVICE_FALLBACK = 'No service data is available.'
const INCIDENT_FALLBACK = 'No incidents match selected filters.'

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

const route = reactive<{ path: string; query: Record<string, string> }>({
  path: '/operations/system',
  query: {},
})

const systemStub = vi.hoisted(() => ({
  services: [] as Array<Record<string, unknown>>,
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

function installFetch(): void {
  vi.stubGlobal(
    '$fetch',
    vi.fn(() =>
      Promise.resolve({
        items: [makeIncident('incident-1')],
        retention: { max_incidents: 50, max_days: 7 },
      }),
    ),
  )
}

async function mountPage() {
  const { mountWithPlugins } = await import('../helpers/mount')
  const mod = await import('~/pages/operations/system.vue')
  return mountWithPlugins(mod.default)
}

beforeEach(() => {
  setActivePinia(createPinia())
  route.path = '/operations/system'
  route.query = { tab: 'services' }
  systemStub.services = []
  systemStub.isLoading = false
  systemStub.error = null
  systemStub.actionError = null
  navigateTo.mockClear()
  installFetch()
  ;(globalThis as Record<string, unknown>).navigateTo = navigateTo
  ;(globalThis as Record<string, unknown>).useRoute = () => route
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('Operations System — service fallback (UI-191)', () => {
  it('does not render the empty-state text under a filled service table', async () => {
    systemStub.services = [
      { name: 'otalon-api', status: 'running', image: 'otalon-suite-otalon-api', ports: '8090', core_db: false },
      { name: 'postgres', status: 'running', image: 'postgres:15', ports: '5432', core_db: true },
    ]
    const wrapper = await mountPage()
    await flushPromises()

    expect(wrapper.find('.system-services-table').exists()).toBe(true)
    expect(wrapper.text()).not.toContain(SERVICE_FALLBACK)
  })

  it('renders each service exactly once — the removed legacy list must not come back', async () => {
    systemStub.services = [
      { name: 'otalon-api', status: 'running', image: 'otalon-suite-otalon-api', ports: '8090', core_db: false },
      { name: 'postgres', status: 'running', image: 'postgres:15', ports: '5432', core_db: true },
    ]
    const wrapper = await mountPage()
    await flushPromises()

    const exactNameNodes = wrapper
      .findAll('*')
      .filter((node) => node.element.children.length === 0 && node.text() === 'otalon-api')
    expect(exactNameNodes).toHaveLength(1)
    expect(wrapper.findAll('.system-services-table tbody tr')).toHaveLength(2)
  })

  it('renders the empty-state text when the service list is empty and loading finished', async () => {
    const wrapper = await mountPage()
    await flushPromises()

    expect(wrapper.text()).toContain(SERVICE_FALLBACK)
  })

  it('renders the empty-state text while the first load is still running', async () => {
    systemStub.isLoading = true
    const wrapper = await mountPage()
    await flushPromises()

    expect(wrapper.text()).not.toContain(SERVICE_FALLBACK)
  })
})

describe('Operations System — incident fallback (UI-191)', () => {
  it('does not render the empty-state text under a filled incident list', async () => {
    route.query = { tab: 'health' }
    const wrapper = await mountPage()
    await flushPromises()

    const store = useHealthIncidentsStore()
    store.history = [makeIncident('incident-1'), makeIncident('incident-2')]
    await flushPromises()

    expect(wrapper.findAll('.q-item').filter((n) => n.text().includes('cause incident-1'))).toHaveLength(1)
    expect(wrapper.text()).not.toContain(INCIDENT_FALLBACK)
  })

  it('renders the empty-state text when no incident matches the filters', async () => {
    route.query = { tab: 'health' }
    const wrapper = await mountPage()
    await flushPromises()

    const store = useHealthIncidentsStore()
    store.history = []
    await flushPromises()

    expect(wrapper.text()).toContain(INCIDENT_FALLBACK)
  })

  it('keeps the acknowledge error banner independent of the empty-state text', async () => {
    route.query = { tab: 'health' }
    const wrapper = await mountPage()
    await flushPromises()

    const store = useHealthIncidentsStore()
    store.history = [makeIncident('incident-1')]
    store.acknowledgeError = 'backend down'
    await flushPromises()

    expect(wrapper.find('[data-test="acknowledge-error"]').exists()).toBe(true)
    expect(wrapper.text()).not.toContain(INCIDENT_FALLBACK)
  })
})
