/**
 * Page-level tests for the UI-175 alarm-route-selection contract.
 *
 * Asserts that mounting the alarms page with a ``?group=<id>`` query
 * selects exactly that alarm group (not the topmost), that mounting
 * without the param selects the topmost group, and that an unknown id
 * falls back to the topmost. The real ``useAlarmsStore`` is exercised
 * against the MSW golden alarm-groups handler; every other page
 * dependency is stubbed or mocked.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'

import { useAlarmsStore } from '~/stores/alarmsStore'
import { useAppStore } from '~/stores/appStore'
import { useDisplaySettings } from '~/composables/useDisplaySettings'
import { GOLDEN_ALARM_GROUPS } from '../mocks/golden-data'

vi.mock('quasar', () => ({ useQuasar: () => ({ notify: vi.fn() }) }))
vi.mock('~/composables/useNavigation', () => ({ DOMAIN_ICONS: { connections: 'device_hub' } }))
vi.mock('~/composables/useChatContext', () => ({ provideChatContext: () => {} }))
vi.mock('~/utils/chatContext', () => ({ buildAlarmsContribution: () => ({}) }))
vi.mock('~/stores/subagentStore', () => ({
  useSubagentStore: () => ({ jobsByAlarm: {}, liveJobsById: {}, loadLatestFullJobs: vi.fn() }),
}))

// Auto-imported (no import statement in the SFC) stores/composables must be
// registered as globals so the compiled <script setup> can resolve them.
globalThis.useAlarmsStore = useAlarmsStore
globalThis.useAppStore = useAppStore
globalThis.useDisplaySettings = useDisplaySettings
globalThis.useSse = () => {}
globalThis.usePolling = () => {}

const originalUseRoute = globalThis.useRoute

const TOP_GROUP = GOLDEN_ALARM_GROUPS[0]
const MIDDLE_GROUP = GOLDEN_ALARM_GROUPS[1]

const PAGE_STUBS = {
  SharedTimeToolbarRow: { template: '<div />' },
  SharedErrorBanner: { template: '<div />' },
  AlarmGroupTable: { template: '<div data-testid="group-table" />' },
  AlarmDetailPanel: { template: '<div data-testid="detail-panel" />' },
  SharedDisplaySettingsDialog: { template: '<div />' },
  'q-splitter': { template: '<div class="q-splitter" />' },
}

async function mountAlarms(query: Record<string, unknown>) {
  globalThis.useRoute = vi.fn(() => ({ meta: {}, query, params: {}, path: '/alarms' }))
  const { mountWithPlugins } = await import('../helpers/mount')
  const mod = await import('~/pages/alarms.vue')
  const wrapper = mountWithPlugins(mod.default, { global: { stubs: PAGE_STUBS } })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  // Force the narrow-viewport (dialog) layout branch so the q-splitter
  // block is skipped and the page renders its simpler alarm-list path.
  Object.defineProperty(window, 'innerWidth', { value: 1024, writable: true, configurable: true })
})

afterEach(() => {
  globalThis.useRoute = originalUseRoute
  vi.clearAllMocks()
})

describe('alarms page — ?group= query selection (UI-175)', () => {
  it('selects the alarm group named by ?group=<id>, not the topmost', async () => {
    await mountAlarms({ group: MIDDLE_GROUP.id })
    const store = useAlarmsStore()

    expect(store.selectedGroupId).toBe(MIDDLE_GROUP.id)
    expect(store.selectedGroupId).not.toBe(TOP_GROUP.id)
  })

  it('selects the topmost group when no ?group= param is present', async () => {
    await mountAlarms({})
    const store = useAlarmsStore()

    expect(store.selectedGroupId).toBe(TOP_GROUP.id)
  })

  it('falls back to the topmost group when ?group=<id> does not match any loaded group', async () => {
    await mountAlarms({ group: 'nonexistent-alarm-id-0000' })
    const store = useAlarmsStore()

    expect(store.selectedGroupId).toBe(TOP_GROUP.id)
  })
})
