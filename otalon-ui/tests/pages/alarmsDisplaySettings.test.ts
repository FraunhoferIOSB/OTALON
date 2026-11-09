/**
 * Page-level tests for the UI-176 alarms-list display-settings contract.
 *
 * Asserts that the default column-visibility set shows the new relative
 * "Age" column while hiding Start/End Time, and that toggling those
 * columns back on via the display-settings dialog re-enables them. The
 * real ``alarms.vue`` is mounted against MSW golden alarm-groups data;
 * ``AlarmGroupTable`` and ``SharedDisplaySettingsDialog`` are capturing
 * stubs so the ``visibleColumns`` prop and the dialog ``modelValue`` are
 * observable without rendering the full Quasar table/dialog.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { defineComponent } from 'vue'

import { useAlarmsStore } from '~/stores/alarmsStore'
import { useAppStore } from '~/stores/appStore'
import { useDisplaySettings } from '~/composables/useDisplaySettings'
import type { DisplaySettingsValue } from '~/components/shared/DisplaySettingsDialog.vue'

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

// Capturing stubs: named so they are findable via findComponent({ name }).
const AlarmGroupTableStub = defineComponent({
  name: 'AlarmGroupTable',
  props: ['groups', 'visibleColumns', 'rowsPerPage', 'selectedGroupId'],
  template: '<div data-testid="group-table" />',
})

const DisplaySettingsDialogStub = defineComponent({
  name: 'SharedDisplaySettingsDialog',
  props: ['modelValue', 'open', 'tableColumns'],
  emits: ['update:modelValue', 'update:open', 'reset', 'commit'],
  template: '<div data-testid="display-settings" />',
})

const PAGE_STUBS = {
  SharedTimeToolbarRow: { template: '<div />' },
  SharedErrorBanner: { template: '<div />' },
  AlarmGroupTable: AlarmGroupTableStub,
  AlarmDetailPanel: { template: '<div />' },
  SharedDisplaySettingsDialog: DisplaySettingsDialogStub,
  'q-splitter': { template: '<div class="q-splitter" />' },
}

async function mountAlarms(): ReturnType<(typeof import('../helpers/mount'))['mountWithPlugins']> {
  globalThis.useRoute = vi.fn(() => ({ meta: {}, query: {}, params: {}, path: '/alarms' }))
  const { mountWithPlugins } = await import('../helpers/mount')
  const mod = await import('~/pages/alarms.vue')
  const wrapper = mountWithPlugins(mod.default, { global: { stubs: PAGE_STUBS } })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  // Force the narrow-viewport (dialog) layout branch so only the single
  // non-splitter AlarmGroupTable mounts and is findable.
  Object.defineProperty(window, 'innerWidth', { value: 1024, writable: true, configurable: true })
  if (typeof window !== 'undefined') window.localStorage.clear()
})

afterEach(() => {
  globalThis.useRoute = originalUseRoute
  vi.clearAllMocks()
})

describe('alarms page — column display settings (UI-176)', () => {
  it('shows the Age column and hides Start/End Time by default', async () => {
    const wrapper = await mountAlarms()
    const table = wrapper.findComponent({ name: 'AlarmGroupTable' })
    const visible = table.props('visibleColumns') as string[]

    expect(visible).toContain('relative')
    expect(visible).not.toContain('start_timestamp')
    expect(visible).not.toContain('end_timestamp')
  })

  it('re-enables Start/End Time when their display-settings toggles are turned on', async () => {
    const wrapper = await mountAlarms()
    const table = wrapper.findComponent({ name: 'AlarmGroupTable' })
    const dialog = wrapper.findComponent({ name: 'SharedDisplaySettingsDialog' })

    // Simulate the operator turning the Start/End Time toggles on.
    const current = dialog.props('modelValue') as DisplaySettingsValue
    dialog.vm.$emit('update:modelValue', {
      ...current,
      visibleColumns: { ...current.visibleColumns, start_timestamp: true, end_timestamp: true },
    })
    await flushPromises()

    const visible = table.props('visibleColumns') as string[]
    expect(visible).toContain('start_timestamp')
    expect(visible).toContain('end_timestamp')
    // The Age column stays visible alongside the re-enabled timestamps.
    expect(visible).toContain('relative')
  })
})
