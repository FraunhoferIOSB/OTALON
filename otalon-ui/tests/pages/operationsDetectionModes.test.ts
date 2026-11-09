/**
 * Component tests for the UI-080 Round 3 "Detection modes" operator surface.
 *
 * Cover the four operator-reported regressions:
 *   1. every readiness card names Bounds *and* Frequency as enabled/disabled,
 *      sourced from the same runtime gate state the dialog's toggles bind to,
 *      and keeps the raw count next to it;
 *   2. the dialog's info tooltip trigger sits in the same row as the title;
 *   3. the error alert is absent from the DOM while idle and only mounts once
 *      a real Apply failure produced a message;
 *   4. an Apply carrying a Bounds or a Frequency toggle change reaches the
 *      runtime-job endpoint and is reported as success.
 *
 * Both stores are stubbed, so no network call is made.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { h, type Component } from 'vue'

import type { DetectionModule } from '~/stores/detectionStore'
import type { RuntimeConfigItem, RuntimeConfigWrite } from '~/types/api'

vi.mock('~/composables/usePolling', () => ({ usePolling: () => ({ pause: vi.fn(), resume: vi.fn() }) }))
const operationsRefresh = {
  register: vi.fn(),
  unregister: vi.fn(),
  refresh: vi.fn().mockResolvedValue(undefined),
  isAvailable: { value: true },
  isLoading: { value: false },
}
vi.mock('~/composables/useOperationsRefresh', () => ({
  OPERATIONS_HEAVY_POLL_INTERVAL_MS: 30_000,
  useOperationsRefresh: () => operationsRefresh,
}))

const notify = vi.fn()
vi.mock('quasar', () => ({ useQuasar: () => ({ notify }) }))

const GATE_MODULES = ['conn', 'mac_traffic', 'proto_traffic'] as const

function readinessItem(module: string, overrides: Partial<DetectionModule> = {}): DetectionModule {
  return {
    module,
    state: 'ready',
    detection_mode: 'active',
    bounds_series_count: 38,
    no_bounds_count: 0,
    no_bounds_event_count: 0,
    no_bounds_series_count: 0,
    frequency_profile_count: 36,
    last_training: '2026-08-01T10:00:00+00:00',
    schema_version: 'bounds-v1',
    schema_compatible: true,
    classification_state: 'disabled',
    bounds_state: 'enabled',
    frequency_state: 'enabled',
    ...overrides,
  } as DetectionModule
}

function makeStoreStub() {
  return {
    modules: GATE_MODULES.map((module) => readinessItem(module)),
    bounds: [],
    artifacts: [],
    baselines: [],
    loading: false,
    error: null,
    boundsError: null,
    activeTrainingJob: null,
    trainingError: null,
    retrainCooldownActive: false,
    retrainCooldownRemainingSeconds: 0,
    retrainCooldownTick: 0,
    trainingBusy: false,
    totalNoBounds: 0,
    livePollIntervalSeconds: 5,
    load: vi.fn().mockResolvedValue(undefined),
    filterBounds: vi.fn().mockResolvedValue(undefined),
    reconcileTrainingStatus: vi.fn().mockResolvedValue(undefined),
    refreshReadiness: vi.fn().mockResolvedValue(undefined),
    fetchSeriesTimeseries: vi.fn().mockResolvedValue([]),
    advanceRetrainCooldown: vi.fn(),
    createBaseline: vi.fn(),
    startBoundsTraining: vi.fn(),
    startClassifierTraining: vi.fn(),
  }
}

const runtimeItem = (key: string, value: string): RuntimeConfigItem => ({
  service: 'otalon-clas',
  key,
  value,
  value_prev: null,
  updated_at: null,
  updated_by: null,
  type: 'bool',
  domain: null,
  description: key,
})

/** Runtime keys as the live control plane returns them for all three targets. */
function makeRuntimeItems(overrides: Record<string, string> = {}): RuntimeConfigItem[] {
  const items: RuntimeConfigItem[] = []
  for (const module of GATE_MODULES) {
    for (const gate of ['bounds_enabled', 'classification_enabled', 'frequency_enabled']) {
      const key = `detection.${module}.${gate}`
      items.push(runtimeItem(key, overrides[key] ?? 'true'))
    }
  }
  return items
}

function makeConfigurationStub() {
  return {
    runtime: makeRuntimeItems(),
    runtimeError: '',
    fetchRuntime: vi.fn().mockResolvedValue(undefined),
    fetchRuntimeStrict: vi.fn().mockResolvedValue(undefined),
    saveRuntimeJob: vi.fn<(requests: RuntimeConfigWrite[]) => Promise<unknown>>().mockResolvedValue({ job: { id: 1 } }),
  }
}

let storeStub = makeStoreStub()
let configurationStub = makeConfigurationStub()

vi.mock('~/stores/detectionStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('~/stores/detectionStore')>()
  return { ...actual, useDetectionStore: () => storeStub }
})
vi.mock('~/stores/configurationStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('~/stores/configurationStore')>()
  return { ...actual, useConfigurationStore: () => configurationStub }
})

const passthrough = (tag: string): Component => ({
  setup:
    (
      _props: unknown,
      { slots, attrs }: { slots: Record<string, undefined | (() => unknown)>; attrs: Record<string, unknown> },
    ) =>
    () =>
      h(tag, attrs, slots.default?.() ?? []),
})

const extraStubs = {
  'q-drawer': passthrough('aside'),
  'q-scroll-area': passthrough('div'),
  CdStateBadge: { props: ['label', 'kind'], template: '<span class="state-badge">{{ label }}</span>' },
  StateBadge: { props: ['label', 'kind'], template: '<span class="state-badge">{{ label }}</span>' },
  TimeseriesChart: { props: ['data', 'showBounds', 'showViolations', 'height'], template: '<div class="ts-chart" />' },
}

async function mountPage() {
  const { mountWithPlugins } = await import('../helpers/mount')
  const mod = await import('~/pages/operations/detection.vue')
  const wrapper = mountWithPlugins(mod.default, { global: { stubs: extraStubs } })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  storeStub = makeStoreStub()
  configurationStub = makeConfigurationStub()
  notify.mockReset()
  operationsRefresh.register.mockReset()
  operationsRefresh.unregister.mockReset()
  operationsRefresh.refresh.mockReset().mockResolvedValue(undefined)
  localStorage.clear()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Fix 1 — Bounds and Frequency report an explicit enabled/disabled state', () => {
  it('labels both gates on every detection target card, keeping the raw count', async () => {
    const wrapper = await mountPage()

    for (const module of GATE_MODULES) {
      const bounds = wrapper.get(`[data-test="bounds-gate-state-${module}"]`)
      const frequency = wrapper.get(`[data-test="frequency-gate-state-${module}"]`)
      expect(bounds.text()).toContain('38')
      expect(bounds.text()).toContain('enabled')
      expect(frequency.text()).toContain('36')
      expect(frequency.text()).toContain('enabled')
    }
  })

  it('reads the same runtime gate state the dialog toggles bind to', async () => {
    configurationStub.runtime = makeRuntimeItems({
      'detection.conn.bounds_enabled': 'false',
      'detection.proto_traffic.frequency_enabled': 'false',
    })
    const wrapper = await mountPage()

    expect(wrapper.get('[data-test="bounds-gate-state-conn"]').text()).toContain('disabled')
    expect(wrapper.get('[data-test="frequency-gate-state-conn"]').text()).toContain('enabled')
    expect(wrapper.get('[data-test="frequency-gate-state-proto_traffic"]').text()).toContain('disabled')
    expect(wrapper.get('[data-test="bounds-gate-state-proto_traffic"]').text()).toContain('enabled')
  })

  it('still renders classification as its own enabled/disabled state', async () => {
    const wrapper = await mountPage()
    expect(wrapper.get('[data-test="classification-gate-state-conn"]').text()).toBe('disabled')
  })
})

describe('Fix 2 — the dialog info tooltip sits next to the title', () => {
  it('renders the help trigger as a sibling of the title in the same header row', async () => {
    const wrapper = await mountPage()
    await wrapper.get('[data-test="change-detection-gates-conn"]').trigger('click')
    await flushPromises()

    const help = wrapper.get('[data-test="detection-gates-help"]')
    const header = help.element.parentElement
    expect(header).not.toBeNull()
    expect(header?.className).toContain('row')
    const title = header?.querySelector('#detection-gates-title')
    expect(title).not.toBeNull()
    expect(title?.textContent).toContain('Detection modes: Connections')
    // The icon must directly follow the title, not sit on its own line.
    expect(title?.nextElementSibling).toBe(help.element)
  })
})

describe('Fix 3 — the error alert is conditionally rendered', () => {
  it('does not mount the alert element while the dialog is idle', async () => {
    const wrapper = await mountPage()
    await wrapper.get('[data-test="change-detection-gates-conn"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[data-test="detection-gates-dialog"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="gate-error"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="gate-reason-error"]').exists()).toBe(false)
  })

  it('mounts the alert only after a failed Apply and reports the server message', async () => {
    configurationStub.saveRuntimeJob.mockRejectedValueOnce(new Error('Internal Server Error'))
    const wrapper = await mountPage()
    await wrapper.get('[data-test="change-detection-gates-conn"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="gate-error"]').exists()).toBe(false)

    await wrapper.get('[data-test="live-bounds-toggle"] input').setValue(false)
    await wrapper.get('[data-test="apply-live-gates"]').trigger('click')
    await flushPromises()

    const alert = wrapper.get('[data-test="gate-error"]')
    expect(alert.text()).toContain('Internal Server Error')
    expect(alert.attributes('role')).toBe('alert')
  })
})

describe('Fix 4 — Apply succeeds for Bounds and Frequency toggle changes', () => {
  it.each([
    ['live-bounds-toggle', 'detection.conn.bounds_enabled'],
    ['live-frequency-toggle', 'detection.conn.frequency_enabled'],
  ])('submits a runtime job for the %s change', async (toggle, expectedKey) => {
    const wrapper = await mountPage()
    await wrapper.get('[data-test="change-detection-gates-conn"]').trigger('click')
    await flushPromises()

    await wrapper.get(`[data-test="${toggle}"] input`).setValue(false)
    await wrapper.get('[data-test="apply-live-gates"]').trigger('click')
    await flushPromises()

    expect(configurationStub.saveRuntimeJob).toHaveBeenCalledTimes(1)
    expect(configurationStub.saveRuntimeJob).toHaveBeenCalledWith([
      expect.objectContaining({ service: 'otalon-clas', key: expectedKey, value: 'false' }),
    ])
    expect(wrapper.find('[data-test="gate-error"]').exists()).toBe(false)
    expect(notify).toHaveBeenCalledWith(expect.objectContaining({ type: 'positive' }))
  })

  it('keeps Apply disabled until a gate actually changed', async () => {
    // The `changed` guard reads through an unwrapped computed; before the
    // Fix 3 unwrap it was a always-truthy Ref and could never disable Apply.
    const wrapper = await mountPage()
    await wrapper.get('[data-test="change-detection-gates-conn"]').trigger('click')
    await flushPromises()

    const vm = wrapper.vm as unknown as { gateChanged: boolean }
    expect(vm.gateChanged).toBe(false)

    await wrapper.get('[data-test="live-frequency-toggle"] input').setValue(false)
    await flushPromises()
    expect(vm.gateChanged).toBe(true)
  })
})
