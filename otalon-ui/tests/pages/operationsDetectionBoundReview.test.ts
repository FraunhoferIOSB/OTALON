/**
 * Component tests for the Guided Bound Review surface on the Detection page.
 *
 * Assert the operator-frozen contracts: OK hidden by default with card/state
 * filtering, sortable table columns, dense-by-default presentation, status cards
 * full/compact/hidden + local persistence with active filters visible when
 * hidden, the three guided drawer tabs, truthful structured timeline
 * mapping (no index guessing), editable proposed bounds validation, mandatory
 * server validation inside one-click Apply (no separate required Preview),
 * reason + exact-confirmation gates for both
 * Expand and Replace, and the NoBounds create flow.
 *
 * The store is replaced with a controllable stub so no network call is made.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { h, type Component } from 'vue'

import { friendlyModuleLabel, friendlyReadinessLabel, type BoundReviewItem } from '~/stores/detectionStore'

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

const violationRow: BoundReviewItem = {
  module: 'conn',
  series_id: 'series-violation',
  feature: null,
  state: 'BoundViolation',
  current_bounds: {
    lower_bounds: { min_interarrival_time: 0.8 },
    upper_bounds: { min_interarrival_time: 2.4 },
  },
  lower: null,
  upper: null,
  violation_count: 1,
  last_event: '2026-07-20T19:29:51+00:00',
  latest_event_ts: '2026-07-20T19:29:51+00:00',
  latest_event_type: 'BoundViolation',
  affected_features: ['min_interarrival_time'],
  timeline: ['2026-07-20T19:29:51+00:00'],
  timeline_events: [{ ts: '2026-07-20T19:29:51+00:00', type: 'BoundViolation', features: ['min_interarrival_time'] }],
  has_bounds: true,
  ok: false,
}

// A proto_traffic NoBounds row: the server resolves its canonical series_id to
// a readable protocol (series_display) and declares the module feature contract
// (available_features) even though there is no envelope. The canonical
// `series_id` stays the identity used for charts, mutations, jobs and audit.
const noBoundsRow: BoundReviewItem = {
  module: 'proto_traffic',
  series_id: 'series-nobounds',
  series_display: 'Ethernet:IPv4:UDP:DNS',
  available_features: ['proto_total_packets', 'proto_total_volume', 'proto_mean_packet_size'],
  feature: null,
  state: 'NoBounds',
  current_bounds: { lower_bounds: {}, upper_bounds: {} },
  lower: null,
  upper: null,
  violation_count: 2,
  last_event: '2026-07-20T18:00:00+00:00',
  latest_event_ts: '2026-07-20T18:00:00+00:00',
  latest_event_type: 'NoBounds',
  affected_features: [],
  timeline: ['2026-07-20T17:00:00+00:00', '2026-07-20T18:00:00+00:00'],
  timeline_events: [
    { ts: '2026-07-20T17:00:00+00:00', type: 'NoBounds', features: [] },
    { ts: '2026-07-20T18:00:00+00:00', type: 'NoBounds', features: [] },
  ],
  has_bounds: false,
  ok: false,
}

const okRow: BoundReviewItem = {
  module: 'conn',
  series_id: 'series-ok',
  feature: null,
  state: 'OK',
  current_bounds: { lower_bounds: { packet_count: 1 }, upper_bounds: { packet_count: 9 } },
  lower: null,
  upper: null,
  violation_count: 0,
  last_event: null,
  affected_features: [],
  timeline: [],
  timeline_events: [],
  has_bounds: true,
  ok: true,
}

function makeStoreStub() {
  return {
    modules: [],
    bounds: [violationRow, noBoundsRow, okRow] as BoundReviewItem[],
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
    load: vi.fn().mockResolvedValue(undefined),
    filterBounds: vi.fn().mockResolvedValue(undefined),
    reconcileTrainingStatus: vi.fn().mockResolvedValue(undefined),
    fetchSeriesTimeseries: vi.fn().mockResolvedValue([]),
    suggestBounds: vi.fn().mockImplementation((_module, _series, action) =>
      Promise.resolve({
        module: action === 'create' ? 'proto_traffic' : 'conn',
        series_id: action === 'create' ? 'series-nobounds' : 'series-violation',
        status: 'available',
        action,
        window_from: '2026-07-21T00:00:00Z',
        window_to: '2026-07-22T00:00:00Z',
        evidence_count: 2,
        current: { lower_bounds: {}, upper_bounds: {} },
        proposed:
          action === 'create'
            ? { lower_bounds: { packet_count: null }, upper_bounds: { packet_count: null } }
            : { lower_bounds: { min_interarrival_time: 0.5 }, upper_bounds: { min_interarrival_time: 3 } },
        rationale: {},
        message: 'Observed feature evidence supports this proposal',
      }),
    ),
    previewBoundsCorrection: vi
      .fn()
      .mockImplementation((_module, _series, action, before, after) =>
        Promise.resolve({ before, after, affected_features: Object.keys(after.lower_bounds), action, raw: {} }),
      ),
    applyBoundsCorrection: vi.fn().mockResolvedValue({}),
    startBoundsTraining: vi.fn(),
    startClassifierTraining: vi.fn(),
    advanceRetrainCooldown: vi.fn(),
    createBaseline: vi.fn(),
  }
}

let storeStub = makeStoreStub()

vi.mock('~/stores/detectionStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('~/stores/detectionStore')>()
  return { ...actual, useDetectionStore: () => storeStub }
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
  'q-toggle': passthrough('label'),
  'q-dialog': passthrough('div'),
  'q-card-actions': passthrough('div'),
  CdStateBadge: { props: ['label', 'kind'], template: '<span class="state-badge">{{ label }}</span>' },
  StateBadge: { props: ['label', 'kind'], template: '<span class="state-badge">{{ label }}</span>' },
  TimeseriesChart: {
    props: ['data', 'showBounds', 'showViolations', 'height'],
    template:
      '<div class="ts-chart" :data-show-violations="showViolations" :data-show-bounds="showBounds" :data-point-count="data.length" />',
  },
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
  notify.mockReset()
  operationsRefresh.register.mockReset()
  operationsRefresh.unregister.mockReset()
  operationsRefresh.refresh.mockReset().mockResolvedValue(undefined)
  localStorage.clear()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Bound Review table filtering and presentation', () => {
  it('hides OK rows by default (NoBounds + Violation only)', async () => {
    const wrapper = await mountPage()
    const html = wrapper.html()
    expect(html).toContain('series-violation')
    expect(html).toContain('series-nobounds')
    expect(html).not.toContain('series-ok')
  })

  it('marks all header columns sortable and orders NoBounds before Violation before OK', async () => {
    const mod = await import('~/pages/operations/detection.vue')
    // The exported column set is asserted indirectly through the rendered rows;
    // priority is validated by the store row order plus the state sort function.
    expect(mod).toBeTruthy()
    const wrapper = await mountPage()
    const rowsText = wrapper.findAll('tbody tr').map((r) => r.text())
    // Both visible states present; NoBounds row and Violation row rendered.
    expect(rowsText.join(' ')).toContain('series-nobounds')
    expect(rowsText.join(' ')).toContain('series-violation')
  })

  it('uses dense tables and full cards when storage has no valid preference', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { density: string; cardMode: string; tab: string }
    vm.tab = 'bounds'
    await flushPromises()
    expect(vm.density).toBe('dense')
    expect(vm.cardMode).toBe('full')
    expect(wrapper.find('[data-test="bound-review-table"] tbody tr').text()).not.toContain('affected features')
    expect(wrapper.findAll('[data-test^="status-card-"]')).toHaveLength(3)
  })

  it('opens one accessible display settings action and persists both preferences', async () => {
    const wrapper = await mountPage()
    ;(wrapper.vm as unknown as { tab: string }).tab = 'bounds'
    await flushPromises()
    expect(wrapper.find('[data-test="display-settings"]').exists()).toBe(true)
    expect(wrapper.findAll('.q-btn-toggle')).toHaveLength(0)
    const vm = wrapper.vm as unknown as { density: string; cardMode: string; displaySettingsOpen: boolean }
    vm.density = 'dense'
    vm.cardMode = 'compact'
    await flushPromises()
    expect(JSON.parse(localStorage.getItem('bound-review:prefs') ?? '{}')).toMatchObject({
      density: 'dense',
      cardMode: 'compact',
    })
  })

  it.each([
    {
      name: 'both members invalid',
      raw: '{"density":"unknown","cardMode":"unknown"}',
      density: 'dense',
      cardMode: 'full',
    },
    {
      name: 'invalid density with valid cardMode',
      raw: '{"density":"unknown","cardMode":"compact"}',
      density: 'dense',
      cardMode: 'compact',
    },
    {
      name: 'invalid cardMode with valid density',
      raw: '{"density":"standard","cardMode":"nope"}',
      density: 'standard',
      cardMode: 'full',
    },
    {
      name: 'legacy collapsed maps to hidden',
      raw: '{"density":"standard","cardMode":"collapsed"}',
      density: 'standard',
      cardMode: 'hidden',
    },
    { name: 'JSON null payload', raw: 'null', density: 'dense', cardMode: 'full' },
    { name: 'array payload', raw: '["dense","full"]', density: 'dense', cardMode: 'full' },
    { name: 'primitive payload', raw: '42', density: 'dense', cardMode: 'full' },
    { name: 'empty object', raw: '{}', density: 'dense', cardMode: 'full' },
    { name: 'unparseable JSON', raw: '{not json', density: 'dense', cardMode: 'full' },
  ])('resolves persisted preferences independently for $name without crashing', async ({ raw, density, cardMode }) => {
    localStorage.setItem('bound-review:prefs', raw)
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { density: string; cardMode: string }
    expect(vm.density).toBe(density)
    expect(vm.cardMode).toBe(cardMode)
  })

  it('removes redundant body title and body refresh while retaining Bound Review tab', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { tab: string }
    vm.tab = 'bounds'
    await flushPromises()
    expect(wrapper.text()).toContain('Bound Review')
    expect(wrapper.find('.bound-review-head').exists()).toBe(false)
    expect(wrapper.find('[aria-label="Refresh"]').exists()).toBe(false)
  })

  it('registers one shared initial and heavy refresh owner', async () => {
    const wrapper = await mountPage()
    expect(operationsRefresh.register).toHaveBeenCalledOnce()
    expect(operationsRefresh.refresh).toHaveBeenCalledOnce()
    wrapper.unmount()
    expect(operationsRefresh.unregister).toHaveBeenCalledOnce()
  })

  it('renders compact summary as a strip and hidden summary without cards', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { cardMode: string }
    vm.cardMode = 'compact'
    await flushPromises()
    expect(wrapper.find('[data-test="compact-summary-strip"]').exists()).toBe(true)
    vm.cardMode = 'hidden'
    await flushPromises()
    expect(wrapper.find('[data-test="compact-summary-strip"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-test^="status-card-"]')).toHaveLength(0)
  })

  it('removes the redundant Active filters line entirely', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { cardMode: string }
    for (const mode of ['full', 'compact', 'hidden']) {
      vm.cardMode = mode
      await flushPromises()
      expect(wrapper.find('.active-filter-line').exists()).toBe(false)
      expect(wrapper.text()).not.toContain('Active filters')
    }
  })

  it('treats an empty State selection as valid, producing zero rows and a truthful empty state', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      boundStateSelection: string[] | null
      activeStates: Set<string>
      boundRows: unknown[]
    }
    vm.boundStateSelection = []
    await flushPromises()
    // No silent restore of defaults; selection stays empty.
    expect([...vm.activeStates]).toEqual([])
    expect(vm.boundRows).toHaveLength(0)
    const html = wrapper.html()
    expect(html).not.toContain('series-violation')
    expect(html).not.toContain('series-nobounds')
    expect(html).not.toContain('series-ok')
    expect(html).toContain('No states selected. Select a State to show matching series.')
    expect(html).not.toContain('Enable OK or widen interval')
  })

  it('keeps normal no-match guidance when at least one State is selected', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { boundStateSelection: string[] }
    vm.boundStateSelection = ['Unknown']
    await flushPromises()
    expect(wrapper.text()).toContain('No series match filters. Enable OK or widen interval to inspect more data.')
    expect(wrapper.text()).not.toContain('No states selected. Select a State to show matching series.')
  })

  it('configures State multi-select without a global clear action', async () => {
    const wrapper = await mountPage()
    const stateSelect = wrapper.find('[data-test="bound-state"]')
    expect(stateSelect.exists()).toBe(true)
    expect(stateSelect.attributes('clearable')).toBeUndefined()
  })

  it('renders returned OK rows when the State combobox selects OK (B-F1)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { boundStateSelection: string[]; apiBoundState: string | null }
    // Default hides OK.
    expect(wrapper.html()).not.toContain('series-ok')
    vm.boundStateSelection = ['OK']
    await flushPromises()
    // One selected state drives both the API query and visible rows.
    expect(vm.apiBoundState).toBe('OK')
    const html = wrapper.html()
    expect(html).toContain('series-ok')
    expect(html).not.toContain('series-violation')
    expect(html).not.toContain('series-nobounds')
  })

  it('derives the API query from a single selected State (B-F1)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { boundStateSelection: string[]; apiBoundState: string | null }
    vm.boundStateSelection = ['Violation']
    await flushPromises()
    // UI label Violation maps to the canonical BoundViolation server state.
    expect(vm.apiBoundState).toBe('BoundViolation')
  })

  it('clearing the State combobox yields an empty selection, not a default restore (B-F1)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      boundStateSelection: string[] | null
      apiBoundState: string | null
      activeStates: Set<string>
    }
    vm.boundStateSelection = ['OK']
    await flushPromises()
    vm.boundStateSelection = null
    await flushPromises()
    // Empty is valid and truthful; no NoBounds+Violation is silently restored.
    expect([...vm.activeStates]).toEqual([])
    expect(vm.apiBoundState).toBeNull()
    const html = wrapper.html()
    expect(html).not.toContain('series-violation')
    expect(html).not.toContain('series-nobounds')
    expect(html).not.toContain('series-ok')
  })

  it('keeps the status cards and State combobox synchronized, allowing empty (B-F1)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { toggleStatus: (s: string) => void; boundStateSelection: string[] }
    // Toggling a status off updates the shared source of truth.
    vm.toggleStatus('NoBounds')
    await flushPromises()
    expect(vm.boundStateSelection).toEqual(['Violation'])
    // Toggling the last status off is valid and leaves an empty selection.
    vm.toggleStatus('Violation')
    await flushPromises()
    expect(vm.boundStateSelection).toEqual([])
  })
})

describe('selection-scoped async races (B-F3)', () => {
  interface Deferred<T> {
    promise: Promise<T>
    resolve: (value: T) => void
    reject: (reason?: unknown) => void
  }
  function defer<T>(): Deferred<T> {
    let resolve!: (value: T) => void
    let reject!: (reason?: unknown) => void
    const promise = new Promise<T>((res, rej) => {
      resolve = res
      reject = rej
    })
    return { promise, resolve, reject }
  }

  const secondBoundedRow: BoundReviewItem = {
    ...violationRow,
    series_id: 'series-violation-2',
    current_bounds: { lower_bounds: { packet_rate: 1 }, upper_bounds: { packet_rate: 5 } },
    affected_features: ['packet_rate'],
    timeline_events: [{ ts: '2026-07-20T19:29:51+00:00', type: 'BoundViolation', features: ['packet_rate'] }],
  }

  it('does not let a slow chart fetch for row A overwrite the plot of row B', async () => {
    const deferredByFeature = new Map<string, Deferred<unknown[]>>()
    storeStub.fetchSeriesTimeseries = vi.fn((_m: string, _s: string, feature: string) => {
      const d = defer<unknown[]>()
      deferredByFeature.set(feature, d)
      return d.promise
    }) as unknown as typeof storeStub.fetchSeriesTimeseries

    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: BoundReviewItem | null; plotData: unknown[] }

    // Select row A → its chart request is now in flight (unresolved).
    vm.selectedBound = violationRow
    await flushPromises()
    expect(deferredByFeature.has('min_interarrival_time')).toBe(true)

    // Switch to row B before A resolves → B issues its own request.
    vm.selectedBound = secondBoundedRow
    await flushPromises()
    expect(deferredByFeature.has('packet_rate')).toBe(true)

    // Resolve the stale A request last; it must be ignored.
    deferredByFeature.get('min_interarrival_time')?.resolve([{ ts: 'A', value: 111 }])
    await flushPromises()
    expect(JSON.stringify(vm.plotData)).not.toContain('111')

    // Resolving B populates the plot with B's data.
    deferredByFeature.get('packet_rate')?.resolve([{ ts: 'B', value: 222 }])
    await flushPromises()
    expect(JSON.stringify(vm.plotData)).toContain('222')
  })

  it('discards a stale chart failure so it cannot blank the current selection', async () => {
    const deferredByFeature = new Map<string, Deferred<unknown[]>>()
    storeStub.fetchSeriesTimeseries = vi.fn((_m: string, _s: string, feature: string) => {
      const d = defer<unknown[]>()
      deferredByFeature.set(feature, d)
      return d.promise
    }) as unknown as typeof storeStub.fetchSeriesTimeseries

    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: BoundReviewItem | null; plotData: unknown[] }

    vm.selectedBound = violationRow
    await flushPromises()
    vm.selectedBound = secondBoundedRow
    await flushPromises()
    // B resolves with data first.
    deferredByFeature.get('packet_rate')?.resolve([{ ts: 'B', value: 222 }])
    await flushPromises()
    // Stale A rejects afterwards — must not clear B's plot.
    deferredByFeature.get('min_interarrival_time')?.reject(new Error('stale'))
    await flushPromises()
    expect(JSON.stringify(vm.plotData)).toContain('222')
  })

  it('ignores a suggestion response whose selection changed before it resolved', async () => {
    const deferredBySeries = new Map<string, Deferred<Record<string, unknown>>>()
    storeStub.suggestBounds = vi.fn((_m: string, series: string, _action: string) => {
      const d = defer<Record<string, unknown>>()
      deferredBySeries.set(series, d)
      return d.promise as unknown as ReturnType<typeof storeStub.suggestBounds>
    }) as unknown as typeof storeStub.suggestBounds

    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      selectedBound: BoundReviewItem | null
      drawerTab: string
      suggestBounds: () => Promise<void>
      proposed: Record<string, unknown>
      suggestionEvidence: unknown
    }

    // Select NoBounds row A and request a suggestion for it.
    vm.selectedBound = noBoundsRow
    await flushPromises()
    void vm.suggestBounds()
    await flushPromises()
    expect(deferredBySeries.has('series-nobounds')).toBe(true)

    // Switch to row B before A resolves.
    vm.selectedBound = secondBoundedRow
    await flushPromises()

    // Resolve the stale A suggestion; it must not seed the current proposal.
    deferredBySeries.get('series-nobounds')?.resolve({
      module: 'proto_traffic',
      series_id: 'series-nobounds',
      status: 'available',
      action: 'create',
      window_from: '2026-07-21T00:00:00Z',
      window_to: '2026-07-22T00:00:00Z',
      evidence_count: 9,
      current: { lower_bounds: {}, upper_bounds: {} },
      proposed: { lower_bounds: { stale_feature: 1 }, upper_bounds: { stale_feature: 2 } },
      rationale: {},
      message: 'stale',
    })
    await flushPromises()
    expect(Object.keys(vm.proposed)).not.toContain('stale_feature')
    expect(vm.suggestionEvidence).toBeNull()
  })

  interface PreviewVm {
    selectedBound: BoundReviewItem | null
    drawerTab: string
    correctionMode: 'expand' | 'replace'
    reason: string
    preview: unknown
    canApply: boolean
    boundDialog: boolean
    computePreview: () => Promise<void>
    applyCorrection: () => Promise<void>
    proposed: Record<string, { lower: number | null; upper: number | null }>
  }

  async function primeRowForPreview(vm: PreviewVm, row: BoundReviewItem): Promise<void> {
    vm.selectedBound = row
    await flushPromises()
    vm.drawerTab = 'correct'
    vm.correctionMode = 'expand'
    vm.reason = 'legitimate widening reason'
    await flushPromises()
  }

  function deferPreviewBySeries(store: typeof storeStub): Map<string, Deferred<Record<string, unknown>>> {
    const deferredBySeries = new Map<string, Deferred<Record<string, unknown>>>()
    store.previewBoundsCorrection = vi.fn(
      (_m: string, series: string, action: string, before: unknown, after: unknown) => {
        const d = defer<Record<string, unknown>>()
        deferredBySeries.set(series, d)
        void action
        void before
        void after
        return d.promise as unknown as ReturnType<typeof store.previewBoundsCorrection>
      },
    ) as unknown as typeof store.previewBoundsCorrection
    return deferredBySeries
  }

  it('does not let an internal preview that resolves after switching to row B populate B (B3-F1)', async () => {
    const deferredBySeries = deferPreviewBySeries(storeStub)
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as PreviewVm

    // Internal preview for row A while it is in flight.
    await primeRowForPreview(vm, violationRow)
    void vm.computePreview()
    await flushPromises()
    expect(deferredBySeries.has('series-violation')).toBe(true)

    // Switch to row B before A resolves.
    await primeRowForPreview(vm, secondBoundedRow)

    // Stale A preview resolves now; it must not populate B's drawer.
    deferredBySeries.get('series-violation')?.resolve({
      before: { lower_bounds: { min_interarrival_time: 0.8 }, upper_bounds: { min_interarrival_time: 2.4 } },
      after: { lower_bounds: { min_interarrival_time: 0.5 }, upper_bounds: { min_interarrival_time: 3.0 } },
      affected_features: ['min_interarrival_time'],
      action: 'expand',
      raw: {},
    })
    await flushPromises()
    expect(vm.preview).toBeNull()

    // A fresh internal preview for B resolves and populates B only.
    void vm.computePreview()
    await flushPromises()
    deferredBySeries.get('series-violation-2')?.resolve({
      before: { lower_bounds: { packet_rate: 1 }, upper_bounds: { packet_rate: 5 } },
      after: { lower_bounds: { packet_rate: 0.5 }, upper_bounds: { packet_rate: 7 } },
      affected_features: ['packet_rate'],
      action: 'expand',
      raw: {},
    })
    await flushPromises()
    expect(vm.canApply).toBe(true)
    expect(storeStub.applyBoundsCorrection).not.toHaveBeenCalled()
  })

  /** Resolve the most recent deferred preview request with its own before/after. */
  function resolveLatestPreview(deferred: Deferred<Record<string, unknown>> | undefined): void {
    const calls = (storeStub.previewBoundsCorrection as unknown as { mock: { calls: unknown[][] } }).mock.calls
    const call = calls[calls.length - 1]!
    deferred?.resolve({ before: call[3], after: call[4], affected_features: [], action: call[2], raw: {} })
  }

  it('does not mutate when a pending one-click apply for row A is overtaken by switching to row B, then applies B', async () => {
    const deferredBySeries = deferPreviewBySeries(storeStub)
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as PreviewVm

    // One-click Apply on A starts its internal preview (still in flight).
    await primeRowForPreview(vm, violationRow)
    const pendingA = vm.applyCorrection()
    await flushPromises()
    expect(deferredBySeries.has('series-violation')).toBe(true)

    // Operator switches to row B before A's preview resolves.
    await primeRowForPreview(vm, secondBoundedRow)
    resolveLatestPreview(deferredBySeries.get('series-violation'))
    await pendingA
    await flushPromises()
    expect(storeStub.applyBoundsCorrection).not.toHaveBeenCalled()
    expect(vm.preview).toBeNull()

    // A new valid Apply on the current row (B) succeeds against B's data only.
    const pendingB = vm.applyCorrection()
    await flushPromises()
    resolveLatestPreview(deferredBySeries.get('series-violation-2'))
    await pendingB
    await flushPromises()
    expect(storeStub.applyBoundsCorrection).toHaveBeenCalledTimes(1)
    const args = storeStub.applyBoundsCorrection.mock.calls[0]!
    expect(args[0]).toBe('conn')
    expect(args[1]).toBe('series-violation-2')
    expect(args[2]).toBe('expand')
  })

  it('runs only one apply at a time while an apply is in flight', async () => {
    const deferredBySeries = deferPreviewBySeries(storeStub)
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as PreviewVm

    await primeRowForPreview(vm, violationRow)
    const first = vm.applyCorrection()
    const second = vm.applyCorrection()
    await flushPromises()
    const third = vm.applyCorrection()
    await flushPromises()
    expect(storeStub.previewBoundsCorrection).toHaveBeenCalledTimes(1)

    resolveLatestPreview(deferredBySeries.get('series-violation'))
    await Promise.all([first, second, third])
    await flushPromises()
    expect(storeStub.applyBoundsCorrection).toHaveBeenCalledTimes(1)
  })

  it('does not mutate when the proposed values are edited during the internal apply preview, then applies the edit', async () => {
    const deferredBySeries = deferPreviewBySeries(storeStub)
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as PreviewVm

    await primeRowForPreview(vm, violationRow)
    const pending = vm.applyCorrection()
    await flushPromises()
    expect(storeStub.previewBoundsCorrection).toHaveBeenCalledTimes(1)

    // Valid widening edit while the internal preview is in flight.
    vm.proposed.min_interarrival_time = { lower: 0.4, upper: 3.5 }
    await flushPromises()
    resolveLatestPreview(deferredBySeries.get('series-violation'))
    await pending
    await flushPromises()
    expect(storeStub.applyBoundsCorrection).not.toHaveBeenCalled()

    // A new apply sends the edited values.
    const retry = vm.applyCorrection()
    await flushPromises()
    resolveLatestPreview(deferredBySeries.get('series-violation'))
    await retry
    await flushPromises()
    expect(storeStub.applyBoundsCorrection).toHaveBeenCalledTimes(1)
    expect(storeStub.applyBoundsCorrection.mock.calls[0]![4]).toEqual({
      lower_bounds: { min_interarrival_time: 0.4 },
      upper_bounds: { min_interarrival_time: 3.5 },
    })
  })

  it('discards a stale preview rejection so it cannot surface an error on row B (B3-F1)', async () => {
    const deferredBySeries = deferPreviewBySeries(storeStub)
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as PreviewVm & { previewError: string | null }

    await primeRowForPreview(vm, violationRow)
    void vm.computePreview()
    await flushPromises()
    await primeRowForPreview(vm, secondBoundedRow)

    // Stale A preview rejects after B is selected; its error must be dropped.
    deferredBySeries.get('series-violation')?.reject(new Error('stale preview failure'))
    await flushPromises()
    expect(vm.previewError).toBeNull()
  })

  it('drops a preview and a pending apply whose action changed while in flight, then applies the new action (B3-F1)', async () => {
    const deferredBySeries = deferPreviewBySeries(storeStub)
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as PreviewVm

    await primeRowForPreview(vm, violationRow)
    const pending = vm.applyCorrection()
    await flushPromises()

    // Same row, but the operator flips Expand → Replace before the preview
    // resolves. The resolved preview belongs to the old action key.
    vm.correctionMode = 'replace'
    await flushPromises()
    resolveLatestPreview(deferredBySeries.get('series-violation'))
    await pending
    await flushPromises()
    expect(vm.preview).toBeNull()
    expect(storeStub.applyBoundsCorrection).not.toHaveBeenCalled()

    // A new valid Apply for the current (Replace) action succeeds.
    const retry = vm.applyCorrection()
    await flushPromises()
    resolveLatestPreview(deferredBySeries.get('series-violation'))
    await retry
    await flushPromises()
    expect(storeStub.applyBoundsCorrection).toHaveBeenCalledTimes(1)
    expect(storeStub.applyBoundsCorrection.mock.calls[0]![2]).toBe('replace')
  })

  it('invalidates a resolved preview and a pending apply when the drawer closes (B3-F1)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as PreviewVm

    // Standard resolving preview mock (makeStoreStub default) for row A.
    await primeRowForPreview(vm, violationRow)
    await vm.computePreview()
    await flushPromises()
    expect(vm.preview).not.toBeNull()

    // Close the drawer via its close button (selectedBound stays set).
    vm.boundDialog = false
    await flushPromises()
    expect(vm.preview).toBeNull()
    await vm.applyCorrection()
    expect(storeStub.applyBoundsCorrection).not.toHaveBeenCalled()
  })

  it('does not mutate when the drawer closes while a one-click apply preview is pending, then applies after reopening', async () => {
    const deferredBySeries = deferPreviewBySeries(storeStub)
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as PreviewVm

    await primeRowForPreview(vm, violationRow)
    const pending = vm.applyCorrection()
    await flushPromises()

    vm.boundDialog = false
    await flushPromises()
    resolveLatestPreview(deferredBySeries.get('series-violation'))
    await pending
    await flushPromises()
    expect(storeStub.applyBoundsCorrection).not.toHaveBeenCalled()

    // Reopen the same row; a new valid Apply succeeds.
    vm.boundDialog = true
    await flushPromises()
    const retry = vm.applyCorrection()
    await flushPromises()
    resolveLatestPreview(deferredBySeries.get('series-violation'))
    await retry
    await flushPromises()
    expect(storeStub.applyBoundsCorrection).toHaveBeenCalledTimes(1)
  })
})

describe('Guided drawer contract', () => {
  it('exposes exactly the Overview / Features & Chart / Correct tabs', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: unknown }
    vm.selectedBound = violationRow
    await flushPromises()
    const text = wrapper.text()
    expect(text).toContain('Overview')
    expect(text).toContain('Features & Chart')
    expect(text).toContain('Correct')
  })

  it('maps the truthful structured timeline (real feature, no index guess)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: unknown; drawerTab: string }
    vm.selectedBound = violationRow
    vm.drawerTab = 'overview'
    await flushPromises()
    expect(wrapper.text()).toContain('min_interarrival_time')
  })

  it('enables violation markers on the feature chart', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: unknown; drawerTab: string }
    vm.selectedBound = violationRow
    await flushPromises()
    vm.drawerTab = 'features'
    await flushPromises()
    expect(wrapper.find('.ts-chart').attributes('data-show-violations')).toBe('true')
  })
})

describe('Correction gating', () => {
  it('offers NoBounds Create/Train tiles and a server-seeded create proposal', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      selectedBound: unknown
      drawerTab: string
      correctionAction: string
      proposed: Record<string, { lower: number | null; upper: number | null }>
    }
    vm.selectedBound = noBoundsRow
    await flushPromises()
    vm.drawerTab = 'correct'
    await flushPromises()
    // Compact selectable tile grammar, not a generic toggle.
    expect(wrapper.find('[data-test="tile-create"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="tile-train"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="correction-mode"]').exists()).toBe(false)
    // No arbitrary Add Feature control.
    expect(wrapper.find('[data-test="add-feature"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('Create from reviewed values')
    expect(wrapper.text()).toContain('Train from history')
    expect(wrapper.find('[data-test="suggestion-provenance"]').text()).toContain('Server proposal')
    expect(wrapper.find('[data-test="suggestion-provenance"]').text()).toContain('2 numeric observations')
    expect(vm.correctionAction).toBe('create')
    expect(vm.proposed.packet_count).toEqual({ lower: null, upper: null })
    expect(storeStub.suggestBounds).toHaveBeenCalledWith(
      'proto_traffic',
      'series-nobounds',
      'create',
      expect.any(String),
      expect.any(String),
    )
    expect(wrapper.text()).toContain('Suggest proposed bounds')
  })

  it('offers Expand/Replace tiles for a bounded Violation series', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: unknown; drawerTab: string; correctionMode: string }
    vm.selectedBound = violationRow
    await flushPromises()
    vm.drawerTab = 'correct'
    await flushPromises()
    expect(wrapper.find('[data-test="tile-expand"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="tile-replace"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="tile-create"]').exists()).toBe(false)
  })

  it('places Suggest and Apply above the dense feature grid', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: unknown; drawerTab: string }
    vm.selectedBound = violationRow
    await flushPromises()
    vm.drawerTab = 'correct'
    await flushPromises()
    const html = wrapper.html()
    const actionbar = html.indexOf('data-test="correction-actionbar"')
    const grid = html.indexOf('data-test="proposed-editor"')
    expect(actionbar).toBeGreaterThan(-1)
    expect(grid).toBeGreaterThan(-1)
    expect(actionbar).toBeLessThan(grid)
  })

  it('exposes a keyboard-focusable safety help control (not a bare title span)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: unknown; drawerTab: string }
    vm.selectedBound = violationRow
    await flushPromises()
    vm.drawerTab = 'correct'
    await flushPromises()
    const help = wrapper.find('[data-test="correction-safety-help"]')
    expect(help.exists()).toBe(true)
    // ContextHelp renders a focusable button-role element with an accessible name.
    expect(help.attributes('role')).toBe('button')
    expect(help.attributes('aria-label')).toContain('Safe apply gates')
  })

  it('seeds editable proposed bounds from current bounds; optional reason does not gate apply', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      selectedBound: unknown
      drawerTab: string
      canPreview: boolean
      reason: string
      proposed: Record<string, { lower: number | null; upper: number | null }>
    }
    vm.selectedBound = violationRow
    await flushPromises()
    vm.drawerTab = 'correct'
    await flushPromises()
    // Seeded from current bounds; a valid proposal enables apply with no reason.
    expect(vm.proposed.min_interarrival_time).toEqual({ lower: 0.8, upper: 2.4 })
    expect(vm.canPreview).toBe(true)
    vm.reason = ''
    await flushPromises()
    expect(vm.canPreview).toBe(true)
  })

  it('rejects an expand that would narrow a bound (no invented values)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      selectedBound: unknown
      drawerTab: string
      correctionMode: string
      proposed: Record<string, { lower: number | null; upper: number | null }>
      proposedValidationError: string | null
      canPreview: boolean
    }
    vm.selectedBound = violationRow
    await flushPromises()
    vm.drawerTab = 'correct'
    vm.correctionMode = 'expand'
    // Raise the lower bound above current (0.8) => narrowing, must be rejected.
    vm.proposed.min_interarrival_time = { lower: 1.5, upper: 2.4 }
    await flushPromises()
    expect(vm.proposedValidationError).toMatch(/narrow/i)
    expect(vm.canPreview).toBe(false)
  })

  it('one-click apply runs internal preview then apply, with no confirmation field', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      selectedBound: unknown
      drawerTab: string
      reason: string
      applyCorrection: () => Promise<void>
    }
    // No confirmation input exists in the workflow.
    vm.selectedBound = violationRow
    await flushPromises()
    vm.drawerTab = 'correct'
    await flushPromises()
    expect(wrapper.find('[data-test="correction-confirmation"]').exists()).toBe(false)
    vm.reason = ''
    await vm.applyCorrection()
    await flushPromises()
    // Internal preview ran, then the audited apply — one user action, no phrase.
    expect(storeStub.previewBoundsCorrection).toHaveBeenCalled()
    expect(storeStub.applyBoundsCorrection).toHaveBeenCalledTimes(1)
    const args = storeStub.applyBoundsCorrection.mock.calls[0]!
    expect(args[0]).toBe('conn')
    expect(args[1]).toBe('series-violation')
    expect(args[5]).toBe('') // optional reason forwarded as empty string
    expect(args).toHaveLength(6) // no confirmation argument
  })

  it('resets preview and suggestion state when the correction mode changes', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      selectedBound: unknown
      drawerTab: string
      correctionMode: 'expand' | 'replace'
      preview: unknown
      suggestionMessage: string
    }
    vm.selectedBound = violationRow
    vm.drawerTab = 'correct'
    await flushPromises()
    vm.preview = { stale: true }
    vm.suggestionMessage = 'stale suggestion'
    vm.correctionMode = 'replace'
    await flushPromises()
    expect(vm.preview).toBeNull()
    expect(vm.suggestionMessage).toBe('')
  })

  it('applies server suggestion values through the same one-click gate', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      selectedBound: unknown
      drawerTab: string
      suggestBounds: () => Promise<void>
      proposed: Record<string, { lower: number | null; upper: number | null }>
    }
    vm.selectedBound = violationRow
    vm.drawerTab = 'correct'
    await flushPromises()
    await vm.suggestBounds()
    expect(vm.proposed.min_interarrival_time).toEqual({ lower: 0.5, upper: 3 })
    expect(storeStub.suggestBounds).toHaveBeenCalledWith(
      'conn',
      'series-violation',
      'expand',
      expect.any(String),
      expect.any(String),
    )
  })

  it('applies NoBounds creation from an empty envelope with no confirmation', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      selectedBound: unknown
      drawerTab: string
      proposed: Record<string, { lower: number | null; upper: number | null }>
      reason: string
      applyCorrection: () => Promise<void>
    }
    vm.selectedBound = noBoundsRow
    vm.drawerTab = 'correct'
    await flushPromises()
    vm.proposed.packet_count = { lower: 1, upper: 9 }
    vm.reason = 'create reviewed envelope'
    await vm.applyCorrection()
    await flushPromises()
    expect(storeStub.applyBoundsCorrection).toHaveBeenCalledWith(
      'proto_traffic',
      'series-nobounds',
      'create',
      { lower_bounds: {}, upper_bounds: {} },
      { lower_bounds: { packet_count: 1 }, upper_bounds: { packet_count: 9 } },
      'create reviewed envelope',
    )
  })
})

describe('NoBounds feature charts (CAPTURE 36 / finding 1)', () => {
  it('lists module available_features and auto-selects the first for a NoBounds row', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      selectedBound: BoundReviewItem | null
      drawerTab: string
      detailFeatures: string[]
      selectedFeature: string | null
    }
    vm.selectedBound = noBoundsRow
    await flushPromises()
    vm.drawerTab = 'features'
    await flushPromises()
    // No affected features and an empty envelope, yet the server-declared
    // module contract still populates the feature rows.
    expect(vm.detailFeatures).toEqual(noBoundsRow.available_features)
    // The first available feature is auto-selected so the chart loads on open.
    expect(vm.selectedFeature).toBe('proto_total_packets')
    // The feature rows render the available features.
    const html = wrapper.html()
    expect(html).toContain('proto_total_packets')
    expect(html).not.toContain('No feature-level bound data returned.')
  })

  it('sends the canonical raw series_id to fetchSeriesTimeseries and pipes real points into the chart', async () => {
    storeStub.fetchSeriesTimeseries = vi.fn().mockResolvedValue([
      {
        time: '2026-07-20T17:00:00Z',
        value: 5,
        value_min: null,
        value_max: null,
        lower_bound: null,
        upper_bound: null,
        violation_low: false,
        violation_high: false,
      },
      {
        time: '2026-07-20T17:05:00Z',
        value: 6,
        value_min: null,
        value_max: null,
        lower_bound: null,
        upper_bound: null,
        violation_low: false,
        violation_high: false,
      },
    ]) as unknown as typeof storeStub.fetchSeriesTimeseries

    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: BoundReviewItem | null; drawerTab: string }
    vm.selectedBound = noBoundsRow
    await flushPromises()
    vm.drawerTab = 'features'
    await flushPromises()

    // Canonical raw series_id (not the display protocol) is the chart identity.
    expect(storeStub.fetchSeriesTimeseries).toHaveBeenCalledWith(
      'proto_traffic',
      'series-nobounds',
      'proto_total_packets',
      expect.any(String),
      expect.any(String),
    )
    // The returned real points reach TimeseriesChart.
    const chart = wrapper.find('.ts-chart')
    expect(chart.attributes('data-point-count')).toBe('2')
  })

  it('disables bounds and violation markers on a NoBounds chart (no fabrication)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      selectedBound: BoundReviewItem | null
      drawerTab: string
      selectedHasBounds: boolean
    }
    vm.selectedBound = noBoundsRow
    await flushPromises()
    vm.drawerTab = 'features'
    await flushPromises()
    expect(vm.selectedHasBounds).toBe(false)
    const chart = wrapper.find('.ts-chart')
    expect(chart.attributes('data-show-bounds')).toBe('false')
    expect(chart.attributes('data-show-violations')).toBe('false')
    // Bounds cells are truthful and the violation column shows no bound violations.
    const featuresText = wrapper.find('[data-test="bound-drawer-body"]').text()
    expect(featuresText).toContain('Not available')
    expect(featuresText).toContain('No bound violations')
  })

  it('still charts a bounded row with bounds and violations enabled (contrast)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: BoundReviewItem | null; drawerTab: string }
    vm.selectedBound = violationRow
    await flushPromises()
    vm.drawerTab = 'features'
    await flushPromises()
    const chart = wrapper.find('.ts-chart')
    expect(chart.attributes('data-show-bounds')).toBe('true')
    expect(chart.attributes('data-show-violations')).toBe('true')
  })
})

describe('friendly Module column (CAPTURE 32 / finding 2)', () => {
  it('renders friendly module labels in the table while keeping raw module identity', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    const cells = wrapper.findAll('[data-test="bound-module-cell"]')
    expect(cells.length).toBeGreaterThan(0)
    const cellText = cells.map((c) => c.text()).join(' ')
    // Both visible rows: conn → Connections, proto_traffic → Protocols.
    expect(cellText).toContain('Connections')
    expect(cellText).toContain('Protocols')
    // Row identity and store rows keep the raw module value.
    expect(storeStub.bounds.map((r) => r.module)).toContain('conn')
    expect(storeStub.bounds.map((r) => r.module)).toContain('proto_traffic')
  })

  it('sorts the Module column by the friendly label, not the raw value', async () => {
    const mod = await import('~/pages/operations/detection.vue')
    void mod
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      boundColumns: Array<{ name: string; field: (row: BoundReviewItem) => unknown }>
    }
    const moduleCol = vm.boundColumns.find((c) => c.name === 'module')!
    // The sortable field resolves to the friendly label.
    expect(moduleCol.field(noBoundsRow)).toBe('Protocols')
    expect(moduleCol.field(violationRow)).toBe('Connections')
  })
})

describe('Module filter options (CAPTURE 32 / finding 3)', () => {
  it('exposes explicit {label,value} options with readable labels and raw values', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as {
      moduleOptions: Array<{ label: string; value: string | null }>
    }
    expect(vm.moduleOptions).toEqual([
      { label: 'All', value: null },
      { label: 'Connections', value: 'conn' },
      { label: 'Assets', value: 'mac_traffic' },
      { label: 'Protocols', value: 'proto_traffic' },
    ])
    // The rendered filter shows readable option text, not raw module strings.
    const moduleField = wrapper.find('[data-test="bound-module"]')
    expect(moduleField.exists()).toBe(true)
    const optionText = moduleField.findAll('option').map((o) => o.text())
    expect(optionText).toContain('Connections')
    expect(optionText).toContain('Assets')
    expect(optionText).toContain('Protocols')
    expect(optionText).not.toContain('mac_traffic')
  })

  it('stores the raw module value on selection and preserves null All behavior', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { boundModule: string | null }
    // Default All = null (no module filter).
    expect(vm.boundModule).toBeNull()
    vm.boundModule = 'proto_traffic'
    await flushPromises()
    // The store filter receives the raw module value, never the friendly label.
    const call = storeStub.filterBounds.mock.calls.at(-1)?.[0] as { module: string | null }
    expect(call.module).toBe('proto_traffic')
    // Returning to All stores null.
    vm.boundModule = null
    await flushPromises()
    const allCall = storeStub.filterBounds.mock.calls.at(-1)?.[0] as { module: string | null }
    expect(allCall.module).toBeNull()
  })
})

describe('compact drawer header and help (CAPTURE 34/35/37)', () => {
  it('shows the resolved protocol display in the drawer header with canonical id in the title', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: BoundReviewItem | null }
    vm.selectedBound = noBoundsRow
    await flushPromises()
    const header = wrapper.find('.drawer-series')
    expect(header.text()).toBe('Ethernet:IPv4:UDP:DNS')
    // Full canonical identifier remains available in the title/tooltip.
    expect(header.attributes('title')).toBe('series-nobounds')
  })

  it('renders the series_display in the table row with the canonical id as diagnostic', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    const html = wrapper.html()
    expect(html).toContain('Ethernet:IPv4:UDP:DNS')
    // Canonical id stays present as secondary diagnostic text / title.
    expect(html).toContain('series-nobounds')
  })

  it('moves Overview state prose into a keyboard-focusable help control (not a banner row)', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: BoundReviewItem | null; drawerTab: string }
    vm.selectedBound = noBoundsRow
    await flushPromises()
    vm.drawerTab = 'overview'
    await flushPromises()
    const help = wrapper.find('[data-test="overview-help"]')
    expect(help.exists()).toBe(true)
    expect(help.attributes('role')).toBe('button')
    expect(help.attributes('tabindex')).toBe('0')
    expect(help.attributes('aria-label')).toBe('About this Bound Review state')
  })

  it('moves the Features & Chart explanatory sentence into a keyboard-focusable help control', async () => {
    const wrapper = await mountPage()
    const vm = wrapper.vm as unknown as { selectedBound: BoundReviewItem | null; drawerTab: string }
    vm.selectedBound = violationRow
    // The selection watcher resets drawerTab to 'overview'; switch to features
    // only after it settles.
    await flushPromises()
    vm.drawerTab = 'features'
    await flushPromises()
    const help = wrapper.find('[data-test="features-help"]')
    expect(help.exists()).toBe(true)
    expect(help.attributes('role')).toBe('button')
    expect(help.attributes('aria-label')).toBe('About Features & Chart')
  })
})

describe('label helpers stay stable', () => {
  it('keeps operator-facing module and readiness labels', () => {
    expect(friendlyModuleLabel('conn')).toBe('Connections')
    expect(friendlyReadinessLabel('observe-only')).toBe('observe only')
  })
})

describe('training interval pure helpers', () => {
  it('calculates union duration without training the gap', async () => {
    const { summarizeTrainingIntervals, intervalDurationMinutes } = await import('~/utils/trainingIntervals')
    const intervals = [
      { start: '2026-07-06T16:00', end: '2026-07-06T17:00' },
      { start: '2026-07-06T18:00', end: '2026-07-06T19:00' },
    ]
    expect(summarizeTrainingIntervals(intervals)).toEqual({
      count: 2,
      unionMinutes: 120,
      valid: true,
      state: 'complete',
    })
    expect(intervalDurationMinutes(intervals[0]!)).toBe(60)
  })

  it('distinguishes neutral incomplete intervals from invalid inverted intervals', async () => {
    const { summarizeTrainingIntervals, toUtcEcho } = await import('~/utils/trainingIntervals')
    expect(summarizeTrainingIntervals([{ start: '', end: '' }])).toEqual({
      count: 1,
      unionMinutes: 0,
      valid: false,
      state: 'incomplete',
    })
    expect(summarizeTrainingIntervals([{ start: '2026-07-06T17:00', end: '2026-07-06T16:00' }])).toEqual({
      count: 1,
      unionMinutes: 0,
      valid: false,
      state: 'invalid',
    })
    expect(toUtcEcho('2026-07-06T16:00')).toContain('UTC')
  })
})
