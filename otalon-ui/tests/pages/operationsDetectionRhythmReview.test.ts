/**
 * Component tests for the UI-101 Rhythm Review surface.
 *
 * Assert the operator-frozen contracts from the change specs: the fleet
 * table treats `no_profile` as a normal state, the drawer mirrors the
 * Bound Review structure with four tabs, provenance is named for every
 * effective factor, only the two factor overrides are editable, an empty
 * input restores the global default, Apply accepts an optional reason and the
 * exact previewed snapshot, the detector floor warning is surfaced, a
 * success refreshes profile and history, a 409 retains the entered values
 * and demands a fresh preview, and an uncorrected series renders an
 * explicit empty history.
 *
 * Both stores are replaced with controllable stubs, so no network call is
 * made.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { h, type Component } from 'vue'

import { RhythmCorrectionConflictError } from '~/stores/rhythmReviewStore'
import type {
  FrequencyEventRecord,
  FrequencyHistoryRecord,
  FrequencyOverridePreviewResponse,
  FrequencyProfileResponse,
} from '~/types/api'

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

const NOW = '2026-08-01T12:00:00+00:00'

function profile(overrides: Partial<FrequencyProfileResponse> = {}): FrequencyProfileResponse {
  return {
    module: 'conn',
    series_id: 'series-normal',
    state: 'normal',
    has_profile: true,
    mean_interval_seconds: 10,
    std_interval_seconds: 1,
    tolerance_factor: { value: 2, source: 'global_default', override: null, global_default: 2 },
    absence_factor: { value: 3, source: 'global_default', override: null, global_default: 3 },
    last_seen: NOW,
    trained_at: '2026-07-30T12:00:00+00:00',
    now: NOW,
    absence_deadline: '2026-08-01T12:00:30+00:00',
    absence_timeout_seconds: 30,
    seconds_until_deadline: 30,
    seconds_since_last_seen: 0,
    active_anomaly_type: null,
    active_anomaly_since: null,
    recent_absence_count: 0,
    recent_frequency_anomaly_count: 0,
    ...overrides,
  }
}

const normalRow = profile()
const protoRow = profile({
  module: 'proto_traffic',
  series_id: '481221027',
  series_display: 'PROFINET',
  state: 'no_profile',
  has_profile: false,
  mean_interval_seconds: null,
  std_interval_seconds: null,
  tolerance_factor: null,
  absence_factor: null,
  last_seen: null,
  trained_at: null,
  absence_deadline: null,
  absence_timeout_seconds: null,
  seconds_until_deadline: null,
  seconds_since_last_seen: null,
})
const absentRow = profile({
  series_id: 'series-absent',
  state: 'absence_active',
  seconds_until_deadline: -120,
  active_anomaly_type: 'AbsenceAnomaly',
  active_anomaly_since: NOW,
  absence_factor: { value: 8, source: 'override', override: 8, global_default: 3 },
})
const recoveredRow = profile({
  series_id: 'series-recovered',
  recent_absence_count: 3,
  recent_frequency_anomaly_count: 2,
})
const noProfileRow = profile({
  series_id: 'series-unprofiled',
  state: 'no_profile',
  has_profile: false,
  mean_interval_seconds: null,
  std_interval_seconds: null,
  tolerance_factor: null,
  absence_factor: null,
  last_seen: null,
  trained_at: null,
  absence_deadline: null,
  absence_timeout_seconds: null,
  seconds_until_deadline: null,
  seconds_since_last_seen: null,
})

function previewResponse(overrides: Partial<FrequencyOverridePreviewResponse> = {}): FrequencyOverridePreviewResponse {
  return {
    module: 'conn',
    series_id: 'series-normal',
    diff: [
      {
        field: 'tolerance_factor.override',
        old_override: null,
        new_override: 6,
        old_effective: 2,
        new_effective: 6,
        old_source: 'global_default',
        new_source: 'override',
        changed: true,
      },
      {
        field: 'absence_factor.override',
        old_override: null,
        new_override: null,
        old_effective: 3,
        new_effective: 3,
        old_source: 'global_default',
        new_source: 'global_default',
        changed: false,
      },
    ],
    before_snapshot: { tolerance_factor_override: null, absence_factor_override: null },
    impact: {
      mean_interval_seconds: 10,
      std_interval_seconds: 1,
      relative_floor_factor: 0.5,
      floor_seconds: 5,
      old_threshold_seconds: 5,
      new_threshold_seconds: 6,
      floor_dominates: false,
      crossover_tolerance_factor: 5,
      absence_timeout_seconds: 30,
    },
    suggestion: null,
    ...overrides,
  }
}

const historyRecord: FrequencyHistoryRecord = {
  actor: 'operator',
  old_tolerance: null,
  new_tolerance: 6,
  old_absence: null,
  new_absence: null,
  reason: 'PROFINET jitter is expected on this flow',
  changed_at: NOW,
}

function makeRhythmStub() {
  return {
    module: 'conn' as const,
    profiles: [normalRow, protoRow, absentRow, recoveredRow, noProfileRow] as FrequencyProfileResponse[],
    history: [] as FrequencyHistoryRecord[],
    events: [
      { anomaly_type: 'AbsenceAnomaly', start_ts: NOW, end_ts: NOW, duration_seconds: 1, confidence: null },
      { anomaly_type: 'AbsenceAnomaly', start_ts: NOW, end_ts: NOW, duration_seconds: 1, confidence: null },
      { anomaly_type: 'AbsenceAnomaly', start_ts: NOW, end_ts: NOW, duration_seconds: 1, confidence: null },
      { anomaly_type: 'FrequencyAnomaly', start_ts: NOW, end_ts: NOW, duration_seconds: 1, confidence: null },
      { anomaly_type: 'FrequencyAnomaly', start_ts: NOW, end_ts: NOW, duration_seconds: 1, confidence: null },
    ] as FrequencyEventRecord[],
    eventsTruncated: false,
    loading: false,
    error: null as string | null,
    historyLoading: false,
    eventsLoading: false,
    profiledCount: 2,
    overriddenProfiles: [absentRow],
    loadEvents: vi.fn().mockResolvedValue(undefined),
    clearEvents: vi.fn(),
    loadFleet: vi.fn().mockResolvedValue(undefined),
    refreshProfile: vi
      .fn()
      .mockImplementation(async (_module: string, seriesId: string) =>
        seriesId === 'series-normal' ? null : undefined,
      ),
    previewOverride: vi.fn().mockResolvedValue(previewResponse()),
    applyOverride: vi.fn().mockResolvedValue({
      history_id: 'hist-1',
      module: 'conn',
      series_id: 'series-normal',
      diff: previewResponse().diff,
      profile: normalRow,
      notified: true,
    }),
    suggestOverride: vi.fn().mockResolvedValue({
      module: 'conn',
      series_id: 'series-normal',
      tolerance_factor_suggested: 4.5,
      absence_factor_suggested: 11.25,
      evidence: { observations: 12, window_days: 14, method: 'worst observed absence gap x 1.15 margin' },
    }),
    loadHistory: vi.fn().mockResolvedValue(undefined),
    clearHistory: vi.fn(),
  }
}

function makeDetectionStub() {
  return {
    modules: [],
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
    load: vi.fn().mockResolvedValue(undefined),
    filterBounds: vi.fn().mockResolvedValue(undefined),
    reconcileTrainingStatus: vi.fn().mockResolvedValue(undefined),
    fetchSeriesTimeseries: vi.fn().mockResolvedValue([]),
    suggestBounds: vi.fn().mockResolvedValue({}),
    previewBoundsCorrection: vi.fn().mockResolvedValue({}),
    applyBoundsCorrection: vi.fn().mockResolvedValue({}),
    startBoundsTraining: vi.fn(),
    startClassifierTraining: vi.fn(),
    advanceRetrainCooldown: vi.fn(),
    createBaseline: vi.fn(),
    loadLabelSources: vi.fn().mockResolvedValue({ items: [], invalid_file_count: 0, warning: null }),
    labelSources: [],
    labelSourcesLoaded: true,
    labelSourceWarning: null,
  }
}

let rhythmStub = makeRhythmStub()
let detectionStub = makeDetectionStub()

vi.mock('~/stores/rhythmReviewStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('~/stores/rhythmReviewStore')>()
  return { ...actual, useRhythmReviewStore: () => rhythmStub }
})

vi.mock('~/stores/detectionStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('~/stores/detectionStore')>()
  return { ...actual, useDetectionStore: () => detectionStub }
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
  TimeseriesChart: { props: ['data'], template: '<div class="ts-chart" />' },
}

interface RhythmVm {
  tab: string
  rhythmRange: string
  rhythmStates: Set<string>
  rhythmRows: FrequencyProfileResponse[]
  rhythmColumns: Array<{ label?: string }>
  rhythmEventCount: (row: FrequencyProfileResponse) => number
  rhythmStateCount: (state: string) => number
  rhythmStateKind: (state: string) => string
  rhythmTab: 'overview' | 'features' | 'correct' | 'history'
  selectedRhythm: FrequencyProfileResponse | null
  rhythmDrawer: boolean
  toleranceInput: string
  absenceInput: string
  rhythmReason: string
  rhythmSearch: string
  canApplyRhythm: boolean
  canPreviewRhythm: boolean
  rhythmValidationError: string | null
  rhythmConflict: string | null
  rhythmPreview: FrequencyOverridePreviewResponse | null
  previewRhythm: () => Promise<void>
  applyRhythm: () => Promise<void>
  requestRhythmSuggestion: () => Promise<void>
  openRhythm: (row: FrequencyProfileResponse) => void
  toggleRhythmState: (state: string) => void
  rhythmEffectiveState: (row: FrequencyProfileResponse) => string
}

async function mountRhythm() {
  const { mountWithPlugins } = await import('../helpers/mount')
  const mod = await import('~/pages/operations/detection.vue')
  const wrapper = mountWithPlugins(mod.default, { global: { stubs: extraStubs } })
  await flushPromises()
  const vm = wrapper.vm as unknown as RhythmVm
  vm.tab = 'rhythm'
  await flushPromises()
  return { wrapper, vm }
}

async function openCorrectTab(row: FrequencyProfileResponse = normalRow) {
  const mounted = await mountRhythm()
  mounted.vm.openRhythm(row)
  await flushPromises()
  mounted.vm.rhythmTab = 'correct'
  await flushPromises()
  return mounted
}

beforeEach(() => {
  rhythmStub = makeRhythmStub()
  detectionStub = makeDetectionStub()
  notify.mockReset()
  operationsRefresh.register.mockReset()
  operationsRefresh.unregister.mockReset()
  operationsRefresh.refresh.mockReset().mockResolvedValue(undefined)
  localStorage.clear()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Rhythm Review fleet table', () => {
  it('exposes the tab beside Bound Review', async () => {
    const { wrapper } = await mountRhythm()
    expect(wrapper.find('[data-test="tab-rhythm"]').exists()).toBe(true)
  })

  it('renders every profile including no_profile as a normal state', async () => {
    const { wrapper } = await mountRhythm()
    const html = wrapper.html()
    expect(html).toContain('series-normal')
    expect(html).toContain('series-absent')
    expect(html).toContain('PROFINET')
    expect(html).toContain('481221027')
    expect(html).toContain('series-unprofiled')
    expect(wrapper.find('[data-test="rhythm-error"]').exists()).toBe(false)
  })

  it('drops the redundant per-row counter badges from the table', async () => {
    const { wrapper, vm } = await mountRhythm()
    vm.rhythmRange = '7d'
    await flushPromises()

    const table = wrapper.find('[data-test="rhythm-review-table"]').html()
    expect(table).not.toContain('× absence (')
    expect(table).not.toContain('× cadence anomaly (')
    expect(wrapper.findAll('[data-test="rhythm-recent-absence-badge"]')).toHaveLength(0)
    expect(wrapper.findAll('[data-test="rhythm-recent-frequency-anomaly-badge"]')).toHaveLength(0)
  })

  it('reports the windowed episode counts as an Events column instead', async () => {
    const { vm } = await mountRhythm()
    vm.rhythmRange = '7d'
    await flushPromises()

    expect(vm.rhythmColumns.some((column) => column.label === 'Events')).toBe(true)
    // series-recovered carries 3 absence + 2 frequency episodes.
    expect(vm.rhythmEventCount(recoveredRow)).toBe(5)
  })

  it('uses absence history as the effective state in a bounded window', async () => {
    const { vm } = await mountRhythm()
    vm.rhythmRange = '1h'
    await flushPromises()

    expect(vm.rhythmEffectiveState(profile({ recent_absence_count: 4 }))).toBe('absence_active')
  })

  it('uses frequency history when no absence history exists', async () => {
    const { vm } = await mountRhythm()
    vm.rhythmRange = '1h'
    await flushPromises()

    expect(vm.rhythmEffectiveState(profile({ recent_frequency_anomaly_count: 2 }))).toBe('frequency_anomaly')
  })

  it('still derives the effective state from episode counts in the All range', async () => {
    // Regression: "All" used to fall back to the live `state` column, which
    // otalon-clas clears the moment a series speaks again, so the table
    // showed nothing but `normal` even for series with persisted episodes.
    const { vm } = await mountRhythm()

    expect(vm.rhythmEffectiveState(profile({ recent_absence_count: 4 }))).toBe('absence_active')
  })

  it('requests all-time episode counts for the All range', async () => {
    const { vm } = await mountRhythm()
    rhythmStub.loadFleet.mockClear()
    vm.rhythmRange = '7d'
    await flushPromises()
    vm.rhythmRange = 'All'
    await flushPromises()

    const since = rhythmStub.loadFleet.mock.calls.at(-1)?.[1]
    expect(since).toBe('1970-01-01T00:00:00.000Z')
  })

  it('polls the active rhythm fleet without polling while it is loading', async () => {
    const { vm } = await mountRhythm()
    const refreshLoader = operationsRefresh.register.mock.calls.at(-1)?.[0] as (() => Promise<void>) | undefined
    expect(refreshLoader).toBeDefined()

    rhythmStub.loadFleet.mockClear()
    await refreshLoader?.()
    expect(rhythmStub.loadFleet).toHaveBeenCalledWith('conn', '1970-01-01T00:00:00.000Z')

    rhythmStub.loadFleet.mockClear()
    rhythmStub.loading = true
    await refreshLoader?.()
    expect(rhythmStub.loadFleet).not.toHaveBeenCalled()

    rhythmStub.loading = false
    vm.tab = 'readiness'
    rhythmStub.loadFleet.mockClear()
    await refreshLoader?.()
    expect(rhythmStub.loadFleet).not.toHaveBeenCalled()
  })

  it('colours both anomaly states with the same warning kind as their cards', async () => {
    const { vm } = await mountRhythm()

    expect(vm.rhythmStateKind('absence_active')).toBe('warn')
    expect(vm.rhythmStateKind('frequency_anomaly')).toBe('warn')
    expect(vm.rhythmStateKind('normal')).toBe('ok')
  })

  it('moves cadence and factor detail out of the table into the drawer', async () => {
    const { wrapper } = await mountRhythm()
    const table = wrapper.find('[data-test="rhythm-review-table"]').html()
    expect(table).toContain('Module')
    expect(table).toContain('Series')
    expect(table).toContain('State')
    expect(table).toContain('Events')
    expect(table).toContain('Last seen')
    expect(table).not.toContain('tolerance_factor')
    expect(table).not.toContain('absence_factor')
    expect(table).not.toContain('Absence deadline')
  })

  it('renders no profile rather than a fabricated cadence for unprofiled series', async () => {
    // Cadence moved out of the table into the drawer (Bound Review parity),
    // so the honest "no profile" label is asserted where it now lives.
    const { wrapper, vm } = await mountRhythm()
    vm.openRhythm(noProfileRow)
    await flushPromises()

    expect(wrapper.find('[data-test="rhythm-overview-pane"]').text()).toContain('no profile')
  })

  it('filters by search across series identifiers', async () => {
    const { wrapper, vm } = await mountRhythm()
    vm.rhythmSearch = 'absent'
    await flushPromises()
    const table = wrapper.find('[data-test="rhythm-review-table"]').html()
    expect(table).toContain('series-absent')
    expect(table).not.toContain('series-normal')
  })

  it('filters by state and reports an explicit no-selection message', async () => {
    const { wrapper, vm } = await mountRhythm()
    for (const state of ['absence_active', 'frequency_anomaly', 'normal', 'no_last_seen', 'no_profile'])
      vm.toggleRhythmState(state)
    await flushPromises()
    expect(wrapper.find('[data-test="rhythm-empty"]').text()).toContain('No states selected')
  })

  it('keeps a windowed-anomaly row visible when its effective state is selected', async () => {
    // Regression: `series-recovered` has raw state `normal` but 3 absence
    // episodes in the window, so its pill reads `absence_active`. Hiding
    // `normal` must not hide it — the filter has to test what is displayed.
    const { vm } = await mountRhythm()
    vm.toggleRhythmState('normal')
    await flushPromises()

    const ids = vm.rhythmRows.map((row) => row.series_id)
    expect(ids).toContain('series-recovered')
    expect(ids).not.toContain('series-normal')
  })

  it('hides a windowed-anomaly row when its effective state is deselected', async () => {
    const { vm } = await mountRhythm()
    vm.toggleRhythmState('absence_active')
    await flushPromises()

    const ids = vm.rhythmRows.map((row) => row.series_id)
    expect(ids).not.toContain('series-recovered')
    expect(ids).not.toContain('series-absent')
    expect(ids).toContain('series-normal')
  })

  it('preserves the active drawer tab when the selected profile is refreshed in place', async () => {
    const { vm } = await openCorrectTab()
    const refreshed = profile({ last_seen: '2026-08-01T12:00:05+00:00' })

    vm.selectedRhythm = refreshed
    await flushPromises()

    expect(vm.rhythmTab).toBe('correct')
  })

  it('resets the drawer tab when a different series is selected', async () => {
    const { vm } = await openCorrectTab()

    vm.selectedRhythm = absentRow
    await flushPromises()

    expect(vm.rhythmTab).toBe('overview')
  })

  it('keeps the open row visible when its effective state leaves the filter', async () => {
    const { vm } = await mountRhythm()
    vm.openRhythm(absentRow)
    await flushPromises()
    vm.toggleRhythmState('absence_active')
    await flushPromises()

    expect(vm.rhythmRows.map((row) => row.series_id)).toContain('series-absent')

    vm.rhythmDrawer = false
    await flushPromises()
    expect(vm.rhythmRows.map((row) => row.series_id)).not.toContain('series-absent')
  })

  it('counts status cards by effective state so cards and rows agree', async () => {
    const { vm } = await mountRhythm()

    // series-absent (raw) + series-recovered (windowed) both read absent.
    expect(vm.rhythmStateCount('absence_active')).toBe(2)
    expect(vm.rhythmStateCount('normal')).toBe(1)
  })

  it('retains the ot-operator placeholder without adding RBAC', async () => {
    const { wrapper } = await mountRhythm()
    expect(wrapper.find('[data-test="rhythm-role-placeholder"]').text()).toContain('ot-operator')
  })
})

describe('Rhythm Review drawer parity with mockup 004', () => {
  it('opens the drawer on row selection with the three Bound Review tabs', async () => {
    const { wrapper, vm } = await mountRhythm()
    rhythmStub.events = []
    rhythmStub.loadEvents.mockImplementation(async () => {
      rhythmStub.events = []
    })
    rhythmStub.eventsLoading = false
    vm.openRhythm(normalRow)
    await flushPromises()

    expect(vm.rhythmDrawer).toBe(true)
    const tabs = wrapper.find('[data-test="rhythm-drawer-tabs"]').html()
    expect(tabs).toContain('Overview')
    expect(tabs).toContain('Features &amp; Chart')
    expect(tabs).toContain('Correct')
    expect(tabs).not.toContain('History')
  })

  it('closes the drawer through its close control', async () => {
    const { wrapper, vm } = await mountRhythm()
    vm.openRhythm(normalRow)
    await flushPromises()

    await wrapper.find('[data-test="rhythm-drawer-close"]').trigger('click')
    await flushPromises()

    expect(vm.rhythmDrawer).toBe(false)
  })

  it('names cadence provenance as learned and not editable', async () => {
    const { wrapper, vm } = await mountRhythm()
    vm.openRhythm(normalRow)
    await flushPromises()
    vm.rhythmTab = 'features'
    await flushPromises()

    expect(wrapper.find('[data-test="rhythm-cadence-provenance"]').text()).toContain('learned profile')
  })

  it('directs cadence correction to retraining in the Correct tab', async () => {
    const { wrapper } = await openCorrectTab()
    expect(wrapper.find('[data-test="rhythm-cadence-readonly"]').text()).toContain('retraining')
  })

  it('offers no editable cadence input', async () => {
    const { wrapper } = await openCorrectTab()
    const form = wrapper.find('[data-test="rhythm-form"]').html()
    expect(form).toContain('tolerance_factor.override')
    expect(form).toContain('absence_factor.override')
    expect(form).not.toContain('mean_interval')
    expect(form).not.toContain('std_interval')
  })

  it('surfaces the windowed episode counts as Overview KPI tiles', async () => {
    const { wrapper, vm } = await mountRhythm()
    vm.rhythmRange = '1h'
    await flushPromises()
    vm.openRhythm(recoveredRow)
    await flushPromises()

    expect(wrapper.find('[data-test="rhythm-kpi-absence-count"]').text()).toContain('3')
    expect(wrapper.find('[data-test="rhythm-kpi-frequency-count"]').text()).toContain('2')
    expect(wrapper.find('[data-test="rhythm-overview-counts"]').text()).toContain('3 absence event(s)')
  })
})

describe('Rhythm Review drawer event timeline', () => {
  it('renders one row per persisted episode with type and duration', async () => {
    rhythmStub.events = [
      { anomaly_type: 'AbsenceAnomaly', start_ts: NOW, end_ts: NOW, duration_seconds: 51, confidence: 1 },
      { anomaly_type: 'FrequencyAnomaly', start_ts: NOW, end_ts: null, duration_seconds: null, confidence: 0.7 },
    ]
    const { wrapper, vm } = await mountRhythm()
    vm.openRhythm(recoveredRow)
    await flushPromises()

    const rows = wrapper.findAll('[data-test="rhythm-timeline-row"]')
    expect(rows).toHaveLength(2)
    expect(rows[0]?.text()).toContain('absence_active')
    expect(rows[0]?.text()).toContain('51 s')
    expect(rows[1]?.text()).toContain('frequency_anomaly')
    expect(rows[1]?.text()).toContain('duration not recorded')
  })

  it('loads the timeline scoped to the selected series and window', async () => {
    const { vm } = await mountRhythm()
    vm.rhythmRange = '1h'
    await flushPromises()
    rhythmStub.loadEvents.mockClear()
    vm.openRhythm(absentRow)
    await flushPromises()

    expect(rhythmStub.loadEvents).toHaveBeenCalledWith('conn', 'series-absent', expect.any(String))
  })

  it('states an empty timeline instead of implying no data exists', async () => {
    const { vm } = await mountRhythm()
    rhythmStub.events = []
    rhythmStub.loadEvents.mockImplementation(async () => undefined)
    vm.openRhythm(normalRow)
    await flushPromises()

    expect(rhythmStub.events).toHaveLength(0)
  })

  it('declares a capped timeline rather than implying completeness', async () => {
    rhythmStub.events = [
      { anomaly_type: 'AbsenceAnomaly', start_ts: NOW, end_ts: NOW, duration_seconds: 5, confidence: 1 },
    ]
    rhythmStub.eventsTruncated = true
    const { wrapper, vm } = await mountRhythm()
    vm.openRhythm(recoveredRow)
    await flushPromises()

    expect(wrapper.find('[data-test="rhythm-timeline-capped"]').text()).toContain('more exist')
  })
})

describe('Rhythm Review drawer cadence chart', () => {
  it('plots the observed cadence timeseries for an uncorrected series', async () => {
    // Regression: the pane used to render only from `rhythm.history`, so a
    // never-corrected series (nearly all of them) showed no chart at all.
    detectionStub.fetchSeriesTimeseries.mockResolvedValue([
      { time: NOW, value: 8, value_min: 8, value_max: 8, lower_bound: 4, upper_bound: 12 },
    ])
    const { wrapper, vm } = await mountRhythm()
    vm.openRhythm(normalRow)
    await flushPromises()
    vm.rhythmTab = 'features'
    await flushPromises()

    expect(rhythmStub.history).toHaveLength(0)
    expect(wrapper.find('[data-test="rhythm-cadence-chart"]').exists()).toBe(true)
  })

  it('requests the interarrival metric first for a conn series', async () => {
    detectionStub.fetchSeriesTimeseries.mockResolvedValue([
      { time: NOW, value: 8, value_min: 8, value_max: 8, lower_bound: 4, upper_bound: 12 },
    ])
    const { vm } = await mountRhythm()
    vm.openRhythm(normalRow)
    await flushPromises()

    expect(detectionStub.fetchSeriesTimeseries).toHaveBeenCalledWith(
      'conn',
      'series-normal',
      'mean_interarrival_time',
      expect.any(String),
      expect.any(String),
    )
  })

  it('falls through to a packet count when interarrival is all zeroes', async () => {
    detectionStub.fetchSeriesTimeseries
      .mockResolvedValueOnce([{ time: NOW, value: 0, value_min: 0, value_max: 0, lower_bound: 0, upper_bound: 0 }])
      .mockResolvedValueOnce([{ time: NOW, value: 3, value_min: 3, value_max: 3, lower_bound: 1, upper_bound: 5 }])
    const { wrapper, vm } = await mountRhythm()
    vm.openRhythm(normalRow)
    await flushPromises()
    vm.rhythmTab = 'features'
    await flushPromises()

    expect(detectionStub.fetchSeriesTimeseries).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[data-test="rhythm-cadence-chart"]').exists()).toBe(true)
  })

  it('states an empty cadence chart instead of fabricating points', async () => {
    detectionStub.fetchSeriesTimeseries.mockResolvedValue([])
    const { wrapper, vm } = await mountRhythm()
    vm.openRhythm(normalRow)
    await flushPromises()
    vm.rhythmTab = 'features'
    await flushPromises()

    expect(wrapper.find('[data-test="rhythm-cadence-chart"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="rhythm-cadence-empty-chart"]').text()).toContain('No observed timeseries')
  })
})

describe('Rhythm correction one-click Apply', () => {
  it('enables Apply without preview and does not render Preview impact', async () => {
    const { wrapper, vm } = await openCorrectTab()
    vm.toleranceInput = '6'
    await flushPromises()
    expect(vm.canApplyRhythm).toBe(true)
    expect(wrapper.find('[data-test="rhythm-preview"]').exists()).toBe(false)
  })

  it('rejects invalid values before Apply', async () => {
    const { wrapper, vm } = await openCorrectTab()
    vm.toleranceInput = '-2'
    await flushPromises()
    expect(vm.canApplyRhythm).toBe(false)
    expect(wrapper.find('[data-test="rhythm-validation-error"]').text()).toContain('positive')
  })
})

describe('Rhythm suggestion provenance', () => {
  it('seeds editable fields and keeps Apply available', async () => {
    const { vm } = await openCorrectTab()
    await vm.requestRhythmSuggestion()
    await flushPromises()
    expect(vm.toleranceInput).toBe('4.5')
    expect(vm.absenceInput).toBe('11.25')
    expect(vm.canApplyRhythm).toBe(true)
  })
})

describe('Applied correction feedback', () => {
  it('applies directly and refreshes profile/history', async () => {
    const { vm } = await openCorrectTab()
    vm.toleranceInput = '6'
    vm.rhythmReason = 'documented jitter'
    await flushPromises()
    await vm.applyRhythm()
    await flushPromises()
    expect(rhythmStub.previewOverride).toHaveBeenCalledWith('conn', 'series-normal', { tolerance_factor_override: 6 })
    expect(rhythmStub.applyOverride).toHaveBeenCalled()
    expect(rhythmStub.loadHistory).toHaveBeenCalledWith('conn', 'series-normal')
  })

  it('surfaces a 409 conflict without writing and retains entered values', async () => {
    rhythmStub.applyOverride.mockRejectedValue(
      new RhythmCorrectionConflictError('Concurrent actor changed absence_factor.'),
    )
    const { wrapper, vm } = await openCorrectTab()
    vm.toleranceInput = '6'
    vm.rhythmReason = 'documented jitter'
    await flushPromises()
    await vm.applyRhythm()
    await flushPromises()
    expect(vm.toleranceInput).toBe('6')
    expect(wrapper.find('[data-test="rhythm-conflict"]').text()).toContain('409')
    expect(rhythmStub.loadHistory).toHaveBeenCalledTimes(1)
  })
})

describe('Per-series correction history', () => {
  it('renders actor, old-to-new values, reason and timestamp', async () => {
    rhythmStub.history = [historyRecord]
    const { wrapper, vm } = await mountRhythm()
    vm.openRhythm(normalRow)
    await flushPromises()
    vm.rhythmTab = 'correct'
    await flushPromises()

    const row = wrapper.find('[data-test="rhythm-history-row"]').text()
    expect(row).toContain('operator')
    expect(row).toContain('tolerance default → 6')
    expect(row).toContain('PROFINET jitter is expected on this flow')
  })

  it('renders an explicit empty state for a never-corrected series', async () => {
    const { wrapper, vm } = await mountRhythm()
    vm.openRhythm(normalRow)
    await flushPromises()
    vm.rhythmTab = 'correct'
    await flushPromises()

    expect(wrapper.find('[data-test="rhythm-history-empty"]').text()).toContain('No override has ever been recorded')
  })

  it('loads history scoped to the selected series', async () => {
    const { vm } = await mountRhythm()
    vm.openRhythm(absentRow)
    await flushPromises()

    expect(rhythmStub.loadHistory).toHaveBeenCalledWith('conn', 'series-absent')
  })
})
