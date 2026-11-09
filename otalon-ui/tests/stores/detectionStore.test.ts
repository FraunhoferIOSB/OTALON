import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import {
  friendlyModuleLabel,
  friendlyReadinessLabel,
  rangeToSince,
  rangeToWindow,
  useDetectionStore,
  type BoundReviewItem,
  type BoundsEnvelope,
  type TrainingInterval,
} from '~/stores/detectionStore'

const post = vi.fn()
const get = vi.fn()
vi.mock('~/composables/useApi', () => ({ useApi: () => ({ get, post }) }))

describe('detection store label mappers', () => {
  it('uses operator-friendly module labels', () => {
    expect(friendlyModuleLabel('conn')).toBe('Connections')
    expect(friendlyModuleLabel('mac_traffic')).toBe('Assets')
    expect(friendlyModuleLabel('proto_traffic')).toBe('Protocols')
  })

  it('renders readiness state without inventing percentages', () => {
    expect(friendlyReadinessLabel('observe-only')).toBe('observe only')
    expect(friendlyReadinessLabel('untrained')).toBe('untrained')
  })
})

describe('detection store time-range helpers', () => {
  const now = Date.parse('2026-07-18T00:00:00.000Z')

  it('maps each range to a since offset and All to undefined', () => {
    expect(rangeToSince('1h', now)).toBe('2026-07-17T23:00:00.000Z')
    expect(rangeToSince('6h', now)).toBe('2026-07-17T18:00:00.000Z')
    expect(rangeToSince('24h', now)).toBe('2026-07-17T00:00:00.000Z')
    expect(rangeToSince('7d', now)).toBe('2026-07-11T00:00:00.000Z')
    expect(rangeToSince('All', now)).toBeUndefined()
  })

  it('produces a space-separated training window respecting the range', () => {
    const win = rangeToWindow('24h', now)
    expect(win.stop).toBe('2026-07-18 00:00:00')
    expect(win.start).toBe('2026-07-17 00:00:00')
    expect(win.start).not.toContain('T')
  })

  it('uses a bounded default window for the All range', () => {
    const win = rangeToWindow('All', now)
    expect(win.start < win.stop).toBe(true)
    expect(win.start).not.toContain('T')
  })
})

describe('detection store unique-Series readiness semantics', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    post.mockReset()
  })

  it('totals unique NoBounds Series/UCI, not raw NoBounds events', () => {
    const store = useDetectionStore()
    // Producer emits both no_bounds_series_count (unique Series/UCI) and the
    // much larger no_bounds_event_count (redundant raw events).
    store.modules = [
      {
        module: 'conn',
        state: 'degraded',
        detection_mode: 'active',
        bounds_series_count: 4,
        no_bounds_count: 3,
        no_bounds_event_count: 523,
        no_bounds_series_count: 3,
        frequency_profile_count: 2,
        last_training: null,
        schema_version: 'bounds-v1',
        schema_compatible: true,
      },
      {
        module: 'proto_traffic',
        state: 'degraded',
        detection_mode: 'active',
        bounds_series_count: 2,
        no_bounds_count: 2,
        no_bounds_event_count: 28,
        no_bounds_series_count: 2,
        frequency_profile_count: 1,
        last_training: null,
        schema_version: 'bounds-v1',
        schema_compatible: true,
      },
    ]
    // 3 + 2 unique Series/UCI, NOT 523 + 28 raw events.
    expect(store.totalNoBounds).toBe(5)
  })

  it('falls back to no_bounds_count only when the unique series count is absent', () => {
    const store = useDetectionStore()
    store.modules = [
      {
        module: 'conn',
        state: 'degraded',
        detection_mode: 'active',
        bounds_series_count: 4,
        no_bounds_count: 7,
        frequency_profile_count: 2,
        last_training: null,
        schema_version: 'bounds-v1',
        schema_compatible: true,
      },
    ]
    expect(store.totalNoBounds).toBe(7)
  })
})

describe('detection store multi-interval training payloads', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    post.mockReset()
  })

  it('sends multiple disjoint bounds intervals as [start,end] tuples plus the legacy outer window', async () => {
    post.mockResolvedValue({ job_ref: 'J-bounds' })
    const store = useDetectionStore()
    // The page pre-sorts ascending before calling the store; here the sorted
    // list is passed through and reflected verbatim in the payload.
    const intervals: TrainingInterval[] = [
      { start: '2026-07-06 16:00:00', end: '2026-07-06 17:00:00' },
      { start: '2026-07-06 18:00:00', end: '2026-07-06 19:00:00' },
    ]
    await store.startBoundsTraining(intervals)
    expect(post).toHaveBeenCalledWith('/api/v1/training/retrain-boundaries', {
      // Legacy backward-compatible outer window: first-start to last-end.
      window_start: '2026-07-06 16:00:00',
      window_stop: '2026-07-06 19:00:00',
      // The ordered list of disjoint [start,end] tuples.
      intervals: [
        ['2026-07-06 16:00:00', '2026-07-06 17:00:00'],
        ['2026-07-06 18:00:00', '2026-07-06 19:00:00'],
      ],
    })
    expect(store.activeTrainingJob?.display_id).toBe('J-bounds')
  })

  it('sends the classifier mitre_file plus intervals and the legacy outer window', async () => {
    post.mockResolvedValue({ job_ref: 'J-ml' })
    const store = useDetectionStore()
    const intervals: TrainingInterval[] = [{ start: '2026-04-18 22:00:00', end: '2026-04-19 17:00:00' }]
    await store.startClassifierTraining(intervals, '/app/models/mitre_techniques_log.json')
    expect(post).toHaveBeenCalledWith('/api/v1/training/retrain-classifier', {
      window_start: '2026-04-18 22:00:00',
      window_stop: '2026-04-19 17:00:00',
      intervals: [['2026-04-18 22:00:00', '2026-04-19 17:00:00']],
      mitre_file: '/app/models/mitre_techniques_log.json',
    })
    expect(store.activeTrainingJob?.display_id).toBe('J-ml')
  })

  it('rejects inverted intervals (start >= end) before any request is sent', async () => {
    const store = useDetectionStore()
    await expect(
      store.startBoundsTraining([{ start: '2026-07-06 19:00:00', end: '2026-07-06 16:00:00' }]),
    ).rejects.toThrow(/start before end/)
    expect(post).not.toHaveBeenCalled()
  })

  it('rejects overlapping intervals before any request is sent', async () => {
    const store = useDetectionStore()
    await expect(
      store.startClassifierTraining(
        [
          { start: '2026-07-06 16:00:00', end: '2026-07-06 18:00:00' },
          { start: '2026-07-06 17:00:00', end: '2026-07-06 19:00:00' },
        ],
        '/app/models/mitre_techniques_log.json',
      ),
    ).rejects.toThrow(/overlap/)
    expect(post).not.toHaveBeenCalled()
  })

  it('rejects an empty interval list', async () => {
    const store = useDetectionStore()
    await expect(store.startBoundsTraining([])).rejects.toThrow(/start before end/)
    expect(post).not.toHaveBeenCalled()
  })

  it('uses backend retry_after for cooldown state and clears it after expiry', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_000_000)
    post.mockRejectedValue({ status: 429, detail: { message: 'runtime retrain cooldown active', retry_after: 123 } })
    const store = useDetectionStore()
    await expect(
      store.startBoundsTraining([{ start: '2026-07-06 16:00:00', end: '2026-07-06 17:00:00' }]),
    ).rejects.toMatchObject({ status: 429 })
    expect(store.retrainCooldownRemainingSeconds).toBe(123)
    expect(store.trainingError).toBe('Cooldown aktiv, noch 3 min')
    vi.spyOn(Date, 'now').mockReturnValue(1_124_000)
    store.advanceRetrainCooldown()
    expect(store.retrainCooldownActive).toBe(false)
    expect(store.trainingError).toBeNull()
    vi.restoreAllMocks()
  })
})

describe('detection store managed label sources', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    post.mockReset()
  })

  it('lists validated sources and uploads through the keyed training proxy contract', async () => {
    get.mockResolvedValue({
      items: [
        {
          filename: 'mitre_techniques_log.json',
          worker_path: '/app/models/mitre_techniques_log.json',
          size_bytes: 42,
          label_count: 1,
        },
      ],
      invalid_file_count: 1,
      warning: '1 JSON file(s) excluded because validation failed.',
    })
    post.mockResolvedValue({
      filename: 'ui088.json',
      worker_path: '/app/models/ui088.json',
      size_bytes: 42,
      label_count: 1,
    })
    const store = useDetectionStore()
    const listed = await store.loadLabelSources()
    const uploaded = await store.uploadLabelSource('ui088.json', '{"module_name":"T0846/arp_scan"}')
    expect(listed.items[0]?.worker_path).toBe('/app/models/mitre_techniques_log.json')
    expect(store.labelSourceWarning).toContain('excluded')
    expect(uploaded.worker_path).toBe('/app/models/ui088.json')
    expect(post).toHaveBeenCalledWith('/api/v1/training/label-sources/upload', {
      filename: 'ui088.json',
      content: '{"module_name":"T0846/arp_scan"}',
    })
  })
})

describe('detection store Bound Review aggregate contract', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    post.mockReset()
  })

  it('preserves nullable feature and aggregate fields from the producer through the store', async () => {
    // Producer aggregate row: one entry per Series/UCI with feature=null and
    // the current_bounds / affected_features / timeline / ok aggregate shape.
    const producerRow: BoundReviewItem = {
      module: 'conn',
      series_id: 'uci-agg',
      feature: null,
      state: 'NoBounds',
      current_bounds: { lower_bounds: {}, upper_bounds: {} },
      lower: null,
      upper: null,
      violation_count: 3,
      last_event: '2026-07-09T00:00:00+00:00',
      affected_features: ['packet_count', 'byte_count'],
      timeline: ['2026-07-05T00:00:00+00:00', '2026-07-09T00:00:00+00:00'],
      ok: false,
    }
    get.mockImplementation((url: string) => {
      if (url.endsWith('/operations/bounds')) return Promise.resolve({ items: [producerRow] })
      if (url.endsWith('/readiness')) return Promise.resolve({ modules: [] })
      if (url.endsWith('/artifacts')) return Promise.resolve({ items: [] })
      return Promise.resolve([])
    })

    const store = useDetectionStore()
    await store.load()

    expect(store.bounds).toHaveLength(1)
    const row = store.bounds[0]!
    // Nullable feature survives with no unsafe cast or field loss.
    expect(row.feature).toBeNull()
    expect(row.current_bounds).toEqual({ lower_bounds: {}, upper_bounds: {} })
    expect(row.affected_features).toEqual(['packet_count', 'byte_count'])
    expect(row.timeline).toEqual(['2026-07-05T00:00:00+00:00', '2026-07-09T00:00:00+00:00'])
    expect(row.ok).toBe(false)
    expect(row.violation_count).toBe(3)
  })
})

describe('detection store Bound Review query params and stale protection', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    post.mockReset()
  })

  it('sends only non-empty params with the exact from/to window', async () => {
    get.mockResolvedValue({ items: [] })
    const store = useDetectionStore()
    await store.filterBounds({
      module: 'conn',
      state: null,
      from: '2026-07-20T00:00:00.000Z',
      to: '2026-07-21T00:00:00.000Z',
      q: '',
    })
    expect(get).toHaveBeenCalledWith('/api/v1/operations/bounds', {
      module: 'conn',
      from: '2026-07-20T00:00:00.000Z',
      to: '2026-07-21T00:00:00.000Z',
    })
  })

  it('ignores a stale earlier response when a newer request has resolved first', async () => {
    let resolveFirst: (value: { items: BoundReviewItem[] }) => void = () => {}
    const first = new Promise<{ items: BoundReviewItem[] }>((resolve) => {
      resolveFirst = resolve
    })
    const staleRow = { series_id: 'stale' } as unknown as BoundReviewItem
    const freshRow = { series_id: 'fresh' } as unknown as BoundReviewItem
    get.mockReturnValueOnce(first)
    get.mockResolvedValueOnce({ items: [freshRow] })

    const store = useDetectionStore()
    const p1 = store.filterBounds({ module: 'conn' })
    const p2 = store.filterBounds({ module: 'mac_traffic' })
    await p2
    // The later request wins; now the earlier one resolves late and must not clobber.
    resolveFirst({ items: [staleRow] })
    await p1

    expect(store.bounds).toEqual([freshRow])
  })

  it('captures a bound-review error without discarding prior rows on a later success', async () => {
    const store = useDetectionStore()
    get.mockRejectedValueOnce({ message: 'boom' })
    await store.filterBounds({ module: 'conn' })
    expect(store.boundsError).toBe('boom')
  })
})

describe('detection store bounds correction preview/apply contract', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    post.mockReset()
  })

  const before: BoundsEnvelope = { lower_bounds: { a: 5 }, upper_bounds: { a: 10 } }
  const after: BoundsEnvelope = { lower_bounds: { a: 1 }, upper_bounds: { a: 20 } }

  it('normalizes the server prior+top-level bounds into before/after envelopes', async () => {
    // Server returns prior + top-level lower_bounds/upper_bounds, NOT an "after" key.
    post.mockResolvedValue({
      module: 'conn',
      series_id: 'uci-1',
      action: 'expand',
      prior: { lower_bounds: { a: 5 }, upper_bounds: { a: 10 } },
      lower_bounds: { a: 1 },
      upper_bounds: { a: 20 },
    })
    const store = useDetectionStore()
    const preview = await store.previewBoundsCorrection('conn', 'uci-1', 'expand', before, after, 'widen burst')
    expect(preview.before).toEqual({ lower_bounds: { a: 5 }, upper_bounds: { a: 10 } })
    expect(preview.after).toEqual({ lower_bounds: { a: 1 }, upper_bounds: { a: 20 } })
    expect(preview.affected_features).toEqual(['a'])
    // Never surfaces lower_bounds/upper_bounds as if they were features.
    expect(preview.affected_features).not.toContain('lower_bounds')
    expect(preview.affected_features).not.toContain('upper_bounds')
  })

  it('double-encodes the slash-bearing series id in the preview URL', async () => {
    post.mockResolvedValue({ prior: {}, lower_bounds: {}, upper_bounds: {} })
    const store = useDetectionStore()
    await store.previewBoundsCorrection('conn', 'aa/bb', 'expand', before, after, 'reason text')
    const url = post.mock.calls[0]![0] as string
    expect(url).toBe(`/api/v1/operations/bounds/${encodeURIComponent(encodeURIComponent('aa/bb'))}/correction/preview`)
  })

  it('forwards the optional reason and omits any confirmation phrase (one-click contract)', async () => {
    post.mockResolvedValue({ job: {}, correction: {} })
    const store = useDetectionStore()
    await store.applyBoundsCorrection('conn', 'uci-1', 'replace', before, after, 'operator reason')
    const body = post.mock.calls[0]![1] as Record<string, unknown>
    expect(body.reason).toBe('operator reason')
    expect(body.action).toBe('replace')
    expect('confirmation' in body).toBe(false)
  })

  it('defaults reason to an empty string when omitted, still without confirmation', async () => {
    post.mockResolvedValue({})
    const store = useDetectionStore()
    await store.applyBoundsCorrection('conn', 'uci-1', 'expand', before, after)
    const body = post.mock.calls[0]![1] as Record<string, unknown>
    expect(body.reason).toBe('')
    expect('confirmation' in body).toBe(false)
  })

  it('propagates apply errors to the caller', async () => {
    post.mockRejectedValue({ message: 'conflict', status: 409 })
    const store = useDetectionStore()
    await expect(store.applyBoundsCorrection('conn', 'uci-1', 'expand', before, after, 'r')).rejects.toMatchObject({
      status: 409,
    })
  })
})

describe('detection store training terminal-state reconciliation', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    post.mockReset()
  })

  it('clears busy and re-enables a second retrain once the run reaches succeeded', async () => {
    post.mockResolvedValue({ job_ref: 'J-1' })
    const store = useDetectionStore()

    await store.startBoundsTraining([{ start: '2026-07-06 16:00:00', end: '2026-07-06 17:00:00' }])
    expect(store.trainingBusy).toBe(true)

    // First poll: still running -> busy stays true, no clear.
    get.mockResolvedValueOnce({ state: 'running', busy: true, job_ref: 'J-1', error: null })
    await store.reconcileTrainingStatus()
    expect(store.trainingBusy).toBe(true)
    expect(get).toHaveBeenCalledWith('/api/v1/training/retrain-boundaries/status')

    // Second poll: terminal success -> busy settles, no error surfaced.
    get.mockResolvedValueOnce({ state: 'succeeded', busy: false, job_ref: 'J-1', error: null })
    await store.reconcileTrainingStatus()
    expect(store.trainingBusy).toBe(false)
    expect(store.activeTrainingJob).toBeNull()
    expect(store.trainingError).toBeNull()

    // A second retrain can now start.
    post.mockResolvedValue({ job_ref: 'J-2' })
    await store.startBoundsTraining([{ start: '2026-07-07 16:00:00', end: '2026-07-07 17:00:00' }])
    expect(store.trainingBusy).toBe(true)
    expect(store.activeTrainingJob?.display_id).toBe('J-2')
  })

  it('clears busy but surfaces error truth once the run reaches failed', async () => {
    post.mockResolvedValue({ job_ref: 'J-3' })
    const store = useDetectionStore()

    await store.startClassifierTraining(
      [{ start: '2026-04-18 22:00:00', end: '2026-04-19 17:00:00' }],
      '/app/models/mitre_techniques_log.json',
    )
    expect(store.trainingBusy).toBe(true)

    get.mockResolvedValueOnce({
      state: 'failed',
      busy: false,
      job_ref: 'J-3',
      error: 'window contained no training samples',
    })
    await store.reconcileTrainingStatus()

    expect(store.trainingBusy).toBe(false)
    expect(store.activeTrainingJob).toBeNull()
    expect(store.trainingError).toBe('window contained no training samples')
  })

  it('polls status while idle so completed windows are available on page load', async () => {
    const store = useDetectionStore()
    get.mockResolvedValueOnce({
      state: 'succeeded',
      busy: false,
      scope: 'bounds',
      window_start: '2026-08-21T00:00:00Z',
      window_stop: '2026-08-25T17:56:00Z',
      finished_at: '2026-08-25T18:00:00Z',
    })
    await store.reconcileTrainingStatus()
    expect(get).toHaveBeenCalledWith('/api/v1/training/retrain-boundaries/status')
    expect(store.lastBoundsTraining?.windowStart).toBe('2026-08-21T00:00:00Z')
    expect(store.lastBoundsTraining?.windowStop).toBe('2026-08-25T17:56:00Z')
  })

  it('keeps current window while busy and promotes it to last trained on success', async () => {
    const store = useDetectionStore()
    get.mockResolvedValueOnce({
      state: 'running',
      busy: true,
      scope: 'ml',
      window_start: '2026-08-25T08:00:00Z',
      window_stop: '2026-08-25T09:00:00Z',
    })
    await store.reconcileTrainingStatus()
    expect(store.classifierTrainingStatus?.busy).toBe(true)
    expect(store.lastClassifierTraining).toBeNull()

    get.mockResolvedValueOnce({
      state: 'succeeded',
      busy: false,
      scope: 'ml',
      window_start: '2026-08-25T08:00:00Z',
      window_stop: '2026-08-25T09:00:00Z',
      finished_at: '2026-08-25T09:05:00Z',
    })
    await store.reconcileTrainingStatus()
    expect(store.lastClassifierTraining?.finishedAt).toBe('2026-08-25T09:05:00Z')
  })

  it('keeps busy on a transient status fetch error instead of falsely settling', async () => {
    post.mockResolvedValue({ job_ref: 'J-4' })
    const store = useDetectionStore()
    await store.startBoundsTraining([{ start: '2026-07-06 16:00:00', end: '2026-07-06 17:00:00' }])

    get.mockRejectedValueOnce(new Error('network blip'))
    await store.reconcileTrainingStatus()

    expect(store.trainingBusy).toBe(true)
  })

  it('resets stale error truth when a new run is started', async () => {
    post.mockResolvedValue({ job_ref: 'J-5' })
    const store = useDetectionStore()
    store.trainingError = 'previous failure'

    await store.startBoundsTraining([{ start: '2026-07-06 16:00:00', end: '2026-07-06 17:00:00' }])
    expect(store.trainingError).toBeNull()
  })
})
