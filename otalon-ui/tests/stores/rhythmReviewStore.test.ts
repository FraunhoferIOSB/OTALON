/**
 * Tests for the Rhythm Review store's URL contract (UI-101).
 *
 * The one thing a `conn` series id always is, is full of `/`. Uvicorn
 * percent-decodes a path exactly once before Starlette matches the route, so
 * a singly-encoded series id splits into several segments and 404s; the id
 * must therefore be encoded twice for the path while the raw value travels in
 * the body/query as the authoritative identifier. UI-101 shipped without a
 * test that ever put a `/` in a series id, which is how the mismatch reached
 * the browser.
 *
 * These tests use a verbatim production UCI and assert the whole round trip:
 * Preview → Apply, plus Suggest and History.
 */
import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useRhythmReviewStore } from '~/stores/rhythmReviewStore'
import type { FrequencyOverridePreviewResponse } from '~/types/api'

/** A verbatim production `conn` UCI — eight literal `/`, IPv6 colons. */
const REAL_CONN_SERIES =
  '7c:cb:e2:ea:0d:65/33:33:00:00:00:fb//IPv6/fe80::f6f7:3be0:3c8d:5089/ff02::fb/5353/5353/Ethernet:IPv6:UDP:DNS'

const DOUBLE_ENCODED = encodeURIComponent(encodeURIComponent(REAL_CONN_SERIES))

const fetchMock = vi.fn()

function previewResponse(): FrequencyOverridePreviewResponse {
  return {
    module: 'conn',
    series_id: REAL_CONN_SERIES,
    diff: [],
    before_snapshot: { tolerance_factor_override: null, absence_factor_override: null },
    impact: {
      mean_interval_seconds: 3600,
      std_interval_seconds: 0,
      relative_floor_factor: 0.5,
      floor_seconds: 1800,
      old_threshold_seconds: 1800,
      new_threshold_seconds: 1800,
      floor_dominates: true,
      crossover_tolerance_factor: null,
      absence_timeout_seconds: 10800,
    },
    suggestion: null,
  } as FrequencyOverridePreviewResponse
}

/** The path the store put on the wire for the most recent call. */
function calledPath(): string {
  return String(fetchMock.mock.calls.at(-1)?.[0] ?? '')
}

/** The series-id segment of that path, i.e. the part between the fixed pieces. */
function calledSegment(): string {
  return calledPath().replace('/api/v1/frequency/', '').split('/')[0] ?? ''
}

beforeEach(() => {
  setActivePinia(createPinia())
  fetchMock.mockReset()
  fetchMock.mockResolvedValue(previewResponse())
  vi.stubGlobal('$fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('rhythmReviewStore — slash-bearing series id in the path', () => {
  it('double-encodes the series id for Preview', async () => {
    const store = useRhythmReviewStore()

    await store.previewOverride('conn', REAL_CONN_SERIES, { tolerance_factor_override: 3 })

    expect(calledSegment()).toBe(DOUBLE_ENCODED)
  })

  it('double-encodes the series id for Apply', async () => {
    const store = useRhythmReviewStore()

    await store.applyOverride(
      'conn',
      REAL_CONN_SERIES,
      { tolerance_factor_override: 3 },
      { tolerance_factor_override: null, absence_factor_override: null },
      'documented maintenance window',
    )

    expect(calledSegment()).toBe(DOUBLE_ENCODED)
  })

  it('double-encodes the series id for Suggest and History', async () => {
    const store = useRhythmReviewStore()

    await store.suggestOverride('conn', REAL_CONN_SERIES)
    expect(calledSegment()).toBe(DOUBLE_ENCODED)

    fetchMock.mockResolvedValue({ module: 'conn', series_id: REAL_CONN_SERIES, count: 0, data: [] })
    await store.loadHistory('conn', REAL_CONN_SERIES)
    expect(calledSegment()).toBe(DOUBLE_ENCODED)
  })

  it('keeps the whole id inside ONE path segment', async () => {
    const store = useRhythmReviewStore()

    await store.previewOverride('conn', REAL_CONN_SERIES, { tolerance_factor_override: 3 })

    // The raw id has 8 separators; if any survived the encoding the route
    // would not match and the API would answer 404.
    expect(REAL_CONN_SERIES.split('/').length - 1).toBe(8)
    expect(calledSegment()).not.toContain('/')
    expect(calledPath()).toBe(`/api/v1/frequency/${DOUBLE_ENCODED}/override/preview?module=conn`)
  })

  it('survives exactly one server-side decode back to the single-encoded form', async () => {
    const store = useRhythmReviewStore()

    await store.previewOverride('conn', REAL_CONN_SERIES, { tolerance_factor_override: 3 })

    // Uvicorn decodes once …
    const afterUvicorn = decodeURIComponent(calledSegment())
    expect(afterUvicorn).toBe(encodeURIComponent(REAL_CONN_SERIES))
    expect(afterUvicorn).not.toContain('/')
    // … and `_resolve_series` unquotes once more to recover the raw UCI.
    expect(decodeURIComponent(afterUvicorn)).toBe(REAL_CONN_SERIES)
  })

  it('still sends the raw id as the authoritative body value', async () => {
    const store = useRhythmReviewStore()

    await store.previewOverride('conn', REAL_CONN_SERIES, { tolerance_factor_override: 3 })

    const body = fetchMock.mock.calls.at(-1)?.[1]?.body as Record<string, unknown>
    expect(body.series_id).toBe(REAL_CONN_SERIES)
  })

  it('leaves a series id without separators readable', async () => {
    const store = useRhythmReviewStore()

    await store.previewOverride('mac_traffic', 'aabbccddeeff', { tolerance_factor_override: 3 })

    expect(calledSegment()).toBe('aabbccddeeff')
  })
})

describe('rhythmReviewStore — all module fleet', () => {
  it('loads and merges profiles from each supported module', async () => {
    fetchMock
      .mockResolvedValueOnce({ module: 'conn', count: 1, data: [{ module: 'conn', series_id: 'conn-series' }] })
      .mockResolvedValueOnce({
        module: 'mac_traffic',
        count: 1,
        data: [{ module: 'mac_traffic', series_id: 'mac-series' }],
      })
      .mockResolvedValueOnce({
        module: 'proto_traffic',
        count: 1,
        data: [{ module: 'proto_traffic', series_id: 'proto-series' }],
      })
    const store = useRhythmReviewStore()

    await store.loadFleet(null)

    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(fetchMock.mock.calls.map((call) => call[1]?.params?.module)).toEqual([
      'conn',
      'mac_traffic',
      'proto_traffic',
    ])
    expect(store.module).toBeNull()
    expect(store.profiles.map((profile) => profile.module)).toEqual(['conn', 'mac_traffic', 'proto_traffic'])
  })

  it('passes the selected history window and omits it when absent', async () => {
    fetchMock.mockResolvedValue({ module: 'conn', count: 0, data: [] })
    const store = useRhythmReviewStore()

    await store.loadFleet('conn', '2026-08-02T12:00:00.000Z')
    expect(fetchMock.mock.calls[0]?.[1]?.params).toEqual({
      module: 'conn',
      since: '2026-08-02T12:00:00.000Z',
    })

    fetchMock.mockClear()
    await store.loadFleet('conn')
    expect(fetchMock.mock.calls[0]?.[1]?.params).toEqual({ module: 'conn' })
  })
})
