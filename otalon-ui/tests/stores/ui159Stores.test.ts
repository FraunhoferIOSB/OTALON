/**
 * Regression tests for the UI-159 store fixes.
 *
 * * UI-07 — `alarmsStore` wrote pagination state two different ways
 *   (`fetchGroups` replaced, `loadMore` appended), so the two could disagree.
 * * UI-08 — `timeseriesStore.fetchPlotData` had no sequence guard, so a slow
 *   earlier response could overwrite a newer one.
 * * UI-12 — `devicesStore` fetched a single 200-row page with no way to
 *   reach the rest of the inventory.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useAlarmsStore } from '~/stores/alarmsStore'
import { useDevicesStore } from '~/stores/devicesStore'
import { useTimeseriesStore } from '~/stores/timeseriesStore'

function group(id: string) {
  return { id, module: 'conn', primary_type: 'BoundViolation', is_active: true, confirmed: false }
}

function device(id: number) {
  return { id, hostname: `d${id}`, vendor: 'ACME', interfaces: [], vulnerabilities: [], last_scan_at: null }
}

beforeEach(() => {
  setActivePinia(createPinia())
  vi.unstubAllGlobals()
})

// ── UI-07: unified alarm pagination state ──────────────────────────────

describe('alarmsStore pagination consistency (UI-07)', () => {
  it('replaces on fetch and appends on loadMore with consistent counters', async () => {
    const store = useAlarmsStore()
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ data: [group('a'), group('b')], row_count: 4 })
      .mockResolvedValueOnce({ data: [group('c'), group('d')], row_count: 4 })
    vi.stubGlobal('$fetch', fetchMock)

    await store.fetchGroups()
    expect(store.groups.map((g) => g.id)).toEqual(['a', 'b'])
    expect(store.hasMore).toBe(true)

    await store.loadMore()
    expect(store.groups.map((g) => g.id)).toEqual(['a', 'b', 'c', 'd'])
    expect(store.hasMore).toBe(false)
    expect(store.totalRowCount).toBe(4)
  })

  it('a refresh after loadMore resets the list and hasMore together', async () => {
    const store = useAlarmsStore()
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ data: [group('a')], row_count: 2 })
      .mockResolvedValueOnce({ data: [group('b')], row_count: 2 })
      .mockResolvedValueOnce({ data: [group('z')], row_count: 1 })
    vi.stubGlobal('$fetch', fetchMock)

    await store.fetchGroups()
    await store.loadMore()
    expect(store.groups).toHaveLength(2)

    await store.fetchGroups()
    expect(store.groups.map((g) => g.id)).toEqual(['z'])
    expect(store.totalRowCount).toBe(1)
    expect(store.hasMore).toBe(false)
  })

  it('de-duplicates rows that shift across the offset window', async () => {
    const store = useAlarmsStore()
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ data: [group('a'), group('b')], row_count: 4 })
      // 'b' repeats because a new alarm was inserted upstream meanwhile.
      .mockResolvedValueOnce({ data: [group('b'), group('c')], row_count: 4 })
    vi.stubGlobal('$fetch', fetchMock)

    await store.fetchGroups()
    await store.loadMore()

    expect(store.groups.map((g) => g.id)).toEqual(['a', 'b', 'c'])
  })
})

// ── UI-08: timeseries request-sequence guard ───────────────────────────

describe('timeseriesStore race guard (UI-08)', () => {
  it('ignores a slow earlier response that resolves after a newer one', async () => {
    const store = useTimeseriesStore()

    let releaseSlow: () => void = () => undefined
    const slow = new Promise<void>((resolve) => {
      releaseSlow = resolve
    })

    const fetchMock = vi
      .fn()
      .mockImplementation(async (_url: string, opts: { params: Record<string, unknown> }) => {
        const metric = opts.params.metric
        if (metric === 'stale_feature') await slow
        return {
          data: [{ time: '2026-01-01T00:00:00Z', value: metric }],
          row_count: 1,
          parameters: { bucket_seconds: 60 },
        }
      })
    vi.stubGlobal('$fetch', fetchMock)

    // Start the slow request first, then supersede it with a newer one.
    const first = store.fetchPlotData('uci-1', ['stale_feature'], 'a', 'b')
    const second = store.fetchPlotData('uci-1', ['fresh_feature'], 'c', 'd')

    await second
    expect(Object.keys(store.plotData)).toEqual(['fresh_feature'])

    // Now let the superseded request finish; it must not write.
    releaseSlow()
    await first

    expect(Object.keys(store.plotData)).toEqual(['fresh_feature'])
  })

  it('the newest request still writes its data', async () => {
    const store = useTimeseriesStore()
    vi.stubGlobal(
      '$fetch',
      vi.fn().mockResolvedValue({
        data: [{ time: '2026-01-01T00:00:00Z', value: 1 }],
        row_count: 1,
        parameters: { bucket_seconds: 30 },
      }),
    )

    await store.fetchPlotData('uci-1', ['packet_count'], 'a', 'b')

    expect(Object.keys(store.plotData)).toEqual(['packet_count'])
    expect(store.bucketSeconds).toBe(30)
  })
})

// ── UI-12: device inventory pagination ─────────────────────────────────

describe('devicesStore pagination (UI-12)', () => {
  it('reports more devices when the backend total exceeds the page', async () => {
    const store = useDevicesStore()
    vi.stubGlobal('$fetch', vi.fn().mockResolvedValue({ devices: [device(1), device(2)], total: 5 }))

    await store.fetchDevices(2)

    expect(store.hasMoreDevices).toBe(true)
  })

  it('appends the next page and stops when everything is loaded', async () => {
    const store = useDevicesStore()
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ devices: [device(1), device(2)], total: 4 })
      .mockResolvedValueOnce({ devices: [device(3), device(4)], total: 4 })
    vi.stubGlobal('$fetch', fetchMock)

    await store.fetchDevices(2)
    await store.loadMoreDevices()

    expect(store.devices.map((d) => d.id)).toEqual([1, 2, 3, 4])
    expect(store.hasMoreDevices).toBe(false)
  })

  it('requests the next page at the current offset', async () => {
    const store = useDevicesStore()
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ devices: [device(1), device(2)], total: 4 })
      .mockResolvedValueOnce({ devices: [device(3)], total: 4 })
    vi.stubGlobal('$fetch', fetchMock)

    await store.fetchDevices(2)
    await store.loadMoreDevices()

    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({ params: { limit: 2, offset: 2 } })
  })

  it('de-duplicates devices repeated across pages', async () => {
    const store = useDevicesStore()
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ devices: [device(1), device(2)], total: 4 })
      .mockResolvedValueOnce({ devices: [device(2), device(3)], total: 4 })
    vi.stubGlobal('$fetch', fetchMock)

    await store.fetchDevices(2)
    await store.loadMoreDevices()

    expect(store.devices.map((d) => d.id)).toEqual([1, 2, 3])
  })

  it('does not issue a request when everything is already loaded', async () => {
    const store = useDevicesStore()
    const fetchMock = vi.fn().mockResolvedValue({ devices: [device(1)], total: 1 })
    vi.stubGlobal('$fetch', fetchMock)

    await store.fetchDevices(10)
    await store.loadMoreDevices()

    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
