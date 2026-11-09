/**
 * UI-195 regression against the REAL alarmsStore.
 *
 * A point alarm (start_timestamp == end_timestamp) must not reach the bounds
 * endpoint with from == to, because the API answers 400 ("from must be before to").
 * This spies on the $fetch used by the store and asserts the window it sends.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useAlarmsStore } from '~/stores/alarmsStore'

const POINT = '2026-10-30T14:12:20.000Z'

function groupFor(start: string, end: string) {
  return {
    id: 'g1',
    module: 'mac_traffic',
    start_timestamp: start,
    end_timestamp: end,
    primary_type: 'x',
    multi_type: false,
    series_ids: ['s1'],
  } as never
}

describe('UI-195 alarmsStore bounds request for point alarms', () => {
  let calls: Array<{ url: string; opts: { params: { from: string; to: string } } }>

  beforeEach(() => {
    setActivePinia(createPinia())
    calls = []
    globalThis.$fetch = vi.fn(async (url: string, opts: never) => {
      calls.push({ url, opts })
      return { items: [] }
    }) as never
  })

  it('sends a strictly ordered window for a point alarm (from < to)', async () => {
    const store = useAlarmsStore()
    await store.fetchAffectedFeatures(groupFor(POINT, POINT))
    const bounds = calls.filter((c) => c.url === '/api/v1/operations/bounds')
    expect(bounds.length).toBeGreaterThan(0)
    for (const c of bounds) {
      const { from, to } = c.opts.params
      expect(new Date(from).getTime()).toBeLessThan(new Date(to).getTime())
    }
  })

  it('still sends the original end for a ranged alarm', async () => {
    const store = useAlarmsStore()
    const end = '2026-10-30T14:30:00.000Z'
    await store.fetchAffectedFeatures(groupFor('2026-10-30T14:00:00.000Z', end))
    const bounds = calls.filter((c) => c.url === '/api/v1/operations/bounds')
    expect(bounds.length).toBeGreaterThan(0)
    for (const c of bounds) expect(c.opts.params.to).toBe(end)
  })
})
