/**
 * Unit tests for the alarms store.
 *
 * Validates fetching, filtering, selection, optimistic PATCH mutations
 * with rollback, SSE update handling, and the $reset() behavior
 * against golden data.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { http, HttpResponse } from 'msw'

import { useAlarmsStore } from '~/stores/alarmsStore'
import { GOLDEN_ALARM_GROUPS } from '../mocks/golden-data'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

describe('alarmsStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('fetchGroups', () => {
    it('loads alarm groups from API', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      expect(store.groups).toHaveLength(GOLDEN_ALARM_GROUPS.length)
    })

    it('stores data matching golden data', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      expect(store.groups[0].id).toBe(GOLDEN_ALARM_GROUPS[0].id)
      expect(store.groups[0].module).toBe(GOLDEN_ALARM_GROUPS[0].module)
      expect(store.groups[0].primary_type).toBe(GOLDEN_ALARM_GROUPS[0].primary_type)
      expect(store.groups[0].confirmed).toBe(GOLDEN_ALARM_GROUPS[0].confirmed)
      expect(store.groups[0].is_active).toBe(GOLDEN_ALARM_GROUPS[0].is_active)
      expect(store.groups[0].series_ids).toEqual(GOLDEN_ALARM_GROUPS[0].series_ids)
    })

    it('sets isLoading during request', async () => {
      const store = useAlarmsStore()
      const promise = store.fetchGroups()

      expect(store.isLoading).toBe(true)

      await promise

      expect(store.isLoading).toBe(false)
    })

    it('does not set isLoading on subsequent fetches', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      expect(store.isInitialLoad).toBe(false)

      const promise = store.fetchGroups()
      expect(store.isLoading).toBe(false)
      await promise
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.groups404)
      const store = useAlarmsStore()
      await store.fetchGroups()

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch alarm groups')
    })

    it('applies filter overrides', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups({ limit: 1 })

      expect(store.groups).toHaveLength(1)
      expect(store.filter.limit).toBe(1)
    })

    it('forwards timeParams start/stop to the API', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups(undefined, {
        start: '2025-06-01T00:00:00Z',
        stop: '2025-06-01T06:00:00Z',
      })

      expect(store.groups).toBeDefined()
      expect(store.error).toBeNull()
    })

    it('merges filter and timeParams into a single request', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups(
        { module: 'netcap', limit: 2 },
        { start: '2025-06-01T00:00:00Z', stop: '2025-06-01T06:00:00Z' },
      )

      expect(store.groups).toHaveLength(2)
      expect(store.filter.module).toBe('netcap')
      expect(store.error).toBeNull()
    })

    it('resets a persisted module filter when called with module undefined (UI-039)', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups({ module: 'proto_traffic' })
      expect(store.filter.module).toBe('proto_traffic')

      await store.fetchGroups({ module: undefined })
      expect(store.filter.module).toBeUndefined()
      expect(store.error).toBeNull()
    })
  })

  describe('fetchAffectedFeatures', () => {
    it('retains bound features and marks FrequencyAnomaly series as rhythm-anomalous', async () => {
      const store = useAlarmsStore()
      const group = {
        ...GOLDEN_ALARM_GROUPS[0],
        id: 'rhythm-series',
        series_ids: ['series-bound', 'series-rhythm', 'series-plain'],
      }
      let anomalySeriesCalls = 0
      server.use(
        http.get('*/api/v1/anomalies/series', ({ request }) => {
          anomalySeriesCalls += 1
          expect(new URL(request.url).searchParams.get('uci')).toBeNull()
          return HttpResponse.json({
            data: [
              { series_id: 'series-bound', anomaly_type: 'BoundViolation', violated_features: ['packet_count'] },
              { series_id: 'series-rhythm', anomaly_type: 'FrequencyAnomaly', violated_features: [] },
              { series_id: 'series-plain', anomaly_type: 'BoundViolation', violated_features: [] },
            ],
          })
        }),
      )

      await store.fetchAffectedFeatures(group)

      const cache = store.affectedFeaturesByGroup[group.id]
      expect(cache?.bySeries['series-bound']?.features).toEqual(['packet_count'])
      expect(cache?.bySeries['series-bound']?.rhythmAnomaly).toBe(false)
      expect(cache?.bySeries['series-rhythm']?.rhythmAnomaly).toBe(true)
      expect(cache?.bySeries['series-plain']?.rhythmAnomaly).toBe(false)
      expect(anomalySeriesCalls).toBe(1)
    })

    it('marks AbsenceAnomaly series as rhythm-anomalous without feature values', async () => {
      const store = useAlarmsStore()
      const group = { ...GOLDEN_ALARM_GROUPS[0], id: 'absence-series', series_ids: ['series-absence'] }
      server.use(
        http.get('*/api/v1/anomalies/series', () =>
          HttpResponse.json({ data: [{ series_id: 'series-absence', anomaly_type: 'AbsenceAnomaly', violated_features: [] }] }),
        ),
      )

      await store.fetchAffectedFeatures(group)

      const entry = store.affectedFeaturesByGroup[group.id]?.bySeries['series-absence']
      expect(entry?.features).toEqual([])
      expect(entry?.rhythmAnomaly).toBe(true)
    })

    it('queries conn for slash-bearing series in multi-type groups', async () => {
      const store = useAlarmsStore()
      const group = {
        ...GOLDEN_ALARM_GROUPS[0],
        id: 'multi-conn',
        module: 'multi' as const,
        series_ids: ['00:01:05:2b:ae:a2/a8:74:1d:02:99:8d/0//////Ethernet:VLAN:PROFINET_RT'],
        enrichment: { mac: [], proto: [] },
      }
      server.use(
        http.get('*/api/v1/anomalies/series', ({ request }) => {
          const params = new URL(request.url).searchParams
          if (params.get('module') !== 'conn') return HttpResponse.json({ data: [] })
          return HttpResponse.json({
            data: [{ series_id: group.series_ids[0], violated_features: ['packet_count'] }],
          })
        }),
      )

      await store.fetchAffectedFeatures(group)

      expect(group.affected_features).toEqual(['packet_count'])
      expect(store.affectedFeaturesByGroup[group.id]?.bySeries[group.series_ids[0]]?.features).toEqual(['packet_count'])
    })

    it('keeps affected features scoped to each series while retaining the group union', async () => {
      const store = useAlarmsStore()
      const group = {
        ...GOLDEN_ALARM_GROUPS[0],
        id: 'multi-series',
        module: 'multi' as const,
        series_ids: ['series-a', 'series-b'],
        enrichment: { mac: [{ module: 'mac_traffic' }], proto: [] },
      }
      let anomalySeriesCalls = 0
      server.use(
        http.get('*/api/v1/anomalies/series', ({ request }) => {
          anomalySeriesCalls += 1
          const params = new URL(request.url).searchParams
          if (params.get('module') === 'mac_traffic') {
            return HttpResponse.json({
              data: [
                { series_id: 'series-a', violated_features: ['mac_a'] },
                { series_id: 'series-b', violated_features: ['mac_b'] },
              ],
            })
          }
          return HttpResponse.json({ data: [] })
        }),
      )

      await store.fetchAffectedFeatures(group)

      const cache = store.affectedFeaturesByGroup[group.id]
      expect(cache?.bySeries['series-a']?.features).toEqual(['mac_a'])
      expect(cache?.bySeries['series-b']?.features).toEqual(['mac_b'])
      expect(cache?.features).toEqual(['mac_a', 'mac_b'])
      expect(anomalySeriesCalls).toBe(1)
    })

    it('runs the NoBounds fallback once per module (not per series) even when only one series is missing features', async () => {
      const store = useAlarmsStore()
      const group = {
        ...GOLDEN_ALARM_GROUPS[0],
        id: 'mixed-fallback-series',
        series_ids: ['series-with-features', 'series-without-features'],
      }
      const boundsModuleCalls: string[] = []
      let anomalySeriesCalls = 0
      server.use(
        http.get('*/api/v1/anomalies/series', ({ request }) => {
          anomalySeriesCalls += 1
          expect(new URL(request.url).searchParams.get('uci')).toBeNull()
          return HttpResponse.json({
            data: [
              { series_id: 'series-with-features', violated_features: ['packet_count'] },
              { series_id: 'series-without-features', anomaly_type: 'NoBounds', violated_features: [] },
            ],
          })
        }),
        http.get('*/api/v1/operations/bounds', ({ request }) => {
          const params = new URL(request.url).searchParams
          boundsModuleCalls.push(String(params.get('module')))
          // Regression guard (UI-143 N+1 fan-out, fixed 2026-08-19): the endpoint
          // must be called once per module, never per series (`q` no longer sent).
          expect(params.get('q')).toBeNull()
          return HttpResponse.json({
            items: [
              { series_id: 'series-with-features', affected_features: ['packet_count'] },
              { series_id: 'series-without-features', affected_features: ['octet_count'] },
            ],
          })
        }),
      )

      await store.fetchAffectedFeatures(group)

      const cache = store.affectedFeaturesByGroup[group.id]
      expect(anomalySeriesCalls).toBe(1)
      expect(boundsModuleCalls).toEqual(['conn'])
      expect(cache?.bySeries['series-with-features']?.features).toEqual(['packet_count'])
      expect(cache?.bySeries['series-without-features']).toEqual({
        features: ['octet_count'],
        state: 'NoBounds',
        rhythmAnomaly: false,
      })
      expect(cache?.features).toEqual(['octet_count', 'packet_count'])
    })
  })

  describe('isInitialLoad', () => {
    it('starts as true', () => {
      const store = useAlarmsStore()
      expect(store.isInitialLoad).toBe(true)
    })

    it('becomes false after first fetchGroups', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      expect(store.isInitialLoad).toBe(false)
    })
  })

  describe('selectGroup', () => {
    it('sets selectedGroupId', async () => {
      const store = useAlarmsStore()
      const targetId = GOLDEN_ALARM_GROUPS[0].id

      store.selectGroup(targetId)

      expect(store.selectedGroupId).toBe(targetId)
    })
  })

  describe('selectedGroup getter', () => {
    it('returns the correct group', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      store.selectGroup(GOLDEN_ALARM_GROUPS[1].id)

      expect(store.selectedGroup).toBeDefined()
      expect(store.selectedGroup!.id).toBe(GOLDEN_ALARM_GROUPS[1].id)
    })

    it('returns undefined when no selection', () => {
      const store = useAlarmsStore()

      expect(store.selectedGroup).toBeUndefined()
    })
  })

  describe('filteredGroups getter', () => {
    it('returns all groups when no status filter', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      expect(store.filteredGroups).toHaveLength(GOLDEN_ALARM_GROUPS.length)
    })

    it('filters by active status', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()
      store.filter = { ...store.filter, status: 'active' }

      const activeGroups = GOLDEN_ALARM_GROUPS.filter((g) => g.is_active)
      expect(store.filteredGroups).toHaveLength(activeGroups.length)
      for (const group of store.filteredGroups) {
        expect(group.is_active).toBe(true)
      }
    })

    it('filters by confirmed status', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()
      store.filter = { ...store.filter, status: 'confirmed' }

      const confirmedGroups = GOLDEN_ALARM_GROUPS.filter((g) => g.confirmed)
      expect(store.filteredGroups).toHaveLength(confirmedGroups.length)
      for (const group of store.filteredGroups) {
        expect(group.confirmed).toBe(true)
      }
    })
  })

  describe('activeCount getter', () => {
    it('returns correct count', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      const expected = GOLDEN_ALARM_GROUPS.filter((g) => g.is_active).length
      expect(store.activeCount).toBe(expected)
    })
  })

  describe('confirmedCount getter', () => {
    it('returns correct count', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      const expected = GOLDEN_ALARM_GROUPS.filter((g) => g.confirmed).length
      expect(store.confirmedCount).toBe(expected)
    })
  })

  describe('totalCount getter', () => {
    it('returns correct count', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      expect(store.totalCount).toBe(GOLDEN_ALARM_GROUPS.length)
    })
  })

  describe('connectionCount getter', () => {
    it('counts unique series_ids', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      const allSeriesIds = new Set<string>()
      for (const group of GOLDEN_ALARM_GROUPS) {
        for (const sid of group.series_ids) {
          allSeriesIds.add(sid)
        }
      }
      expect(store.connectionCount).toBe(allSeriesIds.size)
    })
  })

  describe('confirmGroup', () => {
    it('sends PATCH with confirmed=true', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      const groupId = GOLDEN_ALARM_GROUPS[0].id
      await store.confirmGroup(groupId)

      const group = store.groups.find((g) => g.id === groupId)
      expect(group!.confirmed).toBe(true)
    })

    it('applies optimistic update immediately', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      const groupId = GOLDEN_ALARM_GROUPS[0].id
      expect(store.groups.find((g) => g.id === groupId)!.confirmed).toBe(false)

      const promise = store.confirmGroup(groupId)

      expect(store.groups.find((g) => g.id === groupId)!.confirmed).toBe(true)

      await promise
    })

    it('rollbacks on API error', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      server.use(
        http.patch('*/api/v1/anomalies/groups/:groupId', () => {
          return HttpResponse.json({ detail: 'Internal Server Error' }, { status: 500 })
        }),
      )

      const groupId = GOLDEN_ALARM_GROUPS[0].id
      await store.confirmGroup(groupId)

      expect(store.groups.find((g) => g.id === groupId)!.confirmed).toBe(false)
      expect(store.error).toContain('Failed to confirm group')
    })

    it('tracks patchingIds during flight', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      const groupId = GOLDEN_ALARM_GROUPS[0].id
      const promise = store.confirmGroup(groupId)

      expect(store.patchingIds).toContain(groupId)

      await promise

      expect(store.patchingIds).not.toContain(groupId)
    })
  })

  describe('unconfirmGroup', () => {
    it('sends PATCH with confirmed=false', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      const groupId = GOLDEN_ALARM_GROUPS[2].id
      expect(store.groups.find((g) => g.id === groupId)!.confirmed).toBe(true)

      await store.unconfirmGroup(groupId)

      expect(store.groups.find((g) => g.id === groupId)!.confirmed).toBe(false)
    })

    it('applies optimistic update immediately', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      const groupId = GOLDEN_ALARM_GROUPS[2].id
      expect(store.groups.find((g) => g.id === groupId)!.confirmed).toBe(true)

      const promise = store.unconfirmGroup(groupId)

      expect(store.groups.find((g) => g.id === groupId)!.confirmed).toBe(false)

      await promise
    })
  })

  describe('handleAnomalyUpdate', () => {
    it('updates existing group', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      const updatedGroup = {
        ...GOLDEN_ALARM_GROUPS[0],
        confirmed: true,
        is_active: true,
      }

      store.handleAnomalyUpdate(updatedGroup)

      const group = store.groups.find((g) => g.id === GOLDEN_ALARM_GROUPS[0].id)
      expect(group!.confirmed).toBe(true)
      expect(group!.is_active).toBe(true)
      expect(store.groups).toHaveLength(GOLDEN_ALARM_GROUPS.length)
    })

    it('prepends new group', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()

      const newGroup = {
        ...GOLDEN_ALARM_GROUPS[0],
        id: 'brand-new-group-id',
      }

      store.handleAnomalyUpdate(newGroup)

      expect(store.groups).toHaveLength(GOLDEN_ALARM_GROUPS.length + 1)
      expect(store.groups[0].id).toBe('brand-new-group-id')
    })
  })

  describe('$reset', () => {
    it('clears all state', async () => {
      const store = useAlarmsStore()
      await store.fetchGroups()
      store.selectGroup(GOLDEN_ALARM_GROUPS[0].id)
      store.filter = { module: 'netcap', status: 'active' }

      store.$reset()

      expect(store.groups).toEqual([])
      expect(store.selectedGroupId).toBeNull()
      // $reset() restores the store's INITIAL state, which carries the
      // default page size ({ limit: 50 }, alarmsStore.ts:94) — not an
      // empty object. The old expectation described a default the store
      // never had, so this test was permanently red (SUITE-034).
      expect(store.filter).toEqual({ limit: 50 })
      expect(store.isLoading).toBe(false)
      expect(store.error).toBeNull()
      expect(store.patchingIds).toEqual([])
      expect(store.isInitialLoad).toBe(true)
    })
  })
})
