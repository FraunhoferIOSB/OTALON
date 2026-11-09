/**
 * Unit tests for the MAC timeseries store.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useMacTimeseriesStore } from '~/stores/macTimeseriesStore'
import { GOLDEN_MAC_FEATURES, GOLDEN_MAC_BOUNDS_DATA, GOLDEN_MAC_ALARM_INTERVALS } from '../mocks/golden-data'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

describe('macTimeseriesStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('fetchFeatures', () => {
    it('loads MAC feature list from API', async () => {
      const store = useMacTimeseriesStore()
      await store.fetchFeatures()

      expect(store.availableFeatures).toEqual(GOLDEN_MAC_FEATURES)
    })

    it('sets visibleFeatures to default subset on first load', async () => {
      const store = useMacTimeseriesStore()
      await store.fetchFeatures()

      expect(store.visibleFeatures.length).toBeGreaterThan(0)
      expect(store.visibleFeatures.length).toBeLessThan(GOLDEN_MAC_FEATURES.length)
    })

    it('preserves existing visibleFeatures on re-fetch', async () => {
      const store = useMacTimeseriesStore()
      store.visibleFeatures = ['out_total_packets', 'out_total_volume']
      await store.fetchFeatures()

      expect(store.visibleFeatures).toEqual(['out_total_packets', 'out_total_volume'])
    })

    it('defaultVisibleFeatures returns the intersection of available and defaults', async () => {
      const store = useMacTimeseriesStore()
      await store.fetchFeatures()

      expect(store.defaultVisibleFeatures.length).toBeGreaterThan(0)
      expect(store.defaultVisibleFeatures.every((f) => GOLDEN_MAC_FEATURES.includes(f))).toBe(true)
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.macFeatures500)
      const store = useMacTimeseriesStore()
      await store.fetchFeatures()

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch MAC features')
    })
  })

  describe('fetchPlotData', () => {
    it('loads plot data for MAC features', async () => {
      const store = useMacTimeseriesStore()
      await store.fetchPlotData(
        '00:1b:1b:f8:3a:02',
        ['out_total_packets', 'out_total_volume'],
        '2026-03-07T00:00:00Z',
        '2026-03-07T23:59:59Z',
      )

      expect(store.plotData['out_total_packets']).toBeDefined()
      expect(store.plotData['out_total_volume']).toBeDefined()
      expect(store.plotData['out_total_packets']).toHaveLength(GOLDEN_MAC_BOUNDS_DATA.length)
    })
  })

  describe('fetchAnomalyIntervals', () => {
    it('loads MAC alarm intervals from API', async () => {
      const store = useMacTimeseriesStore()
      await store.fetchAnomalyIntervals('00:1b:1b:f8:3a:02', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.anomalyIntervals).toHaveLength(GOLDEN_MAC_ALARM_INTERVALS.length)
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.macIntervals500)
      const store = useMacTimeseriesStore()
      await store.fetchAnomalyIntervals('00:1b:1b:f8:3a:02', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch MAC anomaly intervals')
    })
  })

  describe('fetchAllForMac', () => {
    it('loads plot data and intervals in parallel', async () => {
      const store = useMacTimeseriesStore()
      store.availableFeatures = ['out_total_packets', 'out_total_volume']
      store.visibleFeatures = ['out_total_packets', 'out_total_volume']

      await store.fetchAllForMac('00:1b:1b:f8:3a:02', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(Object.keys(store.plotData).length).toBeGreaterThan(0)
      expect(store.anomalyIntervals.length).toBeGreaterThan(0)
    })

    it('sets isLoading during request', async () => {
      const store = useMacTimeseriesStore()
      const promise = store.fetchAllForMac('00:1b:1b:f8:3a:02', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.isLoading).toBe(true)
      await promise
      expect(store.isLoading).toBe(false)
    })
  })
})
