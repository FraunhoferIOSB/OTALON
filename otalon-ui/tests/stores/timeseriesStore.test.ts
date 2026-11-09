/**
 * Unit tests for the timeseries store.
 *
 * Validates feature loading, plot data fetching, anomaly interval
 * fetching, parallel fetch, getter behavior, and state mutations.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useTimeseriesStore } from '~/stores/timeseriesStore'
import { GOLDEN_FEATURES, GOLDEN_BOUNDS_DATA, GOLDEN_ALARM_INTERVALS } from '../mocks/golden-data'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

describe('timeseriesStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('fetchFeatures', () => {
    it('loads feature list from API', async () => {
      const store = useTimeseriesStore()
      await store.fetchFeatures()

      expect(store.availableFeatures).toEqual(GOLDEN_FEATURES)
    })

    it('sets visibleFeatures to the 6 defaults on first load', async () => {
      const store = useTimeseriesStore()
      await store.fetchFeatures()

      expect(store.visibleFeatures).toEqual([
        'packet_count',
        'total_volume',
        'min_packet_size',
        'max_packet_size',
        'min_interarrival_time',
        'max_interarrival_time',
      ])
    })

    it('falls back to all features when none of the defaults are available', async () => {
      server.use(errorHandlers.featuresNoDefaults)
      const store = useTimeseriesStore()
      await store.fetchFeatures()

      expect(store.visibleFeatures).toEqual(['mean_packet_size', 'std_packet_size'])
    })

    it('preserves existing visibleFeatures on re-fetch', async () => {
      const store = useTimeseriesStore()
      store.visibleFeatures = ['packet_count', 'total_volume']
      await store.fetchFeatures()

      expect(store.visibleFeatures).toEqual(['packet_count', 'total_volume'])
    })

    it('defaultVisibleFeatures returns the intersection of available and defaults', async () => {
      const store = useTimeseriesStore()
      await store.fetchFeatures()

      expect(store.defaultVisibleFeatures).toEqual([
        'packet_count',
        'total_volume',
        'min_packet_size',
        'max_packet_size',
        'min_interarrival_time',
        'max_interarrival_time',
      ])
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.features500)
      const store = useTimeseriesStore()
      await store.fetchFeatures()

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch features')
    })
  })

  describe('fetchPlotData', () => {
    it('loads plot data for each feature', async () => {
      const store = useTimeseriesStore()
      await store.fetchPlotData(
        'L2_00:1B:1B:F8:3A:02_00:1B:1B:F8:3A:03_PROFINET_RT',
        ['packet_count', 'total_volume'],
        '2026-03-07T00:00:00Z',
        '2026-03-07T23:59:59Z',
      )

      expect(store.plotData['packet_count']).toBeDefined()
      expect(store.plotData['total_volume']).toBeDefined()
      expect(store.plotData['packet_count']).toHaveLength(GOLDEN_BOUNDS_DATA.length)
    })

    it('stores TimeseriesWithBoundsItem data correctly', async () => {
      const store = useTimeseriesStore()
      await store.fetchPlotData('test-uci', ['packet_count'], '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const firstPoint = store.plotData['packet_count'][0]
      expect(firstPoint).toHaveProperty('time')
      expect(firstPoint).toHaveProperty('value')
      expect(firstPoint).toHaveProperty('value_min')
      expect(firstPoint).toHaveProperty('value_max')
      expect(firstPoint).toHaveProperty('lower_bound')
      expect(firstPoint).toHaveProperty('upper_bound')
      expect(firstPoint).toHaveProperty('violation_low')
      expect(firstPoint).toHaveProperty('violation_high')
    })
  })

  describe('fetchPlotData empty response (B-17)', () => {
    it('stores empty arrays when API returns no data', async () => {
      server.use(errorHandlers.boundsEmpty)
      const store = useTimeseriesStore()
      await store.fetchPlotData(
        'test-uci',
        ['packet_count', 'total_volume'],
        '2026-03-07T00:00:00Z',
        '2026-03-07T23:59:59Z',
      )

      expect(store.plotData['packet_count']).toBeDefined()
      expect(store.plotData['packet_count']).toHaveLength(0)
      expect(store.plotData['total_volume']).toBeDefined()
      expect(store.plotData['total_volume']).toHaveLength(0)
    })

    it('all features empty does not set error', async () => {
      server.use(errorHandlers.boundsEmpty)
      const store = useTimeseriesStore()
      await store.fetchPlotData(
        'test-uci',
        ['packet_count', 'total_volume'],
        '2026-03-07T00:00:00Z',
        '2026-03-07T23:59:59Z',
      )

      expect(store.error).toBeNull()
    })

    it('visiblePlotData includes empty arrays for visible features', async () => {
      server.use(errorHandlers.boundsEmpty)
      const store = useTimeseriesStore()
      store.visibleFeatures = ['packet_count', 'total_volume']
      await store.fetchPlotData(
        'test-uci',
        ['packet_count', 'total_volume'],
        '2026-03-07T00:00:00Z',
        '2026-03-07T23:59:59Z',
      )

      const visible = store.visiblePlotData
      expect(Object.keys(visible)).toEqual(['packet_count', 'total_volume'])
      expect(visible['packet_count']).toHaveLength(0)
      expect(visible['total_volume']).toHaveLength(0)
    })
  })

  describe('fetchPlotData single point response (B-17)', () => {
    it('stores a single data point per feature', async () => {
      server.use(errorHandlers.boundsSinglePoint)
      const store = useTimeseriesStore()
      await store.fetchPlotData('test-uci', ['packet_count'], '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.plotData['packet_count']).toHaveLength(1)
      expect(store.plotData['packet_count'][0]).toHaveProperty('time')
      expect(store.plotData['packet_count'][0]).toHaveProperty('value')
    })

    it('single point data includes bounds fields', async () => {
      server.use(errorHandlers.boundsSinglePoint)
      const store = useTimeseriesStore()
      await store.fetchPlotData('test-uci', ['packet_count'], '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const point = store.plotData['packet_count'][0]
      expect(point).toHaveProperty('lower_bound')
      expect(point).toHaveProperty('upper_bound')
      expect(point).toHaveProperty('violation_low')
      expect(point).toHaveProperty('violation_high')
    })
  })

  describe('fetchAnomalyIntervals', () => {
    it('loads alarm intervals from API', async () => {
      const store = useTimeseriesStore()
      await store.fetchAnomalyIntervals('test-uci', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.anomalyIntervals).toHaveLength(GOLDEN_ALARM_INTERVALS.length)
      expect(store.anomalyIntervals[0].start_timestamp).toBe(GOLDEN_ALARM_INTERVALS[0].start_timestamp)
      expect(store.anomalyIntervals[0].anomaly_type).toBe(GOLDEN_ALARM_INTERVALS[0].anomaly_type)
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.intervals500)
      const store = useTimeseriesStore()
      await store.fetchAnomalyIntervals('test-uci', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch anomaly intervals')
    })
  })

  describe('fetchAllForUci', () => {
    it('loads plot data and intervals in parallel', async () => {
      const store = useTimeseriesStore()
      store.availableFeatures = ['packet_count', 'total_volume']
      store.visibleFeatures = ['packet_count', 'total_volume']

      await store.fetchAllForUci('test-uci', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(Object.keys(store.plotData).length).toBeGreaterThan(0)
      expect(store.anomalyIntervals.length).toBeGreaterThan(0)
    })

    it('sets isLoading during request', async () => {
      const store = useTimeseriesStore()
      const promise = store.fetchAllForUci('test-uci', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.isLoading).toBe(true)

      await promise

      expect(store.isLoading).toBe(false)
    })

    it('clears error on success', async () => {
      const store = useTimeseriesStore()
      store.error = 'previous error'

      await store.fetchAllForUci('test-uci', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.error).toBeNull()
    })

    it('defaults visibleFeatures to plotData keys when catalog and selection are both empty', async () => {
      const store = useTimeseriesStore()

      await store.fetchAllForUci('test-uci', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.visibleFeatures.length).toBeGreaterThan(0)
      expect(store.visibleFeatures).toEqual(expect.arrayContaining(['packet_count', 'total_volume']))
    })

    it('preserves empty visibleFeatures when the feature catalog is already known', async () => {
      const store = useTimeseriesStore()
      store.availableFeatures = ['packet_count', 'total_volume']
      store.visibleFeatures = []

      await store.fetchAllForUci('test-uci', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.visibleFeatures).toEqual([])
    })
  })

  describe('visiblePlotData', () => {
    it('filters plotData by visibleFeatures', async () => {
      const store = useTimeseriesStore()
      await store.fetchPlotData(
        'test-uci',
        ['packet_count', 'total_volume', 'mean_packet_size'],
        '2026-03-07T00:00:00Z',
        '2026-03-07T23:59:59Z',
      )

      store.visibleFeatures = ['packet_count', 'total_volume']
      const visible = store.visiblePlotData

      expect(Object.keys(visible)).toEqual(['packet_count', 'total_volume'])
      expect(visible['mean_packet_size']).toBeUndefined()
    })

    it('returns empty when no features visible', async () => {
      const store = useTimeseriesStore()
      await store.fetchPlotData('test-uci', ['packet_count'], '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      store.visibleFeatures = []
      expect(Object.keys(store.visiblePlotData)).toHaveLength(0)
    })
  })

  describe('state mutations', () => {
    it('setGridColumns updates gridColumns', () => {
      const store = useTimeseriesStore()
      // Default is a single column so the feature plots line up with the
      // rhythm lane stacked above them (UI-094).
      expect(store.gridColumns).toBe(1)

      store.setGridColumns(3)
      expect(store.gridColumns).toBe(3)
    })

    it('setPlotSize updates plotSize', () => {
      const store = useTimeseriesStore()
      expect(store.plotSize).toBe('normal')

      store.setPlotSize('compact')
      expect(store.plotSize).toBe('compact')
    })

    it('setVisibleFeatures updates visibleFeatures', () => {
      const store = useTimeseriesStore()
      store.setVisibleFeatures(['packet_count', 'total_volume'])

      expect(store.visibleFeatures).toEqual(['packet_count', 'total_volume'])
    })
  })

  describe('$reset', () => {
    it('clears all data', async () => {
      const store = useTimeseriesStore()
      await store.fetchFeatures()
      await store.fetchAllForUci('test-uci', '2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.availableFeatures.length).toBeGreaterThan(0)

      store.$reset()

      expect(store.plotData).toEqual({})
      expect(store.anomalyIntervals).toEqual([])
      expect(store.availableFeatures).toEqual([])
      expect(store.visibleFeatures).toEqual([])
      expect(store.isLoading).toBe(false)
      expect(store.error).toBeNull()
      expect(store.gridColumns).toBe(1)
      expect(store.plotSize).toBe('normal')
    })
  })
})
