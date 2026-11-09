/**
 * Unit tests for the app store.
 *
 * Validates all state mutations, getters, and the $reset() behavior
 * of the central application store.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useAppStore } from '~/stores/appStore'

describe('appStore', () => {
  beforeEach(() => {
    localStorage.clear()
    setActivePinia(createPinia())
  })

  describe('toggleLiveMode', () => {
    it('toggles between true and false', () => {
      const store = useAppStore()
      expect(store.liveMode).toBe(true)

      store.toggleLiveMode()
      expect(store.liveMode).toBe(false)

      store.toggleLiveMode()
      expect(store.liveMode).toBe(true)
    })
  })

  describe('setLiveMode', () => {
    it('sets the live mode explicitly', () => {
      const store = useAppStore()

      store.setLiveMode(false)
      expect(store.liveMode).toBe(false)

      store.setLiveMode(true)
      expect(store.liveMode).toBe(true)
    })
  })

  describe('setLiveInterval', () => {
    it('accepts valid intervals only', () => {
      const store = useAppStore()
      const validIntervals = [60, 300, 600, 900, 1800, 3600]

      for (const interval of validIntervals) {
        store.setLiveInterval(interval)
        expect(store.liveIntervalSeconds).toBe(interval)
      }
    })

    it('rejects invalid intervals', () => {
      const store = useAppStore()
      const originalInterval = store.liveIntervalSeconds

      store.setLiveInterval(30)
      expect(store.liveIntervalSeconds).toBe(originalInterval)

      store.setLiveInterval(120)
      expect(store.liveIntervalSeconds).toBe(originalInterval)

      store.setLiveInterval(86400)
      expect(store.liveIntervalSeconds).toBe(originalInterval)

      store.setLiveInterval(999)
      expect(store.liveIntervalSeconds).toBe(originalInterval)

      store.setLiveInterval(0)
      expect(store.liveIntervalSeconds).toBe(originalInterval)

      store.setLiveInterval(-1)
      expect(store.liveIntervalSeconds).toBe(originalInterval)
    })
  })

  describe('setTimeRange', () => {
    it('accepts a valid range where start < end', () => {
      const store = useAppStore()
      const start = '2025-01-01T00:00:00Z'
      const end = '2025-01-01T01:00:00Z'

      const accepted = store.setTimeRange(start, end)

      expect(accepted).toBe(true)
      expect(store.timeRange.start).toBe(start)
      expect(store.timeRange.end).toBe(end)
    })

    it('rejects a range where start > end', () => {
      const store = useAppStore()
      const originalRange = { ...store.timeRange }

      const accepted = store.setTimeRange('2025-06-15T12:00:00Z', '2025-06-15T06:00:00Z')

      expect(accepted).toBe(false)
      expect(store.timeRange.start).toBe(originalRange.start)
      expect(store.timeRange.end).toBe(originalRange.end)
    })

    it('rejects a range where start equals end', () => {
      const store = useAppStore()
      const originalRange = { ...store.timeRange }
      const same = '2025-03-01T10:00:00Z'

      const accepted = store.setTimeRange(same, same)

      expect(accepted).toBe(false)
      expect(store.timeRange.start).toBe(originalRange.start)
      expect(store.timeRange.end).toBe(originalRange.end)
    })

    it('rejects an inverted range spanning different days', () => {
      const store = useAppStore()
      const originalRange = { ...store.timeRange }

      const accepted = store.setTimeRange('2025-12-31T00:00:00Z', '2025-01-01T00:00:00Z')

      expect(accepted).toBe(false)
      expect(store.timeRange.start).toBe(originalRange.start)
      expect(store.timeRange.end).toBe(originalRange.end)
    })

    it('preserves last valid range after a rejected update', () => {
      const store = useAppStore()
      const validStart = '2025-02-01T00:00:00Z'
      const validEnd = '2025-02-01T12:00:00Z'

      store.setTimeRange(validStart, validEnd)

      const rejected = store.setTimeRange('2025-02-01T18:00:00Z', '2025-02-01T06:00:00Z')

      expect(rejected).toBe(false)
      expect(store.timeRange.start).toBe(validStart)
      expect(store.timeRange.end).toBe(validEnd)
    })
  })

  describe('toggleSidebar', () => {
    it('toggles sidebarExpanded', () => {
      const store = useAppStore()
      expect(store.sidebarExpanded).toBe(false)

      store.toggleSidebar()
      expect(store.sidebarExpanded).toBe(true)

      store.toggleSidebar()
      expect(store.sidebarExpanded).toBe(false)
    })
  })

  describe('setTheme', () => {
    it('updates theme', () => {
      const store = useAppStore()

      store.setTheme('light')
      expect(store.theme).toBe('light')

      store.setTheme('dark')
      expect(store.theme).toBe('dark')
    })
  })

  describe('toggleTheme', () => {
    it('switches between light and dark', () => {
      const store = useAppStore()
      store.setTheme('dark')

      store.toggleTheme()
      expect(store.theme).toBe('light')

      store.toggleTheme()
      expect(store.theme).toBe('dark')
    })
  })

  describe('setSseStatus', () => {
    it('updates sseConnectionStatus', () => {
      const store = useAppStore()

      store.setSseStatus('connected')
      expect(store.sseConnectionStatus).toBe('connected')

      store.setSseStatus('reconnecting')
      expect(store.sseConnectionStatus).toBe('reconnecting')

      store.setSseStatus('disconnected')
      expect(store.sseConnectionStatus).toBe('disconnected')
    })
  })

  describe('setPollingInterval', () => {
    it('accepts valid polling intervals', () => {
      const store = useAppStore()
      const validIntervals = [10_000, 15_000, 30_000, 60_000, 120_000]

      for (const interval of validIntervals) {
        store.setPollingInterval(interval)
        expect(store.pollingIntervalMs).toBe(interval)
      }
    })

    it('rejects invalid polling intervals', () => {
      const store = useAppStore()
      const originalInterval = store.pollingIntervalMs

      store.setPollingInterval(7500)
      expect(store.pollingIntervalMs).toBe(originalInterval)

      store.setPollingInterval(45_000)
      expect(store.pollingIntervalMs).toBe(originalInterval)

      store.setPollingInterval(0)
      expect(store.pollingIntervalMs).toBe(originalInterval)

      store.setPollingInterval(-1)
      expect(store.pollingIntervalMs).toBe(originalInterval)
    })
  })

  describe('pollingIntervalOptions getter', () => {
    it('returns the six polling interval options', () => {
      const store = useAppStore()
      const options = store.pollingIntervalOptions

      expect(options).toHaveLength(6)
      expect(options[0]).toEqual({ label: '5s', value: 5_000 })
      expect(options[1]).toEqual({ label: '10s', value: 10_000 })
      expect(options[2]).toEqual({ label: '15s', value: 15_000 })
      expect(options[3]).toEqual({ label: '30s', value: 30_000 })
      expect(options[4]).toEqual({ label: '60s', value: 60_000 })
      expect(options[5]).toEqual({ label: '120s', value: 120_000 })
    })
  })

  describe('isDark getter', () => {
    it('returns true for dark theme', () => {
      const store = useAppStore()
      store.setTheme('dark')
      expect(store.isDark).toBe(true)

      store.setTheme('light')
      expect(store.isDark).toBe(false)
    })
  })

  describe('sidebarMini getter', () => {
    it('returns inverted sidebarExpanded', () => {
      const store = useAppStore()
      expect(store.sidebarMini).toBe(true)

      store.toggleSidebar()
      expect(store.sidebarMini).toBe(false)
    })
  })

  describe('intervalOptions getter', () => {
    it('returns the six live-window options', () => {
      const store = useAppStore()
      const options = store.intervalOptions

      expect(options).toHaveLength(6)
      expect(options[0]).toEqual({ label: '1m', value: 60 })
      expect(options[1]).toEqual({ label: '5m', value: 300 })
      expect(options[2]).toEqual({ label: '10m', value: 600 })
      expect(options[3]).toEqual({ label: '15m', value: 900 })
      expect(options[4]).toEqual({ label: '30m', value: 1800 })
      expect(options[5]).toEqual({ label: '60m', value: 3600 })
    })
  })

  describe('effectiveTimeRange getter', () => {
    it('returns a sliding window in live mode', () => {
      const store = useAppStore()
      store.setLiveMode(true)
      store.setLiveInterval(300)

      const before = Date.now()
      const range = store.effectiveTimeRange
      const after = Date.now()

      const startMs = new Date(range.start).getTime()
      const endMs = new Date(range.end).getTime()
      const windowMs = endMs - startMs

      expect(windowMs).toBeGreaterThanOrEqual(299_000)
      expect(windowMs).toBeLessThanOrEqual(301_000)
      expect(endMs).toBeGreaterThanOrEqual(before)
      expect(endMs).toBeLessThanOrEqual(after + 50)
    })

    it('reflects the selected interval width', () => {
      const store = useAppStore()
      store.setLiveMode(true)
      store.setLiveInterval(3600)

      const range = store.effectiveTimeRange
      const windowMs = new Date(range.end).getTime() - new Date(range.start).getTime()

      expect(windowMs).toBeGreaterThanOrEqual(3_599_000)
      expect(windowMs).toBeLessThanOrEqual(3_601_000)
    })

    it('returns the manual timeRange in history mode', () => {
      const store = useAppStore()
      store.setLiveMode(false)
      store.setTimeRange('2025-06-01T00:00:00Z', '2025-06-01T12:00:00Z')

      const range = store.effectiveTimeRange

      expect(range.start).toBe('2025-06-01T00:00:00Z')
      expect(range.end).toBe('2025-06-01T12:00:00Z')
    })
  })

  describe('apiTimeParams getter', () => {
    it('maps effectiveTimeRange end to stop', () => {
      const store = useAppStore()
      store.setLiveMode(false)
      store.setTimeRange('2025-01-01T00:00:00Z', '2025-01-01T06:00:00Z')

      const params = store.apiTimeParams

      expect(params.start).toBe('2025-01-01T00:00:00Z')
      expect(params.stop).toBe('2025-01-01T06:00:00Z')
    })
  })

  describe('timeRangeLabel getter', () => {
    it('names the selected live window', () => {
      const store = useAppStore()
      store.setLiveMode(true)
      store.setLiveInterval(300)

      expect(store.timeRangeLabel).toBe('Last 5m')
    })

    it('follows the live interval after a period change', () => {
      const store = useAppStore()
      store.setLiveMode(true)
      store.setLiveInterval(900)

      expect(store.timeRangeLabel).toBe('Last 15m')

      store.setLiveInterval(3600)
      expect(store.timeRangeLabel).toBe('Last 60m')
    })

    it('renders the applied history window in history mode', () => {
      const store = useAppStore()
      store.setLiveMode(false)
      store.setTimeRange('2025-06-01T00:00:00Z', '2025-06-01T12:00:00Z')

      const label = store.timeRangeLabel

      expect(label).not.toBe('Last hour')
      expect(label).toContain('–')
    })

    it('falls back to a seconds label for an out-of-set interval', () => {
      const store = useAppStore()
      store.setLiveMode(true)
      store.liveIntervalSeconds = 42

      expect(store.timeRangeLabel).toBe('Last 42s')
    })
  })

  describe('$reset', () => {
    it('restores default values', () => {
      const store = useAppStore()

      store.setLiveMode(false)
      store.toggleSidebar()
      store.setSseStatus('connected')
      store.setLiveInterval(60)
      store.setPollingInterval(60_000)

      localStorage.clear()
      store.$reset()

      expect(store.liveMode).toBe(true)
      expect(store.sidebarExpanded).toBe(false)
      expect(store.sseConnectionStatus).toBe('disconnected')
      expect(store.pollingIntervalMs).toBe(5_000)
    })
  })
})
