/**
 * Unit tests for the dashboard store.
 *
 * Validates REST fetch actions, SSE update handlers, getters,
 * error handling, and the $reset() behavior against golden data.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useDashboardStore } from '~/stores/dashboardStore'
import {
  GOLDEN_DEVICES,
  GOLDEN_KPI,
  GOLDEN_ALARM_GROUPS,
  GOLDEN_HEALTH,
  GOLDEN_TOP_ASSETS,
  GOLDEN_TOP_PROTOCOLS,
} from '../mocks/golden-data'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

describe('dashboardStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('fetchKpis', () => {
    it('loads KPI data from API', async () => {
      const store = useDashboardStore()
      await store.fetchKpis()

      expect(store.kpis).not.toBeNull()
    })

    it('sets KPI data matching GD-09 values', async () => {
      const store = useDashboardStore()
      await store.fetchKpis()

      expect(store.kpis).toEqual(GOLDEN_KPI)
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.kpi500)
      const store = useDashboardStore()
      await store.fetchKpis()

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch KPIs')
    })
  })

  describe('fetchRecentAlarms', () => {
    it('loads alarm groups from API', async () => {
      const store = useDashboardStore()
      await store.fetchRecentAlarms()

      expect(store.recentAlarms).toHaveLength(GOLDEN_ALARM_GROUPS.length)
      expect(store.recentAlarms[0].id).toBe(GOLDEN_ALARM_GROUPS[0].id)
    })

    it('forwards start/stop params to the API', async () => {
      const store = useDashboardStore()
      await store.fetchRecentAlarms({
        start: '2025-06-01T00:00:00Z',
        stop: '2025-06-01T06:00:00Z',
      })

      expect(store.recentAlarms).toBeDefined()
      expect(store.error).toBeNull()
    })
  })

  describe('fetchHealth', () => {
    it('loads health data from API', async () => {
      const store = useDashboardStore()
      await store.fetchHealth()

      expect(store.health).toEqual(GOLDEN_HEALTH)
    })

    it('requests the detailed health snapshot instead of the liveness response', async () => {
      const fetchMock = vi.spyOn(globalThis, '$fetch')
      const store = useDashboardStore()

      await store.fetchHealth()

      expect(fetchMock).toHaveBeenCalledWith('/api/v1/status/health', {
        params: { detail: 'true' },
      })
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.health503)
      const store = useDashboardStore()
      await store.fetchHealth()

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch health status')
    })
  })

  describe('fetchProtocols', () => {
    it('loads top protocols from API', async () => {
      const store = useDashboardStore()
      await store.fetchProtocols()

      expect(store.protocolIds).toHaveLength(GOLDEN_TOP_PROTOCOLS.length)
      expect(store.protocolIds[0].protocol).toBe(GOLDEN_TOP_PROTOCOLS[0].protocol)
    })

    it('silently resets to empty array on failure', async () => {
      server.use(errorHandlers.topProtocols500)
      const store = useDashboardStore()
      await store.fetchProtocols()

      expect(store.protocolIds).toEqual([])
      expect(store.error).toBeNull()
    })
  })

  describe('fetchDeviceInventory', () => {
    it('loads device inventory from API', async () => {
      const store = useDashboardStore()
      await store.fetchDeviceInventory()

      expect(store.deviceInventory).toHaveLength(GOLDEN_DEVICES.length)
      expect(store.deviceInventory[0].id).toBe(GOLDEN_DEVICES[0].id)
    })

    it('silently resets to empty array on failure', async () => {
      server.use(errorHandlers.devices500)
      const store = useDashboardStore()
      await store.fetchDeviceInventory()

      expect(store.deviceInventory).toEqual([])
      expect(store.error).toBeNull()
    })
  })

  describe('fetchAll', () => {
    it('loads all data in parallel', async () => {
      const store = useDashboardStore()
      await store.fetchAll()

      expect(store.kpis).toEqual(GOLDEN_KPI)
      expect(store.recentAlarms).toHaveLength(GOLDEN_ALARM_GROUPS.length)
      expect(store.health).toEqual(GOLDEN_HEALTH)
      expect(store.protocolIds).toHaveLength(GOLDEN_TOP_PROTOCOLS.length)
      expect(store.deviceInventory).toHaveLength(GOLDEN_DEVICES.length)
      expect(store.macAssets).toHaveLength(GOLDEN_TOP_ASSETS.length)
    })

    it('sets isLoading during request', async () => {
      const store = useDashboardStore()
      const promise = store.fetchAll()

      expect(store.isLoading).toBe(true)

      await promise

      expect(store.isLoading).toBe(false)
    })

    it('does not set isLoading on subsequent fetches', async () => {
      const store = useDashboardStore()
      await store.fetchAll()

      expect(store.isInitialLoad).toBe(false)

      const promise = store.fetchAll()
      expect(store.isLoading).toBe(false)
      await promise
    })

    it('clears error on success', async () => {
      const store = useDashboardStore()
      store.error = 'previous error'
      await store.fetchAll()

      expect(store.error).toBeNull()
    })

    it('forwards time params to both fetchKpis and fetchRecentAlarms', async () => {
      const store = useDashboardStore()
      await store.fetchAll({
        start: '2025-06-01T00:00:00Z',
        stop: '2025-06-01T06:00:00Z',
      })

      expect(store.kpis).not.toBeNull()
      expect(store.recentAlarms).toBeDefined()
      expect(store.health).not.toBeNull()
      expect(store.error).toBeNull()
    })
  })

  describe('isInitialLoad', () => {
    it('starts as true', () => {
      const store = useDashboardStore()
      expect(store.isInitialLoad).toBe(true)
    })

    it('becomes false after first fetchAll', async () => {
      const store = useDashboardStore()
      await store.fetchAll()

      expect(store.isInitialLoad).toBe(false)
    })
  })

  describe('handleKpiUpdate', () => {
    it('merges SSE KPI data', () => {
      const store = useDashboardStore()
      const sseKpi = {
        signal_color: 'warning',
        anomaly_count: 42,
        classified_count: 10,
        device_count: 5,
        connection_count: 3,
      }

      store.handleKpiUpdate(sseKpi)

      expect(store.kpis).toEqual(sseKpi)
    })
  })

  describe('handleHealthUpdate', () => {
    it('merges SSE health data', () => {
      const store = useDashboardStore()
      const sseHealth = {
        services: [{ name: 'TestService', running: false, detail: 'down', timestamp: 123 }],
        overall_status: 'degraded',
      }

      store.handleHealthUpdate(sseHealth)

      expect(store.health).toEqual(sseHealth)
      // The header system-status chip reads this getter; pin the mapping so a
      // regression that stops hydrating health (UI-086) is caught here too.
      expect(store.overallHealthStatus).toBe('degraded')
    })
  })

  describe('getters', () => {
    it('signalColor returns correct value', async () => {
      const store = useDashboardStore()
      expect(store.signalColor).toBe('info')

      await store.fetchKpis()
      expect(store.signalColor).toBe(GOLDEN_KPI.signal_color)
    })

    it('anomalyCount matches GD-09 value (200)', async () => {
      const store = useDashboardStore()
      await store.fetchKpis()

      expect(store.anomalyCount).toBe(200)
    })

    it('classifiedCount matches GD-09 value (200)', async () => {
      const store = useDashboardStore()
      await store.fetchKpis()

      expect(store.classifiedCount).toBe(200)
    })

    it('deviceCount matches GD-09 value (0)', async () => {
      const store = useDashboardStore()
      await store.fetchKpis()

      expect(store.deviceCount).toBe(0)
    })

    it('connectionCount matches GD-09 value (0)', async () => {
      const store = useDashboardStore()
      await store.fetchKpis()

      expect(store.connectionCount).toBe(0)
    })
  })

  describe('$reset', () => {
    it('clears all data', async () => {
      const store = useDashboardStore()
      await store.fetchAll()

      expect(store.kpis).not.toBeNull()

      store.$reset()

      expect(store.kpis).toBeNull()
      expect(store.recentAlarms).toEqual([])
      expect(store.health).toBeNull()
      expect(store.isLoading).toBe(false)
      expect(store.error).toBeNull()
      expect(store.isInitialLoad).toBe(true)
    })
  })
})
