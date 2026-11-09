/**
 * Unit tests for operationsOverviewStore.
 *
 * Validates pipeline/attention/health fetch actions, KPI mapping, SSE
 * health update handler, error states and loading flags.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { serviceBadge, useOperationsOverviewStore } from '~/stores/operationsOverviewStore'
import type { DetectionReadinessItem, HealthCheckItem } from '~/types/api'
import { GOLDEN_ATTENTION, GOLDEN_HEALTH, GOLDEN_PIPELINE } from '../mocks/golden-data'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

describe('operationsOverviewStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('loadAll', () => {
    it('loads pipeline, attention and health', async () => {
      const store = useOperationsOverviewStore()
      await store.loadAll()

      expect(store.pipeline).toEqual(GOLDEN_PIPELINE)
      expect(store.attention).toEqual(GOLDEN_ATTENTION.findings)
      expect(store.health).toEqual(GOLDEN_HEALTH)
      expect(store.readiness?.modules).toHaveLength(3)
      expect(store.storage?.host.used_pct).toBe(62.5)
      expect(store.pipelineError).toBeNull()
      expect(store.attentionError).toBeNull()
      expect(store.healthError).toBeNull()
    })

    it('sets loading flags during request', async () => {
      const store = useOperationsOverviewStore()
      const promise = store.loadAll()

      expect(store.isLoadingPipeline).toBe(true)
      expect(store.isLoadingAttention).toBe(true)
      expect(store.isLoadingHealth).toBe(true)

      await promise

      expect(store.isLoadingPipeline).toBe(false)
      expect(store.isLoadingAttention).toBe(false)
      expect(store.isLoadingHealth).toBe(false)
    })

    it('maps the suite KPI to healthy when health is healthy', async () => {
      const store = useOperationsOverviewStore()
      await store.loadAll()

      expect(store.suiteKpi.value).toBe('Healthy')
      expect(store.suiteKpi.signal).toBe('green')
    })

    it('maps the pipeline KPI to amber when a source is stale', async () => {
      const store = useOperationsOverviewStore()
      await store.loadAll()

      expect(store.pipelineKpi.value).toBe('Needs attention')
      expect(store.pipelineKpi.signal).toBe('amber')
    })

    it('maps two of three ready modules to amber Partially ready', async () => {
      const store = useOperationsOverviewStore()
      await store.loadAll()

      expect(store.detectionKpi).toEqual({
        value: 'Partially ready',
        signal: 'amber',
        sub: '2/3 modules ready',
      })
    })

    it('maps all ready modules to green Ready', () => {
      const store = useOperationsOverviewStore()
      const module = (name: string): DetectionReadinessItem => ({
        module: name,
        state: 'ready',
        detection_mode: 'active',
        bounds_series_count: 1,
        no_bounds_count: 0,
        frequency_profile_count: 1,
        last_training: null,
        schema_version: '1',
        schema_compatible: true,
      })
      store.readiness = {
        modules: [module('conn'), module('mac_traffic'), module('proto_traffic')],
      }

      expect(store.detectionKpi.value).toBe('Ready')
      expect(store.detectionKpi.signal).toBe('green')
    })

    it('maps real host storage usage to the documented normal threshold', () => {
      const store = useOperationsOverviewStore()
      store.storage = {
        host: { total_gib: 100, used_gib: 80, free_gib: 20, used_pct: 80, mount: '/', fs: 'ext4' },
        ringbuffer: { size_gib: 1, cap_gib: 48.8, files: 2, file_cap: 2000, state: 'rotating' },
        contributors: [],
        unattributed_gib: 80,
      }

      expect(store.storageKpi).toEqual({ value: '80% used', signal: 'amber', sub: 'Attention' })
    })

    it('uses neutral Unknown KPIs when fact sources are unavailable', () => {
      const store = useOperationsOverviewStore()

      expect(store.detectionKpi).toEqual({
        value: 'Unknown',
        signal: 'grey',
        sub: 'Detection readiness unavailable',
      })
      expect(store.storageKpi.value).toBe('Unknown')
      expect(store.storageKpi.signal).toBe('grey')
    })
  })

  describe('error handling', () => {
    it('records a pipeline error when the endpoint fails', async () => {
      server.use(errorHandlers.pipeline500)
      const store = useOperationsOverviewStore()
      await store.fetchPipeline()

      expect(store.pipeline).toBeNull()
      expect(store.pipelineError).toContain('Failed to load pipeline freshness')
    })

    it('records an auth error when the endpoint returns 401', async () => {
      server.use(errorHandlers.operations401)
      const store = useOperationsOverviewStore()
      await store.fetchPipeline()

      expect(store.pipelineError).toContain('Insufficient permissions')
    })
  })

  describe('handleHealthUpdate', () => {
    it('replaces health state with SSE payload', () => {
      const store = useOperationsOverviewStore()
      const updated = { ...GOLDEN_HEALTH, overall_status: 'degraded' as const }

      store.handleHealthUpdate(updated)

      expect(store.health?.overall_status).toBe('degraded')
    })

    it('a pushed update flips the suite KPI signal', () => {
      const store = useOperationsOverviewStore()
      store.handleHealthUpdate({ ...GOLDEN_HEALTH, overall_status: 'unhealthy' as const })

      expect(store.suiteKpi.value).toBe('Unhealthy')
      expect(store.suiteKpi.signal).toBe('red')
    })
  })

  describe('getters', () => {
    it('problemServices lists only non-running services', async () => {
      const store = useOperationsOverviewStore()
      await store.fetchHealth()
      expect(store.problemServices).toEqual([])
      expect(store.healthyCount).toBe(2)
    })

    it('badgeFor maps a not-configured optional service to a non-failed badge', () => {
      const store = useOperationsOverviewStore()
      const optional: HealthCheckItem = {
        name: 'OTALON-AI',
        running: false,
        detail: 'connection refused',
        timestamp: 1,
        classification: 'optional',
        status: 'not-configured',
      }
      const badge = store.badgeFor(optional)
      expect(badge.kind).not.toBe('err')
      expect(badge.label).toBe('not configured')
    })
  })
})

describe('serviceBadge', () => {
  it('healthy → ok/healthy', () => {
    const badge = serviceBadge({ name: 'X', running: true, detail: 'ok', timestamp: 1, status: 'healthy' })
    expect(badge).toEqual({ kind: 'ok', label: 'healthy', icon: 'check_circle' })
  })

  it('failed core → err/failed', () => {
    const badge = serviceBadge({ name: 'X', running: false, detail: 'down', timestamp: 1, status: 'failed' })
    expect(badge).toEqual({ kind: 'err', label: 'failed', icon: 'cancel' })
  })

  it('not-configured optional → info/not configured (never failed)', () => {
    const badge = serviceBadge({
      name: 'AI',
      running: false,
      detail: 'refused',
      timestamp: 1,
      classification: 'optional',
      status: 'not-configured',
    })
    expect(badge.kind).toBe('info')
    expect(badge.label).toBe('not configured')
  })

  it('falls back to legacy running/classification when status is absent', () => {
    const optionalDown = serviceBadge({
      name: 'AI',
      running: false,
      detail: 'refused',
      timestamp: 1,
      classification: 'optional',
    })
    expect(optionalDown.label).toBe('not configured')
    const coreDown = serviceBadge({ name: 'PG', running: false, detail: 'down', timestamp: 1 })
    expect(coreDown.label).toBe('failed')
  })
})
