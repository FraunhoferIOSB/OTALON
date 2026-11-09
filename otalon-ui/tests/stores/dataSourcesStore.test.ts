/**
 * Unit tests for dataSourcesStore.
 *
 * Validates capture status + pipeline fetching, friendly label mapping
 * (const and getter), non-causal stale banner semantics, and error handling.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { DATA_SOURCE_LABELS, staleBannerText, useDataSourcesStore } from '~/stores/dataSourcesStore'
import {
  GOLDEN_CAPTURE_STATUS,
  GOLDEN_PASSIVE_DISCOVERY,
  GOLDEN_PASSIVE_SEEDER_STATUS,
  GOLDEN_PIPELINE,
} from '../mocks/golden-data'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

describe('dataSourcesStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('loadAll', () => {
    it('loads pipeline, capture status and passive discovery', async () => {
      const store = useDataSourcesStore()
      await store.loadAll()

      expect(store.pipeline).toEqual(GOLDEN_PIPELINE)
      expect(store.captureStatus).toEqual(GOLDEN_CAPTURE_STATUS)
      expect(store.passiveDiscovery).toEqual(GOLDEN_PASSIVE_DISCOVERY)
      expect(store.pipelineError).toBeNull()
      expect(store.captureError).toBeNull()
      expect(store.passiveError).toBeNull()
    })

    it('sets loading flags during request', async () => {
      const store = useDataSourcesStore()
      const promise = store.loadAll()

      expect(store.isLoading).toBe(true)

      await promise

      expect(store.isLoading).toBe(false)
    })
  })

  describe('friendly labels', () => {
    it('maps conn/mac/proto to friendly labels via the const', () => {
      expect(DATA_SOURCE_LABELS.conn).toBe('Connections')
      expect(DATA_SOURCE_LABELS.mac).toBe('Assets')
      expect(DATA_SOURCE_LABELS.proto).toBe('Protocols')
    })

    it('resolves labels through the store getter', () => {
      const store = useDataSourcesStore()
      expect(store.friendlyLabel('conn')).toBe('Connections')
      expect(store.friendlyLabel('mac')).toBe('Assets')
      expect(store.friendlyLabel('proto')).toBe('Protocols')
    })

    it('falls back to the raw id for an unknown source', () => {
      const store = useDataSourcesStore()
      // @ts-expect-error - exercising the runtime fallback for an unmapped id
      expect(store.friendlyLabel('other')).toBe('other')
    })
  })

  describe('stale banner', () => {
    it('states staleness without asserting a cause', () => {
      const sources = GOLDEN_PIPELINE.sources.map((s, i) => (i === 0 ? { ...s, state: 'stale' as const } : s))
      const text = staleBannerText(sources)
      expect(text).toContain('stale')
      expect(text).not.toContain('ingest path is broken')
      expect(text).not.toContain('traffic present')
    })

    it('uses friendly labels for stale sources', () => {
      const sources = GOLDEN_PIPELINE.sources.map((s) => ({ ...s, name: 'conn', state: 'stale' as const }))
      const text = staleBannerText(sources)
      expect(text).toContain('Connections')
    })

    it('returns null when no sources are stale', () => {
      const sources = GOLDEN_PIPELINE.sources.map((s) => ({ ...s, state: 'current' as const }))
      expect(staleBannerText(sources)).toBeNull()
    })

    it('is exposed via the store getter after load', async () => {
      const store = useDataSourcesStore()
      await store.loadAll()
      // GOLDEN_PIPELINE may or may not contain stale rows; the getter must
      // never throw and must return a string or null.
      const banner = store.staleBanner
      expect(banner === null || typeof banner === 'string').toBe(true)
    })
  })

  describe('passive discovery', () => {
    it('exposes an active badge when the producer is current', async () => {
      const store = useDataSourcesStore()
      await store.fetchPassiveDiscovery()

      expect(store.passiveDiscovery?.freshness).toBe('current')
      expect(store.passiveDiscovery?.observed_asset_count).toBe(10)
      expect(store.passiveDiscovery?.runtime_control_enabled).toBe(false)
      expect(store.passiveBadge).toEqual({ label: 'active', kind: 'ok' })
    })

    it('exposes a stale badge when the latest observation is aged', async () => {
      server.use(errorHandlers.passiveDiscoveryStale)
      const store = useDataSourcesStore()
      await store.fetchPassiveDiscovery()

      expect(store.passiveDiscovery?.freshness).toBe('stale')
      expect(store.passiveBadge).toEqual({ label: 'stale', kind: 'warn' })
    })

    it('exposes a no-data badge when no passive inventory exists', async () => {
      server.use(errorHandlers.passiveDiscoveryNoData)
      const store = useDataSourcesStore()
      await store.fetchPassiveDiscovery()

      expect(store.passiveDiscovery?.freshness).toBe('no-data')
      expect(store.passiveBadge).toEqual({ label: 'no data', kind: 'muted' })
    })

    it('never reports the runtime control as enabled', async () => {
      const store = useDataSourcesStore()
      await store.fetchPassiveDiscovery()

      expect(store.passiveDiscovery?.runtime_control_enabled).toBe(false)
    })

    it('records a passive error when the endpoint fails', async () => {
      server.use(errorHandlers.passiveDiscovery500)
      const store = useDataSourcesStore()
      await store.fetchPassiveDiscovery()

      expect(store.passiveDiscovery).toBeNull()
      expect(store.passiveError).toContain('Failed to load passive discovery status')
    })
  })

  describe('error handling', () => {
    it('records a capture error when the endpoint fails', async () => {
      server.use(errorHandlers.captureStatus500)
      const store = useDataSourcesStore()
      await store.fetchCaptureStatus()

      expect(store.captureStatus).toBeNull()
      expect(store.captureError).toContain('Failed to load capture status')
    })

    it('records a Wave-B aligned auth error when the endpoint returns 401', async () => {
      server.use(errorHandlers.captureStatus401)
      const store = useDataSourcesStore()
      await store.fetchCaptureStatus()

      expect(store.captureError).toContain('Insufficient permissions')
      expect(store.captureError).not.toContain('settings')
    })
  })

  describe('passive seeder status', () => {
    it('loads the seeder status row alongside the other surfaces', async () => {
      const store = useDataSourcesStore()
      await store.loadAll()

      expect(store.seederStatus).toEqual(GOLDEN_PASSIVE_SEEDER_STATUS)
      expect(store.seederError).toBeNull()
      expect(store.seederState).toBe('running')
      expect(store.seederBadge).toEqual({ label: 'running', kind: 'ok' })
    })

    it('reports unknown — not disabled — when no status row exists', async () => {
      server.use(errorHandlers.passiveSeederStatusUnknown)
      const store = useDataSourcesStore()
      await store.fetchSeederStatus()

      expect(store.seederState).toBe('unknown')
      expect(store.seederBadge).toEqual({ label: 'unknown', kind: 'muted' })
    })

    it('carries the seeder last_error through unchanged', async () => {
      server.use(errorHandlers.passiveSeederStatusError)
      const store = useDataSourcesStore()
      await store.fetchSeederStatus()

      expect(store.seederState).toBe('error')
      expect(store.seederBadge.kind).toBe('err')
      expect(store.seederStatus?.last_error).toBe('influx query failed: connection refused')
    })

    it('defaults to unknown before any fetch has completed', async () => {
      const store = useDataSourcesStore()
      expect(store.seederStatus).toBeNull()
      expect(store.seederState).toBe('unknown')
    })

    it('captures a fetch failure without discarding the other surfaces', async () => {
      server.use(errorHandlers.passiveSeederStatus500)
      const store = useDataSourcesStore()
      await store.loadAll()

      expect(store.seederError).toContain('Failed to load passive seeder status')
      expect(store.pipeline).toEqual(GOLDEN_PIPELINE)
    })
  })
})
