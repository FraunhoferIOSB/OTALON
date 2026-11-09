/**
 * Unit tests for the protocol timeseries store.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useProtoTimeseriesStore } from '~/stores/protoTimeseriesStore'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

describe('protoTimeseriesStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('fetchFeatures', () => {
    it('loads protocol feature list from API', async () => {
      const store = useProtoTimeseriesStore()
      await store.fetchFeatures()

      expect(store.availableFeatures.length).toBeGreaterThan(0)
    })

    it('sets visibleFeatures to default subset on first load', async () => {
      const store = useProtoTimeseriesStore()
      await store.fetchFeatures()

      expect(store.visibleFeatures.length).toBeGreaterThan(0)
    })

    it('preserves existing visibleFeatures on re-fetch', async () => {
      const store = useProtoTimeseriesStore()
      store.visibleFeatures = ['proto_total_packets', 'proto_total_volume']
      await store.fetchFeatures()

      expect(store.visibleFeatures).toEqual(['proto_total_packets', 'proto_total_volume'])
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.protoFeatures500)
      const store = useProtoTimeseriesStore()
      await store.fetchFeatures()

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch protocol features')
    })
  })

  describe('defaultVisibleFeatures', () => {
    it('returns the intersection of available and defaults', async () => {
      const store = useProtoTimeseriesStore()
      await store.fetchFeatures()

      expect(store.defaultVisibleFeatures.length).toBeGreaterThan(0)
      expect(store.defaultVisibleFeatures.every((f) => store.availableFeatures.includes(f))).toBe(true)
    })
  })

  describe('silent profiled protocol selection', () => {
    it('deduplicates a profiled hash matching a live readable protocol', () => {
      const store = useProtoTimeseriesStore()
      store.liveProtocols = ['Ethernet:ARP']
      store.profiledProtocols = ['1513662987', '1834999852']
      store.showSilentProfiled = true

      expect(store.selectableProtocols).toEqual(['Ethernet:ARP', '1834999852'])
      expect(store.silentProfiledCount).toBe(1)
    })

    it('retains a profiled protocol with no live counterpart', () => {
      const store = useProtoTimeseriesStore()
      store.liveProtocols = ['Ethernet:ARP']
      store.profiledProtocols = ['1834999852']
      store.showSilentProfiled = true

      expect(store.selectableProtocols).toEqual(['Ethernet:ARP', '1834999852'])
    })
  })
})
