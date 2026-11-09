/**
 * Unit tests for the MAC sources store.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useMacSourcesStore } from '~/stores/macSourcesStore'
import { GOLDEN_MAC_LIST } from '../mocks/golden-data'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

describe('macSourcesStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('fetchMacs', () => {
    it('loads MAC list from API', async () => {
      const store = useMacSourcesStore()
      await store.fetchMacs('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.macs).toHaveLength(GOLDEN_MAC_LIST.length)
      expect(store.macs[0].mac).toBe(GOLDEN_MAC_LIST[0].id)
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.macIds500)
      const store = useMacSourcesStore()
      await store.fetchMacs('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch MAC list')
    })
  })

  describe('enrichWithDevices', () => {
    it('matches MACs to device metadata', () => {
      const store = useMacSourcesStore()
      store.macs = [
        { mac: 'aa:bb:cc:dd:ee:ff', name: null, ip: null },
        { mac: '11:22:33:44:55:66', name: null, ip: null },
      ]

      store.enrichWithDevices([
        {
          hostname: null,
          product_name: null,
          device_family: 'S7-1500',
          device_type: 'PLC',
          interfaces: [{ mac_address: 'AA:BB:CC:DD:EE:FF', ipv4_address: '192.168.0.10' }],
        },
      ])

      expect(store.macs[0].name).toBe('S7-1500')
      expect(store.macs[0].ip).toBe('192.168.0.10')
      expect(store.macs[1].name).toBeNull()
    })

    it('prefers hostname over product_name and device_family', () => {
      const store = useMacSourcesStore()
      store.macs = [{ mac: 'aa:bb:cc:dd:ee:ff', name: null, ip: null }]

      store.enrichWithDevices([
        {
          hostname: 'axc-f-2152-1',
          product_name: 'AXC F 2152',
          device_family: 'Controller',
          device_type: 'PLC',
          interfaces: [{ mac_address: 'AA:BB:CC:DD:EE:FF', ipv4_address: '192.168.0.10' }],
        },
      ])

      expect(store.macs[0].name).toBe('axc-f-2152-1')
    })

    it('falls back to product_name when hostname is null', () => {
      const store = useMacSourcesStore()
      store.macs = [{ mac: 'aa:bb:cc:dd:ee:ff', name: null, ip: null }]

      store.enrichWithDevices([
        {
          hostname: null,
          product_name: 'AXC F 2152',
          device_family: 'Controller',
          device_type: 'PLC',
          interfaces: [{ mac_address: 'AA:BB:CC:DD:EE:FF', ipv4_address: '192.168.0.10' }],
        },
      ])

      expect(store.macs[0].name).toBe('AXC F 2152')
    })
  })

  describe('selectMac', () => {
    it('updates selectedMac', () => {
      const store = useMacSourcesStore()
      store.selectMac('aa:bb:cc:dd:ee:ff')
      expect(store.selectedMac).toBe('aa:bb:cc:dd:ee:ff')
    })

    it('clears selectedMac with null', () => {
      const store = useMacSourcesStore()
      store.selectMac('aa:bb:cc:dd:ee:ff')
      store.selectMac(null)
      expect(store.selectedMac).toBeNull()
    })
  })
})
