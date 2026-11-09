/**
 * Unit tests for useDeviceLookup composable.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { buildDeviceLookupMaps, deviceDisplayName } from '~/composables/useDeviceLookup'
import { useDevicesStore } from '~/stores/devicesStore'
import type { DeviceItem } from '~/types/api'

function makeDevice(overrides: Partial<DeviceItem> = {}): DeviceItem {
  return {
    id: 1,
    hostname: null,
    vendor: null,
    device_family: null,
    device_type: null,
    description: null,
    article_number: null,
    device_role: null,
    firmware_version: null,
    product_name: null,
    hw_version: null,
    sw_version: null,
    serial_number: null,
    vulnerabilities: null,
    update_available: false,
    last_scan_at: null,
    notes: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: null,
    interfaces: [],
    ...overrides,
  } as DeviceItem
}

describe('deviceDisplayName', () => {
  it('returns hostname when present', () => {
    const result = deviceDisplayName({ hostname: 'plc-01', product_name: 'S7-1500', device_family: 'PLC' })
    expect(result).toBe('plc-01')
  })

  it('falls back to product_name when hostname is null', () => {
    const result = deviceDisplayName({ hostname: null, product_name: 'S7-1500', device_family: 'PLC' })
    expect(result).toBe('S7-1500')
  })

  it('falls back to device_family when hostname and product_name are null', () => {
    const result = deviceDisplayName({ hostname: null, product_name: null, device_family: 'PLC' })
    expect(result).toBe('PLC')
  })

  it('returns null when all fields are null', () => {
    const result = deviceDisplayName({ hostname: null, product_name: null, device_family: null })
    expect(result).toBeNull()
  })
})

describe('buildDeviceLookupMaps', () => {
  it('builds maps keyed by lower-case MAC and raw IP', () => {
    const devices: DeviceItem[] = [
      makeDevice({
        hostname: 'axc-f-2152-1',
        product_name: 'AXC F 2152',
        device_family: 'Controller',
        interfaces: [{ id: 1, mac_address: '00:01:05:2B:AE:A2', ipv4_address: '192.168.1.10' }],
      }),
    ]

    const { byMac, byIp } = buildDeviceLookupMaps(devices)
    expect(byMac.get('00:01:05:2b:ae:a2')?.hostname).toBe('axc-f-2152-1')
    expect(byIp.get('192.168.1.10')?.hostname).toBe('axc-f-2152-1')
  })

  it('skips interfaces without mac_address or ipv4_address', () => {
    const devices: DeviceItem[] = [
      makeDevice({
        hostname: 'plc-01',
        interfaces: [{ id: 1, mac_address: null, ipv4_address: null }],
      }),
    ]

    const { byMac, byIp } = buildDeviceLookupMaps(devices)
    expect(byMac.size).toBe(0)
    expect(byIp.size).toBe(0)
  })

  it('deduplicates by first-seen MAC', () => {
    const devices: DeviceItem[] = [
      makeDevice({
        hostname: 'first',
        interfaces: [{ id: 1, mac_address: 'aa:bb:cc:dd:ee:ff', ipv4_address: '10.0.0.1' }],
      }),
      makeDevice({
        hostname: 'second',
        interfaces: [{ id: 2, mac_address: 'aa:bb:cc:dd:ee:ff', ipv4_address: '10.0.0.2' }],
      }),
    ]

    const { byMac, byIp } = buildDeviceLookupMaps(devices)
    expect(byMac.get('aa:bb:cc:dd:ee:ff')?.hostname).toBe('first')
    expect(byIp.get('10.0.0.1')?.hostname).toBe('first')
    expect(byIp.get('10.0.0.2')?.hostname).toBe('second')
  })
})

describe('useDeviceLookup', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('nameForMac returns hostname via case-insensitive MAC match', async () => {
    const { useDeviceLookup } = await import('~/composables/useDeviceLookup')
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: 'bk9103',
        interfaces: [{ id: 1, mac_address: '00:50:56:C0:00:08', ipv4_address: '192.168.1.20' }],
      }),
    ]

    const lookup = useDeviceLookup()
    expect(lookup.nameForMac('00:50:56:c0:00:08')).toBe('bk9103')
    expect(lookup.nameForMac('00:50:56:C0:00:08')).toBe('bk9103')
  })

  it('nameForMac falls back to product_name then device_family', async () => {
    const { useDeviceLookup } = await import('~/composables/useDeviceLookup')
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: null,
        product_name: 'AXC F 2152',
        device_family: 'Controller',
        interfaces: [{ id: 1, mac_address: 'aa:bb:cc:dd:ee:ff', ipv4_address: null }],
      }),
    ]

    const lookup = useDeviceLookup()
    expect(lookup.nameForMac('aa:bb:cc:dd:ee:ff')).toBe('AXC F 2152')
  })

  it('labelForEndpoint prefers IP-based hostname', async () => {
    const { useDeviceLookup } = await import('~/composables/useDeviceLookup')
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: 'ip-device',
        interfaces: [{ id: 1, mac_address: 'aa:bb:cc:dd:ee:ff', ipv4_address: '10.0.0.1' }],
      }),
    ]

    const lookup = useDeviceLookup()
    expect(lookup.labelForEndpoint('10.0.0.1', 'aa:bb:cc:dd:ee:ff')).toBe('ip-device')
  })

  it('labelForEndpoint falls back to MAC-based hostname when IP absent', async () => {
    const { useDeviceLookup } = await import('~/composables/useDeviceLookup')
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: 'mac-device',
        interfaces: [{ id: 1, mac_address: 'aa:bb:cc:dd:ee:ff', ipv4_address: null }],
      }),
    ]

    const lookup = useDeviceLookup()
    expect(lookup.labelForEndpoint(null, 'aa:bb:cc:dd:ee:ff')).toBe('mac-device')
  })

  it('labelForEndpoint falls back to IP then MAC when no hostname', async () => {
    const { useDeviceLookup } = await import('~/composables/useDeviceLookup')
    const devicesStore = useDevicesStore()
    devicesStore.devices = []

    const lookup = useDeviceLookup()
    expect(lookup.labelForEndpoint('10.0.0.1', 'aa:bb:cc:dd:ee:ff')).toBe('10.0.0.1')
    expect(lookup.labelForEndpoint(null, 'aa:bb:cc:dd:ee:ff')).toBe('aa:bb:cc:dd:ee:ff')
    expect(lookup.labelForEndpoint('', '')).toBe('')
  })
})
