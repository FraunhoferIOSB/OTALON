/**
 * Unit tests for topology graph label resolution.
 *
 * Validates that the shared device-lookup wiring produces human-readable
 * asset names in "auto" identifier mode while leaving the "ip" and "mac"
 * overrides unchanged.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useTopologyGraph } from '~/composables/useTopologyGraph'
import { useDevicesStore } from '~/stores/devicesStore'
import type { TopologyNode } from '~/types/golden-data'
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

function makeNode(overrides: Partial<TopologyNode> = {}): TopologyNode {
  return {
    id: 'node-1',
    label: '',
    type: 'PLC',
    isAnomaly: false,
    meta: {
      name: '',
      alias: '',
      device_type_name: '',
      device_role: '',
      mac: '',
      ip4: [],
    },
    ...overrides,
  } as TopologyNode
}

describe('useTopologyGraph resolveNodeLabel', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('auto mode resolves hostname by IP when device is known', () => {
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: 'plc-assembly-01',
        interfaces: [{ id: 1, mac_address: '00:11:22:33:44:55', ipv4_address: '10.0.0.10' }],
      }),
    ]

    const node = makeNode({
      id: '1',
      meta: {
        name: '',
        alias: '',
        device_type_name: 'PLC',
        device_role: '',
        mac: '00:11:22:33:44:55',
        ip4: ['10.0.0.10'],
      },
    })

    const { resolveNodeLabel } = useTopologyGraph()
    expect(resolveNodeLabel(node, 'auto')).toBe('plc-assembly-01')
  })

  it('auto mode resolves hostname by MAC when IP is absent', () => {
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: 'io-module-b',
        interfaces: [{ id: 1, mac_address: 'aa:bb:cc:dd:ee:ff', ipv4_address: null }],
      }),
    ]

    const node = makeNode({
      id: 'unresolved:aa:bb:cc:dd:ee:ff',
      meta: {
        name: '',
        alias: '',
        device_type_name: 'IO',
        device_role: '',
        mac: 'aa:bb:cc:dd:ee:ff',
        ip4: [],
      },
    })

    const { resolveNodeLabel } = useTopologyGraph()
    expect(resolveNodeLabel(node, 'auto')).toBe('io-module-b')
  })

  it('auto mode falls back to IP when hostname is absent', () => {
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: null,
        product_name: 'S7-1500',
        device_family: 'PLC',
        interfaces: [{ id: 1, mac_address: '11:22:33:44:55:66', ipv4_address: '192.168.1.5' }],
      }),
    ]

    const node = makeNode({
      id: '2',
      meta: {
        name: '',
        alias: '',
        device_type_name: 'PLC',
        device_role: '',
        mac: '11:22:33:44:55:66',
        ip4: ['192.168.1.5'],
      },
    })

    const { resolveNodeLabel } = useTopologyGraph()
    expect(resolveNodeLabel(node, 'auto')).toBe('192.168.1.5')
  })

  it('auto mode falls back to IP, then MAC, then id when no asset name is known', () => {
    const devicesStore = useDevicesStore()
    devicesStore.devices = []

    const nodeWithIp = makeNode({
      id: '3',
      meta: {
        name: '',
        alias: '',
        device_type_name: 'Other',
        device_role: '',
        mac: '00:00:00:00:00:01',
        ip4: ['172.16.0.3'],
      },
    })
    const nodeWithMac = makeNode({
      id: '4',
      meta: {
        name: '',
        alias: '',
        device_type_name: 'Other',
        device_role: '',
        mac: '00:00:00:00:00:02',
        ip4: [],
      },
    })
    const bareNode = makeNode({
      id: '5',
      label: '',
      meta: {
        name: '',
        alias: '',
        device_type_name: 'Other',
        device_role: '',
        mac: '',
        ip4: [],
      },
    })

    const { resolveNodeLabel } = useTopologyGraph()
    expect(resolveNodeLabel(nodeWithIp, 'auto')).toBe('172.16.0.3')
    expect(resolveNodeLabel(nodeWithMac, 'auto')).toBe('00:00:00:00:00:02')
    expect(resolveNodeLabel(bareNode, 'auto')).toBe('5')
  })

  it("auto mode uses device lookup even when the node's label is a raw IP", () => {
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: 'hmi-panel',
        interfaces: [{ id: 1, mac_address: '22:22:22:22:22:22', ipv4_address: '10.20.30.40' }],
      }),
    ]

    const node = makeNode({
      id: '6',
      label: '10.20.30.40',
      meta: {
        name: '10.20.30.40',
        alias: '',
        device_type_name: 'IPC',
        device_role: '',
        mac: '22:22:22:22:22:22',
        ip4: ['10.20.30.40'],
      },
    })

    const { resolveNodeLabel } = useTopologyGraph()
    expect(resolveNodeLabel(node, 'auto')).toBe('hmi-panel')
  })

  it("ip mode is unchanged and forces the node's IP", () => {
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: 'should-not-appear',
        interfaces: [{ id: 1, mac_address: '33:33:33:33:33:33', ipv4_address: '10.10.10.10' }],
      }),
    ]

    const node = makeNode({
      id: '7',
      meta: {
        name: '',
        alias: '',
        device_type_name: 'PLC',
        device_role: '',
        mac: '33:33:33:33:33:33',
        ip4: ['10.10.10.10'],
      },
    })

    const { resolveNodeLabel } = useTopologyGraph()
    expect(resolveNodeLabel(node, 'ip')).toBe('10.10.10.10')
  })

  it("mac mode is unchanged and forces the node's MAC", () => {
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: 'should-not-appear',
        interfaces: [{ id: 1, mac_address: '44:44:44:44:44:44', ipv4_address: '10.10.10.11' }],
      }),
    ]

    const node = makeNode({
      id: '8',
      meta: {
        name: '',
        alias: '',
        device_type_name: 'PLC',
        device_role: '',
        mac: '44:44:44:44:44:44',
        ip4: ['10.10.10.11'],
      },
    })

    const { resolveNodeLabel } = useTopologyGraph()
    expect(resolveNodeLabel(node, 'mac')).toBe('44:44:44:44:44:44')
  })

  it('auto mode ignores node.label and uses hostname/IP/MAC like connections page', () => {
    const devicesStore = useDevicesStore()
    devicesStore.devices = [
      makeDevice({
        hostname: 'device-hostname',
        interfaces: [{ id: 1, mac_address: '55:55:55:55:55:55', ipv4_address: '10.0.0.99' }],
      }),
    ]

    const node = makeNode({
      id: '9',
      label: 'Engineering-Workstation',
      meta: {
        name: 'Engineering-Workstation',
        alias: '',
        device_type_name: 'IPC',
        device_role: '',
        mac: '55:55:55:55:55:55',
        ip4: ['10.0.0.99'],
      },
    })

    const { resolveNodeLabel } = useTopologyGraph()
    expect(resolveNodeLabel(node, 'auto')).toBe('device-hostname')
  })
})
