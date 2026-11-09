/**
 * Unit tests for the scan-heuristic pure function.
 */
import { describe, expect, it } from 'vitest'

import { computeScanHeuristic, primaryIpOf } from '~/utils/scanHeuristic'
import type { DeviceItem } from '~/types/api'

function deviceWith(opts: {
  ipv4?: string | null
  subnet?: string | null
  ports?: { port: number; protocol: string; service?: string | null }[]
}): DeviceItem {
  return {
    id: 1,
    vendor: null,
    device_family: null,
    device_type: null,
    description: null,
    article_number: null,
    device_role: null,
    firmware_version: null,
    vulnerabilities: null,
    update_available: false,
    last_scan_at: null,
    notes: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: null,
    interfaces: [
      {
        id: 1,
        mac_address: null,
        ipv4_address: opts.ipv4 ?? null,
        ipv6_address: null,
        subnet: opts.subnet ?? null,
        open_ports_summary: opts.ports ?? null,
        last_scan_at: null,
        notes: null,
      },
    ],
  }
}

describe('computeScanHeuristic', () => {
  it('picks opcua_discover when OPC-UA port 4840 is open', () => {
    const dev = deviceWith({
      ipv4: '10.0.0.5',
      ports: [{ port: 4840, protocol: 'tcp', service: 'opc-ua' }],
    })
    const result = computeScanHeuristic([dev])
    expect(result.module).toBe('opcua_discover')
    expect(result.targetIp).toBe('10.0.0.5')
    expect(result.reason).toContain('4840')
  })

  it('picks snmp_scan when SNMP port 161 is open', () => {
    const dev = deviceWith({
      ipv4: '10.0.0.6',
      ports: [{ port: 161, protocol: 'udp', service: 'snmp' }],
    })
    const result = computeScanHeuristic([dev])
    expect(result.module).toBe('snmp_scan')
    expect(result.targetIp).toBe('10.0.0.6')
    expect(result.reason).toContain('161')
  })

  it('prefers OPC-UA over SNMP when both are open', () => {
    const dev = deviceWith({
      ipv4: '10.0.0.7',
      ports: [
        { port: 161, protocol: 'udp', service: 'snmp' },
        { port: 4840, protocol: 'tcp', service: 'opc-ua' },
      ],
    })
    const result = computeScanHeuristic([dev])
    expect(result.module).toBe('opcua_discover')
  })

  it('falls back to port_scan when no signal present', () => {
    const dev = deviceWith({ ipv4: '10.0.0.8', ports: [] })
    const result = computeScanHeuristic([dev])
    expect(result.module).toBe('port_scan')
    expect(result.targetIp).toBe('10.0.0.8')
  })

  it('falls back to port_scan when ports is null', () => {
    const dev = deviceWith({ ipv4: '10.0.0.9', ports: null })
    const result = computeScanHeuristic([dev])
    expect(result.module).toBe('port_scan')
  })

  it('device without IP returns null targetIp but still recommends', () => {
    const dev = deviceWith({ ipv4: null, ports: [{ port: 4840, protocol: 'tcp' }] })
    const result = computeScanHeuristic([dev])
    expect(result.module).toBe('opcua_discover')
    expect(result.targetIp).toBeNull()
  })

  it('multi-target with PROFINET signal selects pn_discovery', () => {
    const result = computeScanHeuristic([], true)
    expect(result.module).toBe('pn_discovery')
    expect(result.reason).toContain('PROFINET')
  })

  it('multi-target without PROFINET signal selects arp_scan', () => {
    const result = computeScanHeuristic([], false)
    expect(result.module).toBe('arp_scan')
    expect(result.reason).toContain('ARP')
  })

  it('null devices degrades to arp_scan', () => {
    const result = computeScanHeuristic(null)
    expect(result.module).toBe('arp_scan')
  })

  it('empty devices degrades to arp_scan', () => {
    const result = computeScanHeuristic([])
    expect(result.module).toBe('arp_scan')
  })

  it('falls back to port_scan with null targetIp when interfaces array is empty', () => {
    const dev = { ...deviceWith({}), interfaces: [] } as unknown as DeviceItem
    const result = computeScanHeuristic([dev])
    expect(result.module).toBe('port_scan')
    expect(result.targetIp).toBeNull()
    expect(result.reason).toContain('fallback')
  })

  it('falls back to port_scan with null targetIp when interfaces is null', () => {
    const dev = { ...deviceWith({}), interfaces: null } as unknown as DeviceItem
    const result = computeScanHeuristic([dev])
    expect(result.module).toBe('port_scan')
    expect(result.targetIp).toBeNull()
  })
})

describe('primaryIpOf', () => {
  it('returns the first interface IPv4 address when present', () => {
    expect(primaryIpOf(deviceWith({ ipv4: '10.0.0.1' }))).toBe('10.0.0.1')
  })

  it('returns null for null/undefined device', () => {
    expect(primaryIpOf(null)).toBeNull()
    expect(primaryIpOf(undefined)).toBeNull()
  })

  it('returns null when interfaces is empty or null', () => {
    expect(primaryIpOf({ ...deviceWith({}), interfaces: [] } as unknown as DeviceItem)).toBeNull()
    expect(primaryIpOf({ ...deviceWith({}), interfaces: null } as unknown as DeviceItem)).toBeNull()
  })

  it('returns null when first interface has no IPv4 address', () => {
    expect(primaryIpOf(deviceWith({ ipv4: null }))).toBeNull()
  })
})
