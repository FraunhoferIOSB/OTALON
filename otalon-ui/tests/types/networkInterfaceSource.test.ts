import { describe, expect, it } from 'vitest'

import type { NetworkInterfaceItem } from '~/types/api'

describe('NetworkInterfaceItem passive provenance contract', () => {
  it('carries the producer source through the frontend interface without loss', () => {
    // Producer (postgres_repo selects network_interfaces.source) may emit
    // 'passive' for passive-seeder-discovered interfaces. The frontend type
    // must preserve it verbatim; it asserts no traffic/freshness fact by itself.
    const passive: NetworkInterfaceItem = {
      id: 7,
      mac_address: '00:1b:1b:f8:3a:02',
      ipv4_address: '192.168.1.10',
      ipv6_address: null,
      subnet: null,
      open_ports_summary: null,
      last_scan_at: null,
      notes: null,
      source: 'passive',
    }

    const roundTripped: NetworkInterfaceItem = JSON.parse(JSON.stringify(passive))
    expect(roundTripped.source).toBe('passive')
  })

  it('allows a null source when the producer does not attribute provenance', () => {
    const unattributed: NetworkInterfaceItem = {
      id: 8,
      mac_address: null,
      ipv4_address: null,
      ipv6_address: null,
      subnet: null,
      open_ports_summary: null,
      last_scan_at: null,
      notes: null,
      source: null,
    }
    expect(unattributed.source).toBeNull()
  })
})
