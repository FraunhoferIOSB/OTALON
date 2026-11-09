/**
 * Unit tests for the connections store.
 *
 * Validates UCI fetching, connection selection, UCI parsing,
 * getter behavior, error handling, and $reset().
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { http, HttpResponse } from 'msw'

import { useConnectionsStore } from '~/stores/connectionsStore'
import { GOLDEN_UCI_LIST } from '../mocks/golden-data'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

describe('connectionsStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('fetchConnections', () => {
    it('loads UCI list from API', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.connections).toHaveLength(GOLDEN_UCI_LIST.length)
    })

    it('parses UCI strings into Connection objects', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const profinet = store.connections.find(
        (c) => c.uci === '00:1B:1B:F8:3A:02/00:1B:1B:F8:3A:03///////Ethernet:PROFINET_RT:PROFINET_RT_IO',
      )
      expect(profinet).toBeDefined()
      expect(profinet!.source).toBe('00:1B:1B:F8:3A:02')
      expect(profinet!.destination).toBe('00:1B:1B:F8:3A:03')
      expect(profinet!.protocol).toContain('PROFINET_RT')
      expect(profinet!.sourceMac).toBe('00:1B:1B:F8:3A:02')
      expect(profinet!.sourceIp).toBeNull()
      expect(profinet!.destMac).toBe('00:1B:1B:F8:3A:03')
      expect(profinet!.destIp).toBeNull()
    })

    it('parses IP-based UCI strings correctly', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const mdns = store.connections.find(
        (c) => c.uci === '00:1B:1B:F8:3A:04/01:00:5E:00:00:FB///192.168.1.20/224.0.0.251//5353/Ethernet:IPv4:UDP:mDNS',
      )
      expect(mdns).toBeDefined()
      expect(mdns!.source).toBe('192.168.1.20')
      expect(mdns!.destination).toBe('224.0.0.251')
      expect(mdns!.protocol).toContain('mDNS')
      expect(mdns!.sourceIp).toBe('192.168.1.20')
      expect(mdns!.sourceMac).toBe('00:1B:1B:F8:3A:04')
      expect(mdns!.destIp).toBe('224.0.0.251')
      expect(mdns!.destMac).toBe('01:00:5E:00:00:FB')
    })

    it('sets isLoading during request', async () => {
      const store = useConnectionsStore()
      const promise = store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.isLoading).toBe(true)

      await promise

      expect(store.isLoading).toBe(false)
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.ids500)
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch connections')
    })

    it('clears error on successful fetch', async () => {
      const store = useConnectionsStore()
      store.error = 'previous error'
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.error).toBeNull()
    })
  })

  describe('selectConnection', () => {
    it('sets selectedUci', () => {
      const store = useConnectionsStore()
      store.selectConnection('test-uci')

      expect(store.selectedUci).toBe('test-uci')
    })

    it('clears selectedUci with null', () => {
      const store = useConnectionsStore()
      store.selectConnection('test-uci')
      store.selectConnection(null)

      expect(store.selectedUci).toBeNull()
    })
  })

  describe('getters', () => {
    it('connectionCount returns number of connections', async () => {
      const store = useConnectionsStore()
      expect(store.connectionCount).toBe(0)

      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')
      expect(store.connectionCount).toBe(GOLDEN_UCI_LIST.length)
    })

    it('selectedConnection returns matching connection', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      store.selectConnection(GOLDEN_UCI_LIST[0].uci)
      expect(store.selectedConnection).toBeDefined()
      expect(store.selectedConnection!.uci).toBe(GOLDEN_UCI_LIST[0].uci)
    })

    it('selectedConnection returns undefined when nothing selected', () => {
      const store = useConnectionsStore()

      expect(store.selectedConnection).toBeUndefined()
    })
  })

  describe('parseUci collapsed_port_count', () => {
    it('maps backend collapsed_port_count for wildcard UCIs', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const wildcard = store.connections.find(
        (c) => c.uci === 'aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//*/*/Ethernet:IPv4:TCP',
      )
      expect(wildcard).toBeDefined()
      expect(wildcard!.isWildcard).toBe(true)
      expect(wildcard!.collapsed_port_count).toBe(7)
    })

    it('defaults collapsed_port_count to null when absent', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const clientWildcard = store.connections.find(
        (c) => c.uci === 'aa:bb:cc:dd:ee:03/aa:bb:cc:dd:ee:04/0//10.0.0.1//*/*/Ethernet:IPv4:TCP',
      )
      expect(clientWildcard).toBeDefined()
      expect(clientWildcard!.isWildcard).toBe(true)
      expect(clientWildcard!.collapsed_port_count).toBeNull()
    })

    it('non-wildcard connections have collapsed_port_count null', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const concrete = store.connections.find(
        (c) =>
          c.uci === 'a8:74:1d:02:99:8d/00:1B:1B:F8:3A:05//6/192.168.1.10/192.168.1.20//502/Ethernet:IPv4:TCP:Modbus',
      )
      expect(concrete).toBeDefined()
      expect(concrete!.isWildcard).toBe(false)
      expect(concrete!.collapsed_port_count).toBeNull()
    })
  })

  describe('parseUci port separation', () => {
    it('separates protocol name from port for TCP/UDP connections', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const mdns = store.connections.find((c) => c.uci === GOLDEN_UCI_LIST[1].uci)
      expect(mdns).toBeDefined()
      expect(mdns!.protocol).toBe('mDNS')
      expect(mdns!.port).toBe('5353')
    })

    it('extracts port for Modbus connection', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const modbus = store.connections.find((c) => c.uci === GOLDEN_UCI_LIST[3].uci)
      expect(modbus).toBeDefined()
      expect(modbus!.protocol).toBe('Modbus')
      expect(modbus!.port).toBe('502')
    })

    it('extracts port for OPC_UA connection', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const opcua = store.connections.find((c) => c.uci === GOLDEN_UCI_LIST[4].uci)
      expect(opcua).toBeDefined()
      expect(opcua!.protocol).toBe('OPC_UA')
      expect(opcua!.port).toBe('4840')
    })

    it('sets port to null for Layer-2 connections without ports', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const arp = store.connections.find((c) => c.uci === GOLDEN_UCI_LIST[2].uci)
      expect(arp).toBeDefined()
      expect(arp!.protocol).toBe('ARP')
      expect(arp!.port).toBeNull()
    })

    it('sets port to null for PROFINET_RT connections (no port)', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const profinet = store.connections.find((c) => c.uci === GOLDEN_UCI_LIST[0].uci)
      expect(profinet).toBeDefined()
      expect(profinet!.protocol).toBe('PROFINET_RT_IO')
      expect(profinet!.port).toBeNull()
    })

    it('protocol field does not contain port suffix', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      for (const conn of store.connections) {
        expect(conn.protocol).not.toMatch(/ :\d+/)
      }
    })

    it('showPortColumn defaults to true and can be toggled', () => {
      const store = useConnectionsStore()
      expect(store.showPortColumn).toBe(true)

      store.setShowPortColumn(false)
      expect(store.showPortColumn).toBe(false)

      store.setShowPortColumn(true)
      expect(store.showPortColumn).toBe(true)
    })

    it('$reset clears showPortColumn to default', () => {
      const store = useConnectionsStore()
      store.setShowPortColumn(false)
      expect(store.showPortColumn).toBe(false)

      store.$reset()
      expect(store.showPortColumn).toBe(true)
    })
  })

  describe('parseUci IPv6 handling (B-17)', () => {
    it('parses IPv6 multicast mDNS UCI with link-local source', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const ipv6Mdns = store.connections.find(
        (c) =>
          c.uci ===
          '00:1B:1B:F8:3A:07/33:33:00:00:00:FB//17/fe80::1b:1bff:fef8:3a07/ff02::fb//5353/Ethernet:IPv6:UDP:mDNS',
      )
      expect(ipv6Mdns).toBeDefined()
      expect(ipv6Mdns!.source).toBe('fe80::1b:1bff:fef8:3a07')
      expect(ipv6Mdns!.destination).toBe('ff02::fb')
      expect(ipv6Mdns!.protocol).toBe('mDNS')
      expect(ipv6Mdns!.port).toBe('5353')
    })

    it('parses IPv6 global unicast TCP UCI correctly', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const ipv6Tls = store.connections.find(
        (c) => c.uci === 'a8:74:1d:02:99:8e/00:1B:1B:F8:3A:08//6/2001:db8::1/2001:db8::2//443/Ethernet:IPv6:TCP:TLS',
      )
      expect(ipv6Tls).toBeDefined()
      expect(ipv6Tls!.source).toBe('2001:db8::1')
      expect(ipv6Tls!.destination).toBe('2001:db8::2')
      expect(ipv6Tls!.protocol).toBe('TLS')
      expect(ipv6Tls!.port).toBe('443')
    })

    it('parses IPv6 ICMPv6 UCI with port 0 as null', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const icmpv6 = store.connections.find(
        (c) => c.uci === '00:1B:1B:F8:3A:09/33:33:FF:F8:3A:07///fe80::1b:1bff:fef8:3a09///0/Ethernet:IPv6:ICMPv6',
      )
      expect(icmpv6).toBeDefined()
      expect(icmpv6!.source).toBe('fe80::1b:1bff:fef8:3a09')
      expect(icmpv6!.destination).toBe('33:33:FF:F8:3A:07')
      expect(icmpv6!.protocol).toBe('ICMPv6')
      expect(icmpv6!.port).toBe('0')
    })

    it('includes IPv6 connections in total connection count', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      expect(store.connectionCount).toBe(GOLDEN_UCI_LIST.length)
      const ipv6Connections = store.connections.filter((c) => c.source.includes('::') || c.destination.includes('::'))
      expect(ipv6Connections).toHaveLength(3)
    })

    it('uses IPv6 address for source instead of MAC when available', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')

      const ipv6Tls = store.connections.find(
        (c) => c.uci === 'a8:74:1d:02:99:8e/00:1B:1B:F8:3A:08//6/2001:db8::1/2001:db8::2//443/Ethernet:IPv6:TCP:TLS',
      )
      expect(ipv6Tls!.source).not.toBe('a8:74:1d:02:99:8e')
      expect(ipv6Tls!.source).toBe('2001:db8::1')
    })
  })

  describe('profiled-but-silent connections', () => {
    const SILENT_UCI = '00:1B:1B:F8:3A:aa/00:1B:1B:F8:3A:bb///////Ethernet:PROFINET_RT:PROFINET_RT_IO'
    const LIVE_UCI = GOLDEN_UCI_LIST[0].uci

    /** Serve a `/frequency/profiles` list containing the given series ids. */
    function profilesHandler(seriesIds: string[]) {
      return http.get('*/api/v1/frequency/profiles', () =>
        HttpResponse.json({
          module: 'conn',
          count: seriesIds.length,
          data: seriesIds.map((series_id) => ({ series_id, has_profile: true, module: 'conn', state: 'normal' })),
        }),
      )
    }

    it('lists a profiled connection that has no live traffic', async () => {
      server.use(profilesHandler([LIVE_UCI, SILENT_UCI]))
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')
      await store.fetchProfiledUcis()

      expect(store.silentProfiledConnections.map((c) => c.uci)).toEqual([SILENT_UCI])
      expect(store.silentProfiledCount).toBe(1)
    })

    it('never counts a profiled connection that is currently sending as silent', async () => {
      server.use(profilesHandler([LIVE_UCI]))
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')
      await store.fetchProfiledUcis()

      expect(store.silentProfiledConnections).toEqual([])
      expect(store.silentProfiledCount).toBe(0)
    })

    it('keeps silent rows out of the selectable list until the toggle is on', async () => {
      server.use(profilesHandler([SILENT_UCI]))
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')
      await store.fetchProfiledUcis()

      expect(store.selectableConnections.map((c) => c.uci)).not.toContain(SILENT_UCI)

      store.setShowSilentProfiled(true)
      expect(store.selectableConnections.map((c) => c.uci)).toContain(SILENT_UCI)
    })

    it('tags live and silent rows distinguishably', async () => {
      server.use(profilesHandler([SILENT_UCI]))
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')
      await store.fetchProfiledUcis()
      store.setShowSilentProfiled(true)

      const silent = store.selectableConnections.find((c) => c.uci === SILENT_UCI)
      const live = store.selectableConnections.find((c) => c.uci === LIVE_UCI)
      expect(silent!.presence).toBe('silent')
      expect(live!.presence).toBe('live')
    })

    it('parses a silent profiled UCI into readable endpoints', async () => {
      server.use(profilesHandler([SILENT_UCI]))
      const store = useConnectionsStore()
      await store.fetchProfiledUcis()

      const silent = store.silentProfiledConnections[0]!
      expect(silent.source).toBe('00:1B:1B:F8:3A:aa')
      expect(silent.destination).toBe('00:1B:1B:F8:3A:bb')
      expect(silent.protocol).toBe('PROFINET_RT_IO')
    })

    it('resolves a selected silent connection that is absent from live traffic', async () => {
      server.use(profilesHandler([SILENT_UCI]))
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')
      await store.fetchProfiledUcis()
      store.selectConnection(SILENT_UCI)

      expect(store.selectedConnection).toBeDefined()
      expect(store.selectedConnection!.uci).toBe(SILENT_UCI)
      expect(store.selectedConnection!.presence).toBe('silent')
    })

    it('ignores profiles the backend reports without a trained cadence', async () => {
      server.use(
        http.get('*/api/v1/frequency/profiles', () =>
          HttpResponse.json({
            module: 'conn',
            count: 2,
            data: [
              { series_id: SILENT_UCI, has_profile: true, module: 'conn', state: 'normal' },
              { series_id: 'ghost/series///////Ethernet', has_profile: false, module: 'conn', state: 'no_profile' },
            ],
          }),
        ),
      )
      const store = useConnectionsStore()
      await store.fetchProfiledUcis()

      expect(store.profiledUcis).toEqual([SILENT_UCI])
    })

    it('degrades quietly when the profile list is unavailable', async () => {
      server.use(http.get('*/api/v1/frequency/profiles', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })))
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')
      await store.fetchProfiledUcis()

      expect(store.profiledUcis).toEqual([])
      expect(store.error).toBeNull()
      expect(store.connections.length).toBeGreaterThan(0)
    })
  })

  describe('$reset', () => {
    it('clears all data', async () => {
      const store = useConnectionsStore()
      await store.fetchConnections('2026-03-07T00:00:00Z', '2026-03-07T23:59:59Z')
      store.selectConnection(GOLDEN_UCI_LIST[0].uci)

      expect(store.connections).not.toHaveLength(0)

      store.$reset()

      expect(store.connections).toEqual([])
      expect(store.selectedUci).toBeNull()
      expect(store.isLoading).toBe(false)
      expect(store.error).toBeNull()
    })
  })
})
