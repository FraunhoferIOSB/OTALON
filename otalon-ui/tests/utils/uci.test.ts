import { describe, expect, it } from 'vitest'

import {
  alarmFilteredConnections,
  matchesPortCollapseAlarmFilter,
  matchesPortCollapseSibling,
  parseUciToConnection,
} from '~/utils/uci'
import type { Connection } from '~/types/golden-data'

const alarmSeriesId =
  '38:4b:24:fa:b6:34/cc:82:7f:a1:8a:37//IPv4/192.168.0.233/192.168.0.201/161/47584/Ethernet:IPv4:UDP'
const liveWildcardConnection =
  'cc:82:7f:a1:8a:36/38:4b:24:fa:b6:34//IPv4/192.168.0.201/192.168.0.233/*/161/Ethernet:IPv4:UDP'

describe('matchesPortCollapseAlarmFilter', () => {
  it('matches asymmetric request/response port collapse siblings', () => {
    expect(matchesPortCollapseAlarmFilter(liveWildcardConnection, new Set([alarmSeriesId]))).toBe(true)
  })

  it('does not match an unrelated device pair', () => {
    const unrelatedConnection = 'aa:bb:cc:dd:ee:ff/11:22:33:44:55:66//IPv4/10.0.0.1/10.0.0.2/*/161/Ethernet:IPv4:UDP'

    expect(matchesPortCollapseAlarmFilter(unrelatedConnection, new Set([alarmSeriesId]))).toBe(false)
  })
})

describe('matchesPortCollapseSibling', () => {
  it('matches two concrete UCIs sharing a base key with different ports', () => {
    const staleAlarmUci =
      '38:4b:24:fa:b6:34/cc:82:7f:a1:8a:37//IPv4/192.168.0.233/192.168.0.201/50000/50462/Ethernet:IPv4:UDP:DCE_RPC'
    const rotatedLiveUci =
      '38:4b:24:fa:b6:34/cc:82:7f:a1:8a:37//IPv4/192.168.0.233/192.168.0.201/50000/56247/Ethernet:IPv4:UDP:DCE_RPC'

    expect(matchesPortCollapseSibling(staleAlarmUci, rotatedLiveUci)).toBe(true)
    expect(matchesPortCollapseAlarmFilter(rotatedLiveUci, new Set([staleAlarmUci]))).toBe(true)
  })

  it('does not badge-match a broadcast target against a different unicast connection', () => {
    // P8-#3D operator report: a broadcast ARP connection has no reverse
    // direction and must not badge-match a unicast connection sharing one MAC.
    const broadcastConnection = '38:4b:24:fa:b6:34/ff:ff:ff:ff:ff:ff///////Ethernet:ARP'
    const unrelatedUnicastAlarm = '7c:cb:e2:ea:0d:65/38:4b:24:fa:b6:34///////Ethernet:ARP'

    expect(matchesPortCollapseSibling(broadcastConnection, unrelatedUnicastAlarm)).toBe(false)
    expect(matchesPortCollapseAlarmFilter(broadcastConnection, new Set([unrelatedUnicastAlarm]))).toBe(false)
  })

  it('does not match two concrete UCIs with different base keys', () => {
    const first =
      '38:4b:24:fa:b6:34/cc:82:7f:a1:8a:37//IPv4/192.168.0.233/192.168.0.201/50000/50462/Ethernet:IPv4:UDP:DCE_RPC'
    const otherDevice =
      '38:4b:24:fa:b6:34/cc:82:7f:a1:8a:37//IPv4/192.168.0.233/192.168.0.202/50000/50462/Ethernet:IPv4:UDP:DCE_RPC'

    expect(matchesPortCollapseSibling(first, otherDevice)).toBe(false)
  })
})

/**
 * Fixtures for {@link alarmFilteredConnections} — the pure helper behind the
 * Connections page `filteredByAlarm` computed (UI-174).
 */
const ABSENT_UCI = '38:4b:24:fa:b6:34/cc:82:7f:a1:8a:37//IPv4/192.168.0.233/192.168.0.201/161/47584/Ethernet:IPv4:UDP'
const ABSENT_SIBLING_UCI =
  '38:4b:24:fa:b6:34/cc:82:7f:a1:8a:37//IPv4/192.168.0.233/192.168.0.201/161/56247/Ethernet:IPv4:UDP'
const UNRELATED_LIVE = 'aa:bb:cc:dd:ee:ff/11:22:33:44:55:66//IPv4/10.0.0.1/10.0.0.2/1234/80/Ethernet:IPv4:TCP'
const NON_UCI_SERIES = 'mac_traffic:38:4b:24:fa:b6:34'

const live = (uci: string): Connection => parseUciToConnection({ uci }, 'live')

describe('alarmFilteredConnections', () => {
  it('appends an absent alarm series as a silent row when it is not in the selectable list', () => {
    // The absence-anomaly scenario: the alarm series has no live traffic, so
    // without the fix the alarm-filtered table would be empty (UI-174).
    const result = alarmFilteredConnections([live(UNRELATED_LIVE)], [ABSENT_UCI], () => false)

    expect(result).toHaveLength(1)
    expect(result[0]?.uci).toBe(ABSENT_UCI)
    expect(result[0]?.presence).toBe('silent')
  })

  it('does not duplicate a series already present as a live connection sibling', () => {
    const result = alarmFilteredConnections([live(ABSENT_SIBLING_UCI)], [ABSENT_UCI], () => false)

    expect(result).toHaveLength(1)
    expect(result[0]?.uci).toBe(ABSENT_SIBLING_UCI)
  })

  it('skips non-UCI series identifiers (MAC/protocol series without a slash)', () => {
    const result = alarmFilteredConnections([live(UNRELATED_LIVE)], [NON_UCI_SERIES, ABSENT_UCI], () => false)

    expect(result).toHaveLength(1)
    expect(result[0]?.uci).toBe(ABSENT_UCI)
  })

  it('deduplicates port-collapse sibling series to a single silent row', () => {
    const result = alarmFilteredConnections([], [ABSENT_UCI, ABSENT_SIBLING_UCI], () => false)

    expect(result).toHaveLength(1)
    expect(result[0]?.presence).toBe('silent')
  })

  it('marks absent rows as anomaly when the enricher flags them', () => {
    const result = alarmFilteredConnections([live(UNRELATED_LIVE)], [ABSENT_UCI], (uci) => uci === ABSENT_UCI)

    const silentRow = result.find((c) => c.uci === ABSENT_UCI)
    expect(silentRow?.state).toBe('anomaly')
  })

  it('returns the enriched selectable list unchanged when no alarm group is selected', () => {
    const result = alarmFilteredConnections([live(UNRELATED_LIVE)], [], (uci) => uci === UNRELATED_LIVE)

    expect(result).toHaveLength(1)
    expect(result[0]?.state).toBe('anomaly')
  })
})
