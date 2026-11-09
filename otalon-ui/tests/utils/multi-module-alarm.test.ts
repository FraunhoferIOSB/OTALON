/**
 * Regression tests for UI-092 — cross-module alarms (`module='multi'`) must
 * populate the Connections and Protocols tabs.
 *
 * Operator finding (2026-07-27, alarms `ae41f35e…` and `7ae9233f…`): after
 * CLAS-016 started labelling cross-module alarms with the sentinel
 * `module='multi'`, three places in the detail panel still keyed their logic off
 * `module` and did not know that value:
 *
 *   - `isConnectionAlarm` accepted only `conn` / `netcap`, so `connectionIds`
 *     returned [] even though the alarm carried a real UCI.
 *   - the protocol path only ran `buildProtocolItems` for `proto_traffic`;
 *     the fallback ignored `protocols[]` and dropped hash ids, so the tab was
 *     empty even though the API delivered a valid protocol label.
 *
 * These tests pin resolution by SERIES TYPE, so a new module name can never
 * silently empty a tab again.
 */
import { describe, it, expect } from 'vitest'

import { buildProtocolItems, classifySeriesIdentifier } from '~/utils/protocol'
import { extractAlarmMacs } from '~/utils/mac-match'
import { isNonUnicastMac } from '~/utils/format'

/** Real payload of operator alarm ae41f35e… (mac_traffic + proto_traffic). */
const MULTI_MAC_PROTO = {
  id: 'ae41f35e48084180b762695626dc8de2',
  module: 'multi',
  series_ids: ['1635346917', '33:33:00:00:00:02'],
  protocols: ['Ethernet:IPv6:ICMPv6', null],
}

/** Real payload of operator alarm 7ae9233f… (conn + proto_traffic). */
const MULTI_CONN_PROTO = {
  id: '7ae9233f9cd04524bceb3a9550798847',
  module: 'multi',
  series_ids: ['00:01:05:93:50:9b/a8:74:1d:02:99:8d///////Ethernet:PROFINET_RT:PROFINET_RT_IO', '481221027'],
  protocols: [null, 'Ethernet:PROFINET_RT:PROFINET_RT_IO'],
}

/** Mirrors the shipped `connectionIds` computed: classify, never match module. */
function connectionIds(group: { series_ids: string[] }): string[] {
  return group.series_ids.filter((id) => classifySeriesIdentifier(id) === 'connection')
}

describe('UI-092 — connections tab for module="multi"', () => {
  it('lists the UCI of a conn+proto alarm', () => {
    expect(connectionIds(MULTI_CONN_PROTO)).toEqual([MULTI_CONN_PROTO.series_ids[0]])
  })

  it('does not depend on the module name', () => {
    for (const module of ['multi', 'conn', 'netcap', 'some_future_module']) {
      expect(connectionIds({ ...MULTI_CONN_PROTO, module } as never)).toHaveLength(1)
    }
  })

  it('lists no connection when the alarm carries none', () => {
    expect(connectionIds(MULTI_MAC_PROTO)).toEqual([])
  })
})

describe('UI-092 — protocols tab for module="multi"', () => {
  it('resolves the protocol of the mac+proto alarm', () => {
    const items = buildProtocolItems(MULTI_MAC_PROTO.series_ids, MULTI_MAC_PROTO.protocols)
    expect(items.map((i) => i.label)).toEqual(['ICMPv6'])
  })

  it('resolves the protocol of the conn+proto alarm', () => {
    const items = buildProtocolItems(MULTI_CONN_PROTO.series_ids, MULTI_CONN_PROTO.protocols)
    expect(items.map((i) => i.label)).toEqual(['PROFINET RT IO'])
  })

  it('never renders the MAC or the UCI as a protocol', () => {
    const labels = [
      ...buildProtocolItems(MULTI_MAC_PROTO.series_ids, MULTI_MAC_PROTO.protocols),
      ...buildProtocolItems(MULTI_CONN_PROTO.series_ids, MULTI_CONN_PROTO.protocols),
    ].map((i) => i.label)
    expect(labels).not.toContain('02')
    expect(labels.filter((l) => l === 'PROFINET RT IO')).toHaveLength(1)
  })
})

describe('UI-092 — assets tab', () => {
  it('still surfaces the multicast MAC of the mac+proto alarm', () => {
    expect(extractAlarmMacs(MULTI_MAC_PROTO as never)).toEqual(['33:33:00:00:00:02'])
  })

  it('marks that MAC as non-navigable', () => {
    expect(isNonUnicastMac('33:33:00:00:00:02')).toBe(true)
  })

  it('keeps real device MACs navigable', () => {
    expect(isNonUnicastMac('a8:74:1d:02:99:8d')).toBe(false)
  })
})
