/**
 * Regression tests for protocol alarm hash↔plaintext matching (UI-036).
 *
 * Since API-011 the backend delivers BOTH the hash series_id and the readable
 * protocol name on proto_traffic alarm groups.  The helpers under test build
 * lookup sets that contain BOTH representations so the UI matches correctly
 * regardless of whether the table uses hashes or plaintext for `id`.
 */
import { describe, it, expect } from 'vitest'

import type { AnomalyGroupItem } from '~/types/api'
import type { ProtoSourceItem } from '~/stores/protoSourcesStore'
import { buildProtoAlarmSets, isProtoAnomalous } from '~/utils/proto-match'
import {
  hasWildcardPorts,
  matchesPortCollapseAlarmFilter,
  portCollapseBaseKey,
  portCollapsedConnectionCount,
} from '~/utils/uci'

const HASH_TCP = '1435473285'
const HASH_UDP = '1449078924'
const READABLE_TCP = 'Ethernet:IPv4:TCP'
const READABLE_UDP = 'Ethernet:IPv4:UDP'

function makeGroup(overrides: Partial<AnomalyGroupItem> = {}): AnomalyGroupItem {
  return {
    id: 'group-001',
    module: 'proto_traffic',
    start_timestamp: '2026-03-07T01:00:00Z',
    end_timestamp: '2026-03-07T05:00:00Z',
    primary_type: 'BoundViolation',
    multi_type: false,
    confirmed: false,
    is_active: true,
    series_ids: [],
    protocols: null,
    anomaly_type_stats: {},
    ...overrides,
  }
}

function makeProto(overrides: Partial<ProtoSourceItem> = {}): ProtoSourceItem {
  return {
    id: HASH_TCP,
    protocol: READABLE_TCP,
    ...overrides,
  }
}

describe('buildProtoAlarmSets', () => {
  it('collects hashes from series_ids', () => {
    const group = makeGroup({ series_ids: [HASH_TCP] })
    const { anomalousIds, groupProtocolMap } = buildProtoAlarmSets([group])

    expect(anomalousIds.has(HASH_TCP)).toBe(true)
    expect(groupProtocolMap.get('group-001')?.has(HASH_TCP)).toBe(true)
  })

  it('collects readable protocols from protocols field', () => {
    const group = makeGroup({ series_ids: [HASH_TCP], protocols: [READABLE_TCP] })
    const { anomalousIds, groupProtocolMap } = buildProtoAlarmSets([group])

    expect(anomalousIds.has(READABLE_TCP)).toBe(true)
    expect(groupProtocolMap.get('group-001')?.has(READABLE_TCP)).toBe(true)
  })

  it('handles groups without protocols field (backward compat)', () => {
    const group = makeGroup({ series_ids: [HASH_TCP], protocols: null })
    const { anomalousIds } = buildProtoAlarmSets([group])

    expect(anomalousIds.has(HASH_TCP)).toBe(true)
    expect(anomalousIds.has(READABLE_TCP)).toBe(false)
  })

  it('aggregates multiple groups', () => {
    const groups: AnomalyGroupItem[] = [
      makeGroup({ id: 'g1', series_ids: [HASH_TCP], protocols: [READABLE_TCP] }),
      makeGroup({ id: 'g2', series_ids: [HASH_UDP], protocols: [READABLE_UDP] }),
    ]
    const { anomalousIds, groupProtocolMap } = buildProtoAlarmSets(groups)

    expect(anomalousIds.size).toBe(4)
    expect(groupProtocolMap.get('g1')?.size).toBe(2)
    expect(groupProtocolMap.get('g2')?.size).toBe(2)
  })
})

describe('isProtoAnomalous', () => {
  it('matches when proto.id equals a hash in the set', () => {
    const ids = new Set([HASH_TCP])
    expect(isProtoAnomalous(makeProto({ id: HASH_TCP, protocol: null }), ids)).toBe(true)
  })

  it('matches when proto.protocol equals a readable name in the set', () => {
    const ids = new Set([READABLE_TCP])
    expect(isProtoAnomalous(makeProto({ id: 'other', protocol: READABLE_TCP }), ids)).toBe(true)
  })

  it('matches when proto.id equals a readable name in the set (API-011 id field)', () => {
    const ids = new Set([READABLE_TCP])
    expect(isProtoAnomalous(makeProto({ id: READABLE_TCP, protocol: null }), ids)).toBe(true)
  })

  it('returns false for a normal proto', () => {
    const ids = new Set([HASH_TCP])
    expect(isProtoAnomalous(makeProto({ id: HASH_UDP, protocol: READABLE_UDP }), ids)).toBe(false)
  })

  it('returns false for empty set', () => {
    expect(isProtoAnomalous(makeProto(), new Set())).toBe(false)
  })
})

describe('port-collapse UCI identity', () => {
  const exact = '00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/192.168.0.2/192.168.0.41/1234/5678/Ethernet:IPv4:UDP:PROFINET_DCE_RPC'
  const wildcard = '00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/192.168.0.2/192.168.0.41/*/*/Ethernet:IPv4:UDP:PROFINET_DCE_RPC'
  const unrelated = '00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/192.168.0.2/192.168.0.42/*/*/Ethernet:IPv4:UDP:PROFINET_DCE_RPC'

  it('keeps normal and wildcard sibling UCIs on same base key', () => {
    expect(portCollapseBaseKey(exact)).toBe(portCollapseBaseKey(wildcard))
    expect(hasWildcardPorts(exact)).toBe(false)
    expect(hasWildcardPorts(wildcard)).toBe(true)
  })

  it('does not match wildcard UCI with unrelated base key', () => {
    expect(portCollapseBaseKey(unrelated)).not.toBe(portCollapseBaseKey(exact))
  })

  it('keeps direct series and same-base wildcard sibling, excluding unrelated wildcard', () => {
    const affected = new Set([exact])
    expect(matchesPortCollapseAlarmFilter(exact, affected)).toBe(true)
    expect(matchesPortCollapseAlarmFilter(wildcard, affected)).toBe(true)
    expect(matchesPortCollapseAlarmFilter(unrelated, affected)).toBe(false)
  })

  it('counts many raw ports as one collapsed connection group', () => {
    const rawPorts = Array.from(
      { length: 339 },
      (_, index) =>
        `00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/192.168.0.2/192.168.0.41/${1000 + index}/5678/Ethernet:IPv4:TCP:OPC_UA`,
    )
    const secondGroup =
      '00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/192.168.0.2/192.168.0.42/4000/4840/Ethernet:IPv4:TCP:OPC_UA'

    expect(portCollapsedConnectionCount([...rawPorts, secondGroup])).toBe(2)
  })
})
