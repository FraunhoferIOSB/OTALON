/**
 * Regression tests for MAC alarm correlation (UI-037).
 *
 * A conn-primary alarm (e.g. `icmp_flood`) carries its affected MACs in
 * the `enrichment.mac` cross-source bucket — NOT in `series_ids` (those
 * are connection UCIs).  Earlier the Assets-Subpage filter and the
 * Alarm-Detail Assets tab only looked at `series_ids`, so such an alarm
 * was neither selectable nor flagged red and the Assets tab was empty.
 *
 * These tests pin the enrichment-aware resolution: both a pure
 * `mac_traffic` alarm and a conn-primary alarm with `enrichment.mac`
 * resolve to the correct plaintext MAC set.  The enrichment payloads
 * mirror the real producer (`otalon-clas cross_source._evidence_entry`).
 */
import { describe, it, expect } from 'vitest'

import type { AnomalyGroupItem } from '~/types/api'
import { buildAnomalousMacSet, extractAlarmMacs, groupAffectsMac, parseEnrichmentMacEntries } from '~/utils/mac-match'

const MAC_A = '30:b8:51:31:06:84'
const MAC_B = '7c:cb:e2:ea:0d:65'
const ICMP_UCI = `${MAC_A}/${MAC_B}//IPv4/192.168.0.1/192.168.0.196/0/0/Ethernet:IPv4:ICMP`

function macEvidence(mac: string): Record<string, unknown> {
  return {
    anomaly_id: `mac_traffic|${mac}|2026-06-20T10:47:15+00:00|2026-06-20T10:47:15+00:00`,
    module: 'mac_traffic',
    series_id: mac,
    anomaly_type: 'BoundViolation',
    confidence: 1.0,
    start_ts: '2026-06-20T12:47:15+02:00',
    end_ts: '2026-06-20T12:47:15+02:00',
  }
}

function makeGroup(overrides: Partial<AnomalyGroupItem> = {}): AnomalyGroupItem {
  return {
    id: 'group-001',
    module: 'conn',
    start_timestamp: '2026-06-20T10:47:00Z',
    end_timestamp: '2026-06-20T10:48:00Z',
    primary_type: 'icmp_flood',
    multi_type: false,
    confirmed: false,
    is_active: true,
    series_ids: [],
    protocols: null,
    anomaly_type_stats: {},
    enrichment: null,
    ...overrides,
  }
}

describe('parseEnrichmentMacEntries', () => {
  it('reads plaintext MAC series_ids from the enrichment.mac bucket', () => {
    const group = makeGroup({
      enrichment: { schema: 1, mac: [macEvidence(MAC_A), macEvidence(MAC_B)], proto: [] },
    })
    expect(parseEnrichmentMacEntries(group)).toEqual([MAC_A, MAC_B])
  })

  it('returns [] when enrichment is null', () => {
    expect(parseEnrichmentMacEntries(makeGroup({ enrichment: null }))).toEqual([])
  })

  it('returns [] when the mac bucket is missing or empty', () => {
    expect(parseEnrichmentMacEntries(makeGroup({ enrichment: { schema: 1, proto: [] } }))).toEqual([])
    expect(parseEnrichmentMacEntries(makeGroup({ enrichment: { schema: 1, mac: [], proto: [] } }))).toEqual([])
  })
})

describe('extractAlarmMacs', () => {
  it('resolves series_ids for a mac_traffic alarm', () => {
    const group = makeGroup({ module: 'mac_traffic', primary_type: 'BoundViolation', series_ids: [MAC_A, MAC_B] })
    expect(extractAlarmMacs(group)).toEqual([MAC_A, MAC_B])
  })

  it('resolves enrichment.mac for a conn-primary icmp_flood alarm (the core fix)', () => {
    const group = makeGroup({
      series_ids: [ICMP_UCI, '1513662987'],
      enrichment: { schema: 1, mac: [macEvidence(MAC_A), macEvidence(MAC_B)], proto: [] },
    })
    expect(extractAlarmMacs(group)).toEqual([MAC_A, MAC_B])
  })

  it('does NOT treat a conn UCI as a MAC', () => {
    const group = makeGroup({ series_ids: [ICMP_UCI, '1513662987'], enrichment: null })
    expect(extractAlarmMacs(group)).toEqual([])
  })

  it('de-duplicates MACs across series_ids and enrichment, case-insensitively', () => {
    const group = makeGroup({
      module: 'mac_traffic',
      primary_type: 'BoundViolation',
      series_ids: [MAC_A],
      enrichment: { schema: 1, mac: [macEvidence(MAC_A.toUpperCase()), macEvidence(MAC_B)], proto: [] },
    })
    const macs = extractAlarmMacs(group)
    expect(macs).toContain(MAC_A)
    expect(macs).toContain(MAC_B)
    expect(macs).toHaveLength(2)
  })

  it('ignores standalone MAC series_ids only when they are real MACs', () => {
    const group = makeGroup({ series_ids: [MAC_A, 'not-a-mac', '1513662987'], enrichment: null })
    expect(extractAlarmMacs(group)).toEqual([MAC_A])
  })
})

describe('groupAffectsMac', () => {
  it('is true for a conn-primary alarm with enrichment.mac', () => {
    const group = makeGroup({
      series_ids: [ICMP_UCI],
      enrichment: { schema: 1, mac: [macEvidence(MAC_A)], proto: [] },
    })
    expect(groupAffectsMac(group)).toBe(true)
  })

  it('is false for a conn alarm with only UCIs and no mac enrichment', () => {
    expect(groupAffectsMac(makeGroup({ series_ids: [ICMP_UCI], enrichment: { schema: 1, mac: [], proto: [] } }))).toBe(
      false,
    )
  })
})

describe('buildAnomalousMacSet', () => {
  it('unions MACs from series_ids and enrichment across groups, lower-cased', () => {
    const groups: AnomalyGroupItem[] = [
      makeGroup({ id: 'g1', module: 'mac_traffic', primary_type: 'BoundViolation', series_ids: [MAC_A] }),
      makeGroup({ id: 'g2', series_ids: [ICMP_UCI], enrichment: { schema: 1, mac: [macEvidence(MAC_B)], proto: [] } }),
    ]
    const set = buildAnomalousMacSet(groups)
    expect(set.has(MAC_A.toLowerCase())).toBe(true)
    expect(set.has(MAC_B.toLowerCase())).toBe(true)
    expect(set.size).toBe(2)
  })

  it('flags the enrichment MAC red even though it is not in series_ids', () => {
    const group = makeGroup({
      series_ids: [ICMP_UCI],
      enrichment: { schema: 1, mac: [macEvidence(MAC_A)], proto: [] },
    })
    const set = buildAnomalousMacSet([group])
    // The MAC participates in the conn anomaly only via enrichment.
    expect(set.has(MAC_A.toLowerCase())).toBe(true)
  })
})
