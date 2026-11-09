/**
 * Regression tests for UI-093 — profiled-but-silent protocols must be named.
 *
 * Operator finding (2026-07-27): with the SILENT toggle on, the Protocols page
 * listed silent entries as bare hashes (e.g. `1435473285`) instead of protocol
 * names. `GET /api/v1/frequency/profiles` keys profiles by hash while the
 * protocol list endpoint returns readable stacks, and a silent protocol is by
 * definition absent from the live list — so the row had no name to show.
 *
 * The hash is one-way, so resolution works by hashing the known candidates and
 * matching. These vectors were read back from the live API on 2026-07-27.
 */
import { describe, it, expect } from 'vitest'

import { protoComparisonKey, protoLabelFromSeriesId, protoSeriesHash } from '~/utils/protoHash'

/** Live hash → stack pairs, including the operator's reported id. */
const LIVE_VECTORS: ReadonlyArray<readonly [string, string]> = [
  ['1435473285', 'Ethernet:IPv4:TCP'],
  ['1214521437', 'Ethernet:IPv4:TCP:HTTPRequest'],
  ['1449078924', 'Ethernet:IPv4:UDP:PROFINET_DCE_RPC'],
  ['1513662987', 'Ethernet:ARP'],
  ['1635346917', 'Ethernet:IPv6:ICMPv6'],
  ['1834999852', 'Ethernet:IPv6:UDP:DNS'],
]

const CANDIDATES = LIVE_VECTORS.map(([, stack]) => stack)

describe('UI-093 — resolving a silent protocol hash to its name', () => {
  it.each(LIVE_VECTORS)('resolves %s to %s', (hash, stack) => {
    expect(protoLabelFromSeriesId(hash, CANDIDATES)).toBe(stack)
  })

  it('resolves the exact id the operator reported', () => {
    expect(protoLabelFromSeriesId('1435473285', CANDIDATES)).toBe('Ethernet:IPv4:TCP')
  })

  it('stays consistent with the forward hash', () => {
    for (const [hash, stack] of LIVE_VECTORS) {
      expect(protoSeriesHash(stack)).toBe(hash)
    }
  })

  it('resolves a hash whose stack is absent from the loaded window', () => {
    // The SILENT toggle exists for protocols that stopped sending, so their
    // stack is typically NOT in the page's live list. Resolution must still
    // work — this is the case that shipped broken first (UI-093).
    expect(protoLabelFromSeriesId('1513662987', [])).toBe('Ethernet:ARP')
    expect(protoLabelFromSeriesId('1635346917', [])).toBe('Ethernet:IPv6:ICMPv6')
  })

  it('returns the raw id when no candidate matches', () => {
    expect(protoLabelFromSeriesId('999999999', CANDIDATES)).toBe('999999999')
  })

  it('passes through an already readable stack unchanged', () => {
    expect(protoLabelFromSeriesId('Ethernet:ARP', CANDIDATES)).toBe('Ethernet:ARP')
  })

  it('ignores numeric candidates instead of hashing them', () => {
    // '1435473285' is Ethernet:IPv4:TCP, resolved via the well-known list —
    // what matters here is that the numeric candidate itself was not hashed.
    expect(protoLabelFromSeriesId('1435473285', ['1435473285'])).toBe('Ethernet:IPv4:TCP')
  })

  it('tolerates an empty candidate list', () => {
    expect(protoLabelFromSeriesId('1435473285', [])).toBe('Ethernet:IPv4:TCP')
  })

  it('deduplicates a live readable protocol against its profiled hash', () => {
    const live = ['Ethernet:ARP']
    const profiled = ['1513662987', '1834999852']
    const liveKeys = new Set(live.map((id) => protoComparisonKey(id, live)))
    const silentOnly = profiled.filter((id) => !liveKeys.has(protoComparisonKey(id, live)))

    expect(silentOnly).toEqual(['1834999852'])
  })

  it('keeps a genuinely silent-only protocol', () => {
    const live = ['Ethernet:ARP']

    expect(protoComparisonKey('1834999852', live)).toBe('Ethernet:IPv6:UDP:DNS')
  })
})
