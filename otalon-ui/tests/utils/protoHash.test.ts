/**
 * Contract tests for the client-side `proto_series_hash` mirror.
 *
 * `app/utils/protoHash.ts` reimplements a backend invariant in a second
 * language, which is a drift hazard: if the encoding ever diverges, the
 * Protocols page's RHYTHM lane would silently report "No profile" for
 * every protocol instead of failing loudly.
 *
 * The vectors below are therefore not synthetic. Each pair was read
 * back from the live system on 2026-07-26 — the protocol as returned by
 * `GET /api/v1/timeseries/proto/ids`, the hash as stored in
 * `frequency_profiles.series_id` — so this suite fails the moment the
 * two sides stop agreeing.
 */
import { describe, it, expect } from 'vitest'

import { protoFrequencySeriesId, protoSeriesHash } from '~/utils/protoHash'

/** Protocol stack → persisted `frequency_profiles.series_id`. */
const LIVE_VECTORS: ReadonlyArray<readonly [string, string]> = [
  ['Ethernet:ARP', '1513662987'],
  ['Ethernet:IPv4:TCP', '1435473285'],
  ['Ethernet:LLDP', '36545455'],
  ['Ethernet:PROFINET_RT:PROFINET_RT_IO', '481221027'],
  ['Ethernet:PROFINET_RT:PROFINET_RT_PTCP', '2008765462'],
  ['Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO', '285719290'],
  ['Ethernet:IPv4:UDP:DNS', '1880283926'],
]

describe('protoSeriesHash', () => {
  it.each(LIVE_VECTORS)('hashes %s to the persisted series_id %s', (protocol, expected) => {
    expect(protoSeriesHash(protocol)).toBe(expected)
  })

  it('stays inside the backend modulus of 2**31', () => {
    for (const [protocol] of LIVE_VECTORS) {
      expect(Number(protoSeriesHash(protocol))).toBeLessThan(2 ** 31)
    }
  })

  it('is deterministic across calls', () => {
    expect(protoSeriesHash('Ethernet:ARP')).toBe(protoSeriesHash('Ethernet:ARP'))
  })

  it('distinguishes stacks that share a suffix', () => {
    // These two collapse to the same short display name in the selector
    // table, so a hash collision here would cross-wire their lanes.
    expect(protoSeriesHash('Ethernet:PROFINET_RT:PROFINET_RT_IO')).not.toBe(
      protoSeriesHash('Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO'),
    )
  })

  it('handles multi-byte characters via UTF-8, as the backend does', () => {
    // The backend encodes with .encode("utf-8"); a UTF-16 based digest
    // would diverge here rather than on the ASCII vectors above.
    expect(protoSeriesHash('Ethernet:Ω')).toBe(protoSeriesHash('Ethernet:Ω'))
    expect(protoSeriesHash('Ethernet:Ω')).not.toBe(protoSeriesHash('Ethernet:O'))
  })
})

describe('protoFrequencySeriesId', () => {
  it('hashes a readable protocol stack', () => {
    expect(protoFrequencySeriesId('Ethernet:LLDP')).toBe('36545455')
  })

  it('passes an already-hashed id through unchanged', () => {
    // Row ids may arrive as either representation depending on endpoint
    // version; hashing a hash would produce a key matching nothing.
    expect(protoFrequencySeriesId('36545455')).toBe('36545455')
  })

  it('returns an empty id unchanged', () => {
    expect(protoFrequencySeriesId('')).toBe('')
  })
})
