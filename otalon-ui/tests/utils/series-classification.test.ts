/**
 * Regression tests for UI-091 — mixed-module alarm series must not be
 * rendered as protocols.
 *
 * Operator finding (alarm ``c8d9a1bfa66942d8a8106e2630a5256e``, 2026-07-27):
 * a single alarm bundles anomalies from three detection modules, so its
 * ``series_ids`` contains a connection UCI, a numeric protocol hash id and a
 * MAC address. The old rendering paired ``series_ids`` positionally against
 * ``protocols[]`` and pushed every entry through ``humanizeProtocolStack``
 * (which returns the last ``:``-separated segment), so:
 *
 *   - the conn UCI surfaced as the protocol "PROFINET RT IO"
 *   - the MAC ``33:33:00:00:00:02`` surfaced as the protocol "02"
 *
 * The backend root cause is tracked separately as CLAS-016; these tests pin
 * the UI-side defense so non-protocol identifiers can never be rendered as
 * protocols again, even when the backend delivers a clean payload.
 */
import { describe, it, expect } from 'vitest'

import { buildProtocolItems, classifySeriesIdentifier } from '~/utils/protocol'
import { isMacAddress, isNonUnicastMac } from '~/utils/format'

/** Real payload of the operator-reported alarm, verified against the live API. */
const REAL_UCI = '00:01:05:93:50:9b/a8:74:1d:02:99:8d///////Ethernet:PROFINET_RT:PROFINET_RT_IO'
const REAL_PROTO_HASH = '1635346917'
const REAL_MAC = '33:33:00:00:00:02'

const REAL_SERIES_IDS = [REAL_UCI, REAL_PROTO_HASH, REAL_MAC]
const REAL_PROTOCOLS = [REAL_UCI, 'Ethernet:IPv6:ICMPv6', REAL_MAC]

describe('classifySeriesIdentifier', () => {
  it('recognises a connection UCI by its slash separators', () => {
    expect(classifySeriesIdentifier(REAL_UCI)).toBe('connection')
  })

  it('recognises a MAC address', () => {
    expect(classifySeriesIdentifier(REAL_MAC)).toBe('mac')
    expect(classifySeriesIdentifier('a8:74:1d:02:99:8d')).toBe('mac')
  })

  it('recognises a numeric protocol hash id', () => {
    expect(classifySeriesIdentifier(REAL_PROTO_HASH)).toBe('protocol_hash')
  })

  it('treats a real protocol stack as a protocol', () => {
    expect(classifySeriesIdentifier('Ethernet:IPv6:ICMPv6')).toBe('protocol')
    expect(classifySeriesIdentifier('Ethernet:IPv4:TCP')).toBe('protocol')
  })
})

describe('buildProtocolItems with the real mixed-module payload', () => {
  const items = buildProtocolItems(REAL_SERIES_IDS, REAL_PROTOCOLS)

  it('keeps only the single genuine protocol', () => {
    expect(items).toHaveLength(1)
    expect(items[0]?.label).toBe('ICMPv6')
  })

  it('never renders the MAC address as the protocol "02"', () => {
    expect(items.map((i) => i.label)).not.toContain('02')
  })

  it('never renders the connection UCI as "PROFINET RT IO"', () => {
    expect(items.map((i) => i.label)).not.toContain('PROFINET RT IO')
  })

  it('reports one real protocol, not three series ids', () => {
    expect(REAL_SERIES_IDS).toHaveLength(3)
    expect(buildProtocolItems(REAL_SERIES_IDS, REAL_PROTOCOLS)).toHaveLength(1)
  })

  it('keeps the protocol entry tied to its own series id', () => {
    expect(items[0]?.id).toBe(REAL_PROTO_HASH)
    expect(items[0]?.label).not.toBe(REAL_MAC)
  })

  it('falls back to the id when no label is supplied', () => {
    const withoutLabels = buildProtocolItems(['Ethernet:IPv4:TCP'])
    expect(withoutLabels).toEqual([{ id: 'Ethernet:IPv4:TCP', label: 'TCP' }])
  })
})

describe('isNonUnicastMac', () => {
  it('flags the IPv6 multicast MAC from the operator report', () => {
    expect(isNonUnicastMac(REAL_MAC)).toBe(true)
  })

  it('flags the broadcast MAC', () => {
    expect(isNonUnicastMac('ff:ff:ff:ff:ff:ff')).toBe(true)
  })

  it('accepts a real unicast device MAC', () => {
    expect(isNonUnicastMac('a8:74:1d:02:99:8d')).toBe(false)
    expect(isNonUnicastMac('00:01:05:93:50:9b')).toBe(false)
  })

  it('returns false for values that are not MAC addresses at all', () => {
    expect(isNonUnicastMac(REAL_UCI)).toBe(false)
    expect(isNonUnicastMac(REAL_PROTO_HASH)).toBe(false)
    expect(isNonUnicastMac('')).toBe(false)
  })

  it('stays consistent with isMacAddress', () => {
    expect(isMacAddress(REAL_MAC)).toBe(true)
    expect(isMacAddress(REAL_UCI)).toBe(false)
  })
})
