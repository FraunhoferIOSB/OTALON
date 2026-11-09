import { isMacAddress } from '~/utils/format'

/**
 * Classification of a raw anomaly `series_id`.
 *
 * A single alarm can bundle series from several detection modules, so the
 * identifiers arriving in `series_ids` are heterogeneous: connection UCIs,
 * MAC addresses, numeric protocol hash ids and real protocol stacks. Pairing
 * them positionally against `protocols[]` renders MACs and UCIs as protocol
 * names (a MAC `33:33:00:00:00:02` would surface as the protocol "02").
 */
export type SeriesIdentifierType = 'connection' | 'mac' | 'protocol_hash' | 'protocol'

/**
 * Classify a mixed anomaly series identifier before rendering it.
 *
 * @param id - Raw series identifier from an anomaly group.
 * @returns The identifier category; only `'protocol'` may be shown as a protocol.
 */
export function classifySeriesIdentifier(id: string): SeriesIdentifierType {
  if (id.includes('/')) return 'connection'
  if (isMacAddress(id)) return 'mac'
  if (isProtocolHashId(id)) return 'protocol_hash'
  return 'protocol'
}

/**
 * Return only genuine protocol series, resolving each id to a readable label.
 *
 * A proto_traffic series is identified by a numeric hash id whose readable
 * protocol stack arrives in the index-parallel ``protocols[]`` array (API-021),
 * so
 * the decision whether an entry is a protocol MUST be made on the resolved
 * label, not on the id. Judging by id alone would drop every real protocol
 * (its id is a hash) and keep nothing.
 *
 * The API uses ``null`` for non-protocol series, regardless of module.
 *
 * Entries whose label still resolves to a connection UCI or a MAC address —
 * the cross-module pollution described in CLAS-016 — are dropped. An entry
 * whose id is a hash but whose label is missing is dropped too, because a
 * bare hash is not a meaningful protocol name. An entry whose id is ITSELF a
 * readable protocol stack keeps working without a label: callers pass
 * `protocols ?? []`, so an absent array must not silently empty the tab.
 *
 * @param ids - Raw `series_ids` of an anomaly group.
 * @param labels - Optional `protocols[]` labels from the API.
 * @returns Protocol entries with humanized labels; non-protocol ids are dropped.
 */
export function buildProtocolItems(ids: string[], labels: (string | null)[] = []): { id: string; label: string }[] {
  const result: { id: string; label: string }[] = []
  for (const [index, id] of ids.entries()) {
    const type = classifySeriesIdentifier(id)
    if (type !== 'protocol' && type !== 'protocol_hash') continue

    const supplied = labels[index]
    // A hash id carries no meaning on its own, so it needs a resolved label.
    // A readable stack id is its own fallback when the API sent none.
    const label = supplied ?? (type === 'protocol' ? id : null)
    if (label === null || label === undefined) continue
    if (classifySeriesIdentifier(label) !== 'protocol') continue

    result.push({ id, label: humanizeProtocolStack(label) })
  }
  return result
}

/**
 * Humanize a protocol stack label by extracting the most-specific segment
 * and replacing underscores with spaces.
 *
 * @example
 * humanizeProtocolStack('Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO')
 * // => 'PROFINET RT IO'
 *
 * @example
 * humanizeProtocolStack('Ethernet:IPv4:TCP')
 * // => 'TCP'
 *
 * @param label - Raw protocol chain from the backend.
 * @returns Human-readable protocol name.
 */
export function humanizeProtocolStack(label: string): string {
  if (!label) return ''
  const top = label.split(':').pop() ?? label
  return top.replace(/_/g, ' ')
}

/**
 * Determine whether a raw protocol / series identifier is a numeric hash
 * that should be hidden from the UI.
 *
 * @param id - Raw identifier string.
 * @returns `true` when the string consists only of digits.
 */
export function isProtocolHashId(id: string): boolean {
  return /^\d+$/.test(id)
}
