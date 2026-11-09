/**
 * UCI parsing helpers shared by the live-traffic list and the
 * frequency-profile list.
 *
 * A connection reaches the connections page through two independent
 * doors: `GET /api/v1/timeseries/ids` (it is sending right now) and
 * `GET /api/v1/frequency/profiles` (it has a learned cadence, whether or
 * not it is sending). Both carry the same UCI string, so the parsing
 * lives here instead of inside one store.
 */
import type { Connection, ConnectionPresence, ConnectionState } from '~/types/golden-data'

/**
 * Fields needed to build a {@link Connection} from any UCI-carrying payload.
 */
export interface UciSource {
  uci: string
  is_wildcard?: boolean
  member_count?: number
  collapsed_port_count?: number | null
  rule_trained?: boolean
  profiled?: boolean
}

const UCI_SEGMENTS = 9

/**
 * Return UCI identity fields that survive port collapse.
 *
 * @param uci - Connection UCI in its canonical slash-separated form.
 * @returns Identity key containing MAC, IP, VLAN, IP protocol, and protocol stack.
 */
export function portCollapseBaseKey(uci: string): string {
  const parts = uci.split('/')
  while (parts.length < UCI_SEGMENTS) {
    parts.push('')
  }
  return [0, 1, 2, 3, 4, 5, 8].map((index) => parts[index] ?? '').join('/')
}

/**
 * Check whether UCI uses a wildcard value for either collapsed port field.
 *
 * @param uci - Connection UCI to inspect.
 * @returns Whether source or destination port is wildcarded.
 */
export function hasWildcardPort(uci: string): boolean {
  const parts = uci.split('/')
  return parts[6] === '*' || parts[7] === '*'
}

/**
 * Backward-compatible alias for callers that use plural naming.
 *
 * @param uci - Connection UCI to inspect.
 * @returns Whether source or destination port is wildcarded.
 */
export function hasWildcardPorts(uci: string): boolean {
  return hasWildcardPort(uci)
}

/**
 * Match two UCIs when they identify the same connection or port-collapse sibling.
 *
 * Two concrete UCIs that share a port-collapse base key are treated as
 * siblings even when neither side carries a wildcard port: the base key
 * strips exactly the port fields, so equal base keys identify the same
 * connection with possibly rotated concrete ports (e.g. a DCE/RPC
 * endpoint that rotated its ephemeral port after the rule was trained).
 *
 * @param left - First UCI to compare.
 * @param right - Second UCI to compare.
 * @returns Whether UCIs match exactly or share port-collapse identity
 *   (directly, across a wildcard port, or as a direction-swapped sibling).
 */
export function matchesPortCollapseSibling(left: string, right: string): boolean {
  if (left === right) return true
  const leftParts = left.split('/')
  const rightParts = right.split('/')
  const directMatch = portCollapseBaseKey(left) === portCollapseBaseKey(right)
  // A direction swap is only meaningful between two real endpoint MACs. A
  // broadcast/multicast address (e.g. ff:ff:ff:ff:ff:ff as ARP target) has no
  // "reverse direction" — treating it as swappable made a broadcast connection
  // match a completely different unicast connection that merely shares one MAC
  // (P8-#3D operator report: `38:4b…/ff:ff…/ARP` wrongly badge-matched
  // `7c:cb…/38:4b…/ARP`). Require all four MACs to be unicast.
  const isUnicastMac = (mac: string): boolean => {
    if (!mac) return false
    if (mac.toLowerCase() === 'ff:ff:ff:ff:ff:ff') return false
    const firstOctet = Number.parseInt(mac.split(':')[0] ?? '', 16)
    return Number.isFinite(firstOctet) && (firstOctet & 0x01) === 0
  }
  const allUnicast =
    isUnicastMac(leftParts[0] ?? '') &&
    isUnicastMac(leftParts[1] ?? '') &&
    isUnicastMac(rightParts[0] ?? '') &&
    isUnicastMac(rightParts[1] ?? '')
  const reverseMatch =
    allUnicast &&
    leftParts[2] === rightParts[2] &&
    leftParts[3] === rightParts[3] &&
    leftParts[4] === rightParts[5] &&
    leftParts[5] === rightParts[4] &&
    leftParts[8] === rightParts[8] &&
    (leftParts[0] === rightParts[1] || leftParts[1] === rightParts[0]) &&
    // Ports must mirror too, but a wildcard port on either side collapses the
    // whole port dimension (P8-#3E): `*/161` reverses to `161/*` and still
    // matches an alarm stored as `161/47584`. Require each mirrored port pair
    // to be equal OR wildcarded, so an unrelated concrete port does NOT match.
    (leftParts[6] === '*' || rightParts[7] === '*' || leftParts[6] === rightParts[7]) &&
    (leftParts[7] === '*' || rightParts[6] === '*' || leftParts[7] === rightParts[6])
  return directMatch || reverseMatch
}

/**
 * Match a connection against alarm series, including port-collapse siblings.
 *
 * @param uci - Candidate connection UCI.
 * @param affectedUcis - UCIs returned in selected alarm group's series_ids.
 * @returns Whether candidate is directly affected or a wildcard sibling.
 */
export function matchesPortCollapseAlarmFilter(uci: string, affectedUcis: Set<string>): boolean {
  return [...affectedUcis].some((affectedUci) => matchesPortCollapseSibling(uci, affectedUci))
}

/**
 * Collapse connection UCIs into one representative per port-collapsed group.
 *
 * Non-UCI identifiers are ignored because alarm groups can contain MAC and
 * protocol series alongside connection series.
 *
 * @param ucis - Raw alarm series identifiers.
 * @returns One UCI for each distinct port-collapsed identity.
 */
export function collapsePortUcis(ucis: string[]): string[] {
  const groups = new Map<string, string>()
  for (const uci of ucis) {
    if (!uci.includes('/')) continue
    const key = portCollapseBaseKey(uci)
    const current = groups.get(key)
    if (!current || hasWildcardPort(uci)) groups.set(key, uci)
  }
  return [...groups.values()]
}

/**
 * Count distinct port-collapsed connection groups in raw alarm identifiers.
 *
 * @param ucis - Raw alarm series identifiers.
 * @returns Number of distinct connection identities after port collapse.
 */
export function portCollapsedConnectionCount(ucis: string[]): number {
  return collapsePortUcis(ucis).length
}

/**
 * Parse a backend UCI string into a {@link Connection}.
 *
 * The backend UCI format uses `/` as segment separator with 9 fixed
 * segments: `src_mac/dst_mac/vlan/ip_proto/src_ip/dst_ip/src_port/dst_port/protocols`.
 *
 * Source/destination are derived from IP addresses when available,
 * falling back to MAC addresses. Protocol is the last colon-separated
 * token from the protocols segment. Port is extracted separately from
 * the dst_port segment (null when wildcard or absent).
 *
 * @param item - Any payload carrying a `uci` plus optional wildcard metadata.
 * @param presence - Whether the connection is currently sending (`live`)
 *   or only known from a learned profile (`silent`).
 * @returns A Connection object with parsed fields.
 *
 * @example
 * ```ts
 * const conn = parseUciToConnection({ uci: 'aa:bb/cc:dd///////Ethernet:ARP' }, 'silent')
 * conn.protocol // 'ARP'
 * ```
 */
export function parseUciToConnection(item: UciSource, presence: ConnectionPresence = 'live'): Connection {
  const parts = item.uci.split('/')
  while (parts.length < UCI_SEGMENTS) {
    parts.push('')
  }

  const srcMac = parts[0] ?? ''
  const dstMac = parts[1] ?? ''
  const srcIp = parts[4] ?? ''
  const dstIp = parts[5] ?? ''
  // parts[6] is src_port — not currently surfaced in the UI; intentionally skipped.
  const dstPort = parts[7] ?? ''
  const protocols = parts[8] ?? ''

  const protocolParts = protocols.split(':').filter(Boolean)
  const protocol = protocolParts.length > 0 ? (protocolParts[protocolParts.length - 1] as string) : 'Unknown'

  return {
    uci: item.uci,
    source: srcIp || srcMac,
    destination: dstIp || dstMac,
    sourceIp: srcIp || null,
    sourceMac: srcMac || null,
    destIp: dstIp || null,
    destMac: dstMac || null,
    protocol,
    port: dstPort && dstPort !== '*' ? dstPort : null,
    state: 'normal' as ConnectionState,
    isWildcard: item.is_wildcard ?? false,
    memberCount: item.member_count ?? 0,
    collapsed_port_count: item.collapsed_port_count ?? null,
    ruleTrained: item.rule_trained ?? true,
    profiled: item.profiled ?? true,
    presence,
  }
}

/**
 * Build the Connections list filtered by the selected alarm group.
 *
 * When an alarm group is active, only connections affected by it are shown.
 * A series that triggered an absence anomaly may be absent from the live
 * list entirely (no traffic in the current window), so it would vanish from
 * the table whenever {@link ConnectionsState.showSilentProfiled} is off. To
 * keep the alarm story complete regardless of the toggle, such series are
 * materialised here as `silent` rows.
 *
 * Non-UCI series identifiers (MAC/protocol traffic, no `/`) are skipped —
 * only connection series render on the Connections page. Port-collapse
 * siblings are deduplicated so a single connection identity never produces
 * two rows.
 *
 * @param selectable - The connections offered for selection (live, plus
 *   silent profiled when the toggle is on).
 * @param seriesIds - Raw series identifiers from the selected alarm group
 *   (empty when no group is active).
 * @param isAnomalous - Predicate deciding whether a UCI is in an anomaly
 *   state, used to enrich each returned row.
 * @returns When no group is active, the enriched selectable list unchanged;
 *   otherwise the affected connections followed by absent series
 *   materialised as `silent` rows, each enriched with anomaly state.
 *
 * @example
 * ```ts
 * const rows = alarmFilteredConnections(liveRows, group.series_ids, isAnomalous)
 * ```
 */
export function alarmFilteredConnections(
  selectable: Connection[],
  seriesIds: string[],
  isAnomalous: (uci: string) => boolean,
): Connection[] {
  const enrich = (c: Connection): Connection => (isAnomalous(c.uci) ? { ...c, state: 'anomaly' } : c)

  if (seriesIds.length === 0) return selectable.map(enrich)

  const affectedUcis = new Set(seriesIds)
  const base = selectable.filter((c) => matchesPortCollapseAlarmFilter(c.uci, affectedUcis))

  const absent: Connection[] = []
  for (const sid of seriesIds) {
    if (!sid.includes('/')) continue
    if (base.some((c) => matchesPortCollapseSibling(c.uci, sid))) continue
    if (absent.some((c) => matchesPortCollapseSibling(c.uci, sid))) continue
    absent.push(parseUciToConnection({ uci: sid }, 'silent'))
  }

  return [...base, ...absent].map(enrich)
}
