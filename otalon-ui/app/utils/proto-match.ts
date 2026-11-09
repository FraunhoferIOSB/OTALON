/**
 * Protocol alarm correlation helpers.
 *
 * Since API-011 the backend delivers BOTH the hash series_id and the
 * readable protocol name on proto_traffic alarm groups.  The protocol
 * selector table may use either representation as `id` depending on
 * the endpoint version.  These helpers build lookup sets that contain
 * BOTH keys so the UI matches correctly regardless of which side is
 * hash or plaintext.
 */

import type { AnomalyGroupItem } from '~/types/api'
import type { ProtoSourceItem } from '~/stores/protoSourcesStore'

/**
 * Build lookup structures for protocol-to-alarm matching.
 *
 * @param groups - Anomaly groups from the alarms store.
 * @returns Object containing:
 *   - `anomalousIds`: Set of all hashes **and** readable protocols that
 *     appear in any group.
 *   - `groupProtocolMap`: Map from group id → Set of hashes+readable
 *     protocols for that group.
 */
export function buildProtoAlarmSets(groups: AnomalyGroupItem[]): {
  anomalousIds: Set<string>
  groupProtocolMap: Map<string, Set<string>>
} {
  const anomalousIds = new Set<string>()
  const groupProtocolMap = new Map<string, Set<string>>()

  for (const group of groups) {
    const ids = new Set<string>()
    for (const sid of group.series_ids) {
      anomalousIds.add(sid)
      ids.add(sid)
    }
    for (const proto of group.protocols ?? []) {
      if (proto === null) continue
      anomalousIds.add(proto)
      ids.add(proto)
    }
    groupProtocolMap.set(group.id, ids)
  }

  return { anomalousIds, groupProtocolMap }
}

/**
 * Return whether a given protocol source item is present in the
 * anomalous set.
 *
 * Matches against **both** `proto.id` and `proto.protocol` so the
 * check survives API changes that swap which field carries the hash.
 *
 * @param proto - A protocol source item from the store.
 * @param anomalousIds - Set built by {@link buildProtoAlarmSets}.
 * @returns `true` when either the id or the readable protocol is
 *   found in the anomalous set.
 */
export function isProtoAnomalous(proto: ProtoSourceItem, anomalousIds: Set<string>): boolean {
  return anomalousIds.has(proto.id) || anomalousIds.has(proto.protocol ?? '')
}
