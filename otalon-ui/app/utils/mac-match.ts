/**
 * MAC alarm correlation helpers (UI-037).
 *
 * For a pure `mac_traffic` alarm the affected MACs are the group's
 * `series_ids` (plaintext lower-cased MAC addresses).  For a
 * conn-primary alarm (e.g. `icmp_flood`) the participating MACs are NOT
 * in `series_ids` — those are connection UCIs — they are cross-attributed
 * by the otalon-clas `cross_source` step into the additive
 * `enrichment.mac` bucket, where each entry's `series_id` is the
 * plaintext MAC address (verified against the real producer
 * `cross_source._evidence_entry`).
 *
 * The Assets-Subpage filter and the Alarm-Detail Assets tab both need the
 * SAME resolution so a conn-primary alarm becomes selectable, the
 * affected MAC is flagged red, and the Assets tab lists the MAC(s).  These
 * helpers bring both sides — `series_ids` AND `enrichment.mac` — onto one
 * lower-cased key set.
 */

import type { AnomalyGroupItem } from '~/types/api'
import { isMacAddress } from '~/utils/format'

/**
 * Extract the plaintext MAC addresses affected by an alarm group.
 *
 * Resolution order, all merged into one de-duplicated list:
 *   1. `mac_traffic` group → every `series_id` is a MAC.
 *   2. any `series_id` that looks like a MAC (a conn UCI is never a bare
 *      MAC, so this only adds standalone MAC series, never UCIs).
 *   3. `enrichment.mac[].series_id` — the cross-attributed MACs for a
 *      conn-primary alarm.
 *
 * @param group - An anomaly group from the alarms store.
 * @returns De-duplicated list of MAC addresses in their original casing.
 */
export function extractAlarmMacs(group: AnomalyGroupItem): string[] {
  const seen = new Set<string>()
  const result: string[] = []

  const add = (raw: unknown): void => {
    if (typeof raw !== 'string') return
    const mac = raw.trim()
    if (!mac || !isMacAddress(mac)) return
    const key = mac.toLowerCase()
    if (seen.has(key)) return
    seen.add(key)
    result.push(mac)
  }

  for (const sid of group.series_ids) add(sid)

  for (const entry of parseEnrichmentMacEntries(group)) {
    add(entry)
  }

  return result
}

/**
 * Read the plaintext MAC `series_id` values from a group's
 * `enrichment.mac` bucket.
 *
 * @param group - An anomaly group from the alarms store.
 * @returns List of raw `series_id` strings (may be non-MAC; the caller
 *   validates).
 */
export function parseEnrichmentMacEntries(group: AnomalyGroupItem): string[] {
  const enrichment = group.enrichment
  if (!enrichment || typeof enrichment !== 'object') return []
  const bucket = (enrichment as Record<string, unknown>).mac
  if (!Array.isArray(bucket)) return []

  const ids: string[] = []
  for (const item of bucket) {
    if (!item || typeof item !== 'object') continue
    const sid = (item as Record<string, unknown>).series_id
    if (typeof sid === 'string') ids.push(sid)
  }
  return ids
}

/**
 * Build the union of all anomalous MACs across a set of groups, as a
 * lower-cased lookup set for the "is this MAC under alarm?" red-flag
 * check.
 *
 * @param groups - Anomaly groups from the alarms store.
 * @returns Set of lower-cased MAC addresses appearing in any group
 *   (via `series_ids` or `enrichment.mac`).
 */
export function buildAnomalousMacSet(groups: AnomalyGroupItem[]): Set<string> {
  const set = new Set<string>()
  for (const group of groups) {
    for (const mac of extractAlarmMacs(group)) {
      set.add(mac.toLowerCase())
    }
  }
  return set
}

/**
 * Whether a group affects at least one MAC (so it should appear in the
 * Assets-Subpage alarm filter dropdown).
 *
 * @param group - An anomaly group from the alarms store.
 * @returns `true` when the group has any resolvable affected MAC.
 */
export function groupAffectsMac(group: AnomalyGroupItem): boolean {
  return extractAlarmMacs(group).length > 0
}
