import type { AffectedFeaturesBySeriesEntry } from '~/stores/alarmsStore'
import type { AnomalyGroupItem } from '~/types/api'
import { matchesPortCollapseSibling } from '~/utils/uci'

export interface SelectedSeriesAlarmBadge {
  features: string[]
  state: 'NoBounds' | 'BoundViolation' | undefined
}

/**
 * Alarm groups whose `series_ids` cover any of `seriesIds`.
 *
 * The single source of truth for "is this series alarmed". Both the list's
 * red status indicator and the detail badge/highlights derive from this, so
 * the two sides cannot disagree (audit SUITE-047).
 *
 * They previously used different rules: the list tested direct
 * `uci ∈ group.series_ids` membership, while the badge additionally required
 * a `matchesPortCollapseSibling` match AND a loaded per-series feature
 * entry. A connection could therefore be red on the left with nothing on the
 * right. `matchesPortCollapseSibling` is a strict superset of direct
 * membership (it short-circuits on `left === right`), so routing both through
 * it widens the list to include port-collapse siblings without weakening any
 * existing match.
 *
 * @param groups - Alarm groups in the current window.
 * @param seriesIds - Series/UCIs to test (usually one selected series).
 * @returns The matching groups, in input order.
 */
export function getGroupsForSeries(groups: AnomalyGroupItem[], seriesIds: string[]): AnomalyGroupItem[] {
  const ids = seriesIds.filter(Boolean)
  if (ids.length === 0) return []
  return groups.filter((group) =>
    group.series_ids.some((seriesId) => ids.some((candidate) => matchesPortCollapseSibling(seriesId, candidate))),
  )
}

/** Collect alarm evidence for selected series, independent of alarm-filter selection. */
export function getSelectedSeriesAlarmBadge(
  groups: AnomalyGroupItem[],
  affectedFeaturesByGroup: Record<string, { bySeries: Record<string, AffectedFeaturesBySeriesEntry> }>,
  seriesIds: string[],
): SelectedSeriesAlarmBadge {
  const ids = new Set(seriesIds.filter(Boolean))
  const features = new Set<string>()
  let state: SelectedSeriesAlarmBadge['state']

  for (const group of groups) {
    const matchingId = group.series_ids.find((seriesId) =>
      [...ids].some((selectedId) => matchesPortCollapseSibling(seriesId, selectedId)),
    )
    if (!matchingId) continue
    const entry = affectedFeaturesByGroup[group.id]?.bySeries[matchingId]
    if (!entry) continue
    entry.features.forEach((feature) => features.add(feature))
    if (entry.state === 'NoBounds') state = 'NoBounds'
    else if (entry.state === 'BoundViolation' && state === undefined) state = 'BoundViolation'
  }

  return { features: [...features], state }
}
