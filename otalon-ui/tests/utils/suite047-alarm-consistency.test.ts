/**
 * Regression tests for SUITE-047 — Connections list and detail pane disagreed.
 *
 * A connection could show a red status indicator in the list while selecting
 * it produced no violation badge and no 2D highlights in the feature plots.
 * The two sides derived "is this series alarmed" differently:
 *
 *   left  — direct `uci ∈ group.series_ids` membership
 *   right — `matchesPortCollapseSibling` AND a loaded
 *           `affectedFeaturesByGroup[group.id].bySeries[matchingId]` entry
 *
 * ...and nothing ever populated `affectedFeaturesByGroup` when a *series*
 * was selected: `fetchAffectedFeatures` only ran from `selectGroup`, i.e.
 * when an alarm *group* was picked on the alarms page.
 *
 * These tests pin the shared derivation (`getGroupsForSeries`) that both
 * sides now use, and the store action that loads the detail the badge needs.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useAlarmsStore } from '~/stores/alarmsStore'
import { getGroupsForSeries, getSelectedSeriesAlarmBadge } from '~/utils/alarm-badge'
import type { AnomalyGroupItem } from '~/types/api'

const UCI = 'aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02//IPv4/192.168.0.10/192.168.0.20/4840/50001/Ethernet:IPv4:TCP'
/** Same flow, different ephemeral source port — a port-collapse sibling. */
const SIBLING = 'aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02//IPv4/192.168.0.10/192.168.0.20/4840/50002/Ethernet:IPv4:TCP'
const UNRELATED = 'aa:bb:cc:dd:ee:09/aa:bb:cc:dd:ee:08//IPv4/10.0.0.1/10.0.0.2/80/443/Ethernet:IPv4:TCP'

function group(id: string, seriesIds: string[]): AnomalyGroupItem {
  return {
    id,
    module: 'conn',
    primary_type: 'BoundViolation',
    series_ids: seriesIds,
    start_timestamp: '2026-08-30T10:00:00Z',
    end_timestamp: '2026-08-30T11:00:00Z',
    confirmed: false,
    is_active: false,
  } as AnomalyGroupItem
}

describe('getGroupsForSeries — the shared source of truth', () => {
  it('matches direct membership, as the list always did', () => {
    const groups = [group('g1', [UCI])]

    expect(getGroupsForSeries(groups, [UCI]).map((g) => g.id)).toEqual(['g1'])
  })

  it('matches a port-collapse sibling, as the badge always did', () => {
    const groups = [group('g1', [SIBLING])]

    expect(getGroupsForSeries(groups, [UCI]).map((g) => g.id)).toEqual(['g1'])
  })

  it('does not match an unrelated series', () => {
    const groups = [group('g1', [UNRELATED])]

    expect(getGroupsForSeries(groups, [UCI])).toEqual([])
  })

  it('returns every covering group, not just the first', () => {
    const groups = [group('g1', [UCI]), group('g2', [SIBLING]), group('g3', [UNRELATED])]

    expect(getGroupsForSeries(groups, [UCI]).map((g) => g.id)).toEqual(['g1', 'g2'])
  })

  it('ignores empty and blank series ids', () => {
    expect(getGroupsForSeries([group('g1', [UCI])], [])).toEqual([])
    expect(getGroupsForSeries([group('g1', [UCI])], [''])).toEqual([])
  })

  it('is a superset of direct membership — no connection loses its red state', () => {
    // The property that makes routing the list through this matcher safe.
    const groups = [group('g1', [UCI])]
    const directMembership = groups.some((g) => g.series_ids.includes(UCI))

    expect(directMembership).toBe(true)
    expect(getGroupsForSeries(groups, [UCI]).length).toBeGreaterThan(0)
  })
})

describe('left/right agreement', () => {
  const groups = [group('g1', [UCI])]

  it('a series with a covering group also yields a badge once detail is loaded', () => {
    const affected = {
      g1: { bySeries: { [UCI]: { features: ['packet_count'], state: 'BoundViolation' as const } } },
    }

    expect(getGroupsForSeries(groups, [UCI]).length).toBeGreaterThan(0)
    const badge = getSelectedSeriesAlarmBadge(groups, affected, [UCI])
    expect(badge.state).toBe('BoundViolation')
    expect(badge.features).toEqual(['packet_count'])
  })

  it('reproduces the reported bug when detail is missing', () => {
    // Red on the left (a group covers the series) but nothing on the right,
    // because affectedFeaturesByGroup was never populated. This is what the
    // store action now prevents.
    expect(getGroupsForSeries(groups, [UCI]).length).toBeGreaterThan(0)

    const badge = getSelectedSeriesAlarmBadge(groups, {}, [UCI])
    expect(badge.state).toBeUndefined()
    expect(badge.features).toEqual([])
  })

  it('a series with no covering group yields no badge', () => {
    expect(getGroupsForSeries(groups, [UNRELATED])).toEqual([])

    const badge = getSelectedSeriesAlarmBadge(groups, {}, [UNRELATED])
    expect(badge.state).toBeUndefined()
  })
})

describe('alarmsStore.loadAffectedFeaturesForSeries', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.unstubAllGlobals()
  })

  it('fetches detail for the groups covering the series', async () => {
    const store = useAlarmsStore()
    store.groups = [group('g1', [UCI]), group('g2', [UNRELATED])]
    const spy = vi.fn().mockResolvedValue([])
    store.fetchAffectedFeatures = spy as never

    await store.loadAffectedFeaturesForSeries([UCI])

    expect(spy).toHaveBeenCalledTimes(1)
    expect((spy.mock.calls[0] as [AnomalyGroupItem])[0].id).toBe('g1')
  })

  it('includes port-collapse sibling groups', async () => {
    const store = useAlarmsStore()
    store.groups = [group('g1', [SIBLING])]
    const spy = vi.fn().mockResolvedValue([])
    store.fetchAffectedFeatures = spy as never

    await store.loadAffectedFeaturesForSeries([UCI])

    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('skips groups whose detail is already cached', async () => {
    const store = useAlarmsStore()
    store.groups = [group('g1', [UCI])]
    store.affectedFeaturesByGroup = {
      g1: { features: ['packet_count'], state: 'BoundViolation', bySeries: {} },
    } as never
    const spy = vi.fn().mockResolvedValue([])
    store.fetchAffectedFeatures = spy as never

    await store.loadAffectedFeaturesForSeries([UCI])

    expect(spy).not.toHaveBeenCalled()
  })

  it('is a no-op when no group covers the series', async () => {
    const store = useAlarmsStore()
    store.groups = [group('g1', [UNRELATED])]
    const spy = vi.fn().mockResolvedValue([])
    store.fetchAffectedFeatures = spy as never

    await store.loadAffectedFeaturesForSeries([UCI])

    expect(spy).not.toHaveBeenCalled()
  })

  it('does not reject when one group fetch fails', async () => {
    const store = useAlarmsStore()
    store.groups = [group('g1', [UCI]), group('g2', [SIBLING])]
    store.fetchAffectedFeatures = vi.fn().mockRejectedValue(new Error('upstream down')) as never

    await expect(store.loadAffectedFeaturesForSeries([UCI])).resolves.toBeUndefined()
  })
})
