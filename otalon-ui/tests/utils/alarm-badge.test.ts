import { describe, expect, it } from 'vitest'

import { getSelectedSeriesAlarmBadge } from '~/utils/alarm-badge'
import type { AnomalyGroupItem } from '~/types/api'

const groups = [{ id: 'alarm-1', series_ids: ['series-1'] }] as AnomalyGroupItem[]
const evidence = {
  'alarm-1': {
    bySeries: { 'series-1': { features: ['packet_count'], state: 'BoundViolation', rhythmAnomaly: false } },
  },
}
const asymmetricAlarmSeriesId =
  '38:4b:24:fa:b6:34/cc:82:7f:a1:8a:37//IPv4/192.168.0.233/192.168.0.201/161/47584/Ethernet:IPv4:UDP'
const asymmetricWildcardSeriesId =
  'cc:82:7f:a1:8a:36/38:4b:24:fa:b6:34//IPv4/192.168.0.201/192.168.0.233/*/161/Ethernet:IPv4:UDP'

describe('getSelectedSeriesAlarmBadge', () => {
  it.each(['filter-on', 'filter-off'])('returns evidence with %s', () => {
    expect(getSelectedSeriesAlarmBadge(groups, evidence, ['series-1'])).toEqual({
      features: ['packet_count'],
      state: 'BoundViolation',
    })
  })

  it('returns no evidence for a series without an alarm', () => {
    expect(getSelectedSeriesAlarmBadge(groups, {}, ['series-3'])).toEqual({ features: [], state: undefined })
  })

  it('returns evidence for an asymmetric wildcard sibling', () => {
    expect(
      getSelectedSeriesAlarmBadge(
        [{ id: 'alarm-asymmetric', series_ids: [asymmetricAlarmSeriesId] }] as AnomalyGroupItem[],
        {
          'alarm-asymmetric': {
            bySeries: {
              [asymmetricAlarmSeriesId]: {
                features: ['packet_count'],
                state: 'BoundViolation',
                rhythmAnomaly: false,
              },
            },
          },
        },
        [asymmetricWildcardSeriesId],
      ),
    ).toEqual({ features: ['packet_count'], state: 'BoundViolation' })
  })
})
