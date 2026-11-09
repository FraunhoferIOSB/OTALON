/**
 * Unit tests for shared chart utilities.
 *
 * Covers buildMarkAreaData for anomaly interval → ECharts markArea
 * conversion, including narrow interval widening and empty inputs.
 */
import { describe, it, expect } from 'vitest'
import { buildMarkAreaData, toEpoch } from '~/utils/chart'
import type { AnomalyInterval } from '~/types/golden-data'

describe('buildMarkAreaData', () => {
  it('converts a normal interval to markArea coordinates', () => {
    const intervals: AnomalyInterval[] = [{ start: '2026-03-07T02:00:00Z', end: '2026-03-07T05:00:00Z' }]
    const result = buildMarkAreaData(intervals)
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual([{ xAxis: toEpoch('2026-03-07T02:00:00Z') }, { xAxis: toEpoch('2026-03-07T05:00:00Z') }])
  })

  it('widens a point-in-time interval to a minimum visible band', () => {
    const intervals: AnomalyInterval[] = [{ start: '2026-03-07T02:00:00Z', end: '2026-03-07T02:00:00Z' }]
    const result = buildMarkAreaData(intervals)
    expect(result).toHaveLength(1)
    const startMs = toEpoch('2026-03-07T02:00:00Z')
    const expectedPad = 15_000 // ceil(30_000 / 2)
    expect(result[0]).toEqual([{ xAxis: startMs - expectedPad }, { xAxis: startMs + expectedPad }])
  })

  it('widens a narrow interval symmetrically', () => {
    const start = '2026-03-07T02:00:00Z'
    const end = '2026-03-07T02:00:10Z'
    const intervals: AnomalyInterval[] = [{ start, end }]
    const result = buildMarkAreaData(intervals)
    const width = toEpoch(end) - toEpoch(start) // 10_000 ms
    const pad = Math.ceil((30_000 - width) / 2) // 10_000 ms
    expect(result[0]).toEqual([{ xAxis: toEpoch(start) - pad }, { xAxis: toEpoch(end) + pad }])
  })

  it('produces an empty array for empty intervals', () => {
    expect(buildMarkAreaData([])).toEqual([])
  })

  it('handles multiple intervals in order', () => {
    const intervals: AnomalyInterval[] = [
      { start: '2026-03-07T02:00:00Z', end: '2026-03-07T03:00:00Z' },
      { start: '2026-03-07T14:00:00Z', end: '2026-03-07T16:30:00Z' },
    ]
    const result = buildMarkAreaData(intervals)
    expect(result).toHaveLength(2)
    expect(result[0]).toEqual([{ xAxis: toEpoch('2026-03-07T02:00:00Z') }, { xAxis: toEpoch('2026-03-07T03:00:00Z') }])
    expect(result[1]).toEqual([{ xAxis: toEpoch('2026-03-07T14:00:00Z') }, { xAxis: toEpoch('2026-03-07T16:30:00Z') }])
  })
})
