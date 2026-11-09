import { parseApiTimestamp } from './format'

export const MIN_MARK_AREA_WIDTH_MS = 30_000

/**
 * Convert an ISO timestamp string to a Unix epoch millisecond value.
 *
 * Naive timestamps without timezone suffix are treated as UTC, matching
 * the backend serialization convention.
 */
export function toEpoch(iso: string): number {
  return parseApiTimestamp(iso).getTime()
}

/**
 * Build ECharts markArea data from anomaly intervals using epoch timestamps.
 *
 * Intervals narrower than `MIN_MARK_AREA_WIDTH_MS` (30 s) are widened
 * symmetrically so they remain visible on the chart.  This handles
 * point-in-time anomalies where `start === end`.
 */
export function buildMarkAreaData(intervals: Array<{ start: string; end: string }>): Array<Array<{ xAxis: number }>> {
  return intervals.map((interval) => {
    let startMs = toEpoch(interval.start)
    let endMs = toEpoch(interval.end)
    const width = endMs - startMs
    if (width < MIN_MARK_AREA_WIDTH_MS) {
      const pad = Math.ceil((MIN_MARK_AREA_WIDTH_MS - width) / 2)
      startMs -= pad
      endMs += pad
    }
    return [{ xAxis: startMs }, { xAxis: endMs }]
  })
}
