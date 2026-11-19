/**
 * Composable providing time-axis gap-filling for API timeseries data.
 *
 * Uses the `bucket_seconds` value from the API response metadata to
 * create a regular time grid and inserts null-valued entries for any
 * missing timestamps. This ensures ECharts plots render gaps correctly
 * instead of drawing misleading straight lines through missing data.
 */
import { parseApiTimestamp } from '~/utils/format'

/**
 * Fill gaps in a timeseries array so that every expected bucket is present.
 *
 * Produces a regular time grid from the first to the last data point,
 * spaced `bucketSeconds` apart. All original points, including duplicates
 * and off-grid points, remain in order; missing positions receive a skeleton
 * entry with the `time` field set and all other fields set to `null`.
 *
 * @param data - The sparse timeseries data array. Each item must have a `time` field with an ISO 8601 string.
 * @param bucketSeconds - The expected interval between data points in seconds.
 * @param timeField - The name of the time field in each data item. Defaults to `'time'`.
 * @returns A new array with gaps filled. Original items are not mutated.
 */
export function fillTimeIndices<T extends Record<string, unknown>>(
  data: T[],
  bucketSeconds: number,
  timeField: string = 'time',
): T[] {
  const intervalMs = bucketSeconds * 1000
  if (data.length < 2 || !Number.isFinite(intervalMs) || intervalMs < 1) {
    return [...data]
  }

  // The length guard guarantees endpoints; map preserves the paired arrays'
  // length, and the index guards below keep every access in range.
  const times = data.map(item => parseApiTimestamp(item[timeField] as string).getTime())
  if (times.some((time, index) => !Number.isFinite(time) || (index > 0 && time < times[index - 1]!))) {
    return [...data]
  }
  const firstTime = times[0]!
  const lastTime = times[times.length - 1]!

  const result: T[] = []
  let index = 0
  for (let currentTime = firstTime + intervalMs; currentTime < lastTime; currentTime += intervalMs) {
    while (index < data.length && times[index]! <= currentTime) {
      result.push(data[index++]!)
    }
    // A nearby original point occupies the grid position without being sampled
    // away. Only empty tolerance windows receive a null, never trailing gaps.
    const previousDistance = index > 0 ? currentTime - times[index - 1]! : Infinity
    const nextDistance = index < data.length ? times[index]! - currentTime : Infinity
    if (Math.min(previousDistance, nextDistance) > intervalMs / 2) {
      result.push(buildSkeleton<T>(data[0]!, timeField, new Date(currentTime).toISOString()))
    }
  }
  while (index < data.length) {
    result.push(data[index++]!)
  }

  return result
}

/**
 * Build a skeleton entry with the time field set and all other fields nulled.
 *
 * @param template - A reference item from the data array to derive field names.
 * @param timeField - The name of the time field.
 * @param timeValue - The ISO 8601 time string for this skeleton entry.
 * @returns A new object with the same keys as template but null values (except time).
 */
function buildSkeleton<T extends Record<string, unknown>>(template: T, timeField: string, timeValue: string): T {
  const skeleton = {} as Record<string, unknown>
  for (const key of Object.keys(template)) {
    skeleton[key] = key === timeField ? timeValue : null
  }
  return skeleton as T
}
