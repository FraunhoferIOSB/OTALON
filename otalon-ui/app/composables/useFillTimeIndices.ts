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
 * spaced `bucketSeconds` apart. Existing data points are preserved at
 * their matching grid positions; missing positions receive a skeleton
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
  if (data.length === 0 || bucketSeconds <= 0) {
    return []
  }

  if (data.length === 1) {
    return [...data]
  }

  const firstTime = parseApiTimestamp(data[0][timeField] as string).getTime()
  const lastTime = parseApiTimestamp(data[data.length - 1][timeField] as string).getTime()
  const intervalMs = bucketSeconds * 1000

  const dataMap = new Map<number, T>()
  for (const item of data) {
    const ts = parseApiTimestamp(item[timeField] as string).getTime()
    dataMap.set(ts, item)
  }

  const result: T[] = []
  let currentTime = firstTime

  while (currentTime <= lastTime + intervalMs / 2) {
    const existing = dataMap.get(currentTime)
    if (existing) {
      result.push(existing)
    } else {
      const closestKey = findClosestKey(dataMap, currentTime, intervalMs / 2)
      if (closestKey !== null) {
        result.push(dataMap.get(closestKey)!)
        dataMap.delete(closestKey)
      } else {
        const skeleton = buildSkeleton<T>(data[0], timeField, new Date(currentTime).toISOString())
        result.push(skeleton)
      }
    }
    currentTime += intervalMs
  }

  return result
}

/**
 * Find the closest key in a map within a tolerance window.
 *
 * @param map - Map of timestamp keys to data items.
 * @param target - The target timestamp to find the closest match for.
 * @param tolerance - Maximum allowed deviation in milliseconds.
 * @returns The closest key within tolerance, or null if none found.
 */
function findClosestKey<T>(map: Map<number, T>, target: number, tolerance: number): number | null {
  let bestKey: number | null = null
  let bestDiff = Infinity

  for (const key of map.keys()) {
    const diff = Math.abs(key - target)
    if (diff < bestDiff && diff <= tolerance) {
      bestDiff = diff
      bestKey = key
    }
  }

  return bestKey
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
