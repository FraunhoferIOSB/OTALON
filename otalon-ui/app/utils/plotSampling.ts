export const DEFAULT_SAMPLE_MAX_POINTS = 300
export const SAMPLE_MAX_POINT_OPTIONS = [150, 300, 600, 1200, 2400]

export interface PlotSamplingSummary {
  pointCount: number
  bucketSeconds: number | null
}

export function getPlotSamplingSummary(points: Array<{ time: string }>): PlotSamplingSummary {
  if (points.length < 2) return { pointCount: points.length, bucketSeconds: null }

  const timestamps = points
    .map((point) => Date.parse(point.time))
    .filter((timestamp) => Number.isFinite(timestamp))
    .sort((left, right) => left - right)
  if (timestamps.length < 2) return { pointCount: points.length, bucketSeconds: null }

  const deltas = timestamps.slice(1).map((timestamp, index) => timestamp - timestamps[index])
  const positiveDeltas = deltas.filter((delta) => delta > 0)
  if (positiveDeltas.length === 0) return { pointCount: points.length, bucketSeconds: null }

  const bucketSeconds = Math.round(Math.min(...positiveDeltas) / 1000)
  return { pointCount: points.length, bucketSeconds: bucketSeconds > 0 ? bucketSeconds : null }
}
