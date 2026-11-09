export interface ChartFramePoint {
  time: string
  violation_low: boolean
  violation_high: boolean
}

export interface FramedChart<T extends ChartFramePoint> {
  points: T[]
  focused: boolean
  edgePadding: boolean
}

export interface ChartFrameOptions {
  maxPoints: number
  padRatio: number
}

export interface ChartEdgePaddingOptions {
  ratio?: number
  minCategories?: number
  maxCategories?: number
}

/** Returns bounded empty category count reserving proportional chart edge space. */
export function getChartEdgePaddingCount(pointCount: number, options: ChartEdgePaddingOptions = {}): number {
  const ratio = options.ratio ?? 0.03
  const minCategories = options.minCategories ?? 1
  const maxCategories = options.maxCategories ?? 24
  const framedCategoryCount = Math.max(1, Math.floor(pointCount))
  return Math.min(maxCategories, Math.max(minCategories, Math.ceil(framedCategoryCount * ratio)))
}

export function capChartPoints<T extends ChartFramePoint>(points: T[], maxPoints: number): T[] {
  if (points.length <= maxPoints) return [...points]
  const stride = Math.ceil(points.length / maxPoints)
  const sampled = points.filter((_point, index) => index % stride === 0)
  for (const point of points) {
    if ((point.violation_low || point.violation_high) && !sampled.includes(point)) sampled.push(point)
  }
  return sampled.sort((a, b) => a.time.localeCompare(b.time))
}

export function frameChartPoints<T extends ChartFramePoint>(source: T[], options: ChartFrameOptions): FramedChart<T> {
  const points = [...source].sort((a, b) => a.time.localeCompare(b.time))
  const capped = capChartPoints(points, options.maxPoints)
  if (points.length <= 2) {
    const edgePadding = points.some((point) => point.violation_low || point.violation_high)
    return { points: capped, focused: edgePadding, edgePadding }
  }
  const violations = points.reduce<number[]>((indices, point, index) => {
    if (point.violation_low || point.violation_high) indices.push(index)
    return indices
  }, [])
  if (!violations.length) return { points: capped, focused: false, edgePadding: false }
  const first = violations[0]!
  const last = violations[violations.length - 1]!
  const pad = Math.max(1, Math.ceil(Math.max(last - first, 1) * options.padRatio))
  const start = Math.max(0, first - pad)
  const end = Math.min(points.length - 1, last + pad)
  const edgePadding = first === 0 || last === points.length - 1
  return {
    points: capChartPoints(points.slice(start, end + 1), options.maxPoints),
    focused: start > 0 || end < points.length - 1 || edgePadding,
    edgePadding,
  }
}
