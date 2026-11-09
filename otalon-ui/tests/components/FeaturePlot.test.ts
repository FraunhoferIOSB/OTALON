/**
 * Unit tests for FeaturePlot.vue helper functions.
 *
 * Tests extendBoundsToChartRange() for threshold line extension logic,
 * detectSparseData() for scatter-vs-line heuristics, showSymbol logic
 * for low data point counts (B-17 fix), and x-axis time range
 * calculation (B-17 follow-up).
 *
 * Because these functions are defined inside <script setup>, they cannot
 * be imported directly. The implementations are replicated here as pure
 * functions for isolated testing.
 */
import { describe, it, expect } from 'vitest'

function extendBoundsToChartRange(
  lowerBounds: (number | null)[][],
  upperBounds: (number | null)[][],
  bandData: (number | null)[][],
  xMin: number,
  xMax: number,
): void {
  const firstLower = lowerBounds.find((p) => p[1] != null)
  const firstUpper = upperBounds.find((p) => p[1] != null)
  const lastLower = [...lowerBounds].reverse().find((p) => p[1] != null)
  const lastUpper = [...upperBounds].reverse().find((p) => p[1] != null)

  if (firstLower && (firstLower[0] as number) > xMin) {
    const lb = firstLower[1] as number
    const ub = (firstUpper?.[1] as number) ?? lb
    lowerBounds.unshift([xMin, lb])
    upperBounds.unshift([xMin, ub])
    bandData.unshift([xMin, ub - lb])
  }

  if (lastLower && (lastLower[0] as number) < xMax) {
    const lb = lastLower[1] as number
    const ub = (lastUpper?.[1] as number) ?? lb
    lowerBounds.push([xMax, lb])
    upperBounds.push([xMax, ub])
    bandData.push([xMax, ub - lb])
  }
}

describe('extendBoundsToChartRange', () => {
  it('prepends synthetic point at xMin when bounds start after xMin', () => {
    const lowerBounds: (number | null)[][] = [[5000, 10]]
    const upperBounds: (number | null)[][] = [[5000, 30]]
    const bandData: (number | null)[][] = [[5000, 20]]

    extendBoundsToChartRange(lowerBounds, upperBounds, bandData, 1000, 10000)

    expect(lowerBounds[0]).toEqual([1000, 10])
    expect(upperBounds[0]).toEqual([1000, 30])
    expect(bandData[0]).toEqual([1000, 20])
  })

  it('appends synthetic point at xMax when bounds end before xMax', () => {
    const lowerBounds: (number | null)[][] = [[8000, 15]]
    const upperBounds: (number | null)[][] = [[8000, 25]]
    const bandData: (number | null)[][] = [[8000, 10]]

    extendBoundsToChartRange(lowerBounds, upperBounds, bandData, 1000, 10000)

    expect(lowerBounds[lowerBounds.length - 1]).toEqual([10000, 15])
    expect(upperBounds[upperBounds.length - 1]).toEqual([10000, 25])
    expect(bandData[bandData.length - 1]).toEqual([10000, 10])
  })

  it('prepends and appends when bounds are in the middle', () => {
    const lowerBounds: (number | null)[][] = [
      [3000, 10],
      [7000, 12],
    ]
    const upperBounds: (number | null)[][] = [
      [3000, 30],
      [7000, 32],
    ]
    const bandData: (number | null)[][] = [
      [3000, 20],
      [7000, 20],
    ]

    extendBoundsToChartRange(lowerBounds, upperBounds, bandData, 1000, 10000)

    expect(lowerBounds).toHaveLength(4)
    expect(upperBounds).toHaveLength(4)
    expect(bandData).toHaveLength(4)
    expect(lowerBounds[0]).toEqual([1000, 10])
    expect(lowerBounds[3]).toEqual([10000, 12])
  })

  it('does not modify arrays when bounds already cover the full range', () => {
    const lowerBounds: (number | null)[][] = [
      [1000, 10],
      [10000, 12],
    ]
    const upperBounds: (number | null)[][] = [
      [1000, 30],
      [10000, 32],
    ]
    const bandData: (number | null)[][] = [
      [1000, 20],
      [10000, 20],
    ]

    extendBoundsToChartRange(lowerBounds, upperBounds, bandData, 1000, 10000)

    expect(lowerBounds).toHaveLength(2)
    expect(upperBounds).toHaveLength(2)
    expect(bandData).toHaveLength(2)
  })

  it('handles empty bounds arrays without error', () => {
    const lowerBounds: (number | null)[][] = []
    const upperBounds: (number | null)[][] = []
    const bandData: (number | null)[][] = []

    extendBoundsToChartRange(lowerBounds, upperBounds, bandData, 1000, 10000)

    expect(lowerBounds).toHaveLength(0)
    expect(upperBounds).toHaveLength(0)
    expect(bandData).toHaveLength(0)
  })

  it('handles bounds with only null values', () => {
    const lowerBounds: (number | null)[][] = [[5000, null]]
    const upperBounds: (number | null)[][] = [[5000, null]]
    const bandData: (number | null)[][] = [[5000, null]]

    extendBoundsToChartRange(lowerBounds, upperBounds, bandData, 1000, 10000)

    expect(lowerBounds).toHaveLength(1)
    expect(upperBounds).toHaveLength(1)
    expect(bandData).toHaveLength(1)
  })

  it('band data is calculated as upper minus lower', () => {
    const lowerBounds: (number | null)[][] = [[5000, 10]]
    const upperBounds: (number | null)[][] = [[5000, 30]]
    const bandData: (number | null)[][] = [[5000, 20]]

    extendBoundsToChartRange(lowerBounds, upperBounds, bandData, 1000, 10000)

    expect(bandData[0]).toEqual([1000, 20])
    expect(bandData[bandData.length - 1]).toEqual([10000, 20])
  })

  it('uses lower bound value as fallback when upper bound is null', () => {
    const lowerBounds: (number | null)[][] = [[5000, 10]]
    const upperBounds: (number | null)[][] = [[5000, null]]
    const bandData: (number | null)[][] = [[5000, null]]

    extendBoundsToChartRange(lowerBounds, upperBounds, bandData, 1000, 10000)

    expect(lowerBounds[0]).toEqual([1000, 10])
    expect(upperBounds[0]).toEqual([1000, 10])
    expect(bandData[0]).toEqual([1000, 0])
  })
})

/**
 * Replicated showSymbol logic from FeaturePlot.vue for isolated testing.
 *
 * The B-17 fix changed `showSymbol` from `isSparse` to
 * `isSparse || dataLength <= 5` so that charts with very few data
 * points still display visible symbols.
 */
function computeShowSymbol(isSparse: boolean, dataLength: number): boolean {
  return isSparse || dataLength <= 5
}

describe('showSymbol low data point fix (B-17)', () => {
  it('shows symbols when data has exactly 1 point', () => {
    expect(computeShowSymbol(false, 1)).toBe(true)
  })

  it('shows symbols when data has exactly 5 points', () => {
    expect(computeShowSymbol(false, 5)).toBe(true)
  })

  it('hides symbols when data has 6 points (non-sparse)', () => {
    expect(computeShowSymbol(false, 6)).toBe(false)
  })

  it('hides symbols when data has 20 points (non-sparse)', () => {
    expect(computeShowSymbol(false, 20)).toBe(false)
  })

  it('shows symbols when data is sparse regardless of length', () => {
    expect(computeShowSymbol(true, 100)).toBe(true)
  })

  it('shows symbols when data is sparse and has few points', () => {
    expect(computeShowSymbol(true, 3)).toBe(true)
  })

  it('shows symbols for empty data array', () => {
    expect(computeShowSymbol(false, 0)).toBe(true)
  })
})

/**
 * Replicated detectSparseData() from FeaturePlot.vue for isolated testing.
 */
function detectSparseData(times: string[], values: number[]): boolean {
  if (times.length < 3) return false

  const timestamps = times.map((t) => new Date(t).getTime())
  const intervals: number[] = []
  for (let i = 1; i < timestamps.length; i++) {
    intervals.push(timestamps[i] - timestamps[i - 1])
  }
  intervals.sort((a, b) => a - b)
  const median = intervals[Math.floor(intervals.length / 2)]
  if (median > 0) {
    const largeGaps = intervals.filter((iv) => iv > median * 3).length
    if (largeGaps / intervals.length > 0.4) return true
  }

  const nonNull = values.filter((v) => v !== null && v !== undefined)
  if (nonNull.length < 3) return false
  const freq = new Map<number, number>()
  for (const v of nonNull) {
    freq.set(v, (freq.get(v) ?? 0) + 1)
  }
  let maxCount = 0
  let dominantValue = 0
  for (const [val, count] of freq) {
    if (count > maxCount) {
      maxCount = count
      dominantValue = val
    }
  }
  if (dominantValue <= 2 && maxCount / nonNull.length > 0.8) return true

  return false
}

describe('detectSparseData', () => {
  it('returns false for data with fewer than 3 points', () => {
    expect(detectSparseData(['2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z'], [10, 20])).toBe(false)
  })

  it('returns true for data with large temporal gaps', () => {
    const times = [
      '2026-01-01T00:00:00Z',
      '2026-01-01T00:01:00Z',
      '2026-01-01T00:02:00Z',
      '2026-01-01T00:03:00Z',
      '2026-01-01T00:04:00Z',
      '2026-01-01T06:00:00Z',
      '2026-01-01T12:00:00Z',
      '2026-01-01T18:00:00Z',
    ]
    const values = [100, 200, 300, 400, 500, 600, 700, 800]
    expect(detectSparseData(times, values)).toBe(true)
  })

  it('returns true for constant low-value data', () => {
    const times = Array.from({ length: 10 }, (_, i) => `2026-01-01T00:0${i}:00Z`)
    const values = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    expect(detectSparseData(times, values)).toBe(true)
  })

  it('returns false for evenly-spaced non-constant data', () => {
    const times = Array.from({ length: 10 }, (_, i) => {
      const d = new Date('2026-01-01T00:00:00Z')
      d.setMinutes(i)
      return d.toISOString()
    })
    const values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    expect(detectSparseData(times, values)).toBe(false)
  })
})

/**
 * Replicated x-axis range calculation from FeaturePlot.vue (initChart)
 * for isolated testing (B-17 follow-up).
 *
 * When a timeRange prop is provided, the chart uses the query time window
 * directly. Otherwise it falls back to the data extent with symmetric
 * padding (minimum 30 s).
 */
function toEpoch(iso: string): number {
  return new Date(iso).getTime()
}

interface XAxisRange {
  xMin: number | undefined
  xMax: number | undefined
}

function computeXAxisRange(dataEpochs: number[], timeRange?: { start: string; stop: string }): XAxisRange {
  const dataMin = dataEpochs.length > 0 ? Math.min(...dataEpochs) : undefined
  const dataMax = dataEpochs.length > 0 ? Math.max(...dataEpochs) : undefined

  let xMin: number | undefined
  let xMax: number | undefined
  if (timeRange) {
    xMin = toEpoch(timeRange.start)
    xMax = toEpoch(timeRange.stop)
  } else if (dataMin !== undefined && dataMax !== undefined) {
    const pad = Math.max((dataMax - dataMin) * 0.02, 30000)
    xMin = dataMin - pad
    xMax = dataMax + pad
  }
  return { xMin, xMax }
}

describe('x-axis time range calculation (B-17 follow-up)', () => {
  it('uses timeRange directly when provided, ignoring data point positions', () => {
    const timeRange = {
      start: '2026-04-01T20:43:00Z',
      stop: '2026-04-01T21:13:00Z',
    }
    const dataEpochs = [toEpoch('2026-04-01T20:46:00Z')]

    const { xMin, xMax } = computeXAxisRange(dataEpochs, timeRange)

    expect(xMin).toBe(toEpoch('2026-04-01T20:43:00Z'))
    expect(xMax).toBe(toEpoch('2026-04-01T21:13:00Z'))
    expect(xMin).not.toBe(dataEpochs[0])
  })

  it('uses timeRange even when data spans a wider range', () => {
    const timeRange = {
      start: '2026-04-01T20:50:00Z',
      stop: '2026-04-01T21:00:00Z',
    }
    const dataEpochs = [toEpoch('2026-04-01T20:40:00Z'), toEpoch('2026-04-01T21:10:00Z')]

    const { xMin, xMax } = computeXAxisRange(dataEpochs, timeRange)

    expect(xMin).toBe(toEpoch('2026-04-01T20:50:00Z'))
    expect(xMax).toBe(toEpoch('2026-04-01T21:00:00Z'))
  })

  it('uses timeRange with empty data array', () => {
    const timeRange = {
      start: '2026-04-01T20:43:00Z',
      stop: '2026-04-01T21:13:00Z',
    }

    const { xMin, xMax } = computeXAxisRange([], timeRange)

    expect(xMin).toBe(toEpoch('2026-04-01T20:43:00Z'))
    expect(xMax).toBe(toEpoch('2026-04-01T21:13:00Z'))
  })

  it('falls back to data range with padding when timeRange is undefined', () => {
    const dataEpochs = [toEpoch('2026-04-01T20:00:00Z'), toEpoch('2026-04-01T21:00:00Z')]
    const span = dataEpochs[1] - dataEpochs[0]
    const expectedPad = span * 0.02

    const { xMin, xMax } = computeXAxisRange(dataEpochs, undefined)

    expect(xMin).toBe(dataEpochs[0] - expectedPad)
    expect(xMax).toBe(dataEpochs[1] + expectedPad)
  })

  it('applies minimum 30s padding for single data point without timeRange', () => {
    const singleEpoch = toEpoch('2026-04-01T20:46:00Z')
    const dataEpochs = [singleEpoch]

    const { xMin, xMax } = computeXAxisRange(dataEpochs, undefined)

    expect(xMin).toBe(singleEpoch - 30000)
    expect(xMax).toBe(singleEpoch + 30000)
  })

  it('applies minimum 30s padding for very narrow data span without timeRange', () => {
    const t1 = toEpoch('2026-04-01T20:46:00.000Z')
    const t2 = toEpoch('2026-04-01T20:46:00.500Z')
    const dataEpochs = [t1, t2]

    const { xMin, xMax } = computeXAxisRange(dataEpochs, undefined)

    expect(xMin).toBe(t1 - 30000)
    expect(xMax).toBe(t2 + 30000)
  })

  it('returns undefined for both axes when no data and no timeRange', () => {
    const { xMin, xMax } = computeXAxisRange([], undefined)

    expect(xMin).toBeUndefined()
    expect(xMax).toBeUndefined()
  })

  it('updates x-axis when timeRange prop changes (live mode poll)', () => {
    const dataEpochs = [toEpoch('2026-04-01T20:46:00Z')]

    const range1 = {
      start: '2026-04-01T20:43:00Z',
      stop: '2026-04-01T21:13:00Z',
    }
    const result1 = computeXAxisRange(dataEpochs, range1)
    expect(result1.xMin).toBe(toEpoch('2026-04-01T20:43:00Z'))
    expect(result1.xMax).toBe(toEpoch('2026-04-01T21:13:00Z'))

    const range2 = {
      start: '2026-04-01T20:44:00Z',
      stop: '2026-04-01T21:14:00Z',
    }
    const result2 = computeXAxisRange(dataEpochs, range2)
    expect(result2.xMin).toBe(toEpoch('2026-04-01T20:44:00Z'))
    expect(result2.xMax).toBe(toEpoch('2026-04-01T21:14:00Z'))

    expect(result2.xMin).not.toBe(result1.xMin)
    expect(result2.xMax).not.toBe(result1.xMax)
  })

  it('uses 2% padding for multi-point data without timeRange', () => {
    const t1 = toEpoch('2026-04-01T20:00:00Z')
    const t2 = toEpoch('2026-04-01T20:30:00Z')
    const t3 = toEpoch('2026-04-01T21:00:00Z')
    const dataEpochs = [t1, t2, t3]
    const span = t3 - t1
    const expectedPad = span * 0.02

    const { xMin, xMax } = computeXAxisRange(dataEpochs, undefined)

    expect(xMin).toBe(t1 - expectedPad)
    expect(xMax).toBe(t3 + expectedPad)
    expect(expectedPad).toBeGreaterThan(30000)
  })
})
