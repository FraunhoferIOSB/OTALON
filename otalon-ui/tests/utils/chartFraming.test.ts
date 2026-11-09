import { describe, expect, it } from 'vitest'
import { capChartPoints, frameChartPoints, getChartEdgePaddingCount, type ChartFramePoint } from '~/utils/chartFraming'

interface Point extends ChartFramePoint {
  time: string
  value: number
}
const point = (time: string, violation = false): Point => ({
  time,
  value: Number(time),
  violation_low: violation,
  violation_high: false,
})
const options = { maxPoints: 4, padRatio: 0.15 }

describe('chart framing', () => {
  it('reserves proportional edge categories for capped and small charts', () => {
    expect(getChartEdgePaddingCount(4)).toBe(1)
    expect(getChartEdgePaddingCount(240)).toBeGreaterThan(1)
    expect(getChartEdgePaddingCount(240)).toBe(8)
    expect(getChartEdgePaddingCount(10_000)).toBe(24)
  })

  it.each([
    ['empty', [], false],
    ['no violations', [point('1'), point('2'), point('3')], false],
    ['single point', [point('1', true)], true],
    ['all violations', [point('1', true), point('2', true), point('3', true)], true],
    ['first edge', [point('1', true), point('2'), point('3')], true],
    ['last edge', [point('1'), point('2'), point('3', true)], true],
    ['both edges', [point('1', true), point('2'), point('3', true)], true],
  ])('%s has deterministic framing', (_name, source, focused) => {
    const result = frameChartPoints(source, options)
    expect(result.focused).toBe(focused)
    expect(result.points.every((item) => source.some((candidate) => candidate.time === item.time))).toBe(true)
  })

  it('caps rendered points without dropping violations', () => {
    const source = Array.from({ length: 10 }, (_, index) => point(String(index), index === 0 || index === 9))
    const result = capChartPoints(source, 4)
    expect(result.length).toBeGreaterThanOrEqual(4)
    expect(result.filter((item) => item.violation_low)).toHaveLength(2)
  })
})
