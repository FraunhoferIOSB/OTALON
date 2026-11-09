/**
 * Unit tests for the fillTimeIndices composable.
 *
 * Validates time-axis gap-filling with various intervals,
 * edge cases, and boundary preservation.
 */
import { describe, it, expect } from 'vitest'
import { fillTimeIndices } from '~/composables/useFillTimeIndices'

interface TestPoint {
  time: string
  value: number
  lower_bound: number
  upper_bound: number
}

function makePoint(offsetSeconds: number, value: number): TestPoint {
  const base = new Date('2026-03-07T00:00:00Z')
  const time = new Date(base.getTime() + offsetSeconds * 1000)
  return {
    time: time.toISOString(),
    value,
    lower_bound: value * 0.8,
    upper_bound: value * 1.2,
  }
}

describe('fillTimeIndices', () => {
  it('returns empty array for empty input', () => {
    const result = fillTimeIndices([], 10)
    expect(result).toEqual([])
  })

  it('returns single-element array unchanged', () => {
    const data = [makePoint(0, 100)]
    const result = fillTimeIndices(data, 10)
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual(data[0])
  })

  it('returns data unchanged when no gaps exist (10s interval)', () => {
    const data = [makePoint(0, 100), makePoint(10, 110), makePoint(20, 120), makePoint(30, 130)]
    const result = fillTimeIndices(data, 10)
    expect(result).toHaveLength(4)
    expect(result[0].value).toBe(100)
    expect(result[1].value).toBe(110)
    expect(result[2].value).toBe(120)
    expect(result[3].value).toBe(130)
  })

  it('fills single gap with null-valued skeleton (10s interval)', () => {
    const data = [makePoint(0, 100), makePoint(20, 120)]
    const result = fillTimeIndices(data, 10)
    expect(result).toHaveLength(3)
    expect(result[0].value).toBe(100)
    expect(result[1].value).toBeNull()
    expect(result[1].lower_bound).toBeNull()
    expect(result[1].upper_bound).toBeNull()
    expect(result[2].value).toBe(120)
  })

  it('fills multiple gaps correctly', () => {
    const data = [makePoint(0, 100), makePoint(40, 140)]
    const result = fillTimeIndices(data, 10)
    expect(result).toHaveLength(5)
    expect(result[0].value).toBe(100)
    expect(result[1].value).toBeNull()
    expect(result[2].value).toBeNull()
    expect(result[3].value).toBeNull()
    expect(result[4].value).toBe(140)
  })

  it('preserves first and last data points (boundary preservation)', () => {
    const data = [makePoint(0, 100), makePoint(30, 130)]
    const result = fillTimeIndices(data, 10)
    expect(result[0]).toEqual(data[0])
    expect(result[result.length - 1]).toEqual(data[1])
  })

  it('works with 60s bucket interval', () => {
    const data = [makePoint(0, 100), makePoint(180, 400)]
    const result = fillTimeIndices(data, 60)
    expect(result).toHaveLength(4)
    expect(result[0].value).toBe(100)
    expect(result[1].value).toBeNull()
    expect(result[2].value).toBeNull()
    expect(result[3].value).toBe(400)
  })

  it('works with 300s (5m) bucket interval', () => {
    const data = [makePoint(0, 100), makePoint(600, 200)]
    const result = fillTimeIndices(data, 300)
    expect(result).toHaveLength(3)
    expect(result[0].value).toBe(100)
    expect(result[1].value).toBeNull()
    expect(result[2].value).toBe(200)
  })

  it('returns empty for zero bucket seconds', () => {
    const data = [makePoint(0, 100), makePoint(10, 110)]
    const result = fillTimeIndices(data, 0)
    expect(result).toEqual([])
  })

  it('returns empty for negative bucket seconds', () => {
    const data = [makePoint(0, 100), makePoint(10, 110)]
    const result = fillTimeIndices(data, -10)
    expect(result).toEqual([])
  })

  it('skeleton entries have time field set correctly', () => {
    const data = [makePoint(0, 100), makePoint(20, 120)]
    const result = fillTimeIndices(data, 10)
    const gap = result[1]
    const expectedTime = new Date(new Date('2026-03-07T00:00:00Z').getTime() + 10000).toISOString()
    expect(gap.time).toBe(expectedTime)
  })

  it('does not mutate original data array', () => {
    const data = [makePoint(0, 100), makePoint(20, 120)]
    const original = [...data]
    fillTimeIndices(data, 10)
    expect(data).toEqual(original)
  })

  it('supports custom time field name', () => {
    const data = [
      { timestamp: '2026-03-07T00:00:00.000Z', value: 100 },
      { timestamp: '2026-03-07T00:00:20.000Z', value: 120 },
    ]
    const result = fillTimeIndices(data, 10, 'timestamp')
    expect(result).toHaveLength(3)
    expect(result[1].value).toBeNull()
  })
})
