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

  it('preserves input for zero bucket seconds', () => {
    const data = [makePoint(0, 100), makePoint(10, 110)]
    const result = fillTimeIndices(data, 0)
    expect(result).toEqual(data)
  })

  it('preserves input for negative bucket seconds', () => {
    const data = [makePoint(0, 100), makePoint(10, 110)]
    const result = fillTimeIndices(data, -10)
    expect(result).toEqual(data)
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

  it('preserves close fractional, off-grid and duplicate points in order', () => {
    const data = [makePoint(0.123, 1), makePoint(0.187, 2), makePoint(0.187, 3), makePoint(1.123, 4)]
    const original = structuredClone(data)
    const result = fillTimeIndices(data, 1)
    expect(result).toEqual(data)
    result.forEach((point, index) => expect(point).toBe(data[index]))
    expect(data).toEqual(original)
  })

  it('keeps the first-anchored grid and inserts only unoccupied gaps', () => {
    const data = [makePoint(0.123, 1), makePoint(0.187, 2), makePoint(3.187, 3)]
    const result = fillTimeIndices(data, 1)
    expect(result.map(point => point.value)).toEqual([1, 2, null, null, 3])
    expect(result[2].time).toBe(makePoint(1.123, 0).time)
    expect(result[3].time).toBe(makePoint(2.123, 0).time)
  })

  it('does not repeat an off-grid point at an adjacent grid position', () => {
    const data = [makePoint(0, 1), makePoint(0.5, 2), makePoint(1.5, 3), makePoint(2, 4)]
    const result = fillTimeIndices(data, 1)
    expect(result).toEqual(data)
  })

  it.each([NaN, Infinity, Number.MIN_VALUE])('preserves points for unusable interval %s', (interval) => {
    const data = [makePoint(0, 1), makePoint(1, 2)]
    expect(fillTimeIndices(data, interval)).toEqual(data)
  })

  it('preserves inputs without filling when a timestamp is invalid', () => {
    const data = [makePoint(0, 1), { ...makePoint(1, 2), time: 'invalid' }]
    expect(fillTimeIndices(data, 1)).toEqual(data)
  })

  it('preserves unsorted fractional inputs without filling or reordering', () => {
    const data = [makePoint(1.187, 1), makePoint(0.123, 2), makePoint(0.123, 3)]
    const original = structuredClone(data)
    const result = fillTimeIndices(data, 1)
    expect(result).not.toBe(data)
    expect(result).toEqual(original)
    result.forEach((point, index) => expect(point).toBe(data[index]))
    expect(data).toEqual(original)
  })

  it('preserves every point for a positive submillisecond interval', () => {
    const data = [makePoint(0.123, 1), makePoint(0.123, 2), makePoint(0.187, 3)]
    const original = structuredClone(data)
    const result = fillTimeIndices(data, 0.0005)
    expect(result).not.toBe(data)
    expect(result).toEqual(original)
    result.forEach((point, index) => expect(point).toBe(data[index]))
    expect(data).toEqual(original)
  })
})
