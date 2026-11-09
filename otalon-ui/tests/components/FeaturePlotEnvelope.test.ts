/**
 * Unit tests for FeaturePlot.vue envelope visibility logic.
 *
 * Replicates the pure decision rules from the component so they can be
 * tested without mounting ECharts in happy-dom.
 */
import { describe, it, expect } from 'vitest'

import {
  TOOLTIP_HIDDEN_SERIES,
  TOOLTIP_VISIBLE_SERIES,
  tooltipSeriesLabel,
  tooltipSeriesRank,
  violationMarkerValue,
} from '~/components/connection/featurePlotTooltip'

interface Point {
  value_min: number | null
  value_max: number | null
}

const SPREAD_EPSILON = 1e-9

function dataHasSpread(data: Point[]): boolean {
  return data.some(
    (p) =>
      p.value_min != null &&
      p.value_max != null &&
      Math.abs((p.value_max as number) - (p.value_min as number)) > SPREAD_EPSILON,
  )
}

function envelopeVisible(mode: 'auto' | 'on' | 'off', data: Point[]): boolean {
  if (mode === 'off') return false
  return dataHasSpread(data)
}

function showNoSpreadHint(mode: 'auto' | 'on' | 'off', data: Point[]): boolean {
  return mode === 'on' && !dataHasSpread(data) && data.length > 0
}

function makePoints(spread: boolean): Point[] {
  return Array.from({ length: 3 }, (_, i) => ({
    value_min: spread ? 9 + i : 10 + i,
    value_max: spread ? 11 + i : 10 + i,
  }))
}

describe('FeaturePlot envelope visibility', () => {
  it('returns false when mode is off regardless of spread', () => {
    expect(envelopeVisible('off', makePoints(true))).toBe(false)
    expect(envelopeVisible('off', makePoints(false))).toBe(false)
  })

  it('returns true in on mode when data has spread', () => {
    expect(envelopeVisible('on', makePoints(true))).toBe(true)
  })

  it('returns false in on mode when data has zero spread', () => {
    expect(envelopeVisible('on', makePoints(false))).toBe(false)
  })

  it('returns true in auto mode when data has spread', () => {
    expect(envelopeVisible('auto', makePoints(true))).toBe(true)
  })

  it('returns false in auto mode when data has zero spread', () => {
    expect(envelopeVisible('auto', makePoints(false))).toBe(false)
  })

  it('treats epsilon-level differences as zero spread', () => {
    const epsilonData: Point[] = [{ value_min: 10, value_max: 10 + SPREAD_EPSILON / 2 }]
    expect(envelopeVisible('auto', epsilonData)).toBe(false)
    expect(envelopeVisible('on', epsilonData)).toBe(false)
  })

  it('treats null min/max as zero spread', () => {
    const nullData: Point[] = [{ value_min: null, value_max: null }]
    expect(envelopeVisible('auto', nullData)).toBe(false)
    expect(envelopeVisible('on', nullData)).toBe(false)
  })

  it('shows hint in on mode with zero spread and non-empty data', () => {
    expect(showNoSpreadHint('on', makePoints(false))).toBe(true)
  })

  it('hides hint in on mode when data has spread', () => {
    expect(showNoSpreadHint('on', makePoints(true))).toBe(false)
  })

  it('hides hint in auto mode regardless of spread', () => {
    expect(showNoSpreadHint('auto', makePoints(false))).toBe(false)
    expect(showNoSpreadHint('auto', makePoints(true))).toBe(false)
  })

  it('hides hint when data is empty', () => {
    expect(showNoSpreadHint('on', [])).toBe(false)
  })
})

describe('FeaturePlot tooltip HIDDEN_SERIES', () => {
  // Regression guard for bcca1c47, which widened the hidden-series list and
  // silently removed Upper/Lower Bound from the tooltip. The previous version
  // of these tests re-declared the list inline, so it asserted against a copy
  // and stayed green while the component drifted. Always assert against the
  // exported constant.
  it('hides only the stacking helper series', () => {
    expect([...TOOLTIP_HIDDEN_SERIES].sort()).toEqual(
      ['Band', 'Envelope Band', 'Envelope Low', 'Lower Bound'].sort(),
    )
  })

  it('does not hide Envelope Min or Envelope Max from tooltip', () => {
    expect(TOOLTIP_HIDDEN_SERIES).not.toContain('Envelope Min')
    expect(TOOLTIP_HIDDEN_SERIES).not.toContain('Envelope Max')
  })

  it('does not hide the upper and lower bound outlines from tooltip', () => {
    expect(TOOLTIP_HIDDEN_SERIES).not.toContain('Upper Bound')
    expect(TOOLTIP_HIDDEN_SERIES).not.toContain('Lower')
  })

  it('keeps hidden and operator-visible series disjoint', () => {
    for (const name of TOOLTIP_VISIBLE_SERIES) {
      expect(TOOLTIP_HIDDEN_SERIES).not.toContain(name)
    }
  })

  it('relabels the internal "Lower" series as "Lower Bound"', () => {
    expect(tooltipSeriesLabel('Lower')).toBe('Lower Bound')
    expect(tooltipSeriesLabel('Upper Bound')).toBe('Upper Bound')
    expect(tooltipSeriesLabel('Value')).toBe('Value')
  })

  it('orders tooltip rows upper before value before lower', () => {
    const ordered = ['Envelope Max', 'Upper Bound', 'Value', 'Lower', 'Envelope Min']
    const ranks = ordered.map(tooltipSeriesRank)
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b))
    expect(tooltipSeriesRank('Upper Bound')).toBeLessThan(tooltipSeriesRank('Value'))
    expect(tooltipSeriesRank('Value')).toBeLessThan(tooltipSeriesRank('Lower'))
  })
})

describe('violationMarkerValue', () => {
  // Regression guard for the downsampling false-positive report: at
  // sample_max_points=300 a one-second spike lands in a 15s bucket, the mean
  // stays inside the band, and the marker used to be drawn at that mean —
  // floating inside the bounds with no visible cause.
  it('anchors a high violation to the bucket max, not the mean', () => {
    expect(
      violationMarkerValue({
        value: 1.2,
        value_min: 1,
        value_max: 9,
        violation_high: true,
        upper_bound: 2,
      }),
    ).toBe(9)
  })

  it('anchors a low violation to the bucket min, not the mean', () => {
    expect(
      violationMarkerValue({
        value: 1.8,
        value_min: 0.1,
        value_max: 2,
        violation_low: true,
        lower_bound: 0.8,
      }),
    ).toBe(0.1)
  })

  it('returns null for a sample without any violation', () => {
    expect(violationMarkerValue({ value: 1, value_min: 1, value_max: 1 })).toBeNull()
  })

  it('falls back to the mean when extrema are absent', () => {
    expect(violationMarkerValue({ value: 5, violation_high: true })).toBe(5)
  })

  it('keeps the marker on the plotted mean when the bucket holds a single sample', () => {
    // Unaggregated buckets have min == mean == max; the marker must not move.
    expect(
      violationMarkerValue({ value: 7, value_min: 7, value_max: 7, violation_high: true }),
    ).toBe(7)
  })

  it('places the marker outside the band it violated', () => {
    const upper = 2
    const marker = violationMarkerValue({
      value: 1.1,
      value_min: 0.9,
      value_max: 4.5,
      violation_high: true,
      upper_bound: upper,
    })
    expect(marker).not.toBeNull()
    expect(marker as number).toBeGreaterThan(upper)
  })
})
