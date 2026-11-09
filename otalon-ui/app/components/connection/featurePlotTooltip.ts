/**
 * Series-name bookkeeping for feature-plot tooltips.
 *
 * The bound and envelope overlays are drawn with stacked helper series: the
 * visible band is produced by stacking a transparent baseline plus a filled
 * delta. Those helpers carry stacking offsets rather than measured values, so
 * showing them in the tooltip would print numbers that do not exist in the
 * data. The outline series, by contrast, carry the real upper/lower values and
 * must stay visible.
 */

/**
 * Helper series whose values are stacking artefacts, not measurements.
 *
 * Keep this list minimal: every name added here disappears from the tooltip.
 * `Upper Bound`, `Lower`, `Envelope Min` and `Envelope Max` are deliberately
 * absent — they hold the real bound values the operator reads off the tooltip.
 */
export const TOOLTIP_HIDDEN_SERIES: readonly string[] = [
  'Lower Bound',
  'Band',
  'Envelope Low',
  'Envelope Band',
]

/**
 * Series carrying operator-visible values that must never be hidden.
 *
 * Exported so tests can assert the two sets stay disjoint.
 */
export const TOOLTIP_VISIBLE_SERIES: readonly string[] = [
  'Value',
  'Upper Bound',
  'Lower',
  'Envelope Min',
  'Envelope Max',
]

/**
 * Human-facing tooltip label for a series.
 *
 * The internal series names are chosen for stacking mechanics, so `Lower` is
 * the counterpart of `Upper Bound`. Presenting that asymmetry to the operator
 * is confusing; relabel it into a matching pair.
 */
export function tooltipSeriesLabel(seriesName: string): string {
  return seriesName === 'Lower' ? 'Lower Bound' : seriesName
}

/**
 * Sample shape needed to place a violation marker.
 *
 * Mirrors the relevant subset of `FeatureTimeseriesPoint`; kept structural so
 * the helper stays unit-testable without the full API type.
 */
export interface ViolationSample {
  value: number | null
  value_min?: number | null
  value_max?: number | null
  violation_low?: boolean
  violation_high?: boolean
  lower_bound?: number | null
  upper_bound?: number | null
}

/**
 * Pick the y-value at which a violation marker should be drawn.
 *
 * Plotted samples are bucket aggregates: `value` is the bucket mean while
 * `value_min`/`value_max` preserve the extremes the mean averages away. The
 * backend raises `violation_high`/`violation_low` from those extremes, so a
 * single spike inside a wide bucket is correctly flagged even though the mean
 * stays well inside the band.
 *
 * Drawing such a marker at `value` puts it inside the bounds, which reads to
 * the operator as a false positive — the dot floats in the normal band with no
 * visible cause. Anchoring it to the extreme that actually breached the bound
 * makes the triggering sample visible at any sampling resolution.
 *
 * Returns `null` when the sample carries no violation.
 */
export function violationMarkerValue(point: ViolationSample): number | null {
  const high = point.violation_high === true
  const low = point.violation_low === true
  if (!high && !low) return null

  // Prefer the breaching extreme; fall back to the mean when extrema are
  // absent (unaggregated responses omit the min/max columns entirely).
  if (high && typeof point.value_max === 'number') return point.value_max
  if (low && typeof point.value_min === 'number') return point.value_min
  return typeof point.value === 'number' ? point.value : null
}

/**
 * Order tooltip rows so the reading is Upper → Value → Lower.
 *
 * ECharts hands the formatter its series in draw order, which puts the bounds
 * around the value in an arbitrary sequence. A stable vertical ordering makes
 * the value's position inside its bounds readable at a glance.
 */
export function tooltipSeriesRank(seriesName: string): number {
  switch (seriesName) {
    case 'Envelope Max':
      return 0
    case 'Upper Bound':
      return 1
    case 'Value':
      return 2
    case 'Lower':
      return 3
    case 'Envelope Min':
      return 4
    default:
      return 5
  }
}
