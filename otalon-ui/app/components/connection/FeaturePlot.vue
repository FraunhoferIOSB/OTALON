<template>
  <q-card
    flat
    bordered
    class="feature-plot-card"
    :class="{ 'feature-plot-card--affected': affected }"
    :data-feature="featureName"
  >
    <q-card-section class="q-pa-sm card-title">
      <div class="text-subtitle2 text-weight-bold q-mb-xs">{{ title }}</div>
      <q-badge v-if="affected" color="negative" label="Affected feature" />
      <div v-if="showNoSpreadHint" class="text-caption text-muted">
        No min/max spread in this window — select a longer time range
      </div>
    </q-card-section>
    <q-card-section class="q-pa-none card-chart">
      <ClientOnly>
        <div ref="chartRef" class="chart-container" />
        <template #fallback>
          <div class="chart-placeholder row items-center justify-center">
            <q-spinner-dots size="24px" color="primary" />
          </div>
        </template>
      </ClientOnly>
    </q-card-section>
  </q-card>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import type { FeatureTimeseriesPoint, AnomalyInterval, EnvelopeMode } from '~/types/golden-data'
import { useResizeObserver } from '@vueuse/core'
import { parseApiTimestamp } from '~/utils/format'
import { buildMarkAreaData, toEpoch } from '~/utils/chart'
import { getCssVar } from '~/utils/cssVar'
import { useSharedCrosshair } from '~/composables/useSharedCrosshair'
import {
  TOOLTIP_HIDDEN_SERIES,
  tooltipSeriesLabel,
  tooltipSeriesRank,
  violationMarkerValue,
} from './featurePlotTooltip'

/**
 * Single feature timeseries plot using ECharts.
 *
 * Renders a line chart with value, upper/lower bounds as a shaded area,
 * optional anomaly markArea regions, and dark-mode-aware colors via CSS
 * custom properties.
 */
const props = withDefaults(
  defineProps<{
    title: string
    featureName: string
    data: FeatureTimeseriesPoint[]
    anomalyIntervals?: AnomalyInterval[]
    forceScatter?: boolean
    timeRange?: { start: string; stop: string }
    showEnvelope?: EnvelopeMode
    affected?: boolean
  }>(),
  {
    anomalyIntervals: () => [],
    forceScatter: false,
    timeRange: undefined,
    showEnvelope: 'auto',
    affected: false,
  },
)

const $q = useQuasar()
const chartRef = ref<HTMLElement | null>(null)
const sharedCrosshair = useSharedCrosshair()
const GRID_LEFT = 50
const GRID_RIGHT = 12
const GRID_TOP = 8
// Loosely typed at the boundary: echarts' ECharts type is loaded lazily
// inside initChart(), so the instance is duck-typed to the operations we
// actually perform on it.
interface EChartsInstance {
  setOption: (opt: unknown) => void
  resize: () => void
  dispose: () => void
  getZr?: () => {
    on: (event: string, handler: (event: { offsetX: number }) => void) => void
  }
  dispatchAction?: (action: unknown) => void
}

let chartInstance: EChartsInstance | null = null

const SPREAD_EPSILON = 1e-9

const _dataHasSpread = computed<boolean>(() =>
  props.data.some(
    (p) => p.value_min != null && p.value_max != null && Math.abs(p.value_max - p.value_min) > SPREAD_EPSILON,
  ),
)

const envelopeVisible = computed<boolean>(
  () =>
    // Min/Max envelope disabled (P8 on-hold, UI-071) — re-enable when the bounds-spread bug is fixed.
    false,
)

const showNoSpreadHint = computed<boolean>(
  // Min/Max envelope disabled (P8 on-hold, UI-071) — re-enable when the bounds-spread bug is fixed.
  () => false,
)

function getChartColors() {
  return {
    bg: getCssVar('--cd-plot-bg', '#f5f7f8'),
    text: getCssVar('--cd-plot-text', '#37474f'),
    grid: getCssVar('--cd-plot-grid', '#cfd8dc'),
    line: getCssVar('--cd-plot-line', '#005b7f'),
    boundLine: getCssVar('--cd-plot-bounds-upper', '#118046'),
    boundFill: getCssVar('--cd-plot-area', 'rgba(17, 128, 70, 0.15)'),
    anomaly: getCssVar('--cd-plot-anomaly-fill', 'rgba(255, 77, 77, 0.18)'),
    envelope: getCssVar('--cd-plot-envelope', 'rgba(92, 107, 192, 0.35)'),
    envelopeLine: getCssVar('--cd-plot-envelope-line', 'rgba(92, 107, 192, 0.9)'),
    violation: getCssVar('--cd-plot-violation', '#ff4d4d'),
  }
}

/**
 * Detect whether timeseries data should be rendered as scatter points
 * instead of a continuous line.
 *
 * Uses two complementary heuristics:
 * 1. **Temporal sparsity**: More than 40% of inter-point intervals exceed
 *    3x the median interval (large time gaps between data points).
 * 2. **Low-variance constant data**: More than 80% of values are identical
 *    and the dominant value is small (<=2), indicating periodic single-packet
 *    connections (e.g., LLDP sending 1 packet per interval).
 *
 * @param times - Array of ISO 8601 timestamps.
 * @param values - Array of numeric values corresponding to each timestamp.
 * @returns True if scatter rendering is more appropriate than a line.
 */
function detectSparseData(times: string[], values: number[]): boolean {
  if (times.length < 3) return false

  const timestamps = times.map((t) => parseApiTimestamp(t).getTime())
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

/**
 * Extend bounds data arrays to cover the full chart range [xMin, xMax].
 *
 * Inserts synthetic data points at xMin and xMax using the values from
 * the first and last real bound points respectively.  This ensures the
 * threshold lines are drawn across the entire visible chart area, even
 * when the actual data starts later or ends earlier.
 */
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

async function initChart(): Promise<void> {
  if (!chartRef.value || !props.data || props.data.length === 0) return

  const echarts = await import('echarts')
  if (chartInstance) {
    chartInstance.dispose()
  }

  chartInstance = echarts.init(chartRef.value)
  // Expose instance for E2E tests (non-standard, test-only)
  // @ts-expect-error __echartsInstance is not in HTMLElement type
  if (chartRef.value) chartRef.value.__echartsInstance = chartInstance
  const colors = getChartColors()

  const times = props.data.map((p) => p.time)
  const values = props.data.map((p) => p.value)
  const isSparse = props.forceScatter || detectSparseData(times, values)

  const timeValues = props.data.map((p) => [toEpoch(p.time), p.value])

  const hasBounds = props.data.some((p) => p.lower_bound != null) || props.data.some((p) => p.upper_bound != null)

  const lowerBoundsTV = props.data.map((p) => [toEpoch(p.time), p.lower_bound ?? null])
  const upperBoundsTV = props.data.map((p) => [toEpoch(p.time), p.upper_bound ?? null])
  const bandDataTV = hasBounds
    ? props.data.map((p) => {
        if (p.upper_bound == null || p.lower_bound == null) return [toEpoch(p.time), null]
        return [toEpoch(p.time), p.upper_bound - p.lower_bound]
      })
    : []

  const valueMinTV = envelopeVisible.value ? props.data.map((p) => [toEpoch(p.time), p.value_min ?? null]) : null
  const valueMaxTV = envelopeVisible.value ? props.data.map((p) => [toEpoch(p.time), p.value_max ?? null]) : null
  const envelopeBandTV = envelopeVisible.value
    ? props.data.map((p) => {
        const min = p.value_min
        const max = p.value_max
        return [toEpoch(p.time), max != null && min != null ? max - min : null]
      })
    : null

  // Anchor violation markers to the extreme that breached the bound, not to
  // the bucket mean — otherwise a spike averaged away by downsampling renders
  // inside the band and reads as a false positive.
  const violationPoints = props.data
    .map((p) => [toEpoch(p.time), violationMarkerValue(p)])
    .filter((pair) => pair[1] !== null)
  const violationTV = violationPoints.length > 0 ? violationPoints : null

  const markAreaData = buildMarkAreaData(props.anomalyIntervals)

  const dataEpochs = props.data.map((p) => toEpoch(p.time))
  const dataMin = dataEpochs.length > 0 ? Math.min(...dataEpochs) : undefined
  const dataMax = dataEpochs.length > 0 ? Math.max(...dataEpochs) : undefined

  let xMin: number | undefined
  let xMax: number | undefined
  if (props.timeRange) {
    xMin = toEpoch(props.timeRange.start)
    xMax = toEpoch(props.timeRange.stop)
  } else if (dataMin !== undefined && dataMax !== undefined) {
    const pad = Math.max((dataMax - dataMin) * 0.02, 30000)
    xMin = dataMin - pad
    xMax = dataMax + pad
  }

  if (hasBounds && xMin !== undefined && xMax !== undefined) {
    extendBoundsToChartRange(lowerBoundsTV, upperBoundsTV, bandDataTV, xMin, xMax)
  }

  const option = {
    backgroundColor: 'transparent',
    animation: false,
    tooltip: {
      trigger: 'axis',
      backgroundColor: colors.bg,
      borderColor: colors.grid,
      textStyle: { color: colors.text, fontSize: 11 },
      // ECharts tooltip formatter receives an array of per-series points;
      // shape varies by chart type, so we keep a loose Record locally.
      formatter(params: Array<Record<string, unknown>>) {
        if (!params || params.length === 0) return ''
        const ts = params[0].axisValue
        const time = new Date(typeof ts === 'number' ? ts : ts)
        const h = time.getHours()
        const m = String(time.getMinutes()).padStart(2, '0')
        const s = String(time.getSeconds()).padStart(2, '0')
        let html = `<div style="font-weight:600">${h}:${m}:${s}</div>`
        const rows = params
          .filter((p) => !TOOLTIP_HIDDEN_SERIES.includes(p.seriesName as string))
          .sort(
            (a, b) =>
              tooltipSeriesRank(a.seriesName as string) - tooltipSeriesRank(b.seriesName as string),
          )
        for (const p of rows) {
          const raw = Array.isArray(p.value) ? p.value[1] : p.value
          const val = typeof raw === 'number' ? raw.toPrecision(4) : (raw ?? 'N/A')
          html += `<div>${p.marker} ${tooltipSeriesLabel(p.seriesName as string)}: ${val}</div>`
        }
        return html
      },
    },
    grid: {
      left: 50,
      right: 12,
      top: 8,
      bottom: 24,
    },
    xAxis: {
      type: 'time',
      min: xMin,
      max: xMax,
      axisLabel: {
        fontSize: 10,
        color: colors.text,
        formatter: {
          hour: '{HH}:{mm}',
          minute: '{HH}:{mm}',
          second: '{HH}:{mm}:{ss}',
        },
      },
      axisLine: { lineStyle: { color: colors.grid } },
      axisTick: { lineStyle: { color: colors.grid } },
      splitLine: { show: false },
      // The time axis owns the crosshair. Configuring it here rather than at
      // the option root is deliberate: a root-level `axisPointer` is inherited
      // by BOTH axes and draws a full cross. `show: true` (not the default
      // 'auto') is required so the pointer also renders when a sibling plot
      // drives it through `updateAxisPointer` without this chart being hovered.
      axisPointer: {
        show: true,
        type: 'line',
        snap: false,
        lineStyle: { color: colors.line, width: 1, type: 'dashed' },
        label: { show: false },
      },
    },
    yAxis: {
      type: 'value',
      axisLabel: {
        fontSize: 10,
        color: colors.text,
        formatter(val: number) {
          if (Math.abs(val) >= 10000) return `${(val / 1000).toFixed(0)}k`
          if (Math.abs(val) >= 1) return val.toFixed(0)
          return val.toPrecision(2)
        },
      },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: colors.grid, type: 'dashed', opacity: 0.5 } },
      axisPointer: { show: false },
    },
    series: [
      ...(hasBounds
        ? [
            {
              name: 'Lower Bound',
              type: 'line',
              data: lowerBoundsTV,
              smooth: false,
              showSymbol: false,
              lineStyle: { width: 0 },
              areaStyle: { color: 'transparent' },
              stack: 'bounds',
              silent: true,
            },
            {
              name: 'Band',
              type: 'line',
              data: bandDataTV,
              smooth: false,
              showSymbol: false,
              lineStyle: { width: 0 },
              areaStyle: { color: colors.boundFill },
              stack: 'bounds',
              silent: true,
            },
            {
              name: 'Upper Bound',
              type: 'line',
              data: upperBoundsTV,
              smooth: false,
              showSymbol: false,
              lineStyle: { width: 1, type: 'dashed', color: colors.boundLine },
              itemStyle: { color: colors.boundLine },
              z: 2,
            },
            {
              name: 'Lower',
              type: 'line',
              data: lowerBoundsTV,
              smooth: false,
              showSymbol: false,
              lineStyle: { width: 1, type: 'dashed', color: colors.boundLine },
              itemStyle: { color: colors.boundLine },
              z: 2,
            },
          ]
        : []),
      {
        name: 'Value',
        type: isSparse ? 'scatter' : 'line',
        data: timeValues,
        smooth: false,
        showSymbol: isSparse || (props.data?.length ?? 0) <= 5,
        symbolSize: isSparse ? 3 : 4,
        lineStyle: isSparse ? { width: 0 } : { width: 2, color: colors.line },
        itemStyle: { color: colors.line },
        z: 3,
        ...(markAreaData.length > 0
          ? {
              markArea: {
                silent: true,
                itemStyle: {
                  color: colors.anomaly,
                },
                data: markAreaData,
              },
            }
          : {}),
      },
      ...(envelopeBandTV
        ? [
            {
              name: 'Envelope Low',
              type: 'line',
              data: valueMinTV,
              smooth: false,
              showSymbol: false,
              lineStyle: { width: 0 },
              areaStyle: { color: 'transparent' },
              stack: 'envelope',
              silent: true,
              z: 2.5,
            },
            {
              name: 'Envelope Band',
              type: 'line',
              data: envelopeBandTV,
              smooth: false,
              showSymbol: false,
              lineStyle: { width: 0 },
              areaStyle: { color: colors.envelope },
              stack: 'envelope',
              silent: true,
              z: 2.5,
            },
            {
              name: 'Envelope Min',
              type: 'line',
              data: valueMinTV,
              smooth: false,
              showSymbol: false,
              lineStyle: { width: 1, color: colors.envelopeLine },
              itemStyle: { color: colors.envelopeLine },
              z: 2.6,
            },
            {
              name: 'Envelope Max',
              type: 'line',
              data: valueMaxTV,
              smooth: false,
              showSymbol: false,
              lineStyle: { width: 1, color: colors.envelopeLine },
              itemStyle: { color: colors.envelopeLine },
              z: 2.6,
            },
          ]
        : []),
      ...(violationTV
        ? [
            {
              name: 'Violations',
              type: 'scatter',
              data: violationTV,
              symbolSize: 8,
              itemStyle: { color: colors.violation },
              z: 4,
            },
          ]
        : []),
    ],
  }

  chartInstance.setOption(option)
  registerCrosshairBridge(chartInstance, xMin, xMax)
}

/**
 * Wire this chart into the shared crosshair bus.
 *
 * Publishes the hovered timestamp to sibling plots and the rhythm lane, and
 * renders this chart's own pointer when a sibling publishes.
 *
 * `initChart()` disposes and re-creates the ECharts instance on every data
 * refresh, so the zrender handler is bound to a fresh instance each time and
 * cannot accumulate. The window listener is owned by `subscribe()`, which
 * releases it via `onScopeDispose`.
 */
function registerCrosshairBridge(
  instance: EChartsInstance,
  xMin: number | undefined,
  xMax: number | undefined,
): void {
  const toPixelRatio = (offsetX: number): number => {
    const width = chartRef.value?.clientWidth ?? 0
    const span = Math.max(1, width - GRID_LEFT - GRID_RIGHT)
    return Math.max(0, Math.min(1, (offsetX - GRID_LEFT) / span))
  }

  const zr = instance.getZr?.()
  zr?.on('mousemove', (event) => {
    if (!sharedCrosshair.enabled.value || xMin === undefined || xMax === undefined) return
    sharedCrosshair.publish(xMin + toPixelRatio(event.offsetX) * (xMax - xMin))
  })
  // Clear the shared pointer when the cursor leaves this chart, otherwise the
  // dashed line stays frozen at its last position in every sibling plot.
  zr?.on('globalout', () => {
    if (!sharedCrosshair.enabled.value) return
    sharedCrosshair.publish(null)
  })

  sharedCrosshair.subscribe((time) => {
    if (time === null) {
      instance.dispatchAction?.({ type: 'hideTip' })
      instance.dispatchAction?.({ type: 'updateAxisPointer', currTrigger: 'leave' })
      return
    }
    if (xMin === undefined || xMax === undefined) return
    const width = chartRef.value?.clientWidth ?? 0
    const span = Math.max(0, width - GRID_LEFT - GRID_RIGHT)
    const pixel = GRID_LEFT + ((time - xMin) / (xMax - xMin)) * span
    // `currTrigger: 'mousemove'` is required: without it ECharts keeps the
    // pointer status at 'hide' and no line is drawn in charts that are not
    // themselves under the cursor.
    instance.dispatchAction?.({
      type: 'updateAxisPointer',
      currTrigger: 'mousemove',
      x: pixel,
      y: GRID_TOP + 1,
    })
  })
}

onMounted(() => {
  nextTick(() => {
    initChart()
  })
})

onBeforeUnmount(() => {
  if (chartInstance) {
    chartInstance.dispose()
    chartInstance = null
  }
  // @ts-expect-error __echartsInstance is test-only
  if (chartRef.value) chartRef.value.__echartsInstance = undefined
})

watch(
  () => props.data,
  () => {
    nextTick(() => {
      initChart()
    })
  },
)

watch(
  () => props.anomalyIntervals,
  () => {
    nextTick(() => {
      initChart()
    })
  },
)

watch(
  () => props.showEnvelope,
  () => {
    nextTick(() => {
      initChart()
    })
  },
)

watch(
  () => props.timeRange,
  () => {
    nextTick(() => {
      initChart()
    })
  },
  { deep: true },
)

watch(
  () => $q.dark.isActive,
  () => {
    nextTick(() => {
      initChart()
    })
  },
)

useResizeObserver(chartRef, () => {
  chartInstance?.resize()
})
</script>

<style scoped lang="scss">
.feature-plot-card {
  background-color: var(--cd-surface);
  border-color: var(--cd-border);
  height: 100%;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.feature-plot-card--affected {
  border: 2px solid var(--q-negative);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--q-negative) 20%, transparent);
}

.card-title {
  flex-shrink: 0;
}

.card-chart {
  flex: 1;
  min-height: 0;
}

.chart-container {
  position: relative;
  width: 100%;
  height: 100%;
  min-height: 50px;
}

.shared-crosshair {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  background: var(--q-primary);
  pointer-events: none;
  z-index: 10;
}

.chart-placeholder {
  height: 100%;
  min-height: 50px;
}
</style>
