<template>
  <ClientOnly>
    <div
      ref="chartRef"
      :style="{ height: `${height}px`, width: '100%' }"
      :data-violation-count="showViolations ? violationCount : 0"
      :aria-label="showViolations ? `${violationCount} out-of-bound datapoints` : 'Timeseries chart'"
      data-test="timeseries-chart"
    />
    <template #fallback>
      <div class="row items-center justify-center text-muted" :style="{ height: `${height}px` }">
        <q-spinner-dots size="32px" color="primary" />
      </div>
    </template>
  </ClientOnly>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import type { TimeseriesPoint } from '~/types/golden-data'
import { useResizeObserver } from '@vueuse/core'
import { parseApiTimestamp } from '~/utils/format'
import { getCssVar } from '~/utils/cssVar'
import { getChartEdgePaddingCount } from '~/utils/chartFraming'

/**
 * Timeseries line chart using ECharts wrapped in ClientOnly for SSR safety.
 *
 * Renders value line with optional upper/lower bounds and violation symbols.
 */
const props = withDefaults(
  defineProps<{
    data: TimeseriesPoint[]
    height?: number
    showBounds?: boolean
    showViolations?: boolean
  }>(),
  {
    height: 380,
    showBounds: false,
    showViolations: false,
  },
)

interface ViolationDatum {
  value: [number, number]
  timestamp: string
  violationLow: boolean
  violationHigh: boolean
}

function violationValue(point: TimeseriesPoint, low: boolean, high: boolean): number {
  const valueMin = point.value_min ?? point.value ?? 0
  const valueMax = point.value_max ?? point.value ?? 0
  const lowerBound = point.lower_bound ?? valueMin
  const upperBound = point.upper_bound ?? valueMax
  if (low && high) return Math.abs(valueMin - lowerBound) >= Math.abs(valueMax - upperBound) ? valueMin : valueMax
  if (low) return valueMin
  return valueMax
}

interface TooltipParam {
  axisValue?: string | number
  axisValueLabel?: string
  marker?: string
  seriesName?: string
  value?: number | [number, number]
  data?: number | ViolationDatum
}

function formatTooltip(params: unknown): string {
  if (!Array.isArray(params) || params.length === 0) return ''

  const entries = params as TooltipParam[]
  const title = entries[0]?.axisValueLabel ?? entries[0]?.axisValue ?? ''
  const lines = title ? [title] : []

  for (const entry of entries) {
    if (entry.seriesName === 'Violations' && typeof entry.data === 'object') {
      const violation = entry.data
      const violationLabel =
        violation.violationLow && violation.violationHigh
          ? 'Lower and upper bound violation'
          : violation.violationLow
            ? 'Lower bound violation'
            : 'Upper bound violation'
      lines.push(`${entry.marker ?? ''}${violationLabel}`)
      lines.push(`Actual value: ${violation.value[1]}`)
      continue
    }

    const value = Array.isArray(entry.value) ? entry.value[1] : entry.value
    lines.push(`${entry.marker ?? ''}${entry.seriesName ?? ''}: ${value ?? ''}`)
  }

  return lines.join('<br/>')
}

const $q = useQuasar()
const chartRef = ref<HTMLElement | null>(null)
const violationCount = computed(() => props.data.filter((point) => point.violation_low || point.violation_high).length)
// Loosely typed ECharts handle — only setOption/resize/dispose are used.
let chartInstance: {
  setOption: (opt: unknown) => void
  resize: () => void
  dispose: () => void
} | null = null

async function initChart(): Promise<void> {
  if (!chartRef.value) return
  if (!props.data || props.data.length === 0) return

  const echarts = await import('echarts')

  if (chartInstance) {
    chartInstance.dispose()
  }

  chartInstance = echarts.init(chartRef.value)

  const lineColor = getCssVar('--cd-plot-line', '#005b7f')
  const boundsColor = getCssVar('--cd-plot-bounds-upper', '#118046')
  const areaColor = getCssVar('--cd-plot-area', 'rgba(17, 128, 70, 0.15)')
  const textColor = getCssVar('--cd-plot-text', '#37474f')
  const gridColor = getCssVar('--cd-plot-grid', '#cfd8dc')

  const times = props.data.map((p) => {
    const d = parseApiTimestamp(p.time)
    return `${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`
  })
  const edgePaddingCount = getChartEdgePaddingCount(props.data.length)
  const emptyCategories = Array.from({ length: edgePaddingCount }, () => '')
  const values: Array<number | null> = [
    ...emptyCategories.map(() => null),
    ...props.data.map((p) => p.value),
    ...emptyCategories.map(() => null),
  ]
  const categories = [...emptyCategories, ...times, ...emptyCategories]

  // ECharts series-option array — entries are heterogeneous (line + markArea
  // + markLine), so we keep a loose Record locally rather than importing the
  // full SeriesOption union just for one assignment.
  const series: Array<Record<string, unknown>> = [
    {
      name: 'Value',
      type: 'line',
      data: values,
      smooth: true,
      showSymbol: props.data.length <= 10,
      symbolSize: 7,
      lineStyle: { width: 2.5, color: lineColor },
      itemStyle: { color: lineColor },
      z: 12,
    },
  ]

  if (props.showBounds) {
    const lowerBounds: Array<number | null> = [
      ...emptyCategories.map(() => null),
      ...props.data.map((p) => p.lower_bound),
      ...emptyCategories.map(() => null),
    ]
    const upperBounds: Array<number | null> = [
      ...emptyCategories.map(() => null),
      ...props.data.map((p) => p.upper_bound),
      ...emptyCategories.map(() => null),
    ]

    series.push(
      {
        name: 'Lower Bound',
        type: 'line',
        data: lowerBounds,
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 1, type: 'dashed', color: boundsColor },
        itemStyle: { color: boundsColor },
      },
      {
        name: 'Upper Bound',
        type: 'line',
        data: upperBounds,
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 1, type: 'dashed', color: boundsColor },
        itemStyle: { color: boundsColor },
        areaStyle: {
          color: areaColor,
          origin: 'auto',
        },
      },
    )
  }

  if (props.showViolations) {
    const violations: ViolationDatum[] = props.data.flatMap((point, index) =>
      point.violation_low || point.violation_high
        ? [
            {
              value: [index + edgePaddingCount, violationValue(point, point.violation_low, point.violation_high)],
              timestamp: point.time,
              violationLow: point.violation_low,
              violationHigh: point.violation_high,
            },
          ]
        : [],
    )

    series.push({
      name: 'Violations',
      type: 'scatter',
      data: violations,
      symbol: 'circle',
      symbolSize: 5,
      itemStyle: { color: '#d32f2f', opacity: 0.48 },
      emphasis: { itemStyle: { opacity: 1 }, scale: 1.8 },
      z: 6,
    })
  }

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      textStyle: { color: textColor },
      formatter: formatTooltip,
    },
    grid: {
      left: 60,
      right: 20,
      top: 40,
      bottom: 60,
    },
    xAxis: {
      type: 'category',
      data: categories,
      boundaryGap: true,
      axisLabel: {
        formatter: (value: string, index: number) =>
          index < edgePaddingCount || index >= categories.length - edgePaddingCount ? '' : value,
        rotate: 30,
        fontSize: 11,
        color: textColor,
      },
      axisLine: { lineStyle: { color: gridColor } },
      axisTick: { lineStyle: { color: gridColor } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: textColor },
      splitLine: { lineStyle: { color: gridColor, type: 'dashed' } },
    },
    series,
    legend: {
      show: series.length > 1,
      bottom: 0,
      textStyle: { color: textColor },
    },
  }

  chartInstance.setOption(option)
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
})

watch(
  () => [props.data, props.showBounds, props.showViolations],
  () => {
    nextTick(() => {
      initChart()
    })
  },
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
