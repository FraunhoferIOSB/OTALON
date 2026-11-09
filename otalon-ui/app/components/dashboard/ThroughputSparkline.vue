<template>
  <ClientOnly>
    <div v-if="props.data.length === 0" class="no-data-container">
      <q-icon name="show_chart" size="24px" color="grey-5" />
      <span class="text-caption text-muted q-ml-sm">No throughput data available</span>
    </div>
    <div v-else class="sparkline-wrapper">
      <div ref="chartRef" class="sparkline-chart" />
      <div class="sparkline-label text-caption text-muted">
        {{ lastValueLabel }}
      </div>
    </div>
    <template #fallback>
      <div class="no-data-container">
        <q-spinner-dots size="20px" color="primary" />
      </div>
    </template>
  </ClientOnly>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import { useResizeObserver } from '@vueuse/core'
import type { ThroughputDataPoint } from '~/types/api'
import { formatBytes, parseApiTimestamp } from '~/utils/format'
import { getCssVar } from '~/utils/cssVar'

/**
 * Compact ECharts area-line sparkline for network throughput.
 *
 * Renders total_bytes as a smooth area chart with no axes, grid,
 * or tooltip — designed to fit in ~80px height as a dashboard widget.
 * Adapts colors to dark/light mode via CSS custom properties.
 */
const props = defineProps<{
  data: ThroughputDataPoint[]
}>()

const $q = useQuasar()
const chartRef = ref<HTMLElement | null>(null)
// Loosely typed ECharts handle — only setOption/resize/dispose are used.
let chartInstance: {
  setOption: (opt: unknown) => void
  resize: () => void
  dispose: () => void
} | null = null

/**
 * Compute a human-readable label for the most recent throughput value.
 *
 * Divides total_bytes by bucket_seconds to approximate bytes/s,
 * then formats with appropriate unit suffix.
 */
const lastValueLabel = computed(() => {
  if (props.data.length === 0) return ''
  const last = props.data[props.data.length - 1]
  return `${formatBytes(last.total_bytes)} total`
})

function buildOption(): Record<string, unknown> {
  const lineColor = getCssVar('--cd-plot-line', '#005b7f')
  const areaColor = getCssVar('--cd-plot-area', 'rgba(0, 91, 127, 0.15)')
  const timeValues = props.data.map((p) => [parseApiTimestamp(p.timestamp).getTime(), p.total_bytes])

  return {
    backgroundColor: 'transparent',
    animation: true,
    animationDuration: 600,
    animationDurationUpdate: 600,
    animationEasingUpdate: 'cubicInOut',
    tooltip: {
      trigger: 'axis',
      confine: true,
      backgroundColor: getCssVar('--cd-plot-bg', '#f5f7f8'),
      borderColor: getCssVar('--cd-plot-grid', '#cfd8dc'),
      textStyle: {
        color: getCssVar('--cd-plot-text', '#37474f'),
        fontSize: 11,
      },
      // ECharts tooltip formatter — see FeaturePlot for rationale.
      formatter(params: Array<Record<string, unknown>>) {
        if (!params || params.length === 0) return ''
        const ts = params[0].axisValue
        const time = new Date(typeof ts === 'number' ? ts : ts)
        const h = String(time.getHours()).padStart(2, '0')
        const m = String(time.getMinutes()).padStart(2, '0')
        const raw = Array.isArray(params[0].value) ? params[0].value[1] : params[0].value
        return `<div style="font-weight:600">${h}:${m}</div><div>${formatBytes(raw as number)}</div>`
      },
    },
    grid: {
      left: 0,
      right: 0,
      top: 4,
      bottom: 0,
      containLabel: false,
    },
    xAxis: {
      type: 'time',
      show: false,
    },
    yAxis: {
      type: 'value',
      show: false,
      min: 0,
    },
    series: [
      {
        type: 'line',
        data: timeValues,
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 2, color: lineColor },
        itemStyle: { color: lineColor },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: areaColor },
              { offset: 1, color: 'transparent' },
            ],
          },
        },
      },
    ],
  }
}

async function ensureChart(): Promise<void> {
  if (!chartRef.value) return
  if (!chartInstance) {
    const echarts = await import('echarts')
    chartInstance = echarts.init(chartRef.value)
  }
}

async function updateChart(): Promise<void> {
  if (props.data.length === 0) return
  await ensureChart()
  if (!chartInstance) return
  chartInstance.setOption(buildOption(), { notMerge: false, lazyUpdate: true })
}

onMounted(() => {
  nextTick(() => updateChart())
})

onBeforeUnmount(() => {
  if (chartInstance) {
    chartInstance.dispose()
    chartInstance = null
  }
})

watch(
  () => props.data,
  () => nextTick(() => updateChart()),
)

watch(
  () => $q.dark.isActive,
  () => {
    if (chartInstance) {
      chartInstance.dispose()
      chartInstance = null
    }
    nextTick(() => updateChart())
  },
)

useResizeObserver(chartRef, () => {
  chartInstance?.resize()
})
</script>

<style scoped lang="scss">
.sparkline-wrapper {
  position: relative;
  width: 100%;
}

.sparkline-chart {
  width: 100%;
  height: 80px;
}

.sparkline-label {
  position: absolute;
  right: 8px;
  top: 4px;
  font-size: 11px;
  pointer-events: none;
  z-index: 10;
  padding: 0 4px;
  border-radius: 2px;
}

.no-data-container {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 80px;
  width: 100%;
}
</style>
