<template>
  <ClientOnly>
    <div
      v-if="hasData"
      ref="chartRef"
      class="inline-sparkline"
      :style="{ width: `${props.width}px`, height: `${props.height}px` }"
    />
  </ClientOnly>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import { getCssVar } from '~/utils/cssVar'

/**
 * Tiny inline ECharts sparkline for embedding in list items.
 *
 * Renders a smooth area-line with no axes, grid, or tooltip.
 * Designed for ~60×20px inline display next to traffic metrics.
 * Renders nothing when data is empty or all zeros.
 */
const props = withDefaults(
  defineProps<{
    data: number[]
    color?: string
    width?: number
    height?: number
  }>(),
  {
    color: '',
    width: 60,
    height: 20,
  },
)

const $q = useQuasar()
const chartRef = ref<HTMLElement | null>(null)
// Loosely typed ECharts handle — only setOption/resize/dispose are used.
let chartInstance: {
  setOption: (opt: unknown) => void
  resize: () => void
  dispose: () => void
} | null = null

const hasData = computed(() => {
  return props.data.length > 0 && props.data.some((v) => v !== 0)
})

function resolveColor(): string {
  if (props.color) return props.color
  return getCssVar('--cd-plot-line', '#005b7f')
}

function buildOption(): Record<string, unknown> {
  const lineColor = resolveColor()

  return {
    backgroundColor: 'transparent',
    animation: true,
    animationDuration: 400,
    animationDurationUpdate: 400,
    animationEasingUpdate: 'cubicInOut',
    grid: {
      left: 0,
      right: 0,
      top: 0,
      bottom: 0,
      containLabel: false,
    },
    xAxis: {
      type: 'category',
      show: false,
      data: props.data.map((_, i) => i),
    },
    yAxis: {
      type: 'value',
      show: false,
      min: 0,
    },
    series: [
      {
        type: 'line',
        data: props.data,
        smooth: 0.3,
        showSymbol: false,
        lineStyle: { width: 1.5, color: lineColor },
        itemStyle: { color: lineColor },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: lineColor + '30' },
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
  if (!hasData.value) return
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
</script>

<style scoped lang="scss">
.inline-sparkline {
  display: inline-block;
  vertical-align: middle;
  flex-shrink: 0;
}
</style>
