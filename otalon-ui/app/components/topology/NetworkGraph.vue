<template>
  <q-card flat bordered class="network-graph-card">
    <q-card-section class="q-pa-sm row items-center justify-between">
      <div class="text-caption text-muted">{{ nodeCount }} Nodes · {{ edgeCount }} Edges</div>
      <div class="row q-gutter-xs">
        <q-btn flat dense round icon="zoom_in" @click="zoomIn">
          <q-tooltip>Zoom In</q-tooltip>
        </q-btn>
        <q-btn flat dense round icon="zoom_out" @click="zoomOut">
          <q-tooltip>Zoom Out</q-tooltip>
        </q-btn>
        <q-btn flat dense round icon="fit_screen" @click="resetZoom">
          <q-tooltip>Reset View</q-tooltip>
        </q-btn>
        <q-btn flat dense round icon="tune" @click="showSettings = true">
          <q-tooltip>Display Settings</q-tooltip>
        </q-btn>
      </div>

      <!-- Settings Dialog -->
      <q-dialog v-model="showSettings" position="right">
        <q-card style="min-width: 320px" class="settings-dialog">
          <q-card-section class="row items-center no-wrap q-pb-sm">
            <q-icon name="tune" size="20px" class="q-mr-sm" />
            <span class="text-subtitle1 text-weight-bold">Display Settings</span>
            <q-space />
            <q-btn flat round dense icon="close" @click="showSettings = false" />
          </q-card-section>

          <q-separator />

          <q-card-section>
            <div class="text-caption text-weight-bold q-mb-xs">Layout</div>
            <q-select
              v-model="graphSettings.layout"
              :options="layoutOptions"
              dense
              outlined
              emit-value
              map-options
              class="q-mb-md"
              @update:model-value="applySettings"
            />

            <div class="text-caption text-weight-bold q-mb-xs">Friction ({{ graphSettings.friction.toFixed(2) }})</div>
            <q-slider
              v-model="graphSettings.friction"
              :min="0.1"
              :max="1.0"
              :step="0.05"
              :disable="graphSettings.layout !== 'force'"
              label
              label-always
              :label-value="graphSettings.friction.toFixed(2)"
              color="primary"
              class="q-mb-md"
              @change="applySettings"
            />
            <div class="text-caption text-muted q-mb-md">Higher values = faster stabilization. 1.0 = instant stop.</div>

            <q-separator class="q-my-md" />

            <div class="text-caption text-weight-bold q-mb-xs">Node Labels</div>
            <q-select
              v-model="graphSettings.identifierMode"
              :options="identifierOptions"
              dense
              outlined
              emit-value
              map-options
              class="q-mb-md"
              @update:model-value="applySettings"
            />

            <div class="text-caption text-weight-bold q-mb-xs">Font Size ({{ graphSettings.labelFontSize }}px)</div>
            <q-slider
              v-model="graphSettings.labelFontSize"
              :min="8"
              :max="24"
              :step="1"
              label
              label-always
              :label-value="`${graphSettings.labelFontSize}px`"
              color="primary"
              class="q-mb-md"
              @change="applySettings"
            />

            <q-separator class="q-my-md" />

            <div class="text-caption text-weight-bold q-mb-xs">Filter Nodes</div>
            <q-toggle
              v-model="graphSettings.hideBroadcast"
              label="Hide Broadcast"
              color="primary"
              dense
              class="q-mb-xs"
              @update:model-value="applySettings"
            />
            <q-toggle
              v-model="graphSettings.hideMulticast"
              label="Hide Multicast"
              color="primary"
              dense
              @update:model-value="applySettings"
            />

            <q-separator class="q-my-md" />

            <q-btn
              flat
              no-caps
              color="negative"
              icon="restart_alt"
              label="Reset to defaults"
              class="full-width"
              @click="resetGraphSettings"
            />
          </q-card-section>
        </q-card>
      </q-dialog>
    </q-card-section>
    <q-card-section class="q-pa-none">
      <ClientOnly>
        <div ref="chartRef" class="graph-container" />
        <template #fallback>
          <div class="graph-placeholder row items-center justify-center">
            <q-spinner-dots size="32px" color="primary" />
          </div>
        </template>
      </ClientOnly>
    </q-card-section>
  </q-card>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import { useResizeObserver } from '@vueuse/core'

/**
 * Interactive network topology graph using ECharts.
 *
 * Renders nodes/edges with force-directed layout and SVG device icons,
 * supports zoom, pan, node dragging, and emits click events for both
 * node and edge selection.
 */
// Props are declared on the public component surface (parents pass these
// for layout sizing) but the current implementation does not read them
// directly. Keep the contract; underscore-prefix to satisfy no-unused-vars.
const _props = withDefaults(
  defineProps<{
    nodeCount: number
    edgeCount: number
  }>(),
  {},
)

const emit = defineEmits<{
  'node-click': [nodeId: string]
  'edge-click': [payload: { source: string; target: string; edge: Record<string, unknown> }]
}>()

const $q = useQuasar()
const chartRef = ref<HTMLElement | null>(null)
// Loosely typed ECharts handle — only setOption/resize/dispose/on used.
let chartInstance: {
  setOption: (opt: unknown) => void
  resize: () => void
  dispose: () => void
  on: (event: string, handler: (params: Record<string, unknown>) => void) => void
  getOption: () => Record<string, unknown>
} | null = null
let currentZoom = 1

const { buildOption, graphSettings, topologySignature, nodeLabelSignature } = useTopologyGraph()

const showSettings = ref(false)

const layoutOptions = [
  { label: 'Force-Directed', value: 'force' },
  { label: 'Circular', value: 'circular' },
]

const identifierOptions = [
  { label: 'Auto (Name → IP → MAC)', value: 'auto' },
  { label: 'IP only', value: 'ip' },
  { label: 'MAC only', value: 'mac' },
]

/**
 * Apply changed settings to the running chart without full re-initialization.
 *
 * Uses setOption() to update graph data and force parameters in-place so the
 * simulation can respond to friction changes without resetting node positions.
 */
function applySettings(): void {
  if (!chartInstance) return
  const dark = $q.dark.isActive
  const option = buildOption(dark)
  chartInstance.setOption(option, { notMerge: false, lazyUpdate: true })
}

function resetGraphSettings(): void {
  graphSettings.layout = 'circular'
  graphSettings.friction = 0.9
  graphSettings.hideBroadcast = true
  graphSettings.hideMulticast = true
  graphSettings.identifierMode = 'auto'
  graphSettings.labelFontSize = 10
  applySettings()
}

/**
 * Refresh chart data without recreating the ECharts instance.
 *
 * Preferred over a full {@link initChart} re-init because it preserves
 * pan/zoom, force-layout node positions, and the simulation state.
 * Used when the underlying graph data changes (SSE push, manual refresh,
 * filter toggle) but the visual configuration remains the same.
 */
function refreshChart(): void {
  if (!chartInstance) return
  const dark = $q.dark.isActive
  const option = buildOption(dark)
  chartInstance.setOption(option, { notMerge: false, lazyUpdate: true })
}

async function initChart(): Promise<void> {
  if (!chartRef.value) return

  const echarts = await import('echarts')
  if (chartInstance) {
    chartInstance.dispose()
  }

  chartInstance = echarts.init(chartRef.value)
  const dark = $q.dark.isActive
  const option = buildOption(dark)
  chartInstance.setOption(option)

  // ECharts click handler — `params` shape varies by dataType (node/edge),
  // keep it loose at the boundary and narrow inside the body.
  chartInstance.on('click', (params: Record<string, unknown>) => {
    if (params.dataType === 'node' && params.data?.originalNode) {
      emit('node-click', params.data.originalNode.id)
    }
    if (params.dataType === 'edge' && params.data?.originalEdge) {
      const edge = params.data.originalEdge
      emit('edge-click', {
        source: edge.source,
        target: edge.target,
        edge,
      })
    }
  })

  currentZoom = 1
}

function zoomIn(): void {
  if (!chartInstance) return
  currentZoom = Math.min(currentZoom * 1.3, 5)
  chartInstance.dispatchAction({
    type: 'graphRoam',
    seriesIndex: 0,
    zoom: 1.3,
  })
}

function zoomOut(): void {
  if (!chartInstance) return
  currentZoom = Math.max(currentZoom / 1.3, 0.2)
  chartInstance.dispatchAction({
    type: 'graphRoam',
    seriesIndex: 0,
    zoom: 1 / 1.3,
  })
}

function resetZoom(): void {
  if (!chartInstance) return
  initChart()
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

useResizeObserver(chartRef, () => {
  chartInstance?.resize()
})

watch(
  () => $q.dark.isActive,
  () => {
    nextTick(() => {
      initChart()
    })
  },
)

// Refresh the chart in-place when the underlying topology actually changes.
// Watching the structural signature instead of the store reference avoids
// a full dispose/init on every SSE push that delivers identical data and
// preserves the user's current pan/zoom and node positions.
watch(topologySignature, () => {
  if (!chartInstance) {
    nextTick(() => initChart())
    return
  }
  nextTick(() => refreshChart())
})

// Labels also change when the devices store resolves asset names for
// already-rendered nodes; refresh the chart without a full re-init.
watch(nodeLabelSignature, () => {
  if (!chartInstance) {
    nextTick(() => initChart())
    return
  }
  nextTick(() => refreshChart())
})

/** Expose reinit so the parent can trigger a redraw on dark-mode toggle. */
defineExpose({ reinit: initChart })
</script>

<style scoped lang="scss">
.network-graph-card {
  background-color: var(--cd-surface);
  border-color: var(--cd-border);
}

.settings-dialog {
  background-color: var(--cd-surface);
}

.graph-container {
  height: calc(100vh - 240px);
  min-height: 400px;
  width: 100%;
}

.graph-placeholder {
  height: calc(100vh - 240px);
  min-height: 400px;
}

@media (max-width: 1024px) {
  .graph-container,
  .graph-placeholder {
    height: calc(100vh - 260px);
    min-height: 320px;
  }
}
</style>
