<template>
  <div class="feature-plot-grid">
    <template v-if="selectedUci">
      <ConnectionEmptyMetricsHint
        v-if="allFeaturesEmpty && selectedUci"
        :selected-uci="selectedUci"
        :time-range="timeRange"
        @jump="(uci: string) => emit('jump', uci)"
      />

      <div v-else-if="filteredTimeseries.length > 0" class="plot-container plot-grid">
        <div v-for="ts in filteredTimeseries" :key="ts.feature" class="plot-cell" :data-feature="ts.feature">
          <ConnectionFeaturePlot
            :title="featureLabels[ts.feature]"
            :feature-name="ts.feature"
            :data="ts.points"
            :anomaly-intervals="anomalyIntervals"
            :force-scatter="forceScatter"
            :time-range="timeRange"
            :show-envelope="showEnvelope"
            :affected="affectedFeatures.includes(ts.feature)"
          />
        </div>
      </div>

      <div v-else class="placeholder column items-center justify-center">
        <q-icon name="show_chart" size="48px" color="grey-6" class="q-mb-sm" />
        <div class="text-subtitle1 text-grey-6">No feature data to display</div>
        <div class="text-body2 text-grey-5 q-mt-sm">Try enabling more features in the settings above</div>
      </div>
    </template>

    <template v-else>
      <div class="placeholder column items-center justify-center">
        <q-icon :name="DOMAIN_ICONS.connections" size="64px" color="grey-6" class="q-mb-md" />
        <div class="text-h6 text-grey-6">Select a connection to view feature plots</div>
        <div class="text-body2 text-grey-5 q-mt-sm">
          Click on a row in the connection table to display timeseries data
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import type { FeatureTimeseries, FeatureName, AnomalyInterval, EnvelopeMode } from '~/types/golden-data'

/**
 * Grid of feature timeseries plots for a selected connection.
 *
 * Supports configurable grid columns, plot height presets, and
 * feature visibility toggling via the settings menu.
 * Offers both grid and stacked list layout modes.
 * Displays a placeholder when no connection is selected.
 */
const props = defineProps<{
  selectedUci: string | null
  allTimeseries: FeatureTimeseries[]
  featureLabels: Record<FeatureName, string>
  defaultFeatures?: FeatureName[]
  anomalyIntervals?: AnomalyInterval[]
  forceScatter?: boolean
  timeRange?: { start: string; stop: string }
  affectedFeatures?: string[]
}>()

const emit = defineEmits<{
  (e: 'jump', uci: string): void
}>()

const visibleFeatures = defineModel<FeatureName[]>('visibleFeatures', { required: true })
const columns = defineModel<number>('columns', { required: true })
const plotSize = defineModel<string>('plotSize', { required: true })
const showEnvelope = defineModel<EnvelopeMode>('showEnvelope', { required: true })
defineModel<boolean>('showPortColumn', { required: true })
defineModel<number>('sampleMaxPoints', { required: true })

const PLOT_SIZE_MAP: Record<string, number> = {
  compact: 180,
  normal: 250,
  large: 360,
}


const filteredTimeseries = computed(() =>
  props.allTimeseries.filter((ts) => visibleFeatures.value.includes(ts.feature)),
)
const affectedFeatures = computed(() => props.affectedFeatures ?? [])

/**
 * True when features are loaded but every visible feature has an empty data array.
 */
const allFeaturesEmpty = computed<boolean>(() => {
  if (filteredTimeseries.value.length === 0) return false
  return filteredTimeseries.value.every((ts) => ts.points.length === 0)
})

const plotHeightPx = computed(() => `${PLOT_SIZE_MAP[plotSize.value] || 250}px`)

const gridColumnsStyle = computed(() => `repeat(${columns.value}, 1fr)`)

watch(plotSize, async () => {
  await nextTick()
  window.dispatchEvent(new Event('resize'))
})

watch(columns, async () => {
  await nextTick()
  window.dispatchEvent(new Event('resize'))
})
</script>

<style scoped lang="scss">
.feature-plot-grid {
  height: 100%;
  display: flex;
  flex-direction: column;
  padding: $spacing-sm;
}

.plot-container {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
}

.plot-grid {
  display: grid;
  grid-template-columns: v-bind(gridColumnsStyle);
  grid-auto-rows: v-bind(plotHeightPx);
  gap: $spacing-xs;
}

.plot-grid .plot-cell {
  min-height: 0;
  overflow: hidden;
}

.placeholder {
  height: 100%;
  min-height: 400px;
  text-align: center;
}
</style>
