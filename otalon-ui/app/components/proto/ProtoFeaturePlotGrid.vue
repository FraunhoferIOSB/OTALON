<template>
  <div class="feature-plot-grid">
    <template v-if="selectedProtoId">
      <div v-if="allFeaturesEmpty" class="placeholder column items-center justify-center">
        <q-icon name="hourglass_empty" size="48px" color="grey-6" class="q-mb-sm" />
        <div class="text-subtitle1 text-grey-6">No measurements in the selected time range</div>
        <div class="text-body2 text-grey-5 q-mt-sm">
          Try widening the time window or switching to a longer live interval
        </div>
      </div>

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
        <q-icon :name="DOMAIN_ICONS.protocols" size="64px" color="grey-6" class="q-mb-md" />
        <div class="text-h6 text-grey-6">Select a protocol to view feature plots</div>
        <div class="text-body2 text-grey-5 q-mt-sm">Click on a row in the table to display timeseries data</div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import type { FeatureTimeseries, FeatureName, AnomalyInterval, EnvelopeMode } from '~/types/golden-data'
import { DOMAIN_ICONS } from '~/composables/useNavigation'

const props = defineProps<{
  selectedProtoId: string | null
  selectedProtoLabel: string | null
  allTimeseries: FeatureTimeseries[]
  featureLabels: Record<FeatureName, string>
  defaultFeatures?: FeatureName[]
  anomalyIntervals?: AnomalyInterval[]
  forceScatter?: boolean
  timeRange?: { start: string; stop: string }
  affectedFeatures?: string[]
}>()

const visibleFeatures = defineModel<FeatureName[]>('visibleFeatures', { required: true })
const columns = defineModel<number>('columns', { required: true })
const plotSize = defineModel<string>('plotSize', { required: true })
const showEnvelope = defineModel<EnvelopeMode>('showEnvelope', { required: true })
defineModel<boolean>('showIdColumn', { default: false })
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
