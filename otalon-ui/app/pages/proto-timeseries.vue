<template>
  <div>
    <q-page class="proto-timeseries-page time-toolbar-page">
      <SharedTimeToolbarRow toolbar-class="col" @update="onTimeUpdate">
        <div class="alarm-filter-panel row items-center no-wrap q-gutter-x-sm">
          <span class="alarm-filter-label text-caption text-muted">Alarm Filter</span>
          <q-select
            v-model="selectedAlarmGroupId"
            :options="alarmGroupOptions"
            option-value="value"
            option-label="label"
            emit-value
            map-options
            dense
            outlined
            clearable
            placeholder="All"
            class="alarm-filter-select"
          >
            <template #prepend>
              <q-icon name="warning_amber" size="18px" />
            </template>
            <template #no-option>
              <q-item>
                <q-item-section class="text-grey">No alarms in time range</q-item-section>
              </q-item>
            </template>
          </q-select>
        </div>
        <q-btn flat dense round icon="tune" aria-label="Display settings" @click="displayDialogOpen = true" />
      </SharedTimeToolbarRow>

      <SharedErrorBanner
        :message="protoSourcesStore.error ?? protoTimeseriesStore.error"
        @retry="reload()"
        @dismiss="dismissError()"
      />

      <div class="splitter-wrapper" style="position: relative">
        <q-inner-loading
          :showing="protoSourcesStore.isLoading && protoSourcesStore.protos.length === 0"
          label="Loading protocols…"
        />

        <q-splitter
          v-show="protoSourcesStore.protos.length > 0 || !protoSourcesStore.isLoading"
          v-model="splitterModel"
          :limits="[20, 60]"
          class="proto-timeseries-splitter"
        >
          <template #before>
            <div class="panel-left q-pa-sm">
              <ProtoSelectorTable
                v-model:show-silent-profiled="boundShowSilentProfiled"
                :protos="selectableProtos"
                :initial-proto-id="initialProtoId"
                :show-id-column="boundShowIdColumn"
                :silent-profiled-count="protoTimeseriesStore.silentProfiledCount"
                @select="onProtoSelect"
              />
            </div>
          </template>

          <template #after>
            <div class="panel-right">
              <SharedPanelSubjectHeading
                :label="selectedProtoLabel"
                :raw-id="protoSourcesStore.selectedProtoId"
                noun="protocol"
                :icon="DOMAIN_ICONS.protocols"
                :affected-features="selectedSeriesAlarmBadge.features"
                :affected-feature-state="selectedSeriesAlarmBadge.state"
                :feature-labels="featureLabels"
                :visible-features="boundVisibleFeatures"
                :rhythm-anomaly="selectedAlarmRhythmAnomaly"
                @reveal-feature="revealFeature"
              />
              <ConnectionRhythmLane
                v-if="frequencySeriesId && displaySettings.featureToggles.rhythmVisible"
                :selected-uci="frequencySeriesId"
                :arrival-times="arrivalTimes"
                :time-range="chartTimeRange"
                :affected-features="selectedAlarmAffectedFeatures"
                :windows-visible="displaySettings.featureToggles.windowsVisible"
                :forecast-visible="displaySettings.featureToggles.forecastVisible"
                module="proto_traffic"
              />
              <ProtoFeaturePlotGrid
                v-model:visible-features="boundVisibleFeatures"
                v-model:columns="boundGridColumns"
                v-model:plot-size="boundPlotSize"
                v-model:show-envelope="boundShowEnvelope"
                v-model:show-id-column="boundShowIdColumn"
                v-model:sample-max-points="boundSampleMaxPoints"
                :selected-proto-id="protoSourcesStore.selectedProtoId"
                :selected-proto-label="selectedProtoLabel"
                :all-timeseries="allTimeseries"
                :feature-labels="featureLabels"
                :default-features="protoTimeseriesStore.defaultVisibleFeatures"
                :anomaly-intervals="mappedAnomalyIntervals"
                :time-range="chartTimeRange"
              />
            </div>
          </template>
        </q-splitter>
      </div>
    </q-page>
    <SharedDisplaySettingsDialog
      v-model="displaySettings"
      v-model:open="displayDialogOpen"
      :table-columns="[]"
      :feature-toggles="featureToggles"
      :feature-names="Object.keys(featureLabels)"
      :feature-labels="featureLabels"
      :default-features="protoTimeseriesStore.defaultVisibleFeatures"
      :visible-features="boundVisibleFeatures"
      :grid-columns="boundGridColumns"
      :plot-size="boundPlotSize"
      :sample-max-points="boundSampleMaxPoints"
      :show-id-column="boundShowIdColumn"
      @update:visible-features="boundVisibleFeatures = $event"
      @update:grid-columns="boundGridColumns = $event"
      @update:plot-size="boundPlotSize = $event"
      @update:sample-max-points="boundSampleMaxPoints = $event"
      @update:show-id-column="boundShowIdColumn = $event"
      @commit="persistDisplaySettings"
    />
  </div>
</template>

<script setup lang="ts">
import type { FeatureTimeseries, FeatureName, AnomalyInterval, EnvelopeMode } from '~/types/golden-data'
import { useProtoSourcesStore } from '~/stores/protoSourcesStore'
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import { useProtoTimeseriesStore } from '~/stores/protoTimeseriesStore'
import { useAlarmsStore } from '~/stores/alarmsStore'
import { useAppStore } from '~/stores/appStore'
import { useFrequencyStore } from '~/stores/frequencyStore'
import { buildProtoAlarmSets, isProtoAnomalous } from '~/utils/proto-match'
import { protoComparisonKey, protoFrequencySeriesId, protoLabelFromSeriesId } from '~/utils/protoHash'
import { provideChatContext } from '~/composables/useChatContext'
import { buildProtoTimeseriesContribution, buildTimeseriesSummary } from '~/utils/chatContext'
import type { FeatureToggleDefinition } from '~/components/shared/DisplaySettingsDialog.vue'
import { useDisplaySettings } from '~/composables/useDisplaySettings'
import { buildProtocolItems } from '~/utils/protocol'
import { getSelectedSeriesAlarmBadge } from '~/utils/alarm-badge'

definePageMeta({
  title: 'Protocols',
})

const route = useRoute()
const appStore = useAppStore()
const protoSourcesStore = useProtoSourcesStore()
const protoTimeseriesStore = useProtoTimeseriesStore()
const alarmsStore = useAlarmsStore()
const frequencyStore = useFrequencyStore()

/**
 * Detection module whose frequency profiles this page inspects.
 */
const FREQUENCY_MODULE = 'proto_traffic' as const

const splitterModel = ref(35)
const featureToggles: FeatureToggleDefinition[] = [
  { value: 'rhythmVisible', label: 'CADENCE widget', defaultValue: true },
  { value: 'windowsVisible', label: 'Windows', defaultValue: false },
  { value: 'forecastVisible', label: 'Forecast', defaultValue: true },
]
const {
  settings: displaySettings,
  dialogOpen: displayDialogOpen,
  persist: persistDisplaySettings,
} = useDisplaySettings({
  storageKey: 'proto-timeseries:displaySettings',
  columnDefaults: {},
  featureToggleDefaults: { rhythmVisible: true, windowsVisible: false, forecastVisible: true },
})

const initialProtoId = computed(() => (route.query.proto as string) ?? '')
const initialAlarmGroup = computed(() => (route.query.alarmGroup as string) ?? '')
const initialAlarmProtoId = computed(() => (route.query.alarmProtoId as string) ?? '')

const FEATURE_LABELS: Record<string, string> = {
  proto_conn_count: 'Conn Count',
  proto_total_packets: 'Total Packets',
  proto_total_volume: 'Total Volume',
  proto_unique_src_mac: 'Unique Src MAC',
  proto_unique_dst_mac: 'Unique Dst MAC',
  proto_unique_mac_pairs: 'Unique MAC Pairs',
  proto_mean_packets_per_conn: 'Mean Packets/Conn',
  proto_mean_volume_per_conn: 'Mean Volume/Conn',
  proto_mean_packet_size: 'Mean Packet Size',
  proto_std_packet_size: 'Std Packet Size',
}

const featureLabels = computed<Record<FeatureName, string>>(() => {
  return FEATURE_LABELS as Record<FeatureName, string>
})

const lastFetchParams = ref(appStore.freshApiTimeParams())
const chartTimeRange = ref(appStore.freshApiTimeParams())

const boundVisibleFeatures = computed<FeatureName[]>({
  get: () => protoTimeseriesStore.visibleFeatures as FeatureName[],
  set: (val: FeatureName[]) => protoTimeseriesStore.setVisibleFeatures(val),
})

function revealFeature(feature: string): void {
  if (boundVisibleFeatures.value.includes(feature as FeatureName)) return
  boundVisibleFeatures.value = [...boundVisibleFeatures.value, feature as FeatureName]
}

const boundGridColumns = computed<number>({
  get: () => protoTimeseriesStore.gridColumns,
  set: (val: number) => protoTimeseriesStore.setGridColumns(val),
})

const boundPlotSize = computed<string>({
  get: () => protoTimeseriesStore.plotSize,
  set: (val: string) => protoTimeseriesStore.setPlotSize(val),
})

const boundShowEnvelope = computed<EnvelopeMode>({
  get: () => protoTimeseriesStore.showEnvelope,
  set: (val: EnvelopeMode) => protoTimeseriesStore.setShowEnvelope(val),
})

const boundShowIdColumn = computed<boolean>({
  get: () => protoSourcesStore.showIdColumn,
  set: (val: boolean) => protoSourcesStore.setShowIdColumn(val),
})
const boundSampleMaxPoints = computed<number>({
  get: () => protoTimeseriesStore.sampleMaxPoints,
  set: (val: number) => {
    protoTimeseriesStore.setSampleMaxPoints(val)
    void softReload()
  },
})

const boundShowSilentProfiled = computed<boolean>({
  get: () => protoTimeseriesStore.showSilentProfiled,
  set: (value: boolean) => protoTimeseriesStore.setShowSilentProfiled(value),
})

const allTimeseries = computed<FeatureTimeseries[]>(() => {
  const plotData = protoTimeseriesStore.visiblePlotData
  return Object.entries(plotData).map(([feature, data]) => ({
    feature: feature as FeatureName,
    points: data.map((item) => ({
      time: item.time,
      value: item.value ?? 0,
      upper_bound: item.upper_bound,
      lower_bound: item.lower_bound,
      value_min: item.value_min ?? null,
      value_max: item.value_max ?? null,
      violation_low: item.violation_low,
      violation_high: item.violation_high,
    })),
  }))
})

const mappedAnomalyIntervals = computed<AnomalyInterval[]>(() => {
  return protoTimeseriesStore.anomalyIntervals.map((item) => ({
    start: item.start_timestamp,
    end: item.end_timestamp,
    label: item.anomaly_type ?? undefined,
  }))
})

const selectedAlarmGroupId = ref<string | null>(null)
const selectedAlarmAffectedFeatures = computed<string[]>(() => {
  const group = alarmsStore.groups.find((item) => item.id === selectedAlarmGroupId.value)
  if (!group) return []
  const cache = alarmsStore.affectedFeaturesByGroup[group.id]
  const selectedId = protoSourcesStore.selectedProtoId
  const selectedProtocol = protoSourcesStore.selectedProtoItem?.protocol
  const seriesId = group.series_ids.includes(selectedId ?? '')
    ? selectedId
    : group.series_ids.includes(selectedProtocol ?? '')
      ? selectedProtocol
      : selectedId
  return cache?.bySeries[seriesId ?? '']?.features ?? []
})
watch(
  selectedAlarmAffectedFeatures,
  (features) => {
    if (features.length === 0) return
    features.forEach(revealFeature)
  },
  { immediate: true },
)
const selectedAlarmRhythmAnomaly = computed<boolean>(() => {
  const group = alarmsStore.groups.find((item) => item.id === selectedAlarmGroupId.value)
  if (!group) return false
  const cache = alarmsStore.affectedFeaturesByGroup[group.id]
  const selectedId = protoSourcesStore.selectedProtoId
  const selectedProtocol = protoSourcesStore.selectedProtoItem?.protocol
  const seriesId = group.series_ids.includes(selectedId ?? '')
    ? selectedId
    : group.series_ids.includes(selectedProtocol ?? '')
      ? selectedProtocol
      : selectedId
  return cache?.bySeries[seriesId ?? '']?.rhythmAnomaly ?? false
})
const selectedSeriesAlarmBadge = computed(() =>
  getSelectedSeriesAlarmBadge(alarmsStore.groups, alarmsStore.affectedFeaturesByGroup, [
    protoSourcesStore.selectedProtoId ?? '',
    protoSourcesStore.selectedProtoItem?.protocol ?? '',
  ]),
)

const alarmGroupOptions = computed(() => {
  return alarmsStore.groups.map((g) => ({
    label: `${g.primary_type} (${buildProtocolItems(g.series_ids, g.protocols ?? []).length} protocols)`,
    value: g.id,
  }))
})

const protoAlarmSets = computed(() => buildProtoAlarmSets(alarmsStore.groups))
const anomalousProtoIds = computed(() => protoAlarmSets.value.anomalousIds)
const groupProtocolMap = computed(() => protoAlarmSets.value.groupProtocolMap)

const enrichedProtos = computed(() => {
  const ids = anomalousProtoIds.value
  if (!selectedAlarmGroupId.value) {
    return protoSourcesStore.protos.map((p) => ({
      ...p,
      state: isProtoAnomalous(p, ids) ? 'anomaly' : 'normal',
    }))
  }
  const affectedIds = groupProtocolMap.value.get(selectedAlarmGroupId.value)
  if (!affectedIds) {
    return protoSourcesStore.protos.map((p) => ({
      ...p,
      state: isProtoAnomalous(p, ids) ? 'anomaly' : 'normal',
    }))
  }
  return protoSourcesStore.protos
    .filter((p) => isProtoAnomalous(p, affectedIds))
    .map((p) => ({ ...p, state: isProtoAnomalous(p, ids) ? 'anomaly' : 'normal' }))
})

const selectableProtos = computed(() => {
  if (!protoTimeseriesStore.showSilentProfiled) return enrichedProtos.value
  // Profiles are keyed by hash while the rows carry readable stacks, so a
  // silent protocol would otherwise render as a bare number (UI-093).
  const knownStacks = protoSourcesStore.protos.map((proto) => proto.protocol || proto.id)
  const live = new Set(enrichedProtos.value.map((proto) => protoComparisonKey(proto.protocol || proto.id, knownStacks)))
  return [
    ...enrichedProtos.value,
    ...protoTimeseriesStore.profiledProtocols
      .filter((id) => !live.has(protoComparisonKey(id, knownStacks)))
      .map((id) => ({
        id,
        protocol: protoLabelFromSeriesId(id, knownStacks),
        presence: 'silent' as const,
        state: 'normal' as const,
      })),
  ]
})

const selectedProtoLabel = computed(() => {
  const item = protoSourcesStore.selectedProtoItem
  if (!item) return null
  return item.protocol || item.id
})

/**
 * Identifier the frequency detector keys the selected protocol by.
 *
 * The page selects a READABLE protocol stack (API-011 made
 * `/timeseries/proto/ids` return e.g. `"Ethernet:LLDP"` as the row id),
 * but `proto_traffic` frequency profiles are persisted under a stable
 * hash of that stack. Unlike `/anomalies/proto/intervals`, the
 * frequency endpoint matches `series_id` verbatim and does no
 * translation, so the readable stack must be hashed here — otherwise
 * every protocol reports "No profile" while 15 profiles exist.
 */
const frequencySeriesId = computed<string | null>(() => {
  const id = protoSourcesStore.selectedProtoId
  return id ? protoFrequencySeriesId(id) : null
})

/**
 * Arrival timestamps for the RHYTHM lane markers.
 *
 * Reuses the packet series already loaded for the feature grid, so the
 * lane introduces no second timeseries request. Buckets with no packets
 * are not arrivals and are filtered out.
 */
const arrivalTimes = computed<string[]>(() => {
  const data = protoTimeseriesStore.plotData['proto_total_packets']
  if (!data) return []
  return data.filter((p) => (p.value ?? 0) > 0).map((p) => p.time)
})

async function loadInitialData(): Promise<void> {
  const params = appStore.freshApiTimeParams()
  lastFetchParams.value = params
  chartTimeRange.value = params
  const { start, stop } = params

  await Promise.allSettled([
    protoSourcesStore.fetchProtos(start, stop),
    protoTimeseriesStore.fetchProfiledProtocols(),
    protoTimeseriesStore.fetchFeatures(),
    alarmsStore.fetchGroups({ module: undefined }, { start, stop }),
  ])
  protoTimeseriesStore.setLiveProtocols(protoSourcesStore.protos.map((proto) => proto.id))
  protoTimeseriesStore.setLiveProtocols(protoSourcesStore.protos.map((proto) => proto.id))
}

async function reload(): Promise<void> {
  await loadInitialData()
  if (protoSourcesStore.selectedProtoId) {
    const params = lastFetchParams.value
    chartTimeRange.value = params
    const { start, stop } = params
    await Promise.allSettled([
      protoTimeseriesStore.fetchAllForProto(protoSourcesStore.selectedProtoId, start, stop),
      frequencyStore.fetchProfile(protoFrequencySeriesId(protoSourcesStore.selectedProtoId), FREQUENCY_MODULE),
    ])
  }
}

function dismissError(): void {
  protoSourcesStore.error = null
  protoTimeseriesStore.error = null
}

function onProtoSelect(protoItem: { id: string } | null): void {
  if (protoItem) {
    protoSourcesStore.selectProto(protoItem.id)
    const params = lastFetchParams.value
    chartTimeRange.value = params
    const { start, stop } = params
    protoTimeseriesStore.fetchAllForProto(protoItem.id, start, stop)
    frequencyStore.fetchProfile(protoFrequencySeriesId(protoItem.id), FREQUENCY_MODULE)
  } else {
    protoSourcesStore.selectProto(null)
    protoTimeseriesStore.plotData = {}
    protoTimeseriesStore.anomalyIntervals = []
    frequencyStore.clear()
  }
}

async function softReload(): Promise<void> {
  const params = appStore.freshApiTimeParams()
  lastFetchParams.value = params
  chartTimeRange.value = params
  const { start, stop } = params
  await Promise.allSettled([
    protoSourcesStore.fetchProtos(start, stop),
    ...(protoTimeseriesStore.showSilentProfiled ? [protoTimeseriesStore.fetchProfiledProtocols()] : []),
    alarmsStore.fetchGroups({ module: undefined }, { start, stop }),
  ])
  if (protoSourcesStore.selectedProtoId) {
    await Promise.allSettled([
      protoTimeseriesStore.fetchAllForProto(protoSourcesStore.selectedProtoId, start, stop),
      frequencyStore.fetchProfile(protoFrequencySeriesId(protoSourcesStore.selectedProtoId), FREQUENCY_MODULE),
    ])
  }
}

function onTimeUpdate(): void {
  softReload()
}

async function pollLiveData(): Promise<void> {
  const params = appStore.freshApiTimeParams()
  lastFetchParams.value = params
  chartTimeRange.value = params
  const { start, stop } = params

  alarmsStore.fetchGroups({ module: undefined }, { start, stop })
  protoSourcesStore.fetchProtos(start, stop)
  if (protoTimeseriesStore.showSilentProfiled) protoTimeseriesStore.fetchProfiledProtocols()

  if (!protoSourcesStore.selectedProtoId) return
  if (protoTimeseriesStore.isLoading) return
  await Promise.allSettled([
    protoTimeseriesStore.fetchAllForProto(protoSourcesStore.selectedProtoId, start, stop),
    frequencyStore.fetchProfile(protoFrequencySeriesId(protoSourcesStore.selectedProtoId), FREQUENCY_MODULE),
  ])
}

const liveEnabled = computed(() => appStore.liveMode)
const pollingInterval = computed(() => appStore.pollingIntervalMs)
usePolling(pollLiveData, pollingInterval, { enabled: liveEnabled })

watch(
  () => appStore.liveIntervalSeconds,
  () => {
    if (!appStore.liveMode) return
    softReload()
  },
)

const deepLinkApplied = ref(false)

watch(
  () => alarmsStore.groups,
  (groups) => {
    if (deepLinkApplied.value) return
    if (groups.length === 0) return
    if (!initialAlarmGroup.value && !initialAlarmProtoId.value) {
      deepLinkApplied.value = true
      return
    }

    if (initialAlarmGroup.value) {
      const match = groups.find((g) => String(g.id) === initialAlarmGroup.value)
      if (match) {
        selectedAlarmGroupId.value = match.id
        deepLinkApplied.value = true
        return
      }
    }

    if (initialAlarmProtoId.value) {
      const match = groups.find(
        (g) =>
          g.series_ids.includes(initialAlarmProtoId.value) || (g.protocols ?? []).includes(initialAlarmProtoId.value),
      )
      if (match) {
        selectedAlarmGroupId.value = match.id
        deepLinkApplied.value = true
      }
    }
  },
  { immediate: true },
)

const router = useRouter()
watch(selectedAlarmGroupId, (val, prev) => {
  if (prev != null && val == null && (route.query.alarmGroup || route.query.alarmProtoId)) {
    const cleaned = { ...route.query }
    delete cleaned.alarmGroup
    delete cleaned.alarmProtoId
    router.replace({ path: route.path, query: cleaned })
  }
})

onMounted(() => {
  loadInitialData()
})

/**
 * Release the shared frequency state when leaving the page.
 *
 * The frequency store is a singleton used by the connections, Assets
 * and Protocols pages alike. Clearing on unmount keeps a stale
 * `proto_traffic` profile from being the store's content while another
 * page's lane mounts, and stops an in-flight request from landing after
 * the page is gone.
 */
onUnmounted(() => {
  frequencyStore.clear()
})

provideChatContext(() => {
  const protoItem = protoSourcesStore.selectedProtoItem
  const contrib = buildProtoTimeseriesContribution({
    protos: enrichedProtos.value.map((p) => ({
      id: p.id,
      label: p.protocol || p.id,
      isAnomalous: p.state === 'anomaly',
    })),
    selectedProto: protoItem ? { id: protoItem.id, label: protoItem.protocol || protoItem.id } : null,
    filters: {
      alarm_group_id: selectedAlarmGroupId.value ?? null,
    },
    totalProtos: protoSourcesStore.protos.length,
  })

  if (protoItem) {
    const summaryTable = buildTimeseriesSummary({
      seriesId: protoItem.id,
      plotData: protoTimeseriesStore.visiblePlotData,
      featureLabels: FEATURE_LABELS,
    })
    contrib.visible_data = [...(contrib.visible_data ?? []), ...summaryTable]
  }

  return contrib
})
</script>

<style scoped lang="scss">
.proto-timeseries-page {
  display: flex;
  flex-direction: column;
  padding: $spacing-md;
  height: calc(100dvh - var(--cd-header-height, 51px));
  overflow: hidden;
}

.alarm-filter-panel {
  padding: 6px 12px;
  border-radius: $border-radius-md;
  background-color: var(--cd-surface);
  border: 1px solid var(--cd-border);
  flex-shrink: 0;
}

.alarm-filter-label {
  font-weight: 700;
  font-size: 12px;
  letter-spacing: 0.8px;
  white-space: nowrap;
}

.alarm-filter-select {
  min-width: 220px;

  :deep(.q-field__control) {
    min-height: 32px;
  }
}

.splitter-wrapper {
  flex: 1;
  min-height: 0;
  overflow: hidden;
}

.proto-timeseries-splitter {
  height: 100%;

  :deep(.q-splitter__before),
  :deep(.q-splitter__after) {
    overflow: hidden;
  }

  :deep(.q-splitter__separator) {
    background-color: var(--cd-border);
    width: 3px;

    &:hover {
      background-color: var(--q-primary);
    }
  }
}

.panel-left {
  height: 100%;
  overflow-y: auto;
}

.panel-right {
  height: 100%;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

/* The rhythm lane is a fixed-height strip; the feature grid keeps taking
   all remaining height so its own layout is untouched. */
.panel-right > .rhythm-lane {
  margin: $spacing-sm $spacing-sm 0;
}

.panel-right > .feature-plot-grid {
  flex: 1;
  min-height: 0;
}
</style>
