<template>
  <div>
    <q-page class="mac-timeseries-page time-toolbar-page">
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
        :message="macSourcesStore.error ?? macTimeseriesStore.error"
        @retry="reload()"
        @dismiss="dismissError()"
      />

      <div class="splitter-wrapper" style="position: relative">
        <q-inner-loading
          :showing="macSourcesStore.isLoading && macSourcesStore.macs.length === 0"
          label="Loading MAC addresses…"
        />

        <q-splitter
          v-show="macSourcesStore.macs.length > 0 || !macSourcesStore.isLoading"
          v-model="splitterModel"
          :limits="[20, 60]"
          class="mac-timeseries-splitter"
        >
          <template #before>
            <div class="panel-left q-pa-sm">
              <MacSelectorTable
                v-model:show-silent-profiled="boundShowSilentProfiled"
                :macs="selectableMacs"
                :initial-mac="initialMac"
                :visible-columns="boundVisibleTableColumns"
                :silent-profiled-count="macTimeseriesStore.silentProfiledCount"
                @select="onMacSelect"
              />
            </div>
          </template>

          <template #after>
            <div class="panel-right">
              <SharedPanelSubjectHeading
                :label="selectedMacLabel"
                :raw-id="macSourcesStore.selectedMac"
                noun="asset"
                :icon="DOMAIN_ICONS.assets"
                :affected-features="selectedSeriesAlarmBadge.features"
                :affected-feature-state="selectedSeriesAlarmBadge.state"
                :feature-labels="featureLabels"
                :visible-features="boundVisibleFeatures"
                :rhythm-anomaly="selectedAlarmRhythmAnomaly"
                @reveal-feature="revealFeature"
              />
              <ConnectionRhythmLane
                v-if="macSourcesStore.selectedMac && displaySettings.featureToggles.rhythmVisible"
                :selected-uci="macSourcesStore.selectedMac"
                :arrival-times="arrivalTimes"
                :time-range="chartTimeRange"
                :affected-features="selectedAlarmAffectedFeatures"
                :windows-visible="displaySettings.featureToggles.windowsVisible"
                :forecast-visible="displaySettings.featureToggles.forecastVisible"
                module="mac_traffic"
              />
              <MacFeaturePlotGrid
                v-model:visible-features="boundVisibleFeatures"
                v-model:columns="boundGridColumns"
                v-model:plot-size="boundPlotSize"
                v-model:show-envelope="boundShowEnvelope"
                v-model:visible-table-columns="boundVisibleTableColumns"
                v-model:sample-max-points="boundSampleMaxPoints"
                :selected-mac="macSourcesStore.selectedMac"
                :all-timeseries="allTimeseries"
                :feature-labels="featureLabels"
                :default-features="macTimeseriesStore.defaultVisibleFeatures"
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
      :default-features="macTimeseriesStore.defaultVisibleFeatures"
      :visible-features="boundVisibleFeatures"
      :grid-columns="boundGridColumns"
      :plot-size="boundPlotSize"
      :sample-max-points="boundSampleMaxPoints"
      :visible-table-columns="boundVisibleTableColumns"
      @update:visible-features="boundVisibleFeatures = $event"
      @update:grid-columns="boundGridColumns = $event"
      @update:plot-size="boundPlotSize = $event"
      @update:sample-max-points="boundSampleMaxPoints = $event"
      @update:visible-table-columns="boundVisibleTableColumns = $event"
      @commit="persistDisplaySettings"
    />
  </div>
</template>

<script setup lang="ts">
import type { FeatureTimeseries, FeatureName, AnomalyInterval, EnvelopeMode } from '~/types/golden-data'
import type { DeviceItem } from '~/types/api'
import type { MacSourceItem } from '~/stores/macSourcesStore'
import { buildAnomalousMacSet, extractAlarmMacs, groupAffectsMac } from '~/utils/mac-match'
import { useMacSourcesStore } from '~/stores/macSourcesStore'
import { useMacTimeseriesStore } from '~/stores/macTimeseriesStore'
import { useFrequencyStore } from '~/stores/frequencyStore'
import { useDevicesStore } from '~/stores/devicesStore'
import { useAppStore } from '~/stores/appStore'
import { useAlarmsStore } from '~/stores/alarmsStore'
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import { provideChatContext } from '~/composables/useChatContext'
import { buildMacTimeseriesContribution, buildTimeseriesSummary } from '~/utils/chatContext'
import type { FeatureToggleDefinition } from '~/components/shared/DisplaySettingsDialog.vue'
import { useDisplaySettings } from '~/composables/useDisplaySettings'
import { getSelectedSeriesAlarmBadge } from '~/utils/alarm-badge'

definePageMeta({
  title: 'Assets',
})

const route = useRoute()
const appStore = useAppStore()
const macSourcesStore = useMacSourcesStore()
const macTimeseriesStore = useMacTimeseriesStore()
const devicesStore = useDevicesStore()
const alarmsStore = useAlarmsStore()
const frequencyStore = useFrequencyStore()

/**
 * Detection module whose frequency profiles this page inspects.
 *
 * `mac_traffic` series ids ARE the MAC addresses the page selects, so
 * the selected row id is passed to the frequency store unchanged.
 */
const FREQUENCY_MODULE = 'mac_traffic' as const

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
  storageKey: 'mac-timeseries:displaySettings',
  columnDefaults: {},
  featureToggleDefaults: { rhythmVisible: true, windowsVisible: false, forecastVisible: true },
})
const selectedAlarmGroupId = ref<string | null>(null)
const selectedAlarmAffectedFeatures = computed<string[]>(() => {
  const group = alarmsStore.groups.find((item) => item.id === selectedAlarmGroupId.value)
  return group
    ? (alarmsStore.affectedFeaturesByGroup[group.id]?.bySeries[macSourcesStore.selectedMac ?? '']?.features ?? [])
    : []
})
const selectedAlarmRhythmAnomaly = computed<boolean>(() => {
  const group = alarmsStore.groups.find((item) => item.id === selectedAlarmGroupId.value)
  return group
    ? (alarmsStore.affectedFeaturesByGroup[group.id]?.bySeries[macSourcesStore.selectedMac ?? '']?.rhythmAnomaly ??
        false)
    : false
})
const selectedSeriesAlarmBadge = computed(() =>
  getSelectedSeriesAlarmBadge(alarmsStore.groups, alarmsStore.affectedFeaturesByGroup, [macSourcesStore.selectedMac ?? '']),
)

const initialMac = computed(() => (route.query.mac as string) ?? '')
const initialAlarmGroup = computed(() => (route.query.alarmGroup as string) ?? '')

const FEATURE_LABELS: Record<string, string> = {
  out_conn_count: 'Out Conn Count',
  out_total_packets: 'Out Total Packets',
  out_total_volume: 'Out Total Volume',
  out_unique_dst_count: 'Out Unique Dst',
  out_unique_proto_count: 'Out Unique Proto',
  in_conn_count: 'In Conn Count',
  in_total_packets: 'In Total Packets',
  in_total_volume: 'In Total Volume',
  in_unique_src_count: 'In Unique Src',
  ratio_in_out_packets: 'Ratio In/Out Packets',
  ratio_in_out_volume: 'Ratio In/Out Volume',
  total_unique_peers: 'Total Unique Peers',
  total_conn_count: 'Total Conn Count',
}

const featureLabels = computed<Record<FeatureName, string>>(() => {
  return FEATURE_LABELS as Record<FeatureName, string>
})

const lastFetchParams = ref(appStore.freshApiTimeParams())
const chartTimeRange = ref(appStore.freshApiTimeParams())

const boundVisibleFeatures = computed<FeatureName[]>({
  get: () => macTimeseriesStore.visibleFeatures as FeatureName[],
  set: (val: FeatureName[]) => macTimeseriesStore.setVisibleFeatures(val),
})

function revealFeature(feature: string): void {
  if (boundVisibleFeatures.value.includes(feature as FeatureName)) return
  boundVisibleFeatures.value = [...boundVisibleFeatures.value, feature as FeatureName]
}

watch(
  selectedAlarmAffectedFeatures,
  (features) => {
    if (features.length === 0) return
    features.forEach(revealFeature)
  },
  { immediate: true },
)

const boundGridColumns = computed<number>({
  get: () => macTimeseriesStore.gridColumns,
  set: (val: number) => macTimeseriesStore.setGridColumns(val),
})

const boundPlotSize = computed<string>({
  get: () => macTimeseriesStore.plotSize,
  set: (val: string) => macTimeseriesStore.setPlotSize(val),
})

const boundShowEnvelope = computed<EnvelopeMode>({
  get: () => macTimeseriesStore.showEnvelope,
  set: (val: EnvelopeMode) => macTimeseriesStore.setShowEnvelope(val),
})

const boundVisibleTableColumns = computed<string[]>({
  get: () => macTimeseriesStore.visibleTableColumns,
  set: (val: string[]) => macTimeseriesStore.setVisibleTableColumns(val),
})
const boundSampleMaxPoints = computed<number>({
  get: () => macTimeseriesStore.sampleMaxPoints,
  set: (val: number) => {
    macTimeseriesStore.setSampleMaxPoints(val)
    void softReload()
  },
})

const boundShowSilentProfiled = computed<boolean>({
  get: () => macTimeseriesStore.showSilentProfiled,
  set: (value: boolean) => macTimeseriesStore.setShowSilentProfiled(value),
})

const alarmGroupOptions = computed(() => {
  return alarmsStore.groups
    .filter((g) => groupAffectsMac(g))
    .map((g) => {
      const macCount = extractAlarmMacs(g).length
      const type = Array.isArray(g.primary_type) ? (g.primary_type[0] ?? '—') : g.primary_type
      return {
        label: `${type} (${macCount} MACs)`,
        value: g.id,
      }
    })
})

const anomalousMacs = computed<Set<string>>(() => buildAnomalousMacSet(alarmsStore.groups))

function isBroadcastOrMulticastMac(mac: string): boolean {
  const cleaned = mac.toLowerCase().replace(/[^a-f0-9]/g, '')
  if (cleaned === 'ffffffffffff') return true
  const first = parseInt(cleaned.substring(0, 2), 16)
  return (first & 1) === 1
}

const filteredByAlarm = computed<MacSourceItem[]>(() => {
  const enrich = (m: MacSourceItem): MacSourceItem =>
    anomalousMacs.value.has(m.mac.toLowerCase()) ? { ...m, state: 'anomaly' } : { ...m, state: 'normal' }

  const result = macSourcesStore.macs.filter((m) => !isBroadcastOrMulticastMac(m.mac)).map(enrich)

  if (!selectedAlarmGroupId.value) {
    return result
  }
  const group = alarmsStore.groups.find((g) => g.id === selectedAlarmGroupId.value)
  if (!group) return result
  const affectedMacs = new Set(extractAlarmMacs(group).map((s) => s.toLowerCase()))
  return result.filter((m) => affectedMacs.has(m.mac.toLowerCase()))
})

const selectableMacs = computed<MacSourceItem[]>(() => {
  const live = new Set(filteredByAlarm.value.map((mac) => mac.mac))
  if (!macTimeseriesStore.showSilentProfiled) return filteredByAlarm.value
  return [
    ...filteredByAlarm.value,
    ...macTimeseriesStore.profiledMacs
      .filter((mac) => !live.has(mac) && !isBroadcastOrMulticastMac(mac))
      .map((mac) => ({ mac, name: null, ip: null, presence: 'silent' as const })),
  ]
})

const allTimeseries = computed<FeatureTimeseries[]>(() => {
  const plotData = macTimeseriesStore.visiblePlotData
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
  return macTimeseriesStore.anomalyIntervals.map((item) => ({
    start: item.start_timestamp,
    end: item.end_timestamp,
    label: item.anomaly_type ?? undefined,
  }))
})

/**
 * Arrival timestamps for the RHYTHM lane markers.
 *
 * Reuses a packet series already loaded for the feature grid, so the
 * lane introduces no second timeseries request. Buckets with no packets
 * are not arrivals and are filtered out.
 */
const arrivalTimes = computed<string[]>(() => {
  const data = macTimeseriesStore.plotData['out_total_packets'] ?? macTimeseriesStore.plotData['in_total_packets']
  if (!data) return []
  return data.filter((p) => (p.value ?? 0) > 0).map((p) => p.time)
})

/**
 * Readable name for the selected asset, falling back to its MAC.
 *
 * Operator preference is a label over a raw identifier wherever a label
 * exists; the device inventory supplies hostnames for known assets.
 */
const selectedMacLabel = computed<string | null>(() => {
  const item = macSourcesStore.selectedMacItem
  if (!item) return null
  return item.name || item.mac
})

async function loadInitialData(): Promise<void> {
  const params = appStore.freshApiTimeParams()
  lastFetchParams.value = params
  chartTimeRange.value = params
  const { start, stop } = params

  await Promise.allSettled([
    macSourcesStore.fetchMacs(start, stop),
    macTimeseriesStore.fetchProfiledMacs(),
    macTimeseriesStore.fetchFeatures(),
    devicesStore.fetchDevices(),
    alarmsStore.fetchGroups({ module: undefined }, { start, stop }),
  ])
  macTimeseriesStore.setLiveMacs(macSourcesStore.macs.map((mac) => mac.mac))
  macTimeseriesStore.setLiveMacs(macSourcesStore.macs.map((mac) => mac.mac))

  if (devicesStore.devices.length > 0) {
    macSourcesStore.enrichWithDevices(devicesStore.devices as DeviceItem[])
  }
}

async function reload(): Promise<void> {
  await loadInitialData()
  if (macSourcesStore.selectedMac) {
    const params = lastFetchParams.value
    chartTimeRange.value = params
    const { start, stop } = params
    await Promise.allSettled([
      macTimeseriesStore.fetchAllForMac(macSourcesStore.selectedMac, start, stop),
      frequencyStore.fetchProfile(macSourcesStore.selectedMac, FREQUENCY_MODULE),
    ])
  }
}

function dismissError(): void {
  macSourcesStore.error = null
  macTimeseriesStore.error = null
}

function onMacSelect(macItem: { mac: string } | null): void {
  if (macItem) {
    macSourcesStore.selectMac(macItem.mac)
    const params = lastFetchParams.value
    chartTimeRange.value = params
    const { start, stop } = params
    macTimeseriesStore.fetchAllForMac(macItem.mac, start, stop)
    frequencyStore.fetchProfile(macItem.mac, FREQUENCY_MODULE)
  } else {
    macSourcesStore.selectMac(null)
    macTimeseriesStore.plotData = {}
    macTimeseriesStore.anomalyIntervals = []
    frequencyStore.clear()
  }
}

async function softReload(): Promise<void> {
  const params = appStore.freshApiTimeParams()
  lastFetchParams.value = params
  chartTimeRange.value = params
  const { start, stop } = params
  await Promise.allSettled([
    macSourcesStore.fetchMacs(start, stop),
    ...(macTimeseriesStore.showSilentProfiled ? [macTimeseriesStore.fetchProfiledMacs()] : []),
    alarmsStore.fetchGroups({ module: undefined }, { start, stop }),
  ])
  if (macSourcesStore.selectedMac) {
    await Promise.allSettled([
      macTimeseriesStore.fetchAllForMac(macSourcesStore.selectedMac, start, stop),
      frequencyStore.fetchProfile(macSourcesStore.selectedMac, FREQUENCY_MODULE),
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

  macSourcesStore.fetchMacs(start, stop)
  if (macTimeseriesStore.showSilentProfiled) macTimeseriesStore.fetchProfiledMacs()
  alarmsStore.fetchGroups({ module: undefined }, { start, stop })

  if (!macSourcesStore.selectedMac) return
  if (macTimeseriesStore.isLoading) return
  await Promise.allSettled([
    macTimeseriesStore.fetchAllForMac(macSourcesStore.selectedMac, start, stop),
    frequencyStore.fetchProfile(macSourcesStore.selectedMac, FREQUENCY_MODULE),
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
    if (!initialAlarmGroup.value) {
      deepLinkApplied.value = true
      return
    }

    const match = groups.find((g) => String(g.id) === initialAlarmGroup.value)
    if (match) {
      selectedAlarmGroupId.value = match.id
      deepLinkApplied.value = true
    }
  },
  { immediate: true },
)

const router = useRouter()
watch(selectedAlarmGroupId, (val, prev) => {
  if (prev != null && val == null && route.query.alarmGroup) {
    const cleaned = { ...route.query }
    delete cleaned.alarmGroup
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
 * `mac_traffic` profile from being the store's content while another
 * page's lane mounts, and stops an in-flight request from landing after
 * the page is gone.
 */
onUnmounted(() => {
  frequencyStore.clear()
})

provideChatContext(() => {
  const macItem = macSourcesStore.selectedMacItem
  const contrib = buildMacTimeseriesContribution({
    macs: filteredByAlarm.value.map((m) => ({ mac: m.mac, name: m.name, state: m.state })),
    selectedMac: macItem ? { mac: macItem.mac, name: macItem.name, ip: macItem.ip, state: macItem.state } : null,
    filters: {
      alarm_group_id: selectedAlarmGroupId.value ?? null,
    },
    totalMacs: macSourcesStore.macs.length,
  })

  if (macItem) {
    const summaryTable = buildTimeseriesSummary({
      seriesId: macItem.mac,
      plotData: macTimeseriesStore.visiblePlotData,
      featureLabels: FEATURE_LABELS,
    })
    contrib.visible_data = [...(contrib.visible_data ?? []), ...summaryTable]
  }

  return contrib
})
</script>

<style scoped lang="scss">
.mac-timeseries-page {
  display: flex;
  flex-direction: column;
  padding: $spacing-md;
  height: calc(100dvh - var(--cd-header-height, 51px));
  overflow: hidden;
}

.splitter-wrapper {
  flex: 1;
  min-height: 0;
  overflow: hidden;
}

.mac-timeseries-splitter {
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
</style>
