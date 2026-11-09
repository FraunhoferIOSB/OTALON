<template>
  <div>
    <q-page class="connections-page time-toolbar-page">
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
        :message="connectionsStore.error ?? timeseriesStore.error"
        @retry="reload()"
        @dismiss="dismissError()"
      />

      <div class="splitter-wrapper" style="position: relative">
        <q-inner-loading
          :showing="connectionsStore.isLoading && connectionsStore.connections.length === 0"
          label="Loading connections…"
        />

        <q-splitter
          v-show="connectionsStore.connections.length > 0 || !connectionsStore.isLoading"
          v-model="splitterModel"
          :limits="[20, 60]"
          class="connections-splitter"
        >
          <template #before>
            <div class="panel-left q-pa-sm">
              <ConnectionSelectorTable
                ref="selectorTable"
                v-model:show-silent-profiled="boundShowSilentProfiled"
                :connections="filteredByAlarm"
                :initial-uci="initialUci"
                :initial-device-filter="initialDeviceFilter"
                :show-port-column="boundShowPortColumn"
                :silent-profiled-count="connectionsStore.silentProfiledCount"
                :resolve-label="deviceLookup.labelForEndpoint"
                @select="onConnectionSelect"
              />
            </div>
          </template>

          <template #after>
            <div class="panel-right">
              <SharedPanelSubjectHeading
                :label="selectedConnectionLabel"
                :raw-id="connectionsStore.selectedUci"
                noun="connection"
                :icon="DOMAIN_ICONS.connections"
                :affected-features="selectedSeriesAlarmBadge.features"
                :affected-feature-state="selectedSeriesAlarmBadge.state"
                :feature-labels="featureLabels"
                :visible-features="boundVisibleFeatures"
                :rhythm-anomaly="selectedAlarmRhythmAnomaly"
                @reveal-feature="revealFeature"
              />
              <ConnectionRhythmLane
                v-if="connectionsStore.selectedUci && displaySettings.featureToggles.rhythmVisible"
                :selected-uci="connectionsStore.selectedUci"
                :arrival-times="arrivalTimes"
                :time-range="chartTimeRange"
                :affected-features="selectedAlarmAffectedFeatures"
                :windows-visible="displaySettings.featureToggles.windowsVisible"
                :forecast-visible="displaySettings.featureToggles.forecastVisible"
              />
              <ConnectionFeaturePlotGrid
                v-model:visible-features="boundVisibleFeatures"
                v-model:columns="boundGridColumns"
                v-model:plot-size="boundPlotSize"
                v-model:show-envelope="boundShowEnvelope"
                v-model:show-port-column="boundShowPortColumn"
                v-model:sample-max-points="boundSampleMaxPoints"
                :selected-uci="connectionsStore.selectedUci"
                :all-timeseries="allTimeseries"
                :feature-labels="featureLabels"
                :default-features="timeseriesStore.defaultVisibleFeatures"
                :anomaly-intervals="mappedAnomalyIntervals"
                :force-scatter="connectionIsSparse"
                :time-range="chartTimeRange"
                @jump="onSiblingJump"
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
      :default-features="timeseriesStore.defaultVisibleFeatures"
      :visible-features="boundVisibleFeatures"
      :grid-columns="boundGridColumns"
      :plot-size="boundPlotSize"
      :sample-max-points="boundSampleMaxPoints"
      :show-port-column="boundShowPortColumn"
      @update:visible-features="boundVisibleFeatures = $event"
      @update:grid-columns="boundGridColumns = $event"
      @update:plot-size="boundPlotSize = $event"
      @update:sample-max-points="boundSampleMaxPoints = $event"
      @update:show-port-column="boundShowPortColumn = $event"
      @commit="persistDisplaySettings"
    />
  </div>
</template>

<script setup lang="ts">
import type { Connection, FeatureTimeseries, FeatureName, AnomalyInterval, EnvelopeMode } from '~/types/golden-data'
import { useConnectionsStore } from '~/stores/connectionsStore'
import { useFrequencyStore } from '~/stores/frequencyStore'
import { useTimeseriesStore } from '~/stores/timeseriesStore'
import { useAlarmsStore } from '~/stores/alarmsStore'
import { useAppStore } from '~/stores/appStore'
import { useDevicesStore } from '~/stores/devicesStore'
import { useDeviceLookup } from '~/composables/useDeviceLookup'
import { provideChatContext } from '~/composables/useChatContext'
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import { buildConnectionsContribution, buildTimeseriesSummary } from '~/utils/chatContext'
import { formatUci } from '~/utils/format'
import { alarmFilteredConnections } from '~/utils/uci'
import { useDisplaySettings } from '~/composables/useDisplaySettings'
import type { FeatureToggleDefinition } from '~/components/shared/DisplaySettingsDialog.vue'
import { getGroupsForSeries, getSelectedSeriesAlarmBadge } from '~/utils/alarm-badge'

definePageMeta({
  title: 'Connections',
})

const route = useRoute()
const appStore = useAppStore()
const connectionsStore = useConnectionsStore()
const timeseriesStore = useTimeseriesStore()
const frequencyStore = useFrequencyStore()
const alarmsStore = useAlarmsStore()
const devicesStore = useDevicesStore()
const deviceLookup = useDeviceLookup()

const selectedAlarmGroupId = ref<string | null>(null)
const selectedAlarmAffectedFeatures = computed<string[]>(() => {
  const group = alarmsStore.groups.find((item) => item.id === selectedAlarmGroupId.value)
  return group
    ? (alarmsStore.affectedFeaturesByGroup[group.id]?.bySeries[connectionsStore.selectedUci ?? '']?.features ?? [])
    : []
})
const selectedAlarmRhythmAnomaly = computed<boolean>(() => {
  const group = alarmsStore.groups.find((item) => item.id === selectedAlarmGroupId.value)
  return group
    ? (alarmsStore.affectedFeaturesByGroup[group.id]?.bySeries[connectionsStore.selectedUci ?? '']?.rhythmAnomaly ??
        false)
    : false
})
const selectedSeriesAlarmBadge = computed(() =>
  getSelectedSeriesAlarmBadge(alarmsStore.groups, alarmsStore.affectedFeaturesByGroup, [
    connectionsStore.selectedUci ?? '',
  ]),
)

const FEATURE_LABELS: Record<string, string> = {
  packet_count: 'Packet Count',
  total_volume: 'Total Volume',
  mean_packet_size: 'Mean Packet Size',
  min_packet_size: 'Min Packet Size',
  max_packet_size: 'Max Packet Size',
  mean_interarrival_time: 'Mean IAT',
  min_interarrival_time: 'Min IAT',
  max_interarrival_time: 'Max IAT',
  std_packet_size: 'Std Packet Size',
  std_interarrival_time: 'Std IAT',
}

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
  storageKey: 'connections:displaySettings',
  columnDefaults: {},
  featureToggleDefaults: { rhythmVisible: true, windowsVisible: false, forecastVisible: true },
})

const initialUci = computed(() => (route.query.uci as string) ?? '')
const initialDeviceFilter = computed(() => (route.query.device as string) ?? '')
const initialAlarmGroup = computed(() => (route.query.alarmGroup as string) ?? '')
const initialAlarmUci = computed(() => (route.query.alarmUci as string) ?? '')

/**
 * Dropdown options for the alarm-filter select.
 */
const alarmGroupOptions = computed(() => {
  return alarmsStore.groups.map((g) => ({
    label: g.primary_type,
    value: g.id,
  }))
})

/**
 * Set of UCIs referenced by any alarm group inside the current time window.
 *
 * The ``Connection.state`` returned by the connections endpoint is always
 * ``'normal'`` because the backend has no anomaly information at that level.
 * The connections table derives the per-row status indicator from the
 * alarm groups instead: any UCI that is referenced by at least one alarm
 * group within the loaded time range is marked as ``'anomaly'``.
 *
 * The ``is_active`` flag from the backend is intentionally **not** used as
 * a filter here.  A group flips to ``is_active=false`` as soon as its
 * ``end_timestamp`` is in the past, which can happen mere seconds after a
 * short-lived alarm fires.  Filtering by ``is_active`` would clear the red
 * highlight while the user is still looking at the very alarm event that
 * appears in the alarms list, which is exactly the behavior we want to
 * avoid.  Both pages now agree: if an alarm group is in the queried
 * window, its connections render in the anomaly state.
 */
const anomalousUcis = computed<Set<string>>(() => {
  const ids = new Set<string>()
  for (const group of alarmsStore.groups) {
    for (const sid of group.series_ids) {
      ids.add(sid)
    }
  }
  return ids
})

/**
 * Whether a connection is alarmed, using the SAME derivation as the detail
 * badge (audit SUITE-047).
 *
 * The list previously tested direct `uci ∈ series_ids` membership while the
 * badge used `matchesPortCollapseSibling`, so the two could disagree.
 * Routing both through `getGroupsForSeries` means a red row always has a
 * badge, and a row without a badge is never red. The sibling matcher
 * short-circuits on equality, so every previously-red connection stays red.
 */
function isAnomalous(uci: string): boolean {
  if (anomalousUcis.value.has(uci)) return true
  return getGroupsForSeries(alarmsStore.groups, [uci]).length > 0
}

/**
 * The connections list with state enriched from active alarm groups,
 * filtered by the selected alarm group's series_ids when one is active.
 *
 * Absence anomalies affect series that carry no live traffic in the current
 * window, so the affected UCI is absent from the live list. When
 * {@link ConnectionsState.showSilentProfiled} is off those series would
 * vanish from the table entirely; {@link alarmFilteredConnections}
 * materialises them as `silent` rows so the alarm story stays complete
 * regardless of the toggle (UI-174).
 */
const filteredByAlarm = computed<Connection[]>(() => {
  const group = selectedAlarmGroupId.value
    ? alarmsStore.groups.find((g) => g.id === selectedAlarmGroupId.value)
    : undefined
  return alarmFilteredConnections(connectionsStore.selectableConnections, group?.series_ids ?? [], isAnomalous)
})

/**
 * Map feature labels with FeatureName type safety for the plot grid.
 */
const featureLabels = computed<Record<FeatureName, string>>(() => {
  return FEATURE_LABELS as Record<FeatureName, string>
})

/**
 * Build FeatureTimeseries array from timeseriesStore.visiblePlotData
 * to match the FeaturePlotGrid's expected props format.
 */
const allTimeseries = computed<FeatureTimeseries[]>(() => {
  const plotData = timeseriesStore.visiblePlotData
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

/**
 * Arrival timestamps for the RHYTHM lane markers.
 *
 * Reuses the packet_count series already loaded for the feature grid, so
 * the lane introduces no second timeseries request. Buckets with no
 * packets are not arrivals and are filtered out.
 */
const arrivalTimes = computed<string[]>(() => {
  const pktData = timeseriesStore.plotData['packet_count']
  if (!pktData) return []
  return pktData.filter((p) => (p.value ?? 0) > 0).map((p) => p.time)
})

/**
 * Connection-level sparsity flag based on the packet_count feature.
 *
 * When packet_count values are dominated by small constants (e.g., LLDP
 * sending exactly 1 packet per interval), ALL feature plots for this
 * connection should render as scatter points.
 */
const connectionIsSparse = computed<boolean>(() => {
  const pktData = timeseriesStore.plotData['packet_count']
  if (!pktData || pktData.length < 3) return false
  const values = pktData.map((p) => p.value).filter((v): v is number => v !== null)
  if (values.length < 3) return false
  const freq = new Map<number, number>()
  for (const v of values) {
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
  return dominantValue <= 2 && maxCount / values.length > 0.8
})

/**
 * Map AlarmIntervalItem[] from store to AnomalyInterval[] for FeaturePlot.
 */
const mappedAnomalyIntervals = computed<AnomalyInterval[]>(() => {
  return timeseriesStore.anomalyIntervals.map((item) => ({
    start: item.start_timestamp,
    end: item.end_timestamp,
    label: item.anomaly_type ?? undefined,
  }))
})

/**
 * Current time window for chart x-axis bounds.
 *
 * Stored as a reactive ref and updated alongside every data fetch so
 * that the chart axis range always matches the queried window. A plain
 * `computed` over `freshApiTimeParams()` would cache the value because
 * `new Date()` is not a reactive dependency.
 */
const lastFetchParams = ref(appStore.freshApiTimeParams())
const chartTimeRange = ref(appStore.freshApiTimeParams())

/**
 * Readable name of the selected connection for the panel heading.
 *
 * A raw UCI is a nine-field slash-joined string, so it is condensed to the
 * "source → destination · protocol" form the table already shows (UI-094).
 */
const selectedConnectionLabel = computed<string | null>(() => {
  const uci = connectionsStore.selectedUci
  return uci ? formatUci(uci) : null
})

/**
 * Resolve the currently-applied time window and publish it to the reactive
 * display refs.
 *
 * This is the single source of truth for "which window does a fetch use".
 * It always re-reads {@link useAppStore.freshApiTimeParams} at call time, so
 * a fetch can never reuse a stale snapshot captured at an earlier moment
 * (the UI-017 stale-time-param bug). Both the connection-table query and the
 * feature-plot/bounds query draw their `start`/`stop` from here, keeping them
 * consistent with the Start/End fields and the LIVE rolling window alike.
 *
 * @returns The applied `{ start, stop }` window as ISO 8601 UTC strings.
 */
function applyCurrentWindow(): { start: string; stop: string } {
  const params = appStore.freshApiTimeParams()
  lastFetchParams.value = params
  chartTimeRange.value = params
  return params
}

/**
 * Two-way binding for visible features via the store.
 */
const boundVisibleFeatures = computed<FeatureName[]>({
  get: () => timeseriesStore.visibleFeatures as FeatureName[],
  set: (val: FeatureName[]) => timeseriesStore.setVisibleFeatures(val),
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

/**
 * Two-way binding for grid columns via the store.
 */
const boundGridColumns = computed<number>({
  get: () => timeseriesStore.gridColumns,
  set: (val: number) => timeseriesStore.setGridColumns(val),
})

/**
 * Two-way binding for plot size via the store.
 */
const boundPlotSize = computed<string>({
  get: () => timeseriesStore.plotSize,
  set: (val: string) => timeseriesStore.setPlotSize(val),
})

/**
 * Two-way binding for the envelope display mode via the store.
 */
const boundShowEnvelope = computed<EnvelopeMode>({
  get: () => timeseriesStore.showEnvelope,
  set: (val: EnvelopeMode) => timeseriesStore.setShowEnvelope(val),
})

/**
 * Two-way binding for the port column visibility via the connections store.
 */
const boundShowPortColumn = computed<boolean>({
  get: () => connectionsStore.showPortColumn,
  set: (val: boolean) => connectionsStore.setShowPortColumn(val),
})
const boundSampleMaxPoints = computed<number>({
  get: () => timeseriesStore.sampleMaxPoints,
  set: (val: number) => {
    timeseriesStore.setSampleMaxPoints(val)
    void softReload()
  },
})

/**
 * Two-way binding for the profiled-but-silent rows via the connections store.
 */
const boundShowSilentProfiled = computed<boolean>({
  get: () => connectionsStore.showSilentProfiled,
  set: (val: boolean) => connectionsStore.setShowSilentProfiled(val),
})

/**
 * Load initial data on mount: connections list and feature names.
 */
async function loadInitialData(): Promise<void> {
  const { start, stop } = applyCurrentWindow()
  await Promise.allSettled([
    connectionsStore.fetchConnections(start, stop),
    connectionsStore.fetchProfiledUcis(),
    timeseriesStore.fetchFeatures(),
    alarmsStore.fetchGroups({}, { start, stop }),
    devicesStore.fetchDevices(),
  ])
}

/**
 * Full reload: fetch connections + features, then re-fetch selected UCI data.
 */
async function reload(): Promise<void> {
  await loadInitialData()
  if (connectionsStore.selectedUci) {
    const { start, stop } = applyCurrentWindow()
    await Promise.allSettled([
      timeseriesStore.fetchAllForUci(connectionsStore.selectedUci, start, stop),
      frequencyStore.fetchProfile(connectionsStore.selectedUci),
      // The alarm groups were just refetched for the new window, so the
      // cached feature detail belongs to the previous one. Reload it for the
      // still-selected connection, otherwise changing the time range leaves
      // a red row with an empty detail pane — the reported symptom
      // (audit SUITE-047).
      alarmsStore.loadAffectedFeaturesForSeries([connectionsStore.selectedUci]),
    ])
  }
}

/**
 * Dismiss errors from both stores.
 */
function dismissError(): void {
  connectionsStore.error = null
  timeseriesStore.error = null
}

/**
 * Handle connection selection from the table.
 */
function onConnectionSelect(connection: Connection | null): void {
  if (connection) {
    connectionsStore.selectConnection(connection.uci)
    const { start, stop } = applyCurrentWindow()
    timeseriesStore.fetchAllForUci(connection.uci, start, stop)
    frequencyStore.fetchProfile(connection.uci)
    // Without this the violation badge and the per-feature highlights stay
    // empty for a connection the list already marks red: nothing else
    // populates affectedFeaturesByGroup when a *series* (rather than an
    // alarm group) is selected (audit SUITE-047).
    alarmsStore.loadAffectedFeaturesForSeries([connection.uci])
  } else {
    connectionsStore.selectConnection(null)
    timeseriesStore.plotData = {}
    timeseriesStore.anomalyIntervals = []
    frequencyStore.clear()
  }
}

/**
 * Jump to a base-key sibling UCI surfaced by the empty-metrics rotating-port
 * hint (UI-017b). Selects the sibling and loads its timeseries in the current
 * window so the operator immediately sees the active-port data.
 */
function onSiblingJump(uci: string): void {
  connectionsStore.selectConnection(uci)
  const { start, stop } = applyCurrentWindow()
  timeseriesStore.fetchAllForUci(uci, start, stop)
  frequencyStore.fetchProfile(uci)
}

/**
 * Soft reload: refresh data without setting isLoading, preventing UI flicker.
 * Used when switching live intervals where the layout should stay stable.
 */
async function softReload(): Promise<void> {
  const { start, stop } = applyCurrentWindow()
  await Promise.allSettled([
    connectionsStore.fetchConnections(start, stop),
    connectionsStore.fetchProfiledUcis(),
    alarmsStore.fetchGroups({}, { start, stop }),
  ])
  if (connectionsStore.selectedUci) {
    await Promise.allSettled([
      timeseriesStore.fetchAllForUci(connectionsStore.selectedUci, start, stop),
      frequencyStore.fetchProfile(connectionsStore.selectedUci),
    ])
  }
}

/**
 * Handle time toolbar updates — reload data with new time range.
 */
function onTimeUpdate(): void {
  softReload()
}

/**
 * Polling callback for live mode — re-fetch selected UCI data and the
 * alarm groups so the table's status column reflects the current state.
 */
async function pollLiveData(): Promise<void> {
  const { start, stop } = applyCurrentWindow()

  alarmsStore.fetchGroups({}, { start, stop })
  connectionsStore.fetchConnections(start, stop)
  // Only polled while the silent rows are actually on screen — the profile
  // list is window-independent, so refreshing it every live tick would be a
  // recurring query for a list nobody is looking at.
  if (connectionsStore.showSilentProfiled) {
    connectionsStore.fetchProfiledUcis()
  }

  if (!connectionsStore.selectedUci) return
  if (timeseriesStore.isLoading) return
  await Promise.allSettled([
    timeseriesStore.fetchAllForUci(connectionsStore.selectedUci, start, stop),
    frequencyStore.fetchProfile(connectionsStore.selectedUci),
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

/**
 * Pre-set the alarm filter dropdown when navigating from another page.
 *
 * Supports two lookup modes:
 * - ``?alarmGroup=<id>`` — direct group ID (from Alarms page)
 * - ``?alarmUci=<uci>`` — find the group that contains this UCI (from Topology page)
 *
 * The alarm groups are fetched asynchronously during ``loadInitialData()``,
 * so this watcher fires once the groups arrive and applies the filter
 * **exactly once** (controlled by ``deepLinkApplied``).  Without that
 * one-shot guard the filter would be re-applied on every live-mode
 * refresh, silently re-selecting an alarm the user just cleared from
 * the dropdown.
 */
const deepLinkApplied = ref(false)

watch(
  () => alarmsStore.groups,
  (groups) => {
    if (deepLinkApplied.value) return
    if (groups.length === 0) return
    if (!initialAlarmGroup.value && !initialAlarmUci.value) {
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

    if (initialAlarmUci.value) {
      const match = groups.find((g) => g.series_ids.includes(initialAlarmUci.value))
      if (match) {
        selectedAlarmGroupId.value = match.id
        deepLinkApplied.value = true
      }
    }
  },
  { immediate: true },
)

/**
 * Strip the deep-link query parameters from the URL once the user clears
 * the alarm filter so subsequent page reloads do not silently re-apply
 * the original filter.
 */
const router = useRouter()
watch(selectedAlarmGroupId, (val, prev) => {
  if (prev != null && val == null && (route.query.alarmGroup || route.query.alarmUci)) {
    const cleaned = { ...route.query }
    delete cleaned.alarmGroup
    delete cleaned.alarmUci
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
 * and Protocols pages alike. Clearing on unmount keeps a stale `conn`
 * profile from being the store's content while another page's lane
 * mounts, and stops an in-flight request from landing after the page is
 * gone.
 */
onUnmounted(() => {
  frequencyStore.clear()
})

provideChatContext(() => {
  const conns = filteredByAlarm.value
  const sel = connectionsStore.selectedConnection

  const pktData = timeseriesStore.plotData['packet_count']
  const volData = timeseriesStore.plotData['total_volume']
  const selectedPackets = pktData ? pktData.reduce((s, p) => s + (p.value ?? 0), 0) : null
  const selectedBytes = volData ? volData.reduce((s, p) => s + (p.value ?? 0), 0) : null

  const contrib = buildConnectionsContribution({
    connections: conns.map((c) => ({
      uci: c.uci,
      source: c.source,
      destination: c.destination,
      protocol: c.protocol,
      port: c.port,
      isWildcard: c.isWildcard,
      memberCount: c.memberCount ?? null,
    })),
    selectedConnection: sel
      ? {
          uci: sel.uci,
          source: sel.source,
          destination: sel.destination,
          protocol: sel.protocol,
          port: sel.port,
          isWildcard: sel.isWildcard,
          memberCount: sel.memberCount ?? null,
        }
      : null,
    selectedPackets,
    selectedBytes,
    filters: {
      alarm_group_id: selectedAlarmGroupId.value ?? null,
      device_filter: initialDeviceFilter.value || null,
      uci_query: initialUci.value || null,
      show_port_column: connectionsStore.showPortColumn,
    },
    totalConnections: connectionsStore.connectionCount,
  })

  if (sel) {
    const summaryTable = buildTimeseriesSummary({
      seriesId: sel.uci,
      plotData: timeseriesStore.visiblePlotData,
      featureLabels: FEATURE_LABELS,
    })
    contrib.visible_data = [...(contrib.visible_data ?? []), ...summaryTable]
  }

  return contrib
})
</script>

<style scoped lang="scss">
.connections-page {
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

.connections-splitter {
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
