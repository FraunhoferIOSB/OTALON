<template>
  <q-page
    padding
    :class="[`time-toolbar-page`, `alarms-density-${displaySettings.density}`]"
    :style="`--page-font-size: ${displaySettings.fontSize}px`"
  >
    <SharedTimeToolbarRow toolbar-class="col" @update="onTimeUpdate" />

    <SharedErrorBanner :message="alarmsStore.error" @retry="reload()" @dismiss="alarmsStore.error = null" />

    <div style="position: relative; min-height: 200px">
      <q-inner-loading :showing="alarmsStore.isLoading" label="Loading alarms…" />

      <template v-if="!alarmsStore.isLoading">
        <div class="row items-center q-gutter-sm q-mb-md">
          <q-badge
            class="kpi-badge"
            :class="alarmsStore.filter.status === 'active' ? 'kpi-badge--selected' : 'kpi-badge--neutral'"
            style="cursor: pointer"
            @click="toggleFilter('active')"
          >
            <q-icon name="warning_amber" size="14px" color="negative" class="q-mr-xs" />
            Active: {{ alarmsStore.activeCount }}
          </q-badge>
          <q-badge
            class="kpi-badge"
            :class="alarmsStore.filter.status === 'confirmed' ? 'kpi-badge--selected' : 'kpi-badge--neutral'"
            style="cursor: pointer"
            @click="toggleFilter('confirmed')"
          >
            <q-icon name="check_circle" size="14px" color="positive" class="q-mr-xs" />
            Confirmed: {{ alarmsStore.confirmedCount }}
          </q-badge>
          <q-badge class="kpi-badge kpi-badge--neutral">
            <q-icon name="groups" size="14px" color="info" class="q-mr-xs" />
            Total Groups: {{ alarmsStore.totalCount }}
          </q-badge>
          <q-badge class="kpi-badge kpi-badge--neutral">
            <q-icon :name="DOMAIN_ICONS.connections" size="14px" color="accent" class="q-mr-xs" />
            Connections: {{ alarmsStore.connectionCount }}
          </q-badge>
          <q-badge
            v-if="alarmsStore.filter.status"
            class="kpi-badge kpi-badge--neutral"
            style="cursor: pointer"
            @click="alarmsStore.filter.status = undefined"
          >
            <q-icon name="filter_alt_off" size="14px" class="q-mr-xs" />
            Clear Filter
          </q-badge>
          <q-space />
          <q-btn flat dense round icon="tune" aria-label="Display settings" @click="dialogOpen = true">
            <q-tooltip>Display Settings</q-tooltip>
          </q-btn>
        </div>

        <!--
          Master-detail layout:
          - Wide viewport (>= 1280 px): q-splitter so list + detail are
            side-by-side and the operator can resize via drag.
          - Narrow viewport (< 1280 px): we keep the legacy right-side
            dialog so mobile/laptop screens stay usable.
        -->
        <q-splitter
          v-if="useSplitLayout"
          v-model="splitRatio"
          :limits="splitLimits"
          unit="%"
          separator-class="splitter-bar"
          class="alarms-splitter"
          @update:model-value="onSplitterChange"
        >
          <template #before>
            <AlarmGroupTable
              :groups="alarmsStore.filteredGroups"
              :visible-columns="visibleColumns"
              :rows-per-page="displaySettings.rowsPerPage"
              :selected-group-id="alarmsStore.selectedGroupId"
              @select="onSelectGroup"
            />
          </template>

          <template #separator>
            <q-icon name="drag_indicator" color="grey-6" size="20px" />
          </template>

          <template #after>
            <div class="detail-pane q-pl-md">
              <AlarmDetailPanel
                v-if="alarmsStore.selectedGroup"
                :group="alarmsStore.selectedGroup"
                :font-size="displaySettings.fontSize"
                @confirm="onConfirm"
                @unconfirm="onUnconfirm"
                @close="onCloseDetail"
              />
              <div v-else class="detail-empty column items-center justify-center text-center q-pa-xl">
                <q-icon name="info" size="48px" color="grey-5" />
                <div class="text-subtitle1 q-mt-md text-muted">No alarm selected</div>
                <div class="text-caption text-muted">
                  Pick a row on the left to inspect details, type statistics and subagent runs.
                </div>
              </div>
            </div>
          </template>
        </q-splitter>

        <AlarmGroupTable
          v-else
          :groups="alarmsStore.filteredGroups"
          :visible-columns="visibleColumns"
          :rows-per-page="displaySettings.rowsPerPage"
          :selected-group-id="alarmsStore.selectedGroupId"
          @select="onSelectGroup"
        />
      </template>
    </div>

    <!--
        Load-more bar: shows when the backend has more groups than loaded.
        Replaces the old load-all-on-mount behaviour (API-041).
      -->
    <div v-if="alarmsStore.hasMore" class="load-more-bar q-py-sm text-center">
      <q-btn
        :loading="alarmsStore.isLoadingMore"
        color="primary"
        outline
        no-caps
        label="Load more alarms"
        @click="onLoadMore"
      />
      <div class="text-caption text-muted q-mt-xs">
        {{ alarmsStore.groups.length }} of {{ alarmsStore.totalRowCount }} loaded
      </div>
    </div>

    <!--
      Narrow-viewport fallback: the legacy right-aligned dialog. Used only
      when the splitter layout is disabled (small screens). On wide screens
      the dialog never opens; selection drives the splitter detail pane.
    -->
    <q-dialog
      v-if="!useSplitLayout"
      v-model="detailDialogOpen"
      position="right"
      full-height
      seamless
      @hide="onCloseDetail"
    >
      <q-card class="alarm-detail-dialog">
        <AlarmDetailPanel
          :group="alarmsStore.selectedGroup ?? null"
          :font-size="displaySettings.fontSize"
          @confirm="onConfirm"
          @unconfirm="onUnconfirm"
          @close="onCloseDetail"
        />
      </q-card>
    </q-dialog>

    <SharedDisplaySettingsDialog
      v-model="displaySettings"
      v-model:open="dialogOpen"
      :table-columns="togglableColumns"
      @reset="resetSettings"
      @commit="persistSettings"
    />
  </q-page>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import type { AnomalyGroupItem, SubagentJob, SubagentJobSummary } from '~/types/api'
import type { ChatSubagentClassification } from '#shared/uiContext'
import { MAX_SUBAGENT_CLASSIFICATIONS, MAX_SUBAGENT_STEP2_PER_JOB } from '#shared/uiContext'
import type { ColumnDefinition } from '~/components/shared/DisplaySettingsDialog.vue'
import { provideChatContext } from '~/composables/useChatContext'
import { useSubagentStore } from '~/stores/subagentStore'
import { buildAlarmsContribution } from '~/utils/chatContext'
import { isMacAddress } from '~/utils/format'
import { humanizeProtocolStack, isProtocolHashId } from '~/utils/protocol'
import { extractAlarmMacs } from '~/utils/mac-match'

definePageMeta({
  title: 'Alarms',
})

const route = useRoute()
const $q = useQuasar()
const appStore = useAppStore()
const alarmsStore = useAlarmsStore()
const subagentStore = useSubagentStore()

/**
 * Whenever the operator selects a new alarm, pre-load the latest few
 * completed subagent classifications for it. This makes the chat-context
 * provider below able to embed the subagent's Step-1 / Step-2 result
 * into the next chat turn without an extra network round-trip.
 */
watch(
  () => alarmsStore.selectedGroupId,
  (id) => {
    if (id) void subagentStore.loadLatestFullJobs(id, MAX_SUBAGENT_CLASSIFICATIONS)
  },
  { immediate: true },
)

const detailDialogOpen = ref(false)
const alarmDetailOpen = ref(false)

/**
 * Split-layout breakpoint.
 *
 * Below this viewport width the legacy right-side dialog is used so the
 * alarm list does not get squeezed below readable size. Above it the
 * master-detail splitter takes over.
 */
const MIN_SPLIT_WIDTH_PX = 1280

/**
 * Track viewport width on the client only. The initial value is ``0`` on
 * both server and client so SSR hydration matches. After mount we read
 * the real ``window.innerWidth``.
 */
const viewportWidth = ref(0)

function onResize(): void {
  viewportWidth.value = window.innerWidth
}

onMounted(() => {
  if (typeof window !== 'undefined') {
    viewportWidth.value = window.innerWidth
    window.addEventListener('resize', onResize)
  }
})
onBeforeUnmount(() => {
  if (typeof window !== 'undefined') {
    window.removeEventListener('resize', onResize)
  }
})

/**
 * True only when the viewport has been measured on the client and is
 * wide enough for the side-by-side master-detail layout.
 */
const useSplitLayout = computed(() => viewportWidth.value >= MIN_SPLIT_WIDTH_PX)

/**
 * Operator-selected splitter ratio, persisted in localStorage so the
 * layout is restored on the next visit.
 */
const SPLIT_RATIO_STORAGE_KEY = 'alarms:splitterRatio'
const splitLimits: [number, number] = [25, 70]
const splitRatio = ref<number>(45)

if (typeof window !== 'undefined') {
  try {
    const stored = window.localStorage.getItem(SPLIT_RATIO_STORAGE_KEY)
    if (stored) {
      const parsed = parseFloat(stored)
      if (Number.isFinite(parsed) && parsed >= splitLimits[0] && parsed <= splitLimits[1]) {
        splitRatio.value = parsed
      }
    }
  } catch {
    /* localStorage may be unavailable in some browsers/contexts; ignore */
  }
}

function onSplitterChange(value: number): void {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(SPLIT_RATIO_STORAGE_KEY, String(value))
  } catch {
    /* ignore */
  }
}

/**
 * Close handler for the detail pane. In the split layout we just clear
 * the selection; in the dialog layout we additionally close the dialog.
 *
 * Wired to the QDialog ``@hide`` event (fires on ESC, backdrop click and
 * programmatic ``v-model=false``) so the alarm-detail state — and thus the
 * LLM chat-context contribution keyed off ``alarmDetailOpen`` — is reset on
 * every dismiss path. Idempotent: a second invocation (e.g. the ``@hide``
 * that our own ``detailDialogOpen=false`` triggers) short-circuits.
 */
function onCloseDetail(): void {
  if (!alarmDetailOpen.value && !detailDialogOpen.value && !alarmsStore.selectedGroupId) return
  alarmsStore.selectGroup(null)
  detailDialogOpen.value = false
  alarmDetailOpen.value = false
}

const sseEnabled = computed(() => appStore.liveMode)

useSse('anomaly', {
  enabled: sseEnabled,
  onEvent: (_topic: string, data: unknown) => {
    alarmsStore.handleAnomalyUpdate(data as AnomalyGroupItem)
    $q.notify({
      type: 'info',
      message: 'New anomaly event received',
      icon: 'notifications_active',
      timeout: 3000,
    })
  },
})

const pollIntervalMs = computed(() => appStore.pollingIntervalMs)

const togglableColumns: ColumnDefinition[] = [
  { value: 'primary_type', label: 'Prediction' },
  { value: 'relative', label: 'Age' },
  { value: 'start_timestamp', label: 'Start Time' },
  { value: 'end_timestamp', label: 'End Time' },
  { value: 'is_active', label: 'Active' },
  { value: 'confirmed', label: 'Confirmed' },
  { value: 'connections', label: 'Connections' },
  { value: 'types', label: 'Types' },
]

const {
  settings: displaySettings,
  dialogOpen,
  persist: persistSettings,
  reset: resetSettings,
} = useDisplaySettings({
  storageKey: 'alarms:displaySettings',
  columnDefaults: {
    primary_type: true,
    relative: true,
    start_timestamp: false,
    end_timestamp: false,
    is_active: true,
    confirmed: true,
    connections: true,
    types: true,
  },
  defaultFontSize: 13,
  defaultRowsPerPage: 25,
})

const visibleColumns = computed(() =>
  togglableColumns.filter((c) => displaySettings.value.visibleColumns[c.value]).map((c) => c.value),
)

watch(
  displaySettings,
  () => {
    persistSettings()
  },
  { deep: true },
)

/**
 * Build the current time range parameters for API calls.
 *
 * @returns Object with `start` and `stop` ISO 8601 UTC strings.
 */
function getTimeParams(): { start: string; stop: string } {
  return appStore.freshApiTimeParams()
}

usePolling(() => alarmsStore.fetchGroups({ module: undefined }, getTimeParams()), pollIntervalMs, {
  enabled: computed(() => appStore.liveMode),
})

watch(
  () => appStore.liveIntervalSeconds,
  () => {
    if (appStore.liveMode) {
      alarmsStore.fetchGroups({ module: undefined }, getTimeParams())
    }
  },
)

/**
 * Load alarm groups from the backend API.
 */
async function reload(): Promise<void> {
  await alarmsStore.fetchGroups({ module: undefined }, getTimeParams())
  selectTopIfNone()
}

/**
 * Load the next page of alarm groups via store.loadMore().
 */
async function onLoadMore(): Promise<void> {
  await alarmsStore.loadMore(getTimeParams())
}

/**
 * Toggle a status filter — clicking an already active filter clears it.
 */
function toggleFilter(filter: 'active' | 'confirmed'): void {
  alarmsStore.filter.status = alarmsStore.filter.status === filter ? undefined : filter
}

onMounted(async () => {
  const statusParam = route.query.status as string | undefined
  if (statusParam === 'active' || statusParam === 'confirmed') {
    alarmsStore.filter.status = statusParam
  }
  await alarmsStore.fetchGroups({ module: undefined }, getTimeParams())
  const groupParam = route.query.group as string | undefined
  if (groupParam && alarmsStore.groups.some((g) => g.id === groupParam)) {
    alarmsStore.selectGroup(groupParam)
  } else {
    selectTopIfNone()
  }
})

provideChatContext(() =>
  buildAlarmsContribution({
    groups: alarmsStore.filteredGroups,
    selectedGroup: alarmsStore.selectedGroup ?? null,
    detailOpen: alarmDetailOpen.value,
    subagentJobs: alarmsStore.selectedGroupId ? (subagentStore.jobsByAlarm[alarmsStore.selectedGroupId] ?? []) : [],
    liveJobsById: subagentStore.liveJobsById,
    filters: {
      status: alarmsStore.filter.status,
      module: alarmsStore.filter.module,
      limit: alarmsStore.filter.limit,
    },
    activeCount: alarmsStore.activeCount,
    totalGroups: alarmsStore.groups.length,
    buildSubagentChatContext: (alarmId) => buildSubagentChatContext(alarmId),
    isMacAddress,
    isProtocolHashId,
    humanizeProtocolStack,
    extractAlarmMacs,
  }),
)

/**
 * Build the compact subagent-classification context block for an alarm.
 *
 * For each of the latest few completed subagent jobs for ``alarmId``, we
 * collect the Step-1 method/activity and the top Step-2 MITRE entries.
 * Full :class:`SubagentJob` records (with reasoning) are preferred over
 * summaries; summaries are used as a fallback when the full record is
 * not yet cached.
 */
function buildSubagentChatContext(alarmId: string): ChatSubagentClassification[] {
  // Read jobsByAlarm directly (rather than via the historyFor getter)
  // so Pinia's reactivity tracks this access cleanly through the
  // computed() in ContextPreview / useChat.
  const summaries: SubagentJobSummary[] = subagentStore.jobsByAlarm[alarmId] ?? []
  if (summaries.length === 0) return []
  const completed = summaries.filter((s) => s.status === 'completed')
  const slice = completed.slice(0, MAX_SUBAGENT_CLASSIFICATIONS)
  const result: ChatSubagentClassification[] = []
  for (const s of slice) {
    const full: SubagentJob | undefined = subagentStore.liveJobsById[s.id]
    if (full) {
      result.push({
        job_id: full.id,
        alarm_id: full.alarm_id,
        prompt_variant: full.prompt_variant,
        llm: `${full.llm_provider}/${full.llm_model}`,
        created_at: full.created_at,
        duration_seconds: full.duration_seconds ?? null,
        step1_method: full.step1_technical?.technical_method ?? null,
        step1_activity: full.step1_technical?.observed_activity ?? null,
        step2: (full.step2_classification?.classifications ?? []).slice(0, MAX_SUBAGENT_STEP2_PER_JOB).map((c) => ({
          technique_id: c.technique_id,
          technique_name: c.technique_name ?? null,
          confidence: c.confidence ?? 0,
          reasoning: c.reasoning ?? null,
        })),
      })
    } else {
      // Fallback to the summary view (no reasoning available).
      result.push({
        job_id: s.id,
        alarm_id: s.alarm_id,
        prompt_variant: s.prompt_variant,
        llm: `${s.llm_provider}/${s.llm_model}`,
        created_at: s.created_at,
        duration_seconds: s.duration_seconds ?? null,
        step1_method: s.step1_method ?? null,
        step1_activity: null,
        step2: s.top_step2
          ? [
              {
                technique_id: s.top_step2.technique_id,
                technique_name: s.top_step2.technique_name ?? null,
                confidence: s.top_step2.confidence ?? 0,
                reasoning: s.top_step2.reasoning ?? null,
              },
            ]
          : [],
      })
    }
  }
  return result
}

/**
 * Handle alarm group row selection.
 *
 * - Split layout: selecting a row simply updates the store; the right
 *   pane renders the new alarm.
 * - Dialog fallback (narrow viewport): selection also opens the dialog.
 */
function onSelectGroup(group: AnomalyGroupItem): void {
  alarmsStore.selectGroup(group.id)
  alarmDetailOpen.value = true
  if (!useSplitLayout.value) {
    detailDialogOpen.value = true
  }
}

/**
 * Confirm an alarm group after user confirmation via dialog.
 */
function onConfirm(group: AnomalyGroupItem): void {
  $q.dialog({
    title: 'Confirm Alarm Group',
    message: `Mark alarm group ${group.id.substring(0, 8)} as confirmed?`,
    cancel: true,
    persistent: false,
  }).onOk(async () => {
    await alarmsStore.confirmGroup(group.id)
    if (alarmsStore.error) {
      $q.notify({
        type: 'negative',
        message: alarmsStore.error,
        icon: 'error',
        timeout: 4000,
      })
      return
    }
    $q.notify({
      type: 'positive',
      message: 'Alarm group confirmed',
      icon: 'check_circle',
      timeout: 2500,
    })
  })
}

/**
 * Revoke confirmation for an alarm group.
 */
async function onUnconfirm(group: AnomalyGroupItem): Promise<void> {
  await alarmsStore.unconfirmGroup(group.id)
  if (alarmsStore.error) {
    $q.notify({
      type: 'negative',
      message: alarmsStore.error,
      icon: 'error',
      timeout: 4000,
    })
    return
  }
  $q.notify({
    type: 'warning',
    message: 'Alarm group confirmation revoked',
    icon: 'undo',
    timeout: 2500,
  })
}

/**
 * Reload alarm groups when the time toolbar emits an update.
 */
async function onTimeUpdate(): Promise<void> {
  await alarmsStore.fetchGroups({ module: undefined }, getTimeParams())
  selectTopIfNone()
}

/**
 * Auto-select the top alarm group if nothing is currently selected.
 *
 * Respects the default table sort order (start_timestamp descending).
 */
function selectTopIfNone(): void {
  if (alarmsStore.selectedGroupId) return
  const groups = alarmsStore.filteredGroups
  if (groups.length === 0) return
  const top = [...groups].sort(
    (a, b) => new Date(b.start_timestamp).getTime() - new Date(a.start_timestamp).getTime(),
  )[0]
  if (top) alarmsStore.selectGroup(top.id)
}
</script>

<style scoped lang="scss">
.kpi-badge {
  padding: 6px 12px;
  font-size: 13px;
  font-weight: 600;
  border-radius: 4px;
}

.kpi-badge--neutral {
  background-color: var(--cd-surface);
  color: var(--cd-surface-text);
  border: 1px solid var(--cd-border);
}

.kpi-badge--selected {
  background-color: rgba(var(--cd-primary-rgb), 0.15);
  color: var(--q-primary);
  outline: 1.5px solid var(--q-primary);
}

.body--dark .kpi-badge--selected {
  background-color: rgba(var(--cd-primary-rgb), 0.3);
}

.alarm-detail-dialog {
  min-width: 400px;
  max-width: 600px;
  width: 520px;
  margin-top: 50px;
  height: calc(100dvh - var(--cd-header-height, 51px)) !important;
  max-height: calc(100dvh - var(--cd-header-height, 51px)) !important;
  border-radius: 0;
}

.alarms-splitter {
  min-height: calc(100vh - 220px);
}

.alarms-splitter :deep(.splitter-bar) {
  background-color: var(--cd-border);
  width: 4px;
  cursor: col-resize;
}

.alarms-splitter :deep(.q-splitter__separator-area) {
  display: flex;
  align-items: center;
  justify-content: center;
}

.detail-pane {
  height: 100%;
  overflow-y: auto;
}

.detail-empty {
  height: 100%;
  min-height: 300px;
  color: var(--cd-text-muted);
}

.alarms-density-compact :deep(.alarm-group-table thead th),
.alarms-density-compact :deep(.alarm-group-table tbody td) {
  padding-top: 2px !important;
  padding-bottom: 2px !important;
}

.alarms-density-comfortable :deep(.alarm-group-table thead th),
.alarms-density-comfortable :deep(.alarm-group-table tbody td) {
  padding-top: 12px !important;
  padding-bottom: 12px !important;
}

.q-page :deep(.alarm-group-table thead th),
.q-page :deep(.alarm-group-table tbody td),
.q-page :deep(.alarm-group-table .q-chip),
.q-page :deep(.alarm-group-table .q-badge) {
  font-size: var(--page-font-size);
}
</style>
