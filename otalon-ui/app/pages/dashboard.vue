<template>
  <q-page class="time-toolbar-page" :style="`--page-font-size: ${displaySettings.fontSize}px`">
    <SharedTimeToolbarRow toolbar-class="col" @update="onTimeUpdate">
      <q-btn
        v-if="$q.screen.gt.sm"
        flat
        dense
        round
        icon="dashboard_customize"
        aria-label="Edit layout"
        :color="layoutStore.editMode ? 'primary' : undefined"
        @click="layoutStore.toggleEditMode()"
      >
        <q-tooltip>{{ layoutStore.editMode ? 'Done editing' : 'Edit Layout' }}</q-tooltip>
      </q-btn>
      <q-btn
        v-if="layoutStore.editMode && $q.screen.gt.sm"
        flat
        dense
        round
        icon="restart_alt"
        aria-label="Reset layout to default"
        @click="layoutStore.resetToDefault()"
      >
        <q-tooltip>Reset to Default Layout</q-tooltip>
      </q-btn>
      <q-btn flat dense round icon="tune" aria-label="Display settings" @click="dialogOpen = true">
        <q-tooltip>Display Settings</q-tooltip>
      </q-btn>
    </SharedTimeToolbarRow>

    <q-dialog v-model="dialogOpen" position="right">
      <q-card style="min-width: 320px" class="settings-dialog">
        <q-card-section class="row items-center no-wrap q-pb-sm">
          <q-icon name="tune" size="20px" class="q-mr-sm" />
          <span class="text-subtitle1 text-weight-bold">Display Settings</span>
          <q-space />
          <q-btn flat round dense icon="close" @click="dialogOpen = false" />
        </q-card-section>
        <q-separator />
        <q-card-section>
          <div class="text-caption text-weight-bold q-mb-xs">Font Size ({{ displaySettings.fontSize }}px)</div>
          <q-slider
            v-model="displaySettings.fontSize"
            :min="10"
            :max="22"
            :step="1"
            label
            label-always
            :label-value="`${displaySettings.fontSize}px`"
            color="primary"
            class="q-mb-md"
            @change="persistSettings"
          />

          <q-separator class="q-my-md" />

          <div class="text-caption text-weight-bold q-mb-xs">Widget Visibility</div>
          <q-item v-for="def in widgetRegistryList" :key="def.id" dense>
            <q-item-section>
              <q-toggle
                :model-value="layoutStore.isVisible(def.id)"
                :label="def.label"
                dense
                color="primary"
                @update:model-value="(val: boolean) => layoutStore.setVisibility(def.id, val)"
              />
            </q-item-section>
          </q-item>
        </q-card-section>
      </q-card>
    </q-dialog>

    <SharedErrorBanner :message="dashboardStore.error" @retry="reload()" @dismiss="dashboardStore.error = null" />

    <div style="position: relative; min-height: 200px" data-test="dashboard-content">
      <q-inner-loading :showing="dashboardStore.isInitialLoad" label="Loading dashboard…" />

      <template v-if="!dashboardStore.isInitialLoad">
        <DashboardGrid />
      </template>
    </div>
  </q-page>
</template>

<script setup lang="ts">
import type { SignalColor } from '~/types/golden-data'
import { useQuasar } from 'quasar'
import { getActivePinia } from 'pinia'
import { useAppStore } from '~/stores/appStore'
import { useDashboardStore } from '~/stores/dashboardStore'
import { useDashboardLayoutStore } from '~/stores/dashboardLayoutStore'
import { formatUci } from '~/utils/format'
import { WIDGET_REGISTRY } from '~/components/dashboard/widgets/registry'
import { provideChatContext } from '~/composables/useChatContext'
import { buildDashboardContribution } from '~/utils/chatContext'

definePageMeta({
  title: 'Dashboard',
})

const $q = useQuasar()
const appStore = useAppStore()
const dashboardStore = useDashboardStore()
const layoutStore = useDashboardLayoutStore()
if (import.meta.client) {
  ;(window as unknown as { __ppinia?: unknown }).__ppinia = getActivePinia()
  ;(window as unknown as { __pstore?: unknown }).__pstore = layoutStore
}

const BACKEND_SIGNAL_MAP: Record<string, SignalColor> = {
  success: 'success',
  warning: 'warning',
  danger: 'danger',
}

const SIGNAL_LABELS: Record<SignalColor, string> = {
  danger: 'Critical',
  warning: 'Warning',
  success: 'Normal',
  info: 'Info',
}

const mappedSignalColor = computed<SignalColor>(() => {
  return BACKEND_SIGNAL_MAP[dashboardStore.signalColor] ?? 'info'
})

const signalLabel = computed(() => SIGNAL_LABELS[mappedSignalColor.value] ?? dashboardStore.signalColor)

const pollIntervalMs = computed(() => appStore.pollingIntervalMs)

const widgetRegistryList = computed(() => Object.values(WIDGET_REGISTRY))

/**
 * Build the current time range parameters for API calls.
 *
 * @returns Object with `start` and `stop` ISO 8601 UTC strings.
 */
function getTimeParams(): { start: string; stop: string } {
  return appStore.freshApiTimeParams()
}

const dialogOpen = ref(false)
const displaySettings = reactive({
  fontSize: 13,
})

function persistSettings(): void {
  if (!import.meta.client) return
  try {
    localStorage.setItem('dashboard:displaySettings', JSON.stringify(displaySettings))
  } catch {
    /* ignore quota errors */
  }
}

function loadSettings(): void {
  if (!import.meta.client) return
  try {
    const raw = localStorage.getItem('dashboard:displaySettings')
    if (raw) {
      const parsed = JSON.parse(raw) as Record<string, unknown>
      if (typeof parsed.fontSize === 'number' && Number.isFinite(parsed.fontSize)) {
        displaySettings.fontSize = parsed.fontSize
      }
    }
  } catch {
    /* ignore parse errors */
  }
}

usePolling(() => dashboardStore.fetchAll(getTimeParams()), pollIntervalMs, {
  enabled: computed(() => appStore.liveMode),
})

watch(
  () => appStore.liveIntervalSeconds,
  () => {
    if (appStore.liveMode) {
      dashboardStore.fetchAll(getTimeParams())
    }
  },
)

/**
 * Reload all dashboard data from the backend.
 */
async function reload(): Promise<void> {
  await dashboardStore.fetchAll(getTimeParams())
}

/**
 * Handle time toolbar update events by refreshing dashboard data.
 */
function onTimeUpdate(): void {
  dashboardStore.fetchAll(getTimeParams())
}

onMounted(async () => {
  loadSettings()
  await layoutStore.load()
  dashboardStore.fetchAll(getTimeParams())
})

provideChatContext(() => {
  const visibleWidgets: string[] = []
  const hiddenWidgets: string[] = []
  for (const key of Object.keys(WIDGET_REGISTRY)) {
    if (layoutStore.isVisible(key)) visibleWidgets.push(key)
    else hiddenWidgets.push(key)
  }

  return buildDashboardContribution({
    visibleWidgets,
    hiddenWidgets,
    recentAlarms: dashboardStore.recentAlarms,
    topConnections: dashboardStore.topConnections,
    topProtocols: dashboardStore.protocolIds,
    topAssets: dashboardStore.macAssets,
    vulnerabilitySummary: dashboardStore.vulnerabilitySummary,
    signalColor: dashboardStore.signalColor,
    signalLabel: signalLabel.value,
    anomalyCount: dashboardStore.anomalyCount,
    classifiedCount: dashboardStore.classifiedCount,
    connectionCount: dashboardStore.connectionCount,
    assetCount: dashboardStore.deviceCount,
    protocolCount: dashboardStore.protocolCount,
    healthStatus: dashboardStore.overallHealthStatus,
    healthServices: dashboardStore.healthServices,
    formatUci,
  })
})
</script>
