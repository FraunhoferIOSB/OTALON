<template>
  <q-layout view="lHh Lpr lFf">
    <q-header elevated class="app-header">
      <q-toolbar>
        <q-btn flat dense round icon="menu" aria-label="Toggle navigation" @click="appStore.toggleSidebar()" />

        <!-- Brand mark. Wordmark and symbol are both rendered and swapped via
             CSS media queries rather than v-if, so a viewport resize never
             triggers a component remount or a layout jump. Below the wordmark
             breakpoint the ~209px wordmark would crowd out the route title and
             the toolbar controls, so the compact symbol takes over. -->
        <NuxtLink to="/dashboard" class="app-logo-link q-ml-sm" aria-label="OTALON — go to dashboard">
          <OtalonWordmark class="app-logo app-logo--wordmark" />
          <OtalonSymbol class="app-logo app-logo--symbol" />
        </NuxtLink>

        <q-separator v-if="pageTitle" vertical inset class="q-mx-sm page-title-separator" />
        <span v-if="pageTitle" class="text-subtitle1 page-title" :title="pageTitle">
          {{ pageTitle }}
        </span>

        <q-space />

        <q-btn
          v-if="isOperationsChildRoute"
          flat
          dense
          round
          icon="refresh"
          aria-label="Refresh operations page"
          :loading="operationsRefreshLoading"
          :disable="!operationsRefreshAvailable"
          class="operations-refresh"
          @click="operationsRefresh.refresh"
        />

        <div v-if="auth.user" class="identity-whoami row items-center q-gutter-sm">
          <span class="text-caption text-muted">{{ auth.user.username }}</span>
          <q-chip dense outline size="sm" class="identity-role">{{ auth.user.role }}</q-chip>
          <q-btn flat dense label="Sign out" aria-label="Sign out" data-test="sign-out" @click="signOut" />
        </div>

        <div class="header-indicators row items-center q-gutter-x-md">
          <q-chip
            dense
            :color="systemStatusColor"
            text-color="white"
            size="sm"
            class="status-chip"
            :class="{ 'status-chip--recent-incident': showRecentIncidentRing }"
            clickable
            :aria-label="healthChipAriaLabel"
            data-test="system-status-chip"
            @click="openLatestIncident"
          >
            <span class="status-dot status-dot--sm status-chip__dot" :class="`status-dot--${systemStatusColor}`" />
            {{ systemStatusLabel }}
            <q-icon
              v-if="showRecentIncidentRing"
              name="history"
              size="14px"
              class="q-ml-xs status-chip__recent-icon"
              data-test="system-status-recent-icon"
            />
            <q-tooltip>{{ healthChipTooltip }}</q-tooltip>
          </q-chip>

          <div v-if="appStore.liveMode" class="live-indicator row items-center">
            <span class="status-dot status-dot--green status-dot--pulse" />
            <span class="q-ml-xs text-caption text-weight-medium">LIVE</span>
          </div>

          <span
            class="sse-dot"
            :class="`sse-dot--${sseStatusColor}`"
            tabindex="0"
            aria-label="Live health event connection"
          >
            <q-tooltip
              >Live health event connection: {{ appStore.sseConnectionStatus }}. It does not replace system
              health.</q-tooltip
            >
          </span>

          <q-btn flat dense round icon="notifications" aria-label="Alarms" to="/alarms">
            <q-badge v-if="dashboardStore.anomalyCount > 0" color="red" floating>
              {{ dashboardStore.anomalyCount }}
            </q-badge>
            <q-tooltip>Alarms</q-tooltip>
          </q-btn>

          <q-btn flat dense round icon="work_history" aria-label="Operations Jobs" to="/operations/jobs">
            <!-- Running count and the failed indicator are shown together so a
                 failure is never hidden behind a concurrent running job (B-F08). -->
            <q-badge
              v-if="operationsJobsStore.runningCount > 0"
              color="info"
              floating
              :aria-label="`${operationsJobsStore.runningCount} running jobs`"
            >
              {{ operationsJobsStore.runningCount }}
            </q-badge>
            <q-badge
              v-if="operationsJobsStore.hasFailed"
              color="red"
              floating
              :class="operationsJobsStore.runningCount > 0 ? 'operations-failed-badge--stacked' : ''"
              aria-label="Failed jobs present"
            >
              !
            </q-badge>
            <q-tooltip>Operations Jobs</q-tooltip>
          </q-btn>
        </div>

        <q-btn
          flat
          dense
          round
          :icon="isDark ? 'light_mode' : 'dark_mode'"
          :aria-label="isDark ? 'Switch to light mode' : 'Switch to dark mode'"
          class="q-ml-sm"
          @click="onToggleTheme"
        >
          <q-tooltip>{{ isDark ? 'Switch to light mode' : 'Switch to dark mode' }}</q-tooltip>
        </q-btn>
      </q-toolbar>
    </q-header>

    <q-drawer
      :model-value="true"
      bordered
      :mini="appStore.sidebarMini"
      :breakpoint="0"
      :width="220"
      :mini-width="60"
      class="app-sidebar"
    >
      <q-list padding class="sidebar-navigation q-pt-none">
        <template v-for="entry in navItems" :key="entry.label">
          <q-item
            v-if="isNavigationItem(entry)"
            v-ripple
            clickable
            :to="entry.route"
            :active="isActive(entry)"
            active-class="nav-item-active"
            class="nav-item"
          >
            <q-item-section avatar>
              <q-icon :name="entry.icon" />
            </q-item-section>
            <q-item-section>{{ entry.label }}</q-item-section>
          </q-item>

          <template v-else>
            <q-item
              v-if="appStore.sidebarMini"
              v-ripple
              clickable
              :class="{ 'nav-group-active': isGroupActive(entry) }"
              class="nav-item"
            >
              <q-item-section avatar>
                <q-icon :name="entry.icon" />
              </q-item-section>
              <q-menu anchor="top right" self="top left" :offset="[4, 0]">
                <q-list>
                  <q-item
                    v-for="child in entry.children"
                    :key="child.route"
                    v-ripple
                    v-close-popup
                    clickable
                    :to="child.route"
                    :active="isActive(child)"
                    active-class="nav-item-active"
                    class="nav-item"
                  >
                    <q-item-section avatar>
                      <q-icon :name="child.icon" />
                    </q-item-section>
                    <q-item-section>{{ child.label }}</q-item-section>
                  </q-item>
                </q-list>
              </q-menu>
            </q-item>

            <q-expansion-item
              v-else
              :icon="entry.icon"
              :label="entry.label"
              :default-opened="isGroupActive(entry)"
              dense-toggle
              class="nav-group"
              :class="{ 'nav-group-active': isGroupActive(entry) }"
            >
              <q-item
                v-for="child in entry.children"
                :key="child.route"
                v-ripple
                clickable
                :to="child.route"
                :active="isActive(child)"
                active-class="nav-item-active"
                class="nav-item nav-item--child"
              >
                <q-item-section avatar>
                  <q-icon :name="child.icon" />
                </q-item-section>
                <q-item-section>{{ child.label }}</q-item-section>
              </q-item>
            </q-expansion-item>
          </template>
        </template>
      </q-list>

      <q-space />

      <div class="sidebar-footer q-pa-sm">
        <div class="sidebar-chat-slot" data-test="sidebar-chat-slot" />
        <div class="row items-center justify-center">
          <q-btn
            flat
            dense
            icon="tour"
            :label="appStore.sidebarMini ? undefined : 'Getting Started'"
            aria-label="Open product tour"
            data-test="open-onboarding-tour"
            @click="openTour"
          />
          <span v-if="!appStore.sidebarMini" class="text-caption text-muted q-ml-xs">v0.1</span>
        </div>
      </div>
    </q-drawer>

    <a href="#main-content" class="skip-link">Skip to main content</a>
    <q-page-container>
      <div id="main-content">
        <slot />
      </div>
    </q-page-container>

    <ChatOverlay />
    <OnboardingTour />

    <!-- Global Scan Detail modal so row clicks work from any page -->
    <ScanDetailModal v-model="scanDetailOpen" :scan-id="scanDetailId" @replay="onReplayScanFromDetail" />

    <!-- Lightweight replay modal for the global detail view -->
    <ScanRunModal
      v-model="replayModalOpen"
      :target-devices="[]"
      :replay-scan-id="replayScanId"
      @started="onReplayStarted"
      @finished="onReplayFinished"
    />

    <JobNotificationListener
      v-for="jobId in jobStore.watchedLookupIds"
      :key="`lookup:${jobId}`"
      kind="lookup"
      :job-id="jobId"
    />
    <JobNotificationListener
      v-for="jobId in jobStore.watchedScanIds"
      :key="`scan:${jobId}`"
      kind="scan"
      :job-id="jobId"
    />
    <OperationsJobSseListener />
    <AppHealthSseListener />
    <HealthIncidentDrawer v-model="incidentDrawerOpen" :incident="incidentsStore.selected ?? incidentsStore.latest" />
  </q-layout>
</template>

<script setup lang="ts">
/**
 * Default application layout.
 *
 * Provides the header with status indicators, the collapsible sidebar
 * navigation, and the main content area. Reads global state from
 * appStore and dashboardStore instead of local refs.
 *
 * F-13.1: hosts the global Recent-Scans modal and ScanDetailModal so
 * scan history is reachable from any page without navigating back to
 * Assets.
 */
import { useQuasar } from 'quasar'

import { useAppStore } from '~/stores/appStore'
import { useDashboardStore } from '~/stores/dashboardStore'
import { useJobNotificationsStore } from '~/stores/jobNotificationsStore'
import { useOperationsJobsStore } from '~/stores/operationsJobsStore'
import { useOperationsRefresh } from '~/composables/useOperationsRefresh'
import JobNotificationListener from '~/components/JobNotificationListener.vue'
import AppHealthSseListener from '~/components/operations/AppHealthSseListener.vue'
import OperationsJobSseListener from '~/components/operations/OperationsJobSseListener.vue'
import HealthIncidentDrawer from '~/components/operations/HealthIncidentDrawer.vue'
import { useHealthIncidentsStore } from '~/stores/healthIncidentsStore'
import ScanDetailModal from '~/components/scan/ScanDetailModal.vue'
import ScanRunModal from '~/components/scan/ScanRunModal.vue'
import OnboardingTour from '~/components/shared/OnboardingTour.vue'
import OtalonSymbol from '~/components/shared/OtalonSymbol.vue'
import OtalonWordmark from '~/components/shared/OtalonWordmark.vue'
import { useAuthStore } from '~/stores/authStore'

const $q = useQuasar()
const route = useRoute()
const appStore = useAppStore()
const auth = useAuthStore()
const dashboardStore = useDashboardStore()
const jobStore = useJobNotificationsStore()
const operationsJobsStore = useOperationsJobsStore()
const incidentsStore = useHealthIncidentsStore()
const { navItems, isActive, isGroupActive } = useNavigation()
const tour = useOnboardingTour()
const operationsRefresh = useOperationsRefresh()
const { isAvailable: operationsRefreshAvailable, isLoading: operationsRefreshLoading } = operationsRefresh

async function signOut(): Promise<void> {
  await auth.logout()
  await navigateTo('/login', { replace: true })
}

const isDark = computed(() => $q.dark.isActive)
const incidentDrawerOpen = computed({
  get: () => incidentsStore.drawerOpen,
  set: (open: boolean) => {
    if (open) incidentsStore.drawerOpen = true
    else incidentsStore.close()
  },
})
const pageTitle = computed(() => (route.meta.title as string) ?? '')
const operationsChildRoutes = new Set([
  '/operations/overview',
  '/operations/data-sources',
  '/operations/detection',
  '/operations/jobs',
  '/operations/configuration',
  '/operations/system',
])
const isOperationsChildRoute = computed(() => operationsChildRoutes.has(route.path))

const replayModalOpen = ref(false)
const replayScanId = ref<string | null>(null)

const scanDetailOpen = computed({
  get: () => appStore.scanDetailModalOpen,
  set: (v: boolean) => {
    if (v) {
      appStore.openScanDetailModal(appStore.scanDetailModalScanId ?? '')
    } else {
      appStore.closeScanDetailModal()
    }
  },
})
const scanDetailId = computed(() => appStore.scanDetailModalScanId)

const systemStatusColor = computed(() => {
  const status = dashboardStore.overallHealthStatus
  switch (status) {
    case 'healthy':
      return 'green'
    case 'degraded':
      return 'amber'
    case 'unhealthy':
      return 'red'
    default:
      return 'grey'
  }
})

const systemStatusLabel = computed(() => {
  const status = dashboardStore.overallHealthStatus
  switch (status) {
    case 'healthy':
      return 'OK'
    case 'degraded':
      return 'WARN'
    case 'unhealthy':
      return 'ALARM'
    default:
      return '—'
  }
})

// After a recovery the aggregate returns to healthy, but the chip keeps an
// inspectable recent-incident ring + affordance for the 15-minute recent
// window so the operator can still open the evidence. Active incidents already
// force a non-green status, so the ring only decorates the recovered-recently
// case.
const showRecentIncidentRing = computed(() => !incidentsStore.hasActive && incidentsStore.hasRecent)

const healthChipTooltip = computed(() => {
  if (incidentsStore.hasActive) {
    return 'Active health incident — open the backend-owned evidence. SSE status describes only the live event connection.'
  }
  if (showRecentIncidentRing.value) {
    return 'Recovered health incident in the last 15 minutes — open the evidence. SSE status describes only the live event connection.'
  }
  return 'System status summarizes backend health checks. SSE status describes only the live event connection.'
})

const healthChipAriaLabel = computed(() => {
  if (showRecentIncidentRing.value) return 'Open recent health incident evidence'
  return `Open ${systemStatusLabel.value} health evidence`
})

async function openLatestIncident(): Promise<void> {
  if (incidentsStore.latest) {
    await incidentsStore.open(incidentsStore.latest.id)
  } else void navigateTo('/operations/system?tab=health')
}

const sseStatusColor = computed(() => {
  switch (appStore.sseConnectionStatus) {
    case 'connected':
      return 'green'
    case 'reconnecting':
      return 'amber'
    case 'disconnected':
      return 'red'
    default:
      return 'red'
  }
})

function onToggleTheme(): void {
  appStore.toggleTheme()
  $q.dark.set(appStore.isDark)
}

function onReplayScanFromDetail(scanId: string): void {
  replayScanId.value = scanId
  replayModalOpen.value = true
}

function onReplayStarted(scanId: string): void {
  $q.notify({ type: 'positive', message: `Scan started (${scanId})`, timeout: 3000 })
}

function onReplayFinished(scanId: string, status: 'completed' | 'failed' | 'cancelled'): void {
  $q.notify({
    type: status === 'completed' ? 'positive' : 'negative',
    message: `Scan ${status} (${scanId})`,
    timeout: 3000,
  })
}

watch(
  () => appStore.theme,
  (theme) => {
    $q.dark.set(theme === 'dark')
  },
)

onMounted(async () => {
  appStore.hydrateFromStorage()
  // Await the tour state (server + cache OR-merge) before deciding to open:
  // an account that completed the tour anywhere must never see the dialog,
  // not even for the round-trip duration of GET /dashboard/tour.
  await tour.setRoute(route.path)
  if (!tour.hasCompleted.value) tour.open()
  $q.dark.set(appStore.isDark)
  operationsJobsStore.fetchJobs().catch(() => {
    /* non-fatal for shell indicator */
  })
})

watch(
  () => route.path,
  async (path) => {
    await tour.setRoute(path)
    if (!tour.hasCompleted.value) tour.open()
  },
)

function openTour(): void {
  tour.open()
}

watch(
  () => operationsJobsStore.unnotifiedCompletions.length,
  (len) => {
    if (len === 0) return
    const list = operationsJobsStore.unnotifiedCompletions
    for (const job of list) {
      // markNotified is called synchronously BEFORE notify so a re-entrant
      // watcher tick cannot double-fire the same job (dedup, B-F08).
      operationsJobsStore.markNotified(job.id)
      $q.notify({
        // Include the job title so the operator knows which job J-<n> is.
        type: job.state === 'completed' ? 'positive' : 'negative',
        message: `Job ${job.display_id} (${job.title}) ${job.state}`,
        timeout: 6000,
        actions: [
          {
            label: 'Open',
            color: 'white',
            // Deep-link carries the job id so the page expands/focuses it.
            handler: () => navigateTo(`/operations/jobs?job=${job.id}`),
          },
        ],
      })
    }
    operationsJobsStore.persistNotifiedIds()
  },
)

watch(
  () => jobStore.unshown,
  (list) => {
    for (const n of list) {
      jobStore.markShown(n.id)
      $q.notify({
        type: n.status === 'completed' ? 'positive' : 'negative',
        message: `${n.title}: ${n.message}`,
        timeout: 6000,
        actions: [
          {
            label: 'Details',
            color: 'white',
            handler: () => {
              if (n.kind === 'lookup') {
                appStore.openCveLookupDialog(n.jobId)
              } else {
                appStore.openScanDetailModal(n.jobId)
              }
            },
          },
        ],
      })
    }
  },
  { deep: true },
)
</script>

<style scoped lang="scss">
.skip-link {
  position: absolute;
  top: -40px;
  left: 0;
  background: var(--cd-background);
  color: var(--cd-surface-text);
  padding: 8px 16px;
  z-index: 10000;
  text-decoration: none;
  font-weight: 600;
  border: 1px solid var(--cd-border);
  border-radius: 0 0 4px 0;
  transition: top 0.2s ease;
}
.skip-link:focus {
  top: 0;
}

#main-content {
  min-width: 0;
}

@media (max-width: 700px) {
  #main-content {
    padding-right: 0;
    padding-bottom: 88px;
  }
}

/* The 1px bottom border is part of the header box, so the header measures
   51px while pages sized themselves with `calc(100vh - 50px)` — a one-pixel
   overflow that produced a permanent, near-empty scrollbar on every full-height
   page (UI-095). The real height is published here so pages subtract the
   measured value instead of a hard-coded guess. */
:global(:root) {
  --cd-header-height: 51px;
}

.app-header {
  background-color: var(--cd-background);
  color: var(--cd-surface-text);
  border-bottom: 1px solid var(--cd-border);
}

.body--dark .app-header {
  background-color: $dark-header-bg;
}

// ── Brand mark (replaces the former .app-title wordmark text) ──────────
// The link is the sizing anchor; the two marks inherit their height from it so
// the wordmark/symbol swap never changes the toolbar height (the published
// --cd-header-height above depends on it).
.app-logo-link {
  display: inline-flex;
  align-items: center;
  flex: 0 0 auto;
  color: inherit;
  text-decoration: none;
  border-radius: 4px;
  // Keyboard focus must stay visible: the mark is the only route to the
  // dashboard from a child page besides the sidebar.
  &:focus-visible {
    outline: 2px solid var(--q-primary);
    outline-offset: 2px;
  }
}

// Descendant selector on purpose: the marks carry their own scoped default
// height, and a bare `.app-logo` would tie the outcome to stylesheet order.
.app-logo-link .app-logo {
  height: 22px;
  width: auto;
}

// Above the breakpoint the wordmark (~209px at 22px height) fits comfortably.
.app-logo-link .app-logo--symbol {
  display: none;
}

.page-title {
  font-weight: 500;
  opacity: 0.85;
  white-space: nowrap;
  // Allow the route title to shrink and truncate instead of pushing the
  // refresh/theme controls off a narrow viewport (B-F2). The full title stays
  // available via the `title` attribute tooltip and is never removed.
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
}

.app-sidebar {
  display: flex;
  flex-direction: column;
  background-color: var(--cd-background);
}

.sidebar-navigation {
  flex: 0 1 auto;
  min-height: 0;
  overflow-y: auto;
}

.body--dark .app-sidebar {
  background-color: $dark-sidebar-bg;
}

.nav-item {
  border-radius: 0;
  margin: 1px 0;
  padding-left: 12px;
  border-left: 3px solid transparent;
  transition:
    border-color 0.2s ease,
    background-color 0.2s ease;
}

.nav-item-active {
  border-left: 3px solid var(--q-primary);
  background-color: rgba(var(--cd-primary-rgb), 0.1);
  color: var(--q-primary);
  font-weight: 600;
}

.nav-item--child {
  padding-left: 24px;
}

.nav-group :deep(.q-expansion-item__container > .q-item) {
  border-radius: 0;
  margin: 1px 0;
  padding-left: 12px;
  border-left: 3px solid transparent;
}

.nav-group-active :deep(.q-expansion-item__container > .q-item) {
  color: var(--q-primary);
  font-weight: 600;
}

.nav-item.nav-group-active {
  color: var(--q-primary);
  font-weight: 600;
}

.sidebar-footer {
  position: relative;
  min-height: 72px;
  border-top: 1px solid var(--cd-border);
}

.sidebar-chat-slot {
  width: 44px;
  height: 56px;
  margin: 0 auto;
}

@media (max-width: 700px) {
  .sidebar-chat-slot {
    display: none;
  }
}

.header-indicators {
  font-size: 13px;
}

.operations-refresh {
  flex: 0 0 auto;
  margin-right: 8px;
}

.status-chip {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.5px;

  .status-dot {
    margin-right: 4px;
  }
}

// Recovered-recently affordance: the aggregate is healthy again, but a
// recent incident is still inspectable, so the chip carries a distinct ring
// and a history icon that does not rely on color alone.
.status-chip--recent-incident {
  box-shadow: 0 0 0 2px var(--cd-warning, #b26a00);
  outline: 1px solid rgba(0, 0, 0, 0.15);

  .status-chip__recent-icon {
    opacity: 0.95;
  }
}

.live-indicator {
  font-size: 12px;
  color: $color-success;
}

.sse-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;

  &--green {
    background-color: $color-success;
  }

  &--amber {
    background-color: $color-warning;
  }

  &--red {
    background-color: $color-danger;
  }
}

// When a running-count badge and the failed indicator are shown together,
// offset the failed badge so both remain visible on the same button (B-F08).
.operations-failed-badge--stacked {
  transform: translateY(18px);
}

// ── Brand mark breakpoint ──────────────────────────────────────────────
// The wordmark needs ~209px at 22px height. Together with the menu button, the
// route title and the indicator cluster that no longer fits below 1024px, so
// the square symbol (22px) takes over. Both marks stay mounted; only their
// visibility flips, which keeps resizing free of layout jumps.
@media (max-width: 1023px) {
  .app-logo-link .app-logo--wordmark {
    display: none;
  }
  .app-logo-link .app-logo--symbol {
    display: block;
  }
}

// ── Narrow-viewport header grammar (B-F2) ──────────────────────────────
// Below 700px the toolbar must keep the route title readable AND keep the
// Operations refresh, theme toggle and jobs entry wholly inside the viewport
// and keyboard reachable. Lower-priority status indicators compact or hide
// accessibly; the essential live/status truth stays present via the system
// status chip. No horizontal overflow is introduced.
@media (max-width: 700px) {
  .app-header .q-toolbar {
    padding-left: 8px;
    padding-right: 8px;
    flex-wrap: nowrap;
  }
  .page-title {
    // Cap the title so it can never crowd out the action controls; it still
    // shows an ellipsis + tooltip rather than being removed.
    max-width: 34vw;
    font-size: 13px;
  }
  .header-indicators.q-gutter-x-md {
    // Tighten the indicator gutter (Quasar applies it as child margins, so it
    // must be overridden per-child) to reclaim width for the action controls.
    margin-left: -8px;
  }
  .header-indicators.q-gutter-x-md > * {
    margin-left: 8px;
  }
  // The pulsing LIVE word is redundant with the SSE dot on very small widths.
  .live-indicator .text-caption {
    display: none;
  }
}

@media (max-width: 480px) {
  .page-title {
    max-width: 30vw;
  }
  .header-indicators.q-gutter-x-md {
    margin-left: -4px;
  }
  .header-indicators.q-gutter-x-md > * {
    margin-left: 4px;
  }
  // The system status chip keeps its colored dot (health truth) but drops the
  // textual label to save width; the tooltip still explains it.
  .status-chip {
    padding: 0 4px;
  }
  .status-chip :deep(.q-chip__content) {
    font-size: 0;
  }
  .status-chip :deep(.status-chip__dot) {
    margin-right: 0;
  }
  // Alarms + jobs badges remain, but the notifications bell is lower priority
  // than refresh/theme; hide it here to guarantee the primary controls fit.
  .header-indicators .q-btn[aria-label='Alarms'] {
    display: none;
  }
}

@media (max-width: 390px) {
  .page-title {
    max-width: 26vw;
  }
  .page-title-separator {
    display: none;
  }
}
</style>
