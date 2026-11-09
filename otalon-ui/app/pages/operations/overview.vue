<template>
  <div class="cd-overview">
    <InsufficientPermissionsNotice :message="firstAuthorizationError" />
    <q-banner v-if="bannerVisible && bannerFinding" rounded dense class="cd-banner q-mb-md">
      <template #avatar>
        <q-icon name="warning" color="warning" size="22px" />
      </template>
      <b>{{ bannerFinding.title }}</b>
      <template #action>
        <q-btn flat dense no-caps size="sm" label="Inspect" :to="bannerFinding.link.route" />
        <q-btn flat dense no-caps size="sm" label="Acknowledge" @click="bannerVisible = false" />
      </template>
    </q-banner>

    <div class="row q-col-gutter-md q-mb-md">
      <div class="col-12 col-sm-6 col-md-3">
        <KpiCard
          label="Suite"
          :value="store.suiteKpi.value"
          icon="admin_panel_settings"
          :signal-color="kpiSignalColor(store.suiteKpi.signal)"
          :trend-label="store.suiteKpi.sub"
          to="/operations/system"
        />
      </div>
      <div class="col-12 col-sm-6 col-md-3">
        <KpiCard
          label="Pipeline"
          :value="store.pipelineKpi.value"
          icon="cloud_upload"
          :signal-color="kpiSignalColor(store.pipelineKpi.signal)"
          :trend-label="store.pipelineKpi.sub"
          to="/operations/data-sources"
        />
      </div>
      <div class="col-12 col-sm-6 col-md-3">
        <KpiCard
          label="Detection"
          :value="store.detectionKpi.value"
          icon="psychology"
          :signal-color="kpiSignalColor(store.detectionKpi.signal)"
          :trend-label="store.detectionKpi.sub"
          to="/operations/detection"
        />
      </div>
      <div class="col-12 col-sm-6 col-md-3">
        <KpiCard
          label="Storage"
          :value="store.storageKpi.value"
          icon="storage"
          :signal-color="kpiSignalColor(store.storageKpi.signal)"
          :trend-label="store.storageKpi.sub"
          to="/operations/system?tab=storage"
        />
      </div>
    </div>

    <q-card flat bordered class="q-mb-md">
      <q-card-section class="cd-section-title row items-center no-wrap">
        <span>Data path freshness</span>
        <q-spinner
          v-if="isInitialLoading"
          size="14px"
          class="q-ml-sm text-primary"
          aria-label="Loading operations data"
        />
        <span v-if="isInitialLoading" class="text-caption text-muted q-ml-xs">loading…</span>
      </q-card-section>
      <q-separator />
      <q-card-section class="cd-pipeline row items-stretch no-wrap">
        <div class="cd-stage col">
          <div class="cd-stage__head">
            <CdSignalDot :signal="captureSignal" />
            <span>Capture</span>
          </div>
          <div class="cd-stage__rows">
            <span>{{ captureLabel }}</span>
          </div>
        </div>
        <q-icon name="arrow_forward" class="cd-stage__arrow self-center" size="28px" />
        <div class="cd-stage col" :class="{ 'cd-stage--warn': influxStage.warn }">
          <div class="cd-stage__head">
            <CdSignalDot :signal="influxStage.signal" />
            <span>Influx ingest</span>
          </div>
          <div class="cd-stage__rows">
            <span
              v-for="source in sourceRows"
              :key="source.name"
              :class="{ 'text-warning text-weight-bold': source.warn }"
            >
              {{ source.label }} {{ source.text }}
            </span>
          </div>
        </div>
        <q-icon name="arrow_forward" class="cd-stage__arrow self-center" size="28px" />
        <div class="cd-stage col" :class="{ 'cd-stage--warn': detectionStage.warn }">
          <div class="cd-stage__head">
            <CdSignalDot :signal="detectionStage.signal" />
            <span>Detection</span>
          </div>
          <div class="cd-stage__rows">
            <span>{{ detectionStage.cycleText }}</span>
            <span>{{ detectionStage.durationText }}</span>
            <span>{{ detectionStage.seriesText }}</span>
          </div>
        </div>
        <q-icon name="arrow_forward" class="cd-stage__arrow self-center" size="28px" />
        <div class="cd-stage col">
          <div class="cd-stage__head">
            <CdSignalDot :signal="persistenceSignal" />
            <span>Persistence</span>
          </div>
          <div class="cd-stage__rows">
            <span>{{ persistenceWriteText }}</span>
            <span>{{ persistenceBacklogText }}</span>
          </div>
        </div>
        <q-icon name="info" size="16px" class="cd-pipeline__help text-grey-5">
          <q-tooltip max-width="340px">
            Freshness is judged against the configured capture/poll frequency — "no data", "stale" and "current" are
            distinct states.
          </q-tooltip>
        </q-icon>
      </q-card-section>
    </q-card>

    <div class="row q-col-gutter-md">
      <div class="col-12 col-md-7">
        <q-card flat bordered class="full-height">
          <q-card-section class="row items-center q-py-sm">
            <span class="cd-card-title">Service Health</span>
            <q-space />
            <span class="text-caption text-muted">polled {{ store.healthPolledAt ?? '—' }}</span>
          </q-card-section>
          <q-separator />
          <q-item
            v-for="incident in incidentsStore.unacknowledged.slice(0, 3)"
            :key="incident.id"
            clickable
            class="incident-row q-mx-sm q-my-sm"
            @click="openIncident(incident)"
          >
            <q-item-section avatar
              ><q-icon
                :name="incident.status === 'active' ? 'warning' : 'history'"
                :color="incident.status === 'active' ? 'warning' : 'positive'"
            /></q-item-section>
            <q-item-section>
              <q-item-label>Health incident · {{ incident.service }}</q-item-label>
              <q-item-label caption
                >{{ incident.status === 'active' ? 'Active' : 'Recovered recently' }} ·
                {{ incident.cause }}</q-item-label
              >
            </q-item-section>
            <q-item-section side>
              <q-btn
                flat
                dense
                no-caps
                label="Acknowledge"
                :loading="incidentsStore.isAcknowledging(incident.id)"
                :disable="incidentsStore.isAcknowledging(incident.id)"
                :aria-busy="incidentsStore.isAcknowledging(incident.id)"
                :aria-label="`Acknowledge health incident for ${incident.service}`"
                :data-test="`acknowledge-${incident.id}`"
                @click.stop="acknowledgeIncident(incident.id)"
              />
              <q-icon name="chevron_right" />
            </q-item-section>
          </q-item>
          <q-banner
            v-if="incidentsStore.acknowledgeError"
            dense
            class="bg-negative text-white q-mx-sm q-mb-sm"
            role="alert"
            data-test="acknowledge-error"
          >
            {{ incidentsStore.acknowledgeError }}
          </q-banner>
          <q-markup-table flat dense class="cd-table">
            <thead>
              <tr>
                <th class="text-left">Service</th>
                <th class="text-left">State</th>
                <th class="text-right">Detail</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="svc in store.problemServices" :key="svc.name">
                <td class="cd-mono">
                  {{ svc.name }}
                  <q-icon
                    v-if="svc.classification === 'optional'"
                    name="extension"
                    size="12px"
                    class="text-muted q-ml-xs"
                  >
                    <q-tooltip>Optional component — "not configured" is not a failure.</q-tooltip>
                  </q-icon>
                </td>
                <td>
                  <CdStateBadge
                    :kind="store.badgeFor(svc).kind"
                    :label="store.badgeFor(svc).label"
                    :icon="store.badgeFor(svc).icon"
                  />
                </td>
                <td class="text-right cd-mono">{{ svc.detail }}</td>
              </tr>
              <tr class="cd-summary-row">
                <td class="text-positive row items-center no-wrap">
                  <q-icon name="check_circle" size="16px" class="q-mr-xs" />
                  {{ store.healthyCount }} healthy
                </td>
                <td colspan="2" class="text-right">
                  <q-btn
                    flat
                    dense
                    no-caps
                    size="sm"
                    color="primary"
                    label="Services & Logs"
                    to="/operations/system?tab=services"
                  />
                </td>
              </tr>
            </tbody>
          </q-markup-table>
        </q-card>
      </div>

      <div class="col-12 col-md-5">
        <q-card flat bordered class="full-height">
          <q-card-section class="row items-center q-py-sm">
            <span class="cd-card-title">Attention Required</span>
            <q-space />
            <q-icon name="info" size="14px" class="text-grey-5">
              <q-tooltip max-width="320px">
                Ranked by operational impact. Click a link to open the owning page.
              </q-tooltip>
            </q-icon>
          </q-card-section>
          <q-separator />
          <q-list separator>
            <q-item v-for="finding in store.attention" :key="finding.title">
              <q-item-section avatar class="cd-priority">
                <CdStateBadge :kind="badgeKind(finding.priority)" :label="finding.priority" />
              </q-item-section>
              <q-item-section>
                <q-item-label class="text-body2">{{ finding.title }}</q-item-label>
              </q-item-section>
              <q-item-section side>
                <q-btn
                  flat
                  dense
                  no-caps
                  size="sm"
                  color="primary"
                  :label="finding.link.label"
                  :to="finding.link.route"
                  :aria-label="`Open ${finding.link.label}`"
                />
              </q-item-section>
            </q-item>
            <q-item v-if="store.attention.length === 0">
              <q-item-section>
                <q-item-label class="text-body2 text-muted"> No operational findings require attention. </q-item-label>
              </q-item-section>
            </q-item>
          </q-list>
        </q-card>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import CdSignalDot from '~/components/operations/SignalDot.vue'
import CdStateBadge from '~/components/operations/StateBadge.vue'
import KpiCard from '~/components/shared/KpiCard.vue'
import InsufficientPermissionsNotice from '~/components/shared/InsufficientPermissionsNotice.vue'
import { useOperationsRefresh } from '~/composables/useOperationsRefresh'
import { SOURCE_LABELS, useOperationsOverviewStore } from '~/stores/operationsOverviewStore'
import type { HealthIncidentSummary, PipelineSource } from '~/types/api'
import type { SignalColor } from '~/types/golden-data'
import { useHealthIncidentsStore } from '~/stores/healthIncidentsStore'
import { isInsufficientPermissionsMessage } from '~/utils/permissions'

/**
 * Operations / Overview — the read-only summary of suite readiness.
 *
 * Renders the four frozen KPIs, a real pipeline freshness strip, the Service
 * Health summary and the Attention Required list. Detection and Storage use
 * their live readiness and host-usage fact sources.
 */

definePageMeta({
  title: 'Operations / Overview',
})

const store = useOperationsOverviewStore()
const firstAuthorizationError = computed(() =>
  [store.pipelineError, store.attentionError, store.healthError, store.readinessError, store.storageError].find((error) =>
    isInsufficientPermissionsMessage(error),
  ) ?? null,
)
const incidentsStore = useHealthIncidentsStore()
const bannerVisible = ref(true)
const operationsRefresh = useOperationsRefresh()

onMounted(() => {
  operationsRefresh.register(
    () => store.loadAll(),
    () => store.isLoadingPipeline || store.isLoadingAttention || store.isLoadingHealth,
  )
  void operationsRefresh.refresh()
})

onUnmounted(operationsRefresh.unregister)

usePolling(operationsRefresh.refresh, 5000)

// Live health is owned by the persistent shell `AppHealthSseListener` (a single
// global `health` stream fanned out to this store as well as the dashboard
// store that backs the header chip). The page therefore does NOT open its own
// health stream — that would duplicate the upstream connection. The initial
// snapshot arrives via `loadAll()` → `fetchHealth()`, and subsequent live
// updates via the shared shell listener's `handleHealthUpdate` fan-out.

const bannerFinding = computed(() => store.attention[0] ?? null)

async function openIncident(incident: HealthIncidentSummary): Promise<void> {
  await navigateTo(`/operations/system?tab=health&incident=${encodeURIComponent(incident.id)}`)
}

async function acknowledgeIncident(id: string): Promise<void> {
  await incidentsStore.acknowledge(id)
}

// Bounded, non-obscuring loading indicator: only while the first pipeline
// fetch is in flight AND no data has arrived yet. It clears as soon as data
// (or an error) lands, so the page shell always paints and the spinner never
// lingers or covers content.
const isInitialLoading = computed(
  () => store.isLoadingPipeline && store.pipeline === null && store.pipelineError === null,
)

const kpiSignalColor = (signal: string): SignalColor | undefined => {
  if (signal === 'green') return 'success'
  if (signal === 'amber') return 'warning'
  if (signal === 'red') return 'danger'
  return undefined
}

const badgeKind = (priority: string): 'err' | 'warn' | 'info' => {
  switch (priority) {
    case 'High':
      return 'err'
    case 'Medium':
      return 'warn'
    default:
      return 'info'
  }
}

const sourceByName = (name: string): PipelineSource | undefined => store.pipeline?.sources.find((s) => s.name === name)

const sourceRows = computed(() => {
  return (['conn', 'mac', 'proto'] as const).map((name) => {
    const source = sourceByName(name)
    const label = SOURCE_LABELS[name]
    if (!source) {
      return { name, label, text: '—', warn: false }
    }
    if (source.state === 'no-data') {
      return { name, label, text: 'no data', warn: true }
    }
    if (source.state === 'stale') {
      return {
        name,
        label,
        text: `stale · ${formatDuration(source.age_seconds ?? 0)}`,
        warn: true,
      }
    }
    return {
      name,
      label,
      text: `current · ${formatDuration(source.age_seconds ?? 0)}`,
      warn: false,
    }
  })
})

const influxStage = computed(() => {
  const staleCount = sourceRows.value.filter((s) => s.warn).length
  const hasNoData = store.pipeline?.sources.some((s) => s.state === 'no-data') ?? false
  if (hasNoData) {
    return { signal: 'red' as const, warn: true }
  }
  if (staleCount > 0) {
    return { signal: 'amber' as const, warn: true }
  }
  return { signal: 'green' as const, warn: false }
})

const captureSignal = computed(() => {
  if (influxStage.value.signal === 'red') return 'red' as const
  if (influxStage.value.signal === 'amber') return 'amber' as const
  return 'green' as const
})

const captureLabel = computed(() => {
  if (influxStage.value.signal === 'red') return 'capture path unclear'
  if (influxStage.value.signal === 'amber') return 'capture active · ingest delayed'
  return 'capture active'
})

const detectionStage = computed(() => {
  const detection = store.pipeline?.detection
  if (!detection?.last_cycle) {
    return {
      signal: 'grey' as const,
      warn: false,
      cycleText: 'last cycle —',
      durationText: 'duration unavailable',
      seriesText: 'series —',
    }
  }
  const signal = (detection.age_seconds ?? 0) > 300 ? ('amber' as const) : ('green' as const)
  const duration = detection.duration_seconds
  return {
    signal,
    warn: signal === 'amber',
    cycleText: `last cycle ${formatDuration(detection.age_seconds ?? 0)} ago`,
    // Render unavailable cleanly — never a dangling "duration — s".
    durationText: duration === null || duration === undefined ? 'duration unavailable' : `duration ${duration} s`,
    seriesText: `${detection.series_evaluated ?? '—'} series evaluated`,
  }
})

const persistenceSignal = computed(() => {
  if (influxStage.value.signal === 'red') return 'red' as const
  if (influxStage.value.signal === 'amber') return 'amber' as const
  return 'green' as const
})

const persistenceWriteText = computed(() => {
  const age = store.pipeline?.influx.age_seconds
  if (age === null || age === undefined) return 'latest record —'
  return `latest record ${formatDuration(age)} ago`
})

const persistenceBacklogText = computed(() => {
  const backlog = store.pipeline?.backlog
  if (backlog === null || backlog === undefined) return 'backlog —'
  return `backlog ${backlog}`
})

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds} s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min`
  return `${Math.floor(seconds / 3600)} h ${Math.floor((seconds % 3600) / 60)} min`
}
</script>

<style scoped lang="scss">
.cd-overview > :first-child {
  margin-top: 0 !important;
}

.cd-banner {
  border: 1px solid rgba(var(--cd-warning-rgb), 0.4);
  background: rgba(var(--cd-warning-rgb), 0.08);
}

.cd-section-title {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.4px;
  color: var(--cd-muted);
}

.cd-pipeline {
  gap: 8px;
  position: relative;

  &__help {
    position: absolute;
    top: 10px;
    right: 12px;
  }
}

.cd-stage {
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-md;
  padding: 10px 12px;
  min-width: 0;

  &--warn {
    border-color: rgba(var(--cd-warning-rgb), 0.5);
    background: rgba(var(--cd-warning-rgb), 0.05);
  }

  &__head {
    display: flex;
    align-items: center;
    gap: 6px;
    font-weight: 700;
    font-size: 14px;
    margin-bottom: 8px;
  }

  &__rows {
    display: flex;
    flex-direction: column;
    gap: 2px;
    font-size: 12px;
    color: var(--cd-muted);
  }

  &__arrow {
    color: var(--q-primary);
    flex: 0 0 auto;
    opacity: 0.6;
  }
}

.cd-card-title {
  font-size: 14px;
  font-weight: 600;
}

.cd-table {
  td,
  th {
    font-size: 12px;
  }
}

.cd-mono {
  font-family: $font-family-mono;
  font-size: 12px;
}

.cd-priority {
  min-width: 0;
  padding-right: 8px;

  :deep(.cd-state-badge) {
    min-width: 72px;
  }
}

.cd-summary-row {
  background: rgba(var(--cd-success-rgb), 0.04);
}

.incident-row {
  border: 1px solid var(--cd-border);
  border-left: 3px solid var(--q-warning);
  border-radius: $border-radius-sm;
}

@media (max-width: 1023px) {
  .cd-pipeline {
    flex-wrap: wrap;

    .cd-stage {
      flex: 1 1 40%;
    }

    .cd-stage__arrow {
      display: none;
    }
  }
}
</style>
