<template>
  <div class="cd-data-sources">
    <div class="row q-col-gutter-md q-mb-md">
      <div class="col-12 col-md-7">
        <q-card flat bordered class="full-height">
          <q-card-section class="row items-center q-py-sm">
            <span class="cd-card-title">Live Capture</span>
            <q-spinner
              v-if="isInitialLoading"
              size="14px"
              class="q-ml-sm text-primary"
              aria-label="Loading capture status"
              data-test="loading-spinner"
            />
            <span v-if="isInitialLoading" class="text-caption text-muted q-ml-xs">loading…</span>
            <q-space />
            <span
              v-if="store.captureStatus?.interface"
              class="text-subtitle1 text-weight-bold cd-mono"
              data-test="capture-interface"
            >
              {{ store.captureStatus.interface }}
            </span>
          </q-card-section>
          <q-separator />
          <q-card-section v-if="loadError" class="q-py-sm">
             <InsufficientPermissionsNotice :message="loadError" />
             <q-banner v-if="!isInsufficientPermissionsMessage(loadError)" rounded dense class="cd-inline-warn" data-test="load-error">
              <template #avatar>
                <q-icon name="error_outline" color="negative" size="18px" />
              </template>
              <span class="text-caption">{{ loadError }}</span>
            </q-banner>
          </q-card-section>
          <q-separator v-if="loadError" />
          <q-card-section class="row q-col-gutter-md">
            <div class="col-6 col-sm-3">
              <div class="cd-fact__label">
                Interface
                 <q-icon name="info" color="grey-5" size="14px"
                  ><q-tooltip>Physical capture link state reported by recorder.</q-tooltip></q-icon
                >
              </div>
              <CdSignalDot :signal="linkSignal" :label="linkLabel" data-test="capture-link" />
            </div>
            <div class="col-6 col-sm-3">
              <div class="cd-fact__label">
                Recording
                 <q-icon name="info" color="grey-5" size="14px"
                  ><q-tooltip>Whether recorder is writing captured traffic.</q-tooltip></q-icon
                >
              </div>
              <CdSignalDot :signal="recordingSignal" :label="recordingLabel" data-test="capture-recording" />
            </div>
            <div class="col-6 col-sm-3">
              <div class="cd-fact__label">
                Drops (24 h)
                 <q-icon name="info" color="grey-5" size="14px"
                  ><q-tooltip>Packets dropped by recorder in last 24 hours. Dash means unavailable.</q-tooltip></q-icon
                >
              </div>
              <span class="text-subtitle2 text-weight-bold" data-test="capture-drops">
                {{ dropsLabel }}
              </span>
            </div>
            <div class="col-6 col-sm-3">
              <div class="cd-fact__label">
                Overflows
                 <q-icon name="info" color="grey-5" size="14px"
                  ><q-tooltip>Capture buffer overflows reported by recorder. Dash means unavailable.</q-tooltip></q-icon
                >
              </div>
              <span class="text-subtitle2 text-weight-bold" data-test="capture-overflows">
                {{ overflowsLabel }}
              </span>
            </div>
          </q-card-section>
          <q-separator />
          <q-card-section class="q-py-sm">
            <q-markup-table flat dense class="cd-table cd-source-table">
              <thead>
                <tr>
                  <th class="text-left">Source</th>
                  <th class="text-left">Status</th>
                  <th class="text-left">Last record</th>
                  <th class="text-right">Records/h</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="src in store.sourceRows" :key="src.name" :data-source="src.name" data-test="source-row">
                  <td>
                    <div class="row items-center no-wrap">
                      <q-icon :name="sourceIcon(src.name)" size="18px" color="primary" class="q-mr-sm" />
                      <span class="text-weight-bold">{{ friendlySourceName(src.name) }}</span>
                    </div>
                    <div class="text-caption text-muted">{{ src.name }}</div>
                  </td>
                  <td>
                    <CdStateBadge :kind="sourceBadgeKind(src.state)" :label="src.state" />
                  </td>
                  <td>
                    {{ lastRecordText(src.last_record) }}
                    <div class="text-caption text-muted">{{ ageLabel(src.age_seconds) }}</div>
                  </td>
                  <td class="text-right">
                    {{ recordsPerHourText(src) }}
                  </td>
                </tr>
                <tr v-if="isSourcesEmpty" data-test="source-empty">
                  <td colspan="4" class="text-center text-muted q-py-md">
                    {{ loadError ? 'Source freshness unavailable.' : 'No source freshness data yet.' }}
                  </td>
                </tr>
              </tbody>
            </q-markup-table>
            <q-banner v-if="store.staleBanner" rounded dense class="cd-inline-warn q-mt-sm" data-test="stale-banner">
              <template #avatar>
                <q-icon name="warning_amber" color="warning" size="18px" />
              </template>
              <span class="text-caption">{{ store.staleBanner }}</span>
            </q-banner>
          </q-card-section>
        </q-card>
      </div>

      <div class="col-12 col-md-5">
        <q-card flat bordered class="full-height">
          <q-card-section class="row items-center q-py-sm">
            <span class="cd-card-title">Passive Discovery</span>
            <q-space />
            <CdStateBadge
              :kind="passiveBadge.kind"
              :label="passiveBadge.label"
              :icon="passiveBadgeIcon"
              data-test="passive-badge"
            />
            <q-icon name="info" size="14px" class="text-grey-5 q-ml-sm">
              <q-tooltip max-width="320px">
                Discovers assets from observed traffic persisted by the passive seeder — no packets are sent. Enable
                state, poll interval and lookback window are runtime-controlled; this page shows status only, the
                controls live on Operations → Configuration → Runtime.
              </q-tooltip>
            </q-icon>
          </q-card-section>
          <q-separator />
          <q-card-section v-if="store.passiveError" class="q-py-sm">
             <InsufficientPermissionsNotice :message="store.passiveError" />
             <q-banner v-if="!isInsufficientPermissionsMessage(store.passiveError)" rounded dense class="cd-inline-warn" data-test="passive-error">
              <template #avatar>
                <q-icon name="error_outline" color="negative" size="18px" />
              </template>
              <span class="text-caption">{{ store.passiveError }}</span>
            </q-banner>
          </q-card-section>
          <q-separator v-if="store.passiveError" />
          <q-card-section>
            <div class="row q-col-gutter-md">
              <div class="col-6">
                <div class="cd-fact__label">
                  Assets known
                  <q-icon name="info" size="14px"
                     color="grey-5"><q-tooltip>Distinct devices with a persisted passively-observed interface.</q-tooltip></q-icon
                  >
                </div>
                <span class="text-subtitle1 text-weight-bold cd-mono" data-test="passive-assets">
                  {{ passiveAssetsLabel }}
                </span>
              </div>
              <div class="col-6">
                <div class="cd-fact__label">
                  Last observed
                  <q-icon name="info" size="14px"
                     color="grey-5"><q-tooltip>Most recent passively-observed timestamp persisted by the seeder.</q-tooltip></q-icon
                  >
                </div>
                <span class="text-subtitle2 text-weight-bold cd-mono" data-test="passive-last-seen">
                  {{ passiveLastSeenLabel }}
                </span>
                <div class="text-caption text-muted" data-test="passive-age">{{ passiveAgeLabel }}</div>
              </div>
            </div>
            <q-separator class="q-my-md" />

            <div class="row items-center q-gutter-sm q-mb-sm">
              <span class="cd-fact__label q-mb-none">Seeder process</span>
              <CdStateBadge :kind="seederBadge.kind" :label="seederBadge.label" data-test="seeder-state" />
            </div>

            <q-banner
              v-if="store.seederError && !isInsufficientPermissionsMessage(store.seederError)"
              rounded
              dense
              class="cd-inline-warn q-mb-sm"
              data-test="seeder-fetch-error"
            >
              <template #avatar>
                <q-icon name="error_outline" color="negative" size="18px" />
              </template>
              <span class="text-caption">{{ store.seederError }}</span>
            </q-banner>

            <q-banner
              v-if="store.seederStatus?.last_error"
              rounded
              dense
              class="cd-inline-warn q-mb-sm"
              data-test="seeder-last-error"
            >
              <template #avatar>
                <q-icon name="error_outline" color="negative" size="18px" />
              </template>
              <span class="text-caption">{{ store.seederStatus.last_error }}</span>
            </q-banner>

            <div v-if="seederState === 'unknown'" class="text-caption text-muted q-mb-sm" data-test="seeder-unknown">
              The seeder has not reported a status yet — no status row exists. This is not the same as being disabled.
            </div>

            <div class="row q-col-gutter-md">
              <div class="col-4">
                <div class="cd-fact__label">
                  Last cycle
                  <q-icon name="info" size="14px"
                     color="grey-5"><q-tooltip>When the seeder last completed a poll cycle.</q-tooltip></q-icon
                  >
                </div>
                <span class="text-subtitle2 text-weight-bold cd-mono" data-test="seeder-last-cycle">
                  {{ seederLastCycleLabel }}
                </span>
              </div>
              <div class="col-4">
                <div class="cd-fact__label">
                  Rows last cycle
                  <q-icon name="info" size="14px"
                     color="grey-5"><q-tooltip
                      >Rows written by the most recent cycle only — this is not a cumulative total.</q-tooltip
                    ></q-icon
                  >
                </div>
                <span class="text-subtitle2 text-weight-bold cd-mono" data-test="seeder-rows">
                  {{ seederRowsLabel }}
                </span>
              </div>
              <div class="col-4">
                <div class="cd-fact__label">
                  Poll interval
                  <q-icon name="info" size="14px"
                     color="grey-5"><q-tooltip>Interval the seeder is currently applying.</q-tooltip></q-icon
                  >
                </div>
                <span class="text-subtitle2 text-weight-bold cd-mono" data-test="seeder-poll-interval">
                  {{ seederPollIntervalLabel }}
                </span>
              </div>
            </div>

            <div class="row items-center q-mt-md">
              <div class="col text-caption text-muted" data-test="passive-controls-note">
                Status only on this page — enable state, poll interval and lookback window are changed on Configuration
                → Runtime and apply within one poll cycle.
              </div>
            </div>
            <div class="row items-center q-mt-sm">
              <q-btn
                flat
                dense
                no-caps
                color="primary"
                icon="tune"
                label="Open Runtime configuration"
                data-test="seeder-runtime-link"
                :to="RUNTIME_CONFIG_ROUTE"
              />
            </div>
          </q-card-section>
        </q-card>
      </div>
    </div>

    <div class="row q-col-gutter-md">
      <div class="col-12">
        <q-card flat bordered>
          <q-card-section class="row items-center q-py-xs">
            <span class="cd-card-title">PCAP Import &amp; Replay</span>
          </q-card-section>
          <q-separator />
          <q-card-section class="q-py-sm">
            <input
              ref="fileInput"
              type="file"
              class="hidden"
              accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
              data-test="file-input"
              @change="onFilePicked"
            />
            <div
              class="cd-dropzone"
              :class="{ 'cd-dropzone--busy': store.isUploading, 'cd-dropzone--over': isDragOver }"
              role="button"
              tabindex="0"
              aria-label="Drop PCAP or PCAPNG here or press Enter to browse"
              data-test="dropzone"
              @click="openFilePicker"
              @keydown.enter.prevent="openFilePicker"
              @keydown.space.prevent="openFilePicker"
              @dragover.prevent="isDragOver = true"
              @dragleave.prevent="isDragOver = false"
              @drop.prevent="onFileDropped"
            >
              <q-icon name="upload_file" size="20px" class="q-mr-sm" />
              <span class="text-weight-bold">Drop PCAP / PCAPNG here or click to browse</span>
              <span class="text-caption text-muted q-ml-sm">
                Validated by leading bytes, not extension · limit {{ formatBytes(UPLOAD_LIMIT_BYTES) }}
              </span>
            </div>

            <div v-if="store.isUploading" class="row items-center q-gutter-sm q-mt-md" data-test="import-uploading">
              <q-spinner size="16px" color="primary" />
              <span class="text-caption">Uploading {{ store.importFile?.name }} …</span>
            </div>

            <q-banner
              v-if="rejection && rejection.kind !== 'conflict'"
              rounded
              dense
              class="cd-inline-warn q-mt-md"
              :data-test="`import-error-${rejection.kind}`"
            >
              <template #avatar>
                <q-icon name="error_outline" color="negative" size="18px" />
              </template>
              <div class="text-caption text-weight-bold">{{ rejectionHeadline }}</div>
              <div class="text-caption" data-test="import-error-message">{{ rejection.message }}</div>
              <div
                v-if="rejection.kind === 'too-large' && rejection.limitBytes"
                class="text-caption text-muted"
                data-test="import-error-limit"
              >
                Limit: {{ formatBytes(rejection.limitBytes) }} · your file:
                {{ formatBytes(store.importFile?.size ?? 0) }}
              </div>
            </q-banner>

            <q-banner v-if="conflict" rounded dense class="cd-inline-warn q-mt-md" data-test="import-conflict">
              <template #avatar>
                <q-icon name="warning_amber" color="warning" size="18px" />
              </template>
              <div class="text-caption" data-test="import-conflict-message">{{ conflict.message }}</div>
              <div class="text-caption text-weight-bold cd-mono q-mt-xs" data-test="import-conflict-range">
                {{ formatTimestamp(conflict.conflict?.conflict_start) }} –
                {{ formatTimestamp(conflict.conflict?.conflict_end) }}
              </div>
              <template #action>
                <q-btn
                  unelevated
                  dense
                  no-caps
                  color="primary"
                  label="Cancel"
                  data-test="import-conflict-dismiss"
                  @click="onResetImport"
                />
                <q-btn
                  flat
                  dense
                  no-caps
                  color="negative"
                  label="Import anyway"
                  data-test="import-force"
                  :loading="store.isUploading"
                  @click="onForceImport"
                />
              </template>
            </q-banner>

            <div v-if="activeImport" class="q-mt-md" data-test="import-progress">
              <div class="row items-center q-gutter-sm">
                <CdStateBadge :kind="importBadgeKind" :label="activeImport.state" data-test="import-state" />
                <span class="text-caption cd-mono">{{ activeImport.original_filename ?? store.importFile?.name }}</span>
                <q-space />
                <q-btn
                  v-if="store.isImportRunning"
                  flat
                  dense
                  no-caps
                  size="sm"
                  color="negative"
                  label="Cancel"
                  data-test="import-cancel"
                  @click="store.cancelImport()"
                />
              </div>
              <div class="text-caption text-muted q-mt-xs" data-test="import-phase">{{ importPhaseLabel }}</div>
              <div v-if="notDeliveredYet" class="text-caption text-muted" data-test="import-queued-note">
                The worker is busy — the job is queued and will be picked up automatically.
              </div>
              <div v-if="activeImport.error" class="text-caption text-negative q-mt-xs" data-test="import-job-error">
                {{ activeImport.error }}
              </div>
              <div v-if="importResultLabel" class="text-caption q-mt-xs" data-test="import-result">
                {{ importResultLabel }}
              </div>
              <div v-if="activeImport.state === 'completed'" class="row q-gutter-sm q-mt-sm">
                <q-btn
                  flat
                  dense
                  no-caps
                  size="sm"
                  color="primary"
                  icon="schedule"
                  label="Set time range"
                  data-test="import-jump-to-data"
                  :disable="!store.completedImportRange"
                  @click="applyImportRange(store.completedImportRange)"
                />
                <q-btn
                  flat
                  dense
                  no-caps
                  size="sm"
                  color="primary"
                  icon="policy"
                  label="Detection for this range"
                  data-test="import-run-detection"
                  @click="onRunDetection"
                />
              </div>
            </div>
          </q-card-section>

          <q-separator />
          <InsufficientPermissionsNotice :message="store.recentError" />
          <q-card-section v-if="store.recentError && !isInsufficientPermissionsMessage(store.recentError)" class="q-py-sm q-pb-none">
            <q-banner rounded dense class="cd-inline-warn" data-test="recent-imports-error">
              <template #avatar>
                <q-icon name="error_outline" color="negative" size="18px" />
              </template>
              <span class="text-caption">{{ store.recentError }}</span>
            </q-banner>
          </q-card-section>
          <q-card-section class="q-py-sm">
            <div class="row items-center">
              <span class="cd-fact__label q-mb-none">Recent Imports</span>
              <q-icon name="info" size="14px" class="text-grey-5 q-ml-sm">
                <q-tooltip max-width="320px">
                  "Set time range" switches the global time filter from live to the capture's detected historic range.
                  It does not navigate away from this page.
                </q-tooltip>
              </q-icon>
            </div>
            <q-markup-table flat dense wrap-cells class="cd-table cd-import-table">
              <thead>
                <tr>
                  <th class="text-left">File</th>
                  <th class="text-left">Capture range</th>
                  <th class="text-left">Outcome</th>
                  <th class="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="entry in store.recentImports"
                  :key="entry.display_id"
                  :data-import-id="entry.display_id"
                  data-test="recent-import-row"
                >
                  <td>
                    <div class="row items-baseline no-wrap q-gutter-xs">
                      <span class="text-weight-bold ellipsis" data-test="recent-import-filename">
                        {{ entry.original_filename ?? '—' }}
                      </span>
                      <span class="text-caption text-muted no-wrap">
                        {{ entry.size_bytes ? formatBytes(entry.size_bytes) : '—' }} · {{ entry.display_id }}
                      </span>
                    </div>
                  </td>
                  <td class="cd-mono text-caption" data-test="recent-import-range">
                    {{ rangeLabel(entry) }}
                  </td>
                  <td>
                    <div class="row items-center no-wrap q-gutter-xs">
                      <CdStateBadge
                        :kind="stateBadgeKind(entry.state)"
                        :label="entry.state"
                        data-test="recent-import-state"
                      />
                      <span class="text-caption text-muted ellipsis" data-test="recent-import-outcome">
                        {{ outcomeLabel(entry) }}
                      </span>
                    </div>
                  </td>
                  <td class="text-right">
                    <q-btn
                      flat
                      dense
                      no-caps
                      size="sm"
                      color="primary"
                      icon="schedule"
                      label="Set time range"
                      data-test="recent-import-jump"
                      :disable="!importRange(entry)"
                      @click="applyImportRange(importRange(entry))"
                    />
                  </td>
                </tr>
                <tr v-if="isRecentEmpty" data-test="recent-imports-empty">
                  <td colspan="4" class="text-center text-muted q-py-md">
                    {{
                      store.recentError
                        ? 'Import history unavailable.'
                        : 'No PCAP has been imported yet — the history is empty, not unavailable.'
                    }}
                  </td>
                </tr>
              </tbody>
            </q-markup-table>
          </q-card-section>
        </q-card>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'

import CdSignalDot from '~/components/operations/SignalDot.vue'
import CdStateBadge from '~/components/operations/StateBadge.vue'
import InsufficientPermissionsNotice from '~/components/shared/InsufficientPermissionsNotice.vue'
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import { useOperationsRefresh } from '~/composables/useOperationsRefresh'
import type { PcapImportState, PcapImportStatus } from '~/composables/usePcapImport'
import { DATA_SOURCE_LABELS, importRange, useDataSourcesStore } from '~/stores/dataSourcesStore'
import type { SourceId } from '~/stores/dataSourcesStore'
import { useAppStore } from '~/stores/appStore'
import type { PipelineSource } from '~/types/api'
import { isInsufficientPermissionsMessage } from '~/utils/permissions'

/**
 * Operations / Data Sources.
 *
 * Owned surfaces: live capture status + source freshness table + stale banner
 * + passive-seeder status, plus the PCAP import workflow and its history,
 * which share one full-width card (compact dropzone above, recent-imports
 * table below) so the history columns get the whole page width. Passive
 * discovery is status-only here; its runtime controls live on
 * Operations → Configuration → Runtime.
 */

definePageMeta({
  title: 'Operations / Data Sources',
})

const store = useDataSourcesStore()
const appStore = useAppStore()
const $q = useQuasar()
const operationsRefresh = useOperationsRefresh()

/**
 * Server-side upload ceiling (`PCAP_IMPORT_MAX_UPLOAD_BYTES`, 512 MiB).
 * Shown up front so the limit is known before a large file is chosen; the
 * server remains the authority and answers `413` itself.
 */
const UPLOAD_LIMIT_BYTES = 536_870_912

const fileInput = ref<HTMLInputElement | null>(null)
const isDragOver = ref(false)

onMounted(() => {
  operationsRefresh.register(
    () => store.loadAll(),
    () => store.isLoading,
  )
  void operationsRefresh.refresh()
})

onUnmounted(operationsRefresh.unregister)

usePolling(operationsRefresh.refresh, 5000)

/**
 * True only on the very first load, before any owned data or error lands, so
 * the page shell always paints and the spinner never flickers on refresh.
 */
const isInitialLoading = computed(
  () =>
    store.isLoading &&
    store.pipeline === null &&
    store.captureStatus === null &&
    store.pipelineError === null &&
    store.captureError === null,
)

/**
 * First non-null owned-surface error message, or null when both loaded.
 */
const loadError = computed<string | null>(() => store.captureError ?? store.pipelineError ?? null)

/**
 * True when loading has settled with no source rows to show.
 */
const isSourcesEmpty = computed(() => !store.isLoading && store.sourceRows.length === 0)

const linkSignal = computed(() => {
  const up = store.captureStatus?.link_up
  if (up === true) return 'green'
  if (up === false) return 'red'
  return 'grey'
})

const linkLabel = computed(() => {
  const up = store.captureStatus?.link_up
  if (up === true) return 'link up'
  if (up === false) return 'link down'
  return 'unknown'
})

const recordingSignal = computed(() => {
  const rec = store.captureStatus?.recording
  if (rec === true) return 'green'
  if (rec === false) return 'red'
  return 'grey'
})

const recordingLabel = computed(() => {
  const rec = store.captureStatus?.recording
  if (rec === true) return 'recording'
  if (rec === false) return 'not recording'
  return 'unknown'
})

const dropsLabel = computed(() => {
  const pct = store.captureStatus?.drops_24h_pct
  return pct == null ? '—' : `${pct.toFixed(2)} %`
})

const overflowsLabel = computed(() => {
  const val = store.captureStatus?.overflows
  return val == null ? '—' : String(val)
})

function friendlySourceName(name: string): string {
  return DATA_SOURCE_LABELS[name as SourceId] ?? name
}

/**
 * Records/h cell text. A ``no-data`` source reports 0 from the Wave-A
 * backend only because there is no data to measure; render an em-dash there
 * so the column never implies a measured rate of exactly zero.
 *
 * @param src - The pipeline source row.
 * @returns A localized rate, or "—" when the rate is not meaningful.
 */
function recordsPerHourText(src: PipelineSource): string {
  if (src.state === 'no-data') return '—'
  return src.records_per_hour.toLocaleString('en-US')
}

function sourceIcon(name: string): string {
  switch (name) {
    case 'conn':
      return DOMAIN_ICONS.connections
    case 'mac':
      return DOMAIN_ICONS.assets
    default:
      return DOMAIN_ICONS.protocols
  }
}

function sourceBadgeKind(state: string): 'ok' | 'warn' | 'err' | 'info' {
  switch (state) {
    case 'current':
      return 'ok'
    case 'stale':
      return 'warn'
    case 'no-data':
      return 'err'
    default:
      return 'info'
  }
}

function lastRecordText(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleTimeString()
}

function ageLabel(seconds: number | null): string {
  if (seconds == null) return ''
  if (seconds < 60) return '<1 min ago'
  return `${Math.floor(seconds / 60)} min ago`
}

/**
 * Passive Discovery status badge (kind + label) from persisted producer
 * truth. Describes the observed inventory, not the seeder process.
 */
const passiveBadge = computed(() => store.passiveBadge)

/**
 * Deep link to the runtime control surface that owns the seeder's
 * enable state, poll interval and lookback window (decision D1: this page
 * shows status only).
 */
const RUNTIME_CONFIG_ROUTE = '/operations/configuration'

/** Seeder-reported operational state, `unknown` when it has never reported. */
const seederState = computed(() => store.seederState)

/** Badge descriptor for the seeder's own operational state. */
const seederBadge = computed(() => store.seederBadge)

/**
 * Timestamp of the seeder's most recent completed cycle, or an em-dash.
 */
const seederLastCycleLabel = computed(() => {
  const iso = store.seederStatus?.last_cycle_at
  if (!iso) return '—'
  return new Date(iso).toLocaleTimeString()
})

/**
 * Rows written by the last cycle. Deliberately not a cumulative total; an
 * em-dash is rendered while no status row exists so `0` is never implied.
 */
const seederRowsLabel = computed(() => {
  const status = store.seederStatus
  if (!status || status.state === 'unknown') return '—'
  return status.rows_seeded.toLocaleString('en-US')
})

/**
 * Effective poll interval the seeder reports, or an em-dash when unknown.
 */
const seederPollIntervalLabel = computed(() => {
  const seconds = store.seederStatus?.poll_interval_s
  if (seconds == null) return '—'
  return `${seconds} s`
})

/**
 * Icon paired with the passive badge kind.
 */
const passiveBadgeIcon = computed(() => {
  switch (passiveBadge.value.kind) {
    case 'ok':
      return 'sensors'
    case 'warn':
      return 'warning_amber'
    default:
      return 'pause_circle'
  }
})

/**
 * Distinct passively-observed assets, or an em-dash before first load.
 */
const passiveAssetsLabel = computed(() => {
  const status = store.passiveDiscovery
  if (!status) return '—'
  return status.observed_asset_count.toLocaleString('en-US')
})

/**
 * Most recent persisted passive observation as a local time, or em-dash.
 */
const passiveLastSeenLabel = computed(() => {
  const iso = store.passiveDiscovery?.latest_seen_at
  if (!iso) return '—'
  return new Date(iso).toLocaleTimeString()
})

/**
 * Human-friendly age of the latest passive observation.
 */
const passiveAgeLabel = computed(() => ageLabel(store.passiveDiscovery?.age_seconds ?? null))

/* ── PCAP import (UI-078 Wave D) ─────────────────────────────── */

/** Normalised rejection of the last upload attempt, if any. */
const rejection = computed(() => store.importRejection)

/** The pending overlap conflict, which alone offers a follow-up action. */
const conflict = computed(() => store.importConflict)

/**
 * Followed import job: the polled status once available, otherwise the
 * acceptance envelope so the card paints immediately after the upload.
 */
const activeImport = computed<PcapImportStatus | null>(() => {
  if (store.importStatus) return store.importStatus
  const accepted = store.importAccepted
  if (!accepted) return null
  return {
    display_id: accepted.display_id,
    job_id: accepted.job_id,
    state: accepted.state,
    phase_current: null,
    phase_total: null,
    phase_label: null,
    latest_event: null,
    original_filename: accepted.original_filename,
    size_bytes: accepted.size_bytes,
    time_start: accepted.time_start,
    time_end: accepted.time_end,
    forced: accepted.forced,
    started_at: null,
    ended_at: null,
    error: null,
    result: null,
  }
})

/**
 * True when the worker was busy at upload time. This is not a failure —
 * the api retries delivery — and must not be rendered as one.
 */
const notDeliveredYet = computed(
  () => store.importAccepted?.delivered === false && activeImport.value?.state === 'queued',
)

/** True once the listing has settled with nothing to show. */
const isRecentEmpty = computed(() => store.recentLoaded && store.recentImports.length === 0)

/**
 * Short headline naming which kind of rejection occurred, above the
 * server's own message which is always shown verbatim below it.
 */
const rejectionHeadline = computed(() => {
  switch (rejection.value?.kind) {
    case 'unsupported':
      return 'File is not a valid capture'
    case 'too-large':
      return 'File exceeds the upload limit'
    case 'unauthorized':
      return 'Not authorized to import'
    case 'malformed':
      return 'Upload could not be read'
    default:
      return 'Import rejected'
  }
})

/** Progress line: phase counter plus the worker's latest event text. */
const importPhaseLabel = computed(() => {
  const job = activeImport.value
  if (!job) return ''
  const phase =
    job.phase_current != null && job.phase_total != null ? `Phase ${job.phase_current}/${job.phase_total}` : null
  return [phase, job.phase_label, job.latest_event].filter(Boolean).join(' · ') || 'Waiting for the worker …'
})

/** Point/record counts of a completed import, or an empty string. */
const importResultLabel = computed(() => {
  const result = activeImport.value?.result
  if (!result) return ''
  const parts: string[] = []
  if (result.records_processed != null) parts.push(`${result.records_processed.toLocaleString('en-US')} Records`)
  if (result.points_written != null) parts.push(`${result.points_written.toLocaleString('en-US')} points`)
  return parts.join(' · ')
})

/** Badge kind for the followed job's state. */
const importBadgeKind = computed(() => stateBadgeKind(activeImport.value?.state))

/**
 * Map an import lifecycle state onto a badge kind.
 *
 * @param state - The job state.
 * @returns The badge kind to render.
 */
function stateBadgeKind(state: PcapImportState | undefined): 'ok' | 'warn' | 'err' | 'info' {
  switch (state) {
    case 'completed':
      return 'ok'
    case 'failed':
    case 'rejected':
      return 'err'
    case 'cancelled':
    case 'cancelling':
      return 'warn'
    default:
      return 'info'
  }
}

/**
 * Format a byte count with binary units.
 *
 * @param bytes - Number of bytes.
 * @returns A short human-readable size.
 */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`
}

/**
 * Format an ISO timestamp for display, or an em-dash.
 *
 * @param iso - ISO 8601 timestamp.
 * @returns A localized date-time string.
 */
function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'medium' })
}

/**
 * Capture-window cell text for one history entry.
 *
 * @param entry - An import status envelope.
 * @returns The window, or an em-dash when none was detected.
 */
function rangeLabel(entry: PcapImportStatus): string {
  const range = importRange(entry)
  if (!range) return '—'
  return `${formatTimestamp(range.start)} – ${formatTimestamp(range.end)}`
}

/**
 * Outcome cell text: point count when completed, diagnosis when failed.
 *
 * @param entry - An import status envelope.
 * @returns A short outcome description.
 */
function outcomeLabel(entry: PcapImportStatus): string {
  if (entry.state === 'completed' && entry.result?.points_written != null) {
    return `${entry.result.points_written.toLocaleString('en-US')} points`
  }
  if (entry.error) return entry.error
  if (entry.latest_event) return entry.latest_event
  return ''
}

/** Open the hidden file input from the dropzone. */
function openFilePicker(): void {
  if (store.isUploading) return
  fileInput.value?.click()
}

/**
 * Handle a file chosen through the picker.
 *
 * @param event - The input change event.
 */
function onFilePicked(event: Event): void {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) void startUpload(file)
  // Reset so re-picking the same file fires `change` again.
  input.value = ''
}

/**
 * Handle a file dropped onto the dropzone.
 *
 * @param event - The drop event.
 */
function onFileDropped(event: DragEvent): void {
  isDragOver.value = false
  const file = event.dataTransfer?.files?.[0]
  if (file) void startUpload(file)
}

/**
 * Upload a capture and begin following the job.
 *
 * No client-side content check is performed: the server validates by magic
 * bytes and owns the size limit, and a browser-side gate would only be a
 * convenience an operator could bypass.
 *
 * @param file - The chosen capture.
 */
async function startUpload(file: File): Promise<void> {
  const accepted = await store.uploadCapture(file)
  if (accepted) followImport()
}

/** Re-post the retained capture past an overlap conflict. */
async function onForceImport(): Promise<void> {
  const accepted = await store.forceRetryUpload()
  if (accepted) followImport()
}

/** Clear the current upload and any pending conflict. */
function onResetImport(): void {
  store.resetImport()
}

let importPoll: ReturnType<typeof setInterval> | null = null

/**
 * Poll the followed job until it reaches a terminal state.
 *
 * Polling, not SSE: `/api/v1/operations/jobs/{job_id}/events` emits only on
 * a *state* change, so it would show nothing between `running` and the
 * terminal state — the phase and latest-event progress an operator needs
 * lives on the status endpoint alone.
 */
function followImport(): void {
  stopFollowing()
  importPoll = setInterval(() => {
    void (async () => {
      await store.refreshImportStatus()
      if (!store.isImportRunning) {
        stopFollowing()
        await store.fetchRecentImports()
      }
    })()
  }, 2000)
}

function stopFollowing(): void {
  if (importPoll !== null) {
    clearInterval(importPoll)
    importPoll = null
  }
}

onUnmounted(stopFollowing)

/**
 * Switch the global time filter to an imported capture's window.
 *
 * Sets the time range only — it deliberately performs no navigation, which
 * is why the control is labelled "Set time range". Reuses the UI-079
 * mechanism (`appStore` history mode + range) that the shared TimeToolbar
 * and `useDataExtent` already drive, so the imported data is visible
 * everywhere rather than only on this page.
 *
 * @param range - The capture window to apply to the global time filter.
 */
function applyImportRange(range: { start: string; end: string } | null): void {
  if (!range) return
  appStore.setLiveMode(false)
  if (!appStore.setTimeRange(range.start, range.end)) return
  $q.notify({
    type: 'positive',
    message: `Time range set to the imported capture (${formatTimestamp(range.start)} – ${formatTimestamp(range.end)}).`,
  })
}

/**
 * Explain the detection situation after a completed import.
 *
 * Detection is deliberately never triggered automatically (design.md §7):
 * importing month-old material must not raise retroactive alarms. There is
 * currently no reachable endpoint that runs detection over an arbitrary
 * window — otalon-clas is a daemon with no HTTP surface, and the only
 * range-bounded training call is boundary/classifier retraining, which is a
 * different operation. Rather than fake a button, the action states the
 * situation and points at the surface that does exist.
 */
function onRunDetection(): void {
  $q.notify({
    type: 'info',
    timeout: 8000,
    message:
      'Detection is deliberately not triggered automatically for an import. ' +
      'There is currently no endpoint that runs detection over an arbitrary range ' +
      '— use Detection → Bounds/Training to evaluate it.',
    actions: [{ label: 'Open Detection', color: 'white', handler: () => navigateTo('/operations/detection') }],
  })
}
</script>

<style scoped lang="scss">
.cd-data-sources > :first-child {
  margin-top: 0 !important;
}

.cd-card-title {
  font-size: 15px;
  font-weight: 600;
}

.cd-fact__label {
  font-size: 11px;
  font-weight: 600;
  color: var(--cd-muted);
  text-transform: uppercase;
  letter-spacing: 0.4px;
  margin-bottom: 4px;
}

.cd-mono {
  font-family: monospace;
}

.cd-dropzone {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-wrap: wrap;
  gap: 2px;
  border: 2px dashed color-mix(in srgb, var(--cd-info) 45%, var(--cd-border));
  border-radius: $border-radius-md;
  padding: 18px 16px;
  text-align: center;
  color: var(--cd-text);
  cursor: pointer;
  transition:
    border-color 0.15s ease,
    background-color 0.15s ease;

  &:hover,
  &:focus-visible {
    border-color: var(--q-primary);
  }

  &--over {
    border-color: var(--q-primary);
    background-color: rgba(var(--q-primary-rgb, 25, 118, 210), 0.06);
  }

  &--busy {
    opacity: 0.65;
    cursor: progress;
  }
}

/**
 * Recent-imports table inside the merged full-width card.
 *
 * `table-layout: fixed` plus explicit column shares makes the four columns
 * share the available width instead of each sizing to its content, which is
 * what pushed the ACTIONS column out of the old half-width card and produced
 * a horizontal scrollbar. Overflow is therefore impossible by construction.
 */
.cd-import-table {
  :deep(table) {
    table-layout: fixed;
    width: 100%;
  }

  :deep(th),
  :deep(td) {
    overflow-wrap: anywhere;
    white-space: normal;
  }

  /* The merged card must not be taller than the two cards it replaced. The
     extra width is spent on single-line rows instead of extra height. */
  :deep(th) {
    height: auto;
    padding-top: 2px;
    padding-bottom: 2px;
  }

  :deep(td) {
    height: auto;
    padding-top: 1px;
    padding-bottom: 1px;
  }

  :deep(td .q-btn) {
    padding: 0 6px;
    min-height: 22px;
  }

  :deep(th:nth-child(1)),
  :deep(td:nth-child(1)) {
    width: 30%;
  }

  :deep(th:nth-child(2)),
  :deep(td:nth-child(2)) {
    width: 28%;
  }

  :deep(th:nth-child(3)),
  :deep(td:nth-child(3)) {
    width: 24%;
  }

  :deep(th:nth-child(4)),
  :deep(td:nth-child(4)) {
    width: 18%;
  }
}
</style>
