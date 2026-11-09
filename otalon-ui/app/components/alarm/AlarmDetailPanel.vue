<template>
  <div v-if="!group" class="column items-center justify-center q-pa-xl text-center full-height">
    <q-icon name="touch_app" size="64px" color="grey-5" class="q-mb-md" />
    <div class="text-h6 text-muted">Select an alarm group to view details</div>
  </div>

  <div v-else class="alarm-detail-panel column" :style="rootStyle">
    <!-- ── Sticky header: alarm summary + action buttons ─────────── -->
    <div class="detail-header q-pa-md">
      <div class="row items-center q-mb-sm">
        <q-icon name="summarize" color="primary" size="22px" />
        <div class="q-ml-sm row q-col-gutter-md items-center">
          <div>
            <div class="text-caption text-muted">Prediction</div>
            <div class="text-body2 text-weight-medium">{{ predictionLabel }}</div>
          </div>
          <div>
            <div class="text-caption text-muted">Start Time</div>
            <div class="text-body2">{{ formatDateTime(group.start_timestamp) }}</div>
          </div>
          <div>
            <div class="text-caption text-muted">End Time</div>
            <div class="text-body2">{{ formatDateTime(group.end_timestamp, 'ongoing') }}</div>
          </div>
        </div>
        <q-space />
        <q-btn flat round dense icon="close" @click="$emit('close')">
          <q-tooltip>Close detail panel</q-tooltip>
        </q-btn>
      </div>

      <div class="row q-gutter-sm q-mb-sm">
        <q-badge :color="group.is_active ? 'negative' : 'grey-6'" :label="group.is_active ? 'Active' : 'Closed'" />
        <q-badge
          :color="group.confirmed ? 'primary' : 'grey-6'"
          :label="group.confirmed ? 'Confirmed' : 'Unconfirmed'"
        />
      </div>

      <!--
        Action buttons row (always visible, not inside a tab).
        Visual hierarchy:
        - Primary  (filled, teal): AI-Agent Forensic Analysis (AI-driven; the
          flagship operator action on this page).
        - Secondary (outlined, positive/grey): Confirm/Unconfirm (state change).
        - Tertiary (outlined neutral): PCAP download.
        All same size, same height, no q-space gap; the row is left-aligned
        and wraps gracefully on narrow viewports.
      -->
      <div class="row q-gutter-sm action-bar">
        <q-btn
          no-caps
          color="teal"
          icon="auto_awesome"
          :label="reAnalyzeLabel"
          :disable="subagentStore.isAlarmInflight(group.id)"
          class="action-btn action-btn--primary"
          @click="showTriggerModal = true"
        >
          <q-tooltip> Run an independent zero-shot LLM classification on this alarm </q-tooltip>
        </q-btn>
        <q-btn
          v-if="!group.confirmed"
          outline
          no-caps
          color="positive"
          icon="check_circle"
          label="Confirm"
          class="action-btn"
          @click="$emit('confirm', group)"
        />
        <q-btn
          v-else
          outline
          no-caps
          color="grey-7"
          icon="undo"
          label="Unconfirm"
          class="action-btn"
          @click="$emit('unconfirm', group)"
        />
        <q-btn
          outline
          no-caps
          icon="download"
          label="PCAP"
          :loading="pcapDownloadInflight"
          :disable="pcapDownloadInflight"
          class="action-btn action-btn--tertiary"
          data-testid="alarm-detail-pcap-download-btn"
          @click="downloadPcap"
        >
          <q-tooltip>Download all PCAP chunks for this alarm as a ZIP</q-tooltip>
        </q-btn>
      </div>
    </div>

    <!-- ── Tabs strip ──────────────────────────────────────────── -->
    <q-tabs
      v-model="activeTab"
      dense
      no-caps
      align="left"
      indicator-color="primary"
      active-color="primary"
      class="detail-tabs"
    >
      <q-tab name="overview" icon="summarize" label="Meta" />
      <q-tab name="typestats" icon="bar_chart">
        <div class="row items-center no-wrap">
          <span>Prediction Stats</span>
          <q-badge color="primary" class="q-ml-xs" :label="typeStatsRows.length" />
        </div>
      </q-tab>
      <q-tab name="subagent" icon="auto_awesome">
        <div class="row items-center no-wrap">
          <span>AI-Agent Forensics</span>
          <q-badge v-if="subagentJobsCount > 0" color="teal" class="q-ml-xs" :label="subagentJobsCount" />
        </div>
      </q-tab>
      <q-tab name="connections" :icon="DOMAIN_ICONS.connections">
        <div class="row items-center no-wrap">
          <span>Connections</span>
          <q-badge color="accent" class="q-ml-xs" :label="connectionCount" />
        </div>
      </q-tab>
      <q-tab name="macs" :icon="DOMAIN_ICONS.assets">
        <div class="row items-center no-wrap">
          <span>Assets</span>
          <q-badge color="accent" class="q-ml-xs" :label="macIds.length" />
        </div>
      </q-tab>
      <q-tab name="protocols" :icon="DOMAIN_ICONS.protocols">
        <div class="row items-center no-wrap">
          <span>Protocols</span>
          <q-badge color="accent" class="q-ml-xs" :label="protoItems.length" />
        </div>
      </q-tab>
    </q-tabs>

    <q-separator />

    <!-- ── Tab panels (scrollable) ────────────────────────────── -->
    <q-tab-panels v-model="activeTab" animated class="detail-panels col" keep-alive>
      <!-- Meta tab — alarm metadata at-a-glance -->
      <q-tab-panel name="overview" class="q-pa-md">
        <div class="row q-col-gutter-md">
          <div class="col-12 col-md-6">
            <div class="text-caption text-muted">ID</div>
            <div class="text-body2 text-weight-medium text-mono">{{ group.id }}</div>
          </div>
          <div class="col-12">
            <div class="text-caption text-muted">Prediction</div>
            <div class="q-mt-xs primary-type-chips">
              <template v-if="Array.isArray(group.primary_type)">
                <q-chip
                  v-for="pt in group.primary_type"
                  :key="pt"
                  :color="mitreChipColor(pt)"
                  text-color="white"
                  class="q-mr-xs primary-type-chip"
                >
                  {{ pt }}
                </q-chip>
              </template>
              <q-chip v-else :color="mitreChipColor(group.primary_type)" text-color="white" class="primary-type-chip">
                {{ group.primary_type }}
              </q-chip>
            </div>
          </div>
          <div class="col-12 col-md-6">
            <div class="text-caption text-muted">Start Time</div>
            <div class="text-body2">{{ formatDateTime(group.start_timestamp) }}</div>
          </div>
          <div class="col-12 col-md-6">
            <div class="text-caption text-muted">End Time</div>
            <div class="text-body2">{{ formatDateTime(group.end_timestamp, 'ongoing') }}</div>
          </div>
        </div>
      </q-tab-panel>

      <!-- Prediction Stats tab -->
      <q-tab-panel name="typestats" class="q-pa-md">
        <div v-for="row in typeStatsRows" :key="row.type" class="type-stat-row q-mb-md">
          <div class="row items-center no-wrap q-mb-xs">
            <q-chip :color="mitreChipColor(row.type)" text-color="white" class="primary-type-chip">
              {{ row.type }}
            </q-chip>
            <q-space />
            <span class="text-caption text-weight-bold"> Score: {{ row.score_norm.toFixed(2) }} </span>
          </div>
          <q-linear-progress
            :value="row.score_norm"
            :color="scoreBarColor(row.score_norm)"
            :track-color="$q.dark.isActive ? 'grey-9' : 'grey-3'"
            rounded
            size="6px"
            class="q-mb-xs"
          />
          <div class="row q-col-gutter-sm text-caption text-muted">
            <div class="col"><strong>Confidence:</strong> {{ (row.confidence_mean * 100).toFixed(0) }}%</div>
            <div class="col"><strong>Intervals:</strong> {{ row.interval_count }}</div>
            <div class="col"><strong>Anomalies:</strong> {{ row.count }}</div>
            <div class="col"><strong>Pkt/s:</strong> {{ row.packet_rate_mean?.toFixed(1) ?? '—' }}</div>
            <div class="col"><strong>B/s:</strong> {{ row.byte_rate_mean?.toFixed(0) ?? '—' }}</div>
          </div>
        </div>
        <div v-if="typeStatsRows.length === 0" class="text-caption text-muted text-center q-pa-md">
          No anomaly type statistics available.
        </div>
      </q-tab-panel>

      <!-- AI-Agent Forensics tab — live trace + history -->
      <q-tab-panel name="subagent" class="q-pa-md">
        <div v-if="activeJobId" :id="`subagent-${activeJobId}`" class="q-mb-md">
          <SubagentTraceCard :job-id="activeJobId" @open-detail="onOpenForensicModal" />
        </div>
        <SubagentHistoryPanel :alarm-id="group.id" @select="onSelectHistoricJob" @open-detail="onOpenForensicModal" />
      </q-tab-panel>

      <!-- Connections tab -->
      <q-tab-panel name="connections" class="q-pa-md">
        <AlarmConnectionList :series-ids="connectionIds" :group-id="group.id" />
      </q-tab-panel>

      <!-- MACs / Assets tab -->
      <q-tab-panel name="macs" class="q-pa-md">
        <AlarmMacAssetList :macs="macIds" :group-id="group.id" />
      </q-tab-panel>

      <!-- Protocols tab -->
      <q-tab-panel name="protocols" class="q-pa-md">
        <AlarmProtocolList :protos="protoItems" :group-id="group.id" />
      </q-tab-panel>
    </q-tab-panels>

    <SubagentTriggerModal v-model="showTriggerModal" :alarm-id="group.id" @started="onSubagentStarted" />
    <ForensicTraceModal v-model="forensicModalOpen" :job-id="forensicModalJobId" />
  </div>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import { computed, ref, watch } from 'vue'
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import AlarmMacAssetList from '~/components/alarm/AlarmMacAssetList.vue'
import AlarmProtocolList from '~/components/alarm/AlarmProtocolList.vue'
import ForensicTraceModal from '~/components/subagent/ForensicTraceModal.vue'
import SubagentHistoryPanel from '~/components/subagent/HistoryPanel.vue'
import SubagentTraceCard from '~/components/subagent/TraceCard.vue'
import SubagentTriggerModal from '~/components/subagent/TriggerModal.vue'
import { useSubagentStore } from '~/stores/subagentStore'
import { usePcapDownload, type PcapDownloadError } from '~/composables/usePcapDownload'
import type { AnomalyGroupItem, AnomalyTypeStatDetail } from '~/types/api'
import { mitreChipColor } from '~/utils/mitre-colors'
import { formatDateTime } from '~/utils/format'
import { extractAlarmMacs } from '~/utils/mac-match'
import { buildProtocolItems, classifySeriesIdentifier, humanizeProtocolStack, isProtocolHashId } from '~/utils/protocol'
import { portCollapsedConnectionCount } from '~/utils/uci'

/**
 * Detail panel for a selected anomaly group (rendered inside a modal dialog).
 *
 * Layout order per S-08: ML Prediction (with integrated type stats) → Anomaly Info → Affected Connections.
 * Emits 'close' for the parent dialog to dismiss.
 */

interface TypeStatRow extends AnomalyTypeStatDetail {
  type: string
}

interface Props {
  group: AnomalyGroupItem | null
  /**
   * Operator-controlled base font size in pixels (from the Alarms-page
   * display settings). Forwarded as a CSS variable so chips, badges and
   * body text inside this panel scale together with the list density.
   */
  fontSize?: number
}

const props = withDefaults(defineProps<Props>(), {
  fontSize: 13,
})
defineEmits<{
  (e: 'confirm' | 'unconfirm', group: AnomalyGroupItem): void
  (e: 'close'): void
}>()

/**
 * Inline style applied to the panel root so the font-size cascade also
 * works for the Quasar dialog teleported to body (where the page's
 * scoped CSS does not reach).
 */
const rootStyle = computed(() => ({
  height: '100%',
  '--detail-font-size': `${props.fontSize}px`,
}))

const $q = useQuasar()
const subagentStore = useSubagentStore()
const pcapDownload = usePcapDownload()
const showTriggerModal = ref(false)
const activeJobId = ref<string | null>(null)
const pcapDownloadInflight = ref<boolean>(false)
const forensicModalOpen = ref(false)
const forensicModalJobId = ref<string | null>(null)

/**
 * Currently selected tab in the detail panel.
 *
 * - `typestats`  — per-anomaly-type score / count / rates (default; this
 *   is what the operator most often needs first when triaging an alarm).
 * - `overview`   — alarm metadata at a glance.
 * - `subagent`   — live trace card + history of subagent runs.
 * - `connections`— affected connections list.
 * - `macs`       — affected MAC addresses / assets list.
 * - `protocols`  — affected protocol stacks list.
 *
 * The active tab switches to ``subagent`` automatically when the operator
 * starts a new subagent run (see ``onSubagentStarted``) so they see the
 * live trace right away.
 */
const activeTab = ref<'overview' | 'typestats' | 'subagent' | 'connections' | 'macs' | 'protocols'>('typestats')

const predictionLabel = computed(() => {
  if (!props.group) return '—'
  const pt = props.group.primary_type
  const first = Array.isArray(pt) ? (pt[0] ?? '') : pt
  return first || '—'
})

const reAnalyzeLabel = computed(() =>
  props.group && subagentStore.isAlarmInflight(props.group.id)
    ? 'Forensic analysis running…'
    : 'AI-Agent Forensic Analysis',
)

/**
 * Number of subagent runs known for this alarm (used as a tab badge).
 */
const subagentJobsCount = computed<number>(() => {
  if (!props.group) return 0
  return (subagentStore.jobsByAlarm[props.group.id] ?? []).length
})

/**
 * Clear alarm-specific subagent selection whenever a different alarm is
 * selected while preserving the operator's currently active tab.
 */
watch(
  () => props.group?.id,
  (newId, oldId) => {
    if (newId !== oldId) {
      activeJobId.value = null
    }
  },
)

function onSubagentStarted(jobId: string): void {
  activeJobId.value = jobId
  activeTab.value = 'subagent'
}

function onSelectHistoricJob(jobId: string): void {
  activeJobId.value = jobId
  activeTab.value = 'subagent'
  void subagentStore.loadJob(jobId)
}

function onOpenForensicModal(jobId: string): void {
  forensicModalJobId.value = jobId
  forensicModalOpen.value = true
}

/**
 * Compute anomaly type statistics rows sorted by score (S-09: integrated into ML card).
 */
const typeStatsRows = computed<TypeStatRow[]>(() => {
  if (!props.group) return []
  return Object.entries(props.group.anomaly_type_stats)
    .map(([type, stat]) => ({ type, ...stat }))
    .sort((a, b) => b.score_norm - a.score_norm)
})

interface EnrichmentEntry {
  key: string
  module: string
  series_id: string
  protocol: string | null
  anomaly_type: string | null
  start_timestamp: string
  end_timestamp: string
}

/**
 * Parse a single enrichment bucket (mac or proto) into typed entries.
 *
 * Consumes the real producer contract written by otalon-clas
 * `cross_source.to_payload`:
 *   `{ schema: 1, mac: EvidenceEntry[], proto: EvidenceEntry[] }`
 * where each `EvidenceEntry` carries its own `module`, `series_id`,
 * `anomaly_type`, and ISO `start_ts` / `end_ts`. Proto entries may
 * also carry a human-readable `protocol` field (API-011).
 */
function parseEnrichmentBucket(bucket: 'mac' | 'proto'): EnrichmentEntry[] {
  if (!props.group?.enrichment) return []
  const enr = props.group.enrichment as Record<string, unknown>
  const value = enr[bucket]
  if (!Array.isArray(value)) return []

  const entries: EnrichmentEntry[] = []
  for (const item of value) {
    if (!item || typeof item !== 'object') continue
    const obj = item as Record<string, unknown>
    const moduleName = String(obj.module ?? (bucket === 'mac' ? 'mac_traffic' : 'proto_traffic'))
    entries.push({
      key: `${moduleName}-${String(obj.series_id ?? obj.anomaly_id ?? entries.length)}`,
      module: moduleName,
      series_id: String(obj.series_id ?? '—'),
      protocol: obj.protocol != null ? String(obj.protocol) : null,
      anomaly_type: obj.anomaly_type != null ? String(obj.anomaly_type) : null,
      start_timestamp: String(obj.start_ts ?? '—'),
      end_timestamp: String(obj.end_ts ?? '—'),
    })
  }
  return entries
}

const enrichmentProtoEntries = computed<EnrichmentEntry[]>(() => parseEnrichmentBucket('proto'))

/**
 * Series ids that represent connections (UCIs).
 *
 * Resolution is by SERIES TYPE, not by `group.module`: since CLAS-016 a
 * cross-module alarm carries the sentinel `module='multi'`, so keying off the
 * module name silently emptied this tab for exactly the alarms that bundle the
 * most information (operator finding, alarm `7ae9233f…`). Every identifier the
 * classifier recognises as a connection is listed, regardless of module.
 */
const connectionIds = computed<string[]>(() => {
  if (!props.group) return []
  return props.group.series_ids.filter((id) => classifySeriesIdentifier(id) === 'connection')
})

const connectionCount = computed<number>(() => portCollapsedConnectionCount(connectionIds.value))

/**
 * MAC addresses shown in the Assets tab.
 *
 * Resolution is delegated to the shared {@link extractAlarmMacs} helper
 * (UI-037) so the Assets tab and the Assets-Subpage filter agree: for a
 * `mac_traffic` alarm the `series_ids` ARE the MACs, for a conn-primary
 * alarm (e.g. `icmp_flood`) the MACs come from the `enrichment.mac`
 * cross-source bucket. Both sides resolve to plaintext MACs.
 */
const macIds = computed<string[]>(() => {
  if (!props.group) return []
  return extractAlarmMacs(props.group)
})

/**
 * Protocol items shown in the Protocols tab.
 *
 * Resolution is by SERIES TYPE, not by `group.module`. A proto series is
 * identified by a numeric hash id and carries its readable stack in the
 * index-parallel `protocols[]` array (API-021), so `buildProtocolItems` — which pairs
 * the two and decides on the resolved label — is ALWAYS applied. Keying this on
 * `module === 'proto_traffic'` emptied the tab for `module='multi'` alarms,
 * because the fallback below ignores `protocols[]` and drops hash ids
 * (operator finding, alarms `ae41f35e…` / `7ae9233f…`).
 *
 * Cross-source `enrichment.proto` entries are merged on top, de-duplicated by
 * series id.
 */
const protoItems = computed<{ id: string; label: string }[]>(() => {
  if (!props.group) return []
  const map = new Map<string, { id: string; label: string }>()
  for (const item of buildProtocolItems(props.group.series_ids, props.group.protocols ?? [])) {
    map.set(item.id, item)
  }
  for (const e of enrichmentProtoEntries.value) {
    if (isProtocolHashId(e.series_id) && !e.protocol) continue
    map.set(e.series_id, { id: e.series_id, label: humanizeProtocolStack(e.protocol ?? e.series_id) })
  }
  return Array.from(map.values())
})

/**
 * Return a color for the score progress bar.
 */
function scoreBarColor(score: number): string {
  if (score >= 0.8) return 'negative'
  if (score >= 0.5) return 'warning'
  return 'positive'
}

/**
 * Map a PCAP-download HTTP failure to a user-facing toast message.
 */
function pcapErrorMessage(status: number): string {
  if (status === 404) return 'No PCAP data available for this alarm'
  if (status === 502) return 'PCAP service unreachable, try again later'
  if (status === 503) return 'PCAP service unavailable'
  if (status === 504) return 'PCAP download timed out, try again'
  return 'PCAP download failed, try again'
}

/**
 * Download the alarm's PCAP-bundle ZIP.
 *
 * Calls the backend endpoint that streams a ZIP archive of every PCAP
 * chunk belonging to the alarm (plus a ``metadata.json``) and triggers
 * a browser-initiated file download. Failures are surfaced as toasts
 * via {@link pcapErrorMessage}.
 */
async function downloadPcap(): Promise<void> {
  if (!props.group?.id) return
  const alarmId = props.group.id
  pcapDownloadInflight.value = true
  try {
    const blob = await pcapDownload.fetchAlarmPcapZip(alarmId)
    pcapDownload.triggerBrowserDownload(blob, `alarm-${alarmId}-pcap.zip`)
  } catch (error: unknown) {
    const status = error && typeof error === 'object' && 'status' in error ? (error as PcapDownloadError).status : 0
    $q.notify({
      type: 'negative',
      message: pcapErrorMessage(status),
      timeout: 5000,
    })
  } finally {
    pcapDownloadInflight.value = false
  }
}
</script>

<style scoped lang="scss">
.alarm-detail-panel {
  scrollbar-width: thin;
  background: var(--cd-surface);
  border-radius: 4px;
  /*
   * Cascade the operator-controlled font size to every text node, chip
   * and badge inside the panel. Subtitle elements get a small uplift so
   * the visual hierarchy survives across all density levels.
   */
  font-size: var(--detail-font-size, 13px);
}

.alarm-detail-panel :deep(.text-body2),
.alarm-detail-panel :deep(.text-caption) {
  font-size: var(--detail-font-size, 13px);
}

.alarm-detail-panel :deep(.text-subtitle1),
.alarm-detail-panel :deep(.text-subtitle2) {
  font-size: calc(var(--detail-font-size, 13px) + 2px);
}

.alarm-detail-panel :deep(.q-badge) {
  font-size: calc(var(--detail-font-size, 13px) - 1px);
}

/*
 * Primary type chip — scales with the operator-controlled font-size.
 * We deliberately avoid Quasar's ``size="sm"`` prop because it bakes a
 * fixed pixel value into the element style with high specificity. The
 * ``:deep(.q-chip.primary-type-chip)`` selector reaches the Quasar chip
 * even though it's a child component, and the ``height`` is derived
 * from the font-size so the chip stays compact at every density.
 */
.alarm-detail-panel :deep(.q-chip.primary-type-chip) {
  font-size: calc(var(--detail-font-size, 13px) - 1px);
  height: calc(var(--detail-font-size, 13px) + 14px);
  padding: 0 8px;
  line-height: 1;
}

.detail-header {
  background: var(--cd-surface);
  border-bottom: 1px solid var(--cd-border);
}

.detail-tabs {
  background: var(--cd-surface);
}

/* ── Action button bar ───────────────────────────────────────────
 * All buttons share a consistent height and padding so the row reads
 * as a single object. Visual hierarchy is conveyed by fill vs. outline
 * (not by size or vertical alignment).
 */
.action-bar {
  flex-wrap: wrap;
}

.action-btn {
  min-height: 36px;
  padding: 0 14px;
  font-weight: 500;
}

/* Primary CTA — gets a subtle drop shadow so it lifts above the page */
.action-btn--primary {
  font-weight: 600;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12);
}

.action-btn--primary:hover:not([disabled]) {
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.18);
}

/* Tertiary outlined button — softer, neutral border */
.action-btn--tertiary {
  color: var(--cd-text-muted);
}

.body--dark .action-btn--tertiary {
  color: var(--cd-text-muted);
}

.detail-panels {
  /* Each panel scrolls independently; the header + tabs stay fixed. */
  overflow: hidden;
}

.detail-panels :deep(.q-tab-panel) {
  height: 100%;
  overflow-y: auto;
  scrollbar-width: thin;
}

/*
 * Type-stats rows — no fill background (was inconsistent between
 * light and dark themes and the indented strip looked asymmetric vs.
 * the full-width header). A subtle border + bottom-padding gives the
 * same separation in both modes and stays full-width within the panel.
 */
.type-stat-row {
  padding: 10px 0;
  border-bottom: 1px solid var(--cd-border);
}

.type-stat-row:last-child {
  border-bottom: none;
}

.text-mono {
  font-family: $font-family-mono;
  word-break: break-all;
}
</style>
