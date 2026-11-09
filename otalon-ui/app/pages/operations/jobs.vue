<template>
  <div class="cd-operations-jobs">
    <!-- KPIs -->
    <div class="row q-col-gutter-sm q-mb-md jobs-kpis">
      <div class="col-12 col-sm-4">
        <KpiCard :value="store.runningCount" label="Running" icon="directions_run" signal-color="info" />
      </div>
      <div class="col-12 col-sm-4">
        <KpiCard
          :value="store.failed7dCount"
          label="Failed (7 d)"
          icon="error"
          :signal-color="store.failed7dCount > 0 ? 'danger' : 'success'"
        />
      </div>
      <div class="col-12 col-sm-4">
        <KpiCard :value="store.completed7dCount" label="Completed (7 d)" icon="check_circle" signal-color="success" />
      </div>
    </div>

    <!-- Jobs master list + full-width detail -->
    <section class="jobs-workspace q-mb-md" data-test="jobs-workspace">
      <q-card flat bordered class="jobs-list-panel" data-test="jobs-list-panel">
        <q-card-section class="jobs-panel-header">
          <div class="row items-center q-gutter-x-sm">
            <q-icon name="work" color="primary" />
            <span class="text-subtitle1">Jobs</span>
            <q-space />
            <span class="jobs-panel-header__descriptor">select a row to open detail</span>
            <ContextHelp
              label="Jobs help"
              text="Jobs are executable operations with lifecycle states and optional cancel/retry actions. Change Audit is separate: an immutable record of who changed what and why."
            />
          </div>
        </q-card-section>

        <q-card-section class="jobs-list-body">
          <div class="row q-col-gutter-sm q-mb-md">
            <div class="col-12 col-sm-3">
              <q-select
                v-model="store.jobsFilter.state"
                label="State"
                :options="stateOptions"
                option-label="label"
                option-value="value"
                emit-value
                map-options
                outlined
                dense
                clearable
              />
            </div>
            <div class="col-12 col-sm-3">
              <q-select v-model="store.jobsFilter.type" label="Type" :options="typeOptions" outlined dense clearable />
            </div>
            <div class="col-12 col-sm-3">
              <q-input v-model="store.jobsFilter.actor" label="Actor" outlined dense clearable />
            </div>
            <div class="col-12 col-sm-3">
              <q-input
                v-model="store.jobsFilter.since"
                label="Since (local date and time)"
                type="datetime-local"
                outlined
                dense
                clearable
                data-test="jobs-since"
              />
            </div>
          </div>

          <div v-if="store.isLoadingJobs" class="jobs-empty" role="status">Loading jobs…</div>
          <div v-else-if="!store.filteredJobs.length" class="jobs-empty" role="status">
            <q-icon name="work_off" size="20px" class="q-mr-sm" />{{ jobsEmptyMessage }}
          </div>
          <div v-else class="job-list" role="list" aria-label="Operations jobs">
            <div v-for="row in store.filteredJobs" :key="row.id" class="job-row-wrap" role="listitem">
              <button
                type="button"
                class="job-row"
                :class="{ 'job-row--selected': selectedId === row.id }"
                :data-job-row="row.id"
                :aria-expanded="selectedId === row.id"
                :aria-controls="selectedId === row.id ? `job-detail-${row.id}` : undefined"
                :aria-label="`${selectedId === row.id ? 'Collapse' : 'Open'} ${row.display_id} ${row.title}, state ${row.state}`"
                @click="onToggleDetail(row)"
              >
                <span class="job-row__id">{{ row.display_id }}</span>
                <span class="job-row__main"
                  ><strong>{{ row.title }}</strong
                  ><span class="job-row__compact-state" data-test="job-compact-state">{{ row.state }}</span
                  ><small>{{ row.type }} · {{ row.actor ?? 'system' }} · {{ row.started_at }}</small></span
                >
                <span class="job-row__state">
                  <StateBadge :kind="badgeForState(row.state)" :label="row.state" />
                </span>
                <span class="job-row__open" aria-hidden="true">
                  <q-icon
                    :name="selectedId === row.id ? 'expand_less' : 'chevron_right'"
                    :data-test="selectedId === row.id ? 'job-collapse-icon' : 'job-expand-icon'"
                  />
                </span>
              </button>
              <div class="job-row__actions">
                <template v-if="row.can_cancel">
                  <q-btn
                    flat
                    dense
                    size="sm"
                    color="warning"
                    label="Cancel"
                    disable
                    data-test="backend-pending-mutation"
                    :aria-label="`Cancel ${row.display_id}`"
                    @click.stop="onCancel(row)"
                    ><q-tooltip
                      >Cancel is unavailable until external management authentication is configured.</q-tooltip
                    ></q-btn
                  >
                  <!-- The disabled button cannot receive keyboard focus, so a
                       focusable help target carries the same explanation for
                       keyboard users (B-F6). -->
                  <ContextHelp
                    :label="`Why is Cancel ${row.display_id} unavailable?`"
                    text="Cancel is unavailable until external management authentication is configured."
                    data-test="cancel-unavailable-help"
                    @click.stop
                  />
                </template>
                <template v-if="row.can_retry">
                  <q-btn
                    flat
                    dense
                    size="sm"
                    color="primary"
                    label="Retry"
                    disable
                    data-test="backend-pending-mutation"
                    :aria-label="`Retry ${row.display_id}`"
                    @click.stop="onRetry(row)"
                    ><q-tooltip
                      >Retry is unavailable until external management authentication is configured.</q-tooltip
                    ></q-btn
                  >
                  <ContextHelp
                    :label="`Why is Retry ${row.display_id} unavailable?`"
                    text="Retry is unavailable until external management authentication is configured."
                    data-test="retry-unavailable-help"
                    @click.stop
                  />
                </template>
              </div>
              <section
                v-if="selectedId === row.id"
                :id="`job-detail-${row.id}`"
                class="job-detail-panel"
                aria-label="Job detail"
                data-test="job-detail-panel"
              >
                <div v-if="store.selectedJob" class="job-detail-panel__body" data-test="job-detail-panel-body">
                  <section class="job-detail-meta">
                    <div class="detail-heading">Job</div>
                    <dl class="detail-fields" data-test="job-metadata">
                      <template v-for="field in selectedJobMetadata" :key="field.label"
                        ><dt>{{ field.label }}</dt>
                        <dd>{{ field.value }}</dd></template
                      >
                    </dl>
                    <div class="detail-heading q-mt-md">Parameters</div>
                    <dl v-if="selectedJobParams.length" class="detail-fields" data-test="job-parameters">
                      <template v-for="field in selectedJobParams" :key="field.label"
                        ><dt>{{ field.label }}</dt>
                        <dd>{{ field.value }}</dd></template
                      >
                    </dl>
                    <div v-else class="text-muted" data-test="job-parameters-empty">No parameters recorded</div>
                    <div class="detail-heading q-mt-md">Windows</div>
                    <div v-if="selectedJobParams.some((field) => field.label === 'Intervals')" class="window-note">
                      Atomic union; gaps are not trained.
                    </div>
                    <div v-else class="text-muted">No training windows recorded</div>
                    <div class="detail-heading q-mt-md">Result</div>
                    <div class="result-note">
                      {{ store.selectedJob.result ?? store.selectedJob.error ?? 'No terminal result recorded' }}
                    </div>
                  </section>
                  <section class="job-detail-log">
                    <div class="detail-heading">
                      Phase &amp; event timeline
                      <ContextHelp
                        label="About job phase and metric semantics"
                        text="Phases describe server-reported lifecycle checkpoints, not percentage progress. Metric chips are truthful values returned by the job."
                      />
                    </div>
                    <div v-if="store.selectedJob.phase_label" class="phase-note">
                      Current phase: {{ store.selectedJob.phase_label }}
                    </div>
                    <ol v-if="selectedJobLog.length" class="job-log" data-test="job-log">
                      <li
                        v-for="entry in selectedJobLog"
                        :key="`${entry.timestamp}-${entry.message}`"
                        class="job-log-entry"
                        data-test="job-log-entry"
                      >
                        <div class="row items-center q-gutter-x-sm">
                          <span class="text-caption text-muted">{{ entry.timestamp }}</span
                          ><q-chip dense outline>{{ entry.phase }}</q-chip>
                        </div>
                        <div class="job-log-message">{{ entry.message }}</div>
                        <div v-if="entry.metrics.length" class="job-log-metrics">
                          <q-chip v-for="metric in entry.metrics" :key="metric.label" dense
                            >{{ metric.label }}: {{ metric.value }}</q-chip
                          >
                        </div>
                      </li>
                    </ol>
                    <div v-else class="text-muted" data-test="job-log-empty">No log entries recorded</div>
                  </section>
                </div>
              </section>
            </div>
          </div>
          <InsufficientPermissionsNotice :message="store.jobsError" />
          <q-banner v-if="store.jobsError && !isInsufficientPermissionsMessage(store.jobsError)" class="bg-negative text-white q-mt-md">
            {{ store.jobsError }}
          </q-banner>
        </q-card-section>
      </q-card>
    </section>

    <!-- Change Audit section -->
    <q-card flat bordered>
      <q-card-section>
        <div class="row items-center q-gutter-x-sm">
          <q-icon name="history" color="primary" />
          <span class="text-subtitle1">Change Audit</span>
          <q-space />
          <ContextHelp
            label="Change Audit help"
            text="Change Audit is an immutable record of who changed what and why, including configuration, bounds, resets, services, jobs and access events. Unlike Jobs, audit entries attribute changes and are never modified."
          />
        </div>
      </q-card-section>

      <q-card-section>
        <div class="row q-col-gutter-sm q-mb-md">
          <div class="col-12 col-sm-3">
            <q-select
              v-model="store.auditFilter.category"
              label="Category"
              :options="auditCategoryOptions"
              option-label="label"
              option-value="value"
              emit-value
              map-options
              outlined
              dense
              clearable
            />
          </div>
          <div class="col-12 col-sm-3">
            <q-input v-model="store.auditFilter.actor" label="Actor" outlined dense clearable />
          </div>
          <div class="col-12 col-sm-3">
            <q-input
              v-model="store.auditFilter.since"
              label="Since (local date and time)"
              type="datetime-local"
              outlined
              dense
              clearable
            />
          </div>
          <div class="col-12 col-sm-3">
            <q-input v-model="store.auditFilter.q" label="Search action / target" outlined dense clearable>
              <template #append>
                <q-icon name="search" />
              </template>
            </q-input>
          </div>
        </div>

        <q-table
          :rows="store.filteredAudit"
          :columns="auditColumns"
          row-key="id"
          :loading="store.isLoadingAudit"
          flat
          bordered
          :pagination="{ rowsPerPage: 10 }"
          class="audit-table"
        >
          <template #no-data>
            <div class="full-width row flex-center q-py-md text-muted" role="status">
              <q-icon name="history_toggle_off" size="20px" class="q-mr-sm" />
              <span>{{ auditEmptyMessage }}</span>
            </div>
          </template>
        </q-table>
        <InsufficientPermissionsNotice :message="store.auditError" />
        <q-banner v-if="store.auditError && !isInsufficientPermissionsMessage(store.auditError)" class="bg-negative text-white q-mt-md">
          {{ store.auditError }}
        </q-banner>
      </q-card-section>
    </q-card>
  </div>
</template>

<script setup lang="ts">
/**
 * Operations / Jobs & History page.
 *
 * Renders truthful job summaries (Running, Failed 7d, Completed 7d),
 * filterable job table, indeterminate progress, safe cancel/retry, and
 * the immutable Change Audit table.
 */
import { computed, nextTick, onMounted, ref, watch } from 'vue'

import StateBadge from '~/components/operations/StateBadge.vue'
import ContextHelp from '~/components/operations/ContextHelp.vue'
import KpiCard from '~/components/shared/KpiCard.vue'
import InsufficientPermissionsNotice from '~/components/shared/InsufficientPermissionsNotice.vue'
import { OPERATIONS_HEAVY_POLL_INTERVAL_MS, useOperationsRefresh } from '~/composables/useOperationsRefresh'
import { usePolling } from '~/composables/usePolling'
import { useOperationsJobsStore, type JobsFilter } from '~/stores/operationsJobsStore'
import type { OperationsJobSummary, OperationsJobState, AuditFilter } from '~/types/api'
import { formatJobLog, formatJobMetadata, formatJobParams } from '~/utils/operationsJobFormatting'
import { isInsufficientPermissionsMessage } from '~/utils/permissions'

definePageMeta({ title: 'Operations / Jobs & History' })

const store = useOperationsJobsStore()
const route = useRoute()
const operationsRefresh = useOperationsRefresh()
const selectedId = ref<number | null>(null)
const selectedJobMetadata = computed(() => (store.selectedJob ? formatJobMetadata(store.selectedJob) : []))
const selectedJobParams = computed(() => (store.selectedJob ? formatJobParams(store.selectedJob.params) : []))
const selectedJobLog = computed(() => (store.selectedJob ? formatJobLog(store.selectedJob.log) : []))

// Distinguish "there are genuinely no rows" from "your filter matched none"
// so the operator is never left staring at a blank table (B-F11). The empty
// slot only renders when the *filtered* list is empty, so a non-empty raw
// list implies the filters excluded everything.
const jobsEmptyMessage = computed(() =>
  store.jobs.length === 0
    ? 'No jobs yet. Operations jobs will appear here as work runs.'
    : 'No jobs match the current filters.',
)

const auditEmptyMessage = computed(() =>
  store.audit.length === 0 ? 'No Change Audit entries yet.' : 'No Change Audit entries match the current filters.',
)

usePolling(operationsRefresh.refresh, OPERATIONS_HEAVY_POLL_INTERVAL_MS)

const stateOptions: Array<{ label: string; value: JobsFilter['state'] }> = [
  { label: 'All', value: 'all' },
  { label: 'Queued', value: 'queued' },
  { label: 'Running', value: 'running' },
  { label: 'Cancelling', value: 'cancelling' },
  { label: 'Completed', value: 'completed' },
  { label: 'Failed', value: 'failed' },
  { label: 'Cancelled', value: 'cancelled' },
]

const typeOptions = ['training', 'ingest', 'backup', 'service', 'maintenance']

const auditCategoryOptions: Array<{ label: string; value: AuditFilter['category'] }> = [
  { label: 'All', value: 'all' },
  { label: 'Config', value: 'config' },
  { label: 'Bounds', value: 'bounds' },
  { label: 'Reset', value: 'reset' },
  { label: 'Service', value: 'service' },
  { label: 'Job', value: 'job' },
  { label: 'Access', value: 'access' },
]

const auditColumns = [
  { name: 'at', label: 'Timestamp', field: 'at', align: 'left' as const, sortable: true },
  { name: 'category', label: 'Category', field: 'category', align: 'left' as const, sortable: true },
  { name: 'actor', label: 'User', field: 'actor', align: 'left' as const, sortable: true },
  { name: 'action', label: 'Action', field: 'action', align: 'left' as const, sortable: true },
  { name: 'target', label: 'Object', field: 'target', align: 'left' as const, sortable: true },
  { name: 'reason', label: 'Message', field: 'reason', align: 'left' as const, sortable: true },
]

function badgeForState(state: OperationsJobState) {
  switch (state) {
    case 'running':
      return 'info'
    case 'completed':
      return 'ok'
    case 'failed':
      return 'err'
    case 'cancelled':
    case 'cancelling':
      return 'warn'
    default:
      return 'muted'
  }
}

async function refreshJobs(): Promise<void> {
  const selected = selectedId.value
  await Promise.all([
    store.fetchJobs(),
    store.fetchAudit(),
    selected === null ? Promise.resolve() : store.fetchJobDetail(selected),
  ])
}

async function onToggleDetail(row: OperationsJobSummary): Promise<void> {
  if (selectedId.value === row.id) {
    selectedId.value = null
    store.clearSelectedJob()
    return
  }
  selectedId.value = row.id
  await store.fetchJobDetail(row.id)
}

/**
 * Expand and focus a job addressed by the `?job=<id>` deep-link so a
 * completion notification lands the operator directly on that row (B-F08).
 */
async function expandJobFromQuery(rawId: unknown): Promise<void> {
  const id = Number(rawId)
  if (!Number.isFinite(id) || id <= 0) return
  selectedId.value = id
  await store.fetchJobDetail(id)
  await nextTick()
  const el = document.querySelector<HTMLElement>(`[data-job-row="${id}"]`)
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
    el.focus()
  }
}

async function onCancel(row: OperationsJobSummary): Promise<void> {
  await store.cancelJob(row.id)
  if (selectedId.value === row.id) {
    await store.fetchJobDetail(row.id)
  }
}

async function onRetry(row: OperationsJobSummary): Promise<void> {
  await store.retryJob(row.id)
  if (selectedId.value === row.id) {
    selectedId.value = null
    store.clearSelectedJob()
  }
}

onMounted(async () => {
  operationsRefresh.register(refreshJobs, () => store.isLoadingJobs || store.isLoadingAudit)
  await operationsRefresh.refresh()
  if (route.query.job) {
    await expandJobFromQuery(route.query.job)
  }
})

onUnmounted(operationsRefresh.unregister)

// Handle in-app deep-links (e.g. the completion toast "Open" action)
// that change only the `?job=` query while the page is already mounted.
watch(
  () => route.query.job,
  async (jobId) => {
    if (jobId) {
      await expandJobFromQuery(jobId)
    }
  },
)
</script>

<style scoped lang="scss">
.cd-operations-jobs {
  width: 100%;
  min-width: 0;
}
.cd-operations-jobs > :first-child {
  margin-top: 0 !important;
}

.jobs-panel-header__descriptor {
  color: var(--cd-muted);
  font-size: 11.5px;
}

.jobs-kpis :deep(.kpi-card__body) {
  padding: 8px 12px;
}

.jobs-kpis :deep(.kpi-card__value) {
  font-size: 24px;
}

.jobs-kpis :deep(.kpi-card__signal-dot) {
  width: 14px;
  height: 14px;
}

.jobs-panel-header {
  padding: 9px 12px;
  border-bottom: 1px solid var(--cd-border);
}

.jobs-workspace {
  display: flex;
  flex-direction: column;
  gap: 0;
  min-width: 0;
}

.jobs-list-panel,
.job-detail-panel {
  width: 100%;
  min-width: 0;
}

.jobs-list-body {
  min-width: 0;
  padding: 10px 12px 12px;
}

.audit-table {
  max-width: 100%;
}

.audit-table :deep(.q-table__middle) {
  overflow-x: auto;
}

.audit-table :deep(th),
.audit-table :deep(td) {
  min-width: 110px;
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.jobs-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 120px;
  color: var(--cd-muted);
}

.job-list {
  overflow: hidden;
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-sm;
}

.job-row-wrap {
  position: relative;
  border-bottom: 1px solid var(--cd-border);
}

.job-row-wrap:last-child {
  border-bottom: 0;
}

.job-row {
  display: grid;
  grid-template-columns: 64px minmax(0, 1fr) auto 24px;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 10px 12px;
  border: 0;
  background: var(--cd-surface);
  color: var(--cd-surface-text);
  text-align: left;
  cursor: pointer;
}

.job-row:hover,
.job-row--selected {
  background: color-mix(in srgb, var(--cd-primary) 10%, var(--cd-surface));
}
.job-row--selected {
  box-shadow: inset 3px 0 0 var(--cd-primary);
}
.job-row__id {
  color: var(--cd-muted);
  font-family: monospace;
  font-size: 0.75rem;
}
.job-row__main {
  min-width: 0;
}
.job-row__main strong,
.job-row__main small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.job-row__main small {
  margin-top: 2px;
  color: var(--cd-muted);
  font-size: 0.72rem;
}
.job-row__compact-state {
  display: none;
  color: var(--cd-muted);
  font-size: 0.72rem;
  font-weight: 700;
  line-height: 1.2;
  white-space: nowrap;
}
.job-row__open {
  display: flex;
  justify-content: flex-end;
  min-width: 0;
  color: var(--cd-muted);
}
.job-row__actions {
  display: flex;
  gap: 4px;
  padding: 0 12px 8px 86px;
  background: var(--cd-surface);
}

// Ordinary job detail expands to its natural content height and uses more
// vertical page space (CAPTURE 30). No panel-level max-height and no body-level
// overflow, so J-1114/J-1115 metadata+timeline render fully without an internal
// scrollbar (scrollHeight === clientHeight). Only an exceptionally long event
// timeline is bounded, and that bound is scoped to `.job-log` alone (below).
.job-detail-panel {
  display: flex;
  min-height: 0;
  max-height: none;
  flex-direction: column;
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-sm;
  background: var(--cd-surface);
}

.job-detail-panel__body {
  display: grid;
  min-height: 0;
  flex: 1;
  grid-template-columns: minmax(0, 5fr) minmax(0, 6fr);
  padding-bottom: 12px;
}

.job-detail-meta,
.job-detail-log {
  min-width: 0;
  padding: 12px;
}
.job-detail-meta {
  border-right: 1px solid var(--cd-border);
}
.job-detail-log {
  background: color-mix(in srgb, var(--cd-background) 55%, var(--cd-surface));
}
.detail-heading {
  color: var(--cd-muted);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.window-note,
.result-note,
.phase-note {
  margin-top: 6px;
  padding: 7px 9px;
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-sm;
  font-size: 0.78rem;
  overflow-wrap: anywhere;
}
.window-note {
  color: var(--q-info);
}
.result-note {
  color: var(--cd-surface-text);
}

@media (max-width: 900px) {
  .job-detail-panel__body {
    grid-template-columns: 1fr;
  }
  .job-detail-meta {
    border-right: 0;
    border-bottom: 1px solid var(--cd-border);
  }
}

@media (max-width: 620px) {
  .job-row {
    grid-template-columns: 58px minmax(0, 1fr) 24px;
  }
  .job-row__state {
    display: none;
  }
  .job-row__compact-state {
    display: block;
  }
  .job-row__actions {
    padding-left: 70px;
  }
}

.detail-fields {
  display: grid;
  grid-template-columns: minmax(90px, 0.35fr) minmax(0, 1fr);
  gap: 6px 12px;
  margin: 8px 0 0;
  font-size: 12px;
}

.detail-fields dt {
  color: var(--cd-muted);
  font-weight: 600;
}

.detail-fields dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.job-log {
  display: grid;
  gap: 8px;
  list-style: none;
  margin: 8px 0 0;
  padding: 0;
}

// Only an exceptionally long event timeline is bounded, and the bound is scoped
// here to the timeline list alone — never the whole detail body (CAPTURE 30).
// The cap is materially larger than the retired 340px panel cap and is
// viewport-responsive, so ordinary J-1114/J-1115 timelines stay well under it
// and never trigger a scrollbar; only a genuinely long log scrolls internally.
.job-log {
  max-height: max(70vh, 620px);
  overflow-y: auto;
}
.job-log::-webkit-scrollbar {
  width: 10px;
}
.job-log::-webkit-scrollbar-thumb {
  border-radius: 6px;
  background: color-mix(in srgb, var(--cd-muted) 55%, transparent);
}
.job-log::-webkit-scrollbar-track {
  background: transparent;
}

.job-log-entry {
  background: var(--cd-surface);
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-sm;
  padding: 7px 8px;
  font-size: 12px;
  word-break: break-word;
}

.job-log-message {
  margin-top: 4px;
}

.job-log-metrics {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 6px;
}
// Detail phase/metric chips: compact but legible, suite-consistent target
// (12px / 24px). Smaller than the old oversized badges yet readable and
// higher-contrast than the 11px interim size. The header state badge stays
// canonical (StateBadge), unaffected by this scope.
.job-log-entry :deep(.q-chip) {
  min-height: 24px;
  padding: 0 8px;
  font-size: 12px;
}
.job-log-entry .text-caption {
  font-size: 12px;
}

.operations-job-detail-row,
.operations-job-detail-row > td {
  background: var(--cd-surface) !important;
  color: var(--cd-surface-text);
}
</style>
