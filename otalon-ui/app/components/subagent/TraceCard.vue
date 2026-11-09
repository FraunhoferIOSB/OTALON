<template>
  <q-card flat bordered class="trace-card" :class="{ 'trace-card--compact': compact }">
    <q-card-section class="row items-center q-pb-sm">
      <q-icon name="auto_awesome" color="teal" class="q-mr-sm" />
      <div class="text-subtitle2">Forensic Trace</div>
      <q-space />
      <q-badge :color="statusColor" :label="job?.status ?? 'unknown'" class="q-mr-sm" />
      <span v-if="elapsedLabel" class="text-caption text-muted q-mr-sm">
        {{ elapsedLabel }}
      </span>
      <q-btn
        flat
        dense
        icon="open_in_full"
        size="sm"
        data-testid="trace-open-detail"
        @click="$emit('open-detail', props.jobId)"
      >
        <q-tooltip>Open Forensic Trace detail</q-tooltip>
      </q-btn>
      <q-btn
        v-if="canCancel"
        flat
        dense
        icon="cancel"
        color="negative"
        size="sm"
        :loading="cancelling"
        @click="onCancel"
      >
        <q-tooltip>Cancel running analysis</q-tooltip>
      </q-btn>
    </q-card-section>

    <q-separator />

    <!-- Tool calls list -->
    <q-card-section class="trace-list q-py-sm">
      <div v-if="(job?.tool_trace?.length ?? 0) === 0" class="text-caption text-muted">
        Waiting for first tool call …
      </div>
      <div
        v-for="(entry, idx) in job?.tool_trace ?? []"
        :key="idx"
        class="trace-entry row items-center no-wrap q-py-xs"
      >
        <q-chip dense size="sm" color="grey-3" text-color="grey-9" class="q-mr-sm"> r{{ entry.round }} </q-chip>
        <span class="text-mono text-body2 trace-entry__tool">{{ entry.tool }}</span>
        <span class="text-caption text-muted q-ml-sm trace-entry__args">
          {{ summariseArgs(entry.args) }}
        </span>
        <q-space />
        <span v-if="entry.error" class="text-caption text-negative q-mr-sm">
          <q-icon name="error" size="14px" /> {{ entry.error.slice(0, 40) }}
        </span>
        <span class="text-caption text-muted q-mr-sm"> {{ entry.result_chars.toLocaleString() }} chars </span>
        <span class="text-caption text-muted"> {{ entry.duration_ms }} ms </span>
      </div>
    </q-card-section>

    <!-- Final result -->
    <template v-if="hasFinal">
      <q-separator />
      <q-card-section class="q-pa-md">
        <div class="row items-center q-mb-sm">
          <q-icon name="check_circle" color="positive" class="q-mr-sm" />
          <div class="text-subtitle2">Classification</div>
        </div>

        <div class="row q-col-gutter-md">
          <div class="col-12">
            <div class="text-caption text-muted">Step 1 — Attack method</div>
            <div class="row items-center q-gutter-sm no-wrap">
              <q-chip dense color="teal" text-color="white">
                {{ job?.step1_technical?.technical_method ?? '—' }}
              </q-chip>
              <q-btn
                v-if="canAdoptStep1"
                outline
                dense
                no-caps
                size="sm"
                color="teal"
                icon="check_small"
                :label="adoptedPrimaryType === step1Method ? 'Adopted' : 'Adopt as Prediction'"
                :loading="adopting"
                :disable="adoptedPrimaryType === step1Method || adopting"
                @click="onAdoptStep1"
              >
                <q-tooltip v-if="adoptedPrimaryType !== step1Method">
                  Replace the supervised-ML prediction of this alarm with the subagent's Step-1 attack-method label.
                </q-tooltip>
              </q-btn>
            </div>
            <div v-if="job?.step1_technical?.observed_activity" class="text-body2 q-mt-xs">
              {{ job.step1_technical.observed_activity }}
            </div>
          </div>

          <div class="col-12 q-mt-sm">
            <div class="text-caption text-muted q-mb-xs">Step 2 — MITRE ICS</div>
            <template v-if="showMitreClassifications">
              <div
                v-for="(c, i) in job?.step2_classification?.classifications ?? []"
                :key="c.technique_id + i"
                class="mitre-row q-mb-sm"
              >
                <div class="row items-center no-wrap">
                  <q-chip dense color="primary" text-color="white" class="q-mr-sm">
                    {{ c.technique_id }}
                  </q-chip>
                  <span class="text-body2 text-weight-medium">
                    {{ c.technique_name ?? '' }}
                  </span>
                  <q-space />
                  <span class="text-body2 text-weight-bold"> {{ Math.round((c.confidence ?? 0) * 100) }}% </span>
                </div>
                <q-linear-progress
                  :value="c.confidence ?? 0"
                  :color="confidenceColor(c.confidence ?? 0)"
                  rounded
                  size="6px"
                  class="q-my-xs"
                />
                <div v-if="c.reasoning && !compact" class="text-caption text-muted">
                  {{ c.reasoning }}
                </div>
              </div>
            </template>
            <template v-else-if="job?.verdict">
              <q-banner :class="verdictBannerClass(job.verdict.outcome)" class="rounded-borders q-pa-sm">
                <q-badge
                  :color="verdictBadgeColor(job.verdict.outcome)"
                  :label="verdictBadgeLabel(job.verdict.outcome)"
                  class="q-mr-sm"
                />
                <span v-if="humanizeFpReason(job.verdict.fp_reason)" class="text-weight-medium q-mr-sm">
                  {{ humanizeFpReason(job.verdict.fp_reason) }}
                </span>
                {{ job.verdict.reasoning }}
              </q-banner>
            </template>
            <template v-else>
              <q-banner class="bg-grey-2 text-grey-8 rounded-borders q-pa-sm">
                <q-icon name="info" color="grey-5" class="q-mr-sm" />
                No attack detected — analysis concluded this alarm is likely benign or a false positive.
              </q-banner>
            </template>
          </div>

          <div class="col-12 row q-col-gutter-sm text-caption text-muted q-mt-sm">
            <div class="col"><strong>Tools:</strong> {{ job?.tool_trace?.length ?? 0 }}</div>
            <div class="col">
              <strong>Tokens:</strong>
              {{ ((job?.tokens_prompt ?? 0) + (job?.tokens_completion ?? 0)).toLocaleString() }}
            </div>
            <div class="col"><strong>Duration:</strong> {{ job?.duration_seconds?.toFixed(1) ?? '—' }}s</div>
            <div v-if="compact" class="col">
              <q-btn
                flat
                dense
                size="sm"
                color="primary"
                :to="`/alarms?selected=${job?.alarm_id}#subagent-${job?.id}`"
                icon="open_in_new"
                label="Full trace"
              />
            </div>
          </div>
        </div>
      </q-card-section>
    </template>

    <!-- Error -->
    <template v-if="job?.status === 'failed' || job?.status === 'timeout' || job?.status === 'cancelled'">
      <q-separator />
      <q-card-section class="text-negative q-pa-md">
        <q-icon name="error_outline" class="q-mr-sm" />
        <span class="text-body2">
          {{ job?.error_message ?? `Job ended with status ${job?.status}` }}
        </span>
      </q-card-section>
    </template>
  </q-card>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import { computed, onMounted, ref, toRef } from 'vue'

import { useSubagentSse } from '~/composables/useSubagentSse'
import { useAlarmsStore } from '~/stores/alarmsStore'
import { useSubagentStore } from '~/stores/subagentStore'
import {
  humanizeFpReason,
  shouldShowMitreClassifications,
  verdictBadgeColor,
  verdictBadgeLabel,
  verdictBannerClass,
} from '~/utils/subagentVerdict'

const props = withDefaults(
  defineProps<{
    jobId: string
    compact?: boolean
  }>(),
  { compact: false },
)

defineEmits<{
  (e: 'open-detail', jobId: string): void
}>()

const $q = useQuasar()
const store = useSubagentStore()
const alarmsStore = useAlarmsStore()
const cancelling = ref(false)
const adopting = ref(false)

const jobIdRef = toRef(props, 'jobId')
useSubagentSse(jobIdRef)

onMounted(() => {
  // Ensure live state exists even if SSE proxy is slow to send first event
  if (!store.liveJobsById[props.jobId]) {
    void store.loadJob(props.jobId)
  }
})

const job = computed(() => store.liveJobsById[props.jobId])

const hasFinal = computed(() => job.value?.status === 'completed')
const showMitreClassifications = computed(() => {
  const classifications = job.value?.step2_classification?.classifications ?? []
  return shouldShowMitreClassifications(job.value?.verdict?.outcome, classifications.length)
})

const canCancel = computed(() => job.value?.status === 'pending' || job.value?.status === 'running')

const statusColor = computed(() => {
  switch (job.value?.status) {
    case 'completed':
      return 'positive'
    case 'pending':
      return 'grey'
    case 'running':
      return 'primary'
    case 'failed':
    case 'timeout':
    case 'cancelled':
      return 'negative'
    default:
      return 'grey'
  }
})

const elapsedLabel = computed(() => {
  const j = job.value
  if (!j) return null
  if (j.duration_seconds != null) {
    return `${j.duration_seconds.toFixed(1)}s`
  }
  if (j.started_at) {
    const ms = Date.now() - new Date(j.started_at).getTime()
    return `${(ms / 1000).toFixed(0)}s`
  }
  return null
})

function summariseArgs(args: Record<string, unknown> | undefined | null): string {
  if (!args || Object.keys(args).length === 0) return ''
  const s = JSON.stringify(args)
  return s.length > 100 ? s.slice(0, 100) + '…' : s
}

function confidenceColor(value: number): string {
  if (value >= 0.85) return 'positive'
  if (value >= 0.6) return 'warning'
  return 'negative'
}

async function onCancel(): Promise<void> {
  cancelling.value = true
  const ok = await store.cancel(props.jobId)
  cancelling.value = false
  $q.notify({
    type: ok ? 'info' : 'negative',
    message: ok ? 'Cancellation requested' : 'Could not cancel job',
    timeout: 3000,
  })
}

/**
 * Step-1 attack-method label produced by the subagent (or undefined).
 */
const step1Method = computed<string | undefined>(() => {
  const v = job.value?.step1_technical?.technical_method
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined
})

/**
 * Current alarm row from the alarms store (resolved by the job's alarm_id).
 * Used to compare the existing primary_type against the subagent's Step-1
 * label so the Adopt button only appears when adoption is meaningful.
 */
const alarmRow = computed(() => {
  const id = job.value?.alarm_id
  if (!id) return undefined
  return alarmsStore.groups.find((g) => g.id === id)
})

/**
 * Currently effective primary_type as a single string (joins arrays).
 */
const adoptedPrimaryType = computed<string | undefined>(() => {
  const pt = alarmRow.value?.primary_type
  if (Array.isArray(pt)) return pt.length > 0 ? pt.join(',') : undefined
  return typeof pt === 'string' && pt.trim() !== '' ? pt.trim() : undefined
})

/**
 * Show the Adopt button only when:
 * - the subagent produced a Step-1 method,
 * - the alarm exists in the local store (so we can refresh state), and
 * - the current primary_type is not already equal to the suggestion.
 */
const canAdoptStep1 = computed<boolean>(() => {
  return Boolean(step1Method.value && alarmRow.value && adoptedPrimaryType.value !== step1Method.value)
})

async function onAdoptStep1(): Promise<void> {
  if (!step1Method.value || !alarmRow.value) return
  const targetLabel = step1Method.value
  const previous = adoptedPrimaryType.value ?? '(unset)'
  adopting.value = true
  const ok = await alarmsStore.adoptPrimaryType(alarmRow.value.id, targetLabel)
  adopting.value = false
  if (ok) {
    $q.notify({
      type: 'positive',
      icon: 'check_small',
      message: `primary_type updated: "${previous}" → "${targetLabel}"`,
      timeout: 3500,
    })
  } else {
    $q.notify({
      type: 'negative',
      icon: 'error',
      message: alarmsStore.error ?? 'Could not adopt primary_type',
      timeout: 4500,
    })
  }
}
</script>

<style scoped lang="scss">
.trace-card {
  width: 100%;
}

.trace-card--compact {
  font-size: 0.85rem;
}

.trace-list {
  max-height: 340px;
  overflow-y: auto;
  scrollbar-width: thin;
}

.trace-entry {
  border-bottom: 1px dashed var(--cd-table-row-even);
}

.trace-entry__tool {
  font-weight: 600;
}

.trace-entry__args {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 220px;
}

.text-mono {
  font-family: $font-family-mono;
}

.mitre-row {
  background: var(--cd-table-row-even);
  padding: 6px 8px;
  border-radius: 4px;
}
</style>
