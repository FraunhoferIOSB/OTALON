<template>
  <q-dialog :model-value="modelValue" @update:model-value="$emit('update:modelValue', $event)">
    <q-card style="min-width: 720px; max-width: 1100px; width: 80vw" class="forensic-modal-card">
      <q-card-section class="row items-center q-pb-sm">
        <q-icon name="auto_awesome" color="teal" class="q-mr-sm" />
        <div class="text-h6">Forensic Trace</div>
        <q-space />
        <q-btn v-close-popup icon="close" flat round dense />
      </q-card-section>

      <q-separator />

      <q-card-section class="q-py-sm">
        <div class="row items-center q-gutter-sm">
          <span v-if="job" class="text-mono text-caption text-muted">{{ job.id.slice(0, 8) }}</span>
          <q-badge v-if="job" :color="statusColor(job.status)" :label="job.status" />
        </div>
        <div v-if="job" class="text-caption text-muted q-mt-xs">
          {{ job.prompt_variant }} / {{ job.llm_model }}
          <span v-if="job.duration_seconds != null"> · {{ job.duration_seconds.toFixed(1) }}s</span>
          <span v-if="totalTokens > 0"> · {{ totalTokens.toLocaleString() }} tokens</span>
          <span v-if="job.tool_trace?.length"> · {{ job.tool_trace.length }} tool calls</span>
        </div>
      </q-card-section>

      <q-separator />

      <q-card-section class="scrollable-section q-pa-sm">
        <div v-if="!job" class="text-caption text-muted">Loading …</div>
        <div v-else-if="(job.tool_trace?.length ?? 0) === 0" class="text-caption text-muted">
          No tool calls recorded.
        </div>
        <q-list v-else dense>
          <q-expansion-item
            v-for="(entry, idx) in job.tool_trace"
            :key="idx"
            :default-opened="!!entry.error"
            dense
            class="tool-expansion"
          >
            <template #header>
              <q-item-section avatar>
                <q-chip dense size="sm" color="grey-3" text-color="grey-9"> r{{ entry.round }} </q-chip>
              </q-item-section>
              <q-item-section>
                <div class="row items-center no-wrap">
                  <span class="text-mono text-body2">{{ entry.tool }}</span>
                  <span class="text-caption text-muted q-ml-sm">{{ entry.duration_ms }} ms</span>
                  <span class="text-caption text-muted q-ml-sm"> {{ entry.result_chars.toLocaleString() }} chars </span>
                  <q-badge v-if="entry.error" color="negative" class="q-ml-sm" label="error" />
                </div>
              </q-item-section>
            </template>

            <q-card flat class="q-ml-lg q-mt-xs q-mb-sm">
              <q-card-section class="q-pa-sm">
                <div class="text-caption text-weight-bold q-mb-xs">Arguments</div>
                <pre class="text-mono args-pre">{{ JSON.stringify(entry.args, null, 2) }}</pre>

                <div class="text-caption text-weight-bold q-mt-sm q-mb-xs">Output</div>
                <pre class="text-mono output-pre">{{ formatPreview(entry) }}</pre>
                <div
                  v-if="entry.result_chars > (entry.result_preview?.length ?? 0)"
                  class="text-caption text-muted q-mt-xs"
                >
                  … truncated ({{ entry.result_chars.toLocaleString() }} chars total)
                </div>
                <div v-else-if="entry.result_preview == null" class="text-caption text-muted q-mt-xs">
                  Output not recorded (job predates output capture)
                </div>
              </q-card-section>
            </q-card>
          </q-expansion-item>
        </q-list>
      </q-card-section>

      <q-separator />

      <q-card-section v-if="hasClassification" class="q-pa-md">
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
                  :track-color="$q.dark.isActive ? 'grey-9' : 'grey-3'"
                  rounded
                  size="6px"
                  class="q-my-xs"
                />
                <div v-if="c.reasoning" class="text-caption text-muted">
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
        </div>
      </q-card-section>
    </q-card>
  </q-dialog>
</template>

<script setup lang="ts">
import { computed, watch } from 'vue'
import { useQuasar } from 'quasar'

import { useSubagentStore } from '~/stores/subagentStore'
import type { SubagentJobStatus, SubagentTraceEntry } from '~/types/api'
import {
  humanizeFpReason,
  shouldShowMitreClassifications,
  verdictBadgeColor,
  verdictBadgeLabel,
  verdictBannerClass,
} from '~/utils/subagentVerdict'

const props = defineProps<{
  modelValue: boolean
  jobId: string | null
}>()

defineEmits<{
  (e: 'update:modelValue', value: boolean): void
}>()

const $q = useQuasar()
const store = useSubagentStore()

const job = computed(() => (props.jobId ? store.liveJobsById[props.jobId] : null))

const totalTokens = computed(() => {
  const j = job.value
  if (!j) return 0
  return (j.tokens_prompt ?? 0) + (j.tokens_completion ?? 0)
})

const hasClassification = computed(() => job.value?.status === 'completed')
const showMitreClassifications = computed(() => {
  const classifications = job.value?.step2_classification?.classifications ?? []
  return shouldShowMitreClassifications(job.value?.verdict?.outcome, classifications.length)
})

watch(
  () => props.modelValue,
  (open) => {
    if (open && props.jobId && !store.liveJobsById[props.jobId]) {
      void store.loadJob(props.jobId)
    }
  },
)

function statusColor(status: SubagentJobStatus): string {
  switch (status) {
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
}

function confidenceColor(value: number): string {
  if (value >= 0.85) return 'positive'
  if (value >= 0.6) return 'warning'
  return 'negative'
}

function formatPreview(entry: SubagentTraceEntry): string {
  const raw = entry.result_preview
  if (raw == null) return ''
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}
</script>

<style scoped lang="scss">
.forensic-modal-card {
  max-height: 90vh;
  display: flex;
  flex-direction: column;
}

.scrollable-section {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
}

.text-mono {
  font-family: $font-family-mono;
}

.args-pre,
.output-pre {
  background: var(--cd-surface);
  border: 1px solid var(--cd-border);
  border-radius: 4px;
  padding: 8px;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 12px;
  max-height: 300px;
  overflow-y: auto;
}

.mitre-row {
  background: var(--cd-table-row-even);
  padding: 6px 8px;
  border-radius: 4px;
}
</style>
