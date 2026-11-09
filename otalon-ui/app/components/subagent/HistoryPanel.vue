<template>
  <q-expansion-item
    icon="history"
    :label="`Forensic History (${jobs.length})`"
    header-class="text-subtitle2"
    default-opened
  >
    <q-card flat>
      <q-card-section class="q-pa-sm">
        <div v-if="store.loadingHistory[alarmId]" class="text-caption text-muted">Loading…</div>
        <div v-else-if="jobs.length === 0" class="text-caption text-muted">No prior forensic runs for this alarm.</div>
        <q-list dense bordered separator>
          <q-item v-for="job in jobs" :key="job.id" clickable @click="$emit('select', job.id)">
            <q-item-section avatar>
              <q-icon :name="statusIcon(job.status)" :color="statusColor(job.status)" size="20px" />
            </q-item-section>
            <q-item-section>
              <q-item-label class="row items-center">
                <span class="text-mono">{{ job.id.slice(0, 8) }}</span>
                <q-chip v-if="job.step1_method" dense size="sm" color="teal" text-color="white" class="q-ml-sm">
                  {{ job.step1_method }}
                </q-chip>
                <q-chip v-if="job.top_step2" dense size="sm" color="primary" text-color="white" class="q-ml-xs">
                  {{ job.top_step2.technique_id }}
                  ({{ Math.round((job.top_step2.confidence ?? 0) * 100) }}%)
                </q-chip>
                <q-badge
                  v-else-if="job.verdict_outcome"
                  :color="verdictBadgeColor(job.verdict_outcome)"
                  :label="verdictBadgeLabel(job.verdict_outcome)"
                  class="q-ml-xs"
                />
              </q-item-label>
              <q-item-label caption>
                {{ formatTime(job.created_at) }}
                · {{ job.prompt_variant }}/{{ job.llm_model }}
                <span v-if="job.duration_seconds"> · {{ job.duration_seconds.toFixed(1) }}s </span>
                · {{ job.tool_trace_count }} tools · {{ job.tokens_total.toLocaleString() }} tokens
              </q-item-label>
            </q-item-section>
            <q-item-section side>
              <q-btn
                flat
                dense
                icon="open_in_full"
                size="sm"
                data-testid="history-open-detail"
                @click.stop="$emit('open-detail', job.id)"
              >
                <q-tooltip>Open Forensic Trace detail</q-tooltip>
              </q-btn>
            </q-item-section>
          </q-item>
        </q-list>
      </q-card-section>
    </q-card>
  </q-expansion-item>
</template>

<script setup lang="ts">
import { computed, onMounted, watch } from 'vue'

import { useSubagentStore } from '~/stores/subagentStore'
import type { SubagentJobStatus } from '~/types/api'
import { verdictBadgeColor, verdictBadgeLabel } from '~/utils/subagentVerdict'

const props = defineProps<{
  alarmId: string
}>()

defineEmits<{
  (e: 'select' | 'open-detail', jobId: string): void
}>()

const store = useSubagentStore()

const jobs = computed(() => store.historyFor(props.alarmId))

watch(
  () => props.alarmId,
  (id) => {
    if (id) void store.loadHistory(id)
  },
  { immediate: true },
)

onMounted(() => {
  if (props.alarmId) void store.loadHistory(props.alarmId)
})

function statusIcon(status: SubagentJobStatus): string {
  switch (status) {
    case 'completed':
      return 'check_circle'
    case 'pending':
    case 'running':
      return 'hourglass_top'
    case 'failed':
      return 'error_outline'
    case 'timeout':
      return 'schedule'
    case 'cancelled':
      return 'cancel'
    default:
      return 'help_outline'
  }
}

function statusColor(status: SubagentJobStatus): string {
  switch (status) {
    case 'completed':
      return 'positive'
    case 'running':
      return 'primary'
    case 'pending':
      return 'grey'
    case 'failed':
    case 'timeout':
      return 'negative'
    case 'cancelled':
      return 'orange'
    default:
      return 'grey'
  }
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString()
}
</script>
