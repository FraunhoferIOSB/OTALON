<template>
  <q-dialog v-model="show" persistent role="dialog" aria-modal="true" aria-labelledby="scan-detail-modal-title">
    <q-card class="scan-detail-modal__card">
      <q-card-section class="row items-center q-pb-none">
        <div id="scan-detail-modal-title" class="text-h6 row items-center">
          <q-icon name="info" color="grey-5" size="22px" class="q-mr-sm" />
          Scan details
        </div>
        <q-space />
        <q-btn icon="close" flat round dense aria-label="Close scan detail dialog" @click="onClose" />
      </q-card-section>

      <q-card-section v-if="loading" class="text-muted q-py-md"> Loading scan details… </q-card-section>
      <q-card-section
        v-else-if="upstreamNotImplemented"
        class="text-muted q-py-md"
        data-testid="scan-detail-unavailable"
      >
        Scan details not available yet
      </q-card-section>
      <q-card-section
        v-else-if="detail"
        class="scan-detail-modal__body q-gutter-y-md"
        data-testid="scan-detail-content"
      >
        <!-- Module + scan_id -->
        <div class="row items-center q-gutter-x-sm">
          <q-badge color="primary" class="text-body2">{{ detail.module }}</q-badge>
          <span class="text-mono text-caption">{{ detail.scan_id }}</span>
        </div>

        <!-- Status + timestamps -->
        <div class="row items-center q-gutter-x-sm">
          <q-badge :color="statusColor(detail.status)" :label="detail.status" class="q-px-sm" />
          <span v-if="detail.started_at" class="text-caption">
            {{ formatDateTime(detail.started_at) }}
            ({{ formatRelativeTime(detail.started_at) }})
          </span>
        </div>

        <!-- Duration -->
        <div class="text-caption text-muted">
          <q-icon name="timer" size="16px" class="q-mr-xs" />
          Duration: {{ durationText }}
        </div>

        <!-- Target -->
        <div v-if="targetText" class="text-body2">
          <q-icon name="my_location" size="18px" class="q-mr-xs text-primary" />
          Target: {{ targetText }}
        </div>

        <!-- Error -->
        <q-banner
          v-if="detail.error_message"
          rounded
          class="bg-red-1 text-red-9"
          data-testid="scan-detail-error-banner"
        >
          <template #avatar>
            <q-icon name="error" color="negative" />
          </template>
          {{ detail.error_message }}
        </q-banner>

        <!-- L-02: persisted findings snapshot -->
        <ScanResultDisplay v-if="findingsResult" :result="findingsResult" data-testid="scan-detail-findings" />
        <div v-else-if="findingsEmpty" class="text-caption text-muted" data-testid="scan-detail-no-findings">
          <q-icon name="search_off" size="16px" class="q-mr-xs" />
          No findings were recorded for this scan.
        </div>

        <!-- Raw detail accordion -->
        <q-expansion-item v-model="rawExpanded" label="Parameters / Raw" dense data-testid="scan-detail-raw-accordion">
          <pre class="text-mono q-pa-sm raw-json">{{ prettyJson(detail) }}</pre>
        </q-expansion-item>
      </q-card-section>

      <q-card-actions align="right" class="q-pa-md">
        <q-btn flat label="Close" @click="onClose" />
        <q-btn
          v-if="detail"
          color="primary"
          icon="replay"
          label="Replay"
          data-testid="scan-detail-replay-btn"
          @click="onReplay"
        />
      </q-card-actions>
    </q-card>
  </q-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import ScanResultDisplay from '~/components/scan/ScanResultDisplay.vue'
import { useApi, type ApiError } from '~/composables/useApi'
import type { ScanItem } from '~/types/scans'
import { formatDateTime, formatRelativeTime } from '~/utils/format'

interface Props {
  modelValue: boolean
  scanId?: string | null
}

const props = withDefaults(defineProps<Props>(), {
  scanId: null,
})

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'replay', scanId: string): void
}>()

const api = useApi()

const show = computed({
  get: () => props.modelValue,
  set: (v: boolean) => emit('update:modelValue', v),
})

const loading = ref(false)
const upstreamNotImplemented = ref(false)
const detail = ref<ScanItem | null>(null)
const rawExpanded = ref(false)

const durationText = computed<string>(() => {
  const s = detail.value?.started_at
  const f = detail.value?.finished_at
  if (!s) return '—'
  if (!f) {
    const lower = detail.value?.status.toLowerCase()
    if (lower === 'running') return 'running'
    return '—'
  }
  const startMs = new Date(s).getTime()
  const endMs = new Date(f).getTime()
  const diff = Math.max(0, endMs - startMs)
  const totalSeconds = Math.floor(diff / 1000)
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  if (minutes > 0) return `${minutes}m ${seconds}s`
  return `${seconds}s`
})

const targetText = computed<string>(() => {
  const params = detail.value?.parameters
  if (!params || typeof params !== 'object') return ''
  const p = params as Record<string, unknown>
  if (typeof p.target_subnet === 'string') return p.target_subnet
  if (typeof p.target_ip === 'string') return p.target_ip
  if (typeof p.subnet === 'string') return p.subnet
  if (typeof p.ip === 'string') return p.ip
  return ''
})

// L-02: surface the persisted per-scan findings snapshot. ScanResultDisplay
// expects a ``{module_name, findings, status}`` shape, so adapt the detail
// record into that contract when findings are present.
const findingsResult = computed<Record<string, unknown> | null>(() => {
  const list = detail.value?.findings
  if (!Array.isArray(list) || list.length === 0) return null
  return {
    module_name: detail.value?.module ?? '',
    status: detail.value?.status ?? null,
    findings: list,
  }
})

// True when the scan completed but recorded zero findings (vs. a legacy scan
// predating the snapshot column, where ``findings`` is absent/null).
const findingsEmpty = computed<boolean>(() => {
  const list = detail.value?.findings
  return Array.isArray(list) && list.length === 0
})

watch(
  () => props.modelValue,
  (open) => {
    if (open && props.scanId) {
      void fetchDetail(props.scanId)
    } else if (!open) {
      detail.value = null
      upstreamNotImplemented.value = false
      rawExpanded.value = false
    }
  },
)

async function fetchDetail(scanId: string): Promise<void> {
  loading.value = true
  upstreamNotImplemented.value = false
  detail.value = null
  try {
    const response = await api.get<ScanItem>(`/api/v1/scans/${encodeURIComponent(scanId)}`)
    detail.value = response
  } catch (err) {
    const apiErr = err as ApiError
    if (apiErr.status === 404 || apiErr.status === 501) {
      upstreamNotImplemented.value = true
    } else {
      console.warn('ScanDetailModal: fetchDetail failed', apiErr)
    }
  } finally {
    loading.value = false
  }
}

function statusColor(status: string): string {
  const lower = status.toLowerCase()
  if (lower === 'completed' || lower === 'done') return 'positive'
  if (lower === 'failed' || lower === 'error') return 'negative'
  if (lower === 'running') return 'primary'
  return 'grey-6'
}

function prettyJson(data: unknown): string {
  try {
    return JSON.stringify(data, null, 2)
  } catch {
    return String(data)
  }
}

function onClose(): void {
  show.value = false
}

function onReplay(): void {
  if (detail.value) {
    emit('replay', detail.value.scan_id)
  }
  onClose()
}
</script>

<style scoped lang="scss">
.scan-detail-modal__card {
  min-width: 520px;
  max-width: 640px;
  max-height: 88vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.scan-detail-modal__body {
  flex: 1;
  overflow-y: auto;
  min-height: 0;
}

.text-mono {
  font-family: $font-family-mono;
}

.raw-json {
  font-size: 12px;
  background: rgba(0, 0, 0, 0.03);
  border-radius: 6px;
  overflow-x: auto;
  max-height: 320px;
}
</style>
