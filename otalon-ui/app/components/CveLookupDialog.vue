<template>
  <q-dialog
    v-model="show"
    :persistent="isRunning"
    role="dialog"
    aria-modal="true"
    aria-labelledby="cve-lookup-dialog-title"
    data-testid="cve-lookup-dialog"
  >
    <q-card class="cve-lookup-dialog">
      <!-- Header -->
      <q-card-section class="row items-center q-pb-none">
        <div id="cve-lookup-dialog-title" class="text-h6 row items-center">
          <q-spinner v-if="isRunning" color="primary" size="24px" class="q-mr-sm" />
          <q-icon v-else-if="isCompleted" name="check_circle" color="positive" size="24px" class="q-mr-sm" />
          <q-icon v-else-if="isFailed" name="error" color="negative" size="24px" class="q-mr-sm" />
          <q-icon v-else name="search" color="primary" size="24px" class="q-mr-sm" />
          {{ dialogTitle }}
        </div>
        <q-space />
        <q-btn
          icon="close"
          flat
          round
          dense
          :aria-label="isRunning ? 'Hide (lookup continues)' : 'Close CVE lookup dialog'"
          data-testid="cve-dialog-close-btn"
          @click="onClose"
        />
      </q-card-section>

      <q-card-section class="cve-lookup-dialog__body q-pa-md">
        <!-- Ready state -->
        <template v-if="!currentJobId">
          <div class="row items-center q-mb-md">
            <q-icon name="devices" size="18px" class="q-mr-sm text-primary" />
            <span class="text-body2">{{ targetLabel }}</span>
          </div>

          <q-banner v-if="showRateLimitBox" rounded class="rate-limit-banner q-mb-md">
            <template #avatar>
              <q-icon name="warning" color="warning" />
            </template>
            <div class="text-caption">
              NVD rate limit without API key: ~5 req/30s. Consider adding an API key for faster lookups.
            </div>
          </q-banner>
        </template>

        <!-- Running / Terminal state -->
        <template v-if="currentJobId">
          <div class="cve-lookup-dialog__progress q-pa-sm q-mb-md">
            <div class="row items-center no-wrap">
              <q-spinner v-if="isRunning" color="primary" size="22px" />
              <q-icon v-else-if="isCompleted" name="check_circle" color="positive" size="22px" />
              <q-icon v-else-if="isFailed" name="error" color="negative" size="22px" />
              <q-icon v-else-if="isAborted" name="cancel" color="warning" size="22px" />
              <q-icon v-else name="stop_circle" color="warning" size="22px" />
              <span class="q-ml-sm text-weight-medium" data-testid="cve-dialog-status-badge">
                {{ statusLabel }}
              </span>
              <q-space />
              <span v-if="isRunning" class="text-mono text-amber q-mr-md" data-testid="cve-dialog-timer">
                {{ elapsedFormatted }}
              </span>
            </div>

            <q-linear-progress
              v-if="showProgressBar"
              :value="progressValue"
              color="info"
              class="q-mt-sm"
              data-testid="cve-dialog-progress-bar"
            />

            <div class="row items-center q-mt-xs">
              <span class="text-mono text-positive" data-testid="cve-dialog-live-count">
                {{ liveCountText }}
              </span>
              <q-space />
              <q-btn
                v-if="isRunning"
                color="negative"
                icon="stop"
                label="Stop"
                size="sm"
                :loading="stopping"
                :disable="stopping"
                data-testid="cve-dialog-stop-btn"
                @click="onStop"
              >
                <q-tooltip>Stop this CVE lookup</q-tooltip>
              </q-btn>
            </div>
          </div>

          <!-- Failed banner -->
          <q-banner
            v-if="isFailed"
            rounded
            class="bg-negative text-white q-mb-md"
            data-testid="cve-dialog-failed-banner"
          >
            <template #avatar>
              <q-icon name="error" color="white" />
            </template>
            <div class="text-body2">{{ lookupRecord?.error || 'Lookup failed' }}</div>
          </q-banner>

          <!-- Aborted banner -->
          <q-banner
            v-if="isAborted"
            rounded
            class="bg-warning text-white q-mb-md"
            data-testid="cve-dialog-aborted-banner"
          >
            <template #avatar>
              <q-icon name="cancel" color="white" />
            </template>
            <div class="text-body2">{{ lookupRecord?.error || 'Lookup cancelled by operator' }}</div>
          </q-banner>

          <!-- Completed results -->
          <template v-if="isCompleted">
            <CveResultDisplay :lookup="lookupRecord" :devices="store.devices" data-testid="cve-dialog-result-display" />
          </template>
        </template>
      </q-card-section>

      <q-separator />

      <!-- Actions -->
      <q-card-actions align="right" class="q-pa-md">
        <q-btn flat label="Close" :disable="starting" @click="onClose" />
        <q-btn
          v-if="!currentJobId"
          color="primary"
          icon="play_arrow"
          label="Start lookup"
          :loading="starting"
          :disable="starting"
          data-testid="cve-dialog-start-btn"
          @click="onStart"
        />
      </q-card-actions>
    </q-card>
  </q-dialog>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { useQuasar } from 'quasar'

import CveResultDisplay from '~/components/scan/CveResultDisplay.vue'
import { useApi } from '~/composables/useApi'
import { useCveLookupSse } from '~/composables/useCveLookupSse'
import { useJobNotificationsStore } from '~/stores/jobNotificationsStore'
import { useVulnerabilitiesStore } from '~/stores/vulnerabilitiesStore'
import type { ApiError } from '~/composables/useApi'
import type { CveLookupItem, VulnerabilityLookupRequest } from '~/types/api'

interface Props {
  modelValue: boolean
  initialDeviceId?: number
  initialJobId?: string
}

const props = defineProps<Props>()
const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
}>()

const store = useVulnerabilitiesStore()
const jobStore = useJobNotificationsStore()
const $q = useQuasar()
const api = useApi()

const show = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const currentJobId = ref<string | null>(null)
const lookupRecord = ref<CveLookupItem | null>(null)
const lookupStatus = ref<string | null>(null)
const starting = ref(false)
const stopping = ref(false)

/* Timer ─────────────────────────────────────────────────────────── */
const scanStartTime = ref<number | null>(null)
const timerNow = ref(Date.now())
let timerInterval: ReturnType<typeof setInterval> | null = null

const sseJobId = computed(() => {
  if (lookupStatus.value === 'running' && currentJobId.value) {
    return currentJobId.value
  }
  return null
})

const sse = useCveLookupSse(sseJobId)

/* Watchers ──────────────────────────────────────────────────────── */
watch(
  () => show.value,
  async (isOpen) => {
    if (isOpen) {
      resetDialog()
      if (props.initialJobId) {
        await loadLookup(props.initialJobId)
        if (lookupStatus.value === 'completed') {
          await store.fetchDevices().catch(() => {
            /* ignore */
          })
        }
      } else if (props.initialDeviceId != null && !store.devices.some((d) => d.id === props.initialDeviceId)) {
        /* R-01: ensure the device record is present so the idle title resolves
         * to a human-readable label instead of the raw `Device <id>` form. */
        await store.fetchDevices().catch(() => {
          /* ignore */
        })
      }
      /* else: ready state — no auto-trigger */
    } else {
      sse.close()
      stopTimer()
      currentJobId.value = null
      lookupRecord.value = null
      lookupStatus.value = null
    }
  },
)

watch(
  () => sse.terminalEvent.value,
  async (terminal) => {
    if (terminal) {
      lookupStatus.value = terminal.status
      stopTimer()
      await loadLookup(terminal.job_id)
      await store.fetchDevices().catch(() => {
        /* ignore refetch errors after terminal event */
      })
    }
  },
)

watch(
  () => sse.progressEvents.value,
  (events) => {
    if (events.length > 0 && scanStartTime.value === null) {
      startTimer()
    }
  },
)

watch(currentJobId, (id) => {
  if (id) {
    lookupStatus.value = 'running'
    startTimer()
  }
})

/* Computed helpers ──────────────────────────────────────────────── */
const isRunning = computed(() => lookupStatus.value === 'running')
const isCompleted = computed(() => lookupStatus.value === 'completed')
const isFailed = computed(() => lookupStatus.value === 'failed')
const isAborted = computed(() => lookupStatus.value === 'aborted')

const elapsedFormatted = computed(() => {
  if (scanStartTime.value === null) return '00:00.0'
  const ms = timerNow.value - scanStartTime.value
  const totalSeconds = Math.floor(ms / 1000)
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  const tenths = Math.floor((ms % 1000) / 100)
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}.${tenths}`
})

const dialogTitle = computed(() => {
  if (props.initialDeviceId != null) {
    return `CVE Lookup \u2014 ${deviceName(props.initialDeviceId)}`
  }
  return 'CVE Lookup'
})

const targetLabel = computed(() => {
  if (props.initialDeviceId != null) {
    const d = store.devices.find((dev) => dev.id === props.initialDeviceId)
    const ip = d?.interfaces?.[0]?.ipv4_address ?? ''
    return ip ? `${deviceName(props.initialDeviceId)} (${ip})` : deviceName(props.initialDeviceId)
  }
  return 'All eligible assets'
})

const statusLabel = computed(() => {
  if (isCompleted.value) return 'Completed'
  if (isFailed.value) return 'Failed'
  if (isAborted.value) return 'Cancelled'
  return 'Running'
})

const showProgressBar = computed(() => {
  if (!isRunning.value) return false
  const s = lookupRecord.value?.summary
  const eligible = (s?.eligible_assets as number | undefined) ?? (s?.assets_scanned as number | undefined) ?? 0
  return eligible > 1
})

const progressValue = computed(() => {
  if (!sse.progressEvents.value.length) return 0
  const latest = sse.progressEvents.value[sse.progressEvents.value.length - 1]
  if (!latest.total) return 0
  return latest.index / latest.total
})

const liveCountText = computed(() => {
  if (lookupRecord.value?.summary) {
    const s = lookupRecord.value.summary
    const assets = (s.assets_scanned as number | undefined) ?? (s.eligible_assets as number | undefined) ?? 0
    const cves = (s.cves_found as number | undefined) ?? 0
    return `${cves} CVE${cves === 1 ? '' : 's'} across ${assets} asset${assets === 1 ? '' : 's'}`
  }
  const progressCount = sse.progressEvents.value.length
  if (progressCount > 0) {
    const latest = sse.progressEvents.value[sse.progressEvents.value.length - 1]
    return `${latest.index} / ${latest.total} assets processed`
  }
  return 'Waiting for events\u2026'
})

const showRateLimitBox = computed(() => {
  const rec = lookupRecord.value
  if (rec) {
    return !rec.api_key_used && (rec.status === 'running' || rec.status === 'completed')
  }
  return false
})

/* Helpers ───────────────────────────────────────────────────────── */
/**
 * Human-readable label for a device, used for the dialog title in both the
 * idle and completed states. Preference order: hostname → vendor/product →
 * primary IPv4 → raw `Device <id>` fallback. Keeping a single ordering here
 * means the idle title never regresses to the raw `Device <id>` form once the
 * device record is loaded (R-01).
 */
function deviceName(deviceId: number): string {
  const d = store.devices.find((dev) => dev.id === deviceId)
  if (!d) return `Device ${deviceId}`
  const vendorProduct = `${d.vendor ?? ''} ${d.product_name ?? d.device_family ?? ''}`.trim()
  const ip = d.interfaces?.[0]?.ipv4_address ?? ''
  return d.hostname || vendorProduct || ip || `Device ${deviceId}`
}

function startTimer(): void {
  scanStartTime.value = Date.now()
  timerNow.value = Date.now()
  if (timerInterval) clearInterval(timerInterval)
  timerInterval = setInterval(() => {
    timerNow.value = Date.now()
  }, 100)
}

function stopTimer(): void {
  if (timerInterval) {
    clearInterval(timerInterval)
    timerInterval = null
  }
}

function resetDialog(): void {
  currentJobId.value = null
  lookupRecord.value = null
  lookupStatus.value = null
  sse.progressEvents.value = []
  sse.terminalEvent.value = null
  stopTimer()
  scanStartTime.value = null
  starting.value = false
  stopping.value = false
}

async function loadLookup(jobId: string): Promise<void> {
  try {
    const res = await api.get<CveLookupItem>(`/api/v1/vulnerabilities/lookups/${jobId}`)
    lookupRecord.value = res
    lookupStatus.value = res.status
    currentJobId.value = jobId
  } catch {
    /* ignore refetch errors */
  }
}

async function onStart(): Promise<void> {
  starting.value = true
  try {
    const body: VulnerabilityLookupRequest = {}
    if (props.initialDeviceId != null) {
      body.device_ids = [props.initialDeviceId]
    } else {
      body.all = true
    }
    const res = await store.runLookup(body)
    currentJobId.value = res.job_id
    jobStore.watchLookup(res.job_id)
    lookupStatus.value = 'running'
    startTimer()
  } catch (err: unknown) {
    const e = err as ApiError
    $q.notify({
      type: 'negative',
      message: `Lookup failed: ${e.message ?? 'Unknown error'}`,
      timeout: 5000,
    })
  } finally {
    starting.value = false
  }
}

async function onStop(): Promise<void> {
  if (!currentJobId.value) return
  stopping.value = true
  try {
    await store.stopLookup(currentJobId.value)
    /* The backend finalizes the job as ``aborted`` and emits a terminal
     * ``aborted`` SSE event; the terminalEvent watcher then settles the
     * status and stops the timer. As a guard against a missed terminal
     * frame, optimistically reflect the cancelled state + stop the timer
     * here so the dialog never appears stuck running after Stop. */
    if (isRunning.value) {
      lookupStatus.value = 'aborted'
      stopTimer()
    }
  } catch (err: unknown) {
    const e = err as ApiError
    $q.notify({
      type: 'negative',
      message: `Stop failed: ${e.message ?? 'Unknown error'}`,
      timeout: 5000,
    })
  } finally {
    stopping.value = false
  }
}

function onClose(): void {
  show.value = false
}

onUnmounted(() => {
  stopTimer()
  sse.close()
})
</script>

<style scoped lang="scss">
.cve-lookup-dialog {
  width: 900px;
  max-width: 92vw;
  min-width: 600px;
  height: 80vh;
  max-height: 88vh;
  min-height: 520px;
  display: flex;
  flex-direction: column;
  background: var(--cd-surface);
  resize: both;
  overflow: auto;
}

.cve-lookup-dialog__body {
  flex: 1;
  overflow-y: auto;
}

.cve-lookup-dialog__progress {
  background: rgba(0, 0, 0, 0.03);
  border: 1px solid var(--cd-border, rgba(0, 0, 0, 0.08));
  border-radius: 8px;
}

.rate-limit-banner {
  background: rgba(255, 183, 77, 0.1);
  border: 1px solid rgba(255, 183, 77, 0.4);
}
</style>
