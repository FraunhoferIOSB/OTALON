<template>
  <q-card flat bordered class="recent-scans">
    <q-expansion-item
      v-if="!inline"
      icon="history"
      :label="headerLabel"
      :default-opened="false"
      header-class="recent-scans__header"
      data-testid="recent-scans-panel"
    >
      <q-card-section v-if="loading" class="text-muted q-py-sm"> Loading recent scans… </q-card-section>
      <q-card-section
        v-else-if="upstreamNotImplemented"
        class="text-muted q-py-sm"
        data-testid="recent-scans-empty-state"
      >
        Scan listing not available yet
      </q-card-section>
      <q-card-section v-else-if="scans.length === 0" class="text-muted q-py-sm">
        No scans recorded yet.
      </q-card-section>
      <q-list v-else dense separator data-testid="recent-scans-list">
        <q-item v-if="selectedIds.length > 0" class="q-py-xs bulk-toolbar">
          <q-item-section>
            <div class="row items-center q-gutter-sm">
              <q-icon name="check_box" color="primary" size="18px" />
              <span class="text-body2 text-weight-medium">{{ selectedIds.length }} selected</span>
              <q-space />
              <q-btn
                flat
                no-caps
                dense
                color="grey-8"
                icon="clear"
                label="Clear"
                data-testid="recent-scans-bulk-clear-btn"
                @click="selectedIds = []"
              />
              <q-btn
                color="negative"
                icon="delete"
                label="Delete"
                no-caps
                dense
                :loading="bulkDeleting"
                data-testid="recent-scans-bulk-delete-btn"
                @click="onBulkDelete"
              />
            </div>
          </q-item-section>
        </q-item>

        <q-item v-for="scan in scans" :key="scan.scan_id" clickable class="q-py-sm" @click="$emit('select', scan)">
          <q-item-section side @click.stop>
            <q-checkbox v-model="selectedIds" :val="scan.scan_id" dense data-testid="recent-scans-row-checkbox" />
          </q-item-section>
          <q-item-section avatar>
            <q-badge :color="statusColor(scan.status)" :label="scan.status" class="q-px-sm" />
          </q-item-section>
          <q-item-section>
            <q-item-label data-testid="recent-scans-row-label">{{ scanPrimaryLabel(scan) }}</q-item-label>
            <q-item-label caption class="text-mono scan-uuid" :title="scan.scan_id">{{ scan.scan_id }}</q-item-label>
          </q-item-section>
          <q-item-section side>
            <div class="row items-center q-gutter-x-sm">
              <q-item-label caption>
                {{ scan.started_at ? formatRelativeTime(scan.started_at) : '—' }}
              </q-item-label>
              <q-btn
                flat
                round
                dense
                icon="delete"
                color="negative"
                size="sm"
                :aria-label="`Delete scan ${scan.scan_id}`"
                data-testid="recent-scans-row-delete-btn"
                @click.stop="onSingleDelete(scan)"
              />
            </div>
          </q-item-section>
        </q-item>
      </q-list>

      <!-- F-13 pagination -->
      <q-card-section
        v-if="!upstreamNotImplemented && scans.length > 0"
        class="row items-center justify-center q-gutter-sm q-py-sm"
      >
        <q-btn
          flat
          dense
          round
          icon="arrow_back"
          :disable="page <= 1 || loading"
          data-testid="recent-scans-prev-btn"
          @click="prevPage"
        />
        <span class="text-caption text-weight-medium" data-testid="recent-scans-page-label">Page {{ page }}</span>
        <q-btn
          flat
          dense
          round
          icon="arrow_forward"
          :disable="!hasMore || loading"
          data-testid="recent-scans-next-btn"
          @click="nextPage"
        />
      </q-card-section>
    </q-expansion-item>

    <!-- Inline mode for modal: no expansion wrapper -->
    <template v-else>
      <q-card-section class="row items-center q-py-sm">
        <q-icon name="history" size="20px" class="q-mr-sm" />
        <span class="text-subtitle2 text-weight-medium">{{ headerLabel }}</span>
        <q-space />
        <q-btn flat dense round icon="refresh" :loading="loading" @click="refresh">
          <q-tooltip>Refresh</q-tooltip>
        </q-btn>
      </q-card-section>
      <q-separator />
      <q-card-section v-if="loading" class="text-muted q-py-sm"> Loading recent scans… </q-card-section>
      <q-card-section
        v-else-if="upstreamNotImplemented"
        class="text-muted q-py-sm"
        data-testid="recent-scans-empty-state"
      >
        Scan listing not available yet
      </q-card-section>
      <q-card-section v-else-if="scans.length === 0" class="text-muted q-py-sm">
        No scans recorded yet.
      </q-card-section>
      <q-list v-else dense separator data-testid="recent-scans-list">
        <q-item v-if="selectedIds.length > 0" class="q-py-xs bulk-toolbar">
          <q-item-section>
            <div class="row items-center q-gutter-sm">
              <q-icon name="check_box" color="primary" size="18px" />
              <span class="text-body2 text-weight-medium">{{ selectedIds.length }} selected</span>
              <q-space />
              <q-btn
                flat
                no-caps
                dense
                color="grey-8"
                icon="clear"
                label="Clear"
                data-testid="recent-scans-bulk-clear-btn"
                @click="selectedIds = []"
              />
              <q-btn
                color="negative"
                icon="delete"
                label="Delete"
                no-caps
                dense
                :loading="bulkDeleting"
                data-testid="recent-scans-bulk-delete-btn"
                @click="onBulkDelete"
              />
            </div>
          </q-item-section>
        </q-item>

        <q-item v-for="scan in scans" :key="scan.scan_id" clickable class="q-py-sm" @click="$emit('select', scan)">
          <q-item-section side @click.stop>
            <q-checkbox v-model="selectedIds" :val="scan.scan_id" dense data-testid="recent-scans-row-checkbox" />
          </q-item-section>
          <q-item-section avatar>
            <q-badge :color="statusColor(scan.status)" :label="scan.status" class="q-px-sm" />
          </q-item-section>
          <q-item-section>
            <q-item-label data-testid="recent-scans-row-label">{{ scanPrimaryLabel(scan) }}</q-item-label>
            <q-item-label caption class="text-mono scan-uuid" :title="scan.scan_id">{{ scan.scan_id }}</q-item-label>
          </q-item-section>
          <q-item-section side>
            <div class="row items-center q-gutter-x-sm">
              <q-item-label caption>
                {{ scan.started_at ? formatRelativeTime(scan.started_at) : '—' }}
              </q-item-label>
              <q-btn
                flat
                round
                dense
                icon="delete"
                color="negative"
                size="sm"
                :aria-label="`Delete scan ${scan.scan_id}`"
                data-testid="recent-scans-row-delete-btn"
                @click.stop="onSingleDelete(scan)"
              />
            </div>
          </q-item-section>
        </q-item>
      </q-list>

      <q-card-section
        v-if="!upstreamNotImplemented && scans.length > 0"
        class="row items-center justify-center q-gutter-sm q-py-sm"
      >
        <q-btn
          flat
          dense
          round
          icon="arrow_back"
          :disable="page <= 1 || loading"
          data-testid="recent-scans-prev-btn"
          @click="prevPage"
        />
        <span class="text-caption text-weight-medium" data-testid="recent-scans-page-label">Page {{ page }}</span>
        <q-btn
          flat
          dense
          round
          icon="arrow_forward"
          :disable="!hasMore || loading"
          data-testid="recent-scans-next-btn"
          @click="nextPage"
        />
      </q-card-section>
    </template>
  </q-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'

import { useQuasar } from 'quasar'

import { useApi, type ApiError } from '~/composables/useApi'
import { useJobNotificationsStore } from '~/stores/jobNotificationsStore'
import type { ScanItem } from '~/types/scans'
import { formatRelativeTime } from '~/utils/format'

defineProps<{
  inline?: boolean
}>()

defineEmits<{
  (e: 'select', scan: ScanItem): void
}>()

const $q = useQuasar()
const api = useApi()
const jobStore = useJobNotificationsStore()

const scans = ref<ScanItem[]>([])
const loading = ref(false)
const upstreamNotImplemented = ref(false)
const selectedIds = ref<string[]>([])
const bulkDeleting = ref(false)
const page = ref(1)
const limit = ref(10)
const processedNotificationIds = ref<Set<string>>(new Set())

const hasMore = computed(() => scans.value.length === limit.value)

const headerLabel = computed(() => {
  if (upstreamNotImplemented.value) return 'Recent scans (unavailable)'
  if (scans.value.length === 0) return 'Recent scans'
  return `Recent scans (${scans.value.length})`
})

function moduleLabel(module: string): string {
  const leaf = module.split('/').pop() ?? module
  return leaf.replace(/_scan$/, '').replace(/_/g, ' ')
}

function scanScope(scan: ScanItem): string {
  const p = scan.parameters
  if (!p || typeof p !== 'object') return ''
  const rec = p as Record<string, unknown>
  for (const key of ['target_subnet', 'target_ip', 'subnet', 'ip', 'network_interface', 'interface']) {
    const val = rec[key]
    if (typeof val === 'string' && val.length > 0) return val
  }
  return ''
}

function scanPrimaryLabel(scan: ScanItem): string {
  const parts: string[] = [moduleLabel(scan.module)]
  const scope = scanScope(scan)
  if (scope) parts.push(scope)
  if (scan.started_at) {
    const d = new Date(scan.started_at)
    if (!Number.isNaN(d.getTime())) {
      parts.push(d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))
    }
  }
  return parts.join(' · ')
}

function normaliseList(raw: unknown): ScanItem[] {
  if (Array.isArray(raw)) return raw as ScanItem[]
  if (raw && typeof raw === 'object' && Array.isArray((raw as { scans?: unknown }).scans)) {
    return ((raw as { scans: unknown[] }).scans ?? []) as ScanItem[]
  }
  return []
}

async function refresh(): Promise<void> {
  loading.value = true
  upstreamNotImplemented.value = false
  try {
    const response = await api.get<unknown>('/api/v1/scans', {
      limit: limit.value,
      offset: (page.value - 1) * limit.value,
      order: 'desc',
    })
    scans.value = normaliseList(response)
    const present = new Set(scans.value.map((s) => s.scan_id))
    selectedIds.value = selectedIds.value.filter((id) => present.has(id))
  } catch (err) {
    const apiErr = err as ApiError
    if (apiErr.status === 404 || apiErr.status === 501) {
      upstreamNotImplemented.value = true
      scans.value = []
    } else {
      console.warn('ScanRecentPanel: refresh failed', apiErr)
    }
  } finally {
    loading.value = false
  }
}

function onSingleDelete(scan: ScanItem): void {
  $q.dialog({
    title: 'Delete scan',
    message: `Delete scan ${scan.scan_id}? This cannot be undone.`,
    ok: { label: 'Delete', color: 'negative', noCaps: true },
    cancel: { label: 'Cancel', flat: true, noCaps: true },
    persistent: true,
  }).onOk(() => {
    void performSingleDelete(scan.scan_id)
  })
}

async function performSingleDelete(scanId: string): Promise<void> {
  try {
    await api.del<unknown>(`/api/v1/scans/${encodeURIComponent(scanId)}`, undefined, undefined, {
      responseType: 'text',
    })
    $q.notify({ type: 'positive', message: 'Scan deleted', timeout: 3000 })
    await refresh()
  } catch (err) {
    const apiErr = err as ApiError
    $q.notify({
      type: 'warning',
      message: `Delete failed (${apiErr.status}): ${apiErr.message}`,
      timeout: 5000,
    })
  }
}

function onBulkDelete(): void {
  const count = selectedIds.value.length
  if (count === 0) return
  $q.dialog({
    title: 'Delete scans',
    message: `Delete ${count} scan${count === 1 ? '' : 's'}? This cannot be undone.`,
    ok: { label: 'Delete', color: 'negative', noCaps: true },
    cancel: { label: 'Cancel', flat: true, noCaps: true },
    persistent: true,
  }).onOk(() => {
    void performBulkDelete()
  })
}

async function performBulkDelete(): Promise<void> {
  bulkDeleting.value = true
  try {
    const res = await api.del<{ deleted: string[]; not_found: string[] }>('/api/v1/scans', undefined, {
      ids: selectedIds.value,
    })
    const msg =
      res.not_found.length > 0
        ? `${res.deleted.length} deleted, ${res.not_found.length} not found`
        : `${res.deleted.length} deleted`
    $q.notify({ type: 'positive', message: msg, timeout: 3000 })
    selectedIds.value = []
    await refresh()
  } catch (err) {
    const apiErr = err as ApiError
    $q.notify({
      type: 'warning',
      message: `Bulk delete failed (${apiErr.status}): ${apiErr.message}`,
      timeout: 5000,
    })
  } finally {
    bulkDeleting.value = false
  }
}

function nextPage(): void {
  if (!hasMore.value || loading.value) return
  page.value += 1
}

function prevPage(): void {
  if (page.value <= 1 || loading.value) return
  page.value -= 1
}

function statusColor(status: string): string {
  const lower = status.toLowerCase()
  if (lower === 'completed' || lower === 'done') return 'positive'
  if (lower === 'failed' || lower === 'error') return 'negative'
  if (lower === 'running') return 'primary'
  return 'grey-6'
}

/**
 * F-02 / F-08: watch the global job-notification store for scan-completion
 * events and refresh the list automatically so a running scan flips to
 * completed without a manual page reload.
 */
watch(
  () => jobStore.pending,
  (list) => {
    let shouldRefresh = false
    for (const n of list) {
      if (n.kind === 'scan' && !processedNotificationIds.value.has(n.id)) {
        processedNotificationIds.value.add(n.id)
        shouldRefresh = true
      }
    }
    if (shouldRefresh) {
      void refresh()
    }
  },
  { deep: true },
)

/**
 * F-13: when the page changes, reload the list.
 */
watch(
  () => page.value,
  () => {
    void refresh()
  },
)

defineExpose({ refresh })

onMounted(() => {
  void refresh()
})
</script>

<style scoped lang="scss">
.recent-scans {
  margin-top: 16px;
}

.recent-scans__header {
  font-weight: 600;
}

.bulk-toolbar {
  background-color: rgba(var(--cd-primary-rgb), 0.08);
  border-bottom: 1px solid rgba(var(--cd-primary-rgb), 0.3);
}

.text-mono {
  font-family: $font-family-mono;
  font-size: 0.85rem;
}

.scan-uuid {
  opacity: 0.6;
  font-size: 0.75rem;
}
</style>
