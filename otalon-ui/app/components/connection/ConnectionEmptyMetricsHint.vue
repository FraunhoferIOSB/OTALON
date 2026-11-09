<template>
  <div class="empty-metrics-hint placeholder column items-center justify-center" data-testid="empty-metrics-hint">
    <q-spinner v-if="isLoading" size="36px" color="info" class="q-mb-sm" />

    <template v-else-if="activeSibling">
      <q-icon name="sync_alt" size="48px" class="hint-icon hint-icon--rotating q-mb-sm" />
      <div class="text-subtitle1 hint-title" data-testid="hint-rotating-title">
        No data for port {{ selectedPortLabel }} in this time window
      </div>
      <div class="text-body2 hint-body q-mt-sm" data-testid="hint-rotating-body">
        This connection uses rotating ports — port {{ activePortLabel }} was active here.
      </div>
      <q-btn
        class="q-mt-md"
        color="info"
        unelevated
        no-caps
        icon="open_in_new"
        :label="`Jump to port ${activePortLabel}`"
        data-testid="hint-jump-button"
        @click="onJump"
      />
    </template>

    <template v-else>
      <q-icon name="hourglass_empty" size="48px" class="hint-icon hint-icon--generic q-mb-sm" />
      <div class="text-subtitle1 hint-title" data-testid="hint-generic-title">No data in this time window</div>
      <div class="text-body2 hint-body q-mt-sm" data-testid="hint-generic-body">
        The connection may have been inactive here or used a different port. Try widening the time window.
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import type { SiblingItem, SiblingsResponse } from '~/types/api'

/**
 * Explanatory hint shown in the connections feature-plot panel when the
 * selected connection returns zero metrics for the applied window (UI-017b).
 *
 * On mount / prop change it asks the backend for base-key siblings (same
 * connection, different port) that have non-zero data in the same window.
 * When a sibling is found, it renders a concrete rotating-port hint naming the
 * active port plus a one-click jump; otherwise it renders a generic hint.
 *
 * Styling uses theme CSS variables (never hardcoded colors) so the hint reads
 * correctly in both light and dark themes (recall UI-047).
 */
const props = defineProps<{
  selectedUci: string
  timeRange?: { start: string; stop: string }
}>()

const emit = defineEmits<{
  (e: 'jump', uci: string): void
}>()

const api = useApi()

const isLoading = ref(false)
const siblings = ref<SiblingItem[]>([])

/**
 * Split a 9-field UCI into its parts; returns null when malformed.
 */
function splitUci(uci: string): string[] | null {
  const parts = uci.split('/')
  return parts.length === 9 ? parts : null
}

const selectedParts = computed<string[] | null>(() => splitUci(props.selectedUci))

/**
 * The first active sibling (sorted server-side for determinism).
 */
const activeSibling = computed<SiblingItem | null>(() => siblings.value[0] ?? null)

/**
 * The port label of the selected (no-data) UCI: the dst port if it differs
 * from the active sibling, else the src port. Falls back to the dst port.
 */
const selectedPortLabel = computed<string>(() => {
  const parts = selectedParts.value
  if (!parts) return '?'
  const sib = activeSibling.value
  if (sib && sib.src_port !== parts[6]) return parts[6] ?? '?'
  return parts[7] ?? '?'
})

/**
 * The currently-active port named in the concrete hint: the sibling port that
 * differs from the selected UCI.
 */
const activePortLabel = computed<string>(() => {
  const sib = activeSibling.value
  if (!sib) return '?'
  const parts = selectedParts.value
  if (parts && sib.src_port !== parts[6]) return sib.src_port
  return sib.dst_port
})

/**
 * Fetch base-key siblings with data for the selected UCI + window.
 */
async function fetchSiblings(): Promise<void> {
  if (!props.selectedUci || !props.timeRange) {
    siblings.value = []
    return
  }
  isLoading.value = true
  try {
    const resp = await api.get<SiblingsResponse>('/api/v1/timeseries/siblings', {
      uci: props.selectedUci,
      start: props.timeRange.start,
      stop: props.timeRange.stop,
    })
    siblings.value = resp.has_active_sibling ? resp.siblings : []
  } catch {
    siblings.value = []
  } finally {
    isLoading.value = false
  }
}

/**
 * Emit a jump request to the active sibling UCI.
 */
function onJump(): void {
  const sib = activeSibling.value
  if (sib) emit('jump', sib.uci)
}

watch(
  () => [props.selectedUci, props.timeRange?.start, props.timeRange?.stop],
  () => {
    fetchSiblings()
  },
  { immediate: true },
)
</script>

<style scoped lang="scss">
.empty-metrics-hint {
  height: 100%;
  min-height: 400px;
  text-align: center;
  padding: $spacing-md;
}

.hint-icon--rotating {
  color: var(--cd-info);
}

.hint-icon--generic {
  color: var(--cd-text-muted);
}

.hint-title {
  font-weight: 700;
  color: var(--cd-surface-text);
}

.hint-body {
  max-width: 420px;
  color: var(--cd-text-muted);
}
</style>
