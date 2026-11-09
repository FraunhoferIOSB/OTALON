import { computed, onMounted, ref, watch, type ComputedRef, type Ref } from 'vue'
import { useApi } from '~/composables/useApi'
import { useAppStore } from '~/stores/appStore'

interface DataExtentResponse {
  has_data: boolean
  first_ts: string | null
  last_ts: string | null
}

const hasData = ref(false)
const firstTs = ref<string | null>(null)
const lastTs = ref<string | null>(null)
const isLoading = ref(false)
const loaded = ref(false)
let request: Promise<void> | null = null

/**
 * Decide whether a `[start, end]` window overlaps the `[first, last]` data
 * extent.
 *
 * Unparseable, empty, or inverted bounds are treated as **overlapping**
 * (returning `true`) so the "No data in the selected range" banner is never
 * shown on a transient or malformed state — only a genuine, fully-resolved
 * non-overlap returns `false`.
 *
 * @param start - ISO 8601 start of the selected window.
 * @param end - ISO 8601 end of the selected window.
 * @param first - ISO 8601 first available data timestamp.
 * @param last - ISO 8601 last available data timestamp.
 * @returns `true` when the window overlaps (or the state is transient), `false` only for a genuine non-overlap.
 */
export function overlapsRange(start: string, end: string, first: string, last: string): boolean {
  const s = new Date(start)
  const e = new Date(end)
  const f = new Date(first)
  const l = new Date(last)
  if (
    Number.isNaN(s.getTime()) ||
    Number.isNaN(e.getTime()) ||
    Number.isNaN(f.getTime()) ||
    Number.isNaN(l.getTime())
  ) {
    return true
  }
  if (s.getTime() > e.getTime() || f.getTime() > l.getTime()) {
    return true
  }
  return s.getTime() <= l.getTime() && e.getTime() >= f.getTime()
}

/**
 * Compute the effective selected window directly from the reactive store
 * inputs so Vue tracks `liveMode`, `liveIntervalSeconds`, and `timeRange` as
 * dependencies of {@link isCurrentRangeEmpty}.
 *
 * Reading these raw fields (instead of the cached `effectiveTimeRange`
 * getter whose live-mode `end` is a non-reactive `new Date()` snapshot) makes
 * every re-evaluation use a fresh wall-clock `now` and guarantees the computed
 * re-runs on any mode or window change.
 *
 * @param appStore - The application store providing the reactive inputs.
 * @returns Object with `start` and `end` as ISO 8601 UTC strings.
 */
function effectiveWindow(appStore: ReturnType<typeof useAppStore>): { start: string; end: string } {
  if (appStore.liveMode) {
    const now = new Date()
    const start = new Date(now.getTime() - appStore.liveIntervalSeconds * 1000)
    return { start: start.toISOString(), end: now.toISOString() }
  }
  return { start: appStore.timeRange.start, end: appStore.timeRange.end }
}

/**
 * Load and cache bounded Influx data extent for the shared time toolbar.
 *
 * @returns Reactive extent state, empty-range signal, and refresh function.
 */
export function useDataExtent(): {
  hasData: Ref<boolean>
  firstTs: Ref<string | null>
  lastTs: Ref<string | null>
  isLoading: Ref<boolean>
  isCurrentRangeEmpty: ComputedRef<boolean>
  refresh: () => Promise<void>
} {
  const appStore = useAppStore()
  const api = useApi()

  const refresh = async (): Promise<void> => {
    if (request) return request
    isLoading.value = true
    request = (async () => {
      try {
        const response = await api.get<DataExtentResponse>('/api/v1/timeseries/data-extent')
        hasData.value = response.has_data
        firstTs.value = response.first_ts
        lastTs.value = response.last_ts
        loaded.value = true
      } catch {
        hasData.value = false
        firstTs.value = null
        lastTs.value = null
      } finally {
        isLoading.value = false
        request = null
      }
    })()
    return request
  }

  const isCurrentRangeEmpty = computed(() => {
    if (!loaded.value || !hasData.value || !firstTs.value || !lastTs.value) return false
    const range = effectiveWindow(appStore)
    return !overlapsRange(range.start, range.end, firstTs.value, lastTs.value)
  })

  onMounted(() => {
    if (!loaded.value) void refresh()
  })

  // Keep `firstTs`/`lastTs` fresh across mode/window changes so the empty-range
  // signal does not stick to a stale extent after a live<->history toggle or a
  // window resize. The in-flight `request` guard inside `refresh` coalesces a
  // burst of changes into a single endpoint call.
  watch(
    () => appStore.effectiveTimeRange,
    () => {
      void refresh()
    },
  )

  return { hasData, firstTs, lastTs, isLoading, isCurrentRangeEmpty, refresh }
}
