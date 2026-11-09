import { computed, toValue, type ComputedRef, type MaybeRefOrGetter } from 'vue'

/** Shared cadence for heavier Operations configuration and system snapshots. */
export const OPERATIONS_HEAVY_POLL_INTERVAL_MS = 30_000

type RefreshCallback = () => Promise<void>

export interface OperationsRefreshControl {
  isAvailable: ComputedRef<boolean>
  isLoading: ComputedRef<boolean>
  refresh: RefreshCallback
  register: (callback: RefreshCallback, loading: MaybeRefOrGetter<boolean>) => void
  unregister: () => void
}

/**
 * Share one Operations-page refresh action with the persistent default layout.
 * Each page registers on mount, invokes `refresh()` for its initial load and
 * polling callback, then unregisters on unmount. Concurrent calls reuse the
 * same in-flight promise.
 *
 * @example
 * const refresh = useOperationsRefresh()
 * onMounted(() => {
 *   refresh.register(() => store.load(), () => store.loading)
 *   void refresh.refresh()
 * })
 * onUnmounted(refresh.unregister)
 */
export function useOperationsRefresh(): OperationsRefreshControl {
  const owner = Symbol('operations-refresh-registration')
  const activeCallback = useState<RefreshCallback | null>('operations-refresh:callback', () => null)
  const activeLoading = useState<MaybeRefOrGetter<boolean> | null>('operations-refresh:loading', () => null)
  const inFlight = useState<Promise<void> | null>('operations-refresh:in-flight', () => null)
  const activeOwner = useState<symbol | null>('operations-refresh:owner', () => null)
  // A monotonic route generation. Each register/unregister advances it so an
  // in-flight refresh started under a previous route can neither clear the
  // shared loading state of the new route nor be reused across the boundary
  // (B-F5 / C-3).
  const generation = useState<number>('operations-refresh:generation', () => 0)

  const isAvailable = computed(() => activeCallback.value !== null)
  const isLoading = computed(() => inFlight.value !== null || toValue(activeLoading.value ?? false))

  async function refresh(): Promise<void> {
    if (inFlight.value) return inFlight.value

    const callback = activeCallback.value
    if (!callback) return

    const startGeneration = generation.value
    // Invoke the callback synchronously (callers rely on the request starting
    // immediately) but consume its rejection so a polling `void refresh()` can
    // never surface an unhandled promise rejection; loading cleanup still runs.
    const pending = callback()
      .catch(() => undefined)
      .finally(() => {
        // Only clear the shared in-flight marker if this refresh still belongs
        // to the current route generation and is the tracked promise.
        if (generation.value === startGeneration && inFlight.value === pending) inFlight.value = null
      })
    inFlight.value = pending
    return pending
  }

  function register(callback: RefreshCallback, loading: MaybeRefOrGetter<boolean>): void {
    generation.value += 1
    activeOwner.value = owner
    activeCallback.value = callback
    activeLoading.value = loading
    // A fresh registration always starts with a clean in-flight slate so the
    // new route's initial load is never suppressed by a prior request.
    inFlight.value = null
  }

  function unregister(): void {
    if (activeOwner.value !== owner) return
    generation.value += 1
    activeOwner.value = null
    activeCallback.value = null
    activeLoading.value = null
    // Drop the reference to any in-flight request from this owner so its late
    // completion cannot clear a subsequent route's loading state.
    inFlight.value = null
  }

  return { isAvailable, isLoading, refresh, register, unregister }
}
