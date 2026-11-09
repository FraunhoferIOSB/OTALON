import type { ComputedRef, MaybeRefOrGetter, Ref } from 'vue'
import { useDocumentVisibility } from '@vueuse/core'

/**
 * Options for configuring the polling behavior.
 */
export interface UsePollingOptions {
  immediate?: boolean
  enabled?: Ref<boolean>
}

/**
 * Return type for the usePolling composable.
 */
export interface UsePollingReturn {
  isActive: ComputedRef<boolean>
  pause: () => void
  resume: () => void
}

/**
 * Composable that repeatedly calls an async function at a configurable interval.
 *
 * Automatically pauses when the browser tab becomes hidden and resumes
 * when the tab becomes visible again. Cleans up on component unmount.
 *
 * @param fn - Async function to execute on each polling tick.
 * @param intervalMs - Interval between executions in milliseconds. Accepts a plain number,
 *   a `Ref<number>`, a `ComputedRef<number>`, or a getter `() => number`.
 *   When reactive, the timer restarts automatically on value changes.
 * @param options - Optional configuration for immediate execution and enable/disable control.
 * @returns Controls for observing and managing the polling lifecycle.
 */
export function usePolling(
  fn: () => Promise<void>,
  intervalMs: MaybeRefOrGetter<number>,
  options?: UsePollingOptions,
): UsePollingReturn {
  const resolvedInterval = computed(() => toValue(intervalMs))
  const isClient = import.meta.client ?? typeof window !== 'undefined'
  const visibility = isClient ? useDocumentVisibility() : ref('visible' as DocumentVisibilityState)
  const paused = ref(false)
  let timerId: ReturnType<typeof setInterval> | null = null
  let inFlight = false

  const externalEnabled = options?.enabled ?? ref(true)

  const isActive = computed(() => !paused.value && externalEnabled.value && visibility.value === 'visible')

  function startTimer(): void {
    stopTimer()
    if (!isClient) return
    timerId = setInterval(() => {
      if (isActive.value) {
        if (inFlight) return
        inFlight = true
        // Release the in-flight guard first (same tick as before), then absorb
        // any rejection so an unexpected callback failure never becomes an
        // unhandled promise rejection.
        void fn()
          .finally(() => {
            inFlight = false
          })
          .catch(() => undefined)
      }
    }, resolvedInterval.value)
  }

  function stopTimer(): void {
    if (timerId !== null) {
      clearInterval(timerId)
      timerId = null
    }
  }

  /**
   * Pause polling. No further ticks will fire until resume is called.
   */
  function pause(): void {
    paused.value = true
    stopTimer()
  }

  /**
   * Resume polling after a pause. Restarts the interval timer immediately.
   */
  function resume(): void {
    paused.value = false
    if (externalEnabled.value) {
      startTimer()
    }
  }

  watch(
    isActive,
    (active) => {
      if (active) {
        startTimer()
      } else {
        stopTimer()
      }
    },
    { immediate: true },
  )

  watch(externalEnabled, (enabled) => {
    if (enabled && !paused.value) {
      startTimer()
    } else {
      stopTimer()
    }
  })

  watch(resolvedInterval, () => {
    if (isActive.value) {
      startTimer()
    }
  })

  if (options?.immediate && isClient) {
    inFlight = true
    void fn()
      .finally(() => {
        inFlight = false
      })
      .catch(() => undefined)
  }

  onUnmounted(() => {
    stopTimer()
  })

  return { isActive, pause, resume }
}
