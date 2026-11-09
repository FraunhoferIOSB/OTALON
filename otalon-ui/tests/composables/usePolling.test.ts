/**
 * Unit tests for the usePolling composable.
 *
 * Validates interval-based polling, pause/resume controls,
 * external enabled flag, document visibility integration,
 * and immediate execution behavior. Uses fake timers to
 * advance time deterministically without real delays.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { ref, computed, watch, nextTick, toRef } from 'vue'

vi.stubGlobal('ref', ref)
vi.stubGlobal('computed', computed)
vi.stubGlobal('watch', watch)
vi.stubGlobal('toRef', toRef)
vi.stubGlobal('onUnmounted', vi.fn())

const mockVisibility = ref<DocumentVisibilityState>('visible')

vi.mock('@vueuse/core', () => ({
  useDocumentVisibility: () => mockVisibility,
}))

const { usePolling } = await import('~/composables/usePolling')

describe('usePolling', () => {
  let pollFn: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.useFakeTimers()
    pollFn = vi.fn().mockResolvedValue(undefined)
    mockVisibility.value = 'visible'
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('calls function immediately when immediate option is true', () => {
    usePolling(pollFn, 5000, { immediate: true })

    expect(pollFn).toHaveBeenCalledTimes(1)
  })

  it('does not call function immediately when immediate option is false', () => {
    usePolling(pollFn, 5000, { immediate: false })

    expect(pollFn).not.toHaveBeenCalled()
  })

  it('does not call function immediately when immediate option is omitted', () => {
    usePolling(pollFn, 5000)

    expect(pollFn).not.toHaveBeenCalled()
  })

  it('calls function on each interval tick after prior work settles', async () => {
    usePolling(pollFn, 1000)

    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(1)
    await Promise.resolve()

    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(2)
    await Promise.resolve()

    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(3)
  })

  it('stops calling when paused', () => {
    const { pause } = usePolling(pollFn, 1000)

    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(1)

    pause()

    vi.advanceTimersByTime(3000)
    expect(pollFn).toHaveBeenCalledTimes(1)
  })

  it('resumes calling after pause once prior work settles', async () => {
    const { pause, resume } = usePolling(pollFn, 1000)

    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(1)
    await Promise.resolve()

    pause()
    vi.advanceTimersByTime(3000)
    expect(pollFn).toHaveBeenCalledTimes(1)

    resume()
    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(2)
  })

  it('stops calling when enabled ref is set to false', async () => {
    const enabled = ref(true)
    usePolling(pollFn, 1000, { enabled })

    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(1)

    enabled.value = false
    await nextTick()

    vi.advanceTimersByTime(3000)
    expect(pollFn).toHaveBeenCalledTimes(1)
  })

  it('resumes calling when enabled ref is set back to true', async () => {
    const enabled = ref(true)
    usePolling(pollFn, 1000, { enabled })

    enabled.value = false
    await nextTick()

    vi.advanceTimersByTime(3000)
    expect(pollFn).not.toHaveBeenCalled()

    enabled.value = true
    await nextTick()

    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(1)
  })

  it('isActive reflects true when polling is active', () => {
    const { isActive } = usePolling(pollFn, 1000)

    expect(isActive.value).toBe(true)
  })

  it('isActive reflects false when paused', () => {
    const { isActive, pause } = usePolling(pollFn, 1000)

    pause()
    expect(isActive.value).toBe(false)
  })

  it('isActive reflects false when enabled is false', () => {
    const enabled = ref(false)
    const { isActive } = usePolling(pollFn, 1000, { enabled })

    expect(isActive.value).toBe(false)
  })

  it('isActive reflects false when document is hidden', async () => {
    const { isActive } = usePolling(pollFn, 1000)

    expect(isActive.value).toBe(true)

    mockVisibility.value = 'hidden'
    await nextTick()

    expect(isActive.value).toBe(false)
  })

  it('stops polling when document becomes hidden', async () => {
    usePolling(pollFn, 1000)

    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(1)

    mockVisibility.value = 'hidden'
    await nextTick()

    vi.advanceTimersByTime(5000)
    expect(pollFn).toHaveBeenCalledTimes(1)
  })

  it('resumes polling when document becomes visible again', async () => {
    usePolling(pollFn, 1000)

    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(1)

    mockVisibility.value = 'hidden'
    await nextTick()
    vi.advanceTimersByTime(5000)

    mockVisibility.value = 'visible'
    await nextTick()

    vi.advanceTimersByTime(1000)
    expect(pollFn).toHaveBeenCalledTimes(2)
  })

  it('swallows a rejected callback and keeps polling on the next tick (B-F5)', async () => {
    const unhandled = vi.fn()
    process.on('unhandledRejection', unhandled)
    const rejecting = vi.fn().mockRejectedValue(new Error('poll failed'))
    usePolling(rejecting, 1000)

    vi.advanceTimersByTime(1000)
    expect(rejecting).toHaveBeenCalledTimes(1)
    // Let the rejected promise settle through .catch/.finally.
    await Promise.resolve()
    await Promise.resolve()

    // The in-flight guard was released, so the next tick fires again.
    vi.advanceTimersByTime(1000)
    expect(rejecting).toHaveBeenCalledTimes(2)
    await Promise.resolve()

    expect(unhandled).not.toHaveBeenCalled()
    process.off('unhandledRejection', unhandled)
  })
})
