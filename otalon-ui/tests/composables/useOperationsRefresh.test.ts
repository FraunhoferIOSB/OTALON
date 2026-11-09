import { mount } from '@vue/test-utils'
import { defineComponent, h, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { describe, expect, it, vi } from 'vitest'

import { OPERATIONS_HEAVY_POLL_INTERVAL_MS, useOperationsRefresh } from '~/composables/useOperationsRefresh'

describe('useOperationsRefresh', () => {
  it('registers on mount and unregisters on unmount', async () => {
    const header = useOperationsRefresh()
    const callback = vi.fn().mockResolvedValue(undefined)
    const Page = defineComponent({
      setup() {
        const refresh = useOperationsRefresh()
        onMounted(() => refresh.register(callback, false))
        onUnmounted(refresh.unregister)
        return () => h('div')
      },
    })

    const wrapper = mount(Page)
    await nextTick()
    expect(header.isAvailable.value).toBe(true)

    wrapper.unmount()
    expect(header.isAvailable.value).toBe(false)
  })

  it('deduplicates concurrent initial, polling, and header refresh calls', async () => {
    const page = useOperationsRefresh()
    const header = useOperationsRefresh()
    let resolveRequest: (() => void) | undefined
    const callback = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveRequest = resolve
        }),
    )
    page.register(callback, false)

    const initial = page.refresh()
    const polling = page.refresh()
    const manual = header.refresh()

    expect(callback).toHaveBeenCalledTimes(1)
    expect(page.isLoading.value).toBe(true)
    resolveRequest?.()
    await Promise.all([initial, polling, manual])
    expect(page.isLoading.value).toBe(false)
    page.unregister()
  })

  it('combines registered loading state with shared in-flight state', async () => {
    const page = useOperationsRefresh()
    const header = useOperationsRefresh()
    const loading = ref(true)
    page.register(vi.fn().mockResolvedValue(undefined), loading)

    expect(header.isAvailable.value).toBe(true)
    expect(header.isLoading.value).toBe(true)
    loading.value = false
    await nextTick()
    expect(header.isLoading.value).toBe(false)
    page.unregister()
  })

  it('keeps the next route active when the previous unregisters and its request resolves last', async () => {
    const previousPage = useOperationsRefresh()
    const nextPage = useOperationsRefresh()
    let resolvePrevious: (() => void) | undefined
    const previousCallback = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolvePrevious = resolve
        }),
    )
    const nextLoading = ref(true)
    const nextCallback = vi.fn().mockResolvedValue(undefined)

    // Real route transition order: previous registers + starts a slow request,
    // then unregisters, then the next route registers and loads.
    previousPage.register(previousCallback, false)
    const previousRequest = previousPage.refresh()
    previousPage.unregister()
    nextPage.register(nextCallback, () => nextLoading.value)
    const nextRequest = nextPage.refresh()

    expect(previousCallback).toHaveBeenCalledOnce()
    expect(nextCallback).toHaveBeenCalledOnce()
    // Next route is the active owner and reports loading via its own flag.
    expect(nextPage.isAvailable.value).toBe(true)
    expect(nextPage.isLoading.value).toBe(true)

    // The stale previous request resolves last — it must not clear the next
    // route's in-flight/loading state or unregister the active callback.
    resolvePrevious?.()
    await previousRequest
    expect(nextPage.isAvailable.value).toBe(true)
    expect(nextPage.isLoading.value).toBe(true)

    await nextRequest
    nextLoading.value = false
    await nextTick()
    expect(nextPage.isLoading.value).toBe(false)
    nextPage.unregister()
  })

  it('does not let an earlier route request suppress the next route initial load', async () => {
    const previousPage = useOperationsRefresh()
    const nextPage = useOperationsRefresh()
    let resolvePrevious: (() => void) | undefined
    const previousCallback = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolvePrevious = resolve
        }),
    )
    const nextCallback = vi.fn().mockResolvedValue(undefined)

    previousPage.register(previousCallback, false)
    const previousRequest = previousPage.refresh()
    nextPage.register(nextCallback, false)
    await nextPage.refresh()

    expect(previousCallback).toHaveBeenCalledOnce()
    expect(nextCallback).toHaveBeenCalledOnce()
    resolvePrevious?.()
    await previousRequest
    nextPage.unregister()
  })

  it('consumes a rejected refresh callback without an unhandled rejection', async () => {
    const page = useOperationsRefresh()
    const rejection = vi.fn().mockRejectedValue(new Error('boom'))
    const unhandled = vi.fn()
    process.on('unhandledRejection', unhandled)
    page.register(rejection, false)

    // refresh() resolves (never rejects) even though the callback rejected.
    await expect(page.refresh()).resolves.toBeUndefined()
    // Loading is released so the header spinner does not get stuck.
    expect(page.isLoading.value).toBe(false)
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(unhandled).not.toHaveBeenCalled()
    process.off('unhandledRejection', unhandled)
    page.unregister()
  })

  it('uses the documented 30 second heavy polling cadence', () => {
    expect(OPERATIONS_HEAVY_POLL_INTERVAL_MS).toBe(30_000)
  })
})
