import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { defineComponent, nextTick } from 'vue'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { overlapsRange, useDataExtent } from '~/composables/useDataExtent'
import { useAppStore } from '~/stores/appStore'

const getMock = vi.fn()
vi.mock('~/composables/useApi', () => ({ useApi: () => ({ get: getMock }) }))

interface ExtentPayload {
  has_data: boolean
  first_ts: string | null
  last_ts: string | null
}

function extent(first: string, last: string): ExtentPayload {
  return { has_data: true, first_ts: first, last_ts: last }
}

function mountHarness(): VueWrapper {
  return mount(
    defineComponent({
      setup() {
        return useDataExtent()
      },
      template: '<div />',
    }),
    { global: { plugins: [createPinia()] } },
  )
}

describe('overlapsRange', () => {
  it('treats an unparseable extent as overlapping so the banner stays hidden', () => {
    expect(overlapsRange('2026-09-02T20:00:00Z', '2026-09-02T21:00:00Z', 'garbage', 'also-bad')).toBe(true)
  })

  it('treats an empty/unparseable range as overlapping so no banner shows on a transient state', () => {
    expect(overlapsRange('', '', '2026-09-02T20:00:00Z', '2026-09-02T21:00:00Z')).toBe(true)
  })

  it('treats an inverted range (start > end) as overlapping instead of showing the banner', () => {
    expect(overlapsRange('2026-09-02T22:00:00Z', '2026-09-02T20:00:00Z', '2026-09-02T20:00:00Z', '2026-09-02T21:00:00Z')).toBe(
      true,
    )
  })

  it('returns true for a genuine overlap', () => {
    expect(overlapsRange('2026-09-02T20:30:00Z', '2026-09-02T20:45:00Z', '2026-09-02T20:00:00Z', '2026-09-02T21:00:00Z')).toBe(
      true,
    )
  })

  it('returns false for a genuine non-overlap', () => {
    expect(overlapsRange('2027-01-01T00:00:00Z', '2027-02-01T00:00:00Z', '2026-09-02T20:00:00Z', '2026-09-02T21:00:00Z')).toBe(
      false,
    )
  })
})

describe('useDataExtent', () => {
  let wrapper: VueWrapper | undefined

  beforeEach(() => {
    setActivePinia(createPinia())
    getMock.mockReset()
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-09-02T21:05:00Z'))
  })

  afterEach(async () => {
    await flushPromises()
    wrapper?.unmount()
    wrapper = undefined
    vi.useRealTimers()
  })

  it('reports current range as non-empty when it overlaps extent', async () => {
    getMock.mockResolvedValue(extent('2026-07-29T00:00:00Z', '2026-07-29T12:00:00Z'))

    wrapper = mountHarness()
    const store = useAppStore()
    store.setLiveMode(false)
    store.setTimeRange('2026-07-29T08:00:00Z', '2026-07-29T09:00:00Z')
    await wrapper.vm.refresh()
    await flushPromises()

    expect(wrapper.vm.isCurrentRangeEmpty).toBe(false)
  })

  it('reports current range as empty outside known extent and refreshes safely', async () => {
    getMock.mockResolvedValue(extent('2026-07-29T00:00:00Z', '2026-07-29T12:00:00Z'))

    wrapper = mountHarness()
    const store = useAppStore()
    store.setLiveMode(false)
    store.setTimeRange('2024-01-01T00:00:00Z', '2024-01-01T01:00:00Z')
    await wrapper.vm.refresh()
    await flushPromises()
    expect(wrapper.vm.isCurrentRangeEmpty).toBe(true)

    getMock.mockRejectedValue(new Error('offline'))
    await wrapper.vm.refresh()
    await nextTick()
    expect(wrapper.vm.isCurrentRangeEmpty).toBe(false)
  })

  it('does not show the banner for an unparseable data extent', async () => {
    getMock.mockResolvedValue({ has_data: true, first_ts: 'not-a-date', last_ts: 'also-bad' })

    wrapper = mountHarness()
    const store = useAppStore()
    store.setLiveMode(false)
    store.setTimeRange('2026-09-02T20:00:00Z', '2026-09-02T21:00:00Z')
    await wrapper.vm.refresh()
    await flushPromises()

    expect(wrapper.vm.isCurrentRangeEmpty).toBe(false)
  })

  it('shows the banner for a genuinely non-overlapping live window', async () => {
    // Extent ends well before the live window -> no overlap.
    getMock.mockResolvedValue(extent('2026-09-02T18:00:00Z', '2026-09-02T18:30:00Z'))

    wrapper = mountHarness()
    const store = useAppStore()
    store.setLiveMode(true)
    store.setLiveInterval(300) // window [21:00, 21:05]
    await wrapper.vm.refresh()
    await flushPromises()

    expect(wrapper.vm.isCurrentRangeEmpty).toBe(true)
  })

  it('clears the sticky empty banner after a live<->history toggle once the extent refreshes', async () => {
    // Initial extent is old: live window [21:00, 21:05] does NOT overlap -> banner shows.
    getMock.mockResolvedValue(extent('2026-09-02T20:00:00Z', '2026-09-02T20:10:00Z'))

    wrapper = mountHarness()
    const store = useAppStore()
    store.setLiveMode(true)
    store.setLiveInterval(300)
    await wrapper.vm.refresh()
    await flushPromises()
    expect(wrapper.vm.isCurrentRangeEmpty).toBe(true)

    // Data has since moved into a history range we now select.
    getMock.mockResolvedValue(extent('2026-09-02T20:30:00Z', '2026-09-02T21:10:00Z'))
    store.setLiveMode(false)
    store.setTimeRange('2026-09-02T21:00:00Z', '2026-09-02T21:05:00Z')
    await flushPromises()

    // History range overlaps the refreshed extent -> banner clears.
    expect(wrapper.vm.isCurrentRangeEmpty).toBe(false)
  })

  it('clears the sticky empty banner when the live interval changes and the extent refreshes', async () => {
    // Old extent: live window [21:00, 21:05] does NOT overlap -> banner shows.
    getMock.mockResolvedValue(extent('2026-09-02T20:00:00Z', '2026-09-02T20:10:00Z'))

    wrapper = mountHarness()
    const store = useAppStore()
    store.setLiveMode(true)
    store.setLiveInterval(300)
    await wrapper.vm.refresh()
    await flushPromises()
    expect(wrapper.vm.isCurrentRangeEmpty).toBe(true)

    // Data moved into the live window.
    getMock.mockResolvedValue(extent('2026-09-02T21:00:00Z', '2026-09-02T21:10:00Z'))
    // A meaningful window change triggers a refresh.
    store.setLiveInterval(600) // window [20:55, 21:05]
    await flushPromises()

    // Refreshed extent overlaps the live window -> banner clears.
    expect(wrapper.vm.isCurrentRangeEmpty).toBe(false)
  })

  it('refreshes the data extent when the effective time range changes', async () => {
    getMock.mockResolvedValue(extent('2026-09-02T20:00:00Z', '2026-09-02T21:00:00Z'))

    wrapper = mountHarness()
    const store = useAppStore()
    store.setLiveMode(false)
    store.setTimeRange('2026-09-02T20:00:00Z', '2026-09-02T21:00:00Z')
    await wrapper.vm.refresh()
    await flushPromises()
    expect(getMock).toHaveBeenCalledTimes(1)

    store.setLiveMode(true)
    await flushPromises()
    expect(getMock).toHaveBeenCalledTimes(2)

    store.setLiveInterval(600)
    await flushPromises()
    expect(getMock).toHaveBeenCalledTimes(3)

    store.setLiveMode(false)
    store.setTimeRange('2026-09-02T20:30:00Z', '2026-09-02T21:00:00Z')
    await flushPromises()
    expect(getMock).toHaveBeenCalledTimes(4)
  })

  it('does not spam the endpoint when refresh is called while a request is in flight', async () => {
    let resolveFetch: (value: ExtentPayload) => void = () => {}
    getMock.mockReturnValue(
      new Promise<ExtentPayload>((resolve) => {
        resolveFetch = resolve
      }),
    )

    wrapper = mountHarness()
    // Fire three refreshes without awaiting: the in-flight guard must coalesce
    // them into a single network call.
    const pending = wrapper.vm.refresh()
    void wrapper.vm.refresh()
    void wrapper.vm.refresh()
    expect(getMock).toHaveBeenCalledTimes(1)

    resolveFetch(extent('2026-09-02T20:00:00Z', '2026-09-02T21:00:00Z'))
    await pending
    await flushPromises()
    expect(getMock).toHaveBeenCalledTimes(1)
  })
})
