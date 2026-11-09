import { describe, expect, it, vi, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import { useAppStore } from '~/stores/appStore'
import TimeToolbar from '~/components/shared/TimeToolbar.vue'
import { mountWithPlugins } from '../helpers/mount'

const refreshMock = vi.fn()
const extentState = {
  firstTs: ref('2026-07-29T00:00:00Z'),
  lastTs: ref('2026-07-29T12:00:00Z'),
  isCurrentRangeEmpty: ref(false),
}

vi.mock('~/composables/useDataExtent', () => ({
  useDataExtent: () => ({ ...extentState, refresh: refreshMock, hasData: { value: true }, isLoading: { value: false } }),
}))

describe('TimeToolbar data extent hint', () => {
  beforeEach(() => {
    extentState.isCurrentRangeEmpty.value = false
    refreshMock.mockReset()
  })

  it('hides hint when current range overlaps data', () => {
    const wrapper = mountWithPlugins(TimeToolbar)
    expect(wrapper.find('[data-testid="data-extent-hint"]').exists()).toBe(false)
  })

  it('shows hint for an empty current range', async () => {
    extentState.isCurrentRangeEmpty.value = true
    const wrapper = mountWithPlugins(TimeToolbar)
    await flushPromises()
    expect(wrapper.find('[data-testid="data-extent-hint"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('No data in the selected range')
    expect(wrapper.text()).toContain('Use available range')
  })

  it('sets history range and emits update when button is clicked', async () => {
    extentState.isCurrentRangeEmpty.value = true
    const wrapper = mountWithPlugins(TimeToolbar)
    await wrapper.find('[data-testid="show-data-extent"]').trigger('click')
    const store = useAppStore()
    expect(store.liveMode).toBe(false)
    expect(store.timeRange).toEqual({ start: extentState.firstTs.value, end: extentState.lastTs.value })
    expect(wrapper.emitted('update')).toBeTruthy()
  })
})
