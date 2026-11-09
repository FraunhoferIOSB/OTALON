/**
 * Component tests for the Network Throughput dashboard widget (UI-189).
 *
 * The widget caption used to be the hard-coded string "Last hour" while the
 * sparkline data followed the globally selected time range. These tests pin
 * the caption to the app store so a period change is reflected in the DOM.
 */
import { describe, it, expect, beforeEach } from 'vitest'

import ThroughputWidget from '~/components/dashboard/widgets/ThroughputWidget.vue'
import { useAppStore } from '~/stores/appStore'
import { useDashboardStore } from '~/stores/dashboardStore'
import { mountWithPlugins } from '../helpers/mount'

const STUBS = {
  DashboardThroughputSparkline: {
    name: 'DashboardThroughputSparkline',
    props: ['data'],
    template: '<div data-testid="throughput-sparkline" />',
  },
}

describe('ThroughputWidget range label', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('shows the selected live window instead of a static label', async () => {
    const wrapper = mountWithPlugins(ThroughputWidget, { global: { stubs: STUBS } })
    const appStore = useAppStore()
    appStore.setLiveMode(true)
    appStore.setLiveInterval(300)
    await wrapper.vm.$nextTick()

    const label = wrapper.find('[data-testid="throughput-range-label"]')
    expect(label.exists()).toBe(true)
    expect(label.text()).toBe('Last 5m')
  })

  it('updates the label after the live interval changes', async () => {
    const wrapper = mountWithPlugins(ThroughputWidget, { global: { stubs: STUBS } })
    const appStore = useAppStore()
    appStore.setLiveMode(true)
    appStore.setLiveInterval(300)
    await wrapper.vm.$nextTick()

    const label = wrapper.find('[data-testid="throughput-range-label"]')
    expect(label.text()).toBe('Last 5m')

    appStore.setLiveInterval(1800)
    await wrapper.vm.$nextTick()

    expect(wrapper.find('[data-testid="throughput-range-label"]').text()).toBe('Last 30m')
  })

  it('shows the applied history window when live mode is off', async () => {
    const wrapper = mountWithPlugins(ThroughputWidget, { global: { stubs: STUBS } })
    const appStore = useAppStore()
    appStore.setLiveMode(false)
    appStore.setTimeRange('2025-06-01T00:00:00Z', '2025-06-01T12:00:00Z')
    await wrapper.vm.$nextTick()

    const text = wrapper.find('[data-testid="throughput-range-label"]').text()
    expect(text).not.toBe('Last hour')
    expect(text).toContain(appStore.timeRangeLabel)
    expect(text).toContain('–')
  })

  it('never renders the former hard-coded caption', async () => {
    const wrapper = mountWithPlugins(ThroughputWidget, { global: { stubs: STUBS } })
    const appStore = useAppStore()
    appStore.setLiveMode(true)
    appStore.setLiveInterval(3600)
    await wrapper.vm.$nextTick()

    const dashboardStore = useDashboardStore()
    dashboardStore.throughput = []

    expect(wrapper.text()).not.toContain('Last hour')
  })
})
