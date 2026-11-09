import { describe, it, expect, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createTestingPinia } from '@pinia/testing'
import SignalKpiWidget from '~/components/dashboard/widgets/SignalKpiWidget.vue'
import RecentAlarmsWidget from '~/components/dashboard/widgets/RecentAlarmsWidget.vue'
import { GOLDEN_ALARM_GROUPS } from '../mocks/golden-data'

describe('DashboardWidgets', () => {
  beforeEach(() => {
    // no-op
  })

  it('SignalKpiWidget mounts without error', () => {
    const wrapper = mount(SignalKpiWidget, {
      global: {
        plugins: [
          createTestingPinia({
            stubActions: false,
            initialState: {
              dashboard: {
                kpis: { signal_color: 'success', anomaly_count: 0 },
              },
              dashboardLayout: {
                editMode: false,
                hidden: [],
              },
            },
          }),
        ],
      },
    })

    expect(wrapper.vm).toBeTruthy()
  })

  it('RecentAlarmsWidget renders list without error', () => {
    const wrapper = mount(RecentAlarmsWidget, {
      global: {
        plugins: [
          createTestingPinia({
            stubActions: false,
            initialState: {
              dashboard: {
                recentAlarms: [],
              },
              dashboardLayout: {
                editMode: false,
                hidden: [],
              },
            },
          }),
        ],
      },
    })

    expect(wrapper.text()).toContain('Recent Alarms')
  })

  it('RecentAlarmsWidget links each alarm to /alarms?group=<id> and keeps View All at /alarms', () => {
    const wrapper = mount(RecentAlarmsWidget, {
      global: {
        plugins: [
          createTestingPinia({
            stubActions: false,
            initialState: {
              dashboard: {
                recentAlarms: GOLDEN_ALARM_GROUPS,
              },
              dashboardLayout: {
                editMode: false,
                hidden: [],
              },
            },
          }),
        ],
      },
    })

    const alarmItems = wrapper.findAll('.alarm-item')
    expect(alarmItems.length).toBeGreaterThan(0)

    for (const item of alarmItems) {
      const to = item.attributes('to')
      expect(to).toMatch(/^\/alarms\?group=/)
    }

    // The first rendered alarm must point at its own group id, not the bare route.
    expect(alarmItems[0].attributes('to')).toBe(`/alarms?group=${GOLDEN_ALARM_GROUPS[0].id}`)

    // The "View All" button stays the plain /alarms route (no group query).
    const viewAllBtn = wrapper.find('q-btn')
    expect(viewAllBtn.attributes('to')).toBe('/alarms')
  })
})
