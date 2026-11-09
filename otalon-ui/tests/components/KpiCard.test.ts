/**
 * Component tests for the KpiCard shared component.
 *
 * Validates rendering of value, label, icon, signal dot, trend indicators,
 * color tinting, and click navigation using golden data (GD-09).
 */
import { describe, it, expect } from 'vitest'

import KpiCard from '~/components/shared/KpiCard.vue'
import { GOLDEN_KPI } from '../mocks/golden-data'
import { mountWithPlugins } from '../helpers/mount'

describe('KpiCard', () => {
  it('renders the label text', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 42, label: 'Anomalies' },
    })

    expect(wrapper.text()).toContain('Anomalies')
  })

  it('renders a number value with locale formatting', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: GOLDEN_KPI.anomaly_count, label: 'Anomalies' },
    })

    const formatted = GOLDEN_KPI.anomaly_count.toLocaleString()
    expect(wrapper.text()).toContain(formatted)
  })

  it('renders a string value as-is', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 'N/A', label: 'Status' },
    })

    expect(wrapper.text()).toContain('N/A')
  })

  it('does not render redundant signal dot with danger status', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: {
        value: GOLDEN_KPI.anomaly_count,
        label: 'Anomalies',
        signalColor: 'danger' as const,
      },
    })

    const dot = wrapper.find('.kpi-card__signal-dot')
    expect(dot.exists()).toBe(false)
  })

  it('does not render redundant signal dot with success status', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 0, label: 'Anomalies', signalColor: 'success' as const },
    })

    const dot = wrapper.find('.kpi-card__signal-dot')
    expect(dot.exists()).toBe(false)
  })

  it('does not render redundant signal dot with warning status', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 5, label: 'Devices', signalColor: 'warning' as const },
    })

    const dot = wrapper.find('.kpi-card__signal-dot')
    expect(dot.exists()).toBe(false)
  })

  it('does not render signal dot when signalColor is not provided', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 10, label: 'Connections' },
    })

    expect(wrapper.find('.kpi-card__signal-dot').exists()).toBe(false)
  })

  it('renders the icon', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 42, label: 'Anomalies', icon: 'warning' },
    })

    const icon = wrapper.find('.kpi-card__icon')
    expect(icon.exists()).toBe(true)
  })

  it('renders trend arrow up with trend label', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: {
        value: 200,
        label: 'Anomalies',
        trend: 'up' as const,
        trendLabel: '+12%',
      },
    })

    const trendEl = wrapper.find('.kpi-card__trend')
    expect(trendEl.exists()).toBe(true)
    expect(trendEl.text()).toContain('↑')
    expect(trendEl.text()).toContain('+12%')
  })

  it('renders trend arrow down', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 100, label: 'Anomalies', trend: 'down' as const },
    })

    const trendEl = wrapper.find('.kpi-card__trend')
    expect(trendEl.text()).toContain('↓')
  })

  it('renders trend arrow stable', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 50, label: 'Devices', trend: 'stable' as const },
    })

    const trendEl = wrapper.find('.kpi-card__trend')
    expect(trendEl.text()).toContain('→')
  })

  it('applies positive trend color when trend matches trendPositive', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: {
        value: 100,
        label: 'Anomalies',
        trend: 'down' as const,
        trendPositive: 'down' as const,
      },
    })

    const trendEl = wrapper.find('.kpi-card__trend')
    expect(trendEl.classes()).toContain('text-positive')
  })

  it('applies negative trend color when trend does not match trendPositive', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: {
        value: 200,
        label: 'Anomalies',
        trend: 'up' as const,
        trendPositive: 'down' as const,
      },
    })

    const trendEl = wrapper.find('.kpi-card__trend')
    expect(trendEl.classes()).toContain('text-negative')
  })

  it('applies tint-danger class when signalColor is danger', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: {
        value: GOLDEN_KPI.anomaly_count,
        label: 'Anomalies',
        signalColor: GOLDEN_KPI.signal_color as 'danger',
      },
    })

    expect(wrapper.find('.kpi-card').classes()).toContain('kpi-card--tint-danger')
  })

  it('applies tint-warning class when signalColor is warning', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 5, label: 'Devices', signalColor: 'warning' as const },
    })

    expect(wrapper.find('.kpi-card').classes()).toContain('kpi-card--tint-warning')
  })

  it('applies clickable class when to prop is provided', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 42, label: 'Anomalies', to: '/alarms' },
    })

    expect(wrapper.find('.kpi-card').classes()).toContain('kpi-card--clickable')
  })

  it('does not apply clickable class when to is not provided', () => {
    const wrapper = mountWithPlugins(KpiCard, {
      props: { value: 42, label: 'Anomalies' },
    })

    expect(wrapper.find('.kpi-card').classes()).not.toContain('kpi-card--clickable')
  })
})
