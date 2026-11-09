/**
 * Component contract tests for the shared health-incident quick-preview drawer.
 *
 * The drawer renders backend-owned incident evidence only. These tests pin the
 * frozen hybrid contract: owning service + probe target facts, a bounded
 * ``latest N of total`` excerpt label, a primary ``Health evidence`` action
 * that deep-links to the System health tab, and a clearly secondary
 * ``Services & Logs`` action that deep-links to the owning system service.
 * Both actions must close the drawer (v-model -> false), and the close paths
 * (button + header close) emit the dismissal a parent uses for Escape.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'

import HealthIncidentDrawer from '~/components/operations/HealthIncidentDrawer.vue'
import type { HealthIncidentSummary } from '~/types/api'
import { mountWithPlugins } from '../helpers/mount'

const incident: HealthIncidentSummary = {
  id: '11111111-1111-1111-1111-111111111111',
  service: 'Network Traffic Recorder',
  owning_service: 'otalon-capture',
  probe_target: 'Network Traffic Recorder',
  system_service_id: 'otalon-capture',
  category: 'probe_timeout',
  cause: 'health probe timeout',
  status: 'active',
  first_seen: '2026-07-23T10:00:00Z',
  last_seen: '2026-07-23T10:05:00Z',
  recovered_at: null,
  sample_count: 6,
  failure_count: 5,
  latency_budget_ms: 3000,
  worst_latency_ms: 5010,
  evidence_type: 'operational_health',
  samples: [
    {
      service: 'Network Traffic Recorder',
      running: false,
      category: 'probe_timeout',
      cause: 'health probe timeout',
      latency_ms: 5010,
      latency_budget_ms: 3000,
      timestamp: '2026-07-23T10:05:00Z',
      detail: 'probe timeout after 5010 ms',
    },
  ],
}

function mountDrawer(overrides: Partial<HealthIncidentSummary> | null = {}) {
  return mountWithPlugins(HealthIncidentDrawer, {
    props: {
      modelValue: true,
      incident: overrides === null ? null : { ...incident, ...overrides },
    },
  })
}

describe('HealthIncidentDrawer', () => {
  beforeEach(() => {
    ;(globalThis as Record<string, unknown>).navigateTo = vi.fn(() => Promise.resolve())
  })

  it('renders backend-owned owning service and probe target facts', () => {
    const wrapper = mountDrawer()
    const text = wrapper.text()
    expect(text).toContain('Owning service')
    expect(text).toContain('otalon-capture')
    expect(text).toContain('Probe target')
    expect(text).toContain('Network Traffic Recorder')
  })

  it('labels the timeline as a bounded latest N of total excerpt', () => {
    const wrapper = mountDrawer({ sample_count: 42 })
    expect(wrapper.text()).toContain('latest 1 of 42 samples')
  })

  it('primary Health evidence deep-links to the System health tab and closes', async () => {
    const wrapper = mountDrawer()
    await wrapper.get('[data-test="incident-health-evidence"]').trigger('click')

    expect(globalThis.navigateTo).toHaveBeenCalledWith(
      expect.stringContaining('/operations/system?tab=health&incident='),
    )
    expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual([false])
  })

  it('secondary Services & Logs deep-links to the owning system service and closes', async () => {
    const wrapper = mountDrawer()
    await wrapper.get('[data-test="incident-services-logs"]').trigger('click')

    expect(globalThis.navigateTo).toHaveBeenCalledWith(expect.stringContaining('tab=services'))
    expect(globalThis.navigateTo).toHaveBeenCalledWith(expect.stringContaining('service=otalon-capture'))
    expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual([false])
  })

  it('emits dismissal from the header close control (Escape/backdrop parity)', async () => {
    const wrapper = mountDrawer()
    await wrapper.get('[aria-label="Close incident preview"]').trigger('click')
    expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual([false])
  })

  it('shows an empty state and does not navigate with no incident', async () => {
    const wrapper = mountDrawer(null)
    expect(wrapper.text()).toContain('No incident selected.')
    await wrapper.get('[data-test="incident-health-evidence"]').trigger('click')
    expect(globalThis.navigateTo).not.toHaveBeenCalled()
  })
})
