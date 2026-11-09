import { describe, expect, it, vi } from 'vitest'

import PanelSubjectHeading from '~/components/shared/PanelSubjectHeading.vue'
import { mountWithPlugins } from '../helpers/mount'

describe('PanelSubjectHeading', () => {
  it('renders Rhythm badge independently from affected feature badges', () => {
    const wrapper = mountWithPlugins(PanelSubjectHeading, {
      props: {
        label: 'series-rhythm',
        noun: 'connection',
        affectedFeatures: ['packet_count'],
        rhythmAnomaly: true,
      },
    })

    expect(wrapper.get('[data-testid="rhythm-anomaly-badge"]').text()).toContain('Cadence')
    expect(wrapper.get('[data-testid="rhythm-anomaly-badge"]').text()).not.toContain('Rhythm')
    expect(wrapper.get('[data-testid="affected-features"]').text()).toContain('packet_count')
  })

  it('does not render Rhythm badge for plain bound violations', () => {
    const wrapper = mountWithPlugins(PanelSubjectHeading, {
      props: {
        label: 'series-bound',
        noun: 'connection',
        affectedFeatures: ['packet_count'],
      },
    })

    expect(wrapper.find('[data-testid="rhythm-anomaly-badge"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="affected-features"]').text()).toContain('packet_count')
  })

  it('renders mapped feature showname in affected feature badges', () => {
    const wrapper = mountWithPlugins(PanelSubjectHeading, {
      props: {
        label: 'series-bound',
        noun: 'connection',
        affectedFeatures: ['std_interarrival_time'],
        featureLabels: { std_interarrival_time: 'Std IAT' },
      },
    })

    expect(wrapper.get('[data-testid="affected-features"]').text()).toContain('Std IAT')
    expect(wrapper.get('[data-testid="affected-features"]').text()).not.toContain('std_interarrival_time')
  })

  it('renders one red NoBounds badge without per-feature badges', () => {
    const wrapper = mountWithPlugins(PanelSubjectHeading, {
      props: {
        label: 'series-unprofiled',
        noun: 'connection',
        affectedFeatureState: 'NoBounds',
        affectedFeatures: ['packet_count', 'total_volume'],
      },
    })

    expect(wrapper.findAll('[data-testid="no-bounds-badge"]')).toHaveLength(1)
    expect(wrapper.get('[data-testid="no-bounds-badge"]').text()).toBe('NoBounds')
    expect(wrapper.findAll('[data-feature-badge]').length).toBe(0)
  })

  it('keeps mapped feature badges for BoundViolation state', () => {
    const wrapper = mountWithPlugins(PanelSubjectHeading, {
      props: {
        label: 'series-bound',
        noun: 'connection',
        affectedFeatureState: 'BoundViolation',
        affectedFeatures: ['std_interarrival_time'],
        featureLabels: { std_interarrival_time: 'Std IAT' },
      },
    })

    expect(wrapper.find('[data-testid="no-bounds-badge"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-feature-badge]')).toHaveLength(1)
    expect(wrapper.get('[data-testid="affected-features"]').text()).toContain('Std IAT')
  })

  it('falls back to raw feature key when showname is unmapped', () => {
    const wrapper = mountWithPlugins(PanelSubjectHeading, {
      props: {
        label: 'series-bound',
        noun: 'connection',
        affectedFeatures: ['unknown_feature'],
        featureLabels: { packet_count: 'Packet Count' },
      },
    })

    expect(wrapper.get('[data-testid="affected-features"]').text()).toContain('unknown_feature')
  })

  it('reveals hidden feature before scrolling to its plot cell', async () => {
    const scrollIntoView = vi.fn()
    const cell = document.createElement('div')
    cell.className = 'plot-cell'
    cell.dataset.feature = 'std_interarrival_time'
    cell.scrollIntoView = scrollIntoView
    document.body.append(cell)
    const wrapper = mountWithPlugins(PanelSubjectHeading, {
      props: {
        label: 'series-bound',
        noun: 'connection',
        affectedFeatures: ['std_interarrival_time'],
        visibleFeatures: [],
      },
    })

    await wrapper.get('[data-feature-badge="std_interarrival_time"]').trigger('click')

    expect(wrapper.emitted('reveal-feature')).toEqual([['std_interarrival_time']])
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'nearest' })
    cell.remove()
  })

  it('scrolls visible feature without emitting a reveal request', async () => {
    const scrollIntoView = vi.fn()
    const cell = document.createElement('div')
    cell.className = 'plot-cell'
    cell.dataset.feature = 'packet_count'
    cell.scrollIntoView = scrollIntoView
    document.body.append(cell)
    const wrapper = mountWithPlugins(PanelSubjectHeading, {
      props: {
        label: 'series-bound',
        noun: 'connection',
        affectedFeatures: ['packet_count'],
        visibleFeatures: ['packet_count'],
      },
    })

    await wrapper.get('[data-feature-badge="packet_count"]').trigger('click')

    expect(wrapper.emitted('reveal-feature')).toBeUndefined()
    expect(scrollIntoView).toHaveBeenCalledTimes(1)
    cell.remove()
  })
})
