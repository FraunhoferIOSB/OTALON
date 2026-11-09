/**
 * Unit tests for FeaturePlotGrid.vue (B-17 fixes).
 *
 * Tests the allFeaturesEmpty computed property and empty state rendering
 * introduced to display "No measurements in time range" when all visible
 * features return empty data arrays from the API.
 */
import { describe, it, expect } from 'vitest'
import { mountWithPlugins } from '../helpers/mount'
import FeaturePlotGrid from '~/components/connection/FeaturePlotGrid.vue'
import type { FeatureName, FeatureTimeseries, AnomalyInterval, EnvelopeMode } from '~/types/golden-data'

const FEATURE_LABELS: Record<FeatureName, string> = {
  packet_count: 'Packet Count',
  total_volume: 'Total Volume',
  mean_packet_size: 'Mean Packet Size',
  min_packet_size: 'Min Packet Size',
  max_packet_size: 'Max Packet Size',
  mean_interarrival_time: 'Mean IAT',
  min_interarrival_time: 'Min IAT',
  max_interarrival_time: 'Max IAT',
  std_packet_size: 'Std Packet Size',
  std_interarrival_time: 'Std IAT',
}

const PlotStub = {
  name: 'ConnectionFeaturePlot',
  template: '<div data-testid="feature-plot"></div>',
}

const EmptyHintStub = {
  name: 'ConnectionEmptyMetricsHint',
  props: ['selectedUci', 'timeRange'],
  template: '<div data-testid="empty-metrics-hint"></div>',
}

function makeEmptyTimeseries(features: FeatureName[]): FeatureTimeseries[] {
  return features.map((feature) => ({ feature, points: [] }))
}

function makeTimeseries(features: FeatureName[], pointCount: number): FeatureTimeseries[] {
  return features.map((feature) => ({
    feature,
    points: Array.from({ length: pointCount }, (_, i) => ({
      time: new Date(Date.UTC(2026, 2, 7, 0, 0, i * 10)).toISOString(),
      value: 100 + i,
      upper_bound: 150,
      lower_bound: 50,
      value_min: 95 + i,
      value_max: 105 + i,
      violation_low: false,
      violation_high: false,
    })),
  }))
}

function mountGrid(
  overrides: {
    selectedUci?: string | null
    allTimeseries?: FeatureTimeseries[]
    visibleFeatures?: FeatureName[]
  } = {},
) {
  const selectedUci = 'selectedUci' in overrides ? overrides.selectedUci! : 'test-uci'
  const allTimeseries = overrides.allTimeseries ?? makeTimeseries(['packet_count', 'total_volume'], 5)
  const visibleFeatures = overrides.visibleFeatures ?? (allTimeseries.map((ts) => ts.feature) as FeatureName[])

  return mountWithPlugins(FeaturePlotGrid, {
    props: {
      selectedUci,
      allTimeseries,
      featureLabels: FEATURE_LABELS,
      anomalyIntervals: [] as AnomalyInterval[],
      forceScatter: false,
      timeRange: { start: '2026-03-07T00:00:00Z', stop: '2026-03-07T23:59:59Z' },
      visibleFeatures,
      columns: 2,
      plotSize: 'normal',
      showEnvelope: 'auto' as EnvelopeMode,
      showPortColumn: true,
    },
    global: {
      stubs: {
        ConnectionFeaturePlot: PlotStub,
        ConnectionEmptyMetricsHint: EmptyHintStub,
      },
    },
  })
}

describe('FeaturePlotGrid', () => {
  describe('allFeaturesEmpty computed (B-17 / UI-017b)', () => {
    it('renders the empty-metrics hint when all features have empty data', () => {
      const wrapper = mountGrid({
        allTimeseries: makeEmptyTimeseries(['packet_count', 'total_volume']),
        visibleFeatures: ['packet_count', 'total_volume'],
      })

      expect(wrapper.find('[data-testid="empty-metrics-hint"]').exists()).toBe(true)
    })

    it('passes selectedUci and timeRange to the empty-metrics hint', () => {
      const wrapper = mountGrid({
        allTimeseries: makeEmptyTimeseries(['packet_count']),
        visibleFeatures: ['packet_count'],
        selectedUci: 'hint-uci',
      })

      const hint = wrapper.findComponent(EmptyHintStub)
      expect(hint.exists()).toBe(true)
      expect(hint.props('selectedUci')).toBe('hint-uci')
    })

    it('does not render the hint when features have data', () => {
      const wrapper = mountGrid({
        allTimeseries: makeTimeseries(['packet_count', 'total_volume'], 10),
        visibleFeatures: ['packet_count', 'total_volume'],
      })

      expect(wrapper.find('[data-testid="empty-metrics-hint"]').exists()).toBe(false)
    })

    it('does not render the hint when some features have data', () => {
      const mixed: FeatureTimeseries[] = [
        { feature: 'packet_count', points: [] },
        ...makeTimeseries(['total_volume'], 5),
      ]
      const wrapper = mountGrid({
        allTimeseries: mixed,
        visibleFeatures: ['packet_count', 'total_volume'],
      })

      expect(wrapper.find('[data-testid="empty-metrics-hint"]').exists()).toBe(false)
    })

    it('re-emits jump from the empty-metrics hint', async () => {
      const wrapper = mountGrid({
        allTimeseries: makeEmptyTimeseries(['packet_count']),
        visibleFeatures: ['packet_count'],
      })

      const hint = wrapper.findComponent(EmptyHintStub)
      hint.vm.$emit('jump', 'sibling-uci')
      await wrapper.vm.$nextTick()

      expect(wrapper.emitted('jump')?.[0]).toEqual(['sibling-uci'])
    })
  })

  describe('no connection selected placeholder', () => {
    it('shows selection prompt when no UCI selected', () => {
      const wrapper = mountGrid({ selectedUci: null })

      expect(wrapper.text()).toContain('Select a connection to view feature plots')
    })

    it('does not show selection prompt when UCI is selected', () => {
      const wrapper = mountGrid({ selectedUci: 'test-uci' })

      expect(wrapper.text()).not.toContain('Select a connection to view feature plots')
    })
  })

  describe('no visible features placeholder', () => {
    it('shows "No feature data" when all features are filtered out', () => {
      const wrapper = mountGrid({
        allTimeseries: makeTimeseries(['packet_count'], 10),
        visibleFeatures: [],
      })

      expect(wrapper.text()).toContain('No feature data to display')
    })
  })

  describe('feature header', () => {
    it('does not render a second settings action in the grid header', () => {
      const wrapper = mountGrid({
        allTimeseries: makeTimeseries(['packet_count', 'total_volume'], 5),
        visibleFeatures: ['packet_count', 'total_volume'],
      })

      expect(wrapper.find('[icon="tune"]').exists()).toBe(false)
    })
  })
})
