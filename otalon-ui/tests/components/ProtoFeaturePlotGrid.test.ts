/**
 * Unit tests for ProtoFeaturePlotGrid.vue.
 *
 * Verifies anomaly interval forwarding to child plot components (UI-038).
 */
import { describe, it, expect } from 'vitest'
import { mountWithPlugins } from '../helpers/mount'
import ProtoFeaturePlotGrid from '~/components/proto/ProtoFeaturePlotGrid.vue'
import type { FeatureName, FeatureTimeseries, AnomalyInterval, EnvelopeMode } from '~/types/golden-data'

const FEATURE_LABELS: Record<FeatureName, string> = {
  proto_total_packets: 'Total Packets',
  proto_total_volume: 'Total Volume',
}

const PlotStub = {
  name: 'ConnectionFeaturePlot',
  props: ['title', 'data', 'anomalyIntervals', 'forceScatter', 'timeRange', 'showEnvelope'],
  template: '<div data-testid="feature-plot">{{ title }}</div>',
}

const SettingsStub = {
  name: 'ProtoFeaturePlotSettings',
  props: ['featureNames', 'featureLabels', 'visibleFeatures'],
  template: '<div data-testid="settings"></div>',
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
    selectedProtoId?: string | null
    allTimeseries?: FeatureTimeseries[]
    anomalyIntervals?: AnomalyInterval[]
  } = {},
) {
  return mountWithPlugins(ProtoFeaturePlotGrid, {
    props: {
      selectedProtoId: 'selectedProtoId' in overrides ? overrides.selectedProtoId! : 'test-proto',
      selectedProtoLabel: 'Test Protocol',
      allTimeseries: overrides.allTimeseries ?? makeTimeseries(['proto_total_packets', 'proto_total_volume'], 5),
      featureLabels: FEATURE_LABELS,
      anomalyIntervals: overrides.anomalyIntervals ?? [],
      forceScatter: false,
      timeRange: { start: '2026-03-07T00:00:00Z', stop: '2026-03-07T23:59:59Z' },
      visibleFeatures: Object.keys(FEATURE_LABELS) as FeatureName[],
      columns: 2,
      plotSize: 'normal',
      showEnvelope: 'auto' as EnvelopeMode,
      showIdColumn: false,
    },
    global: {
      stubs: {
        ProtoFeaturePlotSettings: SettingsStub,
        ConnectionFeaturePlot: PlotStub,
      },
    },
  })
}

describe('ProtoFeaturePlotGrid', () => {
  describe('anomaly interval forwarding (UI-038)', () => {
    it('passes anomalyIntervals to each ConnectionFeaturePlot', () => {
      const intervals: AnomalyInterval[] = [{ start: '2026-03-07T02:00:00Z', end: '2026-03-07T05:00:00Z' }]
      const wrapper = mountGrid({ anomalyIntervals: intervals })

      const plots = wrapper.findAllComponents(PlotStub)
      expect(plots.length).toBe(2)
      for (const plot of plots) {
        expect(plot.props('anomalyIntervals')).toEqual(intervals)
      }
    })

    it('passes empty anomalyIntervals when none provided', () => {
      const wrapper = mountGrid({ anomalyIntervals: [] })

      const plots = wrapper.findAllComponents(PlotStub)
      expect(plots.length).toBeGreaterThan(0)
      for (const plot of plots) {
        expect(plot.props('anomalyIntervals')).toEqual([])
      }
    })

    it('does not render plots when no protocol is selected', () => {
      const wrapper = mountGrid({ selectedProtoId: null })

      const plots = wrapper.findAllComponents(PlotStub)
      expect(plots.length).toBe(0)
      expect(wrapper.text()).toContain('Select a protocol to view feature plots')
    })
  })
})
