import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import TimeseriesChart from '~/components/shared/TimeseriesChart.vue'
import type { TimeseriesPoint } from '~/types/golden-data'
import { getChartEdgePaddingCount } from '~/utils/chartFraming'
import { mountWithPlugins } from '../helpers/mount'

const setOption = vi.fn()
const dispose = vi.fn()
const resize = vi.fn()
const init = vi.fn(() => ({ setOption, dispose, resize }))

vi.mock('echarts', () => ({ init }))
vi.mock('quasar', () => ({
  useQuasar: vi.fn(() => ({ dark: { isActive: false } })),
}))

interface ChartSeries {
  name: string
  type: string
  data: unknown[]
  symbolSize?: number
  showSymbol?: boolean
  z?: number
  lineStyle?: { width: number; color?: string }
  itemStyle?: { color: string; opacity?: number }
  emphasis?: { itemStyle?: { opacity?: number }; scale?: number }
  areaStyle?: unknown
}

interface ViolationDatum {
  value: [number, number]
  timestamp: string
  violationLow: boolean
  violationHigh: boolean
}

interface ChartOption {
  series: ChartSeries[]
  tooltip: {
    formatter: (params: unknown) => string
  }
  xAxis: { data: string[]; boundaryGap: boolean }
}

const data: TimeseriesPoint[] = [
  {
    time: '2026-07-22T00:00:00Z',
    value: 10,
    value_min: 10,
    value_max: 10,
    lower_bound: 5,
    upper_bound: 15,
    violation_low: false,
    violation_high: false,
  },
  {
    time: '2026-07-22T00:01:00Z',
    value: 4,
    value_min: 4,
    value_max: 4,
    lower_bound: 5,
    upper_bound: 15,
    violation_low: true,
    violation_high: false,
  },
  {
    time: '2026-07-22T00:02:00Z',
    value: 16,
    value_min: 16,
    value_max: 16,
    lower_bound: 5,
    upper_bound: 15,
    violation_low: false,
    violation_high: true,
  },
  {
    time: '2026-07-22T00:03:00Z',
    value: 20,
    value_min: 20,
    value_max: 20,
    lower_bound: 5,
    upper_bound: 15,
    violation_low: true,
    violation_high: true,
  },
]

function stubClientOnly() {
  return { template: '<slot />' }
}

describe('TimeseriesChart violation symbols', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('plots only flagged actual values and describes each violation in the tooltip', async () => {
    mountWithPlugins(TimeseriesChart, {
      props: {
        data,
        showBounds: true,
        showViolations: true,
      },
      global: {
        stubs: {
          ClientOnly: stubClientOnly(),
          QSpinnerDots: true,
        },
      },
    })
    await flushPromises()

    expect(setOption).toHaveBeenCalledTimes(1)
    const option = setOption.mock.calls[0]?.[0] as ChartOption
    const valueSeries = option.series.find((series) => series.name === 'Value')
    const lowerSeries = option.series.find((series) => series.name === 'Lower Bound')
    const upperSeries = option.series.find((series) => series.name === 'Upper Bound')
    const violationSeries = option.series.find((series) => series.name === 'Violations')

    expect(valueSeries).toMatchObject({
      type: 'line',
      data: [null, 10, 4, 16, 20, null],
      z: 12,
      lineStyle: { width: 2.5 },
    })
    expect(lowerSeries).toMatchObject({ type: 'line', data: [null, 5, 5, 5, 5, null] })
    expect(upperSeries).toMatchObject({ type: 'line', data: [null, 15, 15, 15, 15, null] })
    expect(upperSeries?.areaStyle).toBeDefined()
    expect(violationSeries).toMatchObject({
      type: 'scatter',
      symbolSize: 5,
      z: 6,
      itemStyle: { color: '#d32f2f', opacity: 0.48 },
      emphasis: { itemStyle: { opacity: 1 }, scale: 1.8 },
    })
    expect(valueSeries!.z).toBeGreaterThan(violationSeries!.z!)
    expect(violationSeries?.data).toEqual([
      { value: [2, 4], timestamp: '2026-07-22T00:01:00Z', violationLow: true, violationHigh: false },
      { value: [3, 16], timestamp: '2026-07-22T00:02:00Z', violationLow: false, violationHigh: true },
      { value: [4, 20], timestamp: '2026-07-22T00:03:00Z', violationLow: true, violationHigh: true },
    ])
    // The chart labels points in the viewer's local time (H:mm). Derive the
    // expectation from the same local-time contract so it holds in any TZ.
    const localLabel = (iso: string): string => {
      const date = new Date(iso)
      return `${date.getHours()}:${String(date.getMinutes()).padStart(2, '0')}`
    }
    expect(option.xAxis).toMatchObject({
      data: ['', ...data.map((point) => localLabel(point.time)), ''],
      boundaryGap: true,
    })

    const formatViolation = (datum: ViolationDatum): string =>
      option.tooltip.formatter([
        {
          axisValueLabel: String(datum.value[0]),
          seriesName: 'Violations',
          marker: '<marker>',
          value: datum.value,
          data: datum,
        },
      ])

    expect(formatViolation(violationSeries?.data[0] as ViolationDatum)).toContain('Lower bound violation')
    expect(formatViolation(violationSeries?.data[0] as ViolationDatum)).toContain('Actual value: 4')
    expect(formatViolation(violationSeries?.data[1] as ViolationDatum)).toContain('Upper bound violation')
    expect(formatViolation(violationSeries?.data[2] as ViolationDatum)).toContain('Lower and upper bound violation')
  })

  it('plots the violating extrema instead of an in-bound bucket mean', async () => {
    mountWithPlugins(TimeseriesChart, {
      props: {
        data: [{ ...data[0]!, value: 10, value_min: 2, value_max: 18, violation_low: true, violation_high: true }],
        showBounds: true,
        showViolations: true,
      },
      global: { stubs: { ClientOnly: stubClientOnly(), QSpinnerDots: true } },
    })
    await flushPromises()
    const option = setOption.mock.calls[0]?.[0] as ChartOption
    const violations = option.series.find((series) => series.name === 'Violations')
    expect(violations?.data).toEqual([
      { value: [1, 2], timestamp: '2026-07-22T00:00:00Z', violationLow: true, violationHigh: true },
    ])
  })

  it('shows sparse value markers but keeps dense series marker-free', async () => {
    mountWithPlugins(TimeseriesChart, {
      props: { data: [data[0]!] },
      global: { stubs: { ClientOnly: stubClientOnly(), QSpinnerDots: true } },
    })
    await flushPromises()
    const sparse = setOption.mock.calls[0]?.[0] as ChartOption
    expect(sparse.series.find((series) => series.name === 'Value')).toMatchObject({
      showSymbol: true,
      symbolSize: 7,
    })

    setOption.mockClear()
    const denseData = Array.from({ length: 100 }, (_, index) => ({ ...data[0]!, value: index }))
    mountWithPlugins(TimeseriesChart, {
      props: { data: denseData },
      global: { stubs: { ClientOnly: stubClientOnly(), QSpinnerDots: true } },
    })
    await flushPromises()
    const dense = setOption.mock.calls[0]?.[0] as ChartOption
    expect(dense.series.find((series) => series.name === 'Value')).toMatchObject({ showSymbol: false })
  })

  it('offsets capped edge violations into proportional empty categories', async () => {
    const largeData: TimeseriesPoint[] = Array.from({ length: 240 }, (_, index) => ({
      ...data[0]!,
      time: `2026-07-22T00:${String(index).padStart(2, '0')}:00Z`,
      value: index,
      value_min: index,
      value_max: index,
      violation_low: index === 0,
      violation_high: index === 239,
    }))
    mountWithPlugins(TimeseriesChart, {
      props: { data: largeData, showBounds: true, showViolations: true },
      global: { stubs: { ClientOnly: stubClientOnly(), QSpinnerDots: true } },
    })
    await flushPromises()

    const option = setOption.mock.calls[0]?.[0] as ChartOption
    const padding = getChartEdgePaddingCount(largeData.length)
    const violations = option.series.find((series) => series.name === 'Violations')?.data as ViolationDatum[]
    expect(padding).toBeGreaterThan(1)
    expect(option.xAxis.data).toHaveLength(largeData.length + padding * 2)
    expect(violations.map((item) => item.value[0])).toEqual([padding, largeData.length + padding - 1])
    expect(violations.map((item) => item.timestamp)).toEqual([largeData[0]!.time, largeData.at(-1)!.time])
  })
})
