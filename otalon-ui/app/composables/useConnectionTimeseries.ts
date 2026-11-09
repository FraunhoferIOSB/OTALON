/**
 * Composable for generating mock feature timeseries data per connection.
 *
 * Provides deterministic pseudo-random timeseries data with bounds for
 * all 10 netcap features. Uses a seeded generator so the same UCI always
 * produces identical data across renders.
 *
 * Also provides mock anomaly intervals for connections in anomaly state.
 */

import type { FeatureName, FeatureTimeseriesPoint, FeatureTimeseries, AnomalyInterval } from '~/types/golden-data'

const FEATURE_NAMES: FeatureName[] = [
  'packet_count',
  'total_volume',
  'mean_packet_size',
  'min_packet_size',
  'max_packet_size',
  'mean_interarrival_time',
  'min_interarrival_time',
  'max_interarrival_time',
  'std_packet_size',
  'std_interarrival_time',
]

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

interface FeatureRange {
  base: number
  amplitude: number
  noise: number
}

const FEATURE_RANGES: Record<FeatureName, FeatureRange> = {
  packet_count: { base: 125, amplitude: 40, noise: 15 },
  total_volume: { base: 50000, amplitude: 30000, noise: 5000 },
  mean_packet_size: { base: 400, amplitude: 200, noise: 50 },
  min_packet_size: { base: 64, amplitude: 20, noise: 8 },
  max_packet_size: { base: 1200, amplitude: 300, noise: 80 },
  mean_interarrival_time: { base: 0.01, amplitude: 0.005, noise: 0.002 },
  min_interarrival_time: { base: 0.001, amplitude: 0.0005, noise: 0.0002 },
  max_interarrival_time: { base: 0.08, amplitude: 0.03, noise: 0.01 },
  std_packet_size: { base: 50, amplitude: 25, noise: 10 },
  std_interarrival_time: { base: 0.005, amplitude: 0.002, noise: 0.001 },
}

const NUM_POINTS = 80
const TIME_SPAN_MS = 24 * 60 * 60 * 1000

/**
 * UCIs that have anomaly state in gd01-connections with their mock intervals.
 *
 * Intervals are placed within the 24h timeseries window starting at 2026-03-06T21:00Z.
 */
const ANOMALY_UCI_INTERVALS: Record<string, AnomalyInterval[]> = {
  'L2_00:1B:1B:F8:3A:02_00:1B:1B:F8:3A:03_PROFINET_RT': [
    {
      start: '2026-03-07T02:00:00Z',
      end: '2026-03-07T05:00:00Z',
      label: 'T0802',
    },
    {
      start: '2026-03-07T14:00:00Z',
      end: '2026-03-07T16:30:00Z',
      label: 'T0830',
    },
  ],
  'IP_192.168.1.20_224.0.0.251_5353_mDNS': [
    {
      start: '2026-03-07T06:00:00Z',
      end: '2026-03-07T08:30:00Z',
      label: 'T0802',
    },
  ],
  'L2_00:1B:1B:F8:3A:03_FF:FF:FF:FF:FF:FF_ARP': [
    {
      start: '2026-03-07T09:00:00Z',
      end: '2026-03-07T12:00:00Z',
      label: 'T0830',
    },
    {
      start: '2026-03-07T17:00:00Z',
      end: '2026-03-07T19:00:00Z',
      label: 'T0814',
    },
  ],
}

function hashString(str: string): number {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash + char) | 0
  }
  return Math.abs(hash)
}

function seededRandom(seed: number): () => number {
  let s = seed % 2147483647
  if (s <= 0) s += 2147483646
  return () => {
    s = (s * 16807) % 2147483647
    return (s - 1) / 2147483646
  }
}

function generateFeaturePoints(uci: string, feature: FeatureName, startTime: Date): FeatureTimeseriesPoint[] {
  const seed = hashString(`${uci}:${feature}`)
  const rand = seededRandom(seed)
  const range = FEATURE_RANGES[feature]
  const interval = TIME_SPAN_MS / NUM_POINTS
  const phaseShift = rand() * Math.PI * 2
  const anomalyIndices = new Set<number>()

  anomalyIndices.add(Math.floor(rand() * NUM_POINTS))
  anomalyIndices.add(Math.floor(rand() * NUM_POINTS))

  const points: FeatureTimeseriesPoint[] = []

  for (let i = 0; i < NUM_POINTS; i++) {
    const t = new Date(startTime.getTime() + i * interval)
    const sinComponent = Math.sin((2 * Math.PI * i) / NUM_POINTS + phaseShift)
    const noiseComponent = (rand() - 0.5) * 2 * range.noise
    let value = range.base + sinComponent * range.amplitude + noiseComponent

    if (anomalyIndices.has(i)) {
      value = range.base + range.amplitude * 1.8 + range.noise * 2
    }

    value = Math.max(0, value)

    const boundMargin = range.amplitude * 0.3 + range.noise
    const lower_bound = Math.max(0, range.base - range.amplitude - boundMargin)
    const upper_bound = range.base + range.amplitude + boundMargin

    points.push({
      time: t.toISOString(),
      value: Number(value.toPrecision(6)),
      upper_bound: Number(upper_bound.toPrecision(6)),
      lower_bound: Number(lower_bound.toPrecision(6)),
    })
  }

  return points
}

/**
 * Provide feature timeseries generation for connections.
 *
 * @returns Helper functions and constants for connection timeseries data.
 */
export function useConnectionTimeseries() {
  const startTime = new Date('2026-03-06T21:00:00Z')

  function getFeatureTimeseries(uci: string, feature: FeatureName): FeatureTimeseries {
    return {
      feature,
      points: generateFeaturePoints(uci, feature, startTime),
    }
  }

  function getAllFeatureTimeseries(uci: string): FeatureTimeseries[] {
    return FEATURE_NAMES.map((feature) => getFeatureTimeseries(uci, feature))
  }

  function getAnomalyIntervals(uci: string): AnomalyInterval[] {
    return ANOMALY_UCI_INTERVALS[uci] ?? []
  }

  return {
    featureNames: FEATURE_NAMES,
    featureLabels: FEATURE_LABELS,
    getFeatureTimeseries,
    getAllFeatureTimeseries,
    getAnomalyIntervals,
  }
}
