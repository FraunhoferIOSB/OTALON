/**
 * Pinia store for MAC timeseries plot data and feature configuration.
 *
 * Mirrors `useTimeseriesStore` but uses the MAC-specific endpoints:
 * - /api/v1/timeseries/mac/features
 * - /api/v1/anomalies/mac/bounds
 * - /api/v1/anomalies/mac/intervals
 */
import { defineStore } from 'pinia'

import type {
  AlarmIntervalItem,
  AlarmIntervalsResponse,
  FeaturesResponse,
  TimeseriesWithBoundsItem,
  TimeseriesWithBoundsResponse,
  FrequencyProfileListResponse,
} from '~/types/api'
import type { EnvelopeMode } from '~/types/golden-data'
import { DEFAULT_SAMPLE_MAX_POINTS } from '~/utils/plotSampling'

/**
 * Default-visible feature set for the MAC timeseries page.
 */
export const MAC_DEFAULT_FEATURES = [
  'out_total_packets',
  'out_total_volume',
  'in_total_packets',
  'in_total_volume',
  'total_conn_count',
] as const

export interface MacTimeseriesState {
  plotData: Record<string, TimeseriesWithBoundsItem[]>
  anomalyIntervals: AlarmIntervalItem[]
  availableFeatures: string[]
  visibleFeatures: string[]
  visibleTableColumns: string[]
  isLoading: boolean
  error: string | null
  gridColumns: number
  plotSize: string
  showEnvelope: EnvelopeMode
  sampleMaxPoints: number
  sampledPointCount: number
  bucketSeconds: number | null
  profiledMacs: string[]
  liveMacs: string[]
  showSilentProfiled: boolean
}

function extractErrorMessage(error: unknown): string {
  if (!error || typeof error !== 'object') return 'An unknown error occurred'
  const errObj = error as Record<string, unknown>
  const status = errObj.status ?? errObj.statusCode
  if (status === 502 || status === 503 || status === 504) {
    return 'Backend is unavailable — is otalon-api running on :8090?'
  }
  const msg = String(errObj.message ?? errObj.statusMessage ?? '')
  if (msg.includes('fetch failed') || msg.includes('ECONNREFUSED') || msg.includes('NetworkError')) {
    return 'Cannot reach backend — is otalon-api running on :8090?'
  }
  return msg || 'An unknown error occurred'
}

export const useMacTimeseriesStore = defineStore('macTimeseries', {
  state: (): MacTimeseriesState => ({
    plotData: {},
    anomalyIntervals: [],
    availableFeatures: [],
    visibleFeatures: [],
    visibleTableColumns: ['state', 'name', 'ip', 'mac'],
    isLoading: false,
    error: null,
    gridColumns: 1,
    plotSize: 'normal',
    showEnvelope: 'auto',
    sampleMaxPoints: DEFAULT_SAMPLE_MAX_POINTS,
    sampledPointCount: 0,
    bucketSeconds: null,
    profiledMacs: [],
    liveMacs: [],
    showSilentProfiled: false,
  }),

  getters: {
    visiblePlotData(state): Record<string, TimeseriesWithBoundsItem[]> {
      const result: Record<string, TimeseriesWithBoundsItem[]> = {}
      for (const feature of state.visibleFeatures) {
        if (state.plotData[feature]) {
          result[feature] = state.plotData[feature]
        }
      }
      return result
    },

    loadedFeatureCount(state): number {
      return Object.keys(state.plotData).length
    },

    defaultVisibleFeatures(state): string[] {
      const defaults = state.availableFeatures.filter((f) =>
        MAC_DEFAULT_FEATURES.includes(f as (typeof MAC_DEFAULT_FEATURES)[number]),
      )
      return defaults.length > 0 ? defaults : [...state.availableFeatures]
    },

    silentProfiledCount(state): number {
      const live = new Set(state.liveMacs)
      return state.profiledMacs.filter((mac) => !live.has(mac)).length
    },

    selectableMacs(state): string[] {
      if (!state.showSilentProfiled) return state.liveMacs
      const live = new Set(state.liveMacs)
      return [...state.liveMacs, ...state.profiledMacs.filter((mac) => !live.has(mac))]
    },
  },

  actions: {
    /**
     * Fetch the list of available MAC feature names from the backend.
     */
    async fetchFeatures(): Promise<void> {
      try {
        const response = await $fetch<FeaturesResponse>('/api/v1/timeseries/mac/features')
        this.availableFeatures = response.features
        if (this.visibleFeatures.length === 0) {
          const defaults = response.features.filter((f) =>
            MAC_DEFAULT_FEATURES.includes(f as (typeof MAC_DEFAULT_FEATURES)[number]),
          )
          this.visibleFeatures = defaults.length > 0 ? defaults : [...response.features]
        }
      } catch (error: unknown) {
        this.error = `Failed to fetch MAC features: ${extractErrorMessage(error)}`
      }
    },

    async fetchProfiledMacs(): Promise<void> {
      try {
        const response = await $fetch<FrequencyProfileListResponse>('/api/v1/frequency/profiles', {
          params: { module: 'mac_traffic' },
        })
        this.profiledMacs = response.data.filter((p) => p.has_profile).map((p) => p.series_id)
      } catch {
        this.profiledMacs = []
      }
    },

    setLiveMacs(macs: string[]): void {
    this.liveMacs = macs
    },

    setShowSilentProfiled(show: boolean): void {
      this.showSilentProfiled = show
    },

    /**
     * Fetch merged timeseries+bounds data for multiple MAC features in parallel.
     *
     * @param mac - The MAC address to fetch data for.
     * @param features - Array of feature names to fetch.
     * @param start - ISO 8601 UTC start timestamp.
     * @param stop - ISO 8601 UTC stop timestamp.
     */
    async fetchPlotData(mac: string, features: string[], start: string, stop: string): Promise<void> {
      const results = await Promise.allSettled(
        features.map(async (feature) => {
          const response = await $fetch<TimeseriesWithBoundsResponse>('/api/v1/anomalies/mac/bounds', {
            params: { series_id: mac, metric: feature, start, stop, sample_max_points: this.sampleMaxPoints },
          })
           return { feature, data: response.data as TimeseriesWithBoundsItem[], response }
        }),
      )

      const newPlotData: Record<string, TimeseriesWithBoundsItem[]> = {}
      const errors: string[] = []

      for (const result of results) {
        if (result.status === 'fulfilled') {
          newPlotData[result.value.feature] = result.value.data
          this.sampledPointCount = result.value.response.row_count
          const bucket = result.value.response.parameters.bucket_seconds
          this.bucketSeconds = typeof bucket === 'number' ? bucket : null
        } else {
          errors.push(extractErrorMessage(result.reason))
        }
      }

      this.plotData = newPlotData

      if (errors.length > 0) {
        this.error = `Failed to fetch some MAC features: ${errors.join('; ')}`
      }
    },

    /**
     * Fetch anomaly alarm intervals for a specific MAC address.
     */
    async fetchAnomalyIntervals(mac: string, start: string, stop: string): Promise<void> {
      try {
        const response = await $fetch<AlarmIntervalsResponse>('/api/v1/anomalies/mac/intervals', {
          params: { series_id: mac, start, stop },
        })
        this.anomalyIntervals = response.data
      } catch (error: unknown) {
        this.error = `Failed to fetch MAC anomaly intervals: ${extractErrorMessage(error)}`
      }
    },

    setSampleMaxPoints(points: number): void {
      this.sampleMaxPoints = points
    },

    /**
     * Fetch all data for a MAC: plot data and anomaly intervals in parallel.
     */
    async fetchAllForMac(mac: string, start: string, stop: string): Promise<void> {
      this.isLoading = true
      this.error = null

      const features =
        this.availableFeatures.length > 0
          ? this.availableFeatures
          : [
              'out_conn_count',
              'out_total_packets',
              'out_total_volume',
              'out_unique_dst_count',
              'out_unique_proto_count',
              'in_conn_count',
              'in_total_packets',
              'in_total_volume',
              'in_unique_src_count',
              'ratio_in_out_packets',
              'ratio_in_out_volume',
              'total_unique_peers',
              'total_conn_count',
            ]

      await Promise.allSettled([
        this.fetchPlotData(mac, features, start, stop),
        this.fetchAnomalyIntervals(mac, start, stop),
      ])

      if (this.visibleFeatures.length === 0 && this.availableFeatures.length === 0) {
        this.visibleFeatures = Object.keys(this.plotData)
      }

      this.isLoading = false
    },

    setVisibleFeatures(features: string[]): void {
      this.visibleFeatures = features
    },

    setGridColumns(columns: number): void {
      this.gridColumns = columns
    },

    setPlotSize(size: string): void {
      this.plotSize = size
    },

    setVisibleTableColumns(columns: string[]): void {
      this.visibleTableColumns = columns
    },

    setShowEnvelope(mode: EnvelopeMode): void {
      this.showEnvelope = mode
    },
  },
})
