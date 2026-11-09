/**
 * Pinia store for Protocol timeseries plot data and feature configuration.
 *
 * Mirrors `useMacTimeseriesStore` but uses the protocol-specific endpoints:
 * - /api/v1/timeseries/proto/features
 * - /api/v1/anomalies/proto/bounds
 * - /api/v1/anomalies/proto/intervals
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
import { protoComparisonKey } from '~/utils/protoHash'

/**
 * Default-visible feature set for the protocol timeseries page.
 */
export const PROTO_DEFAULT_FEATURES = [
  'proto_total_packets',
  'proto_total_volume',
  'proto_conn_count',
  'proto_mean_packet_size',
  'proto_unique_mac_pairs',
] as const

export interface ProtoTimeseriesState {
  plotData: Record<string, TimeseriesWithBoundsItem[]>
  anomalyIntervals: AlarmIntervalItem[]
  availableFeatures: string[]
  visibleFeatures: string[]
  isLoading: boolean
  error: string | null
  gridColumns: number
  plotSize: string
  showEnvelope: EnvelopeMode
  sampleMaxPoints: number
  sampledPointCount: number
  bucketSeconds: number | null
  profiledProtocols: string[]
  liveProtocols: string[]
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

export const useProtoTimeseriesStore = defineStore('protoTimeseries', {
  state: (): ProtoTimeseriesState => ({
    plotData: {},
    anomalyIntervals: [],
    availableFeatures: [],
    visibleFeatures: [],
    isLoading: false,
    error: null,
    gridColumns: 1,
    plotSize: 'normal',
    showEnvelope: 'auto',
    sampleMaxPoints: DEFAULT_SAMPLE_MAX_POINTS,
    sampledPointCount: 0,
    bucketSeconds: null,
    profiledProtocols: [],
    liveProtocols: [],
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
        PROTO_DEFAULT_FEATURES.includes(f as (typeof PROTO_DEFAULT_FEATURES)[number]),
      )
      return defaults.length > 0 ? defaults : [...state.availableFeatures]
    },

    silentProfiledCount(state): number {
      const live = new Set(state.liveProtocols.map((id) => protoComparisonKey(id, state.liveProtocols)))
      return state.profiledProtocols.filter((id) => !live.has(protoComparisonKey(id, state.liveProtocols))).length
    },

    selectableProtocols(state): string[] {
      if (!state.showSilentProfiled) return state.liveProtocols
      const live = new Set(state.liveProtocols.map((id) => protoComparisonKey(id, state.liveProtocols)))
      return [
        ...state.liveProtocols,
        ...state.profiledProtocols.filter((id) => !live.has(protoComparisonKey(id, state.liveProtocols))),
      ]
    },
  },

  actions: {
    /**
     * Fetch the list of available protocol feature names from the backend.
     */
    async fetchFeatures(): Promise<void> {
      try {
        const response = await $fetch<FeaturesResponse>('/api/v1/timeseries/proto/features')
        this.availableFeatures = response.features
        if (this.visibleFeatures.length === 0) {
          const defaults = response.features.filter((f) =>
            PROTO_DEFAULT_FEATURES.includes(f as (typeof PROTO_DEFAULT_FEATURES)[number]),
          )
          this.visibleFeatures = defaults.length > 0 ? defaults : [...response.features]
        }
      } catch (error: unknown) {
        this.error = `Failed to fetch protocol features: ${extractErrorMessage(error)}`
      }
    },

    async fetchProfiledProtocols(): Promise<void> {
      try {
        const response = await $fetch<FrequencyProfileListResponse>('/api/v1/frequency/profiles', {
          params: { module: 'proto_traffic' },
        })
        this.profiledProtocols = response.data.filter((p) => p.has_profile).map((p) => p.series_id)
      } catch {
        this.profiledProtocols = []
      }
    },

    setLiveProtocols(ids: string[]): void {
      this.liveProtocols = ids
    },

    setShowSilentProfiled(show: boolean): void {
      this.showSilentProfiled = show
    },

    /**
     * Fetch merged timeseries+bounds data for multiple protocol features in parallel.
     *
     * @param seriesId - The protocol series id to fetch data for.
     * @param features - Array of feature names to fetch.
     * @param start - ISO 8601 UTC start timestamp.
     * @param stop - ISO 8601 UTC stop timestamp.
     */
    async fetchPlotData(seriesId: string, features: string[], start: string, stop: string): Promise<void> {
      const results = await Promise.allSettled(
        features.map(async (feature) => {
          const response = await $fetch<TimeseriesWithBoundsResponse>('/api/v1/anomalies/proto/bounds', {
            params: { series_id: seriesId, metric: feature, start, stop, sample_max_points: this.sampleMaxPoints },
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
        this.error = `Failed to fetch some protocol features: ${errors.join('; ')}`
      }
    },

    /**
     * Fetch anomaly alarm intervals for a specific protocol series.
     */
    async fetchAnomalyIntervals(seriesId: string, start: string, stop: string): Promise<void> {
      try {
        const response = await $fetch<AlarmIntervalsResponse>('/api/v1/anomalies/proto/intervals', {
          params: { series_id: seriesId, start, stop },
        })
        this.anomalyIntervals = response.data
      } catch (error: unknown) {
        this.error = `Failed to fetch protocol anomaly intervals: ${extractErrorMessage(error)}`
      }
    },

    setSampleMaxPoints(points: number): void {
      this.sampleMaxPoints = points
    },

    /**
     * Fetch all data for a protocol: plot data and anomaly intervals in parallel.
     */
    async fetchAllForProto(seriesId: string, start: string, stop: string): Promise<void> {
      this.isLoading = true
      this.error = null

      const features =
        this.availableFeatures.length > 0
          ? this.availableFeatures
          : [
              'proto_conn_count',
              'proto_total_packets',
              'proto_total_volume',
              'proto_unique_src_mac',
              'proto_unique_dst_mac',
              'proto_unique_mac_pairs',
              'proto_mean_packets_per_conn',
              'proto_mean_volume_per_conn',
              'proto_mean_packet_size',
              'proto_std_packet_size',
            ]

      await Promise.allSettled([
        this.fetchPlotData(seriesId, features, start, stop),
        this.fetchAnomalyIntervals(seriesId, start, stop),
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

    setShowEnvelope(mode: EnvelopeMode): void {
      this.showEnvelope = mode
    },
  },
})
