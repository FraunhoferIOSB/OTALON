/**
 * Pinia store for timeseries plot data and feature configuration.
 *
 * Manages per-feature plot data (timeseries with bounds), anomaly
 * alarm intervals, available/visible features, and grid layout
 * settings for the connections page.
 *
 * Uses the Options API pattern so that `$reset()` works automatically.
 */
import { defineStore } from 'pinia'

import type {
  AlarmIntervalItem,
  AlarmIntervalsResponse,
  FeaturesResponse,
  TimeseriesWithBoundsItem,
  TimeseriesWithBoundsResponse,
} from '~/types/api'
import type { EnvelopeMode } from '~/types/golden-data'
import { DEFAULT_SAMPLE_MAX_POINTS } from '~/utils/plotSampling'

/**
 * Default-visible feature set for the connections page.
 *
 * These 6 features are shown on first load; the remaining 4
 * (mean/std variants) are available via Display Settings.
 */
export const CONNECTION_DEFAULT_FEATURES = [
  'packet_count',
  'total_volume',
  'min_packet_size',
  'max_packet_size',
  'min_interarrival_time',
  'max_interarrival_time',
] as const

/**
 * Shape of the timeseries store reactive state.
 */
/**
 * Monotonic token identifying the newest `fetchPlotData` call.
 *
 * Deliberately module-level rather than store state: it is request
 * bookkeeping, and putting it in reactive state would make every in-flight
 * request re-trigger watchers that depend on the store.
 */
let plotRequestSequence = 0

export interface TimeseriesState {
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
}

/**
 * Extract a human-readable error message from an unknown thrown value.
 *
 * Detects common network error patterns (connection refused, 502/503/504)
 * and returns a user-friendly message instead of raw HTTP details.
 *
 * @param error - The caught error value.
 * @returns A descriptive error message string.
 */
function extractErrorMessage(error: unknown): string {
  if (!error || typeof error !== 'object') {
    return 'An unknown error occurred'
  }
  const errObj = error as Record<string, unknown>
  const status = errObj.status ?? errObj.statusCode
  if (status === 502 || status === 503 || status === 504) {
    return 'Backend is unavailable — is otalon-api running on :8090?'
  }
  const msg = String(errObj.message ?? errObj.statusMessage ?? '')
  if (msg.includes('fetch failed') || msg.includes('ECONNREFUSED') || msg.includes('NetworkError')) {
    return 'Cannot reach backend — is otalon-api running on :8090?'
  }
  if (msg) return msg
  return 'An unknown error occurred'
}

export const useTimeseriesStore = defineStore('timeseries', {
  state: (): TimeseriesState => ({
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
  }),

  getters: {
    /**
     * Plot data filtered to only include currently visible features.
     *
     * @returns Record keyed by feature name, containing only visible features.
     */
    visiblePlotData(state): Record<string, TimeseriesWithBoundsItem[]> {
      const result: Record<string, TimeseriesWithBoundsItem[]> = {}
      for (const feature of state.visibleFeatures) {
        if (state.plotData[feature]) {
          result[feature] = state.plotData[feature]
        }
      }
      return result
    },

    /**
     * Number of features with loaded plot data.
     *
     * @returns Count of features in plotData.
     */
    loadedFeatureCount(state): number {
      return Object.keys(state.plotData).length
    },

    /**
     * Default visible features for the connections page.
     *
     * @returns Intersection of available features and the connection default set.
     */
    defaultVisibleFeatures(state): string[] {
      const defaults = state.availableFeatures.filter((f) =>
        (CONNECTION_DEFAULT_FEATURES as readonly string[]).includes(f),
      )
      return defaults.length > 0 ? defaults : [...state.availableFeatures]
    },
  },

  actions: {
    /**
     * Fetch the list of available feature names from the backend.
     *
     * Calls GET /api/v1/timeseries/features. On success, sets both
     * `availableFeatures` and `visibleFeatures` (all visible by default).
     */
    async fetchFeatures(): Promise<void> {
      try {
        const response = await $fetch<FeaturesResponse>('/api/v1/timeseries/features')
        this.availableFeatures = response.features
        if (this.visibleFeatures.length === 0) {
          const defaults = CONNECTION_DEFAULT_FEATURES.filter((f) => response.features.includes(f))
          this.visibleFeatures = defaults.length > 0 ? defaults : [...response.features]
        }
      } catch (error: unknown) {
        this.error = `Failed to fetch features: ${extractErrorMessage(error)}`
      }
    },

    /**
     * Fetch merged timeseries+bounds data for multiple features in parallel.
     *
     * Makes one API call per feature to GET /api/v1/anomalies/bounds.
     * Uses `Promise.allSettled` so that failure of one feature does not
     * block the others. Results are stored in `plotData` keyed by feature name.
     *
     * @param uci - The UCI to fetch data for.
     * @param features - Array of feature names to fetch.
     * @param start - ISO 8601 UTC start timestamp.
     * @param stop - ISO 8601 UTC stop timestamp.
     */
     async fetchPlotData(uci: string, features: string[], start: string, stop: string): Promise<void> {
      // Every in-flight request gets a monotonic token; only the newest may
      // write. Without this a slow earlier request (wider window, more
      // features) could resolve after a newer one and overwrite the plot
      // with data for a range the user already moved off (audit UI-08).
      const requestId = ++plotRequestSequence

      const results = await Promise.allSettled(
        features.map(async (feature) => {
          const response = await $fetch<TimeseriesWithBoundsResponse>('/api/v1/anomalies/bounds', {
            params: { uci, metric: feature, start, stop, sample_max_points: this.sampleMaxPoints },
          })
           return { feature, data: response.data as TimeseriesWithBoundsItem[], response }
        }),
      )

      // A newer request superseded this one while it was in flight: drop the
      // result rather than clobbering fresher data.
      if (requestId !== plotRequestSequence) return

      const newPlotData: Record<string, TimeseriesWithBoundsItem[]> = {}
      const errors: string[] = []
      let sampledPointCount = this.sampledPointCount
      let bucketSeconds = this.bucketSeconds

      for (const result of results) {
        if (result.status === 'fulfilled') {
          newPlotData[result.value.feature] = result.value.data
          sampledPointCount = result.value.response.row_count
          const bucket = result.value.response.parameters.bucket_seconds
          bucketSeconds = typeof bucket === 'number' ? bucket : null
        } else {
          errors.push(extractErrorMessage(result.reason))
        }
      }

      this.plotData = newPlotData
      this.sampledPointCount = sampledPointCount
      this.bucketSeconds = bucketSeconds
      this.error = errors.length > 0 ? `Failed to fetch some features: ${errors.join('; ')}` : null
    },

    /**
     * Fetch anomaly alarm intervals for a specific UCI.
     *
     * Calls GET /api/v1/anomalies/intervals with the given UCI and time range.
     *
     * @param uci - The UCI to fetch intervals for.
     * @param start - ISO 8601 UTC start timestamp.
     * @param stop - ISO 8601 UTC stop timestamp.
     */
    async fetchAnomalyIntervals(uci: string, start: string, stop: string): Promise<void> {
      try {
        const response = await $fetch<AlarmIntervalsResponse>('/api/v1/anomalies/intervals', {
          params: { uci, start, stop },
        })
        this.anomalyIntervals = response.data
      } catch (error: unknown) {
        this.error = `Failed to fetch anomaly intervals: ${extractErrorMessage(error)}`
      }
    },

    /**
     * Fetch all data for a UCI: plot data and anomaly intervals in parallel.
     *
     * Combines `fetchPlotData` and `fetchAnomalyIntervals` using
     * `Promise.allSettled` for resilient parallel loading.
     *
     * @param uci - The UCI to fetch all data for.
     * @param start - ISO 8601 UTC start timestamp.
     * @param stop - ISO 8601 UTC stop timestamp.
     */
    async fetchAllForUci(uci: string, start: string, stop: string): Promise<void> {
      this.isLoading = true
      this.error = null

      const features =
        this.availableFeatures.length > 0
          ? this.availableFeatures
          : [
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

      await Promise.allSettled([
        this.fetchPlotData(uci, features, start, stop),
        this.fetchAnomalyIntervals(uci, start, stop),
      ])

      if (this.visibleFeatures.length === 0 && this.availableFeatures.length === 0) {
        this.visibleFeatures = Object.keys(this.plotData)
      }

      this.isLoading = false
    },

    /**
     * Update the set of visible features.
     *
     * @param features - Array of feature names to make visible.
     */
    setVisibleFeatures(features: string[]): void {
      this.visibleFeatures = features
    },

    /**
     * Set the number of grid columns for the plot layout.
     *
     * @param columns - Number of columns (1, 2, 3, or 5).
     */
    setGridColumns(columns: number): void {
      this.gridColumns = columns
    },

    /**
     * Set the plot size preset.
     *
     * @param size - Size preset name ('compact', 'normal', or 'large').
     */
    setPlotSize(size: string): void {
      this.plotSize = size
    },

    /**
     * Set the envelope display mode.
     *
     * @param mode - Envelope mode: 'auto' (show when data has spread), 'on', or 'off'.
     */
    setShowEnvelope(mode: EnvelopeMode): void {
      this.showEnvelope = mode
    },

    setSampleMaxPoints(points: number): void {
      this.sampleMaxPoints = points
    },
  },
})
