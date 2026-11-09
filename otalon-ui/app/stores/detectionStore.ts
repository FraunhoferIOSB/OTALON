import { defineStore } from 'pinia'

import { useApi, type ApiError, type ApiErrorDetailObject } from '~/composables/useApi'
import { operationErrorMessage } from '~/utils/permissions'

export interface DetectionModule {
  module: string
  state: string
  detection_mode: string
  bounds_series_count: number
  no_bounds_count: number
  no_bounds_event_count?: number
  no_bounds_series_count?: number
  frequency_profile_count: number
  last_training: string | null
  schema_version: string
  schema_compatible: boolean
  classification_state?: string
  bounds_state?: string
  frequency_state?: string
}

export interface BoundReviewBounds {
  lower_bounds: Record<string, number | null>
  upper_bounds: Record<string, number | null>
}

export interface BoundReviewTimelineEvent {
  ts: string
  type: string
  features: string[]
}

export interface BoundReviewItem {
  module: string
  series_id: string
  series_display?: string | null
  available_features?: string[]
  feature: string | null
  state: string
  current_bounds: BoundReviewBounds
  lower: number | null
  upper: number | null
  violation_count: number
  last_event: string | null
  affected_features: string[]
  timeline: string[]
  ok: boolean
  timeline_events?: BoundReviewTimelineEvent[]
  latest_event_ts?: string | null
  latest_event_type?: string | null
  event_count?: number
  nobounds_count?: number
  has_bounds?: boolean
  last_trained_at?: string | null
}

export interface BoundsEnvelope {
  lower_bounds: Record<string, number | null>
  upper_bounds: Record<string, number | null>
}

export interface BoundsCorrectionPreview {
  preview_id?: string
  before: BoundsEnvelope
  after: BoundsEnvelope
  affected_features: string[]
  action: 'expand' | 'replace' | 'create'
  raw: Record<string, unknown>
}

export interface BoundSuggestionFeature {
  evidence_count: number
  lower_rationale: string
  upper_rationale: string
}

export interface BoundSuggestionResponse {
  module: string
  series_id: string
  action: 'expand' | 'replace' | 'create'
  status: 'available' | 'partial' | 'unavailable'
  window_from: string
  window_to: string
  evidence_count: number
  current: BoundsEnvelope
  proposed: BoundsEnvelope
  rationale: Record<string, BoundSuggestionFeature>
  message: string
}

/**
 * Strict, half-open ``[from, to)`` UTC event window used by Bound Review reads
 * and the feature chart. Both boundaries are ISO-8601 UTC strings (``Z``).
 */
export interface BoundReviewWindow {
  from?: string
  to?: string
}

function toEnvelope(value: unknown): BoundsEnvelope {
  const record = (value ?? {}) as Record<string, unknown>
  const lower = (record.lower_bounds ?? {}) as Record<string, number | null>
  const upper = (record.upper_bounds ?? {}) as Record<string, number | null>
  return { lower_bounds: { ...lower }, upper_bounds: { ...upper } }
}

export interface ArtifactManifestItem {
  artifact: string
  status: string
  [key: string]: unknown
}

export interface TimeseriesBoundPoint {
  time: string
  value: number | null
  value_min: number | null
  value_max: number | null
  lower_bound: number | null
  upper_bound: number | null
  violation_low: boolean
  violation_high: boolean
}

export type TimeRangeKey = '1h' | '6h' | '24h' | '7d' | 'All'

export interface TrainingInterval {
  start: string
  end: string
}

export interface LabelSource {
  filename: string
  worker_path: string
  size_bytes: number
  label_count: number
}

export interface LabelSourceList {
  items: LabelSource[]
  invalid_file_count: number
  warning: string | null
}

export type RetrainState = 'idle' | 'queued' | 'running' | 'publishing' | 'succeeded' | 'failed'

export interface RetrainStatus {
  state: RetrainState
  busy: boolean
  job_ref: string | null
  error: string | null
  scope?: 'bounds' | 'ml' | null
  window_start?: string | null
  window_stop?: string | null
  started_at?: string | null
  finished_at?: string | null
  intervals?: [string, string][]
}

export interface TrainingWindowStatus {
  state: RetrainState
  busy: boolean
  windowStart: string | null
  windowStop: string | null
  startedAt: string | null
  finishedAt: string | null
  intervals: [string, string][]
}

const TERMINAL_RETRAIN_STATES: ReadonlySet<RetrainState> = new Set<RetrainState>(['idle', 'succeeded', 'failed'])

const RANGE_HOURS: Record<TimeRangeKey, number | null> = {
  '1h': 1,
  '6h': 6,
  '24h': 24,
  '7d': 24 * 7,
  All: null,
}

export function rangeToSince(range: TimeRangeKey, now: number = Date.now()): string | undefined {
  const hours = RANGE_HOURS[range]
  if (hours === null) return undefined
  return new Date(now - hours * 3600000).toISOString()
}

export function rangeToWindow(range: TimeRangeKey, now: number = Date.now()): { start: string; stop: string } {
  const hours = RANGE_HOURS[range] ?? 24 * 30
  const stop = new Date(now)
  const start = new Date(now - hours * 3600000)
  const fmt = (d: Date): string => d.toISOString().slice(0, 19).replace('T', ' ')
  return { start: fmt(start), stop: fmt(stop) }
}

const labels: Record<string, string> = {
  conn: 'Connections',
  mac_traffic: 'Assets',
  proto_traffic: 'Protocols',
}

export function friendlyModuleLabel(module: string): string {
  return labels[module] ?? module
}

export function friendlyReadinessLabel(state: string): string {
  return state.replace('-', ' ')
}

export const useDetectionStore = defineStore('detection', {
  state: () => ({
    modules: [] as DetectionModule[],
    livePollIntervalSeconds: 5,
    bounds: [] as BoundReviewItem[],
    artifacts: [] as ArtifactManifestItem[],
    baselines: [] as Record<string, unknown>[],
    labelSources: [] as LabelSource[],
    labelSourceWarning: null as string | null,
    labelSourcesLoaded: false,
    loading: false,
    error: null as string | null,
    activeTrainingJob: null as { id: number; display_id: string } | null,
    trainingStatus: {
      bounds: null as TrainingWindowStatus | null,
      ml: null as TrainingWindowStatus | null,
    },
    lastCompletedTraining: {
      bounds: null as TrainingWindowStatus | null,
      ml: null as TrainingWindowStatus | null,
    },
    trainingError: null as string | null,
    retrainCooldownUntil: null as number | null,
    retrainCooldownTick: 0,
    boundsRequest: null as Promise<void> | null,
    boundsError: null as string | null,
    boundsSeq: 0,
  }),
  getters: {
    totalNoBounds: (state): number =>
      state.modules.reduce((total, item) => total + (item.no_bounds_series_count ?? item.no_bounds_count), 0),
    trainingBusy: (state): boolean => state.activeTrainingJob !== null,
    boundsTrainingStatus: (state): TrainingWindowStatus | null => state.trainingStatus.bounds,
    classifierTrainingStatus: (state): TrainingWindowStatus | null => state.trainingStatus.ml,
    lastBoundsTraining: (state): TrainingWindowStatus | null => state.lastCompletedTraining.bounds,
    lastClassifierTraining: (state): TrainingWindowStatus | null => state.lastCompletedTraining.ml,
    retrainCooldownRemainingSeconds: (state): number => {
      void state.retrainCooldownTick
      if (state.retrainCooldownUntil === null) return 0
      return Math.max(0, Math.ceil((state.retrainCooldownUntil - Date.now()) / 1000))
    },
    retrainCooldownActive(): boolean {
      return this.retrainCooldownRemainingSeconds > 0
    },
  },
  actions: {
    async refreshReadiness(): Promise<void> {
      const readiness = await useApi().get<{ modules: DetectionModule[]; live_poll_interval_seconds?: number }>(
        '/api/v1/operations/detection/readiness',
      )
      this.modules = readiness.modules
      this.livePollIntervalSeconds = readiness.live_poll_interval_seconds ?? 5
    },
    async load(boundParams: Record<string, unknown> = {}): Promise<void> {
      const api = useApi()
      this.loading = true
      this.error = null
      try {
        const [readiness, artifacts, baselines] = await Promise.all([
          api.get<{ modules: DetectionModule[]; live_poll_interval_seconds?: number }>(
            '/api/v1/operations/detection/readiness',
          ),
          api.get<{ items: ArtifactManifestItem[] }>('/api/v1/operations/detection/artifacts'),
          api.get<Record<string, unknown>[]>('/api/v1/baselines'),
          this.filterBounds(boundParams),
        ])
        this.modules = readiness.modules
        this.livePollIntervalSeconds = readiness.live_poll_interval_seconds ?? 5
        this.artifacts = artifacts.items
        this.baselines = baselines
        try {
          await this.loadLabelSources()
        } catch (error: unknown) {
          this.labelSourceWarning = error instanceof Error ? error.message : 'Label sources could not be loaded.'
        }
      } catch (error: unknown) {
        this.error = operationErrorMessage(error, 'Detection data could not be loaded')
      } finally {
        this.loading = false
      }
    },
    async loadLabelSources(): Promise<LabelSourceList> {
      const response = await useApi().get<LabelSourceList>('/api/v1/training/label-sources')
      const normalized: LabelSourceList = {
        items: Array.isArray(response.items) ? response.items : [],
        invalid_file_count: Number(response.invalid_file_count ?? 0),
        warning: typeof response.warning === 'string' ? response.warning : null,
      }
      this.labelSources = normalized.items
      this.labelSourceWarning = normalized.warning
      this.labelSourcesLoaded = true
      return normalized
    },
    async uploadLabelSource(filename: string, content: string): Promise<LabelSource> {
      const source = await useApi().post<LabelSource>('/api/v1/training/label-sources/upload', { filename, content })
      await this.loadLabelSources()
      return source
    },
    async filterBounds(params: Record<string, unknown>): Promise<void> {
      const seq = ++this.boundsSeq
      const clean: Record<string, unknown> = {}
      for (const [key, value] of Object.entries(params)) {
        if (value !== null && value !== undefined && value !== '') clean[key] = value
      }
      const request = useApi()
        .get<{ items: BoundReviewItem[] }>('/api/v1/operations/bounds', clean)
        .then((response) => {
          if (seq !== this.boundsSeq) return
          this.bounds = response.items
          this.boundsError = null
        })
        .catch((error: unknown) => {
          if (seq !== this.boundsSeq) return
          this.boundsError = (error as ApiError).message ?? 'Bound review could not be loaded'
        })
      this.boundsRequest = request
      try {
        await request
      } finally {
        if (this.boundsRequest === request) this.boundsRequest = null
      }
    },
    async previewBoundsCorrection(
      module: string,
      seriesId: string,
      action: 'expand' | 'replace' | 'create',
      before: BoundsEnvelope,
      after: BoundsEnvelope,
      reason: string,
    ): Promise<BoundsCorrectionPreview> {
      const response = await useApi().post<Record<string, unknown>>(
        `/api/v1/operations/bounds/${encodeURIComponent(encodeURIComponent(seriesId))}/correction/preview`,
        { module, series_id: seriesId, action, before, after, reason },
      )
      const prior = 'prior' in response ? response.prior : undefined
      const serverAfter: BoundsEnvelope = {
        lower_bounds: { ...((response.lower_bounds as Record<string, number | null>) ?? after.lower_bounds) },
        upper_bounds: { ...((response.upper_bounds as Record<string, number | null>) ?? after.upper_bounds) },
      }
      const normalizedBefore = prior ? toEnvelope(prior) : before
      const affected = Array.from(
        new Set([...Object.keys(serverAfter.lower_bounds), ...Object.keys(serverAfter.upper_bounds)]),
      ).sort()
      return {
        preview_id: typeof response.preview_id === 'string' ? response.preview_id : undefined,
        before: normalizedBefore,
        after: serverAfter,
        affected_features: affected,
        action,
        raw: response,
      }
    },
    async suggestBounds(
      module: string,
      seriesId: string,
      action: 'expand' | 'replace' | 'create',
      from: string,
      to: string,
    ): Promise<BoundSuggestionResponse> {
      return useApi().post<BoundSuggestionResponse>('/api/v1/operations/bounds/suggestion', {
        module,
        series_id: seriesId,
        action,
        from,
        to,
      })
    },
    async applyBoundsCorrection(
      module: string,
      seriesId: string,
      action: 'expand' | 'replace' | 'create',
      before: BoundsEnvelope,
      after: BoundsEnvelope,
      reason = '',
    ): Promise<unknown> {
      return useApi().post(
        `/api/v1/operations/bounds/${encodeURIComponent(encodeURIComponent(seriesId))}/correction/apply`,
        { module, series_id: seriesId, action, before, after, reason },
      )
    },
    async fetchSeriesTimeseries(
      module: string,
      series: string,
      feature: string,
      start: string,
      stop: string,
    ): Promise<TimeseriesBoundPoint[]> {
      const response = await useApi().get<{ data: TimeseriesBoundPoint[] }>('/api/v1/anomalies/bounds', {
        uci: series,
        metric: feature,
        module,
        start,
        stop,
      })
      return response.data ?? []
    },
    async startBoundsTraining(intervals: TrainingInterval[]): Promise<void> {
      validateIntervals(intervals)
      try {
        const response = await useApi().post<RetrainStatus>('/api/v1/training/retrain-boundaries', {
          window_start: intervals[0]?.start,
          window_stop: intervals[intervals.length - 1]?.end,
          intervals: intervals.map((interval) => [interval.start, interval.end]),
        })
        this.trainingError = null
        this.retrainCooldownUntil = null
        this.activeTrainingJob = { id: 0, display_id: response.job_ref ?? 'training' }
        this.recordRetrainStatus({ ...response, state: response.state ?? 'queued', busy: true, scope: 'bounds' })
      } catch (error: unknown) {
        this.captureRetrainError(error)
        throw error
      }
    },
    async startClassifierTraining(intervals: TrainingInterval[], mitreFile: string): Promise<void> {
      validateIntervals(intervals)
      try {
        const response = await useApi().post<RetrainStatus>('/api/v1/training/retrain-classifier', {
          window_start: intervals[0]?.start,
          window_stop: intervals[intervals.length - 1]?.end,
          intervals: intervals.map((interval) => [interval.start, interval.end]),
          mitre_file: mitreFile,
        })
        this.trainingError = null
        this.retrainCooldownUntil = null
        this.activeTrainingJob = { id: 0, display_id: response.job_ref ?? 'classifier-training' }
        this.recordRetrainStatus({ ...response, state: response.state ?? 'queued', busy: true, scope: 'ml' })
      } catch (error: unknown) {
        this.captureRetrainError(error)
        throw error
      }
    },
    captureRetrainError(error: unknown): void {
      const apiError = error as ApiError
      if (apiError.status !== 429) return
      const detail = apiError.detail as ApiErrorDetailObject | undefined
      const retryAfter = typeof detail?.retry_after === 'number' ? Math.max(1, Math.ceil(detail.retry_after)) : 1
      this.retrainCooldownUntil = Date.now() + retryAfter * 1000
      this.trainingError = `Cooldown aktiv, noch ${formatCooldownMinutes(retryAfter)} min`
    },
    advanceRetrainCooldown(): void {
      this.retrainCooldownTick += 1
      if (this.retrainCooldownRemainingSeconds === 0 && this.trainingError?.startsWith('Cooldown aktiv')) {
        this.retrainCooldownUntil = null
        this.trainingError = null
      }
    },
    async reconcileTrainingStatus(): Promise<void> {
      let status: RetrainStatus
      try {
        status = await useApi().get<RetrainStatus>('/api/v1/training/retrain-boundaries/status')
      } catch {
        return
      }
      this.recordRetrainStatus(status)
      if (this.activeTrainingJob === null || !TERMINAL_RETRAIN_STATES.has(status.state)) return
      this.trainingError = status.state === 'failed' ? (status.error ?? 'Training run failed') : null
      this.activeTrainingJob = null
    },
    recordRetrainStatus(status: RetrainStatus): void {
      const scope = status.scope ?? (this.activeTrainingJob ? 'bounds' : null)
      if (!scope) return
      const snapshot: TrainingWindowStatus = {
        state: status.state,
        busy: status.busy,
        windowStart: status.window_start ?? null,
        windowStop: status.window_stop ?? null,
        startedAt: status.started_at ?? null,
        finishedAt: status.finished_at ?? null,
        intervals: status.intervals ?? [],
      }
      this.trainingStatus[scope] = snapshot
      if (status.busy && this.activeTrainingJob === null) {
        this.activeTrainingJob = { id: 0, display_id: status.job_ref ?? 'training' }
      }
      if (status.state === 'succeeded' && snapshot.windowStart && snapshot.windowStop) {
        this.lastCompletedTraining[scope] = snapshot
      }
    },
    async createBaseline(name: string, startTs: string, endTs: string): Promise<void> {
      await useApi().post('/api/v1/baselines', { name, start_ts: startTs, end_ts: endTs })
      await this.load()
    },
  },
})

function validateIntervals(intervals: TrainingInterval[]): void {
  if (!intervals.length || intervals.some((item) => item.start >= item.end))
    throw new Error('Training intervals must have start before end')
  const ordered = [...intervals].sort((left, right) => left.start.localeCompare(right.start))
  if (ordered.some((item, index) => index > 0 && item.start < ordered[index - 1]!.end))
    throw new Error('Training intervals must not overlap')
}

function formatCooldownMinutes(seconds: number): number {
  return Math.max(1, Math.ceil(seconds / 60))
}
