import type { OperationsJob } from '~/types/api'

export interface JobDetailField {
  label: string
  value: string
}

export interface JobLogEntry {
  timestamp: string
  phase: string
  message: string
  metrics: JobDetailField[]
}

const FRIENDLY_LABELS: Record<string, string> = {
  actor: 'Actor',
  end_ts: 'End time',
  end_time: 'End time',
  format: 'Format',
  intervals: 'Intervals',
  module: 'Module',
  modules: 'Modules',
  start_ts: 'Start time',
  start_time: 'Start time',
  window_start: 'Window start',
  window_stop: 'Window stop',
}

const SECRET_KEY = /token|secret|password|api[_-]?key|credential/i

function labelFor(key: string): string {
  return FRIENDLY_LABELS[key] ?? key.replace(/[_-]+/g, ' ').replace(/\b\w/g, (character) => character.toUpperCase())
}

function formatDate(value: unknown): string {
  if (typeof value !== 'string' || !value) return String(value ?? 'Not provided')
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

/**
 * Parse a raw log timestamp into epoch milliseconds for chronological sorting.
 *
 * Accepts ISO strings and numeric epochs (ms or seconds). Returns `null` for
 * missing or unparseable values so the caller can order them deterministically
 * by original arrival index rather than by a locale-formatted display string.
 */
function timestampEpoch(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    // Heuristic: values below ~1e12 are second-precision epochs.
    return value < 1_000_000_000_000 ? value * 1000 : value
  }
  if (typeof value === 'string' && value) {
    const parsed = new Date(value).getTime()
    return Number.isNaN(parsed) ? null : parsed
  }
  return null
}

function formatValue(value: unknown, key = ''): string {
  if (SECRET_KEY.test(key)) return '[redacted]'
  if (value === null || value === undefined || value === '') return 'Not provided'
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'Not provided'
  if (typeof value === 'string') {
    return /(^|_)(at|date|time|ts)$/.test(key) ? formatDate(value) : value
  }
  if (Array.isArray(value)) return value.map((item) => formatValue(item)).join(', ')
  if (typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>)
      .filter(([entryKey]) => !SECRET_KEY.test(entryKey))
      .map(([entryKey, entryValue]) => `${labelFor(entryKey)}: ${formatValue(entryValue, entryKey)}`)
      .join('; ')
  }
  return String(value)
}

function intervalValue(value: unknown): string {
  if (!Array.isArray(value)) return formatValue(value, 'intervals')
  return value
    .map((interval) => {
      if (!Array.isArray(interval) || interval.length < 2) return formatValue(interval)
      return `${formatDate(interval[0])} to ${formatDate(interval[1])}`
    })
    .join('; ')
}

export function formatJobParams(params: Record<string, unknown>): JobDetailField[] {
  return Object.entries(params).map(([key, value]) => ({
    label: labelFor(key),
    value: key === 'intervals' ? intervalValue(value) : formatValue(value, key),
  }))
}

export function formatJobMetadata(job: OperationsJob): JobDetailField[] {
  return [
    ['ID', job.display_id],
    ['Type', job.type],
    ['Trigger', job.trigger],
    ['Actor', job.actor],
    ['Started', job.started_at],
    ['Ended', job.ended_at],
    ['Result', job.result],
    ['Error', job.error],
  ].map(([label, value]) => ({ label, value: formatValue(value, label) }))
}

/**
 * A log entry augmented with the chronological sort keys used internally by
 * {@link formatJobLog}. The keys never leak into the public rendered entry.
 */
interface SortableLogEntry {
  entry: JobLogEntry
  epoch: number | null
  index: number
}

function logEntry(value: unknown, index: number): SortableLogEntry {
  const source = typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {}
  const rawTimestamp = source.timestamp ?? source.ts ?? source.at ?? source.time
  const phase = source.phase ?? source.level ?? source.status ?? 'Event'
  const message =
    source.message ?? source.event ?? source.detail ?? (typeof value === 'string' ? value : 'Event recorded')
  const metrics = Object.entries(source)
    .filter(
      ([key]) =>
        !['timestamp', 'ts', 'at', 'time', 'phase', 'level', 'status', 'message', 'event', 'detail'].includes(key),
    )
    .filter(([key]) => !SECRET_KEY.test(key))
    .map(([key, entryValue]) => ({ label: labelFor(key), value: formatValue(entryValue, key) }))
  const epoch = timestampEpoch(rawTimestamp)
  return {
    entry: {
      // Untimestamped events keep an index-based label instead of coercing the
      // event number into a bogus date; invalid timestamps fall back to raw.
      timestamp: rawTimestamp === undefined ? `Event ${index + 1}` : formatDate(rawTimestamp),
      phase: formatValue(phase),
      message: formatValue(message),
      metrics,
    },
    epoch,
    index,
  }
}

/**
 * Format and chronologically order a raw job log.
 *
 * Sorting is performed on the numeric timestamp epoch (never on the
 * locale-formatted display string), so entries that cross hour or date
 * boundaries always order correctly. Entries with a missing or unparseable
 * timestamp are ordered deterministically by their original arrival index and
 * always sort after timestamped entries.
 *
 * @param log - Raw log items from the API.
 * @returns Display-ready entries in chronological order.
 * @example
 * formatJobLog([
 *   { timestamp: '2026-07-21T10:00:00Z', message: 'later' },
 *   { timestamp: '2026-07-21T09:00:00Z', message: 'earlier' },
 * ]) // -> ['earlier', 'later']
 */
export function formatJobLog(log: unknown[]): JobLogEntry[] {
  return log
    .map(logEntry)
    .sort((left, right) => {
      if (left.epoch !== null && right.epoch !== null) {
        // Stable within equal timestamps: preserve original arrival order.
        return left.epoch === right.epoch ? left.index - right.index : left.epoch - right.epoch
      }
      // Timestamped entries precede untimestamped ones; untimestamped entries
      // stay in their original relative order.
      if (left.epoch !== null) return -1
      if (right.epoch !== null) return 1
      return left.index - right.index
    })
    .map((item) => item.entry)
}
