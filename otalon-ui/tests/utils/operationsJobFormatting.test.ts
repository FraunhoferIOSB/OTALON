import { describe, expect, it } from 'vitest'

import { formatJobLog, formatJobMetadata, formatJobParams } from '~/utils/operationsJobFormatting'

const job = {
  id: 1,
  display_id: 'J-1',
  type: 'training' as const,
  title: 'Boundary retrain',
  state: 'completed' as const,
  trigger: 'operator (UI)',
  actor: 'operator',
  started_at: '2026-07-21T10:00:00Z',
  ended_at: '2026-07-21T10:05:00Z',
  phase_current: 2,
  phase_total: 2,
  phase_label: 'Complete',
  latest_event: 'Done',
  params: {
    intervals: [['2026-07-21T10:00:00Z', '2026-07-21T10:05:00Z']],
    module: 'conn',
    api_key: 'do-not-render',
  },
  log: [
    { timestamp: '2026-07-21T10:02:00Z', phase: 'scan', message: 'Read observations', records: 12 },
    { timestamp: '2026-07-21T10:01:00Z', phase: 'prepare', message: 'Started' },
  ],
  error: null,
  result: 'success',
  can_cancel: false,
  can_retry: false,
  retried_as_id: null,
}

describe('operations job formatting', () => {
  it('humanizes params and redacts secret-like values', () => {
    const fields = formatJobParams(job.params)
    expect(fields).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: 'Intervals', value: expect.stringContaining('to') }),
        expect.objectContaining({ label: 'Module', value: 'conn' }),
        expect.objectContaining({ label: 'Api Key', value: '[redacted]' }),
      ]),
    )
  })

  it('formats metadata and sorts log entries chronologically with metrics', () => {
    expect(formatJobMetadata(job)).toEqual(
      expect.arrayContaining([expect.objectContaining({ label: 'Result', value: 'success' })]),
    )
    const log = formatJobLog(job.log)
    expect(log[0]).toMatchObject({ phase: 'prepare', message: 'Started' })
    expect(log[1]?.metrics).toEqual([{ label: 'Records', value: '12' }])
  })

  it('keeps semantic detail free of a primary raw JSON representation', () => {
    const fields = formatJobParams(job.params)
    expect(fields.some((field) => field.value.includes('{'))).toBe(false)
    expect(formatJobLog(job.log)).toHaveLength(2)
  })

  it('labels untimestamped phase events without parsing their index as a date', () => {
    const log = formatJobLog([
      { phase: 'running', state: 'running' },
      { phase: 'complete', state: 'succeeded' },
    ])
    expect(log.map((entry) => entry.timestamp)).toEqual(['Event 1', 'Event 2'])
    expect(log.some((entry) => entry.timestamp.includes('2001'))).toBe(false)
  })

  it('orders entries chronologically across the 09:xx / 10:xx hour boundary', () => {
    // Provided out of order; 10:00 arrives before 09:00 in the raw log.
    const log = formatJobLog([
      { timestamp: '2026-07-21T10:00:00Z', message: 'ten' },
      { timestamp: '2026-07-21T09:00:00Z', message: 'nine' },
      { timestamp: '2026-07-21T09:30:00Z', message: 'nine-thirty' },
    ])
    expect(log.map((entry) => entry.message)).toEqual(['nine', 'nine-thirty', 'ten'])
  })

  it('orders entries chronologically across a date boundary', () => {
    const log = formatJobLog([
      { timestamp: '2026-07-22T00:15:00Z', message: 'next-day' },
      { timestamp: '2026-07-21T23:45:00Z', message: 'prev-day' },
    ])
    expect(log.map((entry) => entry.message)).toEqual(['prev-day', 'next-day'])
  })

  it('places invalid and untimestamped events after valid timestamps in stable order', () => {
    const log = formatJobLog([
      { timestamp: 'not-a-date', message: 'garbage' },
      { timestamp: '2026-07-21T10:00:00Z', message: 'valid-late' },
      { phase: 'running', message: 'no-timestamp' },
      { timestamp: '2026-07-21T09:00:00Z', message: 'valid-early' },
    ])
    // Valid timestamps sort first (chronologically); invalid/untimestamped
    // preserve their original relative arrival order afterwards.
    expect(log.map((entry) => entry.message)).toEqual(['valid-early', 'valid-late', 'garbage', 'no-timestamp'])
    // An invalid timestamp string is preserved verbatim, never coerced.
    expect(log[2]?.timestamp).toBe('not-a-date')
    // An untimestamped event still gets an index label, not a date.
    expect(log[3]?.timestamp).toBe('Event 3')
  })

  it('accepts numeric epoch timestamps and orders them chronologically', () => {
    const log = formatJobLog([
      { timestamp: 1_753_090_800_000, message: 'ms-late' },
      { timestamp: 1_600_000_000, message: 'seconds-early' },
    ])
    // 1_600_000_000 s (2020-09-13) precedes 1_753_090_800_000 ms (2025-07-21).
    expect(log.map((entry) => entry.message)).toEqual(['seconds-early', 'ms-late'])
  })

  it('does not expose an internal sort key on rendered log entries', () => {
    const [entry] = formatJobLog([{ timestamp: '2026-07-21T10:00:00Z', message: 'only' }])
    expect(Object.keys(entry ?? {}).sort()).toEqual(['message', 'metrics', 'phase', 'timestamp'])
  })
})
