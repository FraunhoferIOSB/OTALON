export interface TrainingIntervalValue {
  start: string
  end: string
}

export interface TrainingIntervalSummary {
  count: number
  unionMinutes: number
  valid: boolean
  state: 'complete' | 'incomplete' | 'invalid' | 'duplicate'
}

function timestamp(value: string): number {
  return Date.parse(value)
}

export function intervalDurationMinutes(interval: TrainingIntervalValue): number | null {
  const start = timestamp(interval.start)
  const end = timestamp(interval.end)
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return null
  return Math.round((end - start) / 60000)
}

export function summarizeTrainingIntervals(intervals: TrainingIntervalValue[]): TrainingIntervalSummary {
  const incomplete = intervals.some((interval) => !interval.start || !interval.end)
  if (!intervals.length || incomplete) {
    return { count: intervals.length, unionMinutes: 0, valid: false, state: 'incomplete' }
  }
  const ordered = intervals
    .map((interval) => ({ ...interval, startMs: timestamp(interval.start), endMs: timestamp(interval.end) }))
    .sort((left, right) => left.startMs - right.startMs)
  const valid = intervals.length > 0 && ordered.every((interval) => interval.endMs > interval.startMs)
  if (!valid) return { count: intervals.length, unionMinutes: 0, valid: false, state: 'invalid' }

  const seen = new Set<string>()
  for (const interval of intervals) {
    const key = `${interval.start}|${interval.end}`
    if (seen.has(key)) return { count: intervals.length, unionMinutes: 0, valid: false, state: 'duplicate' }
    seen.add(key)
  }

  let unionMs = 0
  let currentStart = ordered[0]?.startMs ?? 0
  let currentEnd = ordered[0]?.endMs ?? 0
  for (const interval of ordered.slice(1)) {
    if (interval.startMs <= currentEnd) {
      currentEnd = Math.max(currentEnd, interval.endMs)
    } else {
      unionMs += currentEnd - currentStart
      currentStart = interval.startMs
      currentEnd = interval.endMs
    }
  }
  unionMs += currentEnd - currentStart
  return {
    count: intervals.length,
    unionMinutes: Math.round(unionMs / 60000),
    valid: true,
    state: 'complete',
  }
}

export function toUtcEcho(value: string): string {
  if (!value) return ''
  const wallClock = Date.parse(`${value}:00Z`)
  if (!Number.isFinite(wallClock)) return ''
  const probe = new Date(wallClock)
  const berlinParts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Europe/Berlin',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(probe)
  const values = Object.fromEntries(berlinParts.map((part) => [part.type, part.value]))
  const berlinAsUtc = Date.UTC(
    Number(values.year),
    Number(values.month) - 1,
    Number(values.day),
    Number(values.hour),
    Number(values.minute),
    Number(values.second),
  )
  const utc = new Date(wallClock - (berlinAsUtc - wallClock))
  return `${utc.toISOString().slice(0, 16).replace('T', ' ')} UTC`
}
