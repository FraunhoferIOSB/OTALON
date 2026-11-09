/**
 * Tests for the timestamp parsing helper in `app/utils/format.ts`.
 *
 * The OTALON API serializes datetimes as naive ISO strings in the
 * deployment's configured local timezone. The frontend relies on the
 * native ``Date`` parser for those strings (which already treats naive
 * input as local time) but the helper additionally honors explicit
 * timezone markers like ``Z`` or ``+02:00`` so that future API changes
 * remain compatible.
 */
import { describe, expect, it } from 'vitest'

import { parseApiTimestamp } from '~/utils/format'

describe('parseApiTimestamp', () => {
  it('parses a naive ISO string as local time (matches native Date)', () => {
    const ts = '2026-05-08T13:24:00'
    expect(parseApiTimestamp(ts).getTime()).toBe(new Date(ts).getTime())
  })

  it('honors explicit Z timezone marker', () => {
    const ts = '2026-05-08T13:24:00Z'
    expect(parseApiTimestamp(ts).toISOString()).toBe('2026-05-08T13:24:00.000Z')
  })

  it('honors an explicit positive offset', () => {
    const ts = '2026-05-08T15:24:00+02:00'
    expect(parseApiTimestamp(ts).toISOString()).toBe('2026-05-08T13:24:00.000Z')
  })

  it('honors an explicit negative offset', () => {
    const ts = '2026-05-08T08:24:00-05:00'
    expect(parseApiTimestamp(ts).toISOString()).toBe('2026-05-08T13:24:00.000Z')
  })

  it('returns an invalid Date for an empty string', () => {
    expect(Number.isNaN(parseApiTimestamp('').getTime())).toBe(true)
  })
})
