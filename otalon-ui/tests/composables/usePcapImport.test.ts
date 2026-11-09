/**
 * Unit tests for the PCAP import client (UI-078 Wave D).
 *
 * Two things are pinned here because getting either wrong breaks the
 * operator workflow silently:
 *
 * 1. The multipart envelope the API parses itself — the capture part must
 *    carry a filename, `force` must be an ordinary text field (not a query
 *    parameter), and no `Content-Type` may be set by hand or the browser
 *    cannot emit the boundary.
 * 2. The rejection mapping — in particular that the HTTP 409 `detail` is an
 *    **object**. Rendering it with `String(detail)` would print
 *    `[object Object]` instead of the conflict range.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  parseConflictDetail,
  parseLimitBytes,
  toRejection,
  usePcapImport,
  PCAP_IMPORT_TERMINAL_STATES,
} from '~/composables/usePcapImport'

interface Captured {
  url: string
  options: Record<string, unknown>
}

let calls: Captured[] = []
let nextResponse: unknown = {}
let nextError: unknown = null

beforeEach(() => {
  calls = []
  nextResponse = {}
  nextError = null
  vi.stubGlobal('$fetch', async (url: string, options: Record<string, unknown> = {}) => {
    calls.push({ url, options })
    if (nextError) throw nextError
    return nextResponse
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function makeFile(name = 'kunde.pcap', size = 2048): File {
  return new File([new Uint8Array(size)], name, { type: 'application/octet-stream' })
}

describe('usePcapImport — upload envelope', () => {
  it('POSTs multipart FormData to the operations subtree', async () => {
    await usePcapImport().uploadCapture(makeFile())
    expect(calls[0]?.url).toBe('/api/v1/operations/pcap-import')
    expect(calls[0]?.options.method).toBe('POST')
    expect(calls[0]?.options.body).toBeInstanceOf(FormData)
  })

  it('appends the capture under a part that carries a filename', async () => {
    // The API identifies the capture by the presence of `filename` in the
    // Content-Disposition, not by the field name.
    await usePcapImport().uploadCapture(makeFile('capture-01.pcap'))
    const form = calls[0]?.options.body as FormData
    const part = form.get('file')
    expect(part).toBeInstanceOf(File)
    expect((part as File).name).toBe('capture-01.pcap')
  })

  it('omits force entirely on a normal upload', async () => {
    await usePcapImport().uploadCapture(makeFile())
    const form = calls[0]?.options.body as FormData
    expect(form.get('force')).toBeNull()
  })

  it('sends force as a plain text field, not a query parameter', async () => {
    await usePcapImport().uploadCapture(makeFile(), { force: true })
    const form = calls[0]?.options.body as FormData
    expect(form.get('force')).toBe('true')
    expect(calls[0]?.options.query).toBeUndefined()
    expect(calls[0]?.url).not.toContain('force')
  })

  it('never sets Content-Type by hand so the browser emits the boundary', async () => {
    await usePcapImport().uploadCapture(makeFile())
    const headers = calls[0]?.options.headers as Record<string, string> | undefined
    expect(headers?.['Content-Type'] ?? headers?.['content-type']).toBeUndefined()
  })
})

describe('usePcapImport — reads', () => {
  it('fetches one job status by display id', async () => {
    await usePcapImport().fetchStatus('J-42')
    expect(calls[0]?.url).toBe('/api/v1/operations/pcap-import/J-42')
  })

  it('encodes the display id', async () => {
    await usePcapImport().fetchStatus('J 42/x')
    expect(calls[0]?.url).toBe('/api/v1/operations/pcap-import/J%2042%2Fx')
  })

  it('lists recent imports with a limit', async () => {
    nextResponse = { items: [{ display_id: 'J-1' }], total: 1 }
    const items = await usePcapImport().fetchRecent(5)
    expect(calls[0]?.url).toBe('/api/v1/operations/pcap-import')
    expect(calls[0]?.options.query).toEqual({ limit: 5 })
    expect(items).toHaveLength(1)
  })

  it('tolerates a listing envelope without items', async () => {
    nextResponse = { total: 0 }
    await expect(usePcapImport().fetchRecent()).resolves.toEqual([])
  })

  it('posts a cancel request', async () => {
    await usePcapImport().cancelImport('J-9')
    expect(calls[0]?.url).toBe('/api/v1/operations/pcap-import/J-9/cancel')
    expect(calls[0]?.options.method).toBe('POST')
  })
})

describe('toRejection — 422 unsupported capture', () => {
  it('classifies and preserves the server wording verbatim', () => {
    const rejection = toRejection({ status: 422, detail: 'File is not a pcap or pcapng capture' })
    expect(rejection.kind).toBe('unsupported')
    expect(rejection.message).toBe('File is not a pcap or pcapng capture')
    expect(rejection.conflict).toBeNull()
  })

  it('reads the detail out of a raw $fetch error shape too', () => {
    const rejection = toRejection({
      response: { status: 422 },
      data: { detail: 'File is not a pcap or pcapng capture' },
    })
    expect(rejection.kind).toBe('unsupported')
    expect(rejection.message).toBe('File is not a pcap or pcapng capture')
  })
})

describe('toRejection — 413 too large', () => {
  it('classifies and extracts the byte ceiling for human rendering', () => {
    const rejection = toRejection({
      status: 413,
      detail: 'Upload exceeds the configured limit of 536870912 bytes',
    })
    expect(rejection.kind).toBe('too-large')
    expect(rejection.limitBytes).toBe(536_870_912)
    // The server's own sentence stays reachable, not replaced by a
    // prettified paraphrase.
    expect(rejection.message).toBe('Upload exceeds the configured limit of 536870912 bytes')
  })

  it('survives a 413 whose wording carries no number', () => {
    const rejection = toRejection({ status: 413, detail: 'Payload too large' })
    expect(rejection.kind).toBe('too-large')
    expect(rejection.limitBytes).toBeNull()
  })
})

describe('toRejection — 409 conflict (object detail)', () => {
  const conflictError = {
    status: 409,
    detail: {
      message: "Measurements already exist for this capture's time range. Importing it would overwrite them.",
      conflict_start: '2026-06-01T10:00:00Z',
      conflict_end: '2026-06-01T10:15:00Z',
      measurement: 'network_metrics',
    },
  }

  it('parses the object detail instead of stringifying it', () => {
    const rejection = toRejection(conflictError)
    expect(rejection.kind).toBe('conflict')
    expect(rejection.conflict?.conflict_start).toBe('2026-06-01T10:00:00Z')
    expect(rejection.conflict?.conflict_end).toBe('2026-06-01T10:15:00Z')
    expect(rejection.conflict?.measurement).toBe('network_metrics')
  })

  it('never renders [object Object]', () => {
    const rejection = toRejection(conflictError)
    expect(rejection.message).not.toContain('[object Object]')
    expect(rejection.message).toContain('Measurements already exist')
  })

  it('degrades safely when the conflict payload lacks its range', () => {
    const rejection = toRejection({ status: 409, detail: { message: 'overlap' } })
    expect(rejection.kind).toBe('conflict')
    expect(rejection.conflict).toBeNull()
    expect(rejection.message).toBe('overlap')
  })
})

describe('toRejection — remaining statuses', () => {
  it.each([
    [400, 'malformed'],
    [401, 'unauthorized'],
    [403, 'unauthorized'],
    [500, 'unknown'],
  ])('maps %i to %s', (status, kind) => {
    expect(toRejection({ status, detail: 'x' }).kind).toBe(kind)
  })

  it('falls back to the error message when no detail is present', () => {
    expect(toRejection({ status: 500, message: 'Internal Server Error' }).message).toBe('Internal Server Error')
  })

  it('handles a FastAPI validation array detail', () => {
    const rejection = toRejection({ status: 422, detail: [{ msg: 'field required', loc: ['body'] }] })
    expect(rejection.message).toBe('field required')
  })

  it('handles a completely opaque throw', () => {
    const rejection = toRejection('boom')
    expect(rejection.status).toBe(0)
    expect(rejection.kind).toBe('unknown')
    expect(rejection.message).toBe('Upload failed for an unknown reason.')
  })
})

describe('helpers', () => {
  it('parseConflictDetail rejects a non-conflict payload', () => {
    expect(parseConflictDetail('a string')).toBeNull()
    expect(parseConflictDetail({ message: 'no range' })).toBeNull()
  })

  it('parseLimitBytes ignores small incidental numbers', () => {
    expect(parseLimitBytes('limit of 12 bytes')).toBeNull()
    expect(parseLimitBytes('limit of 536870912 bytes')).toBe(536_870_912)
  })

  it('terminal states use completed, never succeeded', () => {
    expect(PCAP_IMPORT_TERMINAL_STATES).toContain('completed')
    expect(PCAP_IMPORT_TERMINAL_STATES).not.toContain('succeeded')
    expect(PCAP_IMPORT_TERMINAL_STATES).toEqual(['completed', 'failed', 'cancelled', 'rejected'])
  })
})
