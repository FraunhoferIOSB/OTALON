/**
 * Unit tests for the PCAP import slice of dataSourcesStore (UI-078 Wave D).
 *
 * Exercises the upload flow, each distinguishable rejection branch
 * (422 / 413 / 409), the force re-post, job following, the "Recent Imports"
 * listing and the "Set time range" window derivation.
 *
 * MSW is bypassed here in favour of a stubbed `$fetch`: these tests are
 * about which request is issued and how the response/rejection is folded
 * into store state, and a stub lets a rejection carry the exact FastAPI
 * body shape (notably the 409 object `detail`).
 */
import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { importRange, useDataSourcesStore } from '~/stores/dataSourcesStore'
import type { PcapImportStatus } from '~/composables/usePcapImport'

interface Call {
  url: string
  options: Record<string, unknown>
}

let calls: Call[] = []
type Responder = (url: string, options: Record<string, unknown>) => unknown

let responder: Responder = () => ({})

function makeFile(name = 'kunde.pcap', size = 4096): File {
  return new File([new Uint8Array(size)], name)
}

const ACCEPTED = {
  display_id: 'J-42',
  job_id: 42,
  state: 'running',
  filename: '8f3e.pcap',
  original_filename: 'kunde.pcap',
  size_bytes: 4096,
  sha256: 'a'.repeat(64),
  time_start: '2026-06-01T10:00:00Z',
  time_end: '2026-06-01T10:15:00Z',
  forced: false,
  delivered: true,
}

function statusEnvelope(overrides: Partial<PcapImportStatus> = {}): PcapImportStatus {
  return {
    display_id: 'J-42',
    job_id: 42,
    state: 'running',
    phase_current: 2,
    phase_total: 3,
    phase_label: 'Netcap++ liest',
    latest_event: 'lese Pakete',
    original_filename: 'kunde.pcap',
    size_bytes: 4096,
    time_start: '2026-06-01T10:00:00Z',
    time_end: '2026-06-01T10:15:00Z',
    forced: false,
    started_at: '2026-06-01T12:00:00Z',
    ended_at: null,
    error: null,
    result: null,
    ...overrides,
  }
}

const CONFLICT_ERROR = {
  status: 409,
  message: 'Conflict',
  detail: {
    message: "Measurements already exist for this capture's time range. Importing it would overwrite them.",
    conflict_start: '2026-06-01T10:00:00Z',
    conflict_end: '2026-06-01T10:15:00Z',
    measurement: 'network_metrics',
  },
}

beforeEach(() => {
  setActivePinia(createPinia())
  calls = []
  responder = () => ({})
  vi.stubGlobal('$fetch', async (url: string, options: Record<string, unknown> = {}) => {
    calls.push({ url, options })
    const result = responder(url, options)
    if (
      result instanceof Error ||
      (result && typeof result === 'object' && 'status' in result && '__throw' in result)
    ) {
      throw result
    }
    return result
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

/** Build a responder that throws `error` for the upload POST only. */
function rejectUploadWith(error: unknown): Responder {
  return (url, options) => {
    if (options.method === 'POST') throw error
    if (url.endsWith('/pcap-import')) return { items: [], total: 0 }
    return statusEnvelope()
  }
}

describe('uploadCapture — happy path', () => {
  beforeEach(() => {
    responder = (url, options) => {
      if (options.method === 'POST') return ACCEPTED
      if (url.endsWith('/pcap-import')) return { items: [statusEnvelope()], total: 1 }
      return statusEnvelope()
    }
  })

  it('stores the acceptance envelope and reports success', async () => {
    const store = useDataSourcesStore()
    await expect(store.uploadCapture(makeFile())).resolves.toBe(true)
    expect(store.importAccepted?.display_id).toBe('J-42')
    expect(store.importRejection).toBeNull()
  })

  it('retains the file so a conflict can be retried without re-picking', async () => {
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile('capture.pcap'))
    expect(store.importFile?.name).toBe('capture.pcap')
  })

  it('clears the uploading flag when finished', async () => {
    const store = useDataSourcesStore()
    const pending = store.uploadCapture(makeFile())
    expect(store.isUploading).toBe(true)
    await pending
    expect(store.isUploading).toBe(false)
  })

  it('refreshes the status and the recent listing after acceptance', async () => {
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile())
    expect(store.importStatus?.phase_label).toBe('Netcap++ liest')
    expect(store.recentImports).toHaveLength(1)
  })

  it('does not send force unless asked', async () => {
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile())
    const form = calls[0]?.options.body as FormData
    expect(form.get('force')).toBeNull()
  })
})

describe('uploadCapture — 422 unsupported capture', () => {
  it('records a distinguishable rejection with the server wording', async () => {
    responder = rejectUploadWith({ status: 422, detail: 'File is not a pcap or pcapng capture' })
    const store = useDataSourcesStore()
    await expect(store.uploadCapture(makeFile('notes.pcap'))).resolves.toBe(false)
    expect(store.importRejection?.kind).toBe('unsupported')
    expect(store.importRejection?.message).toBe('File is not a pcap or pcapng capture')
    expect(store.importConflict).toBeNull()
    expect(store.importAccepted).toBeNull()
  })
})

describe('uploadCapture — 413 too large', () => {
  it('records the byte ceiling for human-readable rendering', async () => {
    responder = rejectUploadWith({
      status: 413,
      detail: 'Upload exceeds the configured limit of 536870912 bytes',
    })
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile('huge.pcap'))
    expect(store.importRejection?.kind).toBe('too-large')
    expect(store.importRejection?.limitBytes).toBe(536_870_912)
    expect(store.importRejection?.message).toContain('536870912 bytes')
  })
})

describe('uploadCapture — 409 overlap conflict', () => {
  it('exposes the conflict range from the object detail', async () => {
    responder = rejectUploadWith(CONFLICT_ERROR)
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile())
    expect(store.importConflict?.conflict?.conflict_start).toBe('2026-06-01T10:00:00Z')
    expect(store.importConflict?.conflict?.conflict_end).toBe('2026-06-01T10:15:00Z')
    expect(store.importConflict?.message).not.toContain('[object Object]')
  })

  it('force-retries the same file with force=true and succeeds', async () => {
    let attempt = 0
    responder = (url, options) => {
      if (options.method === 'POST') {
        attempt += 1
        if (attempt === 1) throw CONFLICT_ERROR
        return { ...ACCEPTED, forced: true }
      }
      if (url.endsWith('/pcap-import')) return { items: [], total: 0 }
      return statusEnvelope()
    }
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile('kunde.pcap'))
    expect(store.importConflict).not.toBeNull()

    await expect(store.forceRetryUpload()).resolves.toBe(true)
    const uploads = calls.filter((c) => c.options.method === 'POST')
    expect(uploads).toHaveLength(2)
    expect((uploads[1]?.options.body as FormData).get('force')).toBe('true')
    expect(store.importConflict).toBeNull()
    expect(store.importAccepted?.forced).toBe(true)
  })

  it('re-posts the very same capture, so the operator need not pick it again', async () => {
    responder = rejectUploadWith(CONFLICT_ERROR)
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile('kunde.pcap'))
    await store.forceRetryUpload()
    const uploads = calls.filter((c) => c.options.method === 'POST')
    const first = (uploads[0]?.options.body as FormData).get('file') as File
    const second = (uploads[1]?.options.body as FormData).get('file') as File
    expect(second.name).toBe(first.name)
    expect(second.size).toBe(first.size)
  })

  it('does nothing when there is no retained file', async () => {
    const store = useDataSourcesStore()
    await expect(store.forceRetryUpload()).resolves.toBe(false)
    expect(calls).toHaveLength(0)
  })
})

describe('import job following', () => {
  it('treats non-terminal states as running', async () => {
    responder = (url, options) => {
      if (options.method === 'POST') return { ...ACCEPTED, state: 'queued', delivered: false }
      if (url.endsWith('/pcap-import')) return { items: [], total: 0 }
      return statusEnvelope({ state: 'queued' })
    }
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile())
    expect(store.isImportRunning).toBe(true)
  })

  it('settles on completed, never on succeeded', async () => {
    responder = (url, options) => {
      if (options.method === 'POST') return ACCEPTED
      if (url.endsWith('/pcap-import')) return { items: [], total: 0 }
      return statusEnvelope({ state: 'completed', result: { points_written: 987 } })
    }
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile())
    expect(store.importStatus?.state).toBe('completed')
    expect(store.isImportRunning).toBe(false)
  })

  it('keeps the last known status when a poll fails transiently', async () => {
    responder = (url, options) => {
      if (options.method === 'POST') return ACCEPTED
      if (url.endsWith('/pcap-import')) return { items: [], total: 0 }
      return statusEnvelope()
    }
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile())
    const before = store.importStatus

    responder = () => {
      throw new Error('network blip')
    }
    await store.refreshImportStatus()
    expect(store.importStatus).toEqual(before)
  })

  it('does not poll when no job is being followed', async () => {
    const store = useDataSourcesStore()
    await store.refreshImportStatus()
    expect(calls).toHaveLength(0)
  })

  it('cancels the followed job through the cancel endpoint', async () => {
    responder = (url, options) => {
      if (url.endsWith('/cancel')) return statusEnvelope({ state: 'cancelled' })
      if (options.method === 'POST') return ACCEPTED
      if (url.endsWith('/pcap-import')) return { items: [], total: 0 }
      return statusEnvelope()
    }
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile())
    await store.cancelImport()
    expect(calls.some((c) => c.url.endsWith('/pcap-import/J-42/cancel'))).toBe(true)
    expect(store.importStatus?.state).toBe('cancelled')
  })

  it('resetImport clears the whole upload slice', async () => {
    responder = rejectUploadWith(CONFLICT_ERROR)
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile())
    store.resetImport()
    expect(store.importFile).toBeNull()
    expect(store.importRejection).toBeNull()
    expect(store.importAccepted).toBeNull()
    expect(store.importStatus).toBeNull()
  })
})

describe('recent imports', () => {
  it('requests the dedicated listing endpoint', async () => {
    responder = () => ({ items: [], total: 0 })
    const store = useDataSourcesStore()
    await store.fetchRecentImports()
    expect(calls[0]?.url).toBe('/api/v1/operations/pcap-import')
    expect(calls[0]?.options.query).toEqual({ limit: 20 })
  })

  it('distinguishes an honest empty state from an unavailable one', async () => {
    responder = () => ({ items: [], total: 0 })
    const store = useDataSourcesStore()
    await store.fetchRecentImports()
    expect(store.recentLoaded).toBe(true)
    expect(store.recentImports).toEqual([])
    expect(store.recentError).toBeNull()
  })

  it('records a listing error without inventing an empty history', async () => {
    responder = () => {
      throw { status: 500, message: 'Internal Server Error' }
    }
    const store = useDataSourcesStore()
    await store.fetchRecentImports()
    expect(store.recentError).toContain('Failed to load recent imports')
    expect(store.recentLoaded).toBe(true)
  })

  it('keeps the entries the backend ordered, newest first', async () => {
    responder = () => ({
      items: [
        statusEnvelope({ display_id: 'J-3', original_filename: 'newest.pcap' }),
        statusEnvelope({ display_id: 'J-1', original_filename: 'oldest.pcap' }),
      ],
      total: 2,
    })
    const store = useDataSourcesStore()
    await store.fetchRecentImports()
    expect(store.recentImports.map((i) => i.original_filename)).toEqual(['newest.pcap', 'oldest.pcap'])
  })
})

describe('importRange — "Set time range" window', () => {
  it('prefers the completion result over the pre-scan window', () => {
    const range = importRange(
      statusEnvelope({
        state: 'completed',
        result: { time_start: '2026-06-01T10:01:00Z', time_end: '2026-06-01T10:14:00Z' },
      }),
    )
    expect(range).toEqual({ start: '2026-06-01T10:01:00Z', end: '2026-06-01T10:14:00Z' })
  })

  it('falls back to the detected capture window', () => {
    expect(importRange(statusEnvelope())).toEqual({
      start: '2026-06-01T10:00:00Z',
      end: '2026-06-01T10:15:00Z',
    })
  })

  it('is null when no window is known, so the action can be disabled', () => {
    expect(importRange(statusEnvelope({ time_start: null, time_end: null }))).toBeNull()
  })

  it('completedImportRange only reports for a completed job', async () => {
    responder = (url, options) => {
      if (options.method === 'POST') return ACCEPTED
      if (url.endsWith('/pcap-import')) return { items: [], total: 0 }
      return statusEnvelope({ state: 'running' })
    }
    const store = useDataSourcesStore()
    await store.uploadCapture(makeFile())
    expect(store.completedImportRange).toBeNull()

    responder = () => statusEnvelope({ state: 'completed' })
    await store.refreshImportStatus()
    expect(store.completedImportRange).toEqual({
      start: '2026-06-01T10:00:00Z',
      end: '2026-06-01T10:15:00Z',
    })
  })
})
