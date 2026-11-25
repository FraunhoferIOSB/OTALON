import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  usePcapImport,
  type PcapImportAccepted,
  type PcapImportState,
  type PcapImportStatus,
} from '~/composables/usePcapImport'
import { importRange, useDataSourcesStore } from '~/stores/dataSourcesStore'

const BASE = '/api/v1/operations/pcap-import'
const MARKER = 'Cancellation needs reconciliation; worker settlement is unverified.'
const conflict = {
  status: 409,
  detail: {
    message: 'Overwrite existing measurements',
    measurement: 'network_metrics',
    conflict_start: '2026-01-01T00:00:00Z',
    conflict_end: '2026-01-01T00:01:00Z',
  },
}
type Options = {
  method?: string
  body?: FormData
  query?: { limit: number; state?: PcapImportState }
  signal?: AbortSignal
}
type Call = { url: string; options: Options; at: number }
let calls: Call[]
let jobs: Map<string, PcapImportStatus>
let upload: (file: File, options: Options) => Promise<PcapImportAccepted>
let detail: (id: string) => Promise<PcapImportStatus>
let listing: (state: PcapImportState) => unknown
let cancel: (id: string) => Promise<PcapImportStatus>
let store: ReturnType<typeof useDataSourcesStore>

function file(name: string): File {
  return new File([new Uint8Array([1, 2, 3])], name)
}
function status(
  id: string,
  state: PcapImportState = 'running',
  extra: Partial<PcapImportStatus> = {},
): PcapImportStatus {
  return {
    display_id: id,
    job_id: 1,
    state,
    phase_current: null,
    phase_total: null,
    phase_label: null,
    latest_event: null,
    original_filename: `${id}.pcap`,
    size_bytes: null,
    time_start: null,
    time_end: null,
    forced: false,
    started_at: null,
    ended_at: null,
    error: null,
    result: null,
    ...extra,
  }
}
function accepted(id: string, state: PcapImportState = 'running'): PcapImportAccepted {
  return {
    display_id: id,
    job_id: 1,
    state,
    filename: 'stored.pcap',
    original_filename: `${id}.pcap`,
    size_bytes: 3,
    sha256: 'a'.repeat(64),
    time_start: null,
    time_end: null,
    forced: false,
    delivered: state === 'running',
  }
}
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((yes, no) => {
    resolve = yes
    reject = no
  })
  return { promise, resolve, reject }
}
async function flush() {
  for (let i = 0; i < 80; i++) await Promise.resolve()
}
async function advance(ms = 2000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flush()
}
function posts() {
  return calls.filter((c) => c.url === BASE && c.options.method === 'POST')
}
function reads(id: string) {
  return calls.filter((c) => c.url === `${BASE}/${id}`)
}
function names() {
  return posts().map((c) => (c.options.body?.get('file') as File).name)
}

beforeEach(() => {
  vi.useFakeTimers()
  setActivePinia(createPinia())
  calls = []
  jobs = new Map()
  listing = (state) => {
    const items = [...jobs.values()].filter((j) => j.state === state)
    return { items, total: items.length }
  }
  detail = async (id) => {
    const value = jobs.get(id)
    if (!value) throw { status: 404 }
    return value
  }
  upload = async (f) => {
    const id = f.name
    jobs.set(id, status(id))
    return accepted(id)
  }
  cancel = async (id) => {
    const value = status(id, 'cancelling')
    jobs.set(id, value)
    return value
  }
  vi.stubGlobal('$fetch', async (url: string, options: Options = {}) => {
    calls.push({ url, options, at: Date.now() })
    if (url === BASE && options.method === 'POST') return upload(options.body?.get('file') as File, options)
    if (url === BASE && options.query?.state) return listing(options.query.state)
    if (url === BASE) return { items: [...jobs.values()], total: jobs.size }
    const id = decodeURIComponent(url.slice(BASE.length + 1).replace(/\/cancel$/, ''))
    if (url.endsWith('/cancel')) return cancel(id)
    return detail(id)
  })
  store = useDataSourcesStore()
})

afterEach(async () => {
  store.stopImportQueue?.()
  store.$dispose()
  await flush()
  vi.clearAllTimers()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('training import queue', () => {
  it('Q01 materializes every file in order, autostarts, and appends while busy without deduplication', async () => {
    const held = deferred<PcapImportAccepted>()
    upload = () => held.promise
    const a = file('same.pcap')
    const b = file('same.pcap')
    store.enqueueImports([a, b, file('notes.txt')])
    await flush()
    store.enqueueImports([file('later.pcap')])
    expect(store.importQueue.map((r) => r.name)).toEqual(['same.pcap', 'same.pcap', 'notes.txt', 'later.pcap'])
    expect(new Set(store.importQueue.map((r) => r.localId)).size).toBe(4)
    expect(store.importQueue.map((r) => r.sequence)).toEqual([1, 2, 3, 4])
    expect(store.importQueue[0]?.file).toBe(a)
    expect(store.importQueue[1]?.file).toBe(b)
    expect(store.importQueue[0]?.uploadLoaded).toBeNull()
    expect(store.importQueue[0]?.uploadTotal).toBeNull()
    expect(posts()).toHaveLength(1)
    jobs.set('A', status('A'))
    held.resolve(accepted('A'))
    await flush()
    expect(posts()).toHaveLength(1)
  })

  it.each(['queued', 'running', 'cancelling'] as const)(
    'Q02 %s is an accepted persisted barrier, not completion',
    async (state) => {
      upload = async (f) => {
        jobs.set(f.name, status(f.name, state))
        return accepted(f.name, state)
      }
      store.enqueueImports([file('A'), file('B')])
      await flush()
      await advance(6000)
      expect(names()).toEqual(['A'])
      jobs.set('A', status('A', 'completed'))
      await advance()
      expect(names()).toEqual(['A', 'B'])
    },
  )

  it('Q03 SHA reuse consumes actual terminal acceptance and reads exact detail before the next POST', async () => {
    upload = async (f) => {
      jobs.set(f.name, status(f.name, 'completed', { result: { points_written: 7 } }))
      return accepted(f.name, 'completed')
    }
    store.enqueueImports([file('A'), file('A')])
    await flush()
    expect(names()).toEqual(['A', 'A'])
    expect(store.importQueue).toHaveLength(2)
    expect(
      store.importQueue.every((r) => r.accepted?.state === 'completed' && r.status?.result?.points_written === 7),
    ).toBe(true)
    expect(calls.findIndex((c) => c.url === `${BASE}/A`)).toBeLessThan(
      calls.findLastIndex((c) => c.options.method === 'POST'),
    )
  })

  it.each([400, 413, 422, 409])(
    'Q04 definite %i refusal safely advances and retains exact row outcome',
    async (code) => {
      const input = file('A')
      upload = async (f) => {
        if (f.name === 'A') throw code === 409 ? conflict : { status: code, detail: 'exact refusal' }
        jobs.set('B', status('B'))
        return accepted('B')
      }
      store.enqueueImports([input, file('B')])
      await flush()
      expect(names()).toEqual(['A', 'B'])
      expect(store.importQueue[0]?.rejection?.status).toBe(code)
      expect(store.importQueue[0]?.uploadState).toBe(code === 409 ? 'conflict' : 'failed')
      if (code === 409) {
        expect(store.importQueue[0]?.file).toBe(input)
        expect(store.importQueue[0]?.rejection?.conflict).toEqual(conflict.detail)
      }
    },
  )

  it('Q05 confirmed force is per-file and ordered ahead of pending only after the active owner settles', async () => {
    upload = async (f, options) => {
      if (['A', 'B'].includes(f.name) && !options.body?.get('force')) throw conflict
      jobs.set(f.name, status(f.name))
      return { ...accepted(f.name), forced: options.body?.get('force') === 'true' }
    }
    store.enqueueImports([file('A'), file('B'), file('C'), file('D')])
    await flush()
    store.confirmImportForce(store.importQueue[1]!.localId)
    store.confirmImportForce(store.importQueue[0]!.localId)
    await flush()
    expect(names()).toEqual(['A', 'B', 'C'])
    jobs.set('C', status('C', 'completed'))
    await advance()
    expect(names()).toEqual(['A', 'B', 'C', 'B'])
    jobs.set('B', status('B', 'completed'))
    await advance()
    expect(names()).toEqual(['A', 'B', 'C', 'B', 'A'])
    jobs.set('A', status('A', 'completed'))
    await advance()
    expect(names()).toEqual(['A', 'B', 'C', 'B', 'A', 'D'])
    expect(posts().map((c) => c.options.body?.get('force'))).toEqual([null, null, null, 'true', 'true', null])
  })

  it('Q06 pending and conflict cancel release only their own bytes and eligibility', async () => {
    upload = async (f) => {
      if (f.name === 'A') throw conflict
      jobs.set(f.name, status(f.name))
      return accepted(f.name)
    }
    store.enqueueImports([file('A'), file('B'), file('C')])
    await flush()
    await store.cancelQueueImport(store.importQueue[0]!.localId)
    await store.cancelQueueImport(store.importQueue[2]!.localId)
    expect(store.importQueue.map((r) => r.uploadState)).toEqual(['cancelled', 'accepted', 'cancelled'])
    expect(store.importQueue[0]?.file).toBeNull()
    expect(store.importQueue[2]?.file).toBeNull()
    expect(calls.some((c) => c.url.endsWith('/cancel'))).toBe(false)
    expect(names()).toEqual(['A', 'B'])
  })

  it('Q07 accepted cancel consumes same-ID cancelling truth and failed cancel never releases the barrier', async () => {
    store.enqueueImports([file('A'), file('B')])
    await flush()
    cancel = async () => {
      throw { status: 502, message: 'cancel delivery failed' }
    }
    await store.cancelQueueImport(store.importQueue[0]!.localId)
    expect(store.importQueue[0]?.cancelError).toContain('cancel delivery failed')
    expect(store.importQueue[0]?.status?.state).toBe('running')
    cancel = async (id) => {
      jobs.set(id, status(id, 'cancelling'))
      return jobs.get(id)!
    }
    await store.cancelQueueImport(store.importQueue[0]!.localId)
    await advance(6000)
    expect(store.importQueue[0]?.status?.state).toBe('cancelling')
    expect(names()).toEqual(['A'])
    expect(calls.filter((c) => c.url.endsWith('/cancel')).map((c) => c.url)).toEqual([
      `${BASE}/A/cancel`,
      `${BASE}/A/cancel`,
    ])
    jobs.set('A', status('A', 'cancelled'))
    await advance()
    expect(names()).toEqual(['A', 'B'])
  })

  it('Q08 polling is awaited, nonoverlapping, and waits two seconds after settlement', async () => {
    store.enqueueImports([file('A'), file('B')])
    await flush()
    const held = deferred<PcapImportStatus>()
    detail = () => held.promise
    await advance()
    const count = reads('A').length
    const extra = store.refreshImportStatus()
    await advance(10000)
    expect(reads('A')).toHaveLength(count)
    held.resolve(status('A'))
    await extra
    await flush()
    await advance(1999)
    expect(reads('A')).toHaveLength(count)
    await advance(1)
    expect(reads('A')).toHaveLength(count + 1)
  })

  it('Q09 transient failures preserve last truth, expose error, and back off 2/4/8/16/30 seconds', async () => {
    store.enqueueImports([file('A'), file('B')])
    await flush()
    const truth = store.importQueue[0]!.status
    detail = async () => {
      throw new Error('temporary outage')
    }
    for (const ms of [2000, 2000, 4000, 8000, 16000, 30000]) await advance(ms)
    const times = reads('A').map((c) => c.at)
    expect(times.slice(1).map((t, i) => t - times[i]!)).toEqual([2000, 2000, 4000, 8000, 16000, 30000])
    expect(store.importQueue[0]?.status).toEqual(truth)
    expect(store.importQueue[0]?.pollError).toContain('temporary outage')
    expect(names()).toEqual(['A'])
  })

  it.each([401, 403])(
    'Q10 auth %i stops automatic privileged work until explicit recovery without resending',
    async (code) => {
      store.enqueueImports([file('A'), file('B')])
      await flush()
      detail = async () => {
        throw { response: { status: code }, data: { detail: 'denied' } }
      }
      await advance()
      const count = calls.length
      await advance(60000)
      expect(store.importAuthStopped).toBe(true)
      expect(calls).toHaveLength(count)
      detail = async (id) => jobs.get(id)!
      await store.resumeImportQueue()
      expect(store.importAuthStopped).toBe(false)
      expect(names()).toEqual(['A'])
      expect(store.importQueue).toHaveLength(2)
    },
  )

  it('Q11 lost acceptance is uncertain and similar metadata/history is never identity proof or resend permission', async () => {
    upload = async (f) => {
      jobs.set('unobserved', status('unobserved', 'running', { original_filename: f.name, size_bytes: f.size }))
      throw new Error('response lost')
    }
    const input = file('A')
    store.enqueueImports([input, file('B')])
    await flush()
    await advance(60000)
    await store.fetchRecentImports()
    await store.refreshImportQueue()
    expect(store.importQueue[0]?.uploadState).toBe('uncertain')
    expect(store.importQueue[0]?.accepted).toBeNull()
    expect(store.importQueue[0]?.file).toBe(input)
    expect(names()).toEqual(['A'])
    expect(calls.some((c) => c.url.endsWith('/cancel'))).toBe(false)
    expect(store.recentImports[0]?.display_id).toBe('unobserved')
  })

  it('Q12 preflight uses each exact state-filtered import list with limit 200, not generic or recent history', async () => {
    await store.startImportQueue()
    const queries = calls.filter((c) => c.options.query?.state).map((c) => c.options.query)
    expect(queries).toEqual([
      { limit: 200, state: 'queued' },
      { limit: 200, state: 'running' },
      { limit: 200, state: 'cancelling' },
    ])
    expect(calls.every((c) => c.url === BASE)).toBe(true)
    const envelope = await usePcapImport().fetchByState('running')
    expect(envelope).toEqual({ items: [], total: 0 })
  })

  it.each(['saturated', 'missing', 'malformed', 'failure'] as const)(
    'Q13 %s state listing visibly holds new dispatch',
    async (kind) => {
      listing = (state) => {
        if (state !== 'running') return { items: [], total: 0 }
        if (kind === 'failure') throw new Error('list outage')
        if (kind === 'missing') return undefined
        if (kind === 'malformed') return { items: [], total: 1 }
        const items = Array.from({ length: 200 }, (_, i) => status(`old-${i}`))
        return { items, total: 200 }
      }
      store.enqueueImports([file('A')])
      await flush()
      expect(posts()).toHaveLength(0)
      expect(store.importQueueError).toBeTruthy()
    },
  )

  it('Q14 reload finds older active import via producer-filtered list and maps File=null exact identity once', async () => {
    jobs.set('older-import', status('older-import'))
    store.enqueueImports([file('A')])
    await flush()
    await store.refreshImportQueue()
    const owned = store.importQueue.filter((r) => r.status?.display_id === 'older-import')
    expect(owned).toHaveLength(1)
    expect(owned[0]?.file).toBeNull()
    expect(owned[0]?.sizeBytes).toBeNull()
    expect(posts()).toHaveLength(0)
    jobs.set('older-import', status('older-import', 'completed'))
    await advance()
    expect(names()).toEqual(['A'])
    expect(store.importQueue[0]?.name).toBe('A')
  })

  it('Q15 generic Jobs cancellation observed as persisted cancelling retains the same owner barrier', async () => {
    store.enqueueImports([file('A'), file('B')])
    await flush()
    jobs.set('A', status('A', 'cancelling', { latest_event: 'Generic Jobs cancellation requested' }))
    await advance(6000)
    expect(store.importQueue[0]?.status?.state).toBe('cancelling')
    expect(names()).toEqual(['A'])
    expect(calls.some((c) => c.url.includes('/jobs/'))).toBe(false)
  })

  it.each(['error', 'latest_event'] as const)(
    'Q16 reconciliation marker in %s stops endless polling, explicit same-ID cancel resumes until terminal',
    async (field) => {
      store.enqueueImports([file('A'), file('B')])
      await flush()
      jobs.set('A', status('A', 'cancelling', { [field]: MARKER }))
      await advance()
      const count = reads('A').length
      await advance(60000)
      await store.refreshImportStatus()
      expect(reads('A')).toHaveLength(count)
      expect(store.importQueue[0]?.status?.[field]).toBe(MARKER)
      expect(names()).toEqual(['A'])
      await store.cancelQueueImport(store.importQueue[0]!.localId)
      await advance()
      expect(reads('A').length).toBeGreaterThan(count)
      jobs.set('A', status('A', 'completed', { result: { points_written: 4 } }))
      await advance()
      expect(names()).toEqual(['A', 'B'])
      expect(store.importQueue[0]?.status?.result?.points_written).toBe(4)
    },
  )

  it('Q17 reload preserves reconciliation marker and never polls or redispatches the blocked job', async () => {
    jobs.set('blocked', status('blocked', 'cancelling', { error: MARKER, latest_event: MARKER }))
    store.enqueueImports([file('A')])
    await flush()
    await advance(60000)
    expect(reads('blocked')).toHaveLength(0)
    expect(posts()).toHaveLength(0)
    expect(store.importQueue.find((r) => r.status?.display_id === 'blocked')?.status?.error).toBe(MARKER)
  })

  it('Q18 reset preserves active ownership and other rows, dispose removes only owned timers and prevents late writes', async () => {
    store.enqueueImports([file('A'), file('B')])
    await flush()
    store.resetImport()
    expect(store.importQueue).toHaveLength(2)
    expect(store.importQueue[0]?.status?.state).toBe('running')
    const held = deferred<PcapImportStatus>()
    detail = () => held.promise
    await advance()
    const unrelated = vi.fn()
    setTimeout(unrelated, 3000)
    store.$dispose()
    const before = JSON.stringify(store.importQueue)
    held.resolve(status('A', 'completed'))
    await flush()
    await advance(10000)
    expect(JSON.stringify(store.importQueue)).toBe(before)
    expect(unrelated).toHaveBeenCalledOnce()
    expect(calls.some((c) => c.url.endsWith('/cancel'))).toBe(false)
    expect(names()).toEqual(['A'])
  })

  it('Q19 upload abort support is identity-safe uncertainty, and stop retains browser bytes without late acceptance writes', async () => {
    const held = deferred<PcapImportAccepted>()
    upload = () => held.promise
    store.enqueueImports([file('A'), file('B')])
    await flush()
    const row = store.importQueue[0]!
    await store.cancelQueueImport(row.localId)
    expect(posts()[0]?.options.signal?.aborted).toBe(true)
    expect(row.uploadState).toBe('uncertain')
    expect(row.file).not.toBeNull()
    store.stopImportQueue()
    const before = JSON.stringify(store.importQueue)
    held.resolve(accepted('observed-late'))
    await flush()
    expect(JSON.stringify(store.importQueue)).toBe(before)
    expect(names()).toEqual(['A'])
    expect(calls.some((c) => c.url.endsWith('/cancel'))).toBe(false)
  })

  it('Q20 result-preferred import range and nullable producer fields remain unchanged', () => {
    const entry = status('A', 'completed', {
      time_start: 'scan-start',
      time_end: 'scan-end',
      result: { time_start: 'result-start', time_end: 'result-end', points_written: null },
    })
    expect(importRange(entry)).toEqual({ start: 'result-start', end: 'result-end' })
    expect(importRange(status('unknown'))).toBeNull()
  })

  it.each(['failed', 'cancelled', 'rejected'] as const)(
    'Q21 actual %s terminal detail safely releases the next file',
    async (state) => {
      store.enqueueImports([file('A'), file('B')])
      await flush()
      jobs.set('A', status('A', state))
      await advance()
      expect(names()).toEqual(['A', 'B'])
      expect(store.importQueue[0]?.status?.state).toBe(state)
    },
  )

  it('Q22 singleton upload calls share the same queue lock with new enqueue calls', async () => {
    const first = store.uploadCapture(file('A'))
    store.enqueueImports([file('B')])
    await first
    await flush()
    expect(names()).toEqual(['A'])
    expect(store.importQueue).toHaveLength(2)
    jobs.set('A', status('A', 'completed'))
    await advance()
    expect(names()).toEqual(['A', 'B'])
  })

  it('Q23 a late observed acceptance after abort cancels only that exact identity and holds cancelling', async () => {
    const held = deferred<PcapImportAccepted>()
    upload = () => held.promise
    store.enqueueImports([file('A'), file('B')])
    await flush()
    await store.cancelQueueImport(store.importQueue[0]!.localId)
    jobs.set('real-owner', status('real-owner'))
    held.resolve(accepted('real-owner'))
    await flush()
    expect(calls.filter((c) => c.url.endsWith('/cancel')).map((c) => c.url)).toEqual([`${BASE}/real-owner/cancel`])
    expect(store.importQueue[0]?.status?.state).toBe('cancelling')
    expect(names()).toEqual(['A'])
  })

  it('Q24 built-in reset retains owned File bytes and rows while stopping late asynchronous writes', async () => {
    const held = deferred<PcapImportAccepted>()
    upload = () => held.promise
    store.enqueueImports([file('A'), file('B')])
    await flush()
    store.$reset()
    const before = JSON.stringify(store.importQueue)
    expect(store.importQueue).toHaveLength(2)
    expect(store.importQueue[0]?.uploadState).toBe('uncertain')
    expect(store.importQueue[1]?.file?.name).toBe('B')
    held.resolve(accepted('late'))
    await flush()
    await advance(60000)
    expect(JSON.stringify(store.importQueue)).toBe(before)
    expect(names()).toEqual(['A'])
  })

  it('Q25 possible-acceptance failure with a genuinely observed ID reconciles only that identity', async () => {
    upload = async () => {
      jobs.set('observed', status('observed'))
      throw { status: 502, display_id: 'observed', message: 'response interrupted after identity was observed' }
    }
    store.enqueueImports([file('A'), file('B')])
    await flush()
    await advance()
    expect(reads('observed').length).toBeGreaterThan(0)
    expect(store.importQueue[0]?.status?.display_id).toBe('observed')
    expect(names()).toEqual(['A'])
    expect(calls.some((c) => c.url.endsWith('/cancel'))).toBe(false)
  })
})
