/** Deterministic XHR seam only; no live browser, network, or persistence evidence. */
import { createPinia, disposePinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  toRejection,
  usePcapImport,
  type PcapImportAccepted,
  type PcapImportState,
  type PcapImportStatus,
  type UploadCaptureProgress,
} from '~/composables/usePcapImport'
import { useDataSourcesStore } from '~/stores/dataSourcesStore'

const BASE = '/api/v1/operations/pcap-import'
const XHR_EVENTS = ['readystatechange', 'load', 'error', 'timeout', 'abort', 'loadend']

/** Track listener identity while retaining normal EventTarget dispatch semantics. */
class TrackedTarget extends EventTarget {
  listeners = new Map<string, Set<EventListenerOrEventListenerObject>>()

  override addEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject | null,
    options?: boolean | AddEventListenerOptions,
  ): void {
    if (listener) {
      const owned = this.listeners.get(type) ?? new Set()
      owned.add(listener)
      this.listeners.set(type, owned)
    }
    super.addEventListener(type, listener, options)
  }

  override removeEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject | null,
    options?: boolean | EventListenerOptions,
  ): void {
    if (listener) this.listeners.get(type)?.delete(listener)
    super.removeEventListener(type, listener, options)
  }

  get listenerCount(): number {
    return [...this.listeners.values()].reduce((sum, listeners) => sum + listeners.size, 0)
  }

  emit(type: string): void {
    this.dispatchEvent(new Event(type))
  }
}

/** The production client constructs this declared unit seam, not an injected transport. */
class FakeXHR extends TrackedTarget {
  static instances: FakeXHR[] = []
  static failAt: 'constructor' | 'open' | 'send' | null = null
  static onOpen: (() => void) | null = null
  static onSend: ((xhr: FakeXHR) => void) | null = null
  upload = new TrackedTarget()
  readyState = 0
  status = 0
  statusText = ''
  responseText = ''
  withCredentials = false
  responseType = ''
  timeout = 0
  method: string | null = null
  url: string | null = null
  async: boolean | undefined
  body: Document | XMLHttpRequestBodyInit | null = null
  headers: [string, string][] = []
  sendCount = 0
  abortCount = 0
  listenersAtSend: string[] = []

  constructor() {
    super()
    if (FakeXHR.failAt === 'constructor') throw new Error('constructor refused')
    FakeXHR.instances.push(this)
  }

  open(method: string, url: string, async?: boolean): void {
    if (FakeXHR.failAt === 'open') throw new Error('open refused')
    this.method = method
    this.url = url
    this.async = async
    this.readyState = 1
    this.emit('readystatechange')
    FakeXHR.onOpen?.()
  }

  setRequestHeader(name: string, value: string): void {
    this.headers.push([name, value])
  }

  send(body?: Document | XMLHttpRequestBodyInit | null): void {
    this.sendCount++
    this.body = body ?? null
    this.listenersAtSend = [...this.listeners.entries()].filter(([, listeners]) => listeners.size).map(([type]) => type)
    if (FakeXHR.failAt === 'send') throw new Error('send refused')
    FakeXHR.onSend?.(this)
  }

  /** Browser abort discards observable response state and emits abort then loadend. */
  abort(): void {
    this.abortCount++
    this.status = 0
    this.responseText = ''
    this.readyState = 0
    this.emit('abort')
    this.emit('loadend')
  }

  complete(code: number, body: string, statusText = ''): void {
    this.observe(code, body, 4, statusText)
    this.emit('load')
    this.emit('loadend')
  }

  observe(code: number, body: string, readyState = 4, statusText = ''): void {
    this.status = code
    this.statusText = statusText
    this.responseText = body
    this.readyState = readyState
    this.emit('readystatechange')
  }

  progress(values: { lengthComputable?: unknown; loaded?: unknown; total?: unknown }): void {
    const event = new Event('progress')
    for (const [key, value] of Object.entries(values)) Object.defineProperty(event, key, { value })
    this.upload.dispatchEvent(event)
  }
}

function capture(name = 'selected.pcap'): File {
  return new File([new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1, 7])], name, { lastModified: 123 })
}

function accepted(state: PcapImportState = 'running', id = 'J-observed'): PcapImportAccepted {
  return {
    display_id: id,
    job_id: 41,
    state,
    filename: 'stored-uuid.pcap',
    original_filename: 'selected.pcap',
    size_bytes: 5,
    sha256: 'a'.repeat(64),
    time_start: '2026-01-01T00:00:00Z',
    time_end: '2026-01-01T00:01:00Z',
    forced: false,
    delivered: false,
  }
}

function status(state: PcapImportState = 'running', id = 'J-observed'): PcapImportStatus {
  return {
    display_id: id,
    job_id: 41,
    state,
    phase_current: null,
    phase_total: null,
    phase_label: null,
    latest_event: null,
    original_filename: 'selected.pcap',
    size_bytes: 5,
    time_start: null,
    time_end: null,
    forced: false,
    started_at: null,
    ended_at: null,
    error: null,
    result: null,
  }
}

function lastXHR(): FakeXHR {
  expect(FakeXHR.instances.length).toBeGreaterThan(0)
  return FakeXHR.instances[FakeXHR.instances.length - 1]!
}

async function flush(): Promise<void> {
  for (let i = 0; i < 80; i++) await Promise.resolve()
}

function signalTracking(controller: AbortController) {
  return {
    add: vi.spyOn(controller.signal, 'addEventListener'),
    remove: vi.spyOn(controller.signal, 'removeEventListener'),
  }
}

function expectCleanup(xhr: FakeXHR, tracking: ReturnType<typeof signalTracking>): void {
  expect(xhr.listenerCount).toBe(0)
  expect(xhr.upload.listenerCount).toBe(0)
  expect(tracking.add.mock.calls).toHaveLength(tracking.remove.mock.calls.length)
  for (const [type, listener] of tracking.add.mock.calls) {
    expect(
      tracking.remove.mock.calls.some(([removedType, removed]) => removedType === type && removed === listener),
    ).toBe(true)
  }
}

let pinia: ReturnType<typeof createPinia>
let store: ReturnType<typeof useDataSourcesStore> | null
let fetchCalls: { url: string; options: { method?: string; query?: { state?: PcapImportState; limit?: number } } }[]
let jobs: Map<string, PcapImportStatus>

beforeEach(() => {
  vi.useFakeTimers()
  FakeXHR.instances = []
  FakeXHR.failAt = null
  FakeXHR.onOpen = null
  FakeXHR.onSend = null
  vi.stubGlobal('XMLHttpRequest', FakeXHR)
  fetchCalls = []
  jobs = new Map()
  vi.stubGlobal('$fetch', async (url: string, options: (typeof fetchCalls)[number]['options'] = {}) => {
    fetchCalls.push({ url, options })
    if (url === BASE && options.method === 'POST') throw new Error('Upload must use XHR, never $fetch')
    if (url === BASE) {
      const items = [...jobs.values()].filter((job) => !options.query?.state || job.state === options.query.state)
      return { items, total: items.length }
    }
    const id = decodeURIComponent(url.slice(BASE.length + 1).replace(/\/cancel$/, ''))
    if (url.endsWith('/cancel')) jobs.set(id, status('cancelling', id))
    const job = jobs.get(id)
    if (!job) throw { status: 404, detail: 'Import job not found' }
    return job
  })
  pinia = createPinia()
  setActivePinia(pinia)
  store = null
})

afterEach(async () => {
  store?.$dispose()
  disposePinia(pinia)
  for (const xhr of FakeXHR.instances) xhr.abort()
  await flush()
  vi.clearAllTimers()
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  setActivePinia(undefined)
})

describe('training single-file XHR transport', () => {
  it.each([undefined, false, true])('T01 browser multipart reference and explicit force=%s only', async (force) => {
    const file = capture()
    const append = vi.spyOn(FormData.prototype, 'append')
    const arrayBuffer = vi.spyOn(file, 'arrayBuffer').mockRejectedValue(new Error('No file buffering'))
    const text = vi.spyOn(file, 'text').mockRejectedValue(new Error('No file reading'))
    const reader = vi.fn(() => {
      throw new Error('No FileReader')
    })
    vi.stubGlobal('FileReader', reader)
    const promise = usePcapImport().uploadCapture(file, { force })
    const xhr = lastXHR()
    expect(xhr.method).toBe('POST')
    expect(xhr.url).toBe(BASE)
    expect(xhr.async).toBe(true)
    expect(xhr.sendCount).toBe(1)
    expect(xhr.body).toBeInstanceOf(FormData)
    expect(append.mock.calls[0]).toEqual(['file', file, file.name])
    const form = xhr.body as FormData
    expect([...form.keys()]).toEqual(force === true ? ['file', 'force'] : ['file'])
    expect(form.get('force')).toBe(force === true ? 'true' : null)
    const part = form.get('file') as File
    expect(part.name).toBe(file.name)
    expect(part.size).toBe(file.size)
    expect(xhr.headers).toEqual([])
    expect(xhr.withCredentials).toBe(false)
    expect(fetchCalls).toEqual([])
    expect(arrayBuffer).not.toHaveBeenCalled()
    expect(text).not.toHaveBeenCalled()
    expect(reader).not.toHaveBeenCalled()
    xhr.complete(201, JSON.stringify(accepted()))
    await expect(promise).resolves.toEqual(accepted())
    expect(xhr.listenerCount + xhr.upload.listenerCount).toBe(0)
  })

  it.each(['queued', 'running', 'cancelling', 'completed', 'failed', 'cancelled', 'rejected'] as const)(
    'T02 preserves actual %s acceptance without fabricating completion or fields',
    async (state) => {
      const promise = usePcapImport().uploadCapture(capture())
      const envelope = { ...accepted(state), delivered: false, forced: false, extra_observed: 'unchanged' }
      lastXHR().complete(201, JSON.stringify(envelope))
      await expect(promise).resolves.toEqual(envelope)
    },
  )

  it('T03 attaches all owned listeners before send; measured multipart 100% does not settle acceptance', async () => {
    const controller = new AbortController()
    const tracking = signalTracking(controller)
    const progress = vi.fn()
    let settled = 0
    FakeXHR.onSend = (xhr) => {
      expect(tracking.add).toHaveBeenCalled()
      expect(xhr.upload.listenerCount).toBeGreaterThan(0)
      xhr.progress({ lengthComputable: true, loaded: 250, total: 250 })
    }
    const promise = usePcapImport()
      .uploadCapture(capture(), { signal: controller.signal, onUploadProgress: progress })
      .then((value) => {
        settled++
        return value
      })
    const xhr = lastXHR()
    for (const type of XHR_EVENTS) expect(xhr.listenersAtSend).toContain(type)
    expect(progress).toHaveBeenLastCalledWith({ loaded: 250, total: 250 })
    await flush()
    expect(settled).toBe(0)
    xhr.complete(201, JSON.stringify(accepted('queued')))
    await expect(promise).resolves.toEqual(accepted('queued'))
    expect(settled).toBe(1)
    expectCleanup(xhr, tracking)
    xhr.progress({ lengthComputable: true, loaded: 1, total: 1 })
    xhr.complete(201, JSON.stringify(accepted('completed', 'late-other')))
    for (const type of XHR_EVENTS) xhr.emit(type)
    controller.abort()
    expect(progress).toHaveBeenCalledOnce()
    expect(settled).toBe(1)
    expect(xhr.abortCount).toBe(0)
  })

  it.each([
    ['unknown', { lengthComputable: false, loaded: 11, total: 250 }, { loaded: 11, total: null }],
    ['missing', {}, { loaded: null, total: null }],
    ['missing total', { lengthComputable: true, loaded: 11 }, { loaded: 11, total: null }],
    ['zero total', { lengthComputable: true, loaded: 0, total: 0 }, { loaded: 0, total: null }],
    ['NaN loaded', { lengthComputable: true, loaded: NaN, total: 250 }, { loaded: null, total: null }],
    ['infinite total', { lengthComputable: true, loaded: 11, total: Infinity }, { loaded: 11, total: null }],
    ['negative loaded', { lengthComputable: true, loaded: -1, total: 250 }, { loaded: null, total: null }],
    ['infinite loaded', { lengthComputable: true, loaded: Infinity, total: 250 }, { loaded: null, total: null }],
    ['missing loaded', { lengthComputable: true, total: 250 }, { loaded: null, total: null }],
    ['negative total', { lengthComputable: true, loaded: 11, total: -1 }, { loaded: 11, total: null }],
    ['over total', { lengthComputable: true, loaded: 251, total: 250 }, { loaded: 251, total: null }],
    ['string bytes', { lengthComputable: true, loaded: '11', total: '250' }, { loaded: null, total: null }],
    ['truthy not boolean', { lengthComputable: 'true', loaded: 11, total: 250 }, { loaded: 11, total: null }],
  ] as const)('T04 %s measurements stay nullable without file-size substitution', async (_name, values, expected) => {
    const progress = vi.fn<(value: UploadCaptureProgress) => void>()
    const promise = usePcapImport().uploadCapture(capture(), { onUploadProgress: progress })
    const xhr = lastXHR()
    xhr.progress(values)
    expect(progress).toHaveBeenCalledExactlyOnceWith(expected)
    xhr.complete(201, JSON.stringify(accepted()))
    await promise
    expect(xhr.listenerCount + xhr.upload.listenerCount).toBe(0)
  })

  const conflict = {
    message: 'Existing measurements would be overwritten.',
    conflict_start: '2026-01-01T00:00:00Z',
    conflict_end: '2026-01-01T00:01:00Z',
    measurement: 'network_metrics',
  }
  it.each([
    [409, { detail: conflict }, 'conflict', conflict.message],
    [
      413,
      { detail: 'Upload exceeds configured limit of 1073741824 bytes' },
      'too-large',
      'Upload exceeds configured limit of 1073741824 bytes',
    ],
    [422, { detail: [{ msg: 'Not a supported capture', loc: ['body'] }] }, 'unsupported', 'Not a supported capture'],
    [400, { detail: 'Malformed multipart envelope' }, 'malformed', 'Malformed multipart envelope'],
    [401, { detail: 'Authentication required' }, 'unauthorized', 'Authentication required'],
    [403, { detail: 'Insufficient role' }, 'unauthorized', 'Insufficient role'],
    [503, { message: 'Operator proxy is not configured' }, 'unknown', 'Operator proxy is not configured'],
  ] as const)(
    'T05 HTTP %i preserves numeric status and exact JSON detail/message',
    async (code, body, kind, message) => {
      const controller = new AbortController()
      const tracking = signalTracking(controller)
      const progress = vi.fn()
      const failed = usePcapImport()
        .uploadCapture(capture(), { signal: controller.signal, onUploadProgress: progress })
        .catch((error: unknown) => error)
      const xhr = lastXHR()
      xhr.complete(code, JSON.stringify(body))
      const error = await failed
      expect(error).toMatchObject({ status: code, data: body })
      const rejection = toRejection(error)
      expect(rejection).toMatchObject({ status: code, kind, message })
      if (code === 409) expect(rejection.conflict).toEqual(conflict)
      if (code === 413) expect(rejection.limitBytes).toBe(1_073_741_824)
      expectCleanup(xhr, tracking)
      xhr.progress({ lengthComputable: true, loaded: 1, total: 1 })
      xhr.complete(201, JSON.stringify(accepted()))
      controller.abort()
      expect(progress).not.toHaveBeenCalled()
    },
  )

  it.each([
    [
      'HTML',
      '<html><head><title>413 Request Entity Too Large</title></head><body><h1>413 Request Entity Too Large</h1><hr>nginx</body></html>',
    ],
    ['plain', '413 Request Entity Too Large'],
    ['empty', ''],
  ])('T06 %s nginx 413 stays 413 without an invented API payload limit', async (_name, body) => {
    const controller = new AbortController()
    const tracking = signalTracking(controller)
    const failed = usePcapImport()
      .uploadCapture(capture(), { signal: controller.signal })
      .catch((error: unknown) => error)
    const xhr = lastXHR()
    xhr.complete(413, body, 'Request Entity Too Large')
    const rejection = toRejection(await failed)
    expect(rejection).toMatchObject({ kind: 'too-large', status: 413, limitBytes: null })
    expect(rejection.message).toContain('413 Request Entity Too Large')
    expect(rejection.message).not.toContain('1073741824')
    expect(rejection.message).not.toContain('536870912')
    expectCleanup(xhr, tracking)
  })

  it.each([
    ['broken JSON', '{"display_id":"J-partial"'],
    ['opaque HTML', '<html>OK</html>'],
    ['empty', ''],
    ['null', 'null'],
    ['array', '[]'],
    ['string', '"OK"'],
    ['partial identity', '{"display_id":"J-partial"}'],
    ['metadata only', '{"filename":"selected.pcap","size_bytes":5}'],
  ])('T07 successful %s response is uncertain, not proven absence or guessed identity', async (_name, body) => {
    const controller = new AbortController()
    const tracking = signalTracking(controller)
    const failed = usePcapImport()
      .uploadCapture(capture(), { signal: controller.signal })
      .catch((error: unknown) => error)
    const xhr = lastXHR()
    xhr.complete(201, body)
    const error = await failed
    expect(error).toMatchObject({ status: 201, acceptanceUncertain: true })
    expect(error).not.toHaveProperty('display_id')
    expect(toRejection(error).kind).toBe('unknown')
    expect(toRejection(error).message).toMatch(/acceptance.*unverified/i)
    expectCleanup(xhr, tracking)
  })

  it.each(['error', 'timeout', 'abort', 'loadend', 'status0'] as const)(
    'T08 %s promptly settles once as uncertain and cleans every owned listener',
    async (event) => {
      const controller = new AbortController()
      const tracking = signalTracking(controller)
      const progress = vi.fn()
      let settlements = 0
      const failed = usePcapImport()
        .uploadCapture(capture(), { signal: controller.signal, onUploadProgress: progress })
        .catch((error: unknown) => {
          settlements++
          return error
        })
      const xhr = lastXHR()
      if (event === 'status0') xhr.complete(0, '')
      else xhr.emit(event)
      const error = await failed
      expect(error).toMatchObject({ status: 0, acceptanceUncertain: true })
      expect(error).not.toHaveProperty('display_id')
      expect(toRejection(error).message).toMatch(/acceptance.*unverified/i)
      expectCleanup(xhr, tracking)
      for (const type of XHR_EVENTS) xhr.emit(type)
      xhr.complete(201, JSON.stringify(accepted()))
      xhr.progress({ lengthComputable: true, loaded: 5, total: 5 })
      controller.abort()
      await flush()
      expect(settlements).toBe(1)
      expect(progress).not.toHaveBeenCalled()
    },
  )

  it.each(['constructor', 'open', 'send'] as const)(
    'T09 %s failure rejects and detaches owned resources',
    async (stage) => {
      FakeXHR.failAt = stage
      const controller = new AbortController()
      const tracking = signalTracking(controller)
      const failed = usePcapImport()
        .uploadCapture(capture(), { signal: controller.signal })
        .catch((error: unknown) => error)
      const error = await failed
      expect(error).toMatchObject({ status: 0, acceptanceUncertain: true })
      expect(toRejection(error).message).toContain(`${stage} refused`)
      expect(error).not.toHaveProperty('display_id')
      if (stage === 'constructor') expect(FakeXHR.instances).toHaveLength(0)
      else expectCleanup(lastXHR(), tracking)
      expect(tracking.add.mock.calls).toHaveLength(tracking.remove.mock.calls.length)
    },
  )

  it('T10 a pre-aborted signal cannot send any bytes or own lingering listeners', async () => {
    const controller = new AbortController()
    controller.abort()
    const tracking = signalTracking(controller)
    const failed = usePcapImport()
      .uploadCapture(capture(), { signal: controller.signal })
      .catch((error: unknown) => error)
    expect(await failed).toMatchObject({ name: 'AbortError', acceptanceUncertain: true })
    for (const xhr of FakeXHR.instances) {
      expect(xhr.sendCount).toBe(0)
      expectCleanup(xhr, tracking)
    }
    expect(fetchCalls).toEqual([])
  })

  it('T11 in-flight signal abort affects only this XHR and ignores late acceptance/progress', async () => {
    const controller = new AbortController()
    const tracking = signalTracking(controller)
    const progress = vi.fn()
    const failed = usePcapImport()
      .uploadCapture(capture(), { signal: controller.signal, onUploadProgress: progress })
      .catch((error: unknown) => error)
    const xhr = lastXHR()
    const other = usePcapImport().uploadCapture(capture('other.pcap'))
    const otherXHR = lastXHR()
    const unrelated = vi.fn()
    xhr.addEventListener('load', unrelated)
    controller.abort()
    expect(await failed).toMatchObject({ name: 'AbortError', status: 0, acceptanceUncertain: true })
    expect(xhr.abortCount).toBe(1)
    expect(otherXHR.abortCount).toBe(0)
    expect(xhr.listenerCount).toBe(1)
    expect(xhr.upload.listenerCount).toBe(0)
    xhr.complete(201, JSON.stringify(accepted()))
    xhr.progress({ lengthComputable: true, loaded: 5, total: 5 })
    expect(unrelated).toHaveBeenCalledOnce()
    expect(progress).not.toHaveBeenCalled()
    xhr.removeEventListener('load', unrelated)
    expectCleanup(xhr, tracking)
    otherXHR.complete(201, JSON.stringify(accepted('queued', 'J-other')))
    await expect(other).resolves.toEqual(accepted('queued', 'J-other'))
  })

  it('T12 complete observable acceptance wins a near-abort race without losing exact envelope', async () => {
    const controller = new AbortController()
    const tracking = signalTracking(controller)
    const promise = usePcapImport().uploadCapture(capture(), { signal: controller.signal })
    const xhr = lastXHR()
    xhr.observe(201, JSON.stringify(accepted('cancelling')))
    controller.abort()
    await expect(promise).resolves.toEqual(accepted('cancelling'))
    expect(xhr.abortCount).toBe(1)
    expectCleanup(xhr, tracking)
  })

  it.each([
    ['partial bytes', '{"display_id":"J-partial"', 3],
    ['partial envelope', '{"display_id":"J-partial"}', 4],
    ['complete JSON before DONE', JSON.stringify(accepted()), 3],
    ['HTTP refusal identity', JSON.stringify(accepted()), 4, 409],
  ] as const)('T13 %s cannot prove acceptance identity near abort', async (_name, body, readyState, code = 201) => {
    const controller = new AbortController()
    const tracking = signalTracking(controller)
    const failed = usePcapImport()
      .uploadCapture(capture(), { signal: controller.signal })
      .catch((error: unknown) => error)
    const xhr = lastXHR()
    xhr.observe(code, body, readyState)
    controller.abort()
    const error = await failed
    expect(error).toMatchObject({ name: 'AbortError', acceptanceUncertain: true })
    expect(error).not.toHaveProperty('display_id')
    expectCleanup(xhr, tracking)
  })

  it('T14 a genuinely observed acceptance is retained on subsequent response failure evidence', async () => {
    const controller = new AbortController()
    const tracking = signalTracking(controller)
    const failed = usePcapImport()
      .uploadCapture(capture(), { signal: controller.signal })
      .catch((error: unknown) => error)
    const xhr = lastXHR()
    xhr.observe(201, JSON.stringify(accepted()))
    xhr.status = 0
    xhr.responseText = ''
    xhr.emit('error')
    expect(await failed).toMatchObject({
      status: 0,
      acceptanceUncertain: true,
      display_id: 'J-observed',
      accepted: accepted(),
    })
    expectCleanup(xhr, tracking)
  })

  it('T18 signal abort during open cannot reach send and detaches even synchronous listeners', async () => {
    const controller = new AbortController()
    const tracking = signalTracking(controller)
    FakeXHR.onOpen = () => controller.abort()
    const failed = usePcapImport()
      .uploadCapture(capture(), { signal: controller.signal })
      .catch((error: unknown) => error)
    const xhr = lastXHR()
    expect(await failed).toMatchObject({ name: 'AbortError', acceptanceUncertain: true })
    expect(xhr.sendCount).toBe(0)
    expect(xhr.abortCount).toBe(1)
    expectCleanup(xhr, tracking)
  })

  it('T19 status, recent, state list, and exact-ID cancel retain their existing $fetch contract', async () => {
    const id = 'J x/y'
    jobs.set(id, status('running', id))
    await expect(usePcapImport().fetchStatus(id)).resolves.toEqual(status('running', id))
    await expect(usePcapImport().fetchRecent(5)).resolves.toEqual([status('running', id)])
    await expect(usePcapImport().fetchByState('running', 200)).resolves.toEqual({
      items: [status('running', id)],
      total: 1,
    })
    await expect(usePcapImport().cancelImport(id)).resolves.toEqual(status('cancelling', id))
    expect(fetchCalls).toEqual([
      { url: `${BASE}/J%20x%2Fy`, options: {} },
      { url: BASE, options: { query: { limit: 5 } } },
      { url: BASE, options: { query: { limit: 200, state: 'running' } } },
      { url: `${BASE}/J%20x%2Fy/cancel`, options: { method: 'POST' } },
    ])
    expect(FakeXHR.instances).toHaveLength(0)
  })
})

describe('real Pinia queue with declared XHR seam', () => {
  it.each(['queued', 'running', 'cancelling'] as const)(
    'T15 actual %s detail holds second upload until terminal truth',
    async (state) => {
      store = useDataSourcesStore()
      store.enqueueImports([capture(), capture('second.pcap')])
      await flush()
      const xhr = lastXHR()
      xhr.progress({ lengthComputable: true, loaded: 250, total: 250 })
      expect(store.importQueue[0]).toMatchObject({
        uploadState: 'uploading',
        uploadLoaded: 250,
        uploadTotal: 250,
        accepted: null,
      })
      jobs.set('J-observed', status(state))
      xhr.complete(201, JSON.stringify(accepted(state)))
      await flush()
      expect(store.importQueue[0]?.status?.state).toBe(state)
      await vi.advanceTimersByTimeAsync(6000)
      await flush()
      expect(FakeXHR.instances).toHaveLength(1)
      jobs.set('J-observed', status('completed'))
      await vi.advanceTimersByTimeAsync(2000)
      await flush()
      expect(FakeXHR.instances).toHaveLength(2)
      expect((lastXHR().body as FormData).get('file')).toMatchObject({ name: 'second.pcap' })
      lastXHR().complete(422, JSON.stringify({ detail: 'Not a supported capture' }))
      await flush()
      expect(fetchCalls.some((call) => call.url === BASE && call.options.method === 'POST')).toBe(false)
    },
  )

  it('T16 abort with lost ID holds uncertainty despite matching metadata/history and never auto-cancels or resends', async () => {
    store = useDataSourcesStore()
    const file = capture()
    store.enqueueImports([file, capture('second.pcap')])
    await flush()
    const xhr = lastXHR()
    jobs.set('J-unobserved', {
      ...status('completed', 'J-unobserved'),
      original_filename: file.name,
      size_bytes: file.size,
    })
    await store.cancelQueueImport(store.importQueue[0]!.localId)
    await flush()
    xhr.complete(201, JSON.stringify(accepted('running', 'J-unobserved')))
    xhr.progress({ lengthComputable: true, loaded: 5, total: 5 })
    await store.fetchRecentImports()
    await store.refreshImportQueue()
    await vi.advanceTimersByTimeAsync(60000)
    await flush()
    expect(store.importQueue[0]).toMatchObject({
      uploadState: 'uncertain',
      observedDisplayId: null,
      accepted: null,
      file,
      uploadLoaded: null,
      uploadTotal: null,
    })
    expect(store.recentImports[0]?.display_id).toBe('J-unobserved')
    expect(FakeXHR.instances).toHaveLength(1)
    expect(fetchCalls.some((call) => call.url.endsWith('/cancel'))).toBe(false)
  })

  it('T17 near-abort observed acceptance delegates cancellation only to the real store exact-ID owner', async () => {
    store = useDataSourcesStore()
    store.enqueueImports([capture(), capture('second.pcap')])
    await flush()
    jobs.set('J-observed', status())
    jobs.set('J-similar', { ...status('completed', 'J-similar'), original_filename: 'selected.pcap', size_bytes: 5 })
    const xhr = lastXHR()
    xhr.observe(201, JSON.stringify(accepted()))
    await store.cancelQueueImport(store.importQueue[0]!.localId)
    await flush()
    expect(fetchCalls.filter((call) => call.url.endsWith('/cancel')).map((call) => call.url)).toEqual([
      `${BASE}/J-observed/cancel`,
    ])
    expect(store.importQueue[0]).toMatchObject({
      observedDisplayId: 'J-observed',
      accepted: accepted(),
      status: { state: 'cancelling' },
    })
    await vi.advanceTimersByTimeAsync(6000)
    await flush()
    expect(FakeXHR.instances).toHaveLength(1)
    jobs.set('J-observed', status('cancelled'))
    await vi.advanceTimersByTimeAsync(2000)
    await flush()
    expect(FakeXHR.instances).toHaveLength(2)
    lastXHR().complete(400, JSON.stringify({ detail: 'Malformed upload' }))
    await flush()
  })

  it('T20 observed-ID failure reconciles only that owner; explicit cancellation remains store-owned', async () => {
    store = useDataSourcesStore()
    store.enqueueImports([capture(), capture('second.pcap')])
    await flush()
    jobs.set('J-observed', status())
    jobs.set('J-similar', { ...status('completed', 'J-similar'), original_filename: 'selected.pcap', size_bytes: 5 })
    const xhr = lastXHR()
    xhr.observe(201, JSON.stringify(accepted()))
    xhr.status = 0
    xhr.responseText = ''
    xhr.emit('error')
    await flush()
    expect(store.importQueue[0]?.observedDisplayId).toBe('J-observed')
    expect(store.importQueue[0]?.status?.display_id).toBe('J-observed')
    expect(FakeXHR.instances).toHaveLength(1)
    expect(fetchCalls.some((call) => call.url.endsWith('/cancel'))).toBe(false)
    await store.cancelQueueImport(store.importQueue[0]!.localId)
    await flush()
    expect(fetchCalls.filter((call) => call.url.endsWith('/cancel')).map((call) => call.url)).toEqual([
      `${BASE}/J-observed/cancel`,
    ])
    expect(store.importQueue[0]?.status?.state).toBe('cancelling')
    expect(FakeXHR.instances).toHaveLength(1)
  })
})
