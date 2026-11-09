/**
 * Unit tests for the useCveLookupSse composable.
 *
 * Validates the live SSE subscription lifecycle for CVE-lookup jobs:
 * connecting to the per-job events endpoint, collecting progress events,
 * recording the terminal done/failed event, and — critically — the
 * robust reconnect behaviour that fixes the UI-051 live defect. A
 * transient ``onerror`` with ``readyState === CONNECTING`` (not CLOSED)
 * must still schedule a reconnect so the terminal event arriving ~20s
 * later (replayed by the upstream) is not missed. Uses a MockEventSource
 * to simulate browser EventSource behaviour in the happy-dom environment.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { ref, watch } from 'vue'

vi.mock('vue', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vue')>()
  return { ...actual, onBeforeUnmount: vi.fn() }
})

vi.stubGlobal('ref', ref)
vi.stubGlobal('watch', watch)

/**
 * Mock the REST API client so the terminal-reconcile fallback
 * (UI-019) can be driven deterministically. ``apiGet`` is the spy the
 * reconcile path hits via ``useApi().get`` after the live stream drops
 * without a terminal frame.
 */
const apiGet = vi.fn()
vi.mock('~/composables/useApi', () => ({
  useApi: () => ({ get: apiGet, post: vi.fn(), patch: vi.fn(), del: vi.fn() }),
}))

type EventSourceListener = (event: MessageEvent) => void

const CONNECTING = 0
const OPEN = 1
const CLOSED = 2

class MockEventSource {
  static instances: MockEventSource[] = []
  static readonly CONNECTING = CONNECTING
  static readonly OPEN = OPEN
  static readonly CLOSED = CLOSED

  url: string
  readyState: number = CONNECTING
  onopen: ((event: Event) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null

  private listeners: Map<string, EventSourceListener[]> = new Map()

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: EventSourceListener): void {
    const existing = this.listeners.get(type) ?? []
    existing.push(listener)
    this.listeners.set(type, existing)
  }

  removeEventListener(type: string, listener: EventSourceListener): void {
    const existing = this.listeners.get(type) ?? []
    this.listeners.set(
      type,
      existing.filter((l) => l !== listener),
    )
  }

  close(): void {
    this.readyState = CLOSED
  }

  simulateOpen(): void {
    this.readyState = OPEN
    if (this.onopen) this.onopen(new Event('open'))
  }

  /** Fire onerror leaving readyState as-is (default CONNECTING) to model a transient proxy error. */
  simulateError(readyState: number = CONNECTING): void {
    this.readyState = readyState
    if (this.onerror) this.onerror(new Event('error'))
  }

  simulateMessage(type: string, data: unknown): void {
    const event = new MessageEvent(type, {
      data: typeof data === 'string' ? data : JSON.stringify(data),
    })
    const listeners = this.listeners.get(type) ?? []
    for (const listener of listeners) listener(event)
  }

  getListeners(type: string): EventSourceListener[] {
    return this.listeners.get(type) ?? []
  }
}

vi.stubGlobal('EventSource', MockEventSource)

const { useCveLookupSse } = await import('~/composables/useCveLookupSse')

function latestInstance(): MockEventSource {
  return MockEventSource.instances[MockEventSource.instances.length - 1]!
}

const REGISTERED_EVENTS = ['progress', 'done', 'failed', 'error', 'ping']

describe('useCveLookupSse', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    MockEventSource.instances = []
    apiGet.mockReset()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  describe('connection', () => {
    it('connects to the per-job events endpoint', () => {
      useCveLookupSse(ref('job-1'))

      expect(MockEventSource.instances).toHaveLength(1)
      expect(latestInstance().url).toBe('/api/v1/vulnerabilities/lookups/job-1/events')
    })

    it('registers all event listeners on connect', () => {
      useCveLookupSse(ref('job-1'))

      const instance = latestInstance()
      for (const evt of REGISTERED_EVENTS) {
        expect(instance.getListeners(evt)).toHaveLength(1)
      }
    })

    it('does not connect when jobId is null', () => {
      useCveLookupSse(ref<string | null>(null))
      expect(MockEventSource.instances).toHaveLength(0)
    })

    it('collects progress events and sets terminalEvent on done (clean single connection)', () => {
      const { progressEvents, terminalEvent } = useCveLookupSse(ref('job-1'))

      const instance = latestInstance()
      instance.simulateOpen()
      instance.simulateMessage('progress', {
        job_id: 'job-1',
        device_id: 7,
        cve_count: 2,
        index: 1,
        total: 1,
      })
      instance.simulateMessage('done', {
        job_id: 'job-1',
        status: 'completed',
        cves_found: 3,
        critical: 1,
      })

      expect(progressEvents.value).toHaveLength(1)
      expect(progressEvents.value[0]).toMatchObject({ device_id: 7, cve_count: 2 })
      expect(terminalEvent.value).toMatchObject({ status: 'completed', cves_found: 3, critical: 1 })
      // Clean terminal closes the stream and must not reconnect.
      expect(instance.readyState).toBe(CLOSED)
      vi.advanceTimersByTime(60_000)
      expect(MockEventSource.instances).toHaveLength(1)
    })
  })

  describe('robust reconnect (UI-051 live defect)', () => {
    it('reconnects after a transient onerror with readyState CONNECTING (not CLOSED)', () => {
      useCveLookupSse(ref('job-1'))

      const first = latestInstance()
      first.simulateOpen()
      // Transient proxy error: stream is in CONNECTING, NOT CLOSED.
      first.simulateError(CONNECTING)

      expect(MockEventSource.instances).toHaveLength(1)
      vi.advanceTimersByTime(1000)
      expect(MockEventSource.instances).toHaveLength(2)
    })

    it('reconnects after an onerror with readyState CLOSED', () => {
      useCveLookupSse(ref('job-1'))

      latestInstance().simulateOpen()
      latestInstance().simulateError(CLOSED)

      vi.advanceTimersByTime(1000)
      expect(MockEventSource.instances).toHaveLength(2)
    })

    it('delivers the terminal done on the second connection and sets terminalEvent exactly once', () => {
      const { terminalEvent } = useCveLookupSse(ref('job-1'))

      // First connection opens, then dies transiently before the terminal frame.
      const first = latestInstance()
      first.simulateOpen()
      first.simulateError(CONNECTING)
      expect(terminalEvent.value).toBeNull()

      // Reconnect fires; upstream replays history and re-delivers done ~20s later.
      vi.advanceTimersByTime(1000)
      expect(MockEventSource.instances).toHaveLength(2)
      const second = latestInstance()
      // Listeners must be re-registered on the new connection.
      for (const evt of REGISTERED_EVENTS) {
        expect(second.getListeners(evt)).toHaveLength(1)
      }
      second.simulateOpen()
      second.simulateMessage('done', {
        job_id: 'job-1',
        status: 'completed',
        cves_found: 0,
        critical: 0,
      })

      const terminalAfterFirstDone = terminalEvent.value
      expect(terminalAfterFirstDone).toMatchObject({ status: 'completed', cves_found: 0 })
      expect(second.readyState).toBe(CLOSED)

      // A duplicate done delivered across the reconnect must not re-set the ref.
      second.simulateMessage('done', {
        job_id: 'job-1',
        status: 'completed',
        cves_found: 0,
        critical: 0,
      })
      expect(terminalEvent.value).toBe(terminalAfterFirstDone)
    })

    it('uses exponential backoff across repeated transient errors', () => {
      useCveLookupSse(ref('job-1'))

      latestInstance().simulateOpen()
      latestInstance().simulateError(CONNECTING)
      vi.advanceTimersByTime(1000)
      expect(MockEventSource.instances).toHaveLength(2)

      latestInstance().simulateError(CONNECTING)
      vi.advanceTimersByTime(2499)
      expect(MockEventSource.instances).toHaveLength(2)
      vi.advanceTimersByTime(1)
      expect(MockEventSource.instances).toHaveLength(3)

      latestInstance().simulateError(CONNECTING)
      vi.advanceTimersByTime(4999)
      expect(MockEventSource.instances).toHaveLength(3)
      vi.advanceTimersByTime(1)
      expect(MockEventSource.instances).toHaveLength(4)
    })

    it('does not reconnect after a terminal done even if a late onerror fires', () => {
      const { terminalEvent } = useCveLookupSse(ref('job-1'))

      const instance = latestInstance()
      instance.simulateOpen()
      instance.simulateMessage('done', {
        job_id: 'job-1',
        status: 'completed',
        cves_found: 0,
        critical: 0,
      })
      expect(terminalEvent.value).not.toBeNull()

      // A late stray error after terminal must NOT trigger reconnect.
      instance.simulateError(CLOSED)
      vi.advanceTimersByTime(60_000)
      expect(MockEventSource.instances).toHaveLength(1)
    })

    it('dedupes a duplicate done delivered across a reconnect (terminal handled once)', () => {
      const { terminalEvent } = useCveLookupSse(ref('job-1'))

      const first = latestInstance()
      first.simulateOpen()
      first.simulateMessage('done', {
        job_id: 'job-1',
        status: 'completed',
        cves_found: 5,
        critical: 2,
      })
      const firstTerminal = terminalEvent.value
      expect(firstTerminal).toMatchObject({ cves_found: 5, critical: 2 })

      // The store dedupes by id; the composable must not re-set terminalEvent
      // if a stray duplicate done somehow reaches the (now closed) handler.
      first.simulateMessage('done', {
        job_id: 'job-1',
        status: 'completed',
        cves_found: 5,
        critical: 2,
      })
      expect(terminalEvent.value).toBe(firstTerminal)
    })

    it('does not reconnect after close() is called explicitly', () => {
      const { close } = useCveLookupSse(ref('job-1'))

      const instance = latestInstance()
      instance.simulateOpen()
      close()
      // An error after explicit close must not reconnect.
      instance.simulateError(CONNECTING)
      vi.advanceTimersByTime(60_000)
      expect(MockEventSource.instances).toHaveLength(1)
    })
  })

  describe('terminal reconcile fallback (UI-019 shared-queue consumer race)', () => {
    it('synthesises the done terminal from REST when the stream ends without a terminal frame', async () => {
      // Live failure mode: the per-job asyncio.Queue terminal frame was
      // consumed by a sibling EventSource, so THIS stream errors/closes
      // without ever delivering `done`. The REST reconcile must fire the
      // toast from the persisted job state.
      apiGet.mockResolvedValue({
        status: 'completed',
        summary: { cves_found: 4, critical: 2 },
      })

      const { terminalEvent } = useCveLookupSse(ref('job-1'))
      const first = latestInstance()
      first.simulateOpen()
      // Stream drops with NO terminal frame ever delivered to this client.
      first.simulateError(CLOSED)
      expect(terminalEvent.value).toBeNull()

      // Reconcile fires after RECONCILE_DELAY_MS (1500ms); the awaited
      // REST get resolves on the microtask flush between fake timers.
      await vi.advanceTimersByTimeAsync(1500)

      expect(apiGet).toHaveBeenCalledWith('/api/v1/vulnerabilities/lookups/job-1')
      expect(terminalEvent.value).toMatchObject({
        status: 'completed',
        cves_found: 4,
        critical: 2,
      })
    })

    it('synthesises the failed terminal from REST when the stream drops on a failed job', async () => {
      apiGet.mockResolvedValue({ status: 'failed', error: 'scan crashed' })

      const { terminalEvent } = useCveLookupSse(ref('job-1'))
      const first = latestInstance()
      first.simulateOpen()
      first.simulateError(CLOSED)
      expect(terminalEvent.value).toBeNull()

      await vi.advanceTimersByTimeAsync(1500)

      expect(terminalEvent.value).toMatchObject({ status: 'failed', error: 'scan crashed' })
    })

    it('does not synthesise a terminal while the job is still running', async () => {
      apiGet.mockResolvedValue({ status: 'running', summary: null })

      const { terminalEvent } = useCveLookupSse(ref('job-1'))
      latestInstance().simulateOpen()
      latestInstance().simulateError(CLOSED)

      await vi.advanceTimersByTimeAsync(1500)

      expect(apiGet).toHaveBeenCalledTimes(1)
      expect(terminalEvent.value).toBeNull()
    })

    it('synthesises the terminal via the connected-watchdog poll while the stream stays OPEN (ping-only, never errors)', async () => {
      // The decisive live failure mode: a sibling EventSource drained the
      // terminal frame from the shared queue, so THIS stream stays OPEN and
      // only receives pings — onerror never fires, so the error-path
      // reconcile alone can never recover. The connected watchdog must poll
      // the REST header and synthesise the terminal once the backend
      // records it.
      apiGet
        .mockResolvedValueOnce({ status: 'running', summary: null })
        .mockResolvedValue({ status: 'completed', summary: { cves_found: 7, critical: 3 } })

      const { terminalEvent } = useCveLookupSse(ref('job-1'))
      const instance = latestInstance()
      instance.simulateOpen()
      // Stream stays OPEN; no terminal frame, no error — only the watchdog
      // poll can recover. First poll (5s) sees running, second poll sees
      // completed.
      await vi.advanceTimersByTimeAsync(5000)
      expect(terminalEvent.value).toBeNull()
      await vi.advanceTimersByTimeAsync(5000)

      expect(apiGet).toHaveBeenCalledWith('/api/v1/vulnerabilities/lookups/job-1')
      expect(terminalEvent.value).toMatchObject({ status: 'completed', cves_found: 7, critical: 3 })
      // Terminal closes the stream and stops the poll.
      expect(instance.readyState).toBe(CLOSED)
      const callsAtTerminal = apiGet.mock.calls.length
      await vi.advanceTimersByTimeAsync(20_000)
      expect(apiGet.mock.calls.length).toBe(callsAtTerminal)
    })

    it('does not reconcile via REST when the terminal frame did arrive on the live stream', async () => {
      const { terminalEvent } = useCveLookupSse(ref('job-1'))
      const instance = latestInstance()
      instance.simulateOpen()
      instance.simulateMessage('done', {
        job_id: 'job-1',
        status: 'completed',
        cves_found: 1,
        critical: 0,
      })
      expect(terminalEvent.value).toMatchObject({ status: 'completed', cves_found: 1 })

      // Even if a late error fires, no reconcile fetch must happen.
      instance.simulateError(CLOSED)
      await vi.advanceTimersByTimeAsync(60_000)
      expect(apiGet).not.toHaveBeenCalled()
    })
  })

  describe('failed terminal', () => {
    it('records a failed terminal event and stops reconnecting', () => {
      const { terminalEvent } = useCveLookupSse(ref('job-1'))

      const instance = latestInstance()
      instance.simulateOpen()
      instance.simulateMessage('failed', {
        job_id: 'job-1',
        status: 'failed',
        error: 'boom',
      })

      expect(terminalEvent.value).toMatchObject({ status: 'failed', error: 'boom' })
      instance.simulateError(CONNECTING)
      vi.advanceTimersByTime(60_000)
      expect(MockEventSource.instances).toHaveLength(1)
    })
  })
})
