/**
 * Unit tests for the useJobStream composable.
 *
 * Validates the per-job SSE lifecycle: URL resolution (static + Ref + null),
 * event dispatch with JSON parsing, the in-memory event log cap and FIFO
 * eviction, ``latestProgress`` shortcut, reconnect backoff and exhaustion,
 * manual ``connect`` / ``close`` controls, and URL retargeting (closing the
 * previous stream and opening a new one). Uses a MockEventSource similar
 * to the existing tests/composables/useSse.test.ts pattern.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { effectScope, isRef, nextTick, ref, watch } from 'vue'

vi.stubGlobal('ref', ref)
vi.stubGlobal('isRef', isRef)
vi.stubGlobal('watch', watch)

type EventSourceListener = (event: MessageEvent) => void

class MockEventSource {
  static instances: MockEventSource[] = []
  static CLOSED = 2

  url: string
  readyState = 0
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
    this.readyState = 2
  }

  simulateOpen(): void {
    this.readyState = 1
    if (this.onopen) this.onopen(new Event('open'))
  }

  /**
   * Simulate a transient error that puts the source into CLOSED state,
   * which is the precondition for the composable's reconnect logic.
   */
  simulateClosedError(): void {
    this.readyState = 2
    if (this.onerror) this.onerror(new Event('error'))
  }

  /**
   * Simulate a transient error WITHOUT closing the source — the composable
   * should NOT trigger reconnect in this case.
   */
  simulateTransientError(): void {
    if (this.onerror) this.onerror(new Event('error'))
  }

  simulateMessage(type: string, data: unknown): void {
    const event = new MessageEvent(type, {
      data: typeof data === 'string' ? data : JSON.stringify(data),
    })
    const listeners = this.listeners.get(type) ?? []
    for (const listener of listeners) {
      listener(event)
    }
  }

  getListeners(type: string): EventSourceListener[] {
    return this.listeners.get(type) ?? []
  }
}

vi.stubGlobal('EventSource', MockEventSource)

const { useJobStream } = await import('~/composables/useJobStream')

function latestInstance(): MockEventSource {
  const last = MockEventSource.instances[MockEventSource.instances.length - 1]
  if (!last) throw new Error('expected at least one MockEventSource instance')
  return last
}

describe('useJobStream', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    MockEventSource.instances = []
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  describe('connection', () => {
    it('opens an EventSource against a static URL', () => {
      const { status } = useJobStream({ url: '/api/v1/scans/abc/events' })

      expect(MockEventSource.instances).toHaveLength(1)
      expect(latestInstance().url).toBe('/api/v1/scans/abc/events')
      expect(status.value).toBe('connecting')
    })

    it('transitions status to open on EventSource.onopen', () => {
      const { status } = useJobStream({ url: '/api/v1/scans/abc/events' })

      latestInstance().simulateOpen()

      expect(status.value).toBe('open')
    })

    it('stays idle when url is null', () => {
      const { status } = useJobStream({ url: null })

      expect(MockEventSource.instances).toHaveLength(0)
      expect(status.value).toBe('idle')
    })

    it('stays idle when url ref is null', () => {
      const url = ref<string | null>(null)
      const { status } = useJobStream({ url })

      expect(MockEventSource.instances).toHaveLength(0)
      expect(status.value).toBe('idle')
    })

    it('opens when url ref transitions from null to a URL', async () => {
      const url = ref<string | null>(null)
      useJobStream({ url })

      expect(MockEventSource.instances).toHaveLength(0)

      url.value = '/api/v1/scans/xyz/events'
      await nextTick()

      expect(MockEventSource.instances).toHaveLength(1)
      expect(latestInstance().url).toBe('/api/v1/scans/xyz/events')
    })
  })

  describe('event handling', () => {
    it('invokes onEvent with JSON-parsed payloads for progress', () => {
      const onEvent = vi.fn()
      useJobStream({
        url: '/api/v1/scans/abc/events',
        onEvent,
      })
      const instance = latestInstance()
      instance.simulateOpen()

      instance.simulateMessage('progress', { percent: 42, module: 'arp_scan' })

      expect(onEvent).toHaveBeenCalledTimes(1)
      expect(onEvent).toHaveBeenCalledWith('progress', {
        percent: 42,
        module: 'arp_scan',
      })
    })

    it('updates latestProgress on progress events', () => {
      const { latestProgress } = useJobStream({
        url: '/api/v1/scans/abc/events',
      })
      const instance = latestInstance()
      instance.simulateOpen()

      instance.simulateMessage('progress', { percent: 73 })

      expect(latestProgress.value).toEqual({ percent: 73 })
    })

    it('appends events to the log in order', () => {
      const { events } = useJobStream({ url: '/api/v1/scans/abc/events' })
      const instance = latestInstance()
      instance.simulateOpen()

      instance.simulateMessage('progress', { percent: 10 })
      instance.simulateMessage('progress', { percent: 50 })
      instance.simulateMessage('result', { ok: true })

      expect(events.value.map((e) => e.type)).toEqual(['progress', 'progress', 'result'])
      expect(events.value[2]?.data).toEqual({ ok: true })
    })

    it('caps events at 200 entries via FIFO eviction', () => {
      const { events } = useJobStream({ url: '/api/v1/scans/abc/events' })
      const instance = latestInstance()
      instance.simulateOpen()

      for (let i = 0; i < 250; i += 1) {
        instance.simulateMessage('progress', { percent: i })
      }

      expect(events.value).toHaveLength(200)
      // FIFO: oldest entries dropped; latest 200 remain.
      const first = events.value[0]
      const last = events.value[events.value.length - 1]
      expect((first?.data as { percent: number }).percent).toBe(50)
      expect((last?.data as { percent: number }).percent).toBe(249)
    })

    it('falls back to {type, raw} for non-JSON payloads', () => {
      const onEvent = vi.fn()
      useJobStream({ url: '/api/v1/scans/abc/events', onEvent })
      const instance = latestInstance()
      instance.simulateOpen()

      const listeners = instance.getListeners('progress')
      const evt = new MessageEvent('progress', { data: 'not-json' })
      for (const listener of listeners) listener(evt)

      expect(onEvent).toHaveBeenCalledWith('progress', {
        type: 'progress',
        raw: 'not-json',
      })
    })

    it('ignores dataless "error" events (browser auto-reconnect) — F-OE2 regression', () => {
      // After the SSE server closes the stream (e.g. after a successful
      // ``result`` frame), browsers fire a built-in ``error`` event on
      // the EventSource. That event is a plain ``Event`` with no
      // ``data`` payload and must NOT be forwarded as a semantic SSE
      // ``error`` event — otherwise the consumer renders a phantom
      // "error: undefined" entry after every successful scan.
      const onEvent = vi.fn()
      const { events } = useJobStream({
        url: '/api/v1/scans/abc/events',
        onEvent,
      })
      const instance = latestInstance()
      instance.simulateOpen()

      // Simulate browser-generated error event (no data).
      const listeners = instance.getListeners('error')
      const browserErr = new Event('error') as unknown as MessageEvent
      for (const listener of listeners) listener(browserErr)

      expect(onEvent).not.toHaveBeenCalled()
      expect(events.value).toHaveLength(0)
    })

    it('still forwards "error" events that carry a payload', () => {
      // The otalon-api proxy emits ``event: error`` with a JSON
      // body on upstream disconnect. Those semantic frames MUST still
      // reach the consumer.
      const onEvent = vi.fn()
      useJobStream({ url: '/api/v1/scans/abc/events', onEvent })
      const instance = latestInstance()
      instance.simulateOpen()

      instance.simulateMessage('error', { reason: 'upstream_status', status: 500 })

      expect(onEvent).toHaveBeenCalledWith('error', {
        reason: 'upstream_status',
        status: 500,
      })
    })

    it('subscribes to additional knownEventTypes', () => {
      const onEvent = vi.fn()
      useJobStream({
        url: '/api/v1/scans/abc/events',
        knownEventTypes: ['custom_event'],
        onEvent,
      })
      const instance = latestInstance()
      instance.simulateOpen()

      instance.simulateMessage('custom_event', { foo: 'bar' })

      expect(onEvent).toHaveBeenCalledWith('custom_event', { foo: 'bar' })
    })
  })

  describe('reconnection', () => {
    it('reconnects on CLOSED-state error using the first backoff delay', () => {
      useJobStream({
        url: '/api/v1/scans/abc/events',
        reconnectDelaysMs: [1000, 2500],
      })
      const first = latestInstance()
      first.simulateOpen()
      expect(MockEventSource.instances).toHaveLength(1)

      first.simulateClosedError()
      expect(MockEventSource.instances).toHaveLength(1)

      vi.advanceTimersByTime(1000)
      expect(MockEventSource.instances).toHaveLength(2)
      expect(latestInstance().url).toBe('/api/v1/scans/abc/events')
    })

    it('does not reconnect on a transient (non-CLOSED) error', () => {
      useJobStream({ url: '/api/v1/scans/abc/events' })
      const instance = latestInstance()
      instance.simulateOpen()

      instance.simulateTransientError()
      vi.advanceTimersByTime(60_000)

      expect(MockEventSource.instances).toHaveLength(1)
    })

    it('sets status to error after backoff exhaustion', () => {
      const { status } = useJobStream({
        url: '/api/v1/scans/abc/events',
        reconnectDelaysMs: [10, 20],
      })

      // Force three closed errors — backoff has two entries, the third
      // must transition status to 'error' and stop retrying.
      let inst = latestInstance()
      inst.simulateClosedError()
      vi.advanceTimersByTime(10)

      inst = latestInstance()
      inst.simulateClosedError()
      vi.advanceTimersByTime(20)

      inst = latestInstance()
      inst.simulateClosedError()
      // No more entries left → status flips to 'error'.

      expect(status.value).toBe('error')
      const beforeCount = MockEventSource.instances.length
      vi.advanceTimersByTime(60_000)
      expect(MockEventSource.instances).toHaveLength(beforeCount)
    })
  })

  describe('manual controls', () => {
    it('close() tears down the EventSource and sets status to closed', () => {
      const { close, status } = useJobStream({ url: '/api/v1/scans/abc/events' })
      const instance = latestInstance()
      instance.simulateOpen()

      close()

      expect(instance.readyState).toBe(2)
      expect(status.value).toBe('closed')
    })

    it('close() cancels a pending reconnect', () => {
      const { close } = useJobStream({
        url: '/api/v1/scans/abc/events',
        reconnectDelaysMs: [1000],
      })
      const first = latestInstance()
      first.simulateOpen()
      first.simulateClosedError()

      close()
      vi.advanceTimersByTime(5000)

      expect(MockEventSource.instances).toHaveLength(1)
    })

    it('connect() reopens after a manual close', () => {
      const { close, connect } = useJobStream({
        url: '/api/v1/scans/abc/events',
      })
      close()
      expect(MockEventSource.instances).toHaveLength(1)

      connect()

      expect(MockEventSource.instances).toHaveLength(2)
    })
  })

  describe('url retargeting', () => {
    it('closes the previous stream and opens a new one when url ref changes', async () => {
      const url = ref<string | null>('/api/v1/scans/abc/events')
      useJobStream({ url })
      const first = latestInstance()
      first.simulateOpen()

      url.value = '/api/v1/scans/xyz/events'
      await nextTick()

      expect(MockEventSource.instances).toHaveLength(2)
      expect(first.readyState).toBe(2)
      expect(latestInstance().url).toBe('/api/v1/scans/xyz/events')
    })

    it('closes the stream when url ref becomes null', async () => {
      const url = ref<string | null>('/api/v1/scans/abc/events')
      const { status } = useJobStream({ url })
      const first = latestInstance()
      first.simulateOpen()

      url.value = null
      await nextTick()

      expect(first.readyState).toBe(2)
      expect(status.value).toBe('idle')
    })
  })

  describe('lifecycle', () => {
    it('cleans up the EventSource when the effect scope is disposed', () => {
      const scope = effectScope()
      let instance: MockEventSource | null = null
      scope.run(() => {
        useJobStream({ url: '/api/v1/scans/abc/events' })
        instance = latestInstance()
        instance.simulateOpen()
      })

      expect(instance).not.toBeNull()
      expect((instance as unknown as MockEventSource).readyState).toBe(1)

      scope.stop()

      expect((instance as unknown as MockEventSource).readyState).toBe(2)
    })
  })
})
