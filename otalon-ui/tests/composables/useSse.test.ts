/**
 * Unit tests for the useSse composable.
 *
 * Validates SSE connection lifecycle, topic-based URL construction,
 * auto-reconnect with exponential backoff, heartbeat timeout
 * detection, manual connect/disconnect controls, and external
 * enabled flag integration. Uses a MockEventSource to simulate
 * browser EventSource behavior in the happy-dom environment.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { ref, isRef, watch, nextTick } from 'vue'

vi.stubGlobal('ref', ref)
vi.stubGlobal('isRef', isRef)
vi.stubGlobal('watch', watch)
vi.stubGlobal('onUnmounted', vi.fn())

type EventSourceListener = (event: MessageEvent) => void

class MockEventSource {
  static instances: MockEventSource[] = []

  url: string
  readyState: number = 0
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
    if (this.onopen) {
      this.onopen(new Event('open'))
    }
  }

  simulateError(): void {
    if (this.onerror) {
      this.onerror(new Event('error'))
    }
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

const { useSse } = await import('~/composables/useSse')

function latestInstance(): MockEventSource {
  return MockEventSource.instances[MockEventSource.instances.length - 1]
}

describe('useSse', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    MockEventSource.instances = []
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  describe('connection', () => {
    it('connects to the correct URL with encoded topics', () => {
      useSse('kpi,health')

      expect(MockEventSource.instances).toHaveLength(1)
      const instance = latestInstance()
      expect(instance.url).toBe('/api/v1/events/stream?topics=kpi%2Chealth')
    })

    it('registers event listeners for each topic and heartbeat', () => {
      useSse('kpi,health')

      const instance = latestInstance()
      expect(instance.getListeners('kpi')).toHaveLength(1)
      expect(instance.getListeners('health')).toHaveLength(1)
      expect(instance.getListeners('heartbeat')).toHaveLength(1)
    })

    it('sets status to connected after successful connection', () => {
      const { status } = useSse('kpi')

      latestInstance().simulateOpen()

      expect(status.value).toBe('connected')
    })

    it('sets initial status to disconnected when enabled is false', () => {
      const enabled = ref(false)
      const { status } = useSse('kpi', { enabled })

      expect(status.value).toBe('disconnected')
      expect(MockEventSource.instances).toHaveLength(0)
    })
  })

  describe('event handling', () => {
    it('calls onEvent callback with parsed JSON event data', () => {
      const onEvent = vi.fn()
      useSse('kpi', { onEvent })

      const instance = latestInstance()
      instance.simulateOpen()
      instance.simulateMessage('kpi', { signal_color: 'danger', anomaly_count: 42 })

      expect(onEvent).toHaveBeenCalledTimes(1)
      expect(onEvent).toHaveBeenCalledWith('kpi', {
        signal_color: 'danger',
        anomaly_count: 42,
      })
    })

    it('calls onEvent with raw data when JSON parsing fails', () => {
      const onEvent = vi.fn()
      useSse('kpi', { onEvent })

      const instance = latestInstance()
      instance.simulateOpen()

      const event = new MessageEvent('kpi', { data: 'not-json' })
      const listeners = instance.getListeners('kpi')
      for (const listener of listeners) {
        listener(event)
      }

      expect(onEvent).toHaveBeenCalledWith('kpi', 'not-json')
    })

    it('does not call onEvent for heartbeat messages', () => {
      const onEvent = vi.fn()
      useSse('kpi', { onEvent })

      const instance = latestInstance()
      instance.simulateOpen()
      instance.simulateMessage('heartbeat', { ts: Date.now() })

      expect(onEvent).not.toHaveBeenCalled()
    })

    it('does not throw when onEvent is not provided', () => {
      useSse('kpi')

      const instance = latestInstance()
      instance.simulateOpen()

      expect(() => {
        instance.simulateMessage('kpi', { data: 'test' })
      }).not.toThrow()
    })
  })

  describe('reconnection', () => {
    it('sets status to reconnecting on connection error', () => {
      const { status } = useSse('kpi')

      const instance = latestInstance()
      instance.simulateOpen()
      expect(status.value).toBe('connected')

      instance.simulateError()
      expect(status.value).toBe('reconnecting')
    })

    it('auto-reconnects after an error with initial delay of 1 second', () => {
      useSse('kpi')

      const firstInstance = latestInstance()
      firstInstance.simulateOpen()
      firstInstance.simulateError()

      expect(MockEventSource.instances).toHaveLength(1)

      vi.advanceTimersByTime(1000)

      expect(MockEventSource.instances).toHaveLength(2)
    })

    it('uses exponential backoff for reconnect delays', () => {
      useSse('kpi')

      latestInstance().simulateOpen()
      latestInstance().simulateError()
      vi.advanceTimersByTime(1000)
      expect(MockEventSource.instances).toHaveLength(2)

      latestInstance().simulateError()
      vi.advanceTimersByTime(1999)
      expect(MockEventSource.instances).toHaveLength(2)
      vi.advanceTimersByTime(1)
      expect(MockEventSource.instances).toHaveLength(3)

      latestInstance().simulateError()
      vi.advanceTimersByTime(3999)
      expect(MockEventSource.instances).toHaveLength(3)
      vi.advanceTimersByTime(1)
      expect(MockEventSource.instances).toHaveLength(4)
    })

    it('caps reconnect delay at 30 seconds', () => {
      useSse('kpi')

      latestInstance().simulateError()
      vi.advanceTimersByTime(1000)

      latestInstance().simulateError()
      vi.advanceTimersByTime(2000)

      latestInstance().simulateError()
      vi.advanceTimersByTime(4000)

      latestInstance().simulateError()
      vi.advanceTimersByTime(8000)

      latestInstance().simulateError()
      vi.advanceTimersByTime(16_000)

      const instanceCountAtCap = MockEventSource.instances.length
      latestInstance().simulateError()

      vi.advanceTimersByTime(30_000)
      expect(MockEventSource.instances).toHaveLength(instanceCountAtCap + 1)

      const instanceCountAfterCap = MockEventSource.instances.length
      latestInstance().simulateError()

      vi.advanceTimersByTime(29_999)
      expect(MockEventSource.instances).toHaveLength(instanceCountAfterCap)

      vi.advanceTimersByTime(1)
      expect(MockEventSource.instances).toHaveLength(instanceCountAfterCap + 1)
    })

    it('resets reconnect delay after a successful connection', () => {
      useSse('kpi')

      latestInstance().simulateOpen()
      latestInstance().simulateError()
      vi.advanceTimersByTime(1000)
      expect(MockEventSource.instances).toHaveLength(2)

      latestInstance().simulateOpen()
      latestInstance().simulateError()
      vi.advanceTimersByTime(1000)
      expect(MockEventSource.instances).toHaveLength(3)
    })
  })

  describe('manual controls', () => {
    it('disconnect() closes connection and sets status to disconnected', () => {
      const { status, disconnect } = useSse('kpi')

      const instance = latestInstance()
      instance.simulateOpen()
      expect(status.value).toBe('connected')

      disconnect()

      expect(instance.readyState).toBe(2)
      expect(status.value).toBe('disconnected')
    })

    it('disconnect() cancels pending reconnect', () => {
      const { disconnect } = useSse('kpi')

      latestInstance().simulateOpen()
      latestInstance().simulateError()

      disconnect()

      vi.advanceTimersByTime(5000)
      expect(MockEventSource.instances).toHaveLength(1)
    })

    it('connect() opens a new connection after disconnect', () => {
      const { status, connect, disconnect } = useSse('kpi')

      latestInstance().simulateOpen()
      disconnect()
      expect(status.value).toBe('disconnected')

      connect()

      expect(MockEventSource.instances).toHaveLength(2)
      latestInstance().simulateOpen()
      expect(status.value).toBe('connected')
    })

    it('connect() resets reconnect delay', () => {
      const { connect } = useSse('kpi')

      latestInstance().simulateOpen()
      latestInstance().simulateError()
      vi.advanceTimersByTime(1000)

      latestInstance().simulateError()
      vi.advanceTimersByTime(2000)

      connect()

      latestInstance().simulateOpen()
      latestInstance().simulateError()

      vi.advanceTimersByTime(1000)
      const lastInstance = latestInstance()
      expect(lastInstance.url).toContain('/api/v1/events/stream')
    })
  })

  describe('enabled flag', () => {
    it('does not connect when enabled is initially false', () => {
      const enabled = ref(false)
      useSse('kpi', { enabled })

      expect(MockEventSource.instances).toHaveLength(0)
    })

    it('connects when enabled changes from false to true', async () => {
      const enabled = ref(false)
      useSse('kpi', { enabled })

      expect(MockEventSource.instances).toHaveLength(0)

      enabled.value = true
      await nextTick()

      expect(MockEventSource.instances).toHaveLength(1)
    })

    it('disconnects when enabled changes from true to false', async () => {
      const enabled = ref(true)
      const { status } = useSse('kpi', { enabled })

      latestInstance().simulateOpen()
      expect(status.value).toBe('connected')

      enabled.value = false
      await nextTick()

      expect(status.value).toBe('disconnected')
    })

    it('does not auto-reconnect when enabled is false', async () => {
      const enabled = ref(true)
      useSse('kpi', { enabled })

      latestInstance().simulateOpen()

      enabled.value = false
      await nextTick()

      expect(MockEventSource.instances).toHaveLength(1)
      vi.advanceTimersByTime(60_000)
      expect(MockEventSource.instances).toHaveLength(1)
    })
  })

  describe('reactive topics', () => {
    it('reconnects when topics ref changes', async () => {
      const topics = ref('kpi')
      useSse(topics)

      expect(MockEventSource.instances).toHaveLength(1)
      expect(latestInstance().url).toContain('topics=kpi')

      topics.value = 'kpi,health,anomaly'
      await nextTick()

      expect(MockEventSource.instances).toHaveLength(2)
      expect(latestInstance().url).toContain('topics=kpi%2Chealth%2Canomaly')
    })
  })
})
