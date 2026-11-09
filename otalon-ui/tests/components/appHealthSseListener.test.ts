/**
 * Component test: the persistent shell health-SSE listener.
 *
 * Regression coverage for the two recovery2 red findings:
 *   - UI-085: the header `.sse-dot` was permanently red because
 *     `appStore.setSseStatus` had no production caller. This proves the shell
 *     listener mirrors the live SSE connection status into the app store
 *     (connected on open, disconnected on close).
 *   - UI-086: the header system-status chip showed `—` on Operations pages
 *     because nothing hydrated `dashboardStore.health`. This proves the shell
 *     listener performs a bounded initial `fetchHealth()` and fans every pushed
 *     `health` event out to both the dashboard store (chip source) and the
 *     operations-overview store — without opening more than one stream.
 *
 * Uses a MockEventSource to drive the live stream, mirroring
 * `operationsOverviewSse.test.ts`.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'

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
  closed = false

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: EventSourceListener): void {
    const existing = this.listeners.get(type) ?? []
    existing.push(listener)
    this.listeners.set(type, existing)
  }

  removeEventListener(): void {}

  close(): void {
    this.readyState = CLOSED
    this.closed = true
  }

  simulateOpen(): void {
    this.readyState = OPEN
    if (this.onopen) this.onopen(new Event('open'))
  }

  simulateError(): void {
    if (this.onerror) this.onerror(new Event('error'))
  }

  simulateMessage(type: string, data: unknown): void {
    const event = new MessageEvent(type, {
      data: typeof data === 'string' ? data : JSON.stringify(data),
    })
    const listeners = this.listeners.get(type) ?? []
    for (const listener of listeners) listener(event)
  }

  listenerTopics(): string[] {
    return [...this.listeners.keys()]
  }
}

vi.stubGlobal('EventSource', MockEventSource)

const healthFetch = vi.fn(async () => ({
  services: [{ name: 'Postgres', running: true, detail: 'ok', timestamp: 1, status: 'healthy' }],
  overall_status: 'healthy',
}))
vi.stubGlobal('$fetch', vi.fn(healthFetch))

const { mountWithPlugins } = await import('../helpers/mount')
const { useAppStore } = await import('~/stores/appStore')
const { useDashboardStore } = await import('~/stores/dashboardStore')
const { useOperationsOverviewStore } = await import('~/stores/operationsOverviewStore')
const AppHealthSseListener = (await import('~/components/operations/AppHealthSseListener.vue')).default

function latestInstance(): MockEventSource {
  return MockEventSource.instances[MockEventSource.instances.length - 1]!
}

describe('AppHealthSseListener — shell health SSE', () => {
  beforeEach(() => {
    MockEventSource.instances = []
    healthFetch.mockClear()
    setActivePinia(createPinia())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('opens exactly one health stream and subscribes to the health topic', async () => {
    mountWithPlugins(AppHealthSseListener)
    await flushPromises()

    expect(MockEventSource.instances).toHaveLength(1)
    const instance = latestInstance()
    expect(instance.url).toContain('topics=health')
    expect(instance.listenerTopics()).toContain('health')
  })

  it('mirrors the live SSE status into the app store (green when connected)', async () => {
    mountWithPlugins(AppHealthSseListener)
    const appStore = useAppStore()
    await flushPromises()

    // Before the stream opens the status is the disconnected default.
    expect(appStore.sseConnectionStatus).toBe('disconnected')

    latestInstance().simulateOpen()
    await flushPromises()
    expect(appStore.sseConnectionStatus).toBe('connected')
  })

  it('reports reconnecting honestly when the live stream errors', async () => {
    mountWithPlugins(AppHealthSseListener)
    const appStore = useAppStore()
    await flushPromises()

    latestInstance().simulateOpen()
    await flushPromises()
    expect(appStore.sseConnectionStatus).toBe('connected')

    // A stream error closes the connection and schedules a reconnect; the shell
    // listener mirrors that truthfully (amber dot), never a stale green.
    latestInstance().simulateError()
    await flushPromises()
    expect(appStore.sseConnectionStatus).toBe('reconnecting')
  })

  it('closes the single stream on unmount (no leak)', async () => {
    const wrapper = mountWithPlugins(AppHealthSseListener)
    await flushPromises()
    latestInstance().simulateOpen()
    await flushPromises()

    // useSse registers its own onUnmounted teardown → the EventSource closes.
    wrapper.unmount()
    await flushPromises()
    expect(latestInstance().closed).toBe(true)
  })

  it('performs a bounded initial health fetch so the chip is correct immediately', async () => {
    mountWithPlugins(AppHealthSseListener)
    await flushPromises()

    // fetchHealth() hits /api/v1/status/health via $fetch exactly once on mount.
    const fetchMock = globalThis.$fetch as unknown as ReturnType<typeof vi.fn>
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/status/health', { params: { detail: 'true' } })
  })

  it('fans a pushed health event out to both the dashboard and overview stores', async () => {
    mountWithPlugins(AppHealthSseListener)
    const dashboardStore = useDashboardStore()
    const overviewStore = useOperationsOverviewStore()
    await flushPromises()

    latestInstance().simulateOpen()
    latestInstance().simulateMessage('health', {
      services: [{ name: 'Postgres', running: false, detail: 'refused', timestamp: 2, status: 'failed' }],
      overall_status: 'unhealthy',
    })
    await flushPromises()

    // Dashboard store backs the header status chip.
    expect(dashboardStore.overallHealthStatus).toBe('unhealthy')
    // Overview store backs the Service Health / Suite KPI surfaces.
    expect(overviewStore.health?.overall_status).toBe('unhealthy')
  })
})
