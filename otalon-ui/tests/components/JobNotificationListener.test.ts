/**
 * Unit tests for the JobNotificationListener component (lookup kind).
 *
 * Covers the UI-051 lifecycle contract: the listener is mounted by the
 * default layout off ``jobNotificationsStore.watchedLookupIds`` and is
 * independent of the originating CveLookupDialog. Closing the dialog does
 * NOT unwatch the job, so the listener persists and a terminal ``done`` SSE
 * event (replayed by the upstream after a reconnect) still drives
 * ``addNotification`` → exactly one unshown pending entry. Uses a
 * MockEventSource to drive the live SSE stream.
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
  }

  simulateOpen(): void {
    this.readyState = OPEN
    if (this.onopen) this.onopen(new Event('open'))
  }

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
}

vi.stubGlobal('EventSource', MockEventSource)

const { mountWithPlugins } = await import('../helpers/mount')
const { useJobNotificationsStore } = await import('~/stores/jobNotificationsStore')
const JobNotificationListener = (await import('~/components/JobNotificationListener.vue')).default

function latestInstance(): MockEventSource {
  return MockEventSource.instances[MockEventSource.instances.length - 1]!
}

describe('JobNotificationListener (lookup)', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    MockEventSource.instances = []
    setActivePinia(createPinia())
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('records exactly one unshown notification when a terminal done arrives after the dialog closed', async () => {
    // mountWithPlugins installs its own active pinia; read the store afterwards
    // so it is the SAME instance the mounted listener uses.
    mountWithPlugins(JobNotificationListener, {
      props: { kind: 'lookup', jobId: 'job-9' },
    })
    const store = useJobNotificationsStore()
    // The dialog registered the watch when the lookup started; it survives close.
    store.watchLookup('job-9')
    expect(store.watchedLookupIds).toContain('job-9')

    const instance = latestInstance()
    instance.simulateOpen()

    // Simulate the originating dialog having closed already (no effect on the
    // listener's own watch/stream — it lives in the default layout).
    expect(store.watchedLookupIds).toContain('job-9')

    instance.simulateMessage('done', {
      job_id: 'job-9',
      status: 'completed',
      cves_found: 4,
      critical: 2,
    })
    await flushPromises()

    expect(store.pending).toHaveLength(1)
    expect(store.unshown).toHaveLength(1)
    expect(store.pending[0]).toMatchObject({
      id: 'lookup:job-9',
      kind: 'lookup',
      status: 'completed',
      message: '4 CVEs found, 2 critical',
      shown: false,
    })
    expect(store.notified).toContain('lookup:job-9')
  })

  it('still fires the notification when the terminal done only arrives after a transient reconnect', async () => {
    mountWithPlugins(JobNotificationListener, {
      props: { kind: 'lookup', jobId: 'job-late' },
    })
    const store = useJobNotificationsStore()
    store.watchLookup('job-late')

    // First connection dies transiently (readyState CONNECTING) before terminal.
    const first = latestInstance()
    first.simulateOpen()
    first.simulateError(CONNECTING)
    expect(store.pending).toHaveLength(0)

    // Reconnect; upstream replays history and re-delivers done.
    vi.advanceTimersByTime(1000)
    expect(MockEventSource.instances).toHaveLength(2)
    const second = latestInstance()
    second.simulateOpen()
    second.simulateMessage('done', {
      job_id: 'job-late',
      status: 'completed',
      cves_found: 0,
      critical: 0,
    })
    await flushPromises()

    expect(store.unshown).toHaveLength(1)
    expect(store.pending[0]).toMatchObject({ id: 'lookup:job-late', status: 'completed' })
  })
})
