import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useHealthIncidentsStore } from '~/stores/healthIncidentsStore'
import type { HealthIncidentSummary } from '~/types/api'

const incident: HealthIncidentSummary = {
  id: 'incident-1',
  service: 'Network Traffic Recorder',
  category: 'probe_timeout',
  cause: 'health probe timeout',
  status: 'active',
  first_seen: '2026-07-23T10:00:00Z',
  last_seen: '2026-07-23T10:05:00Z',
  recovered_at: null,
  sample_count: 3,
  failure_count: 2,
  latency_budget_ms: 3000,
  worst_latency_ms: 5010,
  evidence_type: 'operational_health',
}

describe('healthIncidentsStore', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('keeps active and recent evidence from one health payload', () => {
    const store = useHealthIncidentsStore()
    store.applyHealth({
      services: [],
      overall_status: 'degraded',
      active_incidents: [incident],
      recent_incidents: [{ ...incident, id: 'incident-2', status: 'recovered', recovered_at: incident.last_seen }],
    })

    expect(store.latest?.id).toBe('incident-1')
    expect(store.current).toHaveLength(2)
  })

  it('selects a cached incident when detail fetch is unavailable', async () => {
    const store = useHealthIncidentsStore()
    store.history = [incident]
    vi.stubGlobal('$fetch', vi.fn().mockRejectedValue(new Error('offline')))

    await store.select(incident.id)

    expect(store.selected).toEqual(incident)
    expect(store.error).toBe('offline')
    vi.unstubAllGlobals()
  })

  it('exposes active/recent affordance getters for the header chip', () => {
    const store = useHealthIncidentsStore()
    store.applyHealth({
      services: [],
      overall_status: 'healthy',
      active_incidents: [],
      recent_incidents: [{ ...incident, id: 'incident-2', status: 'recovered', recovered_at: incident.last_seen }],
    })

    expect(store.hasActive).toBe(false)
    expect(store.hasRecent).toBe(true)
  })

  it('fetches bounded history and retention from the operations endpoint', async () => {
    const store = useHealthIncidentsStore()
    const fetchMock = vi.fn().mockResolvedValue({
      items: [incident],
      retention: { max_incidents: 50, max_days: 7 },
    })
    vi.stubGlobal('$fetch', fetchMock)

    await store.fetchHistory('active')

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/operations/health-incidents?status=active')
    expect(store.history).toEqual([incident])
    expect(store.retention).toEqual({ max_incidents: 50, max_days: 7 })
    vi.unstubAllGlobals()
  })

  it('clears stale detail while a new selection loads', async () => {
    const store = useHealthIncidentsStore()
    store.selected = incident
    let resolveRequest: ((value: HealthIncidentSummary) => void) | undefined
    vi.stubGlobal(
      '$fetch',
      vi.fn(
        () =>
          new Promise<HealthIncidentSummary>((resolve) => {
            resolveRequest = resolve
          }),
      ),
    )

    const pending = store.select('incident-2')

    expect(store.selected).toBeNull()
    expect(store.isDetailLoading).toBe(true)
    resolveRequest?.({ ...incident, id: 'incident-2' })
    await pending
    expect(store.selected?.id).toBe('incident-2')
    expect(store.isDetailLoading).toBe(false)
    vi.unstubAllGlobals()
  })

  it('removes acknowledged incident only after successful backend response', async () => {
    const store = useHealthIncidentsStore()
    store.applyHealth({
      services: [],
      overall_status: 'degraded',
      active_incidents: [incident],
      recent_incidents: [],
      unacknowledged_incidents: [incident],
    })
    const result = { ...incident, acknowledged: true, acknowledged_by: 'alice' }
    const fetchMock = vi.fn().mockResolvedValue(result)
    vi.stubGlobal('$fetch', fetchMock)

    await store.acknowledge(incident.id)

    expect(store.unacknowledged).toEqual([])
    expect(store.active[0]?.acknowledged).toBe(true)
    vi.unstubAllGlobals()
  })

  it('keeps incident visible and reports failed acknowledgement', async () => {
    const store = useHealthIncidentsStore()
    store.applyHealth({
      services: [],
      overall_status: 'degraded',
      active_incidents: [incident],
      recent_incidents: [],
      unacknowledged_incidents: [incident],
    })
    vi.stubGlobal('$fetch', vi.fn().mockRejectedValue(new Error('ack failed')))

    await store.acknowledge(incident.id)

    expect(store.unacknowledged).toEqual([incident])
    expect(store.error).toBe('ack failed')
    // A visible, accessible acknowledge error is exposed for the UI banner.
    expect(store.acknowledgeError).toBe('ack failed')
    // The per-incident pending flag is cleared after a failed POST.
    expect(store.isAcknowledging(incident.id)).toBe(false)
    vi.unstubAllGlobals()
  })

  it('acknowledging a recovered incident hides the recent ring immediately', async () => {
    const store = useHealthIncidentsStore()
    const recovered = { ...incident, id: 'incident-r', status: 'recovered' as const, recovered_at: incident.last_seen }
    store.applyHealth({
      services: [],
      overall_status: 'healthy',
      active_incidents: [],
      recent_incidents: [recovered],
      unacknowledged_incidents: [recovered],
    })
    // Precondition: the header recent-incident ring is on before acknowledge.
    expect(store.hasRecent).toBe(true)
    store.history = [recovered]
    const acked = { ...recovered, acknowledged: true, acknowledged_by: 'op' }
    vi.stubGlobal('$fetch', vi.fn().mockResolvedValue(acked))

    await store.acknowledge(recovered.id)

    // The acknowledged recovered row is pruned from BOTH recent and unack, so
    // the global recent-incident affordance hides immediately (CAPTURE 45).
    expect(store.recent).toEqual([])
    expect(store.hasRecent).toBe(false)
    expect(store.unacknowledged).toEqual([])
    // System history retains the row with the acknowledged badge (not deleted).
    expect(store.history).toHaveLength(1)
    expect(store.history[0]?.acknowledged).toBe(true)
    vi.unstubAllGlobals()
  })

  it('acknowledging an active incident retains truthful active health', async () => {
    const store = useHealthIncidentsStore()
    store.applyHealth({
      services: [],
      overall_status: 'degraded',
      active_incidents: [incident],
      recent_incidents: [],
      unacknowledged_incidents: [incident],
    })
    const acked = { ...incident, acknowledged: true, acknowledged_by: 'op' }
    vi.stubGlobal('$fetch', vi.fn().mockResolvedValue(acked))

    await store.acknowledge(incident.id)

    // The active row stays (health latch truthful) but is now acknowledged,
    // and the Overview unacknowledged affordance is gone.
    expect(store.hasActive).toBe(true)
    expect(store.active[0]?.acknowledged).toBe(true)
    expect(store.unacknowledged).toEqual([])
    vi.unstubAllGlobals()
  })

  it('exposes a per-incident pending flag while the acknowledge POST is in flight', async () => {
    const store = useHealthIncidentsStore()
    store.applyHealth({
      services: [],
      overall_status: 'degraded',
      active_incidents: [incident],
      recent_incidents: [],
      unacknowledged_incidents: [incident],
    })
    let resolveAck: ((value: HealthIncidentSummary) => void) | undefined
    vi.stubGlobal(
      '$fetch',
      vi.fn(() => new Promise<HealthIncidentSummary>((resolve) => (resolveAck = resolve))),
    )

    const pending = store.acknowledge(incident.id)
    // While in flight the per-incident flag is set (drives disable/spinner/aria-busy).
    expect(store.isAcknowledging(incident.id)).toBe(true)
    // A second click while pending is a no-op (cannot double-submit).
    expect(await store.acknowledge(incident.id)).toBeNull()

    resolveAck?.({ ...incident, acknowledged: true })
    await pending
    expect(store.isAcknowledging(incident.id)).toBe(false)
    vi.unstubAllGlobals()
  })

  it('drops an out-of-order stale detail response (real detailRequestSeq guard)', async () => {
    // CAPTURE 44: two overlapping real select() calls resolved OUT OF ORDER
    // (the newer one first, then the older) must leave the NEWER incident
    // selected — the store's detailRequestSeq last-request-wins guard must not
    // let the older response snap the UI back. No stub reimplements the guard.
    const store = useHealthIncidentsStore()
    const resolvers: Record<string, (value: HealthIncidentSummary) => void> = {}
    vi.stubGlobal(
      '$fetch',
      vi.fn(
        (url: string) =>
          new Promise<HealthIncidentSummary>((resolve) => {
            const id = url.includes('incident-1') ? 'incident-1' : 'incident-2'
            resolvers[id] = resolve
          }),
      ),
    )

    const firstPending = store.select('incident-1') // older request
    const secondPending = store.select('incident-2') // newer request

    // Resolve the NEWER (incident-2) first, then the OLDER (incident-1).
    resolvers['incident-2']?.({ ...incident, id: 'incident-2' })
    await secondPending
    expect(store.selected?.id).toBe('incident-2')

    resolvers['incident-1']?.({ ...incident, id: 'incident-1' })
    await firstPending
    // The stale older response must NOT overwrite the newer selection.
    expect(store.selected?.id).toBe('incident-2')
    vi.unstubAllGlobals()
  })

  it('close() invalidates an in-flight detail request so it cannot restore selection', async () => {
    // CAPTURE 44: closing bumps detailRequestSeq; a detail response that lands
    // AFTER close must be dropped so a closed incident never re-opens.
    const store = useHealthIncidentsStore()
    let resolveDetail: ((value: HealthIncidentSummary) => void) | undefined
    vi.stubGlobal(
      '$fetch',
      vi.fn(() => new Promise<HealthIncidentSummary>((resolve) => (resolveDetail = resolve))),
    )

    const pending = store.select('incident-9')
    expect(store.isDetailLoading).toBe(true)
    // Operator closes before the detail resolves.
    store.close()
    expect(store.selected).toBeNull()

    // The now-stale in-flight response arrives — it must be ignored.
    resolveDetail?.({ ...incident, id: 'incident-9' })
    await pending
    expect(store.selected).toBeNull()
    vi.unstubAllGlobals()
  })
})
