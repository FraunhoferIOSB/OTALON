/**
 * SSE subscription composable for CVE-lookup jobs.
 *
 * Connects to ``/api/v1/vulnerabilities/lookups/{job_id}/events`` and
 * collects per-asset ``progress`` events plus the terminal ``done`` /
 * ``failed`` event. Auto-reconnects on any transient disconnect where the
 * EventSource is not ``OPEN`` (covering both ``CLOSED`` and the
 * dead-``CONNECTING`` case produced by the nginx/api proxy chain on a
 * long-lived stream) with exponential backoff.
 *
 * **Terminal reconciliation (UI-019).** The upstream scanner uses a single
 * in-process ``asyncio.Queue`` per job for live progress/terminal events.
 * When two EventSource clients subscribe to the *same live job*
 * concurrently — which happens routinely because the CVE-lookup dialog and
 * the global ``JobNotificationListener`` both open a stream for the job the
 * user just triggered — the terminal ``done`` frame is consumed by at most
 * one of them (and, observed live, frequently by neither). Relying on the
 * SSE terminal frame alone therefore silently drops the completion toast.
 *
 * To be robust against that backend behaviour without touching backend
 * logic, the composable reconciles the job state via
 * ``GET /api/v1/vulnerabilities/lookups/{job_id}`` and synthesises the
 * terminal event from the persisted ``status`` / ``summary`` on two
 * triggers:
 *
 * 1. **Error path** — when the live stream ends or errors without having
 *    delivered a terminal frame (after a short grace, ``RECONCILE_DELAY_MS``).
 * 2. **Connected watchdog** — a low-frequency REST poll
 *    (``RECONCILE_POLL_MS``) that runs *while the stream is OPEN* but no
 *    terminal has arrived. This is essential: the losing subscriber of the
 *    shared queue keeps receiving ``ping`` frames indefinitely and never
 *    errors, so the error path alone never fires for it (observed live: an
 *    87s job stayed OPEN the whole time, the listener got no ``done``).
 *
 * The REST path always reflects the true terminal state (the scanner
 * persists it before closing the queue), so the toast fires regardless of
 * how many clients shared the live stream. Both reconcile triggers and the
 * reconnect loop stop once the terminal event is received or ``close()``
 * is called.
 */
import { onBeforeUnmount, ref, watch } from 'vue'

import { useApi } from '~/composables/useApi'
import type {
  CveLookupProgressEvent,
  CveLookupDoneEvent,
  CveLookupFailedEvent,
  CveLookupAbortedEvent,
} from '~/types/api'

/** Terminal CVE-lookup SSE event variants the dialog reacts to. */
type CveLookupTerminalEvent = CveLookupDoneEvent | CveLookupFailedEvent | CveLookupAbortedEvent

interface SsePayload {
  event?: string
  job_id?: string
  device_id?: number
  cve_count?: number
  index?: number
  total?: number
  status?: string
  cves_found?: number
  critical?: number
  error?: string
}

const RECONNECT_DELAYS_MS = [1000, 2500, 5000, 10_000]

/**
 * Delay before reconciling job state via REST after the stream drops
 * without a terminal frame. Short enough to fire the toast promptly, long
 * enough to let a genuine terminal frame arrive on a reconnect first.
 */
const RECONCILE_DELAY_MS = 1500

/**
 * Interval for the connected-watchdog REST reconcile poll. The shared
 * per-job ``asyncio.Queue`` delivers the terminal ``done`` frame to at
 * most one subscriber, so a sibling EventSource (dialog vs. global
 * listener) routinely keeps streaming ``ping`` frames forever without
 * ever seeing ``done`` and without erroring. ``onerror`` therefore never
 * fires for it, so the error-path reconcile alone cannot recover the
 * toast. While the stream is OPEN but no terminal has arrived, poll the
 * persisted job header at this cadence; the first poll after the backend
 * persists its terminal state synthesises the terminal event.
 */
const RECONCILE_POLL_MS = 5000

const DEBUG = Boolean(import.meta.dev)

function dbg(...args: unknown[]): void {
  if (DEBUG) console.debug('[useCveLookupSse]', ...args)
}

export interface UseCveLookupSseReturn {
  connected: Ref<boolean>
  progressEvents: Ref<CveLookupProgressEvent[]>
  terminalEvent: Ref<CveLookupTerminalEvent | null>
  close: () => void
}

interface LookupHeader {
  status?: string
  error?: string | null
  summary?: Record<string, unknown> | null
}

function numField(summary: Record<string, unknown> | null | undefined, key: string): number {
  const value = summary?.[key]
  return typeof value === 'number' ? value : 0
}

export function useCveLookupSse(jobIdRef: Ref<string | null>): UseCveLookupSseReturn {
  const api = useApi()
  const connected = ref(false)
  const progressEvents = ref<CveLookupProgressEvent[]>([])
  const terminalEvent = ref<CveLookupTerminalEvent | null>(null)

  let eventSource: EventSource | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let reconcileTimer: ReturnType<typeof setTimeout> | null = null
  let reconcilePollTimer: ReturnType<typeof setInterval> | null = null
  let reconnectAttempt = 0
  let closed = false

  function close(): void {
    closed = true
    teardown()
    clearReconcile()
  }

  function clearReconcile(): void {
    if (reconcileTimer) {
      clearTimeout(reconcileTimer)
      reconcileTimer = null
    }
    stopReconcilePoll()
  }

  function startReconcilePoll(jobId: string): void {
    if (reconcilePollTimer || closed || terminalEvent.value) return
    dbg('startReconcilePoll every', RECONCILE_POLL_MS, 'ms')
    reconcilePollTimer = setInterval(() => {
      if (closed || terminalEvent.value) {
        stopReconcilePoll()
        return
      }
      void reconcile(jobId)
    }, RECONCILE_POLL_MS)
  }

  function stopReconcilePoll(): void {
    if (reconcilePollTimer) {
      clearInterval(reconcilePollTimer)
      reconcilePollTimer = null
    }
  }

  function setTerminal(evt: CveLookupTerminalEvent): void {
    if (terminalEvent.value) return
    dbg('setTerminal', evt)
    terminalEvent.value = evt
    close()
  }

  /**
   * Reconcile the terminal state via REST when the live stream dropped
   * without delivering a terminal frame (shared-queue consumer race).
   */
  async function reconcile(jobId: string): Promise<void> {
    if (closed || terminalEvent.value) return
    dbg('reconcile: fetching job header', jobId)
    let header: LookupHeader
    try {
      header = await api.get<LookupHeader>(`/api/v1/vulnerabilities/lookups/${jobId}`)
    } catch (err) {
      dbg('reconcile: fetch failed, will retry on next stream drop', err)
      return
    }
    if (closed || terminalEvent.value) return
    const status = (header?.status ?? '').toLowerCase()
    dbg('reconcile: status', status)
    if (status === 'completed') {
      setTerminal({
        job_id: jobId,
        status: 'completed',
        cves_found: numField(header.summary, 'cves_found'),
        critical: numField(header.summary, 'critical'),
      })
    } else if (status === 'failed') {
      setTerminal({
        job_id: jobId,
        status: 'failed',
        error: header.error ?? 'unknown error',
      })
    } else if (status === 'aborted') {
      setTerminal({
        job_id: jobId,
        status: 'aborted',
      })
    }
    // Still running: leave reconnect logic to recover via the live stream.
  }

  function scheduleReconcile(jobId: string): void {
    if (closed || terminalEvent.value || reconcileTimer) return
    reconcileTimer = setTimeout(() => {
      reconcileTimer = null
      void reconcile(jobId)
    }, RECONCILE_DELAY_MS)
  }

  function scheduleReconnect(jobId: string): void {
    if (closed || terminalEvent.value || reconnectTimer) return
    const delay = RECONNECT_DELAYS_MS[Math.min(reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)] ?? 10_000
    reconnectAttempt += 1
    dbg('scheduleReconnect attempt', reconnectAttempt, 'in', delay, 'ms')
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      open(jobId)
    }, delay)
  }

  function dispatch(jobId: string, type: string, payload: SsePayload): void {
    dbg('dispatch', type, payload)
    if (terminalEvent.value) return
    if (type === 'progress') {
      const evt: CveLookupProgressEvent = {
        job_id: payload.job_id ?? jobId,
        device_id: payload.device_id ?? 0,
        cve_count: payload.cve_count ?? 0,
        index: payload.index ?? 0,
        total: payload.total ?? 0,
      }
      progressEvents.value.push(evt)
    } else if (type === 'done') {
      setTerminal({
        job_id: payload.job_id ?? jobId,
        status: payload.status ?? 'completed',
        cves_found: payload.cves_found ?? 0,
        critical: payload.critical ?? 0,
      })
    } else if (type === 'failed') {
      setTerminal({
        job_id: payload.job_id ?? jobId,
        status: payload.status ?? 'failed',
        error: payload.error ?? 'unknown error',
      })
    } else if (type === 'aborted') {
      setTerminal({
        job_id: payload.job_id ?? jobId,
        status: payload.status ?? 'aborted',
      })
    }
  }

  function teardown(): void {
    if (eventSource) {
      eventSource.close()
      eventSource = null
    }
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    connected.value = false
  }

  function open(jobId: string): void {
    teardown()
    if (terminalEvent.value) return
    closed = false
    const url = `/api/v1/vulnerabilities/lookups/${jobId}/events`
    dbg('open', url)
    try {
      eventSource = new EventSource(url)
    } catch (err) {
      console.error('useCveLookupSse: cannot open EventSource', err)
      return
    }

    eventSource.onopen = () => {
      dbg('onopen, readyState', eventSource?.readyState)
      connected.value = true
      reconnectAttempt = 0
      // Connected-watchdog: a sibling EventSource may have already drained
      // the terminal frame from the shared per-job queue, leaving this
      // stream open and ping-only forever. Poll the persisted header so the
      // toast still fires once the backend records the terminal state.
      startReconcilePoll(jobId)
    }

    const handler = (type: string) => (event: MessageEvent) => {
      let parsed: SsePayload = { event: type }
      try {
        parsed = JSON.parse(event.data) as SsePayload
        if (!parsed.event) parsed.event = type
      } catch {
        /* keep as bare type */
      }
      dispatch(jobId, type, parsed)
    }

    eventSource.onmessage = handler('message')
    for (const evt of ['progress', 'done', 'failed', 'aborted', 'error', 'ping']) {
      eventSource.addEventListener(evt, handler(evt) as EventListener)
    }

    eventSource.onerror = () => {
      dbg('onerror, readyState', eventSource?.readyState)
      connected.value = false
      if (terminalEvent.value || closed) return
      if (!eventSource || eventSource.readyState !== EventSource.OPEN) {
        // The live stream dropped. Two recovery paths run in parallel:
        // (1) reconnect — recovers an in-flight job that is still emitting;
        // (2) reconcile via REST after a short grace — covers the
        //     shared-queue consumer race where the terminal frame was
        //     consumed by a sibling stream and will never be re-delivered
        //     to this one. Whichever sets the terminal first wins; the
        //     other is a no-op (terminalEvent guard).
        scheduleReconnect(jobId)
        scheduleReconcile(jobId)
      }
    }
  }

  watch(
    () => jobIdRef.value,
    (newId) => {
      if (newId) {
        reconnectAttempt = 0
        progressEvents.value = []
        terminalEvent.value = null
        clearReconcile()
        open(newId)
      } else {
        close()
      }
    },
    { immediate: true },
  )

  onBeforeUnmount(() => close())

  return { connected, progressEvents, terminalEvent, close }
}
