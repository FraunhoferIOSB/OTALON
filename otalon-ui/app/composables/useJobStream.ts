/**
 * Generic per-job Server-Sent-Events composable.
 *
 * Designed for any ``/api/v1/.../events`` endpoint that streams a finite
 * sequence of events for a single backend job (scan, baseline, classification,
 * …). The composable manages the EventSource lifecycle (open / reconnect /
 * close), parses JSON-payload events, keeps an in-memory append-only log
 * capped at 200 entries, and exposes reactive state plus a ``latestProgress``
 * shortcut.
 *
 * Distinct from :func:`useSse` which targets the broadcast
 * ``/api/v1/events/stream`` topic-filtered feed (always-on, topic-routed).
 * ``useJobStream`` binds to one SSE URL and is meant to be (re-)created when
 * the consuming component cares about a different job id.
 *
 * Reconnection mirrors :func:`useSubagentSse`: a backoff sequence (default
 * ``[1000, 2500, 5000, 10000]`` ms) retried on transient ``EventSource``
 * errors; after the final entry, ``status`` settles on ``'error'`` and no
 * further attempts are made.
 *
 * Cleanup is automatic via ``onScopeDispose`` — callers do not need to
 * remember to ``close()`` on component unmount.
 *
 * @example
 * ```ts
 * const scanId = ref<string | null>(null)
 * const url = computed(() =>
 *   scanId.value ? `/api/v1/scans/${scanId.value}/events` : null,
 * )
 * const { status, events, latestProgress } = useJobStream({
 *   url,
 *   onEvent: (type, data) => console.log(type, data),
 * })
 * ```
 */

import { getCurrentScope, isRef, onScopeDispose, ref, watch } from 'vue'
import type { Ref } from 'vue'

/**
 * Connection status of the job stream.
 *
 * - ``idle`` — no URL set yet (or last URL was ``null``).
 * - ``connecting`` — EventSource constructed but ``onopen`` not yet fired.
 * - ``open`` — receiving events normally.
 * - ``closed`` — explicitly closed (via ``close()`` or component unmount).
 * - ``error`` — reconnect backoff exhausted; no further retries.
 */
export type JobStreamStatus = 'idle' | 'connecting' | 'open' | 'closed' | 'error'

/**
 * Default SSE named events subscribed to. Callers may extend via
 * ``knownEventTypes`` — the composable will register additional listeners
 * for each entry beyond this default set.
 */
const DEFAULT_KNOWN_EVENT_TYPES: readonly string[] = [
  'progress',
  'result',
  'final',
  'error',
  'status',
  'module_started',
  'module_finished',
]

/**
 * Default reconnect backoff (ms) used when the upstream EventSource enters
 * the CLOSED state after an ``error`` event. Tuned to recover from transient
 * proxy / network blips without hammering the upstream.
 */
const DEFAULT_RECONNECT_DELAYS_MS: readonly number[] = [1000, 2500, 5000, 10_000]

/**
 * Maximum number of events retained in :attr:`UseJobStreamReturn.events`.
 * Older events are dropped FIFO. 200 is chosen as a generous default for an
 * operator-friendly modal log without unbounded memory growth.
 */
const MAX_EVENTS_RETAINED = 200

/**
 * Single event captured from the upstream SSE stream.
 */
export interface JobStreamEvent {
  type: string
  data: unknown
  /** Local timestamp the event was received (ms since epoch). */
  receivedAt: number
}

/**
 * Shape of a typical ``progress`` event payload. The composable does not
 * enforce this shape — it merely stores ``data`` verbatim. Useful for typed
 * consumption when the operator knows the upstream contract.
 */
export interface JobStreamProgressEvent {
  percent?: number
  module?: string
  message?: string
  [key: string]: unknown
}

/**
 * Caller-supplied options for :func:`useJobStream`.
 */
export interface UseJobStreamOptions {
  /**
   * SSE endpoint URL. May be a static string, a static ``null`` (idle), or
   * a ``Ref<string | null>``. When the ref's value changes to a new
   * non-null URL, the composable closes the previous stream and opens a
   * fresh one against the new URL.
   */
  url: Ref<string | null> | string | null
  /** Optional handler invoked for every JSON-parsed event. */
  onEvent?: (type: string, data: unknown) => void
  /** Additional SSE named events to subscribe to beyond the defaults. */
  knownEventTypes?: readonly string[]
  /** Override the default reconnect backoff sequence. */
  reconnectDelaysMs?: readonly number[]
}

/**
 * Return type for :func:`useJobStream`.
 */
export interface UseJobStreamReturn {
  status: Ref<JobStreamStatus>
  events: Ref<JobStreamEvent[]>
  latestProgress: Ref<JobStreamProgressEvent | null>
  /** Manually open (or re-open) the SSE connection. */
  connect: () => void
  /** Manually close the SSE connection and cancel any pending reconnect. */
  close: () => void
}

/**
 * Resolve the URL option to a possibly-null string at the moment of
 * resolution. Centralised so both the watcher and the connect path use the
 * same logic.
 */
function resolveUrl(option: Ref<string | null> | string | null): string | null {
  if (isRef(option)) {
    return option.value
  }
  return option
}

/**
 * Parse a single SSE event payload, falling back to ``{type, raw}`` when the
 * payload is not valid JSON. Centralised so handlers stay tiny.
 */
function parseEventData(type: string, raw: unknown): unknown {
  if (typeof raw !== 'string') {
    return raw
  }
  try {
    return JSON.parse(raw)
  } catch {
    return { type, raw }
  }
}

/**
 * Compose an SSE-backed job stream against a single ``/api/v1/...`` URL.
 *
 * @param options - See :class:`UseJobStreamOptions`.
 * @returns Reactive status / events / latestProgress refs plus manual
 *   ``connect`` / ``close`` controls.
 */
export function useJobStream(options: UseJobStreamOptions): UseJobStreamReturn {
  const status = ref<JobStreamStatus>('idle')
  const events = ref<JobStreamEvent[]>([])
  const latestProgress = ref<JobStreamProgressEvent | null>(null)

  const knownEvents: readonly string[] = [...DEFAULT_KNOWN_EVENT_TYPES, ...(options.knownEventTypes ?? [])]
  const backoff: readonly number[] = options.reconnectDelaysMs ?? DEFAULT_RECONNECT_DELAYS_MS

  let eventSource: EventSource | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let reconnectAttempt = 0

  function clearReconnectTimer(): void {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
  }

  function teardownSource(): void {
    if (eventSource !== null) {
      eventSource.close()
      eventSource = null
    }
  }

  function pushEvent(type: string, data: unknown): void {
    events.value.push({ type, data, receivedAt: Date.now() })
    while (events.value.length > MAX_EVENTS_RETAINED) {
      events.value.shift()
    }
    if (type === 'progress' && data !== null && typeof data === 'object') {
      latestProgress.value = data as JobStreamProgressEvent
    }
  }

  function dispatch(type: string, raw: unknown): void {
    const data = parseEventData(type, raw)
    pushEvent(type, data)
    if (options.onEvent) {
      options.onEvent(type, data)
    }
  }

  function scheduleReconnect(url: string): void {
    const delay = backoff[reconnectAttempt]
    if (delay === undefined) {
      // Backoff sequence exhausted — surface the failure and stop trying.
      status.value = 'error'
      return
    }
    reconnectAttempt += 1
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      openConnection(url)
    }, delay)
  }

  function openConnection(url: string): void {
    teardownSource()
    if (typeof EventSource === 'undefined') {
      status.value = 'error'
      return
    }

    status.value = 'connecting'
    let source: EventSource
    try {
      source = new EventSource(url)
    } catch {
      status.value = 'error'
      return
    }
    eventSource = source

    source.onopen = () => {
      status.value = 'open'
      reconnectAttempt = 0
    }

    source.onerror = () => {
      if (source.readyState === EventSource.CLOSED) {
        teardownSource()
        scheduleReconnect(url)
      }
    }

    source.onmessage = (event: MessageEvent) => {
      dispatch('message', event.data)
    }
    for (const type of knownEvents) {
      source.addEventListener(type, ((event: MessageEvent) => {
        // F-OE2: browsers dispatch a built-in ``error`` event (a plain
        // ``Event``, not a ``MessageEvent``) whenever the underlying
        // connection closes — including legitimate end-of-stream after
        // a successful ``result`` frame. Such events carry no ``data``
        // and must not be forwarded as semantic SSE events, otherwise
        // the modal log shows a trailing "error: undefined" ghost
        // after every successful scan. Only forward when the event
        // carries a payload (server-sent semantic frame).
        if (type === 'error' && (event.data === undefined || event.data === '')) {
          return
        }
        dispatch(type, event.data)
      }) as EventListener)
    }
  }

  function connect(): void {
    const url = resolveUrl(options.url)
    if (!url) {
      status.value = 'idle'
      return
    }
    reconnectAttempt = 0
    clearReconnectTimer()
    openConnection(url)
  }

  function close(): void {
    clearReconnectTimer()
    teardownSource()
    status.value = 'closed'
  }

  // Auto-(re)connect when the URL ref changes. Initial connect is driven by
  // the immediate watcher so callers do not need to call ``connect()`` for
  // the common case.
  if (isRef(options.url)) {
    const urlRef = options.url as Ref<string | null>
    watch(
      urlRef,
      (next) => {
        if (!next) {
          clearReconnectTimer()
          teardownSource()
          status.value = 'idle'
          return
        }
        reconnectAttempt = 0
        clearReconnectTimer()
        openConnection(next)
      },
      { immediate: true },
    )
  } else if (options.url) {
    // Static URL — connect once on creation.
    connect()
  }

  // Auto-cleanup on component unmount / effect-scope disposal.
  if (getCurrentScope()) {
    onScopeDispose(() => {
      clearReconnectTimer()
      teardownSource()
    })
  }

  return { status, events, latestProgress, connect, close }
}
