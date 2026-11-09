import type { Ref } from 'vue'

/**
 * Connection status of the SSE client.
 */
export type SseConnectionStatus = 'connected' | 'disconnected' | 'reconnecting'

/**
 * Options for configuring the SSE client.
 */
export interface UseSseOptions {
  enabled?: Ref<boolean>
  onEvent?: (topic: string, data: unknown) => void
}

/**
 * Return type for the useSse composable.
 */
export interface UseSseReturn {
  status: Ref<SseConnectionStatus>
  connect: () => void
  disconnect: () => void
}

const SSE_BASE_URL = '/api/v1/events/stream'
const INITIAL_RECONNECT_DELAY_MS = 1000
const MAX_RECONNECT_DELAY_MS = 30_000
const HEARTBEAT_TIMEOUT_MS = 60_000

/**
 * Composable for consuming Server-Sent Events from the OTALON backend.
 *
 * Connects to the SSE endpoint with topic filtering, auto-reconnects with
 * exponential backoff on connection loss, and monitors heartbeat events to
 * detect stale connections. Cleans up automatically on component unmount.
 *
 * @param topics - Comma-separated topic string or reactive ref (e.g. `'kpi,health,anomaly'`).
 * @param options - Optional configuration for enable control and event handling.
 * @returns Connection status ref and manual connect/disconnect controls.
 *
 * @example
 * ```ts
 * const { status } = useSse('kpi,health', {
 *   onEvent: (topic, data) => {
 *     console.log(`Received ${topic}:`, data)
 *   },
 * })
 * ```
 */
export function useSse(topics: string | Ref<string>, options?: UseSseOptions): UseSseReturn {
  const status = ref<SseConnectionStatus>('disconnected')
  const externalEnabled = options?.enabled ?? ref(true)

  let eventSource: EventSource | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let heartbeatTimer: ReturnType<typeof setTimeout> | null = null
  let reconnectDelay = INITIAL_RECONNECT_DELAY_MS

  function resolveTopics(): string {
    return isRef(topics) ? topics.value : topics
  }

  function buildUrl(): string {
    const topicValue = resolveTopics()
    return `${SSE_BASE_URL}?topics=${encodeURIComponent(topicValue)}`
  }

  function resetHeartbeatTimer(): void {
    if (heartbeatTimer !== null) {
      clearTimeout(heartbeatTimer)
    }
    heartbeatTimer = setTimeout(() => {
      closeConnection()
      scheduleReconnect()
    }, HEARTBEAT_TIMEOUT_MS)
  }

  function clearHeartbeatTimer(): void {
    if (heartbeatTimer !== null) {
      clearTimeout(heartbeatTimer)
      heartbeatTimer = null
    }
  }

  function clearReconnectTimer(): void {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
  }

  function scheduleReconnect(): void {
    if (!externalEnabled.value) {
      return
    }

    status.value = 'reconnecting'
    clearReconnectTimer()

    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      openConnection()
    }, reconnectDelay)

    reconnectDelay = Math.min(reconnectDelay * 2, MAX_RECONNECT_DELAY_MS)
  }

  function handleMessage(event: MessageEvent): void {
    resetHeartbeatTimer()

    if (event.type === 'heartbeat') {
      return
    }

    if (!options?.onEvent) {
      return
    }

    try {
      const data: unknown = JSON.parse(event.data as string)
      options.onEvent(event.type, data)
    } catch {
      options.onEvent(event.type, event.data)
    }
  }

  function openConnection(): void {
    closeConnection()

    if (!externalEnabled.value) {
      return
    }

    if (typeof EventSource === 'undefined') {
      return
    }

    const url = buildUrl()
    eventSource = new EventSource(url)

    eventSource.onopen = () => {
      status.value = 'connected'
      reconnectDelay = INITIAL_RECONNECT_DELAY_MS
      resetHeartbeatTimer()
    }

    eventSource.onerror = () => {
      closeConnection()
      scheduleReconnect()
    }

    const topicList = resolveTopics()
      .split(',')
      .map((t) => t.trim())
    for (const topic of topicList) {
      eventSource.addEventListener(topic, handleMessage)
    }
    eventSource.addEventListener('heartbeat', handleMessage)
  }

  function closeConnection(): void {
    clearHeartbeatTimer()

    if (eventSource !== null) {
      eventSource.close()
      eventSource = null
    }

    status.value = 'disconnected'
  }

  function teardown(): void {
    clearReconnectTimer()
    closeConnection()
  }

  /**
   * Manually open the SSE connection.
   * If a connection is already active, it will be closed first.
   */
  function connect(): void {
    reconnectDelay = INITIAL_RECONNECT_DELAY_MS
    openConnection()
  }

  /**
   * Manually close the SSE connection and cancel any pending reconnect.
   */
  function disconnect(): void {
    clearReconnectTimer()
    closeConnection()
  }

  if (typeof window !== 'undefined') {
    watch(externalEnabled, (enabled) => {
      if (enabled) {
        openConnection()
      } else {
        teardown()
      }
    })

    if (isRef(topics)) {
      watch(topics, () => {
        if (externalEnabled.value) {
          reconnectDelay = INITIAL_RECONNECT_DELAY_MS
          openConnection()
        }
      })
    }

    if (externalEnabled.value) {
      openConnection()
    }

    onUnmounted(() => {
      teardown()
    })
  }

  return { status, connect, disconnect }
}
