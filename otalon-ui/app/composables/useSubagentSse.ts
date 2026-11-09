/**
 * SSE subscription composable for subagent classification jobs.
 *
 * Connects to ``/api/v1/subagent-jobs/{job_id}/events`` (proxied to the
 * otalon-ai service and dispatches typed events into the
 * ``subagentStore``. Auto-reconnects on transient disconnects with
 * exponential backoff. The store handles trace replay because the proxy
 * already replays history on every (re)connection.
 */
import { onBeforeUnmount, ref, watch } from 'vue'

import { useSubagentStore } from '~/stores/subagentStore'
import type { SubagentJobStatus, SubagentTraceEntry } from '~/types/api'

interface SsePayload {
  type: string
  job_id?: string
  // tool_call_completed / tool_call_started fields:
  round?: number
  tool?: string
  args?: Record<string, unknown>
  result_chars?: number
  result_preview?: string | null
  duration_ms?: number
  error?: string | null
  args_summary?: string
  // final fields:
  status?: SubagentJobStatus
  step1_technical?: unknown
  step2_classification?: unknown
  duration_seconds?: number
  tokens_prompt?: number
  tokens_completion?: number
  // progress / force_classify:
  context_chars?: number
  context_chars_before?: number
  context_chars_after?: number
  // error:
  reason?: string
  detail?: string
}

const RECONNECT_DELAYS_MS = [1000, 2500, 5000, 10_000]

export function useSubagentSse(jobIdRef: Ref<string | null>) {
  const store = useSubagentStore()
  const connected = ref(false)
  const lastEvent = ref<string | null>(null)

  let eventSource: EventSource | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let reconnectAttempt = 0

  function close(): void {
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

  function scheduleReconnect(jobId: string): void {
    const delay = RECONNECT_DELAYS_MS[Math.min(reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)] ?? 10_000
    reconnectAttempt += 1
    reconnectTimer = setTimeout(() => {
      open(jobId)
    }, delay)
  }

  function dispatch(jobId: string, type: string, payload: SsePayload): void {
    lastEvent.value = type
    if (type === 'tool_call_completed' && payload.tool) {
      const entry: SubagentTraceEntry = {
        round: payload.round ?? 0,
        tool: payload.tool,
        args: payload.args ?? {},
        result_chars: payload.result_chars ?? 0,
        result_preview: payload.result_preview ?? null,
        duration_ms: payload.duration_ms ?? 0,
        error: payload.error ?? null,
      }
      store.appendTraceEntry(jobId, entry)
    } else if (type === 'final') {
      store.finalizeJob(jobId, {
        status: (payload.status ?? 'completed') as SubagentJobStatus,
        step1_technical: (payload.step1_technical ?? null) as never,
        step2_classification: (payload.step2_classification ?? null) as never,
        duration_seconds: payload.duration_seconds,
        tokens_prompt: payload.tokens_prompt,
        tokens_completion: payload.tokens_completion,
        error_message: (payload.error ?? null) as string | null,
      })
      close()
    } else if (type === 'error') {
      store.finalizeJob(jobId, {
        status: 'failed',
        step1_technical: null,
        step2_classification: null,
        error_message: payload.detail ?? payload.reason ?? 'unknown error',
      })
      close()
    }
  }

  function open(jobId: string): void {
    close()
    const url = `/api/v1/subagent-jobs/${jobId}/events`
    try {
      eventSource = new EventSource(url)
    } catch (err) {
      console.error('useSubagentSse: cannot open EventSource', err)
      return
    }

    eventSource.onopen = () => {
      connected.value = true
      reconnectAttempt = 0
    }

    const handler = (type: string) => (event: MessageEvent) => {
      let parsed: SsePayload = { type }
      try {
        parsed = JSON.parse(event.data) as SsePayload
        if (!parsed.type) parsed.type = type
      } catch {
        /* keep as bare type */
      }
      dispatch(jobId, type, parsed)
    }

    // Default + named SSE events
    eventSource.onmessage = handler('message')
    for (const evt of [
      'tool_call_started',
      'tool_call_completed',
      'progress',
      'force_classify',
      'final',
      'error',
      'ping',
    ]) {
      eventSource.addEventListener(evt, handler(evt) as EventListener)
    }

    eventSource.onerror = () => {
      connected.value = false
      // Browsers auto-reconnect EventSource, but we prefer to fully close
      // and reopen so we get a fresh history replay if our store missed
      // anything.
      if (eventSource && eventSource.readyState === EventSource.CLOSED) {
        scheduleReconnect(jobId)
      }
    }
  }

  watch(
    () => jobIdRef.value,
    (newId) => {
      if (newId) {
        reconnectAttempt = 0
        open(newId)
      } else {
        close()
      }
    },
    { immediate: true },
  )

  onBeforeUnmount(() => close())

  return { connected, lastEvent, close }
}
