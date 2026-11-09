/**
 * Shared SSE-proxy disconnect-propagation helper (UI-083).
 *
 * The Nitro server proxies three upstream SSE surfaces to the browser:
 *   - the global events feed `/api/v1/events/stream` (dedicated route
 *     `server/api/v1/events/stream.get.ts`, previously a bare `routeRules`
 *     httpxy pass-through);
 *   - the admin-key operator subtrees `/api/v1/operations|training/**`
 *     (`server/utils/operatorProxy.ts`);
 *   - the chat stream `/api/chat/stream` (`server/api/chat/stream.post.ts`).
 *
 * All three used `new Response(upstream.body)` with an upstream `fetch` that
 * was never linked to the *client* connection. When the browser closed the
 * tab, neither httpxy nor the fetch tore the upstream connection down, so the
 * otalon-api SSE endpoint never observed `http.disconnect`. Its
 * `EventBus._connection_count` therefore climbed monotonically to the 50-cap,
 * after which every new stream returned HTTP 429 — killing the live SSE
 * indicator and live health/jobs updates on all Operations pages (and the same
 * mechanism starved chat SSE).
 *
 * The API-side fix (`event_bus.register/release` + `request.is_disconnected()`
 * poll, DONE API-019) only releases a slot when the API itself sees the
 * disconnect. This helper makes the proxy propagate it: an `AbortController` is
 * wired to the client request's `close` event, its signal is handed to the
 * upstream `fetch`, and the upstream body is piped through a `ReadableStream`
 * whose `cancel` also aborts. When the browser goes away the upstream `fetch`
 * is aborted, the upstream TCP connection closes, and the API's
 * `is_disconnected()` poll releases the slot exactly once.
 */

import type { H3Event } from 'h3'

/**
 * A client-disconnect abort signal plus its detach callback.
 */
export interface ClientDisconnect {
  /** Signal to hand to the upstream `fetch`; aborts when the client leaves. */
  signal: AbortSignal
  /**
   * Abort the controller (idempotent) and remove the request listeners.
   * Safe to call from multiple teardown paths; the underlying abort fires at
   * most once so the upstream `fetch` is never double-aborted.
   */
  abort: () => void
  /** Detach the request listeners without aborting (normal completion). */
  detach: () => void
}

/**
 * Minimal event-emitter surface of the raw Node request we depend on. Kept
 * narrow so unit tests can supply a stub without a full `IncomingMessage`.
 */
interface CloseEmitter {
  on?: (event: string, listener: () => void) => unknown
  off?: (event: string, listener: () => void) => unknown
  removeListener?: (event: string, listener: () => void) => unknown
  aborted?: boolean
}

/**
 * Build an {@link AbortController} that fires when the browser disconnects.
 *
 * The raw Node request (`event.node.req`) emits `close` when its socket is torn
 * down — which is exactly what happens when the browser closes the tab,
 * navigates away, or the `EventSource` is `close()`d. Wiring that to
 * `controller.abort()` lets the upstream `fetch` (which received
 * `controller.signal`) be cancelled, closing the upstream connection so the API
 * observes the disconnect.
 *
 * Only the request's `aborted` event (an explicit client-side abort) is treated
 * as an eager disconnect. `req.destroyed`/`req.aborted` are deliberately NOT
 * inspected synchronously: for a POST the request body stream is already
 * consumed (and thus `destroyed`) by the time the handler forwards it upstream,
 * which is a normal completion of the request *body* — not a client disconnect
 * — so keying off it would abort the upstream fetch before it even started.
 *
 * @param event - The h3 event whose client connection lifecycle is tracked.
 * @returns The signal to forward upstream plus idempotent teardown callbacks.
 */
export function clientDisconnectSignal(event: H3Event): ClientDisconnect {
  const controller = new AbortController()
  const req = event.node?.req as CloseEmitter | undefined

  let settled = false

  const onClose = (): void => {
    if (settled) return
    settled = true
    detachListeners()
    if (!controller.signal.aborted) {
      controller.abort()
    }
  }

  function detachListeners(): void {
    if (!req) return
    const remove = req.off ?? req.removeListener
    if (typeof remove === 'function') {
      remove.call(req, 'close', onClose)
      remove.call(req, 'aborted', onClose)
    }
  }

  if (req?.aborted === true) {
    settled = true
    if (!controller.signal.aborted) controller.abort()
  } else if (req && typeof req.on === 'function') {
    req.on('close', onClose)
    req.on('aborted', onClose)
  }

  return {
    signal: controller.signal,
    abort: () => {
      if (settled) return
      settled = true
      detachListeners()
      if (!controller.signal.aborted) controller.abort()
    },
    detach: () => {
      if (settled) return
      settled = true
      detachListeners()
    },
  }
}

/**
 * Standard SSE response headers: keep proxy/browser buffering disabled so
 * events are delivered as they arrive.
 */
const SSE_HEADERS: Readonly<Record<string, string>> = {
  'content-type': 'text/event-stream',
  'cache-control': 'no-cache',
  'x-accel-buffering': 'no',
}

/**
 * Pipe an upstream SSE `fetch` body to the browser while guaranteeing the
 * upstream connection is torn down when the client disconnects.
 *
 * The upstream body is read through a fresh {@link ReadableStream}. Its
 * `cancel` (fired when the downstream consumer / browser goes away) aborts the
 * client-disconnect controller, and any read error / normal end likewise
 * detaches the listeners — so the upstream `fetch` is aborted exactly once and
 * the reader lock is always released.
 *
 * @param upstreamBody - The upstream `Response.body` (must be non-null).
 * @param disconnect - The controller returned by {@link clientDisconnectSignal}
 *   whose `signal` was passed to the upstream `fetch`.
 * @param status - Upstream HTTP status to forward (defaults to 200).
 * @param statusText - Upstream status text to forward.
 * @param contentType - Upstream `content-type` to forward (defaults to
 *   `text/event-stream`).
 * @returns A `Response` streaming the upstream events with buffering disabled.
 */
export function streamUpstreamSse(
  upstreamBody: ReadableStream<Uint8Array>,
  disconnect: ClientDisconnect,
  status = 200,
  statusText = '',
  contentType?: string,
): Response {
  const reader = upstreamBody.getReader()

  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read()
        if (done) {
          controller.close()
          disconnect.detach()
          return
        }
        controller.enqueue(value)
      } catch (err) {
        // Upstream ended or was aborted (e.g. client-close abort propagated).
        disconnect.detach()
        try {
          controller.close()
        } catch {
          controller.error(err)
        }
      }
    },
    cancel() {
      // Browser / downstream consumer went away: abort the upstream fetch so
      // the API sees the disconnect, then release the reader lock.
      disconnect.abort()
      reader.cancel().catch(() => undefined)
    },
  })

  const headers: Record<string, string> = { ...SSE_HEADERS }
  if (contentType) headers['content-type'] = contentType

  return new Response(stream, {
    status,
    statusText,
    headers,
  })
}
