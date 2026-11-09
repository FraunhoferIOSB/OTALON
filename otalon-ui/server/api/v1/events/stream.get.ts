/**
 * Dedicated Nitro proxy for the global events SSE feed `/api/v1/events/stream`.
 *
 * Previously this path was served by the generic `routeRules` httpxy
 * pass-through (`nuxt.config.ts`, `events` prefix). httpxy does not link the
 * upstream connection to the *client* connection, so a browser tab-close never
 * propagated to otalon-api: its `EventBus._connection_count` climbed
 * monotonically to the 50-cap and every subsequent stream returned HTTP 429,
 * killing the live SSE indicator and live health/jobs updates on all
 * Operations pages (UI-083).
 *
 * This handler replaces that pass-through for the SSE route only. It forwards
 * the `topics` query, streams the upstream events through unchanged with
 * buffering disabled, and — crucially — wires the upstream `fetch` to the
 * browser connection via {@link clientDisconnectSignal} so a disconnect aborts
 * it, closing the upstream connection so the API's `is_disconnected()` poll
 * releases the slot exactly once.
 *
 * No operator key is involved here: the events feed is a browser-safe read, so
 * it authenticates with the caller's own product session. The API protects
 * every path (`otalon-api/src/otalon_api/middleware/auth.py`
 * `PROTECTED_PATH_PREFIXES = ("/",)`) and only lets a GET through without an
 * `X-API-Key` when `SessionAuthMiddleware` has attached a validated user — which
 * it can only do if the request carries the `otalon_session` cookie. The
 * handler originally sent no `Cookie` header at all, so every stream was
 * answered with 401 and all live jobs/health/topology/anomaly updates were dead
 * (pages merely looked alive because they fall back to polling) — UI-160.
 * The inbound session cookie is therefore forwarded verbatim, exactly as
 * `server/utils/operatorProxy.ts` does for its session-protected requests.
 */

import { createError, getCookie, getQuery } from 'h3'

import { SESSION_COOKIE_NAME } from '~~/server/utils/productSession'
import { clientDisconnectSignal, streamUpstreamSse } from '~~/server/utils/sseProxy'

function upstreamBase(): string {
  return process.env.NUXT_API_PROXY_TARGET || 'http://localhost:8090'
}

export default defineEventHandler(async (event) => {
  const base = upstreamBase()
  const target = new URL('/api/v1/events/stream', base)

  const topics = getQuery(event).topics
  if (typeof topics === 'string' && topics.length > 0) {
    target.searchParams.set('topics', topics)
  } else if (Array.isArray(topics)) {
    for (const value of topics) target.searchParams.append('topics', String(value))
  }

  const accept = event.node.req.headers['accept']
  const headers = new Headers()
  headers.set('accept', typeof accept === 'string' ? accept : 'text/event-stream')

  // Forward only the product-session cookie, not the raw inbound `Cookie`
  // header: unrelated cookies (analytics, third-party) have no business
  // reaching the API, and re-emitting the whole header would smuggle them
  // across the proxy boundary. Same single-cookie shape as operatorProxy.
  const sessionCookie = getCookie(event, SESSION_COOKIE_NAME)
  if (sessionCookie) headers.set('cookie', `${SESSION_COOKIE_NAME}=${sessionCookie}`)

  const disconnect = clientDisconnectSignal(event)

  let upstream: Response
  try {
    upstream = await fetch(target, { method: 'GET', headers, signal: disconnect.signal })
  } catch (err) {
    disconnect.detach()
    throw createError({ statusCode: 502, statusMessage: 'events-stream-unavailable', cause: err })
  }

  const responseType = upstream.headers.get('content-type') ?? ''

  if (!upstream.body) {
    disconnect.detach()
    throw createError({ statusCode: upstream.status || 502, statusMessage: 'events-stream-unavailable' })
  }

  return streamUpstreamSse(upstream.body, disconnect, upstream.status, upstream.statusText, responseType)
})
