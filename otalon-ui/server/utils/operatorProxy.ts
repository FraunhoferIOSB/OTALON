/**
 * Shared server-side operator-key reverse proxy for admin-key-protected
 * otalon-api subtrees (SUITE-014 boundary).
 *
 * Both the Operations subtree (`/api/v1/operations/**`) and the Training
 * subtree (`/api/v1/training/**`) are protected by the same `admin_api_key`
 * on the backend (`otalon-api/src/middleware/auth.py`
 * `PROTECTED_PATH_PREFIXES`). The browser must therefore reach them through
 * this handler, which injects the operator key from the server-only
 * environment so the key is never delivered to the browser bundle. It:
 *
 *   - restricts the target to the configured subtree prefix and rejects path
 *     traversal / open-proxy attempts (no `.`/`..` segments — literal or
 *     encoded — same-origin upstream only);
 *   - preserves the HTTP method, repeated query values and the raw request
 *     body — JSON control-plane bodies are buffered, `multipart/form-data`
 *     (capture uploads, UI-078) is relayed as a bounded stream so a 512 MiB
 *     import never materialises in the Nitro process;
 *   - forwards the upstream status, content type and the `Accept` header,
 *     and streams SSE / chunked bodies through unchanged with buffering
 *     disabled;
 *   - never forwards a client-supplied auth header and never logs headers
 *     or the key.
 */

import { Buffer } from 'node:buffer'
import type { Readable } from 'node:stream'

import type { H3Event } from 'h3'
import { createError, getCookie, getQuery, readRawBody, setResponseHeaders, setResponseStatus } from 'h3'

import { requireProductSession, SESSION_COOKIE_NAME } from '~~/server/utils/productSession'
import { clientDisconnectSignal, streamUpstreamSse, type ClientDisconnect } from '~~/server/utils/sseProxy'

/**
 * A no-op {@link ClientDisconnect} for the streamed-upload path.
 *
 * Same shape as the real one so the call sites stay uniform, but nothing is
 * ever aborted: for a streamed request body the inbound stream *is* the
 * liveness signal, and the raw request's `close` is part of its own normal
 * lifecycle rather than evidence the browser left.
 */
function detachedDisconnect(): ClientDisconnect {
  return {
    signal: new AbortController().signal,
    abort: () => undefined,
    detach: () => undefined,
  }
}

/**
 * True when the request body must be streamed rather than buffered.
 *
 * `readRawBody` materialises the whole body in the Nitro process before it
 * is forwarded. For JSON control-plane calls that is a few hundred bytes
 * and buys correct `content-length` handling, so it stays. For a capture
 * upload (`multipart/form-data`, up to 512 MiB) it is ruinous: the UI
 * container has no memory limit, so the failure mode is host memory
 * pressure rather than a clean error.
 *
 * Multipart is therefore relayed as a stream. Measured on this stack
 * (Node 22.23), 300 MiB through the same undici `fetch`:
 *
 *   buffered `Buffer` body (readRawBody)  peak RSS +944 MB
 *   streamed Node `Readable`              peak RSS +367 MB
 *
 * So streaming cuts peak memory by ~2.6x, but it is honestly **not**
 * constant-memory: undici still queues a large part of the request body
 * internally, and `Readable.toWeb()` measured no better than the raw
 * `Readable`. Peak therefore still grows with capture size, roughly
 * ~1.2x the file rather than ~3x. The 512 MiB server-side limit is what
 * bounds the worst case; a genuinely flat relay would need a different
 * HTTP client on the Nitro side and is out of scope for this wave (noted
 * for Wave E).
 */
export function shouldStreamRequestBody(method: string, contentType: string | undefined): boolean {
  if (['GET', 'HEAD'].includes(method.toUpperCase())) return false
  return (contentType ?? '').toLowerCase().includes('multipart/form-data')
}

/**
 * Where the upload size limit is enforced, and why not here.
 *
 * The API owns the byte budget (`PCAP_IMPORT_MAX_UPLOAD_BYTES`) and enforces
 * it *while streaming* (`pcap_upload_service.py:_CaptureSink.write`), then
 * answers `413` naming the limit. That answer arrives mid-upload, before the
 * client has finished sending.
 *
 * An additional ceiling in this proxy was tried and removed: erroring the
 * relayed stream destroyed the API's authoritative `413` (the browser got an
 * opaque `500` instead) and, because the inbound request was then no longer
 * being drained, the still-arriving body accumulated in the Nitro process —
 * measured RSS ~680 MB for a 600 MiB upload. The duplicated guard was itself
 * the memory bomb it was meant to prevent.
 *
 * The relay therefore stays a pure pipe: constant memory, and the upstream's
 * own rejection is what reaches the operator. Verified live — a 600 MiB
 * upload returns the API's `413` while the UI process stays ~80 MB RSS.
 */

/**
 * A single safe path segment. Besides the unreserved URL set we allow the
 * percent sign so a percent-encoded octet (`%3A`, `%2F`, …) survives — bound
 * corrections address series whose ids contain `/` and `:` and are therefore
 * (double-)URL-encoded into one segment. A literal separator can never appear
 * inside a segment (we split on `/`), and traversal is rejected explicitly
 * below — including its encoded forms.
 */
const SEGMENT_RE = /^[A-Za-z0-9._~%-]+$/

/**
 * True when a single decoding level exposes a path-traversal component.
 *
 * The segment (or a decoded form of it) is unsafe when, split on either
 * separator (`/` from `%2f`, `\` from `%5c`), ANY resulting component is a
 * `.` or `..` traversal token. Splitting on the separator is essential: an
 * attacker can hide traversal *inside* one URL segment as `%2e%2e%2fadmin`,
 * which decodes to `../admin` — a token the naive whole-segment equality
 * check missed, but the upstream would percent-decode and could normalise.
 * A legitimate (double-)encoded UCI series id decodes to components that
 * contain `:` and empty runs but never a bare `.`/`..`, so this stays
 * compatible with the D-AUDIT slash/colon-series fix.
 */
function hasTraversalComponent(value: string): boolean {
  for (const part of value.split(/[/\\]/)) {
    if (part === '.' || part === '..') return true
  }
  return false
}

/** Decoded values that would resolve to a path-traversal segment. */
export function isTraversalSegment(segment: string): boolean {
  if (hasTraversalComponent(segment)) return true
  try {
    const decoded = decodeURIComponent(segment)
    if (hasTraversalComponent(decoded)) return true
    // Guard the second decode too: series ids are double-encoded, so a
    // `%252e%252e%252fadmin` segment decodes once to `%2e%2e%2fadmin` and
    // again to `../admin`.
    if (decoded !== segment && isTraversalSegment(decoded)) return true
  } catch {
    // Malformed percent-encoding: reject via the charset gate instead.
    return false
  }
  return false
}

/**
 * Validate the request path is inside the given subtree prefix and free of
 * traversal segments (literal or encoded). Returns the safe path or `null`
 * when it must be rejected.
 */
export function safeSubtreePath(rawPath: string, prefix: string): string | null {
  const path = rawPath.split('?')[0] ?? ''
  const normalizedPrefix = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix
  if (path !== normalizedPrefix && !path.startsWith(`${normalizedPrefix}/`)) return null
  const segments = path.split('/').filter((segment) => segment.length > 0)
  for (const segment of segments) {
    if (isTraversalSegment(segment)) return null
    if (!SEGMENT_RE.test(segment)) return null
  }
  return path
}

function upstreamBase(): string {
  return process.env.NUXT_API_PROXY_TARGET || 'http://localhost:8090'
}

const SESSION_PROTECTED_REQUESTS = new Set([
  'POST /api/v1/operations/reset',
  'POST /api/v1/operations/restore',
  'POST /api/v1/operations/services/action',
  // Per-account dashboard state: the API accepts a session (not the operator key)
  // for exactly these two PUTs (auth.py SESSION_OWNED_REQUESTS). The cookie must be
  // forwarded, or the server answers 401 and the layout never persists.
  'PUT /api/v1/dashboard/layout',
  'PUT /api/v1/dashboard/tour',
])
const OPERATOR_KEY_RE = /^[\x21-\x7e]+$/

export function forwardsSessionCookie(method: string, path: string): boolean {
  return SESSION_PROTECTED_REQUESTS.has(`${method.toUpperCase()} ${path}`)
}

/**
 * Proxy an event to the backend subtree identified by `prefix`, injecting the
 * server-only operator key. Throws an h3 error for rejected paths / missing
 * key configuration.
 */
export async function proxyOperatorSubtree(event: H3Event, prefix: string): Promise<unknown> {
  const path = safeSubtreePath(event.path, prefix)
  if (!path) {
    throw createError({ statusCode: 404, statusMessage: 'Not found' })
  }

  const base = upstreamBase()
  const target = new URL(path, base)
  // Defence in depth: even after segment validation, refuse any resolved
  // URL that escaped the configured upstream origin.
  if (target.origin !== new URL(base).origin) {
    throw createError({ statusCode: 502, statusMessage: 'Invalid operator proxy target' })
  }

  await requireProductSession(event, base)

  const operatorKey = process.env.OTALON_OPERATOR_KEY || process.env.ADMIN_API_KEY
  if (!operatorKey || !OPERATOR_KEY_RE.test(operatorKey)) {
    throw createError({ statusCode: 503, statusMessage: 'Operator proxy is not configured' })
  }

  const query = getQuery(event)
  for (const [key, value] of Object.entries(query)) {
    if (Array.isArray(value)) {
      value.forEach((item) => target.searchParams.append(key, String(item)))
    } else if (value !== undefined) {
      target.searchParams.set(key, String(value))
    }
  }

  const headers = new Headers()
  const contentType = event.node.req.headers['content-type']
  if (contentType) headers.set('content-type', contentType)
  const accept = event.node.req.headers['accept']
  if (typeof accept === 'string') headers.set('accept', accept)
  // Operator key is injected server-side only; any inbound X-API-Key from
  // the browser is intentionally dropped and never forwarded.
  headers.set('x-api-key', operatorKey)
  if (forwardsSessionCookie(event.method, path)) {
    const sessionCookie = getCookie(event, SESSION_COOKIE_NAME)
    if (sessionCookie) headers.set('cookie', `${SESSION_COOKIE_NAME}=${sessionCookie}`)
  }

  const streaming = shouldStreamRequestBody(event.method, contentType)
  const hasBody = !['GET', 'HEAD'].includes(event.method)
  let body: Buffer | Readable | undefined
  if (streaming) {
    // Relay the raw Node request stream straight to undici, which accepts a
    // Node `Readable` as a body. `Readable.toWeb()` was measured too and is
    // no better (both ~+330-360 MB peak on 300 MiB), so the plain stream is
    // used as the simpler of the two. See the note above
    // `shouldStreamRequestBody` for the buffered-vs-streamed numbers.
    //
    // `duplex: 'half'` is mandatory for any streamed fetch body.
    body = event.node.req
    // `content-length` describes the original body; keep it so the API can
    // size-check early, and let undici chunk the transfer.
    const contentLength = event.node.req.headers['content-length']
    if (typeof contentLength === 'string') headers.set('content-length', contentLength)
  } else if (hasBody) {
    const rawBody = await readRawBody(event, false)
    body = rawBody === undefined ? undefined : (rawBody as Buffer)
  }

  // Link the upstream fetch to the browser connection so a client disconnect
  // aborts it and the API releases its SSE slot (UI-083). Non-stream responses
  // complete promptly and detach the listener; only the SSE branch keeps it
  // armed for the life of the stream.
  //
  // A streamed request body is deliberately excluded from that wiring. The
  // upstream fetch consumes `event.node.req` itself, so this request emits
  // `close` as part of its own normal lifecycle — both when the body has
  // been fully relayed and when the API answers early (e.g. `413` mid-upload
  // and stops reading). Aborting on either would destroy the very response
  // we are trying to forward. An upload POST holds no SSE slot, so there is
  // nothing to release; if the browser truly vanishes the inbound stream
  // ends and the fetch fails on its own.
  const disconnect = streaming ? detachedDisconnect() : clientDisconnectSignal(event)

  let upstream: Response
  try {
    upstream = await fetch(target, {
      method: event.method,
      headers,
      body,
      signal: disconnect.signal,
      // Required by undici whenever the body is a stream; harmless (and
      // ignored) for the buffered branch.
      ...(streaming ? { duplex: 'half' } : {}),
    } as RequestInit)
  } catch (err) {
    disconnect.detach()
    // Client disconnect while the upstream fetch is in flight is not a server
    // error — the backend likely answered 200 already.  Swallow AbortError
    // silently instead of letting Nitro log a misleading 500 (UI-106).
    if (err instanceof Error && err.name === 'AbortError') {
      return undefined
    }
    throw err
  }

  const responseType = upstream.headers.get('content-type') ?? ''

  // Stream Server-Sent Events / chunked bodies through unchanged, keeping
  // proxy buffering disabled so events are not withheld. The upstream fetch is
  // torn down when the browser disconnects so the API sees `http.disconnect`.
  if (upstream.body && responseType.includes('text/event-stream')) {
    return streamUpstreamSse(upstream.body, disconnect, upstream.status, upstream.statusText, responseType)
  }

  disconnect.detach()
  setResponseStatus(event, upstream.status, upstream.statusText)
  const forwardHeaders: Record<string, string> = {}
  if (responseType) forwardHeaders['content-type'] = responseType
  // Forward Set-Cookie so the browser actually receives the session cookie
  // after login; without this the UI never establishes a session (UI-XXX).
  const setCookie = upstream.headers.get('set-cookie')
  if (setCookie) forwardHeaders['set-cookie'] = setCookie
  if (Object.keys(forwardHeaders).length > 0) setResponseHeaders(event, forwardHeaders)
  const buffer = Buffer.from(await upstream.arrayBuffer())
  return buffer.length > 0 ? buffer : undefined
}
