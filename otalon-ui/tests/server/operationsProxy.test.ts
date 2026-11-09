/**
 * Tests for the Operations server-side operator-key proxy
 * (`server/api/v1/operations/[...path].ts`, SUITE-014 boundary).
 *
 * The h3 helpers and global `fetch` / `defineEventHandler` are stubbed so
 * the handler runs in isolation. These tests assert the security-relevant
 * behaviour: path/traversal rejection, missing-key rejection, target
 * construction, server-side key injection (and that a client-supplied key
 * is dropped), repeated query values, raw body forwarding, status /
 * content-type forwarding and SSE streaming.
 */

import { Buffer } from 'node:buffer'
import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

interface FakeReq {
  headers: Record<string, string>
}

interface FakeEvent {
  path: string
  method: string
  node: { req: FakeReq }
  _query: Record<string, unknown>
  _rawBody?: Buffer | string
  _status?: { code: number; text?: string }
  _headers?: Record<string, string>
}

const errors: Array<{ statusCode: number; statusMessage?: string }> = []

vi.mock('h3', () => ({
  createError: (opts: { statusCode: number; statusMessage?: string }) => {
    errors.push(opts)
    const err = new Error(opts.statusMessage ?? String(opts.statusCode)) as Error & { statusCode: number }
    err.statusCode = opts.statusCode
    return err
  },
  getQuery: (event: FakeEvent) => event._query,
  getCookie: (event: FakeEvent, name: string) => {
    const cookie = event.node.req.headers.cookie ?? ''
    return cookie
      .split(';')
      .map((part) => part.trim().split('='))
      .find(([key]) => key === name)?.[1]
  },
  readRawBody: async (event: FakeEvent) => event._rawBody,
  setResponseStatus: (event: FakeEvent, code: number, text?: string) => {
    event._status = { code, text }
  },
  setResponseHeaders: (event: FakeEvent, headers: Record<string, string>) => {
    event._headers = { ...(event._headers ?? {}), ...headers }
  },
}))

let lastFetch: { url: URL; init: RequestInit } | null = null
let fetchResponse: Response
let authStatus: number
let authRole: 'admin' | 'operator' | 'viewer'
let authMustChangePassword: boolean
let fetchCalls: Array<{ url: URL; init: RequestInit }> = []

function makeEvent(overrides: Partial<FakeEvent> = {}): FakeEvent {
  const event = {
    path: '/api/v1/operations/configuration/boot',
    method: 'GET',
    node: { req: { headers: { cookie: 'otalon_session=test-session-123456' } } },
    _query: {},
    ...overrides,
  }
  if (
    event.node.req.headers.cookie === undefined &&
    (Object.keys(event.node.req.headers).length > 0 ||
      typeof (event.node.req as FakeReq & { on?: unknown }).on === 'function')
  ) {
    event.node.req.headers.cookie = 'otalon_session=test-session-123456'
  }
  return event
}

async function importHandler() {
  const mod = await import('~~/server/api/v1/operations/[...path]')
  return mod.default as (event: FakeEvent) => Promise<unknown>
}

beforeEach(() => {
  errors.length = 0
  lastFetch = null
  fetchCalls = []
  authStatus = 200
  authRole = 'operator'
  authMustChangePassword = false
  fetchResponse = new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } })
  process.env.NUXT_API_PROXY_TARGET = 'http://otalon-api:8090'
  process.env.OTALON_OPERATOR_KEY = 'server-only-operator-key'
  vi.stubGlobal('defineEventHandler', (fn: unknown) => fn)
  vi.stubGlobal('fetch', async (url: URL, init: RequestInit) => {
    fetchCalls.push({ url, init })
    if (url.pathname === '/api/v1/auth/me') {
      return new Response(JSON.stringify({ role: authRole, must_change_password: authMustChangePassword }), {
        status: authStatus,
        headers: { 'content-type': 'application/json' },
      })
    }
    lastFetch = { url, init }
    return fetchResponse
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.resetModules()
  delete process.env.OTALON_OPERATOR_KEY
  delete process.env.ADMIN_API_KEY
})

describe('operations proxy — rejection', () => {
  it('returns 401 without a session and never attempts validation or protected forward', async () => {
    const handler = await importHandler()
    await expect(handler(makeEvent({ node: { req: { headers: {} } } }))).rejects.toMatchObject({ statusCode: 401 })
    expect(fetchCalls).toHaveLength(0)
    expect(lastFetch).toBeNull()
  })

  it('returns 401 when the API rejects the session and never forwards upstream', async () => {
    authStatus = 401
    const handler = await importHandler()
    await expect(handler(makeEvent())).rejects.toMatchObject({ statusCode: 401 })
    expect(fetchCalls).toHaveLength(1)
    expect(fetchCalls[0]?.url.pathname).toBe('/api/v1/auth/me')
    expect(lastFetch).toBeNull()
  })

  it('returns 403 for a viewer session and never forwards upstream', async () => {
    authRole = 'viewer'
    const handler = await importHandler()
    await expect(handler(makeEvent())).rejects.toMatchObject({ statusCode: 403 })
    expect(fetchCalls).toHaveLength(1)
    expect(fetchCalls[0]?.url.pathname).toBe('/api/v1/auth/me')
    expect(lastFetch).toBeNull()
  })

  it.each(['operator', 'admin'] as const)('returns 403 for a %s session requiring password change', async (role) => {
    authRole = role
    authMustChangePassword = true
    const handler = await importHandler()
    const error = await handler(makeEvent()).catch((value: unknown) => value as Error & { statusCode: number })
    expect(error).toMatchObject({ statusCode: 403 })
    expect(error.message).toBe('Insufficient role')
    expect(fetchCalls).toHaveLength(1)
    expect(fetchCalls[0]?.url.pathname).toBe('/api/v1/auth/me')
    expect(lastFetch).toBeNull()
  })

  it('rejects an invalid session cookie without exposing its value', async () => {
    const cookie = 'bad\r\nX-Injected: yes'
    const handler = await importHandler()
    const error = await handler(
      makeEvent({ node: { req: { headers: { cookie: `otalon_session=${cookie}` } } } }),
    ).catch((value: unknown) => value as Error & { statusCode: number })
    expect(error).toMatchObject({ statusCode: 401 })
    expect(error.message).toBe('Authentication required')
    expect(error.message).not.toContain(cookie)
    expect(fetchCalls).toHaveLength(0)
    expect(lastFetch).toBeNull()
  })

  it('rejects a path outside the operations subtree', async () => {
    const handler = await importHandler()
    await expect(handler(makeEvent({ path: '/api/v1/admin/env' }))).rejects.toMatchObject({ statusCode: 404 })
    expect(lastFetch).toBeNull()
  })

  it('rejects a sibling path that only shares the operations prefix', async () => {
    const handler = await importHandler()
    await expect(handler(makeEvent({ path: '/api/v1/operations-archive/configuration/boot' }))).rejects.toMatchObject({
      statusCode: 404,
    })
    expect(lastFetch).toBeNull()
  })

  it('allows a path below the operations subtree', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ path: '/api/v1/operations/configuration/boot' }))
    expect(lastFetch?.url.pathname).toBe('/api/v1/operations/configuration/boot')
  })

  it('rejects a path-traversal segment', async () => {
    const handler = await importHandler()
    await expect(handler(makeEvent({ path: '/api/v1/operations/../admin/env' }))).rejects.toMatchObject({
      statusCode: 404,
    })
    expect(lastFetch).toBeNull()
  })

  it('rejects an encoded-traversal segment', async () => {
    const handler = await importHandler()
    await expect(handler(makeEvent({ path: '/api/v1/operations/%2e%2e/admin' }))).rejects.toMatchObject({
      statusCode: 404,
    })
    expect(lastFetch).toBeNull()
  })

  it('rejects a double-encoded traversal segment', async () => {
    const handler = await importHandler()
    await expect(handler(makeEvent({ path: '/api/v1/operations/%252e%252e/admin' }))).rejects.toMatchObject({
      statusCode: 404,
    })
    expect(lastFetch).toBeNull()
  })

  it('rejects an encoded-separator traversal hidden inside one segment', async () => {
    // E-AUDIT hardening: a single URL segment can carry an encoded separator
    // plus a traversal token (`%2e%2e%2fadmin` -> `../admin`, `..%2fadmin`).
    // The whole-segment equality check missed these because the decoded value
    // is not exactly `..`; the upstream would percent-decode and could
    // normalise them toward the admin subtree with the injected operator key.
    const handler = await importHandler()
    for (const path of [
      '/api/v1/operations/%2e%2e%2fadmin/env',
      '/api/v1/operations/..%2fadmin/env',
      '/api/v1/operations/%2f%2e%2e%2fadmin/env',
      '/api/v1/operations/foo/%252e%252e%252fadmin',
    ]) {
      await expect(handler(makeEvent({ path }))).rejects.toMatchObject({ statusCode: 404 })
      expect(lastFetch).toBeNull()
    }
  })

  it('accepts a bound-correction path whose series id is a (double-)encoded UCI', async () => {
    // Real conn/MAC/proto series ids contain "/" and ":"; the Bound Review
    // dialog double-encodes them into a single path segment. Regression for
    // the audit finding where the strict segment charset 404'd every real
    // slash/colon-bearing correction at the proxy before it reached the API.
    const series = '00:01:05:00:00:02/01:80:c2:00:00:0e///////Ethernet:LLDP'
    const encoded = encodeURIComponent(encodeURIComponent(series))
    const handler = await importHandler()
    await handler(
      makeEvent({
        path: `/api/v1/operations/bounds/${encoded}/expand`,
        method: 'POST',
        node: { req: { headers: { 'content-type': 'application/json' } } },
        _rawBody: Buffer.from(JSON.stringify({ module: 'conn', series_id: series })),
      }),
    )
    expect(lastFetch).not.toBeNull()
    expect(lastFetch?.url.pathname).toBe(`/api/v1/operations/bounds/${encoded}/expand`)
    expect(lastFetch?.init.method).toBe('POST')
  })

  it('returns 503 when no operator key is configured', async () => {
    delete process.env.OTALON_OPERATOR_KEY
    const handler = await importHandler()
    await expect(handler(makeEvent())).rejects.toMatchObject({ statusCode: 503 })
    expect(lastFetch).toBeNull()
  })

  it('returns 503 for an operator key containing forbidden header bytes', async () => {
    process.env.OTALON_OPERATOR_KEY = 'server-only\noperator-key'
    const handler = await importHandler()
    const error = await handler(makeEvent()).catch((value: unknown) => value as Error & { statusCode: number })
    expect(error).toMatchObject({ statusCode: 503 })
    expect(error.message).toBe('Operator proxy is not configured')
    expect(error.message).not.toContain(process.env.OTALON_OPERATOR_KEY)
    expect(error.message).not.toContain('test-session-123456')
    expect(lastFetch).toBeNull()
  })
})

describe('operations proxy — target + headers', () => {
  it.each(['operator', 'admin'] as const)('validates a %s session before forwarding', async (role) => {
    authRole = role
    const handler = await importHandler()
    await handler(makeEvent())
    expect(fetchCalls).toHaveLength(2)
    expect(fetchCalls[0]?.url.pathname).toBe('/api/v1/auth/me')
    expect((fetchCalls[0]?.init.headers as Headers).get('cookie')).toBe('otalon_session=test-session-123456')
    expect(lastFetch).not.toBeNull()
  })

  it('builds the upstream URL against the configured target', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ path: '/api/v1/operations/configuration/boot' }))
    expect(lastFetch?.url.origin).toBe('http://otalon-api:8090')
    expect(lastFetch?.url.pathname).toBe('/api/v1/operations/configuration/boot')
  })

  it('injects the server-side operator key and drops any client key', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ node: { req: { headers: { 'x-api-key': 'attacker-supplied' } } } }))
    const headers = lastFetch?.init.headers as Headers
    expect(headers.get('x-api-key')).toBe('server-only-operator-key')
    expect(headers.get('x-api-key')).not.toBe('attacker-supplied')
  })

  it.each(['/api/v1/operations/reset', '/api/v1/operations/restore', '/api/v1/operations/services/action'])('forwards the validated session cookie for %s', async (path) => {
    const handler = await importHandler()
    await handler(
      makeEvent({
        path,
        method: 'POST',
        node: { req: { headers: { 'content-type': 'application/json' } } },
        _rawBody: Buffer.from('{}'),
      }),
    )

    expect((lastFetch?.init.headers as Headers).get('cookie')).toBe('otalon_session=test-session-123456')
  })

  it('does not forward the session cookie for an unprotected GET path', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ path: '/api/v1/operations/services', method: 'GET' }))

    expect((lastFetch?.init.headers as Headers).get('cookie')).toBeNull()
  })

  it('does not expose the operator key in the browser response', async () => {
    fetchResponse = new Response('{"ok":true}', {
      status: 200,
      headers: { 'content-type': 'application/json', 'x-api-key': 'server-only-operator-key' },
    })
    const handler = await importHandler()
    const event = makeEvent()
    const result = (await handler(event)) as Buffer
    expect(result.toString()).toBe('{"ok":true}')
    expect(event._headers?.['x-api-key']).toBeUndefined()
  })

  it('forwards repeated query values', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ path: '/api/v1/operations/audit', _query: { category: ['config', 'bounds'] } }))
    expect(lastFetch?.url.searchParams.getAll('category')).toEqual(['config', 'bounds'])
  })

  it('forwards the raw request body for a PUT', async () => {
    const handler = await importHandler()
    const raw = Buffer.from(JSON.stringify({ key: 'TZ', value: 'UTC', reason: 'x' }))
    await handler(
      makeEvent({
        path: '/api/v1/operations/configuration/boot',
        method: 'PUT',
        node: { req: { headers: { 'content-type': 'application/json' } } },
        _rawBody: raw,
      }),
    )
    expect(lastFetch?.init.method).toBe('PUT')
    expect(lastFetch?.init.body).toBe(raw)
    expect((lastFetch?.init.headers as Headers).get('content-type')).toBe('application/json')
  })
})

describe('operations proxy — multipart upload streaming (UI-078 Wave D)', () => {
  /**
   * Build a fake raw request that is a readable Node stream of `chunks`,
   * so the handler can convert it with `Readable.toWeb` exactly as it does
   * for a real upload.
   */
  function streamingEvent(chunks: Uint8Array[], headers: Record<string, string> = {}): FakeEvent {
    const req = Readable.from(chunks) as unknown as FakeReq
    ;(req as unknown as { headers: Record<string, string> }).headers = {
      'content-type': 'multipart/form-data; boundary=----x',
      ...headers,
    }
    return makeEvent({
      path: '/api/v1/operations/pcap-import',
      method: 'POST',
      node: { req },
    })
  }

  it('forwards a multipart body as the raw Node stream, not a Buffer', async () => {
    // The body must not be a Buffer: buffering it cost +944 MB peak RSS on a
    // 300 MiB upload versus +367 MB streamed (Node 22.23, measured live).
    // The raw Node `Readable` is used rather than `Readable.toWeb()`; both
    // measured the same, so the simpler one wins.
    const handler = await importHandler()
    const event = streamingEvent([new Uint8Array([1, 2, 3])])
    await handler(event)
    expect(Buffer.isBuffer(lastFetch?.init.body)).toBe(false)
    expect(lastFetch?.init.body).toBe(event.node.req)
    expect(typeof (lastFetch?.init.body as unknown as Readable).pipe).toBe('function')
  })

  it('sets duplex: half so undici accepts the streamed body', async () => {
    const handler = await importHandler()
    await handler(streamingEvent([new Uint8Array([1])]))
    expect((lastFetch?.init as { duplex?: string }).duplex).toBe('half')
  })

  it('preserves the multipart content-type boundary and content-length', async () => {
    const handler = await importHandler()
    await handler(streamingEvent([new Uint8Array([1])], { 'content-length': '4096' }))
    const headers = lastFetch?.init.headers as Headers
    expect(headers.get('content-type')).toBe('multipart/form-data; boundary=----x')
    expect(headers.get('content-length')).toBe('4096')
  })

  it('still injects the operator key on the streamed path', async () => {
    const handler = await importHandler()
    await handler(streamingEvent([new Uint8Array([1])], { 'x-api-key': 'attacker-supplied' }))
    expect((lastFetch?.init.headers as Headers).get('x-api-key')).toBe('server-only-operator-key')
  })

  it('does not buffer the whole body before the upstream fetch starts', async () => {
    // The proof that memory stays flat: the fetch is issued while the body
    // stream is still unread. A buffering proxy could only call fetch after
    // draining every chunk.
    let pulled = 0
    const slow = new Readable({
      read() {
        pulled += 1
        this.push(pulled <= 3 ? new Uint8Array(1024) : null)
      },
    }) as unknown as FakeReq
    ;(slow as unknown as { headers: Record<string, string> }).headers = {
      'content-type': 'multipart/form-data; boundary=----x',
    }
    const handler = await importHandler()
    await handler(makeEvent({ path: '/api/v1/operations/pcap-import', method: 'POST', node: { req: slow } }))
    expect(lastFetch).not.toBeNull()
    expect(pulled).toBeLessThan(3)
  })

  it('relays the body verbatim and lets the API own the size limit', async () => {
    // A ceiling here was tried and removed: erroring the relayed stream
    // swallowed the API's authoritative 413 and stopped draining the inbound
    // request, so the still-arriving body piled up in the Nitro process
    // (~680 MB RSS for a 600 MiB upload). The pipe stays pure.
    const handler = await importHandler()
    const chunks = [new Uint8Array(1024), new Uint8Array(1024), new Uint8Array(1024)]
    await handler(streamingEvent(chunks))
    let relayed = 0
    for await (const chunk of lastFetch?.init.body as unknown as AsyncIterable<Uint8Array>) {
      relayed += chunk.byteLength
    }
    expect(relayed).toBe(3072)
  })

  it('does not abort its own upload when the drained request emits close', async () => {
    // Regression, found live: the upstream fetch consumes `event.node.req`
    // itself, so this request emits `close` as part of its own normal
    // lifecycle — both after the body is fully relayed and when the API
    // answers early (`413`) and stops reading. Wiring that to
    // `controller.abort()` destroyed the very response being forwarded:
    // every real upload died as an AbortError -> HTTP 500, and a genuine
    // 413 never reached the browser.
    const req = Object.assign(Readable.from([] as Uint8Array[]), {
      headers: { 'content-type': 'multipart/form-data; boundary=----x' },
    }) as unknown as FakeReq
    const handler = await importHandler()
    await handler(makeEvent({ path: '/api/v1/operations/pcap-import', method: 'POST', node: { req } }))
    const signal = lastFetch?.init.signal as AbortSignal
    expect(signal.aborted).toBe(false)
    ;(req as unknown as EventEmitter).emit('close')
    expect(signal.aborted).toBe(false)
  })

  it('forwards an early upstream 413 instead of losing it to an abort', async () => {
    // The API enforces its byte budget mid-stream and answers 413 while the
    // client is still sending. That status must survive the proxy.
    fetchResponse = new Response(JSON.stringify({ detail: 'Upload exceeds the configured limit of 536870912 bytes' }), {
      status: 413,
      headers: { 'content-type': 'application/json' },
    })
    const req = Object.assign(Readable.from([] as Uint8Array[]), {
      headers: { 'content-type': 'multipart/form-data; boundary=----x' },
    }) as unknown as FakeReq
    const handler = await importHandler()
    const event = makeEvent({ path: '/api/v1/operations/pcap-import', method: 'POST', node: { req } })
    ;(req as unknown as EventEmitter).emit('close')
    await handler(event)
    expect(event._status?.code).toBe(413)
  })

  it('leaves SSE disconnect propagation untouched (UI-083)', async () => {
    // The opt-out is scoped to streamed request bodies. A GET/SSE request
    // keeps the original wiring, which is what releases the API's SSE slot.
    const req = Object.assign(new EventEmitter(), { headers: {} }) as unknown as FakeReq
    fetchResponse = new Response('event: status\ndata: {}\n\n', {
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
    })
    const handler = await importHandler()
    const result = (await handler(makeEvent({ path: '/api/v1/operations/jobs/1/events', node: { req } }))) as Response
    const signal = lastFetch?.init.signal as AbortSignal
    ;(req as unknown as EventEmitter).emit('close')
    expect(signal.aborted).toBe(true)
    await result.body?.cancel().catch(() => undefined)
  })

  it('buffers a JSON body as before (no behaviour change off the upload path)', async () => {
    const handler = await importHandler()
    const raw = Buffer.from(JSON.stringify({ key: 'TZ' }))
    await handler(
      makeEvent({
        path: '/api/v1/operations/configuration/boot',
        method: 'PUT',
        node: { req: { headers: { 'content-type': 'application/json' } } },
        _rawBody: raw,
      }),
    )
    expect(lastFetch?.init.body).toBe(raw)
    expect((lastFetch?.init as { duplex?: string }).duplex).toBeUndefined()
  })
})

describe('operations proxy — response forwarding', () => {
  it('forwards upstream status and content type', async () => {
    fetchResponse = new Response('{"detail":"nope"}', {
      status: 409,
      headers: { 'content-type': 'application/json' },
    })
    const handler = await importHandler()
    const event = makeEvent()
    await handler(event)
    expect(event._status?.code).toBe(409)
    expect(event._headers?.['content-type']).toBe('application/json')
  })

  it('preserves upstream 401 status (no interception masking)', async () => {
    fetchResponse = new Response('{"detail":"Invalid or missing API key"}', {
      status: 401,
      headers: { 'content-type': 'application/json' },
    })
    const handler = await importHandler()
    const event = makeEvent()
    await handler(event)
    expect(event._status?.code).toBe(401)
  })

  it('streams SSE responses with buffering disabled', async () => {
    fetchResponse = new Response('event: status\ndata: {}\n\n', {
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
    })
    const handler = await importHandler()
    const result = (await handler(makeEvent({ path: '/api/v1/operations/jobs/1/events' }))) as Response
    expect(result).toBeInstanceOf(Response)
    expect(result.headers.get('content-type')).toBe('text/event-stream')
    expect(result.headers.get('x-accel-buffering')).toBe('no')
    expect(result.headers.get('cache-control')).toBe('no-cache')
  })
})

describe('operations proxy — SSE disconnect propagation (UI-083)', () => {
  it('passes a client-disconnect AbortSignal to the upstream fetch', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ path: '/api/v1/operations/jobs/1/events' }))
    expect(lastFetch?.init.signal).toBeInstanceOf(AbortSignal)
    expect((lastFetch?.init.signal as AbortSignal).aborted).toBe(false)
  })

  it('aborts the upstream fetch when the browser connection closes mid-stream', async () => {
    // Never-ending upstream SSE body so the only way it ends is via the
    // client-close abort the fix wires up.
    fetchResponse = new Response(
      new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.enqueue(new TextEncoder().encode('data: keep-alive\n\n'))
        },
      }),
      { status: 200, headers: { 'content-type': 'text/event-stream' } },
    )
    const req = Object.assign(new EventEmitter(), { headers: {} }) as unknown as FakeReq
    const handler = await importHandler()
    const result = (await handler(makeEvent({ path: '/api/v1/operations/jobs/1/events', node: { req } }))) as Response
    const signal = lastFetch?.init.signal as AbortSignal
    expect(signal.aborted).toBe(false)
    // Browser tab-close: the raw request emits `close`.
    ;(req as unknown as EventEmitter).emit('close')
    expect(signal.aborted).toBe(true)
    await result.body?.cancel().catch(() => undefined)
  })

  it('does not leave the request armed after a non-stream response completes', async () => {
    const req = Object.assign(new EventEmitter(), { headers: {} }) as unknown as FakeReq
    const handler = await importHandler()
    await handler(makeEvent({ path: '/api/v1/operations/configuration/boot', node: { req } }))
    // JSON (non-SSE) response: the close listener must be detached so a later
    // close on a reused socket cannot abort an unrelated request.
    expect((req as unknown as EventEmitter).listenerCount('close')).toBe(0)
  })
})
