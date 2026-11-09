/**
 * Tests for the Frequency server-side operator-key proxy
 * (`server/api/v1/frequency/[...path].ts`, UI-101 P1 fix).
 *
 * The rhythm-correction routes carry a per-route
 * `Depends(require_operator_api_key)` even though `/api/v1/frequency` is not
 * in the backend middleware's `PROTECTED_PATH_PREFIXES`. UI-101 shipped with
 * the subtree on the transparent client proxy, which injects no key, so every
 * Preview/Apply answered 401 and the drawer showed "Server preview failed".
 *
 * These tests pin the two halves of the fix that a store-level test cannot
 * see: the key is injected server-side, and the double-encoded slash-bearing
 * series-id segment survives the proxy byte-for-byte (a proxy that decoded or
 * re-encoded it would reintroduce the 404 the double-encoding exists to
 * avoid).
 */

import { Buffer } from 'node:buffer'

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

/** A verbatim production `conn` UCI — eight literal `/`, IPv6 colons. */
const REAL_CONN_SERIES =
  '7c:cb:e2:ea:0d:65/33:33:00:00:00:fb//IPv6/fe80::f6f7:3be0:3c8d:5089/ff02::fb/5353/5353/Ethernet:IPv6:UDP:DNS'

/** What the browser puts on the wire: `encodeURIComponent` applied twice. */
const DOUBLE_ENCODED = encodeURIComponent(encodeURIComponent(REAL_CONN_SERIES))

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
let fetchCalls: Array<{ url: URL; init: RequestInit }> = []

function makeEvent(overrides: Partial<FakeEvent> = {}): FakeEvent {
  const event = {
    path: `/api/v1/frequency/${DOUBLE_ENCODED}/override/preview`,
    method: 'POST',
    node: {
      req: {
        headers: { 'content-type': 'application/json', cookie: 'otalon_session=test-session-123456' },
      },
    },
    _query: { module: 'conn' },
    _rawBody: Buffer.from(JSON.stringify({ series_id: REAL_CONN_SERIES, tolerance_factor_override: 3 })),
    ...overrides,
  }
  if (event.node.req.headers.cookie === undefined) {
    event.node.req.headers.cookie = 'otalon_session=test-session-123456'
  }
  return event
}

async function importHandler() {
  const mod = await import('~~/server/api/v1/frequency/[...path]')
  return mod.default as (event: FakeEvent) => Promise<unknown>
}

beforeEach(() => {
  errors.length = 0
  lastFetch = null
  fetchCalls = []
  fetchResponse = new Response('{"module":"conn"}', { status: 200, headers: { 'content-type': 'application/json' } })
  authStatus = 200
  authRole = 'operator'
  process.env.NUXT_API_PROXY_TARGET = 'http://otalon-api:8090'
  process.env.OTALON_OPERATOR_KEY = 'server-only-operator-key'
  vi.stubGlobal('defineEventHandler', (fn: unknown) => fn)
  vi.stubGlobal('fetch', async (url: URL, init: RequestInit) => {
    fetchCalls.push({ url, init })
    if (url.pathname === '/api/v1/auth/me') {
      return new Response(JSON.stringify({ role: authRole }), {
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

describe('frequency proxy — operator key (UI-101 P1 root cause)', () => {
  it('returns 401 without a session cookie and never forwards upstream', async () => {
    const handler = await importHandler()
    const error = await handler(makeEvent({ node: { req: { headers: { cookie: '' } } } })).catch(
      (value: unknown) => value as Error & { statusCode: number },
    )
    expect(error).toMatchObject({ statusCode: 401 })
    expect(error.message).toBe('Authentication required')
    expect(error.message).not.toContain('test-session-123456')
    expect(fetchCalls).toHaveLength(0)
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

  it('injects the server-side operator key and drops any client key', async () => {
    const handler = await importHandler()

    await handler(
      makeEvent({
        node: { req: { headers: { 'content-type': 'application/json', 'x-api-key': 'browser-supplied' } } },
      }),
    )

    const headers = lastFetch?.init.headers as Headers
    expect(headers.get('x-api-key')).toBe('server-only-operator-key')
    expect(headers.get('x-api-key')).not.toBe('browser-supplied')
  })

  it('rejects a path outside the frequency subtree', async () => {
    const handler = await importHandler()

    await expect(handler(makeEvent({ path: '/api/v1/admin/shutdown' }))).rejects.toMatchObject({ statusCode: 404 })
    expect(lastFetch).toBeNull()
  })

  it('returns 503 when no operator key is configured', async () => {
    delete process.env.OTALON_OPERATOR_KEY
    const handler = await importHandler()

    await expect(handler(makeEvent())).rejects.toMatchObject({ statusCode: 503 })
    expect(lastFetch).toBeNull()
  })

  it('rejects without exposing an operator key or session cookie', async () => {
    delete process.env.OTALON_OPERATOR_KEY
    const handler = await importHandler()
    const error = await handler(makeEvent()).catch((value: unknown) => value as Error & { statusCode: number })
    expect(error).toMatchObject({ statusCode: 503 })
    expect(error.message).toBe('Operator proxy is not configured')
    expect(error.message).not.toContain('server-only-operator-key')
    expect(error.message).not.toContain('test-session-123456')
    expect(lastFetch).toBeNull()
  })
})

describe('frequency proxy — slash-bearing series id', () => {
  it('forwards the double-encoded segment unchanged', async () => {
    const handler = await importHandler()

    await handler(makeEvent())

    // `URL.pathname` keeps the escapes verbatim; decoding once must yield the
    // single-encoded form the API then unquotes back to the raw UCI.
    expect(lastFetch?.url.pathname).toBe(`/api/v1/frequency/${DOUBLE_ENCODED}/override/preview`)
    expect(decodeURIComponent(decodeURIComponent(DOUBLE_ENCODED))).toBe(REAL_CONN_SERIES)
  })

  it('accepts every correction route for a slash-bearing series', async () => {
    const handler = await importHandler()
    const suffixes = ['override/preview', 'override/apply', 'override/suggest', 'history']

    for (const suffix of suffixes) {
      // A `Response` body may only be consumed once, so each iteration needs
      // its own — the proxy reads the upstream body to forward it.
      fetchResponse = new Response('{"module":"conn"}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
      await handler(makeEvent({ path: `/api/v1/frequency/${DOUBLE_ENCODED}/${suffix}` }))
      expect(lastFetch?.url.pathname).toBe(`/api/v1/frequency/${DOUBLE_ENCODED}/${suffix}`)
    }
    expect(errors).toHaveLength(0)
  })

  it('still rejects traversal hidden in a double-encoded segment', async () => {
    const handler = await importHandler()

    await expect(handler(makeEvent({ path: '/api/v1/frequency/%252e%252e%252fadmin/history' }))).rejects.toMatchObject({
      statusCode: 404,
    })
    expect(lastFetch).toBeNull()
  })

  it('forwards the module query parameter and the raw body', async () => {
    const handler = await importHandler()
    const raw = Buffer.from(JSON.stringify({ series_id: REAL_CONN_SERIES, tolerance_factor_override: 3 }))

    await handler(makeEvent({ _rawBody: raw }))

    expect(lastFetch?.url.searchParams.get('module')).toBe('conn')
    expect(lastFetch?.init.body).toBe(raw)
  })
})

describe('frequency proxy — response forwarding', () => {
  it('preserves an upstream 409 stale-snapshot conflict', async () => {
    fetchResponse = new Response('{"detail":"profile changed since preview"}', {
      status: 409,
      headers: { 'content-type': 'application/json' },
    })
    const handler = await importHandler()
    const event = makeEvent({ path: `/api/v1/frequency/${DOUBLE_ENCODED}/override/apply` })

    await handler(event)

    expect(event._status?.code).toBe(409)
  })
})
