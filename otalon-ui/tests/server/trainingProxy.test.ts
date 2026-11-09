/**
 * Tests for the Training server-side operator-key proxy
 * (`server/api/v1/training/[...path].ts`, SUITE-014 boundary).
 *
 * WAVE D drives boundary/classifier retraining from the browser. `/api/v1/training`
 * is admin-key-protected on the backend, so — like the Operations subtree — its
 * traffic must be keyed server-side, not sent through the transparent client
 * proxy (which injects no key and yields HTTP 401). These tests assert the
 * subtree restriction, server-side key injection, that a client-supplied key is
 * dropped, raw-body forwarding for the retrain POST, and upstream 401/409
 * passthrough (no interception masking).
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
    path: '/api/v1/training/retrain-boundaries/status',
    method: 'GET',
    node: { req: { headers: { cookie: 'otalon_session=test-session-123456' } } },
    _query: {},
    ...overrides,
  }
  if (event.node.req.headers.cookie === undefined) {
    event.node.req.headers.cookie = 'otalon_session=test-session-123456'
  }
  return event
}

async function importHandler() {
  const mod = await import('~~/server/api/v1/training/[...path]')
  return mod.default as (event: FakeEvent) => Promise<unknown>
}

beforeEach(() => {
  errors.length = 0
  lastFetch = null
  fetchCalls = []
  fetchResponse = new Response('{"state":"idle"}', { status: 200, headers: { 'content-type': 'application/json' } })
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

describe('training proxy — subtree + key', () => {
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

  it('rejects a path outside the training subtree', async () => {
    const handler = await importHandler()
    await expect(handler(makeEvent({ path: '/api/v1/operations/jobs' }))).rejects.toMatchObject({ statusCode: 404 })
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

  it('injects the server-side operator key and drops any client key', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ node: { req: { headers: { 'x-api-key': 'attacker-supplied' } } } }))
    const headers = lastFetch?.init.headers as Headers
    expect(headers.get('x-api-key')).toBe('server-only-operator-key')
    expect(headers.get('x-api-key')).not.toBe('attacker-supplied')
    expect(lastFetch?.url.pathname).toBe('/api/v1/training/retrain-boundaries/status')
  })

  it('forwards the raw body for a retrain-boundaries POST', async () => {
    const handler = await importHandler()
    const raw = Buffer.from(JSON.stringify({ window_start: '2026-07-01 00:00:00', window_stop: '2026-07-08 00:00:00' }))
    await handler(
      makeEvent({
        path: '/api/v1/training/retrain-boundaries',
        method: 'POST',
        node: { req: { headers: { 'content-type': 'application/json' } } },
        _rawBody: raw,
      }),
    )
    expect(lastFetch?.init.method).toBe('POST')
    expect(lastFetch?.init.body).toBe(raw)
    expect((lastFetch?.init.headers as Headers).get('content-type')).toBe('application/json')
  })
})

describe('training proxy — response forwarding', () => {
  it('preserves an upstream 409 single-flight conflict', async () => {
    fetchResponse = new Response('{"detail":"a retrain is already running"}', {
      status: 409,
      headers: { 'content-type': 'application/json' },
    })
    const handler = await importHandler()
    const event = makeEvent({ path: '/api/v1/training/retrain-boundaries', method: 'POST' })
    await handler(event)
    expect(event._status?.code).toBe(409)
  })

  it('preserves an upstream 401 status (no interception masking)', async () => {
    fetchResponse = new Response('{"detail":"Invalid or missing API key"}', {
      status: 401,
      headers: { 'content-type': 'application/json' },
    })
    const handler = await importHandler()
    const event = makeEvent()
    await handler(event)
    expect(event._status?.code).toBe(401)
  })
})
