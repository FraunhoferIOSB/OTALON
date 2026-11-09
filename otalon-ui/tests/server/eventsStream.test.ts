/**
 * Tests for the dedicated global-events SSE proxy route
 * (`server/api/v1/events/stream.get.ts`, UI-083).
 *
 * This route replaced the `routeRules` httpxy pass-through for
 * `/api/v1/events/stream` so that a browser disconnect is propagated to
 * otalon-api (releasing its SSE connection slot instead of leaking it to
 * the 50-cap → HTTP 429). The tests assert: the upstream target is built
 * against the configured API base, the `topics` query is forwarded, the
 * upstream body is streamed with buffering-disabled SSE headers, a
 * client-disconnect `AbortSignal` is handed to the upstream fetch and fires on
 * the raw request `close`, and an upstream failure surfaces as a 502.
 *
 * UI-160 adds the session-credential cases: the handler forwarded no `Cookie`
 * header, so the API's deny-by-default middleware answered every stream with
 * 401 and no live event ever reached the browser.
 */

import { EventEmitter } from 'node:events'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

interface FakeReq extends EventEmitter {
  headers: Record<string, string>
}

interface FakeEvent {
  path: string
  method: string
  node: { req: FakeReq }
  _query: Record<string, unknown>
  _cookies: Record<string, string>
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
  getCookie: (event: FakeEvent, name: string) => event._cookies[name],
}))

let lastFetch: { url: URL; init: RequestInit } | null = null
let fetchResponse: Response
let fetchShouldThrow = false

function makeReq(): FakeReq {
  return Object.assign(new EventEmitter(), { headers: {} }) as FakeReq
}

function makeEvent(overrides: Partial<FakeEvent> = {}): FakeEvent {
  return {
    path: '/api/v1/events/stream',
    method: 'GET',
    node: { req: makeReq() },
    _query: {},
    _cookies: { otalon_session: 'sess-abcdef0123456789' },
    ...overrides,
  }
}

async function importHandler() {
  const mod = await import('~~/server/api/v1/events/stream.get')
  return mod.default as (event: FakeEvent) => Promise<unknown>
}

beforeEach(() => {
  errors.length = 0
  lastFetch = null
  fetchShouldThrow = false
  fetchResponse = new Response('event: heartbeat\ndata: {}\n\n', {
    status: 200,
    headers: { 'content-type': 'text/event-stream' },
  })
  process.env.NUXT_API_PROXY_TARGET = 'http://otalon-api:8090'
  vi.stubGlobal('defineEventHandler', (fn: unknown) => fn)
  vi.stubGlobal('fetch', async (url: URL, init: RequestInit) => {
    lastFetch = { url, init }
    if (fetchShouldThrow) throw new Error('upstream refused')
    return fetchResponse
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.resetModules()
})

describe('events stream proxy — target + query', () => {
  it('builds the upstream URL against the configured API base', async () => {
    const handler = await importHandler()
    await handler(makeEvent())
    expect(lastFetch?.url.origin).toBe('http://otalon-api:8090')
    expect(lastFetch?.url.pathname).toBe('/api/v1/events/stream')
  })

  it('forwards a single topics query value', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ _query: { topics: 'health' } }))
    expect(lastFetch?.url.searchParams.get('topics')).toBe('health')
  })

  it('forwards repeated topics query values', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ _query: { topics: ['health', 'jobs'] } }))
    expect(lastFetch?.url.searchParams.getAll('topics')).toEqual(['health', 'jobs'])
  })

  it('defaults the Accept header to text/event-stream', async () => {
    const handler = await importHandler()
    await handler(makeEvent())
    expect((lastFetch?.init.headers as Headers).get('accept')).toBe('text/event-stream')
  })
})

describe('events stream proxy — session credential (UI-160)', () => {
  it('forwards the product-session cookie to the upstream API', async () => {
    const handler = await importHandler()
    await handler(makeEvent())
    expect((lastFetch?.init.headers as Headers).get('cookie')).toBe('otalon_session=sess-abcdef0123456789')
  })

  it('forwards only the session cookie, not unrelated inbound cookies', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ _cookies: { otalon_session: 'sess-abcdef0123456789', tracking: 'nope' } }))
    const cookie = (lastFetch?.init.headers as Headers).get('cookie')
    expect(cookie).toBe('otalon_session=sess-abcdef0123456789')
    expect(cookie).not.toContain('tracking')
  })

  it('sends no Cookie header when the request carries no session', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ _cookies: {} }))
    expect((lastFetch?.init.headers as Headers).get('cookie')).toBeNull()
  })
})

describe('events stream proxy — streaming + disconnect (UI-083)', () => {
  it('streams the upstream body with buffering disabled', async () => {
    const handler = await importHandler()
    const res = (await handler(makeEvent())) as Response
    expect(res).toBeInstanceOf(Response)
    expect(res.headers.get('content-type')).toBe('text/event-stream')
    expect(res.headers.get('cache-control')).toBe('no-cache')
    expect(res.headers.get('x-accel-buffering')).toBe('no')
  })

  it('passes a client-disconnect AbortSignal to the upstream fetch', async () => {
    const handler = await importHandler()
    await handler(makeEvent())
    expect(lastFetch?.init.signal).toBeInstanceOf(AbortSignal)
  })

  it('aborts the upstream fetch when the browser connection closes', async () => {
    fetchResponse = new Response(
      new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.enqueue(new TextEncoder().encode('data: tick\n\n'))
        },
      }),
      { status: 200, headers: { 'content-type': 'text/event-stream' } },
    )
    const event = makeEvent()
    const handler = await importHandler()
    const res = (await handler(event)) as Response
    const signal = lastFetch?.init.signal as AbortSignal
    expect(signal.aborted).toBe(false)
    event.node.req.emit('close')
    expect(signal.aborted).toBe(true)
    await res.body?.cancel().catch(() => undefined)
  })

  it('surfaces an upstream connection failure as 502', async () => {
    fetchShouldThrow = true
    const handler = await importHandler()
    await expect(handler(makeEvent())).rejects.toMatchObject({ statusCode: 502 })
  })
})
