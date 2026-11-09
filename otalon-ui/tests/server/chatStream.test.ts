/**
 * Tests for the chat streaming proxy route
 * (`server/api/chat/stream.post.ts`).
 *
 * Focus of this suite: the UI-083 disconnect-propagation fix. The chat proxy
 * used `new Response(upstream.body)` with a timeout-only signal, so a browser
 * disconnect leaked the upstream chat stream to otalon-ai until the 120 s
 * timeout. The route now combines the 120 s timeout with a client-disconnect
 * signal (`AbortSignal.any`) and pipes the body through the shared
 * disconnect-aware helper. Tests assert: a message is required (400), the
 * upstream fetch receives an abort signal that fires on the raw request
 * `close`, the SSE headers are buffering-disabled, and an upstream failure is a
 * 502.
 */

import { EventEmitter } from 'node:events'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// The product-session gate is exercised in productSession.test.ts and
// chatSessionGate.test.ts; stub it here so this suite keeps its focus on the
// server-only credential contract (audit UI-03).
vi.mock('~~/server/utils/productSession', () => ({
  requireProductSession: async () => undefined,
  SESSION_COOKIE_NAME: 'otalon_session',
  apiBase: () => 'http://api.test',
}))
vi.mock('../utils/productSession', () => ({
  requireProductSession: async () => undefined,
  SESSION_COOKIE_NAME: 'otalon_session',
  apiBase: () => 'http://api.test',
}))
vi.mock('../../utils/productSession', () => ({
  requireProductSession: async () => undefined,
  SESSION_COOKIE_NAME: 'otalon_session',
  apiBase: () => 'http://api.test',
}))

interface FakeReq extends EventEmitter {
  headers: Record<string, string>
}

interface FakeEvent {
  node: { req: FakeReq }
  _body: unknown
}

const errors: Array<{ statusCode: number; statusMessage?: string }> = []

vi.mock('h3', () => ({
  createError: (opts: { statusCode: number; statusMessage?: string }) => {
    errors.push(opts)
    const err = new Error(opts.statusMessage ?? String(opts.statusCode)) as Error & { statusCode: number }
    err.statusCode = opts.statusCode
    return err
  },
  readBody: async (event: FakeEvent) => event._body,
}))

let lastFetch: { url: string; init: RequestInit } | null = null
let fetchResponse: Response
let fetchShouldThrow = false

function makeReq(): FakeReq {
  return Object.assign(new EventEmitter(), { headers: {} }) as FakeReq
}

function makeEvent(body: unknown): FakeEvent {
  return { node: { req: makeReq() }, _body: body }
}

async function importHandler() {
  const mod = await import('~~/server/api/chat/stream.post')
  return mod.default as (event: FakeEvent) => Promise<unknown>
}

beforeEach(() => {
  errors.length = 0
  lastFetch = null
  fetchShouldThrow = false
  fetchResponse = new Response('event: token\ndata: {"delta":"hi"}\n\n', {
    status: 200,
    headers: { 'content-type': 'text/event-stream' },
  })
  process.env.CHAT_WEBHOOK_URL = 'http://otalon-ai:9100/api/v1/chat'
  process.env.OTALON_AI_API_KEY = 'server-only-ai-key'
  vi.stubGlobal('defineEventHandler', (fn: unknown) => fn)
  vi.stubGlobal('readBody', async (event: FakeEvent) => event._body)
  vi.stubGlobal('createError', (opts: { statusCode: number; statusMessage?: string }) => {
    errors.push(opts)
    const err = new Error(opts.statusMessage ?? String(opts.statusCode)) as Error & { statusCode: number }
    err.statusCode = opts.statusCode
    return err
  })
  vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
    lastFetch = { url, init }
    if (fetchShouldThrow) throw new Error('ai refused')
    return fetchResponse
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.resetModules()
  delete process.env.CHAT_WEBHOOK_URL
  delete process.env.OTALON_AI_API_KEY
})

describe('chat stream proxy — validation', () => {
  it('rejects an empty message with 400', async () => {
    const handler = await importHandler()
    await expect(handler(makeEvent({ message: '   ' }))).rejects.toMatchObject({ statusCode: 400 })
    expect(lastFetch).toBeNull()
  })
})

describe('chat stream proxy — disconnect propagation (UI-083)', () => {
  it('forwards an abort signal to the upstream AI fetch', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ message: 'hello' }))
    expect(lastFetch?.init.signal).toBeInstanceOf(AbortSignal)
    expect((lastFetch?.init.signal as AbortSignal).aborted).toBe(false)
  })

  it('forwards the server-only AI key and ignores browser headers', async () => {
    const event = makeEvent({ message: 'hello' })
    event.node.req.headers['x-api-key'] = 'browser-attacker-key'
    const handler = await importHandler()
    await handler(event)
    const headers = lastFetch?.init.headers as Record<string, string>
    expect(headers['x-api-key']).toBe('server-only-ai-key')
    expect(JSON.stringify(lastFetch)).not.toContain('browser-attacker-key')
  })

  it('aborts the upstream fetch when the browser connection closes', async () => {
    fetchResponse = new Response(
      new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.enqueue(new TextEncoder().encode('data: token\n\n'))
        },
      }),
      { status: 200, headers: { 'content-type': 'text/event-stream' } },
    )
    const event = makeEvent({ message: 'hello' })
    const handler = await importHandler()
    const res = (await handler(event)) as Response
    const signal = lastFetch?.init.signal as AbortSignal
    expect(signal.aborted).toBe(false)
    event.node.req.emit('close')
    expect(signal.aborted).toBe(true)
    await res.body?.cancel().catch(() => undefined)
  })

  it('streams the upstream body with buffering-disabled SSE headers', async () => {
    const handler = await importHandler()
    const res = (await handler(makeEvent({ message: 'hello' }))) as Response
    expect(res).toBeInstanceOf(Response)
    expect(res.headers.get('content-type')).toBe('text/event-stream')
    expect(res.headers.get('cache-control')).toBe('no-cache')
    expect(res.headers.get('x-accel-buffering')).toBe('no')
  })

  it('maps an upstream failure to 502', async () => {
    fetchShouldThrow = true
    const handler = await importHandler()
    await expect(handler(makeEvent({ message: 'hello' }))).rejects.toMatchObject({ statusCode: 502 })
  })

  it('maps a non-ok upstream response to 502', async () => {
    fetchResponse = new Response('nope', { status: 503 })
    const handler = await importHandler()
    await expect(handler(makeEvent({ message: 'hello' }))).rejects.toMatchObject({ statusCode: 502 })
  })
})
