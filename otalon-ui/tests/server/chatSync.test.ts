/**
 * Tests for the synchronous chat proxy route (`server/api/chat.post.ts`).
 *
 * Focus of this suite: the server-only credential contract for the SYNC
 * chat surface (the streaming counterpart is covered in
 * `chatStream.test.ts`). Asserts that the route
 *   - forwards the server-only `OTALON_AI_API_KEY` (mapped from the
 *     host `OTALON_AI_UI_KEY` by docker-compose) as the outbound
 *     `x-api-key`,
 *   - ignores any browser-supplied `x-api-key` header,
 *   - never leaks the key into the JSON response returned to the client,
 *   - never logs the key,
 *   - reports an actionable auth-unavailable message (not "service down")
 *     when the AI backend answers 401/503.
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

const logCalls: unknown[] = []

vi.mock('../../server/utils/logger', () => ({
  logger: {
    info: (...args: unknown[]) => logCalls.push(...args),
    warn: (...args: unknown[]) => logCalls.push(...args),
    error: (...args: unknown[]) => logCalls.push(...args),
  },
}))

interface FakeReq extends EventEmitter {
  headers: Record<string, string>
}

interface FakeEvent {
  node: { req: FakeReq }
  _body: unknown
}

const SERVER_KEY = 'server-only-ai-key'
const BROWSER_KEY = 'browser-attacker-key'

let lastFetch: { url: string; init: RequestInit } | null = null
let fetchResponse: Response
let fetchShouldThrow = false

function makeEvent(body: unknown, headers: Record<string, string> = {}): FakeEvent {
  const req = Object.assign(new EventEmitter(), { headers }) as FakeReq
  return { node: { req }, _body: body }
}

async function importHandler() {
  const mod = await import('~~/server/api/chat.post')
  return mod.default as (event: FakeEvent) => Promise<Record<string, unknown>>
}

beforeEach(() => {
  logCalls.length = 0
  lastFetch = null
  fetchShouldThrow = false
  fetchResponse = new Response(JSON.stringify({ role: 'assistant', content: 'hi', source: 'otalon-ai' }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
  process.env.CHAT_WEBHOOK_URL = 'http://otalon-ai:9100/api/v1/chat'
  process.env.OTALON_AI_API_KEY = SERVER_KEY
  vi.stubGlobal('defineEventHandler', (fn: unknown) => fn)
  vi.stubGlobal('readBody', async (event: FakeEvent) => event._body)
  vi.stubGlobal(
    'getRequestHeader',
    (event: FakeEvent, name: string) => event.node.req.headers[name.toLowerCase()],
  )
  vi.stubGlobal('createError', (opts: { statusCode: number; statusMessage?: string }) => {
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

describe('chat sync proxy — validation', () => {
  it('rejects an empty message with 400', async () => {
    const handler = await importHandler()
    await expect(handler(makeEvent({ message: '   ' }))).rejects.toMatchObject({ statusCode: 400 })
    expect(lastFetch).toBeNull()
  })
})

describe('chat sync proxy — server-only credential (SUITE-014)', () => {
  it('forwards the server-only AI key and ignores browser headers', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ message: 'hello' }, { 'x-api-key': BROWSER_KEY }))
    const headers = lastFetch?.init.headers as Record<string, string>
    expect(headers['x-api-key']).toBe(SERVER_KEY)
    expect(JSON.stringify(lastFetch)).not.toContain(BROWSER_KEY)
  })

  it('never leaks the server key into the client response body', async () => {
    const handler = await importHandler()
    const result = await handler(makeEvent({ message: 'hello' }, { 'x-api-key': BROWSER_KEY }))
    expect(JSON.stringify(result)).not.toContain(SERVER_KEY)
    expect(JSON.stringify(result)).not.toContain(BROWSER_KEY)
  })

  it('never logs the server key', async () => {
    const handler = await importHandler()
    await handler(makeEvent({ message: 'hello' }, { 'x-api-key': BROWSER_KEY }))
    expect(JSON.stringify(logCalls)).not.toContain(SERVER_KEY)
  })

  it('omits x-api-key entirely when no server key is configured', async () => {
    delete process.env.OTALON_AI_API_KEY
    const handler = await importHandler()
    await handler(makeEvent({ message: 'hello' }, { 'x-api-key': BROWSER_KEY }))
    const headers = lastFetch?.init.headers as Record<string, string>
    expect('x-api-key' in headers).toBe(false)
  })
})

describe('chat sync proxy — auth failure is actionable, not "service down"', () => {
  it.each([401, 503])('maps upstream %s to an auth-unavailable fallback', async (status) => {
    fetchResponse = new Response('nope', { status })
    const handler = await importHandler()
    const result = await handler(makeEvent({ message: 'hello' }))
    expect(result.source).toBe('fallback')
    expect(String(result.content)).toContain('authentication is unavailable')
    expect(String(result.content)).toContain('OTALON_AI_UI_KEY')
    // The key value itself must never be echoed to the client.
    expect(String(result.content)).not.toContain(SERVER_KEY)
  })
})
