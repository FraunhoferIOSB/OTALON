/**
 * Tests that all three chat server routes are behind the product-session
 * gate (audit UI-03).
 *
 * The routes inject the server-only `OTALON_AI_API_KEY`. The regression these
 * tests pin is not "the gate function is correct" (covered in
 * productSession.test.ts) but "each route actually calls it, and refuses to
 * contact otalon-ai when it fails".
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'

const gate = vi.fn()

vi.mock('~~/server/utils/productSession', () => ({
  requireProductSession: gate,
  SESSION_COOKIE_NAME: 'otalon_session',
  apiBase: () => 'http://api.test',
}))
vi.mock('../../utils/productSession', () => ({
  requireProductSession: gate,
  SESSION_COOKIE_NAME: 'otalon_session',
  apiBase: () => 'http://api.test',
}))
vi.mock('../utils/productSession', () => ({
  requireProductSession: gate,
  SESSION_COOKIE_NAME: 'otalon_session',
  apiBase: () => 'http://api.test',
}))

let handlers: Array<(event: unknown) => unknown>
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  handlers = []
  gate.mockReset()
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('defineEventHandler', (fn: (event: unknown) => unknown) => {
    handlers.push(fn)
    return fn
  })
  vi.stubGlobal('getQuery', () => ({ session_id: '11111111-2222-4333-8444-555555555555' }))
  vi.stubGlobal('readBody', async () => ({ message: 'hello' }))
  vi.stubGlobal('getRequestHeader', () => undefined)
  vi.stubGlobal('createError', (opts: { statusCode: number; statusMessage?: string }) => {
    const err = new Error(opts.statusMessage ?? String(opts.statusCode)) as Error & { statusCode: number }
    err.statusCode = opts.statusCode
    return err
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.resetModules()
})

const ROUTES: Array<[string, string]> = [
  ['chat.post', '~~/server/api/chat.post'],
  ['chat/stream.post', '~~/server/api/chat/stream.post'],
  ['chat/session.get', '~~/server/api/chat/session.get'],
]

describe.each(ROUTES)('%s is gated', (_name, modulePath) => {
  it('rejects and never contacts otalon-ai when the session is invalid', async () => {
    const denied = new Error('Authentication required') as Error & { statusCode: number }
    denied.statusCode = 401
    gate.mockRejectedValue(denied)

    const mod = await import(modulePath)
    const handler = mod.default as (event: unknown) => Promise<unknown>

    await expect(handler({ node: { req: { headers: {} } } })).rejects.toThrow()
    expect(gate).toHaveBeenCalledTimes(1)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('calls the gate before doing any upstream work', async () => {
    const order: string[] = []
    gate.mockImplementation(async () => {
      order.push('gate')
    })
    fetchMock.mockImplementation(async () => {
      order.push('fetch')
      return {
        ok: true,
        status: 200,
        body: null,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({ session_id: 'x', messages: [] }),
        text: async () => '{}',
      } as unknown as Response
    })

    const mod = await import(modulePath)
    const handler = mod.default as (event: unknown) => Promise<unknown>

    try {
      await handler({ node: { req: { headers: {} }, res: {} } })
    } catch {
      // Some routes still fail later without full Nitro scaffolding; the
      // ordering assertion below is what matters.
    }

    expect(order[0]).toBe('gate')
  })
})
