/**
 * Tests for the shared product-session gate (`server/utils/productSession.ts`).
 *
 * The chat routes inject the server-only `OTALON_AI_API_KEY`. Without a gate
 * anyone able to reach the UI on :8080 could drive the AI agent anonymously
 * (audit UI-03). These tests pin the decision table — including the
 * fail-closed behaviour when the API cannot be reached.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

interface FakeEvent {
  node: { req: { headers: Record<string, string> } }
}

const errors: Array<{ statusCode: number; statusMessage?: string }> = []

vi.mock('h3', () => ({
  createError: (opts: { statusCode: number; statusMessage?: string }) => {
    errors.push(opts)
    const err = new Error(opts.statusMessage ?? String(opts.statusCode)) as Error & { statusCode: number }
    err.statusCode = opts.statusCode
    return err
  },
  getCookie: (event: FakeEvent, name: string) => {
    const cookie = event.node.req.headers.cookie ?? ''
    return cookie
      .split(';')
      .map((part) => part.trim().split('='))
      .find(([key]) => key === name)?.[1]
  },
}))

const VALID_COOKIE = 'a'.repeat(32)

function eventWith(cookie?: string): FakeEvent {
  return { node: { req: { headers: cookie ? { cookie: `otalon_session=${cookie}` } : {} } } }
}

function authResponse(status: number, body: unknown = {}): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
  } as unknown as Response
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  errors.length = 0
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.resetModules()
})

async function callGate(event: FakeEvent): Promise<void> {
  const { requireProductSession } = await import('~~/server/utils/productSession')
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return requireProductSession(event as any, 'http://api.test')
}

describe('requireProductSession — rejection', () => {
  it('rejects a request without a session cookie', async () => {
    await expect(callGate(eventWith())).rejects.toThrow()
    expect(errors.at(-1)?.statusCode).toBe(401)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('rejects a malformed session cookie without calling the API', async () => {
    await expect(callGate(eventWith('short'))).rejects.toThrow()
    expect(errors.at(-1)?.statusCode).toBe(401)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('maps an upstream 401 to 401', async () => {
    fetchMock.mockResolvedValue(authResponse(401))
    await expect(callGate(eventWith(VALID_COOKIE))).rejects.toThrow()
    expect(errors.at(-1)?.statusCode).toBe(401)
  })

  it('maps an upstream 403 to 403', async () => {
    fetchMock.mockResolvedValue(authResponse(403))
    await expect(callGate(eventWith(VALID_COOKIE))).rejects.toThrow()
    expect(errors.at(-1)?.statusCode).toBe(403)
  })

  it('rejects a viewer role with 403', async () => {
    fetchMock.mockResolvedValue(authResponse(200, { role: 'viewer' }))
    await expect(callGate(eventWith(VALID_COOKIE))).rejects.toThrow()
    expect(errors.at(-1)?.statusCode).toBe(403)
  })

  it('rejects when a password change is outstanding', async () => {
    fetchMock.mockResolvedValue(authResponse(200, { role: 'operator', must_change_password: true }))
    await expect(callGate(eventWith(VALID_COOKIE))).rejects.toThrow()
    expect(errors.at(-1)?.statusCode).toBe(403)
  })

  it('rejects an unknown role with 401', async () => {
    fetchMock.mockResolvedValue(authResponse(200, { role: 'somethingelse' }))
    await expect(callGate(eventWith(VALID_COOKIE))).rejects.toThrow()
    expect(errors.at(-1)?.statusCode).toBe(401)
  })

  it('rejects a payload without a role', async () => {
    fetchMock.mockResolvedValue(authResponse(200, {}))
    await expect(callGate(eventWith(VALID_COOKIE))).rejects.toThrow()
    expect(errors.at(-1)?.statusCode).toBe(401)
  })

  it('fails closed with 502 when the API is unreachable', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(callGate(eventWith(VALID_COOKIE))).rejects.toThrow()
    expect(errors.at(-1)?.statusCode).toBe(502)
  })

  it('fails closed with 502 on an unexpected upstream status', async () => {
    fetchMock.mockResolvedValue(authResponse(500))
    await expect(callGate(eventWith(VALID_COOKIE))).rejects.toThrow()
    expect(errors.at(-1)?.statusCode).toBe(502)
  })
})

describe('requireProductSession — acceptance', () => {
  it.each(['operator', 'admin'])('accepts the %s role', async (role) => {
    fetchMock.mockResolvedValue(authResponse(200, { role }))
    await expect(callGate(eventWith(VALID_COOKIE))).resolves.toBeUndefined()
  })

  it('forwards the session cookie to the API and nothing else', async () => {
    fetchMock.mockResolvedValue(authResponse(200, { role: 'operator' }))
    await callGate(eventWith(VALID_COOKIE))

    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit]
    expect(url.toString()).toBe('http://api.test/api/v1/auth/me')
    expect(init.method).toBe('GET')
    const headers = init.headers as Headers
    expect(headers.get('cookie')).toBe(`otalon_session=${VALID_COOKIE}`)
    expect(headers.get('x-api-key')).toBeNull()
  })
})
