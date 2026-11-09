/**
 * Vitest global setup file.
 *
 * Starts the MSW server before all tests, resets handlers between
 * tests, and shuts down the server after the suite completes.
 * Also polyfills `$fetch` so Pinia stores that use Nuxt's `$fetch`
 * delegate to native `fetch` (which MSW intercepts).
 * Registers Vue reactivity primitives and Nuxt composable stubs as
 * globals so that Nuxt auto-imported identifiers resolve at runtime
 * in component tests (the SFC compiler does not add imports for them).
 */
import { beforeAll, afterAll, afterEach } from 'vitest'
import * as nuxtImports from './mocks/nuxt-imports'

import { __resetChatSettingsHydration } from '~/composables/useChatSettings'
import { server } from './mocks/server'

for (const [key, value] of Object.entries(nuxtImports)) {
  ;(globalThis as Record<string, unknown>)[key] = value
}

globalThis.$fetch = async (url: string, opts?: Record<string, unknown>) => {
  const method = (opts?.method as string) ?? 'GET'
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((opts?.headers as Record<string, string>) ?? {}),
  }

  const fetchOpts: RequestInit = { method, headers }

  if (opts?.body) {
    fetchOpts.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body)
  }

  if (opts?.params) {
    const searchParams = new URLSearchParams()
    for (const [key, value] of Object.entries(opts.params as Record<string, unknown>)) {
      if (value !== undefined && value !== null) {
        searchParams.set(key, String(value))
      }
    }
    const separator = url.includes('?') ? '&' : '?'
    url = `${url}${separator}${searchParams.toString()}`
  }

  const response = await fetch(url, fetchOpts)

  if (!response.ok) {
    const error = new Error(response.statusText) as Error & {
      response: Response
      status: number
      statusMessage: string
      data?: unknown
    }
    error.response = response
    error.status = response.status
    error.statusMessage = response.statusText
    try {
      error.data = await response.json()
    } catch {
      /* response body may not be JSON */
    }
    throw error
  }

  return response.json()
}

beforeAll(() =>
  server.listen({
    // 'error' rather than 'warn': an unhandled request used to fall
    // through to the real network, producing ECONNREFUSED noise against
    // localhost:3000 and — worse — meaning a store could silently depend
    // on a live backend in a unit test (SUITE-034). Failing loudly makes
    // a missing handler obvious at the point it is introduced.
    onUnhandledRequest: 'error',
  }),
)
afterEach(() => {
  server.resetHandlers()
  // Reset the per-key useState cache so each test starts with fresh
  // state (mirrors a fresh Nuxt request).
  ;(nuxtImports as { __resetUseStateCache?: () => void }).__resetUseStateCache?.()
  __resetChatSettingsHydration()
  if (typeof window !== 'undefined') {
    window.localStorage.clear()
  }
})
afterAll(() => server.close())
