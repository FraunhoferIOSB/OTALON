/**
 * Unit tests for the useApi composable.
 *
 * Validates HTTP method delegation, query parameter forwarding,
 * API key header injection, and structured ApiError construction
 * on failed requests. Uses the MSW server from test setup to
 * intercept $fetch calls via the globalThis.$fetch polyfill.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { http, HttpResponse } from 'msw'

import { server } from '../mocks/server'

vi.stubGlobal('useRuntimeConfig', () => ({ public: {} }))

const { useApi } = await import('~/composables/useApi')

describe('useApi', () => {
  let api: ReturnType<typeof useApi>

  beforeEach(() => {
    api = useApi()
  })

  afterEach(() => {
    server.resetHandlers()
  })

  describe('get()', () => {
    it('sends GET request to the correct URL and returns typed data', async () => {
      server.use(
        http.get('*/api/v1/test-resource', () => {
          return HttpResponse.json({ items: [1, 2, 3] })
        }),
      )

      const result = await api.get<{ items: number[] }>('/api/v1/test-resource')
      expect(result.items).toEqual([1, 2, 3])
    })

    it('passes query parameters as URL search params', async () => {
      let capturedUrl = ''

      server.use(
        http.get('*/api/v1/filtered', ({ request }) => {
          capturedUrl = request.url
          return HttpResponse.json({ ok: true })
        }),
      )

      await api.get('/api/v1/filtered', { limit: 10, module: 'netcap' })

      const url = new URL(capturedUrl)
      expect(url.searchParams.get('limit')).toBe('10')
      expect(url.searchParams.get('module')).toBe('netcap')
    })

    it('sends GET request without params when none are provided', async () => {
      let capturedUrl = ''

      server.use(
        http.get('*/api/v1/no-params', ({ request }) => {
          capturedUrl = request.url
          return HttpResponse.json({ ok: true })
        }),
      )

      await api.get('/api/v1/no-params')

      const url = new URL(capturedUrl)
      expect(url.searchParams.toString()).toBe('')
    })
  })

  describe('post()', () => {
    it('sends POST request with JSON body', async () => {
      let capturedBody: unknown = null

      server.use(
        http.post('*/api/v1/resources', async ({ request }) => {
          capturedBody = await request.json()
          return HttpResponse.json({ id: 'new-1' })
        }),
      )

      const result = await api.post<{ id: string }>('/api/v1/resources', { name: 'test' })

      expect(result.id).toBe('new-1')
      expect(capturedBody).toEqual({ name: 'test' })
    })

    it('sends POST request without body when none is provided', async () => {
      server.use(
        http.post('*/api/v1/trigger', () => {
          return HttpResponse.json({ triggered: true })
        }),
      )

      const result = await api.post<{ triggered: boolean }>('/api/v1/trigger')
      expect(result.triggered).toBe(true)
    })
  })

  describe('patch()', () => {
    it('sends PATCH request with JSON body', async () => {
      let capturedBody: unknown = null

      server.use(
        http.patch('*/api/v1/resources/42', async ({ request }) => {
          capturedBody = await request.json()
          return HttpResponse.json({ updated: true })
        }),
      )

      const result = await api.patch<{ updated: boolean }>('/api/v1/resources/42', {
        confirmed: true,
      })

      expect(result.updated).toBe(true)
      expect(capturedBody).toEqual({ confirmed: true })
    })
  })

  describe('del()', () => {
    it('sends DELETE request to the correct URL', async () => {
      let capturedMethod = ''

      server.use(
        http.delete('*/api/v1/resources/42', ({ request }) => {
          capturedMethod = request.method
          return HttpResponse.json({ deleted: true })
        }),
      )

      const result = await api.del<{ deleted: boolean }>('/api/v1/resources/42')

      expect(result.deleted).toBe(true)
      expect(capturedMethod).toBe('DELETE')
    })

    it('passes query parameters on DELETE requests', async () => {
      let capturedUrl = ''

      server.use(
        http.delete('*/api/v1/resources', ({ request }) => {
          capturedUrl = request.url
          return HttpResponse.json({ deleted: true })
        }),
      )

      await api.del('/api/v1/resources', { force: true })

      const url = new URL(capturedUrl)
      expect(url.searchParams.get('force')).toBe('true')
    })
  })

  describe('error handling', () => {
    it('throws ApiError with status 404 on Not Found response', async () => {
      server.use(
        http.get('*/api/v1/missing', () => {
          return HttpResponse.json({ detail: 'Not found' }, { status: 404 })
        }),
      )

      try {
        await api.get('/api/v1/missing')
        expect.fail('Expected ApiError to be thrown')
      } catch (error) {
        const apiError = error as { status: number; message: string; detail?: string }
        expect(apiError.status).toBe(404)
        expect(apiError.message).toBeDefined()
      }
    })

    it('throws ApiError with status 500 on Internal Server Error', async () => {
      server.use(
        http.get('*/api/v1/broken', () => {
          return HttpResponse.json(
            { detail: 'Internal server error', message: 'Something went wrong' },
            { status: 500 },
          )
        }),
      )

      try {
        await api.get('/api/v1/broken')
        expect.fail('Expected ApiError to be thrown')
      } catch (error) {
        const apiError = error as { status: number; message: string; detail?: string }
        expect(apiError.status).toBe(500)
      }
    })

    it('includes detail field from error response body', async () => {
      server.use(
        http.post('*/api/v1/invalid', () => {
          return HttpResponse.json({ detail: 'Validation failed', message: 'Invalid input' }, { status: 422 })
        }),
      )

      try {
        await api.post('/api/v1/invalid', { bad: 'data' })
        expect.fail('Expected ApiError to be thrown')
      } catch (error) {
        const apiError = error as { status: number; message: string; detail?: string }
        expect(apiError.status).toBe(422)
        expect(apiError.detail).toBe('Validation failed')
      }
    })
  })

  describe('API key header', () => {
    it('includes X-API-Key header when apiKey option is provided', async () => {
      let capturedHeaders: Headers | null = null

      server.use(
        http.get('*/api/v1/admin/resource', ({ request }) => {
          capturedHeaders = new Headers(request.headers)
          return HttpResponse.json({ secured: true })
        }),
      )

      const securedApi = useApi({ apiKey: 'test-secret-key' })
      await securedApi.get('/api/v1/admin/resource')

      expect(capturedHeaders).not.toBeNull()
      expect(capturedHeaders!.get('X-API-Key')).toBe('test-secret-key')
    })

    it('does not include X-API-Key header when no apiKey is provided', async () => {
      let capturedHeaders: Headers | null = null

      server.use(
        http.get('*/api/v1/public/resource', ({ request }) => {
          capturedHeaders = new Headers(request.headers)
          return HttpResponse.json({ public: true })
        }),
      )

      await api.get('/api/v1/public/resource')

      expect(capturedHeaders).not.toBeNull()
      expect(capturedHeaders!.get('X-API-Key')).toBeNull()
    })
  })
})
