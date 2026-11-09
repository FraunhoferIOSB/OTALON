import type { NitroFetchOptions } from 'nitropack'

/**
 * Shape of a single FastAPI ``RequestValidationError`` entry inside the
 * array-valued ``detail`` payload returned for HTTP 422 responses.
 */
export interface ApiErrorDetailItem {
  msg?: string
  loc?: unknown[]
  type?: string
  [key: string]: unknown
}

export interface ApiErrorDetailObject {
  message?: string
  retry_after?: number
  [key: string]: unknown
}

/**
 * Structured error returned by API client methods when a request fails.
 *
 * ``detail`` follows FastAPI's response shape and may be:
 * - a plain string (e.g. ``{"detail": "Not Found"}`` from 404 / custom raises),
 * - an array of validation-error objects (FastAPI 422 ``RequestValidationError``),
 * - or ``undefined`` when the upstream did not provide one.
 */
export interface ApiError {
  status: number
  message: string
  detail?: string | ApiErrorDetailItem[] | ApiErrorDetailObject
}

/**
 * Options for configuring the API client.
 */
export interface UseApiOptions {
  apiKey?: string
}

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

/**
 * Return type for the useApi composable.
 */
export interface UseApiReturn {
  get: <T>(url: string, params?: Record<string, unknown>) => Promise<T>
  post: <T>(url: string, body?: unknown) => Promise<T>
  put: <T>(url: string, body?: unknown) => Promise<T>
  patch: <T>(url: string, body?: unknown) => Promise<T>
  del: <T>(url: string, params?: Record<string, unknown>, body?: unknown) => Promise<T>
}

function buildApiError(error: unknown): ApiError {
  if (
    error &&
    typeof error === 'object' &&
    'response' in error &&
    (error as { response?: { status?: number } }).response
  ) {
    const fetchError = error as {
      response: { status: number; statusText?: string }
      data?: { detail?: string | ApiErrorDetailItem[] | ApiErrorDetailObject; message?: string }
    }
    return {
      status: fetchError.response.status,
      message: fetchError.data?.message ?? fetchError.response.statusText ?? 'Request failed',
      detail: fetchError.data?.detail,
    }
  }

  if (error instanceof Error) {
    return { status: 0, message: error.message }
  }

  return { status: 0, message: 'An unknown error occurred' }
}

/**
 * Composable providing a typed $fetch-based API client for the OTALON backend.
 *
 * Uses Nuxt's built-in $fetch with relative URLs (`/api/v1/...`).
 * All methods return typed promises and throw {@link ApiError} on failure.
 *
 * @param options - Optional configuration including an API key for admin endpoints.
 * @returns Object with get, post, patch, and del methods.
 *
 * @example
 * ```ts
 * const api = useApi()
 * const devices = await api.get<Device[]>('/api/v1/devices')
 * ```
 */
export function useApi(options?: UseApiOptions): UseApiReturn {
  const isDev = import.meta.dev

  function resolveApiKey(): string | undefined {
    if (options?.apiKey) {
      return options.apiKey
    }
    return undefined
  }

  function buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {}
    const apiKey = resolveApiKey()
    if (apiKey) {
      headers['X-API-Key'] = apiKey
    }
    return headers
  }

  async function request<T>(method: HttpMethod, url: string, fetchOptions?: NitroFetchOptions<string>): Promise<T> {
    if (isDev) {
      console.debug(`[useApi] ${method} ${url}`)
    }

    try {
      const response = await $fetch<T>(url, {
        method,
        headers: buildHeaders(),
        credentials: 'include',
        ...fetchOptions,
      })

      if (isDev) {
        console.debug(`[useApi] ${method} ${url} → OK`)
      }

      return response as T
    } catch (error: unknown) {
      const apiError = buildApiError(error)

      if (isDev) {
        console.error(`[useApi] ${method} ${url} → ${apiError.status}`, apiError.message)
      }

      throw apiError
    }
  }

  /**
   * Send a GET request.
   *
   * @param url - Relative API URL (e.g. `/api/v1/devices`).
   * @param params - Optional query parameters.
   * @returns Typed response data.
   * @throws {ApiError} On HTTP or network errors.
   */
  function get<T>(url: string, params?: Record<string, unknown>): Promise<T> {
    return request<T>('GET', url, { params })
  }

  /**
   * Send a POST request.
   *
   * @param url - Relative API URL.
   * @param body - Optional request body.
   * @returns Typed response data.
   * @throws {ApiError} On HTTP or network errors.
   */
  function post<T>(url: string, body?: unknown): Promise<T> {
    return request<T>('POST', url, { body: body as NitroFetchOptions<string>['body'] })
  }

  function put<T>(url: string, body?: unknown): Promise<T> {
    return request<T>('PUT', url, { body: body as NitroFetchOptions<string>['body'] })
  }

  /**
   * Send a PATCH request.
   *
   * @param url - Relative API URL.
   * @param body - Optional request body.
   * @returns Typed response data.
   * @throws {ApiError} On HTTP or network errors.
   */
  function patch<T>(url: string, body?: unknown): Promise<T> {
    return request<T>('PATCH', url, { body: body as NitroFetchOptions<string>['body'] })
  }

  /**
   * Send a DELETE request.
   *
   * Supports an optional ``body`` so callers can post a JSON payload
   * alongside the DELETE — used by the bulk-delete endpoint
   * (``DELETE /api/v1/devices`` with ``{"ids": [...]}``). Plain
   * single-id deletes pass only ``url`` and remain wire-compatible.
   *
   * @param url - Relative API URL.
   * @param params - Optional query parameters.
   * @param body - Optional JSON body forwarded verbatim.
   * @returns Typed response data.
   * @throws {ApiError} On HTTP or network errors.
   */
  async function del<T>(
    url: string,
    params?: Record<string, unknown>,
    body?: unknown,
    opts?: Omit<NitroFetchOptions<string>, 'params' | 'body'>,
  ): Promise<T> {
    try {
      return await request<T>('DELETE', url, {
        params,
        body: body as NitroFetchOptions<string>['body'],
        ...opts,
      })
    } catch (error: unknown) {
      const apiErr = error as ApiError
      // DELETE returning 204 No Content has an empty body; if the fetch
      // layer attempts to JSON-parse it we get a syntax error. Treat that
      // as a successful empty response so single deletes work.
      if (apiErr.status === 0 && apiErr.message.includes('Unexpected end of JSON input')) {
        return undefined as T
      }
      throw error
    }
  }

  return { get, post, put, patch, del }
}
