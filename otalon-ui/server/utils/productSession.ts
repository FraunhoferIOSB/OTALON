/**
 * Shared product-session gate for server routes that inject a server-only
 * credential.
 *
 * Any Nitro route that attaches a privileged key from the environment is a
 * confused deputy unless it first proves the caller owns a valid product
 * session: the browser never sees the key, but it does not need to — it
 * only needs to reach the route. The operator-key reverse proxy has always
 * validated the session before injecting `OTALON_OPERATOR_KEY`; the chat
 * routes injected `OTALON_AI_API_KEY` without any such check, so anyone who
 * could reach the UI on :8080 could drive the AI agent anonymously
 * (audit UI-03).
 *
 * Session state is owned by the API. This module deliberately holds no
 * storage of its own and delegates every decision to
 * `GET /api/v1/auth/me`.
 */

import type { H3Event } from 'h3'
import { createError, getCookie } from 'h3'

/** Name of the product-session cookie issued by the API on login. */
export const SESSION_COOKIE_NAME = 'otalon_session'

/** Roles permitted to use a server-side privileged credential. */
const AUTHORIZED_ROLES = new Set(['operator', 'admin'])

/**
 * Shape gate applied before the cookie is forwarded upstream. Rejecting
 * malformed cookies here keeps obviously-bogus values out of the auth call.
 */
const SESSION_COOKIE_RE = /^[A-Za-z0-9_-]{16,128}$/

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function rejectSession(statusCode: 401 | 403): never {
  throw createError({
    statusCode,
    statusMessage: statusCode === 403 ? 'Insufficient role' : 'Authentication required',
  })
}

/** Resolve the API origin these routes validate sessions against. */
export function apiBase(): string {
  return process.env.NUXT_API_PROXY_TARGET || 'http://localhost:8090'
}

/**
 * Throw unless the request carries a valid, sufficiently-privileged product
 * session.
 *
 * Fails closed: a validator that cannot be reached yields 502 rather than
 * granting access.
 *
 * @param event - The incoming H3 event.
 * @param base - API origin to validate against; defaults to {@link apiBase}.
 * @throws 401 when no usable session is present, 403 when the role is
 *   insufficient or a password change is outstanding, 502 when the API
 *   cannot be reached or answers unexpectedly.
 */
export async function requireProductSession(event: H3Event, base: string = apiBase()): Promise<void> {
  const sessionCookie = getCookie(event, SESSION_COOKIE_NAME)
  if (!sessionCookie) rejectSession(401)
  if (!SESSION_COOKIE_RE.test(sessionCookie)) rejectSession(401)

  const authTarget = new URL('/api/v1/auth/me', base)
  const authHeaders = new Headers({
    accept: 'application/json',
    cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}`,
  })

  let response: Response
  try {
    response = await fetch(authTarget, { method: 'GET', headers: authHeaders })
  } catch {
    throw createError({ statusCode: 502, statusMessage: 'Session validation unavailable' })
  }

  if (response.status === 401) rejectSession(401)
  if (response.status === 403) rejectSession(403)
  if (!response.ok) {
    throw createError({ statusCode: 502, statusMessage: 'Session validation failed' })
  }

  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    rejectSession(401)
  }

  const mustChangePassword = isRecord(payload) && payload.must_change_password === true
  if (mustChangePassword) rejectSession(403)

  const role = isRecord(payload) && typeof payload.role === 'string' ? payload.role : undefined
  if (role === 'viewer') rejectSession(403)
  if (!role || !AUTHORIZED_ROLES.has(role)) rejectSession(401)
}
