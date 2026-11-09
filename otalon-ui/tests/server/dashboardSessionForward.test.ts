/**
 * Regression for UI-199: the proxy must forward the session cookie for the
 * per-account dashboard PUTs. The API accepts a session (not the operator key)
 * for exactly these pairs (otalon-api auth.py SESSION_OWNED_REQUESTS). If the
 * proxy list drifts from that set, the layout silently never persists (401).
 */
import { describe, expect, it } from 'vitest'

import { forwardsSessionCookie } from '../../server/utils/operatorProxy'

// Mirror of otalon-api auth.py SESSION_OWNED_REQUESTS (dashboard entries).
const API_SESSION_OWNED_DASHBOARD = [
  ['PUT', '/api/v1/dashboard/layout'],
  ['PUT', '/api/v1/dashboard/tour'],
] as const

describe('dashboard session cookie forwarding (UI-199)', () => {
  it.each(API_SESSION_OWNED_DASHBOARD)('forwards the session cookie for %s %s', (method, path) => {
    expect(forwardsSessionCookie(method, path)).toBe(true)
  })

  it('does not forward the cookie for an anonymous dashboard GET', () => {
    expect(forwardsSessionCookie('GET', '/api/v1/dashboard/layout')).toBe(false)
  })
})
