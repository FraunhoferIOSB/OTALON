/**
 * Server-side operator-key boundary for the Training API (SUITE-014).
 *
 * Boundary/classifier retraining is an operator-grade mutation guarded by the
 * same `admin_api_key` as the Operations subtree
 * (`otalon-api/src/middleware/auth.py` protects `/api/v1/training`).
 * The Detection & Training page (WAVE D) triggers retraining from the browser,
 * so — exactly like `/api/v1/operations/**` — that traffic MUST hit this
 * server-side keyed proxy rather than the transparent client proxy, otherwise
 * the browser reaches the protected endpoint with no key (HTTP 401). The
 * `training` prefix is therefore deliberately absent from
 * `PROXIED_API_PREFIXES` in `nuxt.config.ts`.
 *
 * Mechanics (key injection, traversal rejection, query/body/SSE forwarding)
 * are shared with the Operations proxy via `~~/server/utils/operatorProxy`.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/training'))
