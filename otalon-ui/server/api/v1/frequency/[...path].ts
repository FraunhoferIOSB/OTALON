/**
 * Server-side operator-key boundary for the Frequency API (UI-101).
 *
 * The rhythm-correction routes `/api/v1/frequency/{series_id}/override/{preview,apply,suggest}`
 * and `/api/v1/frequency/{series_id}/history` are declared with
 * `Depends(require_operator_api_key)` in `otalon-api/src/api/v1/frequency.py`.
 * That dependency is enforced per route, independently of the middleware's
 * `PROTECTED_PATH_PREFIXES`, so routing this subtree through the transparent
 * client proxy in `nuxt.config.ts` delivered every correction request to the
 * backend with no key — HTTP 401 for the browser, surfaced in the drawer as
 * "Server preview failed". The Bound Review drawer never hit this because
 * `/api/v1/operations/**` has had a keyed proxy since SUITE-014.
 *
 * The `frequency` prefix is therefore deliberately absent from
 * `PROXIED_API_PREFIXES` in `nuxt.config.ts`; all of its traffic — including
 * the unprotected read endpoints `/profile` and `/profiles`, for which an
 * injected key is a no-op — flows through this handler.
 *
 * Mechanics (key injection, traversal rejection, query/body forwarding, and
 * preservation of the double-encoded series-id segment) are shared with the
 * Operations and Training proxies via `~~/server/utils/operatorProxy`.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/frequency'))
