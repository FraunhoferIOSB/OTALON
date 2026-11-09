/**
 * Server-side operator-key boundary for the Alerts API — bare-path entry.
 *
 * `GET /api/v1/alerts` (no trailing segment) is the alarm-list read. The
 * `[...path]` catch-all requires at least one segment, so the bare path would
 * otherwise fall through to the SPA. Routed through the same keyed proxy so
 * reads and the classify mutation behave identically.
 *
 * Mechanics are shared with the Operations proxy via
 * `~~/server/utils/operatorProxy`.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/alerts'))
