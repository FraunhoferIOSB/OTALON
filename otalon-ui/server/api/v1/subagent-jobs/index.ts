/**
 * Server-side operator-key boundary for the Subagent-Jobs API — bare-path
 * entry. `GET /api/v1/subagent-jobs` (no trailing segment) is the job-list
 * read; the `[...path]` catch-all requires a segment, so the bare path would
 * otherwise fall through to the SPA.
 *
 * Mechanics are shared with the Operations proxy via
 * `~~/server/utils/operatorProxy`.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/subagent-jobs'))
