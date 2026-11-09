/**
 * Server-side operator-key boundary for the Scans API — bare-path entry.
 *
 * `POST /api/v1/scans` (no trailing segment) is the scan-trigger mutation and
 * needs the operator key injected server-side, exactly like the `[...path]`
 * sibling for nested scan paths. Without this index handler the bare path
 * falls through to the SPA (the `[...path]` catch-all requires a segment).
 *
 * Mechanics are shared with the Operations proxy via
 * `~~/server/utils/operatorProxy`.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/scans'))
