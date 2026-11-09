/**
 * Bare-path handler for `/api/v1/devices` (no trailing segment).
 *
 * The `[...path].ts` catch-all only matches paths WITH at least one segment
 * after the prefix; a request to exactly `/api/v1/devices` falls through to
 * the SPA fallback otherwise (HTTP 200 HTML instead of JSON). Mirrors the
 * `scans/index.ts` / `anomalies/index.ts` pattern — the operator key is
 * injected so keyed reads behave identically to keyed mutations.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/devices'))
