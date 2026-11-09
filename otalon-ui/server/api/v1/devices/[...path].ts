/**
 * Server-side operator-key boundary for the Devices API.
 *
 * Editing a device identity is an operator-grade mutation
 * (`PATCH /api/v1/devices/{id}`) guarded by the same `admin_api_key`
 * as the Operations subtree (`otalon-api/.../middleware/auth.py` rejects
 * non-GET without a key). The Asset List side panel edits identity fields
 * from the browser, so — exactly like `/api/v1/anomalies/**` and
 * `/api/v1/scans/**` — that traffic MUST hit this server-side keyed proxy
 * rather than the transparent client proxy, otherwise the browser reaches
 * the protected endpoint with no key (HTTP 401 "Invalid or missing API key").
 * The `devices` prefix is therefore deliberately absent from
 * `PROXIED_API_PREFIXES` in `nuxt.config.ts`.
 *
 * Mechanics (key injection, traversal rejection, query/body/SSE forwarding)
 * are shared with the Operations proxy via `~~/server/utils/operatorProxy`.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/devices'))
