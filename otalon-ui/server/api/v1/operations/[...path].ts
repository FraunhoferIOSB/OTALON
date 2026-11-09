/**
 * Server-side operator-key boundary for the Operations API (SUITE-014).
 *
 * All browser traffic to `/api/v1/operations/**` is routed here (the generic
 * `/api/v1/**` client proxy is disabled for this subtree in `nuxt.config.ts`).
 * The handler injects the operator key from the server-only environment, so
 * the key is never delivered to the browser bundle. The proxy mechanics
 * (path/traversal rejection, key injection, query/body/SSE forwarding) live in
 * the shared `~~/server/utils/operatorProxy` helper and are covered by
 * `tests/server/operationsProxy.test.ts`.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/operations'))
