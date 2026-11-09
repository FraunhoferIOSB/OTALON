/**
 * Server-side operator-key boundary for the Subagent-Jobs API.
 *
 * `POST /api/v1/subagent-jobs/{job_id}/cancel` is an operator-grade mutation
 * guarded by `admin_api_key`. The History / forensic panels also read
 * `/api/v1/subagent-jobs/**` from the browser; routing the whole subtree
 * through this keyed proxy keeps reads working while giving the mutation the
 * operator key the transparent client proxy cannot supply (HTTP 401 without
 * it). The `subagent-jobs` prefix is therefore removed from
 * `PROXIED_API_PREFIXES` in `nuxt.config.ts`.
 *
 * Mechanics are shared with the Operations proxy via
 * `~~/server/utils/operatorProxy`.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/subagent-jobs'))
