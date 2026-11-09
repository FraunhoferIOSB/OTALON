/**
 * Server-side operator-key boundary for the Alerts API.
 *
 * `POST /api/v1/alerts/{alarm_id}/classify` (AI-agent forensic analysis) is an
 * operator-grade mutation guarded by `admin_api_key`. The Alarm list/detail UI
 * also reads `/api/v1/alerts/**` from the browser; routing the whole subtree
 * through this keyed proxy keeps reads working while giving the mutation the
 * operator key the transparent client proxy cannot supply (HTTP 401 without
 * it). The `alerts` prefix is therefore removed from `PROXIED_API_PREFIXES` in
 * `nuxt.config.ts`.
 *
 * Mechanics are shared with the Operations proxy via
 * `~~/server/utils/operatorProxy`.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/alerts'))
