/**
 * Bare-path handler for `/api/v1/vulnerabilities` (no trailing segment).
 * Mirrors the `devices/index.ts` pattern.
 */

import { proxyOperatorSubtree } from '~~/server/utils/operatorProxy'

export default defineEventHandler(async (event) => proxyOperatorSubtree(event, '/api/v1/vulnerabilities'))
