/**
 * Nuxt server route proxying session-history reads to otalon-ai.
 *
 * Query param: session_id (validated UUID, else 400).
 * Returns upstream JSON on success, or { session_id, messages: [] }
 * when the upstream is unavailable so the chat keeps working.
 *
 * Requires a valid product session: the route attaches the server-only
 * OTALON_AI_API_KEY, so without the gate anyone able to reach the UI could
 * read chat history anonymously (audit UI-03).
 */

import { requireProductSession } from '~~/server/utils/productSession'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function deriveAiBase(): string {
  const webhook = process.env.CHAT_WEBHOOK_URL || 'http://otalon-ai:9100/api/v1/chat'
  // Strip trailing /api/v1/chat (or /api/v1/chat/) to get the service base.
  return webhook.replace(/\/api\/v1\/chat\/?$/, '')
}

export default defineEventHandler(async (event) => {
  await requireProductSession(event)

  const query = getQuery(event)
  const sessionId = query.session_id

  if (typeof sessionId !== 'string' || !UUID_RE.test(sessionId)) {
    throw createError({ statusCode: 400, statusMessage: 'Invalid session_id' })
  }

  const aiBase = deriveAiBase()
  try {
    const aiApiKey = process.env.OTALON_AI_API_KEY
    const response = await fetch(`${aiBase}/api/v1/chat/sessions/${encodeURIComponent(sessionId)}`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        ...(aiApiKey ? { 'x-api-key': aiApiKey } : {}),
      },
      signal: AbortSignal.timeout(15_000),
    })

    if (!response.ok) {
      return { session_id: sessionId, messages: [] }
    }

    const data = (await response.json()) as { session_id: string; messages: Array<{ role: string; content: string }> }
    return data
  } catch {
    return { session_id: sessionId, messages: [] }
  }
})
