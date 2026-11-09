/**
 * Nuxt server route proxying chat streaming requests to otalon-ai.
 *
 * Receives { session_id, message, ui_context? } and forwards to
 * POST /api/v1/chat/stream/{session_id} on the AI service, piping
 * the upstream SSE body through unchanged.
 *
 * Requires a valid product session: the route attaches the server-only
 * OTALON_AI_API_KEY, so without the gate anyone able to reach the UI could
 * drive the AI agent anonymously (audit UI-03).
 */

import { buildChatPayload } from '../../utils/chatPayload'
import { requireProductSession } from '../../utils/productSession'
import { clientDisconnectSignal, streamUpstreamSse } from '../../utils/sseProxy'

import type { UiContext } from '~~/shared/uiContext'

interface StreamRequest {
  session_id?: string
  message: string
  ui_context?: UiContext
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function deriveAiBase(): string {
  const webhook = process.env.CHAT_WEBHOOK_URL || 'http://otalon-ai:9100/api/v1/chat'
  return webhook.replace(/\/api\/v1\/chat\/?$/, '')
}

function resolveSessionId(body: StreamRequest): string {
  if (body.session_id && UUID_RE.test(body.session_id)) {
    return body.session_id
  }
  return crypto.randomUUID()
}

export default defineEventHandler(async (event) => {
  await requireProductSession(event)

  const body = await readBody<StreamRequest>(event)

  if (!body?.message?.trim()) {
    throw createError({ statusCode: 400, statusMessage: 'Message is required' })
  }

  const sessionId = resolveSessionId(body)
  const { payload } = buildChatPayload(body.message.trim(), body.ui_context, sessionId, [])
  const aiBase = deriveAiBase()

  // Abort the upstream chat stream both on the 120 s cap AND when the browser
  // disconnects, so otalon-ai releases its side of the stream instead of
  // leaking it until timeout (UI-083; same disconnect-propagation defect as the
  // Operations events feed).
  const disconnect = clientDisconnectSignal(event)
  const signal = AbortSignal.any([disconnect.signal, AbortSignal.timeout(120_000)])

  try {
    const aiApiKey = process.env.OTALON_AI_API_KEY
    const upstream = await fetch(`${aiBase}/api/v1/chat/stream/${encodeURIComponent(sessionId)}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
        ...(aiApiKey ? { 'x-api-key': aiApiKey } : {}),
      },
      body: JSON.stringify({ message: payload.message, metadata: payload.metadata }),
      signal,
    })

    if (!upstream.ok || !upstream.body) {
      disconnect.detach()
      throw createError({ statusCode: 502, statusMessage: 'stream-unavailable' })
    }

    return streamUpstreamSse(upstream.body, disconnect)
  } catch (err) {
    disconnect.detach()
    if (err && typeof err === 'object' && 'statusCode' in err) throw err
    throw createError({ statusCode: 502, statusMessage: 'stream-unavailable' })
  }
})
