/**
 * Nuxt server route proxying chat messages to the otalon-ai chat endpoint.
 *
 * The otalon-ai service orchestrates an AI agent that has access to all
 * MCP tools (InfluxDB, PostgreSQL, PCAP, MITRE ICS ATT&CK).
 *
 * Request payload (matches otalon-ai POST /api/v1/chat):
 *   { session_id, message, history, metadata }
 *
 * Response payload (from otalon-ai):
 *   { role: "assistant", content: string, source: "otalon-ai",
 *     tokens_used?: number, prompt_tokens?: number, completion_tokens?: number,
 *     context_window?: number, tool_calls_count?: number, duration_ms?: number }
 *
 * Legacy n8n shape ({ output | reply }) is still tolerated for backward
 * compatibility but the primary path is the typed otalon-ai shape.
 *
 * Requires a valid product session: the route attaches the server-only
 * OTALON_AI_API_KEY, so without the gate anyone able to reach the UI could
 * drive the AI agent anonymously (audit UI-03).
 */

import { randomUUID } from 'node:crypto'

import { logger } from '../utils/logger'
import { buildChatPayload } from '../utils/chatPayload'
import { requireProductSession } from '../utils/productSession'

import type { UiContext } from '~~/shared/uiContext'

interface ChatRequest {
  session_id?: string
  message: string
  history?: Array<{ role: string; content: string }>
  ui_context?: UiContext
}

interface ChatResponse {
  role: 'assistant'
  content: string
  source: 'otalon-ai' | 'fallback'
  tokens_used?: number
  prompt_tokens?: number
  completion_tokens?: number
  context_window?: number
  tool_calls_count?: number
  duration_ms?: number
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const sessionStore = new Map<string, string>()

/**
 * Resolve or create a stable session ID for the current client.
 * Uses the request's X-Forwarded-For or remote address as a key
 * so repeated requests from the same browser tab share a session.
 */
function resolveSessionId(event: Parameters<typeof defineEventHandler>[0], bodySessionId?: string): string {
  if (bodySessionId && UUID_RE.test(bodySessionId)) {
    return bodySessionId
  }
  const clientKey = getRequestHeader(event, 'x-forwarded-for') ?? getRequestHeader(event, 'x-real-ip') ?? 'anonymous'

  let sessionId = sessionStore.get(clientKey)
  if (!sessionId) {
    sessionId = randomUUID()
    sessionStore.set(clientKey, sessionId)
  }
  return sessionId
}

export default defineEventHandler(async (event): Promise<ChatResponse> => {
  await requireProductSession(event)

  const body = await readBody<ChatRequest>(event)

  if (!body?.message?.trim()) {
    throw createError({
      statusCode: 400,
      statusMessage: 'Message is required',
    })
  }

  const webhookUrl = process.env.CHAT_WEBHOOK_URL || 'http://otalon-ai:9100/api/v1/chat'
  const sessionId = resolveSessionId(event, body.session_id)

  const { payload, uiContextBytes } = buildChatPayload(
    body.message.trim(),
    body.ui_context,
    sessionId,
    body.history ?? [],
  )

  logger.info(
    {
      sessionId,
      route: body.ui_context?.route?.path,
      ui_context_bytes: uiContextBytes,
    },
    'chat request received',
  )

  try {
    const aiApiKey = process.env.OTALON_AI_API_KEY
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(aiApiKey ? { 'x-api-key': aiApiKey } : {}),
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(60_000),
    })

    if (!response.ok) {
      logger.warn({ status: response.status, backendUrl: webhookUrl }, 'chat backend returned non-OK status')
      return {
        role: 'assistant',
        content:
          response.status === 401 || response.status === 503
            ? `AI authentication is unavailable (HTTP ${response.status}). Verify the server-side OTALON_AI_UI_KEY matches an entry in OTALON_AI_ALLOWED_KEYS; the service may be healthy.`
            : `AI backend returned HTTP ${response.status}. Please check the otalon-ai service logs.`,
        source: 'fallback',
      }
    }

    const rawText = await response.text()

    if (!rawText.trim()) {
      logger.warn({ backendUrl: webhookUrl, status: response.status }, 'chat backend returned empty body')
      return {
        role: 'assistant',
        content:
          'The otalon-ai service returned an empty response. This usually means the AI agent or one of its tools (e.g. the MCP server) failed. Please check the otalon-ai logs.',
        source: 'fallback',
      }
    }

    let data: Record<string, unknown>
    try {
      data = JSON.parse(rawText) as Record<string, unknown>
    } catch (parseError) {
      logger.warn(
        { err: parseError, backendUrl: webhookUrl, bodyPreview: rawText.slice(0, 200) },
        'chat backend returned non-JSON body',
      )
      return {
        role: 'assistant',
        content: 'The AI backend returned a non-JSON response. Please check the otalon-ai output format.',
        source: 'fallback',
      }
    }

    // Primary path: otalon-ai returns role/content plus optional token split.
    // Require both ``role === "assistant"`` and a non-empty ``content`` string.
    // Backward-compat: legacy n8n shape { output | reply } is still tolerated.
    let replyText: string | null = null
    let resolvedSource: ChatResponse['source'] = 'otalon-ai'

    if (data.role === 'assistant' && typeof data.content === 'string' && data.content.length > 0) {
      replyText = data.content
      // Trust the backend's ``source`` value when present and valid, else default to otalon-ai.
      if (data.source === 'fallback') resolvedSource = 'fallback'
    } else if (typeof data.reply === 'string') {
      replyText = data.reply
    } else if (typeof data.output === 'string') {
      replyText = data.output
    }

    if (!replyText) {
      logger.warn({ data }, 'unexpected chat response format')
      return {
        role: 'assistant',
        content: 'Received an unexpected response format from the AI backend.',
        source: 'fallback',
      }
    }

    const result: ChatResponse = {
      role: 'assistant',
      content: replyText,
      source: resolvedSource,
    }
    if (typeof data.tokens_used === 'number') result.tokens_used = data.tokens_used
    if (typeof data.prompt_tokens === 'number') result.prompt_tokens = data.prompt_tokens
    if (typeof data.completion_tokens === 'number') result.completion_tokens = data.completion_tokens
    if (typeof data.context_window === 'number') result.context_window = data.context_window
    if (typeof data.tool_calls_count === 'number') result.tool_calls_count = data.tool_calls_count
    if (typeof data.duration_ms === 'number') result.duration_ms = data.duration_ms
    return result
  } catch (error) {
    const isTimeout = error instanceof Error && error.name === 'TimeoutError'
    logger.error({ err: error, backendUrl: webhookUrl }, 'chat backend request failed')
    return {
      role: 'assistant',
      content: isTimeout
        ? 'The AI backend did not respond in time. The otalon-ai service may be slow or stuck.'
        : 'AI chat backend is not reachable. Please ensure the otalon-ai service is running.',
      source: 'fallback',
    }
  }
})
