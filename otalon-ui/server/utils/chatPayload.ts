/**
 * Shared payload builder for chat POST routes (bulk + streaming).
 *
 * Applies the OT redaction policy (redact-by-default on asset/vuln
 * fields, on-prem opt-in for full context), bounds the optional
 * UI-context payload with the 16 KB cap, and renders it into the single
 * ``metadata.ui_context_markdown`` channel that otalon-ai consumes
 * (``otalon_ai/chat/router.py::_extract_ui_context_markdown``).
 */

import { renderUiContextMarkdown } from '~~/shared/renderUiContextMarkdown'

import type { UiContext } from '~~/shared/uiContext'

interface WebhookPayload {
  session_id: string
  message: string
  history: Array<{ role: string; content: string }>
  metadata: Record<string, unknown>
}

interface BuildResult {
  payload: WebhookPayload
  uiContextBytes: number
}

/** Placeholder substituted for every redacted OT value. */
export const OT_REDACTION_PLACEHOLDER = '[redacted]'

/** Hard cap on the rendered UI-context markdown block, in UTF-8 bytes. */
export const MAX_UI_CONTEXT_BYTES = 16_384

/**
 * Env flag enabling full (unredacted) OT context. Only set this when
 * the configured LLM runs on-prem — the default LiteLLM route is an
 * external SaaS provider (Auth-Hardening DECISION 5).
 */
export const ON_PREM_LLM_CONTEXT_ENV = 'OTALON_ON_PREM_LLM_CONTEXT'

const OT_CONTEXT_KEYS = new Set([
  'ip',
  'ip_address',
  'ipv4_address',
  'ipv6_address',
  'primary_ip',
  'mac',
  'mac_address',
  'primary_mac',
  'firmware',
  'firmware_version',
  'endpoint_url',
  'vuln_id',
  'cve',
])

function isOtKey(key: string): boolean {
  return OT_CONTEXT_KEYS.has(key.toLowerCase())
}

function redactCell(value: unknown): unknown {
  return value === null || value === undefined ? value : OT_REDACTION_PLACEHOLDER
}

/**
 * Recursively replace OT-identifying values (``ip``, ``mac``,
 * ``firmware``, ``endpoint_url``, CVE/vuln ids) with
 * :const:`OT_REDACTION_PLACEHOLDER`.
 *
 * Keys and table structure are preserved so the rendered markdown stays
 * well-formed and the LLM can still see *that* a value exists. Values
 * that are already ``null``/``undefined`` are left untouched.
 *
 * @param value - Any JSON-serialisable part of the UI-context snapshot.
 * @returns A redacted copy; non-object inputs are returned unchanged.
 */
export function redactOtContext(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((entry) => redactOtContext(entry))
  if (!value || typeof value !== 'object') return value

  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, isOtKey(key) ? redactCell(entry) : redactOtContext(entry)]),
  )
}

/**
 * Check whether the documented on-prem-LLM opt-in flag is set.
 *
 * @returns ``true`` when full OT context may leave the UI unredacted.
 */
export function isOnPremLlmContextEnabled(): boolean {
  return process.env[ON_PREM_LLM_CONTEXT_ENV] === 'true'
}

function prepareUiContext(uiContext: UiContext | undefined): UiContext | undefined {
  if (!uiContext || typeof uiContext !== 'object') return undefined
  if (isOnPremLlmContextEnabled()) return uiContext
  return redactOtContext(uiContext) as UiContext
}

/**
 * Build the upstream payload for the otalon-ai chat endpoint.
 *
 * The UI context travels over exactly one channel:
 * ``metadata.ui_context_markdown``. The user message is forwarded
 * verbatim — otalon-ai prefixes the context itself
 * (``agent_loop._compose_user_message``), so augmenting the message
 * here would send the same snapshot twice.
 *
 * @param message - The raw user message.
 * @param uiContext - Optional structured UI context.
 * @param sessionId - Resolved session ID.
 * @param history - Optional message history.
 * @returns The payload and the redacted UI context byte count for logging.
 */
export function buildChatPayload(
  message: string,
  uiContext: UiContext | undefined,
  sessionId: string,
  history: Array<{ role: string; content: string }>,
): BuildResult {
  // Validate and bound the optional UI-context payload. Anything that
  // looks malformed is dropped silently so the chat keeps working.
  let validContext: UiContext | undefined
  let uiContextBytes = 0
  const preparedContext = prepareUiContext(uiContext)
  if (preparedContext && typeof preparedContext === 'object') {
    try {
      const serialized = JSON.stringify(preparedContext)
      uiContextBytes = Buffer.byteLength(serialized, 'utf8')
      // Reject snapshots > 16 KB to avoid context-window bloat.
      if (uiContextBytes <= MAX_UI_CONTEXT_BYTES) validContext = preparedContext
    } catch {
      validContext = undefined
    }
  }

  const payload: WebhookPayload = {
    session_id: sessionId,
    message,
    history,
    metadata: {
      source: 'otalon-ui',
      ...(validContext ? { ui_context_markdown: renderUiContextMarkdown(validContext) } : {}),
    },
  }

  return { payload, uiContextBytes }
}
