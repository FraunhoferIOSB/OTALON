/**
 * Composable for managing the chat overlay state.
 *
 * Provides reactive state for chat messages and overlay visibility.
 * Sends messages to the Nuxt server route which proxies to the
 * OTALON-MCP server. Falls back to an informative message
 * when the MCP server is unreachable.
 *
 * Supports both bulk (POST /api/chat) and streaming
 * (POST /api/chat/stream) transports, with automatic fallback from
 * streaming to bulk on network errors.
 */

import type { UiContext } from '~/composables/useChatContext'
import { safeUUID } from '~/utils/uuid'
import { getChatSessionId, rotateChatSessionId } from '~/composables/useChatSession'
import { parseSseStream } from '~/composables/chatStream'

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
  source?: 'otalon-ai' | 'mcp' | 'fallback'
  streaming?: boolean
  toolEvents?: Array<{ name: string; ok?: boolean }>
}

interface ChatState {
  isOpen: boolean
  messages: ChatMessage[]
  isTyping: boolean
  lastTokenUsage: { used: number | null; contextWindow: number | null }
}

interface ChatApiResponse {
  role: 'assistant'
  content: string
  source: 'otalon-ai' | 'mcp' | 'fallback'
  tokens_used?: number
  prompt_tokens?: number
  completion_tokens?: number
  context_window?: number
}

let hydrated = false

/**
 * Global chat state composable using Nuxt's useState for SSR-safe shared state.
 *
 * Communicates with the MCP server via the /api/chat Nuxt server route.
 *
 * @returns Chat state and methods to toggle, send messages, and clear history.
 */
export function useChat() {
  const state = useState<ChatState>('chat', () => ({
    isOpen: false,
    messages: [],
    isTyping: false,
    lastTokenUsage: { used: null, contextWindow: null },
  }))

  const isOpen = computed(() => state.value.isOpen)
  const messages = computed(() => state.value.messages)
  const isTyping = computed(() => state.value.isTyping)
  const lastTokenUsage = computed(() => state.value.lastTokenUsage)

  /**
   * Most recently sent ``ui_context`` snapshot. Available so that the
   * chat overlay can show what was actually transmitted to the agent
   * via the optional ContextPreview component.
   */
  const lastSnapshot = useState<UiContext | null>('chat-last-snapshot', () => null)

  /**
   * Toggle chat overlay visibility.
   */
  function toggleChat(): void {
    state.value.isOpen = !state.value.isOpen
  }

  /**
   * Open the chat overlay.
   */
  function openChat(): void {
    state.value.isOpen = true
  }

  /**
   * Close the chat overlay.
   */
  function closeChat(): void {
    state.value.isOpen = false
  }

  /**
   * Build the message history for the API request.
   *
   * @returns Array of previous messages formatted for the MCP server.
   */
  function buildHistory(): Array<{ role: string; content: string }> {
    return state.value.messages.map((msg) => ({
      role: msg.role,
      content: msg.content,
    }))
  }

  /**
   * Hydrate messages from the server-side session store.
   *
   * Runs only once per browser session and only when the local message
   * list is empty, so it never clobbers an in-flight conversation.
   */
  async function hydrateFromServer(): Promise<void> {
    if (hydrated) return
    hydrated = true
    if (state.value.messages.length > 0) return
    if (typeof window === 'undefined') return

    try {
      const sessionId = getChatSessionId()
      const data = (await $fetch('/api/chat/session', {
        query: { session_id: sessionId },
      })) as { session_id: string; messages: Array<{ role: 'user' | 'assistant'; content: string }> }

      if (data.messages.length > 0) {
        state.value.messages = data.messages.map((m) => ({
          id: safeUUID(),
          role: m.role,
          content: m.content,
          timestamp: new Date(),
          source: 'otalon-ai' as const,
        }))
      }
    } catch {
      /* hydration failure is non-fatal */
    }
  }

  function _updateTokenUsage(response: ChatApiResponse | { tokens_used?: number; prompt_tokens?: number; completion_tokens?: number; context_window?: number }): void {
    if (typeof response.tokens_used === 'number') {
      state.value.lastTokenUsage.used = response.tokens_used
    }
    if (typeof response.context_window === 'number') {
      state.value.lastTokenUsage.contextWindow = response.context_window
    }
  }

  /**
   * Send via the bulk path and append the assistant response.
   */
  async function _sendBulk(content: string, uiContext: UiContext | null): Promise<void> {
    const response = await $fetch<ChatApiResponse>('/api/chat', {
      method: 'POST',
      body: {
        session_id: getChatSessionId(),
        message: content.trim(),
        history: buildHistory(),
        ui_context: uiContext ?? undefined,
      },
    })

    const assistantMessage: ChatMessage = {
      id: safeUUID(),
      role: 'assistant',
      content: response.content,
      timestamp: new Date(),
      source: response.source,
    }
    state.value.messages = [...state.value.messages, assistantMessage]
    _updateTokenUsage(response)
  }

  /**
   * Send via the streaming path.
   */
  async function _sendStreaming(content: string, uiContext: UiContext | null): Promise<void> {
    const placeholder: ChatMessage = {
      id: safeUUID(),
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      source: 'otalon-ai',
      streaming: true,
      toolEvents: [],
    }
    state.value.messages = [...state.value.messages, placeholder]
    state.value.isTyping = true

    const replacePlaceholder = (patch: Partial<ChatMessage>) => {
      const idx = state.value.messages.findIndex((m) => m.id === placeholder.id)
      if (idx !== -1) {
        state.value.messages = state.value.messages.with(idx, { ...state.value.messages[idx], ...patch })
      }
    }

    let receivedFirstEvent = false

    try {
      const res = await fetch('/api/chat/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: getChatSessionId(),
          message: content.trim(),
          ui_context: uiContext ?? undefined,
        }),
      })

      if (!res.ok || !res.body) {
        // Remove placeholder and fall back to bulk.
        state.value.messages = state.value.messages.filter((m) => m.id !== placeholder.id)
        await _sendBulk(content, uiContext)
        return
      }

      const reader = res.body.getReader()
      try {
        await parseSseStream(reader, (evt) => {
          if (!receivedFirstEvent) {
            receivedFirstEvent = true
            state.value.isTyping = false
          }
          const t = evt.type
          if (t === 'token' && typeof evt.delta === 'string') {
            const current = state.value.messages.find((m) => m.id === placeholder.id)?.content ?? ''
            replacePlaceholder({ content: current + evt.delta })
          } else if (t === 'tool_call_started' && typeof evt.name === 'string') {
            const events = placeholder.toolEvents ?? []
            events.push({ name: evt.name })
            replacePlaceholder({ toolEvents: events })
          } else if (t === 'tool_call_completed' && typeof evt.name === 'string') {
            const events = placeholder.toolEvents ?? []
            const existing = events.find((e) => e.name === evt.name)
            if (existing) {
              existing.ok = evt.ok === true
            }
            replacePlaceholder({ toolEvents: [...events] })
          } else if (t === 'final') {
            const contentStr = typeof evt.content === 'string' ? evt.content : placeholder.content
            replacePlaceholder({
              content: contentStr,
              streaming: false,
            })
            _updateTokenUsage({
              tokens_used: typeof evt.tokens_used === 'number' ? evt.tokens_used : undefined,
              prompt_tokens: typeof evt.prompt_tokens === 'number' ? evt.prompt_tokens : undefined,
              completion_tokens: typeof evt.completion_tokens === 'number' ? evt.completion_tokens : undefined,
              context_window: typeof evt.context_window === 'number' ? evt.context_window : undefined,
            })
          } else if (t === 'error' && typeof evt.message === 'string') {
            replacePlaceholder({
              content: evt.message,
              source: 'fallback',
              streaming: false,
            })
          }
        })
      } finally {
        reader.releaseLock()
      }

      // If stream ended without a final event, keep accumulated text.
      const p = state.value.messages.find((m) => m.id === placeholder.id)
      if (p && p.streaming) {
        replacePlaceholder({
          streaming: false,
          source: p.content ? p.source : 'fallback',
        })
      }
    } catch {
      // Network error or parser failure: remove placeholder and try bulk once.
      state.value.messages = state.value.messages.filter((m) => m.id !== placeholder.id)
      await _sendBulk(content, uiContext)
    } finally {
      state.value.isTyping = false
    }
  }

  /**
   * Send a user message and receive an assistant response.
   *
   * Uses streaming when the user setting is enabled, otherwise bulk.
   *
   * @param content - The user's message text.
   */
  async function sendMessage(content: string): Promise<void> {
    if (!content.trim()) return

    const userMessage: ChatMessage = {
      id: safeUUID(),
      role: 'user',
      content: content.trim(),
      timestamp: new Date(),
    }

    state.value.messages = [...state.value.messages, userMessage]
    state.value.isTyping = true

    // Build the UI snapshot lazily so the function works in unit tests
    // that do not register the chat-context composable.
    let uiContext: UiContext | null = null
    try {
      const settings = useChatSettings()
      if (settings.sendUiContext.value) {
        const ctx = useChatContext()
        uiContext = ctx.snapshot()
        lastSnapshot.value = uiContext
      } else {
        lastSnapshot.value = null
      }
    } catch {
      uiContext = null
    }

    try {
      const settings = useChatSettings()
      if (settings.streamResponses.value) {
        await _sendStreaming(content, uiContext)
      } else {
        await _sendBulk(content, uiContext)
      }
    } catch {
      const errorMessage: ChatMessage = {
        id: safeUUID(),
        role: 'assistant',
        content:
          'Failed to reach the chat server. Please check your network connection and ensure the backend services are running.',
        timestamp: new Date(),
        source: 'fallback',
      }
      state.value.messages = [...state.value.messages, errorMessage]
    } finally {
      state.value.isTyping = false
    }
  }

  /**
   * Clear all chat messages and rotate the session ID.
   */
  function clearMessages(): void {
    state.value.messages = []
    state.value.lastTokenUsage = { used: null, contextWindow: null }
    rotateChatSessionId()
  }

  return {
    isOpen,
    messages,
    isTyping,
    lastTokenUsage,
    lastSnapshot,
    toggleChat,
    openChat,
    closeChat,
    sendMessage,
    clearMessages,
    hydrateFromServer,
  }
}
