/**
 * Composable for the AI chat overlay settings.
 *
 * Exposes user‑adjustable preferences for the chat panel:
 *   - font family (system, sans, serif, mono)
 *   - font size  (small | medium | large)
 *   - bubble density (compact | comfortable | spacious)
 *   - timestamp visibility
 *   - send shortcut (Enter to send vs. Ctrl/Cmd + Enter)
 *
 * Settings are persisted to localStorage and exposed as reactive
 * refs plus a derived ``cssVars`` map that the overlay applies to
 * the panel root so individual components do not need to know
 * about the settings themselves.
 */

import { computed, watch } from 'vue'

export type ChatFontFamily = 'system' | 'sans' | 'serif' | 'mono'
export type ChatDensity = 'compact' | 'comfortable' | 'spacious'
export type ChatSendShortcut = 'enter' | 'mod-enter'

export interface ChatSettings {
  fontFamily: ChatFontFamily
  /** Base font size in pixels. */
  fontSize: number
  density: ChatDensity
  showTimestamps: boolean
  sendShortcut: ChatSendShortcut
  /**
   * Whether to send a structured UI-context snapshot along with each
   * chat message so the AI agent knows which page the user is on,
   * what is selected, and what they currently see.
   */
  sendUiContext: boolean
  /**
   * Whether to stream the assistant response token-by-token.
   */
  streamResponses: boolean
}

const STORAGE_KEY = 'cd-chat-settings:v1'

export const CHAT_FONT_SIZE_MIN = 10
export const CHAT_FONT_SIZE_MAX = 24
export const CHAT_FONT_SIZE_DEFAULT = 14

export const DEFAULT_CHAT_SETTINGS: Readonly<ChatSettings> = Object.freeze({
  fontFamily: 'system',
  fontSize: CHAT_FONT_SIZE_DEFAULT,
  density: 'comfortable',
  showTimestamps: true,
  sendShortcut: 'enter',
  sendUiContext: false,
  streamResponses: true,
})

const FONT_FAMILY_STACKS: Record<ChatFontFamily, string> = {
  system: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
  sans: "'Inter', 'Helvetica Neue', Helvetica, Arial, sans-serif",
  serif: "Georgia, 'Times New Roman', Times, serif",
  mono: "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace",
}

/**
 * Clamp a numeric font size to the supported range and round to an
 * integer. Falls back to the default when the input is not a finite
 * number.
 */
export function clampChatFontSize(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(n)) return CHAT_FONT_SIZE_DEFAULT
  return Math.min(CHAT_FONT_SIZE_MAX, Math.max(CHAT_FONT_SIZE_MIN, Math.round(n)))
}

interface DensityTokens {
  bubblePadY: string
  bubblePadX: string
  bubbleGap: string
  rowPadY: string
}

const DENSITY_TOKENS: Record<ChatDensity, DensityTokens> = {
  compact: { bubblePadY: '4px', bubblePadX: '8px', bubbleGap: '2px', rowPadY: '2px' },
  comfortable: { bubblePadY: '8px', bubblePadX: '12px', bubbleGap: '4px', rowPadY: '4px' },
  spacious: { bubblePadY: '12px', bubblePadX: '16px', bubbleGap: '8px', rowPadY: '8px' },
}

function isValidSettings(value: unknown): value is Partial<ChatSettings> {
  return typeof value === 'object' && value !== null
}

function loadSettings(): ChatSettings {
  if (typeof window === 'undefined') {
    return { ...DEFAULT_CHAT_SETTINGS }
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...DEFAULT_CHAT_SETTINGS }
    const parsed: unknown = JSON.parse(raw)
    if (!isValidSettings(parsed)) return { ...DEFAULT_CHAT_SETTINGS }
    const merged = { ...DEFAULT_CHAT_SETTINGS, ...parsed } as ChatSettings
    // Migrate legacy string font sizes ("small"/"medium"/"large") and
    // clamp numeric values to the supported range.
    const legacyMap: Record<string, number> = { small: 12, medium: 14, large: 16 }
    if (typeof (parsed as Record<string, unknown>).fontSize === 'string') {
      const key = String((parsed as Record<string, unknown>).fontSize)
      merged.fontSize = legacyMap[key] ?? CHAT_FONT_SIZE_DEFAULT
    } else {
      merged.fontSize = clampChatFontSize(merged.fontSize)
    }
    return merged
  } catch {
    return { ...DEFAULT_CHAT_SETTINGS }
  }
}

function persistSettings(settings: ChatSettings): void {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
  } catch {
    /* ignore quota errors */
  }
}

// Module-level flag so we hydrate from localStorage exactly once per
// browser session. Subsequent calls to ``useChatSettings`` reuse the
// shared state without re-reading the storage.
let hydratedFromStorage = false

/**
 * Reset the hydration guard. Intended for unit tests that need to
 * simulate a fresh browser session without keeping cached state.
 */
export function __resetChatSettingsHydration(): void {
  hydratedFromStorage = false
}

/**
 * Reactive chat settings shared across the application via Nuxt's
 * ``useState`` so that all chat components see the same values.
 */
export function useChatSettings() {
  const state = useState<ChatSettings>('chat-settings', () => loadSettings())

  const fontFamily = computed({
    get: () => state.value.fontFamily,
    set: (value: ChatFontFamily) => {
      state.value = { ...state.value, fontFamily: value }
    },
  })

  const fontSize = computed({
    get: () => state.value.fontSize,
    set: (value: number) => {
      state.value = { ...state.value, fontSize: clampChatFontSize(value) }
    },
  })

  const density = computed({
    get: () => state.value.density,
    set: (value: ChatDensity) => {
      state.value = { ...state.value, density: value }
    },
  })

  const showTimestamps = computed({
    get: () => state.value.showTimestamps,
    set: (value: boolean) => {
      state.value = { ...state.value, showTimestamps: value }
    },
  })

  const sendShortcut = computed({
    get: () => state.value.sendShortcut,
    set: (value: ChatSendShortcut) => {
      state.value = { ...state.value, sendShortcut: value }
    },
  })

  const sendUiContext = computed({
    get: () => state.value.sendUiContext,
    set: (value: boolean) => {
      state.value = { ...state.value, sendUiContext: value }
    },
  })

  const streamResponses = computed({
    get: () => state.value.streamResponses,
    set: (value: boolean) => {
      state.value = { ...state.value, streamResponses: value }
    },
  })

  /**
   * CSS custom properties derived from the current settings. Apply
   * via ``:style`` on the chat panel root so child components pick
   * up the variables automatically.
   */
  const cssVars = computed<Record<string, string>>(() => {
    const tokens = DENSITY_TOKENS[state.value.density]
    return {
      '--cd-chat-font-family': FONT_FAMILY_STACKS[state.value.fontFamily],
      '--cd-chat-font-size': `${state.value.fontSize}px`,
      '--cd-chat-bubble-pad-y': tokens.bubblePadY,
      '--cd-chat-bubble-pad-x': tokens.bubblePadX,
      '--cd-chat-bubble-gap': tokens.bubbleGap,
      '--cd-chat-row-pad-y': tokens.rowPadY,
    }
  })

  /**
   * Reset all settings to their defaults.
   */
  function reset(): void {
    state.value = { ...DEFAULT_CHAT_SETTINGS }
  }

  // Persist on every change and rehydrate from localStorage once on the
  // client. ``useState`` is initialized during SSR where ``window`` is
  // unavailable, so without this rehydration step the persisted settings
  // would be lost across page reloads.
  if (typeof window !== 'undefined' && !hydratedFromStorage) {
    hydratedFromStorage = true
    const persisted = loadSettings()
    state.value = persisted
    watch(
      state,
      (next) => {
        persistSettings(next)
      },
      { deep: true, flush: 'post' },
    )
  }

  return {
    fontFamily,
    fontSize,
    density,
    showTimestamps,
    sendShortcut,
    sendUiContext,
    streamResponses,
    cssVars,
    reset,
    DEFAULT_CHAT_SETTINGS,
  }
}
