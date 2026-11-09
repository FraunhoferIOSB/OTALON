<template>
  <!--
    Viewport-root overlay. The root is teleported to <body> and pinned to the
    viewport (position:fixed; inset:0) with pointer-events:none, so the FAB and
    panel positioned inside it stay viewport-anchored and safe-area aware
    regardless of route content height, scroll position, theme, transformed or
    filtered ancestors, or navigation sequence. A filtered/transformed ancestor
    can otherwise turn itself into the containing block for position:fixed
    descendants and pull the FAB to page height instead of the viewport.
  -->
  <Teleport to="body">
    <div class="chat-overlay-container" data-test="chat-overlay-root">
      <!-- Floating Action Button -->
      <q-btn
        v-show="!isOpen"
        ref="fabButton"
        fab
        icon="smart_toy"
        color="primary"
        class="chat-fab"
        aria-label="Open AI Assistant"
        aria-haspopup="dialog"
        :aria-expanded="isOpen"
        data-test="chat-fab"
        @click="toggleChat"
      >
        <q-tooltip anchor="top middle" self="bottom middle">AI Assistant</q-tooltip>
      </q-btn>

      <!-- Chat Panel -->
      <Transition name="chat-slide">
        <div
          v-if="isOpen"
          class="chat-panel"
          :style="panelStyle"
          data-test="chat-panel"
          role="dialog"
          aria-modal="false"
          aria-label="AI Assistant chat"
        >
          <!-- Resize handle (top-left corner) -->
          <div
            class="chat-panel__resize"
            role="separator"
            aria-label="Resize chat panel"
            @mousedown.prevent="onResizeStart"
          >
            <q-icon name="open_in_full" size="14px" />
          </div>

          <!-- Header -->
          <div class="chat-panel__header row items-center no-wrap q-px-md q-py-sm">
            <q-icon name="smart_toy" size="22px" color="white" />
            <span class="text-subtitle1 text-weight-bold text-white q-ml-sm">AI Assistant</span>
            <q-space />
            <ChatSettings />
            <q-btn flat dense round icon="close" color="white" size="sm" aria-label="Close chat" @click="closeChat" />
          </div>

          <!-- Messages Area -->
          <div ref="messagesContainer" class="chat-panel__messages">
            <ChatWelcomeMessage v-if="messages.length === 0" @example-click="onExampleClick" />
            <ChatMessage v-for="msg in messages" :key="msg.id" :message="msg" />
            <div v-if="isTyping" class="chat-panel__typing q-px-md q-py-xs">
              <q-chip dense size="sm" color="grey-4" text-color="grey-8">
                <q-icon name="more_horiz" class="typing-dots" />
                AI is thinking...
              </q-chip>
            </div>
          </div>

          <!-- UI Context preview (collapsible) -->
          <ChatContextPreview />

          <!-- Token usage footer -->
          <div
            v-if="lastTokenUsage.used !== null && lastTokenUsage.contextWindow !== null"
            class="chat-panel__footer q-px-sm q-py-xs"
            data-test="chat-token-usage"
          >
            <q-linear-progress :value="tokenProgress" :color="tokenProgressColor" size="4px" class="q-mb-xs" />
            <div class="text-caption text-muted text-right">
              {{ formatTokens(lastTokenUsage.used) }} / {{ formatTokens(lastTokenUsage.contextWindow) }} tokens
            </div>
          </div>

          <!-- Input Area -->
          <div class="chat-panel__input row items-end no-wrap q-pa-sm">
            <q-input
              ref="messageInput"
              v-model="inputText"
              :placeholder="inputPlaceholder"
              aria-label="Chat message"
              dense
              outlined
              autogrow
              class="col"
              :maxlength="2000"
              @keydown="onInputKeydown"
            />
            <q-btn
              flat
              dense
              round
              icon="send"
              color="primary"
              class="q-ml-xs"
              :disable="!inputText.trim()"
              aria-label="Send message"
              @click="onSend"
            />
          </div>
        </div>
      </Transition>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
/**
 * Chat overlay component with FAB toggle and resizable sliding panel.
 *
 * Provides a floating chat interface layered on top of all page content.
 * Uses the useChat composable for global state management.
 *
 * The panel is resizable by dragging the handle in the top-left corner.
 * The chosen size is persisted to localStorage so it survives reloads.
 */

const { isOpen, messages, isTyping, lastTokenUsage, toggleChat, closeChat, sendMessage, hydrateFromServer } = useChat()
const { cssVars: settingsCssVars, sendShortcut } = useChatSettings()

const inputText = ref('')
const messagesContainer = ref<HTMLElement | null>(null)
// Focus targets for accessible open/close handoff (B-F6): focus enters the
// message input when the panel opens and returns to the FAB when it closes.
const fabButton = ref<{ $el?: HTMLElement } | null>(null)
const messageInput = ref<{ focus?: () => void } | null>(null)

// ── Resizable panel ────────────────────────────────────────────────
const DEFAULT_WIDTH = 520
const DEFAULT_HEIGHT = 680
const MIN_WIDTH = 320
const MIN_HEIGHT = 380

const STORAGE_KEY = 'cd-chat-panel-size:v1'

interface PanelSize {
  width: number
  height: number
}

const panelWidth = ref(DEFAULT_WIDTH)
const panelHeight = ref(DEFAULT_HEIGHT)

function clampSize(w: number, h: number): PanelSize {
  if (typeof window === 'undefined') {
    return { width: w, height: h }
  }
  const maxW = Math.max(MIN_WIDTH, window.innerWidth - 40)
  const maxH = Math.max(MIN_HEIGHT, window.innerHeight - 100)
  return {
    width: Math.min(Math.max(MIN_WIDTH, w), maxW),
    height: Math.min(Math.max(MIN_HEIGHT, h), maxH),
  }
}

function loadSize(): void {
  if (typeof window === 'undefined') return
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (!raw) return
    const parsed = JSON.parse(raw) as Partial<PanelSize>
    if (typeof parsed.width === 'number' && typeof parsed.height === 'number') {
      const { width, height } = clampSize(parsed.width, parsed.height)
      panelWidth.value = width
      panelHeight.value = height
    }
  } catch {
    /* ignore corrupted storage */
  }
}

function persistSize(): void {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ width: panelWidth.value, height: panelHeight.value }))
  } catch {
    /* ignore quota errors */
  }
}

const panelStyle = computed<Record<string, string>>(() => ({
  width: `${panelWidth.value}px`,
  height: `${panelHeight.value}px`,
  ...settingsCssVars.value,
}))

interface ResizeContext {
  startX: number
  startY: number
  startW: number
  startH: number
}
let resizeCtx: ResizeContext | null = null

function onResizeMove(event: MouseEvent): void {
  if (!resizeCtx) return
  const dx = resizeCtx.startX - event.clientX
  const dy = resizeCtx.startY - event.clientY
  const { width, height } = clampSize(resizeCtx.startW + dx, resizeCtx.startH + dy)
  panelWidth.value = width
  panelHeight.value = height
}

function onResizeEnd(): void {
  if (!resizeCtx) return
  resizeCtx = null
  document.removeEventListener('mousemove', onResizeMove)
  document.removeEventListener('mouseup', onResizeEnd)
  document.body.classList.remove('cd-chat-resizing')
  persistSize()
}

function onResizeStart(event: MouseEvent): void {
  resizeCtx = {
    startX: event.clientX,
    startY: event.clientY,
    startW: panelWidth.value,
    startH: panelHeight.value,
  }
  document.addEventListener('mousemove', onResizeMove)
  document.addEventListener('mouseup', onResizeEnd)
  document.body.classList.add('cd-chat-resizing')
}

function onWindowResize(): void {
  const { width, height } = clampSize(panelWidth.value, panelHeight.value)
  panelWidth.value = width
  panelHeight.value = height
}

onMounted(() => {
  loadSize()
  window.addEventListener('resize', onWindowResize)
  if (import.meta.client) {
    void hydrateFromServer()
  }
})

onBeforeUnmount(() => {
  if (resizeCtx) onResizeEnd()
  if (typeof window !== 'undefined') {
    window.removeEventListener('resize', onWindowResize)
  }
})

// ── Token usage display ────────────────────────────────────────────

const tokenProgress = computed(() => {
  const used = lastTokenUsage.value.used
  const total = lastTokenUsage.value.contextWindow
  if (used == null || total == null || total <= 0) return 0
  return used / total
})

const tokenProgressColor = computed(() => {
  const p = tokenProgress.value
  if (p >= 0.9) return 'negative'
  if (p >= 0.75) return 'warning'
  return 'primary'
})

function formatTokens(n: number | null): string {
  if (n == null) return '—'
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`
  return `${n}`
}

// ── Chat actions ───────────────────────────────────────────────────

function onExampleClick(text: string): void {
  inputText.value = text
}

const inputPlaceholder = computed(() =>
  sendShortcut.value === 'mod-enter' ? 'Type a message... (Ctrl+Enter to send)' : 'Type a message...',
)

function onInputKeydown(event: KeyboardEvent): void {
  if (event.key !== 'Enter') return
  const isMod = event.ctrlKey || event.metaKey
  if (sendShortcut.value === 'mod-enter') {
    if (!isMod) return
    event.preventDefault()
    void onSend()
    return
  }
  if (event.shiftKey || isMod) return
  event.preventDefault()
  void onSend()
}

async function onSend(): Promise<void> {
  if (!inputText.value.trim()) return
  const text = inputText.value
  inputText.value = ''
  scrollToBottom()
  await sendMessage(text)
  scrollToBottom()
}

function scrollToBottom(): void {
  nextTick(() => {
    if (messagesContainer.value) {
      messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight
    }
  })
}

// Auto-scroll when new messages arrive or message content mutates (streaming).
watch(messages, () => {
  scrollToBottom()
})

// Also scroll on content length changes of the last message (streaming tokens).
watch(
  () => messages.value[messages.value.length - 1]?.content,
  () => {
    scrollToBottom()
  },
)

watch(
  isOpen,
  (open, wasOpen) => {
    if (open) {
      scrollToBottom()
      // Move keyboard focus into the panel so the opened dialog is immediately
      // operable and the FAB (now hidden via v-show) never holds focus.
      nextTick(() => messageInput.value?.focus?.())
    } else if (wasOpen) {
      // Return focus to the trigger when the panel closes.
      nextTick(() => fabButton.value?.$el?.focus?.())
    }
  },
  { flush: 'post' },
)
</script>

<style scoped lang="scss">
// Viewport-pinned overlay root. Fixed + inset:0 makes it exactly the viewport
// rect and, as the nearest positioned ancestor, the containing block for the
// absolutely-positioned FAB and panel inside it — so their geometry follows the
// viewport, not route content height or scroll. pointer-events:none lets clicks
// fall through the empty overlay area; the FAB/panel re-enable pointer events.
.chat-overlay-container {
  position: fixed;
  inset: 0;
  z-index: 9999;
  pointer-events: none;
}

.chat-fab {
  position: absolute;
  bottom: 18px;
  left: 4px;
  width: 52px;
  height: 52px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
  pointer-events: auto;
}

.chat-panel {
  position: absolute;
  bottom: 80px;
  right: 20px;
  pointer-events: auto;
  border-radius: 12px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
  background-color: var(--cd-background);
  border: 1px solid var(--cd-border);
  max-width: calc(100vw - 40px);
  max-height: calc(100vh - 100px);

  &__messages,
  &__input :deep(.q-field__native),
  &__input :deep(textarea),
  &__input :deep(input) {
    font-family: var(--cd-chat-font-family, inherit);
    font-size: var(--cd-chat-font-size, 14px);
  }

  &__resize {
    position: absolute;
    top: 0;
    left: 0;
    width: 22px;
    height: 22px;
    cursor: nwse-resize;
    display: flex;
    align-items: center;
    justify-content: center;
    color: rgba(255, 255, 255, 0.85);
    z-index: 10;
    transform: rotate(90deg);
    border-bottom-right-radius: 6px;
    transition: background-color 0.15s ease;

    &:hover {
      background-color: rgba(255, 255, 255, 0.18);
    }
  }

  &__header {
    background-color: var(--q-primary);
    flex-shrink: 0;
    min-height: 48px;
    padding-left: 28px;
  }

  &__messages {
    flex: 1;
    overflow-y: auto;
    padding: 8px 0;
    background-color: var(--cd-background);
  }

  &__footer {
    flex-shrink: 0;
    border-top: 1px solid var(--cd-border);
    background-color: var(--cd-surface);
  }

  &__input {
    flex-shrink: 0;
    border-top: 1px solid var(--cd-border);
    background-color: var(--cd-surface);
  }
}

.chat-slide-enter-active,
.chat-slide-leave-active {
  transition: all 0.25s ease;
}

.chat-slide-enter-from,
.chat-slide-leave-to {
  opacity: 0;
  transform: translateY(20px) scale(0.95);
}

@media (max-width: 480px) {
  .chat-panel {
    width: calc(100vw - 24px) !important;
    right: 12px;
    bottom: 70px;
    height: 70vh !important;
  }
  .chat-panel__resize {
    display: none;
  }
}

@media (max-width: 700px) {
  .chat-fab {
    bottom: max(20px, env(safe-area-inset-bottom));
  }
}

.chat-panel__typing {
  opacity: 0.8;
}

.typing-dots {
  animation: pulse 1.5s ease-in-out infinite;
}

@keyframes pulse {
  0%,
  100% {
    opacity: 0.4;
  }
  50% {
    opacity: 1;
  }
}
</style>

<style lang="scss">
body.cd-chat-resizing {
  cursor: nwse-resize !important;
  user-select: none !important;
  -webkit-user-select: none !important;
}
</style>
