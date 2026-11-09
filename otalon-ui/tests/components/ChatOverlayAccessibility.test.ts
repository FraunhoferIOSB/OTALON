/**
 * Accessibility contract tests for the Chat overlay (B-F6).
 *
 * The relocated FAB must expose an accessible named dialog and a labeled input,
 * and advertise its popup relationship, so keyboard and screen-reader users can
 * operate the panel. Actual focus-handoff timing is verified end-to-end in
 * Playwright where real browser focus is reliable; here we assert the semantic
 * attributes that make that handoff meaningful.
 */
import { mount } from '@vue/test-utils'
import { defineComponent, h, ref } from 'vue'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

const isOpen = ref(false)
const toggleChat = vi.fn(() => {
  isOpen.value = !isOpen.value
})
const closeChat = vi.fn(() => {
  isOpen.value = false
})

// The SFC resolves useChat / useChatSettings as Nuxt auto-import globals, so
// they are stubbed on globalThis (module mocks would not intercept them).
beforeAll(() => {
  ;(globalThis as Record<string, unknown>).useChat = () => ({
    isOpen,
    messages: ref([]),
    isTyping: ref(false),
    lastTokenUsage: ref({ used: null, contextWindow: null }),
    toggleChat,
    closeChat,
    sendMessage: vi.fn().mockResolvedValue(undefined),
    hydrateFromServer: vi.fn().mockResolvedValue(undefined),
  })
  ;(globalThis as Record<string, unknown>).useChatSettings = () => ({
    cssVars: ref({}),
    sendShortcut: ref('enter'),
  })
})

const passthrough = (tag: string) =>
  defineComponent({
    inheritAttrs: false,
    setup:
      (_p, { attrs, slots }) =>
      () =>
        h(tag, attrs, slots.default?.()),
  })

const inputStub = defineComponent({
  inheritAttrs: false,
  props: ['modelValue', 'placeholder'],
  setup:
    (_p, { attrs }) =>
    () =>
      h('input', { ...attrs }),
})

// Teleport-to-body is stubbed to render its content inline so attribute
// assertions can query it through the wrapper root. The teleport's real
// viewport-root behavior is verified end-to-end in Playwright; here we only
// assert the accessibility semantics on the FAB/panel/input.
const teleportStub = defineComponent({
  props: ['to', 'disabled'],
  setup:
    (_p, { slots }) =>
    () =>
      slots.default?.(),
})

const globalStubs = {
  'q-btn': passthrough('button'),
  'q-tooltip': passthrough('span'),
  'q-icon': passthrough('i'),
  'q-space': passthrough('span'),
  'q-input': inputStub,
  'q-linear-progress': passthrough('div'),
  'q-chip': passthrough('span'),
  Transition: passthrough('div'),
  Teleport: teleportStub,
  ChatSettings: passthrough('div'),
  ChatWelcomeMessage: passthrough('div'),
  ChatMessage: passthrough('div'),
  ChatContextPreview: passthrough('div'),
}

async function mountOverlay() {
  const mod = await import('~/components/chat/Overlay.vue')
  return mount(mod.default, {
    global: {
      stubs: globalStubs,
      mocks: { $q: { dark: { isActive: false } } },
    },
  })
}

describe('Chat overlay accessibility (B-F6)', () => {
  beforeEach(() => {
    isOpen.value = false
    toggleChat.mockClear()
    closeChat.mockClear()
    localStorage.clear()
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  afterAll(() => {
    delete (globalThis as Record<string, unknown>).useChat
    delete (globalThis as Record<string, unknown>).useChatSettings
  })

  it('advertises the FAB as opening a dialog popup', async () => {
    const wrapper = await mountOverlay()
    const fab = wrapper.find('[data-test="chat-fab"]')
    expect(fab.attributes('aria-haspopup')).toBe('dialog')
    expect(fab.attributes('aria-label')).toBe('Open AI Assistant')
  })

  it('exposes the opened panel as a named dialog region', async () => {
    isOpen.value = true
    const wrapper = await mountOverlay()
    const panel = wrapper.find('[data-test="chat-panel"]')
    expect(panel.exists()).toBe(true)
    expect(panel.attributes('role')).toBe('dialog')
    expect(panel.attributes('aria-label')).toBe('AI Assistant chat')
  })

  it('gives the message input an accessible label rather than relying on the placeholder', async () => {
    isOpen.value = true
    const wrapper = await mountOverlay()
    const input = wrapper.find('[data-test="chat-panel"] input')
    expect(input.attributes('aria-label')).toBe('Chat message')
  })
})
