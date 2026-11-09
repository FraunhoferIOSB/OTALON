/**
 * Unit tests for the useChatSettings composable.
 *
 * Verifies defaults, mutation, persistence to localStorage,
 * derived ``cssVars`` mapping and reset behaviour.
 */
import { beforeEach, describe, expect, it } from 'vitest'

import {
  CHAT_FONT_SIZE_DEFAULT,
  CHAT_FONT_SIZE_MAX,
  CHAT_FONT_SIZE_MIN,
  DEFAULT_CHAT_SETTINGS,
  clampChatFontSize,
  useChatSettings,
} from '~/composables/useChatSettings'

describe('useChatSettings', () => {
  beforeEach(() => {
    window.localStorage.clear()
    // Reset Nuxt's useState cache between tests.
    ;(globalThis as unknown as { __NUXT_STATE__: Record<string, unknown> }).__NUXT_STATE__ = {}
  })

  it('returns default settings when nothing is persisted', () => {
    const settings = useChatSettings()
    expect(settings.fontFamily.value).toBe(DEFAULT_CHAT_SETTINGS.fontFamily)
    expect(settings.fontSize.value).toBe(DEFAULT_CHAT_SETTINGS.fontSize)
    expect(settings.density.value).toBe(DEFAULT_CHAT_SETTINGS.density)
    expect(settings.showTimestamps.value).toBe(DEFAULT_CHAT_SETTINGS.showTimestamps)
    expect(settings.sendShortcut.value).toBe(DEFAULT_CHAT_SETTINGS.sendShortcut)
    expect(settings.sendUiContext.value).toBe(false)
  })

  it('persists sendUiContext changes', async () => {
    const settings = useChatSettings()
    settings.sendUiContext.value = false
    await new Promise((r) => setTimeout(r, 0))
    const raw = window.localStorage.getItem('cd-chat-settings:v1')
    expect(raw).toBeTruthy()
    expect(JSON.parse(raw as string).sendUiContext).toBe(false)
  })

  it('exposes derived CSS vars matching the current settings', () => {
    const settings = useChatSettings()
    settings.fontSize.value = 18
    settings.density.value = 'compact'

    const vars = settings.cssVars.value
    expect(vars['--cd-chat-font-size']).toBe('18px')
    expect(vars['--cd-chat-bubble-pad-y']).toBe('4px')
    expect(vars['--cd-chat-font-family']).toContain('system-ui')
  })

  it('clamps the font size to the supported range', () => {
    const settings = useChatSettings()
    settings.fontSize.value = 999
    expect(settings.fontSize.value).toBe(CHAT_FONT_SIZE_MAX)
    settings.fontSize.value = 1
    expect(settings.fontSize.value).toBe(CHAT_FONT_SIZE_MIN)
    settings.fontSize.value = 13.7
    expect(settings.fontSize.value).toBe(14)
    settings.fontSize.value = Number.NaN
    expect(settings.fontSize.value).toBe(CHAT_FONT_SIZE_DEFAULT)
  })

  it('clampChatFontSize handles strings and invalid values', () => {
    expect(clampChatFontSize('17')).toBe(17)
    expect(clampChatFontSize('not a number')).toBe(CHAT_FONT_SIZE_DEFAULT)
    expect(clampChatFontSize(undefined)).toBe(CHAT_FONT_SIZE_DEFAULT)
    expect(clampChatFontSize(-5)).toBe(CHAT_FONT_SIZE_MIN)
  })

  it('migrates legacy string font sizes from older versions', () => {
    window.localStorage.setItem('cd-chat-settings:v1', JSON.stringify({ fontSize: 'large' }))
    const settings = useChatSettings()
    expect(settings.fontSize.value).toBe(16)
  })

  it('uses the mono font stack when fontFamily=mono', () => {
    const settings = useChatSettings()
    settings.fontFamily.value = 'mono'
    expect(settings.cssVars.value['--cd-chat-font-family']).toMatch(/Menlo|monospace/i)
  })

  it('persists changes to localStorage', async () => {
    const settings = useChatSettings()
    settings.density.value = 'spacious'
    settings.showTimestamps.value = false
    // ``flush: 'post'`` watcher — give Vue a tick.
    await new Promise((r) => setTimeout(r, 0))

    const raw = window.localStorage.getItem('cd-chat-settings:v1')
    expect(raw).toBeTruthy()
    const parsed = JSON.parse(raw as string)
    expect(parsed.density).toBe('spacious')
    expect(parsed.showTimestamps).toBe(false)
  })

  it('reset() restores the defaults', () => {
    const settings = useChatSettings()
    settings.fontFamily.value = 'serif'
    settings.fontSize.value = 11
    settings.density.value = 'spacious'
    settings.showTimestamps.value = false
    settings.sendShortcut.value = 'mod-enter'

    settings.reset()

    expect(settings.fontFamily.value).toBe(DEFAULT_CHAT_SETTINGS.fontFamily)
    expect(settings.fontSize.value).toBe(DEFAULT_CHAT_SETTINGS.fontSize)
    expect(settings.density.value).toBe(DEFAULT_CHAT_SETTINGS.density)
    expect(settings.showTimestamps.value).toBe(DEFAULT_CHAT_SETTINGS.showTimestamps)
    expect(settings.sendShortcut.value).toBe(DEFAULT_CHAT_SETTINGS.sendShortcut)
  })

  it('ignores corrupted localStorage entries', () => {
    window.localStorage.setItem('cd-chat-settings:v1', '{not valid json')
    const settings = useChatSettings()
    expect(settings.fontFamily.value).toBe(DEFAULT_CHAT_SETTINGS.fontFamily)
  })
})
