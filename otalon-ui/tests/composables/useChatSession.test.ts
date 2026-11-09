import { describe, it, expect, beforeEach } from 'vitest'
import { getChatSessionId, rotateChatSessionId } from '~/composables/useChatSession'

describe('useChatSession', () => {
  beforeEach(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.clear()
    }
  })

  it('generates a UUID when none is stored', () => {
    const id = getChatSessionId()
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
  })

  it('returns the same ID on repeated calls', () => {
    const a = getChatSessionId()
    const b = getChatSessionId()
    expect(a).toBe(b)
  })

  it('persists to localStorage', () => {
    const id = getChatSessionId()
    expect(window.localStorage.getItem('cd-chat-session-id:v1')).toBe(id)
  })

  it('returns a new ID after rotation', () => {
    const oldId = getChatSessionId()
    const newId = rotateChatSessionId()
    expect(newId).not.toBe(oldId)
    expect(window.localStorage.getItem('cd-chat-session-id:v1')).toBe(newId)
  })
})
