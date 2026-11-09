/**
 * Composable for client-owned chat session identity.
 *
 * Generates a stable UUID once, persists it in localStorage, and
 * provides a rotation helper for "Clear chat".  SSR-safe: returns a
 * fresh random UUID on the server (never persisted).
 */

import { safeUUID } from '~/utils/uuid'

const STORAGE_KEY = 'cd-chat-session-id:v1'

function isValidUUID(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
}

/**
 * Return the current session ID, creating and persisting one if needed.
 */
export function getChatSessionId(): string {
  if (typeof window === 'undefined') {
    return safeUUID()
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (raw && isValidUUID(raw)) {
      return raw
    }
  } catch {
    /* ignore storage errors */
  }
  const id = safeUUID()
  try {
    window.localStorage.setItem(STORAGE_KEY, id)
  } catch {
    /* ignore quota errors */
  }
  return id
}

/**
 * Generate and persist a fresh session ID (used by "Clear chat").
 */
export function rotateChatSessionId(): string {
  const id = safeUUID()
  if (typeof window !== 'undefined') {
    try {
      window.localStorage.setItem(STORAGE_KEY, id)
    } catch {
      /* ignore quota errors */
    }
  }
  return id
}
