/**
 * Secure-context-safe UUID v4 generator.
 *
 * ``crypto.randomUUID()`` is only available in a **secure context**
 * (HTTPS or ``localhost``). When the UI is served over plain HTTP from a
 * LAN IP (e.g. ``http://192.168.0.201:8080``), ``crypto.randomUUID`` is
 * ``undefined`` and calling it throws ``TypeError: crypto.randomUUID is
 * not a function`` — which previously broke the chat "Send" action.
 *
 * This helper prefers the native implementation when present and falls
 * back to a spec-compliant v4 UUID built from ``crypto.getRandomValues``
 * (available in every browser, secure context or not). A final
 * ``Math.random`` fallback covers the theoretical case where the Web
 * Crypto API itself is missing.
 */
export function safeUUID(): string {
  // Fast path: native, available in secure contexts (HTTPS / localhost).
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }

  // Fallback: RFC 4122 v4 from getRandomValues (works over plain HTTP).
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(16)
    crypto.getRandomValues(bytes)
    // Set version (4) and variant (10xx) bits per RFC 4122.
    bytes[6] = (bytes[6]! & 0x0f) | 0x40
    bytes[8] = (bytes[8]! & 0x3f) | 0x80
    const hex: string[] = []
    for (let i = 0; i < 256; i++) {
      hex.push((i + 0x100).toString(16).slice(1))
    }
    return (
      hex[bytes[0]!]! +
      hex[bytes[1]!]! +
      hex[bytes[2]!]! +
      hex[bytes[3]!]! +
      '-' +
      hex[bytes[4]!]! +
      hex[bytes[5]!]! +
      '-' +
      hex[bytes[6]!]! +
      hex[bytes[7]!]! +
      '-' +
      hex[bytes[8]!]! +
      hex[bytes[9]!]! +
      '-' +
      hex[bytes[10]!]! +
      hex[bytes[11]!]! +
      hex[bytes[12]!]! +
      hex[bytes[13]!]! +
      hex[bytes[14]!]! +
      hex[bytes[15]!]!
    )
  }

  // Last-resort fallback: non-cryptographic, but never throws.
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0
    const v = c === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}
