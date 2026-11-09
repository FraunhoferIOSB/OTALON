/** Shared presentation helpers for API authorization failures. */
export const INSUFFICIENT_PERMISSIONS_MESSAGE = 'Insufficient permissions to access this Operations resource.'

/**
 * Identifies an API error that means the current session is not authorized.
 */
export function isAuthorizationError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false
  const status = (error as { status?: unknown }).status
  return status === 401 || status === 403
}

/**
 * Converts an API authorization failure to shared UI wording while preserving
 * unrelated errors for their normal page-specific presentation.
 */
export function operationErrorMessage(error: unknown, fallback: string): string {
  if (isAuthorizationError(error)) return INSUFFICIENT_PERMISSIONS_MESSAGE
  if (error instanceof Error && error.message) return error.message
  if (error && typeof error === 'object' && 'message' in error) {
    const message = (error as { message?: unknown }).message
    if (typeof message === 'string' && message) return message
  }
  return fallback
}

export function isInsufficientPermissionsMessage(message: string | null | undefined): boolean {
  return message?.includes(INSUFFICIENT_PERMISSIONS_MESSAGE) ?? false
}
