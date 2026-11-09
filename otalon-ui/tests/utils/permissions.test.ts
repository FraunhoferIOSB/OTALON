import { describe, expect, it } from 'vitest'

import {
  INSUFFICIENT_PERMISSIONS_MESSAGE,
  isAuthorizationError,
  isInsufficientPermissionsMessage,
  operationErrorMessage,
} from '~/utils/permissions'

describe('operations permission errors', () => {
  it('recognizes only HTTP 401 and 403', () => {
    expect(isAuthorizationError({ status: 401 })).toBe(true)
    expect(isAuthorizationError({ status: 403 })).toBe(true)
    expect(isAuthorizationError({ status: 500 })).toBe(false)
    expect(isAuthorizationError(new Error('network failure'))).toBe(false)
  })

  it('unifies authorization wording and preserves unrelated errors', () => {
    expect(operationErrorMessage({ status: 403, message: 'Insufficient role' }, 'fallback')).toBe(
      INSUFFICIENT_PERMISSIONS_MESSAGE,
    )
    expect(operationErrorMessage({ status: 500, message: 'Server unavailable' }, 'fallback')).toBe('Server unavailable')
    expect(isInsufficientPermissionsMessage('Failed to load: ' + INSUFFICIENT_PERMISSIONS_MESSAGE)).toBe(true)
  })
})
