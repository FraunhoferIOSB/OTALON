/**
 * Unit tests for useOperationsNotify.
 *
 * Verifies the single-toast contract: a second notification dismisses the
 * first one and the toast carries the expected message/type.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockNotify = vi.fn(() => () => {})

vi.doMock('quasar', () => ({
  useQuasar: () => ({ notify: mockNotify }),
}))

const { useOperationsNotify } = await import('~/composables/useOperationsNotify')

describe('useOperationsNotify', () => {
  beforeEach(() => {
    mockNotify.mockClear()
  })

  it('shows one toast with message and type', () => {
    const notify = useOperationsNotify()
    notify({ message: 'Pipeline refreshed', type: 'positive' })

    expect(mockNotify).toHaveBeenCalledTimes(1)
    const call = mockNotify.mock.calls[0]![0] as { message: string; type: string }
    expect(call.message).toBe('Pipeline refreshed')
    expect(call.type).toBe('positive')
    expect(call.position).toBe('bottom-right')
  })

  it('dismisses the previous toast before showing a new one', () => {
    const dismiss = vi.fn()
    mockNotify.mockReturnValueOnce(dismiss)

    const notify = useOperationsNotify()
    notify({ message: 'First' })
    notify({ message: 'Second' })

    expect(dismiss).toHaveBeenCalledTimes(1)
    expect(mockNotify).toHaveBeenCalledTimes(2)
  })
})
