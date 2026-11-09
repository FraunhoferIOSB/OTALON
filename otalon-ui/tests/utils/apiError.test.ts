/**
 * Tests for ``app/utils/apiError.ts`` — FastAPI error-detail formatting.
 *
 * FastAPI returns ``detail`` in three shapes the UI must handle without
 * crashing:
 *
 * 1. **string** — custom raises and stock 404 / 502 / 500 responses.
 * 2. **array of validation errors** — every HTTP 422 from a Pydantic
 *    ``RequestValidationError`` (e.g. ``/scans/start`` rejecting an
 *    invalid override). Calling ``.trim()`` on this used to crash the
 *    Scan modal (see ``feature/scans-live-e2e``, May 2026).
 * 3. **missing / empty** — generic upstream errors with no body.
 */
import { describe, expect, it } from 'vitest'

import type { ApiError } from '~/composables/useApi'
import { formatApiError, formatApiErrorDetail } from '~/utils/apiError'

describe('formatApiErrorDetail', () => {
  it('returns null for undefined / null / empty string', () => {
    expect(formatApiErrorDetail(undefined)).toBeNull()
    expect(formatApiErrorDetail(null)).toBeNull()
    expect(formatApiErrorDetail('')).toBeNull()
    expect(formatApiErrorDetail('   ')).toBeNull()
  })

  it('passes plain strings through trimmed', () => {
    expect(formatApiErrorDetail('Not Found')).toBe('Not Found')
    expect(formatApiErrorDetail('  oops  ')).toBe('oops')
  })

  it('joins a FastAPI 422 validation-error array into a single line', () => {
    const detail = [
      {
        type: 'value_error',
        loc: ['body', 'overrides', 'network_interface'],
        msg: "network_interface 'eno1' not present on host",
      },
      {
        type: 'missing',
        loc: ['body', 'module_name'],
        msg: 'Field required',
      },
    ]
    const out = formatApiErrorDetail(detail)
    expect(out).toBe(
      "overrides.network_interface: network_interface 'eno1' not present on host;" + ' module_name: Field required',
    )
  })

  it('handles validation items without a loc array', () => {
    const detail = [{ msg: 'something broke' }]
    expect(formatApiErrorDetail(detail)).toBe('something broke')
  })

  it('strips the leading "body" segment from loc paths', () => {
    const detail = [{ loc: ['body'], msg: 'top-level rejection' }]
    expect(formatApiErrorDetail(detail)).toBe('top-level rejection')
  })

  it('returns null for an array with no usable entries', () => {
    expect(formatApiErrorDetail([])).toBeNull()
    expect(formatApiErrorDetail([{ type: 'x' }])).toBeNull()
  })
})

describe('formatApiError', () => {
  const base: ApiError = { status: 500, message: 'Request failed' }

  it('uses message when detail missing', () => {
    expect(formatApiError(base, 'Scan start')).toBe('Scan start failed (500): Request failed')
  })

  it('prefers string detail over message', () => {
    const err: ApiError = { ...base, status: 502, detail: 'upstream unreachable' }
    expect(formatApiError(err, 'Scan start')).toBe('Scan start failed (502): upstream unreachable')
  })

  it('does not throw on array detail (regression: TypeError trim)', () => {
    const err: ApiError = {
      status: 422,
      message: 'Validation Error',
      detail: [
        {
          type: 'value_error',
          loc: ['body', 'overrides', 'network_interface'],
          msg: "interface 'eno1' not present",
        },
      ],
    }
    expect(() => formatApiError(err, 'Scan start')).not.toThrow()
    expect(formatApiError(err, 'Scan start')).toBe(
      "Scan start failed (422): overrides.network_interface: interface 'eno1' not present",
    )
  })

  it('falls back to message when detail is empty array', () => {
    const err: ApiError = { ...base, status: 422, detail: [] }
    expect(formatApiError(err, 'Scan start')).toBe('Scan start failed (422): Request failed')
  })
})
