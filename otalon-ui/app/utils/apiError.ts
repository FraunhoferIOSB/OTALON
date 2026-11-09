import type { ApiError, ApiErrorDetailItem } from '~/composables/useApi'

/**
 * Render a FastAPI ``detail`` payload as a single-line string suitable
 * for display in toasts / error banners.
 *
 * Handles all three shapes FastAPI emits:
 *
 * - **string** — passed through verbatim after trim (e.g. ``"Not Found"``,
 *   ``"upstream otalon-scan unreachable: ..."``).
 * - **array of validation errors** — joined with ``"; "``. Each item is
 *   formatted as ``"<loc>: <msg>"`` where ``<loc>`` drops the leading
 *   ``"body"`` segment FastAPI always prepends.
 * - **null / undefined / empty** — returns ``null`` so callers can fall
 *   back to a generic message.
 */
export function formatApiErrorDetail(detail: string | ApiErrorDetailItem[] | null | undefined): string | null {
  if (detail === null || detail === undefined) {
    return null
  }
  if (typeof detail === 'string') {
    const trimmed = detail.trim()
    return trimmed === '' ? null : trimmed
  }
  if (Array.isArray(detail)) {
    const parts: string[] = []
    for (const item of detail) {
      if (item === null || typeof item !== 'object') continue
      const msg = typeof item.msg === 'string' ? item.msg : ''
      const loc = Array.isArray(item.loc) ? item.loc.filter((seg) => seg !== 'body').join('.') : ''
      if (msg === '' && loc === '') continue
      parts.push(loc === '' ? msg : `${loc}: ${msg}`)
    }
    if (parts.length === 0) return null
    return parts.join('; ')
  }
  return null
}

/**
 * Format an :class:`ApiError` for in-modal / toast display.
 *
 * @param err - The structured error from {@link useApi}.
 * @param actionLabel - Short human label of the failed action (e.g.
 *   ``"Scan start"``). Used as the prefix.
 */
export function formatApiError(err: ApiError, actionLabel: string): string {
  const detail = formatApiErrorDetail(err.detail)
  if (detail !== null) {
    return `${actionLabel} failed (${err.status}): ${detail}`
  }
  return `${actionLabel} failed (${err.status}): ${err.message}`
}
