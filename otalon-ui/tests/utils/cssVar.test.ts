/**
 * Regression tests for the shared CSS custom property reader.
 *
 * Ensures getCssVar reads theme tokens from the element that carries
 * Quasar's theme class (<body>), not from <html>, and falls back to a
 * literal value when a token is undefined.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { getCssVar } from '~/utils/cssVar'

describe('getCssVar', () => {
  beforeEach(() => {
    document.body.className = ''
    document.body.style.cssText = ''
    document.documentElement.style.cssText = ''
  })

  it('reads a token from document.body when the theme class is present', () => {
    document.body.classList.add('body--dark')
    document.body.style.setProperty('--cd-plot-text', '#e0f7fa')

    expect(getCssVar('--cd-plot-text', '#37474f')).toBe('#e0f7fa')
  })

  it('returns the fallback when the token is not defined anywhere', () => {
    expect(getCssVar('--cd-plot-text', '#37474f')).toBe('#37474f')
  })
})
